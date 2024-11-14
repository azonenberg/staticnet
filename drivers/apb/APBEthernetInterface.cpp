/***********************************************************************************************************************
*                                                                                                                      *
* staticnet                                                                                                            *
*                                                                                                                      *
* Copyright (c) 2021-2024 Andrew D. Zonenberg and contributors                                                         *
* All rights reserved.                                                                                                 *
*                                                                                                                      *
* Redistribution and use in source and binary forms, with or without modification, are permitted provided that the     *
* following conditions are met:                                                                                        *
*                                                                                                                      *
*    * Redistributions of source code must retain the above copyright notice, this list of conditions, and the         *
*      following disclaimer.                                                                                           *
*                                                                                                                      *
*    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the       *
*      following disclaimer in the documentation and/or other materials provided with the distribution.                *
*                                                                                                                      *
*    * Neither the name of the author nor the names of any contributors may be used to endorse or promote products     *
*      derived from this software without specific prior written permission.                                           *
*                                                                                                                      *
* THIS SOFTWARE IS PROVIDED BY THE AUTHORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED   *
* TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL *
* THE AUTHORS BE HELD LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES        *
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR       *
* BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT *
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE       *
* POSSIBILITY OF SUCH DAMAGE.                                                                                          *
*                                                                                                                      *
***********************************************************************************************************************/

#include <staticnet-config.h>
#include <stdint.h>
#include <string.h>
#include "APBEthernetInterface.h"
#include <ctype.h>

//debug logging
#include <embedded-utils/Logger.h>
extern Logger g_log;

#ifdef HAVE_MDMA
	//New MDMA channel configurations for linked list format
	__attribute__((aligned(16))) MDMATransferConfig g_sendCommitFlagDmaConfig;
	__attribute__((aligned(16))) MDMATransferConfig g_sendPacketDataDmaConfig;

	__attribute__((section(".tcmbss"))) uint32_t g_ethPacketLen;
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Construction / destruction

APBEthernetInterface::APBEthernetInterface(
	volatile APB_EthernetRxBuffer* rxbuf,
	volatile APB_EthernetTxBuffer_10G* txbuf)
	: m_rxBuf(rxbuf)
	, m_txBuf(txbuf)
#ifdef HAVE_MDMA
	, m_commitFlag(1)
	, m_dmaTxFrame(nullptr)
#endif
{
	for(int i=0; i<APB_TX_BUFCOUNT; i++)
		m_txFreeList.push_back(&m_txBuffers[i]);
	for(int i=0; i<APB_RX_BUFCOUNT; i++)
		m_rxFreeList.push_back(&m_rxBuffers[i]);

	//TODO: hardware resets of peripherals?
}

void APBEthernetInterface::Init()
{
	#ifdef HAVE_MDMA

		//Request a DMA channel. If we can't get one, fail
		m_dmaChannel = g_mdma.AllocateChannel();
		if(!m_dmaChannel)
		{
			g_log(Logger::ERROR, "APBEthernetInterface::Init(): fatal error, no MDMA channels available\n");
			while(1)
			{}
		}
		g_log("APBEthernetInterface is using MDMA channel %d\n", m_dmaChannel->GetIndex());

		//Do high level configuration of the DMA channel (same for every packet)
		auto& tc = m_dmaChannel->GetTransferConfig();
		tc.EnableWriteBuffer();
		tc.SetSoftwareRequestMode();
		tc.EnablePackMode();
		tc.SetTriggerMode(MDMATransferConfig::MODE_LINKED_LIST);
		tc.SetSourcePointerMode(
			MDMATransferConfig::SOURCE_INCREMENT,
			MDMATransferConfig::SOURCE_INC_16,
			MDMATransferConfig::SOURCE_SIZE_16);
		tc.SetDestPointerMode(
			MDMATransferConfig::DEST_INCREMENT,
			MDMATransferConfig::DEST_INC_32,
			MDMATransferConfig::DEST_SIZE_32);
		tc.SetBufferTransactionLength(4);
		tc.SetTransferBytes(4);
		tc.SetSourceBurstLength(MDMATransferConfig::SOURCE_BURST_2);
		tc.SetBusConfig(MDMATransferConfig::SRC_TCM, MDMATransferConfig::DST_AXI);

		//Configure DMA for the packet data (copy config from top level channel)
		g_sendPacketDataDmaConfig = tc;
		//BNDTR is updated at packet send time
		//SAR and DAR are updated at packet send time
		g_sendPacketDataDmaConfig.AppendTransfer(&g_sendCommitFlagDmaConfig);

		//Configure DMA for the commit flag
		g_sendCommitFlagDmaConfig = tc;
		g_sendCommitFlagDmaConfig.SetTransferBlockConfig(4, 1);
		g_sendCommitFlagDmaConfig.SetSourcePointer(&m_commitFlag);
		g_sendCommitFlagDmaConfig.SetDestPointer(&m_txBuf->tx_commit);
		g_sendCommitFlagDmaConfig.AppendTransfer(nullptr);

	#endif
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Transmit path

#ifdef HAVE_ITCM
__attribute__((section(".tcmtext")))
#endif
EthernetFrame* APBEthernetInterface::GetTxFrame()
{
	if(m_txFreeList.empty())
		return nullptr;

	else
	{
		auto ret = m_txFreeList.back();
		m_txFreeList.pop_back();
		return ret;
	}
}

#ifdef HAVE_ITCM
__attribute__((section(".tcmtext")))
#endif
void APBEthernetInterface::SendTxFrame(EthernetFrame* frame, bool markFree)
{
	if(frame == nullptr)
	{
		//can't use logger to avoid infinite recursion
		//g_log("tried to send a null frame\n");
		return;
	}

	//Figure out how many 32-bit words to copy
	uint32_t len = frame->Length();
	uint32_t wordlen = len / 4;
	if(len % 4)
		wordlen ++;

	#ifdef QSPI_CACHE_WORKAROUND

		//Send length field
		m_txBuf->tx_len = len;

		//Force 32 bit copies to the tx_word register to avoid weirdness
		uint8_t* src = frame->RawData();
		for(uint32_t i=0; i<wordlen; i++)
		{
			uint8_t* p = src + i*4;
			uint32_t tmp =
				(p[3] << 24) |
				(p[2] << 16) |
				(p[1] << 8) |
				(p[0] << 0);

			m_txBuf->tx_word = tmp;
			asm("dmb st");
		}

		//Commit
		m_txBuf->tx_commit = 1;

		//Done, put on free list
		if(markFree)
			m_txFreeList.push_back(frame);


	#elif defined( HAVE_MDMA )

		//Make sure the previous DMA has completed before we try to reconfigure the channel
		m_dmaChannel->WaitIdle();

		//Mark the previous frame, if any, as free
		//(TODO do this in an ISR)
		if(m_dmaTxFrame)
		{
			m_txFreeList.Push(m_dmaTxFrame);
			m_dmaTxFrame = nullptr;
		}
		g_ethPacketLen = len;

		//First DMA operation: send tx_len then chain to frame data
		auto& tc = m_dmaChannel->GetTransferConfig();
		tc.SetTransferBlockConfig(4, 1);
		tc.SetSourcePointer(&g_ethPacketLen);
		tc.SetDestPointer(&m_txBuf->tx_len);
		tc.AppendTransfer(&g_sendPacketDataDmaConfig);

		//Second DMA operation: Send frame data then chain to commit
		g_sendPacketDataDmaConfig.SetTransferBlockConfig(4, wordlen);
		g_sendPacketDataDmaConfig.SetSourcePointer(frame->RawData());
		g_sendPacketDataDmaConfig.SetDestPointer(&m_txBuf->tx_buf[0]);

		//Chain is constructed, start the DMA
		m_dmaChannel->Start();

		//Mark this frame as in progress
		if(markFree)
			m_dmaTxFrame = frame;

	#else

		//Send length field
		m_txBuf->tx_len = len;

		//Force 32 bit copies for now since the buffer doesn't support anything smaller yet
		volatile uint32_t* dst = reinterpret_cast<volatile uint32_t*>(&m_txBuf->tx_buf[0]);
		uint8_t* src = frame->RawData();
		for(uint32_t i=0; i<wordlen; i++)
		{
			uint8_t* p = src + i*4;
			uint32_t tmp =
				(p[3] << 24) |
				(p[2] << 16) |
				(p[1] << 8) |
				(p[0] << 0);

			dst[i] = tmp;
		}

		//Commit
		m_txBuf->tx_commit = 1;

		//Done, put on free list
		if(markFree)
			m_txFreeList.push_back(frame);

	#endif
}

#ifdef HAVE_ITCM
__attribute__((section(".tcmtext")))
#endif
void APBEthernetInterface::CancelTxFrame(EthernetFrame* frame)
{
	//Return it to the free list
	m_txFreeList.push_back(frame);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Receive path

#ifdef HAVE_ITCM
__attribute__((section(".tcmtext")))
#endif
EthernetFrame* APBEthernetInterface::GetRxFrame()
{
	//Read and sanity check length
	uint16_t len = m_rxBuf->rx_len;
	if(len > 1500)
	{
		g_log(Logger::ERROR, "Got a %d byte long frame (max size 1500, FPGA should not have done this)\n", (int)len);
		return nullptr;
	}
	if(len == 0)
	{
		g_log(Logger::ERROR, "Got a zero-byte Ethernet frame, makes no sense\n");
		m_rxBuf->rx_pop = 1;
		return nullptr;
	}

	//Make sure we have somewhere to put the frame
	if(m_rxFreeList.empty())
	{
		g_log("Frame dropped due to lack of buffers\n");

		//Discard it
		m_rxBuf->rx_pop = 1;
		return nullptr;
	}

	//Read it
	//TODO: DMA optimizations
	//Round transaction length up to an integer number of 32-bit words to force 32-bit copies
	auto frame = m_rxFreeList.back();
	m_rxFreeList.pop_back();
	frame->SetLength(len);
	uint32_t padlen = len;
	if(padlen % 4)
		padlen = (padlen | 3) + 1;
	memcpy(frame->RawData(), (void*)&m_rxBuf->rx_buf, padlen);
	m_rxBuf->rx_pop = 1;

	return frame;
}

#ifdef HAVE_ITCM
__attribute__((section(".tcmtext")))
#endif
void APBEthernetInterface::ReleaseRxFrame(EthernetFrame* frame)
{
	m_rxFreeList.push_back(frame);
}
