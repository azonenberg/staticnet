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

//New MDMA channel configurations for linked list format
__attribute__((aligned(16))) MDMATransferConfig g_sendCommitFlagDmaConfig;
__attribute__((aligned(16))) MDMATransferConfig g_sendPacketDataDmaConfig;

__attribute__((section(".tcmbss"))) uint32_t g_ethCommitFlag;
__attribute__((section(".tcmbss"))) uint32_t g_ethPacketLen;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Construction / destruction

APBEthernetInterface::APBEthernetInterface(
	volatile APB_EthernetRxBuffer* rxbuf,
	volatile APB_EthernetTxBuffer_10G* txbuf)
	: m_rxBuf(rxbuf)
	, m_txBuf(txbuf)
	, m_dmaTxFrame(nullptr)
{
	for(int i=0; i<APB_TX_BUFCOUNT; i++)
		m_txFreeList.Push(&m_txBuffers[i]);
	for(int i=0; i<APB_RX_BUFCOUNT; i++)
		m_rxFreeList.Push(&m_rxBuffers[i]);

	//TODO: hardware resets of peripherals?
}

APBEthernetInterface::~APBEthernetInterface()
{
	//nothing here
}

void APBEthernetInterface::Init()
{
	#ifdef HAVE_MDMA

		//Requeast a DMA channel. If we can't get one, fail
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
		tc.TCR = MDMA_TCR_BWM |
			MDMA_TCR_SWRM | MDMA_TCR_TRGM_LINK | MDMA_TCR_PKE |
			MDMA_TCR_DEST_INC_32 | MDMA_TCR_SRC_INC_16 |
			MDMA_TCR_DEST_SIZE_32 | MDMA_TCR_SRC_SIZE_16 |
			MDMA_TCR_DEST_INC | MDMA_TCR_SRC_INC |
			(1 << 12) |	//move two 16-bit words at a time from the source
			(0 << 15) |	//move one 32-bit word to the destination
			(3 << 18);	//move 4 bytes at a time
		tc.SetBusConfig(MDMATransferConfig::SRC_TCM, MDMATransferConfig::DST_AXI);

		//Configure DMA for the packet data
		g_sendPacketDataDmaConfig.ConfigureDefaults();
		g_sendPacketDataDmaConfig.TCR = MDMA_TCR_BWM |
			MDMA_TCR_SWRM | MDMA_TCR_TRGM_LINK | MDMA_TCR_PKE |
			MDMA_TCR_DEST_INC_32 | MDMA_TCR_SRC_INC_16 |
			MDMA_TCR_DEST_SIZE_32 | MDMA_TCR_SRC_SIZE_16 |
			MDMA_TCR_DEST_INC | MDMA_TCR_SRC_INC |
			(1 << 12) |	//move two 16-bit words at a time from the source
			(0 << 15) |	//move one 32-bit word to the destination
			(3 << 18);	//move 4 bytes at a time
		//BNDTR is updated at packet send time
		g_sendPacketDataDmaConfig.SetBusConfig(MDMATransferConfig::SRC_TCM, MDMATransferConfig::DST_AXI);
		//SAR and DAR are updated at packet send time
		g_sendPacketDataDmaConfig.AppendTransfer(&g_sendCommitFlagDmaConfig);

		//Configure DMA for the commit flag
		g_sendCommitFlagDmaConfig.TCR = MDMA_TCR_BWM |
			MDMA_TCR_SWRM | MDMA_TCR_TRGM_LINK | MDMA_TCR_PKE |
			MDMA_TCR_DEST_INC_32 | MDMA_TCR_SRC_INC_16 |
			MDMA_TCR_DEST_SIZE_32 | MDMA_TCR_SRC_SIZE_16 |
			MDMA_TCR_DEST_INC | MDMA_TCR_SRC_INC |
			(1 << 12) |	//move two 16-bit words at a time from the source
			(0 << 15) |	//move one 32-bit word to the destination
			(3 << 18);	//move 4 bytes at a time
		g_sendCommitFlagDmaConfig.BNDTR =
			(0 << 20) |	//move 1 32-bit words of data
			(4 << 0);	//move 4 bytes per block
		g_sendCommitFlagDmaConfig.SetBusConfig(MDMATransferConfig::SRC_TCM, MDMATransferConfig::DST_AXI);
		g_sendCommitFlagDmaConfig.SetSourcePointer(&g_ethCommitFlag);
		g_sendCommitFlagDmaConfig.SetDestPointer(&m_txBuf->tx_commit);
		g_ethCommitFlag = 1;

	#endif
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Transmit path

EthernetFrame* APBEthernetInterface::GetTxFrame()
{
	if(m_txFreeList.IsEmpty())
		return nullptr;

	else
		return m_txFreeList.Pop();
}

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

	#ifdef HAVE_MDMA
	//#if 0

		//Wait for DMA channel to be idle
		auto& chan = _MDMA.channels[m_dmaChannel->GetIndex()];
		while(chan.ISR & MDMA_ISR_CRQA)
		{}

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
		tc.BNDTR =
			(0 << 20) |	//move 1 32-bit words of data
			(4 << 0);	//move 4 bytes per block
		tc.SetSourcePointer(&g_ethPacketLen);
		tc.SetDestPointer(&m_txBuf->tx_len);
		tc.AppendTransfer(&g_sendPacketDataDmaConfig);

		//Second DMA operation: Send frame data then chain to commit
		g_sendPacketDataDmaConfig.BNDTR =
			((wordlen-1) << 20) |	//move N 32-bit words of data
			(4 << 0);				//move 4 bytes per block
		g_sendPacketDataDmaConfig.SetSourcePointer(frame->RawData());
		g_sendPacketDataDmaConfig.SetDestPointer(&m_txBuf->tx_buf[0]);

		//Start the DMA (need to memory barrier so the descriptor updates commit first!)
		asm("dmb st");
		chan.CR |= MDMA_CR_EN;
		chan.CR |= MDMA_CR_SWRQ;

		//Mark this frame as in progress
		if(markFree)
			m_dmaTxFrame = frame;

	#else

		//Send length field
		m_txBuf->tx_len = len;

		//Force 32 byte copies for now since the buffer doesn't support anything smaller yet
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
			m_txFreeList.Push(frame);

	#endif
}

void APBEthernetInterface::CancelTxFrame(EthernetFrame* frame)
{
	//Return it to the free list
	m_txFreeList.Push(frame);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Receive path

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
	if(m_rxFreeList.IsEmpty())
	{
		g_log("Frame dropped due to lack of buffers\n");

		//Discard it
		m_rxBuf->rx_pop = 1;
		return nullptr;
	}

	//Read it
	//TODO: DMA optimizations
	//Round transaction length up to an integer number of 32-bit words to force 32-bit copies
	auto frame = m_rxFreeList.Pop();
	frame->SetLength(len);
	uint32_t padlen = len;
	if(padlen % 4)
		padlen = (padlen | 3) + 1;
	memcpy(frame->RawData(), (void*)&m_rxBuf->rx_buf, padlen);
	m_rxBuf->rx_pop = 1;

	return frame;
}

void APBEthernetInterface::ReleaseRxFrame(EthernetFrame* frame)
{
	m_rxFreeList.Push(frame);
}
