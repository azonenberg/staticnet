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

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Construction / destruction

APBEthernetInterface::APBEthernetInterface(
	volatile APB_EthernetRxBuffer* rxbuf,
	volatile APB_EthernetTxBuffer_10G* txbuf)
	: m_rxBuf(rxbuf)
	, m_txBuf(txbuf)
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

	uint32_t len = frame->Length();
	m_txBuf->tx_len = len;

	//Force 32 byte copies for now since the buffer doesn't support anything smaller yet
	uint32_t wordlen = len / 4;
	if(len % 4)
		wordlen ++;
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

	m_txBuf->tx_commit = 1;

	//Done, put on free list
	if(markFree)
		m_txFreeList.Push(frame);
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
