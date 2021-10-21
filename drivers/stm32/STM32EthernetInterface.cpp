/***********************************************************************************************************************
*                                                                                                                      *
* staticnet v0.1                                                                                                       *
*                                                                                                                      *
* Copyright (c) 2021 Andrew D. Zonenberg and contributors                                                              *
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
#include <staticnet/stack/staticnet.h>
#include <stm32fxxx.h>
#include "STM32EthernetInterface.h"

#include <util/Logger.h>
extern Logger g_log;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Construction / destruction

STM32EthernetInterface::STM32EthernetInterface()
	: m_nextRxBuffer(0)
{
	//Initialize DMA ring buffers
	for(int i=0; i<4; i++)
	{
		m_rxDmaDescriptors[i].RDES0 = 0x80000000;
		if(i == 3)
			m_rxDmaDescriptors[i].RDES1 = 0x00008800;
		else
			m_rxDmaDescriptors[i].RDES1 = 0x00000800;

		m_rxDmaDescriptors[i].RDES2 = reinterpret_cast<uint32_t>(m_rxBuffers[i].RawData());
		m_rxDmaDescriptors[i].RDES3 = 0;
	}
	EDMA.DMARDLAR = &m_rxDmaDescriptors[0];

	//Poll demand DMA RX
	EDMA.DMARPDR = 0;
}

STM32EthernetInterface::~STM32EthernetInterface()
{
	//nothing here
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Transmit path

EthernetFrame* STM32EthernetInterface::GetTxFrame()
{
	g_log(Logger::ERROR, "GetTxFrame called\n");
	while(1)
	{}
	//return new EthernetFrame;
	return NULL;
}

void STM32EthernetInterface::SendTxFrame(EthernetFrame* frame)
{
	/*
	write(m_hTun, frame->RawData(), frame->Length());
	delete frame;
	*/
}

void STM32EthernetInterface::CancelTxFrame(EthernetFrame* frame)
{
	//delete frame;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Receive path

EthernetFrame* STM32EthernetInterface::GetRxFrame()
{
	int nbuf = m_nextRxBuffer;

	//Check if we have a frame ready to read
	auto& desc = m_rxDmaDescriptors[nbuf];
	if( (desc.RDES0 & 0x80000000) != 0)
		return NULL;

	//TODO: desc.RDES0 & 0x2 indicates CRC error

	auto frame = &m_rxBuffers[nbuf];

	//Get the length (trim the CRC)
	int len = (desc.RDES0 >> 16) & 0x3fff;
	if(len < 4)
		return NULL;
	len -= 4;
	frame->SetLength(len);

	#ifdef STATICNET_PERFORMANCE_COUNTERS

		if(frame->DstMAC().IsUnicast())
			m_perfCounters.m_rxFramesUnicast ++;
		else
			m_perfCounters.m_rxFramesMulticast ++;
		m_perfCounters.m_rxBytesTotal += len;

	#endif

	//Bump the buffer index
	m_nextRxBuffer = (m_nextRxBuffer + 1) % 4;

	//All done
	return frame;
}

void STM32EthernetInterface::ReleaseRxFrame(EthernetFrame* frame)
{
	int numBuffer = frame - &m_rxBuffers[0];
	if(numBuffer >= 4)
		return;

	//Mark the buffer as free for the DMA to use
	m_rxDmaDescriptors[numBuffer].RDES0 |= 0x80000000;

	//and tell the DMA to re-poll the descriptor list
	EDMA.DMARPDR = 0;
}
