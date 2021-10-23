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
#include <peripheral/RCC.h>
#include "STM32EthernetInterface.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Construction / destruction

STM32EthernetInterface::STM32EthernetInterface()
	: m_nextRxBuffer(0)
	, m_nextTxDescriptorWrite(0)
	, m_nextTxDescriptorDone(0)
{
	RCCHelper::Enable(&EMAC);

	//Wait for DMA reset to finish
	while((EDMA.DMABMR & 1) == 1)
	{}
	EMAC.MMCCR = 1;

	//Receive all frames. promiscuous mode
	EMAC.MACFFR = 0x80000001;

	//Initialize DMA RX ring buffers
	for(int i=0; i<4; i++)
	{
		m_rxDmaDescriptors[i].RDES0 = 0x80000000;
		if(i == 3)
			m_rxDmaDescriptors[i].RDES1 = 0x00008000 | ETHERNET_BUFFER_SIZE;
		else
			m_rxDmaDescriptors[i].RDES1 = 0x00000000 | ETHERNET_BUFFER_SIZE;

		m_rxDmaDescriptors[i].RDES2 = m_rxBuffers[i].RawData();
		m_rxDmaDescriptors[i].RDES3 = nullptr;
	}
	EDMA.DMARDLAR = &m_rxDmaDescriptors[0];

	//Initialize DMA TX ring buffers (all zero)
	for(int i=0; i<4; i++)
	{
		m_txDmaDescriptors[i].TDES0 = 0x00000000;
		m_txDmaDescriptors[i].TDES1 = 0x00000000;
		m_txDmaDescriptors[i].TDES2 = 0x00000000;
		m_txDmaDescriptors[i].TDES3 = 0x00000000;
	}
	EDMA.DMATDLAR = &m_txDmaDescriptors[0];

	//Set up free list for transmit frame buffers
	for(int i=0; i<TX_BUFFER_FRAMES; i++)
		m_txFreeList.Push(&m_txBuffers[i]);

	//Poll demand DMA RX
	EDMA.DMARPDR = 0;

	//Select mode: 100/full, RX enabled, TX enabled, no carrier sense
	EMAC.MACCR = 0x1c80c;

	//Enable actual DMA in DMAOMR bits 1/13
	EDMA.DMAOMR |= 0x2002;
}

STM32EthernetInterface::~STM32EthernetInterface()
{
	//nothing here
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Transmit path

EthernetFrame* STM32EthernetInterface::GetTxFrame()
{
	//Check if any of the currently pending transmit frames have completed, and return them to the free list if so
	while(CheckForFinishedFrames())
	{}

	//Return the next buffer in the free list, or null if nothing is there
	if(m_txFreeList.IsEmpty())
		return NULL;

	auto frame = m_txFreeList.Pop();
	return frame;
}

/**
	@brief Check if any frames in the DMA are done, return true if yes
 */
bool STM32EthernetInterface::CheckForFinishedFrames()
{
	if(
		( (m_txDmaDescriptors[m_nextTxDescriptorDone].TDES0 & 0x80000000) == 0)	&&	//buffer owned by us
		  (m_txDmaDescriptors[m_nextTxDescriptorDone].TDES2 != 0)					//valid buffer pointer
		)
	{
		//EthernetFrame has 2 bytes of length before the buffer
		m_txFreeList.Push(reinterpret_cast<EthernetFrame*>(m_txDmaDescriptors[m_nextTxDescriptorDone].TDES2 - 2));

		m_txDmaDescriptors[m_nextTxDescriptorDone].TDES2 = 0;

		//go on to next descriptor in the ring
		m_nextTxDescriptorDone = (m_nextTxDescriptorDone + 1) % 4;

		return true;
	}

	return false;
}

void STM32EthernetInterface::SendTxFrame(EthernetFrame* frame)
{
	//If the descriptor is still busy, block until one frees up
	//TODO: save the frame somewhere
	auto& desc = m_txDmaDescriptors[m_nextTxDescriptorWrite];
	if(desc.TDES0 & 0x80000000)
	{
		while(!CheckForFinishedFrames())
		{}
	}

	//Write the descriptor
	desc.TDES0 = 0xb0000000;
	if(m_nextTxDescriptorWrite == 3)
		desc.TDES0 |= 0x00200000;
	desc.TDES1 = frame->Length();
	desc.TDES2 = frame->RawData();
	desc.TDES3 = nullptr;

	//Set the own bit
	desc.TDES0 |= 0x80000000;

	//Poll descriptor and start DMA again
	EDMA.DMATPDR = 0;
	EDMA.DMAOMR |= 0x2000;

	//Move on to next descriptor
	m_nextTxDescriptorWrite = (m_nextTxDescriptorWrite + 1) % 4;

	//Don't put on free list until DMA is done
}

void STM32EthernetInterface::CancelTxFrame(EthernetFrame* frame)
{
	//Return it to the free list
	m_txFreeList.Push(frame);
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
