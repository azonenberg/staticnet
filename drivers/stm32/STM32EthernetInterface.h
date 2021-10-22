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

/**
	@file
	@brief Declaration of STM32EthernetInterface
 */

#ifndef STM32EthernetInterface_h
#define STM32EthernetInterface_h

#include <stm32fxxx.h>
#include <util/FIFO.h>
#include "../base/EthernetInterface.h"

/**
	@brief Ethernet driver using the STM32 Ethernet MAC
 */
class STM32EthernetInterface : public EthernetInterface
{
public:
	STM32EthernetInterface();
	virtual ~STM32EthernetInterface();

	virtual EthernetFrame* GetTxFrame();
	virtual void SendTxFrame(EthernetFrame* frame);
	virtual void CancelTxFrame(EthernetFrame* frame);
	virtual EthernetFrame* GetRxFrame();
	virtual void ReleaseRxFrame(EthernetFrame* frame);

protected:
	bool CheckForFinishedFrames();

	///@brief RX DMA descriptors
	volatile edma_rx_descriptor_t m_rxDmaDescriptors[4];

	///@brief TX DMA descriptors
	volatile edma_tx_descriptor_t m_txDmaDescriptors[4];

	/**
		@brief RX DMA buffers

		TODO: support having >4 buffers, so we can have some being processed by the app while others are being DMA'd?
	 */
	EthernetFrame m_rxBuffers[4];

	///@brief Index of the next DMA buffer to read from
	int m_nextRxBuffer;

	///@brief Index of the next DMA descriptor to write to
	int m_nextTxDescriptorWrite;

	///@brief Index of the next DMA descriptor to check for completion
	int m_nextTxDescriptorDone;

	///@brief TX buffers for DMA etc
	EthernetFrame m_txBuffers[TX_BUFFER_FRAMES];

	//TODO: pending buffers on hold in case retransmit is needed? need to record they're not free

	///@brief FIFO of free TX buffers
	FIFO<EthernetFrame*, TX_BUFFER_FRAMES> m_txFreeList;
};

#endif
