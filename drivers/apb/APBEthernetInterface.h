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

/**
	@file
	@brief Declaration of APBEthernetInterface
 */

#ifndef APBEthernetInterface_h
#define APBEthernetInterface_h

#include <embedded-utils/FIFO.h>
#include <staticnet/drivers/base/EthernetInterface.h>

#include <APB_EthernetRxBuffer.h>
#include <APB_EthernetTxBuffer_10G.h>

///@brief Number of frame buffers to allocate for frame reception
#define APB_RX_BUFCOUNT 8

///@brief Number of frame buffers to allocate for frame transmission
#define APB_TX_BUFCOUNT 8

//Pull in STM32 headers if we're on one (TODO better detection)
#if !defined(SIMULATION) && !defined(SOFTCORE_NO_IRQ)
#include <stm32.h>
#include <peripheral/MDMA.h>
#endif

/**
	@brief Ethernet driver using FPGA based MAC attached over APB

	NOTE: the current implementation uses some global state and only one instance can be used at a time as a result.
	(it's fine to have multiple objects, but only one can be sending at once)
 */
class APBEthernetInterface : public EthernetInterface
{
public:
	APBEthernetInterface(volatile APB_EthernetRxBuffer* rxbuf, volatile APB_EthernetTxBuffer_10G* txbuf);

	virtual EthernetFrame* GetTxFrame() override;
	virtual void SendTxFrame(EthernetFrame* frame, bool markFree=true) override;
	virtual void CancelTxFrame(EthernetFrame* frame) override;
	virtual EthernetFrame* GetRxFrame() override;
	virtual void ReleaseRxFrame(EthernetFrame* frame) override;

	void Init();

protected:

	///@brief RX packet buffers
	__attribute__((aligned(16))) EthernetFrame m_rxBuffers[APB_RX_BUFCOUNT];

	///@brief FIFO of RX buffers available for use
	FIFO<EthernetFrame*, APB_RX_BUFCOUNT> m_rxFreeList;

	///@brief TX packet buffers
	__attribute__((aligned(16))) EthernetFrame m_txBuffers[APB_TX_BUFCOUNT];

	///@brief FIFO of TX buffers available for use
	FIFO<EthernetFrame*, APB_TX_BUFCOUNT> m_txFreeList;

	///@brief RX buffer
	volatile APB_EthernetRxBuffer* m_rxBuf;

	///@brief TX buffer
	volatile APB_EthernetTxBuffer_10G* m_txBuf;

	#ifdef HAVE_MDMA
		///@brief Our DMA channel
		MDMAChannel* m_dmaChannel;

		///@brief Commit flag (always 1 but has to live in TCM)
		uint32_t m_commitFlag;

		//The frame currently being sent by DMA
		EthernetFrame* m_dmaTxFrame;
	#endif
};

#endif
