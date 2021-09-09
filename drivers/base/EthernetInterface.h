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
	@brief Declaration of EthernetInterface
 */

#ifndef EthernetInterface_h
#define EthernetInterface_h

#include "../../net/ethernet/EthernetFrame.h"
#include "EthernetInterfacePerformanceCounters.h"

/**
	@brief Ethernet driver base class
 */
class EthernetInterface
{
public:
	virtual ~EthernetInterface();

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Transmit path

	/**
		@brief Gets a pointer to a buffer which can be filled with TX frame content.

		The buffer is owned by the caller and must be returned to the driver by calling SendTxFrame() or
		CancelTxFrame().
	 */
	virtual EthernetFrame* GetTxFrame() =0;

	/**
		@brief Sends a frame.

		Ownership of the frame memory is transferred to the interface object, which may free it or return it to a DMA
		queue depending on the implementation.
	 */
	virtual void SendTxFrame(EthernetFrame* frame) =0;

	/**
		@brief Cancels sending of an outbound frame.

		Ownership of the frame memory is transferred to the interface object, which may free it or return it to a DMA
		queue depending on the implementation.
	 */
	virtual void CancelTxFrame(EthernetFrame* frame) =0;

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Receive path

	/**
		@brief Returns the next frame in the receive buffer (or NULL if none is present).

		This function is typically called after an interrupt reports that a frame is ready to process.

		This buffer must be released by calling ReleaseRxFrame() upon completion of processing.
	 */
	virtual EthernetFrame* GetRxFrame() =0;

	/**
		@brief Notifies the driver that we are done with an inbound frame.

		Ownership of the frame memory is transferred to the interface object, which may free it or return it to a DMA
		queue depending on the implementation.
	 */
	virtual void ReleaseRxFrame(EthernetFrame* frame) =0;

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Performance counters

#ifdef STATICNET_PERFORMANCE_COUNTERS

	///@brief Gets the performance counter data for this interface
	const EthernetInterfacePerformanceCounters& PerfCounters()
	{ return m_perfCounters; }

protected:

	///@brief Performance counters
	EthernetInterfacePerformanceCounters m_perfCounters;

#endif
};

#endif
