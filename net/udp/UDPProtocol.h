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
	@brief Declaration of UDPProtocol
 */

#ifndef UDPProtocol_h
#define UDPProtocol_h

#include "UDPPacket.h"

#define UDP_IPV4_PAYLOAD_MTU (IPV4_PAYLOAD_MTU - 4)

/**
	@brief UDP protocol driver
 */
class UDPProtocol
{
public:
	UDPProtocol(IPv4Protocol* ipv4);
	//TODO: IPv6 backend

	void OnRxPacket(
		UDPPacket* packet,
		uint16_t ipPayloadLength,
		IPv4Address sourceAddress,
		uint16_t pseudoHeaderChecksum);

	//Called at 1 Hz by the stack to handle protocol-level aging
	virtual void OnAgingTick()
	{}

	///@brief Allocates an outbound packet
	UDPPacket* GetTxPacket(IPv4Address dstip);

	///@brief Cancels sending of a packet
	void CancelTxPacket(UDPPacket* packet);

	/**
		@brief Sends a UDP packet on a given socket handle
	 */
	void SendTxPacket(
		UDPPacket* packet,
		uint16_t sport,
		uint16_t dport,
		uint16_t payloadLength);

	IPv4Protocol* GetIPv4()
	{ return m_ipv4; }

protected:

	virtual void OnRxData(IPv4Address srcip, uint16_t sport, uint16_t dport, uint8_t* payload, uint16_t payloadLen);

	///@brief The IPv4 protocol stack
	IPv4Protocol* m_ipv4;
};

#endif
