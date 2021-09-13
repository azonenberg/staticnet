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
	@brief Declaration of TCPProtocol
 */

#ifndef TCPProtocol_h
#define TCPProtocol_h

#include "TCPSegment.h"

/**
	@brief A single entry in the TCP socket table
 */
class TCPTableEntry
{
public:
	TCPTableEntry()
	: m_valid(false)
	{}

	bool m_valid;
	IPv4Address m_remoteIP;
	uint16_t m_localPort;
	uint16_t m_remotePort;

	/**
		@brief Expected sequence number of the next incoming packet.

		This is the most recent ACK number we sent.
	 */
	uint32_t m_remoteSeq;

	///@brief Most recent sequence number we sent
	uint32_t m_localSeq;

	//TODO: aging
};

/**
	@brief A single bank of the TCP socket table (direct mapped)
 */
class TCPTableWay
{
public:
	TCPTableEntry m_lines[TCP_TABLE_LINES];
};

#define TCP_IPV4_PAYLOAD_MTU (IPV4_PAYLOAD_MTU - 20)

/**
	@brief TCP protocol driver
 */
class TCPProtocol
{
public:
	TCPProtocol(IPv4Protocol* ipv4);
	//TODO: IPv6 backend

	void OnRxPacket(
		TCPSegment* segment,
		uint16_t ipPayloadLength,
		IPv4Address sourceAddress,
		uint16_t pseudoHeaderChecksum);

protected:
	virtual bool IsPortOpen(uint16_t port);
	virtual uint32_t GenerateInitialSequenceNumber();
	virtual void OnRxData(TCPTableEntry* state, uint8_t* payload, uint16_t payloadLen);

protected:
	void OnRxSYN(TCPSegment* segment, IPv4Address sourceAddress);
	void OnRxRST(TCPSegment* segment, IPv4Address sourceAddress);
	void OnRxACK(TCPSegment* segment, IPv4Address sourceAddress, uint16_t payloadLen);

	uint16_t Hash(IPv4Address ip, uint16_t localPort, uint16_t remotePort);

	TCPTableEntry* AllocateSocketHandle(uint16_t hash);
	TCPTableEntry* GetSocketState(IPv4Address ip, uint16_t localPort, uint16_t remotePort);
	IPv4Packet* CreateReply(TCPTableEntry* state);

	void SendSegment(TCPSegment* segment, IPv4Packet* packet, uint16_t length = sizeof(TCPSegment));

	///@brief The IPv4 protocol stack
	IPv4Protocol* m_ipv4;

	///@brief The socket state table
	TCPTableWay m_socketTable[TCP_TABLE_WAYS];
};

#endif
