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
	@brief Declaration of IPv6Packet
 */

#ifndef IPv6Packet_h
#define IPv6Packet_h

#include "../ipv6/IPv6Address.h"

/**
	@brief An IPv6 packet sent over Ethernet
 */
class __attribute__((packed)) IPv6Packet
{
public:

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Byte ordering correction

	void ByteSwap()
	{
		m_versionTrafficClassFlowLabel = __builtin_bswap32(m_versionTrafficClassFlowLabel);
		m_payloadLength = __builtin_bswap16(m_payloadLength);

		//addresses always in network byte order for now
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Accessors for actual packet data

	//for now this returns payload including all extensions
	uint8_t* Payload()
	{ return reinterpret_cast<uint8_t*>(this) + m_payloadLength; }

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Data members

	///@brief Always 0x6, traffic class, and flow label
	uint32_t m_versionTrafficClassFlowLabel;

	///@brief Upper layer + extension length
	uint16_t m_payloadLength;

	///@brief Upper layer protocol (or extension type)
	uint8_t m_nextHeader;

	///@brief Network layer TTL
	uint8_t m_hopLimit;

	///@brief Origin of the packet
	IPv6Address m_sourceAddress;

	///@brief Destination of the packet
	IPv6Address m_destAddress;

	//Options and upper layer protocol data past here
};

#endif
