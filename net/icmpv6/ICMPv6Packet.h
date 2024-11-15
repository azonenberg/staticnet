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
	@brief Declaration of ICMPv6Packet
 */

#ifndef ICMPv6Packet_h
#define ICMPv6Packet_h

#include "../ipv6/IPv6Address.h"

/**
	@brief An ICMP packet sent over IPv6
 */
class __attribute__((packed)) ICMPv6Packet
{
public:
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Accessors for actual packet data

	//for now this returns payload including all extensions
	uint8_t* Payload()
	{ return reinterpret_cast<uint8_t*>(this) + sizeof(*this); }

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Message type fields

	enum icmptype_t
	{
		//TYPE_ECHO_REPLY		= 0,
		//TYPE_ECHO_REQUEST	= 8
		TYPE_ROUTER_ADVERTISEMENT	= 134
	};

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Data members

	///@brief Message type
	uint8_t		m_type;

	///@brief Message subtype
	uint8_t		m_code;

	///@brief Checksum of the ICMP header plus pseudo-header
	uint16_t	m_checksum;
};

#endif
