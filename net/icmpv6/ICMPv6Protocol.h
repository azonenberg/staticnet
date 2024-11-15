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
	@brief Declaration of ICMPv6Protocol
 */

#ifndef ICMPv6Protocol_h
#define ICMPv6Protocol_h

#include "ICMPv6Packet.h"

/**
	@brief ICMPv6 protocol driver
 */
class ICMPv6Protocol
{
public:
	ICMPv6Protocol(IPv6Protocol& proto);

	void OnRxPacket(
		ICMPv6Packet* packet,
		uint16_t ipPayloadLength,
		IPv6Address sourceAddress,
		uint16_t pseudoHeaderChecksum);

protected:
	void OnRxRouterAdvertisement(
		ICMPv6Packet* packet,
		uint16_t ipPayloadLength,
		IPv6Address sourceAddress);

	enum class RouterAdvertisementOption
	{
		SourceLinkLayerAddress = 1,
		PrefixInformation = 3
	};

/*
	void OnRxEchoRequest(
		ICMPv6Packet* packet,
		uint16_t ipPayloadLength,
		IPv6Address sourceAddress);*/

	///The IPv6 protocol stack
	IPv6Protocol& m_ipv6;
};

#endif
