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

#include <stdio.h>

#include <staticnet-config.h>
#include "../../stack/staticnet.h"

//DEBUG
#include "../../../common-embedded-platform/core/platform.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Construction / destruction

ICMPv6Protocol::ICMPv6Protocol(IPv6Protocol& proto)
	: m_ipv6(proto)
{
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Handler for incoming packets

/**
	@brief Handles an incoming ICMP packet
 */
void ICMPv6Protocol::OnRxPacket(
	ICMPv6Packet* packet,
	uint16_t ipPayloadLength,
	IPv6Address sourceAddress,
	uint16_t pseudoHeaderChecksum)
{
	//g_log("ICMPv6Protocol::OnRxPacket\n");
	//LogIndenter li(g_log);

	//Drop any packets too small for a complete header
	if(ipPayloadLength < 4)
		return;

	//Verify checksum of packet body
	auto checksum = IPv4Protocol::InternetChecksum(
		reinterpret_cast<uint8_t*>(packet),
		ipPayloadLength,
		pseudoHeaderChecksum);
	if(0xffff != checksum)
		return;

	//See what we've got
	switch(packet->m_type)
	{
		case ICMPv6Packet::TYPE_ROUTER_ADVERTISEMENT:
			OnRxRouterAdvertisement(packet, ipPayloadLength, sourceAddress);
			break;

		/*case ICMPv6Packet::TYPE_ECHO_REQUEST:
			OnRxEchoRequest(packet, ipPayloadLength, sourceAddress);
			break;*/

		//ignore anything unrecognized
		default:
			break;
	}
}

void ICMPv6Protocol::OnRxRouterAdvertisement(
	ICMPv6Packet* packet,
	uint16_t ipPayloadLength,
	IPv6Address sourceAddress)
{
	g_log("ICMPv6Protocol::OnRxRouterAdvertisement\n");
	LogIndenter li(g_log);

	g_log("From: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
		__builtin_bswap16(sourceAddress.m_blocks[0]),
		__builtin_bswap16(sourceAddress.m_blocks[1]),
		__builtin_bswap16(sourceAddress.m_blocks[2]),
		__builtin_bswap16(sourceAddress.m_blocks[3]),
		__builtin_bswap16(sourceAddress.m_blocks[4]),
		__builtin_bswap16(sourceAddress.m_blocks[5]),
		__builtin_bswap16(sourceAddress.m_blocks[6]),
		__builtin_bswap16(sourceAddress.m_blocks[7]));

	//Get the payload data
	uint8_t* payload = packet->Payload();

	//[0] = current hop limit, ignore
	//[1] = flags, ignore

	//[2-3] = router lifetime, in seconds
	uint16_t routerLifetimeSec = (payload[2] << 8) | payload[3];
	g_log("Router lifetime: %u sec\n", routerLifetimeSec);

	//[4-7] = reachable time, ignore
	//[8-11] = retransmission time, ignore

	//12 and up = options
	uint8_t* popt = payload + 12;
	uint8_t* pend = payload + ipPayloadLength;
	while(popt < pend)
	{
		auto type = static_cast<RouterAdvertisementOption>(popt[0]);

		//abort on invalid length rather than infinite looping
		uint16_t len = popt[1] * 8;
		if(len == 0)
			break;
		if( (popt + len) > pend)
			break;

		switch(type)
		{
			case RouterAdvertisementOption::SourceLinkLayerAddress:
				{
					//Validate option length
					if(len != 8)
						break;

					g_log("Router MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
						popt[2], popt[3], popt[4], popt[5], popt[6], popt[7]);
				}
				break;

			case RouterAdvertisementOption::PrefixInformation:
				{
					//Validate option length
					if(len != 32)
						break;

					g_log("Prefix information\n");
					LogIndenter li2(g_log);

					uint8_t prefixLen = popt[2];
					if(prefixLen > 64)
						break;
					g_log("Prefix length: /%u\n", prefixLen);

					uint8_t flags = popt[3];
					if( (flags & 0xe0) == 0xe0)
						g_log("SLAAC available, router on link\n");
					else
						break;

					//If we get here it's a valid address we intend to SLAAC with

					uint32_t addressValidSec = (popt[4] << 24) | (popt[5] << 16) | (popt[6] << 8) | popt[7];
					g_log("Address valid for %u sec\n", addressValidSec);

					uint32_t addressPreferredSec = (popt[8] << 24) | (popt[9] << 16) | (popt[10] << 8) | popt[11];
					g_log("Address preferred for %u sec\n", addressPreferredSec);

					//4 bytes reserved

					//Read the prefix
					g_log("Prefix: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
						(popt[16] << 8) | popt[17],
						(popt[18] << 8) | popt[19],
						(popt[20] << 8) | popt[21],
						(popt[22] << 8) | popt[23],
						(popt[24] << 8) | popt[25],
						(popt[26] << 8) | popt[27],
						(popt[28] << 8) | popt[29],
						(popt[30] << 8) | popt[31]);
				}
				break;

			default:
				g_log("Unknown option %u\n", type);
				break;
		}

		popt += len;
	}
}

/**
	@brief Handles an incoming echo request (ping) packet
 */
/*
void ICMPv6Protocol::OnRxEchoRequest(ICMPv6Packet* packet, uint16_t ipPayloadLength, IPv6Address sourceAddress)
{
	//Get ready to send a reply
	auto reply = m_ipv6.GetTxPacket(sourceAddress, IP_PROTO_ICMP);
	if(reply == NULL)
		return;

	//Format the reply
	auto payload = reinterpret_cast<ICMPv6Packet*>(reply->Payload());
	payload->m_type = ICMPv6Packet::TYPE_ECHO_REPLY;
	payload->m_code = 0;
	payload->m_checksum = 0;	//filler for checksum calculation

	//Copy header and payload body unchanged
	memcpy(&payload->m_headerBody, packet->m_headerBody, ipPayloadLength - 4);

	//Calculate the new checksum
	//TODO: we can patch the checksum without fully recalculating,
	//since it's addition based and we only changed one byte!
	payload->m_checksum = ~__builtin_bswap16(
		IPv6Protocol::InternetChecksum(reinterpret_cast<uint8_t*>(payload), ipPayloadLength));

	//Send the reply
	m_ipv6.SendTxPacket(reply, ipPayloadLength);
}
*/
