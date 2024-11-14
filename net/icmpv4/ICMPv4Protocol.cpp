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

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Construction / destruction

ICMPv4Protocol::ICMPv4Protocol(IPv4Protocol& proto)
	: m_ipv4(proto)
{
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Handler for incoming packets

/**
	@brief Handles an incoming ICMP packet
 */
void ICMPv4Protocol::OnRxPacket(ICMPv4Packet* packet, uint16_t ipPayloadLength, IPv4Address sourceAddress)
{
	//Drop any packets too small for a complete header
	if(ipPayloadLength < 8)
		return;

	//Verify checksum of packet body
	if(0xffff != IPv4Protocol::InternetChecksum(reinterpret_cast<uint8_t*>(packet), ipPayloadLength))
		return;

	//See what we've got
	switch(packet->m_type)
	{
		case ICMPv4Packet::TYPE_ECHO_REQUEST:
			OnRxEchoRequest(packet, ipPayloadLength, sourceAddress);
			break;

		//ignore anything unrecognized
		default:
			break;
	}
}

/**
	@brief Handles an incoming echo request (ping) packet
 */
void ICMPv4Protocol::OnRxEchoRequest(ICMPv4Packet* packet, uint16_t ipPayloadLength, IPv4Address sourceAddress)
{
	//Get ready to send a reply
	auto reply = m_ipv4.GetTxPacket(sourceAddress, IP_PROTO_ICMP);
	if(reply == NULL)
		return;

	//Format the reply
	auto payload = reinterpret_cast<ICMPv4Packet*>(reply->Payload());
	payload->m_type = ICMPv4Packet::TYPE_ECHO_REPLY;
	payload->m_code = 0;
	payload->m_checksum = 0;	//filler for checksum calculation

	//Copy header and payload body unchanged
	memcpy(&payload->m_headerBody, packet->m_headerBody, ipPayloadLength - 4);

	//Calculate the new checksum
	//TODO: we can patch the checksum without fully recalculating,
	//since it's addition based and we only changed one byte!
	payload->m_checksum = ~__builtin_bswap16(
		IPv4Protocol::InternetChecksum(reinterpret_cast<uint8_t*>(payload), ipPayloadLength));

	//Send the reply
	m_ipv4.SendTxPacket(reply, ipPayloadLength);
}
