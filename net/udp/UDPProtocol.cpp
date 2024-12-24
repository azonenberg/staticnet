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

#include <staticnet-config.h>
#include <staticnet/stack/staticnet.h>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Construction / destruction

UDPProtocol::UDPProtocol(IPv4Protocol* ipv4)
	: m_ipv4(ipv4)
{
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Handler for incoming packets

/**
	@brief Handles an incoming UDP packet
 */
#ifdef HAVE_ITCM
__attribute__((section(".tcmtext")))
#endif
void UDPProtocol::OnRxPacket(
	UDPPacket* packet,
	uint16_t ipPayloadLength,
	IPv4Address sourceAddress,
	uint16_t pseudoHeaderChecksum)
{
	//Drop any packets too small for a complete UDP header
	if(ipPayloadLength < 8)
		return;

	//Verify checksum of packet body
	if(0xffff != IPv4Protocol::InternetChecksum(
		reinterpret_cast<uint8_t*>(packet),
		ipPayloadLength,
		pseudoHeaderChecksum))
	{
		return;
	}
	packet->ByteSwap();

	//Sanity check packet length fits in the packet
	if(packet->m_len > ipPayloadLength)
		return;

	//Handle the incoming packet
	OnRxData(sourceAddress, packet->m_sourcePort, packet->m_destPort, packet->Payload(), packet->m_len);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Outbound traffic

#ifdef HAVE_ITCM
__attribute__((section(".tcmtext")))
#endif
UDPPacket* UDPProtocol::GetTxPacket(IPv4Address dstip)
{
	//Allocate the frame and fail if we couldn't allocate one
	auto reply = m_ipv4->GetTxPacket(dstip, IP_PROTO_UDP);
	if(reply == nullptr)
		return nullptr;

	//All good, return the packet
	return reinterpret_cast<UDPPacket*>(reply->Payload());
}

void UDPProtocol::CancelTxPacket(UDPPacket* packet)
{
	//Cancel the packet in the upper layer
	m_ipv4->CancelTxPacket(reinterpret_cast<IPv4Packet*>(reinterpret_cast<uint8_t*>(packet) - sizeof(IPv4Packet)));
}

/**
	@brief Does final prep and sends a UDP packet
 */
#ifdef HAVE_ITCM
__attribute__((section(".tcmtext")))
#endif
void UDPProtocol::SendTxPacket(UDPPacket* packet, uint16_t sport, uint16_t dport, uint16_t payloadLen)
{
	auto length = payloadLen + 8;

	//Fill out the headers
	packet->m_sourcePort = sport;
	packet->m_destPort = dport;
	packet->m_len = length;

	//Calculate the pseudoheader checksum
	auto ipack = packet->Parent();
	#ifndef HAVE_UDP_V4_CHECKSUM_OFFLOAD
	auto pseudoHeaderChecksum = m_ipv4->PseudoHeaderChecksum(ipack, length);
	#endif

	//Zeroize the checksum when computing it
	packet->m_checksum = 0;

	//Need to be in network byte order before we send
	packet->ByteSwap();

	#ifdef HAVE_UDP_V4_CHECKSUM_OFFLOAD
		packet->m_checksum = 0x0000;	//will be filled in by hardware, but don't leave uninitialized
	#else
		packet->m_checksum = ~__builtin_bswap16(
			IPv4Protocol::InternetChecksum(reinterpret_cast<uint8_t*>(packet), length, pseudoHeaderChecksum));
	#endif

	//Actually send it
	m_ipv4->SendTxPacket(ipack, length, true);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Overrides for end user application logic

/**
	@brief Handles incoming packet data.

	The default implementation does nothing.
 */
void UDPProtocol::OnRxData(
	[[maybe_unused]] IPv4Address srcip,
	[[maybe_unused]] uint16_t sport,
	[[maybe_unused]] uint16_t dport,
	[[maybe_unused]] uint8_t* payload,
	[[maybe_unused]] uint16_t payloadLen)
{
}

