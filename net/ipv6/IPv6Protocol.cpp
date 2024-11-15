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
#include <staticnet/stack/staticnet.h>

#if !defined(SIMULATION) && !defined(SOFTCORE_NO_IRQ)
#include <stm32.h>
#endif

//DEBUG
#include "../../../common-embedded-platform/core/platform.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Construction / destruction

/**
	@brief Initializes the IPv6 protocol stack
 */
IPv6Protocol::IPv6Protocol(EthernetProtocol& eth, IPv6Config& config)
	: m_eth(eth)
	, m_config(config)
	, m_icmpv6(nullptr)
	//, m_tcp(nullptr)
	//, m_udp(nullptr)
	, m_allowUnknownUnicasts(false)
{

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Checksum calculation

/**
	@brief Calculates the TCP/UDP pseudoheader checksum for a packet
 */
#ifdef HAVE_ITCM
__attribute__((section(".tcmtext")))
#endif
uint16_t IPv6Protocol::PseudoHeaderChecksum(IPv6Packet* packet)
{
	uint16_t workingChecksum = IPv4Protocol::InternetChecksum(packet->m_sourceAddress.m_octets, 16);
	workingChecksum = IPv4Protocol::InternetChecksum(packet->m_destAddress.m_octets, 16, workingChecksum);

	uint8_t pseudoheader[]
	{
		0x0,
		packet->m_nextHeader,
		static_cast<uint8_t>(packet->m_payloadLength >> 8),
		static_cast<uint8_t>(packet->m_payloadLength & 0xff)
	};

	return IPv4Protocol::InternetChecksum(pseudoheader, sizeof(pseudoheader), workingChecksum);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Routing helpers

/**
	@brief Figures out if an address is a unicast to us, a broad/multicast, or something else
 */
IPv6Protocol::AddressType IPv6Protocol::GetAddressType(IPv6Address addr)
{
	//Multicast have the most significant byte set
	if(addr.m_octets[0] == 0xff)
		return ADDR_MULTICAST;

	//TODO: check for match to our link local or globally routable addresses
	//if(addr == m_config.m_address)
	//	return ADDR_UNICAST_US;

	//For anything else
	else
		return ADDR_UNICAST_OTHER;
}

/**
	@brief Checks if an address is in our local subnet or not
 */
/*
bool IPv6Protocol::IsLocalSubnet(IPv6Address addr)
{
	return (addr.m_word & m_config.m_netmask.m_word) == (m_config.m_address.m_word & m_config.m_netmask.m_word);
}
*/

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Handler for incoming packets

/**
	@brief Handle an incoming IPv6 packet
 */
void IPv6Protocol::OnRxPacket(IPv6Packet* packet, uint16_t ethernetPayloadLength)
{
	//See what we got
/*	g_log("IPv6Protocol::OnRxPacket(%u bytes)\n", (uint32_t)ethernetPayloadLength);
	LogIndenter li(g_log);*/

	//There's no checksum over the IPv6 header! So nothing special to do there

	//Swap header fields to host byte order
	packet->ByteSwap();

	//Must be IPv6, ignore traffic class and flow label
	if( (packet->m_versionTrafficClassFlowLabel & 0xf0000000) != 0x60000000)
		return;

	//Length must be plausible (not more than the MTU, we don't support fragmentation)
	if( (packet->m_payloadLength + 36) > ethernetPayloadLength)
		return;

	//Ignore hop limit

	//Print source address
	/*g_log("From: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
		__builtin_bswap16(packet->m_sourceAddress.m_blocks[0]),
		__builtin_bswap16(packet->m_sourceAddress.m_blocks[1]),
		__builtin_bswap16(packet->m_sourceAddress.m_blocks[2]),
		__builtin_bswap16(packet->m_sourceAddress.m_blocks[3]),
		__builtin_bswap16(packet->m_sourceAddress.m_blocks[4]),
		__builtin_bswap16(packet->m_sourceAddress.m_blocks[5]),
		__builtin_bswap16(packet->m_sourceAddress.m_blocks[6]),
		__builtin_bswap16(packet->m_sourceAddress.m_blocks[7]));

	g_log("To:   %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
		__builtin_bswap16(packet->m_destAddress.m_blocks[0]),
		__builtin_bswap16(packet->m_destAddress.m_blocks[1]),
		__builtin_bswap16(packet->m_destAddress.m_blocks[2]),
		__builtin_bswap16(packet->m_destAddress.m_blocks[3]),
		__builtin_bswap16(packet->m_destAddress.m_blocks[4]),
		__builtin_bswap16(packet->m_destAddress.m_blocks[5]),
		__builtin_bswap16(packet->m_destAddress.m_blocks[6]),
		__builtin_bswap16(packet->m_destAddress.m_blocks[7]));*/

	//See what dest address is. It should be us, multicast, or broadcast.
	//Discard any packet that isn't for an address we care about
	//TODO: discard anything directed to a multicast group we're not interested in?
	auto type = GetAddressType(packet->m_destAddress );
	if( (type == ADDR_UNICAST_OTHER) && !m_allowUnknownUnicasts)
		return;

	//Figure out the upper layer protocol
	switch(packet->m_nextHeader)
	{
		//ICMPv6 can be unicast (ping) or multicast (router advertisement)
		case IP_PROTO_ICMPV6:
			if(m_icmpv6 && ( (type == ADDR_UNICAST_US) || (type == ADDR_MULTICAST) ) )
			{
				m_icmpv6->OnRxPacket(
					reinterpret_cast<ICMPv6Packet*>(packet->Payload()),
					packet->m_payloadLength,
					packet->m_sourceAddress,
					PseudoHeaderChecksum(packet));
			}
			break;

		//Drop anything unrecognized
		default:
			g_log("Unknown next header %d, ignoring\n", packet->m_nextHeader);
			break;
	}

	/*
	//TCP segments must be directed at our unicast address.
	//The connection oriented flow makes no sense to be broadcast/multicast.
	case IP_PROTO_TCP:
		if(m_tcp && (type == ADDR_UNICAST_US) )
		{
			m_tcp->OnRxPacket(
				reinterpret_cast<TCPSegment*>(packet->Payload()),
				plen,
				packet->m_sourceAddress,
				PseudoHeaderChecksum(packet, plen));
		}
		break;

	//Allow unknown unicasts on request for UDP to enable e.g. DHCP
	case IP_PROTO_UDP:
		if(m_udp && ( (type == ADDR_UNICAST_US) || m_allowUnknownUnicasts) )
		{
			m_udp->OnRxPacket(
				reinterpret_cast<UDPPacket*>(packet->Payload()),
				plen,
				packet->m_sourceAddress,
				PseudoHeaderChecksum(packet, plen));
		}
		break;
	*/
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Link state changes

/**
	@brief Called when the link comes up
 */
void IPv6Protocol::OnLinkUp()
{
	/*
	//Send an ARP query for the default gateway
	auto arp = m_eth.GetARP();
	if(arp)
		arp->SendQuery(m_config.m_gateway);
	*/
}

/**
	@brief Called when the link goes down
 */
void IPv6Protocol::OnLinkDown()
{
	//m_cache.Clear();
}

/**
	@brief Called at 1 Hz to handle cache aging
 */
/*
void IPv6Protocol::OnAgingTick()
{
	if(m_udp)
		m_udp->OnAgingTick();

	auto expiry = m_cache.GetExpiry(m_config.m_gateway);

	//If it expires soon, send a query
	if(expiry < 15)
	{
		auto arp = m_eth.GetARP();
		if(arp)
			arp->SendQuery(m_config.m_gateway);
	}
}
*/

/**
	@brief Called at 10 Hz to handle retransmit aging
 */
/*
void IPv6Protocol::OnAgingTick10x()
{
	//Check the TCP stack for anything we might have to retransmit etc
	if(m_tcp)
		m_tcp->OnAgingTick10x();
}
*/

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Handler for outbound packets

/**
	@brief Allocates an outbound packet and prepare to send it

	Returns nullptr if we don't have an ARP entry for the destination yet and it's not a broadcast
 */
/*
#ifdef HAVE_ITCM
__attribute__((section(".tcmtext")))
#endif
IPv6Packet* IPv6Protocol::GetTxPacket(IPv6Address dest, ipproto_t proto)
{
	auto arp = m_eth.GetARP();

	//Find target MAC address
	//If not in our subnet, send it to the default gateway
	MACAddress destmac = {{0, 0, 0, 0, 0, 0}};
	if(!IsLocalSubnet(dest))
	{
		if(!m_cache.Lookup(destmac, m_config.m_gateway))
		{
			//Send an ARP query for the default gateway
			if(arp)
				arp->SendQuery(m_config.m_gateway);

			//But  for now, nothing we can do
			return nullptr;
		}
	}

	//It's in the local subnet. Either broadcast or ARP
	else
	{
		auto type = GetAddressType(dest);
		uint16_t expiry;
		switch(type)
		{
			//TODO: use well known mac for some multicasts
			//For now, just fall through to broadcast MAC
			case ADDR_MULTICAST:

			//If it's a broadcast, set it to a layer-2 broadcast MAC
			case ADDR_BROADCAST:
				destmac = MACAddress{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
				break;

			//Unicast? Check the ARP table
			case ADDR_UNICAST_OTHER:

				//Not in ARP cache? Send a query, but nothing we can do right now
				if(!m_cache.LookupAndExpiryCheck(destmac, dest, expiry))
				{
					if(arp)
						arp->SendQuery(dest);
					return nullptr;
				}

				//In cache, but expiring soon? Send a query to refresh the cache entry
				else if(expiry < 15)
				{
					if(arp)
						arp->SendQuery(dest);
				}

				break;

			//invalid destination (can't send to ourself)
			default:
				return nullptr;
		}
	}

	//Allocate the frame and fill headers
	auto frame = m_eth.GetTxFrame(ETHERTYPE_IPV4, destmac);
	if(!frame)
		return nullptr;

	auto reply = reinterpret_cast<IPv6Packet*>(frame->Payload());
	reply->m_versionAndHeaderLen = 0x45;
	reply->m_dscpAndECN = 0;
	reply->m_fragID = 0;
	reply->m_flagsFragOffHigh = 0x40;	//DF
	reply->m_fragOffLow = 0;
	reply->m_ttl = 0xff;
	reply->m_protocol = proto;
	reply->m_sourceAddress = m_config.m_address;
	reply->m_destAddress = dest;
	reply->m_headerChecksum = 0;

	//Done
	return reply;
}
*/

/**
	@brief Sends a packet to the driver

	The packet MUST have been allocated by GetTxPacket().
 */
/*
#ifdef HAVE_ITCM
__attribute__((section(".tcmtext")))
#endif
void IPv6Protocol::SendTxPacket(IPv6Packet* packet, size_t upperLayerLength, bool markFree)
{
	//Get the full frame given the packet
	//TODO: handle VLAN tagging?
	auto frame = reinterpret_cast<EthernetFrame*>(reinterpret_cast<uint8_t*>(packet) - ETHERNET_PAYLOAD_OFFSET);

	//Update length in both IP header and Ethernet frame metadata
	packet->m_totalLength = packet->HeaderLength() + upperLayerLength;
	frame->SetPayloadLength(packet->m_totalLength);

	//Final fixup of checksum and byte ordering before sending it out
	packet->ByteSwap();
	packet->m_headerChecksum = ~__builtin_bswap16(InternetChecksum(reinterpret_cast<uint8_t*>(packet), 20));
	m_eth.SendTxFrame(frame, markFree);
}
*/

/**
	@brief Re-sends a packet without touching the checksums or doing any byte swapping etc
 */
/*
void IPv6Protocol::ResendTxPacket(IPv6Packet* packet, bool markFree)
{
	//Get the full frame given the packet
	//TODO: handle VLAN tagging?
	auto frame = reinterpret_cast<EthernetFrame*>(reinterpret_cast<uint8_t*>(packet) - ETHERNET_PAYLOAD_OFFSET);

	//Send it
	m_eth.ResendTxFrame(frame, markFree);
}
*/
