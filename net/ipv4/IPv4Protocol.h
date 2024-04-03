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
	@brief Declaration of IPv4Protocol
 */

#ifndef IPv4Protocol_h
#define IPv4Protocol_h

#include "IPv4Address.h"
#include "IPv4Packet.h"

inline bool operator!= (const IPv4Address& a, const IPv4Address& b)
{ return a.m_word != b.m_word; }

inline bool operator== (const IPv4Address& a, const IPv4Address& b)
{ return a.m_word == b.m_word; }

/**
	@brief IPv4 address configuration
 */
class IPv4Config
{
public:
	IPv4Address		m_address;
	IPv4Address		m_netmask;
	IPv4Address		m_broadcast;	//precomputed to save time
	IPv4Address		m_gateway;
};

class ICMPv4Protocol;
class TCPProtocol;

#define IPV4_PAYLOAD_MTU (ETHERNET_PAYLOAD_MTU - 20)

/**
	@brief IPv4 protocol driver
 */
class IPv4Protocol
{
public:
	IPv4Protocol(EthernetProtocol& eth, IPv4Config& config, ARPCache& cache);

	enum ipproto_t
	{
		IP_PROTO_ICMP	= 1,
		IP_PROTO_TCP	= 6,
		IP_PROTO_UDP	= 17
	};

	IPv4Packet* GetTxPacket(IPv4Address dest, ipproto_t proto);
	void SendTxPacket(IPv4Packet* packet, size_t upperLayerLength, bool markFree = true);
	void ResendTxPacket(IPv4Packet* packet, bool markFree = false);

	///@brief Cancels sending of a packet
	void CancelTxPacket(IPv4Packet* packet)
	{ m_eth.CancelTxFrame(reinterpret_cast<EthernetFrame*>(reinterpret_cast<uint8_t*>(packet) - ETHERNET_PAYLOAD_OFFSET)); }

	void OnRxPacket(IPv4Packet* packet, uint16_t ethernetPayloadLength);

	void OnLinkUp();
	void OnLinkDown();
	void OnAgingTick();
	void OnAgingTick10x();

	static uint16_t InternetChecksum(uint8_t* data, uint16_t len, uint16_t initial = 0);
	uint16_t PseudoHeaderChecksum(IPv4Packet* packet, uint16_t length);

	enum AddressType
	{
		ADDR_BROADCAST,		//packet was for a broadcast address
		ADDR_MULTICAST,		//packet was for a multicast address
		ADDR_UNICAST_US,	//packet was for our IP
		ADDR_UNICAST_OTHER	//packet was for someone else (only valid in promiscuous mode)
	};

	void UseICMPv4(ICMPv4Protocol* icmpv4)
	{ m_icmpv4 = icmpv4; }

	void UseTCP(TCPProtocol* tcp)
	{ m_tcp = tcp; }

	AddressType GetAddressType(IPv4Address addr);
	bool IsLocalSubnet(IPv4Address addr);

protected:

	///@brief The Ethernet protocol stack
	EthernetProtocol& m_eth;

	///@brief Our local IP address configuration
	IPv4Config& m_config;

	///@brief Cache for storing IP -> MAC associations
	ARPCache& m_cache;

	///@brief ICMPv4 protocol
	ICMPv4Protocol* m_icmpv4;

	///@brief TCP protocol
	TCPProtocol* m_tcp;
};

#endif
