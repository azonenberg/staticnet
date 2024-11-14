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
	@brief Declaration of IPv6Protocol
 */

#ifndef IPv6Protocol_h
#define IPv6Protocol_h

#include <stdint.h>
#include "IPv6Address.h"
#include "IPv6Packet.h"
#include "../IPProtocols.h"

/*
inline bool operator!= (const IPv6Address& a, const IPv6Address& b)
{ return a.m_word != b.m_word; }

inline bool operator== (const IPv6Address& a, const IPv6Address& b)
{ return a.m_word == b.m_word; }
*/

/**
	@brief IPv6 address configuration
 */
class IPv6Config
{
public:
	IPv6Address		m_address;
	IPv6Address		m_netmask;
	IPv6Address		m_broadcast;	//precomputed to save time
	IPv6Address		m_gateway;
};
/*
class ICMPv4Protocol;
class TCPProtocol;
class UDPProtocol;

#define IPV4_PAYLOAD_MTU (ETHERNET_PAYLOAD_MTU - 20)*/

/**
	@brief IPv6 protocol driver
 */
class IPv6Protocol
{
public:
	IPv6Protocol(EthernetProtocol& eth, IPv6Config& config);

	IPv6Protocol(const IPv6Protocol& rhs) =delete;

	/**
		@brief Enables reception of unicast IPv6 packets to addresses other than what we currently have configured
	 */
	void SetAllowUnknownUnicasts(bool allow)
	{ m_allowUnknownUnicasts = allow; }

	/*
	IPv6Packet* GetTxPacket(IPv6Address dest, ipproto_t proto);
	void SendTxPacket(IPv6Packet* packet, size_t upperLayerLength, bool markFree = true);
	void ResendTxPacket(IPv6Packet* packet, bool markFree = false);
	*/

	///@brief Cancels sending of a packet
	void CancelTxPacket(IPv6Packet* packet)
	{ m_eth.CancelTxFrame(reinterpret_cast<EthernetFrame*>(reinterpret_cast<uint8_t*>(packet) - ETHERNET_PAYLOAD_OFFSET)); }

	void OnRxPacket(IPv6Packet* packet, uint16_t ethernetPayloadLength);

	void OnLinkUp();
	void OnLinkDown();
	/*
	void OnAgingTick();
	void OnAgingTick10x();

	static uint16_t InternetChecksum(uint8_t* data, uint16_t len, uint16_t initial = 0);
	uint16_t PseudoHeaderChecksum(IPv6Packet* packet, uint16_t length);
	*/
	enum AddressType
	{
		ADDR_MULTICAST,		//packet was for a multicast address
		ADDR_UNICAST_US,	//packet was for our IP
		ADDR_UNICAST_OTHER	//packet was for someone else (only valid in promiscuous mode)
	};

	/*
	void UseICMPv4(ICMPv4Protocol* icmpv4)
	{ m_icmpv4 = icmpv4; }

	void UseTCP(TCPProtocol* tcp)
	{ m_tcp = tcp; }

	void UseUDP(UDPProtocol* udp)
	{ m_udp = udp; }
	*/

	AddressType GetAddressType(IPv6Address addr);
	/*
	bool IsLocalSubnet(IPv6Address addr);

	EthernetProtocol* GetEthernet()
	{ return &m_eth; }

	IPv6Address GetOurAddress()
	{ return m_config.m_address; }

protected:
	*/
	///@brief The Ethernet protocol stack
	EthernetProtocol& m_eth;

	///@brief Our local IP address configuration
	IPv6Config& m_config;
	/*
	///@brief ICMPv4 protocol
	ICMPv4Protocol* m_icmpv4;

	///@brief TCP protocol
	TCPProtocol* m_tcp;

	///@brief UDP protocol
	UDPProtocol* m_udp;
	*/

	///@brief True to forward unicasts to unknown addresses to us
	bool m_allowUnknownUnicasts;
};

#endif
