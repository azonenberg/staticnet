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

/**
	@brief Initializes the ARP protocol stack
 */
ARPProtocol::ARPProtocol(EthernetProtocol& eth, IPv4Address& ip, ARPCache& cache)
	: m_eth(eth)
	, m_ip(ip)
	, m_cache(cache)
{

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Handler for incoming packets

void ARPProtocol::SendQuery(IPv4Address& ip)
{
	//Prepare reply packet
	auto frame = m_eth.GetTxFrame(ETHERTYPE_ARP, MACAddress{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}});
	frame->SetPayloadLength(sizeof(ARPPacket));
	ARPPacket* query = reinterpret_cast<ARPPacket*>(frame->Payload());

	//Format query packet
	query->m_htype			= 1;
	query->m_ptype			= ETHERTYPE_IPV4;
	query->m_hardwareLen	= ETHERNET_MAC_SIZE;
	query->m_protoLen		= IPV4_ADDR_SIZE;
	query->m_oper			= ARP_REQUEST;

	query->m_senderHardwareAddress = m_eth.GetMACAddress();
	query->m_senderProtocolAddress = m_ip;
	query->m_targetHardwareAddress = MACAddress{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
	query->m_targetProtocolAddress = ip;

	//Swap endianness and send
	query->ByteSwap();
	m_eth.SendTxFrame(frame);
}

/**
	@brief Handle an incoming ARP packet
 */
void ARPProtocol::OnRxPacket(ARPPacket* packet)
{
	packet->ByteSwap();

	//Validate all of our common fields
	if(packet->m_htype != 1)
		return;
	if(packet->m_ptype != ETHERTYPE_IPV4)
		return;
	if(packet->m_hardwareLen != ETHERNET_MAC_SIZE)
		return;
	if(packet->m_protoLen != IPV4_ADDR_SIZE)
		return;

	switch(packet->m_oper)
	{
		case ARP_REQUEST:
			OnRequestPacket(packet);
			break;

		case ARP_REPLY:
			OnReplyPacket(packet);
			break;

		//malformed, ignore it
		default:
			break;
	}
}

/**
	@brief Handle an incoming ARP request
 */
void ARPProtocol::OnRequestPacket(ARPPacket* packet)
{
	//For a request, target hardware address is ignored because they don't know who we are
	//Target protocol address must match our IP or we're not interested
	if(packet->m_targetProtocolAddress != m_ip)
		return;

	//Add entry for sender to our ARP table if needed
	m_cache.Insert(packet->m_senderHardwareAddress, packet->m_senderProtocolAddress);

	//Prepare reply packet
	auto frame = m_eth.GetTxFrame(ETHERTYPE_ARP, packet->m_senderHardwareAddress);
	frame->SetPayloadLength(sizeof(ARPPacket));
	ARPPacket* reply = reinterpret_cast<ARPPacket*>(frame->Payload());

	//Format reply packet
	reply->m_htype			= 1;
	reply->m_ptype			= ETHERTYPE_IPV4;
	reply->m_hardwareLen	= ETHERNET_MAC_SIZE;
	reply->m_protoLen		= IPV4_ADDR_SIZE;
	reply->m_oper			= ARP_REPLY;

	reply->m_senderHardwareAddress = m_eth.GetMACAddress();
	reply->m_senderProtocolAddress = m_ip;
	reply->m_targetHardwareAddress = packet->m_senderHardwareAddress;
	reply->m_targetProtocolAddress = packet->m_senderProtocolAddress;

	//Swap endianness and send
	reply->ByteSwap();
	m_eth.SendTxFrame(frame);
}

/**
	@brief Handle an incoming ARP reply
 */
void ARPProtocol::OnReplyPacket(ARPPacket* packet)
{
	//No filtering needed, any ARP packet gets in our table

	//Add entry for sender to our ARP table
	m_cache.Insert(packet->m_senderHardwareAddress, packet->m_senderProtocolAddress);

	//No reply needed
}

