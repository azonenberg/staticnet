/***********************************************************************************************************************
*                                                                                                                      *
* staticnet v0.1                                                                                                       *
*                                                                                                                      *
* Copyright (c) 2021 Andrew D. Zonenberg and contributors                                                              *
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
#include <stack/staticnet.h>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Construction / destruction

/**
	@brief Initializes the Ethernet protocol stack
 */
EthernetProtocol::EthernetProtocol(EthernetInterface& iface, MACAddress our_mac)
	: m_iface(iface)
	, m_mac(our_mac)
	, m_arp(NULL)
	, m_ipv4(NULL)
{

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Incoming frame processing

void EthernetProtocol::OnRxFrame(EthernetFrame* frame)
{
	//Discard anything that's not a broadcast or sent to us
	//TODO: promiscuous mode
	auto& dst = frame->DstMAC();
	if( (dst != m_mac) && !dst.IsMulticast())
	{
		printf("    Ignoring dest MAC address %02x:%02x:%02x:%02x:%02x:%02x\n",
			dst[0], dst[1], dst[2], dst[3], dst[4], dst[5]);
		m_iface.ReleaseRxFrame(frame);
		return;
	}

	//Byte swap header fields
	frame->ByteSwap();

	//TODO: VLAN processing
	//For now, ignore VLAN tags

	//Send to appropriate upper layer stack
	auto& ethertype = frame->InnerEthertype();
	if(ethertype <= 1500)
	{
		printf("Got LLC frame, ignoring...\n");
	}
	uint16_t plen = frame->GetPayloadLength();
	switch(ethertype)
	{
		//Process ARP frames if we have an attached ARP stack and the frame is big enough to hold a full ARP packet
		case ETHERTYPE_ARP:
			if(m_arp && (plen >= sizeof(ARPPacket)) )
				m_arp->OnRxPacket(reinterpret_cast<ARPPacket*>(frame->Payload()));
			break;

		//Process IPv4 frames if we have an attached IPv4 stack.
		//Don't bother checking length, upper layer can do that
		case ETHERTYPE_IPV4:
			if(m_ipv4)
			{
				//Insert this (IP, MAC) into the ARP cache
				//TODO: wait until upper layer checksum is validated?
				auto packet = reinterpret_cast<IPv4Packet*>(frame->Payload());
				if(m_arp)
					m_arp->Insert(frame->SrcMAC(), packet->m_sourceAddress);

				//then process it
				m_ipv4->OnRxPacket(packet, plen);
			}
			break;

		//TODO: IPv6
		case ETHERTYPE_IPV6:
			break;

		default:
			printf("Got frame with unrecognized Ethertype 0x%04x, ignoring...\n", ethertype);
			break;
	}

	m_iface.ReleaseRxFrame(frame);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Outbound frame path

/**
	@brief Sets up a new frame
 */
EthernetFrame* EthernetProtocol::GetTxFrame(ethertype_t type, const MACAddress& dest)
{
	//Allocate a new frame from the transmit driver
	auto frame = m_iface.GetTxFrame();

	//Fill in header fields (no VLAN tag support for now)
	frame->DstMAC() = dest;
	frame->SrcMAC() = m_mac;
	frame->OuterEthertype() = type;

	//Done
	return frame;
}
