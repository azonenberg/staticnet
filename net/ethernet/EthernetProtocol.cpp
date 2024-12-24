/***********************************************************************************************************************
*                                                                                                                      *
* staticnet                                                                                                            *
*                                                                                                                      *
* Copyright (c) 2024 Andrew D. Zonenberg and contributors                                                              *
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
	@brief Initializes the Ethernet protocol stack
 */
EthernetProtocol::EthernetProtocol(EthernetInterface& iface, MACAddress our_mac)
	: m_iface(iface)
	, m_mac(our_mac)
	, m_arp(nullptr)
	, m_ipv4(nullptr)
	, m_ipv6(nullptr)
	, m_linkUp(false)
{

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Link state changes

void EthernetProtocol::OnLinkUp()
{
	m_linkUp = true;

	if(m_ipv4)
		m_ipv4->OnLinkUp();
	if(m_ipv6)
		m_ipv6->OnLinkUp();
}

void EthernetProtocol::OnLinkDown()
{
	m_linkUp = false;

	if(m_ipv6)
		m_ipv6->OnLinkDown();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Incoming frame processing

#ifdef HAVE_ITCM
__attribute__((section(".tcmtext")))
#endif
void EthernetProtocol::OnRxFrame(EthernetFrame* frame)
{
	//Discard anything that's not a broadcast or sent to us
	//TODO: promiscuous mode
	auto& dst = frame->DstMAC();
	if( (dst != m_mac) && !dst.IsMulticast())
	{
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
		//TODO: process LLC frames
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
				{
					if(m_ipv4->IsLocalSubnet(packet->m_sourceAddress))
						m_arp->Insert(frame->SrcMAC(), packet->m_sourceAddress);
				}

				//then process it
				m_ipv4->OnRxPacket(packet, plen);
			}
			break;

		//Process IPv6 frames if we have an attached IPv6 stack.
		//Don't bother checking length, upper layer can do that
		case ETHERTYPE_IPV6:
			if(m_ipv6)
				m_ipv6->OnRxPacket(reinterpret_cast<IPv6Packet*>(frame->Payload()), plen);
			break;

		//unrecognized ethertype, ignore
		default:
			break;
	}

	m_iface.ReleaseRxFrame(frame);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Outbound frame path

/**
	@brief Sets up a new frame
 */
#ifdef HAVE_ITCM
__attribute__((section(".tcmtext")))
#endif
EthernetFrame* EthernetProtocol::GetTxFrame(ethertype_t type, const MACAddress& dest)
{
	//Allocate a new frame from the transmit driver
	auto frame = m_iface.GetTxFrame();
	if(!frame)
		return nullptr;

	//Fill in header fields (no VLAN tag support for now)
	frame->DstMAC() = dest;
	frame->SrcMAC() = m_mac;
	frame->OuterEthertype() = type;

	//Done
	return frame;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Aging

/**
	@brief Timer handler for aging out stale sockets

	Call this function at approximately 1 Hz.
 */
void EthernetProtocol::OnAgingTick()
{
	if(m_arp)
	{
		m_arp->OnAgingTick();
		if(m_ipv4)
			m_ipv4->OnAgingTick();
	}
}

/**
	@brief Timer handler for TCP retransmits etc

	Call this function at approximately 10 Hz.
 */
void EthernetProtocol::OnAgingTick10x()
{
	if(m_ipv4)
		m_ipv4->OnAgingTick10x();
}
