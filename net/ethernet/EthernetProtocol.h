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
	@brief Definition of EthernetProtocol class
 */

#ifndef EthernetProtocol_h
#define EthernetProtocol_h

#include "EthernetCommon.h"
#include "../../drivers/base/EthernetInterface.h"

class ARPProtocol;
class IPv4Protocol;
class IPv6Protocol;

/**
	@brief Ethernet protocol handling

	One instance of this class must be declared for each physical Ethernet interface on the system.
 */
class EthernetProtocol
{
public:

	EthernetProtocol(EthernetInterface& iface, MACAddress our_mac);

	bool IsTxBufferAvailable()
	{ return m_iface.IsTxBufferAvailable(); }

	EthernetFrame* GetTxFrame(ethertype_t type, const MACAddress& dest);

	///@brief Sends a frame to the driver
	void SendTxFrame(EthernetFrame* frame, bool markFree = true)
	{
		frame->ByteSwap();
		m_iface.SendTxFrame(frame, markFree);
	}

	///@brief Sends a frame to the driver as-is (previously sent)
	void ResendTxFrame(EthernetFrame* frame, bool markFree = true)
	{ m_iface.SendTxFrame(frame, markFree); }

	///@brief Cancels sending of a frame
	void CancelTxFrame(EthernetFrame* frame)
	{ m_iface.CancelTxFrame(frame); }

	void OnRxFrame(EthernetFrame* frame);

	void UseARP(ARPProtocol* arp)
	{ m_arp = arp; }

	void UseIPv4(IPv4Protocol* ipv4)
	{ m_ipv4 = ipv4; }

	void UseIPv6(IPv6Protocol* ipv6)
	{ m_ipv6 = ipv6; }

	const MACAddress& GetMACAddress()
	{ return m_mac; }

	void OnAgingTick();
	void OnAgingTick10x();

	void OnLinkUp();
	void OnLinkDown();

	ARPProtocol* GetARP()
	{ return m_arp; }

	bool IsLinkUp()
	{ return m_linkUp; }

protected:

	///@brief Driver for the Ethernet MAC
	EthernetInterface& m_iface;

	///@brief Our MAC address
	MACAddress m_mac;

	///@brief The ARP protocol stack for this port (if present)
	ARPProtocol* m_arp;

	///@brief The IPv4 protocol stack for this port (if present)
	IPv4Protocol* m_ipv4;

	///@brief The IPv6 protocol stack for this port (if present)
	IPv6Protocol* m_ipv6;

	///@brief Link state
	bool m_linkUp;
};

#endif
