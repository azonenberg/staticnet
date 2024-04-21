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
	@brief Declaration of DHCPClient
 */
#include <staticnet/stack/staticnet.h>
#include "DHCPClient.h"
#include "DHCPPacket.h"

static const int discoverTimeout = 5;
static const int renewTimeout = 5;
static const IPv4Address broadcast = { .m_octets{255, 255,   255,   255} };
static const IPv4Address nulladdr = { .m_octets{0, 0, 0, 0} };

#define DHCP_MAGIC 0x63825363

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Construction / destruction

DHCPClient::DHCPClient(UDPProtocol* udp)
	: m_udp(udp)
	, m_state(STATE_NO_LEASE)
	, m_activeTransactionID(0)
	, m_timeout(0)
	, m_leaseValidTime(0)
	, m_enabled(false)
{
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Timer handlers for state machine

void DHCPClient::OnAgingTick()
{
	if(!m_enabled)
	{
		m_state = STATE_NO_LEASE;
		return;
	}

	//Link down? Nothing to do but reset the state machine
	auto eth = m_udp->GetIPv4()->GetEthernet();
	if(!eth->IsLinkUp())
	{
		m_state = STATE_NO_LEASE;
		return;
	}

	//Count elapsed time since starting the transaction
	m_elapsedTime ++;

	switch(m_state)
	{
		//Link up and no active lease? Send a DHCPDISCOVER
		case STATE_NO_LEASE:
			{
				m_activeTransactionID = GenerateTransactionID();
				m_state = STATE_DISCOVER_SENT;
				m_timeout = discoverTimeout;
				m_elapsedTime = 0;

				SendDiscover();
			}
			break;

		//If still here after timeout expires, send another discover
		case STATE_DISCOVER_SENT:
			if(m_timeout == 0)
			{
				SendDiscover();
				m_timeout = discoverTimeout;
			}
			else
				m_timeout --;
			break;

		//If still here after timeout expires our DHCPREQUEST never made it.
		//Restart and go back to discover (since we didn't cache the DHCPREQUEST)
		case STATE_REQUEST_SENT:
			if(m_timeout == 0)
			{
				SendDiscover();
				m_state = STATE_DISCOVER_SENT;
				m_timeout = discoverTimeout;
			}
			else
				m_timeout --;
			break;

		//Lease is active, wait until we're 30 sec from expiry and then try to renew
		case STATE_LEASE_ACTIVE:
			if(m_leaseValidTime < 30)
			{
				m_activeTransactionID = GenerateTransactionID();
				m_elapsedTime = 0;
				Renew();
			}
			else
				m_leaseValidTime --;
			break;

		//Lease is being renewed, resend request if we get nowhere
		case STATE_LEASE_RENEW:
			if(m_timeout == 0)
			{
				Renew();
				m_timeout = renewTimeout;
			}
			else
				m_timeout --;
			break;

		default:
			break;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Outbound packet generation

/**
	@brief Send a DHCPREQUEST for our current IP address
 */
void DHCPClient::Renew()
{
	auto ipv4 = m_udp->GetIPv4();
	auto eth = ipv4->GetEthernet();

	//Allocate a packet for the reply and give up if we can't make one
	auto upack = m_udp->GetTxPacket(m_serverAddress);
	if(!upack)
		return;

	//Fill out header fields
	auto dpack = reinterpret_cast<DHCPPacket*>(upack->Payload());
	dpack->m_op = DHCPPacket::OP_DHCP_REQUEST;
	dpack->m_htype = DHCPPacket::HTYPE_ETHERNET;
	dpack->m_hlen = ETHERNET_MAC_SIZE;
	dpack->m_hops = 0;
	dpack->m_xid = m_activeTransactionID;
	dpack->m_secs = m_elapsedTime;
	dpack->m_flags = 0;

	//We're configured and know our current IP
	dpack->m_ciaddr = ipv4->GetOurAddress();
	dpack->m_yiaddr = nulladdr;
	dpack->m_siaddr = m_serverAddress;
	dpack->m_giaddr = nulladdr;

	//Other fields are basically the same as a discover
	memcpy(dpack->m_chaddr, &eth->GetMACAddress(), ETHERNET_MAC_SIZE);
	dpack->m_magicCookie = DHCP_MAGIC;

	//Add options
	auto options = dpack->GetOptions();

	//This is a DHCPREQUEST
	uint8_t type = DHCPREQUEST;
	DHCPPacket::AddOption(options, MessageType, sizeof(type), &type);

	//We want to reuse our current IP
	DHCPPacket::AddOption(options, AddressRequest, sizeof(IPv4Address), (uint8_t*)&dpack->m_ciaddr);

	//We're using the DHCP server it came from
	DHCPPacket::AddOption(options, ServerId, sizeof(IPv4Address), (uint8_t*)&m_serverAddress);

	//End of options list
	DHCPPacket::AddOption(options, EndOfOptions, 0, nullptr);

	//Byte swap and send
	dpack->ByteSwap();
	size_t ulen = options - upack->Payload();
	m_udp->SendTxPacket(upack, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, ulen);

	//We sent a request
	m_timeout = renewTimeout;
	m_state = STATE_LEASE_RENEW;
}

/**
	@brief Send a DHCPDISCOVER message
 */
void DHCPClient::SendDiscover()
{
	auto eth = m_udp->GetIPv4()->GetEthernet();

	//Allocate a packet for the reply and give up if we can't make one
	auto upack = m_udp->GetTxPacket(broadcast);
	if(!upack)
	{
		//immediately re-send next tick in hopes of getting a valid packet (link up?)
		m_timeout = 0;
		return;
	}

	auto dpack = reinterpret_cast<DHCPPacket*>(upack->Payload());
	dpack->m_op = DHCPPacket::OP_DHCP_DISCOVER;
	dpack->m_htype = DHCPPacket::HTYPE_ETHERNET;
	dpack->m_hlen = ETHERNET_MAC_SIZE;
	dpack->m_hops = 0;
	dpack->m_xid = m_activeTransactionID;
	dpack->m_secs = m_elapsedTime;
	dpack->m_flags = 0;
	dpack->m_ciaddr = nulladdr;
	dpack->m_yiaddr = nulladdr;
	dpack->m_siaddr = nulladdr;
	dpack->m_giaddr = nulladdr;
	memcpy(dpack->m_chaddr, &eth->GetMACAddress(), ETHERNET_MAC_SIZE);
	dpack->m_magicCookie = DHCP_MAGIC;

	//Add options
	auto options = dpack->GetOptions();

	//This is a DHCPDISCOVER
	uint8_t discover = DHCPDISCOVER;
	DHCPPacket::AddOption(options, MessageType, 1, &discover);

	//Parameters we want
	uint8_t params[] = { SubnetMask, Router, DomainNameServer };
	DHCPPacket::AddOption(options, ParameterRequestList, sizeof(params), params);

	//End of options list
	DHCPPacket::AddOption(options, EndOfOptions, 0, nullptr);

	//Byte swap and send
	dpack->ByteSwap();
	size_t ulen = options - upack->Payload();
	m_udp->SendTxPacket(upack, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, ulen);

	//Tell the IP stack we want all unicasts (since the DHCPOFFER will come to our new unicast address)
	m_udp->GetIPv4()->SetAllowUnknownUnicasts(true);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Inbound packet handling

void DHCPClient::OnRxData(IPv4Address srcip, uint16_t sport, uint16_t dport, uint8_t* payload, uint16_t payloadLen)
{
	if(!m_enabled)
		return;

	//Skip anything with the wrong ports
	if(sport != DHCP_SERVER_PORT)
		return;
	if(dport != DHCP_CLIENT_PORT)
		return;

	//Sanity check the payload is big enough, drop it if not
	if(payloadLen < sizeof(DHCPPacket))
		return;

	//Extract the packet and convert to host endianness
	auto pack = reinterpret_cast<DHCPPacket*>(payload);
	pack->ByteSwap();

	//Validate a bunch of header fields
	if(pack->m_htype != DHCPPacket::HTYPE_ETHERNET)
		return;
	if(pack->m_hlen != ETHERNET_MAC_SIZE)
		return;
	if(pack->m_op != DHCPPacket::OP_BOOT_REPLY)
		return;
	//ignore hops

	//ignore invalid transaction ID
	if(pack->m_xid != m_activeTransactionID)
		return;

	//ignore inbound secs/flags

	//DHCP type option is required, drop the packet if not found or invalid length/type
	uint8_t len;
	uint8_t* args;
	if(!pack->FindOption(payloadLen, MessageType, len, args))
		return;
	if(len != 1)
		return;

	//Process the packet depending on what type it is
	switch(args[0])
	{
		case DHCPOFFER:
			OnRxOffer(pack, srcip, payloadLen);
			return;

		case DHCPACK:
			OnRxACK(pack, srcip, payloadLen);
			return;

		//If we get a NAK, abort whatever we were doing
		case DHCPNAK:
			m_state = STATE_NO_LEASE;
			break;

		//ignore any invalid type
		default:
			break;
	}
}

/**
	@brief Handles a DHCPACK
 */
void DHCPClient::OnRxACK(DHCPPacket* pack, IPv4Address srcip, uint16_t payloadLen)
{
	//We should only get a DHCPACK if we sent a DHCPREQUEST and are awaiting a reply
	//At any other time, ignore it
	if( (m_state != STATE_REQUEST_SENT) && (m_state != STATE_LEASE_RENEW) )
		return;

	//Configure the IP stack based on the fields in the reply
	OnIPAddressChanged(pack->m_yiaddr);

	//Extract other options we care about, if present
	uint8_t len;
	uint8_t* args;
	if(pack->FindOption(payloadLen, Router, len, args))
		OnDefaultGatewayChanged(*reinterpret_cast<IPv4Address*>(args));
	if(pack->FindOption(payloadLen, SubnetMask, len, args))
		OnSubnetMaskChanged(*reinterpret_cast<IPv4Address*>(args));

	//We now have an active lease!
	m_state = STATE_LEASE_ACTIVE;

	//Did we get an option that said how long it was valid for? If not, default to renewing after 1 hour
	if(pack->FindOption(payloadLen, LeaseTime, len, args))
		m_leaseValidTime = __builtin_bswap32(*reinterpret_cast<uint32_t*>(args));
	else
		m_leaseValidTime = 3600;

	//Did we get an option with the server address? If so, use it. If not, default to IP the request came from
	if(pack->FindOption(payloadLen, ServerId, len, args))
		m_serverAddress = *reinterpret_cast<IPv4Address*>(args);
	else
		m_serverAddress = srcip;

	//TODO: save DNS server if we can get it
	//TODO: save NTP server if we can get it

	//Turn on unicast filtering now that we're configured
	m_udp->GetIPv4()->SetAllowUnknownUnicasts(false);
}

/**
	@brief Handles a DHCPOFFER
 */
void DHCPClient::OnRxOffer(DHCPPacket* pack, IPv4Address srcip, uint16_t payloadLen)
{
	auto eth = m_udp->GetIPv4()->GetEthernet();

	//We should only get a DHCPOFFER if we sent a DHCPDISCOVER and are awaiting a reply
	//At any other time, ignore it
	if(m_state != STATE_DISCOVER_SENT)
		return;

	//Make sure it has the optional fields we need (subnet mask and default gateway).
	uint8_t len;
	uint8_t* args;
	if(!pack->FindOption(payloadLen, Router, len, args))
		return;
	if(!pack->FindOption(payloadLen, SubnetMask, len, args))
		return;

	//Allocate a packet for the reply and give up if we can't make one
	auto upack = m_udp->GetTxPacket(broadcast);
	if(!upack)
		return;

	//Fill out header fields
	auto dpack = reinterpret_cast<DHCPPacket*>(upack->Payload());
	dpack->m_op = DHCPPacket::OP_DHCP_REQUEST;
	dpack->m_htype = DHCPPacket::HTYPE_ETHERNET;
	dpack->m_hlen = ETHERNET_MAC_SIZE;
	dpack->m_hops = 0;
	dpack->m_xid = m_activeTransactionID;
	dpack->m_secs = m_elapsedTime;
	dpack->m_flags = 0;

	//We haven't yet configured our IP, but we now know the server's IP
	dpack->m_ciaddr = nulladdr;
	dpack->m_yiaddr = nulladdr;
	dpack->m_siaddr = srcip;
	dpack->m_giaddr = nulladdr;

	//Other fields are basically the same as a discover
	memcpy(dpack->m_chaddr, &eth->GetMACAddress(), ETHERNET_MAC_SIZE);
	dpack->m_magicCookie = DHCP_MAGIC;

	//Add options
	auto options = dpack->GetOptions();

	//This is a DHCPREQUEST
	uint8_t type = DHCPREQUEST;
	DHCPPacket::AddOption(options, MessageType, sizeof(type), &type);

	//We want the IP address they offered to us
	DHCPPacket::AddOption(options, AddressRequest, sizeof(IPv4Address), (uint8_t*)&pack->m_yiaddr);

	//We're using the DHCP server it came from
	DHCPPacket::AddOption(options, ServerId, sizeof(IPv4Address), (uint8_t*)&srcip);

	//End of options list
	DHCPPacket::AddOption(options, EndOfOptions, 0, nullptr);

	//Ignore any other options for now

	//Byte swap and send
	dpack->ByteSwap();
	size_t ulen = options - upack->Payload();
	m_udp->SendTxPacket(upack, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, ulen);

	//We sent a request
	m_state = STATE_REQUEST_SENT;
	m_timeout = discoverTimeout;
}
