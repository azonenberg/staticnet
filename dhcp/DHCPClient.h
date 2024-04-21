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
#ifndef DHCPClient_h
#define DHCPClient_h

#define DHCP_CLIENT_PORT	68
#define DHCP_SERVER_PORT 	67

#include "DHCPPacket.h"
#include "../net/udp/UDPProtocol.h"

class DHCPClient
{
public:
	DHCPClient(UDPProtocol* udp);

	void OnAgingTick();
	void OnRxData(IPv4Address srcip, uint16_t sport, uint16_t dport, uint8_t* payload, uint16_t payloadLen);

	void Enable()
	{ m_enabled = true; }

	void Disable()
	{ m_enabled = false; }

	bool IsEnabled() const
	{ return m_enabled; }

protected:
	void SendDiscover();
	void OnRxOffer(DHCPPacket* pack, IPv4Address srcip, uint16_t payloadLen);
	void OnRxACK(DHCPPacket* pack, IPv4Address srcip, uint16_t payloadLen);
	void Renew();

	UDPProtocol* m_udp;

	///@brief Called with our new IP address when we get it
	virtual void OnIPAddressChanged([[maybe_unused]] IPv4Address addr)
	{}

	///@brief Called with our new default gateway when we get it
	virtual void OnDefaultGatewayChanged([[maybe_unused]] IPv4Address addr)
	{}

	///@brief Called with our new subnet mask when we get it
	virtual void OnSubnetMaskChanged([[maybe_unused]] IPv4Address addr)
	{}

	/**
		@brief Generates a DHCP transaction ID (random 32-bit integer)
	 */
	virtual uint32_t GenerateTransactionID() =0;

	enum option_type
	{
		SubnetMask				= 1,
		Router					= 3,
		DomainNameServer		= 6,
		AddressRequest			= 50,
		LeaseTime				= 51,
		MessageType				= 53,
		ServerId				= 54,
		ParameterRequestList	= 55,
		EndOfOptions			= 255
	};

	enum dhcp_type
	{
		DHCPDISCOVER	= 0x01,
		DHCPOFFER		= 0x02,
		DHCPREQUEST		= 0x03,
		DHCPACK			= 0x05,
		DHCPNAK			= 0x06
	};

	enum state_t
	{
		STATE_NO_LEASE,
		STATE_DISCOVER_SENT,
		STATE_REQUEST_SENT,
		STATE_LEASE_ACTIVE,
		STATE_LEASE_RENEW
	} m_state;

	uint32_t m_activeTransactionID;
	uint32_t m_timeout;
	uint32_t m_elapsedTime;
	uint32_t m_leaseValidTime = 0;

	IPv4Address m_serverAddress;

	bool m_enabled;
};

#endif
