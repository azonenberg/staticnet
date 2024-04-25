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
	@brief Declaration of NTPClient
 */
#include <staticnet/stack/staticnet.h>
#include "NTPClient.h"
#include "NTPPacket.h"

static const uint32_t noReplyTimeout = 10;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Construction / destruction

NTPClient::NTPClient(UDPProtocol* udp)
	: m_udp(udp)
	, m_enabled(false)
	, m_state(STATE_DESYNCED)
	, m_timeout(0)
{
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Timer handlers for state machine

void NTPClient::OnAgingTick()
{
	if(!m_enabled)
		return;

	//Link down? Nothing to do but reset the state machine
	auto eth = m_udp->GetIPv4()->GetEthernet();
	if(!eth->IsLinkUp())
	{
		m_state = STATE_DESYNCED;
		return;
	}

	switch(m_state)
	{
		case STATE_DESYNCED:
			SendQuery();
			break;

		case STATE_QUERY_SENT:

			//If no reply, try again in a few seconds
			if(m_timeout == 0)
				SendQuery();
			else
				m_timeout --;

			break;

		case STATE_SYNCED:

			//Send a query after our sync timeout expires
			if(m_timeout == 0)
				SendQuery();
			else
				m_timeout --;

			break;

		default:
			break;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Outbound packet generation

void NTPClient::SendQuery()
{
	//Allocate a packet for the query and give up if we can't make one
	auto upack = m_udp->GetTxPacket(m_serverAddress);
	if(!upack)
		return;

	//Fill out header fields
	auto npack = reinterpret_cast<NTPPacket*>(upack->Payload());
	npack->m_li_version_mode = 0xe3;	//unsynchronized NTPv4 client
	npack->m_stratum = 16;		//unsynchronized
	npack->m_poll = 10;			//polling interval 1024 sec
	npack->m_precision = -20;	//microsecond precision roughly

	//Set server-only fields to zero
	npack->m_rootDelay = 0;
	npack->m_rootDispersion = 0;
	npack->m_refid = 0x7f000001;	//uncalibrated local source

	//Timestamps are all invalid (zero) except the origin timestamp
	m_originTimestamp = GetLocalTimestamp();
	npack->m_refTimestamp = 0;
	npack->m_originTimestamp = m_originTimestamp;
	npack->m_rxTimestamp = 0;
	npack->m_txTimestamp = 0;

	//Byte swap and send
	npack->ByteSwap();
	m_udp->SendTxPacket(upack, NTP_PORT, NTP_PORT, sizeof(NTPPacket));

	//We sent a request
	m_timeout = noReplyTimeout;
	m_state = STATE_QUERY_SENT;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Inbound packet handling

void NTPClient::OnRxData(
	[[maybe_unused]] IPv4Address srcip,
	uint16_t sport,
	uint16_t dport,
	uint8_t* payload,
	uint16_t payloadLen)
{
	if(!m_enabled)
		return;

	//Skip anything with the wrong ports
	if(sport != NTP_PORT)
		return;
	if(dport != NTP_PORT)
		return;

	//Sanity check the payload is big enough, drop it if not
	if(payloadLen < sizeof(NTPPacket))
		return;

	//Extract the packet and convert to host endianness
	auto pack = reinterpret_cast<NTPPacket*>(payload);
	pack->ByteSwap();

	//Get round trip time as seen by client
	//(don't use the echoed origin timestamp as the server can return zero in this field if we're way off)
	uint64_t tnow = GetLocalTimestamp();
	uint64_t rttClientsideNativeUnits = tnow - m_originTimestamp;

	//Get RX-to-TX processing time as seen by server
	uint64_t rttServersideNativeUnits = pack->m_txTimestamp - pack->m_rxTimestamp;

	//Transit latency is half the difference between these deltas
	uint64_t totalTransitTimeNativeUnits = rttClientsideNativeUnits - rttServersideNativeUnits;
	uint64_t networkLatencyNativeUnits = totalTransitTimeNativeUnits / 2;

	//Given server side transmit time and latency, estimate the current time (server time plus transit delay)
	uint64_t estimatedActualTime = pack->m_txTimestamp + networkLatencyNativeUnits;

	//Crack the timestamp to seconds + fractional
	uint64_t ntpTimestampSec = estimatedActualTime >> 32;
	uint32_t ntpTimestampFrac = estimatedActualTime & 0xffffffff;

	//Native NTP timestamp will wrap in 2036 which is soon enough this code might still be in use!
	//But we're writing this code in 2024 and will never have to deal with timestamps in the past,
	//so we can easily disambiguate. Only one wrap is of interest, the next wrap will be in March 2172.
	//If anybody is still using this code in 2172, I'm sorry!
	//0xe9000000 = november 16th, 2023
	const uint64_t timeNotBefore = 0xe9000000;
	uint64_t ntpTimestampSecUnwrapped = ntpTimestampSec;
	if(ntpTimestampSecUnwrapped < timeNotBefore)
		ntpTimestampSecUnwrapped += (1ULL << 33);

	//Shift the NTP timestamp to be referenced to the Unix epoch
	const uint64_t unixEpochOffsetFromNtpEpoch = 0x83AA7E80;
	uint64_t ntpTimestampSecUnixEpoch = ntpTimestampSecUnwrapped - unixEpochOffsetFromNtpEpoch;

	//we're now synchronized, retry at the polling interval expiration
	m_state = STATE_SYNCED;
	m_timeout = 1 << pack->m_poll;

	//Pass the updated timestamp to the derived class to handle it
	OnTimeUpdated(static_cast<time_t>(ntpTimestampSecUnixEpoch), ntpTimestampFrac);
}
