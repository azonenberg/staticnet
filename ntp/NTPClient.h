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
#ifndef NTPClient_h
#define NTPClient_h

#define NTP_PORT 123

#include "NTPPacket.h"
#include "../net/udp/UDPProtocol.h"
#include <time.h>

/**
	@brief Stripped-down, largely stateless NTP client that makes single queries at a predefined interval

	For now, only implements SNTP
 */
class NTPClient
{
public:
	NTPClient(UDPProtocol* udp);

	void OnAgingTick();
	void OnRxData(IPv4Address srcip, uint16_t sport, uint16_t dport, uint8_t* payload, uint16_t payloadLen);

	void Enable()
	{ m_enabled = true; }

	void Disable()
	{ m_enabled = false; }

	bool IsEnabled() const
	{ return m_enabled; }

	IPv4Address GetServerAddress()
	{ return m_serverAddress; }

	/**
		@brief Sets the address of the time server to use
	 */
	void SetServerAddress(IPv4Address addr)
	{
		m_serverAddress = addr;
		if(m_enabled)
			m_state = STATE_DESYNCED;
	}

protected:

	/**
		@brief Gets our local timestamp (in 32.32 NTP format)
	 */
	virtual uint64_t GetLocalTimestamp() =0;

	/**
		@brief Called when a new timestamp is received (in 64 + 32 fractional time_t format)
	 */
	virtual void OnTimeUpdated([[maybe_unused]] time_t sec, [[maybe_unused]] uint32_t frac)
	{}

	void SendQuery();

	///@brief The UDP protocol instance to use
	UDPProtocol* m_udp;

	///@brief Address of the time server to use
	IPv4Address m_serverAddress;

	///@brief True if the client is enabled, false to do nothing
	bool m_enabled;

	enum
	{
		STATE_DESYNCED,
		STATE_QUERY_SENT,
		STATE_SYNCED
	} m_state;

	//Timeout until next synchronization
	uint32_t m_timeout;

	///@brief Timestamp that we sent the last query at
	uint64_t m_originTimestamp;
};

#endif

