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

#ifndef NTPPacket_h
#define NTPPacket_h

#include <stdint.h>
#include "../net/ipv4/IPv4Address.h"

/**
	@brief A NTPv4 packet sent over UDP
 */
class __attribute__((packed)) NTPPacket
{
public:
	uint8_t	m_li_version_mode;
	uint8_t m_stratum;
	uint8_t m_poll;
	uint8_t m_precision;

	uint32_t m_rootDelay;
	uint32_t m_rootDispersion;
	uint32_t m_refid;

	uint64_t m_refTimestamp;
	uint64_t m_originTimestamp;
	uint64_t m_rxTimestamp;
	uint64_t m_txTimestamp;

	//extensions after here

	void ByteSwap()
	{
		m_rootDelay = __builtin_bswap32(m_rootDelay);
		m_rootDispersion = __builtin_bswap32(m_rootDispersion);
		m_refid = __builtin_bswap32(m_refid);

		m_refTimestamp = __builtin_bswap64(m_refTimestamp);
		m_originTimestamp = __builtin_bswap64(m_originTimestamp);
		m_rxTimestamp = __builtin_bswap64(m_rxTimestamp);
		m_txTimestamp = __builtin_bswap64(m_txTimestamp);
	}
};

#endif
