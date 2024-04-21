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

#ifndef DHCPPacket_h
#define DHCPPacket_h

#include <stdint.h>
#include "../net/ipv4/IPv4Address.h"

/**
	@brief A DHCPv4 packet sent over UDP
 */
class __attribute__((packed)) DHCPPacket
{
public:
	uint8_t	m_op;
	uint8_t	m_htype;
	uint8_t	m_hlen;
	uint8_t	m_hops;

	uint32_t m_xid;

	uint16_t m_secs;
	uint16_t m_flags;

	IPv4Address m_ciaddr;
	IPv4Address m_yiaddr;
	IPv4Address m_siaddr;
	IPv4Address m_giaddr;

	uint8_t m_chaddr[16];
	uint8_t m_sname[64];
	uint8_t m_file[128];

	uint32_t m_magicCookie;

	void ByteSwap()
	{
		m_xid	= __builtin_bswap32(m_xid);
		m_secs	= __builtin_bswap16(m_secs);
		m_flags	= __builtin_bswap16(m_flags);
		m_magicCookie = __builtin_bswap32(m_magicCookie);
	}

	uint8_t* GetOptions()
	{ return reinterpret_cast<uint8_t*>(this) + sizeof(*this); }

	static void AddOption(uint8_t*& ptr, uint8_t code, uint8_t len, uint8_t* args);
	bool ReadNextOption(uint8_t*& ptr, uint16_t totalLen, uint8_t& code, uint8_t& len, uint8_t*& args);
	bool FindOption(uint16_t totalLen, uint8_t targetCode, uint8_t& len, uint8_t*& args);

	//options after here

	//type defines, no variables
public:
	enum op_t
	{
		OP_DHCP_DISCOVER 	= 0x01,
		OP_BOOT_REPLY		= 0x02,
		OP_DHCP_REQUEST		= 0x03,
		OP_DHCP_ACK			= 0x05
	};

	enum htype_t
	{
		HTYPE_ETHERNET = 0x01
	};
};

#endif
