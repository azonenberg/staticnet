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
	@brief Declaration of IPv4Packet
 */

#ifndef IPv4Packet_h
#define IPv4Packet_h

#include "../ipv4/IPv4Address.h"

/**
	@brief An IPv4 packet sent over Ethernet
 */
class __attribute__((packed)) IPv4Packet
{
public:

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Byte ordering correction

	void ByteSwap()
	{
		m_totalLength = __builtin_bswap16(m_totalLength);
		//Don't waste time swapping frag ID because we don't support fragmentation
		//Checksum is patched up later on during the sending path
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Accessors for actual packet data

	uint16_t HeaderLength()
	{ return (m_versionAndHeaderLen & 0xf) * 4; }

	uint16_t PayloadLength()
	{ return m_totalLength - HeaderLength(); }

	uint8_t* Payload()
	{ return reinterpret_cast<uint8_t*>(this) + HeaderLength(); }

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Data members

	///@brief Always 0x45 (options not supported)
	uint8_t m_versionAndHeaderLen;

	///@brief differentiated services / explicit congestion (ignored)
	uint8_t m_dscpAndECN;

	///@brief Total packet length including headers and data
	uint16_t m_totalLength;

	///@brief Fragment ID (ignored, we don't support fragmentation)
	uint16_t m_fragID;

	///@brief Flags and fragment offset
	uint8_t m_flagsFragOffHigh;

	///@brief Low half of fragment offset (not used, we don't support fragmentation)
	uint8_t m_fragOffLow;

	///@brief Time to live (ignored by us, only used by routers)
	uint8_t m_ttl;

	///@brief Upper layer protocol ID
	uint8_t m_protocol;

	///@brief Checksum over the IP header
	uint16_t m_headerChecksum;

	///@brief Origin of the packet
	IPv4Address m_sourceAddress;

	///@brief Destination of the packet
	IPv4Address m_destAddress;

	//Options and upper layer protocol data past here
};

#endif
