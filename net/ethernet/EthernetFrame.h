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

/**
	@file
	@brief Declaration of EthernetFrame
 */

#ifndef EthernetFrame_h
#define EthernetFrame_h

#include "EthernetCommon.h"
#include "Dot1qTag.h"
#include "MACAddress.h"

/**
	@brief A single Ethernet frame, including helpers for reading and writing various fields
 */
class __attribute__((packed)) EthernetFrame
{
public:

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Construction / destruction

	EthernetFrame()
	{
		Reset();
	}

	/**
		@brief Resets this frame to a default state
	 */
	void Reset()
	{
		m_length = 0;

		#ifdef ZEROIZE_BUFFERS_BEFORE_USE
			memset(m_buffer, 0, ETHERNET_BUFFER_SIZE);
		#endif
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Byte ordering correction

	void ByteSwap();

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Header fields

	///@brief Gets the destination MAC address
	MACAddress& DstMAC()
	{ return *reinterpret_cast<MACAddress*>(&m_buffer[0]); }

	///@brief Gets the destination MAC address
	const MACAddress& DstMAC() const
	{ return *reinterpret_cast<const MACAddress*>(&m_buffer[0]); }

	///@brief Gets the source MAC address
	MACAddress& SrcMAC()
	{ return *reinterpret_cast<MACAddress*>(&m_buffer[ETHERNET_MAC_SIZE]); }

	///@brief Gets the source MAC address
	const MACAddress& SrcMAC() const
	{ return *reinterpret_cast<const MACAddress*>(&m_buffer[ETHERNET_MAC_SIZE]); }

	///@brief Gets the outer ethertype/length field (returns ETHERTYPE_DOT1Q if vlan tagged)
	uint16_t& OuterEthertype()
	{ return *reinterpret_cast<uint16_t*>(&m_buffer[ETHERNET_MAC_SIZE*2]); }

	///@brief Gets the outer ethertype/length field (returns ETHERTYPE_DOT1Q if vlan tagged)
	const uint16_t& OuterEthertype() const
	{ return *reinterpret_cast<const uint16_t*>(&m_buffer[ETHERNET_MAC_SIZE*2]); }

	///@brief Gets the inner ethertype/length field (same as OuterEthertype() if untagged)
	uint16_t& InnerEthertype()
	{
		if(IsVlanTagged())
			return *reinterpret_cast<uint16_t*>(&m_buffer[ETHERNET_MAC_SIZE*2 + ETHERNET_DOT1Q_SIZE]);
		else
			return *reinterpret_cast<uint16_t*>(&m_buffer[ETHERNET_MAC_SIZE*2]);
	}

	///@brief Gets the outer ethertype/length field (returns ETHERTYPE_DOT1Q if vlan tagged)
	const uint16_t& InnerEthertype() const
	{
		if(IsVlanTagged())
			return *reinterpret_cast<const uint16_t*>(&m_buffer[ETHERNET_MAC_SIZE*2 + ETHERNET_DOT1Q_SIZE]);
		else
			return *reinterpret_cast<const uint16_t*>(&m_buffer[ETHERNET_MAC_SIZE*2]);
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// VLAN tagging

	///@brief Determines if this frame has a VLAN tag
	bool IsVlanTagged() const
	{ return (OuterEthertype() == ETHERTYPE_DOT1Q); }

	///@brief Gets the VLAN tag (must only be called on ETHERTYPE_DOT1Q frames)
	const Dot1qTag& VlanTag() const
	{ return *reinterpret_cast<const Dot1qTag*>(&m_buffer[ETHERNET_MAC_SIZE*2 + ETHERNET_ETHERTYPE_SIZE]); }

	///@brief Gets the VLAN tag (must only be called on ETHERTYPE_DOT1Q frames)
	Dot1qTag& VlanTag()
	{ return *reinterpret_cast<Dot1qTag*>(&m_buffer[ETHERNET_MAC_SIZE*2 + ETHERNET_ETHERTYPE_SIZE]); }

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Upper layer protocol access

	uint16_t HeaderLength() const
	{
		if(IsVlanTagged())
			return ETHERNET_HEADER_SIZE + ETHERNET_DOT1Q_SIZE;
		else
			return ETHERNET_HEADER_SIZE;
	}

	///@brief Gets the frame data (inside the 802.1q tag, if one is present)
	uint8_t* Payload()
	{ return &m_buffer[HeaderLength()]; }

	///@brief Gets the frame data (inside the 802.1q tag, if one is present)
	const uint8_t* Payload() const
	{ return &m_buffer[HeaderLength()]; }

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Raw frame access

	///@brief Sets the length of the frame payload, updating the full packet length appropriately
	void SetPayloadLength(uint16_t len)
	{
		//Truncate to our MTU
		if(len > ETHERNET_PAYLOAD_MTU)
			len = ETHERNET_PAYLOAD_MTU;

		m_length = HeaderLength() + len;
	}

	///@brief Gets the length of the frame payload
	uint16_t GetPayloadLength() const
	{
		size_t hlen = HeaderLength();
		if(hlen >= m_length)
			return 0;
		return m_length - hlen;
	}

	///@brief Gets the length of the frame, including headers but not preamble or FCS
	uint16_t& Length()
	{ return *(&m_length); }

	///@brief Gets the length of the frame, including headers but not preamble or FCS
	const uint16_t& Length() const
	{ return *(&m_length); }

	///@brief Gets a pointer to the raw frame contents
	const uint8_t* RawData() const
	{ return &m_buffer[0]; }

	///@brief Gets a pointer to the raw frame contents
	uint8_t* RawData()
	{ return &m_buffer[0]; }

protected:

	///@brief Length of the frame, including headers but not preamble or FCS
	uint16_t	m_length;

	/**
		@brief Raw storage for the frame.

		This variable must be located immediately after m_length in order to ensure that it is allocated at an *odd*
		16-bit boundary: an address ending in 0x2, 0x6, 0xa, or 0xe. Aligning the frame this way ensures that the frame
		header (14 or 18 bytes depending on if VLAN tagged) ends on an 32-bit boundary.

		This ensures that upper layer protocol data is aligned on a 32-bit boundary, allowing faster reading/writing.
	 */
	uint8_t		m_buffer[ETHERNET_BUFFER_SIZE];
};

#endif
