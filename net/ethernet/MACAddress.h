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
	@brief Declaration of MACAddress
 */

#ifndef MACAddress_h
#define MACAddress_h

///@brief Size of an Ethernet MAC address
#define ETHERNET_MAC_SIZE 6

/**
	@brief A 48-bit Ethernet MAC address

	Can be seamlessly casted to/from uint8[6].
 */
class MACAddress
{
public:

	/**
		@brief Constructs a MAC address from raw bytes

		This would be a constructor, except that would make this class non-POD which breaks other stuff
	 */
	static MACAddress FromBytes(const uint8_t* rhs)
	{
		MACAddress ret;
		memcpy(ret.m_address, rhs, ETHERNET_MAC_SIZE);
		return ret;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Comparison operators

	bool operator!= (const MACAddress& rhs) const
	{ return 0 != memcmp(m_address, rhs.m_address, ETHERNET_MAC_SIZE); }

	bool operator== (const MACAddress& rhs) const
	{ return 0 == memcmp(m_address, rhs.m_address, ETHERNET_MAC_SIZE); }

	bool operator!= (uint8_t* rhs) const
	{ return 0 != memcmp(m_address, rhs, ETHERNET_MAC_SIZE); }

	bool operator== (uint8_t* rhs) const
	{ return 0 == memcmp(m_address, rhs, ETHERNET_MAC_SIZE); }

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Helpers for checking special bits

	///@brief Returns true if this is a unicast address, false otherwise
	bool IsUnicast() const
	{ return (m_address[0] & 1) == 0; }

	///@brief Returns true if this is a multicast address, false otherwise
	bool IsMulticast() const
	{ return (m_address[0] & 1) == 1; }

	///@brief Returns true if this is a locally administered address, false otherwise
	bool IsLocallyAdministered() const
	{ return (m_address[0] & 2) == 2; }

	///@brief Returns true if this is a universally administered address, false otherwise
	bool IsUniversallyAdministered() const
	{ return (m_address[0] & 2) == 0; }

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Raw field access

	///@brief Bounds checked indexing operator
	uint8_t& operator[](uint8_t index)
	{
		if(index >= ETHERNET_MAC_SIZE)
			return m_address[ETHERNET_MAC_SIZE-1];
		return m_address[index];
	}

	///@brief Bounds checked indexing operator
	const uint8_t& operator[](uint8_t index) const
	{
		if(index >= ETHERNET_MAC_SIZE)
			return m_address[ETHERNET_MAC_SIZE-1];
		return m_address[index];
	}

public:
	uint8_t m_address[ETHERNET_MAC_SIZE];
};

#endif
