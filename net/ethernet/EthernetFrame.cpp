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
	@brief Implementation of EthernetFrame non-inline functions
 */
#include <stdio.h>

#include <staticnet-config.h>
#include <stack/staticnet.h>

/**
	@brief Swap bytes in multi-byte fields from network to host byte ordering

	Assumes host is little endian.
 */
void EthernetFrame::ByteSwap()
{
	//Swap the outer ethertype
	uint8_t outer_hi = m_buffer[ETHERNET_MAC_SIZE*2];
	uint8_t outer_lo = m_buffer[ETHERNET_MAC_SIZE*2 + 1];
	m_buffer[ETHERNET_MAC_SIZE*2] = outer_lo;
	m_buffer[ETHERNET_MAC_SIZE*2 + 1] = outer_hi;

	//VLAN tagged
	if( (outer_lo == (ETHERTYPE_DOT1Q >> 8)) && (outer_hi == (ETHERTYPE_DOT1Q & 0xff) ) )
	{
		//Swap the 802.1q tag
		uint8_t tag_hi = m_buffer[ETHERNET_MAC_SIZE*2 + 2];
		uint8_t tag_lo = m_buffer[ETHERNET_MAC_SIZE*2 + 3];
		m_buffer[ETHERNET_MAC_SIZE*2 + 2] = tag_lo;
		m_buffer[ETHERNET_MAC_SIZE*2 + 3] = tag_hi;

		//Swap the inner ethertype
		uint8_t inner_hi = m_buffer[ETHERNET_MAC_SIZE*2 + 4];
		uint8_t inner_lo = m_buffer[ETHERNET_MAC_SIZE*2 + 5];
		m_buffer[ETHERNET_MAC_SIZE*2 + 4] = inner_lo;
		m_buffer[ETHERNET_MAC_SIZE*2 + 5] = inner_hi;
	}
}
