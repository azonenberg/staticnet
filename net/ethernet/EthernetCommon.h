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
	@brief Sizes and other definitions used by Ethernet protocol logic
 */

#ifndef EthernetCommon_h
#define EthernetCommon_h

///@brief Size of an Ethernet Ethertype
#define ETHERNET_ETHERTYPE_SIZE 2

///@brief Size of an Ethernet VLAN tag
#define ETHERNET_DOT1Q_SIZE 4

///@brief Minimum length of an Ethernet frame payload
#define ETHERNET_PAYLOAD_MIN 46

///@brief Size of Ethernet frame header with no VLAN tag
#define ETHERNET_HEADER_SIZE (2*ETHERNET_MAC_SIZE + ETHERNET_ETHERTYPE_SIZE)

///@brief Minimum length of an Ethernet frame including headers and payload
#define ETHERNET_FRAME_MIN (ETHERNET_HEADER_SIZE + ETHERNET_PAYLOAD_MIN)

///@brief Buffer size sufficient to hold an Ethernet frame including headers (but not preamble or FCS)
#define ETHERNET_BUFFER_SIZE (ETHERNET_HEADER_SIZE + ETHERNET_DOT1Q_SIZE + ETHERNET_PAYLOAD_MTU)



///@brief Outer ethertype for a frame with VLAN tag
#define ETHERTYPE_DOT1Q 0x8100

#endif
