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
	@brief Configuration file for staticnet test platform
 */

#ifndef staticnet_config_h
#define staticnet_config_h

///@brief Maximum size of an Ethernet frame (payload only, headers not included)
#define ETHERNET_PAYLOAD_MTU 1500

///@brief Define this to zeroize all frame buffers between uses
#define ZEROIZE_BUFFERS_BEFORE_USE

///@brief Define this to enable performance counters
#define STATICNET_PERFORMANCE_COUNTERS

///@brief Number of ways of associativity for the ARP cache
#define ARP_CACHE_WAYS 4

///@brief Number of lines per set in the ARP cache
#define ARP_CACHE_LINES 256

///@brief Number of entries in the TCP socket table
#define TCP_TABLE_WAYS 2

///@brief Number of lines per set in the TCP socket table
#define TCP_TABLE_LINES 16

///@brief Maximum number of SSH connections supported
#define SSH_TABLE_SIZE 2

///@brief SSH socket RX buffer size
#define SSH_RX_BUFFER_SIZE 2048

#endif
