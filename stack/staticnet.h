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
	@brief Main header file for staticnet library.
 */

#ifndef staticnet_h
#define staticnet_h

//provided by your project, must be in the search path
#include <staticnet-config.h>

//Pull in STM32 headers if we're on one (TODO better detection)
#if !defined(SIMULATION) && !defined(SOFTCORE_NO_IRQ)
#include <stm32.h>
#include <peripheral/MDMA.h>
#endif

#include <stdint.h>
#include <memory.h>

#include "../drivers/base/EthernetInterface.h"
#include "../net/ethernet/EthernetProtocol.h"
#include "../net/arp/ARPProtocol.h"
#include "../net/ipv4/IPv4Protocol.h"
#include "../net/ipv6/IPv6Protocol.h"
#include "../net/icmpv4/ICMPv4Protocol.h"
#include "../net/icmpv6/ICMPv6Protocol.h"
#include "../net/tcp/TCPProtocol.h"
#include "../net/udp/UDPProtocol.h"

//Constants used for FNV hash
#define FNV_INITIAL	0x811c9dc5
#define FNV_MULT	0x01000193

#endif
