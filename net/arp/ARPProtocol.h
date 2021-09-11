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
	@brief Declaration of ARPProtocol
 */

#ifndef ARPProtocol_h
#define ARPProtocol_h

#include "../ethernet/EthernetProtocol.h"
#include "ARPPacket.h"
#include "ARPCache.h"

/**
	@brief ARP protocol logic for a single physical interface
 */
class ARPProtocol
{
public:
	ARPProtocol(EthernetProtocol& eth, IPv4Address& ip, ARPCache& cache);

	void OnRxPacket(ARPPacket* packet);

	enum
	{
		ARP_REQUEST = 1,
		ARP_REPLY = 2
	};

	void Insert(MACAddress& mac, IPv4Address ip)
	{ m_cache.Insert(mac, ip); }

protected:

	void OnRequestPacket(ARPPacket* packet);
	void OnReplyPacket(ARPPacket* packet);

	///The Ethernet protocol stack
	EthernetProtocol& m_eth;

	///Our local IP address
	IPv4Address& m_ip;

	///Cache for storing IP -> MAC associations
	ARPCache& m_cache;
};

#endif
