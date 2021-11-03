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
	@brief Declaration of ARPCache
 */

#ifndef ARPCache_h
#define ARPCache_h

#include "../ipv4/IPv4Address.h"
#include "../ethernet/MACAddress.h"

/**
	@brief A single entry in an ARP cache
 */
class ARPCacheEntry
{
public:
	ARPCacheEntry()
	: m_valid(false)
	{}

	bool m_valid;
	uint16_t m_lifetime;
	IPv4Address m_ip;
	MACAddress m_mac;
};

/**
	@brief A single bank of the ARP cache (direct mapped)
 */
class ARPCacheWay
{
public:
	ARPCacheEntry m_lines[ARP_CACHE_LINES];
};

/**
	@brief The ARP cache
 */
class ARPCache
{
public:
	ARPCache();

	bool Lookup(MACAddress& mac, IPv4Address ip);
	void Insert(MACAddress& mac, IPv4Address ip);

	void OnAgingTick();

	/**
		@brief Returns the number of ways in the cache
	 */
	uint32_t GetWays()
	{ return ARP_CACHE_WAYS; }

	/**
		@brief Returns the number of lines in each way of the cache
	 */
	uint32_t GetLines()
	{ return ARP_CACHE_LINES; }

	const ARPCacheWay* GetWay(uint32_t i)
	{ return &m_ways[i]; }

protected:

	///@brief The actual cache data
	ARPCacheWay m_ways[ARP_CACHE_WAYS];

	///@brief Cache way to evict next time there's contention for space
	size_t m_nextWayToEvict;

	///@brief Lifetime of cache entries, in seconds
	uint16_t m_cacheLifetime;

	size_t Hash(IPv4Address ip);
};

#endif
