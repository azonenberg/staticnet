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

#include <stdio.h>

#include <staticnet-config.h>
#include <stack/staticnet.h>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Construction / destruction

ARPCache::ARPCache()
	: m_nextWayToEvict(0)
{
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Address hashing

/**
	@brief Hashes an IP address and returns a row index

	32-bit FNV-1 for now. Simple and good mixing, but uses a bunch of multiplies so might be slow?
 */
size_t ARPCache::Hash(IPv4Address ip)
{
	size_t hash = 0x811c9dc5;
	for(size_t i=0; i<4; i++)
		hash = (hash * 0x01000193) ^ ip.m_octets[i];

	return hash % ARP_CACHE_LINES;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Cache operations

/**
	@brief Checks if the ARP cache contains an entry for a given IP, and looks up the corresponding MAC if so
 */
bool ARPCache::Lookup(MACAddress& mac, IPv4Address ip)
{
	size_t hash = Hash(ip);

	for(size_t way=0; way < ARP_CACHE_WAYS; way++)
	{
		auto& row = m_ways[way].m_lines[hash];
		if(row.m_valid && row.m_ip == ip)
		{
			mac = row.m_mac;
			return true;
		}
	}

	return false;
}

/**
	@brief Inserts a new entry into the ARP cache.

	Calling this function if the entry is already present is a legal no-op.
 */
void ARPCache::Insert(MACAddress& mac, IPv4Address ip)
{
	size_t hash = Hash(ip);

	//Look for a free space or duplicate entry
	bool foundEmpty = false;
	size_t way = 0;
	for(; way < ARP_CACHE_WAYS; way ++)
	{
		auto& row = m_ways[way].m_lines[hash];

		//There's something in the row. We can't insert here.
		if(row.m_valid)
		{
			//Does the row already have an entry for this IP? Update the MAC if needed, then we're done
			if(row.m_ip == ip)
			{
				row.m_mac = mac;
				return;
			}

			//Nope, it's another IP. Ignore it.
		}

		//Unoccupied! Report this way as available for insertion
		else
		{
			foundEmpty = true;
			way = way;
		}
	}

	//If we get here, it's not already in the cache. Did we have space to insert?
	//If no space, pick an entry to overwrite
	if(!foundEmpty)
	{
		way = m_nextWayToEvict;

		//Pick another way to use next time
		//For now, sequential replacement policy
		m_nextWayToEvict = (m_nextWayToEvict + 1) % ARP_CACHE_WAYS;
	}

	//Insert the new entry
	auto& row = m_ways[way].m_lines[hash];
	row.m_valid = true;
	row.m_ip = ip;
	row.m_mac = mac;
}
