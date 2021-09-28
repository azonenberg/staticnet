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
#include "SSHTransportServer.h"
#include "SSHTransportPacket.h"
#include "SSHKexInitPacket.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Field accessors

/**
	@brief Gets the length of a name list, given a pointer to the start
 */
uint32_t SSHKexInitPacket::GetNameListLength(uint8_t* start)
{
	return __builtin_bswap32(*reinterpret_cast<uint32_t*>(start));
}

/**
	@brief Gets the data of a name list, given a pointer to the start

	Note: The name list is NOT null terminated!
 */
char* SSHKexInitPacket::GetNameListData(uint8_t* start)
{
	return reinterpret_cast<char*>(start + sizeof(uint32_t));
}

/**
	@brief Gets the start of the next name list, given a pointer to the start of this one
 */
uint8_t* SSHKexInitPacket::GetNextNameListStart(uint8_t* start)
{
	return start + sizeof(uint32_t) + GetNameListLength(start);
}

/**
	@brief Searches a name list for a requested substring
 */
bool SSHKexInitPacket::NameListContains(uint8_t* start, const char* search, uint16_t end)
{
	auto len = GetNameListLength(start);
	auto data = GetNameListData(start);

	//Check each substring in the name list for a match
	uint32_t targetlen = strlen(search);
	uint32_t pos = 0;
	while(pos < (len - targetlen))
	{
		//Bounds check
		if( ((data+pos) - reinterpret_cast<char*>(this)) > end)
			return false;

		//Check this string for a match (must be exact match, not just prefix)
		if( (memcmp(data+pos, search, targetlen) == 0) &&
			( (pos+targetlen == len) || (data[pos+targetlen] == ',') ) )
		{
			return true;
		}

		//Nope, not a match. Skip ahead to the next comma or end of string.
		while( (data[pos] != ',') && (pos < len) )
			pos ++;
		pos ++;
	}

	//If we get to the end without a match, stop
	return false;
}

/**
	@brief Writes a name list to the specified address
 */
void SSHKexInitPacket::SetNameList(uint8_t* start, const char* str)
{
	auto len = strlen(str);

	//Write the length
	*reinterpret_cast<uint32_t*>(start) = __builtin_bswap32(len);

	//Write the payload
	memcpy(start + sizeof(uint32_t), str, len);
}
