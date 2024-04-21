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
	@brief Declaration of DHCPClient
 */
#include <staticnet/stack/staticnet.h>
#include "DHCPClient.h"
#include "DHCPPacket.h"

/**
	@brief Appends an option to the given pointer (which must point to the current end of the options array
 */
void DHCPPacket::AddOption(uint8_t*& ptr, uint8_t code, uint8_t len, uint8_t* args)
{
	//align to next word boundary
	while(reinterpret_cast<uintptr_t>(ptr) & 3)
	{
		*ptr = 0x00;
		ptr ++;
	}

	//Add the option
	*ptr = code;
	ptr++;

	//if not end, add option length and value
	if(code != 0xff)
	{
		*ptr = len;
		ptr ++;

		if(len)
		{
			memcpy(ptr, args, len);
			ptr += len;
		}
	}
}

/**
	@brief Reads the next option (if any)
 */
bool DHCPPacket::ReadNextOption(uint8_t*& ptr, uint16_t totalLen, uint8_t& code, uint8_t& len, uint8_t*& args)
{
	//off end of packet? stop
	uint8_t* end = (reinterpret_cast<uint8_t*>(this) + totalLen);
	if(ptr >= end)
		return false;

	//option code
	code = *ptr;
	ptr++;

	//if option is zero padding, ignore other fields
	if(code == 0)
	{
		len = 0;
		args = nullptr;
		return true;
	}

	//if option is end, stop
	if(code == 0xff)
		return false;

	//anything else is full TLV format
	len = *ptr;
	ptr++;

	//validate length
	if(ptr+len >= end)
		return false;

	//read the argument data
	args = ptr;
	ptr += len;
	return true;
}

/**
	@brief Walk the options list to find a specific option we expect
 */
bool DHCPPacket::FindOption(uint16_t totalLen, uint8_t targetCode, uint8_t& len, uint8_t*& args)
{
	auto ptr = GetOptions();
	uint8_t code;
	while(ReadNextOption(ptr, totalLen, code, len, args))
	{
		if(code == targetCode)
			return true;
	}

	//if we get here, not found
	return false;
}
