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
	@brief Declaration of SSHKexInitPacket
 */
#ifndef SSHKexInitPacket_h
#define SSHKexInitPacket_h

/**
	@brief A SSH_MSG_KEXINIT packet
 */
class __attribute__((packed)) SSHKexInitPacket
{
public:

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Field accessors

	/**
		@brief Gets a pointer to the start of a name list
	 */
	uint8_t* GetFirstNameListStart()
	{ return &m_cookie[0] + sizeof(m_cookie); }

	uint32_t GetNameListLength(uint8_t* start);
	char* GetNameListData(uint8_t* start);
	uint8_t* GetNextNameListStart(uint8_t* start, uint8_t* end);

	bool NameListContains(uint8_t* start, const char* search, uint16_t end);
	void SetNameList(uint8_t* start, const char* str);

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Data fields

	//Random nonce
	uint8_t m_cookie[16];
};

#endif
