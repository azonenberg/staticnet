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
	@brief Declaration of SSHChannelRequestPacket
 */
#ifndef SSHChannelRequestPacket_h
#define SSHChannelRequestPacket_h

/**
	@brief A SSH_MSG_CHANNEL_REQUEST packet
 */
class __attribute__((packed)) SSHChannelRequestPacket
{
public:

	void ByteSwap()
	{
		m_clientChannel	= __builtin_bswap32(m_clientChannel);
		m_requestTypeLength		= __builtin_bswap32(m_requestTypeLength);
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Field accessors

	/**
		@brief Gets a pointer to the start of the request type (NOT null terminated)
	 */
	char* GetRequestTypeStart()
	{ return reinterpret_cast<char*>(&m_requestTypeLength) + sizeof(uint32_t); }

	bool WantReply()
	{
		//sanity check on type length
		if(m_requestTypeLength > 256)
			return false;

		return (GetRequestTypeStart()[m_requestTypeLength]) != 0;
	}

	uint8_t* Payload()
	{ return reinterpret_cast<uint8_t*>(GetRequestTypeStart() + m_requestTypeLength + 1); }

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Field content

	///@brief Channel ID (should match m_sessionChannelID in the state since we only support one channel)
	uint32_t m_clientChannel;

	///@brief Length of the request type
	uint32_t m_requestTypeLength;
};

#endif
