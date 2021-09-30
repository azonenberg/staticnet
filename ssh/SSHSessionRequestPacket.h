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
	@brief Declaration of SSHSessionRequestPacket
 */
#ifndef SSHSessionRequestPacket_h
#define SSHSessionRequestPacket_h

/**
	@brief A SSH_MSG_CHANNEL_OPEN request of type "session"
 */
class __attribute__((packed)) SSHSessionRequestPacket
{
public:

	void ByteSwap()
	{
		m_strSessionLength	= __builtin_bswap32(m_strSessionLength);
		m_senderChannel		= __builtin_bswap32(m_senderChannel);
		m_initialWindowSize = __builtin_bswap32(m_initialWindowSize);
		m_maxPacketSize		= __builtin_bswap32(m_maxPacketSize);
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Field content

	//Constant value 0x7
	uint32_t m_strSessionLength;

	///@brief Constant string "session" (not null terminated)
	char m_strSession[7];

	///@brief Client-chosen channel ID
	uint32_t m_senderChannel;

	///@brief Starting window size
	uint32_t m_initialWindowSize;

	///@brief Max size of the packet
	uint32_t m_maxPacketSize;
};

#endif
