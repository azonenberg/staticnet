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
	@brief Declaration of SSHChannelOpenConfirmationPacket
 */
#ifndef SSHChannelOpenConfirmationPacket_h
#define SSHChannelOpenConfirmationPacket_h

/**
	@brief A SSH_MSG_CHANNEL_OPEN_CONFIRMATION packet
 */
class __attribute__((packed)) SSHChannelOpenConfirmationPacket
{
public:

	void ByteSwap()
	{
		m_clientChannel = __builtin_bswap32(m_clientChannel);
		m_serverChannel = __builtin_bswap32(m_serverChannel);
		m_initialWindowSize = __builtin_bswap32(m_initialWindowSize);
		m_maxPacketSize = __builtin_bswap32(m_maxPacketSize);
	}


	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Field content

	///@brief Channel ID chosen by the client
	uint32_t m_clientChannel;

	///@brief Channel ID chosen by the server (always 0, we only support a single channel for now)
	uint32_t m_serverChannel;

	///@brief Initial window size
	uint32_t m_initialWindowSize;

	///@brief Maximum packet size
	uint32_t m_maxPacketSize;
};

#endif
