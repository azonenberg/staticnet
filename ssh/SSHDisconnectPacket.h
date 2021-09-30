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
	@brief Declaration of SSHDisconnectPacket
 */
#ifndef SSHDisconnectPacket_h
#define SSHDisconnectPacket_h

/**
	@brief A SSH_MSG_DISCONNECT packet
 */
class __attribute__((packed)) SSHDisconnectPacket
{
public:

	void ByteSwap()
	{
		m_reasonCode = __builtin_bswap32(m_reasonCode);
	}

	enum DisconnectReason
	{
		SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT            =  1,
		SSH_DISCONNECT_PROTOCOL_ERROR                         =  2,
		SSH_DISCONNECT_KEY_EXCHANGE_FAILED                    =  3,
		SSH_DISCONNECT_RESERVED                               =  4,
		SSH_DISCONNECT_MAC_ERROR                              =  5,
		SSH_DISCONNECT_COMPRESSION_ERROR                      =  6,
		SSH_DISCONNECT_SERVICE_NOT_AVAILABLE                  =  7,
		SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED         =  8,
		SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE                =  9,
		SSH_DISCONNECT_CONNECTION_LOST                        = 10,
		SSH_DISCONNECT_BY_APPLICATION                         = 11,
		SSH_DISCONNECT_TOO_MANY_CONNECTIONS                   = 12,
		SSH_DISCONNECT_AUTH_CANCELLED_BY_USER                 = 13,
		SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE         = 14,
		SSH_DISCONNECT_ILLEGAL_USER_NAME                      = 15
	};

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Field content

	///@brief Reason code
	uint32_t m_reasonCode;

	///@brief Length of the error message (always zero, we don't support text errors)
	uint32_t m_descriptionLengthAlwaysZero;

	///@brief Length of the language tag (always zero)
	uint32_t m_languageTagAlwaysZero;
};

#endif
