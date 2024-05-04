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
	@brief Declaration of SSHTransportPacket
 */
#ifndef SSHTransportPacket_h
#define SSHTransportPacket_h

class CryptoEngine;

/**
	@brief A single packet in the SSH transport layer
 */
class __attribute__((packed)) SSHTransportPacket
{
public:

	enum sshmsg_t
	{
		SSH_MSG_DISCONNECT					= 1,
		SSH_MSG_IGNORE						= 2,
		SSH_MSG_SERVICE_REQUEST				= 5,
		SSH_MSG_SERVICE_ACCEPT				= 6,

		SSH_MSG_KEXINIT						= 20,
		SSH_MSG_NEWKEYS						= 21,

		SSH_MSG_KEX_ECDH_INIT 				= 30,
		SSH_MSG_KEX_ECDH_REPLY				= 31,

		SSH_MSG_USERAUTH_REQUEST			= 50,
		SSH_MSG_USERAUTH_FAILURE			= 51,
		SSH_MSG_USERAUTH_SUCCESS			= 52,

		SSH_MSG_USERAUTH_PK_OK				= 60,

		SSH_MSG_CHANNEL_OPEN				= 90,
		SSH_MSG_CHANNEL_OPEN_CONFIRMATION	= 91,
		SSH_MSG_CHANNEL_OPEN_FAILURE		= 92,
		SSH_MSG_CHANNEL_DATA				= 94,
		SSH_MSG_CHANNEL_EOF					= 96,
		SSH_MSG_CHANNEL_CLOSE				= 97,
		SSH_MSG_CHANNEL_REQUEST				= 98,
		SSH_MSG_CHANNEL_SUCCESS				= 99,
		SSH_MSG_CHANNEL_FAILURE				= 100,
	};

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Padding / cleanup

	void UpdateLength(uint16_t payloadLength, CryptoEngine* crypto, bool padForEncryption = false);

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Field accessors

	uint8_t* Payload()
	{ return reinterpret_cast<uint8_t*>(this) + sizeof(SSHTransportPacket); }

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Byte ordering correction

	void ByteSwap();

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Data fields

	uint32_t m_packetLength;	//does not include the length field itself!
	uint8_t m_paddingLength;
	uint8_t m_type;

	//After packet:
	//uint8_t padding[]
	//uint8_t mac[32]
};

#endif
