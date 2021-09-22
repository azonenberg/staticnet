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
	@brief Declaration of SSHKexEcdhReplyPacket
 */
#ifndef SSHKexEcdhReplyPacket_h
#define SSHKexEcdhReplyPacket_h

/**
	@brief A SSH_MSG_KEX_ECDH_REPLY packet
 */
class __attribute__((packed)) SSHKexEcdhReplyPacket
{
public:

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Byte ordering correction

	void ByteSwap();

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Server host key

	///@brief Length of the host key blob (always 51)
	uint32_t m_hostKeyLength;

	///@brief Length of the host key type (always 11)
	uint32_t m_hostKeyTypeLength;

	///@brief Type of the host key (always "ssh-ed25519" with no null terminator)
	char m_hostKeyType[11];

	///@brief Length of the host public key (always 32)
	uint32_t m_hostKeyPublicLength;

	///@brief The actual host public key
	uint8_t m_hostKeyPublic[32];

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Ephemeral public key

	///@brief Length of the ephemeral public key (always 32)
	uint32_t m_ephemeralKeyPublicLength;

	///@brief The ephemeral public key blob
	uint8_t m_ephemeralKeyPublic[32];

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Signature

	///@brief Length of the signature blob (always 83)
	uint32_t m_signatureBlobLength;

	///@brief Length of the signature type string (always 11)
	uint32_t m_signatureTypeLength;

	///@brief The signature type string (always "ssh-ed25519" with no null terminator)
	char m_signatureType[11];

	///@brief Length of the actual signature (always 64)
	uint32_t m_signatureLength;

	///@brief The actual signature over the exchange hash
	uint8_t m_signature[64];
};

#endif
