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
	@brief Declaration of CryptoEngine
 */
#ifndef CryptoEngine_h
#define CryptoEngine_h

#include <contrib/tweetnacl_25519.h>

#define ECDH_KEY_SIZE		32
#define SHA256_DIGEST_SIZE	32

/**
	@brief Interface to an external crypto library or accelerator

	Each CryptoEngine object contains state used for one single encrypted/authenticated connection
	(client to server or server to client)
 */
class CryptoEngine
{
public:
	CryptoEngine();
	virtual ~CryptoEngine();

	///@brief Generate cryptographic randomness
	virtual void GenerateRandom(uint8_t* buf, size_t len) =0;

	virtual void Clear();

	/**
		@brief Generates an x25519 key pair.

		The private key is kept internal to the CryptoEngine object.

		The public key is stored in the provided buffer, which must be at least 32 bytes in size.
	 */
	void GenerateX25519KeyPair(uint8_t* pub)
	{
		//To be a valid key, a few bits need well-defined values. The rest are cryptographic randomness.
		GenerateRandom(m_ephemeralkeyPriv, 32);
		m_ephemeralkeyPriv[0] &= 0xF8;
		m_ephemeralkeyPriv[31] &= 0x7f;
		m_ephemeralkeyPriv[31] |= 0x40;

		crypto_scalarmult_base(pub, m_ephemeralkeyPriv);
	}

	///@brief Returns the host public key
	const uint8_t* GetHostPublicKey()
	{ return m_hostkeyPub; }

	///@brief Signs an exchange hash with our host key
	void SignExchangeHash(uint8_t* sigOut, uint8_t* exchangeHash)
	{
		//tweetnacl wants the public key here which is kinda derpy, we don't actually need it
		//TODO: optimize out this stupidiy
		uint8_t keyCombined[64];
		memcpy(keyCombined, m_hostkeyPriv, 32);
		memcpy(keyCombined + 32, m_hostkeyPub, 32);

		uint8_t sm[128];
		uint64_t smlen;
		crypto_sign(sm, &smlen, exchangeHash, SHA256_DIGEST_SIZE, keyCombined);
		memcpy(sigOut, sm, 64);
	}

	///@brief Calculates the shared secret between our ephemeral private key and the client's public key
	void SharedSecret(uint8_t* sharedSecret, uint8_t* clientPublicKey)
	{ crypto_scalarmult(sharedSecret, m_ephemeralkeyPriv, clientPublicKey); }

	///@brief Initialize the SHA-256 context
	virtual void SHA256_Init() =0;

	///@brief Hashes data
	virtual void SHA256_Update(uint8_t* data, uint16_t len) =0;

	///@brief Finishes a hash operation
	virtual void SHA256_Final(uint8_t* digest) =0;

protected:

	///@brief Ed25519 SSH host key (public)
	static uint8_t m_hostkeyPub[32];

	///@brief Ed25519 SSH host key (private)
	static uint8_t m_hostkeyPriv[32];

	///@brief Ephemeral x25519 private key
	uint8_t m_ephemeralkeyPriv[32];

};

#endif
