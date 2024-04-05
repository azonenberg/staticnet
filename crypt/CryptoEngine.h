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
	@brief Declaration of CryptoEngine
 */
#ifndef CryptoEngine_h
#define CryptoEngine_h

#include <staticnet/contrib/tweetnacl_25519.h>

#define ECDH_KEY_SIZE		32
#define ECDSA_KEY_SIZE		32
#define SHA256_DIGEST_SIZE	32
#define SHA512_DIGEST_SIZE	64
#define AES_BLOCK_SIZE		16
#define AES_KEY_SIZE		16
#define GCM_IV_SIZE			12
#define GCM_TAG_SIZE		16
#define ECDSA_SIG_SIZE		64

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

	static void SetHostKey(const uint8_t* pub, const uint8_t* priv)
	{
		memcpy(m_hostkeyPriv, priv, ECDSA_KEY_SIZE);
		memcpy(m_hostkeyPub, pub, ECDSA_KEY_SIZE);
	}

	void GenerateHostKey();

	virtual void Clear();

	/**
		@brief Generates an x25519 key pair.

		The private key is kept internal to the CryptoEngine object.

		The public key is stored in the provided buffer, which must be at least 32 bytes in size.
	 */
	virtual void GenerateX25519KeyPair(uint8_t* pub);

	///@brief Returns the host public key
	static const uint8_t* GetHostPublicKey()
	{ return m_hostkeyPub; }

	///@brief Returns the host private key (normally only used for initial key generation to persist it to flash)
	static const uint8_t* GetHostPrivateKey()
	{ return m_hostkeyPriv; }

	///@brief Signs an exchange hash with our host key
	virtual void SignExchangeHash(uint8_t* sigOut, uint8_t* exchangeHash);

	virtual bool VerifySignature(uint8_t* signedMessage, uint32_t lengthIncludingSignature, uint8_t* publicKey);

	///@brief Calculates the shared secret between our ephemeral private key and the client's public key
	virtual void SharedSecret(uint8_t* sharedSecret, uint8_t* clientPublicKey);

	///@brief Initialize the SHA-256 context
	virtual void SHA256_Init() =0;

	///@brief Hashes data
	virtual void SHA256_Update(const uint8_t* data, uint16_t len) =0;

	///@brief Finishes a hash operation
	virtual void SHA256_Final(uint8_t* digest) =0;

	void DeriveSessionKeys(uint8_t* sharedSecret, uint8_t* exchangeHash, uint8_t* sessionID);
	void DeriveSessionKey(uint8_t* sharedSecret, uint8_t* exchangeHash, uint8_t* sessionID, char keyid, uint8_t* out);

	/**
		@brief Decrypts an encrypted packet in place, and returns true if the MAC is correct.

		If this function returns false the packet should be considered corrupted and discarded immediately.
	 */
	virtual bool DecryptAndVerify(uint8_t* data, uint16_t len) =0;

	/**
		@brief Encrypts a packet in place, and appends the MAC to it

		The supplied buffer must be large enough to hold the packet plus the MAC.
	 */
	virtual void EncryptAndMAC(uint8_t* data, uint16_t len) =0;

	/**
		@brief Gets the host key fingerprint (base64 encoded SHA256).

		This function uses the SHA256 engine and will overwrite any in progress SHA256 hash.
	 */
	void GetHostKeyFingerprint(char* buf, size_t len)
	{ GetKeyFingerprint(buf, len, m_hostkeyPub); }

	void GetKeyFingerprint(char* buf, size_t len, uint8_t* pubkey);

protected:

	///@brief Ed25519 SSH host key (public)
	static uint8_t m_hostkeyPub[ECDSA_KEY_SIZE];

	///@brief Ed25519 SSH host key (private)
	static uint8_t m_hostkeyPriv[ECDSA_KEY_SIZE];

	///@brief Ephemeral x25519 private key
	uint8_t m_ephemeralkeyPriv[ECDH_KEY_SIZE];

	///@brief IV client to server
	uint8_t m_ivClientToServer[GCM_IV_SIZE];

	///@brief IV server to client
	uint8_t m_ivServerToClient[GCM_IV_SIZE];

	///@brief Encryption key client to server
	uint8_t m_keyClientToServer[AES_KEY_SIZE];

	///@brief Encryption key server to client
	uint8_t m_keyServerToClient[AES_KEY_SIZE];
};

#endif
