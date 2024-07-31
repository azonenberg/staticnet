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

#include <staticnet-config.h>
#include "../stack/staticnet.h"
#include "../contrib/base64.h"
#include "CryptoEngine.h"

uint8_t CryptoEngine::m_hostkeyPriv[32];
uint8_t CryptoEngine::m_hostkeyPub[32];

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Construction / destruction

CryptoEngine::CryptoEngine()
{
	memset(m_ephemeralkeyPriv, 0, sizeof(m_ephemeralkeyPriv));

	//Generate a new random SSH host key
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Zeroization

/**
	@brief Zeroizes per-connection state so we can reuse the crypto engine object for a new session.

	Does not zeroize long-lived host keys.
*/
void CryptoEngine::Clear()
{
	memset(m_ephemeralkeyPriv, 0, sizeof(m_ephemeralkeyPriv));
	memset(m_ivClientToServer, 0, sizeof(m_ivClientToServer));
	memset(m_ivServerToClient, 0, sizeof(m_ivServerToClient));
	memset(m_keyClientToServer, 0, sizeof(m_keyClientToServer));
	memset(m_keyServerToClient, 0, sizeof(m_keyServerToClient));
	SHA256_Init();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Session key calculation

/**
	@brief Derives all of our session key material

	This function uses the SHA256 engine and will overwrite any in progress SHA256 hash.
 */
void CryptoEngine::DeriveSessionKeys(uint8_t* sharedSecret, uint8_t* exchangeHash, uint8_t* sessionID)
{
	uint8_t buf[32];
	DeriveSessionKey(sharedSecret, exchangeHash, sessionID, 'A', buf);
	memcpy(m_ivClientToServer, buf, GCM_IV_SIZE);
	DeriveSessionKey(sharedSecret, exchangeHash, sessionID, 'B', buf);
	memcpy(m_ivServerToClient, buf, GCM_IV_SIZE);
	DeriveSessionKey(sharedSecret, exchangeHash, sessionID, 'C', buf);
	memcpy(m_keyClientToServer, buf, AES_KEY_SIZE);
	DeriveSessionKey(sharedSecret, exchangeHash, sessionID, 'D', buf);
	memcpy(m_keyServerToClient, buf, AES_KEY_SIZE);
}

/**
	@brief Derives a single session key

	This function uses the SHA256 engine and will overwrite any in progress SHA256 hash.
 */
void CryptoEngine::DeriveSessionKey(uint8_t* sharedSecret, uint8_t* exchangeHash, uint8_t* sessionID, char keyid, uint8_t* out)
{
	SHA256_Init();

	//Convert the shared secret to OpenSSH mpint format and hash that
	uint8_t bignum_len[5] = {0, 0, 0, 32, 0};
	if(sharedSecret[0] & 0x80)
	{
		bignum_len[3] ++;
		SHA256_Update(bignum_len, 5);
	}
	else
		SHA256_Update(bignum_len, 4);
	SHA256_Update(sharedSecret, ECDH_KEY_SIZE);

	SHA256_Update(exchangeHash, SHA256_DIGEST_SIZE);
	SHA256_Update((uint8_t*)&keyid, 1);
	SHA256_Update(sessionID, SHA256_DIGEST_SIZE);
	SHA256_Final(out);
}

void CryptoEngine::SharedSecret(uint8_t* sharedSecret, uint8_t* clientPublicKey)
{
	crypto_scalarmult(sharedSecret, m_ephemeralkeyPriv, clientPublicKey);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Host key generation

/**
	@brief Performs initial host key generation
 */
void CryptoEngine::GenerateHostKey()
{
	GenerateRandom(m_hostkeyPriv, sizeof(m_hostkeyPriv));
	crypto_sign_keypair(m_hostkeyPub, m_hostkeyPriv);
}

/**
	@brief Generates an x25519 key pair.

	The private key is kept internal to the CryptoEngine object.

	The public key is stored in the provided buffer, which must be at least 32 bytes in size.
 */
void CryptoEngine::GenerateX25519KeyPair(uint8_t* pub)
{
	//To be a valid key, a few bits need well-defined values. The rest are cryptographic randomness.
	GenerateRandom(m_ephemeralkeyPriv, 32);
	m_ephemeralkeyPriv[0] &= 0xF8;
	m_ephemeralkeyPriv[31] &= 0x7f;
	m_ephemeralkeyPriv[31] |= 0x40;

	crypto_scalarmult_base(pub, m_ephemeralkeyPriv);
}

/**
	@brief Gets the host key fingerprint (base64 encoded SHA256).

	This function uses the SHA256 engine and will overwrite any in progress SHA256 hash.
 */
void CryptoEngine::GetKeyFingerprint(char* buf, size_t len, uint8_t* pubkey)
{
	if(len < 49)
		return;

	//Hash the public key (in RFC 4252 format)
	SHA256_Init();
	uint32_t tmp = __builtin_bswap32(11);
	SHA256_Update((uint8_t*)&tmp, sizeof(tmp));
	SHA256_Update((uint8_t*)"ssh-ed25519", 11);
	tmp = __builtin_bswap32(32);
	SHA256_Update((uint8_t*)&tmp, sizeof(tmp));
	SHA256_Update(pubkey, ECDH_KEY_SIZE);

	//Done hashing
	uint8_t digest[SHA256_DIGEST_SIZE];
	SHA256_Final(digest);

	//Base64 encode
	base64_encodestate state;
	base64_init_encodestate(&state);
	int count = base64_encode_block((char*)digest, SHA256_DIGEST_SIZE, buf, &state);
	count += base64_encode_blockend(buf + count, &state);
	buf[count] = '\0';

	//Strip padding characters since OpenSSH doesn't show them
	for(int i=count-1; i >= 0; i--)
	{
		if(buf[i] == '=')
			buf[i] = '\0';
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Signature creation and verification

///@brief Signs an exchange hash with our host key
void CryptoEngine::SignExchangeHash(uint8_t* sigOut, uint8_t* exchangeHash)
{
	//tweetnacl wants the public key here which is kinda derpy, we don't actually need it
	//TODO: optimize out this stupidity
	uint8_t keyCombined[64];
	memcpy(keyCombined, m_hostkeyPriv, 32);
	memcpy(keyCombined + 32, m_hostkeyPub, 32);

	uint8_t sm[128];
	uint64_t smlen;
	crypto_sign(sm, &smlen, exchangeHash, SHA256_DIGEST_SIZE, keyCombined);
	memcpy(sigOut, sm, 64);
}

/**
	@brief Verify a signed message

	The signature is *prepended* to the message: first 64 bytes are signature, then the message
 */
bool CryptoEngine::VerifySignature(uint8_t* signedMessage, uint32_t lengthIncludingSignature, uint8_t* publicKey)
{
	//fixed length cap
	if(lengthIncludingSignature > 1024)
		return false;

	unsigned char tmpbuf[1024];
	return (0 == crypto_sign_open(tmpbuf, signedMessage, lengthIncludingSignature, publicKey));
}
