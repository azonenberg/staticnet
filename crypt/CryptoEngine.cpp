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

#include "bridge.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Construction / destruction

CryptoEngine::CryptoEngine()
{
	memset(m_ephemeralkeyPriv, 0, sizeof(m_ephemeralkeyPriv));
}

CryptoEngine::~CryptoEngine()
{

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
 */
void CryptoEngine::DeriveSessionKeys(uint8_t* sharedSecret, uint8_t* exchangeHash, uint8_t* sessionID)
{
	uint8_t buf[32];
	DeriveSessionKey(sharedSecret, exchangeHash, sessionID, 'A', buf);
	memcpy(m_ivClientToServer, buf, AES_BLOCK_SIZE);
	DeriveSessionKey(sharedSecret, exchangeHash, sessionID, 'B', buf);
	memcpy(m_ivServerToClient, buf, AES_BLOCK_SIZE);
	DeriveSessionKey(sharedSecret, exchangeHash, sessionID, 'C', buf);
	memcpy(m_keyClientToServer, buf, AES_KEY_SIZE);
	DeriveSessionKey(sharedSecret, exchangeHash, sessionID, 'D', buf);
	memcpy(m_keyServerToClient, buf, AES_KEY_SIZE);
}

/**
	@brief Derives a single session key
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
