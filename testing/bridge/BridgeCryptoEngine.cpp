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
#include <stdlib.h>

//Set private key to a hard coded constant (from testdata/id_ed25519)
uint8_t CryptoEngine::m_hostkeyPriv[32] =
{
	0xb2, 0xc8, 0x0c, 0x44, 0xb1, 0xad, 0x19, 0xb5,
	0x7a, 0x66, 0x5e, 0xa1, 0x7c, 0x78, 0x8b, 0x7b,
	0x4d, 0x20, 0xbf, 0x19, 0x49, 0x85, 0x97, 0x9e,
	0xf2, 0x79, 0x3e, 0xdc, 0x83, 0xf4, 0xd1, 0xa7
};

uint8_t CryptoEngine::m_hostkeyPub[32] =
{
	0xf7, 0x45, 0xd2, 0x13, 0x13, 0x4b, 0x19, 0x97,
	0xcf, 0xcf, 0x86, 0x98, 0xcc, 0x2b, 0x0c, 0xd2,
	0xc0, 0x45, 0xb1, 0xc9, 0xd4, 0xba, 0x22, 0x9f,
	0x08, 0x8c, 0x66, 0x90, 0xf2, 0x4b, 0xf4, 0xbf
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Construction / destruction

BridgeCryptoEngine::BridgeCryptoEngine()
{
	m_fpRandom = fopen("/dev/urandom", "rb");
	if(m_fpRandom == NULL)
	{
		perror("open /dev/urandom\n");
		exit(1);
	}
}

BridgeCryptoEngine::~BridgeCryptoEngine()
{
	fclose(m_fpRandom);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// State reset

void BridgeCryptoEngine::Clear()
{
	CryptoEngine::Clear();

	//TODO: reset encryptor and decryptor
	//(mostly for extra safety, they re-key each packet anyway)
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// RNG

void BridgeCryptoEngine::GenerateRandom(uint8_t* buf, size_t len)
{
	fread(buf, 1, len, m_fpRandom);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SHA256

void BridgeCryptoEngine::SHA256_Init()
{
	m_hash.Restart();
}

void BridgeCryptoEngine::SHA256_Update(uint8_t* data, uint16_t len)
{
	m_hash.Update(data, len);
}

void BridgeCryptoEngine::SHA256_Final(uint8_t* digest)
{
	m_hash.Final(digest);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AES


bool BridgeCryptoEngine::DecryptAndVerify(uint8_t* data, uint16_t len)
{
	m_decryptor.SetKeyWithIV(m_keyClientToServer, AES_KEY_SIZE, m_ivClientToServer, GCM_IV_SIZE);

	try
	{
		std::string cleartext;
		CryptoPP::AuthenticatedDecryptionFilter df(
			m_decryptor,
			new CryptoPP::StringSink(cleartext),
			CryptoPP::AuthenticatedDecryptionFilter::MAC_AT_END,
			GCM_TAG_SIZE);

		//Packet length is added as additional authenticated data, but not part of the normal AES payload
		uint32_t len_be = __builtin_bswap32(len - GCM_TAG_SIZE);
		df.ChannelPut( CryptoPP::AAD_CHANNEL, (uint8_t*)&len_be, sizeof(len_be) );

		df.ChannelPut( CryptoPP::DEFAULT_CHANNEL, data, len);

		df.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
		df.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

		//Check the MAC
		if(!df.GetLastResult())
		{
			printf("Verification failed\n");
			return false;
		}

		//Crypto++ can't do in place transforms, so copy it ourselves
		memcpy(data, cleartext.c_str(), cleartext.length());
	}
	catch(...)
	{
		return false;
	}

	//Increment IV
	//high 4 bytes stay constant
	//low 8 bytes are 64 bit big endian integer
	m_ivClientToServer[GCM_IV_SIZE-1] ++;
	for(int i=GCM_IV_SIZE-1; i>=4; i--)
	{
		if(m_ivClientToServer[i] == 0)
			m_ivClientToServer[i-1] ++;
		else
			break;
	}

	return true;
}

void BridgeCryptoEngine::EncryptAndMAC(uint8_t* data, uint16_t len)
{
	m_encryptor.SetKeyWithIV(m_keyServerToClient, AES_KEY_SIZE, m_ivServerToClient, GCM_IV_SIZE);

	std::string ciphertext;
	CryptoPP::AuthenticatedEncryptionFilter ef(
		m_encryptor,
		new CryptoPP::StringSink(ciphertext),
		false,
		GCM_TAG_SIZE,
		CryptoPP::DEFAULT_CHANNEL,
		CryptoPP::AuthenticatedEncryptionFilter::NO_PADDING);

	//Packet length is added as additional authenticated data, but not part of the normal AES payload
	uint32_t len_be = __builtin_bswap32(len);
	ef.ChannelPut( CryptoPP::AAD_CHANNEL, (uint8_t*)&len_be, sizeof(len_be) );

	ef.ChannelPut( CryptoPP::DEFAULT_CHANNEL, data, len);

	ef.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
	ef.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

	//Crypto++ can't do in place transforms, so copy it ourselves
	memcpy(data, ciphertext.c_str(), ciphertext.length());

	//Increment IV
	//high 4 bytes stay constant
	//low 8 bytes are 64 bit big endian integer
	m_ivServerToClient[GCM_IV_SIZE-1] ++;
	for(int i=GCM_IV_SIZE-1; i>=4; i--)
	{
		if(m_ivServerToClient[i] == 0)
			m_ivServerToClient[i-1] ++;
		else
			break;
	}
}
