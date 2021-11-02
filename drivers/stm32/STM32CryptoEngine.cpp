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

#include "STM32CryptoEngine.h"
#include <peripheral/RCC.h>

STM32CryptoEngine* STM32CryptoEngine::m_activeHashEngine = NULL;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Construction / destruction

STM32CryptoEngine::STM32CryptoEngine()
{
	//No initial context
	memset(&m_savedHashContext, 0, sizeof(m_savedHashContext));

	//No partial block to start
	m_partialHashInput = 0;
	m_partialHashLength = 0;

	//Start clocks for each block
	RCCHelper::Enable(&RNG);
	RCCHelper::Enable(&HASH);
	RCCHelper::Enable(&CRYP);

	//Enable clock error detection
	RNG.CR |= RNG_CED;

	//Turn on the RNG
	RNG.CR |= RNG_EN;
}

STM32CryptoEngine::~STM32CryptoEngine()
{
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Zeroization

void STM32CryptoEngine::Clear()
{
	CryptoEngine::Clear();
	memset(&m_savedHashContext, 0, sizeof(m_savedHashContext));
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// RNG

void STM32CryptoEngine::GenerateRandom(uint8_t* buf, size_t len)
{
	for(size_t i=0; i<len; i+=4)
	{
		//Block if RNG is in error state
		while( (RNG.SR & (RNG_SECS | RNG_CECS)) != 0)
		{}

		//Block until data is ready to read
		while( (RNG.SR & RNG_DRDY) == 0)
		{}

		//Get the current data word
		uint32_t data = RNG.DR;

		//Copy data word to output buffer
		for(size_t j=0; j<4; j++)
		{
			if(i+j >= len)
				break;

			buf[i+j] = (data & 0xff);
			data >>= 8;
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Hashing

/**
	@brief Save hash status so we can use the accelerator in another object
 */
void STM32CryptoEngine::HashContextSwitchOut()
{
	for(int i=0; i<54; i++)
		m_savedHashContext[i] = HASH.CSR[i];

	m_activeHashEngine = NULL;
}

/**
	@brief Restore hash status after being interrupted
 */
void STM32CryptoEngine::HashContextSwitchIn()
{
	for(int i=0; i<54; i++)
		HASH.CSR[i] = m_savedHashContext[i];

	m_activeHashEngine = this;
}

void STM32CryptoEngine::SHA256_Init()
{
	m_partialHashLength = 0;

	//We have no context to restore
	//but if somebody ELSE has a hash in progress, we might need to swap them out.
	if( (m_activeHashEngine != NULL) && (m_activeHashEngine != this) )
		m_activeHashEngine->HashContextSwitchOut();
	m_activeHashEngine = this;

	//Set up the hash engine for SHA256, no DMA
	HASH.CR = 0x400A4;
}

void STM32CryptoEngine::SHA256_Update(const uint8_t* data, uint16_t len)
{
	//If we're not active, swap us in
	if(m_activeHashEngine != this)
	{
		if(m_activeHashEngine != NULL)
			m_activeHashEngine->HashContextSwitchOut();
		HashContextSwitchIn();
	}

	//If we have partial input, but not enough to make a whole word when combined, just save it
	if( (m_partialHashLength + len) < 4)
	{
		for(int i=0; i<len; i++)
			m_partialHashInput = (m_partialHashInput >> 8) | (data[i] << 24);
		m_partialHashLength += len;
		return;
	}

	//If we have partial data, but enough to make a whole word when combined, combine and push the first word
	else if(m_partialHashLength != 0)
	{
		//Combine the old and new data
		int nExtra = 4 - m_partialHashLength;
		for(int i=0; i<nExtra; i++)
			m_partialHashInput = (m_partialHashInput >> 8) | (data[i] << 24);

		//Write the combined word
		HASH.DIN = m_partialHashInput;

		//Record how much data we consumed
		data += nExtra;
		len -= nExtra;

		//Partial data is now flushed
		m_partialHashLength = 0;
	}

	//Hash all full words
	int nlast = len - (len % 4);
	for(uint16_t i=0; i<nlast; i += 4)
		HASH.DIN = *reinterpret_cast<const uint32_t*>(data + i);

	//Save any remaining data
	for(int i=nlast; i<len; i++)
		m_partialHashInput = (m_partialHashInput >> 8) | (data[i] << 24);
	m_partialHashLength = len % 4;
}

void STM32CryptoEngine::SHA256_Final(uint8_t* digest)
{
	//If we're not active, swap us in
	if(m_activeHashEngine != this)
	{
		if(m_activeHashEngine != NULL)
			m_activeHashEngine->HashContextSwitchOut();
		HashContextSwitchIn();
	}

	//Block if busy
	while(HASH.SR & HASH_BUSY)
	{}

	//If we have partial data, shift it so it's right justified, then push it
	if(m_partialHashLength != 0)
	{
		m_partialHashInput >>= 8 * (4 - m_partialHashLength);
		HASH.DIN = m_partialHashInput;
	}

	//Start the last hash block
	if(m_partialHashLength != 0)
		HASH.STR = 8 * m_partialHashLength;
	else
		HASH.STR = 0x00;
	HASH.STR = 0x100;

	//Copy output (core automatically blocks on reads if not done)
	auto out = reinterpret_cast<uint32_t*>(digest);
	for(int i=0; i<8; i++)
		out[i] = __builtin_bswap32(HASH.HR[i]);

	//hash is complete, nobody is active
	m_activeHashEngine = NULL;
	m_partialHashInput = 0;
	m_partialHashLength = 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Encryption

bool STM32CryptoEngine::DecryptAndVerify(uint8_t* data, uint16_t len)
{
	//INIT PHASE: set up key
	//Note that table 153 in ST RM0410 is *wrong* (see ST support case 00143246)
	//0x2 goes to IV1RR, not IV0L as documented.
	CRYP.CR = 0;
	CRYP.CR = CRYP_ALG_AES_GCM | CRYP_BSWAP_BYTE | CRYP_KEY_128 | CRYP_DECRYPT | CRYP_GCM_PHASE_INIT;
	CRYP.K0LR = 0;
	CRYP.K0RR = 0;
	CRYP.K1LR = 0;
	CRYP.K1RR = 0;
	CRYP.K2LR = __builtin_bswap32(*reinterpret_cast<uint32_t*>(&m_keyClientToServer[0]));
	CRYP.K2RR = __builtin_bswap32(*reinterpret_cast<uint32_t*>(&m_keyClientToServer[4]));
	CRYP.K3LR = __builtin_bswap32(*reinterpret_cast<uint32_t*>(&m_keyClientToServer[8]));
	CRYP.K3RR = __builtin_bswap32(*reinterpret_cast<uint32_t*>(&m_keyClientToServer[12]));
	CRYP.IV0LR = __builtin_bswap32(*reinterpret_cast<uint32_t*>(&m_ivClientToServer[0]));
	CRYP.IV0RR = __builtin_bswap32(*reinterpret_cast<uint32_t*>(&m_ivClientToServer[4]));
	CRYP.IV1LR = __builtin_bswap32(*reinterpret_cast<uint32_t*>(&m_ivClientToServer[8]));
	CRYP.IV1RR = 2;

	CRYP.CR |= CRYP_EN;
	while(CRYP.CR & CRYP_EN)
	{}
	while(CRYP.SR & CRYP_BUSY)
	{}

	//HEADER PHASE: process AAD (big endian length)
	CRYP.CR |= CRYP_GCM_PHASE_AAD;
	CRYP.CR |= CRYP_EN;
	CRYP.DIN = __builtin_bswap32(len - GCM_TAG_SIZE);
	CRYP.DIN = 0x00000000;
	CRYP.DIN = 0x00000000;
	CRYP.DIN = 0x00000000;
	while(CRYP.SR & CRYP_BUSY)
	{}

	//PAYLOAD PHASE
	CRYP.CR &= ~CRYP_EN;
	CRYP.CR = (CRYP.CR & ~CRYP_GCM_PHASE_MASK) | CRYP_GCM_PHASE_DATA;
	CRYP.CR |= CRYP_EN;
	int reallen = len - GCM_TAG_SIZE;
	for(int i=0; i<reallen; i += 16)
	{
		for(int j=0; j<16; j+= 4)
			CRYP.DIN = (*reinterpret_cast<uint32_t*>(data+i+j));

		while( (CRYP.SR & CRYP_OFNE) == 0)
		{}

		for(int j=0; j<16; j+= 4)
			*reinterpret_cast<uint32_t*>(data+i+j) = (CRYP.DOUT);
	}

	//FINAL PHASE
	//Last block: block 0/2 = 0, block 1 = AAD len, block 3 = payload len
	CRYP.CR &= ~CRYP_EN;
	CRYP.CR &= ~CRYP_DECRYPT;
	CRYP.CR |= CRYP_GCM_PHASE_TAG;
	CRYP.CR |= CRYP_EN;
	CRYP.DIN = 0;
	CRYP.DIN = __builtin_bswap32(32);
	CRYP.DIN = 0;
	CRYP.DIN = __builtin_bswap32(reallen * 8);
	while( (CRYP.SR & CRYP_OFNE) == 0)
	{}
	uint8_t ctag[GCM_TAG_SIZE];
	for(int i=0; i<GCM_TAG_SIZE; i+= 4)
		*reinterpret_cast<uint32_t*>(ctag+i) = (CRYP.DOUT);

	//Verify the tag
	for(int i=0; i<GCM_TAG_SIZE; i++)
		ctag[i] ^= data[reallen+i];
	uint32_t sum = 0;
	for(int i=0; i<GCM_TAG_SIZE; i++)
		sum += ctag[i];
	if(sum != 0)
		return false;

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

void STM32CryptoEngine::EncryptAndMAC(uint8_t* data, uint16_t len)
{
	//INIT PHASE: set up key
	//Note that table 153 in ST RM0410 is *wrong* (see ST support case 00143246)
	//0x2 goes to IV1RR, not IV0L as documented.
	CRYP.CR = 0;
	CRYP.CR = CRYP_ALG_AES_GCM | CRYP_BSWAP_BYTE | CRYP_KEY_128 | CRYP_GCM_PHASE_INIT;
	CRYP.K0LR = 0;
	CRYP.K0RR = 0;
	CRYP.K1LR = 0;
	CRYP.K1RR = 0;
	CRYP.K2LR = __builtin_bswap32(*reinterpret_cast<uint32_t*>(&m_keyServerToClient[0]));
	CRYP.K2RR = __builtin_bswap32(*reinterpret_cast<uint32_t*>(&m_keyServerToClient[4]));
	CRYP.K3LR = __builtin_bswap32(*reinterpret_cast<uint32_t*>(&m_keyServerToClient[8]));
	CRYP.K3RR = __builtin_bswap32(*reinterpret_cast<uint32_t*>(&m_keyServerToClient[12]));
	CRYP.IV0LR = __builtin_bswap32(*reinterpret_cast<uint32_t*>(&m_ivServerToClient[0]));
	CRYP.IV0RR = __builtin_bswap32(*reinterpret_cast<uint32_t*>(&m_ivServerToClient[4]));
	CRYP.IV1LR = __builtin_bswap32(*reinterpret_cast<uint32_t*>(&m_ivServerToClient[8]));
	CRYP.IV1RR = 2;

	CRYP.CR |= CRYP_EN;
	while(CRYP.CR & CRYP_EN)
	{}
	while(CRYP.SR & CRYP_BUSY)
	{}

	//HEADER PHASE: process AAD (big endian length)
	CRYP.CR |= CRYP_GCM_PHASE_AAD;
	CRYP.CR |= CRYP_EN;
	CRYP.DIN = __builtin_bswap32(len);
	CRYP.DIN = 0x00000000;
	CRYP.DIN = 0x00000000;
	CRYP.DIN = 0x00000000;
	while(CRYP.SR & CRYP_BUSY)
	{}

	//PAYLOAD PHASE
	CRYP.CR &= ~CRYP_EN;
	CRYP.CR = (CRYP.CR & ~CRYP_GCM_PHASE_MASK) | CRYP_GCM_PHASE_DATA;
	CRYP.CR |= CRYP_EN;
	for(int i=0; i<len; i += 16)
	{
		for(int j=0; j<16; j+= 4)
			CRYP.DIN = (*reinterpret_cast<uint32_t*>(data+i+j));

		while( (CRYP.SR & CRYP_OFNE) == 0)
		{}

		for(int j=0; j<16; j+= 4)
			*reinterpret_cast<uint32_t*>(data+i+j) = (CRYP.DOUT);
	}

	//FINAL PHASE
	//Last block: block 0/2 = 0, block 1 = AAD len, block 3 = payload len
	CRYP.CR &= ~CRYP_EN;
	CRYP.CR |= CRYP_GCM_PHASE_TAG;
	CRYP.CR |= CRYP_EN;
	CRYP.DIN = 0;
	CRYP.DIN = __builtin_bswap32(32);
	CRYP.DIN = 0;
	CRYP.DIN = __builtin_bswap32(len * 8);
	while( (CRYP.SR & CRYP_OFNE) == 0)
	{}
	for(int i=0; i<GCM_TAG_SIZE; i+= 4)
		*reinterpret_cast<uint32_t*>(data+len+i) = (CRYP.DOUT);

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
