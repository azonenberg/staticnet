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

#include <util/Logger.h>
extern Logger g_log;

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
	g_log("STM32CryptoEngine::HashContextSwitchOut (%08x)\n", this);

	for(int i=0; i<54; i++)
		m_savedHashContext[i] = HASH.CSR[i];

	m_activeHashEngine = NULL;
}

/**
	@brief Restore hash status after being interrupted
 */
void STM32CryptoEngine::HashContextSwitchIn()
{
	g_log("STM32CryptoEngine::HashContextSwitchIn (%08x)\n", this);

	for(int i=0; i<54; i++)
		HASH.CSR[i] = m_savedHashContext[i];

	m_activeHashEngine = this;
}

void STM32CryptoEngine::SHA256_Init()
{
	g_log("STM32CryptoEngine::SHA256_Init\n");
	LogIndenter li(g_log);

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
	g_log("STM32CryptoEngine::SHA256_Update\n");
	LogIndenter li(g_log);

	//If we're not active, swap us in
	if(m_activeHashEngine != this)
	{
		if(m_activeHashEngine != NULL)
			m_activeHashEngine->HashContextSwitchOut();
		HashContextSwitchIn();
	}

	//TODO: handle input not a multiple of 4 bytes
	if(len % 4)
	{
		g_log(Logger::ERROR, "Non multiple of 4 not supported\n");
		while(1)
		{}
	}

	//Process the input in blocks of 4 bytes
	for(uint16_t i=0; i<len; i += 4)
	{
		//Block if busy
		while(HASH.SR & HASH_BUSY)
		{}

		//Write the next input word
		HASH.DIN = *reinterpret_cast<const uint32_t*>(data + i);
	}
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

	g_log("STM32CryptoEngine::SHA256_Final\n");
	LogIndenter li(g_log);

	//Block if busy
	while(HASH.SR & HASH_BUSY)
	{}

	//Start the last hash block
	//TODO: handle partial input
	HASH.STR = 0x00;
	HASH.STR = 0x100;

	//Copy output (core automatically blocks on reads if not done)
	auto out = reinterpret_cast<uint32_t*>(digest);
	for(int i=0; i<8; i++)
		out[i] = __builtin_bswap32(HASH.HR[i]);

	//hash is complete, nobody is active
	m_activeHashEngine = NULL;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Encryption

bool STM32CryptoEngine::DecryptAndVerify(uint8_t* data, uint16_t len)
{
	g_log("STM32CryptoEngine::DecryptAndVerify\n");
	while(1)
	{}
}

void STM32CryptoEngine::EncryptAndMAC(uint8_t* data, uint16_t len)
{
	g_log("STM32CryptoEngine::EncryptAndMAC\n");
	while(1)
	{}
}
