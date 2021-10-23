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

STM32CryptoEngine::STM32CryptoEngine()
{
	//Start RNG clocks
	RCCHelper::Enable(&RNG);

	//Enable clock error detection
	RNG.CR |= RNG_CED;

	//Turn on the RNG
	RNG.CR |= RNG_EN;
}

STM32CryptoEngine::~STM32CryptoEngine()
{
}

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

void STM32CryptoEngine::Clear()
{
	CryptoEngine::Clear();
}

void STM32CryptoEngine::SHA256_Init()
{
	g_log("STM32CryptoEngine::SHA256_Init\n");
	while(1)
	{}
}

void STM32CryptoEngine::SHA256_Update(uint8_t* data, uint16_t len)
{
	g_log("STM32CryptoEngine::SHA256_Update\n");
	while(1)
	{}
}

void STM32CryptoEngine::SHA256_Final(uint8_t* digest)
{
	g_log("STM32CryptoEngine::SHA256_Final\n");
	while(1)
	{}
}

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
