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

#ifndef STM32CryptoEngine_h
#define STM32CryptoEngine_h

#include <stdint.h>
#include <string.h>
#include <stm32fxxx.h>
#include "../../crypt/CryptoEngine.h"

/**
	@brief Driver for the STM32 hardware AES / SHA256 / RNG blocks

	NOT thread safe.

	Includes context switching logic to manage multiple concurrent crypto operations.
 */
class STM32CryptoEngine : public CryptoEngine
{
public:
	STM32CryptoEngine();
	virtual ~STM32CryptoEngine();

	virtual void GenerateRandom(uint8_t* buf, size_t len);
	virtual void Clear();
	virtual void SHA256_Init();
	virtual void SHA256_Update(const uint8_t* data, uint16_t len);
	virtual void SHA256_Final(uint8_t* digest);
	virtual bool DecryptAndVerify(uint8_t* data, uint16_t len);
	virtual void EncryptAndMAC(uint8_t* data, uint16_t len);

protected:

	///@brief The object currently doing a hash (if any)
	static STM32CryptoEngine* m_activeHashEngine;

	void HashContextSwitchOut();
	void HashContextSwitchIn();

	//Saved context for hash engine
	uint32_t m_savedHashContext[54];

	//Saved partial hash data
	uint32_t m_partialHashInput;
	uint32_t m_partialHashLength;
};

#endif
