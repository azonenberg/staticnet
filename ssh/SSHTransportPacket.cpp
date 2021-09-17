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

#include <stdio.h>

#include <staticnet-config.h>
#include <stack/staticnet.h>
#include "SSHTransportServer.h"
#include "SSHTransportPacket.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Byte ordering correction

void SSHTransportPacket::ByteSwap()
{
	m_packetLength = __builtin_bswap32(m_packetLength);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Header stuff

/**
	@brief Fills out the length field in the packet header and appends random padding
 */
void SSHTransportPacket::UpdateLength(uint16_t payloadLength, CryptoEngine* crypto)
{
	//We need a minimum of 4 bytes of padding
	m_paddingLength = 4;

	//Total packet length assuming minimum padding size
	//Padding length and type are counted towards total length, but the length field itself is not
	m_packetLength = payloadLength + m_paddingLength + 2;

	//Add extra padding until we hit a multiple of 8 bytes
	uint32_t paddingMod8 = (m_packetLength + sizeof(uint32_t)) % 8;
	if(paddingMod8 != 0)
	{
		uint32_t extraPaddingToAdd = 8 - paddingMod8;
		m_paddingLength += extraPaddingToAdd;
		m_packetLength += extraPaddingToAdd;
	}

	//Fill the padding with random data
	crypto->GenerateRandom(Payload() + payloadLength, m_paddingLength);
}
