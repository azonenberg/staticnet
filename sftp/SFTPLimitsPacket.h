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

#ifndef SFTPLimitsPacket_h
#define SFTPLimitsPacket_h

class __attribute__((packed)) SFTPLimitsPacket
{
public:

	uint32_t	m_requestid;

	uint64_t	m_maxPacketLength;
	uint64_t	m_maxReadLength;
	uint64_t	m_maxWriteLength;
	uint64_t	m_maxOpenHandles;

	SFTPLimitsPacket()
	{
		m_maxPacketLength = SSH_RX_BUFFER_SIZE;
		m_maxReadLength = 1024;
		m_maxWriteLength = 1024;
		m_maxOpenHandles = 1;
	}

	void ByteSwap()
	{
		m_requestid = __builtin_bswap32(m_requestid);
		m_maxPacketLength = __builtin_bswap64(m_maxPacketLength);
		m_maxReadLength = __builtin_bswap64(m_maxReadLength);
		m_maxWriteLength = __builtin_bswap64(m_maxWriteLength);
		m_maxOpenHandles = __builtin_bswap64(m_maxOpenHandles);
	}


};

#endif
