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

#ifndef SFTPStatusPacket_h
#define SFTPStatusPacket_h

class __attribute__((packed)) SFTPStatusPacket
{
public:
	SFTPStatusPacket()
	{
		m_msgLen = 0;
		m_langLen = 0;
	}

	enum Status
	{
		SSH_FX_OK 							= 0,
		SSH_FX_EOF							= 1,
		SSH_FX_NO_SUCH_FILE					= 2,
		SSH_FX_PERMISSION_DENIED			= 3,
		SSH_FX_FAILURE						= 4,
		SSH_FX_BAD_MESSAGE					= 5,
		SSH_FX_NO_CONNECTION				= 6,
		SSH_FX_CONNECTION_LOST				= 7,
		SSH_FX_OP_UNSUPPORTED				= 8,
		SSH_FX_INVALID_HANDLE				= 9,
		SSH_FX_NO_SUCH_PATH					= 10,
		SSH_FX_FILE_ALREADY_EXISTS			= 11,
		SSH_FX_WRITE_PROTECT				= 12,
		SSH_FX_NO_MEDIA						= 13,
		SSH_FX_NO_SPACE_ON_FILESYSTEM		= 14,
		SSH_FX_QUOTA_EXCEEDED				= 15,
		SSH_FX_UNKNOWN_PRINCIPAL			= 16,
		SSH_FX_LOCK_CONFLICT				= 17,
		SSH_FX_DIR_NOT_EMPTY				= 18,
		SSH_FX_NOT_A_DIRECTORY				= 19,
		SSH_FX_INVALID_FILENAME				= 20,
		SSH_FX_LINK_LOOP					= 21,
		SSH_FX_CANNOT_DELETE				= 22,
		SSH_FX_INVALID_PARAMETER			= 23,
		SSH_FX_FILE_IS_A_DIRECTORY			= 24,
		SSH_FX_BYTE_RANGE_LOCK_CONFLICT		= 25,
		SSH_FX_BYTE_RANGE_LOCK_REFUSED		= 26,
		SSH_FX_DELETE_PENDING				= 27,
		SSH_FX_FILE_CORRUPT					= 28,
		SSH_FX_OWNER_INVALID				= 29,
		SSH_FX_GROUP_INVALID				= 30,
		SSH_FX_NO_MATCHING_BYTE_RANGE_LOCK	= 31
	};

	void ByteSwap()
	{
		m_requestid = __builtin_bswap32(m_requestid);
		m_errorCode = __builtin_bswap32(m_errorCode);
	}

	uint32_t m_requestid;

	uint32_t m_errorCode;

	//For now: no error message or languages
	uint32_t m_msgLen;
	uint32_t m_langLen;
};

#endif

