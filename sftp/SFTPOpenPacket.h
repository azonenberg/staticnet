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

#ifndef SFTPOpenPacket_h
#define SFTPOpenPacket_h

class __attribute__((packed)) SFTPOpenPacket
{
public:

	void ByteSwap()
	{ m_requestid = __builtin_bswap32(m_requestid); }

	uint32_t m_requestid;

	uint32_t m_pathLength;

	enum OpenFlags
	{
		SSH_FXF_ACCESS_DISPOSITION		= 0x00000007,

		SSH_FXF_CREATE_NEW				= 0x00000000,
		SSH_FXF_CREATE_TRUNCATE			= 0x00000001,
		SSH_FXF_OPEN_EXISTING			= 0x00000002,
		SSH_FXF_OPEN_OR_CREATE			= 0x00000003,
		SSH_FXF_TRUNCATE_EXISTING		= 0x00000004,
		SSH_FXF_APPEND_DATA				= 0x00000008,
		SSH_FXF_APPEND_DATA_ATOMIC		= 0x00000010,
		SSH_FXF_TEXT_MODE				= 0x00000020,
		SSH_FXF_BLOCK_READ				= 0x00000040,
		SSH_FXF_BLOCK_WRITE				= 0x00000080,
		SSH_FXF_BLOCK_DELETE			= 0x00000100,
		SSH_FXF_BLOCK_ADVISORY			= 0x00000200,
		SSH_FXF_NOFOLLOW				= 0x00000400,
		SSH_FXF_DELETE_ON_CLOSE			= 0x00000800,
		SSH_FXF_ACCESS_AUDIT_ALARM_INFO	= 0x00001000,
		SSH_FXF_ACCESS_BACKUP			= 0x00002000,
		SSH_FXF_BACKUP_STREAM			= 0x00004000,
		SSH_FXF_OVERRIDE_OWNER			= 0x00008000
	};

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Field accessors

	///@brief Gets a pointer to the start of the path (NOT null terminated)
	char* GetPathStart()
	{ return reinterpret_cast<char*>(&m_pathLength) + sizeof(uint32_t); }

	///@brief Gets the length of the path
	uint32_t GetPathLength()
	{ return __builtin_bswap32(m_pathLength); }

	///@brief Gets the desired access to the file
	uint32_t GetDesiredAccess()
	{
		if(GetPathLength() > MAX_PATH)
			return 0;

		return UnalignedLoad32BE(GetPathStart() + GetPathLength());
	}

	//Get the flags
	uint32_t GetFlags()
	{
		if(GetPathLength() > MAX_PATH)
			return 0;

		return UnalignedLoad32BE(GetPathStart() + GetPathLength() + sizeof(uint32_t));
	}

	//TODO: attributes
};

#endif
