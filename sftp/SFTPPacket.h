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

#ifndef SFTPPacket_h
#define SFTPPacket_h

class __attribute__((packed)) SFTPPacket
{
public:
	void ByteSwap()
	{ m_length = __builtin_bswap32(m_length); }

	uint32_t m_length;
	uint8_t m_type;

	enum PacketType
	{
		SSH_FXP_INIT			= 1,
		SSH_FXP_VERSION 		= 2,
		SSH_FXP_OPEN			= 3,
		SSH_FXP_CLOSE			= 4,
		SSH_FXP_READ			= 5,
		SSH_FXP_WRITE			= 6,
		SSH_FXP_LSTAT			= 7,
		SSH_FXP_FSTAT			= 8,
		SSH_FXP_SETSTAT			= 9,
		SSH_FXP_FSETSTAT		= 10,
		SSH_FXP_OPENDIR			= 11,
		SSH_FXP_READDIR			= 12,
		SSH_FXP_REMOVE			= 13,
		SSH_FXP_MKDIR			= 14,
		SSH_FXP_RMDIR			= 15,
		SSH_FXP_REALPATH		= 16,
		SSH_FXP_STAT			= 17,
		SSH_FXP_RENAME			= 18,
		SSH_FXP_READLINK		= 19,
		//20 reserved
		SSH_FXP_LINK			= 21,
		SSH_FXP_BLOCK			= 22,
		SSH_FXP_UNBLOCK			= 23,

		//24 - 100 reserved

		SSH_FXP_STATUS			= 101,
		SSH_FXP_HANDLE			= 102,
		SSH_FXP_DATA			= 103,
		SSH_FXP_NAME			= 104,
		SSH_FXP_ATTRS			= 105,

		//106 - 199 reserved

		SSH_FXP_EXTENDED		= 200,
		SSH_FXP_EXTENDED_REPLY	= 201

		//202 - 255 reserved
	};

	//Access requests (common to a lot of stuff)
	enum AceMask
	{
		ACE4_READ_DATA			= 0x00000001,
		ACE4_LIST_DIRECTORY		= 0x00000001,
		ACE4_WRITE_DATA			= 0x00000002,
		ACE4_ADD_FILE			= 0x00000002,
		ACE4_APPEND_DATA		= 0x00000004,
		ACE4_ADD_SUBDIRECTORY	= 0x00000004,
		ACE4_READ_NAMED_ATTRS	= 0x00000008,
		AEC4_WRITE_NAMED_ATTRS	= 0x00000010,
		ACE4_EXECUTE			= 0x00000020,
		ACE4_DELETE_CHILD		= 0x00000040,
		ACE4_READ_ATTRIBUTES	= 0x00000080,
		ACE4_WRITE_ATTRIBUTES	= 0x00000100,
		ACE4_DELETE				= 0x00010000,
		ACE4_READ_ACL			= 0x00020000,
		ACE4_WRITE_ACL			= 0x00040000,
		ACE4_WRITE_OWNER		= 0x00080000,
		ACE4_SYNCHRONIZE		= 0x00100000
	};

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Field accessors

	uint8_t* Payload()
	{ return reinterpret_cast<uint8_t*>(this) + sizeof(SFTPPacket); }
};

#endif
