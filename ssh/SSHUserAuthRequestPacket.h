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

/**
	@file
	@brief Declaration of SSHUserAuthRequestPacket
 */
#ifndef SSHUserAuthRequestPacket_h
#define SSHUserAuthRequestPacket_h

/**
	@brief A SSH_MSG_USERAUTH_REQUEST packet

	Parsing is a bit awkward and inefficient due to the in-place nature of the class
	(we can't have any member vars other than data in the packet).
 */
class __attribute__((packed)) SSHUserAuthRequestPacket
{
public:

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Field accessors

	/**
		@brief Gets a pointer to the start of the user name (NOT null terminated)
	 */
	char* GetUserNameStart()
	{ return reinterpret_cast<char*>(&m_usernameLength) + sizeof(uint32_t); }

	/**
		@brief Gets the length of the user name
	 */
	uint32_t GetUserNameLength()
	{ return __builtin_bswap32(m_usernameLength); }

	/**
		@brief Gets a pointer to the start of the service name (NOT null terminated)
	 */
	char* GetServiceNameStart()
	{ return GetUserNameStart() + GetUserNameLength() + sizeof(uint32_t); }

	/**
		@brief Gets the length of the service name
	 */
	uint32_t GetServiceNameLength()
	{ return __builtin_bswap32(*reinterpret_cast<uint32_t*>(GetServiceNameStart() - sizeof(uint32_t))); }

	/**
		@brief Gets a pointer to the start of the auth type (NOT null terminated)
	 */
	char* GetAuthTypeStart()
	{ return GetServiceNameStart() + GetServiceNameLength() + sizeof(uint32_t); }

	/**
		@brief Gets the length of the auth type
	 */
	uint32_t GetAuthTypeLength()
	{ return __builtin_bswap32(*reinterpret_cast<uint32_t*>(GetAuthTypeStart() - sizeof(uint32_t))); }

	/**
		@brief Gets a pointer to the start of the password (NOT null terminated)
	 */
	char* GetPasswordStart()
	{ return GetAuthTypeStart() + GetAuthTypeLength() + sizeof(uint32_t) + 1; /*skip constant boolean value*/ }

	/**
		@brief Gets the length of the auth type
	 */
	uint32_t GetPasswordLength()
	{ return __builtin_bswap32(*reinterpret_cast<uint32_t*>(GetPasswordStart() - sizeof(uint32_t))); }

	/*
		if public key
			string "publickey"
			bool always_true
			string pubkey alg name
			string pubkey to use
			string signature

		if password
			string "password"
			bool always_false
			string password
	 */

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Field content

	uint32_t m_usernameLength;
};

#endif
