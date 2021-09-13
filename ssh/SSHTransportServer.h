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
	@brief Declaration of SSHTransportServer
 */
#ifndef SSHTransportServer_h
#define SSHTransportServer_h

/**
	@brief State for a single SSH connection
 */
class SSHConnectionState
{
public:
	SSHConnectionState()
	{ Clear(); }

	/**
		@brief Clears connection state
	 */
	void Clear()
	{
		m_valid = false;
		m_socket = NULL;
	}

	///@brief True if the connection is valid
	bool	m_valid;

	///@brief Socket state handle
	TCPTableEntry* m_socket;
};

/**
	@brief Server for the SSH transport layer (RFC 4253)
 */
class SSHTransportServer
{
public:
	SSHTransportServer(TCPProtocol& tcp);

	//Event handlers
	void OnConnectionAccepted(TCPTableEntry* state);
	void OnRxData(TCPTableEntry* state, uint8_t* payload, uint16_t payloadLen);

protected:
	int GetConnectionID(TCPTableEntry* state);
	int AllocateConnectionID(TCPTableEntry* state);

	///@brief The transport layer for our traffic
	TCPProtocol& m_tcp;

	///@brief The SSH connection table
	SSHConnectionState m_state[SSH_TABLE_SIZE];
};

#endif
