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

#include "../crypt/CryptoEngine.h"
#include "../util/CircularFIFO.h"

class SSHTransportPacket;
class SSHKexInitPacket;

/**
	@brief State for a single SSH connection
 */
class SSHConnectionState
{
public:
	SSHConnectionState()
		: m_crypto(NULL)
	{ Clear(); }

	/**
		@brief Clears connection state
	 */
	void Clear()
	{
		m_valid = false;
		m_socket = NULL;
		m_state = STATE_BANNER_SENT;

		//Zeroize crypto state
		if(m_crypto)
			m_crypto->Clear();
	}

	///@brief True if the connection is valid
	bool	m_valid;

	///@brief Socket state handle
	TCPTableEntry* m_socket;

	///@brief Position in the connection state machine
	enum
	{
		STATE_BANNER_WAIT,			//connection opened, waiting for client to send banner to us

		STATE_BANNER_SENT,			//Connection opened, we sent our banner to the client
		STATE_KEX_INIT_SENT,		//Got the banner, we sent our kex init message to the client
		STATE_KEX_ECDHINIT_SENT,	//Got the client's ECDH ephemeral key and sent ours
	} m_state;

	CryptoEngine* m_crypto;

	CircularFIFO<SSH_RX_BUFFER_SIZE> m_rxBuffer;
};

/**
	@brief Server for the SSH transport layer (RFC 4253)

	Derived classes must initialize crypto engines in the constructor.
 */
class SSHTransportServer
{
public:
	SSHTransportServer(TCPProtocol& tcp);
	virtual ~SSHTransportServer();

	//Event handlers
	void OnConnectionAccepted(TCPTableEntry* socket);
	bool OnRxData(TCPTableEntry* socket, uint8_t* payload, uint16_t payloadLen);

protected:

	int GetConnectionID(TCPTableEntry* socket);
	int AllocateConnectionID(TCPTableEntry* socket);

	void OnRxBanner(int id, TCPTableEntry* socket);
	void OnRxKexInit(int id, TCPTableEntry* socket);
	bool ValidateKexInit(SSHKexInitPacket* kex);
	void OnRxKexEcdhInit(int id, TCPTableEntry* socket);

	bool IsPacketReady(SSHConnectionState& state);
	SSHTransportPacket* PeekPacket(SSHConnectionState& state);
	void PopPacket(SSHConnectionState& state);

	///@brief The transport layer for our traffic
	TCPProtocol& m_tcp;

	///@brief The SSH connection table
	SSHConnectionState m_state[SSH_TABLE_SIZE];

	/**
		@brief Writes a big-endian uint32_t to a buffer
	 */
	void WriteUint32(uint8_t* ptr, uint32_t value)
	{ *reinterpret_cast<uint32_t*>(ptr) = __builtin_bswap32(value); }
};

#endif
