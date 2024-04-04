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

/**
	@file
	@brief Declaration of SSHTransportServer
 */
#ifndef SSHTransportServer_h
#define SSHTransportServer_h

#include "../crypt/CryptoEngine.h"
#include "../util/CircularFIFO.h"
#include "SSHPasswordAuthenticator.h"
#include "SSHPubkeyAuthenticator.h"
#include "../net/tcp/TCPServer.h"

class SSHTransportPacket;
class SSHKexInitPacket;
class SSHUserAuthRequestPacket;
class SSHSessionRequestPacket;
class SSHPtyRequestPacket;

#ifndef SSH_MAX_ALGLEN
#define SSH_MAX_ALGLEN 16
#endif

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
		m_macPresent = false;
		m_valid = false;
		m_socket = NULL;
		m_state = STATE_BANNER_WAIT;
		m_sessionChannelID = 0;
		m_clientWindowWidthChars = 80;
		m_clientWindowHeightChars = 25;
		m_rxBuffer.Reset();
		memset(m_username, 0, SSH_MAX_USERNAME);

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

		STATE_UNAUTHENTICATED,		//Keys created, session is active, but not authenticated yet
		STATE_AUTH_IN_PROGRESS,		//Sent the service accept for auth
		STATE_AUTHENTICATED,		//Authentication successful

		//TODO
		STATE_INVALID

	} m_state;

	///@brief The crypto engine containing key material for this session
	CryptoEngine* m_crypto;

	///@brief Packet reassembly buffer (may span multiple TCP segments)
	CircularFIFO<SSH_RX_BUFFER_SIZE> m_rxBuffer;

	///@brief If true, we've completed the key exchange and have a MAC at the end of each packet
	bool m_macPresent;

	///@brief Session ID used by upper layer protocols
	uint8_t m_sessionID[SHA256_DIGEST_SIZE];

	///@brief The connection layer channel ID chosen by the client for our session
	uint32_t m_sessionChannelID;

	///@brief X axis dimension of the client window, in characters
	uint32_t m_clientWindowWidthChars;

	///@brief Y axis dimension of the client window, in characters
	uint32_t m_clientWindowHeightChars;

	///@brief Username
	char m_username[SSH_MAX_USERNAME];
};

/**
	@brief Server for the SSH transport layer (RFC 4253)

	Derived classes must initialize crypto engines in the constructor.
 */
class SSHTransportServer : public TCPServer<SSH_TABLE_SIZE, SSHConnectionState>
{
public:
	SSHTransportServer(TCPProtocol& tcp);
	virtual ~SSHTransportServer();

	//Event handlers
	virtual void OnConnectionAccepted(TCPTableEntry* socket) override;
	virtual void OnConnectionClosed(TCPTableEntry* socket) override;
	virtual bool OnRxData(TCPTableEntry* socket, uint8_t* payload, uint16_t payloadLen) override;

	void SendEncryptedPacket(
		int id,
		uint16_t length,
		TCPSegment* segment,
		SSHTransportPacket* packet,
		TCPTableEntry* socket);

	void SendSessionData(int id, TCPTableEntry* socket, const char* data, uint16_t length);

	/**
		@brief Checks if a null terminated C string is equal to an unterminated string with explicit length
	 */
	static bool StringMatchWithLength(const char* c_str, const char* pack_str, uint16_t pack_str_len)
	{
		if(strlen(c_str) != pack_str_len)
			return false;
		return (memcmp(c_str, pack_str, pack_str_len) == 0);
	}

	/**
		@brief Sets the authentication provider we use for checking passwords
	 */
	void UsePasswordAuthenticator(SSHPasswordAuthenticator* auth)
	{ m_passwordAuth = auth; }

	/**
		@brief Sets the authentication provider we use for checking public key logins
	 */
	void UsePubkeyAuthenticator(SSHPubkeyAuthenticator* auth)
	{ m_pubkeyAuth = auth; }

	virtual void GracefulDisconnect(int id, TCPTableEntry* socket) override;

protected:

	void OnRxBanner(int id, TCPTableEntry* socket);
	void OnRxKexInit(int id, TCPTableEntry* socket);
	bool ValidateKexInit(SSHKexInitPacket* kex, uint16_t len);
	void OnRxKexEcdhInit(int id, TCPTableEntry* socket);
	void OnRxNewKeys(int id, TCPTableEntry* socket);
	void OnRxEncryptedPacket(int id, TCPTableEntry* socket);
	void OnRxIgnore(int id, TCPTableEntry* socket, SSHTransportPacket* packet);
	void OnRxServiceRequest(int id, TCPTableEntry* socket, SSHTransportPacket* packet);
	void OnRxServiceRequestUserAuth(int id, TCPTableEntry* socket);
	void OnRxUserAuthRequest(int id, TCPTableEntry* socket, SSHTransportPacket* packet);
	void OnRxAuthTypeQuery(int id, TCPTableEntry* socket);
	void OnRxAuthFail(int id, TCPTableEntry* socket);
	void OnRxAuthTypePassword(int id, TCPTableEntry* socket, SSHUserAuthRequestPacket* packet);
	void OnRxAuthTypePubkey(int id, TCPTableEntry* socket, SSHUserAuthRequestPacket* packet);
	void OnRxAuthSuccess(int id, const char* username, int16_t usernamelen, TCPTableEntry* socket);
	void OnRxChannelOpen(int id, TCPTableEntry* socket, SSHTransportPacket* packet);
	void OnRxChannelOpenSession(int id, TCPTableEntry* socket, SSHSessionRequestPacket* packet);
	void OnRxChannelRequest(int id, TCPTableEntry* socket, SSHTransportPacket* packet);
	void OnRxPtyRequest(int id, SSHPtyRequestPacket* packet);
	void OnRxChannelData(int id, TCPTableEntry* socket, SSHTransportPacket* packet);

	virtual void DropConnection(int id, TCPTableEntry* socket);

	/**
		@brief Called when a session initializes and runs a shell
	 */
	virtual void InitializeShell(int id, TCPTableEntry* socket) =0;

	/**
		@brief Called when new data comes in from stdin on a client session
	 */
	virtual void OnRxShellData(int id, TCPTableEntry* socket, char* data, uint16_t len) =0;

	bool IsPacketReady(SSHConnectionState& state);
	SSHTransportPacket* PeekPacket(SSHConnectionState& state);
	void PopPacket(SSHConnectionState& state);

	///@brief The authenticator for password logins
	SSHPasswordAuthenticator* m_passwordAuth;

	///@brief The authenticator for publickey logins
	SSHPubkeyAuthenticator* m_pubkeyAuth;

	/**
		@brief Writes a big-endian uint32_t to a buffer
	 */
	void WriteUint32(uint8_t* ptr, uint32_t value)
	{ *reinterpret_cast<uint32_t*>(ptr) = __builtin_bswap32(value); }
};

#endif
