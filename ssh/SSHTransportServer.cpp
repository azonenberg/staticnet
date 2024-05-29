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

#include <stdio.h>
#include <algorithm>

#include <staticnet-config.h>
#include "../stack/staticnet.h"
#include "SSHTransportServer.h"
#include "SSHTransportPacket.h"
#include "SSHKexInitPacket.h"
#include "SSHKexEcdhInitPacket.h"
#include "SSHKexEcdhReplyPacket.h"
#include "SSHServiceRequestPacket.h"
#include "SSHUserAuthRequestPacket.h"
#include "SSHSessionRequestPacket.h"
#include "SSHChannelOpenFailurePacket.h"
#include "SSHChannelOpenConfirmationPacket.h"
#include "SSHChannelRequestPacket.h"
#include "SSHChannelStatusPacket.h"
#include "SSHPtyRequestPacket.h"
#include "SSHSubsystemRequestPacket.h"
#include "SSHExecRequestPacket.h"
#include "SSHChannelDataPacket.h"
#include "SSHDisconnectPacket.h"
#include "SSHCurve25519KeyBlob.h"
#include "SSHCurve25519SignatureBlob.h"

//Our single supported cipher suite
static const char* g_sshKexAlg				= "curve25519-sha256";			//RFC 8731
static const char* g_sshHostKeyAlg			= "ssh-ed25519";
static const char* g_sshUserKeyAlg			= "ssh-ed25519";
static const char* g_sshEncryptionAlg		= "aes128-gcm@openssh.com";
static const char* g_sshMacAlg				= "none";						//implicit in GCM
static const char* g_sshCompressionAlg		= "none";

//Other global strings for magic values
static const char* g_strUserAuth			= "ssh-userauth";
static const char* g_strConnection			= "ssh-connection";
static const char* g_strAuthTypeQuery		= "none";
static const char* g_authMethodList			= "publickey";	//TODO: switch for allowing pubkey or password
static const char* g_strAuthMethodPassword	= "password";
static const char* g_strAuthMethodPubkey	= "publickey";
static const char* g_strSession				= "session";
static const char* g_strSftp				= "sftp";
static const char* g_strPtyReq				= "pty-req";
static const char* g_strEnvReq				= "env-req";
static const char* g_strEnv					= "env";
static const char* g_strShellReq			= "shell";
static const char* g_strSubsystemReq		= "subsystem";
static const char* g_strExec				= "exec";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Construction / destruction

SSHTransportServer::SSHTransportServer(TCPProtocol& tcp)
	: TCPServer(tcp)
	, m_passwordAuth(nullptr)
	, m_pubkeyAuth(nullptr)
	, m_sftpServer(nullptr)
{
}

SSHTransportServer::~SSHTransportServer()
{
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Event handlers

/**
	@brief Handles a newly accepted connection
 */
void SSHTransportServer::OnConnectionAccepted(TCPTableEntry* socket)
{
	//Make a new entry in the socket state table
	int id = AllocateConnectionID(socket);
	if(id < 0)
		return;

	m_state[id].m_state = SSHConnectionState::STATE_BANNER_WAIT;
}

/**
	@brief Tears down a connection when the socket is closed
 */
void SSHTransportServer::OnConnectionClosed(TCPTableEntry* socket)
{
	//Connection was terminated by the other end, close our state so we can reuse it
	auto id = GetConnectionID(socket);
	if(id >= 0)
		m_state[id].Clear();
}

/**
	@brief Handler for incoming TCP segments
 */
bool SSHTransportServer::OnRxData(TCPTableEntry* socket, uint8_t* payload, uint16_t payloadLen)
{
	//Look up the connection ID for the incoming session
	auto id = GetConnectionID(socket);
	if(id < 0)
		return true;

	//Push the segment data into our RX FIFO
	if(!m_state[id].m_rxBuffer.Push(payload, payloadLen))
	{
		DropConnection(id, socket);
		return false;
	}

	//If waiting for a client banner, special handling needed (not the normal packet format)
	if(m_state[id].m_state == SSHConnectionState::STATE_BANNER_WAIT)
	{
		OnRxBanner(id, socket);
		return true;
	}

	//Everything else uses the normal SSH packet framing.
	//Process packets (might be several concatenated in a single TCP segment)
	while(IsPacketReady(m_state[id]))
	{
		//Figure out what state we're in so we know what to expect
		switch(m_state[id].m_state)
		{
			//never used, just to prevent compiler warnings about unhandled cases
			case SSHConnectionState::STATE_BANNER_WAIT:
				break;

			//Setup / key exchange
			case SSHConnectionState::STATE_BANNER_SENT:
				OnRxKexInit(id, socket);
				break;

			case SSHConnectionState::STATE_KEX_INIT_SENT:
				OnRxKexEcdhInit(id, socket);
				break;

			case SSHConnectionState::STATE_KEX_ECDHINIT_SENT:
				OnRxNewKeys(id, socket);
				break;

			//By the time we get here, we've got encrypted traffic!
			//Need to decrypt and verify it before doing anything.
			default:
				OnRxEncryptedPacket(id, socket);
				break;
		}

		//Whatever it was, we're done with it. On to th enext one.
		PopPacket(m_state[id]);
	}

	return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Other miscellaneous helpers

/**
	@brief Gracefully disconnects from a session
 */
void SSHTransportServer::GracefulDisconnect(int id, TCPTableEntry* socket)
{
	//Close our channel (if open)
	if(m_state[id].m_sessionChannelID != INVALID_CHANNEL)
	{
		auto segment = m_tcp.GetTxSegment(socket);
		auto reply = reinterpret_cast<SSHTransportPacket*>(segment->Payload());
		reply->m_type = SSHTransportPacket::SSH_MSG_CHANNEL_CLOSE;
		auto stat = reinterpret_cast<SSHChannelStatusPacket*>(reply->Payload());
		stat->m_clientChannel = m_state[id].m_sessionChannelID;
		stat->ByteSwap();
		SendEncryptedPacket(id, sizeof(SSHChannelStatusPacket), segment, reply, socket);

		//channel is now invalid, don't send anything else to it
		m_state[id].m_sessionChannelID = INVALID_CHANNEL;
	}

	//Do not actually close the socket until we get a SSH_MSG_DISCONNECT from the client
}

/**
	@brief Drops a connection due to a protocol error or similar
 */
void SSHTransportServer::DropConnection(int id, TCPTableEntry* socket)
{
	auto segment = m_tcp.GetTxSegment(socket);
	auto reply = reinterpret_cast<SSHTransportPacket*>(segment->Payload());
	reply->m_type = SSHTransportPacket::SSH_MSG_DISCONNECT;
	auto disc = reinterpret_cast<SSHDisconnectPacket*>(reply->Payload());
	disc->m_reasonCode = SSHDisconnectPacket::SSH_DISCONNECT_BY_APPLICATION;
	disc->m_descriptionLengthAlwaysZero = 0;
	disc->m_languageTagAlwaysZero = 0;
	disc->ByteSwap();
	SendEncryptedPacket(id, sizeof(SSHDisconnectPacket), segment, reply, socket);

	m_state[id].Clear();
	m_tcp.CloseSocket(socket);
}

/**
	@brief Helper for sending session data to the client
 */
void SSHTransportServer::SendSessionData(int id, TCPTableEntry* socket, const char* data, uint16_t length)
{
	//abort if we dont have a valid session
	if(m_state[id].m_sessionChannelID == INVALID_CHANNEL)
		return;

	//max 1K per packet for now
	if(length > 1024)
		return;

	//Send the data
	auto segment = m_tcp.GetTxSegment(socket);
	if(!segment)
		return;
	auto reply = reinterpret_cast<SSHTransportPacket*>(segment->Payload());
	reply->m_type = SSHTransportPacket::SSH_MSG_CHANNEL_DATA;
	auto dat = reinterpret_cast<SSHChannelDataPacket*>(reply->Payload());
	dat->m_clientChannel = m_state[id].m_sessionChannelID;
	dat->m_dataLength = length;
	memcpy(dat->Payload(), data, length);
	dat->ByteSwap();
	SendEncryptedPacket(id, sizeof(SSHChannelDataPacket) + length, segment, reply, socket);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Handle inbound protocol data

/**
	@brief Handler for an incoming version banner
 */
void SSHTransportServer::OnRxBanner(int id, TCPTableEntry* socket)
{
	//Rewind the FIFO then see if there's a newline in the buffer
	auto& fifo = m_state[id].m_rxBuffer;
	auto banner = fifo.Rewind();
	auto len = fifo.ReadSize();

	//Search for a \n
	bool newlineFound = false;
	size_t bannerLen = 0;
	for(size_t i=0; i<len; i++)
	{
		if(banner[i] == '\n')
		{
			bannerLen = i+1;
			newlineFound = true;
			break;
		}
	}

	//If NO newline was found, look at the overall banner length.
	if(!newlineFound)
	{
		//If banner was more than 512 bytes long and still no newline, assume something is screwy
		//and drop the connection
		if(len > 512)
			DropConnection(id, socket);
		return;
	}

	//Version should be "SSH-2.0-clientswversion(optional other stuff)\r\n"
	//If it's not a SSH2 client, give up
	if(memcmp(banner, "SSH-2.0", 7) != 0)
	{
		DropConnection(id, socket);
		return;
	}

	//Send our banner to the client
	static const char server_banner[] = "SSH-2.0-staticnet_0.1\r\n";
	auto segment = m_tcp.GetTxSegment(socket);
	auto payload = segment->Payload();
	strncpy((char*)payload, server_banner, TCP_IPV4_PAYLOAD_MTU);
	m_tcp.SendTxSegment(socket, segment, sizeof(server_banner)-1);
	m_state[id].m_state = SSHConnectionState::STATE_BANNER_SENT;

	//Ignore client software version, we don't implement any quirks
	//But we still need to hash it for the signature (note that the \r\n is NOT included in the hash)
	//We also need to include a big-endian length before each ID string, even though this is not actually sent
	//over the wire.
	uint32_t clientBannerLen = bannerLen-2;
	uint32_t clientBannerLen_be = __builtin_bswap32(clientBannerLen);
	m_state[id].m_crypto->SHA256_Update((uint8_t*)&clientBannerLen_be, sizeof(clientBannerLen_be));
	m_state[id].m_crypto->SHA256_Update(banner, clientBannerLen);

	//Do the same thing for the server banner
	uint32_t serverBannerLen = sizeof(server_banner)-3;
	uint32_t serverBannerLen_be = __builtin_bswap32(serverBannerLen);
	m_state[id].m_crypto->SHA256_Update((uint8_t*)&serverBannerLen_be, sizeof(serverBannerLen_be));
	m_state[id].m_crypto->SHA256_Update((uint8_t*)server_banner, serverBannerLen);

	//Pop the banner data off the FIFO
	fifo.Pop(bannerLen);
}

/**
	@brief Handler for an incoming SSH_MSG_KEXINIT packet
 */
void SSHTransportServer::OnRxKexInit(int id, TCPTableEntry* socket)
{
	//Read the packet and make sure it's the right type. If not, drop the connection
	auto pack = PeekPacket(m_state[id]);
	if(pack->m_type != SSHTransportPacket::SSH_MSG_KEXINIT)
	{
		DropConnection(id, socket);
		return;
	}
	pack->ByteSwap();

	//Hash the client key exchange packet.
	//Note that padding and the type field are not included in the hash.
	uint32_t lenUnpadded = pack->m_packetLength - (pack->m_paddingLength + 1);
	if(lenUnpadded > pack->m_packetLength)
	{
		DropConnection(id, socket);
		return;
	}
	uint32_t lenUnpadded_be = __builtin_bswap32(lenUnpadded);
	m_state[id].m_crypto->SHA256_Update((uint8_t*)&lenUnpadded_be, sizeof(lenUnpadded_be));
	m_state[id].m_crypto->SHA256_Update(&pack->m_type, lenUnpadded);

	//Validate the inbound kex init packet
	auto kexInit = reinterpret_cast<SSHKexInitPacket*>(pack->Payload());
	if(!ValidateKexInit(kexInit, lenUnpadded))
	{
		DropConnection(id, socket);
		return;
	}

	//Prepare to reply with a key exchange init packet
	auto segment = m_tcp.GetTxSegment(socket);
	auto packet = reinterpret_cast<SSHTransportPacket*>(segment->Payload());
	packet->m_type = SSHTransportPacket::SSH_MSG_KEXINIT;

	//Set up the nonce
	auto replyStart = packet->Payload();
	auto kexOut = reinterpret_cast<SSHKexInitPacket*>(replyStart);
	m_state[id].m_crypto->GenerateRandom(kexOut->m_cookie, sizeof(kexOut->m_cookie));

	//Kex algorithms
	auto offset = kexOut->GetFirstNameListStart();
	kexOut->SetNameList(offset, g_sshKexAlg);

	//Host key alg
	offset = kexOut->GetNextNameListStart(offset);
	kexOut->SetNameList(offset, g_sshHostKeyAlg);

	//Encryption algorithms (client to server, then server to client)
	offset = kexOut->GetNextNameListStart(offset);
	kexOut->SetNameList(offset, g_sshEncryptionAlg);
	offset = kexOut->GetNextNameListStart(offset);
	kexOut->SetNameList(offset, g_sshEncryptionAlg);

	//MAC algorithms (client to server, then server to client)
	offset = kexOut->GetNextNameListStart(offset);
	kexOut->SetNameList(offset, g_sshMacAlg);
	offset = kexOut->GetNextNameListStart(offset);
	kexOut->SetNameList(offset, g_sshMacAlg);

	//Compression algorithms (client to server, then server to client)
	offset = kexOut->GetNextNameListStart(offset);
	kexOut->SetNameList(offset, g_sshCompressionAlg);
	offset = kexOut->GetNextNameListStart(offset);
	kexOut->SetNameList(offset, g_sshCompressionAlg);

	//Languages (client to server, then server to client)
	offset = kexOut->GetNextNameListStart(offset);
	kexOut->SetNameList(offset, "");
	offset = kexOut->GetNextNameListStart(offset);
	kexOut->SetNameList(offset, "");

	//Done with name lists
	//Add first_kext_packet_follows
	offset = kexOut->GetNextNameListStart(offset);
	*offset = 0;
	offset ++;

	//Add reserved field
	*reinterpret_cast<uint32_t*>(offset) = 0;
	offset += sizeof(uint32_t);

	//Add padding and calculate length
	packet->UpdateLength(offset - replyStart, m_state[id].m_crypto);
	auto len = packet->m_packetLength + sizeof(uint32_t);

	//Hash the server key exchange packet.
	//Note that padding and the type field are not included in the hash.
	lenUnpadded = packet->m_packetLength - (packet->m_paddingLength + 1);
	lenUnpadded_be = __builtin_bswap32(lenUnpadded);
	m_state[id].m_crypto->SHA256_Update((uint8_t*)&lenUnpadded_be, sizeof(lenUnpadded_be));
	m_state[id].m_crypto->SHA256_Update(&packet->m_type, lenUnpadded);

	//Done, send it
	packet->ByteSwap();
	m_tcp.SendTxSegment(socket, segment, len);
	m_state[id].m_state = SSHConnectionState::STATE_KEX_INIT_SENT;
}

/**
	@brief Verifies an inbound SSH_MSG_KEXINIT packet contains our supported cipher suite
 */
bool SSHTransportServer::ValidateKexInit(SSHKexInitPacket* kex, uint16_t len)
{
	//First name list: kex algorithms
	auto offset = kex->GetFirstNameListStart();
	auto first = offset;
	if(!kex->NameListContains(offset, g_sshKexAlg, len))
		return false;

	//Server host key algorithms
	offset = kex->GetNextNameListStart(offset);
	if(!kex->NameListContains(offset, g_sshHostKeyAlg, len))
		return false;

	//Encryption algorithms (client to server)
	offset = kex->GetNextNameListStart(offset);
	if(!kex->NameListContains(offset, g_sshEncryptionAlg, len))
		return false;

	//Encryption algorithms (server to client)
	offset = kex->GetNextNameListStart(offset);
	if(!kex->NameListContains(offset, g_sshEncryptionAlg, len))
		return false;

	//MAC algorithms (client to server)
	//Ignore this, AEAD modes don't use a MAC (client may not actually advertise "none")
	offset = kex->GetNextNameListStart(offset);

	//MAC algorithms (server to client)
	//Ignore this, AEAD modes don't use a MAC (client may not actually advertise "none")
	offset = kex->GetNextNameListStart(offset);

	//Compression algorithms (client to server)
	offset = kex->GetNextNameListStart(offset);
	if(!kex->NameListContains(offset, g_sshCompressionAlg, len))
		return false;

	//Compression algorithms (server to client)
	offset = kex->GetNextNameListStart(offset);
	if(!kex->NameListContains(offset, g_sshCompressionAlg, len))
		return false;

	//Languages (client to server)
	//Ignore this, we don't support any language extensions
	offset = kex->GetNextNameListStart(offset);

	//Languages (server to client)
	//Ignore this, we don't support any language extensions
	offset = kex->GetNextNameListStart(offset);

	//first kex packet follows (not supported)
	offset = kex->GetNextNameListStart(offset);
	if( (offset-first) > len)
		return false;
	bool firstKexFollows = *offset;
	if(firstKexFollows)
		return false;

	//rest of packet is reserved/padding/MAC, ignore it
	return true;
}

/**
	@brief Handles an incoming SSH_MSG_KEX_ECDH_INIT packet
 */
void SSHTransportServer::OnRxKexEcdhInit(int id, TCPTableEntry* socket)
{
	auto& state = m_state[id];

	//Read the packet and make sure it's the right type. If not, drop the connection
	auto pack = PeekPacket(state);
	pack->ByteSwap();
	if(pack->m_type != SSHTransportPacket::SSH_MSG_KEX_ECDH_INIT)
	{
		DropConnection(id, socket);
		return;
	}

	//Validate public key size
	auto kexEcdh = reinterpret_cast<SSHKexEcdhInitPacket*>(pack->Payload());
	kexEcdh->ByteSwap();
	if(kexEcdh->m_length != ECDH_KEY_SIZE)
	{
		DropConnection(id, socket);
		return;
	}

	//Prepare to reply with a key exchange reply packet
	auto segment = m_tcp.GetTxSegment(socket);
	auto packet = reinterpret_cast<SSHTransportPacket*>(segment->Payload());
	packet->m_type = SSHTransportPacket::SSH_MSG_KEX_ECDH_REPLY;
	auto replyStart = packet->Payload();
	auto kexOut = reinterpret_cast<SSHKexEcdhReplyPacket*>(replyStart);

	//Fill out constant length/type fields
	kexOut->m_hostKeyLength = 51;
	kexOut->m_hostKeyTypeLength = 11;
	memcpy(kexOut->m_hostKeyType, g_sshHostKeyAlg, 11);
	kexOut->m_hostKeyPublicLength = ECDH_KEY_SIZE;
	kexOut->m_ephemeralKeyPublicLength = ECDH_KEY_SIZE;
	kexOut->m_signatureBlobLength = 83;
	kexOut->m_signatureTypeLength = 11;
	memcpy(kexOut->m_signatureType, g_sshHostKeyAlg, 11);
	kexOut->m_signatureLength = 64;

	//Copy public host key
	memcpy(kexOut->m_hostKeyPublic, state.m_crypto ->GetHostPublicKey(), ECDH_KEY_SIZE);

	//Generate the ephemeral ECDH key
	state.m_crypto->GenerateX25519KeyPair(kexOut->m_ephemeralKeyPublic);

	//Calculate the shared secret between the client and server ephemeral keys
	uint8_t sharedSecret[ECDH_KEY_SIZE];
	state.m_crypto->SharedSecret(sharedSecret, kexEcdh->m_publicKey);

	//Get the key exchange into network byte order so we can hash all of the header fields correctly
	kexOut->ByteSwap();

	//Hash the rest of the stuff we need for the exchange hash
	//Server public key
	state.m_crypto->SHA256_Update((uint8_t*)&kexOut->m_hostKeyLength, 55);	//host key length + size of length itself

	//Client ephemeral public key
	uint8_t pubkeyLen_be[4] = {0, 0, 0, ECDH_KEY_SIZE};
	state.m_crypto->SHA256_Update(pubkeyLen_be, sizeof(pubkeyLen_be));
	state.m_crypto->SHA256_Update(kexEcdh->m_publicKey, ECDH_KEY_SIZE);

	//Server ephemeral public key
	state.m_crypto->SHA256_Update(pubkeyLen_be, sizeof(pubkeyLen_be));
	state.m_crypto->SHA256_Update(kexOut->m_ephemeralKeyPublic, ECDH_KEY_SIZE);

	//Finally, the last thing left to hash is the shared secret.
	//But we need to do some munging on it to a weird bignum format first.
	//Basically, if the MSB of the shared secret is set, add an extra 0x00 byte before it.
	uint8_t bignum_len[5] = {0, 0, 0, 32, 0};
	if(sharedSecret[0] & 0x80)
	{
		bignum_len[3] ++;
		state.m_crypto->SHA256_Update(bignum_len, 5);
	}
	else
		state.m_crypto->SHA256_Update(bignum_len, 4);
	state.m_crypto->SHA256_Update(sharedSecret, ECDH_KEY_SIZE);

	//Calculate and sign the exchange hash
	state.m_crypto->SHA256_Final(state.m_sessionID);
	state.m_crypto->SignExchangeHash(kexOut->m_signature, state.m_sessionID);

	//Calculate session keys
	//For now we don't support re-keying. In the fist key exchange the exchange hash is also the session ID.
	state.m_crypto->DeriveSessionKeys(sharedSecret, state.m_sessionID, state.m_sessionID);

	//Add padding and calculate length
	packet->UpdateLength(sizeof(SSHKexEcdhReplyPacket), state.m_crypto);
	auto len = packet->m_packetLength + sizeof(uint32_t);
	packet->ByteSwap();

	//Done, send it
	m_tcp.SendTxSegment(socket, segment, len);

	state.m_state = SSHConnectionState::STATE_KEX_ECDHINIT_SENT;

	//We now expect a MAC on all future packets
	state.m_macPresent = true;
}

/**
	@brief Handles a SSH_MSG_NEWKEYS message
 */
void SSHTransportServer::OnRxNewKeys(int id, TCPTableEntry* socket)
{
	//Read the packet and make sure it's the right type. If not, drop the connection
	auto pack = PeekPacket(m_state[id]);
	pack->ByteSwap();
	if(pack->m_type != SSHTransportPacket::SSH_MSG_NEWKEYS)
	{
		DropConnection(id, socket);
		return;
	}

	//Send a canned reply
	auto segment = m_tcp.GetTxSegment(socket);
	auto packet = reinterpret_cast<SSHTransportPacket*>(segment->Payload());
	packet->m_type = SSHTransportPacket::SSH_MSG_NEWKEYS;

	//Add padding and calculate length
	packet->UpdateLength(0, m_state[id].m_crypto);
	auto len = packet->m_packetLength + sizeof(uint32_t);
	packet->ByteSwap();

	//Done, send it
	m_tcp.SendTxSegment(socket, segment, len);

	m_state[id].m_state = SSHConnectionState::STATE_UNAUTHENTICATED;
}

/**
	@brief Handles an encrypted packet of unknown type (not decrypted or verified yet)
 */
void SSHTransportServer::OnRxEncryptedPacket(int id, TCPTableEntry* socket)
{
	//Grab the packet
	auto pack = PeekPacket(m_state[id]);
	pack->ByteSwap();

	//Need to decrypt the entire packet including type field and padding length before doing anything else
	//If verification failure, drop the connection and exit
	if(!m_state[id].m_crypto->DecryptAndVerify(&pack->m_paddingLength, pack->m_packetLength + GCM_TAG_SIZE))
	{
		DropConnection(id, socket);
		return;
	}

	//Sanity check padding length
	if(pack->m_paddingLength > pack->m_packetLength)
	{
		DropConnection(id, socket);
		return;
	}

	switch(pack->m_type)
	{
		case SSHTransportPacket::SSH_MSG_DISCONNECT:
			m_state[id].Clear();
			m_tcp.CloseSocket(socket);
			return;

		case SSHTransportPacket::SSH_MSG_IGNORE:
			OnRxIgnore(id, socket, pack);
			break;

		case SSHTransportPacket::SSH_MSG_SERVICE_REQUEST:
			OnRxServiceRequest(id, socket, pack);
			break;

		case SSHTransportPacket::SSH_MSG_USERAUTH_REQUEST:
			OnRxUserAuthRequest(id, socket, pack);
			break;

		case SSHTransportPacket::SSH_MSG_CHANNEL_OPEN:
			OnRxChannelOpen(id, socket, pack);
			break;

		case SSHTransportPacket::SSH_MSG_CHANNEL_REQUEST:
			OnRxChannelRequest(id, socket, pack);
			break;

		case SSHTransportPacket::SSH_MSG_CHANNEL_DATA:
			OnRxChannelData(id, socket, pack);
			break;

		//we only support one channel so EOF or close means we disconnect
		case SSHTransportPacket::SSH_MSG_CHANNEL_CLOSE:
			m_state[id].m_sessionChannelID = INVALID_CHANNEL;
			break;

		case SSHTransportPacket::SSH_MSG_CHANNEL_EOF:
			GracefulDisconnect(id, socket);
			break;

		default:
			//printf("Got unexpected packet (type %d)\n", pack->m_type);
			break;
	}
}

/**
	@brief Handle a SSH_MSG_IGNORE
 */
void SSHTransportServer::OnRxIgnore(int /*id*/, TCPTableEntry* /*socket*/, SSHTransportPacket* /*packet*/)
{
	//called at start of each connection with "markus" OpenSSH easter egg
}

/**
	@brief Handle a SSH_MSG_SERVICE_REQUEST
 */
void SSHTransportServer::OnRxServiceRequest(int id, TCPTableEntry* socket, SSHTransportPacket* packet)
{
	auto service = reinterpret_cast<SSHServiceRequestPacket*>(packet->Payload());
	service->ByteSwap();

	//bounds check name length
	if(service->m_length >= packet->m_packetLength)
	{
		DropConnection(id, socket);
		return;
	}

	//Payload is expected to be a string. Null terminate it (this overwrites beginning of the MAC but who cares)
	//so we can use C libraries to manipulate it.
	auto payload = service->Payload();
	payload[service->m_length] = '\0';

	//Unauthenticated? Expect "ssh-userauth"
	if(m_state[id].m_state == SSHConnectionState::STATE_UNAUTHENTICATED)
	{
		if(strcmp(payload, g_strUserAuth) != 0)
		{
			DropConnection(id, socket);
			return;
		}

		OnRxServiceRequestUserAuth(id, socket);
	}

	//Authenticated
	else
	{
		//printf("Got SSH_MSG_SERVICE_REQUEST (%s)\n", payload);
	}
}

/**
	@brief Handle a SSH_MSG_SERVICE_REQUEST of type "ssh-userauth"
 */
void SSHTransportServer::OnRxServiceRequestUserAuth(int id, TCPTableEntry* socket)
{
	//Send the acceptance reply
	auto segment = m_tcp.GetTxSegment(socket);
	auto packet = reinterpret_cast<SSHTransportPacket*>(segment->Payload());
	packet->m_type = SSHTransportPacket::SSH_MSG_SERVICE_ACCEPT;
	auto accept = reinterpret_cast<SSHServiceRequestPacket*>(packet->Payload());
	auto len = strlen(g_strUserAuth);
	accept->m_length = len;
	memcpy(accept->Payload(), g_strUserAuth, len);
	accept->ByteSwap();
	SendEncryptedPacket(id, len + sizeof(SSHServiceRequestPacket), segment, packet, socket);

	m_state[id].m_state = SSHConnectionState::STATE_AUTH_IN_PROGRESS;
}

/**
	@brief Handle a SSH_MSG_USERAUTH_REQUEST packet
 */
void SSHTransportServer::OnRxUserAuthRequest(int id, TCPTableEntry* socket, SSHTransportPacket* packet)
{
	//verify state
	if(m_state[id].m_state != SSHConnectionState::STATE_AUTH_IN_PROGRESS)
	{
		DropConnection(id, socket);
		return;
	}

	const int string_max = 1024;

	//Grab initial string fields out of the packet
	//Cap string length to be safe
	auto req = reinterpret_cast<SSHUserAuthRequestPacket*>(packet->Payload());
	auto ulen = req->GetUserNameLength();
	if(ulen > string_max)
	{
		DropConnection(id, socket);
		return;
	}
	auto sname = req->GetServiceNameStart();
	auto slen = req->GetServiceNameLength();
	auto total = ulen + slen;
	if(total > string_max)
	{
		DropConnection(id, socket);
		return;
	}
	auto authtype = req->GetAuthTypeStart();
	auto authlen = req->GetAuthTypeLength();
	total += authlen;
	if(total > string_max)
	{
		DropConnection(id, socket);
		return;
	}

	//We only support authenticating to one service type "ssh-connection"
	if(!StringMatchWithLength(g_strConnection, sname, slen))
	{
		DropConnection(id, socket);
		return;
	}

	//Auth request of type "none" is a query to see what auth types we support
	if(StringMatchWithLength(g_strAuthTypeQuery, authtype, authlen))
	{
		OnRxAuthTypeQuery(id, socket);
		return;
	}

	//Trying to authenticate with a password
	else if(StringMatchWithLength(g_strAuthMethodPassword, authtype, authlen))
	{
		OnRxAuthTypePassword(id, socket, req);
		return;
	}

	//Trying to authenticate with a public key
	else if(StringMatchWithLength(g_strAuthMethodPubkey, authtype, authlen))
	{
		OnRxAuthTypePubkey(id, socket, req);
		return;
	}

	//debug print, unknown type
	else
	{
		char tmp_type[32] = {0};
		if(authlen > 31)
			authlen = 31;
		memcpy(tmp_type, authtype, authlen);
		//printf("SSH_MSG_USERAUTH_REQUEST of type %s\n", tmp_type);
	}
}

/**
	@brief Reports that the previous auth request was uuccessful
 */
void SSHTransportServer::OnRxAuthSuccess(int id, const char* username, int16_t usernamelen, TCPTableEntry* socket)
{
	strncpy(m_state[id].m_username, username, usernamelen);

	auto segment = m_tcp.GetTxSegment(socket);
	auto packet = reinterpret_cast<SSHTransportPacket*>(segment->Payload());
	packet->m_type = SSHTransportPacket::SSH_MSG_USERAUTH_SUCCESS;
	SendEncryptedPacket(id, 0, segment, packet, socket);
}

/**
	@brief Reports that the previous auth request was unsuccessful
 */
void SSHTransportServer::OnRxAuthFail(int id, TCPTableEntry* socket)
{
	auto segment = m_tcp.GetTxSegment(socket);
	auto packet = reinterpret_cast<SSHTransportPacket*>(segment->Payload());
	packet->m_type = SSHTransportPacket::SSH_MSG_USERAUTH_FAILURE;
	auto buf = packet->Payload();
	auto len = strlen(g_authMethodList);
	buf[0] = 0;
	buf[1] = 0;
	buf[2] = 0;
	buf[3] = len;
	strncpy((char*)buf+4, g_authMethodList, 255);
	buf[4+len] = 0x00;	//no partial success
	SendEncryptedPacket(id, len+5, segment, packet, socket);
}

/**
	@brief Handles a SSH_MSG_USERAUTH_REQUEST with type "none"
 */
void SSHTransportServer::OnRxAuthTypeQuery(int id, TCPTableEntry* socket)
{
	OnRxAuthFail(id, socket);
	//no change to state, still waiting for auth to complete
}

/**
	@brief Handles a SSH_MSG_USERAUTH_REQUEST with type "password"
 */
void SSHTransportServer::OnRxAuthTypePassword(int id, TCPTableEntry* socket, SSHUserAuthRequestPacket* req)
{
	//Extract username and password, and sanity check lengths
	auto uname = req->GetUserNameStart();
	auto ulen = req->GetUserNameLength();
	if(ulen >= SSH_MAX_USERNAME)
	{
		DropConnection(id, socket);
		return;
	}
	auto pass = req->GetPasswordStart();
	auto passlen = req->GetPasswordLength();
	if(passlen >= SSH_MAX_PASSWORD)
	{
		DropConnection(id, socket);
		return;
	}

	//If we don't have an authenticator, reject the auth request
	if(!m_passwordAuth)
	{
		//printf("rejecting auth due to no password authenticator\n");
		OnRxAuthFail(id, socket);
		//no change to state, still waiting for auth to complete
		return;
	}

	//Check the credentials
	if(!m_passwordAuth->TestLogin(
		uname,
		ulen,
		pass,
		passlen,
		m_state[id].m_crypto))
	{
		//printf("authenticator reported bad password\n");
		OnRxAuthFail(id, socket);
		//no change to state, still waiting for auth to complete
		return;
	}

	//If we get here, the password was GOOD. Report success.
	OnRxAuthSuccess(id, uname, ulen, socket);
	m_state[id].m_state = SSHConnectionState::STATE_AUTHENTICATED;
}

/**
	@brief Handles a SSH_MSG_USERAUTH_REQUEST with type "publickey"
 */
void SSHTransportServer::OnRxAuthTypePubkey(int id, TCPTableEntry* socket, SSHUserAuthRequestPacket* req)
{
	const uint32_t nomalglen = 11;

	//If we don't have an authenticator, reject the auth request
	if(m_pubkeyAuth == nullptr)
	{
		//no change to state, still waiting for auth to complete
		OnRxAuthFail(id, socket);
		return;
	}

	//Extract username, and sanity check lengths
	auto uname = req->GetUserNameStart();
	auto ulen = req->GetUserNameLength();
	if(ulen >= SSH_MAX_USERNAME)
	{
		OnRxAuthFail(id, socket);
		return;
	}

	//Service name is ssh-connection, no need to check again
	//auth type is publickey, no need to check again

	//Extract the key algorithm
	auto alg = req->GetAlgorithmStart();
	auto alglen = req->GetAlgorithmLength();
	if(alglen >= SSH_MAX_ALGLEN)
	{
		OnRxAuthFail(id, socket);
		return;
	}

	//Reject any keys that aren't ssh-ed25519
	if(!StringMatchWithLength(g_sshUserKeyAlg, alg, alglen))
	{
		OnRxAuthFail(id, socket);
		return;
	}

	//Extract the key blob itself
	auto keyblob = reinterpret_cast<SSHCurve25519KeyBlob*>(req->GetKeyBlobStart());
	auto keylen = req->GetKeyBlobLength();
	if(keylen > 64)
	{
		OnRxAuthFail(id, socket);
		return;
	}
	keyblob->ByteSwap();

	//Validate the blob and make sure it is a well-formed ssh-ed25519 key
	if(keyblob->m_keyTypeLength != nomalglen)
	{
		//g_cliUART->Printf("Invalid key type length (not %d)\n", alglen);
		OnRxAuthFail(id, socket);
		return;
	}
	if(!StringMatchWithLength(g_sshUserKeyAlg, keyblob->m_keyType, keyblob->m_keyTypeLength))
	{
		//g_cliUART->Printf("Invalid key type (not ssh-ed25519)\n");
		OnRxAuthFail(id, socket);
		return;
	}
	if(keyblob->m_pubKeyLength != 32)
	{
		//g_cliUART->Printf("Invalid pubkey length (not 32)\n");
		OnRxAuthFail(id, socket);
		return;
	}

	//Check against our list of allowed keys
	bool actualAuth = req->IsActualAuthRequest();
	if(!m_pubkeyAuth->CanUseKey(uname, ulen, keyblob, actualAuth))
	{
		//g_cliUART->Printf("Auth provider rejected key\n");
		OnRxAuthFail(id, socket);
		return;
	}

	//Actual authentication
	if(actualAuth)
	{
		//Extract the signature blob
		auto sigblob = reinterpret_cast<SSHCurve25519SignatureBlob*>(req->GetSignatureStart());
		auto siglen = req->GetSignatureLength();
		sigblob->ByteSwap();

		//Outer signature blob length should be 83 bytes
		//(4 byte length, 11 byte algorithm name, 4 byte length, 64 byte signature)
		if(siglen != 83)
		{
			OnRxAuthFail(id, socket);
			return;
		}

		//Validate the blob and make sure it is a well-formed ssh-ed25519 signature blob
		if(sigblob->m_keyTypeLength != nomalglen)
		{
			OnRxAuthFail(id, socket);
			return;
		}
		if(!StringMatchWithLength(g_sshUserKeyAlg, sigblob->m_keyType, sigblob->m_keyTypeLength))
		{
			OnRxAuthFail(id, socket);
			return;
		}

		//After the algorithm wrapper we expect the actual signature, 64 bytes in size
		if(sigblob->m_sigLength != ECDSA_SIG_SIZE)
		{
			OnRxAuthFail(id, socket);
			return;
		}

		//Format the buffer of data being signed
		//see RFC4252 page 10
		unsigned char sigbuf[1024];

		//Add the signature to the end of the message since tweetnacl expects that
		uint32_t offset = 0;
		memcpy(sigbuf + offset, sigblob->m_signature, sigblob->m_sigLength);
		offset += sigblob->m_sigLength;

		//string sessid
		uint32_t tmplen = __builtin_bswap32(SHA256_DIGEST_SIZE);
		memcpy(sigbuf+offset, &tmplen, sizeof(tmplen));
		offset += sizeof(tmplen);
		memcpy(sigbuf+offset, m_state[id].m_sessionID, SHA256_DIGEST_SIZE);
		offset += SHA256_DIGEST_SIZE;

		//constant byte
		sigbuf[offset] = SSHTransportPacket::SSH_MSG_USERAUTH_REQUEST;
		offset ++;

		//username
		tmplen = __builtin_bswap32(ulen);
		memcpy(sigbuf+offset, &tmplen, sizeof(tmplen));
		offset += sizeof(tmplen);
		memcpy(sigbuf+offset, uname, ulen);
		offset += ulen;

		//constant string "ssh-connection"
		uint32_t alen = strlen(g_strConnection);
		tmplen = __builtin_bswap32(alen);
		memcpy(sigbuf+offset, &tmplen, sizeof(tmplen));
		offset += sizeof(tmplen);
		memcpy(sigbuf+offset, g_strConnection, alen);
		offset += alen;

		//constant string "publickey"
		alen = strlen(g_strAuthMethodPubkey);
		tmplen = __builtin_bswap32(alen);
		memcpy(sigbuf+offset, &tmplen, sizeof(tmplen));
		offset += sizeof(tmplen);
		memcpy(sigbuf+offset, g_strAuthMethodPubkey, alen);
		offset += alen;

		//Constant byte
		sigbuf[offset] = 1;
		offset ++;

		//Public key algorithm name
		alen = strlen(g_sshUserKeyAlg);
		tmplen = __builtin_bswap32(alen);
		memcpy(sigbuf+offset, &tmplen, sizeof(tmplen));
		offset += sizeof(tmplen);
		memcpy(sigbuf+offset, g_sshUserKeyAlg, alen);
		offset += alen;

		//The public key blob (have to byte swap lengths again)
		keyblob->ByteSwap();
		alen = 51;
		tmplen = __builtin_bswap32(alen);
		memcpy(sigbuf+offset, &tmplen, sizeof(tmplen));
		offset += sizeof(tmplen);
		memcpy(sigbuf+offset, keyblob, alen);
		offset += alen;
		keyblob->ByteSwap();

		//If signature didn't check out, tell the client and don't authenticate
		if(!m_state[id].m_crypto->VerifySignature(sigbuf, offset, keyblob->m_pubKey))
		{
			OnRxAuthFail(id, socket);
			return;
		}

		//Successful!
		OnRxAuthSuccess(id, uname, ulen, socket);
		m_state[id].m_state = SSHConnectionState::STATE_AUTHENTICATED;
	}

	//Just a query to see if this key is OK to use
	else
	{
		//Report that this key is good
		keyblob->ByteSwap();
		auto segment = m_tcp.GetTxSegment(socket);
		auto packet = reinterpret_cast<SSHTransportPacket*>(segment->Payload());
		packet->m_type = SSHTransportPacket::SSH_MSG_USERAUTH_PK_OK;
		auto buf = packet->Payload();

		//Send the algorithm name
		uint32_t alglenSwap = __builtin_bswap32(nomalglen);
		memcpy(buf, &alglenSwap, sizeof(alglenSwap));
		memcpy(buf + sizeof(uint32_t), g_sshUserKeyAlg, nomalglen);

		//Send the key blob length
		uint32_t bloblenSwap = __builtin_bswap32(keylen);
		uint32_t off = sizeof(uint32_t) + nomalglen;
		memcpy(buf + off, &bloblenSwap, sizeof(bloblenSwap));
		off += sizeof(uint32_t);

		//Send the key blob itself
		memcpy(buf+off, keyblob, keylen);
		off += keylen;

		//Send it
		SendEncryptedPacket(id, off, segment, packet, socket);
	}
}

/**
	@brief Handles a SSH_MSG_CHANNEL_OPEN packet
 */
void SSHTransportServer::OnRxChannelOpen(int id, TCPTableEntry* socket, SSHTransportPacket* packet)
{
	//Only valid in an authenticated session
	if(m_state[id].m_state != SSHConnectionState::STATE_AUTHENTICATED)
	{
		DropConnection(id, socket);
		return;
	}

	//Grab the payload and see what type it is
	auto payload = packet->Payload();
	auto len = __builtin_bswap32(*reinterpret_cast<uint32_t*>(payload));
	if(StringMatchWithLength(g_strSession, reinterpret_cast<const char*>(payload+sizeof(uint32_t)), len))
		OnRxChannelOpenSession(id, socket, reinterpret_cast<SSHSessionRequestPacket*>(payload));

	//Unsupported type, discard it
	else
	{
		auto segment = m_tcp.GetTxSegment(socket);
		auto reply = reinterpret_cast<SSHTransportPacket*>(segment->Payload());
		reply->m_type = SSHTransportPacket::SSH_MSG_CHANNEL_OPEN_FAILURE;
		auto fail = reinterpret_cast<SSHChannelOpenFailurePacket*>(reply->Payload());
		auto client_channel = __builtin_bswap32(*reinterpret_cast<uint32_t*>(payload + len + 4));
		fail->m_clientChannel = client_channel;
		fail->m_reasonCode = SSHChannelOpenFailurePacket::SSH_OPEN_UNKNOWN_CHANNEL_TYPE;
		fail->m_descriptionLengthAlwaysZero = 0;
		fail->m_languageTagAlwaysZero = 0;

		fail->ByteSwap();
		SendEncryptedPacket(id, sizeof(SSHChannelOpenFailurePacket), segment, reply, socket);
	}
}

/**
	@brief Handles a SSH_MSG_CHANNEL_REQUEST packet
 */
void SSHTransportServer::OnRxChannelRequest(int id, TCPTableEntry* socket, SSHTransportPacket* packet)
{
	//Only valid in an authenticated session
	if(m_state[id].m_state != SSHConnectionState::STATE_AUTHENTICATED)
	{
		DropConnection(id, socket);
		return;
	}

	//Grab the payload and verify channel ID and request type length
	auto payload = reinterpret_cast<SSHChannelRequestPacket*>(packet->Payload());
	payload->ByteSwap();
	if( (payload->m_clientChannel != m_state[id].m_sessionChannelID) || (payload->m_requestTypeLength > 256) )
	{
		DropConnection(id, socket);
		return;
	}

	//Check type
	bool ok = true;
	if(StringMatchWithLength(g_strPtyReq, payload->GetRequestTypeStart(), payload->m_requestTypeLength))
		OnRxPtyRequest(id, reinterpret_cast<SSHPtyRequestPacket*>(payload->Payload()));
	else if(
		StringMatchWithLength(g_strEnvReq, payload->GetRequestTypeStart(), payload->m_requestTypeLength) ||
		StringMatchWithLength(g_strEnv, payload->GetRequestTypeStart(), payload->m_requestTypeLength)
		)
	{
		//environment variables are ignored, but we don't error on them
	}
	else if(StringMatchWithLength(g_strShellReq, payload->GetRequestTypeStart(), payload->m_requestTypeLength))
		InitializeShell(id, socket);
	else if(StringMatchWithLength(g_strExec, payload->GetRequestTypeStart(), payload->m_requestTypeLength))
		OnExecRequest(id, socket, reinterpret_cast<SSHExecRequestPacket*>(payload->Payload()));

	else if(StringMatchWithLength(g_strSubsystemReq, payload->GetRequestTypeStart(), payload->m_requestTypeLength))
		ok = OnRxSubsystemRequest(id, reinterpret_cast<SSHSubsystemRequestPacket*>(payload->Payload()));
	else
		ok = false;

	//Unknown/unsupported type
	if(!ok)
	{
		if(payload->WantReply())
		{
			auto segment = m_tcp.GetTxSegment(socket);
			if(!segment)
				return;	//TODO: fail without ACKing?
			auto reply = reinterpret_cast<SSHTransportPacket*>(segment->Payload());
			reply->m_type = SSHTransportPacket::SSH_MSG_CHANNEL_FAILURE;
			auto fail = reinterpret_cast<SSHChannelStatusPacket*>(reply->Payload());
			fail->m_clientChannel = m_state[id].m_sessionChannelID;
			fail->ByteSwap();
			SendEncryptedPacket(id, sizeof(SSHChannelStatusPacket), segment, reply, socket);
		}
		return;
	}

	//Request was successful, acknowledge if client wants us to
	if(payload->WantReply() && (m_state[id].m_sessionChannelID != INVALID_CHANNEL) )
	{
		auto segment = m_tcp.GetTxSegment(socket);
		if(!segment)
			return;	//TODO: fail without ACKing?
		auto reply = reinterpret_cast<SSHTransportPacket*>(segment->Payload());
		reply->m_type = SSHTransportPacket::SSH_MSG_CHANNEL_SUCCESS;
		auto success = reinterpret_cast<SSHChannelStatusPacket*>(reply->Payload());
		success->m_clientChannel = m_state[id].m_sessionChannelID;
		success->ByteSwap();
		SendEncryptedPacket(id, sizeof(SSHChannelStatusPacket), segment, reply, socket);
	}
}

void SSHTransportServer::OnExecRequest(int id, TCPTableEntry* socket, SSHExecRequestPacket* packet)
{
	//Excessively long command length? ignore rest of the packet
	uint16_t cmdlen = packet->GetCommandLength();
	if(cmdlen > 256)
		return;

	//Let the derived class actually do something with the command
	DoExecRequest(id, socket, packet->GetCommandStart(), cmdlen);

	//Done, close the connection
	GracefulDisconnect(id, socket);
}

/**
	@brief Handles an SSH_MSG_CHANNEL_REQUEST of type "pty-req"
 */
void SSHTransportServer::OnRxPtyRequest(int id, SSHPtyRequestPacket* packet)
{
	//Excessively long type length? ignore rest of the packet
	int typelen = packet->GetTermTypeLength();
	if(typelen > 256)
		return;

	m_state[id].m_channelType = SSHConnectionState::CHANNEL_TYPE_PTY;

	//For now, ignore pixel dimensions and terminal type

	//Save character dimensions in the session state
	m_state[id].m_clientWindowWidthChars = packet->GetTermWidthChars();
	m_state[id].m_clientWindowHeightChars = packet->GetTermHeightChars();
}

/**
	@brief Handles an SSH_MSG_CHANNEL_REQUEST of type "subsystem"
 */
bool SSHTransportServer::OnRxSubsystemRequest(int id, SSHSubsystemRequestPacket* packet)
{
	//Excessively long type length? ignore rest of the packet
	int typelen = packet->GetNameLength();
	if(typelen > 256)
		return false;

	//SFTP connection? Allow if we have a SFTP server to handle it
	if(m_sftpServer && StringMatchWithLength(g_strSftp, packet->GetNameStart(), packet->GetNameLength()))
	{
		m_state[id].m_channelType = SSHConnectionState::CHANNEL_TYPE_SFTP;

		m_sftpServer->OnConnectionAccepted(id, m_state[id].m_sftpState);
		return true;
	}

	return false;
}

/**
	@brief Handles a SSH_MSG_CHANNEL_OPEN packet of type "ssh-session"
 */
void SSHTransportServer::OnRxChannelOpenSession(int id, TCPTableEntry* socket, SSHSessionRequestPacket* packet)
{
	//Save the channel ID, but ignore window and max packet size for now
	//We send tiny chunks of data in <2 kB packets, any compliant implementation can handle that
	packet->ByteSwap();
	m_state[id].m_sessionChannelID = packet->m_senderChannel;

	//Send the reply confirming we opened it
	auto segment = m_tcp.GetTxSegment(socket);
	auto reply = reinterpret_cast<SSHTransportPacket*>(segment->Payload());
	reply->m_type = SSHTransportPacket::SSH_MSG_CHANNEL_OPEN_CONFIRMATION;
	auto confirm = reinterpret_cast<SSHChannelOpenConfirmationPacket*>(reply->Payload());
	confirm->m_clientChannel = packet->m_senderChannel;
	confirm->m_serverChannel = 0;
	confirm->m_initialWindowSize = 0xffffffff;	//max sized window
	confirm->m_maxPacketSize = 1024;
	confirm->ByteSwap();
	SendEncryptedPacket(id, sizeof(SSHChannelOpenConfirmationPacket), segment, reply, socket);
}

/**
	@brief Handles a SSH_MSG_CHANNEL_DATA packet
 */
void SSHTransportServer::OnRxChannelData(int id, TCPTableEntry* socket, SSHTransportPacket* packet)
{
	//Only valid in an authenticated session
	if(m_state[id].m_state != SSHConnectionState::STATE_AUTHENTICATED)
	{
		DropConnection(id, socket);
		return;
	}

	auto dpack = reinterpret_cast<SSHChannelDataPacket*>(packet->Payload());
	dpack->ByteSwap();

	//Sanity check packet length
	if(dpack->m_dataLength > ETHERNET_PAYLOAD_MTU)
	{
		DropConnection(id, socket);
		return;
	}

	//Drop anything sent to a bogus channel
	//(this guards against a match to m_shellChannelID before we've initialized the shell, etc)
	if(dpack->m_clientChannel == INVALID_CHANNEL)
	{
		DropConnection(id, socket);
		return;
	}

	//Pass to the appropriate subsystem
	if(dpack->m_clientChannel == m_state[id].m_sessionChannelID)
	{
		switch(m_state[id].m_channelType)
		{
			//shell session
			case SSHConnectionState::CHANNEL_TYPE_PTY:
				OnRxShellData(id, socket, dpack->Payload(), dpack->m_dataLength);
				break;

			//sftp session
			case SSHConnectionState::CHANNEL_TYPE_SFTP:
				if(m_sftpServer)
				{
					if(!m_sftpServer->OnRxData(
						id,
						m_state[id].m_sftpState,
						socket,
						(uint8_t*)dpack->Payload(),
						dpack->m_dataLength))
					{
						DropConnection(id, socket);
					}
				}
				break;

			//no application requested yet, or invalid - don't know what to do with it
			case SSHConnectionState::CHANNEL_TYPE_UNINITIALIZED:
			default:
				break;
		}
	}

	//Invalid channel (not an open one)
	else
		DropConnection(id, socket);

	//TODO: keep track of how much data we've received and send SSH_MSG_CHANNEL_WINDOW_ADJUST
	//to acknowledge it. For now, sending a huge initial window lets us go until we get 4GB of data
	//which is probably more than we'll ever move in an embedded device on a single SSH session
}

/**
	@brief Updates the length etc of a packet, encrypts it, and sends it
 */
void SSHTransportServer::SendEncryptedPacket(
	int id,
	uint16_t length,
	TCPSegment* segment,
	SSHTransportPacket* packet,
	TCPTableEntry* socket)
{
	//Add padding and calculate length
	packet->UpdateLength(length, m_state[id].m_crypto, true);
	auto lenOrig = packet->m_packetLength;
	auto len = lenOrig + sizeof(uint32_t);
	packet->ByteSwap();

	//Encrypt and send it
	m_state[id].m_crypto->EncryptAndMAC(&packet->m_paddingLength, lenOrig);
	m_tcp.SendTxSegment(socket, segment, len + GCM_TAG_SIZE);
}

/**
	@brief Checks if a packet is ready to read, or if it hasn't been fully received yet
 */
bool SSHTransportServer::IsPacketReady(SSHConnectionState& state)
{
	auto& fifo = state.m_rxBuffer;
	auto data = fifo.Rewind();
	auto available = fifo.ReadSize();

	if(available < 4)
		return false;

	uint32_t reallen = __builtin_bswap32(*reinterpret_cast<uint32_t*>(data));

	uint32_t actualPacketSize = 4 + reallen; //extra 4 bytes for the length field itself
	if(state.m_state >= SSHConnectionState::STATE_UNAUTHENTICATED)
		actualPacketSize += GCM_TAG_SIZE;	//need to make sure we have space for the MAC too

	if(available >= actualPacketSize)
		return true;

	//TODO: don't wait forever if client sends a packet bigger than our buffer

	return false;
}

/**
	@brief Returns the packet at the head of the RX FIFO without removing it from the buffer
 */
SSHTransportPacket* SSHTransportServer::PeekPacket(SSHConnectionState& state)
{
	return reinterpret_cast<SSHTransportPacket*>(state.m_rxBuffer.Rewind());
}

/**
	@brief Removes the packet at the head of the RX FIFO
 */
void SSHTransportServer::PopPacket(SSHConnectionState& state)
{
	auto& fifo = state.m_rxBuffer;

	//By this point the header is decrypted and in host byte order, so it's easy.
	//Just need to account for the 4-byte length field and (if present) the MAC.
	uint16_t poplen = *reinterpret_cast<uint32_t*>(fifo.Rewind()) + 4;
	if(state.m_macPresent)
		poplen += GCM_TAG_SIZE;

	fifo.Pop(poplen);
}
