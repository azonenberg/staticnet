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
#include "SSHKexInitPacket.h"
#include "SSHKexEcdhInitPacket.h"
#include "SSHKexEcdhReplyPacket.h"
#include "SSHServiceRequestPacket.h"
#include "SSHUserAuthRequestPacket.h"

//Our single supported cipher suite
static const char* g_sshKexAlg				= "curve25519-sha256";				//RFC 8731
static const char* g_sshHostKeyAlg			= "ssh-ed25519";
static const char* g_sshEncryptionAlg		= "aes128-gcm@openssh.com";
static const char* g_sshMacAlg				= "none";	//implicit in GCM
static const char* g_sshCompressionAlg		= "none";

//Other global strings for magic values
static const char* g_strUserAuth			= "ssh-userauth";
static const char* g_strConnection			= "ssh-connection";
static const char* g_strAuthTypeQuery		= "none";
static const char* g_authMethodList			= "password";
static const char* g_strAuthMethodPassword	= "password";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Construction / destruction

SSHTransportServer::SSHTransportServer(TCPProtocol& tcp)
	: m_tcp(tcp)
{
}

SSHTransportServer::~SSHTransportServer()
{
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Event handlers

/**
	@brief Allocates a new connection ID for a connection, or returns -1 if there are no free table entries
 */
int SSHTransportServer::AllocateConnectionID(TCPTableEntry* socket)
{
	for(int i=0; i<SSH_TABLE_SIZE; i++)
	{
		if(!m_state[i].m_valid)
		{
			//Make sure old state is completely wiped
			m_state[i].Clear();

			m_state[i].m_valid = true;
			m_state[i].m_socket = socket;
			return i;
		}
	}

	return -1;
}

/**
	@brief Finds the connection ID for a TCP socket, or returns -1 if it's not a currently connected session
 */
int SSHTransportServer::GetConnectionID(TCPTableEntry* socket)
{
	//Just a linear search for now
	for(int i=0; i<SSH_TABLE_SIZE; i++)
	{
		if(m_state[i].m_valid && (m_state[i].m_socket == socket))
			return i;
	}

	return -1;
}

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
		return false;

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
	@brief Silently drops a connection due to a protocol error or similar
 */
void SSHTransportServer::DropConnection(int id, TCPTableEntry* socket)
{
	m_state[id].Clear();
	m_tcp.CloseSocket(socket);
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
		case SSHTransportPacket::SSH_MSG_IGNORE:
			OnRxIgnore(id, socket, pack);
			break;

		case SSHTransportPacket::SSH_MSG_SERVICE_REQUEST:
			OnRxServiceRequest(id, socket, pack);
			break;

		case SSHTransportPacket::SSH_MSG_USERAUTH_REQUEST:
			OnRxUserAuthRequest(id, socket, pack);
			break;

		default:
			printf("Got unexpected packet (type %d)\n", pack->m_type);
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

	else
		printf("Got SSH_MSG_SERVICE_REQUEST (%s)\n", payload);
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

	m_state[id].m_state = SSHConnectionState::STATE_AUTH_BEGIN;
}

/**
	@brief Handle a SSH_MSG_USERAUTH_REQUEST packet
 */
void SSHTransportServer::OnRxUserAuthRequest(int id, TCPTableEntry* socket, SSHTransportPacket* packet)
{
	//verify state
	if(m_state[id].m_state != SSHConnectionState::STATE_AUTH_BEGIN)
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

	//debug print, unknown type
	else
	{
		char tmp_type[32] = {0};
		if(authlen > 31)
			authlen = 31;
		memcpy(tmp_type, authtype, authlen);
		printf("SSH_MSG_USERAUTH_REQUEST of type %s\n", tmp_type);
	}
}

/**
	@brief Handles a SSH_MSG_USERAUTH_REQUEST with type "none"
 */
void SSHTransportServer::OnRxAuthTypeQuery(int id, TCPTableEntry* socket)
{
	//Send a canned acceptance reply
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

	//no change to state, still waiting for auth to complete
}

/**
	@brief Handles a SSH_MSG_USERAUTH_REQUEST with type "password"
 */
void SSHTransportServer::OnRxAuthTypePassword(int id, TCPTableEntry* socket, SSHUserAuthRequestPacket* req)
{
	const int string_max = 1024;

	auto uname = req->GetUserNameStart();
	auto ulen = req->GetUserNameLength();
	if(ulen > string_max)
	{
		DropConnection(id, socket);
		return;
	}
	auto pass = req->GetPasswordStart();
	auto passlen = req->GetPasswordLength();
	if( ((pass - uname) + passlen) > string_max)
	{
		DropConnection(id, socket);
		return;
	}

	/*
	//debug prints
	char tmp_user[32] = {0};
	if(ulen > 31)
		ulen = 31;
	memcpy(tmp_user, uname, ulen);

	char tmp_pass[32] = {0};
	if(passlen > 31)
		passlen = 31;
	memcpy(tmp_pass, pass, passlen);

	printf("SSH_MSG_USERAUTH_REQUEST (user=%s, password=%s)\n", tmp_user, tmp_pass);
	*/
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
	if(available >= (4+reallen))	//extra 4 bytes for the length field itself
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
