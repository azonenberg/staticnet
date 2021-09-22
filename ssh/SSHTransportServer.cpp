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

//Our single supported cipher suite
static const char* g_sshKexAlg			= "curve25519-sha256";				//RFC 8731
static const char* g_sshHostKeyAlg		= "ssh-ed25519";
static const char* g_sshEncryptionAlg	= "aes128-gcm@openssh.com";
static const char* g_sshMacAlg			= "none";	//implicit in GCM
static const char* g_sshCompressionAlg	= "none";

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

			default:
				printf("unknown state\n");
				break;
		}

		//Whatever it was, we're done with it. On to th enext one.
		PopPacket(m_state[id]);
	}

	return true;
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
		{
			m_state[id].Clear();
			m_tcp.CloseSocket(socket);
		}

		return;
	}

	//Version should be "SSH-2.0-clientswversion(optional other stuff)\r\n"
	//If it's not a SSH2 client, give up
	if(memcmp(banner, "SSH-2.0", 7) != 0)
	{
		//Close our state
		m_state[id].Clear();
		m_tcp.CloseSocket(socket);
		return;
	}

	//Ignore client software version, we don't implement any quirks

	//Send our banner to the client
	static const char server_banner[] = "SSH-2.0-staticnet_0.1\r\n";
	auto segment = m_tcp.GetTxSegment(socket);
	auto payload = segment->Payload();
	strncpy((char*)payload, server_banner, TCP_IPV4_PAYLOAD_MTU);
	m_tcp.SendTxSegment(socket, segment, sizeof(server_banner)-1);
	m_state[id].m_state = SSHConnectionState::STATE_BANNER_SENT;

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
	pack->ByteSwap();
	if(pack->m_type != SSHTransportPacket::SSH_MSG_KEXINIT)
	{
		m_state[id].Clear();
		m_tcp.CloseSocket(socket);
		return;
	}

	//Validate the inbound kex init packet
	auto kexInit = reinterpret_cast<SSHKexInitPacket*>(pack->Payload());
	if(!ValidateKexInit(kexInit))
	{
		m_state[id].Clear();
		m_tcp.CloseSocket(socket);
		return;
	}

	//TODO: save the nonce from the kex init packet

	//Prepare to reply with a key exchange init packet
	auto segment = m_tcp.GetTxSegment(socket);
	auto packet = reinterpret_cast<SSHTransportPacket*>(segment->Payload());
	packet->m_type = SSHTransportPacket::SSH_MSG_KEXINIT;

	//Set up the nonce
	auto replyStart = packet->Payload();
	auto kexOut = reinterpret_cast<SSHKexInitPacket*>(replyStart);
	m_state[id].m_crypto->GenerateRandom(kexOut->m_cookie, sizeof(kexOut->m_cookie));
	//TODO: save the nonce so we can use it for the actual key exchange

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
	packet->ByteSwap();

	//Done, send it
	m_tcp.SendTxSegment(socket, segment, len);
	m_state[id].m_state = SSHConnectionState::STATE_KEX_INIT_SENT;
}

/**
	@brief Verifies an inbound SSH_MSG_KEXINIT packet contains our supported cipher suite
 */
bool SSHTransportServer::ValidateKexInit(SSHKexInitPacket* kex)
{
	//First name list: kex algorithms
	auto offset = kex->GetFirstNameListStart();
	if(!kex->NameListContains(offset, g_sshKexAlg))
		return false;

	//Server host key algorithms
	offset = kex->GetNextNameListStart(offset);
	if(!kex->NameListContains(offset, g_sshHostKeyAlg))
		return false;

	//Encryption algorithms (client to server)
	offset = kex->GetNextNameListStart(offset);
	if(!kex->NameListContains(offset, g_sshEncryptionAlg))
		return false;

	//Encryption algorithms (server to client)
	offset = kex->GetNextNameListStart(offset);
	if(!kex->NameListContains(offset, g_sshEncryptionAlg))
		return false;

	//MAC algorithms (client to server)
	//Ignore this, AEAD modes don't use a MAC (client may not actually advertise "none")
	offset = kex->GetNextNameListStart(offset);

	//MAC algorithms (server to client)
	//Ignore this, AEAD modes don't use a MAC (client may not actually advertise "none")
	offset = kex->GetNextNameListStart(offset);

	//Compression algorithms (client to server)
	offset = kex->GetNextNameListStart(offset);
	if(!kex->NameListContains(offset, g_sshCompressionAlg))
		return false;

	//Compression algorithms (server to client)
	offset = kex->GetNextNameListStart(offset);
	if(!kex->NameListContains(offset, g_sshCompressionAlg))
		return false;

	//Languages (client to server)
	//Ignore this, we don't support any language extensions
	offset = kex->GetNextNameListStart(offset);

	//Languages (server to client)
	//Ignore this, we don't support any language extensions
	offset = kex->GetNextNameListStart(offset);

	//first kex packet follows (not supported)
	offset = kex->GetNextNameListStart(offset);
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
	//Read the packet and make sure it's the right type. If not, drop the connection
	auto pack = PeekPacket(m_state[id]);
	pack->ByteSwap();
	if(pack->m_type != SSHTransportPacket::SSH_MSG_KEX_ECDH_INIT)
	{
		m_state[id].Clear();
		m_tcp.CloseSocket(socket);
		return;
	}

	//Validate public key size
	auto kexEcdh = reinterpret_cast<SSHKexEcdhInitPacket*>(pack->Payload());
	kexEcdh->ByteSwap();
	if(kexEcdh->m_length != 32)
	{
		m_state[id].Clear();
		m_tcp.CloseSocket(socket);
		return;
	}

	//TODO: save client's ephemeral public key so we can use it

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
	kexOut->m_hostKeyPublicLength = 32;
	kexOut->m_ephemeralKeyPublicLength = 32;
	kexOut->m_signatureBlobLength = 83;
	kexOut->m_signatureTypeLength = 11;
	memcpy(kexOut->m_signatureType, g_sshHostKeyAlg, 11);
	kexOut->m_signatureLength = 64;

	//Generate the ephemeral ECDH key
	m_state[id].m_crypto->GenerateX25519KeyPair(kexOut->m_ephemeralKeyPublic);

	//Calculate the shared secret between the client and server ephemeral keys

	//Generate the exchange hash (SHA256)

	/*
	string   V_C, client's identification string (CR and LF excluded)
	string   V_S, server's identification string (CR and LF excluded)
	string   I_C, payload of the client's SSH_MSG_KEXINIT
	string   I_S, payload of the server's SSH_MSG_KEXINIT
	string   K_S, server's public host key
	string   Q_C, client's ephemeral public key octet string
	string   Q_S, server's ephemeral public key octet string
	mpint    K,   shared secret
	*/

	//Sign exchange key
	//for now, use all zero signature
	memset(kexOut->m_signature, 0, 64);

	//Add padding and calculate length
	kexOut->ByteSwap();
	packet->UpdateLength(sizeof(SSHKexEcdhReplyPacket), m_state[id].m_crypto);
	auto len = packet->m_packetLength + sizeof(uint32_t);
	packet->ByteSwap();

	//Done, send it
	m_tcp.SendTxSegment(socket, segment, len);

	m_state[id].m_state = SSHConnectionState::STATE_KEX_ECDHINIT_SENT;
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
	//By this point the header is decrypted and in host byte order, so it's easy
	auto& fifo = state.m_rxBuffer;
	fifo.Pop(*reinterpret_cast<uint32_t*>(fifo.Rewind()) + 4);	//add 4 for length field itself
}
