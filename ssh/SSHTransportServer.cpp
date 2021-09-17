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

	/*
		TODO: the dispatch code below assumes that multiple TCP segments can be combined into a single SSH PDU,
		but only calls the parsers once per TCP segment. This means that if two SSH PDUs occupy a single TCP segment,
		the second PDU will not be processed until another TCP segment arrives.
	 */

	//Figure out what state we're in so we know what to expect
	switch(m_state[id].m_state)
	{
		//Wait for the incoming banner
		case SSHConnectionState::STATE_BANNER_WAIT:
			OnRxBanner(id, socket);
			break;

		//Wait for the incoming key exchange request
		case SSHConnectionState::STATE_BANNER_SENT:
			OnRxKexInit(id, socket);
			break;

		default:
			printf("unknown state\n");
			break;
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
	//Wait until we have a whole packet ready to read
	if(!IsPacketReady(m_state[id]))
		return;

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
	if(!ValidateKexInit(id, kexInit))
	{
		m_state[id].Clear();
		m_tcp.CloseSocket(socket);
		return;
	}

	//TODO: save the nonce from the kex init packet

	//Prepare to reply with a key exchange init packet
	/*
	auto segment = m_tcp.GetTxSegment(socket);
	auto packet = reinterpret_cast<SSHTransportPacket*>(segment->Payload());


	//Fill out the contents
	uint16_t len = 0;
	packet->m_type = SSHTransportPacket::SSH_MSG_KEXINIT;

	//Add padding and calculate length
	packet->UpdateLength(len, m_state[id].m_serverToClientCrypto);
	packet->ByteSwap();

	//0-3: packet length TBD
	//4: padding length TBD

	//5: type
	*/
	/*
		Crypto negotiation header

		uint32_t packet_length
		uint8_t padding_length (must be at least 4)
		payload
			byte type = SSH_MSG_KEXINIT
			byte[16] random_cookie
			name-list kex_algorithms
				uint32_t length
				curve25519-sha256
			name-list server_host_key_algorithms
				uint32_t length
				ssh-ed25519
			name-list encryption_algorithms_client_to_server
				uint32_t length
				aes128-gcm@openssh.com
			name-list encryption_algorithms_server_to_client
				uint32_t length
				aes128-gcm@openssh.com
			name-list mac_algorithms_client_to_server
				uint32_t length
				none
			name-list mac_algorithms_server_to_client
				uint32_t length
				none
			name-list compression_algorithms_client_to_server
				uint32_t length
				none
			name-list compression_algorithms_server_to_client
				uint32_t length
				none
			name-list languages_client_to_server
				uint32_t length = 0
			name-list languages_server_to_client
				uint32_t length = 0
			bool	first_kext_packet_follows = 0
			uint32 reserved = 0
		uint8_t padding[]
		(no mac yet)

		Total packet length after padding must be a multiple of 8
	 */

	//Done, send it
	//m_tcp.SendTxSegment(socket, segment, sizeof(banner)-1);
	m_state[id].m_state = SSHConnectionState::STATE_KEX_INIT_SENT;

	//Done, pop the packet
	PopPacket(m_state[id]);
}

/**
	@brief Verifies an inbound SSH_MSG_KEXINIT packet contains our supported cipher suite
 */
bool SSHTransportServer::ValidateKexInit(int id, SSHKexInitPacket* kex)
{
	//First name list: kex algorithms
	auto offset = kex->GetFirstNameListStart();
	if(!kex->NameListContains(offset, "curve25519-sha256"))
		return false;

	//Server host key algorithms
	offset = kex->GetNextNameListStart(offset);
	if(!kex->NameListContains(offset, "ssh-ed25519"))
		return false;

	//Encryption algorithms (client to server)
	offset = kex->GetNextNameListStart(offset);
	if(!kex->NameListContains(offset, "aes128-gcm@openssh.com"))
		return false;

	//Encryption algorithms (server to client)
	offset = kex->GetNextNameListStart(offset);
	if(!kex->NameListContains(offset, "aes128-gcm@openssh.com"))
		return false;

	//MAC algorithms (client to server)
	//Ignore this, AEAD modes don't use a MAC
	offset = kex->GetNextNameListStart(offset);

	//MAC algorithms (server to client)
	//Ignore this, AEAD modes don't use a MAC
	offset = kex->GetNextNameListStart(offset);

	//Compression algorithms (client to server)
	offset = kex->GetNextNameListStart(offset);
	if(!kex->NameListContains(offset, "none"))
		return false;

	//Compression algorithms (server to client)
	offset = kex->GetNextNameListStart(offset);
	if(!kex->NameListContains(offset, "none"))
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
	@brief Checks if a packet is ready to read, or if it hasn't been fully received yet
 */
bool SSHTransportServer::IsPacketReady(SSHConnectionState& state)
{
	//TODO: This gets extra fun in the case of encrypted packets... because the length is encrypted!
	//How do we know if we decrypted the header or not during a multi segment packet?

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
	fifo.Pop(*reinterpret_cast<uint32_t*>(fifo.Rewind()));
}
