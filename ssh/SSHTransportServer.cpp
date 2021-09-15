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

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Construction / destruction

SSHTransportServer::SSHTransportServer(TCPProtocol& tcp)
	: m_tcp(tcp)
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

	static const char banner[] = "SSH-2.0-staticnet_0.1\r\n";

	//Send our banner to the client
	auto segment = m_tcp.GetTxSegment(socket);
	auto payload = segment->Payload();
	strncpy((char*)payload, banner, TCP_IPV4_PAYLOAD_MTU);
	m_tcp.SendTxSegment(socket, segment, sizeof(banner)-1);

	m_state[id].m_state = SSHConnectionState::STATE_BANNER_SENT;
}

/**
	@brief Handler for incoming TCP segments
 */
void SSHTransportServer::OnRxData(TCPTableEntry* socket, uint8_t* payload, uint16_t payloadLen)
{
	//Look up the connection ID for the incoming session
	auto id = GetConnectionID(socket);
	if(id < 0)
		return;

	//Figure out what state we're in so we know what to expect
	switch(m_state[id].m_state)
	{
		case SSHConnectionState::STATE_BANNER_SENT:
			OnRxBanner(id, socket, payload, payloadLen);
			break;

		default:
			printf("unknown state\n");
			break;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Handle inbound protocol data

/**
	@brief Handler for an incoming version banner
 */
void SSHTransportServer::OnRxBanner(int id, TCPTableEntry* socket, uint8_t* payload, uint16_t /*payloadLen*/)
{
	//Version should be "SSH-2.0-clientswversion(optional other stuff)\r\n"
	//If it's not a SSH2 client, give up
	if(strstr(reinterpret_cast<const char*>(payload), "SSH-2.0") != reinterpret_cast<const char*>(payload))
	{
		//Close our state
		m_state[id].Clear();
		m_tcp.CloseSocket(socket);
		return;
	}

	//Ignore client software version otherwise

	//Prepare the key exchange init packet
	auto segment = m_tcp.GetTxSegment(socket);
	auto payload = segment->Payload();

	//0-3: packet length TBD
	//4: padding length TBD

	//5: type

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
	m_tcp.SendTxSegment(socket, segment, sizeof(banner)-1);
	m_state[id].m_state = STATE_KEX_INIT_SENT;
}
