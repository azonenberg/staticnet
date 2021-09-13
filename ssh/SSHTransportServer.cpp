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
int SSHTransportServer::AllocateConnectionID(TCPTableEntry* state)
{
	for(int i=0; i<SSH_TABLE_SIZE; i++)
	{
		if(!m_state[i].m_valid)
		{
			m_state[i].m_valid = true;
			m_state[i].m_socket = state;
			return i;
		}
	}

	return -1;
}

int SSHTransportServer::GetConnectionID(TCPTableEntry* state)
{
	return -1;
}

/**
	@brief Handles a newly accepted connection
 */
void SSHTransportServer::OnConnectionAccepted(TCPTableEntry* state)
{
	//Make a new entry in the socket state table
	int id = AllocateConnectionID(state);
	if(id < 0)
		return;

	static const char banner[] = "SSH-2.0-staticnet_0.1\r\n";

	//Send our banner to the client
	auto segment = m_tcp.GetTxSegment(state);
	auto payload = segment->Payload();
	strncpy((char*)payload, banner, TCP_IPV4_PAYLOAD_MTU);
	m_tcp.SendTxSegment(state, segment, sizeof(banner)-1);
}

void SSHTransportServer::OnRxData(TCPTableEntry* state, uint8_t* payload, uint16_t payloadLen)
{
}
