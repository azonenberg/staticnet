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

#include "bridge.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Construction / destruction

BridgeSSHTransportServer::BridgeSSHTransportServer(TCPProtocol& tcp)
	: SSHTransportServer(tcp)
{
	//Initialize crypto engines
	for(size_t i=0; i<SSH_TABLE_SIZE; i++)
		m_state[i].m_crypto = new BridgeCryptoEngine;

	UsePasswordAuthenticator(&m_auth);
}

BridgeSSHTransportServer::~BridgeSSHTransportServer()
{
	//Clean up crypto state
	for(size_t i=0; i<SSH_TABLE_SIZE; i++)
	{
		delete m_state[i].m_crypto;
		m_state[i].m_crypto = NULL;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Run a trivial shell

void BridgeSSHTransportServer::InitializeShell(int id, TCPTableEntry* socket)
{
	m_context[id].Reset();
	const char* prompt = "shell> ";
	SendSessionData(id, socket, prompt, strlen(prompt));
}

void BridgeSSHTransportServer::OnRxShellData(int id, TCPTableEntry* socket, char* data, uint16_t len)
{
	for(uint16_t i=0; i<len; i++)
		OnRxShellKeystroke(id, socket, data[i]);
}

void BridgeSSHTransportServer::OnRxShellKeystroke(int id, TCPTableEntry* socket, char c)
{
	auto& ctx = m_context[id];

	//Backspace
	if(c == '\b')
	{
		printf("Backspace\n");

		//Start of line? Nothing to do
		if(ctx.m_position == 0)
		{
		}

		//back up
		else
		{
			const char* backspace = "\b \b";
			SendSessionData(id, socket, backspace, strlen(backspace));
			ctx.m_position --;
		}
	}

	else if( (c == '\n') || (c == '\r') )
	{
		const char* msg = "\r\nYou typed a command!\r\nshell> ";
		SendSessionData(id, socket, msg, strlen(msg));

		if(!strcmp(ctx.m_linebuf, "exit"))
			GracefulDisconnect(id, socket);

		ctx.m_position = 0;
		memset(ctx.m_linebuf, 0, sizeof(ctx.m_linebuf));
	}

	//normal character
	else if(isprint(c) || isspace(c))
	{
		//End of buffer? nothing to do
		if(ctx.m_position >= 62)
		{
		}

		ctx.m_linebuf[ctx.m_position] = c;
		ctx.m_position ++;

		//echo it
		SendSessionData(id, socket, &c, 1);
	}
}
