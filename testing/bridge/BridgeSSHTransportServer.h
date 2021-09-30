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
	@brief Declaration of BridgeSSHTransportServer
 */
#ifndef BridgeSSHTransportServer_h
#define BridgeSSHTransportServer_h

#include <ssh/SSHTransportServer.h>
#include "BridgePasswordAuthenticator.h"

class SimpleShellContext
{
public:
	SimpleShellContext()
	{ Reset(); }

	void Reset()
	{
		m_position = 0;
		memset(m_linebuf, 0, sizeof(m_linebuf));
	}

	char m_linebuf[64];
	int m_position;
};

/**
	@brief SSH server class for the bridge test
 */
class BridgeSSHTransportServer : public SSHTransportServer
{
public:
	BridgeSSHTransportServer(TCPProtocol& tcp);
	virtual ~BridgeSSHTransportServer();

protected:
	virtual void InitializeShell(int id, TCPTableEntry* socket);
	virtual void OnRxShellData(int id, TCPTableEntry* socket, char* data, uint16_t len);

	void OnRxShellKeystroke(int id, TCPTableEntry* socket, char c);

	BridgePasswordAuthenticator m_auth;

	SimpleShellContext m_context[SSH_TABLE_SIZE];
};

#endif
