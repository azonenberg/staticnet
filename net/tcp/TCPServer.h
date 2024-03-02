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
	@brief Declaration of TCPServer
 */
#ifndef TCPServer_h
#define TCPServer_h

/**
	@brief Helper class for implementing TCP servers

	The context type must contain the following members / methods:
		void Clear()
		bool m_valid
		TCPTableEntry* m_socket
 */
template<int MAXCONNS, class ContextType>
class TCPServer
{
public:
	TCPServer(TCPProtocol& tcp)
		: m_tcp(tcp)
	{
	}

	virtual ~TCPServer()
	{}

	virtual void OnConnectionAccepted(TCPTableEntry* socket) =0;
	virtual void OnConnectionClosed(TCPTableEntry* socket) =0;
	virtual bool OnRxData(TCPTableEntry* socket, uint8_t* payload, uint16_t payloadLen) =0;
	virtual void GracefulDisconnect(int id, TCPTableEntry* socket) =0;

	TCPSegment* GetTxSegment(TCPTableEntry* socket)
	{ return m_tcp.GetTxSegment(socket); }

protected:

	/**
		@brief Finds the connection ID for a TCP socket, or returns -1 if it's not a currently connected session
	 */
	int GetConnectionID(TCPTableEntry* socket)
	{
		//Just a linear search for now
		for(int i=0; i<MAXCONNS; i++)
		{
			if(m_state[i].m_valid && (m_state[i].m_socket == socket))
				return i;
		}

		return -1;
	}

	/**
		@brief Allocates a new connection ID for a connection, or returns -1 if there are no free table entries
	 */
	virtual int AllocateConnectionID(TCPTableEntry* socket)
	{
		for(int i=0; i<MAXCONNS; i++)
		{
			if(!m_state[i].m_valid)
			{
				m_state[i].Clear();
				m_state[i].m_valid = true;
				m_state[i].m_socket = socket;
				return i;
			}
		}

		return -1;
	}

protected:

	///@brief The transport layer for our traffic
	TCPProtocol& m_tcp;

	///@brief Context data for connected clients
	ContextType m_state[MAXCONNS];
};

#endif

