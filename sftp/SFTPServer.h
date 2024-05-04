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

#ifndef SFTPServer_h
#define SFTPServer_h

#ifndef SFTP_RX_BUFFER_SIZE
#define SFTP_RX_BUFFER_SIZE 4096
#endif

#ifndef MAX_PATH
#define MAX_PATH 128
#endif

#include "SFTPPacket.h"
#include "../util/CircularFIFO.h"

class SSHTransportServer;

class SFTPConnectionState
{
public:
	SFTPConnectionState()
	{ Clear(); }

	void Clear()
	{
		m_rxBuffer.Reset();
		m_protocolVersion = 0;

		m_hugePacketInProgress = false;
		m_hugePacketType = SFTPPacket::SSH_FXP_INIT;
		m_hugePacketTotalLength = 0;
		m_hugePacketBytesSoFar = 0;
		m_hugePacketRequestID = 0;
		m_writeHandle = 0;
		m_writeOffset = 0;
		m_writeBytesSoFar = 0;
		m_writeLength = 0;
	};

	///@brief Packet reassembly buffer (may span multiple TCP segments)
	CircularFIFO<SFTP_RX_BUFFER_SIZE> m_rxBuffer;

	///@brief Protocol version in use for this connection
	uint32_t m_protocolVersion;

	//Huge packet handling
	bool m_hugePacketInProgress;
	SFTPPacket::PacketType m_hugePacketType;
	uint32_t m_hugePacketTotalLength;
	uint32_t m_hugePacketBytesSoFar;
	uint32_t m_hugePacketRequestID;
	uint32_t m_writeHandle;
	uint64_t m_writeOffset;
	uint32_t m_writeBytesSoFar;
	uint32_t m_writeLength;
};

class SFTPInitPacket;
class SFTPStatPacket;
class SFTPOpenPacket;
class SFTPClosePacket;

#include "SFTPStatusPacket.h"

/**
	@brief Server for the SFTP protocol
 */
class SFTPServer
{
public:
	SFTPServer();
	virtual ~SFTPServer();

	virtual void OnConnectionAccepted(int id, SFTPConnectionState* state);
	bool OnRxData(int id, SFTPConnectionState* state, TCPTableEntry* socket, uint8_t* data, uint16_t len);
	virtual void OnConnectionClosed(int id);

	void UseSSH(SSHTransportServer* ssh)
	{ m_ssh = ssh; }

protected:

	//Message buffering
	bool IsPacketReady(SFTPConnectionState* state);
	bool IsHugePacketReady(SFTPConnectionState* state);
	void StartHugePacket(
		int id,
		TCPTableEntry* socket,
		uint32_t requestid,
		SFTPConnectionState* state,
		SFTPPacket* header);
	void OnHugePacketRxData(int id, SFTPConnectionState* state, TCPTableEntry* socket);
	void OnHugePacketRxData(int id, SFTPConnectionState* state, TCPTableEntry* socket, uint8_t* data, uint32_t len);
	void OnHugePacketWriteData(int id, SFTPConnectionState* state, TCPTableEntry* socket, uint8_t* data, uint32_t len);
	void OnRxPacket(int id, SFTPConnectionState* state, TCPTableEntry* socket, SFTPPacket* pack);

	//Handlers for packet types
	void OnRxInit(int id, SFTPConnectionState* state, TCPTableEntry* socket, SFTPInitPacket* pack);
	void OnRxStat(int id, SFTPConnectionState* state, TCPTableEntry* socket, SFTPStatPacket* pack);
	void OnRxOpen(int id, SFTPConnectionState* state, TCPTableEntry* socket, SFTPOpenPacket* pack);
	void OnRxClose(int id, SFTPConnectionState* state, TCPTableEntry* socket, SFTPClosePacket* pack);

	//Filesystem interface APIs

	/**
		@brief Checks if a file exists without actually trying to open it
	 */
	virtual bool DoesFileExist(const char* path) =0;

	/**
		@brief Checks if the SFTP user is allowed to open the specified file with some access rights
	 */
	virtual bool CanOpenFile(const char* path, uint32_t accessMask, uint32_t flags) =0;

	/**
		@brief Opens a file and returns a handle to it
	 */
	virtual uint32_t OpenFile(const char* path, uint32_t accessMask, uint32_t flags) =0;

	/**
		@brief Writes a chunk of data to an open handle
	 */
	virtual void WriteFile(uint32_t handle, uint64_t offset, const uint8_t* data, uint32_t len) =0;

	/**
		@brief Closes a file
	 */
	virtual bool CloseFile(uint32_t handle) =0;

	//Outbound packet generation
	void SendPacket(int id, TCPTableEntry* socket, SFTPPacket::PacketType type, const uint8_t* data, uint16_t len);
	void SendHandleReply(int id, TCPTableEntry* socket, uint32_t requestid, uint32_t handle);
	void SendStatusReply(int id, TCPTableEntry* socket, uint32_t requestid, SFTPStatusPacket::Status code);

	SSHTransportServer* m_ssh;
};

#endif
