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

#include "../stack/staticnet.h"
#include "SFTPServer.h"
#include "../ssh/SSHTransportServer.h"

#include <algorithm>

#include "SFTPClosePacket.h"
#include "SFTPHandlePacket.h"
#include "SFTPInitPacket.h"
#include "SFTPOpenPacket.h"
#include "SFTPStatPacket.h"
#include "SFTPVersionPacket.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Construction / destruction

SFTPServer::SFTPServer()
	: m_ssh(nullptr)
{
}

SFTPServer::~SFTPServer()
{
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SFTP protocol logic

void SFTPServer::OnConnectionAccepted([[maybe_unused]] int id, SFTPConnectionState* state)
{
	state->m_hugePacketInProgress = false;
}

/**
	@brief Handles incoming data on the SSH data stream
 */
bool SFTPServer::OnRxData(int id, SFTPConnectionState* state, TCPTableEntry* socket, uint8_t* data, uint16_t len)
{
	//Push the data into our RX FIFO
	if(!state->m_rxBuffer.Push(data, len))
		return false;

	//Huge packets (bigger than our RX buffer) get special processing
	if(state->m_hugePacketInProgress)
		OnHugePacketRxData(id, state, socket);

	//Need to check again, since we might have ended a huge packet and still have data in the buffer
	if(!state->m_hugePacketInProgress)
	{
		//Pop full packets out of the buffer, byte swap, and process them as they come in
		while(IsPacketReady(state))
		{
			auto pack = reinterpret_cast<SFTPPacket*>(state->m_rxBuffer.Rewind());
			pack->ByteSwap();
			OnRxPacket(id, state, socket, pack);
			state->m_rxBuffer.Pop(pack->m_length + sizeof(uint32_t));
		}

		//If we have an incoming packet with size too big for the buffer, handle that as soon as we get the header
		if(IsHugePacketReady(state))
		{
			auto pack = reinterpret_cast<SFTPPacket*>(state->m_rxBuffer.Rewind());
			pack->ByteSwap();
			auto requestid = __builtin_bswap32(*reinterpret_cast<uint32_t*>(pack->Payload()));
			StartHugePacket(id, socket, requestid, state, pack);
		}
	}

	//all good
	return true;
}

/**
	@brief Handles a single SFTP packet
 */
void SFTPServer::OnRxPacket(int id, SFTPConnectionState* state, TCPTableEntry* socket, SFTPPacket* pack)
{
	//See what we got
	switch(pack->m_type)
	{
		case SFTPPacket::SSH_FXP_INIT:
			{
				auto payload = reinterpret_cast<SFTPInitPacket*>(pack->Payload());
				payload->ByteSwap();
				OnRxInit(id, state, socket, payload);
			}
			break;

		case SFTPPacket::SSH_FXP_STAT:
		case SFTPPacket::SSH_FXP_LSTAT:
			{
				auto payload = reinterpret_cast<SFTPStatPacket*>(pack->Payload());
				payload->ByteSwap();
				OnRxStat(id, state, socket, payload);
			}
			break;

		case SFTPPacket::SSH_FXP_OPEN:
			{
				auto payload = reinterpret_cast<SFTPOpenPacket*>(pack->Payload());
				payload->ByteSwap();
				OnRxOpen(id, state, socket, payload);
			}
			break;

		case SFTPPacket::SSH_FXP_CLOSE:
			{
				auto payload = reinterpret_cast<SFTPClosePacket*>(pack->Payload());
				payload->ByteSwap();
				OnRxClose(id, state, socket, payload);
			}
			break;

		//TODO: handle non-huge writes!

		//Silently discard fsetstat but pretend it worked
		case SFTPPacket::SSH_FXP_FSETSTAT:
			{
				auto requestid = __builtin_bswap32(*reinterpret_cast<uint32_t*>(pack->Payload()));
				SendStatusReply(id, socket, requestid, SFTPStatusPacket::SSH_FX_OK);
			}
			break;

		//Anything else is unsupported
		default:
			{
				//g_cliUART.Printf("Got unimplemented/unsupported packet (type %d, len %d)\n",
				//	pack->m_type, pack->m_length);
				auto requestid = __builtin_bswap32(*reinterpret_cast<uint32_t*>(pack->Payload()));
				SendStatusReply(id, socket, requestid, SFTPStatusPacket::SSH_FX_OP_UNSUPPORTED);
			}
			break;
	}
}

/**
	@brief Handle a SSH_FXP_INIT packet
 */
void SFTPServer::OnRxInit(int id, SFTPConnectionState* state, TCPTableEntry* socket, SFTPInitPacket* pack)
{
	//Negotiate the protocol version to use
	state->m_protocolVersion = std::min((uint32_t)6, pack->m_version);

	//Send the response
	SFTPVersionPacket reply;
	reply.m_version = state->m_protocolVersion;
	reply.ByteSwap();
	SendPacket(id, socket, SFTPPacket::SSH_FXP_VERSION, (uint8_t*)&reply, sizeof(reply));
}

/**
	@brief Handle a SSH_FXP_STAT or SSH_FXP_LSTAT packet

	(for now, do the same thing since we dont support symlinks)
 */
void SFTPServer::OnRxStat(
	int id,
	[[maybe_unused]] SFTPConnectionState* state,
	TCPTableEntry* socket,
	SFTPStatPacket* pack)
{
	auto path = pack->GetPathStart();

	//Copy path to null terminated buffer
	char spath[MAX_PATH] = {0};
	strncpy(spath, path, std::min((uint32_t)(MAX_PATH-1), pack->GetPathLength()));

	//File doesn't exist? Return error
	if(!DoesFileExist(spath))
		SendStatusReply(id, socket, pack->m_requestid, SFTPStatusPacket::SSH_FX_NO_SUCH_FILE);

	//For now, return OK if the file exists? is that valid?
	else
		SendStatusReply(id, socket, pack->m_requestid, SFTPStatusPacket::SSH_FX_OK);
}

/**
	@brief Handle a SSH_FXP_OPEN packet
 */
void SFTPServer::OnRxOpen(
	int id,
	[[maybe_unused]] SFTPConnectionState* state,
	TCPTableEntry* socket,
	SFTPOpenPacket* pack)
{
	auto path = pack->GetPathStart();

	//Copy path to null terminated buffer
	char spath[MAX_PATH] = {0};
	strncpy(spath, path, std::min((uint32_t)(MAX_PATH-1), pack->GetPathLength()));

	//Reject with an access-denied error if the derived class doesn't like the request
	if(!CanOpenFile(spath, pack->GetDesiredAccess(), pack->GetFlags()))
	{
		SendStatusReply(id, socket, pack->m_requestid, SFTPStatusPacket::SSH_FX_PERMISSION_DENIED);
		return;
	}

	//We're allowed to open the file, actually initialize the handle
	//For now, only one handle per SFTP connection allowed
	auto hfile = OpenFile(spath, pack->GetDesiredAccess(), pack->GetFlags());

	//Send the handle to the client
	SendHandleReply(id, socket, pack->m_requestid, hfile);
}

/**
	@brief Handle a SSH_FXP_CLOSE packet
 */
void SFTPServer::OnRxClose(
	int id,
	[[maybe_unused]] SFTPConnectionState* state,
	TCPTableEntry* socket,
	SFTPClosePacket* pack)
{
	if(pack->m_handleLength != 4)
		SendStatusReply(id, socket, pack->m_requestid, SFTPStatusPacket::SSH_FX_BAD_MESSAGE);

	if(CloseFile(pack->m_handleValue))
		SendStatusReply(id, socket, pack->m_requestid, SFTPStatusPacket::SSH_FX_OK);
	else
		SendStatusReply(id, socket, pack->m_requestid, SFTPStatusPacket::SSH_FX_FAILURE);
}

/**
	@brief Send a SSH_FXP_HANDLE packet
 */
void SFTPServer::SendHandleReply(int id, TCPTableEntry* socket, uint32_t requestid, uint32_t handle)
{
	SFTPHandlePacket reply;
	reply.m_requestid = requestid;
	reply.m_handleValue = handle;
	reply.ByteSwap();
	SendPacket(id, socket, SFTPPacket::SSH_FXP_HANDLE, (uint8_t*)&reply, sizeof(reply));
}

/**
	@brief Send a SSH_FXP_STATUS packet
 */
void SFTPServer::SendStatusReply(int id, TCPTableEntry* socket, uint32_t requestid, SFTPStatusPacket::Status code)
{
	SFTPStatusPacket reply;
	reply.m_requestid = requestid;
	reply.m_errorCode = code;
	reply.ByteSwap();
	SendPacket(id, socket, SFTPPacket::SSH_FXP_STATUS, (uint8_t*)&reply, sizeof(reply));
}

void SFTPServer::SendPacket(
	int id,
	TCPTableEntry* socket,
	SFTPPacket::PacketType type,
	const uint8_t* data,
	uint16_t len)
{
	//Make sure it fits in one frame
	if(len + sizeof(SFTPPacket) > ETHERNET_PAYLOAD_MTU)
		return;

	//TODO: can we make this any more efficient?
	uint8_t reply[ETHERNET_PAYLOAD_MTU];
	auto outer = reinterpret_cast<SFTPPacket*>(&reply[0]);
	outer->m_length = len + sizeof(SFTPPacket) - sizeof(uint32_t);
	outer->m_type = type;
	outer->ByteSwap();
	memcpy(outer->Payload(), data, len);

	//Send the packet with outer framing added
	m_ssh->SendSessionData(id, socket, (const char*)reply, len + sizeof(SFTPPacket));
}

void SFTPServer::OnConnectionClosed([[maybe_unused]] int id)
{
	//ignore for now, the sshd handles all of this
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// FIFO helpers

bool SFTPServer::IsPacketReady(SFTPConnectionState* state)
{
	auto& fifo = state->m_rxBuffer;
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
	@brief Checks if we have the header of a packet too big to fit in our buffer
 */
bool SFTPServer::IsHugePacketReady(SFTPConnectionState* state)
{
	auto& fifo = state->m_rxBuffer;
	auto data = fifo.Rewind();
	auto available = fifo.ReadSize();

	if(available < 4)
		return false;

	uint32_t reallen = __builtin_bswap32(*reinterpret_cast<uint32_t*>(data));
	uint32_t minsize = sizeof(SFTPPacket) + 4;
	if( (available >= minsize) && ( (reallen + 4) >= SFTP_RX_BUFFER_SIZE ) )
		return true;

	return false;
}

/**
	@brief Handle a huge packet
 */
void SFTPServer::StartHugePacket(
	int id,
	TCPTableEntry* socket,
	uint32_t requestid,
	SFTPConnectionState* state,
	SFTPPacket* header)
{
	//For now, only support huge packets of type SSH_FXP_WRITE
	if(header->m_type != SFTPPacket::SSH_FXP_WRITE)
	{
		SendStatusReply(id, socket, requestid, SFTPStatusPacket::SSH_FX_OP_UNSUPPORTED);
		return;
	}

	//Save header fields
	state->m_hugePacketInProgress = true;
	state->m_hugePacketBytesSoFar = 5;	//we've already read the request ID and type, which counts toward the length
	state->m_hugePacketTotalLength = header->m_length;
	state->m_hugePacketRequestID = requestid;
	state->m_hugePacketType = static_cast<SFTPPacket::PacketType>(header->m_type);

	//Pop the packet header (including request ID)
	state->m_rxBuffer.Pop(sizeof(SFTPPacket) + 4);

	//Process payload data, if we have any
	OnHugePacketRxData(id, state, socket);
}

void SFTPServer::OnHugePacketRxData(int id, SFTPConnectionState* state, TCPTableEntry* socket)
{
	//See how much data we have
	auto& fifo = state->m_rxBuffer;
	auto data = fifo.Rewind();
	auto available = fifo.ReadSize();

	//If we have the remainder of the packet in the buffer, process those bytes now
	uint32_t bytesLeft = state->m_hugePacketTotalLength - state->m_hugePacketBytesSoFar;
	if(available >= bytesLeft)
	{
		OnHugePacketRxData(id, state, socket, data, bytesLeft);
		state->m_rxBuffer.Pop(bytesLeft);
		state->m_hugePacketInProgress = false;
	}

	//If we only have part of the packet, process the chunk as long as it's not stupidly small
	//(if we get a tiny trickle of bytes, save CPU time and process them in blocks)
	else if(available > 64)
	{
		OnHugePacketRxData(id, state, socket, data, available);
		state->m_hugePacketBytesSoFar += available;
		state->m_rxBuffer.Pop(available);
	}
}

void SFTPServer::OnHugePacketRxData(
	int id,
	SFTPConnectionState* state,
	TCPTableEntry* socket,
	uint8_t* data,
	uint32_t len)
{
	switch(state->m_hugePacketType)
	{
		//If we're doing anything but a write, bail (we dont know how to handle that)
		case SFTPPacket::SSH_FXP_WRITE:
			OnHugePacketWriteData(id, state, socket, data, len);
			break;

		default:
			SendStatusReply(id, socket, state->m_hugePacketRequestID, SFTPStatusPacket::SSH_FX_OP_UNSUPPORTED);
			break;
	}
}

void SFTPServer::OnHugePacketWriteData(
	int id,
	SFTPConnectionState* state,
	TCPTableEntry* socket,
	uint8_t* data,
	uint32_t len)
{
	//The first block of the packet contains at least 64 bytes or full length, so we can process this in one go
	//string handle (always a uint32 but verify that)
	//uint64 offset
	//string data
	if(state->m_hugePacketBytesSoFar == 5)
	{
		//Not enough bytes for full packet
		if(len < 20)
		{
			SendStatusReply(id, socket, state->m_hugePacketRequestID, SFTPStatusPacket::SSH_FX_BAD_MESSAGE);
			return;
		}

		//Parse the write request
		auto handleLen = __builtin_bswap32(*reinterpret_cast<uint32_t*>(data));
		if(handleLen != 4)
		{
			SendStatusReply(id, socket, state->m_hugePacketRequestID, SFTPStatusPacket::SSH_FX_BAD_MESSAGE);
			return;
		}
		state->m_writeHandle = __builtin_bswap32(*reinterpret_cast<uint32_t*>(data+4));
		state->m_writeOffset = __builtin_bswap64(*reinterpret_cast<uint64_t*>(data+8));
		state->m_writeLength = __builtin_bswap32(*reinterpret_cast<uint64_t*>(data+16));
		state->m_writeBytesSoFar = 0;

		data += 20;
		len -= 20;
	}

	//Process the actual write data
	if(len > 0)
	{
		WriteFile(state->m_writeHandle, state->m_writeOffset, data, len);

		state->m_writeBytesSoFar += len;
		state->m_writeOffset += len;
	}

	//Are we done with the write? Return success if so
	if(state->m_writeBytesSoFar >= state->m_writeLength)
		SendStatusReply(id, socket, state->m_hugePacketRequestID, SFTPStatusPacket::SSH_FX_OK);
}
