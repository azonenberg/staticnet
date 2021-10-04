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
#include <staticnet/stack/staticnet.h>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Construction / destruction

TCPProtocol::TCPProtocol(IPv4Protocol* ipv4)
	: m_ipv4(ipv4)
{
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Handler for incoming packets

/**
	@brief Handles an incoming TCP packet
 */
void TCPProtocol::OnRxPacket(
	TCPSegment* segment,
	uint16_t ipPayloadLength,
	IPv4Address sourceAddress,
	uint16_t pseudoHeaderChecksum)
{
	//Drop any packets too small for a complete TCP header
	if(ipPayloadLength < 20)
		return;

	//Verify checksum of packet body
	if(0xffff != IPv4Protocol::InternetChecksum(
		reinterpret_cast<uint8_t*>(segment),
		ipPayloadLength,
		pseudoHeaderChecksum))
	{
		return;
	}
	segment->ByteSwap();

	//Sanity check that the data offset points within the segment and not after the end
	uint16_t off = segment->GetDataOffsetBytes();
	if(off > ipPayloadLength)
		return;
	uint16_t payloadLen = ipPayloadLength - off;

	//Check flags to see what it is
	if(segment->m_offsetAndFlags & TCPSegment::FLAG_SYN)
	{
		//TODO: check for SYN+ACK (we can only ever see this if we're a client)
		//For now we only support the server use case, so any SYN is a connection request
		OnRxSYN(segment, sourceAddress);
	}

	else if(segment->m_offsetAndFlags & TCPSegment::FLAG_RST)
		OnRxRST(segment, sourceAddress);

	else if(segment->m_offsetAndFlags & TCPSegment::FLAG_ACK)
		OnRxACK(segment, sourceAddress, payloadLen);
}

/**
	@brief Handles an incoming SYN
 */
void TCPProtocol::OnRxSYN(TCPSegment* segment, IPv4Address sourceAddress)
{
	//If port is not open, send a RST
	if(!IsPortOpen(segment->m_destPort))
	{
		//Get ready to send a reply, if no free buffers give up
		auto reply = m_ipv4->GetTxPacket(sourceAddress, IPv4Protocol::IP_PROTO_TCP);
		if(reply == NULL)
			return;

		//Format the reply
		auto payload = reinterpret_cast<TCPSegment*>(reply->Payload());
		payload->m_sourcePort = segment->m_destPort;
		payload->m_destPort = segment->m_sourcePort;
		payload->m_sequence = 0;
		payload->m_ack = segment->m_sequence + 1;
		payload->m_offsetAndFlags = (5 << 12) | TCPSegment::FLAG_RST | TCPSegment::FLAG_ACK;
		payload->m_windowSize = 1;
		payload->m_urgent = 0;

		//Done
		SendSegment(payload, reply);
		return;
	}

	//TODO: See if we already have open state for this hash.
	//If so, this is a repeated SYN for an open socket (our ACK didn't make it)

	//Figure out which socket table entry to use
	auto state = AllocateSocketHandle(Hash(sourceAddress, segment->m_destPort, segment->m_sourcePort));
	if(state == NULL)
	{
		//No free socket handles available.
		//Silently drop the connection request
		return;
	}

	//Fill out the initial table entry
	state->m_remoteIP = sourceAddress;
	state->m_localPort = segment->m_destPort;
	state->m_remotePort = segment->m_sourcePort;
	state->m_remoteSeq = segment->m_sequence + 1;
	state->m_localSeq = GenerateInitialSequenceNumber();

	//Prepare the reply
	auto reply = CreateReply(state);
	auto payload = reinterpret_cast<TCPSegment*>(reply->Payload());
	payload->m_offsetAndFlags |= TCPSegment::FLAG_SYN;

	//Send it
	SendSegment(payload, reply);

	//The SYN flag counts as a byte in the stream, so we expect the next ACK to be one greater than what we sent
	state->m_localSeq ++;

	//Notify upper layer stuff
	OnConnectionAccepted(state);
}

/**
	@brief Handles an incoming SYN
 */
void TCPProtocol::OnRxRST(TCPSegment* /*segment*/, IPv4Address /*sourceAddress*/)
{
	printf("TODO: handle RST\n");
}

/**
	@brief Handles an incoming frame during a connection
 */
void TCPProtocol::OnRxACK(TCPSegment* segment, IPv4Address sourceAddress, uint16_t payloadLen)
{
	//Look up the socket handle for this segment. Drop silently if not a valid segment
	//TODO: should we send a RST?
	auto state = GetSocketState(sourceAddress, segment->m_destPort, segment->m_sourcePort);
	if(state == NULL)
		return;

	//If remote sequence number is too BIG: we missed a packet, this is the next one in line.
	//If too SMALL: this is a duplicate packet.
	//In either case, we don't need to do anything.
	//TODO: Send an ACK for the last packet we *did* get?
	if(state->m_remoteSeq != segment->m_sequence)
		return;

	//If we get here, it's the next packet in line.
	//TODO: Check its ACK number and mark any segments we sent with smaller ACK numbers as OK

	//Process the data
	if(payloadLen > 0)
	{
		//If
		if(!OnRxData(state, segment->Payload(), payloadLen))
			return;
	}

	//If no data, and not a FIN, no action needed (duplicate ACK?)
	else if( (segment->m_offsetAndFlags & TCPSegment::FLAG_FIN) == 0)
		return;

	//Update our ACK number to the end of this segment
	state->m_remoteSeq += payloadLen;

	//Send our reply
	auto reply = CreateReply(state);
	auto payload = reinterpret_cast<TCPSegment*>(reply->Payload());
	if(segment->m_offsetAndFlags & TCPSegment::FLAG_FIN)
	{
		//Set the FIN flag on the outgoing packet.
		//FIN counts as a data byte so increment our ACK number
		payload->m_offsetAndFlags |= TCPSegment::FLAG_FIN;
		payload->m_ack ++;

		//Connection is getting torn down, so close our socket state.
		//Normally we'd go to TIME-WAIT but just close it right away so we can reuse the table entry.
		state->m_valid = false;
	}
	SendSegment(payload, reply);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Outbound traffic

/**
	@brief Does final prep and sends a TCP segment
 */
void TCPProtocol::SendSegment(TCPSegment* segment, IPv4Packet* packet, uint16_t length)
{
	//Calculate the pseudoheader checksum
	auto pseudoHeaderChecksum = m_ipv4->PseudoHeaderChecksum(packet, length);

	//Need to be in network byte order before we send
	segment->ByteSwap();

	segment->m_checksum = ~__builtin_bswap16(
		IPv4Protocol::InternetChecksum(reinterpret_cast<uint8_t*>(segment), length, pseudoHeaderChecksum));
	m_ipv4->SendTxPacket(packet, length);
}

/**
	@brief Create a reply segment for a given socket state
 */
IPv4Packet* TCPProtocol::CreateReply(TCPTableEntry* state)
{
	//Get ready to send a reply, if no free buffers give up
	auto reply = m_ipv4->GetTxPacket(state->m_remoteIP, IPv4Protocol::IP_PROTO_TCP);
	if(reply == NULL)
		return NULL;

	//Format the reply
	auto payload = reinterpret_cast<TCPSegment*>(reply->Payload());
	payload->m_sourcePort = state->m_localPort;
	payload->m_destPort = state->m_remotePort;
	payload->m_sequence = state->m_localSeq;
	payload->m_ack = state->m_remoteSeq;
	payload->m_offsetAndFlags = (5 << 12) | TCPSegment::FLAG_ACK;
	payload->m_windowSize = TCP_IPV4_PAYLOAD_MTU;	//TODO: support variable window size
	payload->m_urgent = 0;

	return reply;
}

/**
	@brief Close a socket
 */
void TCPProtocol::CloseSocket(TCPTableEntry* state)
{
	//Prepare the reply
	auto reply = CreateReply(state);
	auto payload = reinterpret_cast<TCPSegment*>(reply->Payload());
	payload->m_offsetAndFlags |= TCPSegment::FLAG_FIN;

	//Send it
	SendSegment(payload, reply);

	//The FIN flag counts as a byte in the stream, so we expect the next ACK to be one greater than what we sent
	state->m_localSeq ++;

	//Don't close the socket state on our end until we get the FIN+ACK
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Socket table stuff

/**
	@brief Hashes an IP address and returns a row index

	32-bit FNV-1 for now. Simple and good mixing, but uses a bunch of multiplies so might be slow?
 */
uint16_t TCPProtocol::Hash(IPv4Address ip, uint16_t localPort, uint16_t remotePort)
{
	size_t hash = FNV_INITIAL;
	for(size_t i=0; i<4; i++)
		hash = (hash * FNV_MULT) ^ ip.m_octets[i];
	hash = (hash * FNV_MULT) ^ (localPort >> 8);
	hash = (hash * FNV_MULT) ^ (localPort & 0xff);
	hash = (hash * FNV_MULT) ^ (remotePort >> 8);
	hash = (hash * FNV_MULT) ^ (remotePort & 0xff);

	return hash % TCP_TABLE_LINES;
}

/**
	@brief Looks up the socket state for the given connection
 */
TCPTableEntry* TCPProtocol::GetSocketState(IPv4Address ip, uint16_t localPort, uint16_t remotePort)
{
	auto hash = Hash(ip, localPort, remotePort);

	for(size_t way=0; way < TCP_TABLE_WAYS; way ++)
	{
		auto& row = m_socketTable[way].m_lines[hash];

		//Nothing there? No match
		if(!row.m_valid)
			continue;

		//Check table info
		if( (row.m_remoteIP == ip) && (row.m_localPort == localPort) && (row.m_remotePort == remotePort) )
			return &m_socketTable[way].m_lines[hash];
	}

	//Not a valid socket
	return NULL;
}

/**
	@brief Finds a free space in the socket table for the given hash, then marks it as in use and returns the
	socket state object
 */
TCPTableEntry* TCPProtocol::AllocateSocketHandle(uint16_t hash)
{
	for(size_t way=0; way < TCP_TABLE_WAYS; way ++)
	{
		auto& row = m_socketTable[way].m_lines[hash];

		//There's something in the row. We can't insert here.
		if(row.m_valid)
			continue;

		//It's free, all good
		else
		{
			row.m_valid = true;
			return &m_socketTable[way].m_lines[hash];
		}
	}

	//No free entries found
	return NULL;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Overrides for end user application logic

/**
	@brief Handler for a new incoming connection

	Override to initialize application-layer state or do other per-connection setup.

	The default implementation does nothing.
 */
void TCPProtocol::OnConnectionAccepted(TCPTableEntry* /*state*/)
{
}

/**
	@brief Checks if a given port is open or not

	The default implementation returns true for all ports.
 */
bool TCPProtocol::IsPortOpen(uint16_t /*port*/)
{
	return true;
}

/**
	@brief Generates a random initial sequence number for a new socket.

	This should be overridden in derived classes to use the best randomness available (hardware RNG etc).
 */
uint32_t TCPProtocol::GenerateInitialSequenceNumber()
{
	//generated by fair dice roll
	//guaranteed to be random
	return 4;
}

/**
	@brief Handles incoming packet data.

	Return true to send an ACK if everything went smoothly.

	Return false if there was insufficient memory or the packet could not be processed at this time. The stack will
	drop the packet and the sender will retransmit in the future.

	The default implementation does nothing and always returns true.

	@return		True if the data was processed successfully
				False if the data could not be processed
 */
bool TCPProtocol::OnRxData(TCPTableEntry* /*state*/, uint8_t* /*payload*/, uint16_t /*payloadLen*/)
{
	return true;
}
