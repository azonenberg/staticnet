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

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Construction / destruction

/**
	@brief Initializes the ARP protocol stack
 */
ARPProtocol::ARPProtocol(EthernetProtocol& eth)
	: m_eth(eth)
{

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Handler for incoming packets

void ARPProtocol::OnRxPacket(ARPPacket* packet)
{
	packet->ByteSwap();

	printf("Got an ARP packet!\n");

	//Validate all of our common fields
	if(packet->m_htype != 1)
		return;
	if(packet->m_ptype != ETHERTYPE_IPV4)
		return;
	if(packet->m_hardwareLen != ETHERNET_MAC_SIZE)
		return;
	if(packet->m_protoLen != IPV4_ADDR_SIZE)
		return;

	printf("    Sender hardware: %02x:%02x:%02x:%02x:%02x:%02x\n",
		packet->m_senderHardwareAddress[0],
		packet->m_senderHardwareAddress[1],
		packet->m_senderHardwareAddress[2],
		packet->m_senderHardwareAddress[3],
		packet->m_senderHardwareAddress[4],
		packet->m_senderHardwareAddress[5]);
	printf("    Sender protocol: %d.%d.%d.%d\n",
		packet->m_senderProtocolAddress.m_octets[0],
		packet->m_senderProtocolAddress.m_octets[1],
		packet->m_senderProtocolAddress.m_octets[2],
		packet->m_senderProtocolAddress.m_octets[3]);

	printf("    Target hardware: %02x:%02x:%02x:%02x:%02x:%02x\n",
		packet->m_targetHardwareAddress[0],
		packet->m_targetHardwareAddress[1],
		packet->m_targetHardwareAddress[2],
		packet->m_targetHardwareAddress[3],
		packet->m_targetHardwareAddress[4],
		packet->m_targetHardwareAddress[5]);
	printf("    Target protocol: %d.%d.%d.%d\n",
		packet->m_targetProtocolAddress.m_octets[0],
		packet->m_targetProtocolAddress.m_octets[1],
		packet->m_targetProtocolAddress.m_octets[2],
		packet->m_targetProtocolAddress.m_octets[3]);

	/*
	printf("    ");
	auto len = frame->Length();
	for(size_t i=0; i<len; i++)
	{
		printf("%02x ", frame->RawData()[i]);
		if( (i & 31) == 31)
			printf("\n    ");
	}
	printf("\n");
	*/
}
