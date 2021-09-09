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

int main(int /*argc*/, char* /*argv*/[])
{
	/*
	uint8_t src[6] = {0x41, 0xde, 0xad, 0xbe, 0xef, 0x41 };
	uint8_t dst[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	//Build the frame
	EthernetFrame frame;
	frame.SrcMAC() = MACAddress(src);
	frame.DstMAC() = MACAddress(dst);
	frame.OuterEthertype() = ETHERTYPE_DOT1Q;
	frame.VlanTag().m_fields.m_vlanID = 12;
	frame.VlanTag().m_fields.m_dropEligible = 0;
	frame.VlanTag().m_fields.m_priorityCodePoint = 0;
	frame.InnerEthertype() = 0x86dd;
	frame.Payload()[0] = 0x69;
	frame.Length() = ETHERNET_HEADER_SIZE + ETHERNET_DOT1Q_SIZE + 1;

	//Convert all fields to network byte order
	frame.ByteSwap();

	auto len = frame.Length();
	for(size_t i=0; i<len; i++)
	{
		printf("%02x ", frame.RawData()[i]);
		if( (i & 15) == 15)
			printf("\n");
	}
	printf("\n");
*/
	return 0;
}
