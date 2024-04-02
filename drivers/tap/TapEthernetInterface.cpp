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

#include <staticnet-config.h>
#include <staticnet/stack/staticnet.h>
#include "TapEthernetInterface.h"

#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <string.h>
#include <thread>
#include <sys/signal.h>
#include <stdio.h>
#include <stdlib.h>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Construction / destruction

TapEthernetInterface::TapEthernetInterface(const char* name)
{
	signal(SIGPIPE, SIG_IGN);

	//Open the tap handle
	m_hTun = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
	if(m_hTun < 0)
	{
		perror("open tun");
		abort();
	}

	/*

		Configure and name it

		May need "ip tuntap add name simtap mode tap user <username> as root first
		to do this as a non-root user.

		Tried to add CAP_NET_ADMIN | CAP_NET_RAW but this was insufficient for ioctl TUNSETIFF to work?
	 */
	ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	strncpy(ifr.ifr_name, name, IFNAMSIZ-1);
	if(ioctl(m_hTun, TUNSETIFF, &ifr) < 0)
	{
		close(m_hTun);
		perror("TUNSETIFF");
		abort();
	}
}

TapEthernetInterface::~TapEthernetInterface()
{
	close(m_hTun);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Transmit path

EthernetFrame* TapEthernetInterface::GetTxFrame()
{
	return new EthernetFrame;
}

void TapEthernetInterface::SendTxFrame(EthernetFrame* frame)
{
	write(m_hTun, frame->RawData(), frame->Length());
	delete frame;
}

void TapEthernetInterface::CancelTxFrame(EthernetFrame* frame)
{
	delete frame;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Receive path

EthernetFrame* TapEthernetInterface::GetRxFrame()
{
	EthernetFrame* frame = new EthernetFrame;
	int len = read(m_hTun,  frame->RawData(), ETHERNET_BUFFER_SIZE);

	if(len <= 0)
	{
		delete frame;
		return NULL;
	}

	else
	{
		#ifdef STATICNET_PERFORMANCE_COUNTERS

			if(frame->DstMAC().IsUnicast())
				m_perfCounters.m_rxFramesUnicast ++;
			else
				m_perfCounters.m_rxFramesMulticast ++;
			m_perfCounters.m_rxBytesTotal += len;

		#endif

		frame->SetLength(len);
		return frame;
	}
}

void TapEthernetInterface::ReleaseRxFrame(EthernetFrame* frame)
{
	delete frame;
}
