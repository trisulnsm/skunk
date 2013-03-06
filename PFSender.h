/*
 * Copyright (c) 2007-08, Vivek Rajagopalan, vivek at unleashnetworks com
 * All rights reserved
 *
 * This file is part of Trisul Network Metering and Forensics.
 * 
 * Trisul is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Trisul is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Trisul. If not, see <http://www.gnu.org/licenses/>.
 */

 /**/

#ifndef PFSENDER_DEFINED_H
#define PFSENDER_DEFINED_H

#include "INetSender.h"
#include <string>

#include <fcntl.h>
#include <sys/utsname.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>

//////////////////////////////////////
// Send packets using PF_PACKET
//////////////////////////////////////
class CPFSender : public INetSender
{
	enum
	{
		ERRBUF_SIZE=256,
	};

public:
	CPFSender();
	virtual ~CPFSender();

	virtual bool			Open(const char *  lpszInterfaceName);
	virtual const char *	GetLastError();
	virtual void			Close();
	virtual bool			SendPacket(const unsigned char * pBytes, unsigned long uLen);

private:
	int 			GetInterfaceIndex(int fd, const char  *device, char *errbuf);

private:
	std::string				strError;
    struct sockaddr_ll 		sa;
	int						sfd;

};

#endif
