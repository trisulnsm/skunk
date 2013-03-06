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

#include "PFSender.h"
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <stdexcept>
#include <unistd.h>

CPFSender::CPFSender()
: sfd(-1)
{

}
CPFSender::~CPFSender()
{

}
////////////////////////////////////////////////////////////////////////
// Open Live !
////////////////////////////////////////////////////////////////////////
bool			CPFSender::Open(const char *  lpszInterfaceName)
{
	char errBuf[ERRBUF_SIZE];
	const char * device = lpszInterfaceName;

    int mysocket;
    struct ifreq ifr;
    struct sockaddr_ll sa;
    int n = 1, err;
    socklen_t errlen = sizeof(err);

    /* open our socket */
    if ((mysocket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        snprintf(errBuf, 256, "PF_PACKET socket open failed  : %s", strerror(errno));
		throw std::domain_error(errBuf);
    }
   
    /* get the interface id for the device */
    if ((sa.sll_ifindex = GetInterfaceIndex(mysocket, device, errBuf)) < 0) {
        close(mysocket);
        return false; 
    }

    /* bind socket to our interface id */
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    if (bind(mysocket, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        snprintf(errBuf, ERRBUF_SIZE, "bind error: %s", strerror(errno));
        close(mysocket);
		throw std::domain_error(errBuf);
    }
    
    /* check for errors, network down, etc... */
    if (getsockopt(mysocket, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0) {
        snprintf(errBuf, ERRBUF_SIZE, "error opening %s: %s", device, 
            strerror(errno));
        close(mysocket);
		throw std::domain_error(errBuf);
    }
    
    if (err > 0) {
        snprintf(errBuf, ERRBUF_SIZE, "error opening %s: %s", device, 
            strerror(err));
        close(mysocket);
		throw std::domain_error(errBuf);
    }

    /* get hardware type for our interface */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
    
    if (ioctl(mysocket, SIOCGIFHWADDR, &ifr) < 0) {
        close(mysocket);
        sprintf(errBuf, "Error getting hardware type: %s", strerror(errno));
		throw std::domain_error(errBuf);
    }

    /* make sure it's ethernet */
    switch (ifr.ifr_hwaddr.sa_family) {
        case ARPHRD_ETHER:
            break;
		case ARPHRD_LOOPBACK:
			break;
        default:
            snprintf(errBuf, ERRBUF_SIZE, 
                "unsupported pysical layer type 0x%x", ifr.ifr_hwaddr.sa_family);
            close(mysocket);
            return false;
    }
  
    sfd = mysocket;   
	return true;
}

////////////////////////////////////////////////////////////////////////
// Last Error
////////////////////////////////////////////////////////////////////////
const char *	CPFSender::GetLastError()
{
	if (strError.length()>0)
		return strError.c_str();
	else
		return "";

}
////////////////////////////////////////////////////////////////////////
// Last Error
////////////////////////////////////////////////////////////////////////
void			CPFSender::Close()
{
	if (sfd>0)
			close(sfd);
}
////////////////////////////////////////////////////////////////////////
// Last Error
////////////////////////////////////////////////////////////////////////
bool			CPFSender::SendPacket(const unsigned char * pBytes, unsigned long uLen)
{
	char errBuf[ERRBUF_SIZE];


	int retcode = (int)send(sfd, (void *)pBytes, uLen, 0);
	if (retcode < 0) 
	{
		sprintf(errBuf, "Error with pf send(): %s (errno = %d)", strerror(errno), errno);
		strError=errBuf;
		return false;
	}

	return true;
}

///////////////////////////////////////////////////////////////////////////////////
// Get Interface Index for the device, required by the PF_PACKET system calls
///////////////////////////////////////////////////////////////////////////////////
int 		CPFSender::GetInterfaceIndex(int fd, const char  *device, char *errBuf) 
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

	if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) { 
		snprintf(errBuf, ERRBUF_SIZE, "ioctl: %s", strerror(errno));
		return (-1);
	}	

	return ifr.ifr_ifindex;
}  
