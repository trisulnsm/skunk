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

#include "PcapSender.h"
#include  <stdexcept>

CPcapSender::CPcapSender()
: fpOut(0)
{

}
CPcapSender::~CPcapSender()
{

}
////////////////////////////////////////////////////////////////////////
// Open Live !
////////////////////////////////////////////////////////////////////////
bool			CPcapSender::Open(const char *  lpszInterfaceName)
{
	char error[PCAP_ERRBUF_SIZE];
	char errBuf[256];

	// Open the output adapter 
	if((fpOut = pcap_open_live(lpszInterfaceName, 100, 1, 1000, error) ) == NULL)
	{
		sprintf(errBuf,"\nError opening adapter: %s\n", error);
		strError=errBuf;
		throw std::domain_error(errBuf);
	}

	return true;
}
////////////////////////////////////////////////////////////////////////
// Last Error
////////////////////////////////////////////////////////////////////////
const char *	CPcapSender::GetLastError()
{
	if (strError.length()>0)
		return strError.c_str();
	else
		return "";

}
////////////////////////////////////////////////////////////////////////
// Last Error
////////////////////////////////////////////////////////////////////////
void			CPcapSender::Close()
{
	pcap_close(fpOut);
}
////////////////////////////////////////////////////////////////////////
// Last Error
////////////////////////////////////////////////////////////////////////
bool			CPcapSender::SendPacket(const unsigned char * pBytes, unsigned long uLen)
{
	pcap_sendpacket(fpOut,pBytes,uLen);
	return true;
}
