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

// Impex_Libpcap.cpp: implementation of the CImpex_Libpcap class.
//
//////////////////////////////////////////////////////////////////////
#include "Impex_Libpcap.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
extern void  CB_OfflinePacketCallback(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

CImpex_Libpcap::CImpex_Libpcap(LPVOID p)
: pDelegate(p)
{
	fp = NULL;
	pct=NULL;
}
CImpex_Libpcap::~CImpex_Libpcap()
{

}

//////////////////////////////////////////////////////
// OpenDumpFile
//		Open the dump file
//	UNICODE issues: (1) fopen expects ANSI filenames
//					(2) pcap expects ANSI filename
//////////////////////////////////////////////////////
BOOL	CImpex_Libpcap::OpenDumpFile(LPCTSTR pszFile)
{
#ifdef _UNICODE
	USES_CONVERSION;
#endif

	char errbuf[256];
	

	// before opening pcap offline, set the DLT type in the capture
	// summary, so that subsequent writes are handled correctly
#ifndef _UNICODE
	fp = fopen(pszFile,"rb");
#else
	fp = fopen(W2A(pszFile),"rb");
#endif
	if (fp==NULL) {
		SetError(_T("Cant Open Dump File"));
        return FALSE;
	}
	struct pcap_file_header hdr;
    if (fread((char *)&hdr, sizeof(hdr), 1, fp) != 1){
		SetError(_T("Cant read pcap header"));
        return FALSE;
	}

	// check if atleast the first packet is valid (need to prevent crashes)
	// like crash_editcap.tcpd (Bug # 101284)
	pcap_pkthdr phdr;
    if (fread((char *)&phdr, sizeof(phdr), 1, fp) == 1){

		// there is a packet , check its validity
		if (phdr.caplen > phdr.len) {
			// woo error cant capture more than len
			SetError(_T("Corrupted PCAP file (Code 1)"));
			fclose(fp);
			return FALSE;
		}

		// caplen must be less than 65536
		if (phdr.caplen >= 65536 ) {
			// woo error tooo big
			SetError(_T("Corrupted PCAP file (Code 2)"));
			fclose(fp);
			return FALSE;
		}

		// both caplen and len must also be less than 16K 
		// maximum known link layer size (2*Ethernet Jumbo (9K) )
		if (phdr.caplen >= 16384 ||
			phdr.len >= 16384 ) {

			// woo error too big for known link layers
			SetError(_T("Corrupted PCAP file (Code 3)"));
			fclose(fp);
			return FALSE;
		}
	}

	
	fclose(fp);

	// now let pcap take over the opening
#ifndef _UNICODE
	pct = pcap_open_offline(pszFile,errbuf);
#else
	pct = pcap_open_offline(W2A(pszFile),errbuf);
#endif
	if ( pct == NULL)
	{
		SetError("Cant open the pcap offline file for reading");
		return FALSE;
	}


	return TRUE;
}

/////////////////////////////////////////////////////////////////////////////////////
// Close
// 		Clean it up 
/////////////////////////////////////////////////////////////////////////////////////
void		CImpex_Libpcap::CloseDumpFile()
{
	if ( fp){
	//	fclose(fp);
		fp=NULL;
	}

	if (pct)
	{
		pcap_close(pct);
		pct=NULL;
	}
}
/////////////////////////////////////////////////////////////////////////////////////
// ProcessPackets
//		supports both ranges and pcap filters
/////////////////////////////////////////////////////////////////////////////////////
BOOL	CImpex_Libpcap::ProcPackets()
{

	// Start the capture
	pcap_loop(pct, 0, CB_OfflinePacketCallback, (UCHAR*)pDelegate);

	return TRUE;
}
