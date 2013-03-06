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

//////////////////////////////////////////////////////////////////////
// Impex_Libpcap.h: interface for the CImpex_Libpcap class.
//		Import / Export methods from a PCAP file
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_IMPEX_LIBPCAP_H__0BE65AEC_68BA_43DB_8927_3E307E9681B5__INCLUDED_)
#define AFX_IMPEX_LIBPCAP_H__0BE65AEC_68BA_43DB_8927_3E307E9681B5__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "pcap.h"
#include "linuxdefs.h"
#include <string>

class CXDatagram;

class CImpex_Libpcap  
{
	enum
	{
		TCPDUMP_MAGIC = 0xa1b2c3d4,
	};


	FILE			 * fp;
	pcap_t			 * pct;
	void 			 * pDelegate;
	std::string		   strError;

public:
	CImpex_Libpcap(LPVOID  p);
	virtual ~CImpex_Libpcap();

public:
	virtual BOOL	OpenDumpFile(LPCTSTR pszFile);
	virtual BOOL	ProcPackets();
	virtual void	CloseDumpFile();

private:
	void	SetError(LPCTSTR lpszErr) { strError=lpszErr;}
};

#endif // !defined(AFX_IMPEX_LIBPCAP_H__0BE65AEC_68BA_43DB_8927_3E307E9681B5__INCLUDED_)
