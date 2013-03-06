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

// TimeUtils.cpp: implementation of the TimeUtils class.
//
//////////////////////////////////////////////////////////////////////

#ifdef _WINDOWS
#include "stdafx.h"
#include "usnfctr.h"
#endif

#include "TimeUtils.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

const timeval TimeUtils::ZeroTime = {0,0};

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

TimeUtils::TimeUtils()
{

}

TimeUtils::~TimeUtils()
{

}


LPCTSTR TimeUtils::FormatTimeInterval(const timeval& tv_from, const timeval& tv_to)
{
	ULONG ums = TmDiffMs(tv_to, tv_from);
	ULONG sec = ums/1000;

	int   r;
	int   h = sec/3600; 
	r = sec % 3600;
	int   m = r/60;
	r = sec % 60;


	sprintf(m_scratchBuf,"%02dh %02dm %02ds", h, m, r );
	return m_scratchBuf;
}

LPCTSTR TimeUtils::FormatTimeIntervalUs(const timeval& tv_from, const timeval& tv_to)
{
	int64_t us = TmDiffUs(tv_to, tv_from);
	ULONG sec = us/1000000;
	ULONG usr = us % 1000000;


	int   r;
	int   h = sec/3600; 
	r = sec % 3600;
	int   m = r/60;
	r = sec % 60;


	sprintf(m_scratchBuf,"%02dh %02dm %02ds %06du", h, m, r, (int) usr );
	return m_scratchBuf;
}
