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

// TimeUtils.h: interface for the TimeUtils class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_TIMEUTILS_H__71983549_CB58_4395_AABA_DBA402FE9DB2__INCLUDED_)
#define AFX_TIMEUTILS_H__71983549_CB58_4395_AABA_DBA402FE9DB2__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifdef LINUX_BUILD
#include "linuxdefs.h"
#endif

#include <sys/time.h>

class TimeUtils  
{
public:
	enum
	{
		USECS_PER_SEC=1000000,
		USECS_PER_MSEC=1000,
		MSECS_PER_SEC=1000,		
	};


	static const timeval ZeroTime;


public:
	TimeUtils();
	virtual ~TimeUtils();

public:
	inline LPCTSTR	FormatTimestamp(const timeval& tv)
	{
		time_t tt;
		tt = tv.tv_sec;
		struct tm * pTM = localtime( &tt);


		_stprintf(m_scratchBuf,_T("%02d-%02d-%04d %02d:%02d:%02d-%06ld"),
				 pTM->tm_mon+1,pTM->tm_mday,pTM->tm_year+1900,     /* MM-DD-YYYY */
				 pTM->tm_hour,pTM->tm_min,pTM->tm_sec,
				 tv.tv_usec);										/* us         */

		return m_scratchBuf;
	}


	// non-static (slowly remove all other static methods, bad for threaded apps)
	LPCTSTR FormatTimeInterval(const timeval& tv_from, const timeval& tv_to);
	LPCTSTR FormatTimeIntervalUs(const timeval& tv_from, const timeval& tv_to);


	inline LPCTSTR	GetCurrentTimestamp()
	{
		timeval tv;
		gettimeofday(&tv,NULL);
		return FormatTimestamp(tv);
	}

	static inline long		TmDiffMs(const timeval& t1, const timeval& t2)
	{
		return (t1.tv_sec-t2.tv_sec) * MSECS_PER_SEC +
			   (t1.tv_usec-t2.tv_usec)/USECS_PER_MSEC;
	}

	static inline long		TmDiffSecs(const timeval& t1, const timeval& t2)
	{
		return (t1.tv_sec-t2.tv_sec);
	}
	static inline ::int64_t 	TmDiffUs(const timeval& t1, const timeval& t2)
	{
		return (t1.tv_sec-t2.tv_sec)* USECS_PER_SEC +
			   (t1.tv_usec-t2.tv_usec);
	}
	static inline int TmCompare(const timeval& t1, const timeval& t2) 
	{
		if (t1.tv_sec>t2.tv_sec)
		{
			return 1;
		}
		else if (t1.tv_sec==t2.tv_sec)
		{
			if (t1.tv_usec==t2.tv_usec) return 0;
			else return t1.tv_usec<t2.tv_usec?-1:1;
		}
		else 
		{
			return -1;
		}
	}
	static inline bool	IsInTimeWindow(const timeval& tBase, const timeval& tcheck, ULONG windowSizeMs)
	{
		long msdiff = (long) TmDiffMs(tcheck,tBase);
		if (msdiff<0) return false;
		return (msdiff<=(long)windowSizeMs);
	}
	static inline bool	IsAboveTimeWindow(const timeval& tBase, const timeval& tcheck, ULONG windowSizeMs)
	{
		long msdiff = (long) TmDiffMs(tcheck,tBase);
		if (msdiff<0) return false;
		return (msdiff>(long)windowSizeMs);
	}

	static inline timeval IncTimeMs(const timeval& tmVal, ULONG msecs)
	{
		timeval tmNew = tmVal;
		tmNew.tv_usec += USECS_PER_MSEC*(msecs%MSECS_PER_SEC);
		if (tmNew.tv_usec >= USECS_PER_SEC ) 
		{
			tmNew.tv_usec = tmNew.tv_usec - USECS_PER_SEC;
			tmNew.tv_sec += 1;
		}

		tmNew.tv_sec += msecs/MSECS_PER_SEC;
		return tmNew;
	}
    static inline timeval IncTimeSecs(const timeval& tmVal, ULONG secs)
    {
        timeval tmNew = tmVal;
        tmNew.tv_sec += secs;
        return tmNew;
    }
    static inline timeval DecTimeSecs(const timeval& tmVal, ULONG secs)
    {
        timeval tmNew = tmVal;
        tmNew.tv_sec -= secs;
        return tmNew;
    }

	static	inline timeval SeekToMs(timeval& tvMin,ULONG msecsToSeek)
	{
		timeval tvNew = tvMin;

		if (msecsToSeek>=MSECS_PER_SEC)
		{
			// greater than a second (we can ignore the tv_usec part)
			tvNew.tv_usec=0;
			tvNew.tv_sec+=1;

			ULONG seekSecs = msecsToSeek/MSECS_PER_SEC;
			tvNew.tv_sec = tvNew.tv_sec + (seekSecs - tvNew.tv_sec%seekSecs);
		}
		else
		{
			// lesser than a second
			ULONG seekUSecs = msecsToSeek * USECS_PER_MSEC;
			tvNew.tv_usec = tvNew.tv_usec + (seekUSecs - tvNew.tv_usec%seekUSecs);
			if (tvNew.tv_usec >= USECS_PER_SEC)
			{
				tvNew.tv_sec += 1;
				tvNew.tv_usec = tvNew.tv_usec - USECS_PER_SEC;
			}
		}

		return tvNew;
	}
	inline static timeval  Add(const timeval& t1, const timeval& t2)
	{
		timeval tnew = t1;
		tnew.tv_sec=t1.tv_sec+t2.tv_sec;
		tnew.tv_usec=t1.tv_usec+t2.tv_usec;
		if (tnew.tv_usec>=USECS_PER_SEC)
		{
			tnew.tv_sec++;
			tnew.tv_usec=tnew.tv_usec-USECS_PER_SEC;
		}
		return tnew;
	}
	// t1 - t2
	inline static timeval  Diff(const timeval& t1, const timeval& t2)
	{
		timeval tnew = t1;
		tnew.tv_sec=t1.tv_sec-t2.tv_sec;
		tnew.tv_usec=t1.tv_usec-t2.tv_usec;
		if (tnew.tv_usec<0)
		{
			tnew.tv_sec--;
			tnew.tv_usec=USECS_PER_SEC+tnew.tv_usec;
		}
		return tnew;
	}
	// is zero
	inline static bool		IsZero(const timeval& t)
	{
		return t.tv_sec==0 && t.tv_usec==0;
	}

	// is non zero
	inline static bool		IsNonZero(const timeval& t)
	{
		return !IsZero(t);
	}

#ifdef TRIS_TIMEVAL_DEFINED
	// zero out
 	inline static void	ZeroOut(tris_timeval& t)
	{
		t.tv_sec=0;t.tv_usec=0;
	}
#endif

	// zero out
 	inline static void	ZeroOut(timeval& t)
	{
		t.tv_sec=0;t.tv_usec=0;
	}
    
    // floor
    inline static timeval GetRoundFloorMs(const timeval & tvRaw, ULONG msec_width)
    {
        timeval tvOut = tvRaw;
        ULONG sec_width = msec_width/1000;
        ULONG df = tvOut.tv_sec/sec_width;
        tvOut.tv_sec = df * sec_width;
        tvOut.tv_usec=0;
        return tvOut;    
    }

    // floor secs
    inline static timeval GetRoundFloorSecs(const timeval & tvRaw, ULONG sec_width)
    {
        timeval tvOut = tvRaw;
        ULONG df = tvOut.tv_sec/sec_width;
        tvOut.tv_sec = df * sec_width;
        tvOut.tv_usec=0;
        return tvOut;    
    }

private:
	TCHAR 	m_scratchBuf[256];

};

#endif // !defined(AFX_TIMEUTILS_H__71983549_CB58_4395_AABA_DBA402FE9DB2__INCLUDED_)
