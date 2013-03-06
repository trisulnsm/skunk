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

#ifndef  _LINUXDEFS_H_INCLUDED_2
#define  _LINUXDEFS_H_INCLUDED_2

#include <assert.h>
#include <sys/types.h>
#include <inttypes.h>
#include <string>
#include <stdio.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>



typedef char				TCHAR;
typedef char				CHAR;
typedef char		   *	LPTSTR;
typedef char*				BSTR;
typedef const char*			CBSTR;
typedef const 	 char  * 	LPCTSTR;
typedef unsigned char  		BYTE;
typedef unsigned char  		UCHAR;
typedef unsigned char  * 	LPBYTE;
typedef unsigned char  * 	LPUCHAR;
typedef unsigned short 		USHORT;
#if __WORDSIZE==64
typedef u_int32_t			DWORD;
typedef u_int32_t  *		LPULONG;
typedef u_int32_t  			ULONG;
typedef int32_t			    LONG;
typedef u_int64_t		WORDPTR_T;
#else
#if __WORDSIZE==32
typedef unsigned long		DWORD;
typedef unsigned long 		ULONG;
typedef ULONG  		*		LPULONG;
typedef long			    LONG;
typedef u_int32_t		WORDPTR_T;
#endif
#endif
typedef unsigned int		UINT;
typedef void		   *	LPVOID;
typedef FILE *				LPFILE;
typedef u_int32_t			UINT32;
typedef u_int64_t			ULONG64;
typedef int64_t				LONG64;
typedef unsigned long		HRESULT;
typedef bool				VARIANT_BOOL;
typedef int					HANDLE;



#ifndef _T
#define _T(X)	X
#endif

#ifndef ASSERT
#define ASSERT		assert
#endif

#ifndef _ASSERTE
#define ASSERT		assert
#endif



#ifndef MAX_PATH
#define MAX_PATH	1024
#endif

#ifndef ERR_BUF_SIZE
#define ERR_BUF_SIZE 	512
#endif


#ifndef TRIS_USE_DEFAULTS
#define TRIS_USE_DEFAULTS -1
#endif

#ifndef TRUE
#define		TRUE				true
#endif

#ifndef FALSE
#define 	FALSE				false
#endif

#define 	BOOL				bool
#define 	INVALID_HANDLE 		-1
#define 	BITS_PER_BYTE 		8
#define 	SQIFOUT							/* outbound parameter    */
#define 	SQIFIN							/* inbound  parameter    */
#define 	SQIFINOUT						/* in and out  parameter */
#define		VARIANT_TRUE		true
#define		VARIANT_FALSE 		false
#define		STDMETHOD			virtual HRESULT 
#define 	S_OK				0

typedef std::string	CString;
typedef std::string	tstring;

#ifndef SAFE_STROPS_DEFINED
#define SAFE_STROPS_DEFINED
#define _stprintf_s     Lxstprintf_s
#define _stscanf_s      Lxstscanf_s
#define _tcscat_s       Lxtcscat_s
#define _tcscpy_s       Lxtcscpy_s
#define _tcsncpy_s      Lxtcsncpy_s
#define _tcserror_s     Lxtcserror_s
#define _tfopen_s       Lxtfopen_s
#endif

#ifndef UNICODE
#define _stprintf		sprintf
#define _stscanf		sscanf
#define _tcslen			strlen
#define _tcscpy			strcpy
#define _tcsncpy		strncpy
#define _tcscat			strcat
#define _tcscmp			strcmp
#define _ttoi			atoi
#define _tcsdup         strdup
#define _tcstok         strtok
#else
#error "Unicode not yet supported"
#endif


#define MAX(a,b)  (a)>(b)?a:b
#define MIN(a,b)  (a)<(b)?a:b

typedef struct IID
{
	ULONG		Data1;
	USHORT		Data2;
	USHORT		Data3;
	UCHAR		Data4[8];
} IID;

typedef	IID				GUID;
typedef const GUID&		REFGUID;
typedef const GUID&		REFIID;
typedef GUID *			LPGUID;
typedef void			IXMLDOMNode;

inline bool InlineIsEqualGUID(REFGUID g1, REFGUID g2)
{
	return g1.Data1==g2.Data1 &&
		   g1.Data2==g2.Data2 &&
		   g1.Data3==g1.Data3 &&
		   memcmp(&g1.Data4[0],&g2.Data4[0],8)==0;
}

extern "C" const GUID			GUID_NULL;
extern "C" const IID			IID_NULL;

#ifndef STRGUID_SIZE
#define STRGUID_SIZE 128
#endif 


#if __WORDSIZE==64
class tris_timeval
{
public:
	int32_t		tv_sec;
	int32_t		tv_usec;

operator timeval ()
{
	timeval tout; tout.tv_sec=tv_sec;tout.tv_usec=tv_usec;
	return tout;
}
operator const timeval () const 
{
	timeval tout; tout.tv_sec=tv_sec;tout.tv_usec=tv_usec;
	return tout;
}
tris_timeval& operator =(const timeval& t)
{
	tv_sec=t.tv_sec;
	tv_usec=t.tv_usec;
    return *this;
}
};
#define TRIS_TIMEVAL_DEFINED 1
#else
typedef struct timeval	tris_timeval;
#endif

#ifndef  LINUX_SYSALLOCSTRING_DEFINED
#define  LINUX_SYSALLOCSTRING_DEFINED
inline BSTR SysAllocString(const char * str)
{
	size_t slen = _tcslen(str);
	BSTR pout = new char[slen+1];
	_tcscpy(pout,str);
	return pout;
}
inline void SysFreeString(BSTR  str)
{
	delete [] str;
}
#endif 


#ifndef DEFINE_GUID
#define DEFINE_GUID(gname, d1, d2, d3, b1, b2, b3, b4, b5, b6, b7, b8 ) \
    const GUID gname = {  d1, d2, d3, { b1, b2, b3, b4, b5, b6, b7, b8 }  };
#endif

#define DEF_TRC_FILE(x) 	static const TCHAR * D_FL = #x;
#define DEF_TRC_METHOD(x) 	static const TCHAR * D_FN = #x;
#define TRC_LOC				D_FL D_FN

#endif
