/*********************************************************************************
 * MiscUtils.h
 * $Id: MiscUtils.h 5589 2013-02-27 08:43:41Z vivek $
 *                                                                               * 
 * History                                                                       *
 * -------                                                                       *
 * 12/14  Lookup DLL name given COM server CLSID                                 *
 *                                                                               * 
 *********************************************************************************/
#if !defined(AFX_MISCUTILS_H__09543749_0EC4_40B7_A992_7682DE6BFF6C__INCLUDED_)
#define AFX_MISCUTILS_H__09543749_0EC4_40B7_A992_7682DE6BFF6C__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifdef LINUX_BUILD
#include "linuxdefs.h"
#endif


class MiscUtils
{
public:
    static bool     ValidDir(const tstring&  strDir);
    static bool     ValidFile(const tstring&  strDir);
    static bool     EnsureDirExists(const tstring& strDir);
    static bool     HasTTY();
    
    static inline void endian_swap(unsigned short& x)
    {
        x = (x>>8) | 
            (x<<8);
    }
#if __WORDSIZE==32
    static inline void endian_swap(long int& x)
    {
        endian_swap((int32_t&) x);
    }
    static inline void endian_swap(long unsigned int& x)
    {
        endian_swap((u_int32_t&) x);
    }
#endif
    
    static inline void endian_swap(int32_t & x)
    {
        endian_swap((u_int32_t&) x);
    }
    static inline void endian_swap(u_int32_t & x)
    {
        x = (x>>24) | 
            ((x<<8) & 0x00FF0000) |
            ((x>>8) & 0x0000FF00) |
            (x<<24);
    }    
    static inline void endian_swap(::int64_t & x)
    {
        endian_swap((u_int64_t&) x);
    }
    static inline void endian_swap(u_int64_t & x)
    {
    union {
        struct {
            u_int32_t   hi;
            u_int32_t   lo;
        } Un;
        u_int64_t       q;
    };
    q=x;
    endian_swap( Un.hi);
    endian_swap( Un.lo);

    x=q;
    }    
    static inline BYTE    Hex2Byte(TCHAR n1, TCHAR n2)
    {
        n1=toupper(n1);
        n2=toupper(n2);

        BYTE b1=(BYTE) isdigit(n1)?(n1-'0'):(n1-'A'+10);
        BYTE b2=(BYTE) isdigit(n2)?(n2-'0'):(n2-'A'+10);

        return (b1<<4)|b2;
    }    

	static inline TCHAR *   Byte2Hex(BYTE a1, TCHAR * pBuf)
	{
		static const TCHAR  HexLkp[] =
		{
			  _T('0'),_T('1'),_T('2'),_T('3'),
			  _T('4'),_T('5'),_T('6'),_T('7'),
			  _T('8'),_T('9'),_T('a'),_T('b'),
			  _T('c'),_T('d'),_T('e'),_T('f'),
		};
		*pBuf++=HexLkp[(a1&0xf0)>>4];
		*pBuf++=HexLkp[ a1&0x0f];
		*pBuf=0;
		return pBuf;  
	}

};

#endif // !defined(AFX_MISCUTILS_H__09543749_0EC4_40B7_A992_7682DE6BFF6C__INCLUDED_)
