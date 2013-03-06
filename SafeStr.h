/*
 *   Filename:  safestrops.h
 * 
 *   Description:  Safe string operations on linux
 *   We really like the _tcscpy_s type of functions on the VC platform, 
 *   The code base is full of them, but on linux we need to stub it.
 */

#ifndef  SAFESTROPS2_INC
#define  SAFESTROPS2_INC

/* only for linux builds, VC9 already has all these functions */
#include <sys/types.h>
#include <stdio.h>

/* linuxified windows crt safe functions */
int 		Lxstprintf_s(char * buf, size_t buflen, const char * fmt, ...);
int 		Lxstscanf_s(char * buf, const char * fmt, ...);
char * 	Lxtcscat_s(char * buf, size_t buflen, const char * str);
char *   Lxtcscpy_s(char * buf, size_t buflen, const char * str);
char *   Lxtcsncpy_s(char * buf, size_t buflen,  char const * str, size_t nchars);
int      sprintf_s(char * buf, size_t buflen, const char * fmt, ...);
char *   Lxtcserror_s(char * buf, size_t buflen, int eno);
int      Lxtfopen_s(FILE ** ppfp, const char  * filename, const char * mode);

#endif   /* ----- #ifndef SAFESTROPS_INC  ----- */

