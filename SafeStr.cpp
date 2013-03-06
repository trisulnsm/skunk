// Safe string operations
#include "SafeStr.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

int Lxstprintf_s(char * buf, size_t buflen, const char * fmt, ...)
{
    va_list  ap;
    va_start(ap, fmt);
    int n = vsprintf (buf,  fmt, ap);
    va_end(ap);
    return n;
}
int Lxstscanf_s(char * buf, const char * fmt, ...)
{
    va_list  ap;
    va_start(ap, fmt);
    int n = vsscanf (buf,  fmt, ap);
    va_end(ap);
    return n;
}
char * Lxtcscat_s(char * buf, size_t buflen, const char * str)
{
    return strcat(buf,str);
}
char * Lxtcscpy_s(char * buf, size_t buflen, const char * str)
{
    return strcpy(buf,str);
}
char * Lxtcsncpy_s(char * buf, size_t buflen, const char * str, size_t nchars)
{
    return strncpy(buf,str,nchars);
}
int sprintf_s(char * buf, size_t buflen, const char * fmt, ...)
{
    va_list  ap;
    va_start(ap, fmt);
    int n = vsprintf (buf,  fmt, ap);
    va_end(ap);
    return n;
}

char *   Lxtcserror_s(char  * buf, size_t buflen, int eno)
{
    return strerror_r(eno,buf,buflen);
}


int     Lxtfopen_s(FILE ** ppfp, const char * filename, const char * mode)
{
    FILE * fp = fopen(filename,mode);
    *ppfp = fp;
    return fp ? 0 : -1;
}
