// MiscUtils.cpp: implementation of the MiscUtils class.
//
//////////////////////////////////////////////////////////////////////
#include "MiscUtils.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/**
 * Is this a valid directory
 * @param lpszDir 
 * @return 
 */
bool     MiscUtils::ValidDir(const tstring&  strDir)
{
    struct stat st;
    memset(&st,0,sizeof(struct stat));
    stat(strDir.c_str(),&st);
    return S_ISDIR(st.st_mode)?true:false;
}

/**
 * Is this a valid file
 * @param lpszDir 
 * @return 
 */
bool     MiscUtils::ValidFile(const tstring&  strFile)
{
    struct stat st;
    memset(&st,0,sizeof(struct stat));
    stat(strFile.c_str(),&st);
    return S_ISREG(st.st_mode)?true:false;
}

/**
 * Create directory if not exists 
 * @param lpszDir 
 * @return 
 */
bool	MiscUtils::EnsureDirExists(const tstring& tsDir)
{
	if (!ValidDir(tsDir.c_str()))
	{
		int ret  = mkdir(tsDir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	    if (ret<0)
		{
			return false;
		}
	}
	return true;
}

////////////////////////////////////////////
// HasTTY - controlling terminal ?
bool    MiscUtils::HasTTY()
{
  char szTTY[128];
  szTTY[0]=0;
  return (ttyname_r(1, szTTY, 127)==0) && strlen(szTTY)>3;
}

