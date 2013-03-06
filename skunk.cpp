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

#include "skunk.h"
#include "SkunkApp.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "PFSender.h"
#include "PcapSender.h"
#include <cstring>
#include "MiscUtils.h"
#include <unistd.h>

int main (int argc, char **argv)
{
	if (argc!=4 &&  argc!=5 )
	{
		fprintf(stderr,"Usage: skunk /path/to/config/file sourcedir interface <tbeginunixtime> \n");
		fprintf(stderr,"        <tbeginunixtime> - optional start timestamp (num secs from Jan 1 1970)\n");
		return -1;
	}

	///////////////////////////////////////////////////
	// Check if config file exists 
	CString csConfigFile (argv[1]);
	if (!MiscUtils::ValidFile(csConfigFile.c_str()))
	{
		fprintf(stderr,"Config file %s does not exist\n", csConfigFile.c_str());
		return -1;
	}

	////////////////////////////////////////////////////
	// Check if sourcedir exists & remove trailing slash
	CString csSourceFile (argv[2]);
    size_t slash = csSourceFile.rfind('/');
    if (slash!=std::string::npos && slash==csSourceFile.length()-1)
    {
        csSourceFile.erase(slash);
    }
       
	if ( !MiscUtils::ValidDir(csSourceFile.c_str()) &&
	     !MiscUtils::ValidFile(csSourceFile.c_str())) 
	{
		fprintf(stderr,"Source directory %s does not exist or is not a directory\n", csSourceFile.c_str());
		return -1;
	}

	////////////////////////////////////////////////////
	// Interface (lo, eth0, or whatever)
	CString csInterface (argv[3]);
	sleep(1);

	// If start timestamp present validate it 
	timeval start_tm;
	start_tm.tv_sec=0;start_tm.tv_usec=0;
	if (argc==5)
	{
		char * eptr=NULL;
		start_tm.tv_sec = strtol(argv[4],&eptr,10);
		if (eptr==NULL)
		{
			fprintf(stderr,"Invalid begin timestamp (expecting a number) %s \n", argv[4]);
			return -1;
		}
		
	}
	
	/////////////////////////////////////////////////////
	// Pass control to SkunkApp and relax !
	CSkunkApp App;
	App.SetSourceFolder(csSourceFile.c_str());
	App.SetConfigFile(csConfigFile.c_str());
	App.SetInterface(csInterface.c_str());
	// App.SetSender(new CPcapSender);
	App.SetSender(new CPFSender);
	App.SetStartTime(start_tm);
	App.InitInstance();

	return 0;
}
