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

#include "SkunkApp.h"
#include "Impex_Libpcap.h"
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "xmlParser.h"
#include <cstring>
#include <arpa/inet.h>
#include "MiscUtils.h"

const double CSkunkApp::FixedMultipliers[] =
{
    0.02, 0.05,  0.08,  0.10,  0.125,
    0.15, 0.175, 0.20,  0.225, 0.25,
    0.27, 0.28,  0.30,  0.31,  0.33, 
    0.35, 0.37,  0.40,  0.45,  0.50,
    0.55, 0.60,  0.625, 0.70,  0.75, 
    0.80, 0.85,  0.90,  0.95,  1.00,
    1.25, 1.50,  1.75,  1.9,   2.00,
    2.25, 2.50,  2.75,  2.9,   3.00,
    3.25, 3.50,  3.75,  3.9,   4.00,
    4.25, 4.50,  4.75,  4.9,   5.00,
    6.00, 7.00,  8.00,  9.00,  10.00,
    12.0, 15.0,  17.0,  18.00, 20.00,
    22.0, 25.0,  27.0,  28.00, 30.00,
    35.0, 40.0,  45.0,  47.50, 50.00,
    60.0, 70.0,  80.0,  90.0,  100.00,
};


const double CSkunkApp::FixedTimeWindowMultipliers[] = 
{
   0.01,  0.02,  0.05,    0.08,    0.10,  
   0.20,  0.25,  0.50,    0.75,    1.00,
   1.00,  2.00,  3.00,    4.00,    5.00,
   6.00,  7.00,  8.00,    9.00,    10.00,
   12.00, 15.00, 16.00,   19.00,   20.00, 
   30.00, 40.00, 50.00,   70.00,   100.00,
};

CSkunkApp::CSkunkApp()
: 	pSender(NULL),
	ePlayMode(PLAY_FIRST_PACKET_FIXED_RATE),
	nPacketsPlayed(0),
	lBytesPlayed(0),
	lTotalBytesPlayed(0),
    fTerminate(false),
    m_nCurrentIteration(1),
	fUseTimeTunnel(true),
	fUseMACTunnel(false),
	fUseMACLink(false)
{
	// default is  April 1, 2004
	struct tm tmDefault;
	memset(&tmDefault, 0, sizeof(struct tm));
	tmDefault.tm_year = 104;
	tmDefault.tm_mon=3;
	tmDefault.tm_mday=1;
	time_t ts = mktime(&tmDefault);

	m_tmLastPlay.tv_sec=ts;
	m_tmLastPlay.tv_usec=0;

	tmLastSample=m_tmLastPlay;
    TimeUtils::ZeroOut(tmLastScreenUpdate);

	// fixed rate options
	optRate.nBps=1000000;		// 1 mbps default
    optRate.fMultiplier=1.0;    // 1x (same rate)
    optRate.nLoopCount=-1;      // repeat infinitely
	optRate.fTimeWindowMultiplier=1.0;	// timewindow
	optRate.nPps=200;			// 100 packets per second default

	memset(&macTunnelSrcMAC, 0, MAC_ADDRESS_LENGTH);
	memset(&macTunnelDstMAC, 0, MAC_ADDRESS_LENGTH);

	memset(&macLinkSrcMAC, 0, MAC_ADDRESS_LENGTH);
	memset(&macLinkDstMAC, 0, MAC_ADDRESS_LENGTH);
}

CSkunkApp::~CSkunkApp()
{
	UninitScreen();
}
BOOL	CSkunkApp::InitInstance()
{
	try {
		return _IntInitInstance();
	} catch (const std::exception& ex) {
		endwin();
		fprintf(stderr,"\n\n\n\nFailed to run skunk : %s\n", ex.what());
		return FALSE;
	}

}

BOOL	CSkunkApp::_IntInitInstance()
{

    if (!ReadConfiguration())
    {
        return FALSE;
    }


    InitScreen();
	mvwprintw(m_wndOut,0,1,"Skunk - Traffic Generator for Trisul");
	wrefresh(m_wndOut);

	mvwprintw(m_wndStatusBar,0,1,"q - quit | up - increase  | dn - decrease | + - expand | - shrink");
	wrefresh(m_wndStatusBar);

    m_nCurrentIteration=1;
    while (!fTerminate && (optRate.nLoopCount<0 || m_nCurrentIteration<=optRate.nLoopCount))
    {
		if (MiscUtils::ValidDir(strSourceFile.c_str()))
		{
		   PlaybackDirectory(strSourceFile.c_str());
		} 
		else if (MiscUtils::ValidFile(strSourceFile.c_str()))
		{
		   PlaybackFile(strSourceFile.c_str());
		}
		else
		{
			fprintf(stderr,"Specified file %s is not a regular file or a directory\n", strSourceFile.c_str());
			return FALSE;
		}
        m_nCurrentIteration++;   
    }   

	return TRUE;
}

void	CSkunkApp::SetStartTime(const timeval& tm)
{
	m_tmLastPlay=tm;
}
void	CSkunkApp::SetSourceFolder(LPCTSTR lpszPath)
{
	strSourceFile=lpszPath;
}
void	CSkunkApp::SetConfigFile(LPCTSTR lpszConfigFile)
{
	strConfigFile=lpszConfigFile;
}
void	CSkunkApp::SetInterface(LPCTSTR lpszVal)
{
	strInterface=lpszVal;
}
void	CSkunkApp::SetError(LPCTSTR lpszVal)
{
	strError=lpszVal;
}
///////////////////////////////////////////////////////////////////////////////////////
// (FRIEND)
//  CB_OffinePacketCallback WINPCAP pcap_loop callback
//  Called when importing from a capture file
///////////////////////////////////////////////////////////////////////////////////////
void  CB_OfflinePacketCallback(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	CSkunkApp * pDelegate = (CSkunkApp*) param;
	pDelegate->SynchronizedPktCallbackHandler(header,pkt_data);
}

///////////////////////////////////////////////////////////////////////////////////////
// SynchronizedPktCallbackHandler
//		We send windows messages only every 100 packets, other times we rely on timers
//		to flush the queue
///////////////////////////////////////////////////////////////////////////////////////
void CSkunkApp::SynchronizedPktCallbackHandler( const struct pcap_pkthdr * pHeader, 
												const u_char * pkt_data)
{
	// Update packet statistics 
	snfStats.nTotalPktsWire++;
	snfStats.nTotalPktsCaptured++;
	snfStats.nTotalBytesWire+=pHeader->len;
	snfStats.nTotalBytesCaptured+=pHeader->caplen;
	

}
////////////////////////////////////////////////////////////////////
//	StartFileImportLoop		
//		Stream in packets from the given pcap file 
////////////////////////////////////////////////////////////////////
BOOL CSkunkApp::StartFileImportLoop(LPCTSTR lpszFile)
{
	fprintf(stdout, "Streaming in packets from file %s\n", lpszFile);

	CImpex_Libpcap Importer(this);

	if(Importer.OpenDumpFile(lpszFile))
	{
		Importer.ProcPackets();
		Importer.CloseDumpFile();
	}

	fprintf(stdout, "Streaming in packets Finished");
	return TRUE;
}
////////////////////////////////////////////////////////////////////////////////////////////////
// Playback Dir
//      playback all files in the specified directory, apply a profile when playing back
////////////////////////////////////////////////////////////////////////////////////////////////
#undef  D_FN
#define D_FN _T("PlaybackDir : ")
BOOL CSkunkApp::PlaybackDirectory(LPCTSTR lpszPlugInDirectory)
{
        DIR     *dirp;
        struct   dirent *dp;

        dirp = opendir (lpszPlugInDirectory);
        if (!dirp)
        {
            sprintf(errBuf,"Unable to open playback directory, cannot continue %s",lpszPlugInDirectory ); 
            return FALSE;
        }

        
        mvwprintw(m_wndOut,2,1, "Playing files in  %s", lpszPlugInDirectory);
        mvwprintw(m_wndOut,2,65,"Iteration : %d", m_nCurrentIteration);
        wrefresh(m_wndOut);

        // process each plugin file (*.so) in the folder
        while (!fTerminate && ((dp = readdir (dirp)) != 0))
        {
            // convert to a full path
            tstring  csCapFile (lpszPlugInDirectory);
            csCapFile += _T("/");
            csCapFile += dp->d_name;

			PlaybackFile(csCapFile);

        }
        
        return TRUE;
}


BOOL CSkunkApp::PlaybackFile(const tstring& csCapFile)
{
	// some stats 
    mvwprintw(m_wndOut,2,1, "Playing single  file " );
    mvwprintw(m_wndOut,2,65,"Iteration : %d", m_nCurrentIteration);
    wrefresh(m_wndOut);

	// only process normal files
	struct stat st;
	memset(&st,0,sizeof(struct stat));
	stat(csCapFile.c_str(),&st);
	mvwprintw(m_wndOut,3,1,"Now Playing       %s", csCapFile.c_str());
	mvwprintw(m_wndOut,4,1,"Interface         %s", strInterface.c_str());
	wrefresh(m_wndOut);

	if(S_ISREG(st.st_mode))
	{
		switch (ePlayMode)
		{
			case PLAY_NATURAL_RATE:
					PlayFileProportional(csCapFile.c_str());
					break;

			case PLAY_FIRST_PACKET_FIXED_RATE:
					PlayFirstPacketLoop(csCapFile.c_str());
					break;
					
			case PLAY_FIXED_RATE_TIME_EXPAND:
					PlayFileFixedTimeExpand(csCapFile.c_str());
					break;

			default:
					sprintf(errBuf,"Unknown playback mode\n");
					return FALSE;
		}
	}

	return TRUE;
}


//////////////////////////////////////////////////////////////////////////////////
// PlayFileProportional
//		Open the sender and play out the file, packet rate out of interface is
//      proportional to what is seen in capture file
//////////////////////////////////////////////////////////////////////////////////
BOOL	CSkunkApp::PlayFileProportional(LPCTSTR lpszCapFile)
{
		char error[256];
		pcap_t *fpIn;
		long    lPacketsPlayed=0;

		assert(pSender);

        UpdateControlWindow_NaturalRate();

		//////////////////////////
		// Open the output adapter 
		if (!pSender->Open(strInterface.c_str()))
		{
			sprintf(errBuf,"\nError opening adapter: %s\n", pSender->GetLastError());
			SetError(pSender->GetLastError());
			return FALSE;
		}

		//////////////////////////////
		// Open the input capture file 
		if((fpIn = pcap_open_offline(lpszCapFile, error)) == NULL)
		{
			sprintf(errBuf,"\nError opening input capture file : %s\n", error);
			SetError(errBuf);
			return FALSE; 
		}

		// Read and send down each packet, calculate a delay based on user options
		pcap_pkthdr * pktheader;
		const UCHAR * pktdata;
		int   res=0;
		BYTE  outPkt[MAX_PACKET_LEN];

		// Set up timers
		timeval tPlay = m_tmLastPlay;
		timeval tLastCap;
		TimeUtils::ZeroOut(tLastCap);

        bool done=false;
		while(!done && ((res = pcap_next_ex( fpIn, &pktheader, &pktdata)) == 1))
		{
        
            // handle ncurses interaction 
            int current_getch = getch();
            if (current_getch>=0)
            {
               if (!HandleUserInput(current_getch))
               {
                    done=true;
                    fTerminate=true;
                    continue;
                }
            }
            
            // handle rate change
            if (fOptRateChanged)
            {
                fOptRateChanged=false;
                UpdateControlWindow_NaturalRate();
            }

			// precede with new timestamp
			timeval tDelta;
			if (tLastCap.tv_sec>0)
			{
				tDelta = TimeUtils::Diff(pktheader->ts,tLastCap);
                double usecDelta = tDelta.tv_sec*USECS_PER_SEC+tDelta.tv_usec;
                usecDelta = usecDelta/optRate.fMultiplier;            
                tDelta.tv_sec = (long) usecDelta/USECS_PER_SEC;
                tDelta.tv_usec = (long) usecDelta%USECS_PER_SEC;

				// if we find outof order timestamps, use the last ts as is
				if (tDelta.tv_sec<0 || tDelta.tv_usec<0)
				{
					tDelta.tv_sec=0;
					tDelta.tv_usec=0;
				}
			}
			else
			{
				tDelta.tv_sec= SECS_GAP_BETWEEN_CAPFILES;
				tDelta.tv_usec= 0;
			}
			tPlay  = TimeUtils::Add(tPlay, tDelta);
			tLastCap = pktheader->ts;


            // sleep for a while
			if (tDelta.tv_sec>0 || tDelta.tv_usec> 50)
			{
				usleep(tDelta.tv_sec*1000000+tDelta.tv_usec);
			}


			BYTE * outPktPtr = outPkt;

			// if use mac tunnel
			if (fUseMACTunnel)
			{
				memcpy(outPktPtr,macTunnelDstMAC,MAC_ADDRESS_LENGTH);
				outPktPtr+=MAC_ADDRESS_LENGTH;
				memcpy(outPktPtr,macTunnelSrcMAC,MAC_ADDRESS_LENGTH);
				outPktPtr+=MAC_ADDRESS_LENGTH;
				USHORT tunethtype = htons(TUNNEL_ETHERTYPE);
				memcpy(outPktPtr,&tunethtype,sizeof(USHORT));
				outPktPtr+=sizeof(USHORT);
			}


			// if use mac link 
			if (fUseMACLink)
			{
				memcpy(outPktPtr,macLinkDstMAC,MAC_ADDRESS_LENGTH);
				outPktPtr+=MAC_ADDRESS_LENGTH;
				memcpy(outPktPtr,macLinkSrcMAC,MAC_ADDRESS_LENGTH);
				outPktPtr+=MAC_ADDRESS_LENGTH;
				pktdata+=2*MAC_ADDRESS_LENGTH;
				pktheader->caplen-=2*MAC_ADDRESS_LENGTH;
			}

			
			// handle tunneling
			if (fUseTimeTunnel)
			{
				// create new packet with preceding timestamp +[macaddr][ip]..
				memcpy(outPktPtr,&tPlay,sizeof(timeval));
				outPktPtr += sizeof(timeval);
			}


			// send raw packet out the interface
			memcpy(outPktPtr,pktdata,pktheader->caplen);
			outPktPtr += pktheader->caplen;
			pSender->SendPacket(outPkt, outPktPtr-outPkt );
            
            // update ncurses user interface every 100 packets
            ++nPacketsPlayed;
            lBytesPlayed += pktheader->caplen;
			lTotalBytesPlayed += pktheader->caplen;
			++lPacketsPlayed;

            if (nPacketsPlayed%10==0)
            {
                // update only if it has been a while ! (to prevent rapid updates)
                if (tPlay.tv_sec-tmLastScreenUpdate.tv_sec>=SCREEN_FEEDBACK_SECONDS)
                {
                    ULONG msecsDiff = TimeUtils::TmDiffMs(tPlay,tmLastSample);

                    double bps = 0.0;
                    double pps = 0.0;
    
                    if (msecsDiff)
					{
                       bps=(double) ( lBytesPlayed * 8 * 1000) / (double) msecsDiff;
                       pps=(double) ( lPacketsPlayed * 1000  ) / (double) msecsDiff;
					}

                    tmLastSample=tPlay;
                    lBytesPlayed=0;
                    lPacketsPlayed=0;
                    tstring  bpsString ( FormatUnits( (long) bps,"bps") );
                    tstring  ppsString ( FormatUnits( (long) pps,"pps") );
    
					if (fUseTimeTunnel)
						mvwprintw(m_wndOut,5,1,"Timestamp         %s",    tmUtils.FormatTimestamp(tPlay));
					else
						mvwprintw(m_wndOut,5,1,"Timestamp         %s",    tmUtils.FormatTimestamp(tLastCap));

                    // update traffic details
                    mvwprintw(m_wndOut,6,1,"Packets           %ld",   nPacketsPlayed);
					wattron(m_wndOut,A_BOLD|COLOR_PAIR(3));
                    mvwprintw(m_wndOut,6,55,"%6.0f (%12s)",  pps, ppsString.c_str() );
					wattroff(m_wndOut,A_BOLD|COLOR_PAIR(3) );

                    // blank out Bandwidth field first
                    mvwprintw(m_wndOut,7,1, "%70s",  " " ); 
                    mvwprintw(m_wndOut,7,1, "Bytes             %lld",  lTotalBytesPlayed );
					wattron(m_wndOut,A_BOLD|COLOR_PAIR(3));
                    mvwprintw(m_wndOut,7,55,"%6.0f (%12s)",  bps, bpsString.c_str() );
					wattroff(m_wndOut,A_BOLD|COLOR_PAIR(3) );
					

                    wrefresh(m_wndOut);              
                    
                    tmLastScreenUpdate=tPlay;
                }
            }
            

		}
		m_tmLastPlay=tPlay;

		pSender->Close();

		return TRUE;
}

//////////////////////////////////////////////////////////////////////////////////
// PlayFileFixedTimeExpand
//      Output is a fixed rate (i.e. usleep is throttled). The timestamps are
//      timeexpanded. Eg a 15 min capture file can be played as 1 hr
//////////////////////////////////////////////////////////////////////////////////
BOOL    CSkunkApp::PlayFileFixedTimeExpand(LPCTSTR lpszCapFile)
{
        char error[256];
        pcap_t *fpIn;

        assert(pSender);

        //////////////////////////
        // Open the output adapter 
        if (!pSender->Open(strInterface.c_str()))
        {
            sprintf(errBuf,"\nError opening adapter: %s\n", pSender->GetLastError());
            SetError(pSender->GetLastError());
            return FALSE;
        }

        //////////////////////////////
        // Open the input capture file 
        if((fpIn = pcap_open_offline(lpszCapFile, error)) == NULL)
        {
            sprintf(errBuf,"\nError opening input capture file : %s\n", error);
            SetError(errBuf);
            return FALSE; 
        }

        // Read and send down each packet, calculate a delay based on user options
        pcap_pkthdr * pktheader;
        const UCHAR * pktdata;
        int   res=0;
        BYTE  outPkt[MAX_PACKET_LEN];

        // Set up timers
        timeval tPlay = m_tmLastPlay;
        timeval tLastCap;
        TimeUtils::ZeroOut(tLastCap);
		ULONG sleep_usecs=0;

        bool done=false;
        while(!done && ((res = pcap_next_ex( fpIn, &pktheader, &pktdata)) == 1))
        {
        
            // handle ncurses interaction 
            int current_getch = getch();
            if (current_getch>=0)
            {
               if (!HandleUserInput(current_getch))
               {
                    done=true;
                    fTerminate=true;
                    continue;
                }
            }
            
            // handle rate change
            if (fOptRateChanged)
            {
                fOptRateChanged=false;
                UpdateControlWindow_TimeExpand();
            }

            // precede with new timestamp
            timeval tDelta;
            if (tLastCap.tv_sec>0)
            {
                tDelta = TimeUtils::Diff(pktheader->ts,tLastCap);
                double usecDelta = tDelta.tv_sec*USECS_PER_SEC+tDelta.tv_usec;
                usecDelta = usecDelta*optRate.fTimeWindowMultiplier;            
                tDelta.tv_sec = (long) usecDelta/USECS_PER_SEC;
                tDelta.tv_usec = (long) usecDelta%USECS_PER_SEC;

				// if we find outof order timestamps, use the last ts as is
				if (tDelta.tv_sec<0 || tDelta.tv_usec<0)
				{
					tDelta.tv_sec=0;
					tDelta.tv_usec=0;
				}

                // we need to transmit at this interval
                sleep_usecs=(1000000) / optRate.nPps;
            }
            else
            {
                tDelta.tv_sec= SECS_GAP_BETWEEN_CAPFILES;
                tDelta.tv_usec= 0;
            }
            tPlay  = TimeUtils::Add(tPlay, tDelta);
            tLastCap = pktheader->ts;


            // sleep for a while
            usleep(sleep_usecs);

			
			BYTE * outPktPtr = outPkt;

			// if use mac tunnel
			if (fUseMACTunnel)
			{
				memcpy(outPktPtr,macTunnelDstMAC,MAC_ADDRESS_LENGTH);
				outPktPtr+=MAC_ADDRESS_LENGTH;
				memcpy(outPktPtr,macTunnelSrcMAC,MAC_ADDRESS_LENGTH);
				outPktPtr+=MAC_ADDRESS_LENGTH;
				USHORT tunethtype = htons(TUNNEL_ETHERTYPE);
				memcpy(outPktPtr,&tunethtype,sizeof(USHORT));
				outPktPtr+=sizeof(USHORT);
			}


			// if use mac link 
			if (fUseMACLink)
			{
				memcpy(outPktPtr,macLinkDstMAC,MAC_ADDRESS_LENGTH);
				outPktPtr+=MAC_ADDRESS_LENGTH;
				memcpy(outPktPtr,macLinkSrcMAC,MAC_ADDRESS_LENGTH);
				outPktPtr+=MAC_ADDRESS_LENGTH;
				pktdata+=2*MAC_ADDRESS_LENGTH;
				pktheader->caplen-=2*MAC_ADDRESS_LENGTH;
			}

			
			// handle tunneling
			if (fUseTimeTunnel)
			{
				// create new packet with preceding timestamp +[macaddr][ip]..
				memcpy(outPktPtr,&tPlay,sizeof(timeval));
				outPktPtr += sizeof(timeval);
			}


			// send raw packet out the interface
			memcpy(outPktPtr,pktdata,pktheader->caplen);
			outPktPtr += pktheader->caplen;
			pSender->SendPacket(outPkt, outPktPtr-outPkt );
            
            // update ncurses user interface every 100 packets
            ++nPacketsPlayed;
            lBytesPlayed += pktheader->caplen;
            if (nPacketsPlayed%100==0)
            {
                // update only if it has been a while ! (to prevent rapid updates)
                if (tPlay.tv_sec-tmLastScreenUpdate.tv_sec>=SCREEN_FEEDBACK_SECONDS)
                {
                    ULONG msecsDiff = TimeUtils::TmDiffMs(tPlay,tmLastSample);

                    double bps = 0.0;
    
                    if (msecsDiff)
                            bps=(double) ( lBytesPlayed * 8 * 1000) / (double) msecsDiff;
                    else
                            bps=0.0;
    
                    tmLastSample=tPlay;
                    lBytesPlayed=0;
                    LPCTSTR bpsString = FormatUnits( (long) bps,"bps");
    
                    // update traffic details
                    mvwprintw(m_wndOut,5,1,"Packets           %ld",   nPacketsPlayed);

					if (fUseTimeTunnel)
						mvwprintw(m_wndOut,6,1,"Timestamp         %s",    tmUtils.FormatTimestamp(tPlay));
					else
						mvwprintw(m_wndOut,6,1,"Timestamp         %s",    tmUtils.FormatTimestamp(tLastCap));

                    // blank out Bandwidth field first
                    mvwprintw(m_wndOut,7,1,"%70s",  " " ); 
                    mvwprintw(m_wndOut,7,1,"Bandwidth         %.0f bps (%s)",  bps, bpsString );
                    wrefresh(m_wndOut);              
                    
                    tmLastScreenUpdate=tPlay;
                }
            }
            

        }
        m_tmLastPlay=tPlay;

        pSender->Close();

        return TRUE;
}

//////////////////////////////////////////////////////////////////////////////////
// PlayLoopRate
// 		Play the first packet only at a fixed rate
//////////////////////////////////////////////////////////////////////////////////
BOOL	CSkunkApp::PlayFirstPacketLoop(LPCTSTR lpszCapFile)
{
		char error[256];
		pcap_t *fpIn;

		assert(pSender);

		//////////////////////////
		// Open the output adapter 
		if (!pSender->Open(strInterface.c_str()))
		{
			sprintf(errBuf,"\nError opening adapter: %s\n", pSender->GetLastError());
			SetError(pSender->GetLastError());
			return FALSE;
		}

		//////////////////////////////
		// Open the input capture file 
		if((fpIn = pcap_open_offline(lpszCapFile, error)) == NULL)
		{
			sprintf(errBuf,"\nError opening input capture file : %s\n", error);
			SetError(errBuf);
			return FALSE; 
		}

		// Read and send down each packet, calculate a delay based on user options
		pcap_pkthdr * pktheader;
		const UCHAR * pktdata;
		int   res=0;
		BYTE  outPkt[MAX_PACKET_LEN];

		// Set up timers
		timeval tPlay = m_tmLastPlay;
		timeval tLastCap;
		TimeUtils::ZeroOut(tLastCap);

        // Read the first packet only (we dont need pcap after this)
		if((res = pcap_next_ex( fpIn, &pktheader, &pktdata)) != 1)
		{
            pSender->Close();
            pcap_close(fpIn);
            return FALSE;
        }
        pcap_close(fpIn);
        
    
                  

        // Play back the first packet for ever until stopped
        bool done=false;
        fOptRateChanged=true;
        timeval  tDelta;
        tDelta.tv_sec  = 0;
        while (!done)
        {

                // handle ncurses interaction 
                int current_getch = getch();
                if (current_getch>=0)
                {
                    if (!HandleUserInput(current_getch))
                    {
                        done=true;
                        fTerminate=true;
                        continue;
                    }
                }

                // uniform rate (depends on position of slider via optRate.nBps)
                if ( fOptRateChanged)
                {
                    fOptRateChanged=false;
                    if (optRate.nBps>0)
                    {
                        // we need to transmit at this interval
                        tDelta.tv_usec =  (pktheader->len * 8 * 1000000) / optRate.nBps;
                    }
                    else
                    {
                        // nothing to transmit we are at 0bps (wait for slider to increase)
                        usleep(50);  
                        continue;    
                    }
                }
            
                tPlay  = TimeUtils::Add(tPlay, tDelta);
                usleep(tDelta.tv_usec);

				// handle tunneling
				if (fUseTimeTunnel)
				{
						// create new packet with preceding timestamp +[macaddr][ip]..
						memcpy(outPkt,&tPlay,sizeof(timeval));
						memcpy(outPkt+sizeof(timeval),pktdata,pktheader->caplen);
						pSender->SendPacket(outPkt, pktheader->caplen + sizeof (timeval) );
				}
				else
				{
						// send raw packet out the interface
						pSender->SendPacket(pktdata, pktheader->caplen);

				}

                // update ncurses user interface every 1000 packets
                ++nPacketsPlayed;
                lBytesPlayed += pktheader->caplen;
                if (nPacketsPlayed%1000 == 0)
                {
                    ULONG msecsDiff = TimeUtils::TmDiffMs(tPlay,tmLastSample);

                    double bps = 0.0;

                    if (msecsDiff)
                            bps=(double) ( lBytesPlayed * 8 * 1000) / (double) msecsDiff;
                    else
                            bps=0.0;

                    tmLastSample=tPlay;
                    lBytesPlayed=0;
                    LPCTSTR bpsString = FormatUnits( (long) bps,"bps");


                    // update traffic details
                    mvwprintw(m_wndOut,4,1,"Packets    : %ld",   nPacketsPlayed);
                    mvwprintw(m_wndOut,5,1,"Timestamp  : %s",    tmUtils.FormatTimestamp(tPlay));
                    mvwprintw(m_wndOut,6,1,"Bandwidth  : %.0f bps (%s)",  bps, bpsString );
                    wrefresh(m_wndOut);

                    UpdateControlWindow_FirstPacketFixed();
                }
        }

		m_tmLastPlay=tPlay;
        
		pSender->Close();

		return TRUE;
}

//////////////////////////////////////////////////////////////////////
// Init Screen : Create two windows for output etc
//////////////////////////////////////////////////////////////////////
int 	CSkunkApp::InitScreen()
{
		m_wndMain = initscr();
        curs_set(0);      
		start_color();
		noecho();
		cbreak();
		nodelay(m_wndMain, TRUE);
		refresh(); 
		wrefresh(m_wndMain);

		// basic colors (not very important) 
	    init_pair(1,COLOR_BLACK,COLOR_WHITE);
		init_pair(2,COLOR_GREEN,COLOR_BLACK);
		init_pair(3,COLOR_RED,COLOR_BLACK);

		// time pane (header + elapsed time + last seen packet timestamp)	
		m_wndOut= newwin(12, 80, 1, 1);
		box(m_wndOut, ACS_VLINE, ACS_HLINE);
		wbkgd(m_wndOut,COLOR_PAIR(2));

		// mode pane 
		m_wndMode= newwin(11, 80, 13, 1);
		box(m_wndMode, ACS_VLINE, ACS_HLINE);
		wbkgd(m_wndMode,COLOR_PAIR(2));

		// status bar 
	    m_wndStatusBar = newwin(1,80,24,1);
		wbkgd(m_wndStatusBar,COLOR_PAIR(1));

		return 0;
}

//////////////////////////////////////////////////////////////////////
// Uninit Screen 
//////////////////////////////////////////////////////////////////////
void	CSkunkApp::UninitScreen()
{
		endwin();
}

/////////////////////////////////////////////////////////////////////////
// Format Units
//		Conver values to .2K, M, G with optional suffix
/////////////////////////////////////////////////////////////////////////
LPCTSTR  	CSkunkApp::FormatUnits(long  rawVal, LPCTSTR lpszSuffix)
{
	static TCHAR	tbuf[128];
	TCHAR	unitChar;
	double  newVal=0.0;

	if (rawVal>=1000000000)
	{
		unitChar='G';
		newVal=(double)rawVal/1000000000;
	}
	else if (rawVal>=1000000)
	{
		unitChar='M';
		newVal=(double)rawVal/1000000;
	}
	else if (rawVal>=1000)
	{
		unitChar='K';
		newVal=(double)rawVal/1000;
	}
	else
	{
		unitChar=' ';
		newVal=rawVal;
	}

	sprintf(tbuf,"%.2f %c%s", newVal,unitChar,lpszSuffix);
	return tbuf;
}


////////////////////////////////////////////////////////////////////////////
// Update Mode Details : 
////////////////////////////////////////////////////////////////////////////
void		CSkunkApp::UpdateControlWindow_FirstPacketFixed()
{
	mvwprintw(m_wndMode,1,1,"Play Mode     : %s",       "Fixed Rate - First Packet" );
	mvwprintw(m_wndMode,2,1,"How it works  : %s",       "Repeat the first packet in the directory at a fixed rate");
	mvwprintw(m_wndMode,4,1,"Bandwidth     : %d (%s)",  optRate.nBps, FormatUnits(optRate.nBps,"bps"));


	mvwprintw(m_wndMode,6,6,"0    1    2    3    4    5    6    7    8    9    10");
	mvwprintw(m_wndMode,7,6,"|----+----+----+----+----+----+----+----+----+----|");

	int nspaces = (5*optRate.nBps)/1000000;
	char buf[256];
	for (int i=0;i<nspaces;i++)
	{
		buf[i]=' ';
	}
	buf[nspaces]=0;
	mvwprintw(m_wndMode,8,6,"%s^       ", buf);
	mvwprintw(m_wndMode,9,6,"%s%s      ", buf, FormatUnits(optRate.nBps,"bps"));

	wrefresh(m_wndMode);
}

////////////////////////////////////////////////////////////////////////////////
// Update Mode Details :  Natural Rate
//		Playback at the file rate (1/10th, 1/8th, 1/4th, 1/2, 1, 2x, 3x, 5x, 10x
////////////////////////////////////////////////////////////////////////////////
void		CSkunkApp::UpdateControlWindow_NaturalRate()
{
	mvwprintw(m_wndMode,1,1,"Play Mode       : %s",       "Natural Rate" );
	mvwprintw(m_wndMode,2,1,"How it works    : %s",       "Proportional to captured speed");
	mvwprintw(m_wndMode,4,1,"Rate multiplier : %.2f",  	  optRate.fMultiplier);


	mvwprintw(m_wndMode,6,1,"0   1/8  1/4  1/3  1/2  3/4   1   2x   3x   4x   5x   10x  20x  30x  50x  100x");
	mvwprintw(m_wndMode,7,1,"|----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+|");

	int nspaces = SpacesForFixedMultiplier(optRate.fMultiplier);
    if (nspaces<0)
    {
        // error condition (go back to 1.0)
        optRate.fMultiplier=1.0;
        fOptRateChanged=true;
        return;   
    }
    
	char buf[256];
	for (int i=0;i<nspaces;i++)
	{
		buf[i]=' ';
	}
	buf[nspaces]=0;
	mvwprintw(m_wndMode,8,1,"%s^       ", buf);
	mvwprintw(m_wndMode,9,1,"%s%0.3f   ", buf, optRate.fMultiplier);

	wrefresh(m_wndMode);
}

////////////////////////////////////////////////////////////////////////////////
// Update Mode Details :  Time Window Expansion & fixed rate
////////////////////////////////////////////////////////////////////////////////
void		CSkunkApp::UpdateControlWindow_TimeExpand()
{
	mvwprintw(m_wndMode,1,1,"Play Mode       : %s",       "Time Window Expansion" );
	mvwprintw(m_wndMode,2,1,"How it works    : %s",       "Fixed packet rate over larger time window");

	// PPS control 
	mvwprintw(m_wndMode,4,1,"Packet Rate     : %d (%s)",   optRate.nPps, FormatUnits(optRate.nPps,"pps"));
	mvwprintw(m_wndMode,6,6,"0    1K   2K   3K   4K   5K");
	mvwprintw(m_wndMode,7,6,"|----+----+----+----+----|");
	int nspaces = (5*optRate.nPps)/1000;
	char buf[256];
	ASSERT(nspaces<(int) sizeof(buf));
	for (int i=0;i<nspaces;i++)
	{
		buf[i]=' ';
	}
	buf[nspaces]=0;
	mvwprintw(m_wndMode,8,6,"%s^       ", buf);
	mvwprintw(m_wndMode,9,6,"%s%s      ", buf, FormatUnits(optRate.nPps,"pps"));


	// ---- control to update time expansion ---- 
	mvwprintw(m_wndMode,4,40,"Time Expand     : %.2f",  	   optRate.fTimeWindowMultiplier);
	mvwprintw(m_wndMode,6,40,"0   1/10  1    5   10   20   100");
	mvwprintw(m_wndMode,7,40,"|----+----+----+----+----+----+|");

	nspaces = SpacesForTimeWindowMultiplier(optRate.fTimeWindowMultiplier);
    if (nspaces<0)
    {
        // error condition (go back to 1.0)
        optRate.fTimeWindowMultiplier=1.0;
        fOptRateChanged=true;
        return;   
    }
    
	ASSERT(nspaces<(int) sizeof(buf));
	for (int i=0;i<nspaces;i++)
	{
		buf[i]=' ';
	}
	buf[nspaces]=0;
	mvwprintw(m_wndMode,8,40,"%s^       ", buf);
	mvwprintw(m_wndMode,9,40,"%s%0.3f   ", buf, optRate.fTimeWindowMultiplier);

	wrefresh(m_wndMode);
}


/////////////////////////////////////////////////////////////////////////////
// Handle User Input
// 		false to quit ; true to continue
/////////////////////////////////////////////////////////////////////////////
bool		CSkunkApp::HandleUserInput(int inchar)
{
		mvwprintw(m_wndStatusBar,0,60,"Pressed %d ",inchar );
		wrefresh(m_wndStatusBar);

	  switch(inchar)
		{
			case 113: /* 'q' to Quit */
				       return false;
	
			case 65:
			case 67:	/* up or right = faster */
						optRate.nBps=HigherFixedBandwidth(optRate.nBps);                  
                        optRate.fMultiplier=HigherFixedMultiplier(optRate.fMultiplier);                  
						optRate.nPps=HigherFixedPacketRate(optRate.nPps);                  
                        fOptRateChanged=true;                  
						return true;
					
			case 66:
			case 68: /* down or left = slower */
						optRate.nBps=LowerFixedBandwidth(optRate.nBps);                  
                        optRate.fMultiplier=LowerFixedMultiplier(optRate.fMultiplier);                  
						optRate.nPps=LowerFixedPacketRate(optRate.nPps);                  
                        fOptRateChanged=true;                  
						return true;

			case '+': /* timewindow expand */
			case '=': /* timewindow expand */
						optRate.fTimeWindowMultiplier=HigherTimeWindowMultiplier(optRate.fTimeWindowMultiplier);
						fOptRateChanged=true;
						break;

			case '-': /* timewindow shrink  */
						optRate.fTimeWindowMultiplier=LowerTimeWindowMultiplier(optRate.fTimeWindowMultiplier);
						fOptRateChanged=true;
						break;

					
			default: 
						break;


		}
		return true;
		
}


////////////////////////////////////////////////////////
// Read Configuration
//      Skunk configuration
//  Mode selector
//  Traffic profile selector
////////////////////////////////////////////////////////
bool    CSkunkApp::ReadConfiguration()
{
        XMLNode xMainNode=XMLNode::openFileHelper(strConfigFile.c_str(),"USNFSkunkConfig");
        XMLNode xModeNode=xMainNode.getChildNode("Mode");

        tstring strModeName=xModeNode.getAttribute("Active");
        if (strModeName=="NATURAL_RATE")
        {
            ePlayMode=PLAY_NATURAL_RATE;
        } 
        else if (strModeName=="FIRST_PACKET_FIXED_RATE")
        {
            ePlayMode=PLAY_FIRST_PACKET_FIXED_RATE;
        }
		else if (strModeName=="TIME_EXPAND")
		{
            ePlayMode=PLAY_FIXED_RATE_TIME_EXPAND;
		}
        else
        {
            fprintf(stderr, "Error : Invalid mode %s in XML Config file", strModeName.c_str());
            return false;
        }

        tstring strUseTunnel=xModeNode.getAttribute("UseTunnel");
		if (strUseTunnel=="TRUE")
		{
			fUseTimeTunnel=true;
		}
		else
		{
			fUseTimeTunnel=false;
		}
        
        // loop count
        XMLNode xLoopNode=xMainNode.getChildNode("Loop");
        tstring strCount=xLoopNode.getAttribute("Count");
        if (strCount=="INFINITE")
        {
            optRate.nLoopCount=-1;
        }
        else
        {
            optRate.nLoopCount=atoi(strCount.c_str());
            if (optRate.nLoopCount==0)
            {
                fprintf(stderr,"Invalid parameter for loop count %s\n", strCount.c_str());
                return false;
            }
        }
        
		// mac tunneling 
        XMLNode xMacTunnelNode=xMainNode.getChildNode("EthMACTunnel");
        tstring strEnabled =xMacTunnelNode.getAttribute("Enabled");
		if (strEnabled=="TRUE")
		{
			fUseMACTunnel=true;

			tstring strmac;
			
			// tunnel src mac
			strmac = xMacTunnelNode.getChildNode("SrcMAC").getText();
			if (!ParseMAC(strmac.c_str(),macTunnelSrcMAC))
			{
				fprintf(stderr,"Invalid mac address");
				exit (-1);
			}

			// tunnel dst mac
			strmac = xMacTunnelNode.getChildNode("DstMAC").getText();
			if (!ParseMAC(strmac.c_str(),macTunnelDstMAC))
			{
				fprintf(stderr,"Invalid mac address");
				exit (-1);
			}
		}
		else
		{
			fUseMACTunnel=false;
		}


		// mac link  
        XMLNode xnMacLink=xMainNode.getChildNode("EthMACLink");
        strEnabled =xnMacLink.getAttribute("Enabled");
		if (strEnabled=="TRUE")
		{
			fUseMACLink=true;

			tstring strmac;
			
			// tunnel src mac
			strmac = xnMacLink.getChildNode("SrcMAC").getText();
			if (!ParseMAC(strmac.c_str(),macLinkSrcMAC))
			{
				fprintf(stderr,"Invalid src mac address");
				exit (-1);
			}

			// tunnel dst mac
			strmac = xnMacLink.getChildNode("DstMAC").getText();
			if (!ParseMAC(strmac.c_str(),macLinkDstMAC))
			{
				fprintf(stderr,"Invalid dest mac address");
				exit (-1);
			}
		}
		else
		{
			fUseMACLink=false;
		}

        return true;
}

// How many spaces on the scale for a given fixed multiplier
int     CSkunkApp::SpacesForFixedMultiplier(double d)
{
    int arrsize=sizeof(FixedMultipliers)/sizeof(double);
    for (int i=arrsize-1;i>=0;i--)
    {
        if (d==FixedMultipliers[i])
        {
            return i+1;
        }    
    }

    return -1;
}

// Next Fixed Multiplier
double  CSkunkApp::HigherFixedMultiplier(double curr)
{
    int arrsize=sizeof(FixedMultipliers)/sizeof(double);
    for (int i=arrsize-2;i>=0;i--)
    {
        if (curr==FixedMultipliers[i])
        {
            return FixedMultipliers[i+1];
        }    
    }
    return curr;
}

// Prev Fixed Multiplier
double  CSkunkApp::LowerFixedMultiplier(double curr)
{
    int arrsize=sizeof(FixedMultipliers)/sizeof(double);
    for (int i=arrsize-1;i>0;i--)
    {
        if (curr==FixedMultipliers[i])
        {
            return FixedMultipliers[i-1];
        }    
    }
    return curr;
}

// Lower Bandwidth (eg, in steps of 200K down to zero
long    CSkunkApp::LowerFixedBandwidth(long curr)
{
    return (curr>200000)? curr-200000 : curr;
}
// Higher absolute bandwidth on scale (in steps of 200K)
long    CSkunkApp::HigherFixedBandwidth(long curr)
{
    return (curr<10000000)? curr+200000 : curr;
}

// Lower PPS (steps of 200 upto 5K)
long    CSkunkApp::LowerFixedPacketRate(long curr)
{
    return (curr>200)? curr-200 : curr;
}
// Higher absolute bandwidth on scale (in steps of 200K)
long    CSkunkApp::HigherFixedPacketRate(long curr)
{
    return (curr<5000)? curr+200 : curr;
}

// Next Fixed Multiplier
double  CSkunkApp::HigherTimeWindowMultiplier(double curr)
{
    int arrsize=sizeof(FixedTimeWindowMultipliers)/sizeof(double);
    for (int i=arrsize-2;i>=0;i--)
    {
        if (curr==FixedTimeWindowMultipliers[i])
        {
            return FixedTimeWindowMultipliers[i+1];
        }    
    }
    return curr;
}

// Prev TimeWindow Multiplier
double  CSkunkApp::LowerTimeWindowMultiplier(double curr)
{
    int arrsize=sizeof(FixedTimeWindowMultipliers)/sizeof(double);
    for (int i=arrsize-1;i>0;i--)
    {
        if (curr==FixedTimeWindowMultipliers[i])
        {
            return FixedTimeWindowMultipliers[i-1];
        }    
    }
    return curr;
}

// How many spaces on the scale for a given fixed multiplier
int     CSkunkApp::SpacesForTimeWindowMultiplier(double d)
{
    int arrsize=sizeof(FixedTimeWindowMultipliers)/sizeof(double);
    for (int i=arrsize-1;i>=0;i--)
    {
        if (d==FixedTimeWindowMultipliers[i])
        {
            return i+1;
        }    
    }

    return -1;
}

// ParseMac
bool	CSkunkApp::ParseMAC(const char * lpszVal, unsigned char * pout)
{
	unsigned int  v[6];

	if (6!=sscanf(lpszVal,"%02X:%02X:%02X:%02X:%02X:%02X", &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]))
	{
		return false;
	}

	for (int i=0;i<6;i++)
	{
		*pout++=(unsigned char) v[i];
	}
	return true;
}
