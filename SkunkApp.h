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

#ifndef SKUNKAPP_H
#define SKUNKAPP_H
/////////////////////////////////////////////////////////////////////////
// SkunkApp
//		Iterate through all capture files in the folder and play them 
// 		back (there are options how these are played back)
/////////////////////////////////////////////////////////////////////////
#include "linuxdefs.h"
#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <pcap.h>
#include "INetSender.h"
#include <curses.h>
#include "TimeUtils.h"

class CSkunkApp
{

public:
	typedef enum
	{
		SENDER_PCAP,
		SENDER_PF_PACKET,
	} SENDER_TYPE_T; 	

	typedef enum
	{
		PLAY_NATURAL_RATE,
		PLAY_FIRST_PACKET_FIXED_RATE,
        PLAY_FIXED_RATE_TIME_EXPAND,      
	} PLAY_MODE_T;

private:
	enum
	{
		ERR_MSG_BUFLEN=256,					// error message
		SECS_GAP_BETWEEN_CAPFILES=1,		// 1-sec gap in timestamp between capture files
		MAX_PACKET_LEN=65536,				// 64 buffer to hold a packet
        SCREEN_FEEDBACK_SECONDS=1,          // ideal screen update interval
        USECS_PER_SEC=1000000,              // microseconds to seconds
		MAC_ADDRESS_LENGTH=6,				// mac address length
		TUNNEL_ETHERTYPE=0x0AAA,			// custom tunnel ethertype
	};

	typedef struct STATS_STR_T
	{
		ULONG nTotalPktsWire;
		ULONG nTotalPktsCaptured;
		ULONG nTotalBytesWire; 
		ULONG nTotalBytesCaptured; 
	} STATS_STR_T;


	typedef struct
	{
		long			nBps;
        double          fMultiplier;    
        double          fTimeWindowMultiplier;    
        long            nLoopCount;  
		long			nPps;
	} FIXED_RATE_OPTIONS_T;


public:
	CSkunkApp();
	virtual ~CSkunkApp();
	BOOL			InitInstance();

public:
	void			SetStartTime(const timeval& tm);
	void			SetSourceFolder(LPCTSTR lpszPath);
	void			SetConfigFile(LPCTSTR lpszConfigFile);
	void			SetInterface(LPCTSTR lpszInterface);

public:
	inline void		SetSender(INetSender * ps) { pSender=ps;}

public:
	friend void  	CB_OfflinePacketCallback(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

private:
	void 			SynchronizedPktCallbackHandler( const struct pcap_pkthdr * pHeader, const u_char * pkt_data);
	BOOL 			StartFileImportLoop(LPCTSTR lpszFile);
	void			SetError(LPCTSTR lpszMsg);
	BOOL			PlayFileProportional(LPCTSTR lpszCapFile);
    BOOL            PlayFileFixedTimeExpand(LPCTSTR lpszCapFile);   
	BOOL 			PlaybackDirectory(LPCTSTR lpszPlugInDirectory);
	BOOL 			PlaybackFile(const tstring& csCapFile);
	BOOL			PlayFirstPacketLoop(LPCTSTR lpszCapFile);
	void			UninitScreen();
	int				InitScreen();
	LPCTSTR  		FormatUnits(long rawVal, LPCTSTR lpszSuffix);
	void			UpdateControlWindow_FirstPacketFixed();
	void			UpdateControlWindow_NaturalRate();
	void			UpdateControlWindow_TimeExpand();
	bool			HandleUserInput(int inchar);
    bool            ReadConfiguration();
	bool			ParseMAC(const char * lpszVal, unsigned char * pout);
    long            LowerFixedBandwidth(long curr);
    long            HigherFixedBandwidth(long curr);
    double          LowerFixedMultiplier(double curr);
    double          HigherFixedMultiplier(double curr);
    int             SpacesForFixedMultiplier(double d);
	int     		SpacesForTimeWindowMultiplier(double d);
	double  		LowerTimeWindowMultiplier(double curr);
	double  		HigherTimeWindowMultiplier(double curr);
	long    		LowerFixedPacketRate(long curr);
	long    		HigherFixedPacketRate(long curr);
	BOOL			_IntInitInstance();
   
private:
	TCHAR 			errBuf[ERR_MSG_BUFLEN];
	tstring			strSourceFile;
	tstring			strConfigFile;
	tstring			strInterface;
	tstring			strError;
	timeval			m_tmLastPlay;
	timeval		  	tmLastSample;
	STATS_STR_T     snfStats;
	INetSender	  * pSender;
	PLAY_MODE_T		ePlayMode;
	WINDOW		  * m_wndMain;
	WINDOW		  * m_wndOut;
	WINDOW		  * m_wndMode;
	WINDOW		  * m_wndStatusBar;
	long			nPacketsPlayed;
	uint64_t		lBytesPlayed;
	uint64_t		lTotalBytesPlayed;
    bool            fOptRateChanged;   
	FIXED_RATE_OPTIONS_T 	optRate;
    bool            fTerminate;
    timeval         tmLastScreenUpdate;
    int             m_nCurrentIteration;
	bool			fUseTimeTunnel;
    static const double FixedMultipliers[];
	static const double FixedTimeWindowMultipliers[]; 

	bool			fUseMACTunnel;
	unsigned char   macTunnelSrcMAC[MAC_ADDRESS_LENGTH];
	unsigned char   macTunnelDstMAC[MAC_ADDRESS_LENGTH];

	bool			fUseMACLink;
	unsigned char   macLinkSrcMAC[MAC_ADDRESS_LENGTH];
	unsigned char   macLinkDstMAC[MAC_ADDRESS_LENGTH];

	TimeUtils		tmUtils;
};
#endif
