/* $Id: snortpatchb,v 1.5 2005/10/06 08:50:39 fknobbe Exp $
**
** spo_alert_fwsam.h
**
** Copyright (c) 2001-2004 Frank Knobbe <frank@knobbe.us>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* This file gets included in plugbase.c when it is integrated into the rest
 * of the program.
 *
 * For more info, see the beginning of spo_alert_fwsam.c
 *
 */

#ifndef __SPO_FWSAM_H__
#define __SPO_FWSAM_H__

#include "snort.h"
#include "rules.h"
#include "plugbase.h"
#include "plugin_enum.h"
#include "fatal.h"
#include "util.h"
#include "twofish.h"

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>


/* just some compatibility stuff */
#ifdef WIN32
#if !defined(_WINSOCKAPI_) && !defined(_WINSOCK2API_)
#include <winsock.h>
#endif
#define	waitms(x)				Sleep(x)

#else

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netdb.h>

#ifdef SOLARIS
#include <sys/filio.h>
#endif

typedef int SOCKET;

#ifndef INVALID_SOCKET
#define INVALID_SOCKET	-1
#endif

#define	waitms(x)				usleep((x)*1000)

#endif

#ifndef	FALSE
#define FALSE	0
#endif
#ifndef	TRUE
#define	TRUE	!FALSE
#endif
#ifndef	bool
#define	bool	int
#endif


#if defined(_DEBUG) || defined(DEBUG)
#ifndef FWSAMDEBUG
#define FWSAMDEBUG
#endif
#else
#endif


/* Official Snort PlugIn Number has been moved into plugin_enum.h */


/* fixed defines */

#define FWSAM_DEFAULTPORT		898	/* Default port if user does not specify one in snort.conf */
									/* (Was unused last time I checked...) */
#define FWSAM_PACKETVERSION		14	/* version of the packet. Will increase with enhancements. */

#define FWSAM_STATUS_CHECKIN	1	/* snort to fw */
#define FWSAM_STATUS_CHECKOUT	2
#define FWSAM_STATUS_BLOCK		3
#define FWSAM_STATUS_UNBLOCK	9

#define FWSAM_STATUS_OK			4	/* fw to snort */
#define FWSAM_STATUS_ERROR		5
#define FWSAM_STATUS_NEWKEY		6
#define FWSAM_STATUS_RESYNC		7
#define FWSAM_STATUS_HOLD		8

#define FWSAM_LOG_NONE			0
#define FWSAM_LOG_SHORTLOG		1
#define FWSAM_LOG_SHORTALERT	2
#define FWSAM_LOG_LONGLOG		3
#define FWSAM_LOG_LONGALERT		4
#define FWSAM_LOG				(FWSAM_LOG_SHORTLOG|FWSAM_LOG_SHORTALERT|FWSAM_LOG_LONGLOG|FWSAM_LOG_LONGALERT)
#define	FWSAM_WHO_DST			8
#define FWSAM_WHO_SRC			16
#define FWSAM_WHO				(FWSAM_WHO_DST|FWSAM_WHO_SRC)
#define FWSAM_HOW_IN			32
#define FWSAM_HOW_OUT			64
#define FWSAM_HOW_INOUT			(FWSAM_HOW_IN|FWSAM_HOW_OUT)
#define FWSAM_HOW_THIS			128
#define FWSAM_HOW				(FWSAM_HOW_IN|FWSAM_HOW_OUT|FWSAM_HOW_THIS)


/* user adjustable defines */

#define FWSAM_REPET_BLOCKS		10	/* Snort remembers this amount of last blocks and... */
#define FWSAM_REPET_TIME		20	/* ...checks if they fall within this time. If so,... */
									/* ...the blocking request is not send. */

#define FWSAM_NETWAIT			300		/* 100th of a second. 3 sec timeout for network connections */
#define FWSAM_NETHOLD			6000	/* 100th of a second. 60 sec timeout for holding */

#define SID_MAPFILE				"sid-block.map"
#define SID_ALT_MAPFILE			"sid-fwsam.map"

#define FWSAM_FANCYFETCH        /* This will invoke a fast sid lookup routine */


/* vars */

typedef struct _FWsamstation		/* structure of a mgmt station */
{	unsigned short 		myseqno;
	unsigned short 		stationseqno;
	unsigned char		mykeymod[4];
	unsigned char		fwkeymod[4];
	unsigned short		stationport;
	//struct in_addr		stationip;
	sfip_t			stationip;
	struct sockaddr_in	localsocketaddr;
	struct sockaddr_in	stationsocketaddr;
	TWOFISH			*stationfish;
	char			initialkey[TwoFish_KEY_LENGTH+2];
	char			stationkey[TwoFish_KEY_LENGTH+2];
	time_t			lastcontact;
/*	time_t			sleepstart; */
}	FWsamStation;

typedef struct _FWsampacket			/* 2 blocks (3rd block is header from TwoFish) */
{	unsigned short		endiancheck;	/* 0  */
	unsigned char		srcip[4];		/* 2  */
	unsigned char		dstip[4];		/* 6  */
	unsigned char		duration[4];	/* 10 */
	unsigned char		snortseqno[2];	/* 14 */
	unsigned char		fwseqno[2];		/* 16 */
	unsigned char		srcport[2];		/* 18 */
	unsigned char		dstport[2];		/* 20 */
	unsigned char		protocol[2];	/* 22 */
	unsigned char		fwmode;			/* 24 */
	unsigned char		version;		/* 25 */
	unsigned char		status;			/* 26 */
	unsigned char		sig_id[4];		/* 27 */
	unsigned char		fluff;			/* 31 */
}	FWsamPacket;						/* 32 bytes in size */

typedef struct _FWsamoptions	/* snort rule options */
{	unsigned long	sid;
    unsigned long	duration;
	unsigned char	who;
	unsigned char	how;
	unsigned char	loglevel;
}	FWsamOptions;

typedef struct _FWsamlistpointer
{	FWsamStation *station;
	struct _FWsamlistpointer *next;
}	FWsamList;


/* functions */
void AlertFWsamSetup(void);
void AlertFWsamInit(struct _SnortConfig *sc, char *args);
void AlertFWsamOptionInit(struct _SnortConfig *sc, char *args,OptTreeNode *otn,int protocol);
void AlertFWsamCleanExitFunc(int signal, void *arg);
void AlertFWsamRestartFunc(int signal, void *arg);
void AlertFWsam(Packet *p, char *msg, void *arg, Event *event);
int FWsamCheckIn(FWsamStation *station);
void FWsamCheckOut(FWsamStation *station);
void FWsamNewStationKey(FWsamStation *station,FWsamPacket *packet);
void FWsamFixPacketEndian(FWsamPacket *p);
unsigned long FWsamParseDuration(char *p);
void FWsamFree(FWsamList *fwsamlist);
int FWsamStationExists(FWsamStation *who,FWsamList *list);
int FWsamReadLine(char *,unsigned long,FILE *);
void FWsamParseLine(FWsamOptions *,char *);
FWsamOptions *FWsamGetOption(unsigned long);
int FWsamParseOption(FWsamOptions *,char *);

#endif  /* __SPO_FWSAM_H__ */
