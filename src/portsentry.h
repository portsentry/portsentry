#pragma once
/************************************************************************/
/*                                                                      */
/* PortSentry                                                           */
/*                                                                      */
/* This software is Copyright(c) 1997-2003 Craig Rowland                */
/*                                                                      */
/* This software is covered under the Common Public License v1.0        */
/* See the enclosed LICENSE file for more information.                  */
/*                                                                      */
/* Created: 10-12-1997                                                  */
/* Modified: 05-23-2003                                                 */
/*                                                                      */
/* Send all changes/modifications/bugfixes to:                          */
/* craigrowland at users dot sourceforge dot net                        */
/*                                                                      */
/* $Id: portsentry.h,v 1.32 2003/05/23 17:50:20 crowland Exp crowland $ */
/************************************************************************/

#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <netdb.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <assert.h>
#include <limits.h>
#include <sys/param.h>
#include <sys/types.h>
#ifndef _LINUX_C_LIB_VERSION
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#endif
#include <arpa/inet.h>

#include "config.h"
#include "portsentry_io.h"
#include "portsentry_util.h"

#ifdef SUPPORT_STEALTH
  #ifdef LINUX
    #include "portsentry_tcpip.h"
    #include <netinet/in_systm.h>
  #endif

#define TCPPACKETLEN 80
#define UDPPACKETLEN 68
#endif /* SUPPORT_STEALTH */

#define ERROR -1
#define TRUE 1
#define FALSE 0
#define MAXBUF 1024
/* max size of an IP address plus NULL */
#define IPMAXBUF 16
/* max sockets we can open */
#define MAXSOCKS 64

/* Really is about 1025, but we don't need the length for our purposes */
#define DNSMAXBUF 255

/* prototypes */
int PortSentryModeTCP(void);
int PortSentryModeUDP(void);
int DisposeUDP(char *, int);
int DisposeTCP(char *, int);
int SmartVerifyTCP(int);
int SmartVerifyUDP(int);

#ifdef SUPPORT_STEALTH
int PortSentryStealthModeTCP(void);
int PortSentryAdvancedStealthModeTCP(void);
int PortSentryStealthModeUDP(void);
int PortSentryAdvancedStealthModeUDP(void);
char * ReportPacketType(struct tcphdr);
int PacketReadTCP(int, struct iphdr *, struct tcphdr *);
int PacketReadUDP(int, struct iphdr *, struct udphdr *);
#endif
