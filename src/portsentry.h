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

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#ifndef _LINUX_C_LIB_VERSION
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#endif
#include <arpa/inet.h>

enum ProtocolType {
  PROTOCOL_TCP,
  PROTOCOL_UDP
};

#include "config.h"
#include "portsentry_io.h"
#include "portsentry_util.h"

#ifdef SUPPORT_STEALTH
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

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
