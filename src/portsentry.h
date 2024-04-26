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
#include <sys/param.h>

#define TCPPACKETLEN 80
#define UDPPACKETLEN 68

#define ERROR -1
#define TRUE 1
#define FALSE 0
#define MAXBUF 1024
/* max size of an IP address plus NULL */
#define IPMAXBUF 16
/* max sockets we can open */
#define MAXSOCKS 64

#define ERRNOMAXBUF 1024

#define MAX_INTERFACES 1024

#undef max
#define max(x, y) ((x) > (y) ? (x) : (y))
