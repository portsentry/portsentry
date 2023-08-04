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
/* $Id: portsentry_io.h,v 1.17 2003/05/23 17:41:46 crowland Exp crowland $ */
/************************************************************************/

/* prototypes */
int WriteBlocked(char *, char *, int, char *, char *, char *);
void Log(char *, ...);
void Exit(int);
int DaemonSeed(void);
int NeverBlock(char *, char *);
int CheckConfig(void);
int OpenTCPSocket(void);
int OpenUDPSocket(void);
#ifdef SUPPORT_STEALTH
int OpenRAWTCPSocket(void);
int OpenRAWUDPSocket(void);
#endif
int BindSocket(int, int);
int KillRoute(char *, int, char *, char *);
int KillHostsDeny(char *, int, char *, char *);
int KillRunCmd(char *, int, char *, char *);
int IsBlocked(char *, char *);
int SubstString(const char *, const char *, const char *, char *);
int CompareIPs(char *, char *, int);
int copyPrintableString(char *, char *, size_t);
int testFileAccess(char *, char *);
