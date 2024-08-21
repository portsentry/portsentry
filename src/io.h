// SPDX-FileCopyrightText: 2024 Craig Rowland
// SPDX-FileContributor: Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#pragma once
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

int WriteBlocked(char *, char *, int, char *, const char *);
void Log(char *, ...);
void Error(char *, ...);
void Debug(char *logentry, ...);
void Verbose(char *logentry, ...);
void Crash(int errCode, char *logentry, ...);
void Exit(int);
int NeverBlock(const char *, const char *);
int CheckConfig(void);
int OpenTCPSocket(void);
int OpenUDPSocket(void);
int OpenRAWTCPSocket(void);
int OpenRAWUDPSocket(void);
int BindSocket(int, int, int);
int KillRoute(char *, int, char *, char *);
int KillHostsDeny(char *, int, char *, char *);
int KillRunCmd(char *, int, char *, char *);
int IsBlocked(char *, char *);
int SubstString(const char *, const char *, const char *, char *);
int CompareIPs(const char *target, const char *ignoreAddr, const int ignoreNetmaskBits);
int testFileAccess(char *, char *);
void XmitBannerIfConfigured(const int proto, const int socket, const struct sockaddr_in *client);
int PacketRead(int socket, char *packetBuffer, size_t packetBufferSize, struct ip **ipPtr, void **transportPtr);
