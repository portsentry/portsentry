// SPDX-FileCopyrightText: 2024 Craig Rowland
// SPDX-FileContributor: Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#pragma once
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "packet_info.h"

__attribute__((format(printf, 1, 2))) void Log(char *, ...);
__attribute__((format(printf, 1, 2))) void Error(char *, ...);
__attribute__((format(printf, 1, 2))) void Debug(char *logentry, ...);
__attribute__((format(printf, 1, 2))) void Verbose(char *logentry, ...);
__attribute__((format(printf, 2, 3))) void Crash(int errCode, char *logentry, ...);
void Exit(int);
int NeverBlock(const char *, const char *);
int CheckConfig(void);
int OpenSocket(const int family, const int type, const int protocol, const uint8_t tcpReuseAddr);
int BindSocket(int, int, int, int);
int KillRoute(char *, int, char *, char *);
int KillHostsDeny(char *, int, char *, char *);
int KillRunCmd(char *, int, char *, char *);
int SubstString(const char *, const char *, const char *, char *);
int testFileAccess(const char *, const char *, uint8_t);
void XmitBannerIfConfigured(const int proto, const int socket, const struct sockaddr *saddr, const socklen_t saddrLen);
