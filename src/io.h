// SPDX-FileCopyrightText: 2024 Craig Rowland
// SPDX-FileContributor: Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: BSD-2-Clause

#pragma once
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "packet_info.h"

__attribute__((format(printf, 1, 2))) void Log(const char *, ...);
__attribute__((format(printf, 1, 2))) void Error(const char *, ...);
__attribute__((format(printf, 1, 2))) void Debug(const char *logentry, ...);
__attribute__((format(printf, 1, 2))) void Verbose(const char *logentry, ...);
__attribute__((format(printf, 2, 3))) void Crash(const int errCode, const char *logentry, ...);
void Exit(const int);
int NeverBlock(const char *, const char *);
int CheckConfig(void);
int OpenSocket(const int family, const int type, const int protocol, const uint8_t tcpReuseAddr);
int BindSocket(const int, const struct sockaddr *, const socklen_t, const uint8_t proto);
int KillRoute(const char *, const int, const char *, const char *);
int KillHostsDeny(const char *, const int, const char *, const char *);
int KillRunCmd(const char *, const int, const char *, const char *);
int FindInFile(const char *, const char *);
int SubstString(const char *replaceToken, const char *findToken, const char *source, char *dest, const int destSize);
int TestFileAccess(const char *, const char *, const uint8_t);
void XmitBannerIfConfigured(const int proto, const int socket, const struct sockaddr *saddr, const socklen_t saddrLen);
