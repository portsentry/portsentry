// SPDX-FileCopyrightText: 2024 Craig Rowland
// SPDX-FileContributor: Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: BSD-2-Clause

#pragma once
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

#include "packet_info.h"

#define MAX_SAFESTRNCMP_SIZE ((size_t)(1024 * 1024))
#define MIN_DATETIME_BUFFER 32

char *SafeStrncpy(char *, const char *, size_t);
void ResolveAddr(const struct PacketInfo *pi, char *resolvedHost, const socklen_t resolvedHostSize);
long GetLong(const char *buffer);
int StrToUint16_t(const char *str, uint16_t *val);
int DisposeTarget(const char *, int, int);
const char *GetProtocolString(int proto);
const char *GetFamilyString(int family);
int SetupPort(const struct sockaddr *addr, const socklen_t addrLen, uint8_t proto, uint8_t tcpReuseAddr);
int IsPortInUse(struct PacketInfo *pi);
char *ReportPacketType(const struct tcphdr *);
char *ErrnoString(char *buf, const size_t buflen);
int CreateDateTime(char *buf, const size_t size);
__attribute__((format(printf, 3, 4))) char *ReallocAndAppend(char *filter, size_t *filterLen, const char *append, ...);

#ifndef NDEBUG
void DebugWritePacketToFs(const struct PacketInfo *pi);
#endif
