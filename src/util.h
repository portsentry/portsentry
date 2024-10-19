// SPDX-FileCopyrightText: 2024 Craig Rowland
// SPDX-FileContributor: Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#pragma once
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

#include "packet_info.h"

char *SafeStrncpy(char *, const char *, size_t);
void ResolveAddr(struct PacketInfo *pi, char *resolvedHost, const int resolvedHostSize);
long getLong(char *buffer);
int DisposeTarget(char *, int, int);
const char *GetProtocolString(int proto);
const char *GetFamilyString(int family);
const char *GetSocketTypeString(int type);
int SetupPort(int family, uint16_t port, int proto);
int IsPortInUse(struct PacketInfo *pi);
char *ReportPacketType(struct tcphdr *);
char *ErrnoString(char *buf, const size_t buflen);
int CreateDateTime(char *buf, const int size);
int ntohstr(char *buf, const int bufSize, const uint32_t addr);
int StrToUint16_t(const char *str, uint16_t *val);
__attribute__((format(printf, 3, 4))) char *ReallocAndAppend(char *filter, int *filterLen, const char *append, ...);
