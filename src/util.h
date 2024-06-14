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

#include "connection_data.h"
/* IP address length plus null */
#define IPMAXBUF 16

char *SafeStrncpy(char *, const char *, size_t);
char *CleanIpAddr(char *, const char *);
void ResolveAddr(const struct sockaddr *saddr, const socklen_t saddrLen, char *resolvedHost, const int resolvedHostSize);
long getLong(char *buffer);
int DisposeTarget(char *, int, int);
const char *GetProtocolString(int proto);
int SetupPort(uint16_t port, int proto);
int IsPortInUse(uint16_t port, int proto);
char *ReportPacketType(struct tcphdr *);
char *ErrnoString(char *buf, const size_t buflen);
void RunSentry(struct ConnectionData *cd, const struct sockaddr_in *client, struct ip *ip, struct tcphdr *tcp, int *tcpAcceptSocket);
int CreateDateTime(char *buf, const int size);
int SetConvenienceData(struct ConnectionData *connectionData, const int connectionDataSize, const struct ip *ip, const void *p, struct sockaddr_in *client, struct ConnectionData **cd, struct tcphdr **tcp, struct udphdr **udp);
int ntohstr(char *buf, const int bufSize, const uint32_t addr);
