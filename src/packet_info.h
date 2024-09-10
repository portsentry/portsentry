// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#pragma once
#include <netinet/in.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

struct PacketInfo {
  uint8_t version;                // The IP version of the packet (IPPROTO_IPV4 or IPPROTO_IPV6)
  uint8_t protocol;               // The protocol of the packet
  uint16_t port;                  // The destination port for the packet
  struct sockaddr_in sa_saddr;    // The source address for ipv4 connections
  struct sockaddr_in6 sa6_saddr;  // The source address for ipv6 connections
  struct sockaddr_in sa_daddr;    // The dest address for ipv4 connections
  struct sockaddr_in6 sa6_daddr;  // The dest address for ipv6 connections
                                  //  char target[INET6_ADDRSTRLEN];  // The IP address of the target in string form
  char saddr[INET6_ADDRSTRLEN];
  char daddr[INET6_ADDRSTRLEN];
  unsigned char *packet;  // The raw packet + pointers into the various headers, where applicable
  int packetLength;
  struct ip *ip;
  struct ip6_hdr *ip6;
  struct tcphdr *tcp;
  struct udphdr *udp;
  int listenSocket;     // The socket associated with the packet, if any
  int tcpAcceptSocket;  // The socket for which, in connect mode we have an established connection to the client
};

void ClearPacketInfo(struct PacketInfo *pi);
int SetPacketInfo(struct PacketInfo *pi);
int SetSockaddr(struct sockaddr_in *sa, const in_addr_t addr, const uint16_t port, char *buf, size_t buflen);
int SetSockaddr6(struct sockaddr_in6 *sa6, const struct in6_addr addr6, const uint16_t port, char *buf, size_t buflen);
struct sockaddr *GetSourceSockaddrFromPacketInfo(const struct PacketInfo *pi);
socklen_t GetSourceSockaddrLenFromPacketInfo(const struct PacketInfo *pi);
char *GetPacketInfoString(const struct PacketInfo *pi, const char *deviceName, const int hdrCapLen, const int hdrLen);
