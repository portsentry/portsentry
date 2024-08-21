// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#pragma once
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

struct PacketInfo {
  uint8_t version;                // The IP version of the packet (IPPROTO_IPV4 or IPPROTO_IPV6)
  uint8_t protocol;               // The protocol of the packet
  uint16_t port;                  // The destination port for the packet
  struct sockaddr_in client;      // The client address for ipv4 connections
  struct sockaddr_in6 client6;    // The client address for ipv6 connections
  char target[INET6_ADDRSTRLEN];  // The IP address of the target in string form
  unsigned char *packet;          // The raw packet + pointers into the various headers, where applicable
  struct ip *ip;
  struct ip6_hdr *ip6;
  struct tcphdr *tcp;
  struct udphdr *udp;
  int listenSocket;     // The socket associated with the packet, if any
  int tcpAcceptSocket;  // The socket for which, in connect mode we have an established connection to the client
};

void ClearPacketInfo(struct PacketInfo *pi);
char *GetTargetOfPacketInfo(struct PacketInfo *pi);
int ResolveTargetOfPacketInfo(struct PacketInfo *pi);
struct sockaddr *GetClientSockaddrFromPacketInfo(const struct PacketInfo *pi);
socklen_t GetClientSockaddrLenFromPacketInfo(const struct PacketInfo *pi);
