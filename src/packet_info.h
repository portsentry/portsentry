// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: BSD-2-Clause

#pragma once
#include <netinet/in.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

/* Convenient information about a packet, used primarily
 * by the sentry engine to make decisions
 */
struct PacketInfo {
  uint8_t version;                // The IP version of the packet 4 or 6
  uint8_t protocol;               // The protocol of the packet (IPPROTO_TCP/UDP)
  uint16_t port;                  // The destination port for the packet
  struct sockaddr_in sa_saddr;    // The source address for ipv4 connections
  struct sockaddr_in6 sa6_saddr;  // The source address for ipv6 connections
  struct sockaddr_in sa_daddr;    // The dest address for ipv4 connections
  struct sockaddr_in6 sa6_daddr;  // The dest address for ipv6 connections
  char saddr[INET6_ADDRSTRLEN];   // The source address as a string
  char daddr[INET6_ADDRSTRLEN];   // The dest address as a string
  const unsigned char *packet;    // The raw packet + pointers into the various headers, where applicable
  int packetLength;
  struct ip *ip;        // pointer into packet for ipv4 header
  struct ip6_hdr *ip6;  // pointer into packet for ipv6 header
  struct tcphdr *tcp;   // pointer into packet for tcp header (if it's a tcp packet, otherwise NULL)
  struct udphdr *udp;   // pointer into packet for udp header (if it's a udp packet, otherwise NULL)

  // Connection based (sentry_connect) information
  int listenSocket;                    // The listening socket for the connection (also used to sendUDP packets if applicable)
  int tcpAcceptSocket;                 // If TCP connection, the socket that accept()ed the connection
  const struct sockaddr_in *client4;   // The client address for ipv4 connections as returned by accept() or recvfrom()
  const struct sockaddr_in6 *client6;  // The client address for ipv6 connections as returned by accept() or recvfrom()
};

void ClearPacketInfo(struct PacketInfo *pi);

int SetPacketInfoFromPacket(struct PacketInfo *pi, const unsigned char *packet, const uint32_t packetLength);
int SetPacketInfoFromConnectData(struct PacketInfo *pi, const uint16_t port, const int family, const int protocol, const int sockfd, const int incomingSockfd, const struct sockaddr_in *client4, const struct sockaddr_in6 *client6);

struct sockaddr *GetSourceSockaddrFromPacketInfo(const struct PacketInfo *pi);
socklen_t GetSourceSockaddrLenFromPacketInfo(const struct PacketInfo *pi);

struct sockaddr *GetDestSockaddrFromPacketInfo(const struct PacketInfo *pi);
socklen_t GetDestSockaddrLenFromPacketInfo(const struct PacketInfo *pi);

struct sockaddr *GetClientSockaddrFromPacketInfo(const struct PacketInfo *pi);
socklen_t GetClientSockaddrLenFromPacketInfo(const struct PacketInfo *pi);

int IsSameSourceAndDestAddress(const struct PacketInfo *pi);
