// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/udp.h>
#include <assert.h>

#include "portsentry.h"
#include "packet_info.h"
#include "io.h"
#include "util.h"

#define IPV4_MAPPED_IPV6_PREFIX "::ffff:"

static int SetSockaddr4(struct sockaddr_in *sa, const in_addr_t *addr, const uint16_t port, char *buf, size_t buflen);
static int SetSockaddr6(struct sockaddr_in6 *sa6, const struct in6_addr *addr6, const uint16_t port, char *buf, size_t buflen);

void ClearPacketInfo(struct PacketInfo *pi) {
  memset(pi, 0, sizeof(struct PacketInfo));
  pi->listenSocket = -1;
  pi->tcpAcceptSocket = -1;
}

int SetPacketInfoFromPacket(struct PacketInfo *pi, unsigned char *packet, const uint32_t packetLength) {
  int iplen, nextHeader;
  uint8_t protocol, ipVersion;
  struct ip6_ext *ip6ext;
  struct ip *ip = NULL;
  struct ip6_hdr *ip6 = NULL;
  struct tcphdr *tcp = NULL;
  struct udphdr *udp = NULL;

  assert(pi != NULL);
  assert(packet != NULL);

  pi->packet = packet;

  ipVersion = (*pi->packet >> 4) & 0x0f;
  if (ipVersion == 4) {
    if (packetLength < 20) {
      Error("IPv4 packet is too short (%d bytes), ignoring", packetLength);
      return FALSE;
    }

    ip = (struct ip *)pi->packet;
    iplen = ip->ip_hl * 4;
    protocol = ip->ip_p;
  } else if (ipVersion == 6) {
    if (packetLength < 40) {
      Error("IPv6 packet is too short (%d bytes), ignoring", packetLength);
      return FALSE;
    }

    ip6 = (struct ip6_hdr *)pi->packet;
    nextHeader = ip6->ip6_nxt;
    iplen = sizeof(struct ip6_hdr);

    /*
     * RFC8200
     * 0 	IPv6 Hop-by-Hop Option 	[RFC8200]
     * 43 	Routing Header for IPv6 	[RFC8200][RFC5095]
     * 44 	Fragment Header for IPv6 	[RFC8200]
     * 50 	Encapsulating Security Payload 	[RFC4303]
     * 51 	Authentication Header 	[RFC4302]
     * 59 	IPv6-NoNxt 	No Next Header for IPv6 		[RFC8200]
     * 60 	Destination Options for IPv6 	[RFC8200]
     * 135 	Mobility Header 	[RFC6275]
     * 139 	Host Identity Protocol 	[RFC7401]
     * 140 	Shim6 Protocol 	[RFC5533]
     * 253 	Use for experimentation and testing 	[RFC3692][RFC4727]
     * 254 	Use for experimentation and testing 	[RFC3692][RFC4727]
     */

    while (nextHeader == 0 || nextHeader == 43 || nextHeader == 44 || nextHeader == 50 ||
           nextHeader == 51 || nextHeader == 59 || nextHeader == 60 || nextHeader == 135 ||
           nextHeader == 139 || nextHeader == 140 || nextHeader == 253 || nextHeader == 254) {
      Debug("Processing IPv6 extension header %d", nextHeader);
      if (nextHeader == 59) {
        Error("IPv6-NoNxt detected, ignoring packet");
        return FALSE;
      } else if (nextHeader == 44) {
        Error("Fragment Header for IPv6 detected, ignoring packet");
        return FALSE;
      } else if (nextHeader == 253 || nextHeader == 254) {
        Error("RFC3692 Experimental/testing header detected, ignoring packet");
        return FALSE;
      }

      ip6ext = (struct ip6_ext *)(pi->packet + iplen);
      nextHeader = ip6ext->ip6e_nxt;
      if (ip6ext->ip6e_len == 0) {
        Error("IPv6 extension header length is 0, ignoring packet");
        return FALSE;
      }
      iplen += ip6ext->ip6e_len;
    }

    protocol = nextHeader;
  } else {
    Debug("Packet have unknown IP version %d", ipVersion);
    return FALSE;
  }

  if (protocol == IPPROTO_TCP) {
    tcp = (struct tcphdr *)(pi->packet + iplen);
  } else if (protocol == IPPROTO_UDP) {
    udp = (struct udphdr *)(pi->packet + iplen);
  } else {
    // Debug("Unknown protocol %d", protocol);
    return FALSE;
  }

  pi->version = ipVersion;
  pi->protocol = protocol;
  pi->port = (protocol == IPPROTO_TCP) ? ntohs(tcp->th_dport) : ntohs(udp->uh_dport);
  pi->ip = (ip != NULL) ? ip : NULL;
  pi->ip6 = (ip6 != NULL) ? ip6 : NULL;
  pi->tcp = (tcp != NULL) ? tcp : NULL;
  pi->udp = (udp != NULL) ? udp : NULL;

  if (pi->version != 4 && pi->version != 6) {
    Error("Packet validation failes, unknown IP version %d", pi->version);
    return FALSE;
  }

  if (pi->protocol != IPPROTO_TCP && pi->protocol != IPPROTO_UDP) {
    Error("Packet validation failed, unknown protocol %d", pi->protocol);
    return FALSE;
  }

  if (pi->ip == NULL && pi->ip6 == NULL) {
    Error("Packet validation failed, no IP header found");
    return FALSE;
  }

  if (pi->tcp == NULL && pi->udp == NULL) {
    Error("Packet validation failed, no TCP or UDP header found");
    return FALSE;
  }

  if (pi->ip != NULL) {
    if (SetSockaddr4(&pi->sa_saddr, &pi->ip->ip_src.s_addr, (tcp != NULL) ? tcp->th_sport : udp->uh_sport, pi->saddr, sizeof(pi->saddr)) != TRUE) {
      return FALSE;
    }
    if (SetSockaddr4(&pi->sa_daddr, &pi->ip->ip_dst.s_addr, (tcp != NULL) ? tcp->th_dport : udp->uh_dport, pi->daddr, sizeof(pi->daddr)) != TRUE) {
      return FALSE;
    }
  } else if (pi->ip6 != NULL) {
    if (SetSockaddr6(&pi->sa6_saddr, &pi->ip6->ip6_src, (tcp != NULL) ? tcp->th_sport : udp->uh_sport, pi->saddr, sizeof(pi->saddr)) != TRUE) {
      return FALSE;
    }
    if (SetSockaddr6(&pi->sa6_daddr, &pi->ip6->ip6_dst, (tcp != NULL) ? tcp->th_dport : udp->uh_dport, pi->daddr, sizeof(pi->daddr)) != TRUE) {
      return FALSE;
    }
  }

  return TRUE;
}

int SetPacketInfoFromConnectData(struct PacketInfo *pi, const uint16_t port, const int family, const int protocol, const int sockfd, const int incomingSockfd, struct sockaddr_in *client4, struct sockaddr_in6 *client6) {
  pi->protocol = protocol;
  pi->port = port;
  pi->version = (family == AF_INET) ? 4 : 6;
  pi->listenSocket = sockfd;
  pi->tcpAcceptSocket = incomingSockfd;

  // There will only by one correct client address, depending on the family (only valid in sentry_connect)
  if (pi->version == 4) {
    pi->client4 = client4;
    pi->client6 = NULL;
  } else {
    pi->client4 = NULL;
    pi->client6 = client6;
  }

  if (pi->version == 4) {
    SetSockaddr4(&pi->sa_saddr, &client4->sin_addr.s_addr, client4->sin_port, pi->saddr, sizeof(pi->saddr));
    pi->sa_daddr.sin_port = port;
  } else {
    // In a dual stack environment, we may receive an IPv4-mapped IPv6 address
    // In this case, extract the ipv4 address and port from the mapped address
    // in order to present it as an IPv4 address instead of ::ffff:<ipv4>
    if (IN6_IS_ADDR_V4MAPPED(&client6->sin6_addr)) {
      struct in_addr addr4;
      memcpy(&addr4, &client6->sin6_addr.s6_addr[12], sizeof(struct in_addr));
      SetSockaddr4(&pi->sa_saddr, &addr4.s_addr, client6->sin6_port, pi->saddr, sizeof(pi->saddr));
      pi->sa_daddr.sin_port = port;
      pi->version = 4;  // Since we are treating this as an IPv4 address and the sockaddr_in is set, set version to 4 too (needed by GetSourceSockaddr*())
    } else {
      SetSockaddr6(&pi->sa6_saddr, &client6->sin6_addr, client6->sin6_port, pi->saddr, sizeof(pi->saddr));
      pi->sa6_daddr.sin6_port = port;
    }
  }

  return TRUE;
}

static int SetSockaddr4(struct sockaddr_in *sa, const in_addr_t *addr, const uint16_t port, char *buf, size_t buflen) {
  char err[ERRNOMAXBUF];

  memset(sa, 0, sizeof(struct sockaddr_in));
  sa->sin_addr.s_addr = *addr;
  sa->sin_family = AF_INET;
  sa->sin_port = port;

  if (buf != NULL && buflen > 0) {
    if (inet_ntop(AF_INET, &sa->sin_addr, buf, buflen) == NULL) {
      Error("Unable to resolve IP address: %s", ErrnoString(err, sizeof(err)));
      return ERROR;
    }
  }

  return TRUE;
}

static int SetSockaddr6(struct sockaddr_in6 *sa6, const struct in6_addr *addr6, const uint16_t port, char *buf, size_t buflen) {
  char err[ERRNOMAXBUF];

  memset(sa6, 0, sizeof(struct sockaddr_in6));
  memcpy(&sa6->sin6_addr, addr6, sizeof(struct in6_addr));
  sa6->sin6_family = AF_INET6;
  sa6->sin6_port = port;

  if (buf != NULL && buflen > 0) {
    if (inet_ntop(AF_INET6, &sa6->sin6_addr, buf, buflen) == NULL) {
      Error("Unable to resolve IPv6 address: %s", ErrnoString(err, sizeof(err)));
      return ERROR;
    }
  }

  return TRUE;
}

struct sockaddr *GetSourceSockaddrFromPacketInfo(const struct PacketInfo *pi) {
  if (pi->version == 6 && pi->sa6_saddr.sin6_family == AF_INET6) {
    return (struct sockaddr *)&pi->sa6_saddr;
  } else if (pi->version == 4 && pi->sa_saddr.sin_family == AF_INET) {
    return (struct sockaddr *)&pi->sa_saddr;
  }

  return NULL;
}

socklen_t GetSourceSockaddrLenFromPacketInfo(const struct PacketInfo *pi) {
  if (pi->version == 6 && pi->sa6_saddr.sin6_family == AF_INET6) {
    return sizeof(struct sockaddr_in6);
  } else if (pi->version == 4 && pi->sa_saddr.sin_family == AF_INET) {
    return sizeof(struct sockaddr_in);
  }

  return 0;
}

struct sockaddr *GetClientSockaddrFromPacketInfo(const struct PacketInfo *pi) {
  if (pi->client4 != NULL) {
    return (struct sockaddr *)pi->client4;
  } else if (pi->client6 != NULL) {
    return (struct sockaddr *)pi->client6;
  }

  return NULL;
}

socklen_t GetClientSockaddrLenFromPacketInfo(const struct PacketInfo *pi) {
  if (pi->client4 != NULL) {
    return sizeof(struct sockaddr_in);
  } else if (pi->client6 != NULL) {
    return sizeof(struct sockaddr_in6);
  }

  return 0;
}
