// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: BSD-2-Clause

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

static int SetSockaddr4(struct sockaddr_in *sa, const in_addr_t *addr, const uint16_t port, char *buf, const size_t buflen);
static int SetSockaddr6(struct sockaddr_in6 *sa6, const struct in6_addr *addr6, const uint16_t port, char *buf, const size_t buflen);

// Create a lookup table for IPv6 extension headers
static const uint8_t IPV6_EXT_HEADERS[] = {
    0,    // Hop-by-Hop
    43,   // Routing
    44,   // Fragment
    50,   // ESP
    51,   // Auth
    59,   // No Next
    60,   // Dest Options
    135,  // Mobility
    139,  // HIP
    140,  // Shim6
    253,  // Experimental
    254   // Experimental
};

static int IsIpv6ExtensionHeader(uint8_t header) {
  for (size_t i = 0; i < sizeof(IPV6_EXT_HEADERS); i++) {
    if (header == IPV6_EXT_HEADERS[i])
      return TRUE;
  }
  return FALSE;
}

void ClearPacketInfo(struct PacketInfo *pi) {
  memset(pi, 0, sizeof(struct PacketInfo));
  pi->listenSocket = -1;
  pi->tcpAcceptSocket = -1;
}

int SetPacketInfoFromPacket(struct PacketInfo *pi, const unsigned char *packet, const uint32_t packetLength) {
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

    while (IsIpv6ExtensionHeader(nextHeader)) {
      Debug("Processing IPv6 extension header %d", nextHeader);

      if (iplen + sizeof(struct ip6_ext) > packetLength) {
        Error("IPv6 extension header exceeds packet length, ignoring");
        return FALSE;
      }

      // Handle special cases that should be rejected
      switch (nextHeader) {
      case 59:  // IPv6-NoNxt
        Error("IPv6-NoNxt detected, ignoring packet");
        return FALSE;
      case 44:  // Fragment Header
        Error("Fragment Header for IPv6 detected, ignoring packet");
        return FALSE;
      case 253:  // Experimental
      case 254:
        Error("RFC3692 Experimental/testing header detected, ignoring packet");
        return FALSE;
      }

      ip6ext = (struct ip6_ext *)(pi->packet + iplen);
      nextHeader = ip6ext->ip6e_nxt;
      if (ip6ext->ip6e_len == 0) {
        Error("IPv6 extension header length is 0, ignoring packet");
        return FALSE;
      }

      uint32_t extlen = (ip6ext->ip6e_len * 8) + 8;
      if (iplen + extlen > packetLength) {
        Error("IPv6 extension header length exceeds packet bounds, ignoring");
        return FALSE;
      }
      iplen += extlen;
    }

    protocol = nextHeader;
  } else {
    Debug("Packet have unknown IP version %d", ipVersion);
    return FALSE;
  }

  if (protocol == IPPROTO_TCP) {
    if ((int)(packetLength - iplen) < (int)sizeof(struct tcphdr)) {
      Error("Packet is too short for TCP header, ignoring");
      return FALSE;
    }
    tcp = (struct tcphdr *)(pi->packet + iplen);
  } else if (protocol == IPPROTO_UDP) {
    if ((int)(packetLength - iplen) < (int)sizeof(struct udphdr)) {
      Error("Packet is too short for UDP header, ignoring");
      return FALSE;
    }
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

int SetPacketInfoFromConnectData(struct PacketInfo *pi, const uint16_t port, const int family, const int protocol, const int sockfd, const int incomingSockfd, const struct sockaddr_in *client4, const struct sockaddr_in6 *client6) {
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

static int SetSockaddr4(struct sockaddr_in *sa, const in_addr_t *addr, const uint16_t port, char *buf, const size_t buflen) {
  char err[ERRNOMAXBUF];

  if (sa == NULL || addr == NULL) {
    Error("Invalid NULL parameter");
    return ERROR;
  }

  memset(sa, 0, sizeof(struct sockaddr_in));
  sa->sin_addr.s_addr = *addr;
  sa->sin_family = AF_INET;
  sa->sin_port = port;

  if (buf != NULL) {
    if (buflen < INET_ADDRSTRLEN) {
      Error("Buffer too small for IPv4 address");
      return ERROR;
    }
    if (inet_ntop(AF_INET, &sa->sin_addr, buf, buflen) == NULL) {
      Error("Unable to resolve IP address: %s", ErrnoString(err, sizeof(err)));
      return ERROR;
    }
  }

  return TRUE;
}

static int SetSockaddr6(struct sockaddr_in6 *sa6, const struct in6_addr *addr6, const uint16_t port, char *buf, const size_t buflen) {
  char err[ERRNOMAXBUF];

  if (sa6 == NULL || addr6 == NULL) {
    Error("Invalid NULL parameter");
    return ERROR;
  }

  memset(sa6, 0, sizeof(struct sockaddr_in6));
  memcpy(&sa6->sin6_addr, addr6, sizeof(struct in6_addr));
  sa6->sin6_family = AF_INET6;
  sa6->sin6_port = port;

  if (buf != NULL) {
    if (buflen < INET6_ADDRSTRLEN) {
      Error("Buffer too small for IPv6 address");
      return ERROR;
    }
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

struct sockaddr *GetDestSockaddrFromPacketInfo(const struct PacketInfo *pi) {
  if (pi->version == 6 && pi->sa6_daddr.sin6_family == AF_INET6) {
    return (struct sockaddr *)&pi->sa6_daddr;
  } else if (pi->version == 4 && pi->sa_daddr.sin_family == AF_INET) {
    return (struct sockaddr *)&pi->sa_daddr;
  }

  return NULL;
}

socklen_t GetDestSockaddrLenFromPacketInfo(const struct PacketInfo *pi) {
  if (pi->version == 6 && pi->sa6_daddr.sin6_family == AF_INET6) {
    return sizeof(struct sockaddr_in6);
  } else if (pi->version == 4 && pi->sa_daddr.sin_family == AF_INET) {
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

int IsSameSourceAndDestAddress(const struct PacketInfo *pi) {
  if ((pi->version == 4 && pi->sa_saddr.sin_addr.s_addr == pi->sa_daddr.sin_addr.s_addr) ||
      (pi->version == 6 && IN6_ARE_ADDR_EQUAL(&pi->sa6_saddr.sin6_addr, &pi->sa6_daddr.sin6_addr))) {
    return TRUE;
  }

  return FALSE;
}
