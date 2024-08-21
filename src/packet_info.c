// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#include <string.h>
#include <arpa/inet.h>

#include "portsentry.h"
#include "packet_info.h"

void ClearPacketInfo(struct PacketInfo *pi) {
  memset(pi, 0, sizeof(struct PacketInfo));
  pi->listenSocket = -1;
  pi->tcpAcceptSocket = -1;
}

int ResolveTargetOfPacketInfo(struct PacketInfo *pi) {
  if (pi->version == 6 && pi->client6.sin6_family == AF_INET6) {
    if (inet_ntop(AF_INET6, &pi->client6.sin6_addr, pi->target, sizeof(pi->target)) == NULL) {
      return ERROR;
    }
  } else if (pi->version == 4 && pi->client.sin_family == AF_INET) {
    if (inet_ntop(AF_INET, &pi->client.sin_addr, pi->target, sizeof(pi->target)) == NULL) {
      return ERROR;
    }
  } else {
    return ERROR;
  }

  return TRUE;
}

char *GetTargetOfPacketInfo(struct PacketInfo *pi) {
  if (strlen(pi->target) == 0) {
    ResolveTargetOfPacketInfo(pi);
  }

  return pi->target;
}

struct sockaddr *GetClientSockaddrFromPacketInfo(const struct PacketInfo *pi) {
  if (pi->version == 6 && pi->client6.sin6_family == AF_INET6) {
    return (struct sockaddr *)&pi->client6;
  } else if (pi->version == 4 && pi->client.sin_family == AF_INET) {
    return (struct sockaddr *)&pi->client;
  }

  return NULL;
}

socklen_t GetClientSockaddrLenFromPacketInfo(const struct PacketInfo *pi) {
  if (pi->version == 6 && pi->client6.sin6_family == AF_INET6) {
    return sizeof(struct sockaddr_in6);
  } else if (pi->version == 4 && pi->client.sin_family == AF_INET) {
    return sizeof(struct sockaddr_in);
  }

  return 0;
}
