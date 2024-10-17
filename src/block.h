// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#pragma once

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

struct BlockedNode {
  struct sockaddr_in6 address;  // Will be casred to sockaddr_in or sockaddr_in6 depending on address family
  struct BlockedNode *next;
};

struct BlockedState {
  uint8_t isInitialized;
  struct BlockedNode *head;
};

int WriteBlockedFile(struct sockaddr *address, struct BlockedState *bs);
int IsBlocked(struct sockaddr *address, struct BlockedState *bs);
int BlockedStateInit(struct BlockedState *bs);
void BlockedStateFree(struct BlockedState *bs);
