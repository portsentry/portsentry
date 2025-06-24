// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: BSD-2-Clause

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

int WriteBlockedFile(const struct sockaddr *address, struct BlockedState *bs);
int IsBlocked(const struct sockaddr *address, const struct BlockedState *bs);
int BlockedStateInit(struct BlockedState *bs);
void BlockedStateFree(struct BlockedState *bs);
int RewriteBlockedFile(const struct BlockedState *bs);
