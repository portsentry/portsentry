// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include <netinet/in.h>

#include "uthash.h"

struct AddrStateIpv4 {
  in_addr_t ip;
  int count;
  UT_hash_handle hh;
};

struct AddrStateIpv6 {
  struct in6_addr ip;
  int count;
  UT_hash_handle hh;
};

struct SentryState {
  struct AddrStateIpv4 *addrStateIpv4;
  struct AddrStateIpv6 *addrStateIpv6;
  uint8_t isInitialized;
};

void InitSentryState(struct SentryState *sentryState);
void FreeSentryState(struct SentryState *sentryState);
int CheckState(struct SentryState *state, struct sockaddr *addr);
