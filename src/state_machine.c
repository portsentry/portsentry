// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: BSD-2-Clause

#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "config.h"
#include "config_data.h"
#include "portsentry.h"
#include "io.h"
#include "state_machine.h"

#define MAX_HASH_SIZE 1000000

static int CheckStateIpv4(struct SentryState *state, struct sockaddr_in *addr);
static int CheckStateIpv6(struct SentryState *state, struct sockaddr_in6 *addr);

static int CheckStateIpv4(struct SentryState *state, struct sockaddr_in *addr) {
  struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
  struct AddrStateIpv4 *addrStateIpv4;

  HASH_FIND(hh, state->addrStateIpv4, &addr_in->sin_addr.s_addr, sizeof(in_addr_t), addrStateIpv4);

  if (addrStateIpv4 == NULL) {
    if (HASH_COUNT(state->addrStateIpv4) >= MAX_HASH_SIZE) {
      addrStateIpv4 = state->addrStateIpv4;
      HASH_DEL(state->addrStateIpv4, addrStateIpv4);
      free(addrStateIpv4);
    }

    if ((addrStateIpv4 = malloc(sizeof(struct AddrStateIpv4))) == NULL) {
      Error("Unable to allocate new memory for AddrStateIpv4");
      return ERROR;
    }
    addrStateIpv4->ip = addr_in->sin_addr.s_addr;
    addrStateIpv4->count = 0;

    HASH_ADD(hh, state->addrStateIpv4, ip, sizeof(in_addr_t), addrStateIpv4);
  }

  addrStateIpv4->count++;

  if (addrStateIpv4->count >= configData.configTriggerCount) {
    return TRUE;
  }

  return FALSE;
}

static int CheckStateIpv6(struct SentryState *state, struct sockaddr_in6 *addr) {
  struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
  struct AddrStateIpv6 *addrStateIpv6;

  HASH_FIND(hh, state->addrStateIpv6, &addr_in6->sin6_addr, sizeof(struct in6_addr), addrStateIpv6);

  if (addrStateIpv6 == NULL) {
    if (HASH_COUNT(state->addrStateIpv6) >= MAX_HASH_SIZE) {
      addrStateIpv6 = state->addrStateIpv6;
      HASH_DEL(state->addrStateIpv6, addrStateIpv6);
      free(addrStateIpv6);
    }

    if ((addrStateIpv6 = malloc(sizeof(struct AddrStateIpv6))) == NULL) {
      Error("Unable to allocate new memory for AddrStateIpv6");
      return ERROR;
    }
    addrStateIpv6->ip = addr_in6->sin6_addr;
    addrStateIpv6->count = 0;

    HASH_ADD(hh, state->addrStateIpv6, ip, sizeof(struct in6_addr), addrStateIpv6);
  }

  addrStateIpv6->count++;

  if (addrStateIpv6->count >= configData.configTriggerCount) {
    return TRUE;
  }

  return FALSE;
}

void InitSentryState(struct SentryState *sentryState) {
  sentryState->addrStateIpv4 = NULL;
  sentryState->addrStateIpv6 = NULL;
  sentryState->isInitialized = TRUE;
}

void FreeSentryState(struct SentryState *sentryState) {
  struct AddrStateIpv4 *addrStateIpv4, *tmpAddrStateIpv4;
  struct AddrStateIpv6 *addrStateIpv6, *tmpAddrStateIpv6;

  HASH_ITER(hh, sentryState->addrStateIpv4, addrStateIpv4, tmpAddrStateIpv4) {
    HASH_DEL(sentryState->addrStateIpv4, addrStateIpv4);
    free(addrStateIpv4);
  }

  HASH_ITER(hh, sentryState->addrStateIpv6, addrStateIpv6, tmpAddrStateIpv6) {
    HASH_DEL(sentryState->addrStateIpv6, addrStateIpv6);
    free(addrStateIpv6);
  }

  sentryState->isInitialized = FALSE;
}

int CheckState(struct SentryState *state, struct sockaddr *addr) {
  assert(state != NULL);
  assert(addr != NULL);

  if (state->isInitialized == FALSE) {
    Error("Sentry state is not initialized");
    return ERROR;
  }

  // If the trigger count is 0, we don't need to check the state
  if (configData.configTriggerCount == 0) {
    return TRUE;
  }

  if (addr->sa_family == AF_INET) {
    return CheckStateIpv4(state, (struct sockaddr_in *)addr);
  } else if (addr->sa_family == AF_INET6) {
    return CheckStateIpv6(state, (struct sockaddr_in6 *)addr);
  }

  Error("Unsupported address family");
  return ERROR;
}
