// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#pragma once

#include <stdio.h>
#include <netinet/in.h>

struct IgnoreIp {
  union {
    struct in_addr addr4;
    struct in6_addr addr6;
  } ip;
  union {
    struct in_addr mask4;
    struct in6_addr mask6;
  } mask;
  int family;
};

struct IgnoreState {
  struct IgnoreIp *ignoreIpList;
  int ignoreIpListSize;
  uint8_t isInitialized;
};

int InitIgnore(struct IgnoreState *is);
void FreeIgnore(struct IgnoreState *is);
int IgnoreIpIsPresent(const struct IgnoreState *is, const struct sockaddr *sa);
