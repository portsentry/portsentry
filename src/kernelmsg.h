// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: BSD-2-Clause

#pragma once
#include <sys/types.h>
#include <net/if.h>
#include <arpa/inet.h>

#ifdef __linux__
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#endif

#include "pcap_listener.h"
#include "pcap_device.h"

enum KernelMessageType {
  KMT_UNKNOWN = 0,
  KMT_INTERFACE,
  KMT_ADDRESS,
};

enum KernelMessageAction {
  KMA_UNKNOWN = 0,
  KMA_ADD,
  KMA_DEL,
};

struct KernelMessage {
  enum KernelMessageType type;
  enum KernelMessageAction action;
  union {
    struct {
      char ifName[IF_NAMESIZE];
    } interface;
    struct {
      int family;
      char ipAddr[INET6_ADDRSTRLEN];
      char ifName[IF_NAMESIZE];
    } address;
  };
};

int ListenKernel(void);
#ifdef __linux__
int ParseKernelMessage(const struct nlmsghdr *nh, struct KernelMessage *kernelMessage);
#elif defined(__NetBSD__) || defined(__FreeBSD__) || defined(__OpenBSD__)
int ParseKernelMessage(const char *buf, struct KernelMessage *kernelMessage);
#endif
