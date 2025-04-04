// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "portsentry.h"
#include "io.h"
#include "util.h"
#include "kernelmsg.h"

#ifdef __OpenBSD__
#define ROUNDUP(a) ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#endif

int ListenKernel(void) {
  char err[ERRNOMAXBUF];
  int sockFd;

  if ((sockFd = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC)) < 0) {
    Error("Failed to create routing socket: %s", ErrnoString(err, sizeof(err)));
    return ERROR;
  }

  return sockFd;
}

int ParseKernelMessage(const char *buf, struct KernelMessage *kernelMessage) {
  struct rt_msghdr *rtm = (struct rt_msghdr *)buf;
  struct sockaddr *sa;

  memset(kernelMessage, 0, sizeof(struct KernelMessage));

  if (rtm->rtm_type == RTM_IFANNOUNCE) {
    struct if_announcemsghdr *ifan = (struct if_announcemsghdr *)buf;
    switch (ifan->ifan_what) {
    case IFAN_ARRIVAL:
      Debug("Created interface %s (index %d)", ifan->ifan_name,
            ifan->ifan_index);
      kernelMessage->type = KMT_INTERFACE;
      kernelMessage->action = KMA_ADD;
      strncpy(kernelMessage->interface.ifName, ifan->ifan_name, IF_NAMESIZE);
      break;
    case IFAN_DEPARTURE:
      Debug("Removed interface %s (index %d)", ifan->ifan_name,
            ifan->ifan_index);
      kernelMessage->type = KMT_INTERFACE;
      kernelMessage->action = KMA_DEL;
      strncpy(kernelMessage->interface.ifName, ifan->ifan_name, IF_NAMESIZE);
      break;
    default:
      return FALSE;
    }

    return TRUE;
  }

  if (rtm->rtm_type != RTM_NEWADDR && rtm->rtm_type != RTM_DELADDR)
    return FALSE;

  struct ifa_msghdr *ifam = (struct ifa_msghdr *)rtm;
  sa = (struct sockaddr *)(ifam + 1);

  struct in_addr *ifa_addr_v4 = NULL;
  struct in6_addr *ifa_addr_v6 = NULL;
  int addrs = ifam->ifam_addrs;

  // Walk through addresses using the address bitmask
  for (int i = 0; i < RTAX_MAX; i++) {
    if (addrs & (1 << i)) {
#ifdef __NetBSD__
      unsigned char *bytes = (unsigned char *)sa;

      if (i == RTAX_IFA) {
        // Check for IPv4 (0x10 (length), 0x02 (AF_INET)) on offset 4, 5 since
        // version 8+ of netbsd uses some padding before the address. Not sure
        // why this is the case. Please help
        if (bytes[4] == 0x10 && bytes[5] == 0x02) {
          ifa_addr_v4 = (struct in_addr *)(bytes + 8);
          sa = (struct sockaddr *)((char *)sa + 16);
        }
        // Check for IPv6 (0x1c (length), 0x18 (AF_INET6)) on offset 12,13
        // Again, since version 8+ of netbsd uses some padding before the
        // address. Not sure why this is the case. Please help
        else if (bytes[12] == 0x1c && bytes[13] == 0x18) {
          ifa_addr_v6 = (struct in6_addr *)(bytes + 20);
          sa = (struct sockaddr *)((char *)sa + 32);
        } else {
          sa = (struct sockaddr *)((char *)sa + 16);
        }
      } else {
        int len = (sa->sa_len > 0) ? sa->sa_len : 16;
        sa = (struct sockaddr *)((char *)sa + RT_ROUNDUP2(len, 4));
      }
#elif __FreeBSD__ || __OpenBSD__
      if (i == RTAX_IFA) {
        if (sa->sa_family == AF_INET) {
          ifa_addr_v4 = &((struct sockaddr_in *)sa)->sin_addr;
        } else if (sa->sa_family == AF_INET6) {
          ifa_addr_v6 = &((struct sockaddr_in6 *)sa)->sin6_addr;
        }
      }
#endif
#ifdef __FreeBSD__
      sa = (struct sockaddr *)((char *)sa + SA_SIZE(sa));
#elif __OpenBSD__
      sa = (struct sockaddr *)((char *)sa + ROUNDUP(sa->sa_len ? sa->sa_len : sizeof(struct sockaddr)));
#endif
    }
  }

  if (ifa_addr_v4 || ifa_addr_v6) {
    const char *name;
    if ((name = if_indextoname(ifam->ifam_index, kernelMessage->address.ifName)) == NULL) {
      Debug("if_indextoname returned NULL for interface index %d", ifam->ifam_index);
    }

    kernelMessage->type = KMT_ADDRESS;
    kernelMessage->action = (rtm->rtm_type == RTM_NEWADDR) ? KMA_ADD : KMA_DEL;

    if (ifa_addr_v4) {
      kernelMessage->address.family = AF_INET;
      inet_ntop(AF_INET, ifa_addr_v4, kernelMessage->address.ipAddr, sizeof(kernelMessage->address.ipAddr));
    } else if (ifa_addr_v6) {
      kernelMessage->address.family = AF_INET6;
      inet_ntop(AF_INET6, ifa_addr_v6, kernelMessage->address.ipAddr, sizeof(kernelMessage->address.ipAddr));
    }

    Debug("%s IPv%d address %s on interface %s index %d",
          (rtm->rtm_type == RTM_NEWADDR) ? "Added" : "Removed",
          kernelMessage->address.family == AF_INET ? 4 : 6,
          kernelMessage->address.ipAddr,
          name ? kernelMessage->address.ifName : "",
          ifam->ifam_index);
    return TRUE;
  }

  return FALSE;
}
