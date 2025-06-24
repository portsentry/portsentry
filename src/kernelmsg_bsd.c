// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: BSD-2-Clause

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

#if defined(__OpenBSD__) || defined(__FreeBSD__)
#define ROUNDUP(a) \
  ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#define RT_ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))
#endif

static int HandleInterfaceAnnounce(const char *buf, struct KernelMessage *kernelMessage);
static int HandleAddressChange(const char *buf, struct KernelMessage *kernelMessage);
static int HandleRTAX_IFA(const struct sockaddr *sa, struct KernelMessage *kernelMessage);
static int HandleRTAX_IFP(const struct sockaddr *sa, struct KernelMessage *kernelMessage);

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

  memset(kernelMessage, 0, sizeof(struct KernelMessage));

  if (rtm->rtm_type == RTM_IFANNOUNCE) {
    return HandleInterfaceAnnounce(buf, kernelMessage);
  } else if ((rtm->rtm_type == RTM_NEWADDR || rtm->rtm_type == RTM_DELADDR) && rtm->rtm_addrs > 0) {
    return HandleAddressChange(buf, kernelMessage);
  }

  return FALSE;
}

static int HandleInterfaceAnnounce(const char *buf, struct KernelMessage *kernelMessage) {
  struct if_announcemsghdr *ifan = (struct if_announcemsghdr *)buf;

  kernelMessage->type = KMT_INTERFACE;

  switch (ifan->ifan_what) {
  case IFAN_ARRIVAL:
    if (strlen(ifan->ifan_name) >= IF_NAMESIZE) {
      Error("Interface name %s is too long", ifan->ifan_name);
      return FALSE;
    }
    Debug("Interface %s (index %d) arrived", ifan->ifan_name,
          ifan->ifan_index);
    kernelMessage->action = KMA_ADD;
    SafeStrncpy(kernelMessage->interface.ifName, ifan->ifan_name, IF_NAMESIZE);
    break;
  case IFAN_DEPARTURE:
    if (strlen(ifan->ifan_name) >= IF_NAMESIZE) {
      Error("Interface name %s is too long", ifan->ifan_name);
      return FALSE;
    }
    Debug("Interface %s (index %d) departed", ifan->ifan_name,
          ifan->ifan_index);
    kernelMessage->action = KMA_DEL;
    SafeStrncpy(kernelMessage->interface.ifName, ifan->ifan_name, IF_NAMESIZE);
    break;
  default:
    Error("Unknown interface announce type: IFAN_WHAT: %d, ignoring", ifan->ifan_what);
    return FALSE;
  }

  return TRUE;
}

static int HandleAddressChange(const char *buf, struct KernelMessage *kernelMessage) {
  struct ifa_msghdr *ifam = (struct ifa_msghdr *)buf;
  struct sockaddr *sa;
  char *cp;

  cp = ((char *)(ifam + 1));
  kernelMessage->type = KMT_ADDRESS;
  kernelMessage->action = ifam->ifam_type == RTM_NEWADDR ? KMA_ADD : KMA_DEL;

  for (int i = 0; i < RTAX_MAX; i++) {
    if (ifam->ifam_addrs & (1 << i)) {
      sa = (struct sockaddr *)cp;

      if (i == RTAX_IFA) {
        if (HandleRTAX_IFA(sa, kernelMessage) == FALSE) {
          return FALSE;
        }
      } else if (i == RTAX_IFP) {
        if (HandleRTAX_IFP(sa, kernelMessage) == FALSE) {
          return FALSE;
        }
      }

      RT_ADVANCE(cp, sa);
    }
  }

  Debug("Final kernel message: %s IPv%d address %s on interface %s index %d",
        kernelMessage->action == KMA_ADD ? "Added" : "Removed",
        kernelMessage->address.family == AF_INET ? 4 : 6,
        kernelMessage->address.ipAddr,
        kernelMessage->address.ifName,
        ifam->ifam_index);

  return TRUE;
}

static int HandleRTAX_IFA(const struct sockaddr *sa, struct KernelMessage *kernelMessage) {
  if (sa->sa_family == AF_INET) {
    inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr, kernelMessage->address.ipAddr, sizeof(kernelMessage->address.ipAddr));
  } else if (sa->sa_family == AF_INET6) {
    inet_ntop(AF_INET6, &((struct sockaddr_in6 *)sa)->sin6_addr, kernelMessage->address.ipAddr, sizeof(kernelMessage->address.ipAddr));
  } else {
    Error("Unexpected address family: %d for RTAX_IFA. Unable to parse address", sa->sa_family);
    return FALSE;
  }

  kernelMessage->address.family = sa->sa_family;

  return TRUE;
}

static int HandleRTAX_IFP(const struct sockaddr *sa, struct KernelMessage *kernelMessage) {
  if (sa->sa_family != AF_LINK) {
    Error("Unexpected address family: %d for RTAX_IFP. Unable to parse interface name", sa->sa_family);
    return FALSE;
  }

  struct sockaddr_dl *sdl = (struct sockaddr_dl *)sa;
  if (sdl->sdl_nlen >= IF_NAMESIZE) {
    Error("Unexpected interface length %d (IF_NAMESIZE: %d) on RTAX_IFP", sdl->sdl_nlen, IF_NAMESIZE);
    return FALSE;
  } else {
    SafeStrncpy(kernelMessage->address.ifName, sdl->sdl_data, sdl->sdl_nlen + 1);
  }

  return TRUE;
}
