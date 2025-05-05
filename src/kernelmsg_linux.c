// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#include <arpa/inet.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

#include "portsentry.h"
#include "io.h"
#include "util.h"
#include "kernelmsg.h"

static int ParseInterface(const struct nlmsghdr *nh, struct KernelMessage *kernelMessage);
static int ParseAddress(const struct nlmsghdr *nh, struct KernelMessage *kernelMessage);

int ListenKernel(void) {
  char err[ERRNOMAXBUF];
  int sock_fd;
  struct sockaddr_nl addr;

  if ((sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
    Error("Failed to create netlink socket: %s", ErrnoString(err, sizeof(err)));
    return ERROR;
  }

  memset(&addr, 0, sizeof(addr));
  addr.nl_family = AF_NETLINK;
  addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;

  if (bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    Error("Failed to bind netlink socket: %s", ErrnoString(err, sizeof(err)));
    close(sock_fd);
    return ERROR;
  }

  return sock_fd;
}

int ParseKernelMessage(const struct nlmsghdr *nh, struct KernelMessage *kernelMessage) {
  memset(kernelMessage, 0, sizeof(struct KernelMessage));

  if (nh->nlmsg_type == RTM_NEWADDR || nh->nlmsg_type == RTM_DELADDR) {
    struct ifaddrmsg *ifa = NLMSG_DATA(nh);

    // Adding IPv6 address will trigger 2 messages, only care when address is added
    if (nh->nlmsg_type == RTM_NEWADDR && ifa->ifa_family == AF_INET6 &&
        !(ifa->ifa_flags & IFA_F_TENTATIVE)) {
      Debug("ParseKernelMessage: IPv6 addr tentative, ignore");
      return FALSE;
    }
  }

  if (nh->nlmsg_type == RTM_NEWLINK || nh->nlmsg_type == RTM_DELLINK) {
    return ParseInterface(nh, kernelMessage);
  } else if (nh->nlmsg_type == RTM_NEWADDR || nh->nlmsg_type == RTM_DELADDR) {
    return ParseAddress(nh, kernelMessage);
  }

  Debug("Abort: Failed to handle message");
  return FALSE;
}

static int ParseInterface(const struct nlmsghdr *nh, struct KernelMessage *kernelMessage) {
  struct ifinfomsg *ifi = NLMSG_DATA(nh);
  struct rtattr *rta;
  int payload_len = RTM_PAYLOAD(nh);

  kernelMessage->type = KMT_INTERFACE;
  kernelMessage->action = nh->nlmsg_type == RTM_NEWLINK ? KMA_ADD : KMA_DEL;

  for (rta = IFLA_RTA(ifi); RTA_OK(rta, payload_len); rta = RTA_NEXT(rta, payload_len)) {
    if (rta->rta_type == IFLA_IFNAME) {
      if (strlen(RTA_DATA(rta)) >= IF_NAMESIZE) {
        Error("ParseInterface: Interface name %s is too long", RTA_DATA(rta));
        return FALSE;
      }
      SafeStrncpy(kernelMessage->interface.ifName, RTA_DATA(rta), IF_NAMESIZE);
      return TRUE;
    }
  }

  return FALSE;
}

static int ParseAddress(const struct nlmsghdr *nh, struct KernelMessage *kernelMessage) {
  struct ifaddrmsg *ifa = NLMSG_DATA(nh);
  struct rtattr *rta;
  int payload_len = RTM_PAYLOAD(nh);
  int target_type = (ifa->ifa_family == AF_INET6) ? IFA_ADDRESS : IFA_LOCAL;

  kernelMessage->type = KMT_ADDRESS;
  kernelMessage->action = nh->nlmsg_type == RTM_NEWADDR ? KMA_ADD : KMA_DEL;
  kernelMessage->address.family = ifa->ifa_family;

  // Get interface name from index
  if (if_indextoname(ifa->ifa_index, kernelMessage->address.ifName) == NULL) {
    return FALSE;
  }

  for (rta = IFA_RTA(ifa); RTA_OK(rta, payload_len); rta = RTA_NEXT(rta, payload_len)) {
    if (rta->rta_type == target_type) {
      inet_ntop(ifa->ifa_family, RTA_DATA(rta), kernelMessage->address.ipAddr, INET6_ADDRSTRLEN - 1);
      return TRUE;
    }
  }

  return FALSE;
}
