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
int ParseKernelMessage(const struct nlmsghdr *nh, struct KernelMessage *kernelMessage);
struct Device *GetDeviceByKernelMessage(struct ListenerModule *lm, struct KernelMessage *kernelMessage);