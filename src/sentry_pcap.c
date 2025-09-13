// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: BSD-2-Clause

#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <errno.h>

#include "portsentry.h"
#include "sentry_pcap.h"
#include "pcap_listener.h"
#include "pcap_device.h"
#include "io.h"
#include "util.h"
#include "packet_info.h"
#include "sentry.h"
#include "kernelmsg.h"
#include "config_data.h"

#define POLL_TIMEOUT 500

static void HandlePacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
static int PrepPacket(struct PacketInfo *pi, const struct Device *device, const u_char *packet, const uint32_t packetLength);
static void ProcessKernelMessage(const int kernel_socket, struct ListenerModule *lm, struct pollfd **fds, nfds_t *nfds);
static void ExecKernelMessageLogic(struct ListenerModule *lm, struct pollfd **fds, nfds_t *nfds, struct KernelMessage *kernelMessage);
static struct Device *GetDeviceByKernelMessage(struct ListenerModule *lm, struct KernelMessage *kernelMessage);
static void StartDeviceAndAddPollFd(struct Device *device, struct pollfd **fds, nfds_t *nfds);
static void StopDeviceAndRemovePollFd(struct Device *device, struct pollfd **fds, nfds_t *nfds);
static void HandleAddressAdded(struct Device *device, struct KernelMessage *kernelMessage, struct pollfd **fds, nfds_t *nfds);
static void HandleAddressRemoved(struct Device *device, struct KernelMessage *kernelMessage, struct pollfd **fds, nfds_t *nfds);
static void HandleInterfaceAdded(struct Device *device, struct pollfd **fds, nfds_t *nfds);
static void HandleInterfaceRemoved(struct Device *device, struct pollfd **fds, nfds_t *nfds);

extern uint8_t g_isRunning;

#ifdef FUZZ_SENTRY_PCAP_PREP_PACKET
uint8_t g_isRunning = TRUE;
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  struct PacketInfo pi;
  if (PrepPacket(&pi, NULL, Data, Size) != TRUE) {
    return -1;
  }
  return 0;
}
#endif

int PortSentryPcap(void) {
  int status = EXIT_FAILURE, ret, kernel_socket;
  char err[ERRNOMAXBUF];
  struct ListenerModule *lm = NULL;
  struct pollfd *fds = NULL;
  struct Device *current = NULL;
  size_t i;
  nfds_t nfds = 0;

  if ((lm = AllocListenerModule()) == NULL) {
    goto exit;
  }

  if (InitListenerModule(lm) == FALSE) {
    goto exit;
  }

  if ((fds = SetupPollFds(lm, &nfds)) == NULL) {
    Error("Unable to allocate memory for pollfd");
    goto exit;
  }

  if ((kernel_socket = ListenKernel()) == -1) {
    goto exit;
  }

  fds = AddPollFd(fds, &nfds, kernel_socket);

  Log("Portsentry is now active and listening.");

  while (g_isRunning == TRUE) {
    ret = poll(fds, nfds, POLL_TIMEOUT);

    if (ret == -1) {
      if (errno == EINTR) {
        continue;
      }
      Error("poll() failed %s", ErrnoString(err, sizeof(err)));
      goto exit;
    } else if (ret == 0) {
      continue;
    }

    for (i = 0; i < nfds; i++) {
      if (fds[i].revents & POLLIN) {
        if (fds[i].fd == kernel_socket) {
          ProcessKernelMessage(kernel_socket, lm, &fds, &nfds);
          continue;
        }

        if ((current = GetDeviceByFd(lm, fds[i].fd)) == NULL) {
          Error("Unable to find device by fd %d in main pcap loop", fds[i].fd);
          goto exit;
        }

        do {
          ret = pcap_dispatch(current->handle, -1, HandlePacket, (u_char *)current);

          if (ret == PCAP_ERROR) {
            Error("pcap_dispatch() failed %s", pcap_geterr(current->handle));
            if (strncmp("The interface disappeared", pcap_geterr(current->handle), 25) == 0) {
              StopDeviceAndRemovePollFd(current, &fds, &nfds);
            }
          } else if (ret == PCAP_ERROR_BREAK) {
            Error("Got PCAP_ERROR_BREAK, ignoring");
          }
        } while (ret > 0);
      } else if (fds[i].revents & POLLERR) {
        if ((current = GetDeviceByFd(lm, fds[i].fd)) == NULL) {
          Error("On POLLERR: Unable to find device by fd %d in main pcap loop", fds[i].fd);
          goto exit;
        }

        Error("Got POLLERR on %s (fd: %d), stopping interface from sentry", current->name, fds[i].fd);
        StopDeviceAndRemovePollFd(current, &fds, &nfds);
      }
    }
  }

  status = EXIT_SUCCESS;

exit:
  if (fds)
    free(fds);
  if (lm)
    FreeListenerModule(lm);
  return status;
}

static void HandlePacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  struct Device *device = (struct Device *)args;
  struct PacketInfo pi;
  (void)header;

  if (PrepPacket(&pi, device, packet, header->len) == FALSE) {
    return;
  }

  if (pi.protocol == IPPROTO_TCP && (((pi.tcp->th_flags & TH_ACK) != 0) || ((pi.tcp->th_flags & TH_RST) != 0))) {
    return;
  }

  // FIXME: In pcap we need to consider the interface
  if (IsPortInUse(&pi) != FALSE) {
    Log("Ignoring packet from %s to destination port %d, a service is running", pi.saddr, pi.port);
    return;
  }

  RunSentry(&pi);
}

static int PrepPacket(struct PacketInfo *pi, const struct Device *device, const u_char *packet, const uint32_t packetLength) {
  int ipOffset = ERROR;

  if (device == NULL) {
    ipOffset = 0;
  } else if (pcap_datalink(device->handle) == DLT_EN10MB) {
    ipOffset = sizeof(struct ether_header);
  } else if (pcap_datalink(device->handle) == DLT_RAW) {
    ipOffset = 0;
  } else if (pcap_datalink(device->handle) == DLT_NULL) {
    uint32_t nulltype = *packet;
    if (nulltype != 2 && nulltype != 24 && nulltype != 28 && nulltype != 30) {
      Error("Packet on %s have unsupported nulltype set (nulltype: %d) on a DLT_NULL dev", device->name, nulltype);
      return FALSE;
    }
    ipOffset = 4;
  }
#ifdef __OpenBSD__
  else if (pcap_datalink(device->handle) == DLT_LOOP) {
    /*
     * FIXME: On OpenBSD 7.4 the nulltype is 0 on the loopback interface receiving IPv4 packets.
     * According to libpcap documentation it's supposed to be a network byte-order AF_ value.
     * If this holds true for OpenBSD's then packets are for some reason classified as AF_UNSPEC.
     * Confirm this
     */
    uint32_t nulltype = *packet;
    if (nulltype != 0) {
      Error("Packet on %s have unsupported nulltype set (nulltype: %d) on a DLT_LOOP dev", device->name, nulltype);
      return FALSE;
    }
    ipOffset = 4;
  }
#endif
#ifdef __linux__
  else if (pcap_datalink(device->handle) == DLT_LINUX_SLL) {
    if (ntohs(*(const uint16_t *)packet) != 0) {
      Verbose("Packet type on %s is not \"sent to us by somebody else\"", device->name);
      return FALSE;
    }

    if (ntohs(*(const uint16_t *)(packet + 2)) != ARPHRD_ETHER) {
      Verbose("Packet type on %s is not Ethernet (type: %d)", device->name, ntohs(*(const uint16_t *)(packet + 2)));
      return FALSE;
    }

    ipOffset = 16;
  }
#endif
  else {
    Error("Packet on %s have unsupported datalink type set (datalink: %d)", device->name, pcap_datalink(device->handle));
    return FALSE;
  }

  if (ipOffset == ERROR) {
    Error("Unable to determine IP offset for packet on %s", device->name);
    return FALSE;
  }

  if (packetLength < (uint32_t)ipOffset) {
    Error("Packet on %s is too short (%d bytes), ignoring", device->name, packetLength);
    return FALSE;
  }

  ClearPacketInfo(pi);
  return SetPacketInfoFromPacket(pi, (const unsigned char *)packet + ipOffset, packetLength - (uint32_t)ipOffset);
}

#ifdef __linux__
static void ProcessKernelMessage(const int kernel_socket, struct ListenerModule *lm, struct pollfd **fds, nfds_t *nfds) {
  struct nlmsghdr *nh;
  struct KernelMessage kernelMessage;
  char buf[4096];
  struct iovec iov = {buf, sizeof(buf)};
  struct sockaddr_nl sa;
  struct msghdr msg = {.msg_name = &sa,
                       .msg_namelen = sizeof(sa),
                       .msg_iov = &iov,
                       .msg_iovlen = 1};
  char err[ERRNOMAXBUF];
  size_t len;
  ssize_t ret = recvmsg(kernel_socket, &msg, 0);

  if (ret < 0) {
    Error("Failed to receive routing message: %s", ErrnoString(err, sizeof(err)));
    return;
  } else if (ret == 0) {
    Debug("Received 0 bytes from kernel socket");
    return;
  }

  len = (size_t)ret;

  for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
    if (ParseKernelMessage(nh, &kernelMessage) != TRUE) {
      continue;
    }

    ExecKernelMessageLogic(lm, fds, nfds, &kernelMessage);
  }
}

#elif defined(__NetBSD__) || defined(__FreeBSD__) || defined(__OpenBSD__)
static void ProcessKernelMessage(const int kernel_socket, struct ListenerModule *lm, struct pollfd **fds, nfds_t *nfds) {
  char buf[4096];
  char err[ERRNOMAXBUF];
  struct KernelMessage kernelMessage;
  ssize_t len;

  if ((len = read(kernel_socket, buf, sizeof(buf))) < 0) {
    Error("Failed to receive routing message: %s", ErrnoString(err, sizeof(err)));
    return;
  }

  if (ParseKernelMessage(buf, &kernelMessage) != TRUE) {
    return;
  }

  ExecKernelMessageLogic(lm, fds, nfds, &kernelMessage);
}
#endif

static void ExecKernelMessageLogic(struct ListenerModule *lm, struct pollfd **fds, nfds_t *nfds, struct KernelMessage *kernelMessage) {
  struct Device *device = NULL;

  if ((device = GetDeviceByKernelMessage(lm, kernelMessage)) == NULL) {
    if ((IsInterfacePresent(&configData, "ALL") || IsInterfacePresent(&configData, "ALL_NLO")) && kernelMessage->action == KMA_ADD) {
      struct Device *newDevice;
      const char *ifName = kernelMessage->type == KMT_INTERFACE ? kernelMessage->interface.ifName : kernelMessage->address.ifName;

      Debug("ExecKernelMessageLogic - Device not found: %s - attempting bringup", ifName);
      if ((newDevice = CreateDevice(ifName)) == NULL) {
        Error("ExecKernelMessageLogic - Device %s not found, and not able to create it", ifName);
        return;
      }

      if (AddDevice(lm, newDevice) == FALSE) {
        Error("ExecKernelMessageLogic - Device %s not found, and not able to add it", ifName);
        FreeDevice(newDevice);
        newDevice = NULL;
        return;
      }

      device = newDevice;
    } else {
      Debug("ExecKernelMessageLogic - Device not found: %s %s: %s", kernelMessage->type == KMT_INTERFACE ? "Interface" : "Address",
            kernelMessage->action == KMA_ADD ? "Added" : "Removed",
            kernelMessage->type == KMT_INTERFACE ? kernelMessage->interface.ifName : kernelMessage->address.ipAddr);
      return;
    }
  }

  if (kernelMessage->type == KMT_ADDRESS) {
    if (kernelMessage->action == KMA_ADD) {
      HandleAddressAdded(device, kernelMessage, fds, nfds);
    } else if (kernelMessage->action == KMA_DEL) {
      HandleAddressRemoved(device, kernelMessage, fds, nfds);
    }
  } else if (kernelMessage->type == KMT_INTERFACE) {
    if (kernelMessage->action == KMA_ADD) {
      HandleInterfaceAdded(device, fds, nfds);
    } else if (kernelMessage->action == KMA_DEL) {
      HandleInterfaceRemoved(device, fds, nfds);
    }
  }
}

static struct Device *GetDeviceByKernelMessage(struct ListenerModule *lm, struct KernelMessage *kernelMessage) {
  if (kernelMessage->type == KMT_ADDRESS) {
    if (kernelMessage->action == KMA_ADD) {
      return FindDeviceByName(lm, kernelMessage->address.ifName);
    } else if (kernelMessage->action == KMA_DEL) {
      return FindDeviceByIpAddr(lm, kernelMessage->address.ipAddr);
    }
  } else if (kernelMessage->type == KMT_INTERFACE) {
    return FindDeviceByName(lm, kernelMessage->interface.ifName);
  }

  return NULL;
}

static void StartDeviceAndAddPollFd(struct Device *device, struct pollfd **fds, nfds_t *nfds) {
  if (StartDevice(device) == TRUE) {
    *fds = AddPollFd(*fds, nfds, device->fd);
  }
}

static void StopDeviceAndRemovePollFd(struct Device *device, struct pollfd **fds, nfds_t *nfds) {
  int fd = device->fd;
  StopDevice(device);
  *fds = RemovePollFd(*fds, nfds, fd);
}

static void HandleAddressAdded(struct Device *device, struct KernelMessage *kernelMessage, struct pollfd **fds, nfds_t *nfds) {
  if (device->state != DEVICE_STATE_RUNNING) {
    Debug("ProcessKernelMessage[KMT_ADDRESS ADD]: %s not running, starting it", device->name);
    // Start device resets and adds all addresses
    StartDeviceAndAddPollFd(device, fds, nfds);
  } else {
    Debug("ProcessKernelMessage[KMT_ADDRESS ADD]: %s is already running, adding address and refiltering", device->name);
    if (AddAddress(device, kernelMessage->address.ipAddr, kernelMessage->address.family) == TRUE) {
      SetupFilter(device);
    }
  }
}

static void HandleAddressRemoved(struct Device *device, struct KernelMessage *kernelMessage, struct pollfd **fds, nfds_t *nfds) {
  RemoveAddress(device, kernelMessage->address.ipAddr);
  if (GetNoAddresses(device) == 0) {
    Debug("ProcessKernelMessage[KMT_ADDRESS DEL]: No addresses left on %s, stopping device", device->name);
    StopDeviceAndRemovePollFd(device, fds, nfds);
  } else {
    if (device->state == DEVICE_STATE_RUNNING) {
      Debug("ProcessKernelMessage[KMT_ADDRESS DEL]: %s has addresses left, refiltering", device->name);
      SetupFilter(device);
    }
  }
}

static void HandleInterfaceAdded(struct Device *device, struct pollfd **fds, nfds_t *nfds) {
  if (device->state != DEVICE_STATE_RUNNING) {
    Debug("ProcessKernelMessage[KMT_INTERFACE UP]: Device %s was not running, starting it", device->name);
    StartDeviceAndAddPollFd(device, fds, nfds);
  } else {
    Debug("ProcessKernelMessage[KMT_INTERFACE UP]: Device %s is running, reset all addresses and refiltering", device->name);

    // When interface becomes available, it might have new addresses. Reinitialize.
    RemoveAllAddresses(device);

    if (SetAllAddresses(device) == ERROR) {
      Error("ProcessKernelMessage[KMT_INTERFACE UP]: Unable to set all addresses for device %s. Emergency stop", device->name);
      StopDeviceAndRemovePollFd(device, fds, nfds);
      return;
    }

    if (SetupFilter(device) == ERROR) {
      Error("ProcessKernelMessage[KMT_INTERFACE UP]: Unable to setup filter for device %s. Emergency stop", device->name);
      StopDeviceAndRemovePollFd(device, fds, nfds);
    }
  }
}

static void HandleInterfaceRemoved(struct Device *device, struct pollfd **fds, nfds_t *nfds) {
  if (device->state == DEVICE_STATE_RUNNING) {
    Debug("ProcessKernelMessage[KMT_INTERFACE DOWN]: Device %s is running, stopping it", device->name);
    StopDeviceAndRemovePollFd(device, fds, nfds);
  } else {
    Debug("ProcessKernelMessage[KMT_INTERFACE DOWN]: Device %s is not running, skipping", device->name);
  }
}
