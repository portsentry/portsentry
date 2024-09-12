// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

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
#include "config_data.h"
#include "packet_info.h"

#define POLL_TIMEOUT 500

static int PrepPacket(struct PacketInfo *pi, const struct Device *device, const u_char *packet);
struct ip *GetIphdrByOffset(const u_char *packet, const int offset);

extern uint8_t g_isRunning;

int PortSentryPcap(void) {
  int status = EXIT_FAILURE, ret, nfds = 0, i;
  char err[ERRNOMAXBUF];
  struct ListenerModule *lm = NULL;
  struct pollfd *fds = NULL;
  struct Device *current = NULL;

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

  Log("PortSentry is now active and listening.");

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
        if ((current = GetDeviceByFd(lm, fds[i].fd)) == NULL) {
          Error("Unable to find device by fd %d", fds[i].fd);
          goto exit;
        }

        do {
          ret = pcap_dispatch(current->handle, -1, HandlePacket, (u_char *)current);

          if (ret == PCAP_ERROR) {
            Error("pcap_dispatch() failed %s, ignoring", pcap_geterr(current->handle));
          } else if (ret == PCAP_ERROR_BREAK) {
            Error("Got PCAP_ERROR_BREAK, ignoring");
          }
        } while (ret > 0);
      } else if (fds[i].revents & POLLERR) {
        if ((current = GetDeviceByFd(lm, fds[i].fd)) == NULL) {
          Error("Unable to find device by fd %d", fds[i].fd);
          goto exit;
        }

        Error("Got POLLERR on %s (fd: %d), removing interface from sentry", current->name, fds[i].fd);
        if (RemoveDevice(lm, current) == FALSE) {
          Error("Unable to remove device %s from sentry", current->name);
          goto exit;
        }
        if ((fds = RemovePollFd(fds, &nfds, fds[i].fd)) == NULL) {
          Error("Unable to remove fd %d from pollfd", fds[i].fd);
          goto exit;
        }
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

void HandlePacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  struct Device *device = (struct Device *)args;
  struct PacketInfo pi;
  (void)header;

  if (PrepPacket(&pi, device, packet) == FALSE) {
    return;
  }

  if (pi.protocol == IPPROTO_TCP && (((pi.tcp->th_flags & TH_ACK) != 0) || ((pi.tcp->th_flags & TH_RST) != 0))) {
    return;
  }

  // FIXME: In pcap we need to consider the interface
  if (IsPortInUse(pi.port, pi.protocol) != FALSE) {
    return;
  }

  RunSentry(&pi);
}

static int PrepPacket(struct PacketInfo *pi, const struct Device *device, const u_char *packet) {
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
    if (ntohs(*(uint16_t *)packet) != 0) {
      Verbose("Packet type on %s is not \"sent to us by somebody else\"", device->name);
      return FALSE;
    }

    if (ntohs(*(uint16_t *)(packet + 2)) != ARPHRD_ETHER) {
      Verbose("Packet type on %s is not Ethernet (type: %d)", device->name, ntohs(*(uint16_t *)(packet + 2)));
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

  ClearPacketInfo(pi);
  pi->packet = (unsigned char *)packet + ipOffset;
  return SetPacketInfo(pi);
}
