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
#include <errno.h>

#include "portsentry.h"
#include "sentry_pcap.h"
#include "listener.h"
#include "device.h"
#include "io.h"
#include "util.h"
#include "config_data.h"

#define POLL_TIMEOUT 500

static int PrepPacket(const struct Device *device, const struct pcap_pkthdr *header, const u_char *packet, struct ip **ip, struct tcphdr **tcp, struct udphdr **udp);
static int SetSockaddrByPacket(struct sockaddr_in *client, const struct ip *ip, const struct tcphdr *tcp, const struct udphdr *udp);
static void PrintPacket(const struct Device *device, const struct ip *ip, const struct tcphdr *tcp, const struct udphdr *udp, const struct pcap_pkthdr *header);
struct ip *GetIphdrByOffset(const u_char *packet, const int offset);

extern uint8_t g_isRunning;

int PortSentryPcap(void) {
  int status = FALSE, ret, nfds = 0, i;
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

  status = TRUE;

exit:
  if (fds)
    free(fds);
  if (lm)
    FreeListenerModule(lm);
  return status;
}

void HandlePacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  struct sockaddr_in client;
  struct Device *device = (struct Device *)args;
  struct ip *ip;
  struct tcphdr *tcp;
  struct udphdr *udp;
  int proto, port;

  if (PrepPacket(device, header, packet, &ip, &tcp, &udp) == FALSE) {
    return;
  }

  proto = ip->ip_p;
  if (proto == IPPROTO_TCP) {
    port = ntohs(tcp->th_dport);
  } else if (proto == IPPROTO_UDP) {
    port = ntohs(udp->uh_dport);
  } else {
    Error("Unknown protocol %d detected during packet handling", proto);
    return;
  }

  if (SetSockaddrByPacket(&client, ip, tcp, udp) == FALSE) {
    return;
  }

  if (proto == IPPROTO_TCP && (((tcp->th_flags & TH_ACK) != 0) || ((tcp->th_flags & TH_RST) != 0))) {
    Debug("Got TCP packet with ACK=%d RST=%d, ignoring, offending packet was:", (tcp->th_flags & TH_ACK) != 0 ? 1 : 0, (tcp->th_flags & TH_RST) != 0 ? 1 : 0);
    if (configData.logFlags & LOGFLAG_DEBUG) {
      PrintPacket(device, ip, tcp, udp, header);
    }
    return;
  }

  // FIXME: In pcap we need to consider the interface
  if (IsPortInUse(port, proto) != FALSE) {
    return;
  }

  RunSentry(proto, port, -1, &client, ip, tcp, NULL);
}

static int PrepPacket(const struct Device *device, const struct pcap_pkthdr *header, const u_char *packet, struct ip **ip, struct tcphdr **tcp, struct udphdr **udp) {
  int iplen;
  uint8_t protocol;
  *ip = NULL;
  *tcp = NULL;
  *udp = NULL;

  if (device == NULL) {
    *ip = GetIphdrByOffset(packet, 0);
  } else if (pcap_datalink(device->handle) == DLT_EN10MB) {
    *ip = GetIphdrByOffset(packet, sizeof(struct ether_header));
  } else if (pcap_datalink(device->handle) == DLT_RAW) {
    *ip = GetIphdrByOffset(packet, 0);
  } else if (
      pcap_datalink(device->handle) == DLT_NULL
#ifdef __OpenBSD__
      || pcap_datalink(device->handle) == DLT_LOOP
#endif
  ) {
    uint32_t nulltype = *packet;
    if (pcap_datalink(device->handle) == DLT_NULL) {
      if (nulltype != 2) {
        Error("Packet on %s have unsupported nulltype set (nulltype: %d) on a DLT_NULL dev", device->name, nulltype);
        return FALSE;
      }
#ifdef __OpenBSD__
    } else if (pcap_datalink(device->handle) == DLT_LOOP) {
      /*
       * FIXME: On OpenBSD 7.4 the nulltype is 0 on the loopback interface receiving IPv4 packets.
       * According to libpcap documentation it's supposed to be a network byte-order AF_ value.
       * If this holds true for OpenBSD's then packets are for some reason classified as AF_UNSPEC.
       * Confirm this
       */
      if (nulltype != 0) {
        Error("Packet on %s have unsupported nulltype set (nulltype: %d) on a DLT_LOOP dev", device->name, nulltype);
        return FALSE;
      }
#endif
    }

    *ip = GetIphdrByOffset(packet, 4);
  }
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

    *ip = GetIphdrByOffset(packet, 16);
  }
#endif
  else {
    Error("Packet on %s have unsupported datalink type set (datalink: %d)", device->name, pcap_datalink(device->handle));
    return FALSE;
  }

  iplen = (*ip)->ip_hl * 4;
  protocol = (*ip)->ip_p;

  if (protocol == IPPROTO_TCP) {
    *tcp = (struct tcphdr *)(((u_char *)*ip) + iplen);  // ip struct is wider than 1 byte so need recast
  } else if (protocol == IPPROTO_UDP) {
    *udp = (struct udphdr *)(((u_char *)*ip) + iplen);  // ip struct is wider than 1 byte so need recast
  } else {
    Error("Packet on %s have unknown protocol %d", (device != NULL) ? device->name : "NOT SET", protocol);
    if (configData.logFlags & LOGFLAG_DEBUG) {
      PrintPacket(device, *ip, *tcp, *udp, header);
    }
    return FALSE;
  }

  return TRUE;
}

static int SetSockaddrByPacket(struct sockaddr_in *client, const struct ip *ip, const struct tcphdr *tcp, const struct udphdr *udp) {
  uint8_t protocol;

  memset(client, 0, sizeof(struct sockaddr_in));
  protocol = ip->ip_p;
  client->sin_addr.s_addr = ip->ip_src.s_addr;

  client->sin_family = AF_INET;
  if (protocol == IPPROTO_TCP) {
    client->sin_port = tcp->th_dport;
  } else if (protocol == IPPROTO_UDP) {
    client->sin_port = udp->uh_dport;
  } else {
    Error("Unknown protocol %d detected during sockaddr resolution. Attempting to continue.", protocol);
    return FALSE;
  }

  return TRUE;
}

static void PrintPacket(const struct Device *device, const struct ip *ip, const struct tcphdr *tcp, const struct udphdr *udp, const struct pcap_pkthdr *header) {
  int iplen;
  uint8_t protocol, ipVersion, hl;
  char saddr[16], daddr[16];

  ntohstr(saddr, sizeof(saddr), ip->ip_src.s_addr);
  ntohstr(daddr, sizeof(daddr), ip->ip_dst.s_addr);
  iplen = ip->ip_hl * 4;
  protocol = ip->ip_p;
  ipVersion = ip->ip_v;
  hl = ip->ip_hl;

  if (device != NULL) {
    printf("%s: ", device->name);
  }

  if (header != NULL) {
    printf("%d [%d] ", header->caplen, header->len);
  }

  printf("ihl: %d IP len: %d proto: %s (%d) ver: %d saddr: %s daddr: %s ", hl, iplen,
         protocol == IPPROTO_TCP   ? "tcp"
         : protocol == IPPROTO_UDP ? "udp"
                                   : "other",
         protocol,
         ipVersion, saddr, daddr);

  if (protocol == IPPROTO_TCP) {
    printf("sport: %d dport: %d", ntohs(tcp->th_sport), ntohs(tcp->th_dport));
  } else if (protocol == IPPROTO_UDP) {
    printf("sport: %d dport: %d", ntohs(udp->uh_sport), ntohs(udp->uh_dport));
  }
  printf("\n");
}

struct ip *GetIphdrByOffset(const u_char *packet, const int offset) {
  return (struct ip *)(packet + offset);
}
