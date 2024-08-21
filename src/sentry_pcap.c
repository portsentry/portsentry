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

static int PrepPacket(struct PacketInfo *pi, const struct Device *device, const struct pcap_pkthdr *header, const u_char *packet, struct ip **ip, struct ip6_hdr **ip6, struct tcphdr **tcp, struct udphdr **udp);
static int SetSockaddrByPacket(struct sockaddr_in *client, struct sockaddr_in6 *client6, const struct ip *ip, const struct ip6_hdr *ip6, const struct tcphdr *tcp, const struct udphdr *udp);
static void PrintPacket(const struct Device *device, const struct ip *ip, const struct tcphdr *tcp, const struct udphdr *udp, const struct pcap_pkthdr *header);
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
  struct ip *ip;
  struct ip6_hdr *ip6;
  struct tcphdr *tcp;
  struct udphdr *udp;
  struct PacketInfo pi;

  if (PrepPacket(&pi, device, header, packet, &ip, &ip6, &tcp, &udp) == FALSE) {
    return;
  }

  if (pi.protocol == IPPROTO_TCP && (((tcp->th_flags & TH_ACK) != 0) || ((tcp->th_flags & TH_RST) != 0))) {
    Debug("Got TCP packet with ACK=%d RST=%d, ignoring, offending packet was:", (tcp->th_flags & TH_ACK) != 0 ? 1 : 0, (tcp->th_flags & TH_RST) != 0 ? 1 : 0);
    if (configData.logFlags & LOGFLAG_DEBUG) {
      PrintPacket(device, ip, tcp, udp, header);
    }
    return;
  }

  // FIXME: In pcap we need to consider the interface
  if (IsPortInUse(pi.port, pi.protocol) != FALSE) {
    return;
  }

  RunSentry(&pi);
}

static int PrepPacket(struct PacketInfo *pi, const struct Device *device, const struct pcap_pkthdr *header, const u_char *packet, struct ip **ip, struct ip6_hdr **ip6, struct tcphdr **tcp, struct udphdr **udp) {
  int iplen, ipOffset = ERROR, nextHeader;
  uint8_t protocol;
  struct ip6_ext *ip6ext;
  *ip = NULL;
  *ip6 = NULL;
  *tcp = NULL;
  *udp = NULL;

  if (device == NULL) {
    ipOffset = 0;
  } else if (pcap_datalink(device->handle) == DLT_EN10MB) {
    ipOffset = sizeof(struct ether_header);
  } else if (pcap_datalink(device->handle) == DLT_RAW) {
    ipOffset = 0;
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

    ipOffset = 4;
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

  char ipVersion = ((*(char *)(packet + ipOffset)) >> 4) & 0x0f;
  if (ipVersion == 4) {
    Debug("Packet is ipv4");
    *ip = (struct ip *)(packet + ipOffset);
    iplen = (*ip)->ip_hl * 4;
    protocol = (*ip)->ip_p;
  } else if (ipVersion == 6) {
    Debug("Packet is ipv6");
    *ip6 = (struct ip6_hdr *)(packet + ipOffset);
    nextHeader = (*ip6)->ip6_nxt;
    iplen = sizeof(struct ip6_hdr);

    /*
     * RFC8200
     * 0 	IPv6 Hop-by-Hop Option 	[RFC8200]
     * 43 	Routing Header for IPv6 	[RFC8200][RFC5095]
     * 44 	Fragment Header for IPv6 	[RFC8200]
     * 50 	Encapsulating Security Payload 	[RFC4303]
     * 51 	Authentication Header 	[RFC4302]
     * 59 	IPv6-NoNxt 	No Next Header for IPv6 		[RFC8200]
     * 60 	Destination Options for IPv6 	[RFC8200]
     * 135 	Mobility Header 	[RFC6275]
     * 139 	Host Identity Protocol 	[RFC7401]
     * 140 	Shim6 Protocol 	[RFC5533]
     * 253 	Use for experimentation and testing 	[RFC3692][RFC4727]
     * 254 	Use for experimentation and testing 	[RFC3692][RFC4727]
     */

    while (nextHeader == 0 || nextHeader == 43 || nextHeader == 44 || nextHeader == 50 ||
           nextHeader == 51 || nextHeader == 59 || nextHeader == 60 || nextHeader == 135 ||
           nextHeader == 139 || nextHeader == 140 || nextHeader == 253 || nextHeader == 254) {
      Debug("Processing IPv6 extension header %d", nextHeader);
      if (nextHeader == 59) {
        Error("IPv6-NoNxt detected, ignoring packet");
        return FALSE;
      } else if (nextHeader == 44) {
        Error("Fragment Header for IPv6 detected, ignoring packet");
        return FALSE;
      } else if (nextHeader == 253 || nextHeader == 254) {
        Error("RFC3692 Experimental/testing header detected, ignoring packet");
        return FALSE;
      }

      ip6ext = (struct ip6_ext *)(packet + ipOffset + iplen);
      nextHeader = ip6ext->ip6e_nxt;
      iplen += ip6ext->ip6e_len;
    }

    protocol = nextHeader;
  } else {
    Error("Packet on %s have unknown IP version %d", device->name, ipVersion);
    return FALSE;
  }

  if (protocol == IPPROTO_TCP) {
    *tcp = (struct tcphdr *)(packet + ipOffset + iplen);
  } else if (protocol == IPPROTO_UDP) {
    *udp = (struct udphdr *)(packet + ipOffset + iplen);
  } else {
    Error("Packet on %s have unknown protocol %d", (device != NULL) ? device->name : "NOT SET", protocol);
    if (configData.logFlags & LOGFLAG_DEBUG) {
      PrintPacket(device, *ip, *tcp, *udp, header);
    }
    return FALSE;
  }

  ClearPacketInfo(pi);
  pi->version = ipVersion;
  pi->protocol = protocol;
  pi->port = (protocol == IPPROTO_TCP) ? ntohs((*tcp)->th_dport) : ntohs((*udp)->uh_dport);
  pi->packet = (unsigned char *)packet;
  pi->ip = (*ip != NULL) ? *ip : NULL;
  pi->ip6 = (*ip6 != NULL) ? *ip6 : NULL;
  pi->tcp = (*tcp != NULL) ? *tcp : NULL;
  pi->udp = (*udp != NULL) ? *udp : NULL;

  return SetSockaddrByPacket(&pi->client, &pi->client6, pi->ip, pi->ip6, pi->tcp, pi->udp);
}

static int SetSockaddrByPacket(struct sockaddr_in *client, struct sockaddr_in6 *client6, const struct ip *ip, const struct ip6_hdr *ip6, const struct tcphdr *tcp, const struct udphdr *udp) {
  if (ip != NULL) {
    memset(client, 0, sizeof(struct sockaddr_in));
    client->sin_addr.s_addr = ip->ip_src.s_addr;
    client->sin_family = AF_INET;
    if (tcp != NULL) {
      client->sin_port = tcp->th_dport;
    } else if (udp != NULL) {
      client->sin_port = udp->uh_dport;
    } else {
      Error("No protocol header set during sockaddr resolution. Attempting to continue.");
      return FALSE;
    }
  } else if (ip6 != NULL) {
    memset(client6, 0, sizeof(struct sockaddr_in6));
    memcpy(&client6->sin6_addr, &ip6->ip6_src, sizeof(struct in6_addr));
    client6->sin6_family = AF_INET6;
    if (tcp != NULL) {
      client6->sin6_port = tcp->th_dport;
    } else if (udp != NULL) {
      client6->sin6_port = udp->uh_dport;
    } else {
      Error("No protocol header set during sockaddr resolution. Attempting to continue.");
      return FALSE;
    }
  } else {
    Error("No IP header set during sockaddr resolution. Attempting to continue.");
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
