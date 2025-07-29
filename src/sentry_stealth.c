// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
// SPDX-FileContributor: Craig Rowland
//
// SPDX-License-Identifier: BSD-2-Clause

#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>

#include "portsentry.h"
#include "config_data.h"
#include "packet_info.h"
#include "io.h"
#include "util.h"
#include "sentry.h"

#define NFDS 2

extern uint8_t g_isRunning;

static ssize_t PacketRead(const int socket, char *buffer, const size_t bufferLen);

#ifdef FUZZ_SENTRY_STEALTH_PREP_PACKET
uint8_t g_isRunning = TRUE;
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  struct PacketInfo pi;
  ClearPacketInfo(&pi);
  pi.packetLength = IP_MAXPACKET;
  if (SetPacketInfoFromPacket(&pi, (unsigned char *)Data, Size) != TRUE) {
    return -1;
  }
  return 0;
}
#endif

int PortSentryStealthMode(void) {
  ssize_t packetLen;
  int status = EXIT_FAILURE, result;
  char packetBuffer[IP_MAXPACKET], err[ERRNOMAXBUF];
  struct pollfd fds[NFDS];
  struct PacketInfo pi;
  size_t i;
  nfds_t nfds = NFDS;

  assert(configData.sentryMode == SENTRY_MODE_STEALTH);

  memset(fds, 0, sizeof(fds));
  for (i = 0; i < nfds; i++) {
    fds[i].fd = -1;
    fds[i].events = POLLIN;
  }

  /* Listen for IPv4 and IPv6 packets on different sockets, it will probably(?)
   * be faster to let the kernel filter out all the other packet types than
   * using ETH_P_ALL and filter ourselves.
   */
  if ((fds[0].fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0) {
    Error("Unable to create socket: %s", ErrnoString(err, sizeof(err)));
    return ERROR;
  }

  if ((fds[1].fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IPV6))) < 0) {
    Error("Unable to create socket: %s", ErrnoString(err, sizeof(err)));
    return ERROR;
  }

  Log("Portsentry is now active and listening.");

  while (g_isRunning == TRUE) {
    result = poll(fds, nfds, -1);
    if (result == -1) {
      if (errno == EINTR) {
        continue;
      }
      Error("poll() failed: %s. Aborting.", ErrnoString(err, sizeof(err)));
      goto exit;
    } else if (result == 0) {
      Error("poll() timed out. Aborting.");
      goto exit;
    }

    for (i = 0; i < nfds; i++) {
      if (fds[i].revents != POLLIN) {
        continue;
      }

      if ((packetLen = PacketRead(fds[i].fd, packetBuffer, IP_MAXPACKET)) == ERROR)
        continue;

      ClearPacketInfo(&pi);
      pi.packetLength = IP_MAXPACKET;
      if (SetPacketInfoFromPacket(&pi, (unsigned char *)packetBuffer, (uint32_t)packetLen) != TRUE) {
        continue;
      }

      if (pi.protocol == IPPROTO_TCP) {
        if (((pi.tcp->th_flags & TH_ACK) != 0) || ((pi.tcp->th_flags & TH_RST) != 0)) {
          continue;
        }
        if (IsPortPresent(configData.tcpPorts, configData.tcpPortsLength, pi.port) == FALSE) {
          continue;
        }
      } else if (pi.protocol == IPPROTO_UDP) {
        if (IsPortPresent(configData.udpPorts, configData.udpPortsLength, pi.port) == FALSE) {
          continue;
        }
      } else {
        Error("Unknown protocol %d. Skipping", pi.protocol);
        continue;
      }

      if (IsPortInUse(&pi) != FALSE) {
        Log("Ignoring packet from %s to destination port %d, a service is running", pi.saddr, pi.port);
        continue;
      }

      RunSentry(&pi);
    }
  }

  status = EXIT_SUCCESS;

exit:

  for (i = 0; i < nfds; i++) {
    if (fds[i].fd != -1)
      close(fds[i].fd);
  }

  return status;
}

static ssize_t PacketRead(const int socket, char *buffer, const size_t bufferLen) {
  char err[ERRNOMAXBUF];
  ssize_t result;
  struct sockaddr_ll sll;
  socklen_t sllLen = sizeof(struct sockaddr_ll);

  if ((result = recvfrom(socket, buffer, bufferLen, 0, (struct sockaddr *)&sll, &sllLen)) == -1) {
    Error("Could not read from socket %d: %s. Aborting", socket, ErrnoString(err, sizeof(err)));
    return ERROR;
  } else if (result < (ssize_t)sizeof(struct ip)) {
    Error("Packet read from socket %d is too small (%zu bytes). Aborting", socket, result);
    return ERROR;
  }

  if (sll.sll_pkttype != PACKET_HOST) {
    Debug("Recived invalid packet on raw socket PacketRead: sllLen: %d, sll_family: %d, sll_protocol: %d (%x), sll_ifindex: %d, sll_hatype: %d, sll_pkttype: %d (%s), sll_halen: %d", sllLen,
          sll.sll_family, ntohs(sll.sll_protocol), ntohs(sll.sll_protocol), sll.sll_ifindex, sll.sll_hatype, sll.sll_pkttype,
          (sll.sll_pkttype == PACKET_HOST) ? "PACKET_HOST" : (sll.sll_pkttype == PACKET_BROADCAST) ? "PACKET_BROADCAST"
                                                         : (sll.sll_pkttype == PACKET_MULTICAST)   ? "PACKET_MULTICAST"
                                                         : (sll.sll_pkttype == PACKET_OTHERHOST)   ? "PACKET_OTHERHOST"
                                                         : (sll.sll_pkttype == PACKET_OUTGOING)    ? "PACKET_OUTGOING"
                                                         : (sll.sll_pkttype == PACKET_LOOPBACK)    ? "PACKET_LOOPBACK"
                                                         : (sll.sll_pkttype == PACKET_USER)        ? "PACKET_USER"
                                                         : (sll.sll_pkttype == PACKET_KERNEL)      ? "PACKET_KERNEL"
                                                                                                   : "UNKNOWN",
          sll.sll_halen);
    return ERROR;
  }

  return result;
}
