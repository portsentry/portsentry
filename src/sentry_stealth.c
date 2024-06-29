// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
// SPDX-FileContributor: Craig Rowland
//
// SPDX-License-Identifier: CPL-1.0

#include <sys/types.h>
#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

#include "config_data.h"
#include "connection_data.h"
#include "io.h"
#include "portsentry.h"
#include "state_machine.h"
#include "sentry_stealth.h"
#include "util.h"

extern uint8_t g_isRunning;

int PortSentryStealthMode(void) {
  int count, nfds, result;
  int tcpSockfd = -1, udpSockfd = -1, connectionDataSize;
  char packetBuffer[IP_MAXPACKET], err[ERRNOMAXBUF];
  struct sockaddr_in client;
  struct ip *ip = NULL;
  struct tcphdr *tcp = NULL;
  struct udphdr *udp = NULL;
  struct pollfd fds[2];
  struct ConnectionData connectionData[MAXSOCKS];
  struct ConnectionData *cd;
  void *p;

  assert(configData.sentryMode == SENTRY_MODE_STEALTH);

  if ((connectionDataSize = ConstructConnectionData(connectionData, MAXSOCKS)) == 0) {
    Error("Unable to add any ports to the connect sentry. Aborting.");
    return (ERROR);
  }

  if (connectionDataSize == 0) {
    Error("Could not bind ANY sockets. Shutting down.");
    return (ERROR);
  }

  nfds = 0;
  if (configData.tcpPortsLength > 0) {
    if ((tcpSockfd = OpenRAWTCPSocket()) == ERROR) {
      Error("Could not open RAW TCP socket: %s. Aborting.", ErrnoString(err, sizeof(err)));
      return (ERROR);
    }

    fds[nfds].fd = tcpSockfd;
    fds[nfds].events = POLLIN;
    nfds++;
  }

  if (configData.udpPortsLength > 0) {
    if ((udpSockfd = OpenRAWUDPSocket()) == ERROR) {
      Error("Could not open RAW UDP socket: %s. Aborting.", ErrnoString(err, sizeof(err)));
      return (ERROR);
    }

    fds[nfds].fd = udpSockfd;
    fds[nfds].events = POLLIN;
    nfds++;
  }

  Log("PortSentry is now active and listening.");

  while (g_isRunning == TRUE) {
    result = poll(fds, nfds, -1);
    if (result == -1) {
      if (errno == EINTR) {
        continue;
      }
      Error("poll() failed: %s. Aborting.", ErrnoString(err, sizeof(err)));
      return (ERROR);
    } else if (result == 0) {
      Error("poll() timed out. Aborting.");
      return (ERROR);
    }

    for (count = 0; count < nfds; count++) {
      if (fds[count].revents != POLLIN) {
        continue;
      }

      if (PacketRead(fds[count].fd, packetBuffer, IP_MAXPACKET, &ip, &p) != TRUE)
        continue;

      if (SetConvenienceData(connectionData, connectionDataSize, ip, p, &client, &cd, &tcp, &udp) != TRUE) {
        continue;
      }

      if (cd->protocol == IPPROTO_TCP && (((tcp->th_flags & TH_ACK) != 0) || ((tcp->th_flags & TH_RST) != 0))) {
        continue;
      }

      if (IsPortInUse(cd->port, cd->protocol) != FALSE) {
        continue;
      }

      RunSentry(cd, &client, ip, tcp, NULL);
    }
  }

  if (tcpSockfd != -1)
    close(tcpSockfd);

  if (udpSockfd != -1)
    close(udpSockfd);

  return TRUE;
}
