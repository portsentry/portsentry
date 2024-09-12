// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
// SPDX-FileContributor: Craig Rowland
//
// SPDX-License-Identifier: CPL-1.0

#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>

#include "config_data.h"
#include "sentry_connect.h"
#include "io.h"
#include "portsentry.h"
#include "util.h"
#include "packet_info.h"

extern uint8_t g_isRunning;

struct ConnectionData {
  uint16_t port;
  int protocol;
  int sockfd;
};

static int SetConnectionData(struct ConnectionData **cd, const int cdIdx, const uint16_t port, const int proto);
static int ConstructConnectionData(struct ConnectionData **cd);
static void FreeConnectionData(struct ConnectionData **cd, int *cdSize);

int PortSentryConnectMode(void) {
  int status = EXIT_FAILURE;
  struct sockaddr_in6 client;
  socklen_t clientLength;
  int incomingSockfd = -1, result;
  int count = 0;
  char err[ERRNOMAXBUF];
  struct pollfd *fds = NULL;
  struct ConnectionData *connectionData = NULL;
  struct PacketInfo pi;
  int connectionDataSize = 0;
  char tmp;

  assert(configData.sentryMode == SENTRY_MODE_CONNECT);

  if ((connectionDataSize = ConstructConnectionData(&connectionData)) == 0) {
    Error("Unable to add any ports to the connect sentry. Aborting.");
    return EXIT_FAILURE;
  }

  if ((fds = (struct pollfd *)malloc(sizeof(struct pollfd) * connectionDataSize)) == NULL) {
    Error("Unable to allocate memory for pollfd");
    return EXIT_FAILURE;
  }

  for (count = 0; count < connectionDataSize; count++) {
    fds[count].fd = connectionData[count].sockfd;
    fds[count].events = POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI;
    fds[count].revents = 0;
  }

  Log("PortSentry is now active and listening.");

  while (g_isRunning == TRUE) {
    result = poll(fds, connectionDataSize, -1);

    if (result == -1) {
      if (errno == EINTR) {
        continue;
      }
      Error("poll() failed %s", ErrnoString(err, sizeof(err)));
      goto exit;
    } else if (result == 0) {
      Error("poll() timed out. Aborting.");
      goto exit;
    }

    for (count = 0; count < connectionDataSize; count++) {
      if ((fds[count].revents & POLLIN) == 0) {
        continue;
      }

      incomingSockfd = -1;
      clientLength = sizeof(client);

      if (connectionData[count].protocol == IPPROTO_TCP) {
        if ((incomingSockfd = accept(connectionData[count].sockfd, (struct sockaddr *)&client, &clientLength)) == -1) {
          Log("attackalert: Possible stealth scan from unknown host to TCP port: %d (accept failed %d: %s)", connectionData[count].port, errno, ErrnoString(err, sizeof(err)));
          continue;
        }
      } else if (connectionData[count].protocol == IPPROTO_UDP) {
        if (recvfrom(connectionData[count].sockfd, &tmp, 1, 0, (struct sockaddr *)&client, &clientLength) == -1) {
          Error("Could not accept incoming data on UDP port: %d: %s", connectionData[count].port, ErrnoString(err, sizeof(err)));
          continue;
        }
      }

      ClearPacketInfo(&pi);
      pi.protocol = connectionData[count].protocol;
      pi.port = connectionData[count].port;
      pi.version = 6;
      pi.listenSocket = connectionData[count].sockfd;
      pi.tcpAcceptSocket = incomingSockfd;
      SetSockaddr6(&pi.sa6_saddr, client.sin6_addr, client.sin6_port, pi.saddr, sizeof(pi.saddr));
      pi.sa6_daddr.sin6_port = connectionData[count].port;

      RunSentry(&pi);
    }
  }

  status = EXIT_SUCCESS;

exit:
  FreeConnectionData(&connectionData, &connectionDataSize);

  if (fds != NULL) {
    free(fds);
    fds = NULL;
  }

  if (incomingSockfd != -1) {
    close(incomingSockfd);
    incomingSockfd = -1;
  }

  for (count = 0; count < connectionDataSize; count++) {
    if (connectionData[count].sockfd != -1) {
      close(connectionData[count].sockfd);
      connectionData[count].sockfd = -1;
    }
  }

  return status;
}

static int SetConnectionData(struct ConnectionData **cd, const int cdIdx, const uint16_t port, const int proto) {
  int sockfd;
  assert(proto == IPPROTO_TCP || proto == IPPROTO_UDP);

  if (port == 0) {
    Error("Invalid port 0 defined in %s, unable to listen. Skipping", (proto == IPPROTO_TCP ? "TCP_PORTS" : "UDP_PORTS"));
    return FALSE;
  }

  Log("Listen on %s port: %d", (proto == IPPROTO_TCP ? "TCP" : "UDP"), port);

  if ((sockfd = SetupPort(port, proto)) < 0) {
    Error("Could not bind %s socket on port %d. Attempting to continue", GetProtocolString(proto), port);
    return FALSE;
  }

  if ((*cd = realloc(*cd, sizeof(struct ConnectionData) * (cdIdx + 1))) == NULL) {
    Crash(EXIT_FAILURE, "Unable to allocate memory for connection data");
  }

  memset(&(*cd)[cdIdx], 0, sizeof(struct ConnectionData));

  (*cd)[cdIdx].port = port;
  (*cd)[cdIdx].protocol = proto;
  (*cd)[cdIdx].sockfd = sockfd;

  return TRUE;
}

int ConstructConnectionData(struct ConnectionData **cd) {
  int i, j, cdIdx = 0;

  for (i = 0; i < configData.tcpPortsLength; i++) {
    if (IsPortSingle(&configData.tcpPorts[i])) {
      if (SetConnectionData(cd, cdIdx, configData.tcpPorts[i].single, IPPROTO_TCP) == TRUE) {
        cdIdx++;
      }
    } else {
      for (j = configData.tcpPorts[i].range.start; j <= configData.tcpPorts[i].range.end; j++) {
        if (SetConnectionData(cd, cdIdx, j, IPPROTO_TCP) == TRUE) {
          cdIdx++;
        }
      }
    }
  }

  for (i = 0; i < configData.udpPortsLength; i++) {
    if (IsPortSingle(&configData.udpPorts[i])) {
      if (SetConnectionData(cd, cdIdx, configData.udpPorts[i].single, IPPROTO_UDP) == TRUE) {
        cdIdx++;
      }
    } else {
      for (j = configData.udpPorts[i].range.start; j <= configData.udpPorts[i].range.end; j++) {
        if (SetConnectionData(cd, cdIdx, j, IPPROTO_UDP) == TRUE) {
          cdIdx++;
        }
      }
    }
  }

  return cdIdx;
}

void FreeConnectionData(struct ConnectionData **cd, int *cdSize) {
  if (*cd != NULL) {
    free(*cd);
    *cd = NULL;
  }

  *cdSize = 0;
}
