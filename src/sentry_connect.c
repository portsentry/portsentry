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
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include "config_data.h"
#include "sentry_connect.h"
#include "io.h"
#include "portsentry.h"
#include "state_machine.h"
#include "util.h"

extern uint8_t g_isRunning;

struct ConnectionData {
  uint16_t port;
  int protocol;
  int sockfd;
};

static int SetConnectionData(struct ConnectionData *cd, const int cdSize, const int cdIdx, const uint16_t port, const int proto);
static int ConstructConnectionData(struct ConnectionData *cd, const int cdSize);

int PortSentryConnectMode(void) {
  struct sockaddr_in client;
  socklen_t clientLength;
  int incomingSockfd, result;
  int count = 0;
  char err[ERRNOMAXBUF];
  fd_set selectFds;
  int nfds = 0;
  struct ConnectionData connectionData[MAXSOCKS];
  int connectionDataSize = 0;
  char tmp;

  assert(configData.sentryMode == SENTRY_MODE_CONNECT);

  if ((connectionDataSize = ConstructConnectionData(connectionData, MAXSOCKS)) == 0) {
    Error("Unable to add any ports to the connect sentry. Aborting.");
    return (ERROR);
  }

  for (count = 0; count < connectionDataSize; count++) {
    nfds = max(nfds, connectionData[count].sockfd);
  }

  Log("PortSentry is now active and listening.");

  while (g_isRunning == TRUE) {
    FD_ZERO(&selectFds);

    for (count = 0; count < connectionDataSize; count++) {
      FD_SET(connectionData[count].sockfd, &selectFds);
    }

    result = select(nfds + 1, &selectFds, NULL, NULL, (struct timeval *)NULL);

    if (result < 0) {
      if (errno == EINTR) {
        continue;
      }
      Error("Select call failed: %s. Shutting down.", ErrnoString(err, sizeof(err)));
      return (ERROR);
    } else if (result == 0) {
      Debug("Select timeout");
      continue;
    }

    for (count = 0; count < connectionDataSize; count++) {
      if (FD_ISSET(connectionData[count].sockfd, &selectFds) == 0) {
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

      RunSentry(connectionData[count].protocol, connectionData[count].port, connectionData[count].sockfd, &client, NULL, NULL, &incomingSockfd);
    }
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

  return TRUE;
}

static int SetConnectionData(struct ConnectionData *cd, const int cdSize, const int cdIdx, const uint16_t port, const int proto) {
  assert(proto == IPPROTO_TCP || proto == IPPROTO_UDP);

  if (port == 0) {
    Crash(EXIT_FAILURE, "Invalid port 0, unable to listen. Remove from %s", (proto == IPPROTO_TCP ? "TCP_PORTS" : "UDP_PORTS"));
    return ERROR;
  }

  if (cdIdx >= cdSize) {
    Crash(EXIT_FAILURE, "Too many ports specified in %s. Reduce the number of ports to monitor to max %d", (proto == IPPROTO_TCP ? "TCP_PORTS" : "UDP_PORTS"), MAXSOCKS);
    return ERROR;
  }

  memset(&cd[cdIdx], 0, sizeof(struct ConnectionData));

  cd[cdIdx].sockfd = -1;
  cd[cdIdx].port = port;
  cd[cdIdx].protocol = proto;

  Log("Going into listen mode on %s port: %d", (proto == IPPROTO_TCP ? "TCP" : "UDP"), port);

  if ((cd[cdIdx].sockfd = SetupPort(port, proto)) < 0) {
    Error("Could not bind %s socket on port %d. Attempting to continue", GetProtocolString(proto), port);
    return FALSE;
  }

  return TRUE;
}

int ConstructConnectionData(struct ConnectionData *cd, const int cdSize) {
  int i, j, cdIdx = 0;

  if (cdSize <= 0) {
    Error("ConstructConnectionData() called with invalid size. Aborting.");
    return 0;
  }

  for (i = 0; i < configData.tcpPortsLength; i++) {
    if (IsPortSingle(&configData.tcpPorts[i])) {
      if (SetConnectionData(cd, cdSize, cdIdx, configData.tcpPorts[i].single, IPPROTO_TCP) == TRUE) {
        cdIdx++;
      }
    } else {
      for (j = configData.tcpPorts[i].range.start; j <= configData.tcpPorts[i].range.end; j++) {
        if (SetConnectionData(cd, cdSize, cdIdx, j, IPPROTO_TCP) == TRUE) {
          cdIdx++;
        }
      }
    }
  }

  for (i = 0; i < configData.udpPortsLength; i++) {
    if (IsPortSingle(&configData.udpPorts[i])) {
      if (SetConnectionData(cd, cdSize, cdIdx, configData.udpPorts[i].single, IPPROTO_UDP) == TRUE) {
        cdIdx++;
      }
    } else {
      for (j = configData.udpPorts[i].range.start; j <= configData.udpPorts[i].range.end; j++) {
        if (SetConnectionData(cd, cdSize, cdIdx, j, IPPROTO_UDP) == TRUE) {
          cdIdx++;
        }
      }
    }
  }

  return cdIdx;
}
