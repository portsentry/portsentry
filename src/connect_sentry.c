#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include "config_data.h"
#include "connect_sentry.h"
#include "connection_data.h"
#include "io.h"
#include "portsentry.h"
#include "state_machine.h"
#include "util.h"

extern uint8_t g_isRunning;

int PortSentryConnectMode(void) {
  struct sockaddr_in client;
  socklen_t clientLength;
  int incomingSockfd, result;
  int count = 0;
  char err[ERRNOMAXBUF];
  fd_set selectFds;
  int nfds;
  struct ConnectionData connectionData[MAXSOCKS];
  int connectionDataSize = 0;
  char tmp;

  assert(configData.sentryMode == SENTRY_MODE_TCP || configData.sentryMode == SENTRY_MODE_UDP);

  if ((connectionDataSize = ConstructConnectionData(connectionData, MAXSOCKS)) == 0) {
    Error("Unable to add any ports to the connect sentry. Aborting.");
    return (ERROR);
  }

  for (count = 0; count < connectionDataSize; count++) {
    Log("Going into listen mode on %s port: %d", (connectionData[count].protocol == IPPROTO_TCP ? "TCP" : "UDP"), connectionData[count].port);

    connectionData[count].sockfd = SetupPort(connectionData[count].port, connectionData[count].protocol);

    if (connectionData[count].sockfd == ERROR || connectionData[count].sockfd == -2) {
      connectionData[count].portInUse = TRUE;
      Error("Could not bind %s socket: %d. Attempting to continue", GetProtocolString(connectionData[count].protocol), connectionData[count].port);
    } else {
      nfds = max(nfds, connectionData[count].sockfd);
    }
  }

  PruneConnectionDataByInUsePorts(connectionData, &connectionDataSize);

  if (connectionDataSize == 0) {
    Error("Could not bind ANY sockets. Shutting down.");
    return (ERROR);
  }

  Log("PortSentry is now active and listening.");

  while (g_isRunning == TRUE) {
    FD_ZERO(&selectFds);

    for (count = 0; count < connectionDataSize; count++) {
      FD_SET(connectionData[count].sockfd, &selectFds);
    }

    result = select(MAXSOCKS, &selectFds, NULL, NULL, (struct timeval *)NULL);

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

      RunSentry(&connectionData[count], &client, NULL, NULL, &incomingSockfd);

      if (connectionData[count].protocol == IPPROTO_TCP && incomingSockfd > -1) {
        close(incomingSockfd);
        incomingSockfd = -1;
      }
    }
  }

  if (incomingSockfd > -1) {
    close(incomingSockfd);
  }

  CloseConnectionData(connectionData, connectionDataSize);
  return TRUE;
}
