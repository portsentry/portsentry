#include <netinet/in.h>
#include <stddef.h>

#include "config_data.h"
#include "connect_sentry.h"
#include "connection_data.h"
#include "portsentry.h"
#include "state_machine.h"
#include "util.h"

int PortSentryConnectMode(void) {
  struct sockaddr_in client;
  socklen_t clientLength;
  int incomingSockfd, result;
  int count = 0;
  char target[IPMAXBUF];
  char resolvedHost[DNSMAXBUF];
  fd_set selectFds;
  int nfds;
  struct ConnectionData connectionData[MAXSOCKS];
  int connectionDataSize = 0;
  char tmp;

  if ((connectionDataSize = ConstructConnectionData(connectionData, MAXSOCKS)) == 0) {
    Log("adminalert: ERROR: Unable to add any ports to the connect sentry. Aborting.");
    return (ERROR);
  }

  for (count = 0; count < connectionDataSize; count++) {
    Log("adminalert: Going into listen mode on %s port: %d", (connectionData[count].protocol == IPPROTO_TCP ? "TCP" : "UDP"), connectionData[count].port);

    connectionData[count].sockfd = SetupPort(connectionData[count].port, connectionData[count].protocol);

    if (connectionData[count].sockfd == ERROR || connectionData[count].sockfd == -2) {
      connectionData[count].sockfd = ERROR;
      Log("adminalert: ERROR: could not bind %s socket: %d. Attempting to continue", GetProtocolString(connectionData[count].protocol), connectionData[count].port);
    } else {
      nfds = max(nfds, connectionData[count].sockfd);
    }
  }

  PruneConnectionDataByInvalidSockfd(connectionData, &connectionDataSize);

  if (connectionDataSize == 0) {
    Log("adminalert: ERROR: could not bind ANY sockets. Shutting down.");
    return (ERROR);
  }

  Log("adminalert: PortSentry is now active and listening.");

  for (;;) {
    FD_ZERO(&selectFds);

    for (count = 0; count < connectionDataSize; count++) {
      FD_SET(connectionData[count].sockfd, &selectFds);
    }

    result = select(MAXSOCKS, &selectFds, NULL, NULL, (struct timeval *)NULL);

    if (result < 0) {
      Log("adminalert: ERROR: select call failed. Shutting down.");
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
          Log("attackalert: Possible stealth scan from unknown host to TCP port: %d (accept failed)", connectionData[count].port);
          continue;
        }
      } else if (connectionData[count].protocol == IPPROTO_UDP) {
        if (recvfrom(connectionData[count].sockfd, &tmp, 1, 0, (struct sockaddr *)&client, &clientLength) == -1) {
          Log("adminalert: ERROR: could not accept incoming data on UDP port: %d", connectionData[count].port);
          continue;
        }
      }

      SafeStrncpy(target, inet_ntoa(client.sin_addr), IPMAXBUF);

      Debug("PortSentryConnectMode: accepted %s connection from: %s", (connectionData[count].protocol == IPPROTO_TCP) ? "TCP" : "UDP", target);

      if ((result = NeverBlock(target, configData.ignoreFile)) == ERROR) {
        Log("attackalert: ERROR: cannot open ignore file %s. Blocking host anyway.", configData.ignoreFile);
        result = FALSE;
      } else if (result == TRUE) {
        Log("attackalert: Host: %s found in ignore file %s, aborting actions", target, configData.ignoreFile);
        goto continue_loop;
      }

      if (CheckStateEngine(target) != TRUE) {
        goto continue_loop;
      }

      if (configData.sentryMode == SENTRY_MODE_TCP) {
        XmitBannerIfConfigured(IPPROTO_TCP, incomingSockfd, NULL);
      } else if (configData.sentryMode == SENTRY_MODE_UDP) {
        XmitBannerIfConfigured(IPPROTO_UDP, connectionData[count].sockfd, &client);
      }

      close(incomingSockfd);
      incomingSockfd = -1;

      if (configData.resolveHost == TRUE) {
        ResolveAddr((struct sockaddr *)&client, clientLength, resolvedHost, DNSMAXBUF);
      } else {
        snprintf(resolvedHost, DNSMAXBUF, "%s", target);
      }

      Log("attackalert: Connect from host: %s/%s to %s port: %d", resolvedHost, target, (connectionData[count].protocol == IPPROTO_TCP) ? "TCP" : "UDP", connectionData[count].port);

      if (IsBlocked(target, configData.blockedFile) == FALSE) {
        if (DisposeTarget(target, connectionData[count].port, connectionData[count].protocol) != TRUE)
          Log("attackalert: ERROR: Could not block host %s !!", target);
        else
          WriteBlocked(target, resolvedHost, connectionData[count].port, configData.blockedFile, configData.historyFile, (connectionData[count].protocol == IPPROTO_TCP) ? "TCP" : "UDP");
      } else {
        Log("attackalert: Host: %s is already blocked. Ignoring", target);
      }

    continue_loop:
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
}
