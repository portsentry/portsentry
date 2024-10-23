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
#include <sys/resource.h>

#include "config_data.h"
#include "sentry_connect.h"
#include "io.h"
#include "util.h"
#include "portsentry.h"
#include "packet_info.h"
#include "sentry.h"

extern uint8_t g_isRunning;

struct ConnectionData {
  uint16_t port;
  int family;
  int protocol;
  int sockfd;
};

static int SetConnectionData(struct ConnectionData **cd, const int cdIdx, const uint16_t port, const int proto, int family);
static int ConstructConnectionData(struct ConnectionData **cd);
static void FreeConnectionData(struct ConnectionData **cd, int *cdSize);
static int PrepareNoFds(void);

int PortSentryConnectMode(void) {
  int status = EXIT_FAILURE;
  struct sockaddr_in client4;
  struct sockaddr_in6 client6;
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

  if (PrepareNoFds() == FALSE) {
    return EXIT_FAILURE;
  }

  if ((connectionDataSize = ConstructConnectionData(&connectionData)) == 0) {
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

      if (connectionData[count].family == AF_INET) {
        clientLength = sizeof(client4);
      } else {
        clientLength = sizeof(client6);
      }

      if (connectionData[count].protocol == IPPROTO_TCP) {
        if (connectionData[count].family == AF_INET) {
          incomingSockfd = accept(connectionData[count].sockfd, (struct sockaddr *)&client4, &clientLength);
        } else {
          incomingSockfd = accept(connectionData[count].sockfd, (struct sockaddr *)&client6, &clientLength);
        }

        if (incomingSockfd == -1) {
          Log("attackalert: Possible stealth scan from unknown host to TCP port: %d (accept failed %d: %s)", connectionData[count].port, errno, ErrnoString(err, sizeof(err)));
          continue;
        }
      } else if (connectionData[count].protocol == IPPROTO_UDP) {
        if (connectionData[count].family == AF_INET) {
          result = recvfrom(connectionData[count].sockfd, &tmp, 1, 0, (struct sockaddr *)&client4, &clientLength);
        } else {
          result = recvfrom(connectionData[count].sockfd, &tmp, 1, 0, (struct sockaddr *)&client6, &clientLength);
        }
        if (result == -1) {
          Error("Could not receive incoming data on UDP port: %d: %s", connectionData[count].port, ErrnoString(err, sizeof(err)));
          continue;
        }
      }

      ClearPacketInfo(&pi);
      SetPacketInfoFromConnectData(&pi, connectionData[count].port, connectionData[count].family, connectionData[count].protocol, connectionData[count].sockfd, incomingSockfd, &client4, &client6);

      Debug("RunSentry connect mode: accepted %s connection from: %s", GetProtocolString(pi.protocol), pi.saddr);

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

static int SetConnectionData(struct ConnectionData **cd, const int cdIdx, const uint16_t port, const int proto, int family) {
  int sockfd;
  assert(proto == IPPROTO_TCP || proto == IPPROTO_UDP);
  assert(family == AF_INET || family == AF_INET6);

  if (port == 0) {
    Error("Invalid port 0 defined in %s, unable to listen. Skipping", (proto == IPPROTO_TCP ? "TCP_PORTS" : "UDP_PORTS"));
    return FALSE;
  }

  Log("Listen on %s: %s port: %d", (family == AF_INET) ? "AF_INET" : "AF_INET6", (proto == IPPROTO_TCP ? "TCP" : "UDP"), port);

  if ((sockfd = SetupPort(family, port, proto)) < 0) {
    if (errno == EMFILE) {
      Error("Unable to open all ports (TCP_PORTS/UDP_PORTS) specified in the configuration file. Reduce the number of ports to listen to or increase the max number of allowed file descriptors open by a process or use stealth mode instead");
      return ERROR;
    }
    Error("Could not bind %s socket on port %d. Attempting to continue", GetProtocolString(proto), port);
    return FALSE;
  }

  if ((*cd = realloc(*cd, sizeof(struct ConnectionData) * (cdIdx + 1))) == NULL) {
    Crash(EXIT_FAILURE, "Unable to allocate memory for connection data");
  }

  memset(&(*cd)[cdIdx], 0, sizeof(struct ConnectionData));

  (*cd)[cdIdx].port = port;
  (*cd)[cdIdx].family = family;
  (*cd)[cdIdx].protocol = proto;
  (*cd)[cdIdx].sockfd = sockfd;

  return TRUE;
}

int ConstructConnectionData(struct ConnectionData **cd) {
  int i, j, cdIdx = 0, ret;

  /* OpenBSD doesn't support IPv4/IPv6 dual-stack sockets,
   * so we need to manually open an IPv4 socket */
  for (i = 0; i < configData.tcpPortsLength; i++) {
    if (IsPortSingle(&configData.tcpPorts[i])) {
      ret = SetConnectionData(cd, cdIdx, configData.tcpPorts[i].single, IPPROTO_TCP, AF_INET6);
      if (ret == TRUE) {
        cdIdx++;
      } else if (ret == ERROR) {
        goto err;
      }
#ifdef __OpenBSD__
      ret = SetConnectionData(cd, cdIdx, configData.tcpPorts[i].single, IPPROTO_TCP, AF_INET);
      if (ret == TRUE) {
        cdIdx++;
      } else if (ret == ERROR) {
        goto err;
      }
#endif
    } else {
      for (j = configData.tcpPorts[i].range.start; j <= configData.tcpPorts[i].range.end; j++) {
        ret = SetConnectionData(cd, cdIdx, j, IPPROTO_TCP, AF_INET6);
        if (ret == TRUE) {
          cdIdx++;
        } else if (ret == ERROR) {
          goto err;
        }
#ifdef __OpenBSD__
        ret = SetConnectionData(cd, cdIdx, j, IPPROTO_TCP, AF_INET);
        if (ret == TRUE) {
          cdIdx++;
        } else if (ret == ERROR) {
          goto err;
        }
#endif
      }
    }
  }

  for (i = 0; i < configData.udpPortsLength; i++) {
    if (IsPortSingle(&configData.udpPorts[i])) {
      ret = SetConnectionData(cd, cdIdx, configData.udpPorts[i].single, IPPROTO_UDP, AF_INET6);
      if (ret == TRUE) {
        cdIdx++;
      } else if (ret == ERROR) {
        goto err;
      }
#ifdef __OpenBSD__
      ret = SetConnectionData(cd, cdIdx, configData.udpPorts[i].single, IPPROTO_UDP, AF_INET);
      if (ret == TRUE) {
        cdIdx++;
      } else if (ret == ERROR) {
        goto err;
      }
#endif
    } else {
      for (j = configData.udpPorts[i].range.start; j <= configData.udpPorts[i].range.end; j++) {
        ret = SetConnectionData(cd, cdIdx, j, IPPROTO_UDP, AF_INET6);
        if (ret == TRUE) {
          cdIdx++;
        } else if (ret == ERROR) {
          goto err;
        }
#ifdef __OpenBSD__
        ret = SetConnectionData(cd, cdIdx, j, IPPROTO_UDP, AF_INET);
        if (ret == TRUE) {
          cdIdx++;
        } else if (ret == ERROR) {
          goto err;
        }
#endif
      }
    }
  }

  goto exit;

err:
  FreeConnectionData(cd, &cdIdx);
  cdIdx = 0;

exit:

  return cdIdx;
}

void FreeConnectionData(struct ConnectionData **cd, int *cdSize) {
  if (*cd != NULL) {
    free(*cd);
    *cd = NULL;
  }

  *cdSize = 0;
}

static int PrepareNoFds(void) {
  uint32_t noFds;
  struct rlimit rlim;
  char err[ERRNOMAXBUF];

  noFds = GetNoPorts(configData.tcpPorts, configData.tcpPortsLength);
  noFds += GetNoPorts(configData.udpPorts, configData.udpPortsLength);
#ifdef __OpenBSD__
  /* OpenBSD doesn't support IPv4/IPv6 dual-stack sockets,
   * so we need to double the number of file descriptors */
  noFds *= 2;
#endif

  /* FIXME: Should write a portable function to get number of fd's currently open
   * in order to get an accurate count but 4 should be a fairly good guess:
   * stdin, stdout, stderr, CWD */
  noFds += 4;

  if (getrlimit(RLIMIT_NOFILE, &rlim) == -1) {
    Error("getrlimit RLIMIT_NOFILE failed: %s", strerror(errno));
    return FALSE;
  }

  if (rlim.rlim_cur >= noFds) {
    return TRUE;
  }

#ifdef __OpenBSD__
  Debug("Setting RLIMIT_NOFILE to %d (from cur: %llu max: %llu)", noFds, rlim.rlim_cur, rlim.rlim_max);
#else
  Debug("Setting RLIMIT_NOFILE to %d (from cur: %lu max: %lu)", noFds, rlim.rlim_cur, rlim.rlim_max);
#endif
  rlim.rlim_cur = noFds;
  rlim.rlim_max = noFds;
  if (setrlimit(RLIMIT_NOFILE, &rlim) == -1) {
    Error("setrlimit RLIMIT_NOFILE %d failed: %s", noFds, ErrnoString(err, sizeof(err)));
    return FALSE;
  }

  if (getrlimit(RLIMIT_NOFILE, &rlim) == -1) {
    Error("Check getrlimit RLIMIT_NOFILE after set failed: %s", strerror(errno));
    return FALSE;
  }

  if (rlim.rlim_cur >= noFds) {
    return TRUE;
  }

  Error("Unable to increase the number of allowed open file descriptors. Needed fd's: %d, "
#ifdef __OpenBSD__
        "soft limit: %llu, hard limit: %llu."
#else
        "soft limit: %lu, hard limit: %lu."
#endif

        "Reduce the number of ports to listen to or increase the max number of allowed file descriptors open by a process or use stealth mode instead",
        noFds, rlim.rlim_cur, rlim.rlim_max);

  return FALSE;
}
