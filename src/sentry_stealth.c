// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
// SPDX-FileContributor: Craig Rowland
//
// SPDX-License-Identifier: CPL-1.0

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

#include "config_data.h"
#include "io.h"
#include "portsentry.h"
#include "sentry_stealth.h"
#include "util.h"

extern uint8_t g_isRunning;

static int OpenRAWTCPSocket(void);
static int OpenRAWUDPSocket(void);
static int OpenRAWTCPSocket6(void);
static int OpenRAWUDPSocket6(void);
static int PacketRead(int socket, char *buffer, int bufferLen);

int PortSentryStealthMode(void) {
  int status = EXIT_FAILURE;
  int count, nfds, result;
  int tcpSockfd = -1, udpSockfd = -1;
  char packetBuffer[IP_MAXPACKET], err[ERRNOMAXBUF];
  struct pollfd fds[4];
  struct PacketInfo pi;

  assert(configData.sentryMode == SENTRY_MODE_STEALTH);

  nfds = 0;
  if (configData.tcpPortsLength > 0) {
    if ((tcpSockfd = OpenRAWTCPSocket()) == ERROR) {
      goto exit;
    }

    fds[nfds].fd = tcpSockfd;
    fds[nfds].events = POLLIN;
    nfds++;

    if ((tcpSockfd = OpenRAWTCPSocket6()) == ERROR) {
      goto exit;
    }

    fds[nfds].fd = tcpSockfd;
    fds[nfds].events = POLLIN;
    nfds++;
  }

  if (configData.udpPortsLength > 0) {
    if ((udpSockfd = OpenRAWUDPSocket()) == ERROR) {
      goto exit;
    }

    fds[nfds].fd = udpSockfd;
    fds[nfds].events = POLLIN;
    nfds++;

    if ((udpSockfd = OpenRAWUDPSocket6()) == ERROR) {
      goto exit;
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
      goto exit;
    } else if (result == 0) {
      Error("poll() timed out. Aborting.");
      goto exit;
    }

    for (count = 0; count < nfds; count++) {
      if (fds[count].revents != POLLIN) {
        continue;
      }

      if (PacketRead(fds[count].fd, packetBuffer, IP_MAXPACKET) != TRUE)
        continue;

      ClearPacketInfo(&pi);
      pi.packet = (unsigned char *)packetBuffer;
      pi.packetLength = IP_MAXPACKET;
      if (SetPacketInfo(&pi) != TRUE) {
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

      if (IsPortInUse(pi.port, pi.protocol) != FALSE) {
        continue;
      }

      RunSentry(&pi);
    }
  }

  status = EXIT_SUCCESS;

exit:

  if (tcpSockfd != -1)
    close(tcpSockfd);

  if (udpSockfd != -1)
    close(udpSockfd);

  return status;
}

static int OpenRAWTCPSocket(void) {
  int sockfd;
  char err[ERRNOMAXBUF];

  Debug("OpenRAWTCPSocket: opening RAW TCP socket");

  if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
    Error("Unable to create socket: %s", ErrnoString(err, sizeof(err)));
    return ERROR;
  }

  return sockfd;
}

static int OpenRAWUDPSocket(void) {
  int sockfd;
  char err[ERRNOMAXBUF];

  Debug("OpenRAWUDPSocket: opening RAW UDP socket");

  if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
    Error("Unable to create socket: %s", ErrnoString(err, sizeof(err)));
    return ERROR;
  }

  return sockfd;
}

static int OpenRAWTCPSocket6(void) {
  int sockfd;
  char err[ERRNOMAXBUF];

  Debug("OpenRAWTCPSocket: opening RAW IPv6 TCP socket");

  if ((sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP)) < 0) {
    Error("Unable to create socket: %s", ErrnoString(err, sizeof(err)));
    return ERROR;
  }

  return sockfd;
}

static int OpenRAWUDPSocket6(void) {
  int sockfd;
  char err[ERRNOMAXBUF];

  Debug("OpenRAWUDPSocket: opening RAW IPv6 UDP socket");

  if ((sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP)) < 0) {
    Error("Unable to create socket: %s", ErrnoString(err, sizeof(err)));
    return ERROR;
  }

  return sockfd;
}

static int PacketRead(int socket, char *buffer, int bufferLen) {
  char err[ERRNOMAXBUF];
  ssize_t result;

  if ((result = read(socket, buffer, bufferLen)) == -1) {
    Error("Could not read from socket %d: %s. Aborting", socket, ErrnoString(err, sizeof(err)));
    return ERROR;
  } else if (result < (ssize_t)sizeof(struct ip)) {
    Error("Packet read from socket %d is too small (%lu bytes). Aborting", socket, result);
    return ERROR;
  }

  return TRUE;
}
