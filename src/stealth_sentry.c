#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "config_data.h"
#include "connection_data.h"
#include "io.h"
#include "portsentry.h"
#include "state_machine.h"
#include "stealth_sentry.h"
#include "util.h"

int PortSentryStealthMode(void) {
  int count, nfds, result;
  int tcpSockfd, udpSockfd, connectionDataSize;
  char packetBuffer[IP_MAXPACKET], err[ERRNOMAXBUF];
  struct sockaddr_in client;
  struct iphdr *ip = NULL;
  struct tcphdr *tcp = NULL;
  struct udphdr *udp = NULL;
  struct pollfd fds[2];
  struct ConnectionData connectionData[MAXSOCKS];
  struct ConnectionData *cd;
  void *p;

  assert(configData.sentryMode == SENTRY_MODE_STCP || configData.sentryMode == SENTRY_MODE_SUDP);

  if ((connectionDataSize = ConstructConnectionData(connectionData, MAXSOCKS)) == 0) {
    Error("adminalert: Unable to add any ports to the connect sentry. Aborting.");
    return (ERROR);
  }

  if (connectionDataSize == 0) {
    Error("adminalert: could not bind ANY sockets. Shutting down.");
    return (ERROR);
  }

  nfds = 0;
  if (configData.sentryMode == SENTRY_MODE_STCP) {
    if ((tcpSockfd = OpenRAWTCPSocket()) == ERROR) {
      Error("adminalert: could not open RAW TCP socket: %s. Aborting.", ErrnoString(err, sizeof(err)));
      return (ERROR);
    }

    fds[nfds].fd = tcpSockfd;
    fds[nfds].events = POLLIN;
    nfds++;
  }

  if (configData.sentryMode == SENTRY_MODE_SUDP) {
    if ((udpSockfd = OpenRAWUDPSocket()) == ERROR) {
      Error("adminalert: could not open RAW UDP socket: %s. Aborting.", ErrnoString(err, sizeof(err)));
      return (ERROR);
    }

    fds[nfds].fd = udpSockfd;
    fds[nfds].events = POLLIN;
    nfds++;
  }

  Log("adminalert: PortSentry is now active and listening.");

  for (;;) {
    result = poll(fds, nfds, -1);
    if (result == -1) {
      Error("adminalert: poll() failed: %s. Aborting.", ErrnoString(err, sizeof(err)));
      return (ERROR);
    } else if (result == 0) {
      Error("adminalert: poll() timed out. Aborting.");
      return (ERROR);
    }

    for (count = 0; count < nfds; count++) {
      if (fds[count].revents != POLLIN) {
        continue;
      }

      if (PacketRead(fds[count].fd, packetBuffer, IP_MAXPACKET, &ip, &p) != TRUE)
        continue;

      memset(&client, 0, sizeof(client));
      client.sin_family = AF_INET;
      client.sin_addr.s_addr = ip->saddr;
      if (ip->protocol == IPPROTO_TCP) {
        tcp = (struct tcphdr *)p;
        if ((cd = FindConnectionData(connectionData, connectionDataSize, ntohs(tcp->dest), IPPROTO_TCP)) == NULL)
          continue;
        client.sin_port = tcp->dest;
      } else if (ip->protocol == IPPROTO_UDP) {
        udp = (struct udphdr *)p;
        if ((cd = FindConnectionData(connectionData, connectionDataSize, ntohs(udp->dest), IPPROTO_UDP)) == NULL)
          continue;
        client.sin_port = udp->dest;
      } else {
        Error("adminalert: Unknown protocol %d detected. Attempting to continue.", ip->protocol);
        continue;
      }

      // FIXME: Do we need this?
      if (cd->protocol == IPPROTO_TCP && (tcp->ack == 1 || tcp->rst == 1)) {
        continue;
      }

      if (IsPortInUse(cd->port, cd->protocol) != FALSE) {
        continue;
      }

      RunSentry(cd, &client, ip, tcp, NULL);
    }
  }

  close(tcpSockfd);
  close(udpSockfd);
}
