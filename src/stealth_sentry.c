#include <arpa/inet.h>
#include <assert.h>
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
  char target[IPMAXBUF];
  char resolvedHost[DNSMAXBUF], *packetType;
  char packetBuffer[IP_MAXPACKET];
  struct sockaddr_in client;
  struct iphdr *ip;
  struct tcphdr *tcp;
  struct udphdr *udp;
  struct pollfd fds[2];
  struct ConnectionData connectionData[MAXSOCKS];
  struct ConnectionData *cd;
  void *p;

  assert(configData.sentryMode == SENTRY_MODE_STCP || configData.sentryMode == SENTRY_MODE_SUDP);

  if ((connectionDataSize = ConstructConnectionData(connectionData, MAXSOCKS)) == 0) {
    Log("adminalert: ERROR: Unable to add any ports to the connect sentry. Aborting.");
    return (ERROR);
  }

  if (connectionDataSize == 0) {
    Log("adminalert: ERROR: could not bind ANY sockets. Shutting down.");
    return (ERROR);
  }

  nfds = 0;
  if (configData.sentryMode == SENTRY_MODE_STCP) {
    if ((tcpSockfd = OpenRAWTCPSocket()) == ERROR) {
      Log("adminalert: ERROR: could not open RAW TCP socket. Aborting.");
      return (ERROR);
    }

    fds[nfds].fd = tcpSockfd;
    fds[nfds].events = POLLIN;
    nfds++;
  }

  if (configData.sentryMode == SENTRY_MODE_SUDP) {
    if ((udpSockfd = OpenRAWUDPSocket()) == ERROR) {
      Log("adminalert: ERROR: could not open RAW UDP socket. Aborting.");
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
      Log("adminalert: ERROR: poll() failed. Aborting.");
      return (ERROR);
    } else if (result == 0) {
      Log("adminalert: ERROR: poll() timed out. Aborting.");
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
        client.sin_port = tcp->th_dport;
      } else if (ip->protocol == IPPROTO_UDP) {
        udp = (struct udphdr *)p;
        if ((cd = FindConnectionData(connectionData, connectionDataSize, ntohs(udp->dest), IPPROTO_UDP)) == NULL)
          continue;
        client.sin_port = udp->uh_dport;
      }

      // FIXME: Do we need this?
      if (cd->protocol == IPPROTO_TCP && (tcp->ack == 1 || tcp->rst == 1)) {
        continue;
      }

      if (IsPortInUse(cd->port, cd->protocol) != FALSE)
        continue;

      SafeStrncpy(target, inet_ntoa(client.sin_addr), IPMAXBUF);

      if ((result = NeverBlock(target, configData.ignoreFile)) == ERROR) {
        Log("attackalert: ERROR: cannot open ignore file %s. Blocking host anyway.", configData.ignoreFile);
        result = FALSE;
      } else if (result == TRUE) {
        Log("attackalert: Host: %s found in ignore file %s, aborting actions", target, configData.ignoreFile);
        continue;
      }

      if (CheckStateEngine(target) != TRUE) {
        continue;
      }

      if (configData.resolveHost == TRUE) {
        ResolveAddr((struct sockaddr *)&client, sizeof(client), resolvedHost, DNSMAXBUF);
      } else {
        snprintf(resolvedHost, DNSMAXBUF, "%s", target);
      }

      if (cd->protocol == IPPROTO_TCP) {
        packetType = ReportPacketType(tcp);
        Log("attackalert: %s from host: %s/%s to TCP port: %d", packetType, resolvedHost, target, cd->port);
      } else {
        Log("attackalert: UDP scan from host: %s/%s to UDP port: %d", resolvedHost, target, cd->port);
      }

      if (ip->ihl > 5)
        Log("attackalert: Packet from host: %s/%s to TCP port: %d has IP options set (detection avoidance technique).", resolvedHost, target, cd->port);

      if (IsBlocked(target, configData.blockedFile) == FALSE) {
        if (DisposeTarget(target, cd->port, cd->protocol) != TRUE)
          Log("attackalert: ERROR: Could not block host %s/%s !!", resolvedHost, target);
        else
          WriteBlocked(target, resolvedHost, cd->port, configData.blockedFile, configData.historyFile, GetProtocolString(cd->protocol));
      } else {
        Log("attackalert: Host: %s/%s is already blocked Ignoring", resolvedHost, target);
      }
    }
  }

  close(tcpSockfd);
  close(udpSockfd);
}
