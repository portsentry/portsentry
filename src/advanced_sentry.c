#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
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
#include "util.h"

int PortSentryAdvancedStealthMode(void) {
  int result, nfds, tcpSockfd, udpSockfd, count;
  char packetBuffer[IP_MAXPACKET], err[ERRNOMAXBUF];
  struct sockaddr_in client;
  struct iphdr *ip = NULL;
  struct tcphdr *tcp = NULL;
  struct udphdr *udp = NULL;
  struct pollfd fds[2];
  struct ConnectionData connectionData[MAXSOCKS];
  struct ConnectionData *cd, tmpcd;
  int connectionDataSize;
  void *p;

  assert(configData.sentryMode == SENTRY_MODE_ATCP || configData.sentryMode == SENTRY_MODE_AUDP);

  Log("adminalert: Advanced mode will monitor first %d TCP ports and %d UDP ports", configData.tcpAdvancedPort, configData.udpAdvancedPort);

  connectionDataSize = ConstructConnectionData(connectionData, MAXSOCKS);

  if (configData.sentryMode == SENTRY_MODE_ATCP && configData.tcpAdvancedExcludePortsLength > 0) {
    for (count = 0; count < configData.tcpAdvancedExcludePortsLength; count++) {
      if (FindConnectionData(connectionData, MAXSOCKS, configData.tcpAdvancedExcludePorts[count], IPPROTO_TCP) != NULL) {
        Log("adminalert: TCP port %d is already added to exclude list.", configData.tcpAdvancedExcludePorts[count]);
        continue;
      }

      if (connectionDataSize >= MAXSOCKS) {
        Log("adminalert: ERROR: TCP port count exceeds size of ConnectionData array. Aborting.");
        return ERROR;
      }

      SetConnectionData(&connectionData[connectionDataSize], configData.tcpAdvancedExcludePorts[count], IPPROTO_TCP, FALSE);
      connectionData[connectionDataSize].portInUse = TRUE;
      Log("Advanced mode will manually exclude TCP port: %d ", configData.tcpAdvancedExcludePorts[count]);

      connectionDataSize++;
    }
  }

  if (configData.sentryMode == SENTRY_MODE_AUDP && configData.udpAdvancedExcludePortsLength > 0) {
    for (count = 0; count < configData.udpAdvancedExcludePortsLength; count++) {
      if (FindConnectionData(connectionData, MAXSOCKS, configData.udpAdvancedExcludePorts[count], IPPROTO_UDP) != NULL) {
        Log("adminalert: UDP port %d is already added to exclude list.", configData.udpAdvancedExcludePorts[count]);
        continue;
      }

      if (connectionDataSize >= MAXSOCKS) {
        Log("adminalert: ERROR: UDP port count exceeds size of ConnectionData array. Aborting.");
        return ERROR;
      }

      SetConnectionData(&connectionData[connectionDataSize], configData.udpAdvancedExcludePorts[count], IPPROTO_UDP, FALSE);
      connectionData[connectionDataSize].portInUse = TRUE;
      Log("Advanced mode will manually exclude UDP port: %d ", configData.udpAdvancedExcludePorts[count]);

      connectionDataSize++;
    }
  }

  for (count = 0; count < connectionDataSize; count++) {
    Log("adminalert: Advanced Stealth scan detection mode activated. Ignored %s port: %d", GetProtocolString(connectionData[count].protocol), connectionData[count].port);
  }

  nfds = 0;
  if (configData.sentryMode == SENTRY_MODE_ATCP) {
    if ((tcpSockfd = OpenRAWTCPSocket()) == ERROR) {
      Log("adminalert: ERROR: could not open RAW TCP socket: %s. Aborting.", ErrnoString(err, sizeof(err)));
      return (ERROR);
    }

    fds[nfds].fd = tcpSockfd;
    fds[nfds].events = POLLIN;
    nfds++;
  }

  if (configData.sentryMode == SENTRY_MODE_AUDP) {
    if ((udpSockfd = OpenRAWUDPSocket()) == ERROR) {
      Log("adminalert: ERROR: could not open RAW UDP socket: %s. Aborting.", ErrnoString(err, sizeof(err)));
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
      Log("adminalert: ERROR: poll() failed: %s. Aborting.", ErrnoString(err, sizeof(err)));
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
        if (ntohs(tcp->dest) > configData.tcpAdvancedPort)
          continue;
        if ((cd = FindConnectionData(connectionData, connectionDataSize, ntohs(tcp->dest), IPPROTO_TCP)) != NULL)
          continue;
        client.sin_port = tcp->dest;
      } else if (ip->protocol == IPPROTO_UDP) {
        udp = (struct udphdr *)p;
        if (ntohs(udp->dest) > configData.udpAdvancedPort)
          continue;
        if ((cd = FindConnectionData(connectionData, connectionDataSize, ntohs(udp->dest), IPPROTO_UDP)) != NULL)
          continue;
        client.sin_port = udp->dest;
      } else {
        Log("adminalert: ERROR: Unknown protocol %d detected. Attempting to continue.", ip->protocol);
        continue;
      }

      // Since we make heavy use of the ConnectionData structure create a temporary one to hold the current data
      SetConnectionData(&tmpcd, (ip->protocol == IPPROTO_TCP) ? ntohs(tcp->dest) : ntohs(udp->dest), ip->protocol, FALSE);
      tmpcd.portInUse = FALSE;
      cd = &tmpcd;

      // FIXME : Do we need this?
      if (cd->protocol == IPPROTO_TCP && (tcp->ack == 1 || tcp->rst == 1)) {
        continue;
      }

      if (IsPortInUse(cd->port, cd->protocol) != FALSE) {
        continue;
      }

      RunSentry(cd, &client, ip, tcp);
    }
  }

  close(tcpSockfd);
  close(udpSockfd);
}
