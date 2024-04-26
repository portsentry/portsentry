/************************************************************************/
/*                                                                      */
/* PortSentry                                                           */
/*                                                                      */
/* This software is Copyright(c) 1997-2003 Craig Rowland                */
/*                                                                      */
/* This software is covered under the Common Public License v1.0        */
/* See the enclosed LICENSE file for more information.                  */
/*                                                                      */
/* Created: 10-12-1997                                                  */
/* Modified: 05-23-2003                                                 */
/*                                                                      */
/* Send all changes/modifications/bugfixes to;                          */
/* craigrowland at users dot sourceforge dot net                        */
/*                                                                      */
/* $Id: portsentry_util.c,v 1.11 2003/05/23 17:41:59 crowland Exp crowland $ */
/************************************************************************/
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "config_data.h"
#include "connection_data.h"
#include "io.h"
#include "portsentry.h"
#include "state_machine.h"
#include "util.h"

/* A replacement for strncpy that covers mistakes a little better */
char *SafeStrncpy(char *dest, const char *src, size_t size) {
  if (!dest) {
    dest = NULL;
    return (NULL);
  } else if (size < 1) {
    dest = NULL;
    return (NULL);
  }

  memset(dest, '\0', size);
  strncpy(dest, src, size - 1);

  return (dest);
}

/************************************************************************/
/* Generic safety function to process an IP address and remove anything */
/* that is:                                                             */
/* 1) Not a number.                                                     */
/* 2) Not a period.                                                     */
/* 3) Greater than IPMAXBUF (15)                                        */
/************************************************************************/
char *CleanIpAddr(char *cleanAddr, const char *dirtyAddr) {
  int count = 0, maxdot = 0, maxoctet = 0;

  Debug("cleanAddr: Cleaning Ip address: %s", dirtyAddr);

  memset(cleanAddr, '\0', IPMAXBUF);
  /* dirtyAddr must be valid */
  if (dirtyAddr == NULL)
    return (cleanAddr);

  for (count = 0; count < IPMAXBUF - 1; count++) {
    if (isdigit(dirtyAddr[count])) {
      if (++maxoctet > 3) {
        cleanAddr[count] = '\0';
        break;
      }
      cleanAddr[count] = dirtyAddr[count];
    } else if (dirtyAddr[count] == '.') {
      if (++maxdot > 3) {
        cleanAddr[count] = '\0';
        break;
      }
      maxoctet = 0;
      cleanAddr[count] = dirtyAddr[count];
    } else {
      cleanAddr[count] = '\0';
      break;
    }
  }

  Debug("cleanAddr: Cleaned IpAddress: %s Dirty IpAddress: %s", cleanAddr, dirtyAddr);

  return (cleanAddr);
}

void ResolveAddr(const struct sockaddr *saddr, const socklen_t saddrLen, char *resolvedHost, const int resolvedHostSize) {
  assert(saddr != NULL && saddrLen > 0);

  if (getnameinfo(saddr, saddrLen, resolvedHost, resolvedHostSize, NULL, 0, NI_NUMERICHOST) != 0) {
    snprintf(resolvedHost, resolvedHostSize, "<unknown>");
  }

  Debug("ResolveAddr: Resolved: %s", resolvedHost);
}

long getLong(char *buffer) {
  long value = 0;
  char *endptr = NULL;

  if (buffer == NULL)
    return ERROR;

  value = strtol(buffer, &endptr, 10);

  if (value == LONG_MIN || value == LONG_MAX)
    return ERROR;

  if (endptr == buffer)
    return ERROR;

  return value;
}

int DisposeTarget(char *target, int port, int protocol) {
  int status = TRUE;
  int blockProto;

  if (protocol == IPPROTO_TCP) {
    blockProto = configData.blockTCP;
  } else if (protocol == IPPROTO_UDP) {
    blockProto = configData.blockUDP;
  } else {
    Error("DisposeTarget: Unknown protocol: %d", protocol);
    return (FALSE);
  }

  if (blockProto == 0) {
    status = TRUE;
  } else if (blockProto == 1) {
    Debug("DisposeTarget: disposing of host %s on port %d with option: %d (%s)", target, port, configData.blockTCP, (protocol == IPPROTO_TCP) ? "tcp" : "udp");
    Debug("DisposeTarget: killRunCmd: %s", configData.killRunCmd);
    Debug("DisposeTarget: runCmdFirst: %d", configData.runCmdFirst);
    Debug("DisposeTarget: killHostsDeny: %s", configData.killHostsDeny);
    Debug("DisposeTarget: killRoute: %s (%lu)", configData.killRoute, strlen(configData.killRoute));

    if (configData.runCmdFirst == TRUE) {
      status = KillRunCmd(target, port, configData.killRunCmd, GetSentryModeString(configData.sentryMode));
    }

    // FIXME: status could very well be overwritten with a logically incorrect value
    status = KillHostsDeny(target, port, configData.killHostsDeny, GetSentryModeString(configData.sentryMode));
    status = KillRoute(target, port, configData.killRoute, GetSentryModeString(configData.sentryMode));

    if (configData.runCmdFirst == FALSE) {
      status = KillRunCmd(target, port, configData.killRunCmd, GetSentryModeString(configData.sentryMode));
    }
  } else if (blockProto == 2) {
    status = KillRunCmd(target, port, configData.killRunCmd, GetSentryModeString(configData.sentryMode));
  }

  if (status != TRUE)
    status = FALSE;

  return (status);
}

const char *GetProtocolString(int proto) {
  switch (proto) {
  case IPPROTO_TCP:
    return ("TCP");
    break;
  case IPPROTO_UDP:
    return ("UDP");
    break;
  default:
    return ("UNKNOWN");
    break;
  }
}

int SetupPort(uint16_t port, int proto) {
  char err[ERRNOMAXBUF];
  int sock;

  assert(proto == IPPROTO_TCP || proto == IPPROTO_UDP);

  if (proto == IPPROTO_TCP) {
    sock = OpenTCPSocket();
  } else if (proto == IPPROTO_UDP) {
    sock = OpenUDPSocket();
  } else {
    Error("adminalert: invalid protocol %d passed to IsPortInUse on port %d", proto, port);
    return -1;
  }

  if (sock == ERROR) {
    Error("adminalert: could not open %s socket: %s", GetProtocolString(proto), ErrnoString(err, sizeof(err)));
    return -1;
  }

  if (BindSocket(sock, port, proto) == ERROR) {
    Debug("SetupPort: %s port %d failed, in use", GetProtocolString(proto), port);
    close(sock);
    return -2;
  }

  return sock;
}

int IsPortInUse(uint16_t port, int proto) {
  int sock;

  sock = SetupPort(port, proto);

  if (sock == -1) {
    return ERROR;
  } else if (sock == -2) {
    return TRUE;
  } else {
    close(sock);
    return FALSE;
  }
}

/* This takes a tcp packet and reports what type of scan it is */
char *ReportPacketType(struct tcphdr *tcpPkt) {
  static char packetDesc[MAXBUF];
  static char *packetDescPtr = packetDesc;

  if (tcpPkt->th_flags == 0)
    snprintf(packetDesc, MAXBUF, "TCP NULL scan");
  else if (((tcpPkt->th_flags & TH_FIN) != 0) && ((tcpPkt->th_flags & TH_URG) != 0) && ((tcpPkt->th_flags & TH_PUSH) != 0))
    snprintf(packetDesc, MAXBUF, "TCP XMAS scan");
  else if (((tcpPkt->th_flags & TH_FIN) != 0) && ((tcpPkt->th_flags & TH_SYN) == 0) && ((tcpPkt->th_flags & TH_ACK) == 0) &&
           ((tcpPkt->th_flags & TH_PUSH) == 0) && ((tcpPkt->th_flags & TH_RST) == 0) && ((tcpPkt->th_flags & TH_URG) == 0))
    snprintf(packetDesc, MAXBUF, "TCP FIN scan");
  else if (((tcpPkt->th_flags & TH_SYN) != 0) && ((tcpPkt->th_flags & TH_FIN) == 0) && ((tcpPkt->th_flags & TH_ACK) == 0) &&
           ((tcpPkt->th_flags & TH_PUSH) == 0) && ((tcpPkt->th_flags & TH_RST) == 0) && ((tcpPkt->th_flags & TH_URG) == 0))
    snprintf(packetDesc, MAXBUF, "TCP SYN/Normal scan");
  else
    snprintf(packetDesc, MAXBUF,
             "Unknown Type: TCP Packet Flags: SYN: %d FIN: %d ACK: %d PSH: %d URG: %d RST: %d",
             tcpPkt->th_flags & TH_SYN ? 1 : 0, tcpPkt->th_flags & TH_FIN ? 1 : 0, tcpPkt->th_flags & TH_ACK ? 1 : 0,
             tcpPkt->th_flags & TH_PUSH ? 1 : 0, tcpPkt->th_flags & TH_URG ? 1 : 0, tcpPkt->th_flags & TH_RST ? 1 : 0);
  return (packetDescPtr);
}

char *ErrnoString(char *buf, const size_t buflen) {
  char *p;
#if ((_POSIX_C_SOURCE >= 200112L) && !_GNU_SOURCE) || defined(BSD)
  strerror_r(errno, buf, buflen);
  p = buf;
#else
  p = strerror_r(errno, buf, buflen);
#endif
  return p;
}

int RunSentry(struct ConnectionData *cd, const struct sockaddr_in *client, struct ip *ip, struct tcphdr *tcp, int *tcpAcceptSocket) {
  int result;
  char target[IPMAXBUF], resolvedHost[NI_MAXHOST];

  if (configData.sentryMode == SENTRY_MODE_TCP && tcpAcceptSocket == NULL) {
    Error("RunSentry: tcpAcceptSocket is NULL in connect mode");
    return FALSE;
  }

  SafeStrncpy(target, inet_ntoa(client->sin_addr), IPMAXBUF);

  if (configData.sentryMode == SENTRY_MODE_TCP || configData.sentryMode == SENTRY_MODE_UDP) {
    Debug("RunSentry connect mode: accepted %s connection from: %s", (cd->protocol == IPPROTO_TCP) ? "TCP" : "UDP", target);
  }

  if ((result = NeverBlock(target, configData.ignoreFile)) == ERROR) {
    Error("Unable to open ignore file %s. Continuing without it", configData.ignoreFile);
    result = FALSE;
  } else if (result == TRUE) {
    Log("attackalert: Host: %s found in ignore file %s, aborting actions", target, configData.ignoreFile);
    return FALSE;
  }

  if (CheckStateEngine(target) != TRUE) {
    return FALSE;
  }

  if (configData.sentryMode == SENTRY_MODE_TCP) {
    XmitBannerIfConfigured(IPPROTO_TCP, *tcpAcceptSocket, NULL);
    close(*tcpAcceptSocket);
    *tcpAcceptSocket = -1;
  } else if (configData.sentryMode == SENTRY_MODE_UDP) {
    XmitBannerIfConfigured(IPPROTO_UDP, cd->sockfd, client);
  }

  if (configData.resolveHost == TRUE) {
    ResolveAddr((struct sockaddr *)client, sizeof(struct sockaddr_in), resolvedHost, NI_MAXHOST);
  } else {
    snprintf(resolvedHost, NI_MAXHOST, "%s", target);
  }

  if (configData.sentryMode == SENTRY_MODE_TCP || configData.sentryMode == SENTRY_MODE_UDP) {
    Log("attackalert: Connect from host: %s/%s to %s port: %d", resolvedHost, target, (cd->protocol == IPPROTO_TCP) ? "TCP" : "UDP", cd->port);
  } else {
    if (cd->protocol == IPPROTO_TCP) {
      Log("attackalert: %s from host: %s/%s to TCP port: %d", ReportPacketType(tcp), resolvedHost, target, cd->port);
    } else {
      Log("attackalert: UDP scan from host: %s/%s to UDP port: %d", resolvedHost, target, cd->port);
    }

    if (ip->ip_hl > 5)
      Log("attackalert: Packet from host: %s/%s to %s port: %d has IP options set (detection avoidance technique).", resolvedHost, target, GetProtocolString(cd->protocol), cd->port);
  }

  // If in log-only mode, don't run any of the blocking code
  if ((configData.blockTCP == 0 && (configData.sentryMode == SENTRY_MODE_TCP || configData.sentryMode == SENTRY_MODE_STCP || configData.sentryMode == SENTRY_MODE_ATCP)) ||
      (configData.blockUDP == 0 && (configData.sentryMode == SENTRY_MODE_UDP || configData.sentryMode == SENTRY_MODE_SUDP || configData.sentryMode == SENTRY_MODE_AUDP))) {
    return TRUE;
  }

  if (IsBlocked(target, configData.blockedFile) == FALSE) {
    if ((result = DisposeTarget(target, cd->port, cd->protocol)) != TRUE) {
      Error("attackalert: Error during target dispose %s/%s!", resolvedHost, target);
    } else {
      WriteBlocked(target, resolvedHost, cd->port, configData.blockedFile, configData.historyFile, GetProtocolString(cd->protocol));
    }
  } else {
    Log("attackalert: Host: %s/%s is already blocked Ignoring", resolvedHost, target);
  }

  return TRUE;
}

int SetConvenienceData(struct ConnectionData *connectionData, const int connectionDataSize, const struct ip *ip, const void *p, struct sockaddr_in *client, struct ConnectionData **cd, struct tcphdr **tcp, struct udphdr **udp) {
  memset(client, 0, sizeof(struct sockaddr_in));
  *tcp = NULL;
  *udp = NULL;
  *cd = NULL;

  client->sin_family = AF_INET;
  client->sin_addr.s_addr = ip->ip_src.s_addr;
  if (ip->ip_p == IPPROTO_TCP) {
    *tcp = (struct tcphdr *)p;
    if (configData.sentryMode == SENTRY_MODE_ATCP) {
      if (ntohs((*tcp)->th_dport) > configData.tcpAdvancedPort)
        return FALSE;

      /* In advanced mode, the connection data list contains ports which should be ignored- So,
       * finding a match means we should not process. */
      if (((*cd) = FindConnectionData(connectionData, connectionDataSize, ntohs((*tcp)->th_dport), IPPROTO_TCP)) != NULL)
        return FALSE;
    } else if (configData.sentryMode == SENTRY_MODE_STCP) {
      /* Find the port which should trigger the sentry */
      if (((*cd) = FindConnectionData(connectionData, connectionDataSize, ntohs((*tcp)->th_dport), IPPROTO_TCP)) == NULL)
        return FALSE;
    } else {
      Error("adminalert: Unknown sentry mode %s detected. Aborting.\n", GetSentryModeString(configData.sentryMode));
      Exit(EXIT_FAILURE);
    }
    client->sin_port = (*tcp)->th_dport;
  } else if (ip->ip_p == IPPROTO_UDP) {
    *udp = (struct udphdr *)p;
    if (configData.sentryMode == SENTRY_MODE_AUDP) {
      if (ntohs((*udp)->uh_dport) > configData.udpAdvancedPort)
        return FALSE;

      /* In advanced mode, the connection data list contains ports which should be ignored- So,
       * finding a match means we should not process. */
      if (((*cd) = FindConnectionData(connectionData, connectionDataSize, ntohs((*udp)->uh_dport), IPPROTO_UDP)) != NULL)
        return FALSE;
    } else if (configData.sentryMode == SENTRY_MODE_SUDP) {
      /* Find the port which should trigger the sentry */
      if (((*cd) = FindConnectionData(connectionData, connectionDataSize, ntohs((*udp)->uh_dport), IPPROTO_UDP)) == NULL)
        return FALSE;
    } else {
      Error("adminalert: Unknown sentry mode %s detected. Aborting.\n", GetSentryModeString(configData.sentryMode));
      Exit(EXIT_FAILURE);
    }
    client->sin_port = (*udp)->uh_dport;
  } else {
    Error("adminalert: Unknown protocol %d detected. Attempting to continue.", ip->ip_p);
    return FALSE;
  }

  return TRUE;
}

int ntohstr(char *buf, const int bufSize, const uint32_t addr) {
  struct in_addr saddr;

  if (bufSize < 16)
    return FALSE;

  saddr.s_addr = addr;
  snprintf(buf, bufSize, "%s", inet_ntoa(saddr));

  return TRUE;
}
