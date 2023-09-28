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

#include "config_data.h"
#include "io.h"
#include "portsentry.h"
#include <netinet/in.h>

/* A replacement for strncpy that covers mistakes a little better */
char *SafeStrncpy(char *dest, const char *src, size_t size) {
  if (!dest) {
    dest = NULL;
    return (NULL);
  } else if (size < 1) {
    dest = NULL;
    return (NULL);
  }

  /* Null terminate string. Why the hell strncpy doesn't do this */
  /* for you is mystery to me. God I hate C. */
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

/************************************************************************/
/* Generic safety function to process an unresolved address and remove  */
/* anything that is:                                                    */
/* 1) Not a number.                                                     */
/* 2) Not a period.                                                     */
/* 3) Greater than DNSMAXBUF (255)                                      */
/* 4) Not a legal DNS character (a-z, A-Z, 0-9, - )			*/
/* 									*/
/* XXX THIS FUNCTION IS NOT COMPLETE 					*/
/************************************************************************/
int CleanAndResolve(char *resolvedHost, const char *unresolvedHost) {
  struct hostent *hostPtr = NULL;
  struct in_addr addr;

  Debug("CleanAndResolv: Resolving address: %s", unresolvedHost);

  memset(resolvedHost, '\0', DNSMAXBUF);
  /* unresolvedHost must be valid */
  if (unresolvedHost == NULL)
    return (ERROR);

  /* Not a valid address */
  if ((inet_aton(unresolvedHost, &addr)) == 0)
    return (ERROR);

  hostPtr = gethostbyaddr((char *)&addr.s_addr, sizeof(addr.s_addr), AF_INET);
  if (hostPtr != NULL)
    snprintf(resolvedHost, DNSMAXBUF, "%s", hostPtr->h_name);
  else
    snprintf(resolvedHost, DNSMAXBUF, "%s", unresolvedHost);

  Debug("CleanAndResolve: Cleaned Resolved: %s Dirty Unresolved: %s", resolvedHost, unresolvedHost);

  return (TRUE);
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
    Log("DisposeTarget: ERROR: Unknown protocol: %d", protocol);
    return (FALSE);
  }

  Debug("DisposeTarget: disposing of host %s on port %d with option: %d (%s)", target, port, configData.blockTCP, (protocol == IPPROTO_TCP) ? "tcp" : "udp");
  Debug("DisposeTarget: killRunCmd: %s", configData.killRunCmd);
  Debug("DisposeTarget: runCmdFirst: %d", configData.runCmdFirst);
  Debug("DisposeTarget: killHostsDeny: %s", configData.killHostsDeny);
  Debug("DisposeTarget: killRoute: %s (%lu)", configData.killRoute, strlen(configData.killRoute));

  if (blockProto == 0) {
    Log("attackalert: Ignoring %s response per configuration file setting.", (protocol == IPPROTO_TCP) ? "TCP" : "UDP");
    status = TRUE;
  } else if (blockProto == 1) {
    if (configData.runCmdFirst == TRUE) {
      status = KillRunCmd(target, port, configData.killRunCmd, GetSentryModeString(configData.sentryMode));
    }

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
  int sock;

  assert(proto == IPPROTO_TCP || proto == IPPROTO_UDP);

  if (proto == IPPROTO_TCP) {
    sock = OpenTCPSocket();
  } else if (proto == IPPROTO_UDP) {
    sock = OpenUDPSocket();
  } else {
    Log("adminalert: ERROR: invalid protocol %d passed to IsPortInUse on port %d", proto, port);
    return -1;
  }

  if (sock == ERROR) {
    Log("adminalert: ERROR: could not open %s socket", GetProtocolString(proto));
    return -1;
  }

  if (BindSocket(sock, port) == ERROR) {
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

  if ((tcpPkt->syn == 0) && (tcpPkt->fin == 0) && (tcpPkt->ack == 0) &&
      (tcpPkt->psh == 0) && (tcpPkt->rst == 0) && (tcpPkt->urg == 0))
    snprintf(packetDesc, MAXBUF, "TCP NULL scan");
  else if ((tcpPkt->fin == 1) && (tcpPkt->urg == 1) && (tcpPkt->psh == 1))
    snprintf(packetDesc, MAXBUF, "TCP XMAS scan");
  else if ((tcpPkt->fin == 1) && (tcpPkt->syn != 1) && (tcpPkt->ack != 1) &&
           (tcpPkt->psh != 1) && (tcpPkt->rst != 1) && (tcpPkt->urg != 1))
    snprintf(packetDesc, MAXBUF, "TCP FIN scan");
  else if ((tcpPkt->syn == 1) && (tcpPkt->fin != 1) && (tcpPkt->ack != 1) &&
           (tcpPkt->psh != 1) && (tcpPkt->rst != 1) && (tcpPkt->urg != 1))
    snprintf(packetDesc, MAXBUF, "TCP SYN/Normal scan");
  else
    snprintf(packetDesc, MAXBUF,
             "Unknown Type: TCP Packet Flags: SYN: %d FIN: %d ACK: %d PSH: %d URG: %d RST: %d",
             tcpPkt->syn, tcpPkt->fin, tcpPkt->ack, tcpPkt->psh, tcpPkt->urg, tcpPkt->rst);

  return (packetDescPtr);
}
