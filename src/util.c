// SPDX-FileCopyrightText: 2024 Craig Rowland
// SPDX-FileContributor: Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#include <stdarg.h>
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
#include <time.h>
#include <sys/time.h>

#include "config_data.h"
#include "io.h"
#include "portsentry.h"
#include "state_machine.h"
#include "util.h"
#include "packet_info.h"

#define MAX_BUF_SCAN_EVENT 1024

static void LogScanEvent(const char *target, const char *resolvedHost, int protocol, uint16_t port, struct ip *ip, struct tcphdr *tcp, int flagIgnored, int flagTriggerCountExceeded, int flagDontBlock, int flagBlockSuccessful);
static char *Realloc(char *filter, int newLen);

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

void ResolveAddr(struct PacketInfo *pi, char *resolvedHost, const int resolvedHostSize) {
  if (getnameinfo(GetClientSockaddrFromPacketInfo(pi), GetClientSockaddrLenFromPacketInfo(pi), resolvedHost, resolvedHostSize, NULL, 0, NI_NUMERICHOST) != 0) {
    Error("Unable to resolve address for %s", GetTargetOfPacketInfo(pi));
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
  int status, killRunCmdStatus, killHostsDenyStatus, killRouteStatus;
  int blockProtoConfig;

  if (protocol == IPPROTO_TCP) {
    blockProtoConfig = configData.blockTCP;
  } else if (protocol == IPPROTO_UDP) {
    blockProtoConfig = configData.blockUDP;
  } else {
    Error("DisposeTarget: Unknown protocol: %d", protocol);
    return ERROR;
  }

  if (blockProtoConfig == 0) {
    status = FALSE;  // Not an error, but we'r not blocking
  } else if (blockProtoConfig == 1) {
    Debug("DisposeTarget: disposing of host %s on port %d with option: %d (%s)", target, port, blockProtoConfig, (protocol == IPPROTO_TCP) ? "tcp" : "udp");
    Debug("DisposeTarget: killRunCmd: %s", configData.killRunCmd);
    Debug("DisposeTarget: runCmdFirst: %d", configData.runCmdFirst);
    Debug("DisposeTarget: killHostsDeny: %s", configData.killHostsDeny);
    Debug("DisposeTarget: killRoute: %s (%lu)", configData.killRoute, strlen(configData.killRoute));

    // Need to init variable to avoid uninitialized variable warning for some compilers
    killRunCmdStatus = FALSE;

    if (configData.runCmdFirst == TRUE) {
      killRunCmdStatus = KillRunCmd(target, port, configData.killRunCmd, GetSentryModeString(configData.sentryMode));
    }

    killHostsDenyStatus = KillHostsDeny(target, port, configData.killHostsDeny, GetSentryModeString(configData.sentryMode));
    killRouteStatus = KillRoute(target, port, configData.killRoute, GetSentryModeString(configData.sentryMode));

    if (configData.runCmdFirst == FALSE) {
      killRunCmdStatus = KillRunCmd(target, port, configData.killRunCmd, GetSentryModeString(configData.sentryMode));
    }

    /* It's going to be impossible to determine a cookie cutter course of action which will work for everyone, so,
     * if there are multiple actions to take, we'll consider the host "blocked" if any of the actions succeed. */
    if (killRunCmdStatus == TRUE || killHostsDenyStatus == TRUE || killRouteStatus == TRUE) {
      status = TRUE;
    } else {
      status = FALSE;
    }
  } else if (blockProtoConfig == 2) {
    status = KillRunCmd(target, port, configData.killRunCmd, GetSentryModeString(configData.sentryMode));
  } else {
    Error("DisposeTarget: Unknown blockProto: %d", blockProtoConfig);
    status = ERROR;
  }

  return status;
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
    Error("Invalid protocol %d passed to IsPortInUse on port %d", proto, port);
    return -1;
  }

  if (sock == ERROR) {
    Error("Could not open %s socket: %s", GetProtocolString(proto), ErrnoString(err, sizeof(err)));
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

void RunSentry(struct PacketInfo *pi) {
  char resolvedHost[NI_MAXHOST];
  int flagIgnored = -100, flagTriggerCountExceeded = -100, flagDontBlock = -100, flagBlockSuccessful = -100;  // -100 => unset

  // We need to assertain the target IP address textual representation ASAP since sentry_exit requires it
  if (ResolveTargetOfPacketInfo(pi) == ERROR) {
    Error("Unable to determine target IP address");
    return;
  }

  if (configData.resolveHost == TRUE) {
    ResolveAddr(pi, resolvedHost, NI_MAXHOST);
  } else {
    snprintf(resolvedHost, NI_MAXHOST, "%s", GetTargetOfPacketInfo(pi));
  }

  if (configData.sentryMode == SENTRY_MODE_CONNECT) {
    Debug("RunSentry connect mode: accepted %s connection from: %s", GetProtocolString(pi->protocol), GetTargetOfPacketInfo(pi));
  }

  if ((flagIgnored = NeverBlock(GetTargetOfPacketInfo(pi), configData.ignoreFile)) == ERROR) {
    Error("Unable to open ignore file %s. Continuing without it", configData.ignoreFile);
    flagIgnored = FALSE;
  } else if (flagIgnored == TRUE) {
    Log("attackalert: Host: %s found in ignore file %s, aborting actions", GetTargetOfPacketInfo(pi), configData.ignoreFile);
    goto sentry_exit;
  }

  if ((flagTriggerCountExceeded = CheckStateEngine(GetTargetOfPacketInfo(pi))) != TRUE) {
    goto sentry_exit;
  }

  if (configData.sentryMode == SENTRY_MODE_CONNECT && pi->protocol == IPPROTO_TCP) {
    XmitBannerIfConfigured(IPPROTO_TCP, pi->tcpAcceptSocket, NULL, 0);
  } else if (configData.sentryMode == SENTRY_MODE_CONNECT && pi->protocol == IPPROTO_UDP) {
    XmitBannerIfConfigured(IPPROTO_UDP, pi->listenSocket, GetClientSockaddrFromPacketInfo(pi), GetClientSockaddrLenFromPacketInfo(pi));
  }

  // If in log-only mode, don't run any of the blocking code
  if ((configData.blockTCP == 0 && pi->protocol == IPPROTO_TCP) ||
      (configData.blockUDP == 0 && pi->protocol == IPPROTO_UDP)) {
    flagDontBlock = TRUE;
    goto sentry_exit;
  } else {
    flagDontBlock = FALSE;
  }

  if (IsBlocked(GetTargetOfPacketInfo(pi), configData.blockedFile) == FALSE) {
    if ((flagBlockSuccessful = DisposeTarget(GetTargetOfPacketInfo(pi), pi->port, pi->protocol)) != TRUE) {
      Error("attackalert: Error during target dispose %s/%s!", resolvedHost, GetTargetOfPacketInfo(pi));
    } else {
      WriteBlocked(GetTargetOfPacketInfo(pi), resolvedHost, pi->port, configData.blockedFile, GetProtocolString(pi->protocol));
    }
  } else {
    Log("attackalert: Host: %s/%s is already blocked Ignoring", resolvedHost, GetTargetOfPacketInfo(pi));
  }

sentry_exit:
  if (pi->tcpAcceptSocket != -1) {
    close(pi->tcpAcceptSocket);
    pi->tcpAcceptSocket = -1;
  }
  LogScanEvent(GetTargetOfPacketInfo(pi), resolvedHost, pi->protocol, pi->port, pi->ip, pi->tcp, flagIgnored, flagTriggerCountExceeded, flagDontBlock, flagBlockSuccessful);
}

int CreateDateTime(char *buf, const int size) {
  char *p = buf;
  int ret, current_size = size;
  struct tm tm, *tmptr;
  struct timespec ts;

  if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
    Error("Unable to get current clock time");
    return ERROR;
  }

  tmptr = localtime_r(&ts.tv_sec, &tm);

  if (tmptr != &tm) {
    Error("Unable to determine local time");
    return ERROR;
  }

  if ((ret = strftime(p, current_size, "%Y-%m-%dT%H:%M:%S.", tmptr)) == 0) {
    Error("Unable to write datetime format to buffer, insufficient space");
    return ERROR;
  }

  current_size -= ret;
  p += ret;

  if ((ret = snprintf(p, current_size, "%ld", ts.tv_nsec / 1000000)) >= current_size) {
    Error("Insufficient buffer space to write datetime");
    return ERROR;
  }

  current_size -= ret;
  p += ret;

  if ((ret = strftime(p, current_size, "%z", tmptr)) == 0) {
    Error("Unable to fit TZ id, insufficient space\n");
    return ERROR;
  }

  return TRUE;
}

static void LogScanEvent(const char *target, const char *resolvedHost, int protocol, uint16_t port, struct ip *ip, struct tcphdr *tcp, int flagIgnored, int flagTriggerCountExceeded, int flagDontBlock, int flagBlockSuccessful) {
  int ret, bufsize = MAX_BUF_SCAN_EVENT;
  char buf[MAX_BUF_SCAN_EVENT], *p = buf;
  char err[ERRNOMAXBUF];
  FILE *output;

  if (CreateDateTime(p, bufsize) != TRUE) {
    return;
  }

  bufsize -= strlen(p);
  p += strlen(p);

  if (bufsize < 2) {
    Error("Insufficient buffer size to write scan event");
    return;
  }

  *p = ' ';
  p++;
  *p = '\0';
  bufsize--;

  ret = snprintf(p, bufsize, "Scan from: [%s] (%s) protocol: [%s] port: [%d] type: [%s] IP opts: [%s] ignored: [%s] triggered: [%s] noblock: [%s] blocked: [%s]",
                 target,
                 resolvedHost,
                 (protocol == IPPROTO_TCP) ? "TCP" : "UDP",
                 port,
                 (configData.sentryMode == SENTRY_MODE_CONNECT) ? "Connect" : (protocol == IPPROTO_TCP) ? ReportPacketType(tcp)
                                                                                                        : "UDP",
                 (ip != NULL) ? (ip->ip_hl > 5) ? "set" : "not set" : "unknown",
                 (flagIgnored == TRUE) ? "true" : (flagIgnored == -100) ? "unset"
                                                                        : "false",
                 (flagTriggerCountExceeded == TRUE) ? "true" : (flagTriggerCountExceeded == -100) ? "unset"
                                                                                                  : "false",
                 (flagDontBlock == TRUE) ? "true" : (flagDontBlock == -100) ? "unset"
                                                                            : "false",
                 (flagBlockSuccessful == TRUE) ? "true" : (flagBlockSuccessful == -100) ? "unset"
                                                                                        : "false");

  if (ret >= bufsize) {
    Error("Unable to log scan event due to internal buffer too small");
    return;
  }

  // Log w/o date
  Log("%s", p);

  bufsize -= ret;
  p += ret;

  ret = snprintf(p, bufsize, "\n");

  if (ret >= bufsize) {
    Error("Unable to add newline to scan event due to internal buffer too small");
    return;
  }

  bufsize -= ret;
  p += ret;

  if ((output = fopen(configData.historyFile, "a")) == NULL) {
    Log("Unable to open history log file: %s (%s)", configData.historyFile, ErrnoString(err, sizeof(err)));
    return;
  }

  if (fwrite(buf, 1, strlen(buf), output) < strlen(buf)) {
    Error("Unable to write history file");
    return;
  }

  fclose(output);
}

int SetConvenienceData(const struct ip *ip, const void *p, struct sockaddr_in *client, struct tcphdr **tcp, struct udphdr **udp) {
  if (ip->ip_p != IPPROTO_TCP && ip->ip_p != IPPROTO_UDP) {
    Error("Unknown protocol %d detected. Attempting to continue.", ip->ip_p);
    return FALSE;
  }

  *tcp = (ip->ip_p == IPPROTO_TCP) ? (struct tcphdr *)p : NULL;
  *udp = (ip->ip_p == IPPROTO_UDP) ? (struct udphdr *)p : NULL;

  memset(client, 0, sizeof(struct sockaddr_in));
  client->sin_family = AF_INET;
  client->sin_addr.s_addr = ip->ip_src.s_addr;
  client->sin_port = (*tcp != NULL) ? (*tcp)->th_dport : (*udp)->uh_dport;

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

int StrToUint16_t(const char *str, uint16_t *val) {
  char *endptr;
  long value;

  errno = 0;
  value = strtol(str, &endptr, 10);

  // Stingy error checking
  // errno set indicates malformed input
  // endptr == str indicates no digits found
  // value > UINT16_MAX indicates value is too large, since ports can only be 0-65535
  // value <= 0: Don't allow port 0 (or negative ports)
  if (errno != 0 || endptr == str || *endptr != '\0' || value > UINT16_MAX || value <= 0) {
    return FALSE;
  }

  *val = (uint16_t)value;

  return TRUE;
}

static char *Realloc(char *filter, int newLen) {
  char *newFilter = NULL;

  if ((newFilter = realloc(filter, newLen)) == NULL) {
    Error("Unable to reallocate %d bytes of memory for pcap filter", newLen);
    Exit(EXIT_FAILURE);
  }

  return newFilter;
}

char *ReallocAndAppend(char *filter, int *filterLen, const char *append, ...) {
  int neededBufferLen;
  char *p;
  va_list args;

  // Calculate the length of the buffer needed (excluding the null terminator)
  va_start(args, append);
  neededBufferLen = vsnprintf(NULL, 0, append, args);
  va_end(args);

  // First time we're called, make sure we alloc room for the null terminator since *snprintf auto adds it and force truncate if it doesn't fit
  if (filter == NULL)
    neededBufferLen += 1;

  filter = Realloc(filter, *filterLen + neededBufferLen);

  // First time we're called, start at the beginning of the buffer. Otherwise, go to end of buffer - the null terminator
  if (*filterLen == 0)
    p = filter;
  else
    p = filter + *filterLen - 1;

  // store the new length of the buffer
  *filterLen += neededBufferLen;

  // Append the new string to the buffer, *snprintf will add the null terminator
  va_start(args, append);
  vsnprintf(p, (p == filter) ? neededBufferLen : neededBufferLen + 1, append, args);
  va_end(args);

  return filter;
}
