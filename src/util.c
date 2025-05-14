// SPDX-FileCopyrightText: 2024 Craig Rowland
// SPDX-FileContributor: Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#include <stdarg.h>
#include <arpa/inet.h>
#include <assert.h>
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
#include <fcntl.h>

#include "config_data.h"
#include "io.h"
#include "portsentry.h"
#include "util.h"
#include "packet_info.h"

static char *Realloc(char *filter, int newLen);

char *SafeStrncpy(char *dest, const char *src, size_t size) {
  if (dest == NULL || src == NULL) {
    return NULL;
  }

  if (size < 1 || size > MAX_SAFESTRNCMP_SIZE) {
    return NULL;
  }

  if (size > SIZE_MAX - 1) {
    return NULL;
  }

  size_t src_len = strnlen(src, MAX_SAFESTRNCMP_SIZE);
  if (src_len >= MAX_SAFESTRNCMP_SIZE) {
    return NULL;
  }

  size_t copy_size = (src_len < (size - 1)) ? src_len : (size - 1);

  memmove(dest, src, copy_size);
  dest[copy_size] = '\0';

  return dest;
}

void ResolveAddr(const struct PacketInfo *pi, char *resolvedHost, const int resolvedHostSize) {
  if (getnameinfo(GetSourceSockaddrFromPacketInfo(pi), GetSourceSockaddrLenFromPacketInfo(pi), resolvedHost, resolvedHostSize, NULL, 0, NI_NUMERICHOST) != 0) {
    Error("ResolveAddr: Unable to resolve address for %s", pi->saddr);
    if (snprintf(resolvedHost, resolvedHostSize, "<unknown>") >= resolvedHostSize) {
      Error("ResolveAddr: <unknown> placeholder too long for buffer");
      resolvedHost[resolvedHostSize - 1] = '\0';
    }
  }

  Debug("ResolveAddr: Resolved: %s", resolvedHost);
}

long GetLong(const char *buffer) {
  long value = 0;
  char *endptr = NULL;

  if (buffer == NULL)
    return ERROR;

  value = strtol(buffer, &endptr, 10);

  if (value == LONG_MIN || value == LONG_MAX)
    return ERROR;

  if (endptr == buffer)
    return ERROR;

  if (*endptr != '\0')
    return ERROR;

  return value;
}

int DisposeTarget(const char *target, int port, int protocol) {
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

const char *GetFamilyString(int family) {
  switch (family) {
  case AF_INET:
    return ("AF_INET");
    break;
  case AF_INET6:
    return ("AF_INET6");
    break;
  default:
    return ("UNKNOWN");
    break;
  }
}

int SetupPort(int family, uint16_t port, int proto) {
  int sock;

  assert(proto == IPPROTO_TCP || proto == IPPROTO_UDP);

  if ((sock = OpenSocket(family, (proto == IPPROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM, proto, TRUE)) == ERROR) {
    return -1;
  }

  if (BindSocket(sock, family, port, proto) == ERROR) {
    close(sock);
    return -2;
  }

  return sock;
}

int IsPortInUse(struct PacketInfo *pi) {
  int sock;

  sock = SetupPort((pi->version == 4) ? AF_INET : AF_INET6, pi->port, pi->protocol);

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
char *ReportPacketType(const struct tcphdr *tcpPkt) {
  static char packetDesc[MAXBUF];
  static char *packetDescPtr = packetDesc;
  int ret;

  if (tcpPkt->th_flags == 0)
    ret = snprintf(packetDesc, MAXBUF, "TCP NULL scan");
  else if (((tcpPkt->th_flags & TH_FIN) != 0) && ((tcpPkt->th_flags & TH_URG) != 0) && ((tcpPkt->th_flags & TH_PUSH) != 0))
    ret = snprintf(packetDesc, MAXBUF, "TCP XMAS scan");
  else if (((tcpPkt->th_flags & TH_FIN) != 0) && ((tcpPkt->th_flags & TH_SYN) == 0) && ((tcpPkt->th_flags & TH_ACK) == 0) &&
           ((tcpPkt->th_flags & TH_PUSH) == 0) && ((tcpPkt->th_flags & TH_RST) == 0) && ((tcpPkt->th_flags & TH_URG) == 0))
    ret = snprintf(packetDesc, MAXBUF, "TCP FIN scan");
  else if (((tcpPkt->th_flags & TH_SYN) != 0) && ((tcpPkt->th_flags & TH_FIN) == 0) && ((tcpPkt->th_flags & TH_ACK) == 0) &&
           ((tcpPkt->th_flags & TH_PUSH) == 0) && ((tcpPkt->th_flags & TH_RST) == 0) && ((tcpPkt->th_flags & TH_URG) == 0))
    ret = snprintf(packetDesc, MAXBUF, "TCP SYN/Normal scan");
  else
    ret = snprintf(packetDesc, MAXBUF,
                   "Unknown Type: TCP Packet Flags: SYN: %d FIN: %d ACK: %d PSH: %d URG: %d RST: %d",
                   tcpPkt->th_flags & TH_SYN ? 1 : 0, tcpPkt->th_flags & TH_FIN ? 1 : 0, tcpPkt->th_flags & TH_ACK ? 1 : 0,
                   tcpPkt->th_flags & TH_PUSH ? 1 : 0, tcpPkt->th_flags & TH_URG ? 1 : 0, tcpPkt->th_flags & TH_RST ? 1 : 0);

  if (ret >= MAXBUF) {
    Error("ReportPacketType: Packet description too long for buffer: %s, truncating", packetDesc);
    packetDesc[MAXBUF - 1] = '\0';
  }

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

  if ((ret = snprintf(p, current_size, "%03ld", ts.tv_nsec / 1000000)) >= current_size) {
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

#ifndef NDEBUG
void DebugWritePacketToFs(const struct PacketInfo *pi) {
  int fd = -1;
  char filename[64], err[ERRNOMAXBUF];
  int ipLen;
  unsigned char *ip;

  if (pi->ip != NULL) {
    ip = (unsigned char *)pi->ip;
  } else if (pi->ip6 != NULL) {
    ip = (unsigned char *)pi->ip6;
  } else {
    Error("No IP address to write to file");
    goto exit;
  }

  if (pi->tcp != NULL) {
    ipLen = (unsigned char *)pi->tcp - ip;
  } else if (pi->udp != NULL) {
    ipLen = (unsigned char *)pi->udp - ip;
  } else {
    Error("No TCP or UDP header to write to file");
    goto exit;
  }

#ifdef __linux__
  snprintf(filename, sizeof(filename), "/tmp/packet-%lu", time(NULL));
#elif __OpenBSD__
  snprintf(filename, sizeof(filename), "/tmp/packet-%lld", time(NULL));
#else
  snprintf(filename, sizeof(filename), "/tmp/packet-%ld", time(NULL));
#endif
  if ((fd = open(filename, O_CREAT | O_WRONLY, 0644)) == -1) {
    Error("Unable to open file %s for writing: %s", filename, ErrnoString(err, sizeof(err)));
    goto exit;
  }

  if (write(fd, ip, ipLen) == -1) {
    Error("Unable to write IP header to file %s: %s", filename, ErrnoString(err, sizeof(err)));
    goto exit;
  }

  if (pi->tcp != NULL) {
    if (write(fd, pi->tcp, sizeof(struct tcphdr)) == -1) {
      Error("Unable to write TCP header to file %s: %s", filename, ErrnoString(err, sizeof(err)));
      goto exit;
    }
  } else if (pi->udp != NULL) {
    if (write(fd, pi->udp, sizeof(struct udphdr)) == -1) {
      Error("Unable to write UDP header to file %s: %s", filename, ErrnoString(err, sizeof(err)));
      goto exit;
    }
  }

  Debug("Wrote packet to file %s", filename);

exit:
  if (fd != -1)
    close(fd);
}
#endif
