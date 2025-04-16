// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#include <string.h>
#include <netdb.h>
#include <assert.h>

#include "portsentry.h"
#include "config_data.h"
#include "ignore.h"
#include "io.h"
#include "util.h"
#include "packet_info.h"
#include "state_machine.h"
#include "block.h"

#define MAX_BUF_SCAN_EVENT 1024

static uint8_t isInitialized = FALSE;
static struct IgnoreState is = {0};
static struct BlockedState bs = {0};
static struct SentryState ss = {0};

static void LogScanEvent(const char *target, const char *resolvedHost, const int protocol, const uint16_t port, const struct ip *ip, const struct tcphdr *tcp, const int flagIgnored, const int flagTriggerCountExceeded, const int flagDontBlock, const int flagBlockSuccessful);

static void LogScanEvent(const char *target, const char *resolvedHost, const int protocol, const uint16_t port, const struct ip *ip, const struct tcphdr *tcp, const int flagIgnored, const int flagTriggerCountExceeded, const int flagDontBlock, const int flagBlockSuccessful) {
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

  // Log w/o date to stdout/stderr
  Log("%s", p);

  // Also write the log to the history file (if configured)
  if (strlen(configData.historyFile) == 0) {
    return;
  }

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

int InitSentry(void) {
  if (isInitialized == TRUE) {
    return TRUE;
  }

  if (is.isInitialized == FALSE && InitIgnore(&is) == ERROR) {
    Error("Error initializing ignore file %s", configData.ignoreFile);
    return ERROR;
  }

  if (bs.isInitialized == FALSE) {
    int ret;
    ret = BlockedStateInit(&bs);
    if (ret == ERROR) {
      Error("Error initializing blocked file %s", configData.blockedFile);
      FreeIgnore(&is);
      return ERROR;
    } else if (ret == FALSE) {
      if (RewriteBlockedFile(&bs) == ERROR) {
        return ERROR;
      }
    }
  }

  if (ss.isInitialized == FALSE) {
    InitSentryState(&ss);
  }

  isInitialized = TRUE;
  return TRUE;
}

void FreeSentry(void) {
  if (isInitialized == FALSE) {
    return;
  }

  if (is.isInitialized == TRUE) {
    FreeIgnore(&is);
  }

  if (bs.isInitialized == TRUE) {
    BlockedStateFree(&bs);
  }

  isInitialized = FALSE;
}

void RunSentry(const struct PacketInfo *pi) {
  char resolvedHost[NI_MAXHOST];
  int flagIgnored = -100, flagTriggerCountExceeded = -100, flagDontBlock = -100, flagBlockSuccessful = -100;  // -100 => unset

  assert(isInitialized == TRUE);
  assert(pi != NULL);

  if (configData.resolveHost == TRUE) {
    ResolveAddr(pi, resolvedHost, NI_MAXHOST);
  } else {
    snprintf(resolvedHost, NI_MAXHOST, "%s", pi->saddr);
  }

  if ((flagIgnored = IgnoreIpIsPresent(&is, GetSourceSockaddrFromPacketInfo(pi))) == ERROR) {
    flagIgnored = FALSE;
  } else if (flagIgnored == TRUE) {
    Verbose("Host: %s found in ignore file %s, aborting actions", pi->saddr, configData.ignoreFile);
    goto sentry_exit;
  }

  if ((flagTriggerCountExceeded = CheckState(&ss, GetSourceSockaddrFromPacketInfo(pi))) != TRUE) {
    goto sentry_exit;
  }

  if (configData.disableLocalCheck == FALSE && IsSameSourceAndDestAddress(pi) == TRUE) {
    Debug("Source address %s same as destination address %s, skipping", pi->saddr, pi->daddr);
    flagIgnored = TRUE;
    flagDontBlock = TRUE;
    flagBlockSuccessful = FALSE;
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
    flagBlockSuccessful = FALSE;
    goto sentry_exit;
  } else {
    flagDontBlock = FALSE;
  }

  if (IsBlocked(GetSourceSockaddrFromPacketInfo(pi), &bs) == FALSE) {
    if (DisposeTarget(pi->saddr, pi->port, pi->protocol) != TRUE) {
      Error("attackalert: Error during target dispose %s/%s!", resolvedHost, pi->saddr);
      flagBlockSuccessful = FALSE;
    } else {
      WriteBlockedFile(GetSourceSockaddrFromPacketInfo(pi), &bs);
      flagBlockSuccessful = TRUE;
    }
  } else {
    Log("attackalert: Host: %s/%s is already blocked Ignoring", resolvedHost, pi->saddr);
    flagBlockSuccessful = TRUE;
  }

sentry_exit:
  LogScanEvent(pi->saddr, resolvedHost, pi->protocol, pi->port, pi->ip, pi->tcp, flagIgnored, flagTriggerCountExceeded, flagDontBlock, flagBlockSuccessful);
}
