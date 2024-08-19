// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "config_data.h"
#include "io.h"
#include "port.h"
#include "portsentry.h"
#include "util.h"

struct ConfigData configData;

static int IsInterfacePresent(const struct ConfigData *cd, const char *interface);

void ResetConfigData(struct ConfigData *cd) {
  memset(cd, 0, sizeof(struct ConfigData));

#ifndef USE_PCAP
  cd->sentryMethod = SENTRY_METHOD_RAW;
#endif
}

void PostProcessConfig(struct ConfigData *cd) {
  // If no log output is specified, default to stdout
  if ((cd->logFlags & LOGFLAG_OUTPUT_STDOUT) == 0 && (cd->logFlags & LOGFLAG_OUTPUT_SYSLOG) == 0) {
    cd->logFlags |= LOGFLAG_OUTPUT_STDOUT;
  }

  if (cd->daemon == TRUE) {
    cd->logFlags &= ~LOGFLAG_OUTPUT_STDOUT;
    cd->logFlags |= LOGFLAG_OUTPUT_SYSLOG;
  }

  if (strlen(cd->configFile) == 0) {
    if (strlen(CONFIG_FILE) > (sizeof(cd->configFile) - 1)) {
      fprintf(stderr, "Error: Config file path too long\n");
      Exit(EXIT_FAILURE);
    }
    SafeStrncpy(cd->configFile, CONFIG_FILE, sizeof(cd->configFile));
  }

  if (GetNoInterfaces(cd) == 0) {
    AddInterface(cd, "ALL_NLO");
  }
}

void PrintConfigData(const struct ConfigData cd) {
  int i;

  printf("debug: killRoute: %s\n", cd.killRoute);
  printf("debug: killHostsDeny: %s\n", cd.killHostsDeny);
  printf("debug: killRunCmd: %s\n", cd.killRunCmd);

  if (GetNoInterfaces(&cd) > 0) {
    i = 0;
    while (cd.interfaces[i] != NULL) {
      printf("debug: interface: %s\n", cd.interfaces[i]);
      i++;
    }
  } else {
    printf("debug: [no interfaces set]\n");
  }

  printf("debug: tcpPorts (%d): ", cd.tcpPortsLength);
  for (i = 0; i < cd.tcpPortsLength; i++) {
    if (IsPortSingle(&cd.tcpPorts[i])) {
      printf("%d ", cd.tcpPorts[i].single);
    } else {
      printf("%d-%d ", cd.tcpPorts[i].range.start, cd.tcpPorts[i].range.end);
    }
  }
  printf("\n");

  printf("debug: udpPorts (%d): ", cd.udpPortsLength);
  for (i = 0; i < cd.udpPortsLength; i++) {
    if (IsPortSingle(&cd.udpPorts[i])) {
      printf("%d ", cd.udpPorts[i].single);
    } else {
      printf("%d-%d ", cd.udpPorts[i].range.start, cd.udpPorts[i].range.end);
    }
  }
  printf("\n");

  if (cd.portBannerPresent == TRUE) {
    printf("debug: portBanner: %s\n", cd.portBanner);
  }

  printf("debug: configFile: %s\n", cd.configFile);
  printf("debug: blockedFile: %s\n", cd.blockedFile);
  printf("debug: historyFile: %s\n", cd.historyFile);
  printf("debug: ignoreFile: %s\n", cd.ignoreFile);

  printf("debug: blockTCP: %d\n", cd.blockTCP);
  printf("debug: blockUDP: %d\n", cd.blockUDP);
  printf("debug: runCmdFirst: %d\n", cd.runCmdFirst);
  printf("debug: resolveHost: %d\n", cd.resolveHost);
  printf("debug: configTriggerCount: %d\n", cd.configTriggerCount);

  printf("debug: sentryMode: %s\n", GetSentryModeString(cd.sentryMode));

  printf("debug: sentryMethod: %s\n", GetSentryMethodString(cd.sentryMethod));

  printf("debug: log output stdout: %s\n", (cd.logFlags & LOGFLAG_OUTPUT_STDOUT) != 0 ? "true" : "false");
  printf("debug: log output syslog: %s\n", (cd.logFlags & LOGFLAG_OUTPUT_SYSLOG) != 0 ? "true" : "false");
  printf("debug: log debug: %s\n", (cd.logFlags & LOGFLAG_DEBUG) != 0 ? "true" : "false");
  printf("debug: log verbose: %s\n", (cd.logFlags & LOGFLAG_VERBOSE) != 0 ? "true" : "false");

  printf("debug: daemon: %s\n", cd.daemon == TRUE ? "true" : "false");
}

char *GetSentryModeString(const enum SentryMode sentryMode) {
  switch (sentryMode) {
  case SENTRY_MODE_STEALTH:
    return "stealth";
  case SENTRY_MODE_CONNECT:
    return "connect";
  default:
    return "unknown";
  }
}

char *GetSentryMethodString(const enum SentryMethod sentryMethod) {
  switch (sentryMethod) {
  case SENTRY_METHOD_PCAP:
    return "pcap";
  case SENTRY_METHOD_RAW:
    return "raw";
  default:
    return "unknown";
  }
}

int AddInterface(struct ConfigData *cd, const char *interface) {
  int noInterfaces;

  if (strlen(interface) > (IF_NAMESIZE - 1)) {
    fprintf(stderr, "Error: Interface name %s too long\n", interface);
    Exit(EXIT_FAILURE);
  }

  if (IsInterfacePresent(cd, interface) == TRUE) {
    return TRUE;
  }

  noInterfaces = GetNoInterfaces(cd);

  cd->interfaces = realloc(cd->interfaces, noInterfaces + 2 * sizeof(char *));
  cd->interfaces[noInterfaces] = malloc(IF_NAMESIZE);

  SafeStrncpy(cd->interfaces[noInterfaces], interface, IF_NAMESIZE);

  return TRUE;
}

void FreeInterfaces(struct ConfigData *cd) {
  int i;

  if (cd->interfaces == NULL) {
    return;
  }

  i = 0;
  while (cd->interfaces[i] != NULL) {
    free(cd->interfaces[i]);
    i++;
  }

  free(cd->interfaces);
  cd->interfaces = NULL;
}

int GetNoInterfaces(const struct ConfigData *cd) {
  int i = 0;

  if (cd->interfaces == NULL) {
    return 0;
  }

  while (cd->interfaces[i] != NULL) {
    i++;
  }

  return i;
}

static int IsInterfacePresent(const struct ConfigData *cd, const char *interface) {
  int i = 0;

  if (cd->interfaces == NULL) {
    return FALSE;
  }

  while (cd->interfaces[i] != NULL) {
    if (strlen(cd->interfaces[i]) != strlen(interface)) {
      i++;
      continue;
    }

    if (strncmp(cd->interfaces[i], interface, strlen(cd->interfaces[i])) == 0) {
      return TRUE;
    }
  }

  return FALSE;
}
