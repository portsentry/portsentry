#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "config_data.h"
#include "io.h"
#include "portsentry.h"
#include "util.h"

struct ConfigData configData;

void ResetConfigData(struct ConfigData *cd) {
  memset(cd, 0, sizeof(struct ConfigData));
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

  if (strlen(cd->interfaces[0]) == 0) {
    SafeStrncpy(cd->interfaces[0], "ALL_NLO", IF_NAMESIZE);
  }
}

void PrintConfigData(const struct ConfigData cd) {
  int i;

  printf("debug: killRoute: %s\n", cd.killRoute);
  printf("debug: killHostsDeny: %s\n", cd.killHostsDeny);
  printf("debug: killRunCmd: %s\n", cd.killRunCmd);

  i = 0;
  while (strlen(cd.interfaces[i]) > 0) {
    printf("debug: interface: %s\n", cd.interfaces[i]);
    i++;
  }

  printf("debug: tcpPorts (%d): ", cd.tcpPortsLength);
  for (i = 0; i < cd.tcpPortsLength; i++) {
    printf("%d ", cd.tcpPorts[i]);
  }
  printf("\n");

  printf("debug: udpPorts (%d): ", cd.udpPortsLength);
  for (i = 0; i < cd.udpPortsLength; i++) {
    printf("%d ", cd.udpPorts[i]);
  }
  printf("\n");

  printf("debug: tcpAdvancedPort: %d\n", cd.tcpAdvancedPort);
  printf("debug: udpAdvancedPort: %d\n", cd.udpAdvancedPort);

  printf("debug: tcpAdvancedExcludePorts (%d): ", cd.tcpAdvancedExcludePortsLength);
  for (i = 0; i < cd.tcpAdvancedExcludePortsLength; i++) {
    printf("%d ", cd.tcpAdvancedExcludePorts[i]);
  }
  printf("\n");

  printf("debug: udpAdvancedExcludePorts (%d): ", cd.udpAdvancedExcludePortsLength);
  for (i = 0; i < cd.udpAdvancedExcludePortsLength; i++) {
    printf("%d ", cd.udpAdvancedExcludePorts[i]);
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

  printf("debug: sentryMode: %s\n", cd.sentryMode == SENTRY_MODE_NONE ? "none" : cd.sentryMode == SENTRY_MODE_TCP ? "tcp"
                                                                             : cd.sentryMode == SENTRY_MODE_STCP  ? "stcp"
                                                                             : cd.sentryMode == SENTRY_MODE_ATCP  ? "atcp"
                                                                             : cd.sentryMode == SENTRY_MODE_UDP   ? "udp"
                                                                             : cd.sentryMode == SENTRY_MODE_SUDP  ? "sudp"
                                                                             : cd.sentryMode == SENTRY_MODE_AUDP  ? "audp"
                                                                                                                  : "unknown");

  printf("debug: sentryMethod: %s\n", cd.sentryMethod == SENTRY_METHOD_PCAP  ? "pcap"
                                      : cd.sentryMethod == SENTRY_METHOD_RAW ? "raw"
                                                                             : "unknown");

  printf("debug: log output stdout: %s\n", (cd.logFlags & LOGFLAG_OUTPUT_STDOUT) != 0 ? "true" : "false");
  printf("debug: log output syslog: %s\n", (cd.logFlags & LOGFLAG_OUTPUT_SYSLOG) != 0 ? "true" : "false");
  printf("debug: log debug: %s\n", (cd.logFlags & LOGFLAG_DEBUG) != 0 ? "true" : "false");
  printf("debug: log verbose: %s\n", (cd.logFlags & LOGFLAG_VERBOSE) != 0 ? "true" : "false");

  printf("debug: daemon: %s\n", cd.daemon == TRUE ? "true" : "false");
}

char *GetSentryModeString(const enum SentryMode sentryMode) {
  switch (sentryMode) {
  case SENTRY_MODE_NONE:
    return "none";
  case SENTRY_MODE_TCP:
    return "tcp";
  case SENTRY_MODE_STCP:
    return "stcp";
  case SENTRY_MODE_ATCP:
    return "atcp";
  case SENTRY_MODE_UDP:
    return "udp";
  case SENTRY_MODE_SUDP:
    return "sudp";
  case SENTRY_MODE_AUDP:
    return "audp";
  default:
    return "unknown";
  }
}

int AddInterface(struct ConfigData *cd, const char *interface) {
  int i;

  if (strlen(interface) > (IF_NAMESIZE - 1)) {
    fprintf(stderr, "Error: Interface name %s too long\n", interface);
    Exit(EXIT_FAILURE);
  }

  for (i = 0; i < MAX_INTERFACES; i++) {
    if (strlen(cd->interfaces[i]) > 0) {
      if (strncmp(cd->interfaces[i], interface, strlen(cd->interfaces[i])) == 0) {
        return TRUE;
      }
    } else {
      SafeStrncpy(cd->interfaces[i], interface, sizeof(cd->interfaces[i]));
      return TRUE;
    }
  }

  return FALSE;
}
