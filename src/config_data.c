#include <limits.h>

#include "config.h"
#include "portsentry.h"
#include "config_data.h"
#include "portsentry_util.h"

struct ConfigData configData;

void ResetConfigData(struct ConfigData *cd) {
  memset(cd, 0, sizeof(struct ConfigData));
}

void PostProcessConfig(struct ConfigData *cd) {
  // If no log output is specified, default to stdout
  if ((cd->logFlags & LOGFLAG_OUTPUT_STDOUT) == 0 && (cd->logFlags & LOGFLAG_OUTPUT_SYSLOG) == 0) {
    cd->logFlags |= LOGFLAG_OUTPUT_STDOUT;
  }

  if (strlen(cd->configFile) == 0) {
    if (strlen(CONFIG_FILE) > (sizeof(cd->configFile) - 1)) {
      fprintf(stderr, "Error: Config file path too long\n");
      Exit(EXIT_FAILURE);
    }
    SafeStrncpy(cd->configFile, CONFIG_FILE, sizeof(cd->configFile));
  }
}

void PrintConfigData(const struct ConfigData cd) {
  int i;

  printf("killRoute: %s\n", cd.killRoute);
  printf("killHostsDeny: %s\n", cd.killHostsDeny);
  printf("killRunCmd %s\n", cd.killRunCmd);

  printf("ports: %s\n", cd.ports);
  printf("parsedPorts: ");
  for(i=0; i<USHRT_MAX; i++) {
    if (cd.parsedPorts[i] == 0)
      break;
    printf("%d ", cd.parsedPorts[i]);
  }
  printf("\n");

  printf("advancedExclude: %s\n", cd.advancedExclude);

  printf("configFile: %s\n", cd.configFile);
  printf("blockedFile: %s\n", cd.blockedFile);
  printf("historyFile: %s\n", cd.historyFile);
  printf("ignoreFile: %s\n", cd.ignoreFile);

  printf("blockTCP: %d\n", cd.blockTCP);
  printf("blockUDP: %d\n", cd.blockUDP);
  printf("runCmdFirst: %d\n", cd.runCmdFirst);
  printf("resolveHost: %d\n", cd.resolveHost);
  printf("configTriggerCount: %d\n", cd.configTriggerCount);

  printf("sentryMode: %s\n", cd.sentryMode == SENTRY_MODE_NONE ? "none" :
                             cd.sentryMode == SENTRY_MODE_TCP ? "tcp" :
                             cd.sentryMode == SENTRY_MODE_STCP ? "stcp" :
                             cd.sentryMode == SENTRY_MODE_ATCP ? "atcp" :
                             cd.sentryMode == SENTRY_MODE_UDP ? "udp" :
                             cd.sentryMode == SENTRY_MODE_SUDP ? "sudp" :
                             cd.sentryMode == SENTRY_MODE_AUDP ? "audp" : "unknown");

  printf("log output stdout: %s\n", (cd.logFlags & LOGFLAG_OUTPUT_STDOUT) != 0 ? "true" : "false");
  printf("log output syslog: %s\n", (cd.logFlags & LOGFLAG_OUTPUT_SYSLOG) != 0 ? "true" : "false");
  printf("log debug: %s\n", (cd.logFlags & LOGFLAG_DEBUG) != 0 ? "true" : "false");
  printf("log verbose: %s\n", (cd.logFlags & LOGFLAG_VERBOSE) != 0 ? "true" : "false");

  printf("daemon: %s\n", cd.daemon == TRUE ? "true" : "false");
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

void SetConfigData(const struct ConfigData *fileConfig, const struct ConfigData *cmdlineConfig) {
  memcpy(&configData, fileConfig, sizeof(struct ConfigData));
  configData.sentryMode = cmdlineConfig->sentryMode;
  configData.logFlags = cmdlineConfig->logFlags;
  memcpy(configData.configFile, cmdlineConfig->configFile, sizeof(configData.configFile));
  configData.daemon = cmdlineConfig->daemon;
}
