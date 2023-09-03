#pragma once

enum SentryMode { SENTRY_MODE_NONE = 0, SENTRY_MODE_TCP, SENTRY_MODE_STCP, SENTRY_MODE_ATCP, SENTRY_MODE_UDP, SENTRY_MODE_SUDP, SENTRY_MODE_AUDP };

struct ConfigData {
  char killRoute[MAXBUF];
  char killHostsDeny[MAXBUF];
  char killRunCmd[MAXBUF];

  char detectionType[MAXBUF];
  char ports[MAXBUF];
  uint16_t parsedPorts[USHRT_MAX];
  char advancedExclude[MAXBUF];
  char portBanner[MAXBUF];

  char blockedFile[PATH_MAX];
  char historyFile[PATH_MAX];
  char ignoreFile[PATH_MAX];

  int blockTCP;
  int blockUDP;
  int runCmdFirst;
  int resolveHost;
  int configTriggerCount;

  enum SentryMode sentryMode;
};

extern struct ConfigData configData;

void ResetConfigData(struct ConfigData *cd);
