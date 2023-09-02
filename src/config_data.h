#pragma once

enum SentryMode { TCP, STCP, ATCP, UDP, SUDP, AUDP };

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

  SentryMode sentryMode;
};

extern struct ConfigData configData;

void resetConfigData(struct ConfigData cd);
