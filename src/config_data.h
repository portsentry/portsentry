#pragma once

struct ConfigData {
  char gblKillRoute[MAXBUF];
  char gblKillHostsDeny[MAXBUF];
  char gblKillRunCmd[MAXBUF];

  char gblDetectionType[MAXBUF];
  char gblPorts[MAXBUF];
  uint16_t ports[USHRT_MAX];
  char gblAdvancedExclude[MAXBUF];
  char gblPortBanner[MAXBUF];

  char gblBlockedFile[PATH_MAX];
  char gblHistoryFile[PATH_MAX];
  char gblIgnoreFile[PATH_MAX];

  int gblBlockTCP;
  int gblBlockUDP;
  int gblRunCmdFirst;
  int gblResolveHost;
  int gblConfigTriggerCount;
};

extern struct ConfigData configData;

void resetConfigData(struct ConfigData cd);
