// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: BSD-2-Clause

#pragma once
#include <limits.h>
#include <stdint.h>
#include <net/if.h>

#include "portsentry.h"
#include "port.h"

const uint8_t LOGFLAG_NONE = 0x00;
const uint8_t LOGFLAG_DEBUG = 0x1;
const uint8_t LOGFLAG_VERBOSE = 0x2;
const uint8_t LOGFLAG_OUTPUT_STDOUT = 0x4;
const uint8_t LOGFLAG_OUTPUT_SYSLOG = 0x8;

enum SentryMode { SENTRY_MODE_STEALTH = 0,
                  SENTRY_MODE_CONNECT };

enum SentryMethod { SENTRY_METHOD_PCAP = 0,
                    SENTRY_METHOD_RAW };

struct ConfigData {
  char killRoute[MAXBUF];
  char killHostsDeny[MAXBUF];
  char killRunCmd[MAXBUF];

  char **interfaces;

  struct Port *tcpPorts;
  int tcpPortsLength;
  struct Port *udpPorts;
  int udpPortsLength;

  char portBanner[MAXBUF];
  uint8_t portBannerPresent;

  char configFile[PATH_MAX];
  char blockedFile[PATH_MAX];
  char historyFile[PATH_MAX];
  char ignoreFile[PATH_MAX];

  int blockTCP;
  int blockUDP;
  int runCmdFirst;
  int resolveHost;
  int configTriggerCount;
  int disableLocalCheck;

  enum SentryMode sentryMode;
  enum SentryMethod sentryMethod;

  uint8_t logFlags;

  uint8_t daemon;
};

extern struct ConfigData configData;

void ResetConfigData(struct ConfigData *cd);
void PostProcessConfig(struct ConfigData *cd);
void PrintConfigData(const struct ConfigData cd);
char *GetSentryModeString(const enum SentryMode sentryMode);
void SetConfigData(const struct ConfigData *fileConfig, const struct ConfigData *cmdlineConfig);
int AddInterface(struct ConfigData *cd, const char *interface);
int GetNoInterfaces(const struct ConfigData *cd);
void FreeConfigData(struct ConfigData *cd);
int IsInterfacePresent(const struct ConfigData *cd, const char *interface);
