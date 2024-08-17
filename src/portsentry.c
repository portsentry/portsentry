// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
// SPDX-FileContributor: Craig Rowland
//
// SPDX-License-Identifier: CPL-1.0

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sentry_stealth.h"
#include "cmdline.h"
#include "config_data.h"
#include "configfile.h"
#include "sentry_connect.h"
#include "io.h"
#include "portsentry.h"
#ifdef USE_PCAP
#include "sentry_pcap.h"
#endif
#include "sighandler.h"
#include "config.h"

uint8_t g_isRunning = TRUE;

int main(int argc, char *argv[]) {
  int status = 0;
  printf("PortSentry %d.%d\n", PORTSENTRY_VERSION_MAJOR, PORTSENTRY_VERSION_MINOR);

  ParseCmdline(argc, argv);

  if (SetupSignalHandlers() != TRUE) {
    fprintf(stderr, "Could not setup signal handler. Shutting down.\n");
    Exit(EXIT_FAILURE);
  }

  readConfigFile();

  if (configData.logFlags & LOGFLAG_DEBUG) {
    printf("debug: Final Configuration:\n");
    PrintConfigData(configData);
  }

  if ((geteuid()) && (getuid()) != 0) {
    fprintf(stderr, "You need to be root to run this.\n");
    Exit(EXIT_FAILURE);
  }

  if (configData.daemon == TRUE) {
    if (daemon(0, 0) == -1) {
      fprintf(stderr, "Could not go into daemon mode. Shutting down.\n");
      Exit(EXIT_FAILURE);
    }
  }

  if (configData.sentryMode == SENTRY_MODE_CONNECT) {
    status = PortSentryConnectMode();
  } else if (configData.sentryMode == SENTRY_MODE_STEALTH) {
    if (configData.sentryMethod == SENTRY_METHOD_RAW) {
      status = PortSentryStealthMode();
#ifdef USE_PCAP
    } else if (configData.sentryMethod == SENTRY_METHOD_PCAP) {
      status = PortSentryPcap();
#endif
    } else {
      Error("Invalid sentry method specified. Shutting down.");
      Exit(EXIT_FAILURE);
    }
  } else {
    Error("Invalid sentry mode specified. Shutting down.");
    Exit(EXIT_FAILURE);
  }

  Exit(status);
}
