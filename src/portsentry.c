// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
// SPDX-FileContributor: Craig Rowland
//
// SPDX-License-Identifier: CPL-1.0

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef __linux__
#include "sentry_stealth.h"
#endif
#include "cmdline.h"
#include "config_data.h"
#include "configfile.h"
#include "sentry_connect.h"
#include "io.h"
#include "portsentry.h"
#include "sentry.h"
#ifdef USE_PCAP
#include "sentry_pcap.h"
#endif
#include "sighandler.h"
#include "config.h"

uint8_t g_isRunning = TRUE;

int main(int argc, char *argv[]) {
  int status = EXIT_FAILURE;

  Version();

  ParseCmdline(argc, argv);

  if (SetupSignalHandlers() != TRUE) {
    fprintf(stderr, "Could not setup signal handler. Shutting down.\n");
    goto exit;
  }

  ReadConfigFile();

  if (configData.logFlags & LOGFLAG_DEBUG) {
    printf("debug: Final Configuration:\n");
    PrintConfigData(configData);
  }

  if ((geteuid()) && (getuid()) != 0) {
    fprintf(stderr, "You need to be root to run this.\n");
    goto exit;
  }

  if (configData.daemon == TRUE) {
    if (daemon(0, 0) == -1) {
      fprintf(stderr, "Could not go into daemon mode. Shutting down.\n");
      goto exit;
    }
  }

  if (InitSentry() != TRUE) {
    fprintf(stderr, "Could not initialize sentry. Shutting down.\n");
    goto exit;
  }

  if (configData.sentryMode == SENTRY_MODE_CONNECT) {
    status = PortSentryConnectMode();
  } else if (configData.sentryMode == SENTRY_MODE_STEALTH) {
#ifdef __linux__
    if (configData.sentryMethod == SENTRY_METHOD_RAW) {
      status = PortSentryStealthMode();
      goto exit;
    }
#endif
#ifdef USE_PCAP
    if (configData.sentryMethod == SENTRY_METHOD_PCAP) {
      status = PortSentryPcap();
      goto exit;
    }
#endif
    Error("Invalid sentry method specified. Shutting down.");
    goto exit;
  } else {
    Error("Invalid sentry mode specified. Shutting down.");
    goto exit;
  }

exit:
  FreeSentry();
  FreeConfigData(&configData);
  Exit(status);
}
