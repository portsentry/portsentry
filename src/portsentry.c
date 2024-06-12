/************************************************************************/
/*                                                                      */
/* PortSentry                                                           */
/*                                                                      */
/* This software is Copyright(c) 1997-2003 Craig Rowland                */
/*                                                                      */
/* This software is covered under the Common Public License v1.0        */
/* See the enclosed LICENSE file for more information.                  */
/*                                                                      */
/* Created: 10-12-1997                                                  */
/* Modified: 05-23-2003                                                 */
/*                                                                      */
/* Send all changes/modifications/bugfixes to:                          */
/* craigrowland at users dot sourceforge dot net                        */
/*                                                                      */
/* $Id: portsentry.c,v 1.40 2003/05/23 17:41:25 crowland Exp crowland $ */
/************************************************************************/
#include <stdlib.h>
#include <unistd.h>

#include "stealth_sentry.h"
#include "advanced_sentry.h"
#include "cmdline.h"
#include "config_data.h"
#include "configfile.h"
#include "connect_sentry.h"
#include "io.h"
#include "portsentry.h"
#include "sentry_pcap.h"
#include "sighandler.h"
#include "config.h"

uint8_t g_isRunning = TRUE;

int main(int argc, char *argv[]) {
  printf("PortSentry %d.%d\n", PORTSENTRY_VERSION_MAJOR, PORTSENTRY_VERSION_MINOR);

  ParseCmdline(argc, argv);

  if (SetupSignalHandlers() != TRUE) {
    fprintf(stderr, "Could not setup signal handler. Shutting down.\n");
    Exit(EXIT_FAILURE);
  }

  readConfigFile();

  if (configData.logFlags & LOGFLAG_DEBUG) {
    printf("Final Configuration:\n");
    PrintConfigData(configData);
  }

  if ((geteuid()) && (getuid()) != 0) {
    fprintf(stderr, "You need to be root to run this.\n");
    Exit(EXIT_FAILURE);
  }

  if (configData.daemon == TRUE) {
    if (DaemonSeed() == ERROR) {
      fprintf(stderr, "Could not go into daemon mode. Shutting down.\n");
      Exit(EXIT_FAILURE);
    }
  }

  if (configData.sentryMode == SENTRY_MODE_TCP || configData.sentryMode == SENTRY_MODE_UDP) {
    if (PortSentryConnectMode() == ERROR) {
      Error("Could not go into PortSentry mode. Shutting down.");
      Exit(EXIT_FAILURE);
    }
  } else if (configData.sentryMode == SENTRY_MODE_STCP || configData.sentryMode == SENTRY_MODE_SUDP) {
    if (configData.sentryMethod == SENTRY_METHOD_PCAP) {
      if (PortSentryPcap() == ERROR) {
        Error("Could not go into PortSentry mode. Shutting down.");
        Exit(EXIT_FAILURE);
      }
    } else if (configData.sentryMethod == SENTRY_METHOD_RAW) {
      if (PortSentryStealthMode() == ERROR) {
        Error("Could not go into PortSentry mode. Shutting down.");
        Exit(EXIT_FAILURE);
      }
    } else {
      Error("Invalid sentry method specified. Shutting down.");
      Exit(EXIT_FAILURE);
    }
  } else if (configData.sentryMode == SENTRY_MODE_ATCP || configData.sentryMode == SENTRY_MODE_AUDP) {
    if (configData.sentryMethod == SENTRY_METHOD_PCAP) {
      if (PortSentryPcap() == ERROR) {
        Error("Could not go into PortSentry mode. Shutting down.");
        Exit(EXIT_FAILURE);
      }
    } else if (configData.sentryMethod == SENTRY_METHOD_RAW) {
      if (PortSentryAdvancedStealthMode() == ERROR) {
        Error("Could not go into PortSentry mode. Shutting down.");
        Exit(EXIT_FAILURE);
      }
    } else {
      Error("Invalid sentry method specified. Shutting down.");
      Exit(EXIT_FAILURE);
    }
  }

  Exit(EXIT_SUCCESS);
}
