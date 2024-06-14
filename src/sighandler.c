// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#include <stdio.h>
#include <signal.h>
#include <stdint.h>

#include "portsentry.h"

extern uint8_t g_isRunning;

void ExitSignalHandler(int signum);

int SetupSignalHandlers(void) {
  struct sigaction sa;
  signal(SIGPIPE, SIG_IGN);

  sa.sa_handler = ExitSignalHandler;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);

  if (sigaction(SIGINT, &sa, NULL) == -1) {
    perror("sigaction SIGINT");
    return FALSE;
  }
  if (sigaction(SIGTERM, &sa, NULL) == -1) {
    perror("sigaction SIGTERM");
    return FALSE;
  }

  return TRUE;
}

void ExitSignalHandler(int signum) {
  (void)signum;
  g_isRunning = FALSE;
}
