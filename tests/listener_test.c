// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../src/cmdline.h"
#include "../src/config_data.h"
#include "../src/configfile.h"
#include "../src/sentry_connect.h"
#include "../src/io.h"
#include "../src/portsentry.h"
#include "../src/state_machine.h"
#include "../src/sentry_stealth.h"
#include "../src/util.h"

int main(int argc, char *argv[]) {
  ParseCmdline(argc, argv);

  signal(SIGPIPE, SIG_IGN);

  if ((geteuid()) && (getuid()) != 0) {
    printf("You need to be root to run this.\n");
    Exit(EXIT_FAILURE);
  }

  return EXIT_SUCCESS;
}
