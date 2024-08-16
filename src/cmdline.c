// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cmdline.h"
#include "config.h"
#include "config_data.h"
#include "io.h"
#include "portsentry.h"
#include "util.h"

#define CMDLINE_CONNECT 0
#define CMDLINE_STEALTH 1
#define CMDLINE_LOGOUTPUT 'l'
#define CMDLINE_CONFIGFILE 'c'
#define CMDLINE_DAEMON 'D'
#define CMDLINE_DEBUG 'd'
#define CMDLINE_VERBOSE 'v'
#define CMDLINE_HELP 'h'
#define CMDLINE_VERSION 'V'
#define CMDLINE_INTERFACE 'i'
#define CMDLINE_METHOD 'm'

static void Usage(void);
static void Version(void);

void ParseCmdline(int argc, char **argv) {
  int opt;
  uint8_t ifFlagAll = FALSE, ifFlagNlo = FALSE, ifFlagOther = FALSE, flagModeSet = FALSE;
  struct ConfigData cmdlineConfig;
  const struct option long_options[] = {
      {"connect", no_argument, 0, CMDLINE_CONNECT},
      {"stealth", no_argument, 0, CMDLINE_STEALTH},
#ifdef USE_PCAP
      {"interface", required_argument, 0, CMDLINE_INTERFACE},
#endif
      {"logoutput", required_argument, 0, CMDLINE_LOGOUTPUT},
      {"configfile", required_argument, 0, CMDLINE_CONFIGFILE},
      {"daemon", no_argument, 0, CMDLINE_DAEMON},
      {"method", required_argument, 0, CMDLINE_METHOD},
      {"debug", no_argument, 0, CMDLINE_DEBUG},
      {"verbose", no_argument, 0, CMDLINE_VERBOSE},
      {"help", no_argument, 0, CMDLINE_HELP},
      {"version", no_argument, 0, CMDLINE_VERSION},
      {0, 0, 0, 0}};

  ResetConfigData(&cmdlineConfig);

  while (1) {
    int option_index = 0;
    opt = getopt_long(argc, argv, "l:c:t:s:a:u:i:m:DdvhV", long_options, &option_index);

    if (opt >= CMDLINE_CONNECT && opt <= CMDLINE_STEALTH && flagModeSet == TRUE) {
      fprintf(stderr, "Error: Only one mode can be specified, Use only one of --stealth or --connect\n");
      Exit(EXIT_FAILURE);
    } else if (opt == -1) {
      break;
    }

    switch (opt) {
    case CMDLINE_CONNECT:
      cmdlineConfig.sentryMode = SENTRY_MODE_CONNECT;
      flagModeSet = TRUE;
      break;
    case CMDLINE_STEALTH:
      cmdlineConfig.sentryMode = SENTRY_MODE_STEALTH;
      flagModeSet = TRUE;
      break;
    case CMDLINE_INTERFACE:
      if (strncmp(optarg, "ALL", 5) == 0) {
        ifFlagAll = TRUE;
      } else if (strncmp(optarg, "ALL_NLO", 9) == 0) {
        ifFlagNlo = TRUE;
      } else {
        ifFlagOther = TRUE;
      }

      if ((ifFlagAll && ifFlagNlo) || (ifFlagNlo && ifFlagOther) || (ifFlagOther && ifFlagAll)) {
        fprintf(stderr, "Error: Only one interface type can be specified (ALL, ALL_NLO or interfaces)\n");
        Exit(EXIT_FAILURE);
      }
      AddInterface(&cmdlineConfig, optarg);
      break;
    case CMDLINE_LOGOUTPUT:
      if (strcmp(optarg, "stdout") == 0) {
        cmdlineConfig.logFlags |= LOGFLAG_OUTPUT_STDOUT;
      } else if (strcmp(optarg, "syslog") == 0) {
        cmdlineConfig.logFlags |= LOGFLAG_OUTPUT_SYSLOG;
      } else {
        fprintf(stderr, "Error: Invalid log output specified\n");
        Exit(EXIT_FAILURE);
      }
      break;
    case CMDLINE_CONFIGFILE:
      if (strlen(optarg) >= (sizeof(cmdlineConfig.configFile) - 1)) {
        fprintf(stderr, "Error: Config file path too long\n");
        Exit(EXIT_FAILURE);
      }
      SafeStrncpy(cmdlineConfig.configFile, optarg, sizeof(cmdlineConfig.configFile));
      break;
    case CMDLINE_METHOD:
      if (strncmp(optarg, "raw", 3) == 0) {
        cmdlineConfig.sentryMethod = SENTRY_METHOD_RAW;
#ifdef USE_PCAP
      } else if (strncmp(optarg, "pcap", 4) == 0) {
        cmdlineConfig.sentryMethod = SENTRY_METHOD_PCAP;
#endif
      } else {
        fprintf(stderr, "Error: Invalid sentry method specified\n");
        Exit(EXIT_FAILURE);
      }
      break;
    case CMDLINE_DAEMON:
      cmdlineConfig.daemon = TRUE;
      break;
    case CMDLINE_DEBUG:
      cmdlineConfig.logFlags |= LOGFLAG_DEBUG;
      break;
    case CMDLINE_VERBOSE:
      cmdlineConfig.logFlags |= LOGFLAG_VERBOSE;
      break;
    case CMDLINE_HELP:
      Usage();
      break;
    case CMDLINE_VERSION:
      Version();
      break;
    default:
      printf("Unknown argument, getopt returned character code 0%o\n", opt);
      Exit(EXIT_FAILURE);
      break;
    }
  }

#ifdef BSD
  if (cmdlineConfig.sentryMethod == SENTRY_METHOD_RAW) {
    fprintf(stderr, "Error: Raw sockets not supported on BSD\n");
    Exit(EXIT_FAILURE);
  }
#endif

  PostProcessConfig(&cmdlineConfig);

  if (cmdlineConfig.logFlags & LOGFLAG_DEBUG) {
    printf("debug: Command Line Configuration:\n");
    PrintConfigData(cmdlineConfig);
  }

  // Set the global config to the values gotten from the command line
  memcpy(&configData, &cmdlineConfig, sizeof(struct ConfigData));
}

static void Usage(void) {
  printf("PortSentry - Port Scan Detector.\n");
  printf("Usage: portsentry [--stealth, --connect] <options>\n\n");
  printf("--stealth\tUse Stealth mode (default)\n");
  printf("--connect\tUse Connect mode\n");
#ifdef USE_PCAP
  printf("--interface, -i <interface> - Set interface to listen on. Use ALL for all interfaces, ALL_NLO for all interfaces except loopback (default: ALL_NLO)\n");
#endif
  printf("--logoutput, -l [stdout|syslog] - Set Log output (default to stdout)\n");
  printf("--configfile, -c <path> - Set config file path\n");
  printf("--method, -m\t[pcap|raw] - Set sentry method to use the stealth mode. Use libpcap or linux raw sockets (only available on linux) (default: pcap)\n");
  printf("--daemon, -D\tRun as a daemon\n");
  printf("--debug, -d\tEnable debugging output\n");
  printf("--verbose, -v\tEnable verbose output\n");
  printf("--help, -h\tDisplay this help message\n");
  printf("--version, -V\tDisplay version information\n");
  Exit(EXIT_SUCCESS);
}

static void Version(void) {
  printf("Portsentry version %d.%d\n", PORTSENTRY_VERSION_MAJOR, PORTSENTRY_VERSION_MINOR);
  Exit(EXIT_SUCCESS);
}
