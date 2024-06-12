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

#define CMDLINE_TCP 0
#define CMDLINE_STCP 1
#define CMDLINE_ATCP 2
#define CMDLINE_UDP 3
#define CMDLINE_SUDP 4
#define CMDLINE_AUDP 5
#define CMDLINE_LOGOUTPUT 'l'
#define CMDLINE_CONFIGFILE 'c'
#define CMDLINE_DAEMON 'D'
#define CMDLINE_DEBUG 'd'
#define CMDLINE_VERBOSE 'v'
#define CMDLINE_HELP 'h'
#define CMDLINE_VERSION 'V'
#define CMDLINE_INTERFACE 'i'
#define CMDLINE_METHOD 'm'

// FIXME: Hack for now since NetBSD doesn't have getopt_long_only
#define CMDLINE_SHORT_TCP 't'
#define CMDLINE_SHORT_STEALTH 's'
#define CMDLINE_SHORT_ADVANCED 'a'
#define CMDLINE_SHORT_UDP 'u'

static void Usage(void);
static void Version(void);

void ParseCmdline(int argc, char **argv) {
  int opt;
  uint8_t ifFlagAll = FALSE, ifFlagNlo = FALSE, ifFlagOther = FALSE;
  struct ConfigData cmdlineConfig;
  const struct option long_options[] = {
      {"tcp", no_argument, 0, CMDLINE_TCP},
      {"stcp", no_argument, 0, CMDLINE_STCP},
      {"atcp", no_argument, 0, CMDLINE_ATCP},
      {"udp", no_argument, 0, CMDLINE_UDP},
      {"sudp", no_argument, 0, CMDLINE_SUDP},
      {"audp", no_argument, 0, CMDLINE_AUDP},
      {"interface", required_argument, 0, CMDLINE_INTERFACE},
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

    if (opt >= CMDLINE_TCP && opt <= CMDLINE_AUDP && cmdlineConfig.sentryMode != SENTRY_MODE_NONE) {
      fprintf(stderr, "Error: Only one mode can be specified\n");
      Exit(EXIT_FAILURE);
    } else if (opt == -1) {
      break;
    }

    switch (opt) {
    case CMDLINE_TCP:
      cmdlineConfig.sentryMode = SENTRY_MODE_TCP;
      break;
    case CMDLINE_STCP:
      cmdlineConfig.sentryMode = SENTRY_MODE_STCP;
      break;
    case CMDLINE_ATCP:
      cmdlineConfig.sentryMode = SENTRY_MODE_ATCP;
      break;
    case CMDLINE_UDP:
      cmdlineConfig.sentryMode = SENTRY_MODE_UDP;
      break;
    case CMDLINE_SUDP:
      cmdlineConfig.sentryMode = SENTRY_MODE_SUDP;
      break;
    case CMDLINE_AUDP:
      cmdlineConfig.sentryMode = SENTRY_MODE_AUDP;
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
      if (strncmp(optarg, "pcap", 4) == 0) {
        cmdlineConfig.sentryMethod = SENTRY_METHOD_PCAP;
      } else if (strncmp(optarg, "raw", 3) == 0) {
        cmdlineConfig.sentryMethod = SENTRY_METHOD_RAW;
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
    case CMDLINE_SHORT_TCP:
      cmdlineConfig.sentryMode = SENTRY_MODE_TCP;
      break;
    case CMDLINE_SHORT_STEALTH:
      if (strncmp(optarg, "tcp", 3) == 0) {
        cmdlineConfig.sentryMode = SENTRY_MODE_STCP;
      } else if (strncmp(optarg, "udp", 3) == 0) {
        cmdlineConfig.sentryMode = SENTRY_MODE_SUDP;
      } else {
        fprintf(stderr, "Error: Invalid stealth mode specified\n");
        Exit(EXIT_FAILURE);
      }
      break;
    case CMDLINE_SHORT_ADVANCED:
      if (strncmp(optarg, "tcp", 3) == 0) {
        cmdlineConfig.sentryMode = SENTRY_MODE_ATCP;
      } else if (strncmp(optarg, "udp", 3) == 0) {
        cmdlineConfig.sentryMode = SENTRY_MODE_AUDP;
      } else {
        fprintf(stderr, "Error: Invalid advanced mode specified\n");
        Exit(EXIT_FAILURE);
      }
      break;
    case CMDLINE_SHORT_UDP:
      cmdlineConfig.sentryMode = SENTRY_MODE_UDP;
      break;
    default:
      printf("Unknown argument, getopt returned character code 0%o\n", opt);
      Exit(EXIT_FAILURE);
      break;
    }
  }

  if (cmdlineConfig.sentryMode == SENTRY_MODE_NONE) {
    fprintf(stderr, "Error: No sentry mode specified\n");
    Exit(EXIT_FAILURE);
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
  printf("Usage: portsentry [-tcp -udp -stcp -atcp -sudp -audp] <options>\n\n");
  printf("--tcp, -tcp\tSet TCP mode\n");
  printf("--stcp, -stcp\tSet Stealth TCP mode\n");
  printf("--atcp, -atcp\tSet Advanced TCP mode\n");
  printf("--udp, -udp\tSet UDP mode\n");
  printf("--sudp, -sudp\tSet Stealth UDP mode\n");
  printf("--audp, -audp\tSet Advanced UDP mode\n");
  printf("--interface, -i <interface> - Set interface to listen on. Use ALL for all interfaces, ALL_NLO for all interfaces except loopback (default: ALL_NLO)\n");
  printf("--logoutput, -l [stdout|syslog] - Set Log output (default to stdout)\n");
  printf("--configfile, -c <path> - Set config file path\n");
  printf("--method, -m\t[pcap|raw] - Set sentry method. Use libpcap or linux raw sockets (only available on linux) (default: pcap)\n");
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
