#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#include "portsentry.h"
#include "portsentry_util.h"
#include "cmdline.h"
#include "config_data.h"

#define CMDLINE_TCP   0
#define CMDLINE_STCP  1
#define CMDLINE_ATCP  2
#define CMDLINE_UDP   3
#define CMDLINE_SUDP  4
#define CMDLINE_AUDP  5
#define CMDLINE_LOGOUTPUT 'l'
#define CMDLINE_CONFIGFILE 'c'
#define CMDLINE_DAEMON    'D'
#define CMDLINE_DEBUG     'd'
#define CMDLINE_VERBOSE   'v'
#define CMDLINE_HELP      'h'
#define CMDLINE_VERSION   'V'

static void Usage(void);
static void Version(void);

void ParseCmdline(int argc, char **argv) {
  int opt;
  struct ConfigData cmdlineConfig;
  const struct option long_options[] = {
    {"tcp", no_argument, 0, CMDLINE_TCP},
    {"stcp", no_argument, 0, CMDLINE_STCP},
    {"atcp", no_argument, 0, CMDLINE_ATCP},
    {"udp", no_argument, 0, CMDLINE_UDP},
    {"sudp", no_argument, 0, CMDLINE_SUDP},
    {"audp", no_argument, 0, CMDLINE_AUDP},
    {"logoutput", required_argument, 0, CMDLINE_LOGOUTPUT},
    {"configfile", required_argument, 0, CMDLINE_CONFIGFILE},
    {"daemon", no_argument, 0, CMDLINE_DAEMON},
    {"debug", no_argument, 0, CMDLINE_DEBUG},
    {"verbose", no_argument, 0, CMDLINE_VERBOSE},
    {"help", no_argument, 0, CMDLINE_HELP},
    {"version", no_argument, 0, CMDLINE_VERSION},
    {0, 0, 0, 0}
  };

  ResetConfigData(&cmdlineConfig);

  while (1) {
    int option_index = 0;
    opt = getopt_long_only(argc, argv, "l:c:DdvhV", long_options, &option_index);

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
        if(strlen(optarg) >= (sizeof(cmdlineConfig.configFile) - 1)) {
          fprintf(stderr, "Error: Config file path too long\n");
          Exit(EXIT_FAILURE);
        }
        SafeStrncpy(cmdlineConfig.configFile, optarg, sizeof(cmdlineConfig.configFile));
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

  if (cmdlineConfig.sentryMode == SENTRY_MODE_NONE) {
    fprintf(stderr, "Error: No sentry mode specified\n");
    Exit(EXIT_FAILURE);
  }

  PostProcessConfig(&cmdlineConfig);

  if (cmdlineConfig.logFlags & LOGFLAG_DEBUG) {
    printf("Command Line Configuration:\n");
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
  printf("--logoutput, -l [stdout|syslog] - Set Log output (default to stdout)\n");
  printf("--configfile, -c <path> - Set config file path\n");
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
