// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: BSD-2-Clause

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef FUZZ_CMDLINE
#include <setjmp.h>
#endif

#include "cmdline.h"
#include "config.h"
#include "config_data.h"
#include "io.h"
#include "portsentry.h"
#include "util.h"

#ifndef GIT_COMMIT_HASH
#define GIT_COMMIT_HASH "-"
#endif

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
#define CMDLINE_DISABLE_LOCAL_CHECK 'L'
#define CMDLINE_DISABLE_SERVICE_CHECK 'S'

static void Usage(void);

void ParseCmdline(const int argc, char **argv) {
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
      {"disable-local-check", no_argument, 0, CMDLINE_DISABLE_LOCAL_CHECK},
      {"disable-service-check", no_argument, 0, CMDLINE_DISABLE_SERVICE_CHECK},
      {"debug", no_argument, 0, CMDLINE_DEBUG},
      {"verbose", no_argument, 0, CMDLINE_VERBOSE},
      {"help", no_argument, 0, CMDLINE_HELP},
      {"version", no_argument, 0, CMDLINE_VERSION},
      {0, 0, 0, 0}};

  ResetConfigData(&cmdlineConfig);

  while (1) {
    int option_index = 0;
    opt = getopt_long(argc, argv, "l:c:t:s:a:u:i:m:DLSdvhV", long_options, &option_index);

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
    case CMDLINE_DISABLE_LOCAL_CHECK:
      cmdlineConfig.disableLocalCheck = TRUE;
      break;
    case CMDLINE_DISABLE_SERVICE_CHECK:
      cmdlineConfig.disableServiceCheck = TRUE;
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
      exit(EXIT_SUCCESS);
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
  printf("Portsentry - Port Scan Detector.\n");
  printf("Usage: portsentry [--stealth, --connect] <options>\n\n");
  printf("--stealth\tUse Stealth mode (default)\n");
  printf("--connect\tUse Connect mode\n");
#ifdef USE_PCAP
  printf("--interface, -i <interface> - Set interface to listen on. Use ALL for all interfaces, ALL_NLO for all interfaces except loopback (default: ALL_NLO)\n");
#endif
  printf("--logoutput, -l [stdout|syslog] - Set Log output (default to stdout)\n");
  printf("--configfile, -c <path> - Set config file path\n");
  printf("--method, -m\t[pcap|raw] - Set sentry method to use the stealth mode. Use libpcap or linux raw sockets (only available on linux) (default: pcap)\n");
  printf("--disable-local-check, -L\tIf source and destination address are the same we don't do any actions. This option disables this check\n");
  printf("--disable-service-check, -S\tBy default, packets to a destination port where a service is already running are ignored. This option disables that check so detection runs on every port\n");
  printf("--daemon, -D\tRun as a daemon\n");
  printf("--debug, -d\tEnable debugging output\n");
  printf("--verbose, -v\tEnable verbose output\n");
  printf("--help, -h\tDisplay this help message\n");
  printf("--version, -V\tDisplay version information\n");
  Exit(EXIT_SUCCESS);
}

void Version(void) {
  printf("Portsentry %d.%d.%d (%s)\n", PORTSENTRY_VERSION_MAJOR, PORTSENTRY_VERSION_MINOR, PORTSENTRY_VERSION_PATCH, GIT_COMMIT_HASH);
}

#ifdef FUZZ_CMDLINE
/* libFuzzer harness for ParseCmdline().
 *
 * ParseCmdline() reaches Exit() (which calls libc exit()), a raw exit() on the
 * version path, and Usage()->Exit() on almost every malformed argument vector.
 * We intercept libc exit via the linker (-Wl,--wrap=exit) and longjmp back here
 * when inside an iteration, so the fuzzer keeps running instead of terminating.
 *
 * getopt keeps global parsing state across calls; it is reset every iteration.
 * Allocations that ParseCmdline() places in the (local) cmdlineConfig before an
 * Exit() are unreachable after the longjmp; LeakSanitizer is disabled around
 * the call so these intentional exit-path leaks are not reported, and the
 * successful-parse interfaces in the global configData are freed each iteration
 * to keep RSS bounded. */

#define FUZZ_MAX_ARGS 64

extern void __real_exit(int status);

/* Provided by the AddressSanitizer/LeakSanitizer runtime. Declared weak so the
 * OpenBSD fuzzer build (fuzzer without address sanitizer) still links. */
__attribute__((weak)) void __lsan_disable(void);
__attribute__((weak)) void __lsan_enable(void);

static jmp_buf g_fuzzCmdlineJmp;
static int g_fuzzInIteration = 0;

void __wrap_exit(int status) {
  if (g_fuzzInIteration) {
    longjmp(g_fuzzCmdlineJmp, status == 0 ? 1 : status);
  }
  __real_exit(status);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  ResetConfigData(&configData);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  char buffer[4096];
  char *argv[FUZZ_MAX_ARGS + 1];
  int argc = 0;
  size_t i, start, len;

  len = (Size < sizeof(buffer) - 1) ? Size : sizeof(buffer) - 1;
  memcpy(buffer, Data, len);
  buffer[len] = '\0';

  /* Synthetic program name in argv[0], as getopt expects. */
  argv[argc++] = (char *)"portsentry";

  /* Split the input on NUL bytes into NUL-terminated argv tokens. */
  start = 0;
  for (i = 0; i <= len && argc < FUZZ_MAX_ARGS; i++) {
    if (i == len || buffer[i] == '\0') {
      if (i > start) {
        argv[argc++] = &buffer[start];
      }
      start = i + 1;
    }
  }
  argv[argc] = NULL;

  /* Reset getopt's global parsing state before each run. */
#ifdef BSD
  optreset = 1;
  optind = 1;
#else
  optind = 0; /* glibc/musl: forces full reinitialization */
#endif

  if (__lsan_disable) {
    __lsan_disable();
  }

  if (setjmp(g_fuzzCmdlineJmp) == 0) {
    g_fuzzInIteration = 1;
    ParseCmdline(argc, argv);
  }
  g_fuzzInIteration = 0;

  if (__lsan_enable) {
    __lsan_enable();
  }

  /* Free interfaces copied into configData by a successful parse. */
  FreeConfigData(&configData);
  return 0;
}
#endif
