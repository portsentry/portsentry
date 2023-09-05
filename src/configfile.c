#include <stdio.h>
#include <string.h>

#include "configfile.h"
#include "portsentry.h"
#include "portsentry_io.h"
#include "portsentry_util.h"
#include "config_data.h"

static void setConfiguration(char *buffer, size_t keySize, char *ptr, ssize_t valueSize, const size_t line, struct ConfigData *fileConfig, struct ConfigData *cmdlineConfig);
static char *skipSpaceAndTab(char *buffer);
static size_t getKeySize(char *buffer);
static void stripTrailingSpace(char *buffer);
static ssize_t getSizeToQuote(char *buffer);
void validateConfig(struct ConfigData *fileConfig);

struct ConfigData readConfigFile(struct ConfigData *cmdlineConfig) {
  struct ConfigData fileConfig;
  FILE *config;
  char buffer[MAXBUF], *ptr;
  size_t keySize, line = 0;
  ssize_t valueSize;

  ResetConfigData(&fileConfig);

  /* Set defaults */
  if (cmdlineConfig->sentryMode == SENTRY_MODE_ATCP || cmdlineConfig->sentryMode == SENTRY_MODE_AUDP) {
    strcpy(fileConfig.ports, "1024");
  }

  if ((config = fopen(cmdlineConfig->configFile, "r")) == NULL) {
    fprintf(stderr, "Cannot open config file: %s.\n", cmdlineConfig->configFile);
    Exit(EXIT_FAILURE);
  }

  while (fgets(buffer, MAXBUF, config) != NULL) {
    line++;

    if (buffer[0] == '#' || buffer[0] == '\n' || buffer[0] == '\r') { /* Skip comments and blank lines */
      continue;
    }

    stripTrailingSpace(buffer);

    if ((keySize = getKeySize(buffer)) == 0) {
      fprintf(stderr, "Invalid config file entry at line %lu\n", line);
      fclose(config);
      Exit(EXIT_FAILURE);
    }

    ptr = buffer + keySize;
    ptr = skipSpaceAndTab(ptr);

    if (*ptr != '=') {
      fprintf(stderr, "Invalid config file entry at line %lu\n", line);
      fclose(config);
      Exit(EXIT_FAILURE);
    }
    ptr++;

    ptr = skipSpaceAndTab(ptr);

    if (*ptr != '"') {
      fprintf(stderr, "Invalid config file entry at line %lu\n", line);
      fclose(config);
      Exit(EXIT_FAILURE);
    }
    ptr++;

    if ((valueSize = getSizeToQuote(ptr)) == ERROR) {
      fprintf(stderr, "Invalid config file entry at line %lu\n", line);
      fclose(config);
      Exit(EXIT_FAILURE);
    }

    setConfiguration(buffer, keySize, ptr, valueSize, line, &fileConfig, cmdlineConfig);
  }

  fclose(config);


  /* Add implied config file entries */
  if (cmdlineConfig->sentryMode == SENTRY_MODE_ATCP) {
    if (strlen(fileConfig.ports) == 0) {
      snprintf(fileConfig.ports, MAXBUF, "%d", ADVANCED_MODE_PORT_TCP);
    }
  } else if (cmdlineConfig->sentryMode == SENTRY_MODE_AUDP) {
    if (strlen(fileConfig.ports) == 0) {
      snprintf(fileConfig.ports, MAXBUF, "%d", ADVANCED_MODE_PORT_UDP);
    }
  }

  /* Make sure config is valid */
  validateConfig(&fileConfig);

  return fileConfig;
}

static void setConfiguration(char *buffer, size_t keySize, char *ptr, ssize_t valueSize, const size_t line, struct ConfigData *fileConfig, struct ConfigData *cmdlineConfig) {
#ifdef DEBUG
    fprintf(stderr, "setConfiguration: %s keySize: %lu valueSize: %ld sentryMode: %s\n", buffer, keySize, valueSize, GetSentryModeString(cmdlineConfig->sentryMode));
#endif

  if (strncmp(buffer, "BLOCK_TCP", keySize) == 0) {
    if (strncmp(ptr, "1", valueSize) == 0) {
      fileConfig->blockTCP = TRUE;
    } else if (strncmp(ptr, "0", valueSize) == 0) {
      fileConfig->blockTCP = FALSE;
    } else {
      fprintf(stderr, "Invalid config file entry for BLOCK_TCP\n");
      exit(1);
    }
  } else if (strncmp(buffer, "BLOCK_UDP", keySize) == 0) {
    if (strncmp(ptr, "1", valueSize) == 0) {
      fileConfig->blockUDP = TRUE;
    } else if (strncmp(ptr, "0", valueSize) == 0) {
      fileConfig->blockUDP = FALSE;
    } else {
      fprintf(stderr, "Invalid config file entry for BLOCK_UDP\n");
      exit(1);
    }
  } else if (strncmp(buffer, "RESOLVE_HOST", keySize) == 0) {
    if (strncmp(ptr, "1", valueSize) == 0) {
      fileConfig->resolveHost = TRUE;
    } else if (strncmp(ptr, "0", valueSize) == 0) {
      fileConfig->resolveHost = FALSE;
    } else {
      fprintf(stderr, "Invalid config file entry for RESOLVE_HOST\n");
      exit(1);
    }
  } else if (strncmp(buffer, "SCAN_TRIGGER", keySize) == 0) {
    fileConfig->configTriggerCount = getLong(ptr);

    if (fileConfig->configTriggerCount < 0) {
      fprintf(stderr, "Invalid config file entry for SCAN_TRIGGER\n");
      exit(1);
    }
  } else if (strncmp(buffer, "KILL_ROUTE", keySize) == 0) {
    if (copyPrintableString(ptr, fileConfig->killRoute, MAXBUF) == FALSE) {
      fprintf(stderr, "Unable to copy kill route\n");
      exit(1);
    }
  } else if (strncmp(buffer, "KILL_HOSTS_DENY", keySize) == 0) {
    if (copyPrintableString(ptr, fileConfig->killHostsDeny, MAXBUF) == FALSE) {
      fprintf(stderr, "Unable to copy kill hosts deny\n");
      exit(1);
    }
  } else if (strncmp(buffer, "KILL_RUN_CMD", keySize) == 0) {
    if (copyPrintableString(ptr, fileConfig->killRunCmd, MAXBUF) == FALSE) {
      fprintf(stderr, "Unable to copy kill run command\n");
      exit(1);
    }
  } else if (strncmp(buffer, "KILL_RUN_CMD_FIRST", keySize) == 0) {
    if (strncmp(ptr, "1", valueSize) == 0) {
      fileConfig->runCmdFirst = TRUE;
    } else if (strncmp(ptr, "0", valueSize) == 0) {
      fileConfig->runCmdFirst = FALSE;
    } else {
      fprintf(stderr, "Invalid config file entry for KILL_RUN_CMD_FIRST\n");
      exit(1);
    }
  } else if (strncmp(buffer, "BLOCKED_FILE", keySize) == 0) {
    if (copyPrintableString(ptr, fileConfig->blockedFile, PATH_MAX) == FALSE) {
      fprintf(stderr, "Unable to copy blocked file path\n");
      exit(1);
    }
    if (strlen(fileConfig->blockedFile) < (PATH_MAX - 5)) {
      strncat(fileConfig->blockedFile, ".", 1);
      strncat(fileConfig->blockedFile, GetSentryModeString(cmdlineConfig->sentryMode), 4);
    } else {
      fprintf(stderr, "Blocked filename is too long to append sentry mode file extension: %s\n", fileConfig->blockedFile);
      exit(1);
    }

    if (testFileAccess(fileConfig->blockedFile, "w") == FALSE) {
      fprintf(stderr, "Unable to open block file for writing: %s\n", fileConfig->blockedFile);
      exit(1);
    }
  } else if (strncmp(buffer, "HISTORY_FILE", keySize) == 0) {
    if (copyPrintableString(ptr, fileConfig->historyFile, PATH_MAX) == FALSE) {
      fprintf(stderr, "Unable to copy history file path\n");
      exit(1);
    }
  } else if (strncmp(buffer, "IGNORE_FILE", keySize) == 0) {
    if (copyPrintableString(ptr, fileConfig->ignoreFile, PATH_MAX) == FALSE) {
      fprintf(stderr, "Unable to copy ignore file path\n");
      exit(1);
    }
  } else if (strncmp(buffer, "TCP_PORTS", keySize) == 0) {
    if (cmdlineConfig->sentryMode == SENTRY_MODE_TCP || cmdlineConfig->sentryMode == SENTRY_MODE_STCP) {
      if (copyPrintableString(ptr, fileConfig->ports, MAXBUF) == FALSE) {
      fprintf(stderr, "Unable to copy TCP ports\n");
      exit(1);
      }
    }
  } else if (strncmp(buffer, "UDP_PORTS", keySize) == 0) {
    if (cmdlineConfig->sentryMode == SENTRY_MODE_UDP || cmdlineConfig->sentryMode == SENTRY_MODE_SUDP) {
      if (copyPrintableString(ptr, fileConfig->ports, MAXBUF) == FALSE) {
        fprintf(stderr, "Unable to copy UDP ports\n");
        exit(1);
      }
    }
  } else if (strncmp(buffer, "ADVANCED_PORTS_TCP", keySize) == 0) {
    if (cmdlineConfig->sentryMode == SENTRY_MODE_ATCP) {
      if (copyPrintableString(ptr, fileConfig->ports, MAXBUF) == FALSE) {
        fprintf(stderr, "Unable to copy advanced TCP ports\n");
        exit(1);
      }
    }
  } else if (strncmp(buffer, "ADVANCED_PORTS_UDP", keySize) == 0) {
    if (cmdlineConfig->sentryMode == SENTRY_MODE_AUDP) {
      if (copyPrintableString(ptr, fileConfig->ports, MAXBUF) == FALSE) {
        fprintf(stderr, "Unable to copy advanced UDP ports\n");
        exit(1);
      }
    }
  } else if (strncmp(buffer, "ADVANCED_EXCLUDE_TCP", keySize) == 0) {
    if (cmdlineConfig->sentryMode == SENTRY_MODE_ATCP) {
      if (copyPrintableString(ptr, fileConfig->advancedExclude, MAXBUF) == FALSE) {
        fprintf(stderr, "Unable to copy advanced exclude TCP ports\n");
        exit(1);
      }
    }
  } else if (strncmp(buffer, "ADVANCED_EXCLUDE_UDP", keySize) == 0) {
    if (cmdlineConfig->sentryMode == SENTRY_MODE_AUDP) {
      if (copyPrintableString(ptr, fileConfig->advancedExclude, MAXBUF) == FALSE) {
        fprintf(stderr, "Unable to copy advanced exclude UDP ports\n");
        exit(1);
      }
    }
  } else if (strncmp(buffer, "PORT_BANNER", keySize) == 0) {
    copyPrintableString(ptr, fileConfig->portBanner, MAXBUF);
  } else {
    fprintf(stderr, "Invalid config file entry at line %lu\n", line);
    exit(1);
  }
}

void validateConfig(struct ConfigData *fileConfig) {
  // FIXME: When validating configData.ports / configData.excludePorts, make sure the combination w/ configData.detectionType is valid
  // Advanced Ports: If not set, default to 1024
  // Wait with this function until the config file (and cmdline) is stored in a struct fulle parsed
#ifdef DEBUG
  fprintf(stderr, "blockTCP: %d\n", fileConfig->blockTCP);
  fprintf(stderr, "blockUDP: %d\n", fileConfig->blockUDP);
  fprintf(stderr, "resolveHost: %d\n", fileConfig->resolveHost);
  fprintf(stderr, "configTriggerCount: %u\n", fileConfig->configTriggerCount);
  fprintf(stderr, "killRoute: %s\n", fileConfig->killRoute);
  fprintf(stderr, "killHostsDeny: %s\n", fileConfig->killHostsDeny);
  fprintf(stderr, "killRunCmd: %s\n", fileConfig->killRunCmd);
  fprintf(stderr, "runCmdFirst: %d\n", fileConfig->runCmdFirst);
  fprintf(stderr, "ports: %s\n", fileConfig->ports);
  fprintf(stderr, "advancedExclude: %s\n", fileConfig->advancedExclude);
  fprintf(stderr, "portBanner: %s\n", fileConfig->portBanner);
  fprintf(stderr, "blockedFile: %s\n", fileConfig->blockedFile);
  fprintf(stderr, "historyFile: %s\n", fileConfig->historyFile);
  fprintf(stderr, "ignoreFile: %s\n", fileConfig->ignoreFile);
#endif
}

static char *skipSpaceAndTab(char *buffer) {
  char *ptr = buffer;

  while (*ptr == ' ' || *ptr == '\t') {
    ptr++;
  }

  return ptr;
}

static size_t getKeySize(char *buffer) {
  char *ptr = buffer;
  size_t keySize = 0;

  while (isupper(*ptr) || *ptr == '_') {
    ptr++;
    keySize++;
  }

  return keySize;
}

static void stripTrailingSpace(char *buffer) {
  char *ptr = buffer + strlen(buffer) - 1;

  if (ptr < buffer) {
    return;
  }

  while (isspace(*ptr)) {
    *ptr = '\0';

    if (ptr == buffer) {
      break;
    }
  }
}

static ssize_t getSizeToQuote(char *buffer) {
  char *ptr;
  ssize_t valueSize = 0;

  if ((ptr = strstr(buffer, "\"")) == NULL) {
    return ERROR;
  }

  valueSize = ptr - buffer;

  if (valueSize == 0) {
    return ERROR;
  }

  return valueSize;
}
