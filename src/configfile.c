#include <stdio.h>
#include <string.h>

#include "configfile.h"
#include "portsentry.h"
#include "portsentry_io.h"
#include "portsentry_util.h"
#include "config_data.h"

static void setConfiguration(char *buffer, size_t keySize, char *ptr, ssize_t valueSize, const size_t line);
static char *skipSpaceAndTab(char *buffer);
static size_t getKeySize(char *buffer);
static void stripTrailingSpace(char *buffer);
static ssize_t getSizeToQuote(char *buffer);
void validateConfig(void);

struct ConfigData readConfigFile(void) {
  struct ConfigData fileConfig;
  FILE *config;
  char buffer[MAXBUF], *ptr;
  size_t keySize, line = 0;
  ssize_t valueSize;

  ResetConfigData(&fileConfig);

  /* Set defaults */
  if (configData.sentryMode == SENTRY_MODE_ATCP || configData.sentryMode == SENTRY_MODE_AUDP) {
    strcpy(fileConfig.ports, "1024");
  }

  if ((config = fopen(configData.configFile, "r")) == NULL) {
    Log("adminalert: ERROR: Cannot open config file: %s.\n", configData.configFile);
    Exit(EXIT_FAILURE);
  }

  while (fgets(buffer, MAXBUF, config) != NULL) {
    line++;

    if (buffer[0] == '#' || buffer[0] == '\n' || buffer[0] == '\r') { /* Skip comments and blank lines */
      continue;
    }

    stripTrailingSpace(buffer);

    if ((keySize = getKeySize(buffer)) == 0) {
      Log("adminalert: ERROR: Invalid config file entry at line %lu\n", line);
      fclose(config);
      Exit(EXIT_FAILURE);
    }

    ptr = buffer + keySize;
    ptr = skipSpaceAndTab(ptr);

    if (*ptr != '=') {
      Log("adminalert: ERROR: Invalid config file entry at line %lu\n", line);
      fclose(config);
      Exit(EXIT_FAILURE);
    }
    ptr++;

    ptr = skipSpaceAndTab(ptr);

    if (*ptr != '"') {
      Log("adminalert: ERROR: Invalid config file entry at line %lu\n", line);
      fclose(config);
      Exit(EXIT_FAILURE);
    }
    ptr++;

    if ((valueSize = getSizeToQuote(ptr)) == ERROR) {
      Log("adminalert: ERROR: Invalid config file entry at line %lu\n", line);
      fclose(config);
      Exit(EXIT_FAILURE);
    }

    setConfiguration(buffer, keySize, ptr, valueSize, line);
  }

  fclose(config);


  /* Add implied config file entries */
  if (configData.sentryMode == SENTRY_MODE_ATCP) {
    if (strlen(configData.ports) == 0) {
      snprintf(configData.ports, MAXBUF, "%d", ADVANCED_MODE_PORT_TCP);
    }
  } else if (configData.sentryMode == SENTRY_MODE_AUDP) {
    if (strlen(configData.ports) == 0) {
      snprintf(configData.ports, MAXBUF, "%d", ADVANCED_MODE_PORT_UDP);
    }
  }

  /* Make sure config is valid */
  validateConfig();
}

static void setConfiguration(char *buffer, size_t keySize, char *ptr, ssize_t valueSize, const size_t line) {
#ifdef DEBUG
    Log("debug: setConfiguration: %s keySize: %u valueSize: %d configData.sentryMode: %s", buffer, keySize, valueSize, GetSentryModeString(configData.sentryMode));
#endif

  if (strncmp(buffer, "BLOCK_TCP", keySize) == 0) {
    if (strncmp(ptr, "1", valueSize) == 0) {
      configData.blockTCP = TRUE;
    } else if (strncmp(ptr, "0", valueSize) == 0) {
      configData.blockTCP = FALSE;
    } else {
      Log("adminalert: ERROR: Invalid config file entry for BLOCK_TCP\n");
      exit(1);
    }
  } else if (strncmp(buffer, "BLOCK_UDP", keySize) == 0) {
    if (strncmp(ptr, "1", valueSize) == 0) {
      configData.blockUDP = TRUE;
    } else if (strncmp(ptr, "0", valueSize) == 0) {
      configData.blockUDP = FALSE;
    } else {
      Log("adminalert: ERROR: Invalid config file entry for BLOCK_UDP\n");
      exit(1);
    }
  } else if (strncmp(buffer, "RESOLVE_HOST", keySize) == 0) {
    if (strncmp(ptr, "1", valueSize) == 0) {
      configData.resolveHost = TRUE;
    } else if (strncmp(ptr, "0", valueSize) == 0) {
      configData.resolveHost = FALSE;
    } else {
      Log("adminalert: ERROR: Invalid config file entry for RESOLVE_HOST\n");
      exit(1);
    }
  } else if (strncmp(buffer, "SCAN_TRIGGER", keySize) == 0) {
    configData.configTriggerCount = getLong(ptr);

    if (configData.configTriggerCount < 0) {
      Log("adminalert: ERROR: Invalid config file entry for SCAN_TRIGGER\n");
      exit(1);
    }
  } else if (strncmp(buffer, "KILL_ROUTE", keySize) == 0) {
    if (copyPrintableString(ptr, configData.killRoute, MAXBUF) == FALSE) {
      Log("adminalert: ERROR: Unable to copy kill route\n");
      exit(1);
    }
  } else if (strncmp(buffer, "KILL_HOSTS_DENY", keySize) == 0) {
    if (copyPrintableString(ptr, configData.killHostsDeny, MAXBUF) == FALSE) {
      Log("adminalert: ERROR: Unable to copy kill hosts deny\n");
      exit(1);
    }
  } else if (strncmp(buffer, "KILL_RUN_CMD", keySize) == 0) {
    if (copyPrintableString(ptr, configData.killRunCmd, MAXBUF) == FALSE) {
      Log("adminalert: ERROR: Unable to copy kill run command\n");
      exit(1);
    }
  } else if (strncmp(buffer, "KILL_RUN_CMD_FIRST", keySize) == 0) {
    if (strncmp(ptr, "1", valueSize) == 0) {
      configData.runCmdFirst = TRUE;
    } else if (strncmp(ptr, "0", valueSize) == 0) {
      configData.runCmdFirst = FALSE;
    } else {
      Log("adminalert: ERROR: Invalid config file entry for KILL_RUN_CMD_FIRST\n");
      exit(1);
    }
  } else if (strncmp(buffer, "BLOCKED_FILE", keySize) == 0) {
    if (copyPrintableString(ptr, configData.blockedFile, PATH_MAX) == FALSE) {
      Log("adminalert: ERROR: Unable to copy blocked file path\n");
      exit(1);
    }
    if (strlen(configData.blockedFile) < (PATH_MAX - 5)) {
      strncat(configData.blockedFile, ".", 1);
      strncat(configData.blockedFile, GetSentryModeString(configData.sentryMode), 4);
    } else {
      Log("adminalert: ERROR: Blocked filename is too long to append sentry mode file extension: %s\n", configData.blockedFile);
      exit(1);
    }

    if (testFileAccess(configData.blockedFile, "w") == FALSE) {
      Log("adminalert: ERROR: Unable to open block file for writing: %s\n", configData.blockedFile);
      exit(1);
    }
  } else if (strncmp(buffer, "HISTORY_FILE", keySize) == 0) {
    if (copyPrintableString(ptr, configData.historyFile, PATH_MAX) == FALSE) {
      Log("adminalert: ERROR: Unable to copy history file path\n");
      exit(1);
    }
  } else if (strncmp(buffer, "IGNORE_FILE", keySize) == 0) {
    if (copyPrintableString(ptr, configData.ignoreFile, PATH_MAX) == FALSE) {
      Log("adminalert: ERROR: Unable to copy ignore file path\n");
      exit(1);
    }
  } else if (strncmp(buffer, "TCP_PORTS", keySize) == 0) {
    if (configData.sentryMode == SENTRY_MODE_TCP || configData.sentryMode == SENTRY_MODE_STCP) {
      if (copyPrintableString(ptr, configData.ports, MAXBUF) == FALSE) {
      Log("adminalert: ERROR: Unable to copy TCP ports\n");
      exit(1);
      }
    }
  } else if (strncmp(buffer, "UDP_PORTS", keySize) == 0) {
    if (configData.sentryMode == SENTRY_MODE_UDP || configData.sentryMode == SENTRY_MODE_SUDP) {
      if (copyPrintableString(ptr, configData.ports, MAXBUF) == FALSE) {
        Log("adminalert: ERROR: Unable to copy UDP ports\n");
        exit(1);
      }
    }
  } else if (strncmp(buffer, "ADVANCED_PORTS_TCP", keySize) == 0) {
    if (configData.sentryMode == SENTRY_MODE_ATCP) {
      if (copyPrintableString(ptr, configData.ports, MAXBUF) == FALSE) {
        Log("adminalert: ERROR: Unable to copy advanced TCP ports\n");
        exit(1);
      }
    }
  } else if (strncmp(buffer, "ADVANCED_PORTS_UDP", keySize) == 0) {
    if (configData.sentryMode == SENTRY_MODE_AUDP) {
      if (copyPrintableString(ptr, configData.ports, MAXBUF) == FALSE) {
        Log("adminalert: ERROR: Unable to copy advanced UDP ports\n");
        exit(1);
      }
    }
  } else if (strncmp(buffer, "ADVANCED_EXCLUDE_TCP", keySize) == 0) {
    if (configData.sentryMode == SENTRY_MODE_ATCP) {
      if (copyPrintableString(ptr, configData.advancedExclude, MAXBUF) == FALSE) {
        Log("adminalert: ERROR: Unable to copy advanced exclude TCP ports\n");
        exit(1);
      }
    }
  } else if (strncmp(buffer, "ADVANCED_EXCLUDE_UDP", keySize) == 0) {
    if (configData.sentryMode == SENTRY_MODE_AUDP) {
      if (copyPrintableString(ptr, configData.advancedExclude, MAXBUF) == FALSE) {
        Log("adminalert: ERROR: Unable to copy advanced exclude UDP ports\n");
        exit(1);
      }
    }
  } else if (strncmp(buffer, "PORT_BANNER", keySize) == 0) {
    copyPrintableString(ptr, configData.portBanner, MAXBUF);
  } else {
    Log("adminalert: ERROR: Invalid config file entry at line %lu\n", line);
    exit(1);
  }
}

void validateConfig(void) {
  // FIXME: When validating configData.ports / configData.excludePorts, make sure the combination w/ configData.detectionType is valid
  // Advanced Ports: If not set, default to 1024
  // Wait with this function until the config file (and cmdline) is stored in a struct fulle parsed
#ifdef DEBUG
  Log("debug: configData.blockTCP: %d\n", configData.blockTCP);
  Log("debug: configData.blockUDP: %d\n", configData.blockUDP);
  Log("debug: configData.resolveHost: %d\n", configData.resolveHost);
  Log("debug: configData.configTriggerCount: %u\n", configData.configTriggerCount);
  Log("debug: configData.killRoute: %s\n", configData.killRoute);
  Log("debug: configData.killHostsDeny: %s\n", configData.killHostsDeny);
  Log("debug: configData.killRunCmd: %s\n", configData.killRunCmd);
  Log("debug: configData.runCmdFirst: %d\n", configData.runCmdFirst);
  Log("debug: configData.ports: %s\n", configData.ports);
  Log("debug: configData.advancedExclude: %s\n", configData.advancedExclude);
  Log("debug: configData.portBanner: %s\n", configData.portBanner);
  Log("debug: configData.blockedFile: %s\n", configData.blockedFile);
  Log("debug: configData.historyFile: %s\n", configData.historyFile);
  Log("debug: configData.ignoreFile: %s\n", configData.ignoreFile);
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
