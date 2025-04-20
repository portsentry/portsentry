// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config_data.h"
#include "configfile.h"
#include "io.h"
#include "portsentry.h"
#include "util.h"
#include "port.h"

static void SetConfiguration(const char *buffer, const size_t keySize, char *ptr, const ssize_t valueSize, const size_t line, struct ConfigData *fileConfig);
static void ValidateConfig(struct ConfigData *fileConfig);
static void MergeToConfigData(struct ConfigData *fileConfig);
static char *SkipSpaceAndTab(char *buffer);
static size_t GetKeySize(char *buffer);
static void StripTrailingSpace(char *buffer);
static ssize_t GetSizeToQuote(const char *buffer);
static int ParsePortsList(char *str, struct Port **ports, int *portsLength);

void ReadConfigFile(void) {
  struct ConfigData fileConfig;
  FILE *config;
  char buffer[MAXBUF], *ptr;
  size_t keySize, line = 0;
  ssize_t valueSize;

  ResetConfigData(&fileConfig);

  if ((config = fopen(configData.configFile, "r")) == NULL) {
    fprintf(stderr, "Cannot open config file: %s.\n", configData.configFile);
    Exit(EXIT_FAILURE);
  }

  while (fgets(buffer, MAXBUF, config) != NULL) {
    line++;

    if (buffer[0] == '#' || buffer[0] == '\n' || buffer[0] == '\r') { /* Skip comments and blank lines */
      continue;
    }

    StripTrailingSpace(buffer);

    if ((keySize = GetKeySize(buffer)) == 0) {
      fprintf(stderr, "Invalid config file entry at line %lu\n", line);
      fclose(config);
      Exit(EXIT_FAILURE);
    }

    ptr = buffer + keySize;
    ptr = SkipSpaceAndTab(ptr);

    if (*ptr != '=') {
      fprintf(stderr, "Invalid character found after config key. Require equals (=) after key. Line %lu\n", line);
      fclose(config);
      Exit(EXIT_FAILURE);
    }
    ptr++;

    ptr = SkipSpaceAndTab(ptr);

    if (*ptr != '"') {
      fprintf(stderr, "Invalid value on line %lu, require quote character (\") to start value\n", line);
      fclose(config);
      Exit(EXIT_FAILURE);
    }
    ptr++;

    if ((valueSize = GetSizeToQuote(ptr)) == ERROR) {
      fprintf(stderr, "Invalid value at line %lu, require an end quote character (\") at end of value\n", line);
      fclose(config);
      Exit(EXIT_FAILURE);
    }

    *(ptr + valueSize) = '\0';  // Remove trailing quote

    SetConfiguration(buffer, keySize, ptr, valueSize, line, &fileConfig);
  }

  fclose(config);

  /* Make sure config is valid */
  ValidateConfig(&fileConfig);

  MergeToConfigData(&fileConfig);
}

static void SetConfiguration(const char *buffer, const size_t keySize, char *ptr, const ssize_t valueSize, const size_t line, struct ConfigData *fileConfig) {
  char err[ERRNOMAXBUF];
  Debug("SetConfiguration: %s keySize: %lu valueSize: %ld sentryMode: %s", buffer, keySize, valueSize, GetSentryModeString(configData.sentryMode));

  if (strncmp(buffer, "BLOCK_TCP", keySize) == 0) {
    if (strncmp(ptr, "0", valueSize) == 0) {
      fileConfig->blockTCP = 0;
    } else if (strncmp(ptr, "1", valueSize) == 0) {
      fileConfig->blockTCP = 1;
    } else if (strncmp(ptr, "2", valueSize) == 0) {
      fileConfig->blockTCP = 2;
    } else {
      fprintf(stderr, "Invalid config file entry for BLOCK_TCP\n");
      Exit(EXIT_FAILURE);
    }
  } else if (strncmp(buffer, "BLOCK_UDP", keySize) == 0) {
    if (strncmp(ptr, "0", valueSize) == 0) {
      fileConfig->blockUDP = 0;
    } else if (strncmp(ptr, "1", valueSize) == 0) {
      fileConfig->blockUDP = 1;
    } else if (strncmp(ptr, "2", valueSize) == 0) {
      fileConfig->blockUDP = 2;
    } else {
      fprintf(stderr, "Invalid config file entry for BLOCK_UDP\n");
      Exit(EXIT_FAILURE);
    }
  } else if (strncmp(buffer, "RESOLVE_HOST", keySize) == 0) {
    if (strncmp(ptr, "1", valueSize) == 0) {
      fileConfig->resolveHost = TRUE;
    } else if (strncmp(ptr, "0", valueSize) == 0) {
      fileConfig->resolveHost = FALSE;
    } else {
      fprintf(stderr, "Invalid config file entry for RESOLVE_HOST\n");
      Exit(EXIT_FAILURE);
    }
  } else if (strncmp(buffer, "SCAN_TRIGGER", keySize) == 0) {
    fileConfig->configTriggerCount = GetLong(ptr);

    if (fileConfig->configTriggerCount < 0) {
      fprintf(stderr, "Invalid config file entry for SCAN_TRIGGER\n");
      Exit(EXIT_FAILURE);
    }
  } else if (strncmp(buffer, "KILL_ROUTE", keySize) == 0) {
    if (snprintf(fileConfig->killRoute, MAXBUF, "%s", ptr) >= MAXBUF) {
      fprintf(stderr, "KILL_ROUTE value too long\n");
      Exit(EXIT_FAILURE);
    }
  } else if (strncmp(buffer, "KILL_HOSTS_DENY", keySize) == 0) {
    if (snprintf(fileConfig->killHostsDeny, MAXBUF, "%s", ptr) >= MAXBUF) {
      fprintf(stderr, "KILL_HOSTS_DENY value too long\n");
      Exit(EXIT_FAILURE);
    }
  } else if (strncmp(buffer, "KILL_RUN_CMD", keySize) == 0) {
    if (snprintf(fileConfig->killRunCmd, MAXBUF, "%s", ptr) >= MAXBUF) {
      fprintf(stderr, "KILL_RUN_CMD value too long\n");
      Exit(EXIT_FAILURE);
    }
  } else if (strncmp(buffer, "KILL_RUN_CMD_FIRST", keySize) == 0) {
    if (strncmp(ptr, "1", valueSize) == 0) {
      fileConfig->runCmdFirst = TRUE;
    } else if (strncmp(ptr, "0", valueSize) == 0) {
      fileConfig->runCmdFirst = FALSE;
    } else {
      fprintf(stderr, "Invalid config file entry for KILL_RUN_CMD_FIRST\n");
      Exit(EXIT_FAILURE);
    }
  } else if (strncmp(buffer, "BLOCKED_FILE", keySize) == 0) {
    if (snprintf(fileConfig->blockedFile, PATH_MAX, "%s", ptr) >= PATH_MAX) {
      fprintf(stderr, "BLOCKED_FILE path value too long\n");
      Exit(EXIT_FAILURE);
    }

    if (TestFileAccess(fileConfig->blockedFile, "a", TRUE) == FALSE) {
      fprintf(stderr, "Unable to open block file for writing %s: %s\n", fileConfig->blockedFile, ErrnoString(err, sizeof(err)));
      Exit(EXIT_FAILURE);
    }
  } else if (strncmp(buffer, "HISTORY_FILE", keySize) == 0) {
    if (snprintf(fileConfig->historyFile, PATH_MAX, "%s", ptr) >= PATH_MAX) {
      fprintf(stderr, "HISTORY_FILE path value too long\n");
      Exit(EXIT_FAILURE);
    }

    if (TestFileAccess(fileConfig->historyFile, "w", TRUE) == FALSE) {
      fprintf(stderr, "Unable to open history file for writing %s: %s\n", fileConfig->historyFile, ErrnoString(err, sizeof(err)));
      Exit(EXIT_FAILURE);
    }
  } else if (strncmp(buffer, "IGNORE_FILE", keySize) == 0) {
    if (snprintf(fileConfig->ignoreFile, PATH_MAX, "%s", ptr) >= PATH_MAX) {
      fprintf(stderr, "IGNORE_FILE path value too long\n");
      Exit(EXIT_FAILURE);
    }
  } else if (strncmp(buffer, "TCP_PORTS", keySize) == 0) {
    if (ParsePortsList(ptr, &fileConfig->tcpPorts, &fileConfig->tcpPortsLength) == FALSE) {
      fprintf(stderr, "Unable to parse TCP_PORTS directive in config file\n");
      Exit(EXIT_FAILURE);
    }
  } else if (strncmp(buffer, "UDP_PORTS", keySize) == 0) {
    if (ParsePortsList(ptr, &fileConfig->udpPorts, &fileConfig->udpPortsLength) == FALSE) {
      fprintf(stderr, "Unable to parse UDP_PORTS directive in config file\n");
      Exit(EXIT_FAILURE);
    }
  } else if (strncmp(buffer, "PORT_BANNER", keySize) == 0) {
    if (snprintf(fileConfig->portBanner, MAXBUF, "%s", ptr) >= MAXBUF) {
      fprintf(stderr, "PORT_BANNER value too long\n");
      Exit(EXIT_FAILURE);
    }
    fileConfig->portBannerPresent = TRUE;
  } else {
    fprintf(stderr, "Invalid config file entry at line %lu\n", line);
    Exit(EXIT_FAILURE);
  }
}

static void ValidateConfig(struct ConfigData *fileConfig) {
  if (configData.sentryMode == SENTRY_MODE_STEALTH && fileConfig->tcpPortsLength == 0 && fileConfig->udpPortsLength == 0) {
    fprintf(stderr, "Selected mode: %s, but no TCP_PORTS or UDP_PORTS specified in config file\n", GetSentryModeString(configData.sentryMode));
    Exit(EXIT_FAILURE);
  } else if (configData.sentryMode == SENTRY_MODE_CONNECT && fileConfig->tcpPortsLength == 0 && fileConfig->udpPortsLength == 0) {
    fprintf(stderr, "Selected mode: %s, but no TCP_PORTS or UDP_PORTS specified in config file\n", GetSentryModeString(configData.sentryMode));
    Exit(EXIT_FAILURE);
  }

  if (strlen(fileConfig->blockedFile) == 0 && (fileConfig->blockTCP > 0 || fileConfig->blockUDP > 0)) {
    fprintf(stderr, "No BLOCK_FILE specified while BLOCK_TCP and/or BLOCK_UDP is not 0 (logging only)\n");
    Exit(EXIT_FAILURE);
  }

  if (fileConfig->blockTCP < 0 || fileConfig->blockTCP > 2) {
    fprintf(stderr, "Invalid BLOCK_TCP value in config file\n");
    Exit(EXIT_FAILURE);
  }

  if (fileConfig->blockUDP < 0 || fileConfig->blockUDP > 2) {
    fprintf(stderr, "Invalid BLOCK_UDP value in config file\n");
    Exit(EXIT_FAILURE);
  }

  if ((fileConfig->blockTCP == 2 || fileConfig->blockUDP == 2) &&
      strlen(fileConfig->killRunCmd) == 0) {
    fprintf(stderr, "KILL_RUN_CMD must be specified if BLOCK_TCP or BLOCK_UDP is set to 2\n");
    Exit(EXIT_FAILURE);
  }

  if ((fileConfig->blockTCP == 1 || fileConfig->blockUDP == 1) &&
      (strlen(fileConfig->killHostsDeny) == 0 && strlen(fileConfig->killRoute) == 0)) {
    fprintf(stderr, "KILL_HOSTS_DENY and/or KILL_ROUTE must be specified if BLOCK_TCP or BLOCK_UDP is set to 1\n");
    Exit(EXIT_FAILURE);
  }
}

static void MergeToConfigData(struct ConfigData *fileConfig) {
  struct ConfigData temp;

  /*
   * WARNING: Exercise caution when modifying this function. Both configData and fileConfig will hold pointers to to allocated memory.
   * Make sure copying is done correctly so no heap memory is lost.
   * As of this note; the ConfigData structure (config_data.h) holds pointers to:
   *
   * char **interfaces - array of strings of interfaces to listen to. Set in cmdline (therefore present in configData)
   * struct Port *tcpPorts - array of Port structs for TCP ports to listen to. Set in config file (therefore present in fileConfig)
   * struct Port *udpPorts - array of Port structs for UDP ports to listen to. Set in config file (therefore present in fileConfig)
   */

  // backup current configData (at this point,it's assumed the configData holds the cmdline options)
  memcpy(&temp, &configData, sizeof(struct ConfigData));

  // Set values from config file to be the "base" configData
  memcpy(&configData, fileConfig, sizeof(struct ConfigData));

  // Overlay values from the backup (cmdline) onto the configData
  // None of the options below are settable via the config file so they need to be added
  configData.sentryMode = temp.sentryMode;
  configData.sentryMethod = temp.sentryMethod;
  configData.logFlags = temp.logFlags;
  configData.daemon = temp.daemon;
  configData.interfaces = temp.interfaces;
  configData.disableLocalCheck = temp.disableLocalCheck;
  memcpy(configData.configFile, temp.configFile, sizeof(configData.configFile));
}

static char *SkipSpaceAndTab(char *buffer) {
  char *ptr = buffer;

  while (*ptr == ' ' || *ptr == '\t') {
    ptr++;
  }

  return ptr;
}

static size_t GetKeySize(char *buffer) {
  char *ptr = buffer;
  size_t keySize = 0;

  while (isupper((int)*ptr) || *ptr == '_') {
    ptr++;
    keySize++;
  }

  return keySize;
}

static void StripTrailingSpace(char *buffer) {
  char *ptr = buffer + strlen(buffer) - 1;

  if (ptr < buffer) {
    return;
  }

  while (isspace((int)*ptr)) {
    *ptr = '\0';

    if (ptr == buffer) {
      break;
    }
  }
}

static ssize_t GetSizeToQuote(const char *buffer) {
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

static int ParsePortsList(char *str, struct Port **ports, int *portsLength) {
  int count = 0;
  char *temp, *saveptr, *p = str;

  if (strlen(str) == 0) {
    return FALSE;
  }

  if (*ports != NULL) {
    free(*ports);
    *ports = NULL;
    *portsLength = 0;
  }

  while ((temp = strtok_r(p, ",", &saveptr)) != NULL) {
    if ((*ports = realloc(*ports, (count + 1) * sizeof(struct Port))) == NULL) {
      fprintf(stderr, "Unable to allocate memory for ports\n");
      Exit(EXIT_FAILURE);
    }

    ParsePort(temp, &(*ports)[count]);

    p = NULL;
    count++;
  }

  if ((*portsLength = count) == 0) {
    return FALSE;
  }

  return TRUE;
}
