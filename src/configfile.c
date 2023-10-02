#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config_data.h"
#include "configfile.h"
#include "io.h"
#include "portsentry.h"
#include "util.h"

static void setConfiguration(char *buffer, size_t keySize, char *ptr, ssize_t valueSize, const size_t line, struct ConfigData *fileConfig);
static void validateConfig(struct ConfigData *fileConfig);
static void mergeToConfigData(struct ConfigData *fileConfig);
static char *skipSpaceAndTab(char *buffer);
static size_t getKeySize(char *buffer);
static void stripTrailingSpace(char *buffer);
static ssize_t getSizeToQuote(char *buffer);
static int parsePortsList(char *str, uint16_t *ports, int *portsLength, const int maxPorts);
static int StrToUint16_t(const char *str, uint16_t *val);

void readConfigFile(void) {
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

    stripTrailingSpace(buffer);

    if ((keySize = getKeySize(buffer)) == 0) {
      fprintf(stderr, "Invalid config file entry at line %lu\n", line);
      fclose(config);
      Exit(EXIT_FAILURE);
    }

    ptr = buffer + keySize;
    ptr = skipSpaceAndTab(ptr);

    if (*ptr != '=') {
      fprintf(stderr, "Invalid character found after config key. Require equals (=) after key. Line %lu\n", line);
      fclose(config);
      Exit(EXIT_FAILURE);
    }
    ptr++;

    ptr = skipSpaceAndTab(ptr);

    if (*ptr != '"') {
      fprintf(stderr, "Invalid value on line %lu, require quote character (\") to start value\n", line);
      fclose(config);
      Exit(EXIT_FAILURE);
    }
    ptr++;

    if ((valueSize = getSizeToQuote(ptr)) == ERROR) {
      fprintf(stderr, "Invalid value at line %lu, require an end quote character (\") at end of value\n", line);
      fclose(config);
      Exit(EXIT_FAILURE);
    }

    *(ptr + valueSize) = '\0'; // Remove trailing quote

    setConfiguration(buffer, keySize, ptr, valueSize, line, &fileConfig);
  }

  fclose(config);

  // Set default values if not set in config file
  if (fileConfig.tcpAdvancedPort == 0)
    fileConfig.tcpAdvancedPort = ADVANCED_MODE_PORT_TCP;
  if (fileConfig.udpAdvancedPort == 0)
    fileConfig.udpAdvancedPort = ADVANCED_MODE_PORT_UDP;

  /* Make sure config is valid */
  validateConfig(&fileConfig);

  mergeToConfigData(&fileConfig);
}

static void setConfiguration(char *buffer, size_t keySize, char *ptr, ssize_t valueSize, const size_t line, struct ConfigData *fileConfig) {
  Debug("setConfiguration: %s keySize: %lu valueSize: %ld sentryMode: %s", buffer, keySize, valueSize, GetSentryModeString(configData.sentryMode));

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
    fileConfig->configTriggerCount = getLong(ptr);

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
    if (snprintf(fileConfig->blockedFile, PATH_MAX, "%s.%s", ptr, GetSentryModeString(configData.sentryMode)) >= PATH_MAX) {
      fprintf(stderr, "BLOCKED_FILE path value too long\n");
      Exit(EXIT_FAILURE);
    }

    if (testFileAccess(fileConfig->blockedFile, "w") == FALSE) {
      fprintf(stderr, "Unable to open block file for writing: %s\n", fileConfig->blockedFile);
      Exit(EXIT_FAILURE);
    }
  } else if (strncmp(buffer, "HISTORY_FILE", keySize) == 0) {
    if (snprintf(fileConfig->historyFile, PATH_MAX, "%s", ptr) >= PATH_MAX) {
      fprintf(stderr, "HISTORY_FILE path value too long\n");
      Exit(EXIT_FAILURE);
    }
  } else if (strncmp(buffer, "IGNORE_FILE", keySize) == 0) {
    if (snprintf(fileConfig->ignoreFile, PATH_MAX, "%s", ptr) >= PATH_MAX) {
      fprintf(stderr, "IGNORE_FILE path value too long\n");
      Exit(EXIT_FAILURE);
    }
  } else if (strncmp(buffer, "TCP_PORTS", keySize) == 0) {
    if (parsePortsList(ptr, fileConfig->tcpPorts, &fileConfig->tcpPortsLength, MAXSOCKS) == FALSE) {
      fprintf(stderr, "Unable to parse TCP_PORTS directive in config file\n");
      Exit(EXIT_FAILURE);
    }
  } else if (strncmp(buffer, "UDP_PORTS", keySize) == 0) {
    if (parsePortsList(ptr, fileConfig->udpPorts, &fileConfig->udpPortsLength, MAXSOCKS) == FALSE) {
      fprintf(stderr, "Unable to parse UDP_PORTS directive in config file\n");
      Exit(EXIT_FAILURE);
    }
  } else if (strncmp(buffer, "ADVANCED_PORTS_TCP", keySize) == 0) {
    if (StrToUint16_t(ptr, &fileConfig->tcpAdvancedPort) == FALSE) {
      fprintf(stderr, "Unable to parse ADVANCED_PORTS_TCP\n");
      Exit(EXIT_FAILURE);
    }

    fprintf(stderr, "ADVANCED_PORTS_TCP = %d\n", fileConfig->tcpAdvancedPort);
  } else if (strncmp(buffer, "ADVANCED_PORTS_UDP", keySize) == 0) {
    if (StrToUint16_t(ptr, &fileConfig->udpAdvancedPort) == FALSE) {
      fprintf(stderr, "Unable to parse ADVANCED_PORTS_UDP\n");
      Exit(EXIT_FAILURE);
    }

    fprintf(stderr, "ADVANCED_PORTS_UDP = %d\n", fileConfig->udpAdvancedPort);
  } else if (strncmp(buffer, "ADVANCED_EXCLUDE_TCP", keySize) == 0) {
    if (parsePortsList(ptr, fileConfig->tcpAdvancedExcludePorts, &fileConfig->tcpAdvancedExcludePortsLength, UINT16_MAX) == FALSE) {
      fprintf(stderr, "Unable to parse ADVANCED_EXCLUDE_TCP\n");
      Exit(EXIT_FAILURE);
    }
  } else if (strncmp(buffer, "ADVANCED_EXCLUDE_UDP", keySize) == 0) {
    if (parsePortsList(ptr, fileConfig->udpAdvancedExcludePorts, &fileConfig->udpAdvancedExcludePortsLength, UINT16_MAX) == FALSE) {
      fprintf(stderr, "Unable to parse ADVANCED_EXCLUDE_UDP\n");
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

static void validateConfig(struct ConfigData *fileConfig) {
  if (configData.sentryMode == SENTRY_MODE_TCP || configData.sentryMode == SENTRY_MODE_STCP) {
    if (fileConfig->tcpPortsLength == 0) {
      fprintf(stderr, "Selected mode: %s, but no TCP_PORTS specified in config file\n", GetSentryModeString(configData.sentryMode));
      Exit(EXIT_FAILURE);
    }
  } else if (configData.sentryMode == SENTRY_MODE_UDP || configData.sentryMode == SENTRY_MODE_SUDP) {
    if (fileConfig->udpPortsLength == 0) {
      fprintf(stderr, "Selected mode: %s, but no UDP_PORTS specified in config file\n", GetSentryModeString(configData.sentryMode));
      Exit(EXIT_FAILURE);
    }
  } else if (configData.sentryMode == SENTRY_MODE_ATCP) {
    if (fileConfig->tcpAdvancedPort == 0) {
      fprintf(stderr, "Selected mode: %s, but no ADVANCED_PORTS_TCP specified in config file\n", GetSentryModeString(configData.sentryMode));
      Exit(EXIT_FAILURE);
    }
  } else if (configData.sentryMode == SENTRY_MODE_AUDP) {
    if (fileConfig->udpAdvancedPort == 0) {
      fprintf(stderr, "Selected mode: %s, but no ADVANCED_PORTS_UDP specified in config file\n", GetSentryModeString(configData.sentryMode));
      Exit(EXIT_FAILURE);
    }
  }

  if (strlen(fileConfig->ignoreFile) == 0) {
    fprintf(stderr, "No IGNORE_FILE specified in config file\n");
    Exit(EXIT_FAILURE);
  }

  if (strlen(fileConfig->historyFile) == 0) {
    fprintf(stderr, "No HISTORY_FILE specified in config file\n");
    Exit(EXIT_FAILURE);
  }

  if (strlen(fileConfig->blockedFile) == 0) {
    fprintf(stderr, "No BLOCK_FILE specified in config file\n");
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

  /*
   * TODO: Add validation for the following:
      fileConfig->killRoute
      fileConfig->killHostsDeny
      fileConfig->killRunCmd
      fileConfig->blockedFile
      fileConfig->historyFile
      fileConfig->ignoreFile
    */
}

static void mergeToConfigData(struct ConfigData *fileConfig) {
  struct ConfigData temp;

  // backup current configData (at this point,it's assumed the configData holds the cmdline options)
  memcpy(&temp, &configData, sizeof(struct ConfigData));

  // Set values from config file to be the "base" configData
  memcpy(&configData, fileConfig, sizeof(struct ConfigData));

  // Overlay values from the backup (cmdline) onto the configData
  // None of the options below are settable via the config file so they need to be added
  configData.sentryMode = temp.sentryMode;
  configData.logFlags = temp.logFlags;
  memcpy(configData.configFile, temp.configFile, sizeof(configData.configFile));
  configData.daemon = temp.daemon;
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

static int parsePortsList(char *str, uint16_t *ports, int *portsLength, const int maxPorts) {
  int count;
  char *temp, *p = str;

  if (strlen(str) == 0) {
    return FALSE;
  }

  for (count = 0; count < maxPorts; count++) {
    if ((temp = strtok(p, ",")) == NULL) {
      break;
    }

    p = NULL;

    if (StrToUint16_t(temp, &ports[count]) == FALSE) {
      return FALSE;
    }
  }

  if ((*portsLength = count) == 0) {
    return FALSE;
  }

  return TRUE;
}

static int StrToUint16_t(const char *str, uint16_t *val) {
  char *endptr;
  long value;

  errno = 0;
  value = strtol(str, &endptr, 10);

  // Stingy error checking
  // errno set indicates malformed input
  // endptr == str indicates no digits found
  // value > UINT16_MAX indicates value is too large, since ports can only be 0-65535
  // value <= 0: Don't allow port 0 (or negative ports)
  if (errno != 0 || endptr == str || *endptr != '\0' || value > UINT16_MAX || value <= 0) {
    return FALSE;
  }

  *val = (uint16_t)value;

  return TRUE;
}
