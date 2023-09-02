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

int readConfigFile(void) {
  FILE *config;
  char buffer[MAXBUF], *ptr;
  size_t keySize, line = 0;
  ssize_t valueSize;

  // FIXME: Validate that configData.gblDetectionType is a valid type

  /* Set defaults */
  if (strncmp(configData.gblDetectionType, "atcp", 4) == 0 || strncmp(configData.gblDetectionType, "audp", 4) == 0) {
    strcpy(configData.gblPorts, "1024");
  }

  if ((config = fopen(CONFIG_FILE, "r")) == NULL) {
    Log("adminalert: ERROR: Cannot open config file: %s.\n", CONFIG_FILE);
    return ERROR;
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
      return ERROR;
    }

    ptr = buffer + keySize;
    ptr = skipSpaceAndTab(ptr);

    if (*ptr != '=') {
      Log("adminalert: ERROR: Invalid config file entry at line %lu\n", line);
      fclose(config);
      return ERROR;
    }
    ptr++;

    ptr = skipSpaceAndTab(ptr);

    if (*ptr != '"') {
      Log("adminalert: ERROR: Invalid config file entry at line %lu\n", line);
      fclose(config);
      return ERROR;
    }
    ptr++;

    if ((valueSize = getSizeToQuote(ptr)) == ERROR) {
      Log("adminalert: ERROR: Invalid config file entry at line %lu\n", line);
      fclose(config);
      return ERROR;
    }

    setConfiguration(buffer, keySize, ptr, valueSize, line);
  }

  fclose(config);


  /* Add implied config file entries */
  if (strncmp(configData.gblDetectionType, "atcp", 4) == 0) {
    if (strlen(configData.gblPorts) == 0) {
      snprintf(configData.gblPorts, MAXBUF, "%d", ADVANCED_MODE_PORT_TCP);
    }
  } else if (strncmp(configData.gblDetectionType, "audp", 4) == 0) {
    if (strlen(configData.gblPorts) == 0) {
      snprintf(configData.gblPorts, MAXBUF, "%d", ADVANCED_MODE_PORT_UDP);
    }
  }

  /* Make sure config is valid */
  validateConfig();

  return TRUE;
}

static void setConfiguration(char *buffer, size_t keySize, char *ptr, ssize_t valueSize, const size_t line) {
#ifdef DEBUG
    Log("debug: setConfiguration: %s keySize: %u valueSize: %d configData.gblDetectionType: %s", buffer, keySize, valueSize, configData.gblDetectionType);
#endif

  if (strncmp(buffer, "BLOCK_TCP", keySize) == 0) {
    if (strncmp(ptr, "1", valueSize) == 0) {
      configData.gblBlockTCP = TRUE;
    } else if (strncmp(ptr, "0", valueSize) == 0) {
      configData.gblBlockTCP = FALSE;
    } else {
      Log("adminalert: ERROR: Invalid config file entry for BLOCK_TCP\n");
      exit(1);
    }
  } else if (strncmp(buffer, "BLOCK_UDP", keySize) == 0) {
    if (strncmp(ptr, "1", valueSize) == 0) {
      configData.gblBlockUDP = TRUE;
    } else if (strncmp(ptr, "0", valueSize) == 0) {
      configData.gblBlockUDP = FALSE;
    } else {
      Log("adminalert: ERROR: Invalid config file entry for BLOCK_UDP\n");
      exit(1);
    }
  } else if (strncmp(buffer, "RESOLVE_HOST", keySize) == 0) {
    if (strncmp(ptr, "1", valueSize) == 0) {
      configData.gblResolveHost = TRUE;
    } else if (strncmp(ptr, "0", valueSize) == 0) {
      configData.gblResolveHost = FALSE;
    } else {
      Log("adminalert: ERROR: Invalid config file entry for RESOLVE_HOST\n");
      exit(1);
    }
  } else if (strncmp(buffer, "SCAN_TRIGGER", keySize) == 0) {
    configData.gblConfigTriggerCount = getLong(ptr);

    if (configData.gblConfigTriggerCount < 0) {
      Log("adminalert: ERROR: Invalid config file entry for SCAN_TRIGGER\n");
      exit(1);
    }
  } else if (strncmp(buffer, "KILL_ROUTE", keySize) == 0) {
    if (copyPrintableString(ptr, configData.gblKillRoute, MAXBUF) == FALSE) {
      Log("adminalert: ERROR: Unable to copy kill route\n");
      exit(1);
    }
  } else if (strncmp(buffer, "KILL_HOSTS_DENY", keySize) == 0) {
    if (copyPrintableString(ptr, configData.gblKillHostsDeny, MAXBUF) == FALSE) {
      Log("adminalert: ERROR: Unable to copy kill hosts deny\n");
      exit(1);
    }
  } else if (strncmp(buffer, "KILL_RUN_CMD", keySize) == 0) {
    if (copyPrintableString(ptr, configData.gblKillRunCmd, MAXBUF) == FALSE) {
      Log("adminalert: ERROR: Unable to copy kill run command\n");
      exit(1);
    }
  } else if (strncmp(buffer, "KILL_RUN_CMD_FIRST", keySize) == 0) {
    if (strncmp(ptr, "1", valueSize) == 0) {
      configData.gblRunCmdFirst = TRUE;
    } else if (strncmp(ptr, "0", valueSize) == 0) {
      configData.gblRunCmdFirst = FALSE;
    } else {
      Log("adminalert: ERROR: Invalid config file entry for KILL_RUN_CMD_FIRST\n");
      exit(1);
    }
  } else if (strncmp(buffer, "BLOCKED_FILE", keySize) == 0) {
    if (copyPrintableString(ptr, configData.gblBlockedFile, PATH_MAX) == FALSE) {
      Log("adminalert: ERROR: Unable to copy blocked file path\n");
      exit(1);
    }
    if (strlen(configData.gblBlockedFile) < (PATH_MAX - 5)) {
      strncat(configData.gblBlockedFile, ".", 1);
      strncat(configData.gblBlockedFile, configData.gblDetectionType, 4);
    } else {
      Log("adminalert: ERROR: Blocked filename is too long to append detection type file extension: %s\n", configData.gblBlockedFile);
      exit(1);
    }

    if (testFileAccess(configData.gblBlockedFile, "w") == FALSE) {
      Log("adminalert: ERROR: Unable to open block file for writing: %s\n", configData.gblBlockedFile);
      exit(1);
    }
  } else if (strncmp(buffer, "HISTORY_FILE", keySize) == 0) {
    if (copyPrintableString(ptr, configData.gblHistoryFile, PATH_MAX) == FALSE) {
      Log("adminalert: ERROR: Unable to copy history file path\n");
      exit(1);
    }
  } else if (strncmp(buffer, "IGNORE_FILE", keySize) == 0) {
    if (copyPrintableString(ptr, configData.gblIgnoreFile, PATH_MAX) == FALSE) {
      Log("adminalert: ERROR: Unable to copy ignore file path\n");
      exit(1);
    }
  } else if (strncmp(buffer, "TCP_PORTS", keySize) == 0) {
    if (strncmp(configData.gblDetectionType, "tcp", 3) == 0 || strncmp(configData.gblDetectionType, "stcp", 4) == 0) {
      if (copyPrintableString(ptr, configData.gblPorts, MAXBUF) == FALSE) {
      Log("adminalert: ERROR: Unable to copy TCP ports\n");
      exit(1);
      }
    }
  } else if (strncmp(buffer, "UDP_PORTS", keySize) == 0) {
    if ((strncmp(configData.gblDetectionType, "udp", 3) == 0 || strncmp(configData.gblDetectionType, "sudp", 4) == 0)) {
      if (copyPrintableString(ptr, configData.gblPorts, MAXBUF) == FALSE) {
        Log("adminalert: ERROR: Unable to copy UDP ports\n");
        exit(1);
      }
    }
  } else if (strncmp(buffer, "ADVANCED_PORTS_TCP", keySize) == 0) {
    if (strncmp(configData.gblDetectionType, "atcp", 4) == 0) {
      if (copyPrintableString(ptr, configData.gblPorts, MAXBUF) == FALSE) {
        Log("adminalert: ERROR: Unable to copy advanced TCP ports\n");
        exit(1);
      }
    }
  } else if (strncmp(buffer, "ADVANCED_PORTS_UDP", keySize) == 0) {
    if (strncmp(configData.gblDetectionType, "audp", 4) == 0) {
      if (copyPrintableString(ptr, configData.gblPorts, MAXBUF) == FALSE) {
        Log("adminalert: ERROR: Unable to copy advanced UDP ports\n");
        exit(1);
      }
    }
  } else if (strncmp(buffer, "ADVANCED_EXCLUDE_TCP", keySize) == 0) {
    if (strncmp(configData.gblDetectionType, "atcp", 4) == 0) {
      if (copyPrintableString(ptr, configData.gblAdvancedExclude, MAXBUF) == FALSE) {
        Log("adminalert: ERROR: Unable to copy advanced exclude TCP ports\n");
        exit(1);
      }
    }
  } else if (strncmp(buffer, "ADVANCED_EXCLUDE_UDP", keySize) == 0) {
    if (strncmp(configData.gblDetectionType, "audp", 4) == 0) {
      if (copyPrintableString(ptr, configData.gblAdvancedExclude, MAXBUF) == FALSE) {
        Log("adminalert: ERROR: Unable to copy advanced exclude UDP ports\n");
        exit(1);
      }
    }
  } else if (strncmp(buffer, "PORT_BANNER", keySize) == 0) {
    copyPrintableString(ptr, configData.gblPortBanner, MAXBUF);
  } else {
    Log("adminalert: ERROR: Invalid config file entry at line %lu\n", line);
    exit(1);
  }
}

void validateConfig(void) {
  // FIXME: When validating configData.gblPorts / configData.gblExcludePorts, make sure the combination w/ configData.gblDetectionType is valid
  // Advanced Ports: If not set, default to 1024
  // Wait with this function until the config file (and cmdline) is stored in a struct fulle parsed
#ifdef DEBUG
  Log("debug: configData.gblBlockTCP: %d\n", configData.gblBlockTCP);
  Log("debug: configData.gblBlockUDP: %d\n", configData.gblBlockUDP);
  Log("debug: configData.gblResolveHost: %d\n", configData.gblResolveHost);
  Log("debug: configData.gblConfigTriggerCount: %u\n", configData.gblConfigTriggerCount);
  Log("debug: configData.gblKillRoute: %s\n", configData.gblKillRoute);
  Log("debug: configData.gblKillHostsDeny: %s\n", configData.gblKillHostsDeny);
  Log("debug: configData.gblKillRunCmd: %s\n", configData.gblKillRunCmd);
  Log("debug: configData.gblRunCmdFirst: %d\n", configData.gblRunCmdFirst);
  Log("debug: configData.gblPorts: %s\n", configData.gblPorts);
  Log("debug: configData.gblAdvancedExclude: %s\n", configData.gblAdvancedExclude);
  Log("debug: configData.gblPortBanner: %s\n", configData.gblPortBanner);
  Log("debug: configData.gblBlockedFile: %s\n", configData.gblBlockedFile);
  Log("debug: configData.gblHistoryFile: %s\n", configData.gblHistoryFile);
  Log("debug: configData.gblIgnoreFile: %s\n", configData.gblIgnoreFile);
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
