#include <stdio.h>
#include <string.h>

#include "configfile.h"
#include "portsentry.h"
#include "portsentry_io.h"
#include "portsentry_util.h"

extern char gblKillRoute[MAXBUF];
extern char gblKillHostsDeny[MAXBUF];
extern char gblKillRunCmd[MAXBUF];
extern char gblDetectionType[MAXBUF];
extern char gblPorts[MAXBUF];
extern char gblAdvancedExclude[MAXBUF];
extern char gblPortBanner[MAXBUF];

extern char gblBlockedFile[PATH_MAX];
extern char gblHistoryFile[PATH_MAX];
extern char gblIgnoreFile[PATH_MAX];

extern int gblBlockTCP;
extern int gblBlockUDP;
extern int gblRunCmdFirst;
extern int gblResolveHost;
extern int gblConfigTriggerCount;

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

  // FIXME: Validate that gblDetectionType is a valid type

  /* Set defaults */
  bzero(gblKillRoute, MAXBUF);
  bzero(gblKillHostsDeny, MAXBUF);
  bzero(gblKillRunCmd, MAXBUF);
  bzero(gblPorts, MAXBUF);
  bzero(gblAdvancedExclude, MAXBUF);
  bzero(gblPortBanner, MAXBUF);

  bzero(gblBlockedFile, PATH_MAX);
  bzero(gblHistoryFile, PATH_MAX);
  bzero(gblIgnoreFile, PATH_MAX);

  if (strncmp(gblDetectionType, "atcp", 4) == 0 || strncmp(gblDetectionType, "audp", 4) == 0) {
    strcpy(gblPorts, "1024");
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
  if (strncmp(gblDetectionType, "atcp", 4) == 0) {
    if (strlen(gblPorts) == 0) {
      snprintf(gblPorts, MAXBUF, "%d", ADVANCED_MODE_PORT_TCP);
    }
  } else if (strncmp(gblDetectionType, "audp", 4) == 0) {
    if (strlen(gblPorts) == 0) {
      snprintf(gblPorts, MAXBUF, "%d", ADVANCED_MODE_PORT_UDP);
    }
  }

  /* Make sure config is valid */
  validateConfig();

  return TRUE;
}

static void setConfiguration(char *buffer, size_t keySize, char *ptr, ssize_t valueSize, const size_t line) {
#ifdef DEBUG
    Log("debug: setConfiguration: %s keySize: %u valueSize: %d gblDetectionType: %s", buffer, keySize, valueSize, gblDetectionType);
#endif

  if (strncmp(buffer, "BLOCK_TCP", keySize) == 0) {
    if (strncmp(ptr, "1", valueSize) == 0) {
      gblBlockTCP = TRUE;
    } else if (strncmp(ptr, "0", valueSize) == 0) {
      gblBlockTCP = FALSE;
    } else {
      Log("adminalert: ERROR: Invalid config file entry for BLOCK_TCP\n");
      exit(1);
    }
  } else if (strncmp(buffer, "BLOCK_UDP", keySize) == 0) {
    if (strncmp(ptr, "1", valueSize) == 0) {
      gblBlockUDP = TRUE;
    } else if (strncmp(ptr, "0", valueSize) == 0) {
      gblBlockUDP = FALSE;
    } else {
      Log("adminalert: ERROR: Invalid config file entry for BLOCK_UDP\n");
      exit(1);
    }
  } else if (strncmp(buffer, "RESOLVE_HOST", keySize) == 0) {
    if (strncmp(ptr, "1", valueSize) == 0) {
      gblResolveHost = TRUE;
    } else if (strncmp(ptr, "0", valueSize) == 0) {
      gblResolveHost = FALSE;
    } else {
      Log("adminalert: ERROR: Invalid config file entry for RESOLVE_HOST\n");
      exit(1);
    }
  } else if (strncmp(buffer, "SCAN_TRIGGER", keySize) == 0) {
    gblConfigTriggerCount = getLong(ptr);

    if (gblConfigTriggerCount < 0) {
      Log("adminalert: ERROR: Invalid config file entry for SCAN_TRIGGER\n");
      exit(1);
    }
  } else if (strncmp(buffer, "KILL_ROUTE", keySize) == 0) {
    if (copyPrintableString(ptr, gblKillRoute, MAXBUF) == FALSE) {
      Log("adminalert: ERROR: Unable to copy kill route\n");
      exit(1);
    }
  } else if (strncmp(buffer, "KILL_HOSTS_DENY", keySize) == 0) {
    if (copyPrintableString(ptr, gblKillHostsDeny, MAXBUF) == FALSE) {
      Log("adminalert: ERROR: Unable to copy kill hosts deny\n");
      exit(1);
    }
  } else if (strncmp(buffer, "KILL_RUN_CMD", keySize) == 0) {
    if (copyPrintableString(ptr, gblKillRunCmd, MAXBUF) == FALSE) {
      Log("adminalert: ERROR: Unable to copy kill run command\n");
      exit(1);
    }
  } else if (strncmp(buffer, "KILL_RUN_CMD_FIRST", keySize) == 0) {
    if (strncmp(ptr, "1", valueSize) == 0) {
      gblRunCmdFirst = TRUE;
    } else if (strncmp(ptr, "0", valueSize) == 0) {
      gblRunCmdFirst = FALSE;
    } else {
      Log("adminalert: ERROR: Invalid config file entry for KILL_RUN_CMD_FIRST\n");
      exit(1);
    }
  } else if (strncmp(buffer, "BLOCKED_FILE", keySize) == 0) {
    if (copyPrintableString(ptr, gblBlockedFile, PATH_MAX) == FALSE) {
      Log("adminalert: ERROR: Unable to copy blocked file path\n");
      exit(1);
    }
    if (strlen(gblBlockedFile) < (PATH_MAX - 5)) {
      strncat(gblBlockedFile, ".", 1);
      strncat(gblBlockedFile, gblDetectionType, 4);
    } else {
      Log("adminalert: ERROR: Blocked filename is too long to append detection type file extension: %s\n", gblBlockedFile);
      exit(1);
    }

    if (testFileAccess(gblBlockedFile, "w") == FALSE) {
      Log("adminalert: ERROR: Unable to open block file for writing: %s\n", gblBlockedFile);
      exit(1);
    }
  } else if (strncmp(buffer, "HISTORY_FILE", keySize) == 0) {
    if (copyPrintableString(ptr, gblHistoryFile, PATH_MAX) == FALSE) {
      Log("adminalert: ERROR: Unable to copy history file path\n");
      exit(1);
    }
  } else if (strncmp(buffer, "IGNORE_FILE", keySize) == 0) {
    if (copyPrintableString(ptr, gblIgnoreFile, PATH_MAX) == FALSE) {
      Log("adminalert: ERROR: Unable to copy ignore file path\n");
      exit(1);
    }
  } else if (strncmp(buffer, "TCP_PORTS", keySize) == 0) {
    if (strncmp(gblDetectionType, "tcp", 3) == 0 || strncmp(gblDetectionType, "stcp", 4) == 0) {
      if (copyPrintableString(ptr, gblPorts, MAXBUF) == FALSE) {
      Log("adminalert: ERROR: Unable to copy TCP ports\n");
      exit(1);
      }
    }
  } else if (strncmp(buffer, "UDP_PORTS", keySize) == 0) {
    if ((strncmp(gblDetectionType, "udp", 3) == 0 || strncmp(gblDetectionType, "sudp", 4) == 0)) {
      if (copyPrintableString(ptr, gblPorts, MAXBUF) == FALSE) {
        Log("adminalert: ERROR: Unable to copy UDP ports\n");
        exit(1);
      }
    }
  } else if (strncmp(buffer, "ADVANCED_PORTS_TCP", keySize) == 0) {
    if (strncmp(gblDetectionType, "atcp", 4) == 0) {
      if (copyPrintableString(ptr, gblPorts, MAXBUF) == FALSE) {
        Log("adminalert: ERROR: Unable to copy advanced TCP ports\n");
        exit(1);
      }
    }
  } else if (strncmp(buffer, "ADVANCED_PORTS_UDP", keySize) == 0) {
    if (strncmp(gblDetectionType, "audp", 4) == 0) {
      if (copyPrintableString(ptr, gblPorts, MAXBUF) == FALSE) {
        Log("adminalert: ERROR: Unable to copy advanced UDP ports\n");
        exit(1);
      }
    }
  } else if (strncmp(buffer, "ADVANCED_EXCLUDE_TCP", keySize) == 0) {
    if (strncmp(gblDetectionType, "atcp", 4) == 0) {
      if (copyPrintableString(ptr, gblAdvancedExclude, MAXBUF) == FALSE) {
        Log("adminalert: ERROR: Unable to copy advanced exclude TCP ports\n");
        exit(1);
      }
    }
  } else if (strncmp(buffer, "ADVANCED_EXCLUDE_UDP", keySize) == 0) {
    if (strncmp(gblDetectionType, "audp", 4) == 0) {
      if (copyPrintableString(ptr, gblAdvancedExclude, MAXBUF) == FALSE) {
        Log("adminalert: ERROR: Unable to copy advanced exclude UDP ports\n");
        exit(1);
      }
    }
  } else if (strncmp(buffer, "PORT_BANNER", keySize) == 0) {
    copyPrintableString(ptr, gblPortBanner, MAXBUF);
  } else {
    Log("adminalert: ERROR: Invalid config file entry at line %lu\n", line);
    exit(1);
  }
}

void validateConfig(void) {
  // FIXME: When validating gblPorts / gblExcludePorts, make sure the combination w/ gblDetectionType is valid
  // Advanced Ports: If not set, default to 1024
  // Wait with this function until the config file (and cmdline) is stored in a struct fulle parsed
#ifdef DEBUG
  Log("debug: gblBlockTCP: %d\n", gblBlockTCP);
  Log("debug: gblBlockUDP: %d\n", gblBlockUDP);
  Log("debug: gblResolveHost: %d\n", gblResolveHost);
  Log("debug: gblConfigTriggerCount: %u\n", gblConfigTriggerCount);
  Log("debug: gblKillRoute: %s\n", gblKillRoute);
  Log("debug: gblKillHostsDeny: %s\n", gblKillHostsDeny);
  Log("debug: gblKillRunCmd: %s\n", gblKillRunCmd);
  Log("debug: gblRunCmdFirst: %d\n", gblRunCmdFirst);
  Log("debug: gblPorts: %s\n", gblPorts);
  Log("debug: gblAdvancedExclude: %s\n", gblAdvancedExclude);
  Log("debug: gblPortBanner: %s\n", gblPortBanner);
  Log("debug: gblBlockedFile: %s\n", gblBlockedFile);
  Log("debug: gblHistoryFile: %s\n", gblHistoryFile);
  Log("debug: gblIgnoreFile: %s\n", gblIgnoreFile);
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
