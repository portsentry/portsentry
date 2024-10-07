// SPDX-FileCopyrightText: 2024 Craig Rowland
// SPDX-FileContributor: Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <libgen.h>

#include "config.h"
#include "config_data.h"
#include "io.h"
#include "portsentry.h"
#include "util.h"

static int MkdirP(const char *path);

static uint8_t isSyslogOpen = FALSE;

enum LogType { LogTypeNone,
               LogTypeError,
               LogTypeDebug,
               LogTypeVerbose };

static void LogEntry(enum LogType logType, char *logentry, va_list argsPtr);

static void LogEntry(enum LogType logType, char *logentry, va_list argsPtr) {
  char logbuffer[MAXBUF];

  vsnprintf(logbuffer, MAXBUF, logentry, argsPtr);

  if (configData.logFlags & LOGFLAG_OUTPUT_STDOUT) {
    if (logType == LogTypeError) {
      fprintf(stderr, "%s\n", logbuffer);
      fflush(stderr);
    } else {
      printf("%s%s\n", (logType == LogTypeDebug) ? "debug: " : "", logbuffer);
      fflush(stdout);
    }
  }

  if (configData.logFlags & LOGFLAG_OUTPUT_SYSLOG) {
    if (isSyslogOpen == FALSE) {
      openlog("portsentry", LOG_PID, LOG_DAEMON);
      isSyslogOpen = TRUE;
    }
    syslog((logType == LogTypeNone) ? LOG_NOTICE : (logType == LogTypeError) ? LOG_ERR
                                               : (logType == LogTypeDebug)   ? LOG_DEBUG
                                                                             : LOG_INFO,
           "%s%s", (logType == LogTypeDebug) ? "debug: " : "", logbuffer);
  }
}

void Log(char *logentry, ...) {
  va_list argsPtr;
  va_start(argsPtr, logentry);
  LogEntry(LogTypeNone, logentry, argsPtr);
  va_end(argsPtr);
}

void Error(char *logentry, ...) {
  va_list argsPtr;
  va_start(argsPtr, logentry);
  LogEntry(LogTypeError, logentry, argsPtr);
  va_end(argsPtr);
}

void Debug(char *logentry, ...) {
  va_list argsPtr;

  if ((configData.logFlags & LOGFLAG_DEBUG) == 0) {
    return;
  }

  va_start(argsPtr, logentry);
  LogEntry(LogTypeDebug, logentry, argsPtr);
  va_end(argsPtr);
}

void Verbose(char *logentry, ...) {
  va_list argsPtr;

  if ((configData.logFlags & LOGFLAG_VERBOSE) == 0) {
    return;
  }

  va_start(argsPtr, logentry);
  LogEntry(LogTypeVerbose, logentry, argsPtr);
  va_end(argsPtr);
}

void Crash(int errCode, char *logentry, ...) {
  va_list argsPtr;
  va_start(argsPtr, logentry);
  LogEntry(LogTypeError, logentry, argsPtr);
  va_end(argsPtr);

  Exit(errCode);
}

void Exit(int status) {
  Log("PortSentry is shutting down");

  if (isSyslogOpen == TRUE) {
    closelog();
    isSyslogOpen = FALSE;
  }

  if (configData.tcpPorts != NULL) {
    free(configData.tcpPorts);
    configData.tcpPorts = NULL;
    configData.tcpPortsLength = 0;
  }

  if (configData.udpPorts != NULL) {
    free(configData.udpPorts);
    configData.udpPorts = NULL;
    configData.udpPortsLength = 0;
  }

  exit(status);
}

/* Compares an IP address against a listed address and its netmask*/
static int WriteToLogFile(const char *filename, const char *target, const char *resolvedHost, const int port, const char *portType) {
  FILE *output;
  char err[ERRNOMAXBUF];
  struct tm tm, *tmptr;
  time_t current_time;
  current_time = time(0);
  tmptr = localtime_r(&current_time, &tm);

  Debug("WriteToLogFile: Opening: %s ", filename);

  if ((output = fopen(filename, "a")) == NULL) {
    Log("Unable to open block log file: %s (%s)", filename, ErrnoString(err, sizeof(err)));
    return FALSE;
  }

#ifdef __OpenBSD__
  fprintf(output, "%lld - %02d/%02d/%04d %02d:%02d:%02d Host: %s/%s Port: %d %s Blocked\n",
          current_time, tmptr->tm_mon + 1, tmptr->tm_mday, tmptr->tm_year + 1900,
          tmptr->tm_hour, tmptr->tm_min, tmptr->tm_sec, resolvedHost, target, port, portType);
#else
  fprintf(output, "%ld - %02d/%02d/%04d %02d:%02d:%02d Host: %s/%s Port: %d %s Blocked\n",
          current_time, tmptr->tm_mon + 1, tmptr->tm_mday, tmptr->tm_year + 1900,
          tmptr->tm_hour, tmptr->tm_min, tmptr->tm_sec, resolvedHost, target, port, portType);
#endif

  fclose(output);

  return TRUE;
}

int WriteBlocked(char *target, char *resolvedHost, int port, char *blockedFilename, const char *portType) {
  return WriteToLogFile(blockedFilename, target, resolvedHost, port, portType);
}

int BindSocket(int sockfd, int family, int port, int proto) {
  char err[ERRNOMAXBUF];
  struct sockaddr_in6 sin6;
  struct sockaddr_in sin4;

  if (family == AF_INET6) {
    bzero(&sin6, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_addr = in6addr_any;
    sin6.sin6_port = htons(port);
    if (bind(sockfd, (struct sockaddr *)&sin6, sizeof(sin6)) == -1) {
      Error("Binding %s %s %d failed: %s", GetFamilyString(family), GetProtocolString(proto), port, ErrnoString(err, sizeof(err)));
      return ERROR;
    }
  } else {
    bzero(&sin4, sizeof(sin4));
    sin4.sin_family = AF_INET;
    sin4.sin_addr.s_addr = htonl(INADDR_ANY);
    sin4.sin_port = htons(port);
    if (bind(sockfd, (struct sockaddr *)&sin4, sizeof(sin4)) == -1) {
      Error("Binding %s %s %d failed: %s", GetFamilyString(family), GetProtocolString(proto), port, ErrnoString(err, sizeof(err)));
      return ERROR;
    }
  }

  if (proto == IPPROTO_TCP) {
    if (listen(sockfd, 5) == -1) {
      Error("Listen failed: %s %d %s", GetFamilyString(family), port, ErrnoString(err, sizeof(err)));
      return ERROR;
    }
  }

  return TRUE;
}

int OpenSocket(const int family, const int type, const int protocol, const uint8_t tcpReuseAddr) {
  int sockfd;
  int optval;
  socklen_t optlen;
  char err[ERRNOMAXBUF];

  assert(family == AF_INET || family == AF_INET6);
  assert(type == SOCK_STREAM || type == SOCK_DGRAM);
  assert(protocol == IPPROTO_TCP || protocol == IPPROTO_UDP);

  if ((sockfd = socket(family, type, protocol)) < 0) {
    Error("Could not open socket family: %d type: %d protocol: %d: %s", family, type, protocol, ErrnoString(err, sizeof(err)));
    return ERROR;
  }

  if (type == SOCK_STREAM && tcpReuseAddr == TRUE) {
    optval = 1;
    optlen = sizeof(optval);
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, optlen) < 0) {
      Error("Could not set SO_REUSEADDR on TCP socket: %s", ErrnoString(err, sizeof(err)));
      return ERROR;
    }
  }

#ifndef __OpenBSD__
  if (family == AF_INET6) {
    optval = 0;
    optlen = sizeof(optval);
    if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &optval, optlen) < 0) {
      Error("Could not set IPV6_V6ONLY on socket: %s", ErrnoString(err, sizeof(err)));
      return ERROR;
    }

    optlen = sizeof(optval);
    if (getsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &optval, &optlen) < 0) {
      Error("Could not get IPV6_V6ONLY on socket: %s", ErrnoString(err, sizeof(err)));
      return ERROR;
    }

    if (optval != 0) {
      Error("Could not set IPV6_V6ONLY on socket: %s", ErrnoString(err, sizeof(err)));
      return ERROR;
    }
  }
#endif

  return sockfd;
}

/* This will use a system() call to change the route of the target host to */
/* a dead IP address on your LOCAL SUBNET. */
int KillRoute(char *target, int port, char *killString, char *detectionType) {
  char commandStringTemp[MAXBUF];
  char commandStringTemp2[MAXBUF], commandStringFinal[MAXBUF];
  char portString[MAXBUF];
  int killStatus = ERROR, substStatus = ERROR;

  if (strlen(killString) == 0)
    return FALSE;

  snprintf(portString, MAXBUF, "%d", port);

  substStatus = SubstString(target, "$TARGET$", killString, commandStringTemp);
  if (substStatus == 0) {
    Log("No target variable specified in KILL_ROUTE option. Skipping.");
    return ERROR;
  } else if (substStatus == ERROR) {
    Log("Error trying to parse $TARGET$ Token for KILL_ROUTE. Skipping.");
    return ERROR;
  }

  if (SubstString(portString, "$PORT$", commandStringTemp, commandStringTemp2) == ERROR) {
    Log("Error trying to parse $PORT$ Token for KILL_ROUTE. Skipping.");
    return ERROR;
  }

  if (SubstString(detectionType, "$MODE$", commandStringTemp2, commandStringFinal) == ERROR) {
    Log("Error trying to parse $MODE$ Token for KILL_ROUTE. Skipping.");
    return ERROR;
  }

  Debug("KillRoute: running route command: %s", commandStringFinal);

  /* Kill the bastard and report a status */
  killStatus = system(commandStringFinal);

  if (killStatus == 127) {
    Error("There was an error trying to block host (exec fail) %s", target);
    return ERROR;
  } else if (killStatus < 0) {
    Error("There was an error trying to block host (system fail) %s", target);
    return ERROR;
  }

  Log("attackalert: Host %s has been blocked via dropped route using command: \"%s\"", target, commandStringFinal);
  return TRUE;
}

/* This will run a specified command with TARGET as the option if one is given.
 */
int KillRunCmd(char *target, int port, char *killString, char *detectionType) {
  char commandStringTemp[MAXBUF];
  char commandStringTemp2[MAXBUF], commandStringFinal[MAXBUF];
  char portString[MAXBUF];
  int killStatus = ERROR;

  if (strlen(killString) == 0)
    return FALSE;

  snprintf(portString, MAXBUF, "%d", port);

  /* Tokens are not required, but we check for an error anyway */
  if (SubstString(target, "$TARGET$", killString, commandStringTemp) == ERROR) {
    Log("Error trying to parse $TARGET$ Token for KILL_RUN_CMD. Skipping.");
    return ERROR;
  }

  if (SubstString(portString, "$PORT$", commandStringTemp, commandStringTemp2) == ERROR) {
    Log("Error trying to parse $PORT$ Token for KILL_RUN_CMD. Skipping.");
    return ERROR;
  }

  if (SubstString(detectionType, "$MODE$", commandStringTemp2, commandStringFinal) == ERROR) {
    Log("Error trying to parse $MODE$ Token for KILL_RUN_CMD. Skipping.");
    return ERROR;
  }

  /* Kill the bastard and report a status */
  killStatus = system(commandStringFinal);

  if (killStatus == 127) {
    Error("There was an error trying to run command (exec fail) %s", target);
    return ERROR;
  } else if (killStatus < 0) {
    Error("There was an error trying to run command (system fail) %s", target);
    return ERROR;
  }

  /* report success */
  Log("attackalert: External command run for host: %s using command: \"%s\"", target, commandStringFinal);
  return TRUE;
}

/* this function will drop the host into the TCP wrappers hosts.deny file to deny
 * all access. The drop route metod is preferred as this stops UDP attacks as well
 * as TCP. You may find though that host.deny will be a more permanent home.. */
int KillHostsDeny(char *target, int port, char *killString, char *detectionType) {
  FILE *output;
  char commandStringTemp[MAXBUF];
  char commandStringTemp2[MAXBUF], commandStringFinal[MAXBUF];
  char portString[MAXBUF];
  int substStatus = ERROR;

  if (strlen(killString) == 0)
    return FALSE;

  snprintf(portString, MAXBUF, "%d", port);

  Debug("KillHostsDeny: parsing string for block: %s", killString);

  substStatus =
      SubstString(target, "$TARGET$", killString, commandStringTemp);
  if (substStatus == 0) {
    Log("No target variable specified in KILL_HOSTS_DENY option. Skipping.");
    return ERROR;
  } else if (substStatus == ERROR) {
    Log("Error trying to parse $TARGET$ Token for KILL_HOSTS_DENY. Skipping.");
    return ERROR;
  }

  if (SubstString(portString, "$PORT$", commandStringTemp, commandStringTemp2) == ERROR) {
    Log("Error trying to parse $PORT$ Token for KILL_HOSTS_DENY. Skipping.");
    return ERROR;
  }

  if (SubstString(detectionType, "$MODE$", commandStringTemp2, commandStringFinal) == ERROR) {
    Log("Error trying to parse $MODE$ Token for KILL_HOSTS_DENY. Skipping.");
    return ERROR;
  }

  Debug("KillHostsDeny: result string for block: %s", commandStringFinal);

  if ((output = fopen(WRAPPER_HOSTS_DENY, "a")) == NULL) {
    Log("Cannot open hosts.deny file: %s for blocking.", WRAPPER_HOSTS_DENY);
    Error("securityalert: There was an error trying to block host %s", target);
    return ERROR;
  }

  if ((size_t)fprintf(output, "%s\n", commandStringFinal) != (strlen(commandStringFinal) + 1)) {  // +1 for newline
    Error("There was an error writing to hosts.deny file: %s", WRAPPER_HOSTS_DENY);
    fclose(output);
    return ERROR;
  }

  fclose(output);
  Log("attackalert: Host %s has been blocked via wrappers with string: \"%s\"", target, commandStringFinal);
  return TRUE;
}

/* check if the host is already blocked */
int IsBlocked(char *target, char *filename) {
  FILE *input;
  char buffer[MAXBUF], tempBuffer[MAXBUF], err[ERRNOMAXBUF];
  char *ipOffset;
  size_t count;

  Debug("IsBlocked: Opening block file: %s ", filename);

  if ((input = fopen(filename, "r")) == NULL) {
    Error("Cannot open blocked file: %s for reading: %s. Will create.", filename, ErrnoString(err, sizeof(err)));
    return (FALSE);
  }

  while (fgets(buffer, MAXBUF, input) != NULL) {
    if ((ipOffset = strstr(buffer, target)) != NULL) {
      for (count = 0; count < strlen(ipOffset); count++) {
        if ((isdigit((int)ipOffset[count])) || (ipOffset[count] == '.') || (ipOffset[count] == ':')) {
          tempBuffer[count] = ipOffset[count];
        } else {
          tempBuffer[count] = '\0';
          break;
        }
      }
      if (strcmp(target, tempBuffer) == 0) {
        Debug("isBlocked: Host: %s found in blocked file", target);
        fclose(input);
        return (TRUE);
      }
    }
  }
  Debug("IsBlocked: Host: %s NOT found in blocked file", target);
  fclose(input);
  return (FALSE);
}

/*********************************************************************************
 * String substitute function
 *
 * This function takes:
 *
 * 1) A token to use for replacement.
 * 2) A token to find.
 * 3) A string with the tokens in it.
 * 4) A string to write the replaced result.
 *
 * It returns the number of substitutions made during the operation.
 **********************************************************************************/
int SubstString(const char *replace, const char *find, const char *target, char *result) {
  int count = 0, findCount = 0, findLen = 0, numberOfSubst = 0;
  char tempString[MAXBUF], *tempStringPtr;
  size_t replaceCount = 0;

  Debug("SubstString: Processing string: %s %lu", target, strlen(target));
  Debug("SubstString: Processing search text: %s %lu", replace, strlen(replace));
  Debug("SubstString: Processing replace text: %s %lu", find, strlen(find));

  /* string not found in target */
  if (strstr(target, find) == NULL) {
    strncpy(result, target, MAXBUF);
    Debug("SubstString: Result string: %s", result);
    return (numberOfSubst);
  } else if ((strlen(target)) + (strlen(replace)) + (strlen(find)) > MAXBUF) { /* String/victim/target too long */
    return (ERROR);
  }

  memset(tempString, '\0', MAXBUF);
  memset(result, '\0', MAXBUF);
  findLen = strlen(find);
  tempStringPtr = tempString;

  for (count = 0; count < MAXBUF; count++) {
    if (*target == '\0') {
      break;
    } else if ((strncmp(target, find, findLen)) != 0) {
      *tempStringPtr++ = *target++;
    } else {
      numberOfSubst++;
      for (replaceCount = 0; replaceCount < strlen(replace); replaceCount++)
        *tempStringPtr++ = replace[replaceCount];
      for (findCount = 0; findCount < findLen; findCount++)
        target++;
    }
  }

  strncpy(result, tempString, MAXBUF);
  Debug("SubstString: Result string: %s", result);
  return (numberOfSubst);
}

int testFileAccess(const char *filename, const char *mode, uint8_t createDir) {
  FILE *testFile = NULL;
  char *pathCopy = NULL, *dirPath;
  int status = FALSE;

  if ((testFile = fopen(filename, mode)) != NULL) {
    fclose(testFile);
    return TRUE;
  }

  if (createDir == FALSE) {
    goto exit;
  }

  if ((pathCopy = strdup(filename)) == NULL) {
    Error("Unable to allocate memory for path copy: %s", filename);
    goto exit;
  }

  if ((dirPath = dirname(pathCopy)) == NULL) {
    Error("Unable to get directory name from path: %s", filename);
    goto exit;
  }

  if (MkdirP(dirPath) != TRUE) {
    goto exit;
  }

  if ((testFile = fopen(filename, mode)) == NULL) {
    goto exit;
  }

  status = TRUE;
exit:
  if (testFile != NULL) {
    fclose(testFile);
  }

  if (pathCopy != NULL) {
    free(pathCopy);
  }
  return status;
}

static int MkdirP(const char *path) {
  char *p;
  char *pathCopy = NULL;
  int status = ERROR;
  char err[ERRNOMAXBUF];

  assert(path != NULL);

  if ((pathCopy = strdup(path)) == NULL) {
    Error("Could not allocate memory for path copy: %s", ErrnoString(err, sizeof(err)));
    goto exit;
  }

  for (p = strchr(pathCopy + 1, '/'); p; p = strchr(p + 1, '/')) {
    *p = '\0';
    if (mkdir(pathCopy, 0755) == -1 && errno != EEXIST) {
      Error("Could not create directory: %s: %s", pathCopy, ErrnoString(err, sizeof(err)));
      goto exit;
    }
    *p = '/';
  }

  if (mkdir(pathCopy, 0755) == -1 && errno != EEXIST) {
    Error("Could not create directory: %s: %s", pathCopy, ErrnoString(err, sizeof(err)));
    goto exit;
  }

  status = TRUE;
exit:
  if (pathCopy != NULL) {
    free(pathCopy);
  }
  return status;
}

void XmitBannerIfConfigured(const int proto, const int socket, const struct sockaddr *saddr, const socklen_t saddrLen) {
  ssize_t result = 0;
  char err[ERRNOMAXBUF];

  assert(proto == IPPROTO_TCP || proto == IPPROTO_UDP);

  if (configData.portBannerPresent == FALSE)
    return;

  errno = 0;

  if (proto == IPPROTO_TCP) {
    result = write(socket, configData.portBanner, strlen(configData.portBanner));
  } else if (proto == IPPROTO_UDP) {
    if (saddr == NULL) {
      Error("No client address specified for UDP banner transmission (ignoring)");
      return;
    }
    result = sendto(socket, configData.portBanner, strlen(configData.portBanner), 0, (struct sockaddr *)saddr, saddrLen);
  }

  if (result == -1) {
    Error("Could not write banner to socket (ignoring): %s", ErrnoString(err, sizeof(err)));
  }
}
