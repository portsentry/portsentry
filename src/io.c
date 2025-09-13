// SPDX-FileCopyrightText: 2024 Craig Rowland
// SPDX-FileContributor: Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: BSD-2-Clause

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

#define MAXPORTBUF 10

static int MkdirP(const char *path);

static uint8_t isSyslogOpen = FALSE;

enum LogType { LogTypeNone,
               LogTypeError,
               LogTypeDebug,
               LogTypeVerbose };

static void LogEntry(const enum LogType logType, const char *logentry, va_list argsPtr);

static void LogEntry(const enum LogType logType, const char *logentry, va_list argsPtr) {
  char logbuffer[MAXBUF];

  if (vsnprintf(logbuffer, MAXBUF, logentry, argsPtr) >= MAXBUF) {
    logbuffer[MAXBUF - 1] = '\0';
    logbuffer[MAXBUF - 2] = '.';
    logbuffer[MAXBUF - 3] = '.';
    logbuffer[MAXBUF - 4] = '.';
  }

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

void Log(const char *logentry, ...) {
  va_list argsPtr;
  va_start(argsPtr, logentry);
  LogEntry(LogTypeNone, logentry, argsPtr);
  va_end(argsPtr);
}

void Error(const char *logentry, ...) {
  va_list argsPtr;
  va_start(argsPtr, logentry);
  LogEntry(LogTypeError, logentry, argsPtr);
  va_end(argsPtr);
}

void Debug(const char *logentry, ...) {
  va_list argsPtr;

  if ((configData.logFlags & LOGFLAG_DEBUG) == 0) {
    return;
  }

  va_start(argsPtr, logentry);
  LogEntry(LogTypeDebug, logentry, argsPtr);
  va_end(argsPtr);
}

void Verbose(const char *logentry, ...) {
  va_list argsPtr;

  if ((configData.logFlags & LOGFLAG_VERBOSE) == 0) {
    return;
  }

  va_start(argsPtr, logentry);
  LogEntry(LogTypeVerbose, logentry, argsPtr);
  va_end(argsPtr);
}

void Crash(const int errCode, const char *logentry, ...) {
  va_list argsPtr;
  va_start(argsPtr, logentry);
  LogEntry(LogTypeError, logentry, argsPtr);
  va_end(argsPtr);

  Exit(errCode);
}

void Exit(const int status) {
  Log("Portsentry is shutting down");

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

int BindSocket(const int sockfd, const struct sockaddr *addr, const socklen_t addrLen, const uint8_t proto) {
  char err[ERRNOMAXBUF];
  uint16_t port;

  if (addr->sa_family == AF_INET6) {
    const struct sockaddr_in6 *addr6Ptr = (const struct sockaddr_in6 *)addr;
    port = ntohs(addr6Ptr->sin6_port);
  } else if (addr->sa_family == AF_INET) {
    const struct sockaddr_in *addr4Ptr = (const struct sockaddr_in *)addr;
    port = ntohs(addr4Ptr->sin_port);
  } else {
    Error("Unsupported address family: %d", addr->sa_family);
    return ERROR;
  }

  if ((bind(sockfd, addr, addrLen)) == -1) {
    Verbose("Binding %s %s %d failed: %s",
            GetFamilyString(addr->sa_family),
            GetProtocolString(proto), port,
            ErrnoString(err, sizeof(err)));
    return ERROR;
  }

  if (proto == IPPROTO_TCP) {
    if (listen(sockfd, 5) == -1) {
      Error("Listen failed: %s %d %s", GetFamilyString(addr->sa_family), port, ErrnoString(err, sizeof(err)));
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
int KillRoute(const char *target, const int port, const char *killString, const char *detectionType) {
  char commandStringTemp[MAXBUF];
  char commandStringTemp2[MAXBUF], commandStringFinal[MAXBUF];
  char portString[MAXPORTBUF];
  int killStatus = ERROR, substStatus = ERROR;

  if (strlen(killString) == 0)
    return FALSE;

  if (snprintf(portString, MAXPORTBUF, "%d", port) >= MAXPORTBUF) {
    Error("KillRoute: Port number too large for buffer: %d", port);
    return ERROR;
  }

  substStatus = SubstString(target, "$TARGET$", killString, commandStringTemp, MAXBUF);
  if (substStatus == 0) {
    Log("No target variable specified in KILL_ROUTE option. Skipping.");
    return ERROR;
  } else if (substStatus == ERROR) {
    Log("Error trying to parse $TARGET$ Token for KILL_ROUTE. Skipping.");
    return ERROR;
  }

  if (SubstString(portString, "$PORT$", commandStringTemp, commandStringTemp2, MAXBUF) == ERROR) {
    Log("Error trying to parse $PORT$ Token for KILL_ROUTE. Skipping.");
    return ERROR;
  }

  if (SubstString(detectionType, "$MODE$", commandStringTemp2, commandStringFinal, MAXBUF) == ERROR) {
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
int KillRunCmd(const char *target, const int port, const char *killString, const char *detectionType) {
  char commandStringTemp[MAXBUF];
  char commandStringTemp2[MAXBUF], commandStringFinal[MAXBUF];
  char portString[MAXBUF];
  int killStatus = ERROR;

  if (strlen(killString) == 0)
    return FALSE;

  if (snprintf(portString, MAXPORTBUF, "%d", port) >= MAXPORTBUF) {
    Error("KillRunCmd: Port number too large for buffer: %d", port);
    return ERROR;
  }

  /* Tokens are not required, but we check for an error anyway */
  if (SubstString(target, "$TARGET$", killString, commandStringTemp, MAXBUF) == ERROR) {
    Log("Error trying to parse $TARGET$ Token for KILL_RUN_CMD. Skipping.");
    return ERROR;
  }

  if (SubstString(portString, "$PORT$", commandStringTemp, commandStringTemp2, MAXBUF) == ERROR) {
    Log("Error trying to parse $PORT$ Token for KILL_RUN_CMD. Skipping.");
    return ERROR;
  }

  if (SubstString(detectionType, "$MODE$", commandStringTemp2, commandStringFinal, MAXBUF) == ERROR) {
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
int KillHostsDeny(const char *target, const int port, const char *killString, const char *detectionType) {
  FILE *output = NULL;
  char commandStringTemp[MAXBUF];
  char commandStringTemp2[MAXBUF], commandStringFinal[MAXBUF];
  char portString[MAXBUF];
  int substStatus = ERROR;
  struct stat st;
  char err[ERRNOMAXBUF];

  if (strlen(killString) == 0)
    return FALSE;

  if (snprintf(portString, MAXPORTBUF, "%d", port) >= MAXPORTBUF) {
    Error("KillHostsDeny: Port number too large for buffer: %d", port);
    return ERROR;
  }

  Debug("KillHostsDeny: parsing string for block: %s", killString);

  substStatus = SubstString(target, "$TARGET$", killString, commandStringTemp, MAXBUF);
  if (substStatus == 0) {
    Log("No target variable specified in KILL_HOSTS_DENY option. Skipping.");
    return ERROR;
  } else if (substStatus == ERROR) {
    Log("Error trying to parse $TARGET$ Token for KILL_HOSTS_DENY. Skipping.");
    return ERROR;
  }

  if (SubstString(portString, "$PORT$", commandStringTemp, commandStringTemp2, MAXBUF) == ERROR) {
    Log("Error trying to parse $PORT$ Token for KILL_HOSTS_DENY. Skipping.");
    return ERROR;
  }

  if (SubstString(detectionType, "$MODE$", commandStringTemp2, commandStringFinal, MAXBUF) == ERROR) {
    Log("Error trying to parse $MODE$ Token for KILL_HOSTS_DENY. Skipping.");
    return ERROR;
  }

  Debug("KillHostsDeny: result string for block: %s", commandStringFinal);

  if (stat(WRAPPER_HOSTS_DENY, &st) == -1) {
    Error("Cannot stat file %s: %s", WRAPPER_HOSTS_DENY, ErrnoString(err, sizeof(err)));
    return ERROR;
  }

  if (S_ISLNK(st.st_mode)) {
    Error("File %s is a symbolic link, refusing to modify", WRAPPER_HOSTS_DENY);
    return ERROR;
  }

  if ((st.st_mode & S_IWOTH) != 0) {
    Error("File %s is world-writable, refusing to modify", WRAPPER_HOSTS_DENY);
    return ERROR;
  }

  if (FindInFile(commandStringFinal, WRAPPER_HOSTS_DENY) == TRUE) {
    Log("Host %s already in hosts.deny file, skipping.", target);
    return TRUE;
  }

  char tempFile[PATH_MAX];
  if (snprintf(tempFile, PATH_MAX, "%s.tmp", WRAPPER_HOSTS_DENY) >= PATH_MAX) {
    Error("KillHostsDeny: Temp file name too large for buffer: %s", WRAPPER_HOSTS_DENY);
    return ERROR;
  }

  if ((output = fopen(tempFile, "w")) == NULL) {
    Error("Cannot create temporary file %s: %s", tempFile, ErrnoString(err, sizeof(err)));
    return ERROR;
  }

  FILE *input = fopen(WRAPPER_HOSTS_DENY, "r");
  if (input != NULL) {
    char line[MAXBUF];
    while (fgets(line, sizeof(line), input) != NULL) {
      fputs(line, output);
    }
    fclose(input);
  }

  if (fprintf(output, "%s\n", commandStringFinal) < 0) {
    Error("Error writing to temporary file %s", tempFile);
    fclose(output);
    unlink(tempFile);
    return ERROR;
  }

  fclose(output);

  if (rename(tempFile, WRAPPER_HOSTS_DENY) == -1) {
    Error("Cannot rename temporary file %s to %s: %s", tempFile, WRAPPER_HOSTS_DENY, ErrnoString(err, sizeof(err)));
    unlink(tempFile);
    return ERROR;
  }

  Log("attackalert: Host %s has been blocked via wrappers with string: \"%s\"", target, commandStringFinal);
  return TRUE;
}

int FindInFile(const char *searchString, const char *filename) {
  FILE *fp = NULL;
  char line[MAXBUF];
  size_t searchLen;
  int status = ERROR;
  char err[ERRNOMAXBUF];
  struct stat st;

  if (searchString == NULL || filename == NULL) {
    Error("Invalid parameters to FindInFile");
    goto exit;
  }

  if ((fp = fopen(filename, "r")) == NULL) {
    Error("Unable to open file %s for reading: %s", filename, ErrnoString(err, sizeof(err)));
    goto exit;
  }

  if (fstat(fileno(fp), &st) == -1) {
    Error("Cannot stat file %s: %s", filename, ErrnoString(err, sizeof(err)));
    goto exit;
  }

  if (S_ISLNK(st.st_mode)) {
    Error("File %s is a symbolic link, refusing to read", filename);
    goto exit;
  }

  if ((st.st_mode & S_IWOTH) != 0) {
    Error("File %s is world-writable, refusing to read", filename);
    goto exit;
  }

  searchLen = strlen(searchString);
  if (searchLen == 0 || searchLen >= MAXBUF) {
    Error("Invalid search string length");
    goto exit;
  }

  while (fgets(line, sizeof(line), fp) != NULL) {
    size_t lineLen = strlen(line);

    if (lineLen == sizeof(line) - 1 && line[lineLen - 1] != '\n') {
      Error("Line too long in file %s", filename);
      status = ERROR;
      goto exit;
    }

    if (lineLen > 0 && line[lineLen - 1] == '\n') {
      line[lineLen - 1] = '\0';
      lineLen--;
    }

    if (lineLen == searchLen && strcmp(line, searchString) == 0) {
      status = TRUE;
      goto exit;
    }
  }

  status = FALSE;

exit:
  if (fp != NULL) {
    fclose(fp);
  }
  return status;
}

/*********************************************************************************
 * String substitute function
 *
 * replaceToken - The token to replace with.
 * findToken - The token to find.
 * source - The source string to search.
 * dest - The destination string to copy to.
 * destSize - The size of the destination buffer.
 *
 * Returns the number of substitutions made during the operation.
 * Returns ERROR on failure.
 **********************************************************************************/
int SubstString(const char *replaceToken, const char *findToken, const char *source, char *dest, const int destSize) {
  if (replaceToken == NULL || findToken == NULL || source == NULL || dest == NULL || destSize <= 0) {
    return ERROR;
  }

  if (strlen(findToken) == 0) {
    return ERROR;
  }

  size_t remainDestSize = (size_t)destSize;
  size_t findTokenLen = strlen(findToken);
  size_t replaceTokenLen = strlen(replaceToken);
  int numberOfSubst = 0;
  const char *srcPtr = source;
  char *destPtr = dest;

  while (remainDestSize > 1) {
    const char *srcToken = strstr(srcPtr, findToken);
    if (!srcToken) {
      break;
    }

    size_t chunkSize = (size_t)(srcToken - srcPtr);
    if (chunkSize >= remainDestSize) {
      return ERROR;
    }

    if (chunkSize > 0) {
      memcpy(destPtr, srcPtr, chunkSize);
      destPtr += chunkSize;
      remainDestSize -= chunkSize;
    }

    if (replaceTokenLen >= remainDestSize) {
      return ERROR;
    }

    if (replaceTokenLen > 0) {
      memcpy(destPtr, replaceToken, replaceTokenLen);
      destPtr += replaceTokenLen;
      remainDestSize -= replaceTokenLen;
    }

    srcPtr = srcToken + findTokenLen;
    numberOfSubst++;
  }

  size_t remainingLen = strlen(srcPtr);
  if (remainingLen >= remainDestSize) {
    return ERROR;
  }

  if (remainingLen > 0) {
    memcpy(destPtr, srcPtr, remainingLen);
    destPtr += remainingLen;
    remainDestSize -= remainingLen;
  }

  *destPtr = '\0';

  return numberOfSubst;
}

int TestFileAccess(const char *filename, const char *mode, const uint8_t createDir) {
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
    const struct sockaddr *addr = saddr;
    result = sendto(socket, configData.portBanner, strlen(configData.portBanner), 0, addr, saddrLen);
  }

  if (result == -1) {
    Error("Could not write banner to socket (ignoring): %s", ErrnoString(err, sizeof(err)));
  }
}
