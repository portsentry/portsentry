/************************************************************************/
/*                                                                      */
/* PortSentry                                                           */
/*                                                                      */
/* This software is Copyright(c) 1997-2003 Craig Rowland                */
/*                                                                      */
/* This software is covered under the Common Public License v1.0        */
/* See the enclosed LICENSE file for more information.                  */
/*                                                                      */
/* Created: 10-12-1997                                                  */
/* Modified: 05-23-2003                                                 */
/*                                                                      */
/* Send all changes/modifications/bugfixes to:                          */
/* craigrowland at users dot sourceforge dot net                        */
/*                                                                      */
/* $Id: portsentry_io.c,v 1.36 2003/05/23 17:41:40 crowland Exp crowland $ */
/************************************************************************/

#include "portsentry.h"
#include "portsentry_io.h"
#include "portsentry_util.h"
#include "config_data.h"

static uint8_t isSyslogOpen = FALSE;

/* Main logging function to surrogate syslog */
void Log(char *logentry, ...) {
  char logbuffer[MAXBUF];

  va_list argsPtr;
  va_start(argsPtr, logentry);

  vsnprintf(logbuffer, MAXBUF, logentry, argsPtr);

  va_end(argsPtr);

  if (configData.logFlags & LOGFLAG_OUTPUT_STDOUT) {
    printf("%s", logbuffer);
  }

  if (configData.logFlags & LOGFLAG_OUTPUT_SYSLOG) {
    if(isSyslogOpen == FALSE) {
      openlog("portsentry", LOG_PID, SYSLOG_FACILITY);
      isSyslogOpen = TRUE;
    }
    syslog(SYSLOG_LEVEL, "%s", logbuffer);
  }
}

void Exit(int status) {
  Log("PortSentry is shutting down\n");

  if (isSyslogOpen == TRUE) {
    closelog();
    isSyslogOpen = FALSE;
  }

  exit(status);
}

/* The daemonizing code copied from Advanced Programming */
/* in the UNIX Environment by W. Richard Stevens with minor changes */
int DaemonSeed(void) {
  int childpid;

  signal(SIGALRM, SIG_IGN);
  signal(SIGHUP, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGTERM, Exit);
  signal(SIGABRT, Exit);
  signal(SIGURG, Exit);
  signal(SIGKILL, Exit);

  if ((childpid = fork()) < 0)
    return (ERROR);
  else if (childpid > 0)
    exit(0);

  setsid();
  /* FIXME: This should perhaps he a fatal error, also maybe do better daemonizing */
  if (chdir("/") == -1) {
    Log("adminalert: Unable to change to root directory during daemonizing (ignoring)\n");
  }
  umask(077);

  /* close stdout, stdin, stderr */
  close(0);
  close(1);
  close(2);

  return (TRUE);
}

/* Compares an IP address against a listed address and its netmask*/
int CompareIPs(char *target, char *ignoreAddr, int ignoreNetmaskBits) {
  unsigned long int netmaskAddr, ipAddr, targetAddr;

  ipAddr = inet_addr(ignoreAddr);
  targetAddr = inet_addr(target);
  netmaskAddr = htonl(0xFFFFFFFF << (32 - ignoreNetmaskBits));

#ifdef DEBUG
  Log("debug: target %s\n", target);
  Log("debug: ignoreAddr %s\n", ignoreAddr);
  Log("debug: ignoreNetmaskBits %d\n", ignoreNetmaskBits);
  Log("debug: ipAddr %lu\n", ipAddr);
  Log("debug: targetAddr %lu\n", targetAddr);
  Log("debug: netmask %x\n", netmaskAddr);
  Log("debug: mix ipAddr %lu\n", (ipAddr & netmaskAddr));
  Log("debug: mix target %lu\n", (targetAddr & netmaskAddr));
#endif

  /* Network portion mask & op and return */
  if ((ipAddr & netmaskAddr) == (targetAddr & netmaskAddr))
    return (TRUE);
  else
    return (FALSE);
}

/* check hosts that should never be blocked */
int NeverBlock(char *target, char *filename) {
  FILE *input;
  char buffer[MAXBUF], tempBuffer[MAXBUF], netmaskBuffer[MAXBUF];
  char *slashPos;
  int dest = 0, netmaskBits = 0;
  size_t count = 0;

#ifdef DEBUG
  Log("debug: NeverBlock: Opening ignore file: %s \n", filename);
#endif
  if ((input = fopen(filename, "r")) == NULL)
    return (ERROR);

#ifdef DEBUG
  Log("debug: NeverBlock: Doing lookup for host: %s \n", target);
#endif

  while (fgets(buffer, MAXBUF, input) != NULL) {
    /* Reset destination counter */
    dest = 0;

    if ((buffer[0] == '#') || (buffer[0] == '\n'))
      continue;

    for (count = 0; count < strlen(buffer); count++) {
      /* Parse out digits, colons, and slashes. Everything else rejected */
      if ((isdigit(buffer[count])) || (buffer[count] == '.') ||
          (buffer[count] == ':') || (buffer[count] == '/')) {
        tempBuffer[dest++] = buffer[count];
      } else {
        tempBuffer[dest] = '\0';
        break;
      }
    }

    /* Return pointer to slash if it exists and copy data to buffer */
    slashPos = strchr(tempBuffer, '/');
    if (slashPos) {
      SafeStrncpy(netmaskBuffer, slashPos + 1, MAXBUF);
      /* Terminate tempBuffer string at delimeter for later use */
      *slashPos = '\0';
    } else { /* Copy in a 32 bit netmask if none given */
      SafeStrncpy(netmaskBuffer, "32", MAXBUF);
    }

    /* Convert netmaskBuffer to bits in netmask */
    netmaskBits = atoi(netmaskBuffer);
    if ((netmaskBits < 0) || (netmaskBits > 32)) {
      Log("adminalert: Invalid netmask in config file: %s  Ignoring entry.\n", buffer);
      continue;
    }

    if (CompareIPs(target, tempBuffer, netmaskBits)) {
#ifdef DEBUG
      Log("debug: NeverBlock: Host: %s found in ignore file with netmask %s\n", target, netmaskBuffer);
#endif

      fclose(input);
      return (TRUE);
    }
  } /* end while() */

#ifdef DEBUG
  Log("debug: NeverBlock: Host: %s NOT found in ignore file\n", target);
#endif

  fclose(input);
  return (FALSE);
}

/* This writes out blocked hosts to the blocked file. It adds the hostname */
/* time stamp, and port connection that was acted on */
int WriteBlocked(char *target, char *resolvedHost, int port, char *blockedFilename, char *historyFilename, char *portType) {
  FILE *output;
  int blockedStatus = TRUE, historyStatus = TRUE;

  struct tm tm, *tmptr;

  time_t current_time;
  current_time = time(0);
  tmptr = localtime_r(&current_time, &tm);

#ifdef DEBUG
  Log("debug: WriteBlocked: Opening block file: %s \n", blockedFilename);
#endif

  if ((output = fopen(blockedFilename, "a")) == NULL) {
    Log("adminalert: ERROR: Cannot open blocked file: %s.\n", blockedFilename);
    blockedStatus = FALSE;
  } else {
    fprintf(output, "%ld - %02d/%02d/%04d %02d:%02d:%02d Host: %s/%s Port: %d %s Blocked\n",
            current_time, tmptr->tm_mon + 1, tmptr->tm_mday, tmptr->tm_year + 1900,
            tmptr->tm_hour, tmptr->tm_min, tmptr->tm_sec, resolvedHost, target, port, portType);
    fclose(output);
    blockedStatus = TRUE;
  }

#ifdef DEBUG
  Log("debug: WriteBlocked: Opening history file: %s \n", historyFilename);
#endif
  if ((output = fopen(historyFilename, "a")) == NULL) {
    Log("adminalert: ERROR: Cannot open history file: %s.\n", historyFilename);
    historyStatus = FALSE;
  } else {
    fprintf(output, "%ld - %02d/%02d/%04d %02d:%02d:%02d Host: %s/%s Port: %d %s Blocked\n",
            current_time, tmptr->tm_mon + 1, tmptr->tm_mday, tmptr->tm_year + 1900,
            tmptr->tm_hour, tmptr->tm_min, tmptr->tm_sec, resolvedHost, target, port, portType);
    fclose(output);
    historyStatus = TRUE;
  }

  if (historyStatus || blockedStatus == FALSE)
    return (FALSE);
  else
    return (TRUE);
}

/* This will bind a socket to a port. It works for UDP/TCP */
int BindSocket(int sockfd, int port) {
  struct sockaddr_in server;
#ifdef DEBUG
  Log("debug: BindSocket: Binding to port: %d\n", port);
#endif

  bzero((char *)&server, sizeof(server));
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = htonl(INADDR_ANY);
  server.sin_port = htons(port);

  if (bind(sockfd, (struct sockaddr *)&server, sizeof(server)) < 0) {
#ifdef DEBUG
    Log("debug: BindSocket: Binding failed\n");
#endif
    return (ERROR);
  } else {
#ifdef DEBUG
    Log("debug: BindSocket: Binding successful. Doing listen\n");
#endif
    listen(sockfd, 5);
    return (TRUE);
  }
}

/* Open a TCP Socket */
int OpenTCPSocket(void) {
  int sockfd;

#ifdef DEBUG
  Log("debug: OpenTCPSocket: opening TCP socket\n");
#endif

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    return (ERROR);
  else
    return (sockfd);
}

/* Open a UDP Socket */
int OpenUDPSocket(void) {
  int sockfd;

#ifdef DEBUG
  Log("debug: openUDPSocket opening UDP socket\n");
#endif

  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    return (ERROR);
  else
    return (sockfd);
}

#ifdef SUPPORT_STEALTH
/* Open a RAW TCPSocket */
int OpenRAWTCPSocket(void) {
  int sockfd;

#ifdef DEBUG
  Log("debug: OpenRAWTCPSocket: opening RAW TCP socket\n");
#endif

  if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
    return (ERROR);
  else
    return (sockfd);
}

/* Open a RAW UDP Socket */
int OpenRAWUDPSocket(void) {
  int sockfd;

#ifdef DEBUG
  Log("debug: OpenRAWUDPSocket: opening RAW UDP socket\n");
#endif

  if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0)
    return (ERROR);
  else
    return (sockfd);
}
#endif

/* This will use a system() call to change the route of the target host to */
/* a dead IP address on your LOCAL SUBNET. */
int KillRoute(char *target, int port, char *killString, char *detectionType) {
  char cleanAddr[MAXBUF], commandStringTemp[MAXBUF];
  char commandStringTemp2[MAXBUF], commandStringFinal[MAXBUF];
  char portString[MAXBUF];
  int killStatus = ERROR, substStatus = ERROR;

  CleanIpAddr(cleanAddr, target);
  snprintf(portString, MAXBUF, "%d", port);

  substStatus =
      SubstString(cleanAddr, "$TARGET$", killString, commandStringTemp);
  if (substStatus == 0) {
    Log("adminalert: No target variable specified in KILL_ROUTE option. Skipping.\n");
    return (ERROR);
  } else if (substStatus == ERROR) {
    Log("adminalert: Error trying to parse $TARGET$ Token for KILL_ROUTE. Skipping.\n");
    return (ERROR);
  }

  if (SubstString(portString, "$PORT$", commandStringTemp,
                  commandStringTemp2) == ERROR) {
    Log("adminalert: Error trying to parse $PORT$ Token for KILL_ROUTE. Skipping.\n");
    return (ERROR);
  }

  if (SubstString(detectionType, "$MODE$", commandStringTemp2,
                  commandStringFinal) == ERROR) {
    Log("adminalert: Error trying to parse $MODE$ Token for KILL_ROUTE. Skipping.\n");
    return (ERROR);
  }

#ifdef DEBUG
  Log("debug: KillRoute: running route command: %s\n", commandStringFinal);
#endif

  /* Kill the bastard and report a status */
  killStatus = system(commandStringFinal);

  if (killStatus == 127) {
    Log("adminalert: ERROR: There was an error trying to block host (exec fail) %s", target);
    return (ERROR);
  } else if (killStatus < 0) {
    Log("adminalert: ERROR: There was an error trying to block host (system fail) %s", target);
    return (ERROR);
  } else {
    Log("attackalert: Host %s has been blocked via dropped route using command: \"%s\"", target, commandStringFinal);
    return (TRUE);
  }
}

/* This will run a specified command with TARGET as the option if one is given.
 */
int KillRunCmd(char *target, int port, char *killString, char *detectionType) {
  char cleanAddr[MAXBUF], commandStringTemp[MAXBUF];
  char commandStringTemp2[MAXBUF], commandStringFinal[MAXBUF];
  char portString[MAXBUF];
  int killStatus = ERROR;

  CleanIpAddr(cleanAddr, target);
  snprintf(portString, MAXBUF, "%d", port);

  /* Tokens are not required, but we check for an error anyway */
  if (SubstString(cleanAddr, "$TARGET$", killString, commandStringTemp) == ERROR) {
    Log("adminalert: Error trying to parse $TARGET$ Token for KILL_RUN_CMD. Skipping.\n");
    return (ERROR);
  }

  if (SubstString(portString, "$PORT$", commandStringTemp, commandStringTemp2) == ERROR) {
    Log("adminalert: Error trying to parse $PORT$ Token for KILL_RUN_CMD. Skipping.\n");
    return (ERROR);
  }

  if (SubstString(detectionType, "$MODE$", commandStringTemp2, commandStringFinal) == ERROR) {
    Log("adminalert: Error trying to parse $MODE$ Token for KILL_RUN_CMD. Skipping.\n");
    return (ERROR);
  }

  /* Kill the bastard and report a status */
  killStatus = system(commandStringFinal);

  if (killStatus == 127) {
    Log("adminalert: ERROR: There was an error trying to run command (exec fail) %s", target);
    return (ERROR);
  } else if (killStatus < 0) {
    Log("adminalert: ERROR: There was an error trying to run command (system fail) %s", target);
    return (ERROR);
  } else {
    /* report success */
    Log("attackalert: External command run for host: %s using command: \"%s\"", target, commandStringFinal);
    return (TRUE);
  }
}

/* this function will drop the host into the TCP wrappers hosts.deny file to deny
 * all access. The drop route metod is preferred as this stops UDP attacks as well
 * as TCP. You may find though that host.deny will be a more permanent home.. */
int KillHostsDeny(char *target, int port, char *killString, char *detectionType) {
  FILE *output;
  char cleanAddr[MAXBUF], commandStringTemp[MAXBUF];
  char commandStringTemp2[MAXBUF], commandStringFinal[MAXBUF];
  char portString[MAXBUF];
  int substStatus = ERROR;

  CleanIpAddr(cleanAddr, target);

  snprintf(portString, MAXBUF, "%d", port);

#ifdef DEBUG
  Log("debug: KillHostsDeny: parsing string for block: %s\n", killString);
#endif

  substStatus =
      SubstString(cleanAddr, "$TARGET$", killString, commandStringTemp);
  if (substStatus == 0) {
    Log("adminalert: No target variable specified in KILL_HOSTS_DENY option. Skipping.\n");
    return (ERROR);
  } else if (substStatus == ERROR) {
    Log("adminalert: Error trying to parse $TARGET$ Token for KILL_HOSTS_DENY. Skipping.\n");
    return (ERROR);
  }

  if (SubstString(portString, "$PORT$", commandStringTemp, commandStringTemp2) == ERROR) {
    Log("adminalert: Error trying to parse $PORT$ Token for KILL_HOSTS_DENY. Skipping.\n");
    return (ERROR);
  }

  if (SubstString(detectionType, "$MODE$", commandStringTemp2, commandStringFinal) == ERROR) {
    Log("adminalert: Error trying to parse $MODE$ Token for KILL_HOSTS_DENY. Skipping.\n");
    return (ERROR);
  }

#ifdef DEBUG
  Log("debug: KillHostsDeny: result string for block: %s\n", commandStringFinal);
#endif

  if ((output = fopen(WRAPPER_HOSTS_DENY, "a")) == NULL) {
    Log("adminalert: cannot open hosts.deny file: %s for blocking.", WRAPPER_HOSTS_DENY);
    Log("securityalert: ERROR: There was an error trying to block host %s", target);
    return (FALSE);
  } else {
    fprintf(output, "%s\n", commandStringFinal);
    fclose(output);
    Log("attackalert: Host %s has been blocked via wrappers with string: \"%s\"", target, commandStringFinal);
    return (TRUE);
  }
}

/* check if the host is already blocked */
int IsBlocked(char *target, char *filename) {
  FILE *input;
  char buffer[MAXBUF], tempBuffer[MAXBUF];
  char *ipOffset;
  size_t count;

#ifdef DEBUG
  Log("debug: IsBlocked: Opening block file: %s \n", filename);
#endif
  if ((input = fopen(filename, "r")) == NULL) {
    Log("adminalert: ERROR: Cannot open blocked file: %s for reading. Will create.\n", filename);
    return (FALSE);
  }

  while (fgets(buffer, MAXBUF, input) != NULL) {
    if ((ipOffset = strstr(buffer, target)) != NULL) {
      for (count = 0; count < strlen(ipOffset); count++) {
        if ((isdigit(ipOffset[count])) || (ipOffset[count] == '.')) {
          tempBuffer[count] = ipOffset[count];
        } else {
          tempBuffer[count] = '\0';
          break;
        }
      }
      if (strcmp(target, tempBuffer) == 0) {
#ifdef DEBUG
        Log("debug: isBlocked: Host: %s found in blocked file\n", target);
#endif
        fclose(input);
        return (TRUE);
      }
    }
  }
#ifdef DEBUG
  Log("debug: IsBlocked: Host: %s NOT found in blocked file\n", target);
#endif
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

#ifdef DEBUG
  Log("debug: SubstString: Processing string: %s %d", target, strlen(target));
  Log("debug: SubstString: Processing search text: %s %d", replace, strlen(replace));
  Log("debug: SubstString: Processing replace text: %s %d", find, strlen(find));
#endif

  /* string not found in target */
  if (strstr(target, find) == NULL) {
    strncpy(result, target, MAXBUF);
#ifdef DEBUG
    Log("debug: SubstString: Result string: %s", result);
#endif
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
#ifdef DEBUG
  Log("debug: SubstString: Result string: %s", result);
#endif
  return (numberOfSubst);
}

int copyPrintableString(char *ptr, char *configToken, size_t maxbuf) {
  size_t count = 0;

  if(maxbuf == 0) {
    return FALSE;
  }

  while (count < maxbuf - 1) {
    if ((isprint(*ptr)) && *ptr != '"') {
      configToken[count] = *ptr;
    } else {
      break;
    }
    count++;
    ptr++;
  }

  configToken[count] = '\0';

  if (count == maxbuf - 1) {
    return FALSE;
  }

  return TRUE;
}

int testFileAccess(char *filename, char *mode) {
  FILE *testFile;

  if ((testFile = fopen(filename, mode)) == NULL) {
    return (FALSE);
  } else {
    fclose(testFile);
    return (TRUE);
  }
}
