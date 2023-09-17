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
/* Send all changes/modifications/bugfixes to;                          */
/* craigrowland at users dot sourceforge dot net                        */
/*                                                                      */
/* $Id: portsentry_util.c,v 1.11 2003/05/23 17:41:59 crowland Exp crowland $ */
/************************************************************************/

#include "portsentry_util.h"
#include "portsentry.h"
#include "portsentry_io.h"

/* A replacement for strncpy that covers mistakes a little better */
char *SafeStrncpy(char *dest, const char *src, size_t size) {
  if (!dest) {
    dest = NULL;
    return (NULL);
  } else if (size < 1) {
    dest = NULL;
    return (NULL);
  }

  /* Null terminate string. Why the hell strncpy doesn't do this */
  /* for you is mystery to me. God I hate C. */
  memset(dest, '\0', size);
  strncpy(dest, src, size - 1);

  return (dest);
}

/************************************************************************/
/* Generic safety function to process an IP address and remove anything */
/* that is:                                                             */
/* 1) Not a number.                                                     */
/* 2) Not a period.                                                     */
/* 3) Greater than IPMAXBUF (15)                                        */
/************************************************************************/
char *CleanIpAddr(char *cleanAddr, const char *dirtyAddr) {
  int count = 0, maxdot = 0, maxoctet = 0;

  Debug("cleanAddr: Cleaning Ip address: %s", dirtyAddr);

  memset(cleanAddr, '\0', IPMAXBUF);
  /* dirtyAddr must be valid */
  if (dirtyAddr == NULL)
    return (cleanAddr);

  for (count = 0; count < IPMAXBUF - 1; count++) {
    if (isdigit(dirtyAddr[count])) {
      if (++maxoctet > 3) {
        cleanAddr[count] = '\0';
        break;
      }
      cleanAddr[count] = dirtyAddr[count];
    } else if (dirtyAddr[count] == '.') {
      if (++maxdot > 3) {
        cleanAddr[count] = '\0';
        break;
      }
      maxoctet = 0;
      cleanAddr[count] = dirtyAddr[count];
    } else {
      cleanAddr[count] = '\0';
      break;
    }
  }

  Debug("cleanAddr: Cleaned IpAddress: %s Dirty IpAddress: %s", cleanAddr, dirtyAddr);

  return (cleanAddr);
}

/************************************************************************/
/* Generic safety function to process an unresolved address and remove  */
/* anything that is:                                                    */
/* 1) Not a number.                                                     */
/* 2) Not a period.                                                     */
/* 3) Greater than DNSMAXBUF (255)                                      */
/* 4) Not a legal DNS character (a-z, A-Z, 0-9, - )			*/
/* 									*/
/* XXX THIS FUNCTION IS NOT COMPLETE 					*/
/************************************************************************/
int CleanAndResolve(char *resolvedHost, const char *unresolvedHost) {
  struct hostent *hostPtr = NULL;
  struct in_addr addr;

  Debug("CleanAndResolv: Resolving address: %s", unresolvedHost);

  memset(resolvedHost, '\0', DNSMAXBUF);
  /* unresolvedHost must be valid */
  if (unresolvedHost == NULL)
    return (ERROR);

  /* Not a valid address */
  if ((inet_aton(unresolvedHost, &addr)) == 0)
    return (ERROR);

  hostPtr = gethostbyaddr((char *)&addr.s_addr, sizeof(addr.s_addr), AF_INET);
  if (hostPtr != NULL)
    snprintf(resolvedHost, DNSMAXBUF, "%s", hostPtr->h_name);
  else
    snprintf(resolvedHost, DNSMAXBUF, "%s", unresolvedHost);

  Debug("CleanAndResolve: Cleaned Resolved: %s Dirty Unresolved: %s", resolvedHost, unresolvedHost);

  return (TRUE);
}

long getLong(char *buffer) {
  long value = 0;
  char *endptr = NULL;

  if (buffer == NULL)
    return ERROR;

  value = strtol(buffer, &endptr, 10);

  if (value == LONG_MIN || value == LONG_MAX)
    return ERROR;

  if (endptr == buffer)
    return ERROR;

  return value;
}
