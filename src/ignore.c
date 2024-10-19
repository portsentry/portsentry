// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <assert.h>
#include <arpa/inet.h>

#include "io.h"
#include "portsentry.h"
#include "config_data.h"
#include "ignore.h"
#include "util.h"

static int IgnoreParse(const char *buffer, struct IgnoreIp *ignoreIp);
static int IsValidIPChar(char c);

static int IsValidIPChar(char c) {
  if ((c >= '0' && c <= '9') || c == '.' || c == ':' || (c >= 'a' && c <= 'f') || c == '/') {
    return TRUE;
  }

  return FALSE;
}

static int IgnoreParse(const char *buffer, struct IgnoreIp *ignoreIp) {
  int ret, status = ERROR;
  struct addrinfo hints, *res = NULL;
  char *separator = NULL;
  long mask = -1;

  memset(ignoreIp, 0, sizeof(struct IgnoreIp));

  if ((separator = strchr(buffer, '/')) != NULL) {
    *separator = '\0';
    separator++;

    if ((mask = getLong(separator)) == ERROR) {
      separator--;
      *separator = '/';
      Error("Invalid netmask in ignore file: %s", buffer);
      goto exit;
    }

    if (mask < 0 || mask > 128) {
      Error("Invalid netmask in ignore file, must be 0-128: %s", buffer);
      goto exit;
    }
  }

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_NUMERICHOST;

  if ((ret = getaddrinfo(buffer, NULL, &hints, &res)) != 0) {
    Error("Unable to read IP address %s: %s", buffer, gai_strerror(ret));
    goto exit;
  }

  if (res->ai_family == AF_INET) {
    ignoreIp->family = AF_INET;
    memcpy(&ignoreIp->ip.addr4, &((struct sockaddr_in *)res->ai_addr)->sin_addr, sizeof(struct in_addr));
    if (mask == -1) {
      ignoreIp->mask.mask4.s_addr = 0xffffffff;
    } else {
      ignoreIp->mask.mask4.s_addr = htonl(0xffffffff << (32 - mask));
    }
  } else if (res->ai_family == AF_INET6) {
    ignoreIp->family = AF_INET6;
    memcpy(&ignoreIp->ip.addr6, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr, sizeof(struct in6_addr));
    if (mask == -1) {
      memset(&ignoreIp->mask.mask6, 0xff, sizeof(struct in6_addr));
    } else {
      memset(&ignoreIp->mask.mask6, 0, sizeof(struct in6_addr));
      for (int i = 0; i < 16; i++) {
        if (mask >= 8) {
          ignoreIp->mask.mask6.s6_addr[i] = 0xff;
          mask -= 8;
        } else {
          ignoreIp->mask.mask6.s6_addr[i] = 0xff << (8 - mask);
          break;
        }
      }
    }
  } else {
    Error("Invalid IP address family: %s", buffer);
    goto exit;
  }

  status = TRUE;

exit:

  if (res != NULL) {
    freeaddrinfo(res);
    res = NULL;
  }

  return status;
}

void FreeIgnore(struct IgnoreState *is) {
  if (is->ignoreIpList != NULL) {
    free(is->ignoreIpList);
  }

  memset(is, 0, sizeof(struct IgnoreState));
  is->isInitialized = FALSE;
}

/* Initialize the ignore state
 * Returns TRUE if the ignore file is read successfully
 * Returns FALSE if the ignore file is not set
 * Returns ERROR if the ignore file is set but cannot be read
 */
int InitIgnore(struct IgnoreState *is) {
  FILE *fp = NULL;
  int status = ERROR;
  char buffer[MAXBUF];
  struct IgnoreIp ii;

  if (strlen(configData.ignoreFile) == 0) {
    return FALSE;
  }

  FreeIgnore(is);

  if ((fp = fopen(configData.ignoreFile, "r")) == NULL) {
    Error("Unable to open ignore file: %s", configData.ignoreFile);
    goto exit;
  }

  while (fgets(buffer, MAXBUF, fp) != NULL) {
    if ((buffer[0] == '#') || (buffer[0] == '\n'))
      continue;

    buffer[strlen(buffer) - 1] = '\0';  // Remove newline

    for (size_t i = 0; i < strlen(buffer); i++) {
      if (!IsValidIPChar(buffer[i])) {
        Error("Invalid character in ignore file: %s", buffer);
        goto exit;
      }
    }

    if (IgnoreParse(buffer, &ii) != TRUE) {
      goto exit;
    }

    if ((is->ignoreIpList = realloc(is->ignoreIpList, (is->ignoreIpListSize + 1) * sizeof(struct IgnoreIp))) == NULL) {
      Error("Unable to allocate memory for ignore list");
      goto exit;
    }

    is->ignoreIpListSize++;
    memcpy(&is->ignoreIpList[is->ignoreIpListSize - 1], &ii, sizeof(struct IgnoreIp));
  }

  is->isInitialized = TRUE;

  if (configData.logFlags & LOGFLAG_VERBOSE) {
    for (int i = 0; i < is->ignoreIpListSize; i++) {
      if (is->ignoreIpList[i].family == AF_INET) {
        char ip[INET_ADDRSTRLEN];
        char mask[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &is->ignoreIpList[i].ip.addr4, ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &is->ignoreIpList[i].mask.mask4, mask, INET_ADDRSTRLEN);
        Verbose("Ignoring IP: %s/%s", ip, mask);
      } else if (is->ignoreIpList[i].family == AF_INET6) {
        char ip[INET6_ADDRSTRLEN];
        char mask[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &is->ignoreIpList[i].ip.addr6, ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &is->ignoreIpList[i].mask.mask6, mask, INET6_ADDRSTRLEN);
        Verbose("Ignoring IP: %s/%s", ip, mask);
      }
    }
  }

  status = TRUE;

exit:
  if (fp != NULL) {
    fclose(fp);
  }

  if (status != TRUE) {
    FreeIgnore(is);
  }

  return status;
}

int IgnoreIpIsPresent(const struct IgnoreState *is, const struct sockaddr *sa) {
  assert(is != NULL);
  assert(sa != NULL);

  if (is->isInitialized == FALSE) {
    return ERROR;
  }

  for (int i = 0; i < is->ignoreIpListSize; i++) {
    if (is->ignoreIpList[i].family != sa->sa_family) {
      continue;
    }

    if (sa->sa_family == AF_INET) {
      struct sockaddr_in *sin = (struct sockaddr_in *)sa;
      if ((sin->sin_addr.s_addr & is->ignoreIpList[i].mask.mask4.s_addr) == is->ignoreIpList[i].ip.addr4.s_addr) {
        return TRUE;
      }
    } else if (sa->sa_family == AF_INET6) {
      struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
      for (int j = 0; j < 16; j++) {
        if ((sin6->sin6_addr.s6_addr[j] & is->ignoreIpList[i].mask.mask6.s6_addr[j]) != is->ignoreIpList[i].ip.addr6.s6_addr[j]) {
          break;
        }
        if (j == 15) {
          return TRUE;
        }
      }
    }
  }
  return FALSE;
}
