// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <assert.h>

#include "block.h"
#include "portsentry.h"
#include "io.h"
#include "util.h"
#include "config_data.h"

static void FreeBlockedNodeList(struct BlockedNode *node);
static struct BlockedNode *AddBlockedNode(struct BlockedState *bs, const struct sockaddr *address);
static int RemoveBlockedNode(struct BlockedState *bs, struct BlockedNode *node);
static void DebugPrintBlockedNodeList(const char *msg, const struct BlockedState *bs);

int IsBlocked(struct sockaddr *address, struct BlockedState *bs) {
  struct BlockedNode *node;
  char b1[4096], b2[4096];

  assert(address != NULL);
  assert(bs != NULL);

  if (bs == NULL) {
    return FALSE;
  }

  node = bs->head;

  while (node != NULL) {
    if (address->sa_family == AF_INET && node->address.sin6_family == AF_INET) {
      struct sockaddr_in *target = (struct sockaddr_in *)address;
      struct sockaddr_in *current = (struct sockaddr_in *)&node->address;
      Debug("IsBlocked: Checking target %s against %s", DebugPrintSockaddr(address, b1, 4096), DebugPrintSockaddr((struct sockaddr *)&node->address, b2, 4096));
      if (memcmp(&current->sin_addr.s_addr, &target->sin_addr.s_addr, sizeof(target->sin_addr.s_addr)) == 0) {
        return TRUE;
      }
    } else if (address->sa_family == AF_INET6 && node->address.sin6_family == AF_INET6) {
      struct sockaddr_in6 *target = (struct sockaddr_in6 *)address;
      struct sockaddr_in6 *current = (struct sockaddr_in6 *)&node->address;
      Debug("IsBlocked: Checking target %s against %s", DebugPrintSockaddr(address, b1, 4096), DebugPrintSockaddr((struct sockaddr *)&node->address, b2, 4096));
      if (memcmp(&current->sin6_addr, &target->sin6_addr, sizeof(target->sin6_addr)) == 0) {
        return TRUE;
      }
    }

    node = node->next;
  }

  return FALSE;
}

int BlockedStateInit(struct BlockedState *bs) {
  int status = ERROR;
  FILE *fp = NULL;
  char err[ERRNOMAXBUF];
  sa_family_t family;
  struct sockaddr_in6 sa;  // Use the larger sockaddr_in6 to hold both IPv4 and IPv6 addresses. Otherwise _FORTIFY_SOURCE=2 will erroneously complain in AddBlockedNode

  assert(bs != NULL);

  memset(bs, 0, sizeof(struct BlockedState));

  if ((fp = fopen(configData.blockedFile, "r")) == NULL) {
    Error("Cannot open blocked file: %s for reading: %s", configData.blockedFile, ErrnoString(err, sizeof(err)));
    goto exit;
  }

  while (TRUE) {
    memset(&sa, 0, sizeof(sa));

    if (fread(&family, sizeof(family), 1, fp) != 1) {
      if (feof(fp)) {
        break;
      }
      Error("Unable to read address family from blocked file: %s", configData.blockedFile);
      goto exit;
    }

    if (family == AF_INET) {
      struct sockaddr_in *sa4 = (struct sockaddr_in *)&sa;
      if (fread(&sa4->sin_addr.s_addr, sizeof(sa4->sin_addr.s_addr), 1, fp) != 1) {
        Error("Unable to read address from blocked file: %s", configData.blockedFile);
        goto exit;
      }

      sa.sin6_family = family;
      AddBlockedNode(bs, (struct sockaddr *)&sa);
    } else if (family == AF_INET6) {
      if (fread(&sa.sin6_addr, sizeof(sa.sin6_addr), 1, fp) != 1) {
        Error("Unable to read address from blocked file: %s", configData.blockedFile);
        goto exit;
      }

      sa.sin6_family = family;
      AddBlockedNode(bs, (struct sockaddr *)&sa);
    } else {
      Error("Unsupported address family: %d", family);
      goto exit;
    }
  }

  DebugPrintBlockedNodeList("Already blocked:", bs);

  status = TRUE;
  bs->isInitialized = TRUE;

exit:
  if (fp != NULL) {
    fclose(fp);
  }

  if (status != TRUE) {
    BlockedStateFree(bs);
  }

  return status;
}

void BlockedStateFree(struct BlockedState *bs) {
  if (bs->isInitialized == FALSE) {
    return;
  }

  FreeBlockedNodeList(bs->head);
  memset(bs, 0, sizeof(struct BlockedState));
  bs->isInitialized = FALSE;
}

int WriteBlockedFile(struct sockaddr *address, struct BlockedState *bs) {
  int status = ERROR;
  FILE *fp = NULL;
  struct BlockedNode *node = NULL;
  char err[ERRNOMAXBUF];

  assert(address != NULL);
  assert(bs != NULL);
  assert(address->sa_family == AF_INET || address->sa_family == AF_INET6);

  if ((fp = fopen(configData.blockedFile, "a")) == NULL) {
    Error("Unable to open blocked file: %s for writing: %s", configData.blockedFile, ErrnoString(err, sizeof(err)));
    goto exit;
  }

  Debug("Storing blocked address: %s", DebugPrintSockaddr(address, err, ERRNOMAXBUF));
  if ((node = AddBlockedNode(bs, address)) == NULL) {
    Error("Unable to add blocked node");
    goto exit;
  }

  if (address->sa_family == AF_INET) {
    struct sockaddr_in *addr = (struct sockaddr_in *)address;

    if (fwrite(&addr->sin_family, sizeof(addr->sin_family), 1, fp) != 1) {
      Error("Unable to write sin_family to blocked file: %s", configData.blockedFile);
      goto exit;
    }

    if (fwrite(&addr->sin_addr.s_addr, sizeof(addr->sin_addr.s_addr), 1, fp) != 1) {
      Error("Unable to write sin_addr to blocked file: %s", configData.blockedFile);
      goto exit;
    }

  } else if (address->sa_family == AF_INET6) {
    struct sockaddr_in6 *addr = (struct sockaddr_in6 *)address;

    if (fwrite(&addr->sin6_family, sizeof(addr->sin6_family), 1, fp) != 1) {
      Error("Unable to write sin6_family to blocked file: %s", configData.blockedFile);
      goto exit;
    }

    if (fwrite(&addr->sin6_addr, sizeof(addr->sin6_addr), 1, fp) != 1) {
      Error("Unable to write sin6_addr to blocked file: %s", configData.blockedFile);
      goto exit;
    }
  } else {
    Error("Unsupported address family: %d", address->sa_family);
    goto exit;
  }

  status = TRUE;

exit:
  if (fp != NULL) {
    fclose(fp);
  }

  if (status != TRUE) {
    if (node != NULL) {
      RemoveBlockedNode(bs, node);
    }
  }

  return status;
}

static void FreeBlockedNodeList(struct BlockedNode *node) {
  if (node == NULL) {
    return;
  }

  FreeBlockedNodeList(node->next);
  free(node);
}

static struct BlockedNode *AddBlockedNode(struct BlockedState *bs, const struct sockaddr *address) {
  struct BlockedNode *node = NULL;

  assert(bs != NULL);
  assert(address != NULL);
  assert(address->sa_family == AF_INET || address->sa_family == AF_INET6);

  if ((node = calloc(1, sizeof(struct BlockedNode))) == NULL) {
    Error("Unable to allocate memory for blocked node");
    return NULL;
  }

  if (address->sa_family == AF_INET) {
    struct sockaddr_in *addr = (struct sockaddr_in *)address;
    memcpy(&node->address, addr, sizeof(struct sockaddr_in));
  } else if (address->sa_family == AF_INET6) {
    struct sockaddr_in6 *addr = (struct sockaddr_in6 *)address;
    memcpy(&node->address, addr, sizeof(struct sockaddr_in6));
  } else {
    free(node);
    return NULL;
  }

  node->next = bs->head;
  bs->head = node;
  return node;
}

static int RemoveBlockedNode(struct BlockedState *bs, struct BlockedNode *node) {
  struct BlockedNode *prev = NULL;
  struct BlockedNode *current = bs->head;

  if (node == NULL) {
    return FALSE;
  }

  while (current != NULL) {
    if (current == node) {
      if (prev == NULL) {
        bs->head = current->next;
      } else {
        prev->next = current->next;
      }
      free(current);
      return TRUE;
    }
    prev = current;
    current = current->next;
  }
  return FALSE;
}

static void DebugPrintBlockedNodeList(const char *msg, const struct BlockedState *bs) {
  struct BlockedNode *node;

  assert(bs != NULL);

  if (bs == NULL || bs->head == NULL) {
    return;
  }

  node = bs->head;
  while (node != NULL) {
    char buf[MAXBUF];
    Debug("%s %s", msg, DebugPrintSockaddr((struct sockaddr *)&node->address, buf, MAXBUF));
    node = node->next;
  }
}
