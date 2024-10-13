// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include "block.h"
#include "portsentry.h"
#include "io.h"
#include "util.h"
#include "config_data.h"

static void FreeBlockedNodeList(struct BlockedNode *node);
static struct BlockedNode *AddBlockedNode(struct BlockedState *bs, struct sockaddr *address);
static int RemoveBlockedNode(struct BlockedState *bs, struct BlockedNode *node);
static struct sockaddr PrepBlockSockaddr(struct sockaddr *address);

int IsBlocked(struct sockaddr *address, struct BlockedState *bs) {
  struct BlockedNode *node = bs->head;
  struct sockaddr target = PrepBlockSockaddr(address);

  while (node != NULL) {
    if (memcmp(&node->address, &target, sizeof(struct sockaddr)) == 0) {
      return TRUE;
    }
    node = node->next;
  }

  return FALSE;
}

int BlockedStateInit(struct BlockedState *bs) {
  FILE *fp = NULL;
  char err[ERRNOMAXBUF];
  memset(bs, 0, sizeof(struct BlockedState));

  if ((fp = fopen(configData.blockedFile, "r")) == NULL) {
    Error("Cannot open blocked file: %s for reading: %s", configData.blockedFile, ErrnoString(err, sizeof(err)));
    return ERROR;
  }

  while (TRUE) {
    struct sockaddr address;
    if (fread(&address, sizeof(struct sockaddr), 1, fp) != 1) {
      break;
    }
    AddBlockedNode(bs, &address);
  }

  bs->isInitialized = TRUE;

  if (fp != NULL) {
    fclose(fp);
  }

  return TRUE;
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
  FILE *fp;
  struct BlockedNode *node = NULL;
  char err[ERRNOMAXBUF];
  struct sockaddr target = PrepBlockSockaddr(address);

  if ((fp = fopen(configData.blockedFile, "a")) == NULL) {
    Error("Unable to open blocked file: %s for writing: %s", configData.blockedFile, ErrnoString(err, sizeof(err)));
    goto exit;
  }

  if ((node = AddBlockedNode(bs, &target)) == NULL) {
    Error("Unable to add blocked node");
    goto exit;
  }

  if (fwrite(&target, sizeof(struct sockaddr), 1, fp) != 1) {
    Error("Unable to write blocked file: %s", configData.blockedFile);
    RemoveBlockedNode(bs, node);
    goto exit;
  }

  status = TRUE;

exit:
  if (fp != NULL) {
    fclose(fp);
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

static struct BlockedNode *AddBlockedNode(struct BlockedState *bs, struct sockaddr *address) {
  struct BlockedNode *node = NULL;

  if ((node = calloc(1, sizeof(struct BlockedNode))) == NULL) {
    Error("Unable to allocate memory for blocked node");
    return NULL;
  }

  memcpy(&node->address, address, sizeof(struct sockaddr));
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

static struct sockaddr PrepBlockSockaddr(struct sockaddr *address) {
  struct sockaddr sa;
  memset(&sa, 0, sizeof(struct sockaddr));

  if (address->sa_family == AF_INET) {
    ((struct sockaddr_in *)&sa)->sin_addr.s_addr = ((struct sockaddr_in *)address)->sin_addr.s_addr;
  } else if (address->sa_family == AF_INET6) {
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&sa;
    struct sockaddr_in6 *address6 = (struct sockaddr_in6 *)address;
    memcpy(&sa6->sin6_addr, &address6->sin6_addr, sizeof(struct in6_addr));
  }

  return sa;
}
