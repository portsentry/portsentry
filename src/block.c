// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "block.h"
#include "portsentry.h"
#include "io.h"
#include "util.h"
#include "config_data.h"

static void FreeBlockedNodeList(struct BlockedNode *node);
static struct BlockedNode *AddBlockedNode(struct BlockedState *bs, const struct sockaddr *address);
static int RemoveBlockedNode(struct BlockedState *bs, const struct BlockedNode *node);
static int WriteAddressToBlockFile(FILE *fp, const struct sockaddr_in6 *addr);

int IsBlocked(const struct sockaddr *address, const struct BlockedState *bs) {
  struct BlockedNode *node;

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
      if (memcmp(&current->sin_addr.s_addr, &target->sin_addr.s_addr, sizeof(target->sin_addr.s_addr)) == 0) {
        return TRUE;
      }
    } else if (address->sa_family == AF_INET6 && node->address.sin6_family == AF_INET6) {
      struct sockaddr_in6 *target = (struct sockaddr_in6 *)address;
      struct sockaddr_in6 *current = (struct sockaddr_in6 *)&node->address;
      if (memcmp(&current->sin6_addr, &target->sin6_addr, sizeof(target->sin6_addr)) == 0) {
        return TRUE;
      }
    }

    node = node->next;
  }

  return FALSE;
}

/* Initialize the BlockedState structure by reading the blocked file.
 * returns:
 *  TRUE: Success
 *  FALSE: Potentially partial success, but the structure is not fully initialized but usable
 *  ERROR: Failure, unrecoverable error
 */
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
      status = FALSE;
      goto exit;
    }

    if (family == AF_INET) {
      struct sockaddr_in *sa4 = (struct sockaddr_in *)&sa;
      if (fread(&sa4->sin_addr.s_addr, sizeof(sa4->sin_addr.s_addr), 1, fp) != 1) {
        Error("Unable to read address from blocked file: %s", configData.blockedFile);
        status = FALSE;
        goto exit;
      }

      sa.sin6_family = family;
      AddBlockedNode(bs, (struct sockaddr *)&sa);
    } else if (family == AF_INET6) {
      if (fread(&sa.sin6_addr, sizeof(sa.sin6_addr), 1, fp) != 1) {
        Error("Unable to read address from blocked file: %s", configData.blockedFile);
        status = FALSE;
        goto exit;
      }

      sa.sin6_family = family;
      AddBlockedNode(bs, (struct sockaddr *)&sa);
    } else {
      Error("Unsupported address family: %d", family);
      status = FALSE;
      goto exit;
    }
  }

  status = TRUE;

exit:
  if (status == TRUE || status == FALSE) {
    bs->isInitialized = TRUE;
  }

  if (fp != NULL) {
    fclose(fp);
  }

  if (status == ERROR) {
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

int WriteBlockedFile(const struct sockaddr *address, struct BlockedState *bs) {
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

  if ((node = AddBlockedNode(bs, address)) == NULL) {
    Error("Unable to add blocked node");
    goto exit;
  }

  // Ignore file write errors. Atlreast the addr is in memory and will be ignored in this session.
  // The function will report any errors to the log.
  WriteAddressToBlockFile(fp, (struct sockaddr_in6 *)address);
  status = TRUE;

exit:
  if (fp != NULL) {
    fclose(fp);
  }

  if (status != TRUE && node != NULL) {
    RemoveBlockedNode(bs, node);
  }

  return status;
}

int RewriteBlockedFile(const struct BlockedState *bs) {
  int status = ERROR;
  FILE *fp = NULL;
  struct BlockedNode *node = NULL;
  char err[ERRNOMAXBUF];

  assert(bs != NULL);

  if (bs == NULL || bs->isInitialized == FALSE || bs->head == NULL) {
    return FALSE;
  }

  if ((fp = fopen(configData.blockedFile, "w")) == NULL) {
    Error("Unable to open blocked file: %s for writing: %s", configData.blockedFile, ErrnoString(err, sizeof(err)));
    goto exit;
  }

  node = bs->head;
  while (node != NULL) {
    if (WriteAddressToBlockFile(fp, &node->address) == ERROR) {
      goto exit;
    }

    node = node->next;
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

static int RemoveBlockedNode(struct BlockedState *bs, const struct BlockedNode *node) {
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

static int WriteAddressToBlockFile(FILE *fp, const struct sockaddr_in6 *addr) {
  assert(fp != NULL);
  assert(addr != NULL);

  if (fp == NULL || addr == NULL || (addr->sin6_family != AF_INET && addr->sin6_family != AF_INET6)) {
    return FALSE;
  }

  if (addr->sin6_family == AF_INET) {
    struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;

    if (fwrite(&addr4->sin_family, sizeof(addr4->sin_family), 1, fp) != 1) {
      Error("Unable to write sin_family to blocked file: %s", configData.blockedFile);
      return ERROR;
    }

    if (fwrite(&addr4->sin_addr.s_addr, sizeof(addr4->sin_addr.s_addr), 1, fp) != 1) {
      Error("Unable to write sin_addr to blocked file: %s", configData.blockedFile);
      return ERROR;
    }
  } else if (addr->sin6_family == AF_INET6) {
    if (fwrite(&addr->sin6_family, sizeof(addr->sin6_family), 1, fp) != 1) {
      Error("Unable to write sin6_family to blocked file: %s", configData.blockedFile);
      return ERROR;
    }

    if (fwrite(&addr->sin6_addr, sizeof(addr->sin6_addr), 1, fp) != 1) {
      Error("Unable to write sin6_addr to blocked file: %s", configData.blockedFile);
      return ERROR;
    }
  }

  return TRUE;
}
