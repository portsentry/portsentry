// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "portsentry.h"
#include "pcap_device.h"
#include "util.h"
#include "io.h"

struct Device *CreateDevice(const char *name) {
  struct Device *new;

  if (strlen(name) > (IF_NAMESIZE - 1)) {
    Error("Device name %s is too long", name);
    return NULL;
  }

  if ((new = calloc(1, sizeof(struct Device))) == NULL) {
    Error("Unable to allocate memory for device %s", name);
    return NULL;
  }

  SafeStrncpy(new->name, name, IF_NAMESIZE);

  return new;
}

int AddAddress(struct Device *device, const char *address, int type) {
  char **addresses = NULL;
  int addresses_count = 0;

  assert(device != NULL);
  assert(address != NULL);
  assert(type == AF_INET || type == AF_INET6);

  if (AddressExists(device, address, type) == TRUE) {
    return TRUE;
  }

  if (type == AF_INET) {
    addresses = device->inet4_addrs;
    addresses_count = device->inet4_addrs_count;
  } else if (type == AF_INET6) {
    addresses = device->inet6_addrs;
    addresses_count = device->inet6_addrs_count;
  } else {
    Crash(1, "Invalid address type");
  }

  if ((addresses = realloc(addresses, sizeof(char *) * (addresses_count + 1))) == NULL) {
    Crash(1, "Unable to reallocate IP address memory");
  }

  if ((addresses[addresses_count] = strdup(address)) == NULL) {
    Crash(1, "Unable to allocate memory for address %s", address);
  }

  addresses_count++;

  if (type == AF_INET) {
    device->inet4_addrs = addresses;
    device->inet4_addrs_count = addresses_count;
  } else if (type == AF_INET6) {
    device->inet6_addrs = addresses;
    device->inet6_addrs_count = addresses_count;
  } else {
    Crash(1, "Invalid address type");
  }

  return TRUE;
}

int AddressExists(const struct Device *device, const char *address, int type) {
  int i;
  char **addresses = NULL;
  int addresses_count = 0;

  assert(device != NULL);
  assert(address != NULL);
  assert(type == AF_INET || type == AF_INET6);

  if (type == AF_INET) {
    addresses = device->inet4_addrs;
    addresses_count = device->inet4_addrs_count;
  } else if (type == AF_INET6) {
    addresses = device->inet6_addrs;
    addresses_count = device->inet6_addrs_count;
  } else {
    Crash(1, "Invalid address type");
  }

  for (i = 0; i < addresses_count; i++) {
    if (strncmp(addresses[i], address, strlen(addresses[i])) == 0) {
      return TRUE;
    }
  }

  return FALSE;
}

uint8_t FreeDevice(struct Device *device) {
  int i;

  if (device == NULL) {
    return FALSE;
  }

  if (device->handle != NULL) {
    pcap_close(device->handle);
    device->handle = NULL;
  }

  if (device->inet4_addrs != NULL) {
    for (i = 0; i < device->inet4_addrs_count; i++) {
      free(device->inet4_addrs[i]);
    }
    free(device->inet4_addrs);
    device->inet4_addrs = NULL;
  }

  if (device->inet6_addrs != NULL) {
    for (i = 0; i < device->inet6_addrs_count; i++) {
      free(device->inet6_addrs[i]);
    }
    free(device->inet6_addrs);
    device->inet6_addrs = NULL;
  }

  free(device);

  return TRUE;
}
