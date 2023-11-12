#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "portsentry.h"
#include "device.h"
#include "util.h"
#include "io.h"

struct Device *CreateDevice(const char *name) {
  struct Device *new;

  if (strlen(name) > IF_NAMESIZE) {
    Error("Device name %s is too long\n", name);
    return NULL;
  }

  new = malloc(sizeof(struct Device));
  if (new == NULL) {
    Error("Unable to allocate memory for device\n");
    return NULL;
  }

  memset(new, 0, sizeof(struct Device));

  SafeStrncpy(new->name, name, IF_NAMESIZE);

  return new;
}

uint8_t FreeDevice(struct Device *device) {
  if (device == NULL) {
    return FALSE;
  }

  if (device->handle != NULL) {
    pcap_close(device->handle);
    device->handle = NULL;
  }

  free(device);

  return TRUE;
}
