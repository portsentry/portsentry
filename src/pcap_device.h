// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#pragma once
#include <net/if.h>
#include <pcap.h>

#define HAVE_ETHERNET_HDR_FALSE 0
#define HAVE_ETHERNET_HDR_TRUE 1
#define HAVE_ETHERNET_HDR_UNKNOWN 2

struct Device {
  pcap_t *handle;
  char name[IF_NAMESIZE];
  int fd;

  char **inet4_addrs;
  int inet4_addrs_count;
  char **inet6_addrs;
  int inet6_addrs_count;

  struct Device *next;
};

struct Device *CreateDevice(const char *name);
uint8_t FreeDevice(struct Device *device);
int AddAddress(struct Device *device, const char *address, const int type);
int AddressExists(const struct Device *device, const char *address, const int type);
int GetNoAddresses(const struct Device *device);
int RemoveAddress(struct Device *device, const char *address);