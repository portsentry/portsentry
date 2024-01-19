#pragma once
#include <net/if.h>
#include <pcap.h>

struct Device {
  pcap_t *handle;
  char name[IF_NAMESIZE];
  bpf_u_int32 mask;
  bpf_u_int32 net;
  int fd;

  char **inet4_addrs;
  int inet4_addrs_count;
  char **inet6_addrs;
  int inet6_addrs_count;

  struct Device *next;
};

struct Device *CreateDevice(const char *name);
uint8_t FreeDevice(struct Device *device);
int AddAddress(struct Device *device, const char *address, int type);
int AddressExists(const struct Device *device, const char *address, int type);
