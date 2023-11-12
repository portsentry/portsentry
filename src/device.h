#pragma once
#include <net/if.h>
#include <pcap.h>

struct Device {
  pcap_t *handle;
  char name[IF_NAMESIZE];
  bpf_u_int32 mask;
  bpf_u_int32 net;
  struct Device *next;
};

struct Device *CreateDevice(const char *name);
uint8_t FreeDevice(struct Device *device);
