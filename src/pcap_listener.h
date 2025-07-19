// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: BSD-2-Clause

#pragma once
#include <net/if.h>
#include <pcap.h>

struct ListenerModule {
  struct Device *root;
};

int GetNoDevices(const struct ListenerModule *lm);
size_t GetNoRunningDevices(const struct ListenerModule *lm);
struct ListenerModule *AllocListenerModule(void);
void FreeListenerModule(struct ListenerModule *lm);
int InitListenerModule(struct ListenerModule *lm);
uint8_t AddDevice(struct ListenerModule *lm, struct Device *add);
uint8_t RemoveDevice(struct ListenerModule *lm, const struct Device *remove);

struct Device *FindDeviceByName(const struct ListenerModule *lm, const char *name);
struct Device *FindDeviceByIpAddr(const struct ListenerModule *lm, const char *ip_addr);
struct pollfd *SetupPollFds(const struct ListenerModule *lm, nfds_t *nfds);
struct pollfd *RemovePollFd(struct pollfd *fds, nfds_t *nfds, const int fd);
struct Device *GetDeviceByFd(const struct ListenerModule *lm, const int fd);
struct pollfd *AddPollFd(struct pollfd *fds, nfds_t *nfds, const int fd);
// void HandlePacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
