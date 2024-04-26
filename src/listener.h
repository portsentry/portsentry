#pragma once
#include <net/if.h>
#include <pcap.h>

struct ListenerModule {
  struct Device *root;
};

int GetNoDevices(const struct ListenerModule *lm);
struct ListenerModule *AllocListenerModule(void);
void FreeListenerModule(struct ListenerModule *lm);
int InitListenerModule(struct ListenerModule *lm);
uint8_t AddDevice(struct ListenerModule *lm, struct Device *add);
uint8_t RemoveDevice(struct ListenerModule *lm, struct Device *remove);

uint8_t FindDeviceByName(struct ListenerModule *lm, const char *name);
struct pollfd *SetupPollFds(const struct ListenerModule *lm, int *nfds);
struct Device *GetDeviceByFd(const struct ListenerModule *lm, const int fd);
// void HandlePacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
