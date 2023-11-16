#pragma once
#include <net/if.h>
#include <pcap.h>

struct ListenerModule {
  struct Device *root;
};

struct ListenerModule *AllocListenerModule(void);
void FreeListenerModule(struct ListenerModule *lm);
void InitListenerModule(struct ListenerModule *lm);
uint8_t AddDevice(struct ListenerModule *lm, struct Device *add);
uint8_t RemoveDevice(struct ListenerModule *lm, struct Device *remove);

uint8_t FindDeviceByName(struct ListenerModule *lm, const char *name);
