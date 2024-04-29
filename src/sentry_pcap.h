#pragma once
#include <pcap.h>

void HandlePacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
int PortSentryPcap(void);
