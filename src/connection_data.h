#pragma once

#include <stdint.h>

struct ConnectionData {
  uint16_t port;
  int protocol;
  int sockfd;
  uint8_t portInUse;
};

void SetConnectionData(struct ConnectionData *cd, int port, int proto, uint8_t testPort);
int ConstructConnectionData(struct ConnectionData *cd, int cdSize);
void PruneConnectionDataByInUsePorts(struct ConnectionData *connectionData, int *connectionDataSize);
void CloseConnectionData(struct ConnectionData *connectionData, int connectionDataSize);
struct ConnectionData *FindConnectionData(struct ConnectionData *connectionData, int connectionDataSize, uint16_t port, int proto);
