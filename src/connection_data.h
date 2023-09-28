#pragma once

#include <stdint.h>

struct ConnectionData {
  uint16_t port;
  int protocol;
  int sockfd;
  uint8_t portInUse;
};

int ConstructConnectionData(struct ConnectionData *cd, int cdSize);
void PruneConnectionDataByInUsePorts(struct ConnectionData *connectionData, int *connectionDataSize);
void CloseConnectionData(struct ConnectionData *connectionData, int connectionDataSize);
