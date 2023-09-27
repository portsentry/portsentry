#pragma once

#include <stdint.h>

struct ConnectionData {
  uint16_t port;
  int protocol;
  int sockfd;
};

int ConstructConnectionData(struct ConnectionData *cd, int cdSize);
void PruneConnectionDataByInvalidSockfd(struct ConnectionData *connectionData, int *connectionDataSize);
void CloseConnectionData(struct ConnectionData *connectionData, int connectionDataSize);
