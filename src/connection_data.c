#include <string.h>

#include "config_data.h"
#include "connection_data.h"

int ConstructConnectionData(struct ConnectionData *cd, int cdSize) {
  int i, cdIdx;

  memset(cd, 0, sizeof(struct ConnectionData) * cdSize);

  if (cdSize <= 0) {
    Log("adminalert: ERROR: ConstructConnectionData() called with invalid size. Aborting.");
    return 0;
  }

  cdIdx = 0;
  if (configData.sentryMode == SENTRY_MODE_TCP || configData.sentryMode == SENTRY_MODE_STCP) {
    for (i = 0; i < configData.tcpPortsLength; i++) {
      cd[cdIdx].sockfd = ERROR;
      cd[cdIdx].port = configData.tcpPorts[i];
      cd[cdIdx].protocol = IPPROTO_TCP;

      cdIdx++;

      if (cdIdx >= cdSize) {
        Log("adminalert: ERROR: TCP port count exceeds size of ConnectionData array. Aborting.");
        return cdIdx;
      }
    }
  }

  if (configData.sentryMode == SENTRY_MODE_UDP || configData.sentryMode == SENTRY_MODE_SUDP) {
    for (i = 0; i < configData.udpPortsLength; i++) {
      cd[cdIdx].sockfd = ERROR;
      cd[cdIdx].port = configData.udpPorts[i];
      cd[cdIdx].protocol = IPPROTO_UDP;

      cdIdx++;

      if (cdIdx >= cdSize) {
        Log("adminalert: ERROR: UDP port count exceeds size of ConnectionData array. Aborting.");
        return cdIdx;
      }
    }
  }

  return cdIdx;
}

void PruneConnectionDataByInvalidSockfd(struct ConnectionData *connectionData, int *connectionDataSize) {
  int i;

  for (i = 0; i < *connectionDataSize; i++) {
    if (connectionData[i].sockfd == -1) {
      if (i < *connectionDataSize - 1) {
        memmove(&connectionData[i], &connectionData[i + 1], sizeof(struct ConnectionData) * (*connectionDataSize - i - 1));
      }
      (*connectionDataSize)--;
      i--;
    }
  }
}

void CloseConnectionData(struct ConnectionData *connectionData, int connectionDataSize) {
  int i;

  for (i = 0; i < connectionDataSize; i++) {
    if (connectionData[i].sockfd != -1) {
      close(connectionData[i].sockfd);
      connectionData[i].sockfd = -1;
    }
  }
}
