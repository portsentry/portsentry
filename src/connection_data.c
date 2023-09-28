#include <string.h>

#include "config_data.h"
#include "connection_data.h"

static void ResetConnectionData(struct ConnectionData *cd);
static void SetConnectionData(struct ConnectionData *cd, int port, int proto);

static void ResetConnectionData(struct ConnectionData *cd) {
  memset(cd, 0, sizeof(struct ConnectionData));
}

static void SetConnectionData(struct ConnectionData *cd, int port, int proto) {
  assert(proto == IPPROTO_TCP || proto == IPPROTO_UDP);

  ResetConnectionData(cd);

  cd->sockfd = ERROR;
  cd->port = port;
  cd->protocol = proto;
  cd->portInUse = IsPortInUse(port, proto);
}

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
      SetConnectionData(&cd[cdIdx], configData.tcpPorts[i], IPPROTO_TCP);

      if (cd[cdIdx].portInUse != FALSE) {
        continue;
      }

      cdIdx++;

      if (cdIdx >= cdSize) {
        Log("adminalert: ERROR: TCP port count exceeds size of ConnectionData array. Aborting.");
        return cdIdx;
      }
    }
  }

  if (configData.sentryMode == SENTRY_MODE_UDP || configData.sentryMode == SENTRY_MODE_SUDP) {
    for (i = 0; i < configData.udpPortsLength; i++) {
      SetConnectionData(&cd[cdIdx], configData.udpPorts[i], IPPROTO_UDP);

      if (cd[cdIdx].portInUse != FALSE) {
        continue;
      }

      cdIdx++;

      if (cdIdx >= cdSize) {
        Log("adminalert: ERROR: UDP port count exceeds size of ConnectionData array. Aborting.");
        return cdIdx;
      }
    }
  }

  return cdIdx;
}

void PruneConnectionDataByInUsePorts(struct ConnectionData *connectionData, int *connectionDataSize) {
  int i;

  for (i = 0; i < *connectionDataSize; i++) {
    if (connectionData[i].portInUse != FALSE) {
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
