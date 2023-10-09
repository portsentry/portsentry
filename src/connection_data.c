#include <assert.h>
#include <string.h>
#include <unistd.h>

#include "config_data.h"
#include "connection_data.h"
#include "io.h"
#include "util.h"

static void ResetConnectionData(struct ConnectionData *cd);

static void ResetConnectionData(struct ConnectionData *cd) {
  memset(cd, 0, sizeof(struct ConnectionData));
}

void SetConnectionData(struct ConnectionData *cd, int port, int proto, uint8_t testPort) {
  assert(proto == IPPROTO_TCP || proto == IPPROTO_UDP);
  assert(testPort == TRUE || testPort == FALSE);

  ResetConnectionData(cd);

  cd->sockfd = ERROR;
  cd->port = port;
  cd->protocol = proto;

  if (testPort == TRUE) {
    cd->portInUse = IsPortInUse(port, proto);
  } else {
    cd->portInUse = ERROR;
  }
}

int ConstructConnectionData(struct ConnectionData *cd, int cdSize) {
  int i, cdIdx;

  memset(cd, 0, sizeof(struct ConnectionData) * cdSize);

  if (cdSize <= 0) {
    Error("adminalert: ConstructConnectionData() called with invalid size. Aborting.");
    return 0;
  }

  cdIdx = 0;
  if (configData.sentryMode == SENTRY_MODE_TCP || configData.sentryMode == SENTRY_MODE_STCP) {
    for (i = 0; i < configData.tcpPortsLength; i++) {
      SetConnectionData(&cd[cdIdx], configData.tcpPorts[i], IPPROTO_TCP, TRUE);

      if (cd[cdIdx].portInUse != FALSE) {
        continue;
      }

      cdIdx++;

      if (cdIdx >= cdSize) {
        Error("adminalert: TCP port count exceeds size of ConnectionData array. Aborting.");
        return cdIdx;
      }
    }
  } else if (configData.sentryMode == SENTRY_MODE_ATCP) {
    for (i = 0; i < configData.tcpAdvancedPort; i++) {
      SetConnectionData(&cd[cdIdx], i, IPPROTO_TCP, TRUE);

      if (cd[cdIdx].portInUse != TRUE) {
        continue;
      }

      cdIdx++;

      if (cdIdx >= cdSize) {
        Error("adminalert: TCP port count exceeds size of ConnectionData array. Aborting.");
        return cdIdx;
      }
    }
  }

  if (configData.sentryMode == SENTRY_MODE_UDP || configData.sentryMode == SENTRY_MODE_SUDP) {
    for (i = 0; i < configData.udpPortsLength; i++) {
      SetConnectionData(&cd[cdIdx], configData.udpPorts[i], IPPROTO_UDP, TRUE);

      if (cd[cdIdx].portInUse != FALSE) {
        continue;
      }

      cdIdx++;

      if (cdIdx >= cdSize) {
        Error("adminalert: UDP port count exceeds size of ConnectionData array. Aborting.");
        return cdIdx;
      }
    }
  } else if (configData.sentryMode == SENTRY_MODE_AUDP) {
    for (i = 0; i < configData.udpAdvancedPort; i++) {
      SetConnectionData(&cd[cdIdx], i, IPPROTO_UDP, TRUE);

      if (cd[cdIdx].portInUse != TRUE) {
        continue;
      }

      cdIdx++;

      if (cdIdx >= cdSize) {
        Error("adminalert: UDP port count exceeds size of ConnectionData array. Aborting.");
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

struct ConnectionData *FindConnectionData(struct ConnectionData *connectionData, int connectionDataSize, uint16_t port, int proto) {
  int i;

  for (i = 0; i < connectionDataSize; i++) {
    if (connectionData[i].port == port && connectionData[i].protocol == proto) {
      return &connectionData[i];
    }
  }

  return NULL;
}
