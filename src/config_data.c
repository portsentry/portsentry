#include <limits.h>

#include "portsentry.h"
#include "config_data.h"

struct ConfigData configData;

void ResetConfigData(struct ConfigData *cd) {
  memset(cd, 0, sizeof(struct ConfigData));
  cd->logFlags = LOGFLAG_OUTPUT_STDOUT;
}
