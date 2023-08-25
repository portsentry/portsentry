#include <limits.h>

#include "portsentry.h"
#include "config_data.h"

void resetConfigData(struct ConfigData cd) {
  memset(&cd, 0, sizeof(cd));
}
