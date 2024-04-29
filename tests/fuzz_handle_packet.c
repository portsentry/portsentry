#include <stdio.h>
#include <stdint.h>

#include "../src/sentry_pcap.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 80)
    return 0;
  HandlePacket(NULL, NULL, Data);
  return 0;
}
