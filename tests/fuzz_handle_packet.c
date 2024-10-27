// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#include <stdio.h>
#include <stdint.h>

uint8_t g_isRunning = 1;

#include "../src/sentry_pcap.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 80)
    return 0;
  HandlePacket(NULL, NULL, Data);
  return 0;
}
