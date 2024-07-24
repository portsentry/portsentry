// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#pragma once
#include <stdint.h>

struct PortRange {
  uint16_t start;
  uint16_t end;
};

struct Port {
  uint16_t single;
  struct PortRange range;
};

void ResetPort(struct Port *port);
void SetPortSingle(struct Port *port, uint16_t single);
void SetPortRange(struct Port *port, uint16_t start, uint16_t end);
int IsPortInRange(struct Port *port, uint16_t portNumber);
int IsPortSingle(const struct Port *port);
int ParsePort(const char *portString, struct Port *port);
