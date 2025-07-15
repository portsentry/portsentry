// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: BSD-2-Clause

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
void SetPortSingle(struct Port *port, const uint16_t single);
void SetPortRange(struct Port *port, const uint16_t start, const uint16_t end);
int IsPortPresent(const struct Port *port, const int portLength, const uint16_t portNumber);
int IsPortInRange(const struct Port *port, const uint16_t portNumber);
int IsPortSingle(const struct Port *port);
int ParsePort(const char *portString, struct Port *port);
size_t GetNoPorts(const struct Port *port, const size_t portLength);
