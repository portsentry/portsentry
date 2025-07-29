// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: BSD-2-Clause

#include <string.h>

#include "port.h"
#include "portsentry.h"
#include "io.h"
#include "util.h"

#define MAX_RANGE_PORTSTRING 12

void ResetPort(struct Port *port) {
  port->single = 0;
  port->range.start = 0;
  port->range.end = 0;
}

void SetPortSingle(struct Port *port, const uint16_t single) {
  ResetPort(port);
  port->single = single;
}

void SetPortRange(struct Port *port, const uint16_t start, const uint16_t end) {
  ResetPort(port);
  port->range.start = start;
  port->range.end = end;
}

int IsPortPresent(const struct Port *port, const size_t portLength, const uint16_t portNumber) {
  size_t i;

  for (i = 0; i < portLength; i++) {
    if (IsPortInRange(&port[i], portNumber) == TRUE) {
      return TRUE;
    }
  }

  return FALSE;
}

int IsPortInRange(const struct Port *port, const uint16_t portNumber) {
  if (port->single == portNumber) {
    return TRUE;
  }
  if (port->range.start <= portNumber && port->range.end >= portNumber) {
    return TRUE;
  }
  return FALSE;
}

int IsPortSingle(const struct Port *port) {
  return port->single != 0;
}

int ParsePort(const char *portString, struct Port *port) {
  char *dash;
  uint16_t start;
  uint16_t end;
  uint16_t single;
  char ps[MAX_RANGE_PORTSTRING];

  if (strlen(portString) >= MAX_RANGE_PORTSTRING) {
    Error("Invalid port range: %s", portString);
    return ERROR;
  }

  SafeStrncpy(ps, portString, MAX_RANGE_PORTSTRING);

  dash = strchr(ps, '-');
  if (dash != NULL) {
    *dash = '\0';
    if (StrToUint16_t(ps, &start) == FALSE) {
      Error("Unable to extract port range start: %s", portString);
      return ERROR;
    }

    if (StrToUint16_t(dash + 1, &end) == FALSE) {
      Error("Unable to extract port range end: %s", portString);
      return ERROR;
    }

    if (start == 0 || end == 0) {
      Error("Invalid port range: %s, 0 is not a valid port", portString);
      return ERROR;
    }

    SetPortRange(port, start, end);
  } else {
    if (StrToUint16_t(ps, &single) == FALSE) {
      Error("Unable to extract single port: %s", portString);
      return ERROR;
    }

    if (single == 0) {
      Error("Invalid port: %s, 0 is not a valid port", portString);
      return ERROR;
    }
    SetPortSingle(port, single);
  }

  return TRUE;
}

size_t GetNoPorts(const struct Port *port, const size_t portLength) {
  size_t i;
  size_t noPorts = 0;

  for (i = 0; i < portLength; i++) {
    if (IsPortSingle(&port[i])) {
      noPorts++;
    } else {
      noPorts += (size_t)(port[i].range.end - port[i].range.start + 1);
    }
  }

  return noPorts;
}
