// tests/test_port.c

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>

#include "../src/port.h"
#include "../src/util.h"
#include "../src/portsentry.h"

void test_reset_port(void) {
  struct Port port;

  port.single = 1234;
  port.range.start = 1000;
  port.range.end = 2000;

  ResetPort(&port);

  assert(port.single == 0);
  assert(port.range.start == 0);
  assert(port.range.end == 0);
}

void test_set_port_single(void) {
  struct Port port;

  SetPortSingle(&port, 8080);
  assert(port.single == 8080);
  assert(port.range.start == 0);
  assert(port.range.end == 0);

  SetPortSingle(&port, 443);
  assert(port.single == 443);
  assert(port.range.start == 0);
  assert(port.range.end == 0);
}

void test_set_port_range(void) {
  struct Port port;

  SetPortRange(&port, 1000, 2000);
  assert(port.single == 0);
  assert(port.range.start == 1000);
  assert(port.range.end == 2000);

  SetPortRange(&port, 3000, 4000);
  assert(port.single == 0);
  assert(port.range.start == 3000);
  assert(port.range.end == 4000);
}

void test_is_port_present(void) {
  struct Port ports[3];

  SetPortSingle(&ports[0], 80);
  SetPortRange(&ports[1], 1000, 2000);
  SetPortSingle(&ports[2], 443);

  assert(IsPortPresent(ports, 3, 80) == TRUE);
  assert(IsPortPresent(ports, 3, 443) == TRUE);

  assert(IsPortPresent(ports, 3, 1500) == TRUE);
  assert(IsPortPresent(ports, 3, 1000) == TRUE);
  assert(IsPortPresent(ports, 3, 2000) == TRUE);

  assert(IsPortPresent(ports, 3, 81) == FALSE);
  assert(IsPortPresent(ports, 3, 999) == FALSE);
  assert(IsPortPresent(ports, 3, 2001) == FALSE);
  assert(IsPortPresent(ports, 3, 444) == FALSE);
}

void test_is_port_in_range(void) {
  struct Port port;

  SetPortSingle(&port, 80);
  assert(IsPortInRange(&port, 80) == TRUE);
  assert(IsPortInRange(&port, 81) == FALSE);

  SetPortRange(&port, 1000, 2000);
  assert(IsPortInRange(&port, 1000) == TRUE);
  assert(IsPortInRange(&port, 1500) == TRUE);
  assert(IsPortInRange(&port, 2000) == TRUE);
  assert(IsPortInRange(&port, 999) == FALSE);
  assert(IsPortInRange(&port, 2001) == FALSE);
}

void test_is_port_single(void) {
  struct Port port;

  SetPortSingle(&port, 80);
  assert(IsPortSingle(&port) == TRUE);

  SetPortRange(&port, 1000, 2000);
  assert(IsPortSingle(&port) == FALSE);

  ResetPort(&port);
  assert(IsPortSingle(&port) == FALSE);
}

void test_parse_port(void) {
  struct Port port;

  assert(ParsePort("80", &port) == TRUE);
  assert(port.single == 80);
  assert(port.range.start == 0);
  assert(port.range.end == 0);

  assert(ParsePort("1000-2000", &port) == TRUE);
  assert(port.single == 0);
  assert(port.range.start == 1000);
  assert(port.range.end == 2000);

  assert(ParsePort("0", &port) == ERROR);             // Port 0
  assert(ParsePort("0-1000", &port) == ERROR);        // Range start 0
  assert(ParsePort("1000-0", &port) == ERROR);        // Range end 0
  assert(ParsePort("abc", &port) == ERROR);           // Non-numeric
  assert(ParsePort("1000-abc", &port) == ERROR);      // Invalid range end
  assert(ParsePort("abc-2000", &port) == ERROR);      // Invalid range start
  assert(ParsePort("", &port) == ERROR);              // Empty string
  assert(ParsePort("123456789012", &port) == ERROR);  // Too long string
}

void test_get_no_ports(void) {
  struct Port ports[3];

  SetPortSingle(&ports[0], 80);
  SetPortRange(&ports[1], 1000, 2000);
  SetPortSingle(&ports[2], 443);

  int count = GetNoPorts(ports, 3);
  assert(count == 1003);  // 1 + (2000-1000+1) + 1

  assert(GetNoPorts(NULL, 0) == 0);

  struct Port single_port;
  SetPortSingle(&single_port, 80);
  assert(GetNoPorts(&single_port, 1) == 1);

  struct Port range_port;
  SetPortRange(&range_port, 1000, 2000);
  assert(GetNoPorts(&range_port, 1) == 1001);  // 2000-1000+1
}

int main(void) {
  test_reset_port();
  test_set_port_single();
  test_set_port_range();
  test_is_port_present();
  test_is_port_in_range();
  test_is_port_single();
  test_parse_port();
  test_get_no_ports();
  return 0;
}
