#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../src/portsentry.h"
#include "../src/config_data.h"
#include "../src/state_machine.h"

// Redefine MAX_HASH_SIZE to a small value for testing eviction
#define MAX_HASH_SIZE 2

#include "../src/config_data.h"

struct sockaddr_in create_ipv4_addr(const char *ip_str) {
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  if (inet_pton(AF_INET, ip_str, &addr.sin_addr) != 1) {
    perror("inet_pton IPv4 failed");
    exit(EXIT_FAILURE);
  }
  return addr;
}

struct sockaddr_in6 create_ipv6_addr(const char *ip_str) {
  struct sockaddr_in6 addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin6_family = AF_INET6;
  if (inet_pton(AF_INET6, ip_str, &addr.sin6_addr) != 1) {
    perror("inet_pton IPv6 failed");
    exit(EXIT_FAILURE);
  }
  return addr;
}

void test_uninitialized_state() {
  struct SentryState state;
  state.isInitialized = FALSE;
  struct sockaddr_in addr_ipv4 = create_ipv4_addr("192.168.1.1");

  configData.configTriggerCount = 1;

  int result = CheckState(&state, (struct sockaddr *)&addr_ipv4);
  assert(result == ERROR);
}

void test_trigger_count_zero() {
  struct SentryState state;
  InitSentryState(&state);
  struct sockaddr_in addr_ipv4 = create_ipv4_addr("192.168.1.1");

  configData.configTriggerCount = 0;

  int result = CheckState(&state, (struct sockaddr *)&addr_ipv4);
  assert(result == TRUE);

  FreeSentryState(&state);
}

void test_ipv4_trigger_logic() {
  struct SentryState state;
  InitSentryState(&state);
  struct sockaddr_in addr1 = create_ipv4_addr("192.168.0.1");
  struct sockaddr_in addr2 = create_ipv4_addr("192.168.0.2");

  configData.configTriggerCount = 3;
  int result;

  result = CheckState(&state, (struct sockaddr *)&addr1);
  assert(result == FALSE);
  result = CheckState(&state, (struct sockaddr *)&addr1);
  assert(result == FALSE);

  result = CheckState(&state, (struct sockaddr *)&addr2);
  assert(result == FALSE);

  result = CheckState(&state, (struct sockaddr *)&addr1);
  assert(result == TRUE);

  result = CheckState(&state, (struct sockaddr *)&addr1);
  assert(result == TRUE);

  result = CheckState(&state, (struct sockaddr *)&addr2);
  assert(result == FALSE);

  result = CheckState(&state, (struct sockaddr *)&addr2);
  assert(result == TRUE);

  FreeSentryState(&state);
}

void test_ipv4_eviction() {
  assert(MAX_HASH_SIZE == 2);

  struct SentryState state;
  InitSentryState(&state);
  struct sockaddr_in addr1 = create_ipv4_addr("10.0.0.1");
  struct sockaddr_in addr2 = create_ipv4_addr("10.0.0.2");
  struct sockaddr_in addr3 = create_ipv4_addr("10.0.0.3");

  configData.configTriggerCount = 1;
  int result;

  result = CheckState(&state, (struct sockaddr *)&addr1);
  assert(result == FALSE);
  result = CheckState(&state, (struct sockaddr *)&addr2);
  assert(result == FALSE);

  result = CheckState(&state, (struct sockaddr *)&addr3);
  assert(result == FALSE);

  result = CheckState(&state, (struct sockaddr *)&addr1);
  assert(result == FALSE);

  result = CheckState(&state, (struct sockaddr *)&addr2);
  assert(result == FALSE);

  FreeSentryState(&state);
}

void test_ipv6_trigger_logic() {
  struct SentryState state;
  InitSentryState(&state);
  struct sockaddr_in6 addr1 = create_ipv6_addr("2001:db8::1");
  struct sockaddr_in6 addr2 = create_ipv6_addr("2001:db8::2");

  configData.configTriggerCount = 2;
  int result;

  result = CheckState(&state, (struct sockaddr *)&addr1);
  assert(result == FALSE);

  result = CheckState(&state, (struct sockaddr *)&addr2);
  assert(result == FALSE);

  result = CheckState(&state, (struct sockaddr *)&addr1);
  assert(result == TRUE);

  result = CheckState(&state, (struct sockaddr *)&addr1);
  assert(result == TRUE);

  result = CheckState(&state, (struct sockaddr *)&addr2);
  assert(result == TRUE);

  FreeSentryState(&state);
}

void test_ipv6_eviction() {
  assert(MAX_HASH_SIZE == 2);

  struct SentryState state;
  InitSentryState(&state);
  struct sockaddr_in6 addr1 = create_ipv6_addr("2001:db8::a");
  struct sockaddr_in6 addr2 = create_ipv6_addr("2001:db8::b");
  struct sockaddr_in6 addr3 = create_ipv6_addr("2001:db8::c");

  configData.configTriggerCount = 1;
  int result;

  result = CheckState(&state, (struct sockaddr *)&addr1);
  assert(result == FALSE);
  result = CheckState(&state, (struct sockaddr *)&addr2);
  assert(result == FALSE);

  result = CheckState(&state, (struct sockaddr *)&addr3);
  assert(result == FALSE);

  result = CheckState(&state, (struct sockaddr *)&addr1);
  assert(result == FALSE);

  result = CheckState(&state, (struct sockaddr *)&addr2);
  assert(result == FALSE);

  FreeSentryState(&state);
}

void test_unsupported_family() {
  struct SentryState state;
  InitSentryState(&state);

  struct sockaddr unsupported_addr;
  unsupported_addr.sa_family = AF_UNIX;
  configData.configTriggerCount = 1;

  int result = CheckState(&state, &unsupported_addr);
  assert(result == ERROR);

  FreeSentryState(&state);
}

int main() {
  test_uninitialized_state();
  test_trigger_count_zero();
  test_ipv4_trigger_logic();
  test_ipv4_eviction();
  test_ipv6_trigger_logic();
  test_ipv6_eviction();
  test_unsupported_family();

  return 0;
}
