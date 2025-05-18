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

struct sockaddr_in CreateIpv4Addr(const char *ip_str) {
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  if (inet_pton(AF_INET, ip_str, &addr.sin_addr) != 1) {
    perror("inet_pton IPv4 failed");
    exit(EXIT_FAILURE);
  }
  return addr;
}

struct sockaddr_in6 CreateIpv6Addr(const char *ip_str) {
  struct sockaddr_in6 addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin6_family = AF_INET6;
  if (inet_pton(AF_INET6, ip_str, &addr.sin6_addr) != 1) {
    perror("inet_pton IPv6 failed");
    exit(EXIT_FAILURE);
  }
  return addr;
}

void TestUninitializedState(void) {
  struct SentryState state;
  state.isInitialized = FALSE;
  struct sockaddr_in addr_ipv4 = CreateIpv4Addr("192.168.1.1");

  configData.configTriggerCount = 1;

  int result = CheckState(&state, (struct sockaddr *)&addr_ipv4);
  assert(result == ERROR);
}

void TestTriggerCountZero(void) {
  struct SentryState state;
  InitSentryState(&state);
  struct sockaddr_in addr_ipv4 = CreateIpv4Addr("192.168.1.1");

  configData.configTriggerCount = 0;

  int result = CheckState(&state, (struct sockaddr *)&addr_ipv4);
  assert(result == TRUE);

  FreeSentryState(&state);
}

void TestIpv4TriggerLogic(void) {
  struct SentryState state;
  InitSentryState(&state);
  struct sockaddr_in addr1 = CreateIpv4Addr("192.168.0.1");
  struct sockaddr_in addr2 = CreateIpv4Addr("192.168.0.2");

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

void TestIpv4Eviction(void) {
  assert(MAX_HASH_SIZE == 2);

  struct SentryState state;
  InitSentryState(&state);
  struct sockaddr_in addr1 = CreateIpv4Addr("10.0.0.1");
  struct sockaddr_in addr2 = CreateIpv4Addr("10.0.0.2");
  struct sockaddr_in addr3 = CreateIpv4Addr("10.0.0.3");

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

void TestIpv6TriggerLogic(void) {
  struct SentryState state;
  InitSentryState(&state);
  struct sockaddr_in6 addr1 = CreateIpv6Addr("2001:db8::1");
  struct sockaddr_in6 addr2 = CreateIpv6Addr("2001:db8::2");

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

void TestIpv6Eviction(void) {
  assert(MAX_HASH_SIZE == 2);

  struct SentryState state;
  InitSentryState(&state);
  struct sockaddr_in6 addr1 = CreateIpv6Addr("2001:db8::a");
  struct sockaddr_in6 addr2 = CreateIpv6Addr("2001:db8::b");
  struct sockaddr_in6 addr3 = CreateIpv6Addr("2001:db8::c");

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

void TestUnsupportedFamily(void) {
  struct SentryState state;
  InitSentryState(&state);

  struct sockaddr unsupported_addr;
  unsupported_addr.sa_family = AF_UNIX;
  configData.configTriggerCount = 1;

  int result = CheckState(&state, &unsupported_addr);
  assert(result == ERROR);

  FreeSentryState(&state);
}

int main(void) {
  TestUninitializedState();
  TestTriggerCountZero();
  TestIpv4TriggerLogic();
  TestIpv4Eviction();
  TestIpv6TriggerLogic();
  TestIpv6Eviction();
  TestUnsupportedFamily();

  return 0;
}
