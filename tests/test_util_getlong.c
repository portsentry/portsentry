#include <stdio.h>
#include <assert.h>
#include <limits.h>
#include "../src/util.h"
#include "../src/portsentry.h"

void TestGetLongValidNumbers(void) {
  assert(GetLong("123") == 123);
  assert(GetLong("0") == 0);
  assert(GetLong("-456") == -456);
  printf("Valid numbers test passed\n");
}

void TestGetLongNullInput(void) {
  assert(GetLong(NULL) == ERROR);
  printf("Null input test passed\n");
}

void TestGetLongInvalidInput(void) {
  assert(GetLong("abc") == ERROR);
  assert(GetLong("") == ERROR);
  assert(GetLong(" ") == ERROR);
  assert(GetLong("123abc") == ERROR);  // trailing characters
  printf("Invalid input test passed\n");
}

void TestGetLongBoundaryCases(void) {
  char max_buffer[32];
  char min_buffer[32];
  snprintf(max_buffer, sizeof(max_buffer), "%ld", LONG_MAX);
  snprintf(min_buffer, sizeof(min_buffer), "%ld", LONG_MIN);

  assert(GetLong(max_buffer) == ERROR);
  assert(GetLong(min_buffer) == ERROR);
  printf("Boundary cases test passed\n");
}

int main(void) {
  TestGetLongValidNumbers();
  TestGetLongNullInput();
  TestGetLongInvalidInput();
  TestGetLongBoundaryCases();
  printf("All GetLong tests passed!\n");
  return 0;
}
