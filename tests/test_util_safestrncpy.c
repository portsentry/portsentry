#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../src/util.h"

void test_safestrncpy_normal_case(void) {
  char dest[10];
  const char *src = "test";
  char *result = SafeStrncpy(dest, src, sizeof(dest));

  assert(result == dest);
  assert(strcmp(dest, "test") == 0);
  printf("Normal case test passed\n");
}

void test_safestrncpy_null_dest(void) {
  char *result = SafeStrncpy(NULL, "test", 10);
  assert(result == NULL);
  printf("Null destination test passed\n");
}

void test_safestrncpy_zero_size(void) {
  char dest[10];
  char *result = SafeStrncpy(dest, "test", 0);
  assert(result == NULL);
  printf("Zero size test passed\n");
}

void test_safestrncpy_exact_size(void) {
  char dest[5];
  char *result = SafeStrncpy(dest, "test", 5);
  assert(result == dest);
  assert(strcmp(dest, "test") == 0);
  printf("Exact size test passed\n");
}

void test_safestrncpy_truncated(void) {
  char dest[4];
  char *result = SafeStrncpy(dest, "test", 4);
  assert(result == dest);
  assert(strcmp(dest, "tes") == 0);
  printf("Truncated test passed\n");
}

int main(void) {
  test_safestrncpy_normal_case();
  test_safestrncpy_null_dest();
  test_safestrncpy_zero_size();
  test_safestrncpy_exact_size();
  printf("All tests passed!\n");
  return 0;
}