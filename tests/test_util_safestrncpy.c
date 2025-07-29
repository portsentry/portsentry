#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../src/util.h"

void TestSafeStrncpyNormalCase(void);
void TestSafeStrncpyNullDest(void);
void TestSafeStrncpyZeroSize(void);
void TestSafeStrncpyExactSize(void);
void TestSafeStrncpyTruncated(void);
void TestSafeStrncpySecurity(void);

void TestSafeStrncpyNormalCase(void) {
  char dest[10];
  const char *src = "test";
  char *result = SafeStrncpy(dest, src, sizeof(dest));

  assert(result == dest);
  assert(strcmp(dest, "test") == 0);
  printf("Normal case test passed\n");
}

void TestSafeStrncpyNullDest(void) {
  char *result = SafeStrncpy(NULL, "test", 10);
  assert(result == NULL);
  printf("Null destination test passed\n");
}

void TestSafeStrncpyZeroSize(void) {
  char dest[10];
  char *result = SafeStrncpy(dest, "test", 0);
  assert(result == NULL);
  printf("Zero size test passed\n");
}

void TestSafeStrncpyExactSize(void) {
  char dest[5];
  char *result = SafeStrncpy(dest, "test", 5);
  assert(result == dest);
  assert(strcmp(dest, "test") == 0);
  printf("Exact size test passed\n");
}

void TestSafeStrncpyTruncated(void) {
  char dest[4];
  char *result = SafeStrncpy(dest, "test", 4);
  assert(result == dest);
  assert(strcmp(dest, "tes") == 0);
  printf("Truncated test passed\n");
}

void TestSafeStrncpySecurity(void) {
  char dest[32];

  assert(SafeStrncpy(dest, "test", MAX_SAFESTRNCMP_SIZE + 1) == NULL);

  strcpy(dest, "test");
  assert(SafeStrncpy(dest + 1, dest, sizeof(dest) - 1) != NULL);
  assert(strcmp(dest + 1, "test") == 0);

  char *long_string = malloc(MAX_SAFESTRNCMP_SIZE);
  if (long_string) {
    memset(long_string, 'A', MAX_SAFESTRNCMP_SIZE - 1);
    long_string[MAX_SAFESTRNCMP_SIZE - 1] = '\0';
    assert(SafeStrncpy(dest, long_string, sizeof(dest)) != NULL);
    assert(strlen(dest) == sizeof(dest) - 1);
    free(long_string);
  }
}

int main(void) {
  TestSafeStrncpyNormalCase();
  TestSafeStrncpyNullDest();
  TestSafeStrncpyZeroSize();
  TestSafeStrncpyExactSize();
  TestSafeStrncpyTruncated();
  TestSafeStrncpySecurity();
  printf("All tests passed!\n");
  return 0;
}
