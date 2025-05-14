#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include "../src/util.h"

void test_realloc_and_append(void) {
  int len = 0;
  char *buf = NULL;

  buf = ReallocAndAppend(buf, &len, "Hello %s", "World");
  assert(buf != NULL);
  assert(strcmp(buf, "Hello World") == 0);

  char *new_buf = ReallocAndAppend(buf, &len, ", %s!", "User");
  assert(new_buf != NULL);
  assert(strcmp(new_buf, "Hello World, User!") == 0);

  assert(ReallocAndAppend(NULL, NULL, "test") == NULL);
  assert(ReallocAndAppend(buf, &len, NULL) == NULL);

  free(new_buf);
}

int main(void) {
  test_realloc_and_append();
  return 0;
}