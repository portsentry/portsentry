#include <assert.h>
#include <string.h>

#include "../src/util.h"
#include "../src/portsentry.h"

void TestCreateDateTime(void) {
  char buffer[MIN_DATETIME_BUFFER];
  assert(CreateDateTime(buffer, sizeof(buffer)) == TRUE);

  assert(CreateDateTime(NULL, MIN_DATETIME_BUFFER) == ERROR);

  char small_buf[10];
  assert(CreateDateTime(small_buf, sizeof(small_buf)) == ERROR);
}

int main(void) {
  TestCreateDateTime();
  return 0;
}
