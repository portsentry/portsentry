#include <assert.h>
#include "../src/util.h"
#include "../src/portsentry.h"

void TestStrToUint16(void);

void TestStrToUint16(void) {
  uint16_t val;

  // Test valid cases
  assert(StrToUint16_t("1", &val) == TRUE && val == 1);
  assert(StrToUint16_t("65535", &val) == TRUE && val == 65535);
  assert(StrToUint16_t("8080", &val) == TRUE && val == 8080);
  assert(StrToUint16_t(" 123", &val) == TRUE && val == 123);

  // Test invalid cases
  assert(StrToUint16_t(NULL, &val) == FALSE);
  assert(StrToUint16_t("", &val) == FALSE);
  assert(StrToUint16_t("0", &val) == FALSE);
  assert(StrToUint16_t("-1", &val) == FALSE);
  assert(StrToUint16_t("65536", &val) == FALSE);
  assert(StrToUint16_t("12345678", &val) == FALSE);
  assert(StrToUint16_t("123abc", &val) == FALSE);
  assert(StrToUint16_t("abc", &val) == FALSE);
  assert(StrToUint16_t("12.34", &val) == FALSE);
  assert(StrToUint16_t("123 ", &val) == FALSE);
}

int main(void) {
  TestStrToUint16();
  return 0;
}
