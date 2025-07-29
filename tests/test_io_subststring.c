#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <assert.h>
#include "../src/io.h"
#include "../src/portsentry.h"

void TestSubstStringNormalCase(void) {
  char dest[100];
  const char *source = "Hello world, hello universe";
  const char *findToken = "hello";
  const char *replaceToken = "hi";

  int result = SubstString(replaceToken, findToken, source, dest, sizeof(dest));

  assert(result == 1);
  assert(strcmp(dest, "Hello world, hi universe") == 0);
  printf("Normal case test passed\n");
}

void TestSubstStringNoMatch(void) {
  char dest[100];
  const char *source = "Hello world";
  const char *findToken = "xyz";
  const char *replaceToken = "abc";

  int result = SubstString(replaceToken, findToken, source, dest, sizeof(dest));

  assert(result == 0);
  assert(strcmp(dest, "Hello world") == 0);
  printf("No match test passed\n");
}

void TestSubstStringEmptyReplace(void) {
  char dest[100];
  const char *source = "Hello world hello";
  const char *findToken = "hello";
  const char *replaceToken = "";

  int result = SubstString(replaceToken, findToken, source, dest, sizeof(dest));

  assert(result == 1);
  assert(strcmp(dest, "Hello world ") == 0);
  printf("Empty replace token test passed\n");
}

void TestSubstStringNullInputs(void) {
  char dest[100];
  const char *source = "test";
  const char *findToken = "test";
  const char *replaceToken = "new";

  assert(SubstString(NULL, findToken, source, dest, sizeof(dest)) == ERROR);
  assert(SubstString(replaceToken, NULL, source, dest, sizeof(dest)) == ERROR);
  assert(SubstString(replaceToken, findToken, NULL, dest, sizeof(dest)) == ERROR);
  assert(SubstString(replaceToken, findToken, source, NULL, sizeof(dest)) == ERROR);
  printf("Null inputs test passed\n");
}

void TestSubstStringInvalidSize(void) {
  char dest[100];
  const char *source = "test";
  const char *findToken = "test";
  const char *replaceToken = "new";

  assert(SubstString(replaceToken, findToken, source, dest, 0) == ERROR);
  assert(SubstString(replaceToken, findToken, source, dest, -1) == ERROR);
  printf("Invalid size test passed\n");
}

void TestSubstStringEmptyFindToken(void) {
  char dest[100];
  const char *source = "test";
  const char *findToken = "";
  const char *replaceToken = "new";

  assert(SubstString(replaceToken, findToken, source, dest, sizeof(dest)) == ERROR);
  printf("Empty find token test passed\n");
}

void TestSubstStringBufferOverflow(void) {
  char dest[10];
  const char *source = "Hello world hello universe";
  const char *findToken = "hello";
  const char *replaceToken = "very long replacement string";

  int result = SubstString(replaceToken, findToken, source, dest, sizeof(dest));

  assert(result == ERROR);
  printf("Buffer overflow test passed\n");
}

void TestSubstStringExactFit(void) {
  char dest[15];
  const char *source = "Hello world";
  const char *findToken = "world";
  const char *replaceToken = "universe";

  int result = SubstString(replaceToken, findToken, source, dest, sizeof(dest));

  assert(result == 1);
  assert(strcmp(dest, "Hello universe") == 0);
  printf("Exact fit test passed\n");
}

void TestSubstStringMultipleReplacements(void) {
  char dest[200];
  const char *source = "aaa aaa aaa aaa";
  const char *findToken = "aaa";
  const char *replaceToken = "bbb";

  int result = SubstString(replaceToken, findToken, source, dest, sizeof(dest));

  assert(result == 4);
  assert(strcmp(dest, "bbb bbb bbb bbb") == 0);
  printf("Multiple replacements test passed\n");
}

void TestSubstStringOverlappingTokens(void) {
  char dest[100];
  const char *source = "aaaaa";
  const char *findToken = "aaa";
  const char *replaceToken = "b";

  int result = SubstString(replaceToken, findToken, source, dest, sizeof(dest));

  assert(result == 1);
  assert(strcmp(dest, "baa") == 0);
  printf("Overlapping tokens test passed\n");
}

void TestSubstStringSpecialCharacters(void) {
  char dest[100];
  const char *source = "Hello\nworld\thello";
  const char *findToken = "\n";
  const char *replaceToken = " ";

  int result = SubstString(replaceToken, findToken, source, dest, sizeof(dest));

  assert(result == 1);
  assert(strcmp(dest, "Hello world\thello") == 0);
  printf("Special characters test passed\n");
}

void TestSubstStringUnicodeSafe(void) {
  char dest[100];
  const char *source = "Hello\x80\x81\x82 world";
  const char *findToken = "\x80\x81";
  const char *replaceToken = "test";

  int result = SubstString(replaceToken, findToken, source, dest, sizeof(dest));

  assert(result == 1);
  assert(strcmp(dest, "Hellotest\x82 world") == 0);
  printf("Unicode safe test passed\n");
}

void TestSubstStringBoundaryConditions(void) {
  char dest[3];
  const char *source = "test";
  const char *findToken = "test";
  const char *replaceToken = "new";

  // Should fail due to insufficient buffer space
  int result = SubstString(replaceToken, findToken, source, dest, sizeof(dest));
  assert(result == ERROR);

  // Should succeed with exact space
  char dest2[4];
  result = SubstString(replaceToken, findToken, source, dest2, sizeof(dest2));
  assert(result == 1);  // "new" is 3 chars + null terminator = 4, which fits in dest2[4]

  char dest3[5];
  result = SubstString(replaceToken, findToken, source, dest3, sizeof(dest3));
  assert(result == 1);
  assert(strcmp(dest3, "new") == 0);
  printf("Boundary conditions test passed\n");
}

int main(void) {
  TestSubstStringNormalCase();
  TestSubstStringNoMatch();
  TestSubstStringEmptyReplace();
  TestSubstStringNullInputs();
  TestSubstStringInvalidSize();
  TestSubstStringEmptyFindToken();
  TestSubstStringBufferOverflow();
  TestSubstStringExactFit();
  TestSubstStringMultipleReplacements();
  TestSubstStringOverlappingTokens();
  TestSubstStringSpecialCharacters();
  TestSubstStringUnicodeSafe();
  TestSubstStringBoundaryConditions();
  printf("All SubstString tests passed!\n");
  return 0;
}
