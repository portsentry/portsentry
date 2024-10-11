// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "block.h"
#include "portsentry.h"
#include "io.h"
#include "util.h"

int IsBlocked(char *target, char *filename) {
  FILE *input;
  char buffer[MAXBUF], tempBuffer[MAXBUF], err[ERRNOMAXBUF];
  char *ipOffset;
  size_t count;

  Debug("IsBlocked: Opening block file: %s ", filename);

  if ((input = fopen(filename, "r")) == NULL) {
    Error("Cannot open blocked file: %s for reading: %s. Will create.", filename, ErrnoString(err, sizeof(err)));
    return (FALSE);
  }

  while (fgets(buffer, MAXBUF, input) != NULL) {
    if ((ipOffset = strstr(buffer, target)) != NULL) {
      for (count = 0; count < strlen(ipOffset); count++) {
        if ((isdigit((int)ipOffset[count])) || (ipOffset[count] == '.') || (ipOffset[count] == ':')) {
          tempBuffer[count] = ipOffset[count];
        } else {
          tempBuffer[count] = '\0';
          break;
        }
      }
      if (strcmp(target, tempBuffer) == 0) {
        Debug("isBlocked: Host: %s found in blocked file", target);
        fclose(input);
        return (TRUE);
      }
    }
  }
  Debug("IsBlocked: Host: %s NOT found in blocked file", target);
  fclose(input);
  return (FALSE);
}
