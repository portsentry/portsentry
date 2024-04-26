#!/bin/sh
. ./testlib.sh

runNmap 11 U

confirmBlockTriggered audp

verbose "expect block anyway when ignore file not found"
if ! findInFile "^Unable to open ignore file .*/portsentry.ignore. Continuing without it" $PORTSENTRY_STDERR; then
  err "Expected block anyway message not found"
fi

runNmap 11 U

confirmAlreadyBlocked

ok
