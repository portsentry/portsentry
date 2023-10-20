#!/bin/sh
. ./testlib.sh

verbose "expect connect to tcp localhost:11 w/ banner"
if ! $TEST_DIR/portcon 11 tcp | grep -q "Some banner printed on port"; then
  err "Expected banner not found"
fi

confirmBlockTriggered tcp

if ! findInFile "^Unable to open ignore file .*/portsentry.ignore. Continuing without it" $PORTSENTRY_STDERR; then
  err "Expected block anyway message not found"
fi

runNmap 11 T

confirmAlreadyBlocked

ok
