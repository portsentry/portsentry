#!/bin/sh
. ./testlib.sh

# Wait for portsentry to start
findInFile "Going into listen mode on TCP port: 11" $PORTSENTRY_STDOUT || err "Expected port 11 in listen mode"

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
