#!/bin/sh
. ./testlib.sh

verbose "expect connect to udp localhost:11 w/ banner"
if ! $TEST_DIR/portcon 11 udp | grep -q "Some banner printed on port"; then
  err "Expected banner not found"
fi

confirmBlockTriggered udp

runNmap 11 U

confirmAlreadyBlocked

ok
