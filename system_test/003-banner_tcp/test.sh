#!/bin/sh
. ./testlib.sh

verbose "expect connect to tcp localhost:11 w/ banner"
if ! $TEST_DIR/portcon 11 tcp | grep -q "Some banner printed on port"; then
  err "Expected banner not found"
fi

confirmBlockTriggered tcp

runNmap 11 T

confirmAlreadyBlocked

ok
