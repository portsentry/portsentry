#!/bin/sh
. ./testlib.sh

runNmap 11 T

if ! findInFile "^debug: Source address 127.0.0.1 same as destination address 127.0.0.1, skipping" $PORTSENTRY_STDOUT ; then
  err "Expected self-ignore message not found"
fi

ok

