#!/bin/sh
. ./testlib.sh

runNmap 11 T

verbose "expect no trigger"
if ! findInFile "^Scan from: \[127.0.0.1\] (127.0.0.1) protocol: \[TCP\] port: \[11\] type: \[Connect\] IP opts: \[unknown\] ignored: \[false\] triggered: \[false\] noblock: \[unset\]" $PORTSENTRY_STDOUT; then
  err "Unable to find scan message w/ no trigger info"
fi

runNmap 11 T

confirmBlockTriggered tcp
confirmBlockFileSize 1 0

runNmap 11 T

confirmAlreadyBlocked
confirmBlockFileSize 1 0

ok
