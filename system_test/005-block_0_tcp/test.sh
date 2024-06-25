#!/bin/sh
. ./testlib.sh

runNmap 11 T

confirmStdoutScanMessage tcp
confirmHistoryFileMessage tcp

runNmap 11 T

verbose "expect 2 scan messages"
if ! grep "^Scan from: \[127\.0\.0\.1\] (127\.0\.0\.1) protocol: \[TCP\] port: \[11\]" $PORTSENTRY_STDOUT | wc -l | grep -q 2; then
  err "Expected attackalert connect message quantity not found"
fi

ok
