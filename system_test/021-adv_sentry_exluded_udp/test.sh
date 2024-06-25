#!/bin/sh
. ./testlib.sh

runNmap 520 U

verbose "don't expect attackalert block message"
if findInFile "^Scan from: \[127\.0\.0\.1\]" $PORTSENTRY_STDOUT; then
  err "No attackalert message expected but was found"
fi

ok
