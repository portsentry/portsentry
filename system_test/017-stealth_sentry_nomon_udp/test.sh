#!/bin/sh
. ./testlib.sh

runNmap 10 U

verbose "don't expect attackalert block message"
if findInFile "^attackalert: Host 127.0.0.1 has been blocked" $PORTSENTRY_STDOUT; then
  err "No attackalert message expected but was found"
fi

ok
