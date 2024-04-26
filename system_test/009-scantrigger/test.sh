#!/bin/sh
. ./testlib.sh

runNmap 11 T

verbose "don't expect attackalert block message"
if findInFile "^attackalert: Host 127.0.0.1 has been blocked" $PORTSENTRY_STDOUT; then
  err "No attackalert message expected but was found"
fi

runNmap 11 T

confirmBlockTriggered tcp

verbose "expect block anyway when ignore file not found"
if ! findInFile "^Unable to open ignore file .*/portsentry.ignore. Continuing without it" $PORTSENTRY_STDERR; then
  err "Expected block anyway message not found"
fi

runNmap 11 T

verbose "expect attackalert block message"
if ! findInFile "^attackalert: Host 127.0.0.1 has been blocked" $PORTSENTRY_STDOUT; then
  err "Expected attackalert message not found"
fi

confirmAlreadyBlocked

ok
