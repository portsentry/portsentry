#!/bin/sh
. ./testlib.sh

runNmap 11 U

verbose "expect attackalert connect message"
if ! findInFile "^attackalert: Connect from host: 127\.0\.0\.1/127\.0\.0\.1 to UDP port: 11" $PORTSENTRY_STDOUT; then
  err "Expected attackalert connect message not found"
fi

ok
