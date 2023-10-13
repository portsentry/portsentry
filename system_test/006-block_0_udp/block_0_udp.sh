#!/bin/sh
. ./testlib.sh

verbose "expect connect to udp localhost:11"
nmap -sU -p11-11 localhost >/dev/null

verbose "expect attackalert connect message"
if ! findInFile "^attackalert: Connect from host: 127\.0\.0\.1/127\.0\.0\.1 to UDP port: 11" $PORTSENTRY_STDOUT; then
  err "Expected attackalert connect message not found"
fi

ok
