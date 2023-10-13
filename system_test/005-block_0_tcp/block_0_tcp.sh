#!/bin/sh
. ./testlib.sh

verbose "expect connect to tcp localhost:11"
nmap -sT -p11-11 localhost >/dev/null

verbose "expect attackalert connect message"
if ! findInFile "^attackalert: Connect from host: 127\.0\.0\.1/127\.0\.0\.1 to TCP port: 11" $PORTSENTRY_STDOUT; then
  err "Expected attackalert connect message not found"
fi

verbose "expect connect to tcp localhost:11"
nmap -sT -p11-11 localhost >/dev/null

verbose "expect 2 attackalert connect message"

if ! grep "^attackalert: Connect from host: 127\.0\.0\.1/127\.0\.0\.1 to TCP port: 11" $PORTSENTRY_STDOUT | wc -l | grep -q 2; then
  err "Expected attackalert connect message quantity not found"
fi

ok
