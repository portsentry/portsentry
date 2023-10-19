#!/bin/sh
. ./testlib.sh

verbose "expect connect to udp localhost:11"
nmap -sU -p11-11 localhost >/dev/null

confirmBlockTriggered udp

verbose "expect block anyway when ignore file not found"
if ! findInFile "^Unable to open ignore file .*/portsentry.ignore. Continuing without it" $PORTSENTRY_STDERR; then
  err "Expected block anyway message not found"
fi

verbose "Re-connect to UDP localhost:11"
nmap -sU -p11-11 localhost >/dev/null

confirmAlreadyBlocked

ok
