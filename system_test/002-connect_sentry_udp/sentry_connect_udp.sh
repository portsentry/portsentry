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

verbose "expect already blocked message"
if ! findInFile "attackalert: Host: 127.0.0.1/127.0.0.1 is already blocked Ignoring" $PORTSENTRY_STDOUT; then
  err "Expected already blocked message not found"
fi

ok
