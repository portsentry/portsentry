#!/bin/sh
. ./testlib.sh

runNmap 11 U

confirmBlockTriggered udp

runNmap 11 U

confirmAlreadyBlocked

runNmap 11 T
runNmap 11 T

confirmOccurrenceStdout 2 "Scan from: \[127.0.0.1\] (127.0.0.1) protocol: \[TCP\] port: \[11\] type: \[Connect\]"
confirmOccurrenceStdout 2 "Scan from: \[127.0.0.1\] (127.0.0.1) protocol: \[UDP\] port: \[11\] type: \[Connect]"

ok
