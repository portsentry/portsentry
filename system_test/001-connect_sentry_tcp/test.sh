#!/bin/sh
. ./testlib.sh

runNmap 11 T

confirmBlockTriggered tcp

runNmap 11 T

confirmAlreadyBlocked

runNmap 11 U
runNmap 11 U

confirmOccurrenceStdout 2 "Scan from: \[127.0.0.1\] (127.0.0.1) protocol: \[TCP\] port: \[11\] type: \[Connect\]"
confirmOccurrenceStdout 2 "Scan from: \[127.0.0.1\] (127.0.0.1) protocol: \[UDP\] port: \[11\] type: \[Connect]"

ok
