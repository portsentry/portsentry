#!/bin/sh
. ./testlib.sh

runNmap 11 T

confirmBlockTriggered tcp
confirmBlockFileSize 1 0

runNmap 11 T

confirmAlreadyBlocked
confirmBlockFileSize 1 0

runNmap 11 U
runNmap 11 U

confirmOccurrenceStdout 2 "Scan from: \[127.0.0.1\] (127.0.0.1) protocol: \[TCP\] port: \[11\] type: \[Connect\]"
confirmOccurrenceStdout 2 "Scan from: \[127.0.0.1\] (127.0.0.1) protocol: \[UDP\] port: \[11\] type: \[Connect\]"

ok
