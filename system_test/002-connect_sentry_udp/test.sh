#!/bin/sh
. ./testlib.sh

runNmap 11 U

confirmBlockTriggered udp
confirmBlockFileSize 1 0

runNmap 11 U

confirmAlreadyBlocked
confirmBlockFileSize 1 0

runNmap 11 T
runNmap 11 T

confirmOccurrenceStdout 2 "Scan from: \[127.0.0.1\] (127.0.0.1) protocol: \[TCP\] port: \[11\] type: \[Connect\]"
confirmOccurrenceStdout 2 "Scan from: \[127.0.0.1\] (127.0.0.1) protocol: \[UDP\] port: \[11\] type: \[Connect]"

ok
