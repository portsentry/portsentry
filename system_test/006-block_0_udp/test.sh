#!/bin/sh
. ./testlib.sh

runNmap 11 U

confirmStdoutScanMessage udp
confirmHistoryFileMessage udp

runNmap 11 U

confirmOccurrenceStdout 2 "^Scan from: \[127\.0\.0\.1\] (127\.0\.0\.1) protocol: \[UDP\] port: \[11\]"

ok
