#!/bin/sh
. ./testlib.sh

runNmap 11 U

confirmBlockTriggered udp
confirmBlockFileSize 1 0

runNmap 11 U

confirmAlreadyBlocked
confirmBlockFileSize 1 0

ok
