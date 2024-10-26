#!/bin/sh
. ./testlib.sh

runNmap 11 S

confirmSynScan

confirmBlockTriggered tcp
confirmBlockFileSize 1 0

ok
