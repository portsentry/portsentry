#!/bin/sh
. ./testlib.sh

runNmap 11 N

confirmNullScan

confirmBlockTriggered tcp
confirmBlockFileSize 1 0

ok
