#!/bin/sh
. ./testlib.sh

runNmap 11 F

confirmFinScan

confirmBlockTriggered tcp
confirmBlockFileSize 1 0

ok
