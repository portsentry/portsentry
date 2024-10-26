#!/bin/sh
. ./testlib.sh

runNmap 11 X

confirmXmasScan

confirmBlockTriggered tcp
confirmBlockFileSize 1 0

ok
