#!/bin/sh
. ./testlib.sh

runNmap 11 T

confirmBlockTriggered tcp
confirmBlockFileSize 1 0

runNmap 11 T

confirmAlreadyBlocked
confirmBlockFileSize 1 0

ok
