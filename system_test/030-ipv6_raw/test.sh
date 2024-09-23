#!/bin/sh
. ./testlib.sh

runNmap 11 T 6

confirmBlockTriggered tcp 6

runNmap 11 T 6

confirmAlreadyBlocked 6

ok
