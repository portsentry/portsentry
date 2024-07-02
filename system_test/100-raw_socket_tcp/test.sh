#!/bin/sh
. ./testlib.sh

runNmap 11 T

confirmBlockTriggered tcp

runNmap 11 T

confirmAlreadyBlocked

ok
