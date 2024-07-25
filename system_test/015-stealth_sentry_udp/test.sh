#!/bin/sh
. ./testlib.sh

runNmap 11 U

confirmBlockTriggered udp

runNmap 11 U

confirmAlreadyBlocked

ok
