#!/bin/sh
. ./testlib.sh

runNmap 11 F

confirmFinScan

confirmBlockTriggered stcp

ok
