#!/bin/sh
. ./testlib.sh

runNmap 11 N

confirmNullScan

confirmBlockTriggered stcp

ok
