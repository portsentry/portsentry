#!/bin/sh
. ./testlib.sh

runNmap 11 S

confirmSynScan

confirmBlockTriggered stcp

ok
