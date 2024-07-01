#!/bin/sh
. ./testlib.sh

runNmap 11 X

confirmXmasScan

confirmBlockTriggered stcp

ok
