#!/bin/sh
. ./testlib.sh

runNmap 11 T 6

confirmIgnoreFile6

ok
