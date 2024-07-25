#!/bin/sh
. ./testlib.sh

runNmap 11 T

confirmIgnoreFile

ok
