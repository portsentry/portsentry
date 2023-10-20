#!/bin/sh

script=$(find $1 -name "*.sh" -type f | head -1)

./run_test.sh ../debug/portsentry $1/portsentry.conf $1/portsentry.test $script
