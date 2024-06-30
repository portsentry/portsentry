#!/bin/sh
. ./testlib.sh

cat > $TEST_DIR/extcmd.sh <<EOF
#!/bin/sh

echo "\$1 \$2" > /tmp/portsentry-test/extcmd.stdout
EOF

chmod +x $TEST_DIR/extcmd.sh

runNmap 11 T

confirmStdoutScanMessage tcp
confirmHistoryFileMessage tcp

confirmExternalCommandRunMessage

verbose "expect extcmd.sh output"
if ! findInFile "^127\.0\.0\.1 11" $TEST_DIR/extcmd.stdout ; then
  err "Expected extcmd.sh output not found"
fi

ok
