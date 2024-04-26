#!/bin/sh
. ./testlib.sh

cat > $TEST_DIR/extcmd.sh <<EOF
#!/bin/sh

echo "\$1 \$2" > /tmp/portsentry-test/extcmd.stdout
EOF

chmod +x $TEST_DIR/extcmd.sh

runNmap 11 T

confirmBlockTriggered tcp

verbose "expect route kill message"
if ! findInFile "^attackalert: Host 127.0.0.1 has been blocked via dropped route using command" $PORTSENTRY_STDOUT; then
  err "Expected external command run message not found"
fi

verbose "expect extcmd.sh output"
if ! findInFile "^127\.0\.0\.1" $TEST_DIR/extcmd.stdout ; then
  err "Expected extcmd.sh output not found"
fi

ok
