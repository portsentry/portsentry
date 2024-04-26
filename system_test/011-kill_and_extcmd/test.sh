#!/bin/sh
. ./testlib.sh

cat > $TEST_DIR/extcmd.sh <<EOF
#!/bin/sh

echo "\$1 \$2" > /tmp/portsentry-test/extcmd.stdout
EOF

cat > $TEST_DIR/routesim.sh <<EOF
#!/bin/sh

echo "\$1" > /tmp/portsentry-test/routesim.stdout
EOF

chmod +x $TEST_DIR/extcmd.sh
chmod +x $TEST_DIR/routesim.sh

runNmap 11 T

verbose "expect routesim.sh output"
if ! findInFile "^127\.0\.0\.1" $TEST_DIR/routesim.stdout ; then
  err "Expected routesim.sh output not found"
fi

verbose "expect extcmd.sh output"
if ! findInFile "^127\.0\.0\.1 11" $TEST_DIR/extcmd.stdout ; then
  err "Expected extcmd.sh output not found"
fi

verbose "expect correct connect, route kill and external command message ordering"
if ! cat $PORTSENTRY_STDOUT | tr -d '\n' | grep -q "attackalert: Connect from host: 127.0.0.1/127.0.0.1 to TCP port: 11.*attackalert: Host 127.0.0.1 has been blocked via dropped route using command.*attackalert: External command run for host: 127.0.0.1 using command"; then
  err "Expected correct connect, route kill and external command run messages not found"
fi

ok
