#!/bin/sh
. ./testlib.sh

cat > $TEST_DIR/routesim.sh <<EOF
#!/bin/sh

echo "\$1" > /tmp/portsentry-test/routesim.stdout
EOF

chmod +x $TEST_DIR/routesim.sh

verbose "expect connect to tcp localhost:11"
nmap -sT -p11-11 localhost >/dev/null

verbose "expect routesim.sh output"
if ! findInFile "^127\.0\.0\.1" $TEST_DIR/routesim.stdout ; then
  err "Expected routesim.sh output not found"
fi

verbose "expect attackalert connect message"
if ! findInFile "^attackalert: Connect from host: 127\.0\.0\.1/127\.0\.0\.1 to TCP port: 11" $PORTSENTRY_STDOUT; then
  err "Expected attackalert connect message not found"
fi

verbose "expect route kill message"
if ! findInFile "^attackalert: Host 127.0.0.1 has been blocked via dropped route using command" $PORTSENTRY_STDOUT; then
  err "Expected external command run message not found"
fi

verbose "expect attackalert hosts deny block message"
if ! findInFile "^attackalert: Host 127.0.0.1 has been blocked via wrappers with string" $PORTSENTRY_STDOUT; then
  err "Expected attackalert message not found"
fi

ok
