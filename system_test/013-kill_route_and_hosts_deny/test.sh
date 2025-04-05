#!/bin/sh
. ./testlib.sh

rm /etc/hosts.deny
touch /etc/hosts.deny

cat > $TEST_DIR/routesim.sh <<EOF
#!/bin/sh

echo "\$1" > /tmp/portsentry-test/routesim.stdout
EOF

chmod +x $TEST_DIR/routesim.sh

runNmap 11 T

verbose "expect routesim.sh output"
if ! findInFile "^127\.0\.0\.1" $TEST_DIR/routesim.stdout ; then
  err "Expected routesim.sh output not found"
fi

confirmBlockTriggered tcp
confirmBlockFileSize 1 0

confirmRouteKillMessage

confirmHostWrapperMessage

ok
