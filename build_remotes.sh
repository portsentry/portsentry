#!/usr/bin/env bash

[ -z "$BUILD_TYPE" ] && BUILD_TYPE="debug"
if [ -n "$1" ]; then
  REMOTE_HOSTS="$1"
else
  REMOTE_HOSTS="deb-portsentry netbsd freebsd openbsd"
fi

for host in $REMOTE_HOSTS; do
  echo "Building on $host"
  ssh $host "rm -rf /tmp/portsentry"
  rsync -az -e ssh ../portsentry $host:/tmp/
  ssh $host "cd /tmp/portsentry && ./build.sh clean && ./build.sh $BUILD_TYPE"
  if [ $? -ne 0 ]; then
    echo "ERROR: Failed to build on $host"
    exit 1
  fi
  echo
done
