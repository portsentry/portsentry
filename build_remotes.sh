#! env bash

BUILD_TYPE="debug"

for host in $(cat remotes.txt); do
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
