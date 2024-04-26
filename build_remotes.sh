#! env bash

BUILD_TYPE="debug"

if [ -n "$1" ]; then
  BUILD_TYPE="$1"

  if [ "$BUILD_TYPE" != "debug" ] && [ "$BUILD_TYPE" != "release" ]; then
    echo "Invalid build type: $BUILD_TYPE"
    exit 1
  fi
fi

for host in $(cat remotes.txt); do
  if [ "$host" == "[LOCAL]" ]; then
    echo "Building local"
    ./build.sh clean && ./build.sh debug
    if [ $? -ne 0 ]; then
      echo "ERROR: Failed to build local"
      exit 1
    fi
  else
    echo "Building on $host"
    ssh $host "rm -rf /tmp/portsentry"
    rsync -az -e ssh ../portsentry $host:/tmp/
    ssh $host "cd /tmp/portsentry && ./build.sh clean && ./build.sh $BUILD_TYPE"
    if [ $? -ne 0 ]; then
      echo "ERROR: Failed to build on $host"
      exit 1
    fi
  fi

  echo
done
