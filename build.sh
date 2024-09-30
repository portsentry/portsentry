#!/bin/sh

ACTION=$1

if [ "$ACTION" = "clean" ]; then
  rm -rf debug release && \
  rm -f portsentry.blocked.* && \
  rm -f portsentry.history
elif [ "$ACTION" = "debug" ]; then
  cmake -B debug -D CMAKE_BUILD_TYPE=Debug $CMAKE_OPTS
  cmake --build debug -v
elif [ "$ACTION" = "release" ]; then
  cmake -B release -D CMAKE_BUILD_TYPE=Release $CMAKE_OPTS
  cmake --build release -v
elif [ "$ACTION" = "sast" ]; then
  rm -rf /tmp/portsentry
  rsync -avz ../portsentry /tmp/
  codeql database create /tmp/portsentry/codeqldb --language=cpp --source-root=/tmp/portsentry
  codeql database analyze /tmp/portsentry/codeqldb --format=csv --output=/tmp/portsentry/codeqlout.csv
  echo "========== CodeQL Results Start =========="
  cat /tmp/portsentry/codeqlout.csv
  echo "========== CodeQL Results End =========="

  semgrep scan --config=auto

  exit 0
elif [ "$ACTION" = "cdt" ]; then
  $0 clean && \
  $0 debug && \
  $0 test-debug

  if [ "$?" -ne 0 ]; then
    echo "Build failed"
    cat debug/Testing/Temporary/LastTest.log
    exit 1
  fi
elif [ "$ACTION" = "autobuild" ]; then
  while [ 1 ]; do
    inotifywait -e modify src/[a-zA-Z]*.c
    ./build.sh debug && \
    ./build.sh sast
    sleep 5
  done
elif [ "$ACTION" = "test-debug" ]; then
  cd debug && \
  ctest
elif [ "$ACTION" = "test-release" ]; then
  cd release && \
  ctest
elif [ "$ACTION" = "docker" ]; then
  docker build -t portsentry:unstable -f docker/Dockerfile .
else
  echo "Usage: $0 <command>"
  echo "Commands:"
  echo "  clean         - Remove all build files/caches"
  echo "  debug         - Build debug version"
  echo "  release       - Build release version"
  echo "  sast          - Run static analysis tools"
  echo "  cdt           - Run clean, debug, test-debug in sequence"
  echo "  test-debug    - Run unit tests for debug build"
  echo "  test-release  - Run unit tests for release build"
  echo "  docker        - Build docker image"
  exit 0
fi
