#!/bin/sh

ACTION=$1

if [ "$ACTION" = "clean" ]; then
  rm -rf debug release && \
  rm -f portsentry.blocked.* && \
  rm -f portsentry.history
elif [ "$ACTION" = "debug" ]; then
  if [ ! -d "debug" ]; then
    mkdir debug && \
    cd debug && \
    cmake .. -D CMAKE_BUILD_TYPE=Debug && \
    cd ..
  fi
  cd debug && \
  cmake --build . -v
elif [ "$ACTION" = "release" ]; then
  if [ ! -d "release" ]; then
    mkdir release && \
    cd release && \
    cmake .. -D CMAKE_BUILD_TYPE=Release && \
    cd ..
  fi
  cd release && \
  cmake --build . -v
elif [ "$ACTION" = "sast" ]; then
  rm -rf /tmp/portsentry
  rsync -avz ../portsentry /tmp/
  codeql database create /tmp/portsentry/codeqldb --language=cpp --source-root=/tmp/portsentry
  codeql database analyze /tmp/portsentry/codeqldb --format=csv --output=/tmp/portsentry/codeqlout.csv
  echo "========== CodeQL Results Start =========="
  cat /tmp/portsentry/codeqlout.csv
  echo "========== CodeQL Results End =========="

  semgrep scan --config=auto
  flawfinder src

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
elif [ "$ACTION" = "test-debug" ]; then
  cd debug && \
  ctest
elif [ "$ACTION" = "rebuild" ]; then
  $0 clean && \
  $0 debug
elif [ "$ACTION" = "rebuild-release" ]; then
  $0 clean && \
  $0 release
elif [ "$ACTION" = "all" ]; then
  $0 clean && \
  $0 debug && \
  $0 test-debug && \
  $0 release && \
  $0 test-release
elif [ "$ACTION" = "test-release" ]; then
  cd release && \
  ctest
else
  echo "Usage: $0 [debug|release|clean]"
  exit 1
fi
