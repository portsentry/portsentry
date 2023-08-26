#!/bin/bash

ACTION=$1

if [ "$ACTION" == "clean" ]; then
  rm -rf debug release
  exit 0
elif [ "$ACTION" == "debug" ]; then
  if [ ! -d "debug" ]; then
    mkdir debug
    cd debug
    cmake .. -D CMAKE_BUILD_TYPE=Debug -D NODAEMON=ON -D SUPPORT_STEALTH=ON
    cd ..
  fi
  cd debug
  cmake --build . -v
  exit 0
elif [ "$ACTION" == "release" ]; then
  if [ ! -d "release" ]; then
    mkdir release
    cd release
    cmake .. -D CMAKE_BUILD_TYPE=Release -D NODAEMON=ON -D SUPPORT_STEALTH=ON
    cd ..
  fi
  cd release
  cmake --build . -v
  exit 0
elif [ "$ACTION" == "sast" ]; then
  rm -rf /tmp/portsentry
  rsync -avz ../portsentry /tmp/
  codeql database create /tmp/portsentry/codeqldb --language=cpp --source-root=/tmp/portsentry
  codeql database analyze /tmp/portsentry/codeqldb --format=csv --output=/tmp/portsentry/codeqlout.csv
  echo "========== CodeQL Results =========="
  cat /tmp/portsentry/codeqlout.csv

  semgrep scan --config=auto
  flawfinder src

  exit 0
else
  echo "Usage: $0 [debug|release|clean]"
  exit 1
fi



#rsync -avz -e ssh . portsentry:./portsentry
