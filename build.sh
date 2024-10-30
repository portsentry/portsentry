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
elif [ "$ACTION" = "build_fuzz" ]; then
  export CC=/usr/bin/clang
  $0 clean && \
  cmake -B debug -D CMAKE_BUILD_TYPE=Debug -D BUILD_FUZZER=ON $CMAKE_OPTS && \
  cmake --build debug -v
elif [ "$ACTION" = "run_fuzz" ]; then
  total_time=60
  [ -n "$2" ] && total_time=$2
  find debug -maxdepth 1 -name "fuzz_*" | while read f
  do
    echo "Running $f"
    ./$f -max_total_time=$total_time tests/fuzzing/corpus_$(basename $f)
  done
elif [ "$ACTION" = "autobuild" ]; then
  while [ 1 ]; do
    inotifywait -e modify src/[a-zA-Z]*.c
    ./build.sh debug && \
    ./build.sh release && \
    ./build.sh sast
    sleep 5
  done
elif [ "$ACTION" = "docker" ]; then
  docker build -t portsentry:unstable -f docker/Dockerfile .
else
  echo "Usage: $0 <command>"
  echo "Commands:"
  echo "  clean         - Remove all build files/caches"
  echo "  debug         - Build debug version"
  echo "  release       - Build release version"
  echo "  sast          - Run static analysis tools"
  echo "  build_fuzz    - Build fuzzing targets"
  echo "  run_fuzz      - Run fuzzing targets"
  echo "  docker        - Build docker image"
  exit 0
fi
