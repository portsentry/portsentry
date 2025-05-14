#!/bin/sh

ACTION=$1

if [ "$ACTION" = "clean" ]; then
  rm -rf debug release && \
  rm -f portsentry.blocked.* && \
  rm -f portsentry.history && \
  rm -f portsentry*.tar.xz
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
elif [ "$ACTION" = "doc" ]; then
  pandoc --standalone --to man docs/Manual.md -o docs/portsentry.8
  pandoc --standalone --to man docs/portsentry.conf.md -o docs/portsentry.conf.8
elif [ "$ACTION" = "create_src_tarball" ]; then
  version=$(git describe --tags)
  ./build.sh clean && \
  git archive --format=tar --prefix=portsentry-src-${version}/ HEAD | xz > portsentry-src-${version}.tar.xz
elif [ "$ACTION" = "create_bin_tarball" ]; then
  version=$(git describe --tags)
  machine=$(uname -m)
  ./build.sh clean && \
  ./build.sh release && \
  rm -rf /tmp/portsentry-${version}-${machine} && \
  mkdir -p /tmp/portsentry-${version}-${machine} && \
  cp release/portsentry /tmp/portsentry-${version}-${machine}/ && \
  cp -rf docs /tmp/portsentry-${version}-${machine}/ && \
  cp -rf examples /tmp/portsentry-${version}-${machine}/ && \
  cp -rf fail2ban /tmp/portsentry-${version}-${machine}/ && \
  cp -rf init /tmp/portsentry-${version}-${machine}/ && \
  cp Changes.md /tmp/portsentry-${version}-${machine}/ && \
  cp LICENSE /tmp/portsentry-${version}-${machine}/ && \
  cp README.md /tmp/portsentry-${version}-${machine}/ && \
  tar -cvJf portsentry-${machine}-${version}.tar.xz -C /tmp portsentry-${version}-${machine}
elif [ "$ACTION" = "test" ]; then
  if [ -d "debug" ]; then
    ctest --test-dir debug
  elif [ -d "release" ]; then
    ctest --test-dir release
  else
    echo "No build directories (debug or release) found"
    exit 1
  fi
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
