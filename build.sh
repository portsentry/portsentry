#!/bin/sh

ACTION=$1
_SYSTEM=$(uname -s)

if [ "$_SYSTEM" != "Linux" ]; then
  CMAKE_OPTS="$CMAKE_OPTS -DUSE_SYSTEMD=OFF"
fi

if [ "$ACTION" = "clean" ]; then
  rm -rf debug release && \
  rm -f portsentry.blocked.* && \
  rm -f portsentry.history && \
  rm -f portsentry*.tar.xz
  rm -f docs/portsentry.8
  rm -f docs/portsentry.conf.8
elif [ "$ACTION" = "debug" ]; then
  cmake -B debug -D CMAKE_BUILD_TYPE=Debug -D CMAKE_INSTALL_PREFIX=/ $CMAKE_OPTS
  cmake --build debug -v
elif [ "$ACTION" = "release" ]; then
  cmake -B release -D CMAKE_BUILD_TYPE=Release -D CMAKE_INSTALL_PREFIX=/ $CMAKE_OPTS
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
  docker buildx build -t portsentry:unstable -f docker/Dockerfile --platform=linux/amd64,linux/arm64,linux/arm/v7,linux/arm/v6,linux/i386,linux/riscv64 .
elif [ "$ACTION" = "docker_export" ]; then
  BUILD_DIR=/tmp/portsentry-build
  rm -rf $BUILD_DIR
  docker buildx build -t export -f docker/Dockerfile --target export --platform=linux/amd64,linux/arm64,linux/arm/v7,linux/arm/v6,linux/i386,linux/riscv64 --output type=local,dest=$BUILD_DIR .

  find /tmp/portsentry-build -mindepth 2 -type f -regex ".*portsentry-[0-9\.]*-Linux.*" | while read f; do
    new_name=$(echo $f |sed "s/-Linux\./-$(basename $(dirname $f))\./")
    mv -v "$f" "$new_name"
  done
elif [ "$ACTION" = "build_test" ]; then
  ./build.sh clean && \
  CMAKE_OPTS="-D BUILD_TESTS=ON" ./build.sh debug
elif [ "$ACTION" = "run_test" ]; then
  if [ -d "debug" ]; then
    ctest --test-dir debug
  else
    echo "No debug build directory found"
    exit 1
  fi
elif [ "$ACTION" = "test_all" ]; then
  ./build.sh clean && \
  CMAKE_OPTS="-D USE_PCAP=OFF" ./build.sh debug && \
  CMAKE_OPTS="-D USE_PCAP=OFF" ./build.sh release && \
  ./build.sh clean && \
  CMAKE_OPTS="-D BUILD_TESTS=ON" ./build.sh debug && \
  CMAKE_OPTS="-D BUILD_TESTS=ON" ./build.sh release && \
  ctest --test-dir debug && \
  ctest --test-dir release
  (command -v docker >/dev/null 2>&1 && ./build.sh docker)
  cd system_test
  ./run_all_tests.sh
elif [ "$ACTION" = "doc" ]; then
  pandoc --standalone --to man docs/Manual.md -o man/portsentry.8
  pandoc --standalone --to man docs/portsentry.conf.md -o man/portsentry.conf.8
else
  echo "Usage: $0 <command>"
  echo "Commands:"
  echo "  clean         - Remove all build files/caches"
  echo "  debug         - Build debug version"
  echo "  release       - Build release version"
  echo
  echo "  sast          - Run static analysis tools"
  echo "  build_test    - Build unit test targets"
  echo "  run_test      - Run unit test targets"
  echo
  echo "  build_fuzz    - Build fuzzing targets"
  echo "  run_fuzz      - Run fuzzing targets"
  echo "  docker        - Build docker image"
  echo
  echo "  doc           - Build man pages"
  exit 0
fi
