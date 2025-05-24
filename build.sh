#!/bin/sh

ACTION=$1

do_package() {
  if [ -z "$1" ]; then
    echo "Usage: $0 package <version>"
    exit 1
  fi

  local BUILD_DIR=/tmp/portsentry-build
  rm -rf $BUILD_DIR && \
  mkdir -p $BUILD_DIR && \
  ./build.sh clean && \
  git archive --format=tar --prefix=portsentry-$1-src/ HEAD | xz > $BUILD_DIR/portsentry-$1-src.tar.xz && \
  sha256sum $BUILD_DIR/portsentry-$1-src.tar.xz > $BUILD_DIR/portsentry-$1-src.tar.xz.sha256 && \
  ./build.sh doc && \
  docker buildx build -t export -f docker/Dockerfile --target export --platform=linux/amd64,linux/arm64,linux/arm/v7,linux/arm/v6 --output type=local,dest=$BUILD_DIR .

  find $BUILD_DIR -mindepth 1 -maxdepth 1 -type d | while read f
  do
    cp -rf docs $f && \
    cp -rf examples $f && \
    cp -rf fail2ban $f && \
    cp -rf init $f && \
    cp -f Changes.md $f && \
    cp -f LICENSE $f && \
    cp -f README.md $f && \
    cp -f scripts/install.sh $f && \
    cp -f scripts/uninstall.sh $f
    chmod 755 $f/install.sh
    chmod 755 $f/uninstall.sh

    local FINAL_NAME=portsentry-${1}-$(basename $f)
    mv $f $BUILD_DIR/$FINAL_NAME

    tar -cJf $BUILD_DIR/$FINAL_NAME.tar.xz -C $BUILD_DIR $FINAL_NAME
    sha256sum $BUILD_DIR/$FINAL_NAME.tar.xz > $BUILD_DIR/$FINAL_NAME.sha256
    rm -rf $f $BUILD_DIR/$FINAL_NAME
  done

  echo "Packages created in $BUILD_DIR"
}

if [ "$ACTION" = "clean" ]; then
  rm -rf debug release && \
  rm -f portsentry.blocked.* && \
  rm -f portsentry.history && \
  rm -f portsentry*.tar.xz
  rm -f docs/portsentry.8
  rm -f docs/portsentry.conf.8
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
elif [ "$ACTION" = "package" ]; then
  do_package $2
elif [ "$ACTION" = "doc" ]; then
  pandoc --standalone --to man docs/Manual.md -o docs/portsentry.8
  pandoc --standalone --to man docs/portsentry.conf.md -o docs/portsentry.conf.8
elif [ "$ACTION" = "build_test" ]; then
  ./build.sh clean && \
  CMAKE_OPTS="-D BUILD_TESTS=ON" ./build.sh release
elif [ "$ACTION" = "run_test" ]; then
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
