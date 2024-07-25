#!/bin/bash
while [ 1 ]; do
	inotifywait -e modify src/[a-zA-Z]*.c
	./build.sh debug && \
  ./build.sh sast
	sleep 5
done
