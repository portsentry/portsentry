#!/bin/sh

if [ "$(uname -s)" != "Linux" ]; then
  echo "Skipping test on non-Linux system"
  exit 0
fi

