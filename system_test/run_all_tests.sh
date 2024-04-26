#!/bin/sh

for f in $(find . -maxdepth 1 -mindepth 1 -type d |sort); do
  echo "Running test $f"
  if ! ./run_test.sh ../debug/portsentry $f; then
    echo "Stopping further tests due to failure"
    exit 1
  fi
done

echo "All tests passed"
