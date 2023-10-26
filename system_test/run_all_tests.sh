#!/bin/sh

for f in $(find . -maxdepth 1 -type d | sort); do
  if [ "$f" = "." ]; then
    continue
  fi
  echo "Running test $f"
  test_script=$(find $f -name "*.sh" -type f |tail -n 1)
  if ! ./run_test.sh ../debug/portsentry $f/portsentry.conf $f/portsentry.test $test_script; then
    echo "Stopping further tests due to failure"
    exit 1
  fi
done

echo "All tests passed"
