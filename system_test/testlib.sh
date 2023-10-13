SCRIPT_NAME=$(basename $0)
TEST_DIR=$1
PORTSENTRY_EXEC=$2
PORTSENTRY_CONF=$3
PORTSENTRY_TEST=$4
PORTSENTRY_SCRIPT=$5
PORTSENTRY_STDOUT=$6
PORTSENTRY_STDERR=$7

log() {
  echo "$SCRIPT_NAME: $@"
}

debug() {
  if [ -z "$DEBUG" ]; then
    return
  fi
  log "DEBUG: $@"
}

verbose() {
  if [ -z "$VERBOSE" ]; then
    return
  fi
  log "$@"
}

print_env() {
  echo "$0 $@"
  echo "pwd: $(pwd)"
  log $TEST_DIR
  log $PORTSENTRY_EXEC
  log $PORTSENTRY_CONF
  log $PORTSENTRY_TEST
  log $PORTSENTRY_SCRIPT
  log $PORTSENTRY_STDOUT
  log $PORTSENTRY_STDERR
}

ok() {
  log "Test passed OK"
  exit 0
}

err() {
  log "Test failed $@"
  exit 1
}

findInFile() {
  grep -q "$1" $2
}
