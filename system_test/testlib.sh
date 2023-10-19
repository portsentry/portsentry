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

confirmBlockTriggered() {
  if [ "$1" != "tcp" ] && [ "$1" != "udp" ] ; then
    err "confirmBlockTriggered: invalid protocol $1"
  fi

  proto_l=$1
  proto_u=$(echo $proto_l | tr '[:lower:]' '[:upper:]')

  verbose "expect attackalert block message"
  if ! findInFile "^attackalert: Host 127.0.0.1 has been blocked" $PORTSENTRY_STDOUT; then
    err "Expected attackalert message not found"
  fi

  verbose "expect blocked $proto_l port"
  if ! findInFile "Host: 127.0.0.1/127.0.0.1 Port: 11 $proto_u Blocked" $TEST_DIR/portsentry.blocked.$proto_l; then
    err "Expected blocked $proto_u port not found"
  fi

  verbose "expect history entry"
  if ! findInFile ".*127\.0\.0\.1/127\.0\.0\.1 Port: 11 $proto_u Blocked" $TEST_DIR/portsentry.history; then
    err "Expected history entry not found"
  fi

}

confirmAlreadyBlocked() {
  verbose "expect already blocked message"
  if ! findInFile "attackalert: Host: 127.0.0.1/127.0.0.1 is already blocked Ignoring" $PORTSENTRY_STDOUT; then
    err "Expected already blocked message not found"
  fi
}

waitForFile() {
  if [ -z "$1" ]; then
    err "waitForFile: no file specified"
  fi

  local file=$1

  if [ -z "$2" ]; then
    local timeout=5
  else
    local timeout=$2
  fi

  while [ $timeout -gt 0 ]; do
    debug "waiting for file $file"
    if [ -f $file ]; then
      debug "Found file $file"
      return 0
    fi
    sleep 1
    timeout=$((timeout - 1))
  done

  err "Unable to find file $file, giving up"
}
