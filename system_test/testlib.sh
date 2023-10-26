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
  local str="$1"
  local file=$2
  
  if [ -z "$3" ]; then
    local timeout=5
  else
    local timeout=$3
  fi

  while [ $timeout -gt 0 ]; do
    debug "waiting for string $str in file $file"
    if grep -q "$str" $file; then
      debug "Found string $str in file $file"
      return 0
    fi
    sleep 1
    timeout=$((timeout - 1))
  done

  return 1
}

confirmBlockTriggered() {
  proto=$1

  if [ "$1" = "tcp" ] || [ "$1" = "udp" ] ; then
    proto_l=$1
    proto_u=$(echo $proto_l | tr '[:lower:]' '[:upper:]')
  elif [ "$1" = "stcp" ] || [ "$1" = "sudp" ] ; then
    proto_l=$(echo $1 | sed 's/s//')
    proto_u=$(echo $proto_l | tr '[:lower:]' '[:upper:]')
  elif [ "$1" = "atcp" ] || [ "$1" = "audp" ] ; then
    proto_l=$(echo $1 | sed 's/a//')
    proto_u=$(echo $proto_l | tr '[:lower:]' '[:upper:]')
  else
    err "confirmBlockTriggered: invalid protocol $1"
  fi

  verbose "expect attackalert block message"
  if ! findInFile "^attackalert: Host 127.0.0.1 has been blocked" $PORTSENTRY_STDOUT; then
    err "Expected attackalert message not found"
  fi

  verbose "expect blocked $proto_l port"
  if ! findInFile "Host: 127.0.0.1/127.0.0.1 Port: 11 $proto_u Blocked" $TEST_DIR/portsentry.blocked.$proto; then
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

confirmSynScan() {
  verbose "expect syn scan block message"
  if ! findInFile "^attackalert: TCP SYN/Normal scan from host: 127.0.0.1/127.0.0.1 to TCP port: 11" $PORTSENTRY_STDOUT; then
    err "Expected syn scan block message not found"
  fi
}

confirmNullScan() {
  verbose "expect null scan block message"
  if ! findInFile "^attackalert: TCP NULL scan from host: 127.0.0.1/127.0.0.1 to TCP port: 11" $PORTSENTRY_STDOUT; then
    err "Expected null scan block message not found"
  fi
}

confirmXmasScan() {
  verbose "expect xmas scan block message"
  if ! findInFile "^attackalert: TCP XMAS scan from host: 127.0.0.1/127.0.0.1 to TCP port: 11" $PORTSENTRY_STDOUT; then
    err "Expected xmas scan block message not found"
  fi
}

confirmFinScan() {
  verbose "expect fin scan block message"
  if ! findInFile "^attackalert: TCP FIN scan from host: 127.0.0.1/127.0.0.1 to TCP port: 11" $PORTSENTRY_STDOUT; then
    err "Expected fin scan block message not found"
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

runNmap() {
  if [ -z "$1" ]; then
    err "runNmap: no port specified"
  fi

  local port=$1

  if [ "$2" = "T" ]; then
    local proto="T"
  elif [ "$2" = "U" ]; then
    local proto="U"
  elif [ "$2" = "S" ]; then
    local proto="S"
  elif [ "$2" = "N" ]; then
    local proto="N"
  elif [ "$2" = "F" ]; then
    local proto="F"
  elif [ "$2" = "X" ]; then
    local proto="X"
  else
    err "runNmap: invalid protocol $2"
  fi

  verbose "expect connect to $proto localhost:$port"
  nmap -s$proto -p$port-$port localhost >/dev/null
}
