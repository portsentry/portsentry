#!/bin/sh

TEST_DIR=/tmp/portsentry-test
PORTSENTRY_EXEC=""
PORTSENTRY_CONF=""
PORTSENTRY_TEST=""
PORTSENTRY_SCRIPT=""
PORTSENTRY_HOOK_PRE_SETUP=""

log() {
  echo "$@"
}

debug() {
  if [ -z "$DEBUG" ]; then
    return
  fi
  log "DEBUG: $@"
}

init() {
  if [ "$(whoami)" != "root" ]; then
    echo "Need root to run"
    exit 1
  fi

  if [ $# -lt 2 ]; then
    echo "Usage: $0 <portsentry binary> <directory containing test files>"
    exit 1
  fi

  PORTSENTRY_EXEC=$1
  PORTSENTRY_CONF=$2/portsentry.conf
  PORTSENTRY_TEST=$2/portsentry.test
  PORTSENTRY_SCRIPT=$2/test.sh
  PORTSENTRY_HOOK_PRE_SETUP=$2/hook_pre_setup.sh

  if [ ! -x $PORTSENTRY_EXEC ]; then
    echo "Error: portsentry executable file: $PORTSENTRY_EXEC not found or not executable"
    exit 1
  fi

  if [ ! -f $PORTSENTRY_CONF ]; then
    echo "Error: portsentry config: $PORTSENTRY_CONF not found"
    exit 1
  fi

  if [ ! -f $PORTSENTRY_TEST ]; then
    echo "Error: portsentry test file: $PORTSENTRY_TEST not found"
    exit 1
  fi

  if [ ! -x $PORTSENTRY_SCRIPT ]; then
    echo "Error: portsentry script file: $PORTSENTRY_SCRIPT not found or not executable"
    exit 1
  fi
}

hook_pre_setup() {
  if [ -x $PORTSENTRY_HOOK_PRE_SETUP ]; then
    . $PORTSENTRY_HOOK_PRE_SETUP
  fi
}

setup() {
  rm -rf $TEST_DIR
  mkdir -p $TEST_DIR
  cp $PORTSENTRY_EXEC $TEST_DIR
  cp $(dirname $PORTSENTRY_EXEC)/portcon $TEST_DIR
  cp $PORTSENTRY_CONF $TEST_DIR
  cp $PORTSENTRY_TEST $TEST_DIR
  cp $PORTSENTRY_SCRIPT $TEST_DIR
  cp ./testlib.sh $TEST_DIR/testlib.sh

  PORTSENTRY_EXEC=$TEST_DIR/$(basename $PORTSENTRY_EXEC)
  PORTSENTRY_CONF=$TEST_DIR/$(basename $PORTSENTRY_CONF)
  PORTSENTRY_TEST=$TEST_DIR/$(basename $PORTSENTRY_TEST)
  PORTSENTRY_SCRIPT=$TEST_DIR/$(basename $PORTSENTRY_SCRIPT)
  PORTSENTRY_STDOUT=$TEST_DIR/portsentry.stdout
  PORTSENTRY_STDERR=$TEST_DIR/portsentry.stderr

  debug "PORTSENTRY_EXEC: $PORTSENTRY_EXEC"
  debug "PORTSENTRY_CONF: $PORTSENTRY_CONF"
  debug "PORTSENTRY_TEST: $PORTSENTRY_TEST"
  debug "PORTSENTRY_SCRIPT: $PORTSENTRY_SCRIPT"
}

run_portsentry() {
  local switches="$(head -n 1 $PORTSENTRY_TEST)"
  debug "switches: $switches"

  cd $TEST_DIR
  $PORTSENTRY_EXEC -c $PORTSENTRY_CONF $switches > $PORTSENTRY_STDOUT 2>$PORTSENTRY_STDERR &

  local timeout=5
  while [ ! -f $PORTSENTRY_STDOUT ]; do
    debug "waiting for $PORTSENTRY_STDOUT to be created"
    sleep 1
    timeout=$((timeout - 1))
    if [ $timeout -eq 0 ]; then
      echo "Error: Timeout waiting for $PORTSENTRY_STDOUT to be created"
      exit 1
    fi
  done

  timeout=5
  while [ $timeout -gt 0 ]; do
    debug "waiting for portsentry to report ready in $PORTSENTRY_STDOUT"
    if grep -q "adminalert: PortSentry is now active and listening." $PORTSENTRY_STDOUT; then
      return
    fi
    sleep 1
    timeout=$((timeout - 1))
  done

  echo "Error: Unable to parse portsentry ready message, aborting"
  report_and_stop
  exit 1
}

stop_portsentry() {
  if [ -n "$1" ]; then
    local dontExit=1
  fi

  local pid="$(ps aux|grep "$PORTSENTRY_EXEC -c $PORTSENTRY_CONF $switches"|grep -v grep | awk '{print $2}')"
  if [ -n "$pid" ]; then
    kill $pid
    return
  fi

  if [ -z "$dontExit" ]; then
    echo "Error: portsentry not running"
    exit 1
  fi
}

report_and_stop() {
  echo "Detected test failure, stopping portsentry, printing portsentry run log and exit"
  stop_portsentry 1
  echo "#### PORTSENTRY STDOUT ####"
  cat $PORTSENTRY_STDOUT
  echo
  echo "#### PORTSENTRY STDERR ####"
  cat $PORTSENTRY_STDERR
  exit 1
}

run_test() {
  cd $TEST_DIR
  if ! $PORTSENTRY_SCRIPT $TEST_DIR $PORTSENTRY_EXEC $PORTSENTRY_CONF $PORTSENTRY_TEST $PORTSENTRY_SCRIPT $PORTSENTRY_STDOUT $PORTSENTRY_STDERR; then
    report_and_stop
  fi
}

init $@
hook_pre_setup
setup
run_portsentry
run_test
stop_portsentry
