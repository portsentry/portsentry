#!/bin/sh
# Run all portsentry Robot Framework system tests against a remote target.
#
# The target must already have the portsentry binary installed at
# ${PORTSENTRY_TEST_DIR}/portsentry (default /tmp/portsentry-test/portsentry).
# The SSH user must be root (or unrestricted root-equivalent) because tests
# start portsentry, signal it, and touch /etc/hosts.deny.
#
# The runner host needs nmap on PATH and Python 3 with the packages from
# requirements.txt (robotframework + robotframework-sshlibrary). For the
# stealth/SYN/UDP scans nmap requires raw-socket privileges; run this script
# as root or grant CAP_NET_RAW to /usr/bin/nmap.
#
# Required environment variables:
#   PORTSENTRY_HOST       IPv4 hostname or IP of the target machine
#   PORTSENTRY_HOST_IPV6  target's IPv6 address — the runner must have an
#                         IPv6 route to it. There is no opt-out; configure
#                         IPv6 on the test bench or this suite will refuse
#                         to run.
#
# Optional environment variables (defaults shown):
#   PORTSENTRY_USER       SSH user                                  (root)
#   PORTSENTRY_PORT       SSH port                                  (22)
#   PORTSENTRY_KEYFILE    path to an SSH private key                (~/.ssh/id_rsa)
#   PORTSENTRY_PASSWORD   SSH password (key takes priority)         (unset)
#   PORTSENTRY_TEST_DIR   remote working directory                  (/tmp/portsentry-test)
#   ROBOT_ARGS            extra args passed verbatim to `robot`
#
# Examples:
#   PORTSENTRY_HOST=10.0.0.5 ./run_all_tests.sh
#   PORTSENTRY_HOST=tester ROBOT_ARGS='--test "001*" --loglevel DEBUG' ./run_all_tests.sh

set -eu

cd "$(dirname "$0")"

if [ -z "${PORTSENTRY_HOST:-}" ]; then
  echo "Error: PORTSENTRY_HOST is required" >&2
  exit 2
fi

if [ -z "${PORTSENTRY_HOST_IPV6:-}" ]; then
  echo "Error: PORTSENTRY_HOST_IPV6 is required (target's IPv6 address). IPv6 connectivity to the target is mandatory; there is no opt-out." >&2
  exit 2
fi

PORTSENTRY_USER="${PORTSENTRY_USER:-root}"
PORTSENTRY_PORT="${PORTSENTRY_PORT:-22}"
PORTSENTRY_TEST_DIR="${PORTSENTRY_TEST_DIR:-/tmp/portsentry-test}"

if ! command -v robot >/dev/null 2>&1; then
  echo "Error: 'robot' (Robot Framework) is not on PATH. See README.md for setup." >&2
  exit 3
fi

if ! command -v nmap >/dev/null 2>&1; then
  echo "Error: 'nmap' is not on PATH on the runner host." >&2
  exit 4
fi

set -- \
  --variable "PORTSENTRY_HOST:${PORTSENTRY_HOST}" \
  --variable "PORTSENTRY_HOST_IPV6:${PORTSENTRY_HOST_IPV6}" \
  --variable "PORTSENTRY_USER:${PORTSENTRY_USER}" \
  --variable "PORTSENTRY_PORT:${PORTSENTRY_PORT}" \
  --variable "PORTSENTRY_TEST_DIR:${PORTSENTRY_TEST_DIR}"

if [ -n "${PORTSENTRY_KEYFILE:-}" ]; then
  set -- "$@" --variable "PORTSENTRY_KEYFILE:${PORTSENTRY_KEYFILE}"
fi

if [ -n "${PORTSENTRY_PASSWORD:-}" ]; then
  set -- "$@" --variable "PORTSENTRY_PASSWORD:${PORTSENTRY_PASSWORD}"
fi

# shellcheck disable=SC2086
exec robot "$@" ${ROBOT_ARGS:-} tests.robot
