*** Settings ***
Documentation     Shared keywords for the portsentry Robot Framework system tests.
...
...               These keywords drive a *remote* portsentry over SSH while the
...               actual probes (nmap, TCP/UDP banner reads) run on the runner.
...               When the SSH user is not ``root`` the keywords transparently
...               prefix privileged commands with ``sudo -n``; passwordless
...               sudo on the target is therefore required for non-root logins.
Library           SSHLibrary
Library           Process
Library           String
Library           OperatingSystem
Library           Collections
Library           ${CURDIR}${/}..${/}libraries${/}PortsentryLib.py

*** Variables ***
${PORTSENTRY_HOST}        ${EMPTY}
${PORTSENTRY_HOST_IPV6}   ${EMPTY}
${PORTSENTRY_USER}        root
${PORTSENTRY_PORT}        22
${PORTSENTRY_KEYFILE}     ${EMPTY}
${PORTSENTRY_PASSWORD}    ${EMPTY}
${PORTSENTRY_BIN}         ${EMPTY}
${PORTSENTRY_TEST_DIR}    ${EMPTY}
${PORTSENTRY_FAMILY_SIZE}    ${EMPTY}
${PORTSENTRY_SUDO}        ${EMPTY}
${PORTSENTRY_PROC_TAG}    ${EMPTY}
${SSH_TIMEOUT}            30s
${READY_TIMEOUT}          15s
${STOP_TIMEOUT}           10s
${POLL_TIMEOUT}           10s
${SOURCE_IP4}             ${EMPTY}
${SOURCE_IP6}             ${EMPTY}
${RE_SOURCE_IP4}          ${EMPTY}
${RE_SOURCE_IP6}          ${EMPTY}

*** Keywords ***
# ------------------------------------------------------------------ Suite
Portsentry Suite Setup
    Open Portsentry SSH Connection
    Configure Sudo Prefix
    Configure Process Tag
    Verify Portsentry Binary On Target
    Detect Block File Family Size
    Discover Source IPs

Portsentry Suite Teardown
    Run Keyword And Ignore Error    Close All Connections

Open Portsentry SSH Connection
    IF    '${PORTSENTRY_HOST}' == '${EMPTY}'
        Fatal Error    PORTSENTRY_HOST must be set (host of the target machine)
    END
    Open Connection    ${PORTSENTRY_HOST}    port=${PORTSENTRY_PORT}    timeout=${SSH_TIMEOUT}
    IF    '${PORTSENTRY_KEYFILE}' != '${EMPTY}'
        Login With Public Key    ${PORTSENTRY_USER}    ${PORTSENTRY_KEYFILE}
    ELSE IF    '${PORTSENTRY_PASSWORD}' != '${EMPTY}'
        Login    ${PORTSENTRY_USER}    ${PORTSENTRY_PASSWORD}
    ELSE
        Login With Public Key    ${PORTSENTRY_USER}    %{HOME}${/}.ssh${/}id_rsa
    END

Configure Sudo Prefix
    IF    '${PORTSENTRY_USER}' == 'root'    RETURN
    ${rc}=    Execute Command    sudo -n true    return_stdout=False    return_rc=True
    Should Be Equal As Integers    ${rc}    0
    ...    msg=SSH user ${PORTSENTRY_USER} requires passwordless sudo on the target
    Set Suite Variable    ${PORTSENTRY_SUDO}    sudo -n

Configure Process Tag
    [Documentation]    Process name used by pgrep/pkill to find portsentry.
    ...                We match the exact basename via ``-x`` rather than the
    ...                full command line; full-cmdline matching with ``-f``
    ...                false-positives on the shell running pgrep itself
    ...                because the search pattern is in its argv.
    Set Suite Variable    ${PORTSENTRY_PROC_TAG}    portsentry

Verify Portsentry Binary On Target
    [Documentation]    Locate the portsentry binary on the target. Prefer
    ...                /tmp/portsentry/debug/portsentry; fall back to
    ...                /tmp/portsentry/release/portsentry. The chosen path
    ...                is stored in ${PORTSENTRY_BIN} for the rest of the
    ...                suite.
    ${rc_debug}=    Execute Command    test -x /tmp/portsentry/debug/portsentry
    ...    return_stdout=False    return_rc=True
    IF    ${rc_debug} == 0
        Set Suite Variable    ${PORTSENTRY_BIN}    /tmp/portsentry/debug/portsentry
        Log    Using portsentry binary: ${PORTSENTRY_BIN} (debug)    INFO    console=True
        RETURN
    END
    ${rc_release}=    Execute Command    test -x /tmp/portsentry/release/portsentry
    ...    return_stdout=False    return_rc=True
    IF    ${rc_release} == 0
        Set Suite Variable    ${PORTSENTRY_BIN}    /tmp/portsentry/release/portsentry
        Log    Using portsentry binary: ${PORTSENTRY_BIN} (release)    INFO    console=True
        RETURN
    END
    Fatal Error    portsentry binary not found on ${PORTSENTRY_HOST}: neither /tmp/portsentry/debug/portsentry nor /tmp/portsentry/release/portsentry exist or are executable.

Detect Block File Family Size
    [Documentation]    portsentry's blocked file stores one record per host:
    ...                a ``sa_family_t`` followed by the raw address bytes.
    ...                Linux's ``sa_family_t`` is 2 bytes; the BSDs use 1.
    ...                Detect the target's OS once and stash the width in
    ...                ${PORTSENTRY_FAMILY_SIZE} for ``Confirm Block File Size``.
    ...                Mirrors confirmBlockFileSize() in system_test/testlib.sh.
    ${uname}=    Execute Command    uname -s
    ${u}=    Strip String    ${uname}
    IF    '${u}' == 'Linux'
        Set Suite Variable    ${PORTSENTRY_FAMILY_SIZE}    2
    ELSE
        Set Suite Variable    ${PORTSENTRY_FAMILY_SIZE}    1
    END
    Log    Block-file address-family width on ${u}: ${PORTSENTRY_FAMILY_SIZE} byte(s)    INFO    console=True

Discover Source IPs
    [Documentation]    Resolve the runner's source IPv4 toward ${PORTSENTRY_HOST}
    ...                and source IPv6 toward ${PORTSENTRY_HOST_IPV6}. IPv6 is
    ...                mandatory: if PORTSENTRY_HOST_IPV6 is unset, abort the
    ...                whole suite — there is intentionally no opt-out.
    IF    '${PORTSENTRY_HOST_IPV6}' == '${EMPTY}'
        Fatal Error    PORTSENTRY_HOST_IPV6 must be set (target's IPv6 address); IPv6 connectivity is mandatory.
    END
    ${ip4}=    Get Source IP For Target    ${PORTSENTRY_HOST}
    Set Suite Variable    ${SOURCE_IP4}       ${ip4}
    ${re4}=    Regex Escape    ${ip4}
    Set Suite Variable    ${RE_SOURCE_IP4}    ${re4}
    Log    Source IPv4 toward ${PORTSENTRY_HOST}: ${ip4}    INFO    console=True
    ${ip6}=    Get Source IP For Target    ${PORTSENTRY_HOST_IPV6}    ipv6=${True}
    Set Suite Variable    ${SOURCE_IP6}       ${ip6}
    ${re6}=    Regex Escape    ${ip6}
    Set Suite Variable    ${RE_SOURCE_IP6}    ${re6}
    Log    Source IPv6 toward ${PORTSENTRY_HOST_IPV6}: ${ip6}    INFO    console=True

# ------------------------------------------------------------------ Test lifecycle
Test Setup
    [Documentation]    Per-test setup: kill any stale portsentry from a prior
    ...                failed run, reset /etc/hosts.deny, and allocate a fresh
    ...                unique working directory under /tmp via ``mktemp -d``.
    Kill Stale Portsentry
    Reset Hosts Deny
    Create Unique Test Dir

Test Teardown
    [Documentation]    On failure we preserve the per-test working directory
    ...                so the user can inspect ``portsentry.stdout``,
    ...                ``portsentry.history``, ``portsentry.blocked``, helper
    ...                script outputs, etc. ``Stop Portsentry`` and the
    ...                hosts.deny reset always run so the next test starts
    ...                from a clean global state regardless of this test's
    ...                outcome.
    Run Keyword If Test Failed    Dump Portsentry Logs
    ${stop_status}    ${stop_msg}=    Run Keyword And Ignore Error    Stop Portsentry
    Run Keyword And Ignore Error    Reset Hosts Deny
    IF    '${stop_status}' == 'FAIL'
        Fail    Stop Portsentry failed (no SIGKILL escalation): ${stop_msg}
    END
    Run Keyword If Test Passed    Remove Test Dir
    Run Keyword If Test Failed    Preserve Test Dir

Kill Stale Portsentry
    Execute Command    ${PORTSENTRY_SUDO} pkill -TERM -x ${PORTSENTRY_PROC_TAG} 2>/dev/null; sleep 1; true

Reset Hosts Deny
    Execute Command    ${PORTSENTRY_SUDO} rm -f /etc/hosts.deny 2>/dev/null; ${PORTSENTRY_SUDO} touch /etc/hosts.deny 2>/dev/null; true

Create Unique Test Dir
    [Documentation]    Allocate a fresh /tmp/portsentry-test.XXXXXX directory
    ...                owned by the SSH user. Stored as ${PORTSENTRY_TEST_DIR}
    ...                for the duration of this test.
    ${out}=    Execute Command    mktemp -d /tmp/portsentry-test.XXXXXXXX
    ${dir}=    Strip String    ${out}
    Should Not Be Empty    ${dir}    msg=mktemp -d returned no path
    Set Test Variable    ${PORTSENTRY_TEST_DIR}    ${dir}
    Log    Per-test working directory: ${dir}    INFO

Remove Test Dir
    [Documentation]    Best-effort cleanup of the per-test working directory.
    ...                Uses sudo because portsentry (root) may have created
    ...                root-owned children inside it.
    IF    '${PORTSENTRY_TEST_DIR}' == '${EMPTY}'    RETURN
    Execute Command    ${PORTSENTRY_SUDO} rm -rf ${PORTSENTRY_TEST_DIR} 2>/dev/null; true
    Set Test Variable    ${PORTSENTRY_TEST_DIR}    ${EMPTY}

Preserve Test Dir
    [Documentation]    Called from Test Teardown when the test failed. Leaves
    ...                the per-test working directory in place so the user can
    ...                SSH in and inspect portsentry's stdout/stderr, history,
    ...                blocked file, helper-script outputs, etc.
    IF    '${PORTSENTRY_TEST_DIR}' == '${EMPTY}'    RETURN
    Log    Test failed — preserving ${PORTSENTRY_TEST_DIR} on ${PORTSENTRY_HOST} for inspection. Clean up with: ssh ${PORTSENTRY_USER}@${PORTSENTRY_HOST} 'sudo rm -rf ${PORTSENTRY_TEST_DIR}'
    ...    WARN    console=True

# ------------------------------------------------------------------ Skip helpers
Skip If Target Not Linux
    ${uname}=    Execute Command    uname -s
    Skip If    '${uname.strip()}' != 'Linux'    Target OS is ${uname.strip()}, not Linux

Skip If Pcap Not Supported
    ${count}=    Execute Command    ldd ${PORTSENTRY_BIN} 2>/dev/null | grep -c 'libpcap' || true
    ${n}=    Convert To Integer    ${count.strip()}
    Skip If    ${n} == 0    portsentry binary not linked against libpcap

# ------------------------------------------------------------------ Config / file upload
Upload Text To Remote File
    [Documentation]    Write ``${content}`` to a local temp file and Put it
    ...                onto the target at ``${remote_path}``.
    [Arguments]    ${content}    ${remote_path}    ${mode}=0644
    ${tmp}=    Evaluate    tempfile.mkstemp(prefix='psr_', text=True)[1]    modules=tempfile
    OperatingSystem.Create File    ${tmp}    ${content}
    Put File    ${tmp}    ${remote_path}    mode=${mode}
    OperatingSystem.Remove File    ${tmp}

Write Portsentry Config
    [Documentation]    Each argument is one line in the generated
    ...                ``portsentry.conf`` on the target.
    [Arguments]    @{lines}
    ${body}=    Catenate    SEPARATOR=\n    @{lines}
    Upload Text To Remote File    ${body}\n    ${PORTSENTRY_TEST_DIR}/portsentry.conf

Write Portsentry Ignore
    [Documentation]    Each argument is one line in the generated
    ...                ``portsentry.ignore`` on the target.
    [Arguments]    @{lines}
    ${body}=    Catenate    SEPARATOR=\n    @{lines}
    Upload Text To Remote File    ${body}\n    ${PORTSENTRY_TEST_DIR}/portsentry.ignore

Upload Helper Script
    [Documentation]    Drop a tiny ``/bin/sh`` script onto the target. The
    ...                external-command tests reference these from KILL_ROUTE
    ...                / KILL_RUN_CMD.
    [Arguments]    ${name}    ${body}
    ${content}=    Catenate    SEPARATOR=\n    \#!/bin/sh    ${body}    ${EMPTY}
    Upload Text To Remote File    ${content}    ${PORTSENTRY_TEST_DIR}/${name}    mode=0755

# ------------------------------------------------------------------ Portsentry lifecycle
Start Portsentry
    [Documentation]    Launch portsentry on the target with the given switches
    ...                (under sudo when needed) and wait for the "ready" log
    ...                line. Invoked by absolute path so the resulting cmdline
    ...                matches ${PORTSENTRY_PROC_TAG} — pgrep/pkill rely on it.
    ...                stdout/stderr are opened by the SSH-user's shell before
    ...                exec'ing portsentry so we can read them without sudo.
    [Arguments]    ${switches}
    ${cmd}=    Set Variable
    ...    cd ${PORTSENTRY_TEST_DIR} && { nohup ${PORTSENTRY_SUDO} ${PORTSENTRY_BIN} -c portsentry.conf ${switches} </dev/null > portsentry.stdout 2> portsentry.stderr & }
    Execute Command    ${cmd}    return_stdout=False    return_rc=False
    Wait Until Keyword Succeeds    ${READY_TIMEOUT}    1s    Portsentry Should Be Ready

Portsentry Should Be Ready
    ${rc}=    Execute Command    grep -q 'Portsentry is now active and listening.' ${PORTSENTRY_TEST_DIR}/portsentry.stdout
    ...    return_stdout=False    return_rc=True
    IF    ${rc} != 0
        ${alive}=    Execute Command
        ...    ${PORTSENTRY_SUDO} pgrep -x ${PORTSENTRY_PROC_TAG} >/dev/null 2>&1 && echo running || echo gone
        IF    'gone' in '''${alive}'''
            Dump Portsentry Logs
            Fail    portsentry exited before reporting ready
        END
        Fail    portsentry not ready yet
    END

Stop Portsentry
    [Documentation]    Send SIGTERM and wait up to ${STOP_TIMEOUT} for
    ...                portsentry to exit. Does NOT escalate to SIGKILL — if
    ...                the daemon hangs after a TERM, the test is failed.
    ...                portsentry hanging on shutdown is considered a defect.
    Execute Command    ${PORTSENTRY_SUDO} pkill -TERM -x ${PORTSENTRY_PROC_TAG} 2>/dev/null; true
    Wait Until Keyword Succeeds    ${STOP_TIMEOUT}    1s    Portsentry Should Be Gone

Portsentry Should Be Gone
    ${out}=    Execute Command
    ...    ${PORTSENTRY_SUDO} pgrep -x ${PORTSENTRY_PROC_TAG} >/dev/null 2>&1 && echo running || echo stopped
    Should Contain    ${out}    stopped

Dump Portsentry Logs
    ${out}=    Execute Command    ${PORTSENTRY_SUDO} cat ${PORTSENTRY_TEST_DIR}/portsentry.stdout 2>/dev/null; true
    ${err}=    Execute Command    ${PORTSENTRY_SUDO} cat ${PORTSENTRY_TEST_DIR}/portsentry.stderr 2>/dev/null; true
    Log    ==== PORTSENTRY STDOUT ====\n${out}    WARN
    Log    ==== PORTSENTRY STDERR ====\n${err}    WARN

# ------------------------------------------------------------------ Remote file reads / matches
Read Remote File
    [Arguments]    ${name}
    ${out}=    Execute Command    ${PORTSENTRY_SUDO} cat ${PORTSENTRY_TEST_DIR}/${name} 2>/dev/null; true
    RETURN    ${out}

Remote File Should Match
    [Arguments]    ${name}    ${pattern}
    ${content}=    Read Remote File    ${name}
    Should Match Regexp    ${content}    (?m)${pattern}
    ...    msg=Pattern ${pattern} not found in ${name}

Remote File Match Count Should Be
    [Arguments]    ${name}    ${pattern}    ${expected}
    ${content}=    Read Remote File    ${name}
    ${actual}=    Count Pattern Matches    ${content}    ${pattern}
    Should Be Equal As Integers    ${actual}    ${expected}
    ...    msg=Expected ${expected} matches of ${pattern} in ${name}, got ${actual}

Remote File Should Not Match
    [Arguments]    ${name}    ${pattern}
    ${content}=    Read Remote File    ${name}
    Should Not Match Regexp    ${content}    (?m)${pattern}
    ...    msg=Unexpected match of ${pattern} in ${name}

Wait For Stdout Pattern
    [Arguments]    ${pattern}    ${timeout}=${POLL_TIMEOUT}
    Wait Until Keyword Succeeds    ${timeout}    1s    Remote File Should Match    portsentry.stdout    ${pattern}

Wait For Stdout Pattern Count
    [Arguments]    ${expected}    ${pattern}    ${timeout}=${POLL_TIMEOUT}
    Wait Until Keyword Succeeds    ${timeout}    1s    Remote File Match Count Should Be    portsentry.stdout    ${pattern}    ${expected}

Wait For History Pattern
    [Arguments]    ${pattern}    ${timeout}=${POLL_TIMEOUT}
    Wait Until Keyword Succeeds    ${timeout}    1s    Remote File Should Match    portsentry.history    ${pattern}

Wait For Remote File
    [Arguments]    ${name}    ${timeout}=${POLL_TIMEOUT}
    Wait Until Keyword Succeeds    ${timeout}    1s    Remote File Should Exist    ${name}

Remote File Should Exist
    [Arguments]    ${name}
    ${rc}=    Execute Command    ${PORTSENTRY_SUDO} test -f ${PORTSENTRY_TEST_DIR}/${name}
    ...    return_stdout=False    return_rc=True
    Should Be Equal As Integers    ${rc}    0    msg=${name} does not exist on target

# ------------------------------------------------------------------ High-level assertions
Source IP For Family
    [Arguments]    ${ipv}=4
    IF    '${ipv}' == '6'
        RETURN    ${SOURCE_IP6}
    END
    RETURN    ${SOURCE_IP4}

Regex Source IP For Family
    [Arguments]    ${ipv}=4
    IF    '${ipv}' == '6'
        RETURN    ${RE_SOURCE_IP6}
    END
    RETURN    ${RE_SOURCE_IP4}

Confirm Scan Logged
    [Arguments]    ${proto}    ${ipv}=4
    ${ip}=    Regex Source IP For Family    ${ipv}
    Wait For Stdout Pattern    ^Scan from: \\[${ip}\\]

Confirm History Logged
    [Arguments]    ${proto}    ${ipv}=4    ${port}=11
    ${ip}=    Regex Source IP For Family    ${ipv}
    ${pu}=    Convert To Uppercase    ${proto}
    Wait For History Pattern    Scan from: \\[${ip}\\] \\(${ip}\\) protocol: \\[${pu}\\] port: \\[${port}\\]

Confirm Block Triggered
    [Arguments]    ${proto}    ${ipv}=4    ${port}=11
    Confirm Scan Logged    ${proto}    ${ipv}
    Confirm History Logged    ${proto}    ${ipv}    ${port}

Confirm Already Blocked
    [Arguments]    ${ipv}=4
    ${ip}=    Regex Source IP For Family    ${ipv}
    Wait For Stdout Pattern    attackalert: Host: ${ip}/${ip} is already blocked Ignoring

Confirm Block File Size
    [Arguments]    ${ipv4_count}    ${ipv6_count}
    ${expected}=    Expected Block File Size    ${ipv4_count}    ${ipv6_count}
    ...    family_size=${PORTSENTRY_FAMILY_SIZE}
    Wait Until Keyword Succeeds    ${POLL_TIMEOUT}    1s
    ...    Block File Size Should Be    ${expected}

Block File Size Should Be
    [Documentation]    Read the block-file size with ``ls -l | tr -s ' ' | cut
    ...                -d ' ' -f 5`` — the same POSIX pipeline the original
    ...                confirmBlockFileSize() shell helper used. ``stat -c
    ...                '%s'`` is GNU-only and breaks on OpenBSD/FreeBSD.
    [Arguments]    ${expected}
    ${out}=    Execute Command    ${PORTSENTRY_SUDO} ls -l ${PORTSENTRY_TEST_DIR}/portsentry.blocked 2>/dev/null | tr -s ' ' | cut -d ' ' -f 5
    ${size}=    Strip String    ${out}
    Should Be Equal As Strings    ${size}    ${expected}
    ...    msg=Expected block file size ${expected}, got '${size}'

Confirm External Command Run
    Wait For Stdout Pattern    ^attackalert: External command run for host: ${RE_SOURCE_IP4} using command

Confirm Route Kill
    Wait For Stdout Pattern    ^attackalert: Host ${RE_SOURCE_IP4} has been blocked via dropped route using command

Confirm Hosts Deny Block
    Wait For Stdout Pattern    ^attackalert: Host ${RE_SOURCE_IP4} has been blocked via wrappers with string

Confirm Syn Scan
    Wait For Stdout Pattern    Scan from: \\[${RE_SOURCE_IP4}\\] \\(${RE_SOURCE_IP4}\\) protocol: \\[TCP\\] port: \\[11\\] type: \\[TCP SYN/Normal scan\\]

Confirm Null Scan
    Wait For Stdout Pattern    Scan from: \\[${RE_SOURCE_IP4}\\] \\(${RE_SOURCE_IP4}\\) protocol: \\[TCP\\] port: \\[11\\] type: \\[TCP NULL scan\\]

Confirm Xmas Scan
    Wait For Stdout Pattern    Scan from: \\[${RE_SOURCE_IP4}\\] \\(${RE_SOURCE_IP4}\\) protocol: \\[TCP\\] port: \\[11\\] type: \\[TCP XMAS scan\\]

Confirm Fin Scan
    Wait For Stdout Pattern    Scan from: \\[${RE_SOURCE_IP4}\\] \\(${RE_SOURCE_IP4}\\) protocol: \\[TCP\\] port: \\[11\\] type: \\[TCP FIN scan\\]

Confirm Ignore File Match
    [Arguments]    ${ipv}=4
    ${ip}=    Regex Source IP For Family    ${ipv}
    Wait For Stdout Pattern    Host: ${ip} found in ignore file [^ ]* aborting actions
