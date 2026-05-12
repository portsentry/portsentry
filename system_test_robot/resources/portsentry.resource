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
${PORTSENTRY_TEST_DIR}    /tmp/portsentry-test
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
    Claim Remote Test Dir
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
    ${rc}=    Execute Command    test -x ${PORTSENTRY_TEST_DIR}/portsentry
    ...    return_stdout=False    return_rc=True
    Should Be Equal As Integers    ${rc}    0
    ...    msg=portsentry binary not found at ${PORTSENTRY_TEST_DIR}/portsentry on ${PORTSENTRY_HOST}

Claim Remote Test Dir
    [Documentation]    Make sure the test directory is writable by the SSH
    ...                user. Files left over from earlier runs may be
    ...                root-owned; chown them once so SFTP uploads succeed.
    Execute Command    ${PORTSENTRY_SUDO} chown -R ${PORTSENTRY_USER} ${PORTSENTRY_TEST_DIR}
    ...    return_stdout=False    return_rc=False

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
    Reset Remote Test Dir

Test Teardown
    Run Keyword If Test Failed    Dump Portsentry Logs
    ${stop_status}    ${stop_msg}=    Run Keyword And Ignore Error    Stop Portsentry
    Run Keyword And Ignore Error    Reset Remote Test Dir
    IF    '${stop_status}' == 'FAIL'
        Fail    Stop Portsentry failed (no SIGKILL escalation): ${stop_msg}
    END

Reset Remote Test Dir
    Execute Command    ${PORTSENTRY_SUDO} pkill -TERM -x ${PORTSENTRY_PROC_TAG} 2>/dev/null; sleep 1; true
    Execute Command    ${PORTSENTRY_SUDO} find ${PORTSENTRY_TEST_DIR} -mindepth 1 -maxdepth 1 ! -name portsentry ! -name portcon -exec rm -rf {} + 2>/dev/null; true
    Execute Command    ${PORTSENTRY_SUDO} rm -f /etc/hosts.deny 2>/dev/null; ${PORTSENTRY_SUDO} touch /etc/hosts.deny 2>/dev/null; true

# ------------------------------------------------------------------ Skip helpers
Skip If Target Not Linux
    ${uname}=    Execute Command    uname -s
    Skip If    '${uname.strip()}' != 'Linux'    Target OS is ${uname.strip()}, not Linux

Skip If Pcap Not Supported
    ${count}=    Execute Command    ldd ${PORTSENTRY_TEST_DIR}/portsentry 2>/dev/null | grep -c 'libpcap' || true
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
    ...    cd ${PORTSENTRY_TEST_DIR} && { nohup ${PORTSENTRY_SUDO} ${PORTSENTRY_TEST_DIR}/portsentry -c portsentry.conf ${switches} </dev/null > portsentry.stdout 2> portsentry.stderr & }
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

# ------------------------------------------------------------------ Probe wrappers
Run Nmap
    [Documentation]    Convenience wrapper that targets the configured host.
    ...                IPv4 probes go to ${PORTSENTRY_HOST}; IPv6 probes go
    ...                to ${PORTSENTRY_HOST_IPV6}. ``scan_type`` is one of
    ...                T/U/S/N/F/X (see PortsentryLib).
    [Arguments]    ${port}    ${scan_type}    ${ipv}=4
    IF    '${ipv}' == '6'
        Run Nmap Probe    ${PORTSENTRY_HOST_IPV6}    ${port}    ${scan_type}    ipv6=${True}
    ELSE
        Run Nmap Probe    ${PORTSENTRY_HOST}    ${port}    ${scan_type}    ipv6=${False}
    END

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
    Wait Until Keyword Succeeds    ${POLL_TIMEOUT}    1s
    ...    Block File Size Should Be    ${expected}

Block File Size Should Be
    [Arguments]    ${expected}
    ${out}=    Execute Command    ${PORTSENTRY_SUDO} stat -c '%s' ${PORTSENTRY_TEST_DIR}/portsentry.blocked 2>/dev/null || echo MISSING
    ${size}=    Strip String    ${out}
    Should Be Equal As Strings    ${size}    ${expected}
    ...    msg=Expected block file size ${expected}, got ${size}

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
