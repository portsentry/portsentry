*** Settings ***
Documentation     Portsentry system tests.
...
...               Each test writes a self-contained ``portsentry.conf`` (and,
...               when needed, ``portsentry.ignore`` plus a tiny KILL_ROUTE /
...               KILL_RUN_CMD helper script) onto the target over SSH, starts
...               portsentry with the requested switches, drives probes from
...               the runner (nmap, TCP/UDP banner reads), and verifies the
...               daemon's stdout / history / blocked files on the target.
Resource          resources/portsentry.resource

Suite Setup       Portsentry Suite Setup
Suite Teardown    Portsentry Suite Teardown
Test Setup        Test Setup
Test Teardown     Test Teardown

*** Test Cases ***
001 Connect Sentry TCP
    Write Portsentry Config
    ...    TCP_PORTS="1,11"
    ...    UDP_PORTS="1,7,9,11"
    ...    HISTORY_FILE="./portsentry.history"
    ...    BLOCKED_FILE="./portsentry.blocked"
    ...    BLOCK_UDP="1"
    ...    BLOCK_TCP="1"
    ...    KILL_ROUTE="true $TARGET$"
    Start Portsentry    --connect -d
    TCP Connect Probe    ${PORTSENTRY_HOST}    11
    Confirm Block Triggered    tcp
    Confirm Block File Size    1    0
    TCP Connect Probe    ${PORTSENTRY_HOST}    11
    Confirm Already Blocked
    Confirm Block File Size    1    0
    Run Nmap    -sU -p 11 ${PORTSENTRY_HOST}
    Run Nmap    -sU -p 11 ${PORTSENTRY_HOST}
    Wait For Stdout Pattern Count    2    Scan from: \\[${RE_SOURCE_IP4}\\] \\(${RE_SOURCE_IP4}\\) protocol: \\[TCP\\] port: \\[11\\] type: \\[Connect\\]
    Wait For Stdout Pattern Count    2    Scan from: \\[${RE_SOURCE_IP4}\\] \\(${RE_SOURCE_IP4}\\) protocol: \\[UDP\\] port: \\[11\\] type: \\[Connect\\]

002 Connect Sentry UDP
    Write Portsentry Config
    ...    TCP_PORTS="1,11"
    ...    UDP_PORTS="1,7,9,11"
    ...    HISTORY_FILE="./portsentry.history"
    ...    BLOCKED_FILE="./portsentry.blocked"
    ...    BLOCK_UDP="1"
    ...    BLOCK_TCP="1"
    ...    KILL_ROUTE="true $TARGET$"
    Start Portsentry    --connect -d
    Run Nmap    -sU -p 11 ${PORTSENTRY_HOST}
    Confirm Block Triggered    udp
    Confirm Block File Size    1    0
    Run Nmap    -sU -p 11 ${PORTSENTRY_HOST}
    Confirm Already Blocked
    Confirm Block File Size    1    0
    TCP Connect Probe    ${PORTSENTRY_HOST}    11
    TCP Connect Probe    ${PORTSENTRY_HOST}    11
    Wait For Stdout Pattern Count    2    Scan from: \\[${RE_SOURCE_IP4}\\] \\(${RE_SOURCE_IP4}\\) protocol: \\[TCP\\] port: \\[11\\] type: \\[Connect\\]
    Wait For Stdout Pattern Count    2    Scan from: \\[${RE_SOURCE_IP4}\\] \\(${RE_SOURCE_IP4}\\) protocol: \\[UDP\\] port: \\[11\\] type: \\[Connect\\]

003 Banner TCP
    Write Portsentry Config
    ...    TCP_PORTS="1,11"
    ...    UDP_PORTS="1,7,9,11"
    ...    HISTORY_FILE="./portsentry.history"
    ...    BLOCKED_FILE="./portsentry.blocked"
    ...    BLOCK_UDP="1"
    ...    BLOCK_TCP="1"
    ...    PORT_BANNER="Some banner printed on port"
    ...    KILL_ROUTE="true $TARGET$"
    Start Portsentry    --connect -d
    ${banner}=    TCP Banner Probe    ${PORTSENTRY_HOST}    11
    Should Contain    ${banner}    Some banner printed on port
    Confirm Block Triggered    tcp
    Confirm Block File Size    1    0
    TCP Connect Probe    ${PORTSENTRY_HOST}    11
    Confirm Already Blocked
    Confirm Block File Size    1    0

004 Banner UDP
    Write Portsentry Config
    ...    TCP_PORTS="1,11"
    ...    UDP_PORTS="1,7,9,11"
    ...    HISTORY_FILE="./portsentry.history"
    ...    BLOCKED_FILE="./portsentry.blocked"
    ...    BLOCK_UDP="1"
    ...    BLOCK_TCP="1"
    ...    PORT_BANNER="Some banner printed on port"
    ...    KILL_ROUTE="true $TARGET$"
    Start Portsentry    --connect -d
    ${banner}=    UDP Banner Probe    ${PORTSENTRY_HOST}    11
    Should Contain    ${banner}    Some banner printed on port
    Confirm Block Triggered    udp
    Confirm Block File Size    1    0
    Run Nmap    -sU -p 11 ${PORTSENTRY_HOST}
    Confirm Already Blocked
    Confirm Block File Size    1    0

005 Block 0 TCP
    Write Portsentry Config
    ...    TCP_PORTS="1,11"
    ...    HISTORY_FILE="./portsentry.history"
    ...    BLOCKED_FILE="./portsentry.blocked"
    ...    BLOCK_UDP="0"
    ...    BLOCK_TCP="0"
    Start Portsentry    --connect -d
    TCP Connect Probe    ${PORTSENTRY_HOST}    11
    Confirm Scan Logged    tcp
    Confirm History Logged    tcp
    TCP Connect Probe    ${PORTSENTRY_HOST}    11
    Wait For Stdout Pattern Count    2    ^Scan from: \\[${RE_SOURCE_IP4}\\] \\(${RE_SOURCE_IP4}\\) protocol: \\[TCP\\] port: \\[11\\]

006 Block 0 UDP
    Write Portsentry Config
    ...    UDP_PORTS="1,7,9,11"
    ...    HISTORY_FILE="./portsentry.history"
    ...    BLOCKED_FILE="./portsentry.blocked"
    ...    BLOCK_UDP="0"
    ...    BLOCK_TCP="0"
    Start Portsentry    --connect -d
    Run Nmap    -sU -p 11 ${PORTSENTRY_HOST}
    Confirm Scan Logged    udp
    Confirm History Logged    udp
    Run Nmap    -sU -p 11 ${PORTSENTRY_HOST}
    Wait For Stdout Pattern Count    2    ^Scan from: \\[${RE_SOURCE_IP4}\\] \\(${RE_SOURCE_IP4}\\) protocol: \\[UDP\\] port: \\[11\\]

007 Block 2 TCP
    Upload Helper Script    extcmd.sh    echo "$1 $2" > ${PORTSENTRY_TEST_DIR}/extcmd.stdout
    Write Portsentry Config
    ...    TCP_PORTS="1,11"
    ...    UDP_PORTS="1,7,9,11"
    ...    HISTORY_FILE="./portsentry.history"
    ...    BLOCKED_FILE="./portsentry.blocked"
    ...    BLOCK_UDP="2"
    ...    BLOCK_TCP="2"
    ...    KILL_RUN_CMD="${PORTSENTRY_TEST_DIR}/extcmd.sh $TARGET$ $PORT$"
    Start Portsentry    --connect -d
    TCP Connect Probe    ${PORTSENTRY_HOST}    11
    Confirm Scan Logged    tcp
    Confirm History Logged    tcp
    Confirm External Command Run
    Wait For Remote File    extcmd.stdout
    Remote File Should Match    extcmd.stdout    ^${RE_SOURCE_IP4} 11

008 Block 2 UDP
    Upload Helper Script    extcmd.sh    echo "$1 $2" > ${PORTSENTRY_TEST_DIR}/extcmd.stdout
    Write Portsentry Config
    ...    TCP_PORTS="1,11"
    ...    UDP_PORTS="1,7,9,11"
    ...    HISTORY_FILE="./portsentry.history"
    ...    BLOCKED_FILE="./portsentry.blocked"
    ...    BLOCK_UDP="2"
    ...    BLOCK_TCP="2"
    ...    KILL_RUN_CMD="${PORTSENTRY_TEST_DIR}/extcmd.sh $TARGET$ $PORT$"
    Start Portsentry    --connect -d
    Run Nmap    -sU -p 11 ${PORTSENTRY_HOST}
    Confirm Scan Logged    udp
    Confirm History Logged    udp
    Confirm External Command Run
    Wait For Remote File    extcmd.stdout
    Remote File Should Match    extcmd.stdout    ^${RE_SOURCE_IP4} 11

009 Scan Trigger
    Write Portsentry Config
    ...    TCP_PORTS="1,11"
    ...    UDP_PORTS="1,7,9,11"
    ...    HISTORY_FILE="./portsentry.history"
    ...    BLOCKED_FILE="./portsentry.blocked"
    ...    BLOCK_UDP="1"
    ...    BLOCK_TCP="1"
    ...    SCAN_TRIGGER="2"
    ...    KILL_ROUTE="true $TARGET$"
    Start Portsentry    --connect -d
    TCP Connect Probe    ${PORTSENTRY_HOST}    11
    Wait For Stdout Pattern    ^Scan from: \\[${RE_SOURCE_IP4}\\] \\(${RE_SOURCE_IP4}\\) protocol: \\[TCP\\] port: \\[11\\] type: \\[Connect\\] IP opts: \\[unknown\\] ignored: \\[false\\] triggered: \\[false\\] noblock: \\[unset\\]
    TCP Connect Probe    ${PORTSENTRY_HOST}    11
    Confirm Block Triggered    tcp
    Confirm Block File Size    1    0
    TCP Connect Probe    ${PORTSENTRY_HOST}    11
    Confirm Already Blocked
    Confirm Block File Size    1    0

010 Route Kill
    Upload Helper Script    extcmd.sh    echo "$1 $2" > ${PORTSENTRY_TEST_DIR}/extcmd.stdout
    Write Portsentry Config
    ...    TCP_PORTS="1,11"
    ...    UDP_PORTS="1,7,9,11"
    ...    HISTORY_FILE="./portsentry.history"
    ...    BLOCKED_FILE="./portsentry.blocked"
    ...    BLOCK_UDP="1"
    ...    BLOCK_TCP="1"
    ...    KILL_ROUTE="${PORTSENTRY_TEST_DIR}/extcmd.sh $TARGET$"
    Start Portsentry    --connect -d
    TCP Connect Probe    ${PORTSENTRY_HOST}    11
    Confirm Block Triggered    tcp
    Confirm Block File Size    1    0
    Confirm Route Kill
    Wait For Remote File    extcmd.stdout
    Remote File Should Match    extcmd.stdout    ^${RE_SOURCE_IP4}

011 Kill And External Command
    Upload Helper Script    extcmd.sh      echo "$1 $2" > ${PORTSENTRY_TEST_DIR}/extcmd.stdout
    Upload Helper Script    routesim.sh    echo "$1" > ${PORTSENTRY_TEST_DIR}/routesim.stdout
    Write Portsentry Config
    ...    TCP_PORTS="1,11"
    ...    UDP_PORTS="1,7,9,11"
    ...    HISTORY_FILE="./portsentry.history"
    ...    BLOCKED_FILE="./portsentry.blocked"
    ...    BLOCK_UDP="1"
    ...    BLOCK_TCP="1"
    ...    KILL_ROUTE="${PORTSENTRY_TEST_DIR}/routesim.sh $TARGET$"
    ...    KILL_RUN_CMD="${PORTSENTRY_TEST_DIR}/extcmd.sh $TARGET$ $PORT$"
    Start Portsentry    --connect -d
    TCP Connect Probe    ${PORTSENTRY_HOST}    11
    Wait For Remote File    extcmd.stdout
    Sleep    1s
    Confirm Block File Size    1    0
    Wait For Remote File    routesim.stdout
    Remote File Should Match    routesim.stdout    ^${RE_SOURCE_IP4}
    Remote File Should Match    extcmd.stdout      ^${RE_SOURCE_IP4} 11
    Wait For Stdout Pattern    (?s)attackalert: Host ${RE_SOURCE_IP4} has been blocked via dropped route using command.*attackalert: External command run for host: ${RE_SOURCE_IP4} using command.*Scan from: \\[${RE_SOURCE_IP4}\\] \\(${RE_SOURCE_IP4}\\) protocol: \\[TCP\\] port: \\[11\\]

012 External Command And Kill
    Upload Helper Script    extcmd.sh      echo "$1 $2" > ${PORTSENTRY_TEST_DIR}/extcmd.stdout
    Upload Helper Script    routesim.sh    echo "$1" > ${PORTSENTRY_TEST_DIR}/routesim.stdout
    Write Portsentry Config
    ...    TCP_PORTS="1,11"
    ...    UDP_PORTS="1,7,9,11"
    ...    HISTORY_FILE="./portsentry.history"
    ...    BLOCKED_FILE="./portsentry.blocked"
    ...    BLOCK_UDP="1"
    ...    BLOCK_TCP="1"
    ...    KILL_ROUTE="${PORTSENTRY_TEST_DIR}/routesim.sh $TARGET$"
    ...    KILL_RUN_CMD="${PORTSENTRY_TEST_DIR}/extcmd.sh $TARGET$ $PORT$"
    ...    KILL_RUN_CMD_FIRST="1"
    Start Portsentry    --connect -d
    TCP Connect Probe    ${PORTSENTRY_HOST}    11
    Wait For Remote File    extcmd.stdout
    Sleep    1s
    Confirm Block File Size    1    0
    Wait For Remote File    routesim.stdout
    Remote File Should Match    routesim.stdout    ^${RE_SOURCE_IP4}
    Remote File Should Match    extcmd.stdout      ^${RE_SOURCE_IP4} 11
    Wait For Stdout Pattern    (?s)attackalert: External command run for host: ${RE_SOURCE_IP4} using command.*attackalert: Host ${RE_SOURCE_IP4} has been blocked via dropped route using command.*Scan from: \\[${RE_SOURCE_IP4}\\] \\(${RE_SOURCE_IP4}\\) protocol: \\[TCP\\] port: \\[11\\]

013 Kill Route And Hosts Deny
    Upload Helper Script    routesim.sh    echo "$1" > ${PORTSENTRY_TEST_DIR}/routesim.stdout
    Write Portsentry Config
    ...    TCP_PORTS="1,11"
    ...    UDP_PORTS="1,7,9,11"
    ...    HISTORY_FILE="./portsentry.history"
    ...    BLOCKED_FILE="./portsentry.blocked"
    ...    BLOCK_UDP="1"
    ...    BLOCK_TCP="1"
    ...    KILL_ROUTE="${PORTSENTRY_TEST_DIR}/routesim.sh $TARGET$"
    ...    KILL_HOSTS_DENY="ALL: $TARGET$"
    Start Portsentry    --connect -d
    TCP Connect Probe    ${PORTSENTRY_HOST}    11
    Wait For Remote File    routesim.stdout
    Remote File Should Match    routesim.stdout    ^${RE_SOURCE_IP4}
    Confirm Block Triggered    tcp
    Confirm Block File Size    1    0
    Confirm Route Kill
    Confirm Hosts Deny Block

014 Stealth Sentry TCP
    Skip If Pcap Not Supported
    Write Portsentry Config
    ...    TCP_PORTS="1,11,22"
    ...    UDP_PORTS="1,7,9"
    ...    HISTORY_FILE="${PORTSENTRY_TEST_DIR}/portsentry.history"
    ...    BLOCKED_FILE="${PORTSENTRY_TEST_DIR}/portsentry.blocked"
    ...    BLOCK_UDP="1"
    ...    BLOCK_TCP="1"
    ...    KILL_HOSTS_DENY="ALL: $TARGET$"
    Start Portsentry    --stealth -m pcap -d -i ALL -L
    Run Nmap    -sT -p 11 ${PORTSENTRY_HOST}
    Confirm Block Triggered    tcp
    Confirm Block File Size    1    0
    Run Nmap    -sT -p 11 ${PORTSENTRY_HOST}
    Confirm Already Blocked
    Confirm Block File Size    1    0

015 Stealth Sentry UDP
    Skip If Pcap Not Supported
    Write Portsentry Config
    ...    TCP_PORTS="1,11,22"
    ...    UDP_PORTS="1,7,9,11"
    ...    HISTORY_FILE="${PORTSENTRY_TEST_DIR}/portsentry.history"
    ...    BLOCKED_FILE="${PORTSENTRY_TEST_DIR}/portsentry.blocked"
    ...    BLOCK_UDP="1"
    ...    BLOCK_TCP="1"
    ...    KILL_HOSTS_DENY="ALL: $TARGET$"
    Start Portsentry    --stealth -m pcap -d -i ALL -L
    Run Nmap    -sU -p 11 ${PORTSENTRY_HOST}
    Confirm Block Triggered    udp
    Confirm Block File Size    1    0
    Run Nmap    -sU -p 11 ${PORTSENTRY_HOST}
    Confirm Already Blocked
    Confirm Block File Size    1    0

016 Self Ignore
    [Documentation]    The self-ignore code path only fires when the source and
    ...                destination addresses are identical, which cannot happen
    ...                across the network. The probe is therefore executed
    ...                directly on the target against its loopback.
    Skip If Pcap Not Supported
    Write Portsentry Config
    ...    TCP_PORTS="1,11,22"
    ...    HISTORY_FILE="${PORTSENTRY_TEST_DIR}/portsentry.history"
    ...    BLOCKED_FILE="${PORTSENTRY_TEST_DIR}/portsentry.blocked"
    ...    BLOCK_UDP="0"
    ...    BLOCK_TCP="0"
    Start Portsentry    --stealth -m pcap -d -i ALL
    ${rc}=    Execute Command    nmap -Pn -n --max-retries 0 -sT -p 11 127.0.0.1 >/dev/null
    ...    return_stdout=False    return_rc=True
    Should Be Equal As Integers    ${rc}    0    msg=nmap on target failed
    Wait For Stdout Pattern    ^debug: Source address 127\\.0\\.0\\.1 same as destination address 127\\.0\\.0\\.1, skipping

018 SYN Scan
    Skip If Pcap Not Supported
    Write Portsentry Config
    ...    TCP_PORTS="1,11,22"
    ...    UDP_PORTS="1,7,9,11"
    ...    HISTORY_FILE="${PORTSENTRY_TEST_DIR}/portsentry.history"
    ...    BLOCKED_FILE="${PORTSENTRY_TEST_DIR}/portsentry.blocked"
    ...    BLOCK_UDP="1"
    ...    BLOCK_TCP="1"
    ...    KILL_HOSTS_DENY="ALL: $TARGET$"
    Start Portsentry    --stealth -m pcap -d -i ALL -L
    Run Nmap    -sS -p 11 ${PORTSENTRY_HOST}
    Confirm Syn Scan
    Confirm Block Triggered    tcp
    Confirm Block File Size    1    0

019 NULL Scan
    Skip If Pcap Not Supported
    Write Portsentry Config
    ...    TCP_PORTS="1,11,22"
    ...    UDP_PORTS="1,7,9,11"
    ...    HISTORY_FILE="${PORTSENTRY_TEST_DIR}/portsentry.history"
    ...    BLOCKED_FILE="${PORTSENTRY_TEST_DIR}/portsentry.blocked"
    ...    BLOCK_UDP="1"
    ...    BLOCK_TCP="1"
    ...    KILL_HOSTS_DENY="ALL: $TARGET$"
    Start Portsentry    --stealth -m pcap -d -i ALL -L
    Run Nmap    -sN -p 11 ${PORTSENTRY_HOST}
    Confirm Null Scan
    Confirm Block Triggered    tcp
    Confirm Block File Size    1    0

020 XMAS Scan
    Skip If Pcap Not Supported
    Write Portsentry Config
    ...    TCP_PORTS="1,11,22"
    ...    UDP_PORTS="1,7,9,11"
    ...    HISTORY_FILE="${PORTSENTRY_TEST_DIR}/portsentry.history"
    ...    BLOCKED_FILE="${PORTSENTRY_TEST_DIR}/portsentry.blocked"
    ...    BLOCK_UDP="1"
    ...    BLOCK_TCP="1"
    ...    KILL_HOSTS_DENY="ALL: $TARGET$"
    Start Portsentry    --stealth -m pcap -d -i ALL -L
    Run Nmap    -sX -p 11 ${PORTSENTRY_HOST}
    Confirm Xmas Scan
    Confirm Block Triggered    tcp
    Confirm Block File Size    1    0

021 FIN Scan
    Skip If Pcap Not Supported
    Write Portsentry Config
    ...    TCP_PORTS="1,11,22"
    ...    UDP_PORTS="1,7,9,11"
    ...    HISTORY_FILE="${PORTSENTRY_TEST_DIR}/portsentry.history"
    ...    BLOCKED_FILE="${PORTSENTRY_TEST_DIR}/portsentry.blocked"
    ...    BLOCK_UDP="1"
    ...    BLOCK_TCP="1"
    ...    KILL_HOSTS_DENY="ALL: $TARGET$"
    Start Portsentry    --stealth -m pcap -d -i ALL -L
    Run Nmap    -sF -p 11 ${PORTSENTRY_HOST}
    Confirm Fin Scan
    Confirm Block Triggered    tcp
    Confirm Block File Size    1    0

023 Sentry Connect Range
    Write Portsentry Config
    ...    TCP_PORTS="1,5-11"
    ...    UDP_PORTS="1,7-11"
    ...    HISTORY_FILE="./portsentry.history"
    ...    BLOCKED_FILE="./portsentry.blocked"
    ...    BLOCK_UDP="0"
    ...    BLOCK_TCP="0"
    Start Portsentry    --connect -d
    TCP Connect Probe    ${PORTSENTRY_HOST}    11
    Confirm Scan Logged    tcp
    Confirm History Logged    tcp
    TCP Connect Probe    ${PORTSENTRY_HOST}    11
    Wait For Stdout Pattern Count    2    ^Scan from: \\[${RE_SOURCE_IP4}\\] \\(${RE_SOURCE_IP4}\\) protocol: \\[TCP\\] port: \\[11\\]
    Run Nmap    -sU -p 11 ${PORTSENTRY_HOST}
    Confirm Scan Logged    udp
    Confirm History Logged    udp
    Run Nmap    -sU -p 11 ${PORTSENTRY_HOST}
    Wait For Stdout Pattern Count    2    ^Scan from: \\[${RE_SOURCE_IP4}\\] \\(${RE_SOURCE_IP4}\\) protocol: \\[UDP\\] port: \\[11\\]

024 Sentry Pcap Range
    Skip If Pcap Not Supported
    Write Portsentry Config
    ...    TCP_PORTS="1,5-11"
    ...    UDP_PORTS="1,7-11"
    ...    HISTORY_FILE="./portsentry.history"
    ...    BLOCKED_FILE="./portsentry.blocked"
    ...    BLOCK_UDP="0"
    ...    BLOCK_TCP="0"
    Start Portsentry    --stealth -m pcap -d -i ALL
    Run Nmap    -sT -p 11 ${PORTSENTRY_HOST}
    Confirm Scan Logged    tcp
    Confirm History Logged    tcp
    Run Nmap    -sT -p 11 ${PORTSENTRY_HOST}
    Wait For Stdout Pattern Count    2    ^Scan from: \\[${RE_SOURCE_IP4}\\] \\(${RE_SOURCE_IP4}\\) protocol: \\[TCP\\] port: \\[11\\]
    Run Nmap    -sU -p 11 ${PORTSENTRY_HOST}
    Confirm Scan Logged    udp
    Confirm History Logged    udp
    Run Nmap    -sU -p 11 ${PORTSENTRY_HOST}
    Wait For Stdout Pattern Count    2    ^Scan from: \\[${RE_SOURCE_IP4}\\] \\(${RE_SOURCE_IP4}\\) protocol: \\[UDP\\] port: \\[11\\]

025 Pcap Invalid Probe
    Skip If Pcap Not Supported
    Write Portsentry Config
    ...    TCP_PORTS="1,11"
    ...    HISTORY_FILE="./portsentry.history"
    ...    BLOCKED_FILE="./portsentry.blocked"
    ...    BLOCK_UDP="0"
    ...    BLOCK_TCP="0"
    Start Portsentry    --stealth -m pcap -d -i ALL
    Run Nmap    -sT -p 10 ${PORTSENTRY_HOST}
    Sleep    2s
    Remote File Should Not Match    portsentry.stdout    ^Scan from: \\[${RE_SOURCE_IP4}\\]

026 Connect Invalid Probe
    Write Portsentry Config
    ...    TCP_PORTS="1,11"
    ...    HISTORY_FILE="./portsentry.history"
    ...    BLOCKED_FILE="./portsentry.blocked"
    ...    BLOCK_UDP="0"
    ...    BLOCK_TCP="0"
    Start Portsentry    --connect -d -i ALL
    Run Nmap    -sT -p 10 ${PORTSENTRY_HOST}
    Sleep    2s
    Remote File Should Not Match    portsentry.stdout    ^Scan from: \\[${RE_SOURCE_IP4}\\]

027 Stealth Invalid Probe
    Skip If Target Not Linux
    Write Portsentry Config
    ...    TCP_PORTS="1,11"
    ...    HISTORY_FILE="./portsentry.history"
    ...    BLOCKED_FILE="./portsentry.blocked"
    ...    BLOCK_UDP="0"
    ...    BLOCK_TCP="0"
    Start Portsentry    --stealth -m raw -d -i ALL
    Run Nmap    -sT -p 10 ${PORTSENTRY_HOST}
    Sleep    2s
    Remote File Should Not Match    portsentry.stdout    ^Scan from: \\[${RE_SOURCE_IP4}\\]

028 IPv6 Connect
    Write Portsentry Config
    ...    TCP_PORTS="1,11,22"
    ...    UDP_PORTS="1,7,9"
    ...    HISTORY_FILE="${PORTSENTRY_TEST_DIR}/portsentry.history"
    ...    BLOCKED_FILE="${PORTSENTRY_TEST_DIR}/portsentry.blocked"
    ...    BLOCK_UDP="1"
    ...    BLOCK_TCP="1"
    ...    KILL_HOSTS_DENY="ALL: $TARGET$"
    Start Portsentry    --connect -d
    TCP Connect Probe    ${PORTSENTRY_HOST_IPV6}    11    ipv6=True
    Confirm Block Triggered    tcp    6
    Confirm Block File Size    0    1
    TCP Connect Probe    ${PORTSENTRY_HOST_IPV6}    11    ipv6=True
    Confirm Already Blocked    6
    Confirm Block File Size    0    1

029 IPv6 Pcap
    Skip If Pcap Not Supported
    Write Portsentry Config
    ...    TCP_PORTS="1,11,22"
    ...    UDP_PORTS="1,7,9"
    ...    HISTORY_FILE="${PORTSENTRY_TEST_DIR}/portsentry.history"
    ...    BLOCKED_FILE="${PORTSENTRY_TEST_DIR}/portsentry.blocked"
    ...    BLOCK_UDP="1"
    ...    BLOCK_TCP="1"
    ...    KILL_HOSTS_DENY="ALL: $TARGET$"
    Start Portsentry    --stealth -m pcap -d -i ALL -L
    Run Nmap    -6 -sT -p 11 ${PORTSENTRY_HOST_IPV6}
    Confirm Block Triggered    tcp    6
    Confirm Block File Size    0    1
    Run Nmap    -6 -sT -p 11 ${PORTSENTRY_HOST_IPV6}
    Confirm Already Blocked    6
    Confirm Block File Size    0    1

030 IPv6 Raw
    Skip If Target Not Linux
    Write Portsentry Config
    ...    TCP_PORTS="1,11,22"
    ...    UDP_PORTS="1,7,9"
    ...    HISTORY_FILE="${PORTSENTRY_TEST_DIR}/portsentry.history"
    ...    BLOCKED_FILE="${PORTSENTRY_TEST_DIR}/portsentry.blocked"
    ...    BLOCK_UDP="1"
    ...    BLOCK_TCP="1"
    ...    KILL_HOSTS_DENY="ALL: $TARGET$"
    Start Portsentry    --stealth -m raw -d -L
    Run Nmap    -6 -sT -p 11 ${PORTSENTRY_HOST_IPV6}
    Confirm Block Triggered    tcp    6
    Confirm Block File Size    0    1
    Run Nmap    -6 -sT -p 11 ${PORTSENTRY_HOST_IPV6}
    Confirm Already Blocked    6
    Confirm Block File Size    0    1

031 Ignore File
    Skip If Pcap Not Supported
    Write Portsentry Config
    ...    TCP_PORTS="1,11"
    ...    UDP_PORTS="1,7,9,11"
    ...    IGNORE_FILE="./portsentry.ignore"
    ...    HISTORY_FILE="./portsentry.history"
    ...    BLOCKED_FILE="./portsentry.blocked"
    ...    BLOCK_UDP="0"
    ...    BLOCK_TCP="0"
    Write Portsentry Ignore    ${SOURCE_IP4}/32    0.0.0.0
    Start Portsentry    --stealth -m pcap -d -i ALL -v
    Run Nmap    -sT -p 11 ${PORTSENTRY_HOST}
    Confirm Ignore File Match

032 Ignore File No Mask
    Skip If Pcap Not Supported
    Write Portsentry Config
    ...    TCP_PORTS="1,11"
    ...    UDP_PORTS="1,7,9,11"
    ...    IGNORE_FILE="./portsentry.ignore"
    ...    HISTORY_FILE="./portsentry.history"
    ...    BLOCKED_FILE="./portsentry.blocked"
    ...    BLOCK_UDP="0"
    ...    BLOCK_TCP="0"
    Write Portsentry Ignore    ${SOURCE_IP4}    0.0.0.0
    Start Portsentry    --stealth -m pcap -d -i ALL -v
    Run Nmap    -sT -p 11 ${PORTSENTRY_HOST}
    Confirm Ignore File Match

033 Ignore File IPv6
    Skip If Pcap Not Supported
    Write Portsentry Config
    ...    TCP_PORTS="1,11"
    ...    UDP_PORTS="1,7,9,11"
    ...    IGNORE_FILE="./portsentry.ignore"
    ...    HISTORY_FILE="./portsentry.history"
    ...    BLOCKED_FILE="./portsentry.blocked"
    ...    BLOCK_UDP="0"
    ...    BLOCK_TCP="0"
    Write Portsentry Ignore    ${SOURCE_IP6}/128
    Start Portsentry    --stealth -m pcap -d -i ALL -v
    Run Nmap    -6 -sT -p 11 ${PORTSENTRY_HOST_IPV6}
    Confirm Ignore File Match    6

034 Ignore File No Mask IPv6
    Skip If Pcap Not Supported
    Write Portsentry Config
    ...    TCP_PORTS="1,11"
    ...    UDP_PORTS="1,7,9,11"
    ...    IGNORE_FILE="./portsentry.ignore"
    ...    HISTORY_FILE="./portsentry.history"
    ...    BLOCKED_FILE="./portsentry.blocked"
    ...    BLOCK_UDP="0"
    ...    BLOCK_TCP="0"
    Write Portsentry Ignore    ${SOURCE_IP6}
    Start Portsentry    --stealth -m pcap -d -i ALL -v
    Run Nmap    -6 -sT -p 11 ${PORTSENTRY_HOST_IPV6}
    Confirm Ignore File Match    6

100 Raw Socket TCP
    Skip If Target Not Linux
    Write Portsentry Config
    ...    TCP_PORTS="1,11"
    ...    UDP_PORTS="1,7,9"
    ...    HISTORY_FILE="./portsentry.history"
    ...    BLOCKED_FILE="./portsentry.blocked"
    ...    BLOCK_UDP="1"
    ...    BLOCK_TCP="1"
    ...    KILL_HOSTS_DENY="ALL: $TARGET$"
    Start Portsentry    --stealth -m raw -d -L
    Run Nmap    -sT -p 11 ${PORTSENTRY_HOST}
    Confirm Block Triggered    tcp
    Confirm Block File Size    1    0
    Run Nmap    -sT -p 11 ${PORTSENTRY_HOST}
    Confirm Already Blocked
    Confirm Block File Size    1    0

101 Sentry Stealth Range
    Skip If Target Not Linux
    Write Portsentry Config
    ...    TCP_PORTS="1,5-11"
    ...    UDP_PORTS="1,7-11"
    ...    HISTORY_FILE="./portsentry.history"
    ...    BLOCKED_FILE="./portsentry.blocked"
    ...    BLOCK_UDP="0"
    ...    BLOCK_TCP="0"
    Start Portsentry    --stealth -m raw -d
    Run Nmap    -sT -p 11 ${PORTSENTRY_HOST}
    Confirm Scan Logged    tcp
    Confirm History Logged    tcp
    Run Nmap    -sT -p 11 ${PORTSENTRY_HOST}
    Wait For Stdout Pattern Count    2    ^Scan from: \\[${RE_SOURCE_IP4}\\] \\(${RE_SOURCE_IP4}\\) protocol: \\[TCP\\] port: \\[11\\]
    Run Nmap    -sU -p 11 ${PORTSENTRY_HOST}
    Confirm Scan Logged    udp
    Confirm History Logged    udp
    Run Nmap    -sU -p 11 ${PORTSENTRY_HOST}
    Wait For Stdout Pattern Count    2    ^Scan from: \\[${RE_SOURCE_IP4}\\] \\(${RE_SOURCE_IP4}\\) protocol: \\[UDP\\] port: \\[11\\]
