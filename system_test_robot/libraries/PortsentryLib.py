# SPDX-License-Identifier: BSD-2-Clause
"""Python helpers for the portsentry Robot Framework system tests.

These keywords run on the *runner* host (the machine running ``robot``) and
exercise the target machine over the network: they discover the runner's
source IP toward the target, send TCP/UDP banner probes, drive ``nmap``, and
compute the expected block-file size.
"""

import re
import shlex
import shutil
import socket
import subprocess
import time

from robot.api import logger
from robot.api.deco import keyword


def _family(ipv6):
    truthy = str(ipv6).lower() in ("1", "true", "yes", "ipv6", "6")
    return socket.AF_INET6 if truthy else socket.AF_INET


@keyword("Get Source IP For Target")
def get_source_ip_for_target(target, ipv6=False):
    """Return the local IP address the runner would use to reach ``target``.

    Uses a connected UDP socket — no packet actually leaves the kernel, but
    ``getsockname`` returns the source address the OS picks for the route.
    Raises ``OSError`` if no route is available (e.g. no IPv6 connectivity).
    """
    fam = _family(ipv6)
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.connect((target, 65530))
        return s.getsockname()[0]


@keyword("Regex Escape")
def regex_escape(text):
    """Wrap :func:`re.escape` so Robot tests can build patterns from IPs."""
    return re.escape(text)


@keyword("Count Pattern Matches")
def count_pattern_matches(text, pattern):
    """Return the number of matches for ``pattern`` (re.MULTILINE) in ``text``."""
    return len(re.findall(pattern, text, re.MULTILINE))


@keyword("Expected Block File Size")
def expected_block_file_size(ipv4_count, ipv6_count, family_size=2):
    """Compute the expected ``portsentry.blocked`` size in bytes.

    portsentry writes a fixed-size record per blocked host: address family
    identifier (2 bytes on Linux, 1 on BSD) plus the raw address (4 bytes for
    IPv4, 16 for IPv6). The default ``family_size=2`` matches Linux, which is
    the target platform for these tests.
    """
    fs = int(family_size)
    return (int(ipv4_count) * (4 + fs)) + (int(ipv6_count) * (16 + fs))


@keyword("TCP Banner Probe")
def tcp_banner_probe(host, port, timeout=5, ipv6=False):
    """Open a TCP connection to ``host:port``, return up to 1024 bytes received.

    Mirrors the original portcon TCP behaviour: connect, wait up to ``timeout``
    seconds for data, read once. Returns ``""`` on timeout.
    """
    fam = _family(ipv6)
    with socket.socket(fam, socket.SOCK_STREAM) as s:
        s.settimeout(float(timeout))
        s.connect((host, int(port)))
        try:
            data = s.recv(1024)
        except socket.timeout:
            data = b""
        return data.decode("latin-1", errors="replace")


@keyword("TCP Connect Probe")
def tcp_connect_probe(host, port, hold=0.5, timeout=5, ipv6=False):
    """Establish a TCP connection to ``host:port`` and close it cleanly.

    This is the connect-mode equivalent of a port scan, but unlike
    ``nmap -sT`` it does *not* abort the connection with a RST. nmap's
    connect scan completes the handshake and then tears the connection down
    with a RST immediately. On the BSDs a RST that arrives while the
    connection is still on the listen queue (i.e. before portsentry's
    ``accept()`` runs) makes the kernel discard the pending connection and
    return ``ECONNABORTED`` — the peer address is lost and portsentry can
    only log "Possible stealth scan from unknown host". Linux keeps such
    connections, which is why ``nmap -sT`` works there. The original shell
    tests dodged this entirely by scanning ``localhost``.

    To portably exercise connect-mode detection we make a real connection,
    hold it briefly so the daemon's ``accept()`` wins the race, then close
    it with a normal FIN (which never triggers ``ECONNABORTED``). The
    connection carries the runner's source IP exactly like the other probes.
    """
    fam = _family(ipv6)
    with socket.socket(fam, socket.SOCK_STREAM) as s:
        s.settimeout(float(timeout))
        s.connect((host, int(port)))
        if float(hold) > 0:
            time.sleep(float(hold))
    return ""


@keyword("UDP Banner Probe")
def udp_banner_probe(host, port, timeout=5, ipv6=False, payload="Hello"):
    """Send ``payload`` to ``host:port`` over UDP and read any response.

    Mirrors the original portcon UDP behaviour: send a probe, wait for a
    response with timeout, return what came back. Returns ``""`` on timeout.
    """
    fam = _family(ipv6)
    body = payload.encode("latin-1") if isinstance(payload, str) else payload
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.settimeout(float(timeout))
        s.sendto(body, (host, int(port)))
        try:
            data, _ = s.recvfrom(1024)
        except socket.timeout:
            data = b""
        return data.decode("latin-1", errors="replace")


@keyword("Run Nmap")
def run_nmap(*args, timeout=30):
    """Run nmap on the runner with the given arguments.

    Arguments are nmap CLI flags exactly as you'd pass them on the shell,
    including the target host(s). Each Robot argument may be a single
    token or a space-separated string (split via :mod:`shlex`), so either
    of these works::

        Run Nmap    -sT -p 11 ${PORTSENTRY_HOST}
        Run Nmap    -sT    -p    11    ${PORTSENTRY_HOST}

    The boilerplate ``--privileged -Pn -n --max-retries 0`` is prepended
    by the keyword — those flags are testing infrastructure (skip host
    discovery / DNS / retries; trust the runner's CAP_NET_RAW) and not
    something individual tests should think about. Pass a contradicting
    flag later in ``args`` to override.

    Raises ``AssertionError`` if nmap is missing or exits non-zero.
    """
    nmap = shutil.which("nmap")
    if not nmap:
        raise AssertionError("nmap is not installed on the runner")
    cmd = [nmap, "--privileged", "-Pn", "-n", "--max-retries", "0"]
    for a in args:
        cmd.extend(shlex.split(str(a)))
    logger.info("nmap: " + " ".join(cmd))
    completed = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=float(timeout),
    )
    logger.info(
        f"nmap rc={completed.returncode}\n"
        f"--- stdout ---\n{completed.stdout.decode(errors='replace')}\n"
        f"--- stderr ---\n{completed.stderr.decode(errors='replace')}"
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"nmap exited with rc={completed.returncode}; "
            f"stderr: {completed.stderr.decode(errors='replace').strip()}"
        )
