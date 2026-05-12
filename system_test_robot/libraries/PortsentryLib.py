# SPDX-License-Identifier: BSD-2-Clause
"""Python helpers for the portsentry Robot Framework system tests.

These keywords run on the *runner* host (the machine running ``robot``) and
exercise the target machine over the network: they discover the runner's
source IP toward the target, send TCP/UDP banner probes, drive ``nmap``, and
compute the expected block-file size.
"""

import re
import shutil
import socket
import subprocess

from robot.api import logger
from robot.api.deco import keyword


_NMAP_FLAG = {
    "T": "-sT",  # connect
    "U": "-sU",  # UDP
    "S": "-sS",  # SYN
    "N": "-sN",  # NULL
    "F": "-sF",  # FIN
    "X": "-sX",  # XMAS
}


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


@keyword("Run Nmap Probe")
def run_nmap_probe(host, port, scan_type, ipv6=False, timeout=30):
    """Run ``nmap`` against ``host:port`` from the runner.

    ``scan_type`` accepts the single-letter codes used by the original shell
    tests: ``T`` (connect), ``U`` (UDP), ``S`` (SYN), ``N`` (NULL),
    ``F`` (FIN), ``X`` (XMAS). The latter four need raw-socket privileges
    (root or ``CAP_NET_RAW``) on the runner.
    """
    nmap = shutil.which("nmap")
    if not nmap:
        raise AssertionError("nmap is not installed on the runner")
    code = str(scan_type).upper()
    if code not in _NMAP_FLAG:
        raise AssertionError(f"Unknown nmap scan type: {scan_type!r}")
    cmd = [
        nmap,
        "--privileged",
        "-Pn",
        "-n",
        "--max-retries", "0",
        _NMAP_FLAG[code],
        "-p", f"{port}-{port}",
    ]
    if str(ipv6).lower() in ("1", "true", "yes", "ipv6", "6"):
        cmd.append("-6")
    cmd.append(str(host))
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
