<div id="header" align="center">
  <img src="https://portsentry.xyz/img/portsentry.png" width="200" />
</div>

<div id="badges" align="center">
  <img src="https://komarev.com/ghpvc/?username=portsentry&style=flat-square&color=blue" alt=""/>
  <img src="https://github.com/portsentry/portsentry/actions/workflows/cmake-single-platform.yml/badge.svg?branch=master" alt="" />
  <img src="https://github.com/portsentry/portsentry/actions/workflows/codacy.yml/badge.svg?branch=master" alt="" />
  <img src="https://github.com/portsentry/portsentry/actions/workflows/codeql.yml/badge.svg" alt="" />
  <img src="https://img.shields.io/github/v/release/portsentry/portsentry" alt="" />
  <img src="https://img.shields.io/github/last-commit/portsentry/portsentry" alt="" />
</div>

# Portsentry
**Detect and respond to port scans against a target host in real\-time**

## What is Portsentry?

**Port Scan Detection**

Portsentry monitors network traffic to detect port scans in real-time. It can identify several types of scans, including TCP, UDP, SYN, FIN, XMAS, and NULL scans.

**Response Mechanisms**

Upon detecting a port scan, Portsentry can respond in several ways to mitigate the threat:

* Blocking the Attacker: It can automatically add the attacker's IP address to the system's firewall or access control list, effectively blocking any further connections from that IP.
* Logging: Portsentry logs the details of the scan attempt, including the source IP address, timestamp, and type of scan detected. This information can be useful for forensic analysis and monitoring.
* Notification: It can send alerts to system administrators via email or other messaging systems to notify them of the detected scan.

**Stealth Mode**

Portsentry operates in stealth mode where it listens on unused ports. Since these ports should not receive any legitimate traffic, any connection attempts are considered suspicious and are flagged as potential scans.

**Integration with Security Tools**

Portsentry can be integrated with other security tools and systems to provide a comprehensive security solution. For example, it can be used with fail2ban in order to take advantage of its sophisticated blocking mechanism.

## Quickstart

### Docker

```
docker run -d --network=host --name portsentry portsentry/portsentry:unstable
```

More docker configuration options available in the [HOWTO-Docker.md](docs/HOWTO-Docker.md)

### Linux

Download the latest release from the [Release page](https://github.com/portsentry/portsentry/releases)

### *BSD

OpenBSD, NetBSD and FreeBSD is supported but must currently be compiled manually, see below

### Compiling the Source Code

* Make sure you have: **CMake**, **gcc or clang** and **libpcap** installed.
* git clone https://github.com/portsentry/portsentry.git
* ./build.sh release

Detailed compilation instructions can be found on the [HOWTO-Compile](docs/HOWTO-Compile.md) page.

## Documentation

All documentation for portsentry is indexed in the [docs/README.md](docs/README.md).

## Links

Website: https://portsentry.xyz

Github: https://github.com/portsentry/portsentry

Docker Hub: https://hub.docker.com/r/portsentry/portsentry
