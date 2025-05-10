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

Website: https://portsentry.xyz

Github: https://github.com/portsentry/portsentry

Docker Hub: https://hub.docker.com/r/portsentry/portsentry

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
