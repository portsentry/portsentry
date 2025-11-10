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

## What is Portsentry?

**Port Scan Detection**

Portsentry monitors network traffic in order to detect port scans in real-time. It can identify several types of scans, including TCP, SYN, FIN, XMAS, and NULL scans and UDP probing.

**Response Mechanisms**

Upon detecting a port scan, Portsentry can respond in several ways to mitigate the threat:

* Blocking the Attacker: It can automatically add the attacker's IP address to the system's firewall or access control list, effectively blocking any further connections from that IP.
* Logging: Portsentry logs the details of the scan attempt, including the source IP address, timestamp, and type of scan detected. This information can be useful for forensic analysis and monitoring.
* Notification: It can send alerts to system administrators via email or other messaging systems to notify them of the detected scan.

## Quickstart

Detailed installation instructions can be found in the [HOWTO-Use](docs/HOWTO-Use.md) guide.

### Docker

```
docker run -d --network=host --name portsentry portsentry/portsentry:unstable
```

More docker configuration options available in the [HOWTO-Docker.md](docs/HOWTO-Docker.md)

### Linux

#### Debian 13 (trixie)

```
sudo apt install curl gpg
echo 'deb https://download.opensuse.org/repositories/home:/portsentry/Debian_13/ /' | sudo tee /etc/apt/sources.list.d/portsentry.list
curl -fsSL https://download.opensuse.org/repositories/home:/portsentry/Debian_13//Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/portsentry.gpg > /dev/null
sudo apt update
sudo apt install portsentry
```

#### Debian 14

```
sudo apt install portsentry
```

#### Ubuntu 24.04, 25.04, 25.10

```
sudo apt install curl gpg
echo 'deb https://download.opensuse.org/repositories/home:/portsentry/xUbuntu_24.04/ /' | sudo tee /etc/apt/sources.list.d/portsentry.list
curl -fsSL https://download.opensuse.org/repositories/home:/portsentry/xUbuntu_24.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/portsentry.gpg > /dev/null
sudo apt update
sudo apt install portsentry
```

#### Other Linux distributions

Download and extract the tarball and run the installer script by typing:

```bash
sudo tar --strip-components=1 -C / -xvf portsentry-*.tar.xz
```

### *BSD

OpenBSD, NetBSD and FreeBSD is supported but must currently be compiled manually, see below

### Compiling the Source Code

Detailed compilation instructions can be found on the [HOWTO-Compile](docs/HOWTO-Compile.md) page.

## Documentation

All documentation for portsentry is indexed in the [docs/README.md](docs/README.md).

## Support

Please use the [Discussions Forums](https://github.com/portsentry/portsentry/discussions) for any support questions or feedback

## Links

Website: https://portsentry.xyz

Github: https://github.com/portsentry/portsentry

Docker Hub: https://hub.docker.com/r/portsentry/portsentry
