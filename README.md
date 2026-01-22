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

**Portsentry monitors network traffic to detect and respond to port scans and probing attempts in real-time.**

_For a more detailed introduction, review the [HOWTO-Use-Cases](docs/HOWTO-Use-Cases.md) documentation_

## Quickstart

### Docker

```
docker run -d --network=host --name portsentry portsentry/portsentry:latest
```

_More docker configuration options available in the [HOWTO-Docker.md](docs/HOWTO-Docker.md) documentation_

### Debian 13 (trixie)

```sh
sudo apt install curl gpg
echo 'deb https://download.opensuse.org/repositories/home:/portsentry/Debian_13/ /' | sudo tee /etc/apt/sources.list.d/portsentry.list
curl -fsSL https://download.opensuse.org/repositories/home:/portsentry/Debian_13//Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/portsentry.gpg > /dev/null
sudo apt update
sudo apt install portsentry
```

### Debian 14 and later

```sh
sudo apt install portsentry
```

### Ubuntu 24.04, 25.04, 25.10

```sh
sudo apt install curl gpg
echo 'deb https://download.opensuse.org/repositories/home:/portsentry/xUbuntu_24.04/ /' | sudo tee /etc/apt/sources.list.d/portsentry.list
curl -fsSL https://download.opensuse.org/repositories/home:/portsentry/xUbuntu_24.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/portsentry.gpg > /dev/null
sudo apt update
sudo apt install portsentry
```

### Ubuntu 26.04 and later

```sh
sudo apt install portsentry
```

### Fedora 42

```sh
dnf config-manager addrepo --from-repofile=https://download.opensuse.org/repositories/home:/portsentry/Fedora_42/home:portsentry.repo
dnf install portsentry
sudo systemctl enable portsentry
sudo systemctl start portsentry
```

### Fedora 43 and later

```sh
dnf install portsentry
sudo systemctl start portsentry
```

### Arch Linux

```sh
sudo pacman -Sy curl gnupg
curl -fsSL https://download.opensuse.org/repositories/home:/portsentry/Arch/x86_64/home_portsentry_Arch.key -o /tmp/portsentry.key
sudo pacman-key --add /tmp/portsentry.key
KEYID=$(gpg --show-keys /tmp/portsentry.key | grep -A1 "^pub" | tail -n 1 | sed 's/\s*//')
sudo pacman-key --lsign-key "$KEYID"
sudo cat <<EOF >>/etc/pacman.conf
[home_portsentry_Arch]
SigLevel = Required
Server = https://download.opensuse.org/repositories/home:/portsentry/Arch/\$arch/
EOF
sudo pacman -Sy portsentry
sudo systemctl enable portsentry
sudo systemctl start portsentry
```

### openSUSE 16

```sh
sudo zypper addrepo https://download.opensuse.org/repositories/home:/portsentry/16.0/home:portsentry.repo
sudo zypper refresh
sudo zypper install portsentry
sudo systemctl enable portsentry
sudo systemctl start portsentry
```

### openSUSE Tumbleweed

```sh
sudo zypper addrepo https://download.opensuse.org/repositories/home:/portsentry/openSUSE_Tumbleweed/home:portsentry.repo
sudo zypper refresh
sudo zypper install portsentry
sudo systemctl enable portsentry
sudo systemctl start portsentry
```

### openSUSE Slowroll

```sh
sudo zypper addrepo https://download.opensuse.org/repositories/home:/portsentry/openSUSE_Slowroll/home:portsentry.repo
sudo zypper refresh
sudo zypper install portsentry
sudo systemctl enable portsentry
sudo systemctl start portsentry
```

### Other Linux distributions

Download the portsentry tar archive from the [Releases page](https://github.com/portsentry/portsentry/releases) and extract the tarball in the root directory:

```sh
sudo tar --strip-components=1 -C / -xvf portsentry-*.tar.xz
```

### *BSD

OpenBSD, NetBSD and FreeBSD are supported but must currently be compiled manually, see below

### Compiling the Source Code

_Detailed compilation instructions can be found on the [HOWTO-Compile](docs/HOWTO-Compile.md) page._

## Configuration and setup

_The [HOWTO-Use-Cases](docs/HOWTO-Use-Cases.md) documentation provides an overview of how portsentry can be used_

_The [HOWTO-Use](docs/HOWTO-Use.md) documentation provides detailed installation and usage instructions_

_The [Manual](docs/Manual.md) provides details around how Portsentry works and can be configured on the command line_

_The [Portsentry Configuration](docs/portsentry.conf.md) reference provides details on how to configure Portsentry_

_The [Logfile](docs/HOWTO-Logfile.md) reference explains how log entries from Portsentry should be interpreted._

## Documentation

All documentation for portsentry is indexed in the [docs/README.md](docs/README.md).

## Support

Please use the [Discussions Forums](https://github.com/portsentry/portsentry/discussions) for any support questions or feedback

## Links

Website: https://portsentry.xyz

Github: https://github.com/portsentry/portsentry

Docker Hub: https://hub.docker.com/r/portsentry/portsentry
