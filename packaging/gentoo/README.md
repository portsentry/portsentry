# Gentoo packaging for portsentry

This directory is a self-contained [ebuild repository](https://wiki.gentoo.org/wiki/Ebuild_repository)
(overlay) that packages the modern portsentry (2.x) for Gentoo.

It is a **version bump built on top of the existing** `net-analyzer/portsentry`
package in the `::gentoo` tree (which still ships the old 1.2 Sentry Tools
release). It keeps the same category and package name, reuses the
`net-analyzer/portsentry` layout, and updates it for portsentry 2.x:

- Build system: Makefile → **CMake** (via the `cmake` eclass)
- `LICENSE`: `GPL-2` → **`BSD-2`**
- `HOMEPAGE`/`SRC_URI`: SourceForge → **portsentry.xyz / GitHub**
- Binary: `/usr/bin/portsentry` → **`/usr/sbin/portsentry`**
- USE flags: **`pcap`** (`net-libs/libpcap`) and **`systemd`** (install the unit)
- The OpenRC init script and confd are **rewritten** for the 2.x daemon
  (see "Service integration" below)

## Layout

```
packaging/gentoo/
├── metadata/layout.conf          # overlay metadata (masters = gentoo)
├── profiles/repo_name            # repository name: "portsentry"
└── net-analyzer/portsentry/
    ├── portsentry-2.0.7.ebuild
    ├── metadata.xml
    └── files/
        ├── portsentry.initd      # OpenRC service (supervise-daemon)
        └── portsentry.confd      # /etc/conf.d/portsentry
```

## Using the overlay

On a Gentoo system, register this directory as a local repository:

```sh
sudo mkdir -p /etc/portage/repos.conf
sudo tee /etc/portage/repos.conf/portsentry.conf >/dev/null <<'EOF'
[portsentry]
location = /var/db/repos/portsentry
auto-sync = no
EOF

# Copy this overlay into place (the directory that contains metadata/ and profiles/)
sudo cp -a packaging/gentoo /var/db/repos/portsentry

# 2.x is keyworded ~amd64 (testing)
echo "=net-analyzer/portsentry-2.0.7 ~amd64" | sudo tee /etc/portage/package.accept_keywords/portsentry

# Generate the Manifest (fetches the source tarball)
sudo ebuild /var/db/repos/portsentry/net-analyzer/portsentry/portsentry-2.0.7.ebuild manifest

sudo emerge net-analyzer/portsentry
```

USE flags:

```sh
# Disable libpcap (use Linux raw sockets for stealth mode)
USE="-pcap" emerge net-analyzer/portsentry

# Install the systemd unit
USE="systemd" emerge net-analyzer/portsentry
```

## Service integration

portsentry 2.x is **not** invoked the way 1.2 was. The old package looped over
`PORTSENTRY_MODES` and launched one `/usr/bin/portsentry -<mode>` process per
protocol. Version 2.x is a single, config-driven daemon with a completely
different, mutually-exclusive CLI, so the init script and confd were rewritten.

### OpenRC

- `/etc/init.d/portsentry` uses `supervise-daemon` to manage a single
  `/usr/sbin/portsentry` process.
- portsentry runs in the **foreground** by default, which is exactly what
  `supervise-daemon` needs — **do not** add `-D`/`--daemon`; that would fork the
  process and break supervision.
- Command-line switches live in `/etc/conf.d/portsentry` via `PORTSENTRY_OPTS`.

```sh
rc-service portsentry start
rc-update add portsentry default
```

### systemd (USE=systemd)

The upstream unit is installed to the systemd system unit directory:

```sh
systemctl enable --now portsentry
```

## Configuration

Runtime behaviour is configured in `/etc/portsentry/portsentry.conf` (and
`/etc/portsentry/portsentry.ignore`). These live under `/etc`, so they are
covered by Gentoo's default `CONFIG_PROTECT` and preserved across upgrades.

> Note: `--connect` mode is a **legacy** option and its use is discouraged — it
> only registers completed TCP handshakes (missing stealth scans) and has other
> caveats. Prefer the default `--stealth` mode. See `portsentry(8)`.

## Testing

The package was validated end-to-end using [incus](https://linuxcontainers.org/incus/):

- `images:gentoo/openrc` — build, install, and the rewritten OpenRC service
  (start/stop, restart-on-failure, `rc-update`), plus a `USE=-pcap` rebuild.
- `images:gentoo/systemd` — build with `USE=systemd`, unit installation, and
  `systemctl start`.
- `pkgcheck scan` reports no style/warning/error findings.

## Submitting to Gentoo

`net-analyzer/portsentry` is maintained by the Gentoo network monitoring and
analysis project (`netmon@gentoo.org`). The upstream-facing path is to file a
version-bump request / pull request against the `::gentoo` repository (or the
[GURU](https://wiki.gentoo.org/wiki/Project:GURU) user overlay), reusing the
files here. The `metadata.xml` keeps the netmon maintainer for that reason.
