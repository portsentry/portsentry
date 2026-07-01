## 1. Baseline the existing Gentoo package

- [x] 1.1 Pull the current `net-analyzer/portsentry` package files from `::gentoo` (ebuild, `metadata.xml`, `files/portsentry.rc6`, `files/portsentry.confd`) into the scratchpad for reference
- [x] 1.2 Diff old-vs-new package facts and record what must change: build (Makefile→CMake), `LICENSE` GPL-2→BSD-2, HOMEPAGE/SRC_URI, `/usr/bin`→`/usr/sbin`, drop `portsentry-1.2-*.patch`, rewrite init/confd

## 2. Overlay scaffolding (mirrors the ::gentoo path)

- [x] 2.1 Create `packaging/gentoo/` laid out as an ebuild repo: `metadata/layout.conf`, `profiles/repo_name`
- [x] 2.2 Create `packaging/gentoo/net-analyzer/portsentry/` to mirror the upstream package path
- [x] 2.3 Add the new ebuild `portsentry-2.0.7.ebuild` and `files/` directory

## 3. Ebuild body (CMake-based bump)

- [x] 3.1 Header vars: `EAPI=8`, `inherit cmake systemd`, `DESCRIPTION`, `HOMEPAGE="https://portsentry.xyz"`, `SRC_URI` (GitHub/portsentry.xyz release), `LICENSE="BSD-2"`, `SLOT="0"`, `KEYWORDS="~amd64"`
- [x] 3.2 `IUSE="+pcap systemd"`
- [x] 3.3 Dependencies: `BDEPEND` cmake, `DEPEND`/`RDEPEND` with `pcap? ( net-libs/libpcap )` and `systemd? ( sys-apps/systemd )`; drop the old `kernel_Darwin? ( app-shells/tcsh )` and 1.2 `PATCHES`
- [x] 3.4 `src_configure`: `mycmakeargs=( -DUSE_PCAP=$(usex pcap) -DUSE_SYSTEMD=$(usex systemd) -DINSTALL_LICENSE=OFF )`, adding `-DSYSTEMD_SYSTEM_UNIT_DIR="$(systemd_get_systemunitdir)"` only when `use systemd`
- [x] 3.5 `src_install`: `cmake_src_install`, then `newinitd`/`newconfd` the rewritten OpenRC files; confirm config/ignore/logrotate/man/docs land via the CMake install and are not double-installed
- [x] 3.6 Confirm `/etc/portsentry/*` is covered by default `CONFIG_PROTECT`

## 4. Rewrite service integration for v2 (highest risk)

- [x] 4.1 Rewrite `files/portsentry.confd`: remove `PORTSENTRY_MODES`; expose v2 options (mode `--stealth`/`--connect`, interface `-i`, logoutput `-l`, method `-m`) with comments pointing at `portsentry(8)`
- [x] 4.2 Rewrite `files/portsentry.initd`: single `supervise-daemon` managing `/usr/sbin/portsentry` (foreground; no per-mode loop, no `killall`), args sourced from confd, `depend() { need net }`
- [x] 4.3 Update `metadata.xml`: keep netmon maintainer, replace sourceforge `remote-id` with GitHub `portsentry/portsentry`, add `<use>` descriptions for `pcap` and `systemd`

## 5. Local validation on host

- [x] 5.1 Syntax-check init/confd/ebuild (`bash -n`), and `xmllint` `metadata.xml` against the Gentoo metadata DTD if available
- [x] 5.2 Confirm CMake overrides behave outside Gentoo: `-DUSE_SYSTEMD=OFF -DUSE_PCAP=OFF` and a `DESTDIR` staging install produce a sandbox-clean layout (catch build gaps early)

## 6. Incus validation — OpenRC (default profile)

- [x] 6.1 Launch a `gentoo/openrc` incus container with a usable Portage tree
- [x] 6.2 Register `packaging/gentoo/` as a local repo via `/etc/portage/repos.conf`; generate manifest and stage source so fetch succeeds
- [x] 6.3 `emerge net-analyzer/portsentry`; verify the binary runs (`/usr/sbin/portsentry --help`, `--version`)
- [x] 6.4 **Verify the rewritten service**: `rc-service portsentry start` launches exactly one v2 daemon, `rc-update add` works, and `rc-service portsentry stop` cleanly stops it
- [x] 6.5 Rebuild with `USE="-pcap"`; confirm no libpcap dependency and a clean build

## 7. Incus validation — systemd

- [x] 7.1 Launch a `gentoo/systemd` incus instance and register the local repo
- [x] 7.2 `emerge net-analyzer/portsentry` with `USE="systemd"`; confirm `portsentry.service` installs in the systemd unit dir
- [x] 7.3 Verify `systemctl start portsentry` starts the daemon

## 8. QA and documentation

- [x] 8.1 Run `pkgcheck scan` (and/or `repoman full`) in incus; resolve all errors/warnings (metadata DTD, USE descriptions, keywords)
- [x] 8.2 Write `packaging/gentoo/README.md`: local-overlay usage, incus test steps, and the upstream-submission path (bug/PR to the netmon project as a version bump of the existing package)
- [x] 8.3 Add a Gentoo install section to the project docs/README pointing at the overlay
- [x] 8.4 Clean up incus instances (or document how to recreate them) and confirm the change is ready for `/opsx:apply`
