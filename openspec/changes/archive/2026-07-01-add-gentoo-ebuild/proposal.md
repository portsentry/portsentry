## Why

Portsentry is currently packaged for Debian-based distributions (via CPack/`.deb`) but Gentoo has no package for the modern portsentry. Gentoo's `::gentoo` repo *does* ship `net-analyzer/portsentry-1.2-r1`, but that packages the **old Sentry Tools** upstream (SourceForge, GPL-2, Makefile build) maintained by the Gentoo netmon project — not this project's rewrite. We should build **upon** that existing package rather than starting from scratch: bump it to the modern portsentry (v2.0.7, CMake, BSD-2), reusing its category, name, metadata, and OpenRC init/confd structure where they still apply. This gives Gentoo users a current, supported portsentry via Portage.

## What Changes

- Bump the existing `net-analyzer/portsentry` package to a new `portsentry-2.0.7.ebuild` that builds this project's source with the existing CMake build system (replacing the old Makefile `emake <target>` flow).
- Reuse the existing package's structure: keep the `net-analyzer/portsentry` category/name, adapt `metadata.xml` (keep the netmon maintainer, update the upstream `remote-id` and add USE-flag descriptions), and adapt the existing OpenRC `portsentry.rc6`/`portsentry.confd` for the v2 config-driven daemon.
- Correct package facts that changed between 1.2 and 2.x: `LICENSE` `GPL-2` → `BSD-2`, `HOMEPAGE`/`SRC_URI` to portsentry.xyz/GitHub, binary path `/usr/bin` → `/usr/sbin`, and drop the obsolete `portsentry-1.2-*.patch` files.
- Expose the project's build options as Portage USE flags: `pcap` (libpcap support, maps to `USE_PCAP`), `systemd` (install the systemd unit, maps to `USE_SYSTEMD`).
- Declare correct dependencies: `net-libs/libpcap` (under `pcap` USE flag), and toolchain/build deps (`dev-build/cmake`, systemd when the `systemd` USE flag is set).
- Install the daemon, config/ignore files, logrotate snippet, man pages, and docs to Gentoo-appropriate locations via the CMake install, plus a rewritten OpenRC init script + confd so the daemon is manageable on non-systemd (default) Gentoo installs.
- **Rewrite the OpenRC init script and confd** — this is the highest-risk part. The 1.2 init launched one process per mode from a `PORTSENTRY_MODES` list and stopped with `killall`; portsentry 2.x is a single config-driven daemon with an entirely different, mutually-exclusive command-line interface (`--stealth`/`--connect`, `-i/-l/-c/-m/-d/-v/-D`). The old init/confd must not be carried over verbatim.
- Provide an updated `metadata.xml` (netmon maintainer retained, USE flag descriptions, corrected upstream/remote-id) and packaging documentation describing how to build/test the ebuild in an incus Gentoo environment and how to submit the version bump upstream to Gentoo (netmon project) or ship it via an overlay.

## Capabilities

### New Capabilities
- `gentoo-packaging`: Defines the requirements for distributing portsentry as a Gentoo/Portage package — the ebuild, its USE flags, dependencies, install layout, service integration (OpenRC + systemd), and metadata.

### Modified Capabilities
<!-- No existing spec requirements change. The CMake build already supports the needed install-location and unit-dir overrides. -->

## Impact

- **Basis**: Builds upon the existing `net-analyzer/portsentry` package in `::gentoo` (currently `1.2-r1`) — this is a version bump + upstream/build migration, not a brand-new package. Category and package name are preserved.
- **New files**: Gentoo packaging artifacts under a `packaging/gentoo/net-analyzer/portsentry/` directory (the `2.0.7` ebuild, updated `metadata.xml`, rewritten `files/portsentry.initd` + `files/portsentry.confd`, and a README describing overlay/repository/upstream-submission usage). No changes to the C sources.
- **Behavioral migration risk**: The old init/confd assume the 1.2 CLI (per-mode processes, `killall`). The v2 daemon's CLI and runtime behavior differ substantially, so the service integration is rewritten from scratch and validated by actually starting the daemon.
- **Build system**: Relies on existing CMake options (`USE_PCAP`, `USE_SYSTEMD`, `INSTALL_LICENSE`, `SYSTEMD_SYSTEM_UNIT_DIR`, `CMAKE_INSTALL_*`, `DESTDIR`) — no CMake changes are expected. If a gap is found (e.g. an install path that cannot be overridden), a minimal CMake adjustment may be required.
- **Dependencies**: Introduces a runtime/build dependency mapping onto Gentoo packages (`net-libs/libpcap`, `dev-build/cmake`, `sys-apps/systemd`).
- **Package facts corrected vs. 1.2**: `LICENSE` `GPL-2` → `BSD-2`; `HOMEPAGE`/`SRC_URI` moved to portsentry.xyz/GitHub; binary path `/usr/bin` → `/usr/sbin`; obsolete `portsentry-1.2-*.patch` files dropped.
- **Users**: Gentoo users gain an `emerge`-based install of modern portsentry; both the rewritten OpenRC service and the upstream systemd unit become usable.
- **Docs**: Adds Gentoo install instructions; no change to existing runtime behavior or configuration format of portsentry itself.
