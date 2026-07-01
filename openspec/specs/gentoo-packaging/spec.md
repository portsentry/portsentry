# gentoo-packaging

## Purpose

Distribute portsentry as a Gentoo/Portage package. This capability covers the
ebuild, its USE flags, dependencies, install layout, service integration
(OpenRC + systemd), and metadata — delivered as a version bump built upon the
existing `net-analyzer/portsentry` package in the `::gentoo` repository.

## Requirements

### Requirement: Package builds upon the existing Gentoo package

The packaging SHALL be based on the existing `net-analyzer/portsentry` package in the `::gentoo` repository (currently `portsentry-1.2-r1`) rather than introducing a new package. It SHALL preserve the `net-analyzer/portsentry` category and name and SHALL reuse the existing `metadata.xml` maintainer and the existing OpenRC init/confd layout as a starting point. Facts that changed between 1.2 and 2.x SHALL be corrected: `LICENSE` SHALL be `BSD-2` (not `GPL-2`), `HOMEPAGE` and `SRC_URI` SHALL point at this project's site/release, and the obsolete `portsentry-1.2-*.patch` files SHALL NOT be carried forward.

#### Scenario: Version bump of the existing package

- **WHEN** the packaging is assembled
- **THEN** it lives under `net-analyzer/portsentry` with a `portsentry-2.0.7.ebuild` alongside (conceptually replacing) the `1.2-r1` ebuild, and `metadata.xml` retains the Gentoo netmon project maintainer

#### Scenario: Corrected package metadata

- **WHEN** the new ebuild is inspected
- **THEN** `LICENSE="BSD-2"`, `HOMEPAGE` references portsentry.xyz, `SRC_URI` references this project's release, and no `portsentry-1.2-*.patch` files are referenced

### Requirement: Init script and confd rewritten for the v2 daemon

The OpenRC init script and confd SHALL be rewritten for portsentry 2.x rather than reused verbatim, because the command-line interface and runtime behavior changed significantly since 1.2. The 1.2 init launched one process per entry in `PORTSENTRY_MODES` (`-tcp`/`-udp`/`-stcp`/`-sudp`/`-atcp`/`-audp`) and stopped the daemon with `killall`; the v2 daemon is a single config-driven process with one mutually-exclusive mode (`--stealth` default or `--connect`) and the options `-i`, `-l`, `-c`, `-m`, `-d`, `-v`, `-D`, installed at `/usr/sbin/portsentry`. The rewritten init script SHALL manage a single supervised daemon process at `/usr/sbin/portsentry`, and the confd SHALL NOT reference `PORTSENTRY_MODES` or per-mode invocation.

#### Scenario: No 1.2-style per-mode invocation

- **WHEN** the rewritten init script and confd are inspected
- **THEN** they contain no `PORTSENTRY_MODES` loop, no `killall`, and no `/usr/bin/portsentry -tcp`-style per-mode calls

#### Scenario: Single supervised v2 daemon

- **WHEN** `rc-service portsentry start` is run on a v2 install
- **THEN** exactly one `/usr/sbin/portsentry` process is started using v2-valid options, and `rc-service portsentry stop` cleanly stops that supervised process (not via `killall`)

### Requirement: Ebuild builds portsentry from source via CMake

The package SHALL provide a Portage ebuild that builds portsentry from the released source using the project's existing CMake build system, following Gentoo's `cmake` eclass conventions. The ebuild version SHALL track the upstream project version (currently `2.0.7`), and the ebuild filename SHALL follow Gentoo's `<PN>-<PV>.ebuild` naming.

#### Scenario: Building the package from the ebuild

- **WHEN** a Gentoo user runs `emerge` (or `ebuild <file> compile`) against the portsentry ebuild
- **THEN** the source is fetched from the upstream release archive, configured with CMake, and compiled without manual intervention or build errors

#### Scenario: Release build type

- **WHEN** the ebuild configures the CMake build
- **THEN** it builds a Release-type binary (optimized, matching upstream defaults) rather than a Debug build

### Requirement: USE flags map to CMake options

The ebuild SHALL expose portsentry's optional build features as Portage USE flags. The `pcap` USE flag SHALL control the `USE_PCAP` CMake option (libpcap-based detection), and the `systemd` USE flag SHALL control the `USE_SYSTEMD` CMake option (installation of the systemd unit). Each USE flag SHALL be documented in `metadata.xml`.

#### Scenario: pcap USE flag enabled

- **WHEN** the package is built with `USE=pcap`
- **THEN** CMake is invoked with `USE_PCAP=ON` and the resulting binary links against `net-libs/libpcap`

#### Scenario: pcap USE flag disabled

- **WHEN** the package is built with `USE=-pcap`
- **THEN** CMake is invoked with `USE_PCAP=OFF` and libpcap is neither required nor linked

#### Scenario: systemd USE flag controls unit installation

- **WHEN** the package is built with `USE=systemd`
- **THEN** CMake is invoked with `USE_SYSTEMD=ON`, `SYSTEMD_SYSTEM_UNIT_DIR` is set to the location reported by `systemd_get_systemunitdir`, and the unit file is installed there
- **WHEN** the package is built with `USE=-systemd`
- **THEN** CMake is invoked with `USE_SYSTEMD=OFF` and no systemd unit is installed

### Requirement: Dependencies resolve to Gentoo packages

The ebuild SHALL declare dependencies that resolve correctly through Portage. It SHALL depend on `dev-build/cmake` at build time, on `net-libs/libpcap` (build and runtime) conditioned on the `pcap` USE flag, and on `sys-apps/systemd` conditioned on the `systemd` USE flag. Dependencies gated on a USE flag SHALL use Portage USE-conditional syntax.

#### Scenario: Dependency resolution with pcap

- **WHEN** Portage computes the dependency graph for the ebuild with `USE=pcap`
- **THEN** `net-libs/libpcap` is pulled in as a build and runtime dependency

#### Scenario: No stray dependencies without optional flags

- **WHEN** the package is built with `USE=-pcap -systemd`
- **THEN** neither `net-libs/libpcap` nor `sys-apps/systemd` is required

### Requirement: Files install to Gentoo-appropriate locations

The package SHALL install all artifacts under the image directory using `DESTDIR`/Gentoo path variables so that no files are written outside the sandbox. It SHALL install the daemon binary, the example configuration and ignore files under `/etc/portsentry`, the logrotate snippet under `/etc/logrotate.d`, the man pages under the standard man directory, and documentation under the Portage doc directory. Configuration files SHALL be treated as Gentoo config-protected files so user edits are preserved across upgrades.

#### Scenario: Sandbox-clean install

- **WHEN** the ebuild's install phase runs
- **THEN** every file is staged under `${D}` (image directory) and the Portage sandbox reports no violations

#### Scenario: Config files are protected

- **WHEN** the package is upgraded and the user has edited `/etc/portsentry/portsentry.conf`
- **THEN** Portage preserves the user's version and prompts via `CONFIG_PROTECT` rather than silently overwriting it

### Requirement: Service integration for OpenRC and systemd

The package SHALL provide service management for both Gentoo init systems. It SHALL install an OpenRC init script for portsentry so the daemon can be started, stopped, and added to the default runlevel with `rc-update`. When built with the `systemd` USE flag, it SHALL install the upstream systemd unit so the daemon is manageable with `systemctl`.

#### Scenario: OpenRC service management

- **WHEN** portsentry is installed on an OpenRC-based Gentoo system
- **THEN** an init script is present at `/etc/init.d/portsentry` and `rc-service portsentry start` launches the daemon

#### Scenario: systemd service management

- **WHEN** portsentry is installed with `USE=systemd` on a systemd-based Gentoo system
- **THEN** a `portsentry.service` unit is installed in the systemd system unit directory and `systemctl start portsentry` launches the daemon

### Requirement: Package metadata is present and valid

The package SHALL include a `metadata.xml` conforming to the Gentoo metadata DTD, declaring the maintainer, a longdescription, descriptions for every locally defined USE flag, and an upstream `remote-id`. The ebuild SHALL populate `DESCRIPTION`, `HOMEPAGE`, `LICENSE`, `SLOT`, and `KEYWORDS`, and the packaging artifacts SHALL pass Gentoo QA linting.

#### Scenario: Metadata and ebuild pass QA

- **WHEN** `pkgcheck scan` (or `repoman`) is run against the ebuild and `metadata.xml`
- **THEN** there are no errors, and all USE flags used by the ebuild have descriptions in `metadata.xml`

### Requirement: Installation is verifiable in a Gentoo environment

The packaging SHALL be validated in a real Gentoo environment. Using an incus-managed Gentoo instance, the ebuild SHALL be installable from a local overlay and the installed daemon SHALL run. Both the OpenRC image and the systemd image SHALL be exercised to cover both service-integration paths.

#### Scenario: End-to-end install in incus

- **WHEN** the ebuild is added to a local overlay inside a `gentoo/openrc` incus instance and `emerge portsentry` is run
- **THEN** the package builds, installs, `portsentry --help` (or equivalent) succeeds, and the OpenRC service can be started

#### Scenario: systemd path verified

- **WHEN** the ebuild is emerged with `USE=systemd` inside a `gentoo/systemd` incus instance
- **THEN** the package builds, the systemd unit is installed, and `systemctl start portsentry` starts the daemon
