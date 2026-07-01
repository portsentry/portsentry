## Context

Portsentry (v2.0.7) is a C daemon built with CMake. The build already supports the knobs a distro package needs:

- Options: `USE_PCAP` (default ON), `USE_SYSTEMD` (default ON), `INSTALL_LICENSE` (default ON), `BUILD_TESTS`/`BUILD_FUZZER` (OFF).
- Install layout uses `GNUInstallDirs` (`CMAKE_INSTALL_SBINDIR`, `SYSCONFDIR`, `MANDIR`, `DOCDIR`), so `DESTDIR` and prefix overrides work out of the box.
- The systemd unit is generated from `init/portsentry.service.in` and installed to `SYSTEMD_SYSTEM_UNIT_DIR`, which can be passed in externally — exactly what a distro package needs. If `USE_SYSTEMD=ON` and that dir is not provided, CMake `FATAL_ERROR`s.
- CPack currently emits a Debian `.deb`; there is no Gentoo support.

Gentoo installs from source by nature, so an ebuild is a natural fit. Gentoo's default init system is OpenRC (though systemd profiles exist), and upstream ships only a systemd unit — so the package must supply an OpenRC init script itself.

**Existing package.** `::gentoo` already contains `net-analyzer/portsentry-1.2-r1` (EAPI 7, maintained by the netmon project, `netmon@gentoo.org`), but it packages the *old* Sentry Tools upstream: SourceForge `SRC_URI`, `LICENSE=GPL-2`, a Makefile build (`emake CC=... <target>`), several `portsentry-1.2-*.patch` files, and — critically — an OpenRC init (`files/portsentry.rc6`) + confd (`files/portsentry.confd`) built around **1.2 semantics**: it loops over `PORTSENTRY_MODES` launching `/usr/bin/portsentry -<mode>` (one process per `tcp`/`udp`/`stcp`/`sudp`/`atcp`/`audp`) and stops via `killall`.

This project is the modern rewrite (v2.0.7): `LICENSE=BSD-2` (2-clause BSD), CMake build, homepage portsentry.xyz, binary at `/usr/sbin/portsentry`, and a **completely different CLI** — a single config-driven daemon with one mutually-exclusive mode (`--stealth` default / `--connect`), plus `-i/-l/-c/-m/-d/-v/-D`. So the work is a *version bump built on the existing package*: reuse its category/name/metadata skeleton and init/confd as a starting point, but rewrite the build, fix package facts, and — most importantly — rewrite the service integration, which is otherwise silently broken against v2.

Testing happens against `gentoo/openrc` and `gentoo/systemd` incus images already available on this machine.

## Goals / Non-Goals

**Goals:**
- A working, QA-clean ebuild (`portsentry-2.0.7.ebuild`) that builds via the `cmake` eclass and maps `pcap`/`systemd` USE flags to the CMake options.
- Correct dependency declarations resolving to real Gentoo packages.
- Sandbox-clean install with config protection for `/etc/portsentry/*`.
- Service integration for both OpenRC (init script we ship) and systemd (upstream unit).
- `metadata.xml` with maintainer, USE flag docs, and upstream remote-id.
- A local overlay layout plus documentation, validated end-to-end in incus.

**Non-Goals:**
- Submitting/merging into the official `::gentoo` repository (we prepare artifacts and document the path; actual submission is out of scope here).
- Changing portsentry's C code or runtime behavior.
- Restructuring the CMake build beyond, at most, a trivial override gap if one is discovered.
- A live ebuild (`-9999`/git) — we target the tagged release; a live ebuild can be a follow-up.

## Decisions

### Use the `cmake` eclass rather than hand-rolling build phases
Gentoo's `cmake` eclass provides `src_configure`/`src_compile`/`src_install` wired to `econf`-style defaults, `DESTDIR` handling, and out-of-source builds. We set `-DUSE_PCAP`/`-DUSE_SYSTEMD` via `mycmakeargs`. This is idiomatic and minimizes QA issues. Alternative — raw `cmake` calls in custom phases — was rejected as reinventing the eclass and more error-prone under sandbox.

### Map features to USE flags `pcap` and `systemd`
`pcap` and `systemd` are standard Gentoo global USE flags, so users already understand them and `metadata.xml` only needs local descriptions where semantics differ. `USE_SYSTEMD` in CMake requires `SYSTEMD_SYSTEM_UNIT_DIR`; under `USE=systemd` we pass `-DSYSTEMD_SYSTEM_UNIT_DIR="$(systemd_get_systemunitdir)"` via the `systemd` eclass. Under `USE=-systemd` we pass `-DUSE_SYSTEMD=OFF` to avoid the FATAL_ERROR. `INSTALL_LICENSE` is set OFF because Portage installs the license via the `LICENSE` variable / its own mechanisms; shipping it twice is redundant (decision revisitable — keeping it ON is harmless but non-idiomatic).

### Rewrite the OpenRC init script and confd for v2 (do not reuse 1.2's)
This is the riskiest part of the change. The existing `files/portsentry.rc6`/`portsentry.confd` encode 1.2 behavior — a `PORTSENTRY_MODES` loop spawning `/usr/bin/portsentry -<mode>` per mode and `killall` to stop — which is invalid for v2 (single daemon, mutually-exclusive `--stealth`/`--connect`, options `-i/-l/-c/-m/-d/-v/-D`, binary at `/usr/sbin`). Carrying them over would install a service that fails or misbehaves silently. We therefore rewrite:

- **`files/portsentry.initd`**: an `openrc-run` script using `supervise-daemon` to manage a single foreground `/usr/sbin/portsentry` process (portsentry runs in the foreground by default; supervise-daemon handles backgrounding/restart, so we do not pass `-D`). Command args come from confd. `depend()` keeps `need net`.
- **`files/portsentry.confd`**: drop `PORTSENTRY_MODES`; expose v2-appropriate knobs (e.g. `PORTSENTRY_OPTS` defaulting to sane values, or discrete mode/interface/logoutput variables) with comments pointing at `portsentry(8)`.

We keep the existing filenames/`newinitd`/`newconfd` install pattern from the 1.2 ebuild for continuity. Alternative — reuse 1.2 files or ship systemd-only — was rejected: the former is broken against v2, the latter excludes the default OpenRC profile. We verify by actually starting the daemon in incus, not just by installing the file.

### Dependencies
- `BDEPEND="dev-build/cmake"` (provided by eclass, but declared explicitly per policy where needed).
- `pcap? ( net-libs/libpcap )` in both `DEPEND` and `RDEPEND`.
- `systemd? ( sys-apps/systemd )` for the unit dir helper / runtime.
- Standard `virtual/libc` is implicit. No other libs are linked by the core sources.

### Config protection
Files under `/etc/portsentry` are installed as examples upstream but are the real runtime config location. We rely on Gentoo's default `CONFIG_PROTECT` covering `/etc`, so edited configs are preserved and `.cfg` update prompts appear on upgrade. No custom `CONFIG_PROTECT` entry is needed.

### Metadata reuses the existing package's maintainer
`metadata.xml` keeps the existing netmon project maintainer (`netmon@gentoo.org`) since that team owns `net-analyzer/portsentry` in `::gentoo` and would review the bump. We update `<upstream>`: the old `remote-id type="sourceforge">sentrytools` is replaced/augmented with this project's `remote-id` (GitHub `portsentry/portsentry`) and homepage, and we add `<use>` descriptions for the new `pcap`/`systemd` flags.

### Overlay layout mirrors the existing package path
Create `packaging/gentoo/` in the repo, laid out as an ebuild repository that mirrors the upstream Gentoo path: `net-analyzer/portsentry/{portsentry-2.0.7.ebuild,metadata.xml,files/{portsentry.initd,portsentry.confd}}` plus `metadata/layout.conf` and `profiles/repo_name`. This keeps the tree diff-able against `::gentoo`'s `net-analyzer/portsentry/` and drop-in for testing: registered via `/etc/portage/repos.conf` inside the incus instance. Category `net-analyzer` is unchanged from the existing package.

### Testing via incus
Spin up `gentoo/openrc` (container) as the primary target: sync/prime the Portage tree (or use the image's snapshot), drop in the local overlay, `emerge` with default USE and with `-pcap`, verify binary runs and `rc-service portsentry start`. Repeat the systemd path on a `gentoo/systemd` instance with `USE=systemd`. Containers are preferred over VMs for speed; a VM is the fallback if kernel-facing behavior (raw sockets/stealth mode) needs it. `SRC_URI` fetching is avoided during iteration by pointing the ebuild at the release tarball, and for local dev the working tree can be staged so builds don't depend on a published release.

## Risks / Trade-offs

- **[No published release tarball at the expected `SRC_URI`]** → For local/incus testing, stage the source manually (or use a `DISTDIR` drop / `EGIT`-style live ebuild) so validation doesn't block on a GitHub release artifact; the committed ebuild targets the real release URL.
- **[`SYSTEMD_SYSTEM_UNIT_DIR` FATAL_ERROR when systemd off]** → Explicitly pass `-DUSE_SYSTEMD=OFF` under `USE=-systemd`; covered by a test scenario.
- **[Container can't exercise raw-socket/stealth or firewall-blocking behavior]** → Package validation only asserts build/install/service-start and `--help`; full runtime detection behavior is already covered by upstream's own tests and is out of scope for packaging. Use a VM if deeper runtime checks are wanted.
- **[QA/pkgcheck nitpicks (metadata DTD, keywords, missing USE descriptions)]** → Run `pkgcheck scan` in the incus instance and fix before considering the artifact done.
- **[USE=pcap default divergence]** → CMake defaults `USE_PCAP=ON`; we set the ebuild `IUSE="+pcap"` to match upstream's recommended configuration, documented in `metadata.xml`.
- **[KEYWORDS/arch]** → Initial ebuild keywords `~amd64` (and `~arm64` if easily verified) as untested/testing, which is correct for a new package pending broader arch testing.

## Migration Plan

1. Add `packaging/gentoo/` artifacts to the repo (no impact on existing builds/CI).
2. Validate in incus (OpenRC + systemd) and run `pkgcheck` — with explicit emphasis on actually starting the daemon via the rewritten init script.
3. Document overlay usage in `packaging/gentoo/README.md` so users can consume it via a local overlay immediately.
4. (Follow-up, out of scope) Submit the version bump upstream to Gentoo — a bug/PR to the netmon project for `net-analyzer/portsentry`, since they maintain the existing package — or ship via GURU/a portsentry-owned overlay.

Rollback is trivial: the packaging files are additive and isolated under `packaging/gentoo/`; deleting the directory removes the feature with zero effect on the C build or existing Debian packaging.

## Open Questions

- Should the ebuild also provide a live (`-9999`) variant now, or defer? (Deferred by default.)
- Preferred distribution channel for users: GURU overlay vs. a portsentry-owned overlay repo? (Documentation will cover the local-overlay path; channel choice can be finalized later.)
- Exact `SRC_URI` — GitHub release tarball vs. a `portsentry.xyz`-hosted archive — to confirm with the maintainer.
