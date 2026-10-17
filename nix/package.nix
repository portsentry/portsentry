{
  lib,
  stdenv,
  cmake,
  libpcap,
  nix-update-script,
}:

stdenv.mkDerivation (finalAttrs: {
  pname = "portsentry";
  # Keep in sync with the project(... VERSION) line in CMakeLists.txt.
  version = "2.0.7";

  # Use the whole repository as the source. When evaluated from the flake this
  # resolves to the (git-tracked) flake source in the Nix store.
  src = lib.cleanSource ../.;

  nativeBuildInputs = [ cmake ];
  buildInputs = [ libpcap ];

  cmakeFlags = [
    # The NixOS module ships its own systemd unit, so don't install the bundled
    # one into the store (it would also try to write to an absolute path).
    (lib.cmakeBool "USE_SYSTEMD" false)
    (lib.cmakeBool "BUILD_TESTS" false)
    (lib.cmakeBool "BUILD_FUZZER" false)
    (lib.cmakeBool "INSTALL_LICENSE" true)
  ];

  # The binary is installed into sbin.
  passthru.updateScript = nix-update-script { };

  meta = {
    description = "Port scan detection and active defense daemon";
    longDescription = ''
      PortSentry detects and optionally responds to port scans against a host in
      real time. It can simply log probes to syslog/journal (recommended, e.g.
      for use with fail2ban) or actively block scanning hosts via routes,
      TCP wrappers (hosts.deny) or an arbitrary external command.
    '';
    homepage = "https://portsentry.xyz";
    changelog = "https://github.com/portsentry/portsentry/blob/master/Changes.md";
    license = lib.licenses.bsd2;
    mainProgram = "portsentry";
    # Raw sockets / libpcap stealth scanning: Linux and the BSDs. The systemd
    # module below is Linux-only.
    platforms = lib.platforms.unix;
    maintainers = with lib.maintainers; [ ];
  };
})
