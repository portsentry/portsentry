{
  description = "PortSentry — port scan detection and active defense daemon";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      # Systems we build the package for. The NixOS module is Linux-only.
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f:
        nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      # The portsentry package, per system.
      packages = forAllSystems (pkgs: rec {
        portsentry = pkgs.callPackage ./nix/package.nix { };
        default = portsentry;
      });

      # Overlay so downstream users can get `pkgs.portsentry`.
      overlays.default = final: _prev: {
        portsentry = final.callPackage ./nix/package.nix { };
      };

      # The NixOS module providing `services.portsentry`. It is self-contained;
      # its `package` option defaults to `pkgs.portsentry`, so pair it with
      # `overlays.default` (see the usage example in README/NOTES).
      nixosModules.portsentry = ./nix/module.nix;
      nixosModules.default = self.nixosModules.portsentry;

      # `nix fmt`
      formatter = forAllSystems (pkgs: pkgs.nixpkgs-fmt);

      # Automated VM test: a scanner node runs an nmap SYN scan against a target
      # node running portsentry, and we assert portsentry detected it.
      checks.x86_64-linux = {
        vmTest = nixpkgs.legacyPackages.x86_64-linux.testers.runNixOSTest {
          name = "portsentry";

          nodes = {
            target = { ... }: {
              imports = [ self.nixosModules.portsentry ];
              services.portsentry = {
                enable = true;
                # runNixOSTest pins nixpkgs read-only, so set the package directly
                # rather than via overlays.default (which real configs would use).
                package = self.packages.x86_64-linux.portsentry;
                # Watch every non-loopback interface so the test network is covered.
                interface = "ALL_NLO";
                tcpPorts = [ "79" "111" "119" "1" ];
              };
            };

            scanner = { pkgs, ... }: {
              environment.systemPackages = [ pkgs.nmap ];
            };
          };

          testScript = ''
            start_all()

            # portsentry comes up and starts sniffing.
            target.wait_for_unit("portsentry.service")
            target.wait_until_succeeds(
                "journalctl -u portsentry.service | grep -q 'now active and listening'"
            )

            scanner.wait_for_unit("multi-user.target")
            scanner.succeed("ping -c1 target")

            # SYN-scan the monitored (closed) ports on the target.
            scanner.succeed("nmap -sS -p 1,79,111,119 target")

            # portsentry must have detected and logged the scan.
            target.wait_until_succeeds(
                "journalctl -u portsentry.service | grep -q 'Scan from'"
            )
          '';
        };

        package = self.packages.x86_64-linux.portsentry;
      };
    };
}
