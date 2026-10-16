# PortSentry on NixOS

This directory contains the Nix packaging for PortSentry:

- `package.nix` — the `portsentry` derivation (CMake build, links libpcap).
- `module.nix` — the `services.portsentry` NixOS module.

They are exposed from the repo's top-level `flake.nix` as:

| Flake output | What it is |
| --- | --- |
| `packages.<system>.portsentry` | the built daemon |
| `overlays.default` | adds `pkgs.portsentry` |
| `nixosModules.portsentry` | the `services.portsentry` module |
| `checks.x86_64-linux.vmTest` | end-to-end VM test (scan detection) |

## Using it in a flake-based NixOS configuration

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # Pin to the upstream project (or your fork/branch while iterating):
    portsentry.url = "github:portsentry/portsentry";
    portsentry.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { nixpkgs, portsentry, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        portsentry.nixosModules.portsentry
        {
          nixpkgs.overlays = [ portsentry.overlays.default ];
          services.portsentry.enable = true;
        }
      ];
    };
  };
}
```

The module's `package` option defaults to `pkgs.portsentry`, which is why
`overlays.default` must be applied. Alternatively, set
`services.portsentry.package` explicitly and skip the overlay.

## Common configurations

Log-only (recommended — hand blocking off to e.g. fail2ban):

```nix
services.portsentry = {
  enable = true;
  blockTcp = 0;              # default
  ignoreHosts = [ "127.0.0.1/32" "192.168.0.0/16" ];
};
```

Active blocking via nftables/iptables:

```nix
services.portsentry = {
  enable = true;
  blockTcp = 1;
  killRoute = "${pkgs.iptables}/bin/iptables -I INPUT -s $TARGET$ -j DROP";
};
```

Full escape hatch — supply your own `portsentry.conf`:

```nix
services.portsentry = {
  enable = true;
  configFile = ./portsentry.conf;
};
```

See `nix/module.nix` for every option, or `man portsentry.conf` from the
package.

## Notes

- PortSentry requires root (it refuses to start otherwise), so the unit runs as
  root but is confined to `CAP_NET_RAW` (plus `CAP_NET_ADMIN` when active
  blocking is enabled) with extensive systemd sandboxing. Aggressive
  active-response setups (external firewall commands, custom file paths) may
  need `ProtectSystem`/`ReadWritePaths` relaxed via a `systemd.services.portsentry`
  override.
- The history and blocked-host files default to the systemd-managed
  `/var/log/portsentry` and `/run/portsentry` directories respectively.

## Testing

```sh
nix build .#portsentry                       # build the daemon
nix build .#checks.x86_64-linux.vmTest -L    # run the scan-detection VM test
```
