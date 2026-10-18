{ config, lib, pkgs, utils, ... }:

let
  cfg = config.services.portsentry;

  # Render a single `KEY="value"` config line. Booleans map to portsentry's
  # "1"/"0" convention, ints are stringified, strings are used verbatim.
  renderValue = v:
    if lib.isBool v then (if v then "1" else "0")
    else if lib.isInt v then toString v
    else toString v;

  mkLine = name: value: ''${name}="${renderValue value}"'';

  # The hosts that should never be blocked, written to a store file and wired up
  # through IGNORE_FILE.
  ignoreFile = pkgs.writeText "portsentry.ignore"
    (lib.concatStringsSep "\n" cfg.ignoreHosts + "\n");

  # Assemble the effective configuration. High-level options come first and can
  # be overridden/extended through `services.portsentry.settings`.
  baseSettings =
    {
      IGNORE_FILE = toString ignoreFile;
      BLOCK_TCP = cfg.blockTcp;
      BLOCK_UDP = cfg.blockUdp;
      RESOLVE_HOST = cfg.resolveHost;
      SCAN_TRIGGER = cfg.scanTrigger;
    }
    # An empty port list omits the directive entirely, disabling that protocol.
    // lib.optionalAttrs (cfg.tcpPorts != [ ]) { TCP_PORTS = lib.concatStringsSep "," cfg.tcpPorts; }
    // lib.optionalAttrs (cfg.udpPorts != [ ]) { UDP_PORTS = lib.concatStringsSep "," cfg.udpPorts; }
    // lib.optionalAttrs (cfg.historyFile != null) { HISTORY_FILE = cfg.historyFile; }
    // lib.optionalAttrs (cfg.blockedFile != null) { BLOCKED_FILE = cfg.blockedFile; }
    // lib.optionalAttrs (cfg.killRoute != null) { KILL_ROUTE = cfg.killRoute; }
    // lib.optionalAttrs (cfg.killHostsDeny != null) { KILL_HOSTS_DENY = cfg.killHostsDeny; }
    // lib.optionalAttrs (cfg.killRunCmd != null) {
      KILL_RUN_CMD = cfg.killRunCmd;
      KILL_RUN_CMD_FIRST = cfg.killRunCmdFirst;
    }
    // lib.optionalAttrs (cfg.portBanner != null) { PORT_BANNER = cfg.portBanner; };

  finalSettings = baseSettings // cfg.settings;

  generatedConfig = pkgs.writeText "portsentry.conf" (
    lib.concatStringsSep "\n" (lib.mapAttrsToList mkLine finalSettings)
    + lib.optionalString (cfg.extraConfig != "") ("\n" + cfg.extraConfig)
    + "\n"
  );

  configFile = if cfg.configFile != null then cfg.configFile else generatedConfig;

  # Active blocking (mode 1) or routing needs CAP_NET_ADMIN on top of the
  # CAP_NET_RAW required for sniffing.
  needsNetAdmin =
    cfg.blockTcp == 1 || cfg.blockUdp == 1
    || cfg.killRoute != null;

  capabilities =
    [
      "CAP_NET_RAW"
      # The "is a service already running?" check binds to each probed port; on
      # privileged ports (<1024, which dominate the default port lists) that
      # requires CAP_NET_BIND_SERVICE, otherwise the bind fails and portsentry
      # wrongly treats the port as in-use and ignores the scan.
      "CAP_NET_BIND_SERVICE"
    ]
    ++ lib.optional needsNetAdmin "CAP_NET_ADMIN";

  # Writable paths outside the systemd-managed state dirs (custom history/blocked
  # file locations, and /etc for the hosts.deny TCP-wrapper integration).
  extraReadWritePaths =
    lib.optional (cfg.historyFile != null) (builtins.dirOf cfg.historyFile)
    ++ lib.optional (cfg.blockedFile != null) (builtins.dirOf cfg.blockedFile)
    ++ lib.optional (cfg.killHostsDeny != null) "/etc";

  execArgs =
    [ "${cfg.package}/sbin/portsentry" "--${cfg.mode}" ]
    ++ lib.optionals (cfg.mode == "stealth") [ "-m" cfg.method ]
    ++ [ "-i" cfg.interface "-l" cfg.logTarget "-c" configFile ]
    ++ cfg.extraArgs;
in
{
  options.services.portsentry = {
    enable = lib.mkEnableOption "the PortSentry port scan detection daemon";

    package = lib.mkPackageOption pkgs "portsentry" { };

    mode = lib.mkOption {
      type = lib.types.enum [ "stealth" "connect" ];
      default = "stealth";
      description = ''
        Detection mode. `stealth` (the default) passively sniffs for packets to
        the monitored ports and detects stealth scans. `connect` binds the
        monitored ports and detects full TCP/UDP connections, optionally
        presenting {option}`portBanner`.
      '';
    };

    method = lib.mkOption {
      type = lib.types.enum [ "pcap" "raw" ];
      default = "pcap";
      description = ''
        Packet capture backend for `stealth` mode: libpcap or Linux raw sockets.
        Ignored in `connect` mode.
      '';
    };

    interface = lib.mkOption {
      type = lib.types.str;
      default = "ALL_NLO";
      example = "eth0";
      description = ''
        Interface to listen on. `ALL` listens on every interface, `ALL_NLO` on
        every interface except loopback, or name a specific device.
      '';
    };

    logTarget = lib.mkOption {
      type = lib.types.enum [ "syslog" "stdout" ];
      default = "syslog";
      description = ''
        Where portsentry writes its log output. Under systemd both end up in the
        journal; `syslog` is the conventional choice.
      '';
    };

    tcpPorts = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = lib.literalExpression ''config.services.portsentry.recommended.tcpPorts ++ [ "8080" ]'';
      description = ''
        TCP ports (and ranges, e.g. `"512-515"`) to monitor. Ports already in use
        by a running service are automatically excluded by portsentry. An empty
        list (the default) omits `TCP_PORTS` and disables TCP monitoring. At least
        one of this and {option}`udpPorts` must be non-empty. See
        {option}`recommended.tcpPorts` for a suggested starting point.
      '';
    };

    udpPorts = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = lib.literalExpression "config.services.portsentry.recommended.udpPorts";
      description = ''
        UDP ports (and ranges) to monitor. An empty list (the default) omits
        `UDP_PORTS` and disables UDP monitoring. See
        {option}`recommended.udpPorts` for a suggested starting point.
      '';
    };

    # Read-only port lists (mirroring examples/portsentry.conf) that users can
    # assign to, or extend into, tcpPorts/udpPorts.
    recommended.tcpPorts = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      readOnly = true;
      default = [
        "1" "7" "9" "11" "13" "15" "17" "19" "20" "21" "70" "79" "111" "113"
        "119" "389" "512-515" "540" "543-544" "873" "989" "990" "992" "1080"
      ];
      description = ''
        Recommended TCP ports to monitor. Read-only; use it as a value for
        {option}`tcpPorts`, e.g.
        `tcpPorts = config.services.portsentry.recommended.tcpPorts;`.
      '';
    };

    recommended.udpPorts = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      readOnly = true;
      default = [ "7" "9" "13" "19" "111" "389" "513" "517-518" ];
      description = ''
        Recommended UDP ports to monitor. Read-only; use it as a value for
        {option}`udpPorts`.
      '';
    };

    ignoreHosts = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "127.0.0.1/32" ];
      example = [ "127.0.0.1/32" "192.168.0.0/16" ];
      description = ''
        Hosts/networks (CIDR notation) that are never blocked or acted upon.
        Rendered to the IGNORE_FILE.
      '';
    };

    blockTcp = lib.mkOption {
      type = lib.types.enum [ 0 1 2 ];
      default = 0;
      description = ''
        Response to detected TCP scans:
        `0` = log only (recommended; pair with e.g. fail2ban),
        `1` = block via {option}`killRoute`/{option}`killHostsDeny`,
        `2` = run {option}`killRunCmd` only.
      '';
    };

    blockUdp = lib.mkOption {
      type = lib.types.enum [ 0 1 2 ];
      default = 0;
      description = "Response to detected UDP scans. See {option}`blockTcp`.";
    };

    killRoute = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "\${pkgs.iptables}/bin/iptables -I INPUT -s $TARGET$ -j DROP";
      description = ''
        Command run to block a scanning host when blocking is enabled. `$TARGET$`
        is replaced with the attacker's address. Requires blocking mode `1`.
      '';
    };

    killHostsDeny = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "ALL: $TARGET$ : DENY";
      description = ''
        Line appended to {file}`/etc/hosts.deny` (TCP wrappers) when blocking is
        enabled. Requires blocking mode `1`.
      '';
    };

    killRunCmd = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Arbitrary command executed on detection. `$TARGET$` and `$PORT$` are
        substituted. Required for blocking mode `2`.
      '';
    };

    killRunCmdFirst = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Run {option}`killRunCmd` before the blocking action rather than after.
      '';
    };

    resolveHost = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Perform reverse DNS lookups on scanning hosts (slower).";
    };

    scanTrigger = lib.mkOption {
      type = lib.types.int;
      default = 0;
      description = ''
        Number of probes tolerated before an alarm fires. `0` reacts immediately.
      '';
    };

    portBanner = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Banner presented to connecting hosts in `connect` mode before the
        connection is closed.
      '';
    };

    historyFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = "/var/log/portsentry.log";
      description = ''
        File recording hosts that triggered an alert. Set to `null` to disable
        (output still goes to the journal).
      '';
    };

    blockedFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = "/run/portsentry/blocked";
      description = ''
        Internal database of already-blocked hosts, used to avoid re-blocking.
        Defaults to the runtime directory so it is cleared on reboot (as
        recommended upstream). Set to `null` to always act on every detection.
      '';
    };

    settings = lib.mkOption {
      type = lib.types.attrsOf (lib.types.oneOf [ lib.types.str lib.types.int lib.types.bool ]);
      default = { };
      example = lib.literalExpression ''{ RESOLVE_HOST = true; }'';
      description = ''
        Extra `portsentry.conf` key/value pairs, merged over the settings derived
        from the high-level options above (and winning on conflict). Booleans are
        rendered as `1`/`0`.
      '';
    };

    extraConfig = lib.mkOption {
      type = lib.types.lines;
      default = "";
      description = "Raw text appended verbatim to the generated config file.";
    };

    configFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        Use this config file verbatim instead of the one generated from the
        options above. When set, all other configuration options are ignored.
      '';
    };

    extraArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Extra command-line arguments passed to the portsentry daemon.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.configFile == null -> (cfg.tcpPorts != [ ] || cfg.udpPorts != [ ]);
        message = "services.portsentry: set tcpPorts and/or udpPorts (there is no default port list).";
      }
      {
        assertion = cfg.blockTcp == 1 -> (cfg.killRoute != null || cfg.killHostsDeny != null);
        message = "services.portsentry: blockTcp = 1 requires killRoute and/or killHostsDeny to be set.";
      }
      {
        assertion = cfg.blockUdp == 1 -> (cfg.killRoute != null || cfg.killHostsDeny != null);
        message = "services.portsentry: blockUdp = 1 requires killRoute and/or killHostsDeny to be set.";
      }
      {
        assertion = (cfg.blockTcp == 2 || cfg.blockUdp == 2) -> cfg.killRunCmd != null;
        message = "services.portsentry: block mode 2 requires killRunCmd to be set.";
      }
    ];

    systemd.services.portsentry = {
      description = "PortSentry port scan detector";
      documentation = [ "man:portsentry(8)" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "simple";
        ExecStart = utils.escapeSystemdExecArgs execArgs;
        Restart = "on-failure";
        RestartSec = 1;

        # portsentry refuses to run as non-root, so it stays root but is confined
        # to just the capabilities it needs.
        AmbientCapabilities = capabilities;
        CapabilityBoundingSet = capabilities;

        RuntimeDirectory = "portsentry";
        RuntimeDirectoryMode = "0750";
        LogsDirectory = "portsentry";
        LogsDirectoryMode = "0750";

        # Filesystem/kernel hardening. These defaults suit the recommended
        # log-only configuration; aggressive active-response setups (external
        # firewall commands, custom paths) may need to relax ProtectSystem or
        # extend ReadWritePaths via services.portsentry.extraArgs/overrides.
        ProtectSystem = "strict";
        ProtectHome = true;
        ReadWritePaths = lib.unique extraReadWritePaths;
        PrivateTmp = true;
        ProtectClock = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectHostname = true;
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" "AF_PACKET" "AF_NETLINK" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" ];
        UMask = "0027";
      };
    };
  };
}
