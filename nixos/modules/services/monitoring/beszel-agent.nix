{
  config,
  options,
  lib,
  pkgs,
  ...
}:
let

  cfg = config.services.beszel-agent;
  opt = options.services.beszel-agent;

  toAddressAndPort =
    str:
    let
      tks = lib.match "(([^:]*):)?([0-9]+)" str;
      # "localhost:80"   --> [ "localhost:" "localhost" "80" ]
      # ":80"            --> [ ":"         ""           "80" ]
      # "80"             --> [ null        null         "80" ]
      # "does not match" --> null
      toAttrs = tks: {
        address = if (lib.head tks) == ":" then null else lib.elemAt tks 1;
        port = lib.toIntBase10 (lib.elemAt tks 2);
      };
    in
    lib.mapNullable toAttrs tks;

in
{

  options.services.beszel-agent = {

    "enable" = lib.mkEnableOption "Beszel agent";

    "package" = lib.mkPackageOption pkgs "beszel-agent" { };

    "user" = lib.mkOption {
      default = "beszelagent";
      type = lib.types.str;
      description = ''
        User the Beszel agent should run as.
        Unless you leave the default value, the user must exist.
      '';
    };

    "group" = lib.mkOption {
      default = cfg.user;
      defaultText = ''"''${user}"'';
      type = lib.types.str;
      description = ''
        Primary group of the Beszel agent user, will be created if needed.
      '';
    };

    "openFirelwall" = lib.mkOption {
      default = true; # given the nature of beszel-agent
      type = lib.types.bool;
      description = ''
        Allows all incoming traffic to the port specified in
        `services.beszel-agent.environment.PORT`, *regardless* of the address
        that may be optionally configured in that same option (default: true).
      '';
    };

    "setupPodmanSocket" = lib.mkOption {
      default = false;
      type = lib.types.bool;
      description = ''
        Convenience shortcut to setup container monitoring via the system
        podman socket.
        Sets `virtualization.podman.dockerSocket.enable = "true"`,
        `services.beszel-agent.environment.DOCKER_HOST = "unix:///run/podman/podman.sock"`,
        and adds the agent user to the *podman* group.
      '';
    };

    environment = {

      # see https://github.com/henrygd/beszel?tab=readme-ov-file#agent-1

      "DOCKER_HOST" = lib.mkOption {
        default = if cfg.setupPodmanSocket then "unix:///run/podman/podman.sock" else null;
        defaultText = "unix:///var/run/docker.sock";
        type = lib.types.nullOr lib.types.str;
        description = ''
          Url of the docker/podman socket to connect to for monitoring container
          monitoring.
        '';
        example = "unix:///run/user/1000/podman/podman.sock";
      };

      "EXTRA_FILESYSTEMS" = lib.mkOption {
        default = null;
        type = lib.types.nullOr lib.types.str;
        description = ''
          Comma-separated list of extra devices, partitions, or mount points to
          monitor
        '';
        example = "sdb,sdc1,mmcblk0,/mnt/network-share";
      };

      "FILESYSTEM" = lib.mkOption {
        default = null;
        type = lib.types.nullOr lib.types.str;
        description = ''
          Device, partition, or mount point to use for root disk stats.
        '';
      };

      "KEY" = lib.mkOption {
        type = lib.types.str;
        description = ''
          The hub's SSH public key key authorized to connect to the agent.
        '';
        example = "ssh-ed25519 AAAAC3NzaCetcetera/etceteraJZMfk3QPfQ";
      };

      "LOG_LEVEL" = lib.mkOption {
        default = "warn";
        type = lib.types.enum [
          "error"
          "warn"
          "info"
          "debug"
        ];
        description = ''
          Log verbosity level, must be one of "error", "warn", "info" or "debug".
        '';
      };

      "MEM_CALC" = lib.mkOption {
        default = null;
        type = lib.types.nullOr (lib.types.enum [ "htop" ]);
        description = ''
          Specifies a different method for calculating free memory.
          The default is based on gopsutil's Used calculation and aligns fairly
          closely with *free*. Specify `"htop"` for a method that resembles
          *htop*'s calculations.
        '';
      };

      "NICS" = lib.mkOption {
        default = null;
        type = lib.types.nullOr lib.types.str;
        description = ''
          Whitelist of network interfaces to monitor for bandwidth chart.
        '';
      };

      "PORT" = lib.mkOption {
        default = "45876";
        type = (lib.types.addCheck lib.types.str (v: !isNull (toAddressAndPort v))) // {
          description = "string of the form address:port";
        };
        description = ''
          Port or address:port the Beszel agent should listen on.
        '';
        example = "127.0.0.1:45876";
      };

      "SENSORS" = lib.mkOption {
        default = null;
        type = lib.types.nullOr lib.types.str;
        description = ''
          Whitelist of temperature sensors to monitor.
        '';
      };

      "SYS_SENSORS" = lib.mkOption {
        default = null;
        type = lib.types.nullOr lib.types.str;
        description = ''
          Alternate path to use for sensors instead of /sys.
          See https://github.com/henrygd/beszel/discussions/160
        '';
      };

    };

  };

  config =
    let
      port = (toAddressAndPort cfg.environment.PORT).port;
    in
    lib.mkIf cfg.enable {

      users = lib.mkIf (cfg.user == opt.user.default) {
        users.${cfg.user} = {
          isSystemUser = true;
          group = cfg.group;
          home = "/var/empty";
          createHome = false;
          extraGroups = lib.mkIf cfg.setupPodmanSocket [ "podman" ];
        };
        groups.${cfg.group} = { };
      };

      virtualisation = lib.mkIf cfg.setupPodmanSocket {
        podman.dockerSocket.enable = true;
      };

      networking = lib.mkIf cfg.openFirelwall {
        firewall.allowedTCPPorts = [ port ];
      };

      systemd.services.beszel-agent = {
        enable = true;
        description = "Beszel agent";
        after = [ "network.target" ];
        wantedBy = [ "multi-user.target" ];
        # path = [ cfg.package ];
        serviceConfig = {
          Type = "exec";
          User = cfg.user;
          Group = cfg.group;
          Environment =
            let
              toEnv = k: lib.mapNullable (v: ''"${k}=${v}"'') cfg.environment.${k};
            in
            lib.filter (e: !isNull e) (map toEnv (lib.attrNames cfg.environment));
          ExecStart = "${cfg.package}/bin/${cfg.package.meta.mainProgram}";
          # grant CAP_NET_BIND_SERVICE if a low port was specified
          AmbientCapabilities = if port <= 1024 then "CAP_NET_BIND_SERVICE" else "";
          # no extra capabilities allowed
          CapabilityBoundingSet = "";
          # some of the following will add little or no practical benefit, but
          # let'make it easy for whoever next runs
          # `systemd-analyze security beszel-agent.service`
          RemoveIPC = true;
          NoNewPrivileges = true;
          ProtectClock = true;
          ProtectKernelLogs = true;
          ProtectControlGroups = true;
          ProtectKernelModules = true;
          SystemCallArchitectures = "native";
          MemoryDenyWriteExecute = true;
          RestrictNamespaces = true;
          RestrictSUIDSGID = true;
          ProtectHostname = true;
          LockPersonality = true;
          ProtectKernelTunables = true;
          RestrictAddressFamilies = "AF_UNIX AF_INET AF_INET6"; # only AF_PACKET is excluded
          RestrictRealtime = true;
          ProtectSystem = "strict";
          ProtectProc = "invisible";
          ProtectHome = true;
          PrivateUsers = true;
          PrivateTmp = true;
          PrivateMounts = true;
          UMask = "0077";
          SystemCallFilter = [
            # If `systemd-analyze security` complains, try blacklisting more
            # filters and see if the process core dumps with status=31/SYS
            "~@clock @cpu-emulation @debug @module @mount @obsolete @privileged"
            "~@raw-io @reboot @swap"
            # the @resources filer must be allowed
          ];
        };
      };

    };

  meta.maintainers = with lib.maintainers; [ giorgiga ];

}
