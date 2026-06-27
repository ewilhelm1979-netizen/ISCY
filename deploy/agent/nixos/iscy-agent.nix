{ config, lib, ... }:

let
  cfg = config.services.iscy-agent;
in
{
  options.services.iscy-agent = {
    enable = lib.mkEnableOption "ISCY read-only posture agent";

    binary = lib.mkOption {
      type = lib.types.str;
      default = "/usr/local/bin/iscy-agent";
      description = "Absolute path to the iscy-agent binary.";
    };

    backendUrl = lib.mkOption {
      type = lib.types.str;
      example = "https://iscy.example.org";
      description = "ISCY backend base URL.";
    };

    tenantId = lib.mkOption {
      type = lib.types.int;
      default = 1;
      description = "ISCY tenant ID.";
    };

    interval = lib.mkOption {
      type = lib.types.str;
      default = "15min";
      description = "systemd timer interval.";
    };

    environmentFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = "/etc/iscy-agent/agent.env";
      description = "Optional root-readable file for initial enrollment or mTLS settings.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.iscy-agent = {
      description = "ISCY read-only posture agent";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      environment = {
        ISCY_BACKEND_URL = cfg.backendUrl;
        ISCY_TENANT_ID = toString cfg.tenantId;
        ISCY_AGENT_CHANNEL = "nixos";
        ISCY_AGENT_STATE_PATH = "/var/lib/iscy-agent/state.json";
        ISCY_AGENT_QUEUE_DIR = "/var/lib/iscy-agent/queue";
      };
      serviceConfig = {
        Type = "oneshot";
        DynamicUser = true;
        EnvironmentFile = lib.optional (cfg.environmentFile != null) cfg.environmentFile;
        ExecStart = cfg.binary;
        StateDirectory = "iscy-agent";
        StateDirectoryMode = "0700";
        UMask = "0077";
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictSUIDSGID = true;
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
        ];
      };
    };

    systemd.timers.iscy-agent = {
      description = "Collect ISCY endpoint posture periodically";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "5min";
        OnUnitActiveSec = cfg.interval;
        RandomizedDelaySec = "2min";
        Persistent = true;
        Unit = "iscy-agent.service";
      };
    };
  };
}
