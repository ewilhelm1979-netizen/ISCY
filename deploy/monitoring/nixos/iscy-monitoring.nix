{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.iscy.monitoring;
  dashboardDir = pkgs.runCommand "iscy-grafana-dashboards" { } ''
    mkdir -p "$out"
    cp ${../grafana/iscy-operations-dashboard.json} "$out/iscy-operations-dashboard.json"
  '';
in
{
  options.services.iscy.monitoring = {
    enable = lib.mkEnableOption "ISCY Prometheus, Alertmanager and Grafana monitoring";

    iscyTarget = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:9000";
      description = "Host:port target of the ISCY Rust backend metrics endpoint.";
    };

    prometheusPort = lib.mkOption {
      type = lib.types.port;
      default = 9090;
      description = "Prometheus listen port.";
    };

    alertmanagerPort = lib.mkOption {
      type = lib.types.port;
      default = 9093;
      description = "Alertmanager listen port.";
    };

    grafanaPort = lib.mkOption {
      type = lib.types.port;
      default = 3000;
      description = "Grafana listen port.";
    };

    alertWebhookUrl = lib.mkOption {
      type = lib.types.str;
      default = "http://127.0.0.1:9000/api/v1/operations/alertmanager";
      description = "ISCY Alertmanager webhook URL.";
    };
  };

  config = lib.mkIf cfg.enable {
    services.prometheus = {
      enable = true;
      port = cfg.prometheusPort;
      scrapeConfigs = [
        {
          job_name = "iscy-rust";
          metrics_path = "/metrics";
          static_configs = [
            { targets = [ cfg.iscyTarget ]; }
          ];
        }
      ];
      ruleFiles = [
        (pkgs.writeText "iscy-operations-alerts.yml" (
          builtins.readFile ../prometheus/iscy-operations-alerts.yml
        ))
      ];
      alertmanagers = [
        {
          static_configs = [
            { targets = [ "127.0.0.1:${toString cfg.alertmanagerPort}" ]; }
          ];
        }
      ];
    };

    services.prometheus.alertmanager = {
      enable = true;
      port = cfg.alertmanagerPort;
      configuration = {
        global.resolve_timeout = "5m";
        route = {
          receiver = "iscy-operations";
          group_by = [
            "alertname"
            "service"
            "severity"
          ];
          group_wait = "30s";
          group_interval = "5m";
          repeat_interval = "4h";
          routes = [
            {
              receiver = "iscy-critical";
              matchers = [ ''severity="critical"'' ];
              repeat_interval = "30m";
            }
          ];
        };
        receivers = [
          {
            name = "iscy-operations";
            webhook_configs = [
              {
                url = cfg.alertWebhookUrl;
                send_resolved = true;
              }
            ];
          }
          {
            name = "iscy-critical";
            webhook_configs = [
              {
                url = cfg.alertWebhookUrl;
                send_resolved = true;
              }
            ];
          }
        ];
        inhibit_rules = [
          {
            source_matchers = [ ''severity="critical"'' ];
            target_matchers = [ ''severity="warning"'' ];
            equal = [ "service" ];
          }
        ];
      };
    };

    services.grafana = {
      enable = true;
      settings.server.http_port = cfg.grafanaPort;
      provision = {
        datasources.settings.datasources = [
          {
            name = "Prometheus";
            type = "prometheus";
            access = "proxy";
            url = "http://127.0.0.1:${toString cfg.prometheusPort}";
            isDefault = true;
          }
        ];
        dashboards.settings.providers = [
          {
            name = "ISCY";
            orgId = 1;
            folder = "ISCY";
            type = "file";
            disableDeletion = false;
            editable = true;
            options.path = dashboardDir;
          }
        ];
      };
    };
  };
}
