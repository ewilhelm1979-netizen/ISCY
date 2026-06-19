{
  config,
  lib,
  pkgs,
  ...
}:

{
  imports = [
    ./iscy-monitoring.nix
  ];

  services.iscy.monitoring = {
    enable = true;
    iscyTarget = "127.0.0.1:9000";
    prometheusPort = 9090;
    alertmanagerPort = 9093;
    grafanaPort = 3000;
    alertWebhookUrl = "http://127.0.0.1:9000/api/v1/operations/alertmanager";
    alertTenantId = 1;
    alertUserId = 1;
    alertRoles = [ "ADMIN" ];
  };

  networking.firewall.allowedTCPPorts = [
    config.services.iscy.monitoring.prometheusPort
    config.services.iscy.monitoring.alertmanagerPort
    config.services.iscy.monitoring.grafanaPort
  ];

  # Optional: enable a reverse proxy here if Prometheus should scrape tenant-scoped
  # metrics with fixed x-iscy-tenant-id/x-iscy-user-id headers.
  environment.systemPackages = [
    pkgs.curl
  ];
}
