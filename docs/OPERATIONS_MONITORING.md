# ISCY Operations Monitoring

Stand: ISCY V23.7.10 / Rust 0.3.6

Diese Doku beschreibt die maschinenlesbaren Betriebsendpunkte fuer den Rust-only-Betrieb.

## Repo-Artefakte

Fuer den direkten Betrieb liegen Monitoring-Beispiele im Repository:

- `deploy/monitoring/prometheus/iscy-scrape.yml`: minimaler Prometheus-Scrape-Job fuer `/metrics`.
- `deploy/monitoring/prometheus/prometheus.yml`: vollstaendige Prometheus-Konfiguration fuer den Compose-Monitoring-Stack.
- `deploy/monitoring/prometheus/iscy-operations-alerts.yml`: Alert-Regeln fuer kritische Statussignale, Warnungen, Migrationen, Modulstatus und Runtime-Flags.
- `deploy/monitoring/alertmanager/iscy-alertmanager.yml`: Alertmanager-Routing-Beispiel mit getrennten Receivern fuer Warnungen und kritische Meldungen sowie ISCY-Kontext-Headern fuer Incident-/Evidence-Persistenz.
- `deploy/monitoring/grafana/iscy-operations-dashboard.json`: importierbares Grafana-Dashboard fuer Betriebsstatus, offene Signale, Migrationen, Module, Build-Info, Product-Security-Coverage, CVE-Review-Trend und Importvalidierung.
- `deploy/monitoring/docker-compose.yml`: lokaler Monitoring-Stack aus Prometheus, Alertmanager und Grafana.
- `deploy/monitoring/nixos/iscy-monitoring.nix`: NixOS-Modulbeispiel fuer denselben Stack.
- `deploy/monitoring/nixos/example-host.nix`: kleine Beispiel-Hostkonfiguration, die das Modul importiert, Ports freigibt und den lokalen ISCY-Webhook verdrahtet.

Die Alertmanager-Beispielkonfiguration ruft den ISCY-Webhook `POST /api/v1/operations/alertmanager` auf. Wenn `ISCY_ALERTMANAGER_TOKEN` gesetzt ist, muss Alertmanager denselben Wert per Bearer Token oder `x-iscy-alert-token` senden. Ohne Tenant-/User-Kontext normalisiert der Webhook Alerts nur; mit schreibendem Kontext erzeugt ISCY fuer firing Alerts automatisch Incident-Fallakten, verknuepfte Evidence und Timeline-Eintraege. Das lokale Beispiel setzt `x-iscy-tenant-id: 1`, `x-iscy-user-id: 1` und `x-iscy-roles: ADMIN`; produktiv sollten diese Werte auf einen dedizierten technischen Operations-User zeigen.

## Endpunkte

- `GET /health/live`: einfacher Liveness-Check fuer Load Balancer, lokale Starts und CI.
- `GET /health/ready`: Alias fuer Readiness-/Liveness-Probes.
- `GET /status/operations.json`: JSON-Drilldown mit Runtime, Build, Migrationen, Modulen und fachlichen Signalen.
- `GET /api/v1/status/operations`: API-Alias fuer denselben JSON-Drilldown.
- `GET /metrics`: Prometheus-kompatible Textausgabe.
- `GET /api/v1/status/metrics`: API-Alias fuer Prometheus-kompatible Textausgabe.
- `POST /api/v1/operations/alertmanager`: Alertmanager-Webhook, der Alerts validiert, normalisiert und bei schreibendem Tenant-Kontext als Incident/Evidence persistieren kann.
- `GET /api/v1/product-security/trends`: Product-Security-Trends zu CVE-Reviews, Evidence-Luecken, Importvalidierung, Coverage und Snapshots.

Mit Tenant-Kontext liefern die Operations-Endpunkte zusaetzlich fachliche Signale zu ISCY-27, Product Security, CVE-Reviews, Evidence-Luecken und Roadmap-Gaps:

```bash
curl -fsS -H 'x-iscy-tenant-id: 1' -H 'x-iscy-user-id: 1' \
  'http://127.0.0.1:9000/api/v1/status/operations?tenant_id=1&user_id=1'
curl -fsS -H 'x-iscy-tenant-id: 1' -H 'x-iscy-user-id: 1' \
  'http://127.0.0.1:9000/api/v1/status/metrics?tenant_id=1&user_id=1'
```

## Prometheus

Minimaler lokaler Scrape:

```yaml
scrape_configs:
  - job_name: "iscy-rust"
    metrics_path: "/metrics"
    static_configs:
      - targets: ["127.0.0.1:9000"]
```

Dasselbe Beispiel liegt als Datei unter `deploy/monitoring/prometheus/iscy-scrape.yml`.

Wichtige Metriken:

- `iscy_operations_exit_code`: `0` fuer OK, `1` fuer Warnung, `2` fuer kritisch.
- `iscy_operations_issue_count`: Anzahl offener Warn-/Kritisch-Signale.
- `iscy_operations_signal`: einzelne Betriebssignale mit Labels `area`, `signal` und `level`.
- `iscy_operations_module_configured`: Rust-Store-/Modulstatus je Modul.
- `iscy_operations_migration_applied`: angewendete DB-Migrationen.
- `iscy_operations_migration_expected`: erwartete DB-Migrationen.
- `iscy_operations_runtime_flag`: Runtime-Flags wie `rust_only` und `strict_mode`.
- `iscy_operations_build_info`: Build-Metadaten mit Version, Commit, Profil und Target.
- `iscy_product_security_coverage_percent`: SBOM-, CSAF- und Threat-/TARA-Coverage in Prozent.
- `iscy_product_security_import_validation_total`: Product-Security-Importe nach Validierungsstatus.
- `iscy_product_security_trend_signal`: aktuelle Trend-Signale wie offene CVE-Reviews, fehlende Evidence oder Importvalidierungsprobleme.
- `iscy_product_security_snapshot_readiness_percent`: Snapshot-Verlauf fuer CRA-, AI-Act-, Threat-Model- und PSIRT-Readiness.
- `iscy_product_security_snapshot_open_vulnerabilities`: offene Product-Security-Schwachstellen je Snapshot.

Produktive Beispiel-Alerts liegen unter `deploy/monitoring/prometheus/iscy-operations-alerts.yml`. Der Kern ist:

```yaml
groups:
  - name: iscy-operations
    rules:
      - alert: ISCYOperationsCritical
        expr: iscy_operations_exit_code == 2
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "ISCY meldet kritischen Betriebsstatus"

      - alert: ISCYOperationsWarnings
        expr: iscy_operations_exit_code == 1
        for: 30m
        labels:
          severity: warning
        annotations:
          summary: "ISCY meldet offene Warnsignale"

      - alert: ISCYMissingRustModule
        expr: iscy_operations_module_configured == 0
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "Ein ISCY Rust-Modul ist nicht verbunden"
```

## Grafana

Das Dashboard `deploy/monitoring/grafana/iscy-operations-dashboard.json` kann in Grafana ueber **Dashboards -> New -> Import -> Upload JSON file** importiert werden. Danach muss nur die Prometheus-Datasource im Importdialog ausgewaehlt werden.

Die Statusseite `/status/` enthaelt zusaetzlich einen kompakten Grafana-Query-Spickzettel. Sinnvolle Panels:

- Stat: `iscy_operations_exit_code`
- Stat: `iscy_operations_issue_count`
- Table: `iscy_operations_signal`
- Table: `iscy_operations_module_configured`
- Gauge: `iscy_operations_migration_applied / iscy_operations_migration_expected`
- Build-Info: `iscy_operations_build_info`
- Bar Gauge: `iscy_product_security_coverage_percent`
- Time Series: `iscy_product_security_trend_signal{key=~"open_cve_reviews|evidence_missing|risk_missing"}`
- Bar Gauge: `iscy_product_security_import_validation_total{status!="total"}`

Empfohlene Schwellen:

- Exit-Code `0`: gruen
- Exit-Code `1`: gelb
- Exit-Code `2`: rot
- Issue Count `0`: gruen
- Issue Count `> 0`: gelb oder rot je nach `level` der Signale

## Lokaler Monitoring-Stack

ISCY zuerst starten:

```bash
./start.sh
```

Danach den Monitoring-Stack starten:

```bash
docker compose -f deploy/monitoring/docker-compose.yml up -d
```

Standard-URLs:

- Prometheus: `http://127.0.0.1:9090`
- Alertmanager: `http://127.0.0.1:9093`
- Grafana: `http://127.0.0.1:3000`

Grafana-Login im Beispiel: `admin / admin`. Fuer dauerhaften Betrieb `ISCY_GRAFANA_PASSWORD` setzen.

## NixOS-Beispiel

Das Modulbeispiel kann in eine NixOS-Konfiguration importiert werden:

```nix
{
  imports = [
    /home/enricow79/Projekte/ISCY/deploy/monitoring/nixos/iscy-monitoring.nix
  ];

  services.iscy.monitoring = {
    enable = true;
    iscyTarget = "127.0.0.1:9000";
    alertWebhookUrl = "http://127.0.0.1:9000/api/v1/operations/alertmanager";
    alertTenantId = 1;
    alertUserId = 1;
    alertRoles = [ "ADMIN" ];
  };
}
```

Alternativ liegt eine kleine Beispiel-Hostkonfiguration unter `deploy/monitoring/nixos/example-host.nix`. Sie importiert das Modul, setzt die Standardports und oeffnet Prometheus, Alertmanager und Grafana in der lokalen Firewall.

## Runbook: Alert erzeugt Incident

Wenn Alertmanager einen firing Alert mit ISCY-Kontext an `POST /api/v1/operations/alertmanager` sendet, wird in ISCY automatisch ein Incident im Status `TRIAGE` erzeugt. Dazu entsteht eine verknuepfte Evidence mit `OPERATIONS:ALERTMANAGER:<alertname>` und ein Timeline-Eintrag in der Fallakte.

1. In `/incidents/` die neue Fallakte oeffnen und Severity, Scope sowie betroffene Services bestaetigen.
2. Die automatisch angelegte Evidence pruefen und bei Bedarf Monitoring-Screenshot, Grafana-Link oder Log-Auszug nachreichen.
3. Im Incident-Runbook Owner, Eindaemmung, Kommunikationsbedarf und regulatorische Relevanz bewerten.
4. Falls ein Control-, CVE- oder Product-Security-Bezug besteht, Risk-/Roadmap-Arbeit verknuepfen oder neu erzeugen.
5. Nach Behebung Timeline, Lessons Learned und Alert-Schwelle reviewen.

## Betriebshinweise

- `/metrics` ist bewusst ohne Tenant-Kontext abrufbar, damit Prometheus ohne zusaetzliche Header starten kann.
- Fuer mandantenbezogene Metriken kann ein Reverse Proxy den Tenant-/User-Kontext setzen und `/api/v1/status/metrics` scrapen.
- Die Statusseite `/status/` zeigt eine kopierbare Prometheus-Scrape-Konfiguration fuer den aktuell gesetzten `RUST_BACKEND_BIND` und einen Grafana-Query-Spickzettel.
- Der JSON-Endpunkt eignet sich fuer Agenten, Runbooks und externe Checks, die Details wie `severity`, `exit_code`, `signals` und `modules` strukturiert auswerten wollen.
- Der Alertmanager-Webhook persistiert Incidents/Evidence nur, wenn `x-iscy-tenant-id`, `x-iscy-user-id` und eine schreibende Rolle oder Session gesetzt sind. Ohne diesen Kontext bleibt der Webhook ein sicherer Normalisierer fuer Monitoring und ChatOps.
- Alertmanager unterstuetzt die Kontext-Header ueber `http_config.http_headers`; fuer aeltere Alertmanager-Versionen sollte die Konfiguration vor dem Rollout mit `amtool check-config` oder einem Container-Starttest validiert werden.
