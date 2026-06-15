# ISCY Operations Monitoring

Stand: ISCY V23.7.6 / Rust 0.3.2

Diese Doku beschreibt die maschinenlesbaren Betriebsendpunkte fuer den Rust-only-Betrieb.

## Endpunkte

- `GET /health/live`: einfacher Liveness-Check fuer Load Balancer, lokale Starts und CI.
- `GET /health/ready`: Alias fuer Readiness-/Liveness-Probes.
- `GET /status/operations.json`: JSON-Drilldown mit Runtime, Build, Migrationen, Modulen und fachlichen Signalen.
- `GET /api/v1/status/operations`: API-Alias fuer denselben JSON-Drilldown.
- `GET /metrics`: Prometheus-kompatible Textausgabe.
- `GET /api/v1/status/metrics`: API-Alias fuer Prometheus-kompatible Textausgabe.

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

Wichtige Metriken:

- `iscy_operations_exit_code`: `0` fuer OK, `1` fuer Warnung, `2` fuer kritisch.
- `iscy_operations_issue_count`: Anzahl offener Warn-/Kritisch-Signale.
- `iscy_operations_signal`: einzelne Betriebssignale mit Labels `area`, `signal` und `level`.
- `iscy_operations_module_configured`: Rust-Store-/Modulstatus je Modul.
- `iscy_operations_migration_applied`: angewendete DB-Migrationen.
- `iscy_operations_migration_expected`: erwartete DB-Migrationen.
- `iscy_operations_runtime_flag`: Runtime-Flags wie `rust_only` und `strict_mode`.
- `iscy_operations_build_info`: Build-Metadaten mit Version, Commit, Profil und Target.

Beispiel-Alerts:

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

Sinnvolle Panels:

- Stat: `iscy_operations_exit_code`
- Stat: `iscy_operations_issue_count`
- Table: `iscy_operations_signal`
- Table: `iscy_operations_module_configured`
- Gauge: `iscy_operations_migration_applied / iscy_operations_migration_expected`
- Build-Info: `iscy_operations_build_info`

Empfohlene Schwellen:

- Exit-Code `0`: gruen
- Exit-Code `1`: gelb
- Exit-Code `2`: rot
- Issue Count `0`: gruen
- Issue Count `> 0`: gelb oder rot je nach `level` der Signale

## Betriebshinweise

- `/metrics` ist bewusst ohne Tenant-Kontext abrufbar, damit Prometheus ohne zusaetzliche Header starten kann.
- Fuer mandantenbezogene Metriken kann ein Reverse Proxy den Tenant-/User-Kontext setzen und `/api/v1/status/metrics` scrapen.
- Die Statusseite `/status/` zeigt eine kopierbare Prometheus-Scrape-Konfiguration fuer den aktuell gesetzten `RUST_BACKEND_BIND`.
- Der JSON-Endpunkt eignet sich fuer Agenten, Runbooks und externe Checks, die Details wie `severity`, `exit_code`, `signals` und `modules` strukturiert auswerten wollen.
