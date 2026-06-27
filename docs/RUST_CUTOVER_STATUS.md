# ISCY Rust-Cutover-Status

Stand: 2026-06-27

## Kurzfassung

Der Runtime-Cutover nach Rust ist abgeschlossen.

ISCY startet produktiv und lokal ueber den Rust-Axum-Service in `rust/iscy-backend`. Die fruehere Django/Python-Anwendung wurde aus dem Repository entfernt: `apps/`, `config/`, `templates/`, `manage.py`, `requirements*.txt`, der Python-Dockerfile und der Python-Entrypoint sind nicht mehr Teil des Runtime-Pfads.

## Runtime

- Lokaler Start: `./start.sh`
- Nix-App: `nix run .#iscy-backend`
- Compose-App-Service: Rust-Backend auf Port `9000`
- Stage/Production-Reverse-Proxy: Nginx -> `app:9000`
- Healthchecks: `/health/live`, `/health/ready`
- Operations-Drilldown: `/status/operations.json` und `/api/v1/status/operations`
- Prometheus-kompatible Metriken: `/metrics` und `/api/v1/status/metrics`
- Alertmanager-Webhook: `/api/v1/operations/alertmanager` mit optionaler Incident-/Evidence-Persistenz bei schreibendem Tenant-Kontext; Monitoring-Beispiele nutzen den technischen Operations-User `ops-alertmanager`, Secret-Datei fuer Bearer Token, Alert-Incident-Metriken inklusive `resolved`, Deduplizierung ueber Fingerprint/Alertname, automatische Schliessung bei resolved Alerts, optionale Review-Pflicht fuer fehlende Root-Cause-/Lessons-Learned-Dokumentation und die Webuebersicht `/operations/incidents/` mit Filtern fuer open, critical und resolved
- Monitoring-Doku: `docs/OPERATIONS_MONITORING.md`
- Monitoring-Deploy-Artefakte: `deploy/monitoring/prometheus/`, `deploy/monitoring/alertmanager/`, `deploy/monitoring/grafana/`, `deploy/monitoring/docker-compose.yml` und `deploy/monitoring/nixos/`

## Abgedeckte Rust-Web-/API-Bereiche

- Dashboard
- Navigator/Guidance
- Catalog und Requirements
- Assessments
- Organizations
- Risks
- Incidents inklusive NIS2-Erheblichkeitsentscheidung, Meldefristen erst bei erheblichen Sicherheitsvorfaellen, Entscheidungsleiste in der Fallakte, Detailbearbeitung, tenantbezogener Runbook-Template-Bibliothek, manueller Timeline-Notizen, Timeline-/Audit-Events und Markdown-/HTML-/PDF-Meldepaket mit Audit-Timeline
- Evidence inklusive Upload, Incident-Verknuepfung, direktem Fallakten-Upload, automatischem Timeline-Ereignis, Context-Prefill und Ruecksprung zur Ausgangsseite
- Reports
- Roadmap
- Assets
- Imports inklusive CSV/XLSX/XLSM-Preview
- Processes
- AI Governance inklusive AI-Systemregister, AI-Act-Klassifizierung, Human Oversight, Monitoringplan, Evidence-Key, Governance-Gap-Berechnung, Review-Faelligkeit und Rust-only-Betriebssignalen
- Product Security inklusive CSAF-/CycloneDX-/SPDX-Importhistorie, Import-Detailseiten, VEX-Status je Schwachstelle, SBOM-Diff, CRA-Readiness, CVE-Asset-Korrelation, automatischer Risiko-/Roadmap-Ableitung, CVE-Risiko-Review-Queue, Review-Filtern, Bulk-Aktionen, Evidence-Lueckenmetriken, Trend-Dashboard, Prometheus-Trendmetriken und Grafana-Panels fuer Alert-Incidents mit konkretem Incident-Drilldown, Coverage, Review-Trend und Importvalidierung
- Zero Trust inklusive read-only Rust-Agent, Enrollment/Secret-Rotation, Offline-Queue, Policy-Profilen, erwarteter Flottenabdeckung, sicheren Policy-Webhooks, Cooldown/Retry und Delivery-Audit
- CVE Feed, CVE Assessments und NVD-Import
- User-Administration, Rollen, Gruppen und direkte Permissions

## Entfernte Legacy-Pfade

- Django-App-Code und Django-Templates
- Django-Settings, ASGI/WSGI und URL-Konfiguration
- `manage.py`
- Python-Requirements und lokale Python-Bootstrap-Ziele
- Python-Docker-Image und Entrypoint
- Django-Teamtests und Django-Smoke-Checks

## Verbleibende Kompatibilitaet

Die Rust-DB-Schicht nutzt weiterhin bestehende historische Tabellennamen wie `requirements_app_*` oder `vulnerability_intelligence_*`. Das ist Schema-Kompatibilitaet, kein aktiver Django-Runtime-Pfad.

## Cutover-Entscheidung

Status: **abgeschlossen**.

Neue Produktarbeit soll direkt im Rust-Service, den Rust-Stores, Rust-Webrouten, Rust-CLI-Binaries und Rust-Tests erfolgen.
