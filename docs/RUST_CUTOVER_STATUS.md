# ISCY Rust-Cutover-Status

Stand: 2026-06-14

## Kurzfassung

Der Runtime-Cutover nach Rust ist abgeschlossen.

ISCY startet produktiv und lokal ueber den Rust-Axum-Service in `rust/iscy-backend`. Die fruehere Django/Python-Anwendung wurde aus dem Repository entfernt: `apps/`, `config/`, `templates/`, `manage.py`, `requirements*.txt`, der Python-Dockerfile und der Python-Entrypoint sind nicht mehr Teil des Runtime-Pfads.

## Runtime

- Lokaler Start: `./start.sh`
- Nix-App: `nix run .#iscy-backend`
- Compose-App-Service: Rust-Backend auf Port `9000`
- Stage/Production-Reverse-Proxy: Nginx -> `app:9000`
- Healthchecks: `/health/live`, `/health/ready`

## Abgedeckte Rust-Web-/API-Bereiche

- Dashboard
- Navigator/Guidance
- Catalog und Requirements
- Assessments
- Organizations
- Risks
- Incidents inklusive NIS2-Meldefristen, Fallakten, Detailbearbeitung, tenantbezogener Runbook-Template-Bibliothek, manueller Timeline-Notizen, Timeline-/Audit-Events und Markdown-/HTML-/PDF-Meldepaket mit Audit-Timeline
- Evidence inklusive Upload, Incident-Verknuepfung, direktem Fallakten-Upload, automatischem Timeline-Ereignis, Context-Prefill und Ruecksprung zur Ausgangsseite
- Reports
- Roadmap
- Assets
- Imports inklusive CSV/XLSX/XLSM-Preview
- Processes
- Product Security inklusive CSAF-/CycloneDX-/SPDX-Importhistorie, Import-Detailseiten, CVE-Asset-Korrelation, automatischer Risiko-/Roadmap-Ableitung, CVE-Risiko-Review-Queue, Review-Filtern, Bulk-Aktionen und Evidence-Lueckenmetriken
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
