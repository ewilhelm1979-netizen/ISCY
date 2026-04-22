# Rust-Ablöse-Checkliste (Python -> Rust)

Stand: 2026-04-22

## Ziel
Komplette Ablösung der produktiven Python/Django-Pfade durch Rust mit harten Gates gegen Mischbetrieb. Die CVE-Normalisierung war der erste harte Gate-Bereich; CI und lokaler Start laufen inzwischen Rust-first.

## Umgesetzte Punkte
- [x] **Rust-only Gate in den Django-Settings aktiviert** (`VULN_INTEL_RUST_ONLY=True` per Default).
- [x] **Zentrale CVE-Upserts auf Rust-Normalisierung umgestellt** (`NVDService.upsert_cve` normalisiert standardmäßig via Rust).
- [x] **Harter Fehler bei fehlender Rust-Konfiguration** in Rust-only-Modus (`RUST_BACKEND_URL` erforderlich).
- [x] **Legacy-Canary-Import auf Rust-only vereinfacht** (kein `--apply-source` Mischmodus mehr).
- [x] **README auf Rust-only Betrieb aktualisiert**.
- [x] **Regression-Tests ergänzt/angepasst** (Rust-only Verhalten und Legacy-Command).
- [x] **Versionierter Rust-Normalisierungsvertrag eingeführt** (`/api/v1/nvd/normalize` mit `api_version` und stabilen Fehlercodes wie `invalid_cve_id`).
- [x] **Python-Collection-Import im Rust-only-Modus gesperrt**; `import_nvd_cves` und `sync_nvd_recent` orchestrieren den Rust-Primärpfad über die Rust-CLI.
- [x] **CI-Policy auf Rust-first umgestellt**: Rust-Tests, Rust-DB-/HTTP-Smoke und Nix-Rust-App-Smoke sind verbindlich.
- [x] **Rust-Session-Schicht eingefuehrt**: DB-validierte Tenant-/User-Sessions, Cookie/Bearer-Aufloesung und Web-Kontext ohne Query-Parameter.

## Verbleibende Ablösearbeiten
- [ ] CVE-Normalisierung vollständig als produktiven Rust-Primärpfad konsolidieren (inkl. Monitoring, Betriebsdoku und finaler Entfernung des Python-Kompatibilitätsendpunkts).
- [ ] NVD-Collection-Import in Rust um Persistenz-/DB-Schreibpfad erweitern, damit Django nicht mehr für CVE-Upserts benötigt wird.
- [ ] Parity-Reports als optionales Audit-Feature markieren (nicht als Betriebsnotwendigkeit).
- [ ] Betriebsdoku für Stage/Prod um verpflichtende Rust-Health-SLOs und Alerting ergänzen.

## Abnahmekriterien („komplett zu Rust“)
1. **Kein produktiver Python-Fallback** für CVE-Normalisierung mehr aktiv.
2. **Alle produktiven Upserts verwenden Rust-normalisierte CVE-IDs**.
3. **Rust-Healthchecks und Integrationstests sind verbindlich in CI/CD**.
4. **Runbook und Betriebshandbuch enthalten Rust-only Incident- und Rollback-Pfade**.
