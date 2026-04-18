# Rust-Ablöse-Checkliste (Python -> Rust)

Stand: 2026-04-18

## Ziel
Komplette Ablösung der CVE-Normalisierungspfade in der Vulnerability-Intelligence von Python auf Rust mit harten Gates gegen Mischbetrieb.

## Umgesetzte Punkte
- [x] **Rust-only Gate in den Django-Settings aktiviert** (`VULN_INTEL_RUST_ONLY=True` per Default).
- [x] **Zentrale CVE-Upserts auf Rust-Normalisierung umgestellt** (`NVDService.upsert_cve` normalisiert standardmäßig via Rust).
- [x] **Harter Fehler bei fehlender Rust-Konfiguration** in Rust-only-Modus (`RUST_BACKEND_URL` erforderlich).
- [x] **Legacy-Canary-Import auf Rust-only vereinfacht** (kein `--apply-source` Mischmodus mehr).
- [x] **README auf Rust-only Betrieb aktualisiert**.
- [x] **Regression-Tests ergänzt/angepasst** (Rust-only Verhalten und Legacy-Command).

## Verbleibende Ablösearbeiten
- [ ] CVE-Normalisierung vollständig in Rust-Service konsolidieren (inkl. klarer API-Versionierung und Fehlercodes).
- [ ] NVD-Collection-Import logikseitig als Rust-Primärpfad bereitstellen und Django auf orchestrierende Rolle begrenzen.
- [ ] Parity-Reports als optionales Audit-Feature markieren (nicht als Betriebsnotwendigkeit).
- [ ] Betriebsdoku für Stage/Prod um verpflichtende Rust-Health-SLOs und Alerting ergänzen.
- [ ] CI-Policy: Fail, wenn `VULN_INTEL_RUST_ONLY=True` und rust-backend Integrationstests nicht grün.

## Abnahmekriterien („komplett zu Rust“)
1. **Kein produktiver Python-Fallback** für CVE-Normalisierung mehr aktiv.
2. **Alle produktiven Upserts verwenden Rust-normalisierte CVE-IDs**.
3. **Rust-Healthchecks und Integrationstests sind verbindlich in CI/CD**.
4. **Runbook und Betriebshandbuch enthalten Rust-only Incident- und Rollback-Pfade**.

