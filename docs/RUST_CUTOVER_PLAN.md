# ISCY Rust Cutover Plan

## Ziel

Kontrollierter Wechsel von Python-Pfaden auf Rust-Pfade ohne Big-Bang-Risiko. Der fachlich freigegebene Runtime-Cutover ist jetzt als Rust-only-Konfiguration abgesichert.

## Aktueller Cutover-Stand

- `RUST_ONLY_MODE=True` ist der Default.
- `RUST_STRICT_MODE=True` ist der Default.
- `RUST_BACKEND_URL` ist in Rust-only-Runtime Pflicht.
- Alle migrierten Backend-Schalter muessen auf `rust_service` stehen.
- `VULN_INTEL_RUST_ONLY=True` ist Pflicht, damit CVE-Normalisierung und Imports nicht ueber Python-Fallbacks laufen.
- Docker Compose startet die Django-App nur noch mit `rust-backend` als Health-Abhaengigkeit und mit Rust-only-Guards.
- Legacy-Fallbacks sind nur noch fuer explizit markierte Tests/Debug-Laeufe mit `RUST_ONLY_MODE=False` erlaubt.

## Stufe 0 – Vorbereitung

- Rust-Service stabil deployen (`/health/live` erreichbar)
- `RUST_BACKEND_URL` in Stage setzen
- Team-Test + Canary-Report als Pflicht vor Rollout

## Stufe 1 – Canary (Read-Only Vergleich)

- `report_nvd_canary_parity` regelmaessig laufen lassen
- Match-Rate beobachten, Mismatches analysieren
- Keine fachliche Umschaltung, nur Transparenz

## Stufe 2 – Bridge-Write (kontrolliert)

- `import_nvd_cves_via_rust` fuer selektierte Jobs/CVEs aktivieren
- Python-Upsert bleibt Source-of-Truth
- Fehlerbudget + Rollback-Regel definieren

## Stufe 3 – Teil-Cutover

- Rust-CLI/Wrapper (`import_nvd_cves`, `sync_nvd_recent`, `import_nvd_cves_canary`) fuer Stage mit verpflichtendem Rust-Healthcheck erzwingen
- In Production schrittweise per Job-Kohorten aktivieren
- Mismatch-Grenzwerte definieren (z. B. <0.5%)

## Stufe 4 – Voll-Cutover

- Rust-Normalisierung als Default
- Python-Normalisierung nur noch in expliziten Test-/Debug-Laeufen mit `RUST_ONLY_MODE=False`
- Runbook/Alerting auf Rust-Pfade final anpassen
