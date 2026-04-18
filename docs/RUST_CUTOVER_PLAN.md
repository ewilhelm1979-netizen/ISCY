# ISCY Rust Cutover Plan (stufenweise Umschaltung)

## Ziel

Kontrollierter Wechsel von Python-Pfaden auf Rust-Pfade ohne Big-Bang-Risiko.

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
- Python-Normalisierung nur noch Fallback/Debug
- Runbook/Alerting auf Rust-Pfade final anpassen
