# ISCY Rust-Webstack

## Status

Der Rust-Webstack ist der produktive Webstack.

## Architektur

- Axum liefert Weboberflaechen und JSON-APIs.
- Stores in `rust/iscy-backend/src/*_store.rs` kapseln Datenzugriffe.
- `db_admin` initialisiert operative Tabellen und Demo-/Katalogdaten.
- `iscy-canary` uebernimmt NVD-/CVE-Canary- und Importjobs.
- Nginx ist nur Reverse Proxy fuer Stage/Production.
- Product Security, AI Governance, Risk, Roadmap und Evidence sind fachlich gekoppelt: akzeptierte CVE-Korrelationen koennen Risiken und Roadmap-Tasks erzeugen, AI-Systeme tragen Governance-Gaps und Evidence-Keys und sind direkt mit Risiken, Roadmap-Tasks, Incidents und Changes verbunden; die CVE-Risiko-Review-Queue kann gefiltert und per Bulk-Aktion bearbeitet werden, Evidence-Keys halten die Nachweisverknuepfung zusammen.

## Abgeloeste Komponenten

- Django-Views und Templates
- Django-Admin als Runtime-Abhaengigkeit
- Django-Settings, URL-Konfiguration, ASGI/WSGI
- Python-Management-Commands
- Python-Docker-Runtime

## Entwicklungsregel

Neue UI-, API-, Job- und Datenzugriffsarbeit wird im Rust-Backend umgesetzt und mit Rust-Tests oder Rust-Smoke-Probes abgesichert.
