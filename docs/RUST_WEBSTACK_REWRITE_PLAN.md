# ISCY Rust-Webstack

## Status

Der Rust-Webstack ist der produktive Webstack.

## Architektur

- Axum liefert Weboberflaechen und JSON-APIs.
- Stores in `rust/iscy-backend/src/*_store.rs` kapseln Datenzugriffe.
- `db_admin` initialisiert operative Tabellen und Demo-/Katalogdaten.
- `iscy-canary` uebernimmt NVD-/CVE-Canary- und Importjobs.
- Nginx ist nur Reverse Proxy fuer Stage/Production.

## Abgeloeste Komponenten

- Django-Views und Templates
- Django-Admin als Runtime-Abhaengigkeit
- Django-Settings, URL-Konfiguration, ASGI/WSGI
- Python-Management-Commands
- Python-Docker-Runtime

## Entwicklungsregel

Neue UI-, API-, Job- und Datenzugriffsarbeit wird im Rust-Backend umgesetzt und mit Rust-Tests oder Rust-Smoke-Probes abgesichert.
