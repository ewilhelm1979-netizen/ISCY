# ISCY Rust Cutover Plan

## Ziel

Kontrollierter Wechsel der produktiven Runtime auf Rust.

## Ergebnis

Der Cutover ist abgeschlossen. Der fruehere Parallelbetrieb wurde beendet und die Django/Python-Anwendung aus dem Repository entfernt.

## Finaler Betriebsmodus

- `app` in Docker Compose ist der Rust-Axum-Service.
- `rust/iscy-backend` enthaelt Runtime, Weboberflaeche, API, Stores, CLI und Tests.
- Nginx proxyt Stage/Production auf `app:9000`.
- Lokaler Start erfolgt ueber `./start.sh`, `make dev-up` oder `nix run .#iscy-backend`.
- Datenbank-Bootstrap erfolgt ueber `iscy-backend init-demo`.
- Canary-/NVD-Jobs laufen ueber `iscy-canary`.

## Historische Stufen

1. Vorbereitung: Rust-Service mit Health, CI und Compose integriert.
2. Canary: Python/Rust-Paritaet ueber Reports abgesichert.
3. Bridge-Write: Django-Kommandos auf Rust-Backend/CLI umgestellt.
4. Teil-Cutover: zentrale Web-/API-Slices in Rust umgesetzt.
5. Voll-Cutover: Python/Django-Code und Startpfade entfernt.

## Nach dem Cutover

Neue Arbeit erfolgt direkt in Rust. Falls alte Datenbanken weitergenutzt werden, bleiben historische Tabellennamen als Schema-Vertrag erhalten.
