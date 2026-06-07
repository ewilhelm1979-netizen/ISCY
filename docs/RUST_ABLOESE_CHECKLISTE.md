# Rust-Abloese-Checkliste

Stand: 2026-06-07

## Ziel

Komplette Abloesung der produktiven Python/Django-Runtime durch Rust.

## Abschlussstatus

- [x] Rust-Axum-Service ist die einzige produktive App-Runtime.
- [x] Docker Compose baut und startet den Rust-Service als `app`.
- [x] Stage/Production-Nginx proxyt auf den Rust-Service.
- [x] Lokaler Start laeuft ueber `./start.sh` und `nix run .#iscy-backend`.
- [x] CI prueft Rust-Formatierung, Clippy, Rust-Tests, Rust-Smoke, Nix-Smoke und Compose-Konfiguration.
- [x] Django-App-Code wurde entfernt.
- [x] Django-Templates wurden entfernt.
- [x] `manage.py`, Django-Settings und ASGI/WSGI wurden entfernt.
- [x] Python-Requirements wurden entfernt.
- [x] Python-Dockerfile und Python-Entrypoint wurden entfernt.
- [x] Makefile-Ziele verweisen nicht mehr auf Django-Checks oder Django-Tests.
- [x] Env-Beispiele enthalten nur noch Rust-/Compose-relevante Runtime-Schluessel.

## Abnahmekriterien

1. Kein produktiver Request-Pfad ueber Django.
2. Kein Python-Dependency-Install fuer Runtime oder CI.
3. Rust-Healthchecks und Rust-Integrationstests sind verbindlich.
4. Neue Features werden in Rust-Web/API/CLI/Stores umgesetzt.

Status: **erfuellt**.
