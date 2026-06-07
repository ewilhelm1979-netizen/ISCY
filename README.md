# ISCY V23.5

ISCY ist eine ISMS-/Cybersecurity-Plattform mit ISO 27001-, NIS2- und KRITIS-Unterstuetzung, Product Security, lokalem CVE-Enrichment und lokalem LLM-Betrieb.

Der Runtime-Cutover nach Rust ist abgeschlossen: Die produktive Anwendung laeuft ueber den Rust-Axum-Service in `rust/iscy-backend`. Die fruehere Django/Python-Anwendung, ihre Templates, Settings, Requirements und Startpfade wurden aus dem Repository entfernt.

## Lokaler Start

```bash
./start.sh
```

Danach ist die Rust-Weboberflaeche unter `http://127.0.0.1:9000/login/` erreichbar.

Demo-Login:

```text
admin / Admin123!
```

Ohne Wrapper:

```bash
nix run .#iscy-backend -- init-demo
DATABASE_URL=sqlite:///db.sqlite3 RUST_BACKEND_BIND=127.0.0.1:9000 nix run .#iscy-backend
```

Healthcheck:

```bash
curl -fsS http://127.0.0.1:9000/health
```

## Docker Compose

Development:

```bash
cp .env.development.example .env
make dev-up
```

App: `http://127.0.0.1:9000`

Stage:

```bash
cp .env.stage.example .env
make stage-up
```

App via Nginx: `http://127.0.0.1:8080`

Production:

```bash
cp .env.production.example .env
make prod-readiness
make prod-up
```

App via Nginx: `http://127.0.0.1`

## Rust Backend

Wichtige lokale Befehle:

```bash
make rust-build
make rust-test
make rust-smoke
make team-test
```

`make team-test` ist jetzt ein Rust-only Gate aus Rust-Tests und HTTP-Smoke.

Das Backend stellt serverseitige Weboberflaechen und APIs fuer die migrierten Produktbereiche bereit, unter anderem:

- `/dashboard/`
- `/navigator/`
- `/catalog/`
- `/requirements/`
- `/assessments/`
- `/organizations/`
- `/risks/`
- `/evidence/`
- `/reports/`
- `/roadmap/`
- `/assets/`
- `/imports/`
- `/processes/`
- `/product-security/`
- `/cves/`
- `/admin/users/`

## Vulnerability Feeds

Rust-CLI:

```bash
RUST_BACKEND_URL=http://127.0.0.1:9000 cargo run --manifest-path rust/iscy-backend/Cargo.toml --bin iscy-canary -- import-collection --has-kev --max-pages 2
RUST_BACKEND_URL=http://127.0.0.1:9000 cargo run --manifest-path rust/iscy-backend/Cargo.toml --bin iscy-canary -- sync-recent --hours 24 --max-pages 2
RUST_BACKEND_URL=http://127.0.0.1:9000 cargo run --manifest-path rust/iscy-backend/Cargo.toml --bin iscy-canary -- import CVE-2026-1234
```

NVD-Konfiguration:

```text
NVD_API_BASE_URL=https://services.nvd.nist.gov
NVD_API_KEY=
```

## CI

GitHub Actions prueft:

- Rust-Formatierung
- Clippy
- Rust-Backend-Tests
- Rust-DB-/HTTP-Smoke
- Nix-Rust-App-Smoke
- Compose-Konfigurationen fuer Development, Stage, Production und LLM-Profil

## Dokumentation

- Handbuch: `docs/ISCY_Handbuch.md`
- Proxmox-Produktiv-Runbook: `docs/PROXMOX_PRODUCTION_RUNBOOK.md`
- Rust-Cutover-Status: `docs/RUST_CUTOVER_STATUS.md`
- Rust-Abloese-Checkliste: `docs/RUST_ABLOESE_CHECKLISTE.md`
