# ISCY V23.7.2 / Rust 0.3.0

ISCY ist eine ISMS-/Cybersecurity-Plattform mit ISO 27001-, NIS2- und KRITIS-Unterstuetzung, Incident-/Meldeworkflow, Product Security, Zero-Trust-Agent-Posture, lokalem CVE-Enrichment und lokalem LLM-Betrieb.

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
- `/zero-trust/`
- `/catalog/`
- `/requirements/`
- `/assessments/`
- `/organizations/`
- `/risks/`
- `/incidents/`
- `/evidence/`
- `/reports/`
- `/roadmap/`
- `/assets/`
- `/imports/`
- `/processes/`
- `/product-security/`
- `/cves/`
- `/admin/users/`

Incidents werden als Rust-Fallakten unter `/incidents/` gefuehrt. Detailseiten unter `/incidents/{id}` erlauben die Bearbeitung von Typ, Runbook, Status, Severity, Meldezeitpunkten und Behoerdenreferenz; Statuswechsel, Anlage und incidentbezogene Evidence-Uploads werden als Timeline-/Audit-Events in der Fallakte dokumentiert. Verknuepfte Evidence wird direkt in der Fallakte angezeigt und kann dort hochgeladen werden. Das NIS2-Meldepaket kann als Markdown, HTML oder PDF ueber `/incidents/{id}/nis2-export`, `/incidents/{id}/nis2-export.html`, `/incidents/{id}/nis2-export.pdf` sowie die entsprechenden `/api/v1/incidents/{id}/...` Endpunkte exportiert werden.

## Zero-Trust Agent

ISCY `0.3.0` enthaelt einen read-only Agent fuer Windows, macOS und Linux. Der Agent meldet Inventar, Heartbeats sowie OS-/MDM-/EDR- und Zero-Trust-Findings an die Rust-Plattform. Die Plattform stellt dazu `/zero-trust/` sowie API-Endpunkte unter `/api/v1/agents/...` bereit.

Die produktive Agent-Aufnahme ist gehaertet:

- Admins erstellen Enrollment-Token ueber `POST /api/v1/agents/enrollment-tokens`.
- Agenten enrollen mit `x-iscy-agent-enrollment-token` und erhalten einmalig ein Agent-Secret.
- Heartbeats und Findings koennen danach mit `x-iscy-agent-secret` gemeldet werden.
- Optional kann ein mTLS-Client-Zertifikat per Fingerprint an Token und Agent gebunden werden.

Die lokalen Collector-Module pruefen read-only:

- OS-Baseline und Patch-Inventar
- Datentraeger-Verschluesselung: BitLocker, FileVault oder LUKS
- Secure Boot beziehungsweise Plattformintegritaet
- Host-Firewall
- MDM-/Endpoint-Management-Signale
- Endpoint Protection beziehungsweise EDR-Signale

Die Webansicht `/zero-trust/` zeigt neben Score, Devices und Findings jetzt auch den naechsten fachlichen Fokus, Score-Badges und Severity-Badges fuer eine schnellere Priorisierung.

Lokaler Payload-Test:

```bash
nix run .#iscy-agent -- --self-test
```

Meldung an eine lokale Instanz:

```bash
ISCY_BACKEND_URL=http://127.0.0.1:9000 \
ISCY_TENANT_ID=1 \
ISCY_USER_ID=1 \
nix run .#iscy-agent
```

Token-basierter Agent-Lauf:

```bash
ISCY_BACKEND_URL=http://127.0.0.1:9000 \
ISCY_TENANT_ID=1 \
ISCY_AGENT_ENROLLMENT_TOKEN=<token> \
nix run .#iscy-agent
```

Windows-Build aus dem Rust-Code:

```powershell
cargo build --release --manifest-path rust/iscy-backend/Cargo.toml --bin iscy-agent
.\rust\iscy-backend\target\release\iscy-agent.exe --self-test
```

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
- GUI-Screenshots: `docs/GUI_SCREENSHOTS.md`
- Zero-Trust-Agent: `docs/ZERO_TRUST_AGENT.md`
- Proxmox-Produktiv-Runbook: `docs/PROXMOX_PRODUCTION_RUNBOOK.md`
- Rust-Cutover-Status: `docs/RUST_CUTOVER_STATUS.md`
- Rust-Abloese-Checkliste: `docs/RUST_ABLOESE_CHECKLISTE.md`
