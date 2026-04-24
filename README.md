# ISCY V23.5

ISCY ist eine ISMS-/Cybersecurity-Plattform mit ISO 27001-, NIS2- und KRITIS-Unterstuetzung, Product Security, lokalem CVE-Enrichment und lokalem LLM-Betrieb. Der produktive Cutover laeuft auf einen Rust-Axum-Service; lokale Starts, Rust-Sessions und CI-Smokes laufen inzwischen Rust-first, Django/Python bleibt vorerst Legacy-Kompatibilitaet bis zur finalen Dateientfernung.

## Lokale Entwicklung auf NixOS

Fuer NixOS und andere lokale Linux-Setups ist der bevorzugte lokale Pfad jetzt Rust-only:

```bash
./start.sh
```

Danach ist die Rust-Weboberflaeche unter `http://127.0.0.1:9000/login/` erreichbar. Der Rust-Demo-Login lautet `admin / Admin123!`; die Rust-Userverwaltung fuer Anlage, Bearbeitung, Rollen-/Gruppen-/Direktrechtewechsel und Passwortreset liegt unter `http://127.0.0.1:9000/admin/users/`.

Explizit ohne Wrapper:

```bash
nix run .#iscy-backend -- init-demo
DATABASE_URL=sqlite:///db.sqlite3 RUST_BACKEND_BIND=127.0.0.1:9000 nix run .#iscy-backend
```

Der Dev-Shell in `flake.nix` bringt die Build- und Laufzeitbibliotheken für PostgreSQL, SQLite und den lokalen Rust-Service mit.

## Rust-Backend auf NixOS starten

Der Rust-Service kann direkt aus dem Repository-Root gestartet werden:

```bash
nix run .#iscy-backend
```

Mit expliziter lokaler Bind-Adresse und SQLite-Datenbank:

```bash
RUST_BACKEND_BIND=127.0.0.1:9000 DATABASE_URL=sqlite:///db.sqlite3 nix run .#iscy-backend
```

Eine lokale Rust-Demo-Datenbank ohne Django-Migration initialisieren:

```bash
DATABASE_URL=sqlite:///db.sqlite3 nix run .#iscy-backend -- init-demo
RUST_BACKEND_BIND=127.0.0.1:9000 DATABASE_URL=sqlite:///db.sqlite3 nix run .#iscy-backend
```

Healthcheck:

```bash
curl -fsS http://127.0.0.1:9000/health
```

Der lokale Wrapper startet denselben Rust-only-Pfad und initialisiert vorher die Rust-Datenbank:

```bash
./start.sh
```

Login im Browser: `http://127.0.0.1:9000/login/` mit `admin / Admin123!`. Danach ist `/admin/users/` fuer User-Liste, User-Anlage, Bearbeitung, Rollen-/Gruppen-/Direktrechtewechsel und Passwortreset ueber Rust verfuegbar.

## Neu in V23.5

- produktionsnähere **Docker-/Compose-Profile** für Development, Stage und Production
- **Nginx Reverse Proxy** für Stage/Production
- persistente Volumes für:
  - PostgreSQL
  - Media / Evidence
  - Static
  - lokale Modelle
- **Backup-/Restore-Skripte** für Compose-Deployments
- **Support-Matrix** für offiziell getestete Plattformen und Betriebsmodi
- erweitertes **CI** fuer Rust-Tests, Rust-Bootstrap-Smoke, Nix-Rust-Smoke und Compose-Dateien

## Kernmodule

- ISMS- und Umsetzungsplanung
- NIS2-/KRITIS-Relevanzprüfung
- Product Security / CRA / AI Act / IEC 62443 / ISO-SAE 21434
- CVE- und Vulnerability-Intelligence
- lokales LLM-Enrichment mit Qwen3 GGUF
- EPSS-/KEV-/NIS2-kontextualisierte CVE-Bewertung mit Git-/Repository-Vorbereitung
- Reporting, Dashboard, Roadmap, Evidence, Risks, Requirements

## Rust-Backend-Pfad (Rewrite-Vorbereitung)

Der Rust-Service unter `rust/iscy-backend` ist im Compose-Stack als `rust-backend` integrierbar (Health + NVD + LLM-Endpoint als Startpunkt für eine schrittweise Migration).

```bash
make rust-build
make rust-test
make rust-run
```

Zusätzlich stellt `rust-backend` Rust-Weboberflächen für zentrale bisherige Django-Mountpoints bereit (z. B. `/dashboard/`, `/reports/`, `/imports/`, `/admin/users/`, `/cves/`) als Migrationsgrundlage.

## Vordefinierte Security-Template-Pakete (im Fragenkatalog)

Im Seed-Katalog sind zusaetzliche, sofort nutzbare Pakete fuer folgende Schwerpunkte enthalten:

- Cloud-Security (inkl. Cloud-IAM/Schluessel-Absicherung)
- Windows-Hardening (Baseline-orientiert)
- OT-/Produktions-Security (inkl. OPC UA, MES, SCADA, Produktions-Identitaeten)

## Betriebsmodi

### Einfachster Start (empfohlen)

Wenn es "einfach nur laufen" soll:

```bash
make easy-start
```

Der Wrapper `scripts/easy_start.sh` nimmt automatisch den einfacheren Weg:

- mit Docker vorhanden -> `make dev-up`
- ohne Docker -> lokaler Rust-Fallback via `./start.sh`

### 1. Lokale Entwicklung

```bash
cp .env.development.example .env
make dev-up
```

App: `http://127.0.0.1:8000`

**Docker-Funktion (einfach):**

- `make docker-check` prueft, ob alle Compose-Dateien gueltig sind.
- `make docker-smoke` startet eine kleine Funktionsprobe (DB + Migration + Django-Check) und beendet sie wieder.

### 2. Stage

```bash
cp .env.stage.example .env
make stage-up
```

App: `http://127.0.0.1:8080`

### 3. Production ohne lokales LLM

```bash
cp .env.production.example .env
make prod-readiness
make prod-up
```

App: `http://127.0.0.1`

### 4. Production mit lokalem LLM

```bash
cp .env.production.example .env
make prod-up-llm
```

Hinweis: Der Rust-LLM-Pfad nutzt den Service `rust-backend` im Compose-Stack; `make llm-download` ist nur noch ein kompatibler No-Op.

## Backup / Restore

Backup erzeugen:

```bash
ENV_FILE=.env.production ./scripts/backup_compose.sh
```

Restore ausführen:

```bash
ENV_FILE=.env.production ./scripts/restore_compose.sh backups/<timestamp>
```

## Lokales LLM ohne Docker (Rust-Service)

Der funktionierende Referenzpfad auf Ubuntu 24.04 ist:

- Rust Toolchain (`rustup`, `cargo`)
- laufender `rust/iscy-backend` Service
- `LOCAL_LLM_BACKEND=rust_service`
- `LOCAL_LLM_RUST_URL=http://127.0.0.1:9000`
- `RISK_SCORING_BACKEND=rust_service`
- `GUIDANCE_SCORING_BACKEND=rust_service`
- `REPORT_SUMMARY_BACKEND=rust_service`
- `REPORT_SNAPSHOT_BACKEND=rust_service`
- `DASHBOARD_SUMMARY_BACKEND=rust_service`
- `CATALOG_BACKEND=rust_service`
- `REQUIREMENTS_BACKEND=rust_service`
- `ASSET_INVENTORY_BACKEND=rust_service`
- `PROCESS_REGISTER_BACKEND=rust_service`
- `RISK_REGISTER_BACKEND=rust_service`
- `EVIDENCE_REGISTER_BACKEND=rust_service`
- `ASSESSMENT_REGISTER_BACKEND=rust_service`
- `ROADMAP_REGISTER_BACKEND=rust_service`
- `WIZARD_RESULTS_BACKEND=rust_service`
- `IMPORT_CENTER_BACKEND=rust_service`
- `PRODUCT_SECURITY_BACKEND=rust_service`
- `RUST_ONLY_MODE=True` (verbietet lokale Legacy-Fallbacks fuer migrierte Backends)
- `RUST_STRICT_MODE=True` (erzwingt Rust-Backends ohne Fallback)

Danach kann Rust direkt gestartet werden:

```bash
./start.sh
```

Auf NixOS bitte bevorzugt ueber `nix develop` arbeiten.
Auf Debian/Ubuntu und aktuellen apt-basierten Derivaten kann der Rust-Service direkt per `cargo run` gestartet werden.

## Lokale Vulnerability-Feeds

Für lokale EPSS-/KEV-Anreicherung und Git-/Scanner-Vorbereitung stehen Management-Commands bereit:

```bash
python3 manage.py import_epss_feed /pfad/zu/epss_scores.csv
python3 manage.py import_kev_catalog /pfad/zu/known_exploited_vulnerabilities.json --reset-missing
RUST_BACKEND_URL=http://127.0.0.1:9000 iscy-canary import-collection --has-kev --max-pages 2
RUST_BACKEND_URL=http://127.0.0.1:9000 iscy-canary sync-recent --hours 24 --max-pages 2
RUST_BACKEND_URL=http://127.0.0.1:9000 iscy-canary import CVE-2026-1234 CVE-2026-5678
RUST_BACKEND_URL=http://127.0.0.1:9000 iscy-canary import CVE-2026-1234 --skip-healthcheck
iscy-canary parity --out-dir reports/canary CVE-2026-1234 CVE-2026-5678
iscy-canary trend --reports-dir reports/canary --window 30 --max-mismatch-rate 0.5 --enforce-gate
python3 manage.py import_cve_context_csv <tenant-slug> /pfad/zu/cve_context.csv --user-id <id>
```

Ab V23.5 ist der Vulnerability-Import standardmäßig auf **Rust-only-Normalisierung** gestellt (`VULN_INTEL_RUST_ONLY=True`).
Wenn `RUST_BACKEND_URL` fehlt, brechen CVE-Upserts absichtlich mit Fehler ab, um Mischbetrieb zu vermeiden.
NVD-Collection-Imports laufen im Rust-only-Modus nicht mehr über den Python-Service; die Django-Commands `import_nvd_cves` und `sync_nvd_recent` sind Kompatibilitäts-Wrapper um die Rust-CLI.
Außerdem ist der Cutover-Default jetzt `RUST_ONLY_MODE=True` und `RUST_STRICT_MODE=True`, damit migrierte Pfade ohne Rust-Backend nicht still auf Legacy-Fallbacks zurückfallen.

Direkte NVD-Collection-Imports koennen optional mit `--cve-tag`, `--cpe-name`, `--last-mod-start-date` und `--last-mod-end-date` gefiltert werden.
`sync_nvd_recent` ist fuer regelmaessige Jobs gedacht (z. B. stündlich/taeglich) und nutzt automatisch `lastModStartDate/lastModEndDate`.

`import_cve_context_csv` ist für externe Git-/SBOM-/Scanner-Pipelines gedacht. Wichtige CSV-Spalten sind z. B.:
`cve_id`, `product`, `release`, `component`, `repository_name`, `repository_url`, `git_ref`, `source_package`, `source_package_version`, `exposure`, `asset_criticality`, `nis2_relevant`.

## Handbuch

Ein fachliches Handbuch fuer ISCY liegt in `docs/ISCY_Handbuch.md`.
Proxmox-Produktiv-Runbook: `docs/PROXMOX_PRODUCTION_RUNBOOK.md`.
Completion-Backlog: `docs/PROJECT_COMPLETION_BACKLOG.md`.
Rust-Rewrite-Roadmap: `docs/RUST_REWRITE_ROADMAP.md`.
Rust-Cutover-Plan: `docs/RUST_CUTOVER_PLAN.md`.
Rust-Cutover-Status: `docs/RUST_CUTOVER_STATUS.md`.
Rust-Ablöse-Checkliste: `docs/RUST_ABLOESE_CHECKLISTE.md`.
Rust-Webstack-Umbauplan: `docs/RUST_WEBSTACK_REWRITE_PLAN.md`.

PDF-Export:

```bash
make handbook-pdf
```

Das Skript erzeugt `docs/ISCY_Handbuch.pdf`.

## CI

GitHub Actions prüft:

- Rust-Formatierung, Clippy und Rust-Backend-Tests
- Rust-DB-/Bootstrap-Smoke inklusive Healthcheck, Rust-Session-Cookie und zentralen API-Probes
- Nix-Rust-App-Smoke über das flake-basierte Backend
- Validierung aller Compose-Dateien inklusive Stage und Production

## Lokale Kurzbefehle

```bash
make local-bootstrap
make local-check
make local-test
make team-test
make rust-smoke
```

`make local-test` deckt aktuell die Basis-Gesundheitschecks, mandantenbezogene Report-Views und die Product-Security-Routen ab.
`make team-test` ist der Legacy-Django-Kompatibilitaetscheck.
`make rust-smoke` ist der Rust-only Betriebs-Smoke mit DB-Bootstrap, Healthcheck, Rust-Session-Cookie, Dashboard ohne Query-Kontext, Evidence-Upload, Import-Center-Preview/CSV-Probe und zentralen API-Probes.

## Support-Matrix

Siehe [`SUPPORT_MATRIX.md`](SUPPORT_MATRIX.md).
