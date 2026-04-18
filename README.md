# ISCY V23.5

Django-basierte ISMS-/Cybersecurity-Plattform mit ISO 27001-, NIS2- und KRITIS-Unterstützung, Product Security, lokalem CVE-Enrichment und lokalem LLM-Betrieb über einen Rust-Service.

## Lokale Entwicklung auf NixOS

Für NixOS und andere lokale Linux-Setups ist jetzt ein reproduzierbarer Dev-Shell-Pfad vorhanden:

```bash
nix develop
python -m venv .venv
source .venv/bin/activate
python -m ensurepip --upgrade
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
mkdir -p static media staticfiles models
cp .env.example .env
python manage.py migrate
python manage.py check
python manage.py runserver
```

Falls du den lokalen Rust-LLM-Service aktivieren willst:

```bash
nix develop
source .venv/bin/activate
make rust-build
make rust-run
```

Der Dev-Shell in `flake.nix` bringt die Build- und Laufzeitbibliotheken für PostgreSQL, SQLite und den lokalen Rust-Service mit.

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
- erweitertes **CI** für Django, LLM-Runtime und Compose-Dateien

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

Zusätzlich stellt `rust-backend` eine erste Rust-Weboberflächen-Route-Map für die bisherigen Django-Mountpoints bereit (z. B. `/dashboard/`, `/reports/`, `/cves/`) als Migrationsgrundlage.

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
- ohne Docker -> lokaler Fallback via `./start.sh`

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
- `ASSET_INVENTORY_BACKEND=rust_service`
- `PROCESS_REGISTER_BACKEND=rust_service`
- `RUST_STRICT_MODE=True` (erzwingt Rust-Backends ohne Fallback)

Danach kann weiter wie gewohnt gestartet werden:

```bash
RUST_BACKEND_URL=http://127.0.0.1:9000 VERIFY_LOCAL_LLM=1 ./start.sh
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
Außerdem ist der Cutover-Default jetzt `RUST_STRICT_MODE=True`, damit Risk-/Guidance-/Report-Pfade ohne Rust-Backend nicht still auf Legacy-Fallbacks zurückfallen.

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
Rust-Ablöse-Checkliste: `docs/RUST_ABLOESE_CHECKLISTE.md`.
Rust-Webstack-Umbauplan: `docs/RUST_WEBSTACK_REWRITE_PLAN.md`.

PDF-Export:

```bash
make handbook-pdf
```

Das Skript erzeugt `docs/ISCY_Handbuch.pdf`.

## CI

GitHub Actions prüft:

- Django-Konfiguration, Migrationen, Seeds und Health-Endpoints
- Rust-Backend-Tests (inkl. LLM-/NVD-API-Endpunkte)
- Validierung aller Compose-Dateien inklusive Stage und Production

## Lokale Kurzbefehle

```bash
make local-bootstrap
make local-check
make local-test
make team-test
```

`make local-test` deckt aktuell die Basis-Gesundheitschecks, mandantenbezogene Report-Views und die Product-Security-Routen ab.
`make team-test` entspricht einem breiteren Team-Check (Django-Check + zentrale Testpakete inkl. Guidance und Vulnerability-Intelligence).

## Support-Matrix

Siehe [`SUPPORT_MATRIX.md`](SUPPORT_MATRIX.md).
