# ISMS Planner V23.4

Django-basierte ISMS-/Cybersecurity-Plattform mit ISO 27001-, NIS2- und KRITIS-Unterstützung, Product Security, lokalem CVE-Enrichment und lokalem LLM-Betrieb über `llama-cpp-python`.

## Neu in V23.4

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
- Reporting, Dashboard, Roadmap, Evidence, Risks, Requirements

## Betriebsmodi

### 1. Lokale Entwicklung

```bash
cp .env.development.example .env
make dev-up
```

App: `http://127.0.0.1:8000`

### 2. Stage

```bash
cp .env.stage.example .env
make stage-up
```

App: `http://127.0.0.1:8080`

### 3. Production ohne lokales LLM

```bash
cp .env.production.example .env
make prod-up
```

App: `http://127.0.0.1`

### 4. Production mit lokalem LLM

```bash
cp .env.production.example .env
make llm-download
make prod-up-llm
```

## Backup / Restore

Backup erzeugen:

```bash
ENV_FILE=.env.production ./scripts/backup_compose.sh
```

Restore ausführen:

```bash
ENV_FILE=.env.production ./scripts/restore_compose.sh backups/<timestamp>
```

## Lokales LLM ohne Docker

Der funktionierende Referenzpfad auf Ubuntu 24.04 ist:

- `clang`
- `libopenblas-dev`
- `g++-14`
- `libstdc++-14-dev`
- `llama-cpp-python` per Source-Build
- `Qwen3-8B.Q4_K_M.gguf`

Danach kann weiter wie gewohnt gestartet werden:

```bash
AUTO_YES=1 INSTALL_LOCAL_LLM=1 DOWNLOAD_LOCAL_LLM=1 VERIFY_LOCAL_LLM=1 ./start.sh
```

## CI

GitHub Actions prüft:

- Django-Konfiguration, Migrationen, Seeds und Health-Endpoints
- Build der lokalen `llama-cpp-python` Runtime auf Ubuntu 24.04
- Validierung aller Compose-Dateien inklusive Stage und Production

## Support-Matrix

Siehe [`SUPPORT_MATRIX.md`](SUPPORT_MATRIX.md).
