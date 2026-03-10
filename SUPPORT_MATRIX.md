# Support Matrix

## Officially supported host modes

| Mode | Host OS | Python | Database | Local LLM | Status |
|---|---|---:|---|---|---|
| Bare metal / venv | Ubuntu 24.04 LTS | 3.12 | PostgreSQL 15/16 or SQLite (dev) | Optional | Supported |
| Bare metal / venv | Debian 12 | 3.11/3.12 | PostgreSQL 15/16 or SQLite (dev) | Core app only officially; local LLM best-effort | Supported (core) |
| Docker / Compose | Any Linux host with Docker Engine + Compose | bundled | PostgreSQL 16 container | Optional via `docker-compose.llm.yml` | Preferred |

## Deployment profiles

| Profile | Files | Reverse proxy | Persistent volumes | Target |
|---|---|---|---|---|
| Development | `docker-compose.yml` + `docker-compose.override.yml` | no | db, media, static | local dev |
| Stage | `docker-compose.yml` + `docker-compose.stage.yml` | nginx | db, media, static, model | shared test / UAT |
| Production | `docker-compose.yml` + `docker-compose.prod.yml` | nginx | db, media, static, model | controlled production |
| Production + local LLM | `docker-compose.yml` + `docker-compose.prod.yml` + `docker-compose.llm.yml` | nginx | db, media, static, model | product security / CVE enrichment |

## CPU / architecture assumptions

| Item | Supported |
|---|---|
| CPU arch | x86_64 |
| ARM64 | not yet officially tested |
| GPU offload | optional, not part of the official support baseline |

## Local LLM support

| Component | Supported baseline |
|---|---|
| Backend | `llama-cpp-python` |
| Model family | Qwen3 GGUF |
| Recommended model | `Qwen3-8B.Q4_K_M.gguf` |
| Build path | `clang` + OpenBLAS + `g++-14` / `libstdc++-14-dev` |
| Model download | `scripts/download_local_llm.py` or `make llm-download` |

## Backup / restore baseline

| Area | Mechanism | Script |
|---|---|---|
| PostgreSQL | `pg_dump` / `psql` via compose | `scripts/backup_compose.sh`, `scripts/restore_compose.sh` |
| Media / evidence | tar archive from mounted volume | same scripts |
| Static / models | tar archive from mounted volume | same scripts |

## Not officially supported

- Random Debian derivatives without testing
- Python minor versions outside the documented range
- musl-based Linux runtimes for the current `llama-cpp-python` wheel path
- unmanaged host installs without `.venv`
- undocumented OS upgrades without smoke test / CI validation

## Upgrade policy recommendation

After any host OS, Python, compiler, PostgreSQL or `llama-cpp-python` update:

1. run `python manage.py check`
2. run migrations on a copy/staging database
3. run `python manage.py check_local_llm`
4. run a CVE enrichment smoke test
5. validate `docker compose -f docker-compose.yml -f docker-compose.prod.yml config`
6. only then promote to shared/stable environment
