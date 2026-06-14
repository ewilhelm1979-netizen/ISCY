# Support Matrix

## Officially Supported Host Modes

| Mode | Host OS | Runtime | Database | Local LLM | Status |
|---|---|---|---|---|---|
| Bare metal / Nix | NixOS or Linux with Nix flakes | Rust via `nix run .#iscy-backend` | PostgreSQL 15/16 or SQLite dev | Optional | Preferred |
| Bare metal / Cargo | Ubuntu 24.04 LTS or current Debian derivatives | Rust stable | PostgreSQL 15/16 or SQLite dev | Optional | Supported |
| Docker / Compose | Linux host with Docker Engine + Compose | Rust container | PostgreSQL 16 container | Optional via `docker-compose.llm.yml` | Preferred for shared envs |

## Deployment Profiles

| Profile | Files | Reverse proxy | Persistent volumes | Target |
|---|---|---|---|---|
| Development | `docker-compose.yml` + `docker-compose.override.yml` | no | db, media | local dev |
| Stage | `docker-compose.yml` + `docker-compose.stage.yml` | nginx | db, media | shared test / UAT |
| Production | `docker-compose.yml` + `docker-compose.prod.yml` | nginx | db, media | controlled production |
| Production + local LLM | `docker-compose.yml` + `docker-compose.prod.yml` + `docker-compose.llm.yml` | nginx | db, media | product security / CVE enrichment |

## Product-Security Support

| Capability | Supported baseline | Status |
|---|---|---|
| CSAF import | JSON upload with offline profile validation and import history | Supported |
| CycloneDX/SPDX SBOM import | JSON upload, component extraction and CPE/PURL matching | Supported |
| CVE-Asset correlation | Suggested, accepted and rejected correlation workflow | Supported |
| Generated CVE risk work | Accepted correlations can create risk and roadmap work with Evidence-Key linkage | Supported |
| Review queue | Product-Security UI shows open CVE reviews, missing Evidence, missing risks, filters and bulk review actions | Supported |
| Evidence return flow | Evidence uploads started from Product Security, Risk or Roadmap return to the source page | Supported |

## Zero-Trust Agent Support

| Component | Supported baseline | Status |
|---|---|---|
| Backend intake | Rust API under `/api/v1/agents/...` | Supported in ISCY Rust `0.2.0` |
| Web overview | `/zero-trust/` | Supported in ISCY Rust `0.2.0` |
| Agent binary | `nix run .#iscy-agent` or Cargo binary `iscy-agent` | MVP |
| Windows deployment | manual, script, Intune-style wrapper | MVP target |
| macOS deployment | manual, script, Jamf/MDM-style wrapper | MVP target |
| Linux deployment | manual, systemd service/timer wrapper | MVP target |
| Automatic remediation | not enabled | Not supported |
| Secret, browser or packet capture | intentionally excluded | Not supported |

## CPU / Architecture Assumptions

| Item | Supported |
|---|---|
| CPU arch | x86_64 |
| ARM64 | not yet officially tested |
| GPU offload | optional, not part of the official support baseline |

## Local LLM Support

| Component | Supported baseline |
|---|---|
| Backend | Rust service |
| Model family | configured through Rust runtime variables |
| Build path | Rust stable, OpenSSL, PostgreSQL/SQLite client libs |

## Backup / Restore Baseline

| Area | Mechanism | Script |
|---|---|---|
| PostgreSQL | `pg_dump` / `psql` via compose | `scripts/backup_compose.sh`, `scripts/restore_compose.sh` |
| Media / evidence | tar archive from mounted volume | same scripts |

## Not Officially Supported

- Python/Django runtime deployment
- unmanaged host installs without Rust toolchain or Nix
- undocumented OS upgrades without smoke test / CI validation

## Upgrade Policy Recommendation

After any host OS, Rust toolchain, compiler, PostgreSQL or container base update:

1. run `cargo test --manifest-path rust/iscy-backend/Cargo.toml`
2. run `cargo clippy --manifest-path rust/iscy-backend/Cargo.toml --all-targets -- -D warnings`
3. run `make rust-smoke`
4. validate `docker compose -f docker-compose.yml -f docker-compose.prod.yml config`
5. only then promote to shared/stable environment
