# Support Matrix

## Officially Supported Host Modes

| Mode | Host OS | Runtime | Database | CVE LLM mode | Status |
|---|---|---|---|---|---|
| Bare metal / Nix | NixOS or Linux with Nix flakes | Rust via `nix run .#iscy-backend` | PostgreSQL 16 standard; SQLite single-instance dev; PostgreSQL 18.4 compatibility-tested | deterministic Rust stub | Preferred |
| Bare metal / Cargo | Ubuntu 24.04 LTS or current Debian derivatives | Rust stable | PostgreSQL 16 standard; SQLite single-instance dev; PostgreSQL 18.4 compatibility-tested | deterministic Rust stub | Supported |
| Docker / Compose | Linux host with Docker Engine + Compose | Rust container | PostgreSQL 16 standard | deterministic Rust stub; optional compatibility overlay | Preferred for shared envs |

PostgreSQL 15 is not part of the current release validation contract. PostgreSQL 18.4 is a tested logical forward-restore/application-compatibility path, not the production default and not an in-place upgrade promise.

## Deployment Profiles

| Profile | Files | Reverse proxy | Persistent volumes | Target |
|---|---|---|---|---|
| Development | `docker-compose.yml` + `docker-compose.override.yml` | no | db, media | local dev |
| Stage | `docker-compose.yml` + `docker-compose.stage.yml` | nginx | db, media | shared test / UAT |
| Production | `docker-compose.yml` + `docker-compose.prod.yml` | nginx | db, media | controlled production |
| Production + LLM compatibility overlay | `docker-compose.yml` + `docker-compose.prod.yml` + `docker-compose.llm.yml` | nginx | db, media | CVE LLM-stub/runtime metadata only; no model service is started |

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
| Backend intake | Rust API under `/api/v1/agents/...` | Supported in ISCY Rust `0.3.22` |
| Web overview | `/zero-trust/` | Supported in ISCY Rust `0.3.22` |
| Agent binary | `nix run .#iscy-agent` or Cargo binary `iscy-agent` | MVP |
| Windows deployment | manual / Scheduled-Task example / Intune-style handoff | MVP deployment example |
| macOS deployment | manual / LaunchDaemon example / Jamf-style handoff | MVP deployment example |
| Linux deployment | manual / systemd service+timer example | MVP deployment example |
| NixOS deployment | declarative module under `deploy/agent/nixos/` | MVP deployment example |
| Automatic remediation | not enabled | Not supported |
| Secret, browser or packet capture | intentionally excluded | Not supported |

## CPU / Architecture Assumptions

| Item | Supported |
|---|---|
| CPU arch | x86_64 |
| ARM64 | not yet officially tested |
| GPU offload | not active in the current deterministic LLM-stub path |

## CVE LLM / Model Integration Status

| Component | Current status |
|---|---|
| CVE `run_llm` workflow | Implemented as deterministic Rust stub |
| `POST /api/v1/llm/generate` | Implemented; returns deterministic stub output |
| `/cves/llm-test/` | Implemented; tests the same stub path |
| Model-backed local inference | Not implemented in current `main` |
| RAG / embeddings / retrieval | Not implemented in current `main` |
| `LOCAL_LLM_MODEL_NAME` | Metadata/display label; does not prove that a model executed |
| Historical llama-cpp/Qwen path | Legacy pre-Rust-cutover implementation; not the current runtime |

## Backup / Restore Baseline

| Area | Mechanism | Script |
|---|---|---|
| PostgreSQL | `pg_dump` / `psql` via compose | `scripts/backup_compose.sh`, `scripts/restore_compose.sh` |
| Media / evidence | tar archive from mounted volume | same scripts |

## Not Officially Supported

- Python/Django runtime deployment
- model-backed LLM inference or RAG in the current runtime
- unmanaged host installs without Rust toolchain or Nix
- undocumented OS upgrades without smoke test / CI validation

## Upgrade Policy Recommendation

After any host OS, Rust toolchain, compiler, PostgreSQL or container base update:

1. run `cargo test --manifest-path rust/iscy-backend/Cargo.toml`
2. run `cargo clippy --manifest-path rust/iscy-backend/Cargo.toml --all-targets -- -D warnings`
3. run `make rust-smoke`
4. validate `docker compose -f docker-compose.yml -f docker-compose.prod.yml config`
5. only then promote to shared/stable environment
