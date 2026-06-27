# ISCY

[Deutsch](README.de.md)

**Self-hosted open-source cybersecurity governance for ISMS, product security, AI governance, and regulatory evidence.**

ISCY connects risks, controls, assets, incidents, evidence, suppliers, product security, SBOM, CSAF, VEX, CVE, AI governance, and operational posture in one auditable platform.

It is designed for organizations working with frameworks and regulations such as ISO 27001, NIS2, DORA, the Cyber Resilience Act, the EU AI Act, GDPR, and KRITIS.

ISCY follows a local-first and privacy-conscious approach. The production runtime is implemented in Rust with Axum and can be operated in NixOS or Docker-based environments.

> **Project status:** ISCY is actively developed and is currently in an early community-adoption phase. Interfaces, data models, and operational procedures may continue to evolve.

## Core capabilities

- ISMS risk, control, requirement, asset, process, and evidence management
- Security-incident case files and regulatory reporting workflows
- Product-security and vulnerability-management workflows
- SBOM, CSAF, SPDX, CycloneDX, VEX, and CVE processing
- Product-security evidence packages for release and PSIRT decisions
- Supplier and third-party risk management
- AI-system governance and regulatory traceability
- Zero-Trust endpoint posture collection and policy evaluation
- Management reviews, roadmap governance, and audit-ready exports
- Prometheus, Grafana, operational status, and alert workflows

## Security model

ISCY is a multi-tenant, security-sensitive application. Its mandatory security boundaries are documented in:

- [AGENTS.md](AGENTS.md) — rules for AI-assisted and automated contributions
- [Threat model](docs/THREAT_MODEL.md)
- [Authorization model](docs/AUTHORIZATION_MODEL.md)
- [Production hardening](docs/PRODUCTION_HARDENING.md)
- [TLS and reverse-proxy boundaries](docs/TLS_AND_REVERSE_PROXY.md)
- [Security policy](SECURITY.md)

Important invariants include:

- production identity is derived from validated sessions, bearer session tokens, or an explicitly trusted proxy boundary
- tenant-owned records remain tenant-scoped in database queries
- Evidence is not exposed through a public static `/media/` path
- Evidence downloads require authentication, tenant authorization, protection-class authorization, and safe media-root containment
- production startup fails closed when critical security assumptions are missing
- container builds honor `Cargo.lock`, and the application runtime does not run as root
- backups exclude environment snapshots and are verified before restore

ISCY has not undergone an independent penetration test or certification. Regulatory support does not constitute legal advice, certification, conformity assessment, or an audit opinion.

## Quick start on NixOS

```bash
./start.sh
```

The Rust web interface is then available at:

```text
http://127.0.0.1:9000/login/
```

Demo credentials:

```text
admin / Admin123!
```

The demo credentials and demo seeding are development-only and are blocked by production hardening.

Without the wrapper:

```bash
nix run .#iscy-backend -- init-demo
DATABASE_URL=sqlite:///db.sqlite3 \
RUST_BACKEND_BIND=127.0.0.1:9000 \
nix run .#iscy-backend
```

Create the first production administrator without demo data:

```bash
ISCY_INITIAL_ADMIN_PASSWORD_FILE=/run/secrets/iscy-initial-admin-password \
nix run .#iscy-backend -- init-admin
```

## Docker Compose

Development:

```bash
cp .env.development.example .env
make dev-up
```

Application: `http://127.0.0.1:9000`

Stage:

```bash
cp .env.stage.example .env
make stage-up
```

Application through Nginx: `http://127.0.0.1:8080`

Production:

```bash
cp .env.production.example .env
chmod 600 .env
make prod-readiness
make prod-up
```

Application through Nginx: `http://127.0.0.1`

Production deployment requires real secrets, explicit proxy/TLS decisions, and an operator review of the hardening documentation.

## Main product areas

The Rust backend provides server-rendered web interfaces and APIs, including:

- `/dashboard/`
- `/navigator/`
- `/organizations/`
- `/catalog/`
- `/requirements/`
- `/assessments/`
- `/risks/`
- `/incidents/`
- `/operations/incidents/`
- `/evidence/`
- `/evidence/quality/`
- `/reports/`
- `/management-reviews/`
- `/roadmap/`
- `/assets/`
- `/suppliers/`
- `/imports/`
- `/processes/`
- `/ai-governance/`
- `/product-security/`
- `/zero-trust/`
- `/cves/`
- `/admin/users/`

### Incident and regulatory workflows

Incident case files support severity, runbooks, significance decisions, reporting timestamps, authority references, timeline events, Evidence links, and NIS2/DORA/GDPR decision packages. Export formats include Markdown, HTML, PDF, and JSON where applicable.

### Product security

The Product Security workspace supports CSAF, CycloneDX, SPDX, CVE correlation, VEX status, SBOM comparison, CRA-readiness signals, review queues, and versioned release/PSIRT evidence packages.

### Evidence governance

Evidence lifecycle management includes version chains, SHA-256 hashes, validity, retention, review state, traceability, and the protection classes `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, and `RESTRICTED`.

Evidence bytes are available only through authenticated, tenant-aware download routes. Direct static `/media/` access remains denied.

### AI governance

AI Governance records AI systems, providers, models, data categories, decision impact, human oversight, AI Act classification, criticality, review dates, monitoring plans, risks, and Evidence references.

### Supplier risk

The supplier register evaluates criticality, contractual security requirements, data categories, regions, exit dependencies, regulatory scope, review dates, Evidence, product components, vulnerabilities, and documented risks.

### Zero-Trust agent

ISCY includes a read-only Rust agent for Windows, macOS, and Linux. It can collect inventory, heartbeat, OS, patch, encryption, Secure Boot, firewall, MDM, endpoint-protection, and EDR posture signals.

Enrollment uses one-time tokens. Subsequent messages use a device-bound agent secret, with optional client-certificate fingerprint binding. Offline delivery queues, secret rotation, and deployment examples are documented in [docs/ZERO_TRUST_AGENT.md](docs/ZERO_TRUST_AGENT.md).

Local self-test:

```bash
nix run .#iscy-agent -- --self-test
```

## Operations and monitoring

Health and operational endpoints:

```bash
curl -fsS http://127.0.0.1:9000/health
curl -fsS http://127.0.0.1:9000/status/operations.json
curl -fsS http://127.0.0.1:9000/metrics
```

Monitoring assets:

- [Prometheus scrape configuration](deploy/monitoring/prometheus/iscy-scrape.yml)
- [Prometheus alert rules](deploy/monitoring/prometheus/iscy-operations-alerts.yml)
- [Alertmanager routing example](deploy/monitoring/alertmanager/iscy-alertmanager.yml)
- [Grafana dashboard](deploy/monitoring/grafana/iscy-operations-dashboard.json)
- [Monitoring Compose stack](deploy/monitoring/docker-compose.yml)
- [NixOS monitoring module](deploy/monitoring/nixos/iscy-monitoring.nix)

Operational and regression checks:

```bash
nix develop --command make rust-smoke
nix develop --command make rust-restore-smoke
nix develop --command make team-test
```

## Vulnerability feeds

Rust CLI examples:

```bash
RUST_BACKEND_URL=http://127.0.0.1:9000 \
cargo run --manifest-path rust/iscy-backend/Cargo.toml --bin iscy-canary -- \
import-collection --has-kev --max-pages 2

RUST_BACKEND_URL=http://127.0.0.1:9000 \
cargo run --manifest-path rust/iscy-backend/Cargo.toml --bin iscy-canary -- \
sync-recent --hours 24 --max-pages 2
```

NVD configuration:

```text
NVD_API_BASE_URL=https://services.nvd.nist.gov
NVD_API_KEY=
```

For local and air-gapped tests, `NVD_API_BASE_URL` may point to a local NVD JSON response file.

## CI and supply-chain checks

The mandatory GitHub Actions checks cover:

- Rust formatting
- Clippy with warnings denied
- locked Rust tests
- Rust advisory scanning
- dependency license and source-policy checks
- database/bootstrap HTTP smoke tests
- Nix application smoke tests
- effective Compose validation for development, stage, production, and the LLM profile
- hardened non-root Docker image builds

Dependabot monitors Cargo, Docker, and GitHub Actions dependencies weekly. Dependency pull requests are reviewed individually; major upgrades are not merged automatically.

## Documentation

- [German README](README.de.md)
- [Handbook](docs/ISCY_Handbuch.md)
- [Strategic roadmap](docs/ISCY_STRATEGIC_ROADMAP.md)
- [GUI screenshots](docs/GUI_SCREENSHOTS.md)
- [Zero-Trust agent](docs/ZERO_TRUST_AGENT.md)
- [Proxmox production runbook](docs/PROXMOX_PRODUCTION_RUNBOOK.md)
- [Operations monitoring](docs/OPERATIONS_MONITORING.md)
- [Configuration matrix](docs/CONFIGURATION.md)
- [Release notes](docs/releases/)

Generate the PDF handbook reproducibly:

```bash
make docs-pdf
```

## Development and AI-assisted review

OpenAI Codex has been used to assist implementation, migration, testing, and review. AI-assisted contributions remain subject to human responsibility for correctness, security, licensing, provenance, and testing. See [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md).

## Contributing

Focused, tested, and documented contributions are welcome. Security-sensitive changes require negative authorization tests and an explicit description of affected trust boundaries.

Please read:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [SECURITY.md](SECURITY.md)

## License

ISCY is licensed under the GNU Affero General Public License v3.0 only (`AGPL-3.0-only`).
