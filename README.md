# ISCY

[![CI](https://github.com/ewilhelm1979-netizen/ISCY/actions/workflows/ci.yml/badge.svg)](https://github.com/ewilhelm1979-netizen/ISCY/actions/workflows/ci.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)

[Deutsch](README.de.md)

**Self-hosted open-source cybersecurity governance for ISMS, product security, AI governance, and regulatory evidence.**

ISCY connects security risks, controls, assets, incidents, evidence, suppliers, product-security data, and AI systems in one auditable platform. It is designed for organizations working with ISO 27001, NIS2, DORA, the Cyber Resilience Act, the EU AI Act, GDPR, and KRITIS.

The application follows a local-first, privacy-conscious approach. Its production runtime is implemented in Rust with Axum and supports NixOS and Docker-based deployments.

> **Project status:** ISCY is actively developed and is in an early community-adoption phase. Interfaces and operational procedures may still evolve.

## What ISCY covers

| Area | Examples |
| --- | --- |
| ISMS and governance | risks, controls, requirements, assets, processes, evidence, management reviews |
| Incident response | case files, timelines, runbooks, regulatory reporting packages |
| Product security | SBOM, CSAF, SPDX, CycloneDX, VEX, CVE correlation, PSIRT evidence packages |
| Third-party risk | supplier criticality, dependencies, reviews, contracts, evidence |
| AI governance | AI-system inventory, classification, oversight, risks, monitoring plans |
| Zero Trust | endpoint posture, enrollment, policy evaluation, device-bound credentials |
| Operations | audit-ready exports, health endpoints, Prometheus, Grafana, backup and restore checks |

## Quick start

### NixOS / Nix

```bash
./start.sh
```

Open `http://127.0.0.1:9000/login/` and use the development-only demo account:

```text
admin / Admin123!
```

### Docker Compose

```bash
cp .env.development.example .env
make dev-up
```

For stage and production deployment, use the dedicated environment examples and complete the documented readiness checks:

```bash
cp .env.production.example .env
chmod 600 .env
make prod-readiness
make prod-up
```

Do not use demo credentials or demo seeding in production.

## Security by design

ISCY is a multi-tenant, security-sensitive application. Core security boundaries include:

- server-side authentication and tenant-scoped authorization
- authenticated Evidence downloads with protection-class checks
- no public static delivery of uploaded Evidence
- fail-closed production preflight and explicit proxy trust
- locked Rust builds, advisory scanning, and dependency license/source policy checks
- non-root containers and verified backup/restore procedures

Start with the [threat model](docs/THREAT_MODEL.md), [authorization model](docs/AUTHORIZATION_MODEL.md), [production hardening guide](docs/PRODUCTION_HARDENING.md), and [security policy](SECURITY.md).

ISCY has not undergone an independent penetration test or certification. Regulatory support does not constitute legal advice, certification, conformity assessment, or an audit opinion.

## Validation

The protected CI workflow checks Rust formatting, Clippy, locked tests, dependency advisories, dependency licenses and sources, HTTP/database smoke tests, Nix execution, Compose configurations, and the hardened Docker image.

Local validation:

```bash
cargo test --locked --manifest-path rust/iscy-backend/Cargo.toml
make rust-smoke
make rust-restore-smoke
```

## Documentation

- [Handbook](docs/ISCY_Handbuch.md)
- [Strategic roadmap](docs/ISCY_STRATEGIC_ROADMAP.md)
- [GUI screenshots](docs/GUI_SCREENSHOTS.md)
- [Configuration reference](docs/CONFIGURATION.md)
- [Operations and monitoring](docs/OPERATIONS_MONITORING.md)
- [Production hardening](docs/PRODUCTION_HARDENING.md)
- [Proxmox production runbook](docs/PROXMOX_PRODUCTION_RUNBOOK.md)
- [Zero-Trust agent](docs/ZERO_TRUST_AGENT.md)
- [Release notes](docs/releases/)

## Contributing

Focused, tested, and documented contributions are welcome. Security-sensitive changes require explicit trust-boundary analysis and negative authorization tests.

Please read [CONTRIBUTING.md](CONTRIBUTING.md), [AGENTS.md](AGENTS.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and [SECURITY.md](SECURITY.md).

OpenAI Codex has assisted implementation, migration, testing, and review. Human contributors remain responsible for correctness, security, licensing, provenance, and validation.

## License

ISCY is licensed under the GNU Affero General Public License v3.0 only (`AGPL-3.0-only`).
