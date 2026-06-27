# ISCY Agent and AI-Assisted Contribution Guide

This file defines mandatory working rules for automated coding agents and AI-assisted contributors in ISCY.

## Project context

ISCY is a security-sensitive, multi-tenant cybersecurity governance platform. Its Rust/Axum backend processes authentication context, regulatory evidence, incidents, supplier data, product-security information, SBOM/CSAF/VEX imports, AI-governance records, agent posture, and operational webhooks.

A change that appears local can affect tenant isolation, evidence confidentiality, auditability, or production safety. Treat security boundaries as product behavior, not optional hardening.

## Mandatory security invariants

### Identity and authorization

1. Production and non-development deployments must derive identity only from:
   - a valid server-side ISCY session,
   - a validated bearer session token, or
   - an explicitly configured trusted identity proxy boundary.
2. URL query parameters such as `tenant_id`, `user_id`, and `user_email` must never establish identity outside development-only compatibility flows.
3. Caller-controlled `x-iscy-*` headers must not be trusted unless the configured proxy boundary is both explicit and verified.
4. Every object read, write, export, review, and download must remain tenant-scoped in the database query itself.
5. New object routes require negative tests for missing authentication, insufficient role, foreign tenant, manipulated object ID, and manipulated identity context.

### Evidence and sensitive files

1. Evidence files are private application data.
2. Evidence must not be exposed through a public static path, shared web-root, directory listing, or unauthenticated reverse-proxy alias.
3. The authenticated Evidence-download endpoints must continue to validate session, tenant, object ownership, role, sensitivity, and safe media-root containment before returning bytes.
4. Evidence responses must use private/no-store caching and must emit an auditable access decision without logging secrets or stored file paths.
5. Temporary upload files must be removed after validation or persistence failures.
6. Direct static `/media/` delivery must not be restored.

### Secrets and logging

1. Never log database URLs containing credentials, tokens, session values, agent secrets, webhook secrets, or initial-admin passwords.
2. Prefer `*_FILE` secret inputs and read-only runtime mounts.
3. Do not copy production environment files into backups or test artifacts.
4. Example credentials and demo seeding must remain blocked in production mode.

### Deployment and supply chain

1. Rust builds must honor `Cargo.lock`; use `--locked` in CI and release/container builds.
2. Runtime containers must not run as root unless a narrowly documented technical requirement exists.
3. Do not publish the backend container port directly in stage or production when the reverse proxy is the intended ingress boundary.
4. Production startup must fail closed when required security assumptions are missing.
5. New external dependencies require a documented reason, lockfile review, advisory check, license review, and source-policy review.
6. Major dependency upgrades must be isolated, reviewed against upstream migration notes, and tested separately from routine patch maintenance.
7. Do not weaken or remove mandatory CI checks to make a pull request mergeable.

### Webhooks, agents, and outbound requests

1. Webhooks require authentication and replay protection where configured.
2. Outbound webhook destinations must remain subject to scheme, redirect, and host allow-list controls.
3. Agent enrollment and rotation secrets are one-time or secret values and must never appear in logs.
4. Agent device operations must validate both tenant and device binding.

### Imports and generated content

1. Treat CSV, XLSX, SBOM, CSAF, VEX, JSON, uploaded documents, NVD responses, and LLM output as untrusted input.
2. Enforce size, structure, type, and tenant-reference validation before persistence.
3. Generated regulatory text is assistance, not certification, legal advice, or an automatic compliance decision.

## Required validation

Run the relevant subset and explain any skipped command:

```bash
cargo fmt --manifest-path rust/iscy-backend/Cargo.toml -- --check
cargo clippy --locked --manifest-path rust/iscy-backend/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path rust/iscy-backend/Cargo.toml
cargo audit --file rust/iscy-backend/Cargo.lock
cargo deny --manifest-path rust/iscy-backend/Cargo.toml check advisories licenses sources
make rust-smoke
make rust-restore-smoke
docker compose config
docker compose --env-file .env -f docker-compose.yml -f docker-compose.stage.yml config
docker compose --env-file .env -f docker-compose.yml -f docker-compose.prod.yml config
docker build --file rust/iscy-backend/Dockerfile rust/iscy-backend
```

Changes to authorization, tenant scoping, evidence, webhooks, imports, backup/restore, or deployment defaults require focused negative tests in addition to the general suite.

## Pull-request expectations

Every substantial pull request should state the user or operational problem, affected security boundaries, migrations or compatibility effects, tests executed, known limitations, and documentation updated.

AI assistance must be disclosed as described in `CONTRIBUTING.md`. The human contributor remains responsible for correctness, security, licensing, provenance, and review.

## Prohibited shortcuts

Do not bypass authorization because a route is internal, use query parameters as production identity, serve Evidence from a public static directory, weaken production preflight, introduce permissive wildcard webhook destinations, silence security-critical failures with unconditional `|| true`, print secrets for debugging, or disable tests instead of fixing the underlying issue.
