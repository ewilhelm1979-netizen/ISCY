# ISCY Threat Model

## Purpose

This document describes the primary assets, trust boundaries, threats, and security invariants for ISCY Community. It is a living engineering model, not a penetration-test report or certification.

## Scope

Included:

- Rust/Axum web and API runtime
- authentication and tenant authorization
- PostgreSQL and SQLite persistence
- evidence uploads and lifecycle metadata
- incident, risk, supplier, product-security, and AI-governance records
- SBOM, CSAF, VEX, CSV, XLSX, JSON, and NVD processing
- Zero-Trust agent enrollment, heartbeats, findings, and secret rotation
- Alertmanager and notification webhooks
- local LLM integration
- Docker/NixOS deployment boundaries
- backup and restore workflows

Out of scope unless explicitly added by an operator:

- host operating-system hardening
- external TLS termination and PKI
- upstream identity-provider security
- external object storage
- operator network segmentation
- legal or certification conclusions based on ISCY data

## Protected assets

| Asset | Primary security properties |
|---|---|
| Tenant records | confidentiality, integrity, isolation |
| Evidence files and hashes | confidentiality, integrity, traceability, retention |
| Incident and regulatory packages | confidentiality, integrity, availability, auditability |
| Accounts, sessions, and roles | confidentiality, integrity, authenticity |
| Agent enrollment tokens and secrets | confidentiality, authenticity, rotation |
| Webhook secrets and nonces | confidentiality, authenticity, replay resistance |
| Database credentials and runtime secrets | confidentiality |
| SBOM/CSAF/VEX and vulnerability data | integrity, provenance, availability |
| Audit events and review decisions | integrity, non-ambiguity, traceability |
| Backups | confidentiality, integrity, recoverability |

## Actors

- authenticated administrator
- authenticated contributor
- authenticated auditor/read-only user
- enrolled endpoint agent
- trusted reverse proxy or identity boundary
- Alertmanager or approved webhook sender
- external vulnerability-data source
- unauthenticated network client
- malicious or compromised tenant user
- compromised endpoint agent
- operator with deployment access
- dependency or build-system attacker

## Trust boundaries

### Client to reverse proxy

Untrusted internet or network clients reach the configured ingress. The reverse proxy must not expose private evidence volumes and must not create trusted ISCY identity from caller-controlled values.

### Reverse proxy to Rust backend

The backend port is private in stage and production. Proxy trust is explicit. `x-iscy-*` headers are rejected unless identity-header trust is deliberately enabled behind a verified boundary.

### Session or token to tenant context

A valid server-side session or bearer session token establishes user and tenant identity. URL query parameters do not establish identity outside development compatibility flows.

### Backend to database

All tenant-owned data operations must include tenant scope in the database query. UI filtering or a prior object lookup is not a substitute for tenant-scoped persistence access.

### Backend to evidence storage

Evidence bytes are more sensitive than ordinary static assets. The storage path is not a public web root. Metadata access does not automatically grant byte access.

### Backend to external services

NVD, webhooks, and optional integrations cross an outbound trust boundary. URLs, redirects, schemes, payloads, timeouts, and response sizes require validation.

### Endpoint agent to backend

Enrollment tokens create a one-time agent identity. Subsequent messages require the device-bound secret and optional certificate fingerprint. Tenant IDs supplied by an agent are claims that must be verified against the secret/device record.

### Operator to backup storage

Backup files contain production database and evidence data. File permissions, integrity manifests, encrypted storage, and controlled restore authorization are operator responsibilities enforced where practical by scripts.

## Threat analysis

### Identity spoofing through headers or query parameters

**Threat:** A client supplies `tenant_id`, `user_id`, role headers, or URL parameters to impersonate another user or tenant.

**Controls:**

- production denies untrusted `x-iscy-*` identity headers
- non-development server middleware removes legacy identity query parameters before routing
- session and bearer tokens resolve server-side user/tenant context
- production proxy and direct backend exposure are separate explicit boundaries
- negative authorization tests cover manipulated identities and foreign tenants

**Residual risk:** A misconfigured external proxy that is marked trusted can still assert false identity. Proxy configuration and network reachability must be reviewed together.

### Cross-tenant object access

**Threat:** An authenticated user changes an object ID and reads, updates, reviews, or exports another tenant's object.

**Controls:**

- store methods receive tenant ID
- object queries include tenant predicates
- foreign-tenant negative tests are required for new routes
- not-found behavior should avoid disclosing foreign object existence

**Residual risk:** New modules can omit tenant predicates. Review and route-specific negative tests remain mandatory.

### Direct evidence disclosure

**Threat:** Uploaded evidence is fetched directly from a shared static `/media/` path, bypassing tenant authorization and sensitivity rules.

**Controls:**

- the bundled reverse proxy returns `404` for `/media/`
- the reverse proxy does not mount the evidence volume
- evidence storage remains attached only to the application service
- evidence metadata contains tenant and sensitivity information

**Implemented control:** Dedicated authenticated download routes resolve identity from a valid ISCY session, load the Evidence record with a tenant-scoped query, apply role and sensitivity authorization, constrain canonical paths to the configured media root, return private/no-store attachment responses, and emit structured allow/deny security events.

### Malicious upload or import

**Threat:** A document, spreadsheet, SBOM, CSAF, VEX, CSV, JSON, or archive exploits a parser, exhausts memory, creates path traversal, or injects cross-tenant references.

**Controls:**

- body and evidence size limits
- extension and content-type checks
- server-generated storage names and constrained media root
- tenant validation for referenced objects
- temporary-file cleanup after failed persistence
- import validation and error reporting

**Residual risk:** File type and extension validation are not malware detection. Operators should add malware scanning and sandboxed parsing for higher-risk environments.

### Stored or reflected content injection

**Threat:** Imported or user-entered content produces HTML/script injection in web pages or exports.

**Controls:**

- output escaping in server-rendered pages
- restrictive Content Security Policy
- `X-Content-Type-Options`, frame denial, no-store responses
- HTML uploads are blocked as evidence

**Residual risk:** New render paths or generated documents must continue to escape untrusted content by output context.

### Webhook forgery, replay, and SSRF

**Threat:** An attacker forges Alertmanager messages, replays signed requests, or configures a notification channel to target internal services.

**Controls:**

- bearer-token authentication
- optional HMAC timestamp and nonce validation
- previous-secret rotation support
- allowed-host checks
- HTTPS default
- URL credentials and redirects blocked
- delivery audit and bounded retries

**Residual risk:** DNS rebinding and infrastructure-level egress remain operator concerns. Restrict outbound network paths in production.

### Agent enrollment and device impersonation

**Threat:** An attacker steals an enrollment token or agent secret and submits false posture data.

**Controls:**

- time/use-limited enrollment tokens
- one-time plaintext secret delivery
- hashed or protected secret persistence
- device and tenant binding
- secret rotation
- optional mTLS fingerprint binding
- restrictive local secret-file permissions

**Residual risk:** A compromised endpoint can submit plausible false local state. Agent findings are security signals, not proof of host integrity.

### Secret disclosure through logs, Git, or backups

**Threat:** Database credentials or tokens appear in console logs, committed files, CI artifacts, or backup environment snapshots.

**Controls:**

- database URL is redacted in startup output
- production env and `.runtime/` are ignored
- `*_FILE` inputs and read-only runtime mounts
- backup excludes environment snapshots
- CI has read-only repository permissions

**Residual risk:** Operators can still redirect sensitive process environments into external diagnostics. Runtime and CI log access must be controlled.

### Backup tampering or unsafe restore

**Threat:** A corrupted or substituted backup is restored; a mistaken command destroys the active database; evidence and database become inconsistent.

**Controls:**

- restrictive backup permissions
- database and media captured as one backup set
- manifest and SHA-256 checksums
- gzip and tar validation
- explicit destructive-restore confirmation
- application traffic stopped during restore
- database restore uses `ON_ERROR_STOP`
- application restarted only after restore commands succeed

**Residual risk:** SHA-256 detects corruption but does not prove publisher identity. Store backups encrypted and add signed manifests or trusted storage controls in production.

### Dependency or build compromise

**Threat:** A moving dependency, image, or CI action introduces malicious or unexpected code.

**Controls:**

- committed Cargo lockfile
- `--locked` tests and container build
- non-root runtime image
- minimal CI permissions
- automated dependency update review

**Planned controls:** Pin GitHub Actions and container bases by immutable digest, produce release SBOMs and provenance, and sign release artifacts.

### Local LLM and generated compliance content

**Threat:** Prompt injection or untrusted input causes misleading regulatory text, data leakage, or unsafe automated decisions.

**Controls:**

- local-first model option
- generated output remains advisory
- human review and evidence workflow
- explicit project disclaimer that ISCY is not certification or legal advice

**Residual risk:** Model output can be wrong or manipulated. Do not automatically approve risks, incidents, releases, or compliance decisions solely from generated content.

## Security invariants for releases

A release must not knowingly violate these rules:

1. Production identity does not come from URL parameters.
2. Untrusted identity headers do not establish a user or tenant.
3. Tenant-owned object queries remain tenant-scoped.
4. Evidence bytes are not publicly served as static content.
5. Production mode fails closed on demo credentials and missing critical secrets.
6. Database credentials and authentication secrets do not appear in normal logs.
7. Container builds honor `Cargo.lock` and the runtime does not run as root.
8. Backups contain database and evidence together, exclude environment snapshots, and are verified before restore.
9. New security-sensitive routes include negative tests.

## Verification map

| Boundary | Primary verification |
|---|---|
| Identity query sanitization | `security_boundary` unit tests and production HTTP negative tests |
| Identity header trust | `hardening` tests and route negative tests |
| Tenant isolation | store and HTTP foreign-tenant tests |
| Evidence upload | size/type/reference tests and restore smoke |
| Direct evidence serving | reverse-proxy configuration test/manual HTTP check |
| Authenticated Evidence download | session-only authentication, tenant-scoped lookup, protection-class tests, and path-manipulation negative tests |
| Production preflight | hardening unit/integration tests and readiness script |
| Container privilege | Docker build and runtime inspection |
| Backup integrity | generated `SHA256SUMS` and restore preflight |
| Webhook replay | HMAC nonce/timestamp tests |
| Agent secret binding | enrollment, heartbeat, findings, and rotation tests |

## Known limitations and next steps

- authenticated Evidence downloads emit structured runtime security events; durable database-backed download audit persistence and an explicit lifecycle-state denial policy remain future hardening options
- backup manifests are checksummed but not cryptographically signed
- backup encryption depends on the operator's storage or transfer layer
- base container and GitHub Action references are not yet all pinned by digest/commit SHA
- no independent penetration test has been completed
- parser sandboxing and malware scanning are deployment-dependent
- security review remains necessary as new product-security, AI, supplier, and agent workflows are added
