# Changelog

All notable changes to ISCY are documented in this file.

The project uses release tags for immutable release points. Changes under **Unreleased** are part of the next release candidate until they are assigned to a version.

## Unreleased

### Added

- extend the existing secure notification channels, worker, cooldown, and delivery audit to Evidence lifecycle and quality, Product Security/CVE reviews, Incident non-reporting decisions, and Roadmap task deadlines
- add tenant-scoped cross-domain signal evaluation and safe delivery metadata through additive migration `0029_rust_cross_domain_notifications`
- expose safe cross-domain delivery history to authenticated read-only roles while keeping channel and signal-scope configuration administrator-only
- add a guided, three-step Zero-Trust Agent onboarding workflow for Windows, Linux, macOS, and NixOS using the existing deployment artifacts
- add tenant-scoped enrollment-token metadata, revocation, policy assignment, fleet status, and lifecycle audit views
- add enrollment-token lifecycle states for pending, partial, consumed, expired, and revoked rollouts with bounded multi-use support
- connect tenant-scoped AI Governance systems to existing risks, roadmap tasks, incidents, and canonical change records
- add explicit, duplicate-safe roadmap task creation from open AI Governance gaps with a stable origin key
- include frozen AI Governance link summaries in management review UI and Markdown, HTML, PDF, and JSON exports
- add authenticated APIs and Web UI actions to list, create, and remove AI Governance links

### Security

- reserve tenant- and channel-scoped notification dispatch claims atomically before webhook delivery through additive migration `0030_rust_notification_dispatch_claim`, preventing duplicate sends from overlapping manual and periodic evaluations
- correct PostgreSQL integer decoding in the Agent Governance notification path so policy, channel, CVE, device, and delivery metadata use the existing Rust API types consistently
- redact internal Agent Governance store and SQL errors from HTML responses while preserving safe API validation behavior
- keep cross-domain webhook payloads intentionally minimal and exclude stored payloads, internal errors, credentials, authorization headers, and secret references from delivery APIs and read-only views
- preserve production host allow-listing, disabled redirects, bounded retries, stable signal-key deduplication, and per-channel cooldown for every notification domain
- make token consumption, device enrollment, policy assignment, secret-hash persistence, and lifecycle audit events transactional on SQLite and PostgreSQL
- return enrollment tokens and agent secrets only in no-store responses, retain hashes instead of plaintext, and reject untrusted client-supplied mTLS fingerprint headers
- enforce administrator-only token creation and revocation while allowing authenticated read-only roles to inspect safe tenant-scoped metadata
- enforce tenant predicates while resolving every AI Governance system and linked target
- persist link and unlink audit events and reject foreign-tenant, manipulated, and duplicate relationships

### Security and supply chain

- expand staggered weekly Dependabot coverage to Cargo, the backend Dockerfile, root and monitoring Compose stacks, Nix inputs, and GitHub Actions
- update `chrono` from 0.4.44 to 0.4.45 after isolated review and a fully green CI run

## V23.7.27

### Security

- add authenticated, tenant-scoped Evidence downloads with protection-class authorization, safe canonical path resolution, private caching, and structured access decisions
- deny direct reverse-proxy access to uploaded Evidence under `/media/`
- remove legacy URL identity parameters before requests reach non-development route handlers
- keep the backend container port private in stage and production deployments
- bind development database and backend ports to localhost
- enforce explicit production mode, database configuration, secure-cookie settings, and trusted-proxy assumptions
- build the Rust container with `Cargo.lock` and run it as a dedicated non-root user
- drop container capabilities and enable `no-new-privileges` in stage and production
- stop logging complete database URLs
- mount operator-managed runtime secrets read-only and exclude local runtime material from Git
- exclude production environment snapshots from backups
- verify backup checksums and archive structure before destructive restore
- document the project threat model and mandatory AI-assisted contribution invariants
- add mandatory Rust advisory, dependency-license, and source-policy checks to CI

### Operations and community readiness

- add locked Rust and hardened Docker-image checks to CI
- add automated dependency update coverage for Cargo, Docker, and GitHub Actions
- strengthen the production-readiness check for file permissions, placeholders, runtime secrets, and effective Compose configuration
- protect `main` through pull requests, required CI checks, linear history, deletion protection, and force-push protection
- provide a fully English primary README and a maintained German overview
- clarify the implemented Evidence-download invariants in `AGENTS.md`

### Validation

- Rust formatting and Clippy with warnings denied
- locked Rust test suite and negative authorization tests
- Rust DB/bootstrap HTTP smoke
- Nix application smoke
- development, stage, production, and LLM Compose validation
- hardened non-root Docker image build
- Rust advisory, license, and source-policy checks

## V23.7.26

### Added

- versioned Product Security evidence packages for release and PSIRT decisions
- review states, blockers, conditional approvals, and immutable package versions
- Markdown, HTML, PDF, and JSON exports
- operational status signals for package backlog and blockers

### Validation

- 236 Rust tests reported successful for the release commit
- release commit: `4ed62c8`
