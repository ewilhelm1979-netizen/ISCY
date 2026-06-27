# Changelog

All notable changes to ISCY are documented in this file.

The project uses release tags for immutable release points. Changes under **Unreleased** are part of the next release candidate until they are assigned to a version.

## Unreleased

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
