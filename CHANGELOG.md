# Changelog

All notable changes to ISCY are documented in this file.

The project uses release tags for immutable release points. Changes under **Unreleased** are part of the next release candidate until they are assigned to a version.

## Unreleased

### Security

- deny direct reverse-proxy access to uploaded evidence under `/media/`
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

### Operations

- add locked Rust and hardened Docker-image checks to CI
- add automated dependency update coverage for Cargo, Docker, and GitHub Actions
- strengthen the production-readiness check for file permissions, placeholders, runtime secrets, and effective Compose configuration

## v23.7.26

### Added

- versioned Product Security evidence packages for release and PSIRT decisions
- review states, blockers, conditional approvals, and immutable package versions
- Markdown, HTML, PDF, and JSON exports
- operational status signals for package backlog and blockers

### Validation

- 236 Rust tests reported successful for the release commit
- release commit: `4ed62c8`
