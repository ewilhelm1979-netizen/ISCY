# Contributing to ISCY

Thank you for contributing to ISCY.

ISCY is a security-sensitive open-source project. Contributions should be focused, reviewable, tested, and documented.

## Before You Start

- Search existing issues and pull requests first.
- Discuss substantial features or architectural changes in an issue before implementation.
- Report suspected vulnerabilities according to [SECURITY.md](SECURITY.md), not through public issues.
- Keep each pull request focused on one topic.

## Development Checks

The primary runtime is implemented in Rust using Axum. Run the checks relevant to your change:

```bash
make rust-build
make rust-test
make rust-smoke
make team-test
```

## Security Expectations

Changes involving authentication, authorization, tenant boundaries, evidence handling, imports, or audit data should:

- apply least privilege and secure defaults
- preserve tenant isolation for reads and writes
- include negative tests for unauthorized or cross-tenant access
- validate untrusted input and imported data
- avoid exposing sensitive information in logs
- document security assumptions and operational impact
- include migrations for database schema changes

## Code and Documentation

- Follow the existing project structure and Rust conventions.
- Add or update tests for behavioral changes.
- Update documentation when configuration, APIs, workflows, or operations change.
- Justify new dependencies and consider their maintenance and security impact.

## AI-Assisted Contributions

AI-assisted contributions are welcome. Contributors remain responsible for correctness, security, licensing, provenance, and test coverage. Substantial AI assistance should be disclosed in the pull request description, and generated code must be reviewed and validated before submission.

## Pull Requests

A pull request should include:

- a concise description and rationale
- security and compatibility implications
- tests performed
- documentation changes
- screenshots for relevant UI changes

Use clear, imperative commit messages, for example:

```text
Add tenant boundary tests for evidence exports
Harden CSAF import validation
Document production configuration
```

## Licensing

By submitting a contribution, you agree that it is provided under the GNU Affero General Public License v3.0 only (`AGPL-3.0-only`).

## Code of Conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
