# Security Policy

## Supported Versions

Security fixes are applied to the default branch and, where practical, to the latest tagged release.

Older versions may not receive security updates. Please reproduce findings against the current default branch or latest available release whenever possible.

## Reporting a Vulnerability

Do not report suspected vulnerabilities through a public GitHub issue, discussion, or pull request.

Use GitHub's private vulnerability reporting feature where available.

If private reporting is unavailable, contact the maintainer directly:

**Enrico Wilhelm**  
**Email:** enrico.wilhelm@wilhelmgroup.org

Please include:

- the affected version or commit
- the affected component, route, or endpoint
- a technical description of the issue
- the potential security impact
- reproduction steps or a minimal proof of concept
- relevant logs or screenshots with secrets removed
- a suggested mitigation, if known

Do not include passwords, API keys, personal data, or information belonging to third parties.

## Security-Relevant Areas

Reports are especially welcome for findings involving:

- authentication and session handling
- authorization and role enforcement
- tenant isolation
- evidence integrity and file handling
- API access controls
- incident and audit-trail integrity
- SBOM, CSAF, VEX, and CVE import or parsing
- secret or credential exposure
- dependency and software supply-chain risks
- denial-of-service conditions
- insecure default configurations

## Response Process

The maintainer aims to:

1. acknowledge a report within seven days
2. assess severity, scope, and reproducibility
3. coordinate remediation and responsible disclosure
4. publish a fix or mitigation when available
5. credit the reporter unless anonymity is requested

Response times may vary because ISCY is currently maintained primarily by one maintainer.

## Responsible Testing

Please act in good faith and:

- test only systems and data you are authorized to access
- avoid privacy violations, data destruction, or service disruption
- access only the minimum data required to demonstrate the issue
- allow reasonable time for remediation before public disclosure

Thank you for helping improve the security of ISCY.

## Secret Hygiene

Never store passwords, tokens, API keys, private keys, credentialed connection
strings, or other secrets in source, logs, test artifacts, health/status
responses, metrics, panic output, or Nix expressions. Demo values are test data
only and must never be used in stage or production. `.env.example` files may
contain only unambiguous placeholders such as
`API_KEY = "YOUR_API_KEY_HERE"`.

Echte Secrets dürfen niemals als Nix-String in einer `.nix`-Datei stehen. The
following is unsafe because evaluation can copy the value into the
world-readable Nix store:

```nix
environment.variables.API_KEY = "echtes-secret";
```

Use one reviewed mechanism appropriate to the deployment, such as `sops-nix`,
`agenix`, systemd `LoadCredential`, root-only files below `/run/secrets`, or an
`EnvironmentFile` outside the Nix store. Do not install several secret managers
without an explicit migration and recovery plan.

ISCY supports mutually exclusive direct and file sources for:

- `DATABASE_URL_FILE`
- `NVD_API_KEY_FILE`
- `ISCY_INITIAL_ADMIN_PASSWORD_FILE`
- `ISCY_ALERTMANAGER_TOKEN_FILE`
- `ISCY_ALERTMANAGER_HMAC_SECRET_FILE`
- `ISCY_ALERTMANAGER_HMAC_PREVIOUS_SECRET_FILE`
- `ISCY_EVIDENCE_OBJECT_STORAGE_ACCESS_KEY_FILE`
- `ISCY_EVIDENCE_OBJECT_STORAGE_SECRET_KEY_FILE`
- `ISCY_EVIDENCE_OBJECT_STORAGE_SESSION_TOKEN_FILE`
- the official PostgreSQL image's `POSTGRES_PASSWORD_FILE`

If both `VARIABLE` and `VARIABLE_FILE` are set, startup fails closed. Secret
files must be regular, non-symlink files, no larger than 16 KiB, and must have
no group/other permission bits (normally mode `0400` or `0600`). Only trailing
CR/LF bytes are removed. The default allowed directory is `/run/secrets`;
additional application roots require an explicit `ISCY_SECRET_ROOTS` path
list. S3 `file:` references use `/run/secrets` or explicit
`ISCY_EVIDENCE_SECRET_ROOTS`. Secret values are never logged; failures expose
only a variable name and safe error class.

Production Compose mounts the configured host secret directory read-only at
`/run/secrets`. Rotate credentials before any coordinated Git-history cleanup,
then inspect provider, database, object-store, and application audit logs and
assess impact. Never rewrite history automatically.

Run `nix develop --command make secrets` for the current source tree and
`nix develop --command make secrets-history` for the complete local history.
The history scan is a manual or periodic maintenance task. `make check`
includes the current-tree scan, and CI blocks new findings. `.gitignore`
reduces accidental additions but is not a security control and does not protect
tracked content. Optional pre-commit integration may invoke `make secrets`;
installation is manual and CI remains mandatory.

Performance- und Visual-CI-Artefakte werden vor jedem Upload aus privaten
Raw-Roots in ein getrenntes, allowlist-basiertes Staging ueberfuehrt. Nur
synthetische Aggregatmetriken, minimierte synthetische Visual-Ergebnisse,
validierte Diff-PNGs und ein SHA-256-Manifest sind erlaubt. Rohscreenshots,
Traces, Browserprofile, Cookies, Storage-State, Logs, Datenbanken, `.env`,
Zertifikate und Schluessel sind ausgeschlossen. Das Threat Model und die
Restrisiken stehen in `docs/security/ci-artifact-hygiene.md`.
