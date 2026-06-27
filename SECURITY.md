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
