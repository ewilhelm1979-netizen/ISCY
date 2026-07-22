# Native Threat Intelligence and Security Observations

Status: Phase 1 implemented in the `V23.7.31` development cycle.

ISCY provides a local-first, vendor-neutral register for bounded threat
indicators and normalized security observations. The module supports analyst
triage and auditability; it is not a SIEM, EDR, threat-feed collector or active
response system.

## Supported records

Indicators support `IPV4`, `IPV6`, `DOMAIN`, `URL` and `SHA256`. Values are
validated and normalized locally. Each record is tenant-scoped and includes
source, provenance reference, confidence from 0 to 100, validity, lifecycle
(`ACTIVE`, `INACTIVE`, `ARCHIVED`) and classification (`PUBLIC`, `INTERNAL`,
`RESTRICTED` or the supported TLP values).

Observations support three sources:

- `MANUAL` for a bounded analyst record;
- `AGENT_FINDING` for an existing tenant-local Zero-Trust agent finding;
- `VULNERABILITY_FINDING` for an existing tenant-local Product Security
  vulnerability finding.

Referenced findings remain the canonical source. ISCY derives the normalized
snapshot from the existing record and rejects foreign or missing references.
Observation attributes are limited to a small JSON object; raw logs, binary
payloads and unbounded event streams are not accepted.

Indicators can be linked manually to observations as `EXACT`, `CONTEXTUAL` or
`SOURCE_ASSERTED`. Link triage uses `PENDING`, `RELEVANT`, `NOT_RELEVANT` or
`NEEDS_REVIEW`. Matching performs no network lookup and triggers no automated
side effect.

## Authorization

| Capability | SOC_ANALYST | SECURITY_ADMIN |
| --- | --- | --- |
| View indicators and observations | Yes | Yes |
| Triage observations and links | Yes | Yes |
| Create manual links | Yes | Yes |
| Create observations | No | Yes |
| Create or change indicators | No | Yes |
| Archive indicators | No | Yes |

Server-side direct and group permissions may grant the same granular
capabilities. Existing roles are not automatically assigned these permissions.
All object lookups and writes retain tenant predicates in the database query.

## API and web UI

The web workspace is available at `/security-observations/`.

- `GET|POST /api/v1/threat-intelligence/indicators`
- `PATCH /api/v1/threat-intelligence/indicators/{indicator_id}`
- `GET|POST /api/v1/security-observations`
- `GET /api/v1/security-observations/audit`
- `PATCH /api/v1/security-observations/{observation_id}/triage`
- `GET|POST /api/v1/security-observations/{observation_id}/indicator-links`
- `PATCH /api/v1/security-observations/{observation_id}/indicator-links/{link_id}/triage`

Unknown JSON fields are rejected. A caller cannot select a tenant in the URL or
payload. Duplicate indicators, source references, deduplication keys and links
are handled idempotently within the authenticated tenant.

## Operational boundary

The module does not make DNS, HTTP, reputation or feed requests and does not
store raw telemetry. It never creates or changes Incidents or Evidence items.
Audit records capture actor, action, object and bounded metadata without
recording indicator values, source values, credentials or local file paths.

Architecture rationale and future-change conditions are documented in
`ADR_NATIVE_THREAT_INTELLIGENCE_OBSERVATIONS.md`.
