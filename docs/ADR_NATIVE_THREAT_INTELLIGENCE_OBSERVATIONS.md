# ADR: Native Threat Intelligence and Security Observations

Status: Accepted for Phase 1 in `V23.7.31` development.

## Context

ISCY already owns tenant-scoped assets, Zero-Trust agent findings and Product
Security vulnerability findings. Operators also need a vendor-neutral place
to record bounded threat indicators and to triage security observations without
turning ISCY into a SIEM, EDR or raw-log platform.

## Decision

Phase 1 adds two deliberately small concepts:

- `threat_intelligence_indicator` stores locally validated IPv4, IPv6, domain,
  URL and SHA-256 indicators with source, provenance, confidence, validity,
  lifecycle and classification.
- `security_observation` stores a normalized, bounded triage projection. It may
  be entered manually or reference an existing tenant-local Agent Finding or
  Product Security Vulnerability Finding.

The domain boundaries are explicit:

| Concept | Purpose and authority |
| --- | --- |
| Threat-Intelligence Indicator | A locally validated, sourced assertion about an observable value; it is neither a vulnerability nor proof of compromise. |
| Security Observation | A bounded triage record or tenant-local projection of an existing finding; it is not raw telemetry and makes no incident decision. |
| Vulnerability Finding | The existing Product Security record remains the authoritative software weakness and CVE context. |
| Incident | A separately governed case created or changed only by an authorized human workflow. |
| Evidence | A separately governed, access-controlled artifact or record; an indicator, observation or match is not Evidence by itself. |

The existing finding records remain authoritative. Referenced observations do
not copy ownership of those records and cannot alter them. Composite foreign
keys bind source findings, assets, observations and indicators to the same
tenant. Tenant-local uniqueness keys make retries idempotent.

Indicator-to-observation links are manual in Phase 1. A link records the match
type, rationale, evaluator and triage status, but it does not create or update
an Incident, Evidence item, Risk, Roadmap task or endpoint action.
Promotion into an Incident or Evidence workflow remains an explicit future
human decision and is not implemented by this phase.

## Security boundaries

- Identity and tenant context come from the existing authenticated server-side
  boundary. Client-supplied tenant fields are rejected.
- `SOC_ANALYST` may view indicators and observations and may triage or link
  observations. `SECURITY_ADMIN` additionally manages indicators and creates
  observations. Direct/group permissions remain supported through the
  server-side authorization store.
- Existing roles receive no implicit new permission assignment. Existing
  Admin, Staff and Superuser behavior remains unchanged.
- Future adapters may submit only normalized, bounded data through an
  authenticated tenant boundary. They may never choose the tenant, identity,
  roles or effective permissions carried into the store.
- Indicator normalization is local and performs no DNS, HTTP or reputation
  lookup. URL parsing never initiates a network request.
- Attributes are bounded JSON and reject suspicious secret-bearing keys.
- Audit events use bounded summaries and hashes for sensitive source or
  indicator references instead of logging their values.
- SQLite writes are serialized within the process; PostgreSQL and database
  uniqueness constraints provide race-safe deduplication.

## Deliberate exclusions

Phase 1 does not add raw log ingestion, continuous feeds, STIX/TAXII, MISP,
OpenCTI, Wazuh, SIEM/EDR/XDR behavior, active scanning, automatic matching,
automatic Incident/Evidence creation, defensive response orchestration,
active response, remote execution, hackback or legal/compliance decisions.
No exchange-standard conformance is claimed unless a later implementation is
complete and covered by dedicated interoperability tests.

## Consequences

ISCY gains a native governance and triage layer that can connect existing
security signals without introducing a competing source-of-truth model. Future
feed connectors or automated correlation require a separate ADR, explicit
provenance and replay controls, bounded ingestion, tenant-negative tests and a
human review boundary.
