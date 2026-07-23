# ADR: Software Approval and Exception Policy

Status: Accepted for Phase 2 in the `V23.7.31` development cycle.

## Context

Continuous Software Hygiene Phase 1 correlates vulnerability intelligence with
existing tenant assets, products and components. It does not answer the
separate governance question whether a concrete software object is approved,
restricted or prohibited.

ISCY already has canonical tenant-scoped products, information assets,
normalized product components and imported SBOM components. The existing
Product Security finding model is CVE-specific. Reusing it for a policy
violation would falsely imply a vulnerability identifier and would overload a
technical finding with a governance decision.

Phase 2 therefore needs a narrow policy and exception model, but not another
inventory, finding, generic workflow or expression engine.

## Decision

### Exact targets

A policy references exactly one existing object in the same tenant:

- `PRODUCT`: `product_security_product`
- `ASSET`: `assets_app_informationasset`
- `COMPONENT`: `product_security_component`
- `SBOM_COMPONENT`: `product_security_importcomponent`

Composite tenant foreign keys and runtime tenant queries bind the reference.
Free-text matching, wildcards, regular expressions, version expressions,
additional PURL/CPE heuristics and cross-tenant policies are not supported.

### Policy lifecycle

Policies use `DRAFT`, `ACTIVE` and `ARCHIVED`. Only drafts can be edited.
Activation and archival require an expected revision and a reason. Activated
content is immutable; a changed decision requires a new draft. Optional
validity boundaries are normalized to UTC RFC 3339. An archived, not-yet-valid
or expired policy is not effective.

The decisions are `APPROVED`, `RESTRICTED` and `PROHIBITED`. Approval is a
governance statement for the exact target. It is not a statement that the
software has no known vulnerabilities.

### Deterministic precedence

The evaluator uses the server UTC timestamp and sorts identifiers before
persisting provenance. Database row order cannot alter the result.

1. No effective policy produces `UNMANAGED`.
2. Incomplete or inconsistent policy data produces
   `REVIEW_REQUIRED` with completeness `INDETERMINATE`.
3. An unexcepted `PROHIBITED` policy wins.
4. Otherwise an unexcepted `RESTRICTED` policy wins.
5. If every effective restrictive policy has its own current approved
   exception, the result is `EXCEPTION_ACTIVE`.
6. Otherwise an explicit effective `APPROVED` policy produces `APPROVED`.

An exception neutralizes only its referenced policy. It cannot override
another restrictive policy. A general approval therefore cannot hide a
specific prohibition within the exact-target model.

Current effective reads recalculate against server time. Persisted evaluation
rows are historical snapshots and are labelled as the last stored evaluation.
Material decision changes increment the evaluation revision and create one
audit event.

### Exception lifecycle

Exceptions use:

```text
DRAFT -> PENDING_REVIEW -> APPROVED
                        -> REJECTED
APPROVED -> REVOKED
APPROVED -> EXPIRED
```

Every request has a mandatory future expiry and a UTC start. An applicant can
submit only their own draft and can never approve or reject it. Approval,
rejection and revocation have separate server-side permissions. Approved
content cannot be edited or silently extended.

Expiry is enforced in every effective evaluation query. It does not depend on
a scheduler. A mutating evaluation also persists `EXPIRED` and its audit event
transactionally. Read views derive the expired display state immediately even
before that housekeeping write occurs.

### Transactions and concurrency

Policy, exception and audit changes share one transaction. A failed audit
rolls back the state change. Revision predicates reject stale writes.
PostgreSQL uses row locks and a target-specific transaction advisory lock for
evaluation. SQLite uses its existing single-instance model plus a process-local
write mutex. Unique keys make repeated creation idempotent and prevent more
than one approved exception per policy.

Actor references are validated as active users in the same tenant before a
mutation. They intentionally have no deleting foreign key: historical audit
records remain readable as `historical-user` after account deletion. Tenant
object references retain restrictive composite foreign keys.

### Passive boundary

Evaluation is advisory and creates only its bounded evaluation and audit
records. It does not:

- install, uninstall, block, isolate or alter software
- invoke an agent or remote command
- create an Incident, Evidence item, Security Observation or Risk Acceptance
- create or modify VEX
- create a synthetic CVE or overwrite technical findings
- change manual triage, owners, deadlines, comments or compensating controls

## Alternatives considered

### Reuse the CVE finding model

Rejected. The current finding model is vulnerability-specific. A policy
violation without a CVE would be semantically false.

### Add a generic policy expression language

Rejected. It would add parser, authorization and execution risks and is not
needed for exact canonical identities.

### Model exceptions as VEX or Risk Acceptance

Rejected. VEX describes vulnerability applicability and Risk Acceptance is a
risk decision. Neither is a temporary software-use exception.

### Treat missing policy as approved

Rejected. That would be fail-open and would hide unmanaged inventory.

## Consequences and limits

Phase 2 deliberately supports exact object identities only. It has no
vendor-wide rules, fuzzy names, version ranges, EOL/EOS feed, license engine or
automatic enforcement. Where the exact target or policy data cannot be
trusted, the result is review-required rather than approved.

This decision supports human governance and auditability. It is not legal
advice, certification or proof that software is secure.
