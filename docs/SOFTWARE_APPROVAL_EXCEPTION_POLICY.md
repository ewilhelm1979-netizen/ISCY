# Software Approval and Exception Policy

Status: Phase 2 implemented in the `V23.7.31` development cycle.

ISCY records tenant-scoped software decisions for exact existing products,
assets, canonical components and imported SBOM components. The workflow is
passive and advisory.

## Effective states

| State | Meaning |
| --- | --- |
| `APPROVED` | An active matching policy explicitly approves the exact target and no stronger restriction applies. |
| `RESTRICTED` | At least one effective restriction remains without its own valid exception. |
| `PROHIBITED` | At least one effective prohibition remains without its own valid exception. |
| `EXCEPTION_ACTIVE` | Every effective restrictive policy is covered by its own approved, currently valid exception. This is not normal approval. |
| `UNMANAGED` | No currently effective policy exists for the exact target. |
| `REVIEW_REQUIRED` | The decision is incomplete or inconsistent and must not be treated as approval. |

No policy does not mean approved. No known vulnerability does not mean
approved. Approval does not assert that software is vulnerability-free.

## Web workflow

`/software-policies/` provides:

- the last stored evaluations and an explicit passive re-evaluation
- draft creation and editing
- policy activation and archival
- time-bounded exception request, submit, review, reject and revoke actions
- status, validity, owner display names and bounded audit history

The table labels stored evaluations with their evaluation and data-freshness
timestamps. Current effective API reads always recalculate validity using the
server UTC time. Expired exceptions are shown as expired even when no
scheduler has run.

## API

All requests require a server-side ISCY identity. Tenant and actor IDs are
derived from the authenticated context and cannot be assigned through the
payload.

| Method and path | Purpose |
| --- | --- |
| `GET /api/v1/software-policies?limit=&offset=` | List tenant policies |
| `POST /api/v1/software-policies` | Create an idempotent draft |
| `GET /api/v1/software-policies/{policy_id}` | Read one tenant policy |
| `PATCH /api/v1/software-policies/{policy_id}` | Update a draft with `expected_revision` |
| `POST /api/v1/software-policies/{policy_id}/activate` | Activate a draft |
| `POST /api/v1/software-policies/{policy_id}/archive` | Archive a draft or active policy |
| `GET /api/v1/software-policies/targets?limit=&offset=` | List exact tenant target candidates |
| `GET /api/v1/software-policies/effective?target_type=&target_id=` | Calculate the current effective decision without persisting it |
| `POST /api/v1/software-policies/evaluate` | Calculate and persist a passive evaluation |
| `GET /api/v1/software-policies/audit?limit=&offset=` | Read bounded tenant audit history |
| `GET /api/v1/software-policy-exceptions?limit=&offset=` | List tenant exceptions |
| `POST /api/v1/software-policy-exceptions` | Create an idempotent exception draft |
| `POST /api/v1/software-policy-exceptions/{id}/submit` | Submit the applicant's draft |
| `POST /api/v1/software-policy-exceptions/{id}/approve` | Independently approve a pending request |
| `POST /api/v1/software-policy-exceptions/{id}/reject` | Independently reject a pending request |
| `POST /api/v1/software-policy-exceptions/{id}/revoke` | Revoke an approved exception |

List limits are `1..=200`; offsets are `0..=100000`. Request objects reject
unknown fields. Text, identifiers and UTC RFC-3339 windows are bounded and
validated. Foreign and missing tenant objects use the same not-found response.
Database and SQL details are not returned.

Internal creator, updater, applicant, reviewer and audit actor IDs are not
serialized. Tenant-authorized views receive bounded display names. Object IDs
remain available where required for explicit workflow actions and provenance.

## RBAC

Migration `0045_rust_software_approval_exception_policy` adds:

- `view_software_policy`
- `add_software_policy`
- `change_software_policy`
- `activate_software_policy`
- `evaluate_software_policy`
- `view_software_policy_audit`
- `request_software_exception`
- `review_software_exception`
- `revoke_software_exception`

| Role | Effective rights |
| --- | --- |
| `ADMIN`, staff, superuser | All tenant software-policy operations |
| `SECURITY_ADMIN` | All tenant software-policy operations |
| `COMPLIANCE_MANAGER` | All tenant software-policy operations |
| `SOC_ANALYST` | View, evaluate and request an exception |
| `AUDITOR` | View policies and audit history |
| Other role | No implicit software-policy right |

Direct and group permissions remain supported. Self-approval is denied even
when a user has both request and review permissions.

## Exception rules

- Every exception has a mandatory future expiry.
- Start and expiry are normalized and compared in UTC.
- An exception applies only to its referenced tenant policy and exact target.
- Only an effective `RESTRICTED` or `PROHIBITED` policy can be approved for an
  exception.
- Rejection, revocation, expiry or policy archival makes the exception
  ineffective.
- Extending an exception requires a new request and decision.
- The underlying policy remains unchanged and visible.

An exception is neither VEX nor Risk Acceptance. Compensating-control text is
an exception justification and does not overwrite existing control or risk
records.

## Audit and provenance

Bounded events cover policy create/update/activate/archive, exception
create/submit/approve/reject/revoke/expire and material effective-decision
changes. State and audit are committed atomically. Idempotent retries do not
create duplicate success events.

Audit is not Evidence. It stores no SBOM payload, agent command, secret,
credential or local path.

## Security and operational limits

SQL queries bind both tenant and object identity. Composite foreign keys
prevent cross-tenant target links. Optimistic revisions, PostgreSQL row and
advisory locks, SQLite write serialization and uniqueness constraints protect
concurrent decisions.

This phase has no enforcement, software distribution, agent command, remote
execution, automatic incident, Evidence, VEX, Risk Acceptance or Security
Observation creation. EOL/EOS, license compliance, external feeds, fuzzy
matching and version-expression policies remain out of scope.

See `ADR_SOFTWARE_APPROVAL_EXCEPTION_POLICY.md`, `AUTHORIZATION_MODEL.md` and
`THREAT_MODEL.md` for the design and trust boundaries.
