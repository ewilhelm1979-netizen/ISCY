use std::{fmt, sync::Arc};

use anyhow::{bail, Context};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Postgres, Row, Sqlite, Transaction,
};
use tokio::sync::{Mutex, MutexGuard};

use crate::cve_store::normalize_database_url;

pub const PERMISSION_VIEW_SOFTWARE_POLICY: &str = "view_software_policy";
pub const PERMISSION_ADD_SOFTWARE_POLICY: &str = "add_software_policy";
pub const PERMISSION_CHANGE_SOFTWARE_POLICY: &str = "change_software_policy";
pub const PERMISSION_ACTIVATE_SOFTWARE_POLICY: &str = "activate_software_policy";
pub const PERMISSION_EVALUATE_SOFTWARE_POLICY: &str = "evaluate_software_policy";
pub const PERMISSION_VIEW_SOFTWARE_POLICY_AUDIT: &str = "view_software_policy_audit";
pub const PERMISSION_REQUEST_SOFTWARE_EXCEPTION: &str = "request_software_exception";
pub const PERMISSION_REVIEW_SOFTWARE_EXCEPTION: &str = "review_software_exception";
pub const PERMISSION_REVOKE_SOFTWARE_EXCEPTION: &str = "revoke_software_exception";

const POLICY_STATUSES: [&str; 3] = ["DRAFT", "ACTIVE", "ARCHIVED"];
const POLICY_DECISIONS: [&str; 3] = ["APPROVED", "RESTRICTED", "PROHIBITED"];
const TARGET_TYPES: [&str; 4] = ["PRODUCT", "ASSET", "COMPONENT", "SBOM_COMPONENT"];
const EXCEPTION_STATUSES: [&str; 6] = [
    "DRAFT",
    "PENDING_REVIEW",
    "APPROVED",
    "REJECTED",
    "REVOKED",
    "EXPIRED",
];

#[derive(Clone)]
pub enum SoftwarePolicyStore {
    Postgres(PgPool),
    Sqlite {
        pool: SqlitePool,
        write_lock: Arc<Mutex<()>>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoftwarePolicyErrorKind {
    InvalidInput,
    NotFound,
    Conflict,
    Database,
}

#[derive(Debug)]
pub struct SoftwarePolicyError {
    kind: SoftwarePolicyErrorKind,
    code: &'static str,
    message: &'static str,
}

impl SoftwarePolicyError {
    pub fn kind(&self) -> SoftwarePolicyErrorKind {
        self.kind
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &'static str {
        self.message
    }

    pub(crate) fn invalid(code: &'static str, message: &'static str) -> Self {
        Self {
            kind: SoftwarePolicyErrorKind::InvalidInput,
            code,
            message,
        }
    }

    fn not_found() -> Self {
        Self {
            kind: SoftwarePolicyErrorKind::NotFound,
            code: "software_policy_object_not_found",
            message: "Das angeforderte Software-Policy-Objekt wurde nicht gefunden.",
        }
    }

    fn conflict(code: &'static str, message: &'static str) -> Self {
        Self {
            kind: SoftwarePolicyErrorKind::Conflict,
            code,
            message,
        }
    }

    fn database() -> Self {
        Self {
            kind: SoftwarePolicyErrorKind::Database,
            code: "software_policy_database_error",
            message: "Die Software-Policy-Daten konnten intern nicht verarbeitet werden.",
        }
    }
}

impl fmt::Display for SoftwarePolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for SoftwarePolicyError {}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SoftwarePolicyTarget {
    pub target_type: String,
    pub target_id: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwarePolicyCreateRequest {
    pub name: String,
    pub description: Option<String>,
    pub decision: String,
    pub target: SoftwarePolicyTarget,
    pub rationale: String,
    pub owner_id: Option<i64>,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwarePolicyUpdateRequest {
    pub expected_revision: i64,
    pub name: String,
    pub description: Option<String>,
    pub decision: String,
    pub rationale: String,
    pub owner_id: Option<i64>,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwarePolicyTransitionRequest {
    pub expected_revision: i64,
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwarePolicyEvaluationRequest {
    pub target: SoftwarePolicyTarget,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareExceptionCreateRequest {
    pub policy_id: i64,
    pub justification: String,
    pub compensating_controls: Option<String>,
    pub requested_valid_from: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareExceptionTransitionRequest {
    pub expected_revision: i64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SoftwarePolicySummary {
    pub id: i64,
    pub tenant_id: i64,
    pub name: String,
    pub description: String,
    pub status: String,
    pub decision: String,
    pub target: SoftwarePolicyTarget,
    pub target_label: String,
    pub rationale: String,
    #[serde(skip_serializing)]
    pub owner_id: Option<i64>,
    pub owner_display: Option<String>,
    #[serde(skip_serializing)]
    pub created_by_id: i64,
    pub created_by_display: String,
    #[serde(skip_serializing)]
    pub updated_by_id: i64,
    pub updated_by_display: String,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub revision: i64,
    pub activated_at: Option<String>,
    pub archived_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SoftwarePolicyWriteResult {
    pub created: bool,
    pub policy: SoftwarePolicySummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct SoftwareExceptionSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub policy_id: i64,
    pub policy_name: String,
    pub target: SoftwarePolicyTarget,
    pub target_label: String,
    #[serde(skip_serializing)]
    pub applicant_id: i64,
    pub applicant_display: String,
    pub justification: String,
    pub compensating_controls: String,
    pub requested_valid_from: String,
    pub expires_at: String,
    pub status: String,
    #[serde(skip_serializing)]
    pub reviewer_id: Option<i64>,
    pub reviewer_display: Option<String>,
    pub decision_reason: String,
    pub decision_at: Option<String>,
    pub revoked_at: Option<String>,
    pub expired_at: Option<String>,
    pub revision: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SoftwareExceptionWriteResult {
    pub created: bool,
    pub exception: SoftwareExceptionSummary,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SoftwarePolicyEvaluation {
    pub id: i64,
    pub tenant_id: i64,
    pub target: SoftwarePolicyTarget,
    pub target_label: String,
    pub effective_decision: String,
    pub completeness_status: String,
    pub policy_ids: Vec<i64>,
    pub exception_id: Option<i64>,
    pub decision_path: String,
    pub review_required: bool,
    pub evaluated_at: String,
    pub data_fresh_at: String,
    pub revision: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SoftwarePolicyAuditEvent {
    pub id: i64,
    pub tenant_id: i64,
    pub object_type: String,
    pub object_id: i64,
    pub event_type: String,
    #[serde(skip_serializing)]
    pub actor_id: i64,
    pub actor_display: String,
    pub previous_state: String,
    pub new_state: String,
    pub reason: String,
    pub revision: i64,
    pub detail: Value,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SoftwarePolicyTargetOption {
    pub target: SoftwarePolicyTarget,
    pub label: String,
}

#[derive(Debug)]
struct NormalizedPolicy {
    name: String,
    description: String,
    decision: String,
    target: SoftwarePolicyTarget,
    rationale: String,
    owner_id: Option<i64>,
    valid_from: Option<String>,
    valid_until: Option<String>,
    policy_key: String,
    expected_revision: i64,
}

#[derive(Debug)]
struct NormalizedException {
    policy_id: i64,
    justification: String,
    compensating_controls: String,
    requested_valid_from: String,
    expires_at: String,
    request_key: String,
}

#[derive(Debug, Clone)]
struct ApplicablePolicy {
    id: i64,
    decision: String,
    updated_at: String,
    exception_id: Option<i64>,
}

#[derive(Debug, PartialEq, Eq)]
struct Decision {
    effective: &'static str,
    completeness: &'static str,
    policy_ids: Vec<i64>,
    exception_id: Option<i64>,
    path: String,
    review_required: bool,
}

struct AuditRecord<'a> {
    object_type: &'a str,
    object_id: i64,
    event_type: &'a str,
    previous_state: &'a str,
    new_state: &'a str,
    reason: &'a str,
    revision: i64,
    detail: &'a Value,
}

impl SoftwarePolicyStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Software-Policy-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Software-Policy-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite {
                pool,
                write_lock: Arc::new(Mutex::new(())),
            });
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Software-Policy-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite {
            pool,
            write_lock: Arc::new(Mutex::new(())),
        }
    }

    async fn sqlite_write_guard(&self) -> Option<MutexGuard<'_, ()>> {
        match self {
            Self::Sqlite { write_lock, .. } => Some(write_lock.lock().await),
            Self::Postgres(_) => None,
        }
    }

    pub async fn list_policies(
        &self,
        tenant_id: i64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SoftwarePolicySummary>, SoftwarePolicyError> {
        let (limit, offset) = normalize_pagination(limit, offset)?;
        match self {
            Self::Postgres(pool) => sqlx::query(&policy_list_sql(true))
                .bind(tenant_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await
                .map_err(|_| SoftwarePolicyError::database())?
                .into_iter()
                .map(policy_from_pg_row)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| SoftwarePolicyError::database()),
            Self::Sqlite { pool, .. } => sqlx::query(&policy_list_sql(false))
                .bind(tenant_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await
                .map_err(|_| SoftwarePolicyError::database())?
                .into_iter()
                .map(policy_from_sqlite_row)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| SoftwarePolicyError::database()),
        }
    }

    pub async fn get_policy(
        &self,
        tenant_id: i64,
        policy_id: i64,
    ) -> Result<SoftwarePolicySummary, SoftwarePolicyError> {
        match self {
            Self::Postgres(pool) => sqlx::query(&policy_by_id_sql(true, false))
                .bind(tenant_id)
                .bind(policy_id)
                .fetch_optional(pool)
                .await
                .map_err(|_| SoftwarePolicyError::database())?
                .map(policy_from_pg_row)
                .transpose()
                .map_err(|_| SoftwarePolicyError::database())?
                .ok_or_else(SoftwarePolicyError::not_found),
            Self::Sqlite { pool, .. } => sqlx::query(&policy_by_id_sql(false, false))
                .bind(tenant_id)
                .bind(policy_id)
                .fetch_optional(pool)
                .await
                .map_err(|_| SoftwarePolicyError::database())?
                .map(policy_from_sqlite_row)
                .transpose()
                .map_err(|_| SoftwarePolicyError::database())?
                .ok_or_else(SoftwarePolicyError::not_found),
        }
    }

    pub async fn create_policy(
        &self,
        tenant_id: i64,
        actor_id: i64,
        request: SoftwarePolicyCreateRequest,
    ) -> Result<SoftwarePolicyWriteResult, SoftwarePolicyError> {
        let normalized = normalize_policy_create(request)?;
        let _write_guard = self.sqlite_write_guard().await;
        match self {
            Self::Postgres(pool) => {
                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                validate_active_actor_pg(&mut tx, tenant_id, actor_id).await?;
                validate_target_pg(&mut tx, tenant_id, &normalized.target).await?;
                validate_owner_pg(&mut tx, tenant_id, normalized.owner_id).await?;
                if let Some(existing) =
                    policy_by_key_pg(&mut tx, tenant_id, &normalized.policy_key).await?
                {
                    ensure_same_policy(&existing, &normalized)?;
                    tx.commit()
                        .await
                        .map_err(|_| SoftwarePolicyError::database())?;
                    return Ok(SoftwarePolicyWriteResult {
                        created: false,
                        policy: existing,
                    });
                }
                let (policy, created) =
                    insert_policy_pg(&mut tx, tenant_id, actor_id, &normalized).await?;
                if created {
                    insert_audit_pg(
                        &mut tx,
                        tenant_id,
                        actor_id,
                        AuditRecord {
                            object_type: "POLICY",
                            object_id: policy.id,
                            event_type: "policy_created",
                            previous_state: "",
                            new_state: "DRAFT",
                            reason: "Policy-Entwurf erstellt.",
                            revision: policy.revision,
                            detail: &json!({"decision": policy.decision, "target": policy.target}),
                        },
                    )
                    .await?;
                }
                tx.commit()
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                Ok(SoftwarePolicyWriteResult { created, policy })
            }
            Self::Sqlite { pool, .. } => {
                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                validate_active_actor_sqlite(&mut tx, tenant_id, actor_id).await?;
                validate_target_sqlite(&mut tx, tenant_id, &normalized.target).await?;
                validate_owner_sqlite(&mut tx, tenant_id, normalized.owner_id).await?;
                if let Some(existing) =
                    policy_by_key_sqlite(&mut tx, tenant_id, &normalized.policy_key).await?
                {
                    ensure_same_policy(&existing, &normalized)?;
                    tx.commit()
                        .await
                        .map_err(|_| SoftwarePolicyError::database())?;
                    return Ok(SoftwarePolicyWriteResult {
                        created: false,
                        policy: existing,
                    });
                }
                let (policy, created) =
                    insert_policy_sqlite(&mut tx, tenant_id, actor_id, &normalized).await?;
                if created {
                    insert_audit_sqlite(
                        &mut tx,
                        tenant_id,
                        actor_id,
                        AuditRecord {
                            object_type: "POLICY",
                            object_id: policy.id,
                            event_type: "policy_created",
                            previous_state: "",
                            new_state: "DRAFT",
                            reason: "Policy-Entwurf erstellt.",
                            revision: policy.revision,
                            detail: &json!({"decision": policy.decision, "target": policy.target}),
                        },
                    )
                    .await?;
                }
                tx.commit()
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                Ok(SoftwarePolicyWriteResult { created, policy })
            }
        }
    }

    pub async fn update_policy(
        &self,
        tenant_id: i64,
        actor_id: i64,
        policy_id: i64,
        request: SoftwarePolicyUpdateRequest,
    ) -> Result<SoftwarePolicySummary, SoftwarePolicyError> {
        let normalized = normalize_policy_update(request)?;
        let _write_guard = self.sqlite_write_guard().await;
        match self {
            Self::Postgres(pool) => {
                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                validate_active_actor_pg(&mut tx, tenant_id, actor_id).await?;
                validate_owner_pg(&mut tx, tenant_id, normalized.owner_id).await?;
                let current = policy_by_id_pg(&mut tx, tenant_id, policy_id, true)
                    .await?
                    .ok_or_else(SoftwarePolicyError::not_found)?;
                let updated =
                    update_policy_pg(&mut tx, tenant_id, actor_id, &current, &normalized).await?;
                audit_policy_update_pg(&mut tx, tenant_id, actor_id, &current, &updated).await?;
                tx.commit()
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                Ok(updated)
            }
            Self::Sqlite { pool, .. } => {
                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                validate_active_actor_sqlite(&mut tx, tenant_id, actor_id).await?;
                validate_owner_sqlite(&mut tx, tenant_id, normalized.owner_id).await?;
                let current = policy_by_id_sqlite(&mut tx, tenant_id, policy_id)
                    .await?
                    .ok_or_else(SoftwarePolicyError::not_found)?;
                let updated =
                    update_policy_sqlite(&mut tx, tenant_id, actor_id, &current, &normalized)
                        .await?;
                audit_policy_update_sqlite(&mut tx, tenant_id, actor_id, &current, &updated)
                    .await?;
                tx.commit()
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                Ok(updated)
            }
        }
    }

    pub async fn activate_policy(
        &self,
        tenant_id: i64,
        actor_id: i64,
        policy_id: i64,
        request: SoftwarePolicyTransitionRequest,
    ) -> Result<SoftwarePolicySummary, SoftwarePolicyError> {
        self.transition_policy(tenant_id, actor_id, policy_id, request, "ACTIVE")
            .await
    }

    pub async fn archive_policy(
        &self,
        tenant_id: i64,
        actor_id: i64,
        policy_id: i64,
        request: SoftwarePolicyTransitionRequest,
    ) -> Result<SoftwarePolicySummary, SoftwarePolicyError> {
        self.transition_policy(tenant_id, actor_id, policy_id, request, "ARCHIVED")
            .await
    }

    async fn transition_policy(
        &self,
        tenant_id: i64,
        actor_id: i64,
        policy_id: i64,
        request: SoftwarePolicyTransitionRequest,
        target_status: &'static str,
    ) -> Result<SoftwarePolicySummary, SoftwarePolicyError> {
        let reason = required_text(request.reason, 1000, "policy_transition_reason_required")?;
        if request.expected_revision < 1 {
            return Err(stale_revision());
        }
        let _write_guard = self.sqlite_write_guard().await;
        match self {
            Self::Postgres(pool) => {
                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                validate_active_actor_pg(&mut tx, tenant_id, actor_id).await?;
                let current = policy_by_id_pg(&mut tx, tenant_id, policy_id, true)
                    .await?
                    .ok_or_else(SoftwarePolicyError::not_found)?;
                let updated = transition_policy_pg(
                    &mut tx,
                    tenant_id,
                    actor_id,
                    &current,
                    request.expected_revision,
                    target_status,
                )
                .await?;
                insert_audit_pg(
                    &mut tx,
                    tenant_id,
                    actor_id,
                    AuditRecord {
                        object_type: "POLICY",
                        object_id: policy_id,
                        event_type: if target_status == "ACTIVE" {
                            "policy_activated"
                        } else {
                            "policy_archived"
                        },
                        previous_state: &current.status,
                        new_state: target_status,
                        reason: &reason,
                        revision: updated.revision,
                        detail: &json!({"decision": updated.decision, "target": updated.target}),
                    },
                )
                .await?;
                tx.commit()
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                Ok(updated)
            }
            Self::Sqlite { pool, .. } => {
                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                validate_active_actor_sqlite(&mut tx, tenant_id, actor_id).await?;
                let current = policy_by_id_sqlite(&mut tx, tenant_id, policy_id)
                    .await?
                    .ok_or_else(SoftwarePolicyError::not_found)?;
                let updated = transition_policy_sqlite(
                    &mut tx,
                    tenant_id,
                    actor_id,
                    &current,
                    request.expected_revision,
                    target_status,
                )
                .await?;
                insert_audit_sqlite(
                    &mut tx,
                    tenant_id,
                    actor_id,
                    AuditRecord {
                        object_type: "POLICY",
                        object_id: policy_id,
                        event_type: if target_status == "ACTIVE" {
                            "policy_activated"
                        } else {
                            "policy_archived"
                        },
                        previous_state: &current.status,
                        new_state: target_status,
                        reason: &reason,
                        revision: updated.revision,
                        detail: &json!({"decision": updated.decision, "target": updated.target}),
                    },
                )
                .await?;
                tx.commit()
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                Ok(updated)
            }
        }
    }

    pub async fn list_exceptions(
        &self,
        tenant_id: i64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SoftwareExceptionSummary>, SoftwarePolicyError> {
        let (limit, offset) = normalize_pagination(limit, offset)?;
        match self {
            Self::Postgres(pool) => sqlx::query(&exception_list_sql(true))
                .bind(tenant_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await
                .map_err(|_| SoftwarePolicyError::database())?
                .into_iter()
                .map(exception_from_pg_row)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| SoftwarePolicyError::database()),
            Self::Sqlite { pool, .. } => sqlx::query(&exception_list_sql(false))
                .bind(tenant_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await
                .map_err(|_| SoftwarePolicyError::database())?
                .into_iter()
                .map(exception_from_sqlite_row)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| SoftwarePolicyError::database()),
        }
    }

    pub async fn create_exception(
        &self,
        tenant_id: i64,
        actor_id: i64,
        request: SoftwareExceptionCreateRequest,
    ) -> Result<SoftwareExceptionWriteResult, SoftwarePolicyError> {
        let normalized = normalize_exception(request, actor_id)?;
        let _write_guard = self.sqlite_write_guard().await;
        match self {
            Self::Postgres(pool) => {
                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                validate_active_actor_pg(&mut tx, tenant_id, actor_id).await?;
                let policy = policy_by_id_pg(&mut tx, tenant_id, normalized.policy_id, true)
                    .await?
                    .ok_or_else(SoftwarePolicyError::not_found)?;
                ensure_exception_policy_eligible(&policy)?;
                if let Some(existing) =
                    exception_by_key_pg(&mut tx, tenant_id, &normalized.request_key).await?
                {
                    ensure_same_exception(&existing, &normalized, actor_id)?;
                    tx.commit()
                        .await
                        .map_err(|_| SoftwarePolicyError::database())?;
                    return Ok(SoftwareExceptionWriteResult {
                        created: false,
                        exception: existing,
                    });
                }
                let (exception, created) =
                    insert_exception_pg(&mut tx, tenant_id, actor_id, &normalized).await?;
                if created {
                    insert_audit_pg(
                        &mut tx,
                        tenant_id,
                        actor_id,
                        AuditRecord {
                            object_type: "EXCEPTION",
                            object_id: exception.id,
                            event_type: "exception_created",
                            previous_state: "",
                            new_state: "DRAFT",
                            reason: "Ausnahme-Entwurf erstellt.",
                            revision: exception.revision,
                            detail: &json!({"policy_id": exception.policy_id, "expires_at": exception.expires_at}),
                        },
                    )
                    .await?;
                }
                tx.commit()
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                Ok(SoftwareExceptionWriteResult { created, exception })
            }
            Self::Sqlite { pool, .. } => {
                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                validate_active_actor_sqlite(&mut tx, tenant_id, actor_id).await?;
                let policy = policy_by_id_sqlite(&mut tx, tenant_id, normalized.policy_id)
                    .await?
                    .ok_or_else(SoftwarePolicyError::not_found)?;
                ensure_exception_policy_eligible(&policy)?;
                if let Some(existing) =
                    exception_by_key_sqlite(&mut tx, tenant_id, &normalized.request_key).await?
                {
                    ensure_same_exception(&existing, &normalized, actor_id)?;
                    tx.commit()
                        .await
                        .map_err(|_| SoftwarePolicyError::database())?;
                    return Ok(SoftwareExceptionWriteResult {
                        created: false,
                        exception: existing,
                    });
                }
                let (exception, created) =
                    insert_exception_sqlite(&mut tx, tenant_id, actor_id, &normalized).await?;
                if created {
                    insert_audit_sqlite(
                        &mut tx,
                        tenant_id,
                        actor_id,
                        AuditRecord {
                            object_type: "EXCEPTION",
                            object_id: exception.id,
                            event_type: "exception_created",
                            previous_state: "",
                            new_state: "DRAFT",
                            reason: "Ausnahme-Entwurf erstellt.",
                            revision: exception.revision,
                            detail: &json!({"policy_id": exception.policy_id, "expires_at": exception.expires_at}),
                        },
                    )
                    .await?;
                }
                tx.commit()
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                Ok(SoftwareExceptionWriteResult { created, exception })
            }
        }
    }

    pub async fn submit_exception(
        &self,
        tenant_id: i64,
        actor_id: i64,
        exception_id: i64,
        request: SoftwareExceptionTransitionRequest,
    ) -> Result<SoftwareExceptionSummary, SoftwarePolicyError> {
        self.transition_exception(
            tenant_id,
            actor_id,
            exception_id,
            request,
            ExceptionAction::Submit,
        )
        .await
    }

    pub async fn approve_exception(
        &self,
        tenant_id: i64,
        actor_id: i64,
        exception_id: i64,
        request: SoftwareExceptionTransitionRequest,
    ) -> Result<SoftwareExceptionSummary, SoftwarePolicyError> {
        self.transition_exception(
            tenant_id,
            actor_id,
            exception_id,
            request,
            ExceptionAction::Approve,
        )
        .await
    }

    pub async fn reject_exception(
        &self,
        tenant_id: i64,
        actor_id: i64,
        exception_id: i64,
        request: SoftwareExceptionTransitionRequest,
    ) -> Result<SoftwareExceptionSummary, SoftwarePolicyError> {
        self.transition_exception(
            tenant_id,
            actor_id,
            exception_id,
            request,
            ExceptionAction::Reject,
        )
        .await
    }

    pub async fn revoke_exception(
        &self,
        tenant_id: i64,
        actor_id: i64,
        exception_id: i64,
        request: SoftwareExceptionTransitionRequest,
    ) -> Result<SoftwareExceptionSummary, SoftwarePolicyError> {
        self.transition_exception(
            tenant_id,
            actor_id,
            exception_id,
            request,
            ExceptionAction::Revoke,
        )
        .await
    }

    async fn transition_exception(
        &self,
        tenant_id: i64,
        actor_id: i64,
        exception_id: i64,
        request: SoftwareExceptionTransitionRequest,
        action: ExceptionAction,
    ) -> Result<SoftwareExceptionSummary, SoftwarePolicyError> {
        let reason = required_text(request.reason, 1000, "exception_decision_reason_required")?;
        if request.expected_revision < 1 {
            return Err(stale_revision());
        }
        let now = utc_now();
        let _write_guard = self.sqlite_write_guard().await;
        match self {
            Self::Postgres(pool) => {
                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                validate_active_actor_pg(&mut tx, tenant_id, actor_id).await?;
                expire_exceptions_pg(&mut tx, tenant_id, actor_id, &now).await?;
                let current = exception_by_id_pg(&mut tx, tenant_id, exception_id, true)
                    .await?
                    .ok_or_else(SoftwarePolicyError::not_found)?;
                let policy = policy_by_id_pg(&mut tx, tenant_id, current.policy_id, true)
                    .await?
                    .ok_or_else(SoftwarePolicyError::not_found)?;
                validate_exception_transition(&current, &policy, actor_id, &now, action)?;
                let updated = transition_exception_pg(
                    &mut tx,
                    tenant_id,
                    actor_id,
                    &current,
                    ExceptionTransition {
                        expected_revision: request.expected_revision,
                        reason: &reason,
                        now: &now,
                        action,
                    },
                )
                .await?;
                audit_exception_transition_pg(
                    &mut tx, tenant_id, actor_id, &current, &updated, &reason, action,
                )
                .await?;
                tx.commit()
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                Ok(updated)
            }
            Self::Sqlite { pool, .. } => {
                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                validate_active_actor_sqlite(&mut tx, tenant_id, actor_id).await?;
                expire_exceptions_sqlite(&mut tx, tenant_id, actor_id, &now).await?;
                let current = exception_by_id_sqlite(&mut tx, tenant_id, exception_id)
                    .await?
                    .ok_or_else(SoftwarePolicyError::not_found)?;
                let policy = policy_by_id_sqlite(&mut tx, tenant_id, current.policy_id)
                    .await?
                    .ok_or_else(SoftwarePolicyError::not_found)?;
                validate_exception_transition(&current, &policy, actor_id, &now, action)?;
                let updated = transition_exception_sqlite(
                    &mut tx,
                    tenant_id,
                    actor_id,
                    &current,
                    ExceptionTransition {
                        expected_revision: request.expected_revision,
                        reason: &reason,
                        now: &now,
                        action,
                    },
                )
                .await?;
                audit_exception_transition_sqlite(
                    &mut tx, tenant_id, actor_id, &current, &updated, &reason, action,
                )
                .await?;
                tx.commit()
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                Ok(updated)
            }
        }
    }

    pub async fn evaluate(
        &self,
        tenant_id: i64,
        actor_id: i64,
        request: SoftwarePolicyEvaluationRequest,
    ) -> Result<SoftwarePolicyEvaluation, SoftwarePolicyError> {
        let target = normalize_target(request.target)?;
        let now = utc_now();
        let _write_guard = self.sqlite_write_guard().await;
        match self {
            Self::Postgres(pool) => {
                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                validate_active_actor_pg(&mut tx, tenant_id, actor_id).await?;
                let target_label = validate_target_pg(&mut tx, tenant_id, &target).await?;
                expire_exceptions_pg(&mut tx, tenant_id, actor_id, &now).await?;
                let policies = applicable_policies_pg(&mut tx, tenant_id, &target, &now).await?;
                let decision = evaluate_policies(&policies);
                let evaluation = persist_evaluation_pg(
                    &mut tx,
                    tenant_id,
                    actor_id,
                    &target,
                    &target_label,
                    &now,
                    decision,
                )
                .await?;
                tx.commit()
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                Ok(evaluation)
            }
            Self::Sqlite { pool, .. } => {
                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                validate_active_actor_sqlite(&mut tx, tenant_id, actor_id).await?;
                let target_label = validate_target_sqlite(&mut tx, tenant_id, &target).await?;
                expire_exceptions_sqlite(&mut tx, tenant_id, actor_id, &now).await?;
                let policies =
                    applicable_policies_sqlite(&mut tx, tenant_id, &target, &now).await?;
                let decision = evaluate_policies(&policies);
                let evaluation = persist_evaluation_sqlite(
                    &mut tx,
                    tenant_id,
                    actor_id,
                    &target,
                    &target_label,
                    &now,
                    decision,
                )
                .await?;
                tx.commit()
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                Ok(evaluation)
            }
        }
    }

    pub async fn get_evaluation(
        &self,
        tenant_id: i64,
        target: SoftwarePolicyTarget,
    ) -> Result<SoftwarePolicyEvaluation, SoftwarePolicyError> {
        let target = normalize_target(target)?;
        let now = utc_now();
        match self {
            Self::Postgres(pool) => {
                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                let target_label = validate_target_pg(&mut tx, tenant_id, &target).await?;
                let policies = applicable_policies_pg(&mut tx, tenant_id, &target, &now).await?;
                let decision = evaluate_policies(&policies);
                let data_fresh_at =
                    decision_data_fresh_at(&now, &decision.policy_ids, &mut tx, tenant_id).await?;
                tx.commit()
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                Ok(current_read_evaluation(
                    tenant_id,
                    target,
                    target_label,
                    now,
                    data_fresh_at,
                    decision,
                ))
            }
            Self::Sqlite { pool, .. } => {
                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                let target_label = validate_target_sqlite(&mut tx, tenant_id, &target).await?;
                let policies =
                    applicable_policies_sqlite(&mut tx, tenant_id, &target, &now).await?;
                let decision = evaluate_policies(&policies);
                let data_fresh_at =
                    decision_data_fresh_at_sqlite(&now, &decision.policy_ids, &mut tx, tenant_id)
                        .await?;
                tx.commit()
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                Ok(current_read_evaluation(
                    tenant_id,
                    target,
                    target_label,
                    now,
                    data_fresh_at,
                    decision,
                ))
            }
        }
    }

    pub async fn list_evaluations(
        &self,
        tenant_id: i64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SoftwarePolicyEvaluation>, SoftwarePolicyError> {
        let (limit, offset) = normalize_pagination(limit, offset)?;
        match self {
            Self::Postgres(pool) => {
                let rows = sqlx::query(&evaluation_list_sql(true))
                    .bind(tenant_id)
                    .bind(limit)
                    .bind(offset)
                    .fetch_all(pool)
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                rows.into_iter()
                    .map(|row| {
                        let label = row.try_get("target_label")?;
                        evaluation_from_pg_row(row, label)
                    })
                    .collect::<Result<Vec<_>, sqlx::Error>>()
                    .map_err(|_| SoftwarePolicyError::database())
            }
            Self::Sqlite { pool, .. } => {
                let rows = sqlx::query(&evaluation_list_sql(false))
                    .bind(tenant_id)
                    .bind(limit)
                    .bind(offset)
                    .fetch_all(pool)
                    .await
                    .map_err(|_| SoftwarePolicyError::database())?;
                rows.into_iter()
                    .map(|row| {
                        let label = row.try_get("target_label")?;
                        evaluation_from_sqlite_row(row, label)
                    })
                    .collect::<Result<Vec<_>, sqlx::Error>>()
                    .map_err(|_| SoftwarePolicyError::database())
            }
        }
    }

    pub async fn list_audit_events(
        &self,
        tenant_id: i64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SoftwarePolicyAuditEvent>, SoftwarePolicyError> {
        let (limit, offset) = normalize_pagination(limit, offset)?;
        match self {
            Self::Postgres(pool) => sqlx::query(
                "SELECT e.id,e.tenant_id,e.object_type,e.object_id,e.event_type,e.actor_id,COALESCE(u.username,'historical-user') AS actor_display,e.previous_state,e.new_state,e.reason,e.revision,e.detail_json,e.created_at::text AS created_at FROM software_policy_audit_event e LEFT JOIN accounts_user u ON u.tenant_id=e.tenant_id AND u.id=e.actor_id WHERE e.tenant_id=$1 ORDER BY e.created_at DESC,e.id DESC LIMIT $2 OFFSET $3",
            )
            .bind(tenant_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await
            .map_err(|_| SoftwarePolicyError::database())?
            .into_iter()
            .map(audit_from_pg_row)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| SoftwarePolicyError::database()),
            Self::Sqlite { pool, .. } => sqlx::query(
                "SELECT e.id,e.tenant_id,e.object_type,e.object_id,e.event_type,e.actor_id,COALESCE(u.username,'historical-user') AS actor_display,e.previous_state,e.new_state,e.reason,e.revision,e.detail_json,CAST(e.created_at AS TEXT) AS created_at FROM software_policy_audit_event e LEFT JOIN accounts_user u ON u.tenant_id=e.tenant_id AND u.id=e.actor_id WHERE e.tenant_id=?1 ORDER BY e.created_at DESC,e.id DESC LIMIT ?2 OFFSET ?3",
            )
            .bind(tenant_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await
            .map_err(|_| SoftwarePolicyError::database())?
            .into_iter()
            .map(audit_from_sqlite_row)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| SoftwarePolicyError::database()),
        }
    }

    pub async fn list_target_options(
        &self,
        tenant_id: i64,
        limit_per_type: i64,
    ) -> Result<Vec<SoftwarePolicyTargetOption>, SoftwarePolicyError> {
        let limit = limit_per_type.clamp(1, 100);
        match self {
            Self::Postgres(pool) => list_target_options_pg(pool, tenant_id, limit).await,
            Self::Sqlite { pool, .. } => list_target_options_sqlite(pool, tenant_id, limit).await,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExceptionAction {
    Submit,
    Approve,
    Reject,
    Revoke,
}

struct ExceptionTransition<'a> {
    expected_revision: i64,
    reason: &'a str,
    now: &'a str,
    action: ExceptionAction,
}

impl ExceptionAction {
    fn status(self) -> &'static str {
        match self {
            Self::Submit => "PENDING_REVIEW",
            Self::Approve => "APPROVED",
            Self::Reject => "REJECTED",
            Self::Revoke => "REVOKED",
        }
    }

    fn event(self) -> &'static str {
        match self {
            Self::Submit => "exception_submitted",
            Self::Approve => "exception_approved",
            Self::Reject => "exception_rejected",
            Self::Revoke => "exception_revoked",
        }
    }
}

fn normalize_policy_create(
    request: SoftwarePolicyCreateRequest,
) -> Result<NormalizedPolicy, SoftwarePolicyError> {
    let target = normalize_target(request.target)?;
    let name = required_text(request.name, 255, "software_policy_name_required")?;
    let description = optional_text(
        request.description,
        4000,
        "software_policy_description_too_long",
    )?;
    let decision = normalize_enum(
        request.decision,
        &POLICY_DECISIONS,
        "invalid_software_policy_decision",
        "Die Policy-Entscheidung ist nicht unterstuetzt.",
    )?;
    let rationale = required_text(
        request.rationale,
        4000,
        "software_policy_rationale_required",
    )?;
    let (valid_from, valid_until) =
        normalize_optional_window(request.valid_from, request.valid_until)?;
    let policy_key = sha256_hex(
        format!(
            "{}:{}:{}:{}",
            target.target_type,
            target.target_id,
            name.to_lowercase(),
            decision
        )
        .as_bytes(),
    );
    Ok(NormalizedPolicy {
        name,
        description,
        decision,
        target,
        rationale,
        owner_id: positive_optional_id(request.owner_id, "invalid_software_policy_owner")?,
        valid_from,
        valid_until,
        policy_key,
        expected_revision: 0,
    })
}

fn normalize_policy_update(
    request: SoftwarePolicyUpdateRequest,
) -> Result<NormalizedPolicy, SoftwarePolicyError> {
    if request.expected_revision < 1 {
        return Err(stale_revision());
    }
    let name = required_text(request.name, 255, "software_policy_name_required")?;
    let description = optional_text(
        request.description,
        4000,
        "software_policy_description_too_long",
    )?;
    let decision = normalize_enum(
        request.decision,
        &POLICY_DECISIONS,
        "invalid_software_policy_decision",
        "Die Policy-Entscheidung ist nicht unterstuetzt.",
    )?;
    let rationale = required_text(
        request.rationale,
        4000,
        "software_policy_rationale_required",
    )?;
    let (valid_from, valid_until) =
        normalize_optional_window(request.valid_from, request.valid_until)?;
    Ok(NormalizedPolicy {
        name,
        description,
        decision,
        target: SoftwarePolicyTarget {
            target_type: String::new(),
            target_id: 0,
        },
        rationale,
        owner_id: positive_optional_id(request.owner_id, "invalid_software_policy_owner")?,
        valid_from,
        valid_until,
        policy_key: String::new(),
        expected_revision: request.expected_revision,
    })
}

fn normalize_exception(
    request: SoftwareExceptionCreateRequest,
    applicant_id: i64,
) -> Result<NormalizedException, SoftwarePolicyError> {
    if request.policy_id < 1 || applicant_id < 1 {
        return Err(SoftwarePolicyError::invalid(
            "invalid_software_exception_reference",
            "Die Ausnahme referenziert kein gueltiges Objekt.",
        ));
    }
    let justification = required_text(
        request.justification,
        4000,
        "software_exception_justification_required",
    )?;
    let compensating_controls = optional_text(
        request.compensating_controls,
        4000,
        "software_exception_controls_too_long",
    )?;
    let requested_valid_from = normalize_timestamp(&request.requested_valid_from)?;
    let expires_at = normalize_timestamp(&request.expires_at)?;
    let from = parse_timestamp(&requested_valid_from)?;
    let until = parse_timestamp(&expires_at)?;
    let now = Utc::now();
    if until <= from || until <= now {
        return Err(SoftwarePolicyError::invalid(
            "invalid_software_exception_window",
            "Die Ausnahme muss ein zukuenftiges Ablaufdatum nach ihrem Beginn besitzen.",
        ));
    }
    let request_key = sha256_hex(
        format!(
            "{}:{}:{}:{}:{}:{}",
            request.policy_id,
            applicant_id,
            requested_valid_from,
            expires_at,
            justification,
            compensating_controls
        )
        .as_bytes(),
    );
    Ok(NormalizedException {
        policy_id: request.policy_id,
        justification,
        compensating_controls,
        requested_valid_from,
        expires_at,
        request_key,
    })
}

fn normalize_target(
    target: SoftwarePolicyTarget,
) -> Result<SoftwarePolicyTarget, SoftwarePolicyError> {
    if target.target_id < 1 {
        return Err(SoftwarePolicyError::invalid(
            "invalid_software_policy_target",
            "Das Software-Policy-Ziel ist ungueltig.",
        ));
    }
    Ok(SoftwarePolicyTarget {
        target_type: normalize_enum(
            target.target_type,
            &TARGET_TYPES,
            "invalid_software_policy_target",
            "Der Software-Policy-Zieltyp ist nicht unterstuetzt.",
        )?,
        target_id: target.target_id,
    })
}

fn normalize_pagination(limit: i64, offset: i64) -> Result<(i64, i64), SoftwarePolicyError> {
    if !(1..=200).contains(&limit) || !(0..=100_000).contains(&offset) {
        return Err(SoftwarePolicyError::invalid(
            "invalid_software_policy_pagination",
            "Limit oder Offset liegen ausserhalb des zulaessigen Bereichs.",
        ));
    }
    Ok((limit, offset))
}

fn normalize_optional_window(
    valid_from: Option<String>,
    valid_until: Option<String>,
) -> Result<(Option<String>, Option<String>), SoftwarePolicyError> {
    let valid_from = valid_from
        .filter(|value| !value.trim().is_empty())
        .map(|value| normalize_timestamp(&value))
        .transpose()?;
    let valid_until = valid_until
        .filter(|value| !value.trim().is_empty())
        .map(|value| normalize_timestamp(&value))
        .transpose()?;
    if let (Some(from), Some(until)) = (&valid_from, &valid_until) {
        if parse_timestamp(until)? <= parse_timestamp(from)? {
            return Err(SoftwarePolicyError::invalid(
                "invalid_software_policy_window",
                "Das Policy-Ende muss nach dem Policy-Beginn liegen.",
            ));
        }
    }
    Ok((valid_from, valid_until))
}

fn normalize_timestamp(value: &str) -> Result<String, SoftwarePolicyError> {
    Ok(parse_timestamp(value)?.to_rfc3339_opts(SecondsFormat::Secs, true))
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, SoftwarePolicyError> {
    DateTime::parse_from_rfc3339(value.trim())
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| {
            SoftwarePolicyError::invalid(
                "invalid_software_policy_timestamp",
                "Ein Zeitwert ist kein gueltiger RFC-3339-Zeitpunkt.",
            )
        })
}

fn utc_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn required_text(
    value: String,
    max_bytes: usize,
    code: &'static str,
) -> Result<String, SoftwarePolicyError> {
    let value = value.trim().to_string();
    if value.is_empty() || value.len() > max_bytes {
        return Err(SoftwarePolicyError::invalid(
            code,
            "Ein erforderliches Textfeld fehlt oder ist zu lang.",
        ));
    }
    Ok(value)
}

fn optional_text(
    value: Option<String>,
    max_bytes: usize,
    code: &'static str,
) -> Result<String, SoftwarePolicyError> {
    let value = value.unwrap_or_default().trim().to_string();
    if value.len() > max_bytes {
        return Err(SoftwarePolicyError::invalid(
            code,
            "Ein Textfeld ist zu lang.",
        ));
    }
    Ok(value)
}

fn positive_optional_id(
    value: Option<i64>,
    code: &'static str,
) -> Result<Option<i64>, SoftwarePolicyError> {
    if value.is_some_and(|id| id < 1) {
        return Err(SoftwarePolicyError::invalid(
            code,
            "Die referenzierte Benutzer-ID ist ungueltig.",
        ));
    }
    Ok(value)
}

fn normalize_enum(
    value: String,
    allowed: &[&str],
    code: &'static str,
    message: &'static str,
) -> Result<String, SoftwarePolicyError> {
    let normalized = value.trim().to_ascii_uppercase();
    if !allowed.contains(&normalized.as_str()) {
        return Err(SoftwarePolicyError::invalid(code, message));
    }
    Ok(normalized)
}

fn sha256_hex(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn stale_revision() -> SoftwarePolicyError {
    SoftwarePolicyError::conflict(
        "stale_software_policy_revision",
        "Das Objekt wurde zwischenzeitlich geaendert. Bitte laden Sie es neu.",
    )
}

fn ensure_same_policy(
    existing: &SoftwarePolicySummary,
    normalized: &NormalizedPolicy,
) -> Result<(), SoftwarePolicyError> {
    if existing.name == normalized.name
        && existing.decision == normalized.decision
        && existing.target == normalized.target
        && existing.rationale == normalized.rationale
        && existing.description == normalized.description
        && existing.owner_id == normalized.owner_id
        && existing.valid_from == normalized.valid_from
        && existing.valid_until == normalized.valid_until
    {
        return Ok(());
    }
    Err(SoftwarePolicyError::conflict(
        "software_policy_idempotency_conflict",
        "Eine Policy mit demselben stabilen Schluessel besitzt andere Inhalte.",
    ))
}

fn ensure_same_exception(
    existing: &SoftwareExceptionSummary,
    normalized: &NormalizedException,
    applicant_id: i64,
) -> Result<(), SoftwarePolicyError> {
    if existing.policy_id == normalized.policy_id
        && existing.applicant_id == applicant_id
        && existing.justification == normalized.justification
        && existing.compensating_controls == normalized.compensating_controls
        && existing.requested_valid_from == normalized.requested_valid_from
        && existing.expires_at == normalized.expires_at
    {
        return Ok(());
    }
    Err(SoftwarePolicyError::conflict(
        "software_exception_idempotency_conflict",
        "Eine Ausnahme mit demselben stabilen Schluessel besitzt andere Inhalte.",
    ))
}

fn ensure_exception_policy_eligible(
    policy: &SoftwarePolicySummary,
) -> Result<(), SoftwarePolicyError> {
    if policy.status == "ARCHIVED" {
        return Err(SoftwarePolicyError::conflict(
            "software_policy_archived",
            "Fuer eine archivierte Policy kann keine Ausnahme beantragt werden.",
        ));
    }
    if !matches!(policy.decision.as_str(), "RESTRICTED" | "PROHIBITED") {
        return Err(SoftwarePolicyError::invalid(
            "software_exception_requires_restrictive_policy",
            "Ausnahmen sind nur fuer eingeschraenkte oder untersagte Policies zulaessig.",
        ));
    }
    Ok(())
}

fn validate_exception_transition(
    exception: &SoftwareExceptionSummary,
    policy: &SoftwarePolicySummary,
    actor_id: i64,
    now: &str,
    action: ExceptionAction,
) -> Result<(), SoftwarePolicyError> {
    if exception.revision < 1 || !EXCEPTION_STATUSES.contains(&exception.status.as_str()) {
        return Err(SoftwarePolicyError::conflict(
            "software_exception_inconsistent",
            "Die Ausnahme besitzt keinen belastbaren Zustand.",
        ));
    }
    let allowed = match action {
        ExceptionAction::Submit => {
            exception.status == "DRAFT" && actor_id == exception.applicant_id
        }
        ExceptionAction::Approve | ExceptionAction::Reject => exception.status == "PENDING_REVIEW",
        ExceptionAction::Revoke => exception.status == "APPROVED",
    };
    if !allowed {
        return Err(SoftwarePolicyError::conflict(
            "invalid_software_exception_transition",
            "Der Statuswechsel der Ausnahme ist nicht zulaessig.",
        ));
    }
    if matches!(action, ExceptionAction::Approve | ExceptionAction::Reject)
        && actor_id == exception.applicant_id
    {
        return Err(SoftwarePolicyError::conflict(
            "software_exception_self_approval_denied",
            "Antragsteller duerfen ihre eigene Ausnahme nicht entscheiden.",
        ));
    }
    if action == ExceptionAction::Approve {
        if policy.status != "ACTIVE" || !policy_is_effective(policy, now)? {
            return Err(SoftwarePolicyError::conflict(
                "software_policy_not_effective",
                "Nur eine aktuell wirksame Policy kann ausnahmsweise genehmigt werden.",
            ));
        }
        if parse_timestamp(&exception.expires_at)? <= parse_timestamp(now)? {
            return Err(SoftwarePolicyError::conflict(
                "software_exception_expired",
                "Eine bereits abgelaufene Ausnahme kann nicht genehmigt werden.",
            ));
        }
    }
    Ok(())
}

fn policy_is_effective(
    policy: &SoftwarePolicySummary,
    now: &str,
) -> Result<bool, SoftwarePolicyError> {
    let now = parse_timestamp(now)?;
    if policy
        .valid_from
        .as_deref()
        .map(parse_timestamp)
        .transpose()?
        .is_some_and(|from| from > now)
    {
        return Ok(false);
    }
    if policy
        .valid_until
        .as_deref()
        .map(parse_timestamp)
        .transpose()?
        .is_some_and(|until| until <= now)
    {
        return Ok(false);
    }
    Ok(true)
}

fn evaluate_policies(policies: &[ApplicablePolicy]) -> Decision {
    if policies.is_empty() {
        return Decision {
            effective: "UNMANAGED",
            completeness: "COMPLETE",
            policy_ids: Vec::new(),
            exception_id: None,
            path: "Keine aktuell wirksame Policy fuer das exakte tenantgebundene Ziel.".to_string(),
            review_required: false,
        };
    }
    if policies.iter().any(|policy| {
        !POLICY_DECISIONS.contains(&policy.decision.as_str()) || policy.updated_at.is_empty()
    }) {
        return Decision {
            effective: "REVIEW_REQUIRED",
            completeness: "INDETERMINATE",
            policy_ids: sorted_policy_ids(policies),
            exception_id: None,
            path: "Mindestens eine passende Policy ist unvollstaendig oder widerspruechlich."
                .to_string(),
            review_required: true,
        };
    }
    let unexcepted_prohibited = policies
        .iter()
        .filter(|policy| policy.decision == "PROHIBITED" && policy.exception_id.is_none())
        .collect::<Vec<_>>();
    if !unexcepted_prohibited.is_empty() {
        return restrictive_decision("PROHIBITED", policies, &unexcepted_prohibited);
    }
    let unexcepted_restricted = policies
        .iter()
        .filter(|policy| policy.decision == "RESTRICTED" && policy.exception_id.is_none())
        .collect::<Vec<_>>();
    if !unexcepted_restricted.is_empty() {
        return restrictive_decision("RESTRICTED", policies, &unexcepted_restricted);
    }
    let mut active_exceptions = policies
        .iter()
        .filter_map(|policy| policy.exception_id)
        .collect::<Vec<_>>();
    active_exceptions.sort_unstable();
    active_exceptions.dedup();
    if let Some(exception_id) = active_exceptions.first().copied() {
        return Decision {
            effective: "EXCEPTION_ACTIVE",
            completeness: "COMPLETE",
            policy_ids: sorted_policy_ids(policies),
            exception_id: Some(exception_id),
            path: "Eine befristete genehmigte Ausnahme neutralisiert ausschliesslich ihre referenzierte restriktive Policy; keine weitere restriktive Policy bleibt unberuecksichtigt.".to_string(),
            review_required: false,
        };
    }
    Decision {
        effective: "APPROVED",
        completeness: "COMPLETE",
        policy_ids: sorted_policy_ids(policies),
        exception_id: None,
        path: "Mindestens eine aktuell wirksame Policy gibt das exakte Ziel ausdruecklich frei; keine wirksamere restriktive Policy liegt vor.".to_string(),
        review_required: false,
    }
}

fn restrictive_decision(
    effective: &'static str,
    policies: &[ApplicablePolicy],
    restrictive: &[&ApplicablePolicy],
) -> Decision {
    Decision {
        effective,
        completeness: "COMPLETE",
        policy_ids: sorted_policy_ids(policies),
        exception_id: None,
        path: format!(
            "Die restriktivste aktuell wirksame, nicht ausgenommene Entscheidung ist {effective}; {} passende restriktive Policy/Policies bestimmen das Ergebnis.",
            restrictive.len()
        ),
        review_required: false,
    }
}

fn sorted_policy_ids(policies: &[ApplicablePolicy]) -> Vec<i64> {
    let mut ids = policies.iter().map(|policy| policy.id).collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn current_read_evaluation(
    tenant_id: i64,
    target: SoftwarePolicyTarget,
    target_label: String,
    evaluated_at: String,
    data_fresh_at: String,
    decision: Decision,
) -> SoftwarePolicyEvaluation {
    SoftwarePolicyEvaluation {
        id: 0,
        tenant_id,
        target,
        target_label,
        effective_decision: decision.effective.to_string(),
        completeness_status: decision.completeness.to_string(),
        policy_ids: decision.policy_ids,
        exception_id: decision.exception_id,
        decision_path: decision.path,
        review_required: decision.review_required,
        evaluated_at,
        data_fresh_at,
        revision: 0,
    }
}

fn policy_list_sql(postgres: bool) -> String {
    let (p1, p2, p3) = if postgres {
        ("$1", "$2", "$3")
    } else {
        ("?1", "?2", "?3")
    };
    format!(
        "{} WHERE p.tenant_id={p1} ORDER BY p.updated_at DESC,p.id DESC LIMIT {p2} OFFSET {p3}",
        policy_select(postgres)
    )
}

fn policy_by_id_sql(postgres: bool, for_update: bool) -> String {
    let (p1, p2) = if postgres { ("$1", "$2") } else { ("?1", "?2") };
    format!(
        "{} WHERE p.tenant_id={p1} AND p.id={p2}{}",
        policy_select(postgres),
        if postgres && for_update {
            " FOR UPDATE OF p"
        } else {
            ""
        }
    )
}

fn policy_select(postgres: bool) -> &'static str {
    if postgres {
        "SELECT p.id,p.tenant_id,p.name,p.description,p.status,p.decision,p.target_type,p.product_id,p.asset_id,p.component_id,p.sbom_component_id,COALESCE(pr.name,a.name,c.name,ic.name,'') AS target_label,p.rationale,p.owner_id,owner.username AS owner_display,p.created_by_id,COALESCE(creator.username,'historical-user') AS created_by_display,p.updated_by_id,COALESCE(updater.username,'historical-user') AS updated_by_display,p.valid_from,p.valid_until,p.revision,p.activated_at,p.archived_at,p.created_at::text AS created_at,p.updated_at::text AS updated_at FROM software_approval_policy p LEFT JOIN product_security_product pr ON p.target_type='PRODUCT' AND pr.tenant_id=p.tenant_id AND pr.id=p.product_id LEFT JOIN assets_app_informationasset a ON p.target_type='ASSET' AND a.tenant_id=p.tenant_id AND a.id=p.asset_id LEFT JOIN product_security_component c ON p.target_type='COMPONENT' AND c.tenant_id=p.tenant_id AND c.id=p.component_id LEFT JOIN product_security_importcomponent ic ON p.target_type='SBOM_COMPONENT' AND ic.tenant_id=p.tenant_id AND ic.id=p.sbom_component_id LEFT JOIN accounts_user owner ON owner.tenant_id=p.tenant_id AND owner.id=p.owner_id LEFT JOIN accounts_user creator ON creator.tenant_id=p.tenant_id AND creator.id=p.created_by_id LEFT JOIN accounts_user updater ON updater.tenant_id=p.tenant_id AND updater.id=p.updated_by_id"
    } else {
        "SELECT p.id,p.tenant_id,p.name,p.description,p.status,p.decision,p.target_type,p.product_id,p.asset_id,p.component_id,p.sbom_component_id,COALESCE(pr.name,a.name,c.name,ic.name,'') AS target_label,p.rationale,p.owner_id,owner.username AS owner_display,p.created_by_id,COALESCE(creator.username,'historical-user') AS created_by_display,p.updated_by_id,COALESCE(updater.username,'historical-user') AS updated_by_display,p.valid_from,p.valid_until,p.revision,p.activated_at,p.archived_at,CAST(p.created_at AS TEXT) AS created_at,CAST(p.updated_at AS TEXT) AS updated_at FROM software_approval_policy p LEFT JOIN product_security_product pr ON p.target_type='PRODUCT' AND pr.tenant_id=p.tenant_id AND pr.id=p.product_id LEFT JOIN assets_app_informationasset a ON p.target_type='ASSET' AND a.tenant_id=p.tenant_id AND a.id=p.asset_id LEFT JOIN product_security_component c ON p.target_type='COMPONENT' AND c.tenant_id=p.tenant_id AND c.id=p.component_id LEFT JOIN product_security_importcomponent ic ON p.target_type='SBOM_COMPONENT' AND ic.tenant_id=p.tenant_id AND ic.id=p.sbom_component_id LEFT JOIN accounts_user owner ON owner.tenant_id=p.tenant_id AND owner.id=p.owner_id LEFT JOIN accounts_user creator ON creator.tenant_id=p.tenant_id AND creator.id=p.created_by_id LEFT JOIN accounts_user updater ON updater.tenant_id=p.tenant_id AND updater.id=p.updated_by_id"
    }
}

fn exception_list_sql(postgres: bool) -> String {
    let (p1, p2, p3) = if postgres {
        ("$1", "$2", "$3")
    } else {
        ("?1", "?2", "?3")
    };
    format!(
        "{} WHERE e.tenant_id={p1} ORDER BY e.updated_at DESC,e.id DESC LIMIT {p2} OFFSET {p3}",
        exception_select(postgres)
    )
}

fn exception_select(postgres: bool) -> &'static str {
    if postgres {
        "SELECT e.id,e.tenant_id,e.policy_id,p.name AS policy_name,p.target_type,p.product_id,p.asset_id,p.component_id,p.sbom_component_id,COALESCE(pr.name,a.name,c.name,ic.name,'') AS target_label,e.applicant_id,COALESCE(applicant.username,'historical-user') AS applicant_display,e.justification,e.compensating_controls,e.requested_valid_from,e.expires_at,e.status,e.reviewer_id,reviewer.username AS reviewer_display,e.decision_reason,e.decision_at,e.revoked_at,e.expired_at,e.revision,e.created_at::text AS created_at,e.updated_at::text AS updated_at FROM software_policy_exception e JOIN software_approval_policy p ON p.tenant_id=e.tenant_id AND p.id=e.policy_id LEFT JOIN product_security_product pr ON p.target_type='PRODUCT' AND pr.tenant_id=p.tenant_id AND pr.id=p.product_id LEFT JOIN assets_app_informationasset a ON p.target_type='ASSET' AND a.tenant_id=p.tenant_id AND a.id=p.asset_id LEFT JOIN product_security_component c ON p.target_type='COMPONENT' AND c.tenant_id=p.tenant_id AND c.id=p.component_id LEFT JOIN product_security_importcomponent ic ON p.target_type='SBOM_COMPONENT' AND ic.tenant_id=p.tenant_id AND ic.id=p.sbom_component_id LEFT JOIN accounts_user applicant ON applicant.tenant_id=e.tenant_id AND applicant.id=e.applicant_id LEFT JOIN accounts_user reviewer ON reviewer.tenant_id=e.tenant_id AND reviewer.id=e.reviewer_id"
    } else {
        "SELECT e.id,e.tenant_id,e.policy_id,p.name AS policy_name,p.target_type,p.product_id,p.asset_id,p.component_id,p.sbom_component_id,COALESCE(pr.name,a.name,c.name,ic.name,'') AS target_label,e.applicant_id,COALESCE(applicant.username,'historical-user') AS applicant_display,e.justification,e.compensating_controls,e.requested_valid_from,e.expires_at,e.status,e.reviewer_id,reviewer.username AS reviewer_display,e.decision_reason,e.decision_at,e.revoked_at,e.expired_at,e.revision,CAST(e.created_at AS TEXT) AS created_at,CAST(e.updated_at AS TEXT) AS updated_at FROM software_policy_exception e JOIN software_approval_policy p ON p.tenant_id=e.tenant_id AND p.id=e.policy_id LEFT JOIN product_security_product pr ON p.target_type='PRODUCT' AND pr.tenant_id=p.tenant_id AND pr.id=p.product_id LEFT JOIN assets_app_informationasset a ON p.target_type='ASSET' AND a.tenant_id=p.tenant_id AND a.id=p.asset_id LEFT JOIN product_security_component c ON p.target_type='COMPONENT' AND c.tenant_id=p.tenant_id AND c.id=p.component_id LEFT JOIN product_security_importcomponent ic ON p.target_type='SBOM_COMPONENT' AND ic.tenant_id=p.tenant_id AND ic.id=p.sbom_component_id LEFT JOIN accounts_user applicant ON applicant.tenant_id=e.tenant_id AND applicant.id=e.applicant_id LEFT JOIN accounts_user reviewer ON reviewer.tenant_id=e.tenant_id AND reviewer.id=e.reviewer_id"
    }
}

fn target_from_columns(
    target_type: String,
    product_id: Option<i64>,
    asset_id: Option<i64>,
    component_id: Option<i64>,
    sbom_component_id: Option<i64>,
) -> Result<SoftwarePolicyTarget, sqlx::Error> {
    let target_id = match target_type.as_str() {
        "PRODUCT" => product_id,
        "ASSET" => asset_id,
        "COMPONENT" => component_id,
        "SBOM_COMPONENT" => sbom_component_id,
        _ => None,
    }
    .ok_or(sqlx::Error::ColumnNotFound(
        "software_policy_target_id".to_string(),
    ))?;
    Ok(SoftwarePolicyTarget {
        target_type,
        target_id,
    })
}

fn policy_from_pg_row(row: PgRow) -> Result<SoftwarePolicySummary, sqlx::Error> {
    let target = target_from_columns(
        row.try_get("target_type")?,
        row.try_get("product_id")?,
        row.try_get("asset_id")?,
        row.try_get("component_id")?,
        row.try_get("sbom_component_id")?,
    )?;
    Ok(SoftwarePolicySummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        status: row.try_get("status")?,
        decision: row.try_get("decision")?,
        target,
        target_label: row.try_get("target_label")?,
        rationale: row.try_get("rationale")?,
        owner_id: row.try_get("owner_id")?,
        owner_display: row.try_get("owner_display")?,
        created_by_id: row.try_get("created_by_id")?,
        created_by_display: row.try_get("created_by_display")?,
        updated_by_id: row.try_get("updated_by_id")?,
        updated_by_display: row.try_get("updated_by_display")?,
        valid_from: row.try_get("valid_from")?,
        valid_until: row.try_get("valid_until")?,
        revision: row.try_get("revision")?,
        activated_at: row.try_get("activated_at")?,
        archived_at: row.try_get("archived_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn policy_from_sqlite_row(row: SqliteRow) -> Result<SoftwarePolicySummary, sqlx::Error> {
    let target = target_from_columns(
        row.try_get("target_type")?,
        row.try_get("product_id")?,
        row.try_get("asset_id")?,
        row.try_get("component_id")?,
        row.try_get("sbom_component_id")?,
    )?;
    Ok(SoftwarePolicySummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        status: row.try_get("status")?,
        decision: row.try_get("decision")?,
        target,
        target_label: row.try_get("target_label")?,
        rationale: row.try_get("rationale")?,
        owner_id: row.try_get("owner_id")?,
        owner_display: row.try_get("owner_display")?,
        created_by_id: row.try_get("created_by_id")?,
        created_by_display: row.try_get("created_by_display")?,
        updated_by_id: row.try_get("updated_by_id")?,
        updated_by_display: row.try_get("updated_by_display")?,
        valid_from: row.try_get("valid_from")?,
        valid_until: row.try_get("valid_until")?,
        revision: row.try_get("revision")?,
        activated_at: row.try_get("activated_at")?,
        archived_at: row.try_get("archived_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn exception_from_pg_row(row: PgRow) -> Result<SoftwareExceptionSummary, sqlx::Error> {
    let target = target_from_columns(
        row.try_get("target_type")?,
        row.try_get("product_id")?,
        row.try_get("asset_id")?,
        row.try_get("component_id")?,
        row.try_get("sbom_component_id")?,
    )?;
    Ok(with_effective_exception_status(SoftwareExceptionSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        policy_id: row.try_get("policy_id")?,
        policy_name: row.try_get("policy_name")?,
        target,
        target_label: row.try_get("target_label")?,
        applicant_id: row.try_get("applicant_id")?,
        applicant_display: row.try_get("applicant_display")?,
        justification: row.try_get("justification")?,
        compensating_controls: row.try_get("compensating_controls")?,
        requested_valid_from: row.try_get("requested_valid_from")?,
        expires_at: row.try_get("expires_at")?,
        status: row.try_get("status")?,
        reviewer_id: row.try_get("reviewer_id")?,
        reviewer_display: row.try_get("reviewer_display")?,
        decision_reason: row.try_get("decision_reason")?,
        decision_at: row.try_get("decision_at")?,
        revoked_at: row.try_get("revoked_at")?,
        expired_at: row.try_get("expired_at")?,
        revision: row.try_get("revision")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    }))
}

fn exception_from_sqlite_row(row: SqliteRow) -> Result<SoftwareExceptionSummary, sqlx::Error> {
    let target = target_from_columns(
        row.try_get("target_type")?,
        row.try_get("product_id")?,
        row.try_get("asset_id")?,
        row.try_get("component_id")?,
        row.try_get("sbom_component_id")?,
    )?;
    Ok(with_effective_exception_status(SoftwareExceptionSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        policy_id: row.try_get("policy_id")?,
        policy_name: row.try_get("policy_name")?,
        target,
        target_label: row.try_get("target_label")?,
        applicant_id: row.try_get("applicant_id")?,
        applicant_display: row.try_get("applicant_display")?,
        justification: row.try_get("justification")?,
        compensating_controls: row.try_get("compensating_controls")?,
        requested_valid_from: row.try_get("requested_valid_from")?,
        expires_at: row.try_get("expires_at")?,
        status: row.try_get("status")?,
        reviewer_id: row.try_get("reviewer_id")?,
        reviewer_display: row.try_get("reviewer_display")?,
        decision_reason: row.try_get("decision_reason")?,
        decision_at: row.try_get("decision_at")?,
        revoked_at: row.try_get("revoked_at")?,
        expired_at: row.try_get("expired_at")?,
        revision: row.try_get("revision")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    }))
}

fn with_effective_exception_status(
    mut exception: SoftwareExceptionSummary,
) -> SoftwareExceptionSummary {
    let expired = exception.status == "APPROVED"
        && DateTime::parse_from_rfc3339(&exception.expires_at)
            .map(|expires_at| expires_at.with_timezone(&Utc) <= Utc::now())
            .unwrap_or(true);
    if expired {
        exception.status = "EXPIRED".to_string();
        if exception.expired_at.is_none() {
            exception.expired_at = Some(exception.expires_at.clone());
        }
    }
    exception
}

fn evaluation_from_pg_row(
    row: PgRow,
    target_label: String,
) -> Result<SoftwarePolicyEvaluation, sqlx::Error> {
    let target = target_from_columns(
        row.try_get("target_type")?,
        row.try_get("product_id")?,
        row.try_get("asset_id")?,
        row.try_get("component_id")?,
        row.try_get("sbom_component_id")?,
    )?;
    let policy_ids_json: String = row.try_get("policy_ids_json")?;
    Ok(SoftwarePolicyEvaluation {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        target,
        target_label,
        effective_decision: row.try_get("effective_decision")?,
        completeness_status: row.try_get("completeness_status")?,
        policy_ids: serde_json::from_str(&policy_ids_json).unwrap_or_default(),
        exception_id: row.try_get("exception_id")?,
        decision_path: row.try_get("decision_path")?,
        review_required: row.try_get("review_required")?,
        evaluated_at: row.try_get("evaluated_at")?,
        data_fresh_at: row.try_get("data_fresh_at")?,
        revision: row.try_get("revision")?,
    })
}

fn evaluation_from_sqlite_row(
    row: SqliteRow,
    target_label: String,
) -> Result<SoftwarePolicyEvaluation, sqlx::Error> {
    let target = target_from_columns(
        row.try_get("target_type")?,
        row.try_get("product_id")?,
        row.try_get("asset_id")?,
        row.try_get("component_id")?,
        row.try_get("sbom_component_id")?,
    )?;
    let policy_ids_json: String = row.try_get("policy_ids_json")?;
    Ok(SoftwarePolicyEvaluation {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        target,
        target_label,
        effective_decision: row.try_get("effective_decision")?,
        completeness_status: row.try_get("completeness_status")?,
        policy_ids: serde_json::from_str(&policy_ids_json).unwrap_or_default(),
        exception_id: row.try_get("exception_id")?,
        decision_path: row.try_get("decision_path")?,
        review_required: row.try_get::<i64, _>("review_required")? != 0,
        evaluated_at: row.try_get("evaluated_at")?,
        data_fresh_at: row.try_get("data_fresh_at")?,
        revision: row.try_get("revision")?,
    })
}

fn audit_from_pg_row(row: PgRow) -> Result<SoftwarePolicyAuditEvent, sqlx::Error> {
    let detail_json: String = row.try_get("detail_json")?;
    Ok(SoftwarePolicyAuditEvent {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        object_type: row.try_get("object_type")?,
        object_id: row.try_get("object_id")?,
        event_type: row.try_get("event_type")?,
        actor_id: row.try_get("actor_id")?,
        actor_display: row.try_get("actor_display")?,
        previous_state: row.try_get("previous_state")?,
        new_state: row.try_get("new_state")?,
        reason: row.try_get("reason")?,
        revision: row.try_get("revision")?,
        detail: serde_json::from_str(&detail_json).unwrap_or_else(|_| json!({})),
        created_at: row.try_get("created_at")?,
    })
}

fn audit_from_sqlite_row(row: SqliteRow) -> Result<SoftwarePolicyAuditEvent, sqlx::Error> {
    let detail_json: String = row.try_get("detail_json")?;
    Ok(SoftwarePolicyAuditEvent {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        object_type: row.try_get("object_type")?,
        object_id: row.try_get("object_id")?,
        event_type: row.try_get("event_type")?,
        actor_id: row.try_get("actor_id")?,
        actor_display: row.try_get("actor_display")?,
        previous_state: row.try_get("previous_state")?,
        new_state: row.try_get("new_state")?,
        reason: row.try_get("reason")?,
        revision: row.try_get("revision")?,
        detail: serde_json::from_str(&detail_json).unwrap_or_else(|_| json!({})),
        created_at: row.try_get("created_at")?,
    })
}

fn target_bindings(
    target: &SoftwarePolicyTarget,
) -> (Option<i64>, Option<i64>, Option<i64>, Option<i64>) {
    match target.target_type.as_str() {
        "PRODUCT" => (Some(target.target_id), None, None, None),
        "ASSET" => (None, Some(target.target_id), None, None),
        "COMPONENT" => (None, None, Some(target.target_id), None),
        "SBOM_COMPONENT" => (None, None, None, Some(target.target_id)),
        _ => (None, None, None, None),
    }
}

async fn validate_target_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    target: &SoftwarePolicyTarget,
) -> Result<String, SoftwarePolicyError> {
    let sql = match target.target_type.as_str() {
        "PRODUCT" => "SELECT name FROM product_security_product WHERE tenant_id=$1 AND id=$2",
        "ASSET" => "SELECT name FROM assets_app_informationasset WHERE tenant_id=$1 AND id=$2",
        "COMPONENT" => "SELECT name FROM product_security_component WHERE tenant_id=$1 AND id=$2",
        "SBOM_COMPONENT" => {
            "SELECT name FROM product_security_importcomponent WHERE tenant_id=$1 AND id=$2"
        }
        _ => return Err(SoftwarePolicyError::not_found()),
    };
    sqlx::query_scalar(sql)
        .bind(tenant_id)
        .bind(target.target_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| SoftwarePolicyError::database())?
        .ok_or_else(SoftwarePolicyError::not_found)
}

async fn validate_target_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    target: &SoftwarePolicyTarget,
) -> Result<String, SoftwarePolicyError> {
    let sql = match target.target_type.as_str() {
        "PRODUCT" => "SELECT name FROM product_security_product WHERE tenant_id=?1 AND id=?2",
        "ASSET" => "SELECT name FROM assets_app_informationasset WHERE tenant_id=?1 AND id=?2",
        "COMPONENT" => "SELECT name FROM product_security_component WHERE tenant_id=?1 AND id=?2",
        "SBOM_COMPONENT" => {
            "SELECT name FROM product_security_importcomponent WHERE tenant_id=?1 AND id=?2"
        }
        _ => return Err(SoftwarePolicyError::not_found()),
    };
    sqlx::query_scalar(sql)
        .bind(tenant_id)
        .bind(target.target_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| SoftwarePolicyError::database())?
        .ok_or_else(SoftwarePolicyError::not_found)
}

async fn validate_owner_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    owner_id: Option<i64>,
) -> Result<(), SoftwarePolicyError> {
    if let Some(owner_id) = owner_id {
        validate_active_actor_pg(tx, tenant_id, owner_id).await?;
    }
    Ok(())
}

async fn validate_owner_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    owner_id: Option<i64>,
) -> Result<(), SoftwarePolicyError> {
    if let Some(owner_id) = owner_id {
        validate_active_actor_sqlite(tx, tenant_id, owner_id).await?;
    }
    Ok(())
}

async fn validate_active_actor_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    actor_id: i64,
) -> Result<(), SoftwarePolicyError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM accounts_user WHERE tenant_id=$1 AND id=$2 AND is_active=TRUE)",
    )
    .bind(tenant_id)
    .bind(actor_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| SoftwarePolicyError::database())?;
    if !exists {
        return Err(SoftwarePolicyError::not_found());
    }
    Ok(())
}

async fn validate_active_actor_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    actor_id: i64,
) -> Result<(), SoftwarePolicyError> {
    let exists: i64 = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM accounts_user WHERE tenant_id=?1 AND id=?2 AND is_active=1)",
    )
    .bind(tenant_id)
    .bind(actor_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| SoftwarePolicyError::database())?;
    if exists == 0 {
        return Err(SoftwarePolicyError::not_found());
    }
    Ok(())
}

async fn list_target_options_pg(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> Result<Vec<SoftwarePolicyTargetOption>, SoftwarePolicyError> {
    let rows = sqlx::query(
        "SELECT target_type,id,label FROM (
            SELECT 'PRODUCT'::text AS target_type,id,name AS label FROM product_security_product WHERE tenant_id=$1
            UNION ALL SELECT 'ASSET'::text,id,name FROM assets_app_informationasset WHERE tenant_id=$1
            UNION ALL SELECT 'COMPONENT'::text,id,name FROM product_security_component WHERE tenant_id=$1
            UNION ALL SELECT 'SBOM_COMPONENT'::text,id,name FROM product_security_importcomponent WHERE tenant_id=$1
        ) targets ORDER BY target_type,label,id LIMIT $2",
    )
    .bind(tenant_id)
    .bind(limit * TARGET_TYPES.len() as i64)
    .fetch_all(pool)
    .await
    .map_err(|_| SoftwarePolicyError::database())?;
    rows.into_iter()
        .map(|row| {
            Ok(SoftwarePolicyTargetOption {
                target: SoftwarePolicyTarget {
                    target_type: row.try_get("target_type")?,
                    target_id: row.try_get("id")?,
                },
                label: row.try_get("label")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map_err(|_| SoftwarePolicyError::database())
}

async fn list_target_options_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> Result<Vec<SoftwarePolicyTargetOption>, SoftwarePolicyError> {
    let rows = sqlx::query(
        "SELECT target_type,id,label FROM (
            SELECT 'PRODUCT' AS target_type,id,name AS label FROM product_security_product WHERE tenant_id=?1
            UNION ALL SELECT 'ASSET',id,name FROM assets_app_informationasset WHERE tenant_id=?1
            UNION ALL SELECT 'COMPONENT',id,name FROM product_security_component WHERE tenant_id=?1
            UNION ALL SELECT 'SBOM_COMPONENT',id,name FROM product_security_importcomponent WHERE tenant_id=?1
        ) targets ORDER BY target_type,label,id LIMIT ?2",
    )
    .bind(tenant_id)
    .bind(limit * TARGET_TYPES.len() as i64)
    .fetch_all(pool)
    .await
    .map_err(|_| SoftwarePolicyError::database())?;
    rows.into_iter()
        .map(|row| {
            Ok(SoftwarePolicyTargetOption {
                target: SoftwarePolicyTarget {
                    target_type: row.try_get("target_type")?,
                    target_id: row.try_get("id")?,
                },
                label: row.try_get("label")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map_err(|_| SoftwarePolicyError::database())
}

async fn policy_by_key_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    policy_key: &str,
) -> Result<Option<SoftwarePolicySummary>, SoftwarePolicyError> {
    let sql = format!(
        "{} WHERE p.tenant_id=$1 AND p.policy_key=$2",
        policy_select(true)
    );
    sqlx::query(&sql)
        .bind(tenant_id)
        .bind(policy_key)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| SoftwarePolicyError::database())?
        .map(policy_from_pg_row)
        .transpose()
        .map_err(|_| SoftwarePolicyError::database())
}

async fn policy_by_key_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    policy_key: &str,
) -> Result<Option<SoftwarePolicySummary>, SoftwarePolicyError> {
    let sql = format!(
        "{} WHERE p.tenant_id=?1 AND p.policy_key=?2",
        policy_select(false)
    );
    sqlx::query(&sql)
        .bind(tenant_id)
        .bind(policy_key)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| SoftwarePolicyError::database())?
        .map(policy_from_sqlite_row)
        .transpose()
        .map_err(|_| SoftwarePolicyError::database())
}

async fn policy_by_id_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    policy_id: i64,
    for_update: bool,
) -> Result<Option<SoftwarePolicySummary>, SoftwarePolicyError> {
    sqlx::query(&policy_by_id_sql(true, for_update))
        .bind(tenant_id)
        .bind(policy_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| SoftwarePolicyError::database())?
        .map(policy_from_pg_row)
        .transpose()
        .map_err(|_| SoftwarePolicyError::database())
}

async fn policy_by_id_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    policy_id: i64,
) -> Result<Option<SoftwarePolicySummary>, SoftwarePolicyError> {
    sqlx::query(&policy_by_id_sql(false, false))
        .bind(tenant_id)
        .bind(policy_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| SoftwarePolicyError::database())?
        .map(policy_from_sqlite_row)
        .transpose()
        .map_err(|_| SoftwarePolicyError::database())
}

async fn insert_policy_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    actor_id: i64,
    policy: &NormalizedPolicy,
) -> Result<(SoftwarePolicySummary, bool), SoftwarePolicyError> {
    let (product_id, asset_id, component_id, sbom_component_id) = target_bindings(&policy.target);
    let row = sqlx::query(
        "INSERT INTO software_approval_policy (
            tenant_id,policy_key,name,description,status,decision,target_type,
            product_id,asset_id,component_id,sbom_component_id,rationale,owner_id,
            created_by_id,updated_by_id,valid_from,valid_until
        ) VALUES ($1,$2,$3,$4,'DRAFT',$5,$6,$7,$8,$9,$10,$11,$12,$13,$13,$14,$15)
        ON CONFLICT(tenant_id,policy_key) DO NOTHING RETURNING id",
    )
    .bind(tenant_id)
    .bind(&policy.policy_key)
    .bind(&policy.name)
    .bind(&policy.description)
    .bind(&policy.decision)
    .bind(&policy.target.target_type)
    .bind(product_id)
    .bind(asset_id)
    .bind(component_id)
    .bind(sbom_component_id)
    .bind(&policy.rationale)
    .bind(policy.owner_id)
    .bind(actor_id)
    .bind(&policy.valid_from)
    .bind(&policy.valid_until)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| SoftwarePolicyError::database())?;
    if let Some(row) = row {
        let id: i64 = row
            .try_get("id")
            .map_err(|_| SoftwarePolicyError::database())?;
        let policy = policy_by_id_pg(tx, tenant_id, id, false)
            .await?
            .ok_or_else(SoftwarePolicyError::database)?;
        return Ok((policy, true));
    }
    let existing = policy_by_key_pg(tx, tenant_id, &policy.policy_key)
        .await?
        .ok_or_else(SoftwarePolicyError::database)?;
    ensure_same_policy(&existing, policy)?;
    Ok((existing, false))
}

async fn insert_policy_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    actor_id: i64,
    policy: &NormalizedPolicy,
) -> Result<(SoftwarePolicySummary, bool), SoftwarePolicyError> {
    let (product_id, asset_id, component_id, sbom_component_id) = target_bindings(&policy.target);
    let created = sqlx::query(
        "INSERT OR IGNORE INTO software_approval_policy (
            tenant_id,policy_key,name,description,status,decision,target_type,
            product_id,asset_id,component_id,sbom_component_id,rationale,owner_id,
            created_by_id,updated_by_id,valid_from,valid_until
        ) VALUES (?1,?2,?3,?4,'DRAFT',?5,?6,?7,?8,?9,?10,?11,?12,?13,?13,?14,?15)",
    )
    .bind(tenant_id)
    .bind(&policy.policy_key)
    .bind(&policy.name)
    .bind(&policy.description)
    .bind(&policy.decision)
    .bind(&policy.target.target_type)
    .bind(product_id)
    .bind(asset_id)
    .bind(component_id)
    .bind(sbom_component_id)
    .bind(&policy.rationale)
    .bind(policy.owner_id)
    .bind(actor_id)
    .bind(&policy.valid_from)
    .bind(&policy.valid_until)
    .execute(&mut **tx)
    .await
    .map_err(|_| SoftwarePolicyError::database())?
    .rows_affected()
        == 1;
    let existing = policy_by_key_sqlite(tx, tenant_id, &policy.policy_key)
        .await?
        .ok_or_else(SoftwarePolicyError::database)?;
    ensure_same_policy(&existing, policy)?;
    Ok((existing, created))
}

async fn update_policy_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    actor_id: i64,
    current: &SoftwarePolicySummary,
    policy: &NormalizedPolicy,
) -> Result<SoftwarePolicySummary, SoftwarePolicyError> {
    if current.status != "DRAFT" {
        return Err(SoftwarePolicyError::conflict(
            "software_policy_immutable",
            "Nur eine Policy im Entwurfsstatus darf inhaltlich geaendert werden.",
        ));
    }
    let updated = sqlx::query(
        "UPDATE software_approval_policy SET name=$1,description=$2,decision=$3,rationale=$4,
         owner_id=$5,valid_from=$6,valid_until=$7,updated_by_id=$8,revision=revision+1,
         updated_at=(CURRENT_TIMESTAMP)::text
         WHERE tenant_id=$9 AND id=$10 AND revision=$11 AND status='DRAFT' RETURNING id",
    )
    .bind(&policy.name)
    .bind(&policy.description)
    .bind(&policy.decision)
    .bind(&policy.rationale)
    .bind(policy.owner_id)
    .bind(&policy.valid_from)
    .bind(&policy.valid_until)
    .bind(actor_id)
    .bind(tenant_id)
    .bind(current.id)
    .bind(policy.expected_revision)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| SoftwarePolicyError::database())?;
    if updated.is_none() {
        return Err(stale_revision());
    }
    policy_by_id_pg(tx, tenant_id, current.id, false)
        .await?
        .ok_or_else(SoftwarePolicyError::database)
}

async fn update_policy_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    actor_id: i64,
    current: &SoftwarePolicySummary,
    policy: &NormalizedPolicy,
) -> Result<SoftwarePolicySummary, SoftwarePolicyError> {
    if current.status != "DRAFT" {
        return Err(SoftwarePolicyError::conflict(
            "software_policy_immutable",
            "Nur eine Policy im Entwurfsstatus darf inhaltlich geaendert werden.",
        ));
    }
    let changed = sqlx::query(
        "UPDATE software_approval_policy SET name=?1,description=?2,decision=?3,rationale=?4,
         owner_id=?5,valid_from=?6,valid_until=?7,updated_by_id=?8,revision=revision+1,
         updated_at=CURRENT_TIMESTAMP
         WHERE tenant_id=?9 AND id=?10 AND revision=?11 AND status='DRAFT'",
    )
    .bind(&policy.name)
    .bind(&policy.description)
    .bind(&policy.decision)
    .bind(&policy.rationale)
    .bind(policy.owner_id)
    .bind(&policy.valid_from)
    .bind(&policy.valid_until)
    .bind(actor_id)
    .bind(tenant_id)
    .bind(current.id)
    .bind(policy.expected_revision)
    .execute(&mut **tx)
    .await
    .map_err(|_| SoftwarePolicyError::database())?
    .rows_affected();
    if changed != 1 {
        return Err(stale_revision());
    }
    policy_by_id_sqlite(tx, tenant_id, current.id)
        .await?
        .ok_or_else(SoftwarePolicyError::database)
}

async fn transition_policy_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    actor_id: i64,
    current: &SoftwarePolicySummary,
    expected_revision: i64,
    target_status: &str,
) -> Result<SoftwarePolicySummary, SoftwarePolicyError> {
    validate_policy_transition(current, expected_revision, target_status)?;
    let row = sqlx::query(
        "UPDATE software_approval_policy SET status=$1,updated_by_id=$2,revision=revision+1,
         activated_at=CASE WHEN $1='ACTIVE' THEN (CURRENT_TIMESTAMP)::text ELSE activated_at END,
         archived_at=CASE WHEN $1='ARCHIVED' THEN (CURRENT_TIMESTAMP)::text ELSE archived_at END,
         updated_at=(CURRENT_TIMESTAMP)::text
         WHERE tenant_id=$3 AND id=$4 AND revision=$5 RETURNING id",
    )
    .bind(target_status)
    .bind(actor_id)
    .bind(tenant_id)
    .bind(current.id)
    .bind(expected_revision)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| SoftwarePolicyError::database())?;
    if row.is_none() {
        return Err(stale_revision());
    }
    policy_by_id_pg(tx, tenant_id, current.id, false)
        .await?
        .ok_or_else(SoftwarePolicyError::database)
}

async fn transition_policy_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    actor_id: i64,
    current: &SoftwarePolicySummary,
    expected_revision: i64,
    target_status: &str,
) -> Result<SoftwarePolicySummary, SoftwarePolicyError> {
    validate_policy_transition(current, expected_revision, target_status)?;
    let changed = sqlx::query(
        "UPDATE software_approval_policy SET status=?1,updated_by_id=?2,revision=revision+1,
         activated_at=CASE WHEN ?1='ACTIVE' THEN CURRENT_TIMESTAMP ELSE activated_at END,
         archived_at=CASE WHEN ?1='ARCHIVED' THEN CURRENT_TIMESTAMP ELSE archived_at END,
         updated_at=CURRENT_TIMESTAMP
         WHERE tenant_id=?3 AND id=?4 AND revision=?5",
    )
    .bind(target_status)
    .bind(actor_id)
    .bind(tenant_id)
    .bind(current.id)
    .bind(expected_revision)
    .execute(&mut **tx)
    .await
    .map_err(|_| SoftwarePolicyError::database())?
    .rows_affected();
    if changed != 1 {
        return Err(stale_revision());
    }
    policy_by_id_sqlite(tx, tenant_id, current.id)
        .await?
        .ok_or_else(SoftwarePolicyError::database)
}

fn validate_policy_transition(
    current: &SoftwarePolicySummary,
    expected_revision: i64,
    target_status: &str,
) -> Result<(), SoftwarePolicyError> {
    if current.revision != expected_revision {
        return Err(stale_revision());
    }
    if !POLICY_STATUSES.contains(&current.status.as_str())
        || !matches!(
            (current.status.as_str(), target_status),
            ("DRAFT", "ACTIVE") | ("DRAFT", "ARCHIVED") | ("ACTIVE", "ARCHIVED")
        )
    {
        return Err(SoftwarePolicyError::conflict(
            "invalid_software_policy_transition",
            "Der Statuswechsel der Policy ist nicht zulaessig.",
        ));
    }
    if target_status == "ACTIVE"
        && current
            .valid_until
            .as_deref()
            .map(parse_timestamp)
            .transpose()?
            .is_some_and(|until| until <= Utc::now())
    {
        return Err(SoftwarePolicyError::conflict(
            "software_policy_expired",
            "Eine bereits abgelaufene Policy kann nicht aktiviert werden.",
        ));
    }
    Ok(())
}

async fn audit_policy_update_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    actor_id: i64,
    current: &SoftwarePolicySummary,
    updated: &SoftwarePolicySummary,
) -> Result<(), SoftwarePolicyError> {
    let previous_state = format!("{}:{}", current.status, current.decision);
    let new_state = format!("{}:{}", updated.status, updated.decision);
    let detail = json!({"target": updated.target});
    insert_audit_pg(
        tx,
        tenant_id,
        actor_id,
        AuditRecord {
            object_type: "POLICY",
            object_id: current.id,
            event_type: "policy_updated",
            previous_state: &previous_state,
            new_state: &new_state,
            reason: "Policy-Entwurf aktualisiert.",
            revision: updated.revision,
            detail: &detail,
        },
    )
    .await
}

async fn audit_policy_update_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    actor_id: i64,
    current: &SoftwarePolicySummary,
    updated: &SoftwarePolicySummary,
) -> Result<(), SoftwarePolicyError> {
    let previous_state = format!("{}:{}", current.status, current.decision);
    let new_state = format!("{}:{}", updated.status, updated.decision);
    let detail = json!({"target": updated.target});
    insert_audit_sqlite(
        tx,
        tenant_id,
        actor_id,
        AuditRecord {
            object_type: "POLICY",
            object_id: current.id,
            event_type: "policy_updated",
            previous_state: &previous_state,
            new_state: &new_state,
            reason: "Policy-Entwurf aktualisiert.",
            revision: updated.revision,
            detail: &detail,
        },
    )
    .await
}

async fn exception_by_key_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    request_key: &str,
) -> Result<Option<SoftwareExceptionSummary>, SoftwarePolicyError> {
    let sql = format!(
        "{} WHERE e.tenant_id=$1 AND e.request_key=$2",
        exception_select(true)
    );
    sqlx::query(&sql)
        .bind(tenant_id)
        .bind(request_key)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| SoftwarePolicyError::database())?
        .map(exception_from_pg_row)
        .transpose()
        .map_err(|_| SoftwarePolicyError::database())
}

async fn exception_by_key_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    request_key: &str,
) -> Result<Option<SoftwareExceptionSummary>, SoftwarePolicyError> {
    let sql = format!(
        "{} WHERE e.tenant_id=?1 AND e.request_key=?2",
        exception_select(false)
    );
    sqlx::query(&sql)
        .bind(tenant_id)
        .bind(request_key)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| SoftwarePolicyError::database())?
        .map(exception_from_sqlite_row)
        .transpose()
        .map_err(|_| SoftwarePolicyError::database())
}

async fn exception_by_id_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    exception_id: i64,
    for_update: bool,
) -> Result<Option<SoftwareExceptionSummary>, SoftwarePolicyError> {
    let sql = format!(
        "{} WHERE e.tenant_id=$1 AND e.id=$2{}",
        exception_select(true),
        if for_update { " FOR UPDATE OF e" } else { "" }
    );
    sqlx::query(&sql)
        .bind(tenant_id)
        .bind(exception_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| SoftwarePolicyError::database())?
        .map(exception_from_pg_row)
        .transpose()
        .map_err(|_| SoftwarePolicyError::database())
}

async fn exception_by_id_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    exception_id: i64,
) -> Result<Option<SoftwareExceptionSummary>, SoftwarePolicyError> {
    let sql = format!(
        "{} WHERE e.tenant_id=?1 AND e.id=?2",
        exception_select(false)
    );
    sqlx::query(&sql)
        .bind(tenant_id)
        .bind(exception_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| SoftwarePolicyError::database())?
        .map(exception_from_sqlite_row)
        .transpose()
        .map_err(|_| SoftwarePolicyError::database())
}

async fn insert_exception_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    applicant_id: i64,
    exception: &NormalizedException,
) -> Result<(SoftwareExceptionSummary, bool), SoftwarePolicyError> {
    let row = sqlx::query(
        "INSERT INTO software_policy_exception (
            tenant_id,policy_id,request_key,applicant_id,justification,
            compensating_controls,requested_valid_from,expires_at,status
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'DRAFT')
        ON CONFLICT(tenant_id,request_key) DO NOTHING RETURNING id",
    )
    .bind(tenant_id)
    .bind(exception.policy_id)
    .bind(&exception.request_key)
    .bind(applicant_id)
    .bind(&exception.justification)
    .bind(&exception.compensating_controls)
    .bind(&exception.requested_valid_from)
    .bind(&exception.expires_at)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| SoftwarePolicyError::database())?;
    if let Some(row) = row {
        let id = row
            .try_get("id")
            .map_err(|_| SoftwarePolicyError::database())?;
        let exception = exception_by_id_pg(tx, tenant_id, id, false)
            .await?
            .ok_or_else(SoftwarePolicyError::database)?;
        return Ok((exception, true));
    }
    let existing = exception_by_key_pg(tx, tenant_id, &exception.request_key)
        .await?
        .ok_or_else(SoftwarePolicyError::database)?;
    ensure_same_exception(&existing, exception, applicant_id)?;
    Ok((existing, false))
}

async fn insert_exception_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    applicant_id: i64,
    exception: &NormalizedException,
) -> Result<(SoftwareExceptionSummary, bool), SoftwarePolicyError> {
    let created = sqlx::query(
        "INSERT OR IGNORE INTO software_policy_exception (
            tenant_id,policy_id,request_key,applicant_id,justification,
            compensating_controls,requested_valid_from,expires_at,status
        ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'DRAFT')",
    )
    .bind(tenant_id)
    .bind(exception.policy_id)
    .bind(&exception.request_key)
    .bind(applicant_id)
    .bind(&exception.justification)
    .bind(&exception.compensating_controls)
    .bind(&exception.requested_valid_from)
    .bind(&exception.expires_at)
    .execute(&mut **tx)
    .await
    .map_err(|_| SoftwarePolicyError::database())?
    .rows_affected()
        == 1;
    let existing = exception_by_key_sqlite(tx, tenant_id, &exception.request_key)
        .await?
        .ok_or_else(SoftwarePolicyError::database)?;
    ensure_same_exception(&existing, exception, applicant_id)?;
    Ok((existing, created))
}

async fn transition_exception_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    actor_id: i64,
    current: &SoftwareExceptionSummary,
    transition: ExceptionTransition<'_>,
) -> Result<SoftwareExceptionSummary, SoftwarePolicyError> {
    if current.revision != transition.expected_revision {
        return Err(stale_revision());
    }
    let status = transition.action.status();
    let row = sqlx::query(
        "UPDATE software_policy_exception SET status=$1,
         reviewer_id=CASE WHEN $1 IN ('APPROVED','REJECTED','REVOKED') THEN $2 ELSE reviewer_id END,
         decision_reason=CASE WHEN $1 IN ('APPROVED','REJECTED','REVOKED') THEN $3 ELSE decision_reason END,
         decision_at=CASE WHEN $1 IN ('APPROVED','REJECTED') THEN $4 ELSE decision_at END,
         revoked_at=CASE WHEN $1='REVOKED' THEN $4 ELSE revoked_at END,
         revision=revision+1,updated_at=(CURRENT_TIMESTAMP)::text
         WHERE tenant_id=$5 AND id=$6 AND revision=$7 RETURNING id",
    )
    .bind(status)
    .bind(actor_id)
    .bind(transition.reason)
    .bind(transition.now)
    .bind(tenant_id)
    .bind(current.id)
    .bind(transition.expected_revision)
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_write_error)?;
    if row.is_none() {
        return Err(stale_revision());
    }
    exception_by_id_pg(tx, tenant_id, current.id, false)
        .await?
        .ok_or_else(SoftwarePolicyError::database)
}

async fn transition_exception_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    actor_id: i64,
    current: &SoftwareExceptionSummary,
    transition: ExceptionTransition<'_>,
) -> Result<SoftwareExceptionSummary, SoftwarePolicyError> {
    if current.revision != transition.expected_revision {
        return Err(stale_revision());
    }
    let status = transition.action.status();
    let changed = sqlx::query(
        "UPDATE software_policy_exception SET status=?1,
         reviewer_id=CASE WHEN ?1 IN ('APPROVED','REJECTED','REVOKED') THEN ?2 ELSE reviewer_id END,
         decision_reason=CASE WHEN ?1 IN ('APPROVED','REJECTED','REVOKED') THEN ?3 ELSE decision_reason END,
         decision_at=CASE WHEN ?1 IN ('APPROVED','REJECTED') THEN ?4 ELSE decision_at END,
         revoked_at=CASE WHEN ?1='REVOKED' THEN ?4 ELSE revoked_at END,
         revision=revision+1,updated_at=CURRENT_TIMESTAMP
         WHERE tenant_id=?5 AND id=?6 AND revision=?7",
    )
    .bind(status)
    .bind(actor_id)
    .bind(transition.reason)
    .bind(transition.now)
    .bind(tenant_id)
    .bind(current.id)
    .bind(transition.expected_revision)
    .execute(&mut **tx)
    .await
    .map_err(map_write_error)?
    .rows_affected();
    if changed != 1 {
        return Err(stale_revision());
    }
    exception_by_id_sqlite(tx, tenant_id, current.id)
        .await?
        .ok_or_else(SoftwarePolicyError::database)
}

fn map_write_error(error: sqlx::Error) -> SoftwarePolicyError {
    if error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        .is_some_and(|code| matches!(code.as_ref(), "23505" | "2067"))
    {
        return SoftwarePolicyError::conflict(
            "software_policy_concurrent_conflict",
            "Eine parallele Entscheidung hat diesen Zustand bereits belegt.",
        );
    }
    SoftwarePolicyError::database()
}

async fn audit_exception_transition_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    actor_id: i64,
    current: &SoftwareExceptionSummary,
    updated: &SoftwareExceptionSummary,
    reason: &str,
    action: ExceptionAction,
) -> Result<(), SoftwarePolicyError> {
    let detail = json!({"policy_id": updated.policy_id, "expires_at": updated.expires_at});
    insert_audit_pg(
        tx,
        tenant_id,
        actor_id,
        AuditRecord {
            object_type: "EXCEPTION",
            object_id: current.id,
            event_type: action.event(),
            previous_state: &current.status,
            new_state: &updated.status,
            reason,
            revision: updated.revision,
            detail: &detail,
        },
    )
    .await
}

async fn audit_exception_transition_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    actor_id: i64,
    current: &SoftwareExceptionSummary,
    updated: &SoftwareExceptionSummary,
    reason: &str,
    action: ExceptionAction,
) -> Result<(), SoftwarePolicyError> {
    let detail = json!({"policy_id": updated.policy_id, "expires_at": updated.expires_at});
    insert_audit_sqlite(
        tx,
        tenant_id,
        actor_id,
        AuditRecord {
            object_type: "EXCEPTION",
            object_id: current.id,
            event_type: action.event(),
            previous_state: &current.status,
            new_state: &updated.status,
            reason,
            revision: updated.revision,
            detail: &detail,
        },
    )
    .await
}

async fn expire_exceptions_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    actor_id: i64,
    now: &str,
) -> Result<(), SoftwarePolicyError> {
    let rows = sqlx::query(
        "UPDATE software_policy_exception SET status='EXPIRED',expired_at=$1,
         revision=revision+1,updated_at=(CURRENT_TIMESTAMP)::text
         WHERE tenant_id=$2 AND status='APPROVED' AND expires_at <= $1
         RETURNING id,revision,policy_id,expires_at",
    )
    .bind(now)
    .bind(tenant_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| SoftwarePolicyError::database())?;
    for row in rows {
        let id = row
            .try_get("id")
            .map_err(|_| SoftwarePolicyError::database())?;
        let revision = row
            .try_get("revision")
            .map_err(|_| SoftwarePolicyError::database())?;
        let policy_id: i64 = row
            .try_get("policy_id")
            .map_err(|_| SoftwarePolicyError::database())?;
        let expires_at: String = row
            .try_get("expires_at")
            .map_err(|_| SoftwarePolicyError::database())?;
        let detail = json!({"policy_id": policy_id, "expires_at": expires_at});
        insert_audit_pg(
            tx,
            tenant_id,
            actor_id,
            AuditRecord {
                object_type: "EXCEPTION",
                object_id: id,
                event_type: "exception_expired",
                previous_state: "APPROVED",
                new_state: "EXPIRED",
                reason: "Ablauf bei serverseitiger Policy-Auswertung festgestellt.",
                revision,
                detail: &detail,
            },
        )
        .await?;
    }
    Ok(())
}

async fn expire_exceptions_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    actor_id: i64,
    now: &str,
) -> Result<(), SoftwarePolicyError> {
    let rows = sqlx::query(
        "SELECT id,revision,policy_id,expires_at FROM software_policy_exception
         WHERE tenant_id=?1 AND status='APPROVED' AND expires_at <= ?2 ORDER BY id",
    )
    .bind(tenant_id)
    .bind(now)
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| SoftwarePolicyError::database())?;
    for row in rows {
        let id: i64 = row
            .try_get("id")
            .map_err(|_| SoftwarePolicyError::database())?;
        let old_revision: i64 = row
            .try_get("revision")
            .map_err(|_| SoftwarePolicyError::database())?;
        let policy_id: i64 = row
            .try_get("policy_id")
            .map_err(|_| SoftwarePolicyError::database())?;
        let expires_at: String = row
            .try_get("expires_at")
            .map_err(|_| SoftwarePolicyError::database())?;
        let changed = sqlx::query(
            "UPDATE software_policy_exception SET status='EXPIRED',expired_at=?1,
             revision=revision+1,updated_at=CURRENT_TIMESTAMP
             WHERE tenant_id=?2 AND id=?3 AND revision=?4 AND status='APPROVED'",
        )
        .bind(now)
        .bind(tenant_id)
        .bind(id)
        .bind(old_revision)
        .execute(&mut **tx)
        .await
        .map_err(|_| SoftwarePolicyError::database())?
        .rows_affected();
        if changed == 1 {
            let detail = json!({"policy_id": policy_id, "expires_at": expires_at});
            insert_audit_sqlite(
                tx,
                tenant_id,
                actor_id,
                AuditRecord {
                    object_type: "EXCEPTION",
                    object_id: id,
                    event_type: "exception_expired",
                    previous_state: "APPROVED",
                    new_state: "EXPIRED",
                    reason: "Ablauf bei serverseitiger Policy-Auswertung festgestellt.",
                    revision: old_revision + 1,
                    detail: &detail,
                },
            )
            .await?;
        }
    }
    Ok(())
}

async fn applicable_policies_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    target: &SoftwarePolicyTarget,
    now: &str,
) -> Result<Vec<ApplicablePolicy>, SoftwarePolicyError> {
    let (column, target_type) = target_column(&target.target_type)?;
    let sql = format!(
        "SELECT p.id,p.decision,p.updated_at::text AS updated_at,e.id AS exception_id
         FROM software_approval_policy p
         LEFT JOIN software_policy_exception e
           ON e.tenant_id=p.tenant_id AND e.policy_id=p.id AND e.status='APPROVED'
          AND e.requested_valid_from <= $3 AND e.expires_at > $3
         WHERE p.tenant_id=$1 AND p.status='ACTIVE' AND p.target_type='{target_type}'
           AND p.{column}=$2
           AND (p.valid_from IS NULL OR p.valid_from <= $3)
           AND (p.valid_until IS NULL OR p.valid_until > $3)
         ORDER BY CASE p.decision WHEN 'PROHIBITED' THEN 1 WHEN 'RESTRICTED' THEN 2 ELSE 3 END,p.id
         FOR SHARE OF p"
    );
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(target.target_id)
        .bind(now)
        .fetch_all(&mut **tx)
        .await
        .map_err(|_| SoftwarePolicyError::database())?;
    rows.into_iter()
        .map(|row| {
            Ok(ApplicablePolicy {
                id: row.try_get("id")?,
                decision: row.try_get("decision")?,
                updated_at: row.try_get("updated_at")?,
                exception_id: row.try_get("exception_id")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map_err(|_| SoftwarePolicyError::database())
}

async fn applicable_policies_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    target: &SoftwarePolicyTarget,
    now: &str,
) -> Result<Vec<ApplicablePolicy>, SoftwarePolicyError> {
    let (column, target_type) = target_column(&target.target_type)?;
    let sql = format!(
        "SELECT p.id,p.decision,CAST(p.updated_at AS TEXT) AS updated_at,e.id AS exception_id
         FROM software_approval_policy p
         LEFT JOIN software_policy_exception e
           ON e.tenant_id=p.tenant_id AND e.policy_id=p.id AND e.status='APPROVED'
          AND e.requested_valid_from <= ?3 AND e.expires_at > ?3
         WHERE p.tenant_id=?1 AND p.status='ACTIVE' AND p.target_type='{target_type}'
           AND p.{column}=?2
           AND (p.valid_from IS NULL OR p.valid_from <= ?3)
           AND (p.valid_until IS NULL OR p.valid_until > ?3)
         ORDER BY CASE p.decision WHEN 'PROHIBITED' THEN 1 WHEN 'RESTRICTED' THEN 2 ELSE 3 END,p.id"
    );
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(target.target_id)
        .bind(now)
        .fetch_all(&mut **tx)
        .await
        .map_err(|_| SoftwarePolicyError::database())?;
    rows.into_iter()
        .map(|row| {
            Ok(ApplicablePolicy {
                id: row.try_get("id")?,
                decision: row.try_get("decision")?,
                updated_at: row.try_get("updated_at")?,
                exception_id: row.try_get("exception_id")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map_err(|_| SoftwarePolicyError::database())
}

fn target_column(target_type: &str) -> Result<(&'static str, &'static str), SoftwarePolicyError> {
    match target_type {
        "PRODUCT" => Ok(("product_id", "PRODUCT")),
        "ASSET" => Ok(("asset_id", "ASSET")),
        "COMPONENT" => Ok(("component_id", "COMPONENT")),
        "SBOM_COMPONENT" => Ok(("sbom_component_id", "SBOM_COMPONENT")),
        _ => Err(SoftwarePolicyError::invalid(
            "invalid_software_policy_target",
            "Der Software-Policy-Zieltyp ist nicht unterstuetzt.",
        )),
    }
}

fn evaluation_select() -> &'static str {
    "SELECT id,tenant_id,target_type,product_id,asset_id,component_id,sbom_component_id,effective_decision,completeness_status,policy_ids_json,exception_id,decision_path,review_required,evaluated_at,data_fresh_at,revision FROM software_policy_evaluation"
}

fn evaluation_list_sql(postgres: bool) -> String {
    let (p1, p2, p3, created_at) = if postgres {
        ("$1", "$2", "$3", "e.updated_at")
    } else {
        ("?1", "?2", "?3", "e.updated_at")
    };
    format!(
        "SELECT e.id,e.tenant_id,e.target_type,e.product_id,e.asset_id,e.component_id,
         e.sbom_component_id,e.effective_decision,e.completeness_status,e.policy_ids_json,
         e.exception_id,e.decision_path,e.review_required,e.evaluated_at,e.data_fresh_at,e.revision,
         COALESCE(pr.name,a.name,c.name,ic.name,'') AS target_label
         FROM software_policy_evaluation e
         LEFT JOIN product_security_product pr ON e.target_type='PRODUCT' AND pr.tenant_id=e.tenant_id AND pr.id=e.product_id
         LEFT JOIN assets_app_informationasset a ON e.target_type='ASSET' AND a.tenant_id=e.tenant_id AND a.id=e.asset_id
         LEFT JOIN product_security_component c ON e.target_type='COMPONENT' AND c.tenant_id=e.tenant_id AND c.id=e.component_id
         LEFT JOIN product_security_importcomponent ic ON e.target_type='SBOM_COMPONENT' AND ic.tenant_id=e.tenant_id AND ic.id=e.sbom_component_id
         WHERE e.tenant_id={p1} ORDER BY {created_at} DESC,e.id DESC LIMIT {p2} OFFSET {p3}"
    )
}

async fn load_evaluation_tx_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    target: &SoftwarePolicyTarget,
    target_label: &str,
) -> Result<Option<SoftwarePolicyEvaluation>, SoftwarePolicyError> {
    let (column, target_type) = target_column(&target.target_type)?;
    let sql = format!(
        "{} WHERE tenant_id=$1 AND target_type='{target_type}' AND {column}=$2 FOR UPDATE",
        evaluation_select()
    );
    sqlx::query(&sql)
        .bind(tenant_id)
        .bind(target.target_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| SoftwarePolicyError::database())?
        .map(|row| evaluation_from_pg_row(row, target_label.to_string()))
        .transpose()
        .map_err(|_| SoftwarePolicyError::database())
}

async fn load_evaluation_tx_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    target: &SoftwarePolicyTarget,
    target_label: &str,
) -> Result<Option<SoftwarePolicyEvaluation>, SoftwarePolicyError> {
    let (column, target_type) = target_column(&target.target_type)?;
    let sql = format!(
        "{} WHERE tenant_id=?1 AND target_type='{target_type}' AND {column}=?2",
        evaluation_select()
    );
    sqlx::query(&sql)
        .bind(tenant_id)
        .bind(target.target_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| SoftwarePolicyError::database())?
        .map(|row| evaluation_from_sqlite_row(row, target_label.to_string()))
        .transpose()
        .map_err(|_| SoftwarePolicyError::database())
}

fn decision_is_materially_changed(
    existing: &SoftwarePolicyEvaluation,
    decision: &Decision,
) -> bool {
    existing.effective_decision != decision.effective
        || existing.completeness_status != decision.completeness
        || existing.policy_ids != decision.policy_ids
        || existing.exception_id != decision.exception_id
        || existing.review_required != decision.review_required
        || existing.decision_path != decision.path
}

async fn persist_evaluation_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    actor_id: i64,
    target: &SoftwarePolicyTarget,
    target_label: &str,
    now: &str,
    decision: Decision,
) -> Result<SoftwarePolicyEvaluation, SoftwarePolicyError> {
    let lock_key = format!("{tenant_id}:{}:{}", target.target_type, target.target_id);
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(lock_key)
        .execute(&mut **tx)
        .await
        .map_err(|_| SoftwarePolicyError::database())?;
    let existing = load_evaluation_tx_pg(tx, tenant_id, target, target_label).await?;
    let policy_ids_json =
        serde_json::to_string(&decision.policy_ids).map_err(|_| SoftwarePolicyError::database())?;
    let data_fresh_at = decision_data_fresh_at(now, &decision.policy_ids, tx, tenant_id).await?;
    let (id, revision, previous, changed) = if let Some(existing) = existing {
        let changed = decision_is_materially_changed(&existing, &decision);
        let revision = existing.revision + i64::from(changed);
        sqlx::query(
            "UPDATE software_policy_evaluation SET effective_decision=$1,completeness_status=$2,
             policy_ids_json=$3,exception_id=$4,decision_path=$5,review_required=$6,
             evaluated_by_id=$7,evaluated_at=$8,data_fresh_at=$9,revision=$10,
             updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$11 AND id=$12",
        )
        .bind(decision.effective)
        .bind(decision.completeness)
        .bind(&policy_ids_json)
        .bind(decision.exception_id)
        .bind(&decision.path)
        .bind(decision.review_required)
        .bind(actor_id)
        .bind(now)
        .bind(&data_fresh_at)
        .bind(revision)
        .bind(tenant_id)
        .bind(existing.id)
        .execute(&mut **tx)
        .await
        .map_err(|_| SoftwarePolicyError::database())?;
        (existing.id, revision, existing.effective_decision, changed)
    } else {
        let (product_id, asset_id, component_id, sbom_component_id) = target_bindings(target);
        let row = sqlx::query(
            "INSERT INTO software_policy_evaluation (
                tenant_id,target_type,product_id,asset_id,component_id,sbom_component_id,
                effective_decision,completeness_status,policy_ids_json,exception_id,
                decision_path,review_required,evaluated_by_id,evaluated_at,data_fresh_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING id",
        )
        .bind(tenant_id)
        .bind(&target.target_type)
        .bind(product_id)
        .bind(asset_id)
        .bind(component_id)
        .bind(sbom_component_id)
        .bind(decision.effective)
        .bind(decision.completeness)
        .bind(&policy_ids_json)
        .bind(decision.exception_id)
        .bind(&decision.path)
        .bind(decision.review_required)
        .bind(actor_id)
        .bind(now)
        .bind(&data_fresh_at)
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| SoftwarePolicyError::database())?;
        (
            row.try_get("id")
                .map_err(|_| SoftwarePolicyError::database())?,
            1,
            String::new(),
            true,
        )
    };
    if changed {
        let detail = json!({
            "policy_ids": decision.policy_ids,
            "exception_id": decision.exception_id,
            "target": target
        });
        insert_audit_pg(
            tx,
            tenant_id,
            actor_id,
            AuditRecord {
                object_type: "EVALUATION",
                object_id: id,
                event_type: "effective_decision_changed",
                previous_state: &previous,
                new_state: decision.effective,
                reason: &decision.path,
                revision,
                detail: &detail,
            },
        )
        .await?;
    }
    let (column, target_type) = target_column(&target.target_type)?;
    let sql = format!(
        "{} WHERE tenant_id=$1 AND target_type='{target_type}' AND {column}=$2",
        evaluation_select()
    );
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(target.target_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| SoftwarePolicyError::database())?;
    evaluation_from_pg_row(row, target_label.to_string())
        .map_err(|_| SoftwarePolicyError::database())
}

async fn decision_data_fresh_at(
    fallback: &str,
    policy_ids: &[i64],
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
) -> Result<String, SoftwarePolicyError> {
    if policy_ids.is_empty() {
        return Ok(fallback.to_string());
    }
    let value: Option<String> = sqlx::query_scalar(
        "SELECT MAX(updated_at) FROM software_approval_policy WHERE tenant_id=$1 AND id=ANY($2)",
    )
    .bind(tenant_id)
    .bind(policy_ids)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| SoftwarePolicyError::database())?;
    Ok(value.unwrap_or_else(|| fallback.to_string()))
}

async fn persist_evaluation_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    actor_id: i64,
    target: &SoftwarePolicyTarget,
    target_label: &str,
    now: &str,
    decision: Decision,
) -> Result<SoftwarePolicyEvaluation, SoftwarePolicyError> {
    let existing = load_evaluation_tx_sqlite(tx, tenant_id, target, target_label).await?;
    let policy_ids_json =
        serde_json::to_string(&decision.policy_ids).map_err(|_| SoftwarePolicyError::database())?;
    let data_fresh_at =
        decision_data_fresh_at_sqlite(now, &decision.policy_ids, tx, tenant_id).await?;
    let (id, revision, previous, changed) = if let Some(existing) = existing {
        let changed = decision_is_materially_changed(&existing, &decision);
        let revision = existing.revision + i64::from(changed);
        sqlx::query(
            "UPDATE software_policy_evaluation SET effective_decision=?1,completeness_status=?2,
             policy_ids_json=?3,exception_id=?4,decision_path=?5,review_required=?6,
             evaluated_by_id=?7,evaluated_at=?8,data_fresh_at=?9,revision=?10,
             updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?11 AND id=?12",
        )
        .bind(decision.effective)
        .bind(decision.completeness)
        .bind(&policy_ids_json)
        .bind(decision.exception_id)
        .bind(&decision.path)
        .bind(decision.review_required)
        .bind(actor_id)
        .bind(now)
        .bind(&data_fresh_at)
        .bind(revision)
        .bind(tenant_id)
        .bind(existing.id)
        .execute(&mut **tx)
        .await
        .map_err(|_| SoftwarePolicyError::database())?;
        (existing.id, revision, existing.effective_decision, changed)
    } else {
        let (product_id, asset_id, component_id, sbom_component_id) = target_bindings(target);
        let row = sqlx::query(
            "INSERT INTO software_policy_evaluation (
                tenant_id,target_type,product_id,asset_id,component_id,sbom_component_id,
                effective_decision,completeness_status,policy_ids_json,exception_id,
                decision_path,review_required,evaluated_by_id,evaluated_at,data_fresh_at
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)
            RETURNING id",
        )
        .bind(tenant_id)
        .bind(&target.target_type)
        .bind(product_id)
        .bind(asset_id)
        .bind(component_id)
        .bind(sbom_component_id)
        .bind(decision.effective)
        .bind(decision.completeness)
        .bind(&policy_ids_json)
        .bind(decision.exception_id)
        .bind(&decision.path)
        .bind(decision.review_required)
        .bind(actor_id)
        .bind(now)
        .bind(&data_fresh_at)
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| SoftwarePolicyError::database())?;
        (
            row.try_get("id")
                .map_err(|_| SoftwarePolicyError::database())?,
            1,
            String::new(),
            true,
        )
    };
    if changed {
        let detail = json!({
            "policy_ids": decision.policy_ids,
            "exception_id": decision.exception_id,
            "target": target
        });
        insert_audit_sqlite(
            tx,
            tenant_id,
            actor_id,
            AuditRecord {
                object_type: "EVALUATION",
                object_id: id,
                event_type: "effective_decision_changed",
                previous_state: &previous,
                new_state: decision.effective,
                reason: &decision.path,
                revision,
                detail: &detail,
            },
        )
        .await?;
    }
    let (column, target_type) = target_column(&target.target_type)?;
    let sql = format!(
        "{} WHERE tenant_id=?1 AND target_type='{target_type}' AND {column}=?2",
        evaluation_select()
    );
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(target.target_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| SoftwarePolicyError::database())?;
    evaluation_from_sqlite_row(row, target_label.to_string())
        .map_err(|_| SoftwarePolicyError::database())
}

async fn decision_data_fresh_at_sqlite(
    fallback: &str,
    policy_ids: &[i64],
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
) -> Result<String, SoftwarePolicyError> {
    if policy_ids.is_empty() {
        return Ok(fallback.to_string());
    }
    let mut freshest = String::new();
    for policy_id in policy_ids {
        let value: Option<String> = sqlx::query_scalar(
            "SELECT updated_at FROM software_approval_policy WHERE tenant_id=?1 AND id=?2",
        )
        .bind(tenant_id)
        .bind(policy_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| SoftwarePolicyError::database())?;
        if value
            .as_deref()
            .is_some_and(|value| value > freshest.as_str())
        {
            freshest = value.unwrap_or_default();
        }
    }
    Ok(if freshest.is_empty() {
        fallback.to_string()
    } else {
        freshest
    })
}

async fn insert_audit_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    actor_id: i64,
    record: AuditRecord<'_>,
) -> Result<(), SoftwarePolicyError> {
    let detail_json =
        serde_json::to_string(record.detail).map_err(|_| SoftwarePolicyError::database())?;
    if detail_json.len() > 4096 {
        return Err(SoftwarePolicyError::database());
    }
    let inserted = sqlx::query(
        "INSERT INTO software_policy_audit_event (
            tenant_id,object_type,object_id,event_type,actor_id,previous_state,
            new_state,reason,revision,detail_json
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         ON CONFLICT(tenant_id,object_type,object_id,event_type,revision) DO NOTHING",
    )
    .bind(tenant_id)
    .bind(record.object_type)
    .bind(record.object_id)
    .bind(record.event_type)
    .bind(actor_id)
    .bind(record.previous_state)
    .bind(record.new_state)
    .bind(record.reason)
    .bind(record.revision)
    .bind(detail_json)
    .execute(&mut **tx)
    .await
    .map_err(|_| SoftwarePolicyError::database())?
    .rows_affected();
    if inserted != 1 {
        return Err(SoftwarePolicyError::database());
    }
    Ok(())
}

async fn insert_audit_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    actor_id: i64,
    record: AuditRecord<'_>,
) -> Result<(), SoftwarePolicyError> {
    let detail_json =
        serde_json::to_string(record.detail).map_err(|_| SoftwarePolicyError::database())?;
    if detail_json.len() > 4096 {
        return Err(SoftwarePolicyError::database());
    }
    let inserted = sqlx::query(
        "INSERT OR IGNORE INTO software_policy_audit_event (
            tenant_id,object_type,object_id,event_type,actor_id,previous_state,
            new_state,reason,revision,detail_json
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
    )
    .bind(tenant_id)
    .bind(record.object_type)
    .bind(record.object_id)
    .bind(record.event_type)
    .bind(actor_id)
    .bind(record.previous_state)
    .bind(record.new_state)
    .bind(record.reason)
    .bind(record.revision)
    .bind(detail_json)
    .execute(&mut **tx)
    .await
    .map_err(|_| SoftwarePolicyError::database())?
    .rows_affected();
    if inserted != 1 {
        return Err(SoftwarePolicyError::database());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, SecondsFormat, Utc};
    use sqlx::{postgres::PgPoolOptions, sqlite::SqlitePoolOptions, Row};

    use super::{
        evaluate_policies, ApplicablePolicy, SoftwareExceptionCreateRequest,
        SoftwareExceptionTransitionRequest, SoftwarePolicyCreateRequest, SoftwarePolicyErrorKind,
        SoftwarePolicyEvaluationRequest, SoftwarePolicyStore, SoftwarePolicyTarget,
        SoftwarePolicyTransitionRequest, SoftwarePolicyUpdateRequest,
    };
    use crate::db_admin::{run_db_admin_action, run_sqlite_migrations, DbAdminAction};

    async fn sqlite_fixture() -> (SoftwarePolicyStore, sqlx::SqlitePool) {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();
        run_sqlite_migrations(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO organizations_tenant (id,name,slug) VALUES
             (801,'Policy Tenant A','policy-a'),(802,'Policy Tenant B','policy-b')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO accounts_user (
                id,username,email,tenant_id,role,is_active,is_staff,is_superuser
             ) VALUES
             (8101,'policy-applicant','applicant@example.invalid',801,'SOC_ANALYST',1,0,0),
             (8102,'policy-reviewer','reviewer@example.invalid',801,'SECURITY_ADMIN',1,0,0),
             (8201,'foreign-reviewer','foreign@example.invalid',802,'SECURITY_ADMIN',1,0,0)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO product_security_product (id,tenant_id,name,code) VALUES
             (8301,801,'Policy Product','POL-A'),
             (8302,802,'Foreign Product','POL-B')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO assets_app_informationasset (id,tenant_id,name) VALUES
             (8401,801,'Policy Asset'),(8402,802,'Foreign Asset')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO product_security_component (id,tenant_id,product_id,name,version)
             VALUES (8501,801,8301,'Canonical Component','1.0')",
        )
        .execute(&pool)
        .await
        .unwrap();
        (SoftwarePolicyStore::from_sqlite_pool(pool.clone()), pool)
    }

    fn policy_request(decision: &str) -> SoftwarePolicyCreateRequest {
        SoftwarePolicyCreateRequest {
            name: format!("{decision} exact product policy"),
            description: Some("Deterministic tenant-bound test policy".to_string()),
            decision: decision.to_string(),
            target: SoftwarePolicyTarget {
                target_type: "PRODUCT".to_string(),
                target_id: 8301,
            },
            rationale: "Reviewed software governance decision".to_string(),
            owner_id: Some(8102),
            valid_from: None,
            valid_until: None,
        }
    }

    fn transition(revision: i64, reason: &str) -> SoftwarePolicyTransitionRequest {
        SoftwarePolicyTransitionRequest {
            expected_revision: revision,
            reason: reason.to_string(),
        }
    }

    fn policy_update(revision: i64, name: &str) -> SoftwarePolicyUpdateRequest {
        SoftwarePolicyUpdateRequest {
            expected_revision: revision,
            name: name.to_string(),
            description: Some("Concurrent draft update".to_string()),
            decision: "PROHIBITED".to_string(),
            rationale: "Updated governance decision".to_string(),
            owner_id: Some(8102),
            valid_from: None,
            valid_until: None,
        }
    }

    fn exception_transition(revision: i64, reason: &str) -> SoftwareExceptionTransitionRequest {
        SoftwareExceptionTransitionRequest {
            expected_revision: revision,
            reason: reason.to_string(),
        }
    }

    fn evaluation_request() -> SoftwarePolicyEvaluationRequest {
        SoftwarePolicyEvaluationRequest {
            target: SoftwarePolicyTarget {
                target_type: "PRODUCT".to_string(),
                target_id: 8301,
            },
        }
    }

    #[test]
    fn deterministic_precedence_is_order_independent_and_fail_closed() {
        let approved = ApplicablePolicy {
            id: 3,
            decision: "APPROVED".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            exception_id: None,
        };
        let restricted = ApplicablePolicy {
            id: 2,
            decision: "RESTRICTED".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            exception_id: None,
        };
        let prohibited = ApplicablePolicy {
            id: 1,
            decision: "PROHIBITED".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            exception_id: None,
        };
        assert_eq!(evaluate_policies(&[]).effective, "UNMANAGED");
        assert_eq!(
            evaluate_policies(std::slice::from_ref(&approved)).effective,
            "APPROVED"
        );
        assert_eq!(
            evaluate_policies(std::slice::from_ref(&restricted)).effective,
            "RESTRICTED"
        );
        assert_eq!(
            evaluate_policies(std::slice::from_ref(&prohibited)).effective,
            "PROHIBITED"
        );
        let forward =
            evaluate_policies(&[approved.clone(), restricted.clone(), prohibited.clone()]);
        let reverse = evaluate_policies(&[prohibited, restricted, approved]);
        assert_eq!(forward, reverse);
        assert_eq!(forward.effective, "PROHIBITED");

        let incomplete = ApplicablePolicy {
            id: 9,
            decision: "UNKNOWN".to_string(),
            updated_at: String::new(),
            exception_id: None,
        };
        let result = evaluate_policies(&[incomplete]);
        assert_eq!(result.effective, "REVIEW_REQUIRED");
        assert_eq!(result.completeness, "INDETERMINATE");
        assert!(result.review_required);

        let excepted_prohibited = ApplicablePolicy {
            id: 1,
            decision: "PROHIBITED".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            exception_id: Some(101),
        };
        let still_restricted = ApplicablePolicy {
            id: 2,
            decision: "RESTRICTED".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            exception_id: None,
        };
        let result = evaluate_policies(&[excepted_prohibited.clone(), still_restricted]);
        assert_eq!(result.effective, "RESTRICTED");
        assert_eq!(result.exception_id, None);

        let excepted_restricted = ApplicablePolicy {
            id: 2,
            decision: "RESTRICTED".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            exception_id: Some(102),
        };
        let result = evaluate_policies(&[excepted_restricted, excepted_prohibited]);
        assert_eq!(result.effective, "EXCEPTION_ACTIVE");
        assert_eq!(result.exception_id, Some(101));
    }

    #[tokio::test]
    async fn sqlite_vertical_slice_is_tenant_safe_passive_and_audited() {
        let (store, pool) = sqlite_fixture().await;
        let baseline = side_effect_counts(&pool).await;

        let unmanaged = store
            .get_evaluation(
                801,
                SoftwarePolicyTarget {
                    target_type: "PRODUCT".to_string(),
                    target_id: 8301,
                },
            )
            .await
            .unwrap();
        assert_eq!(unmanaged.effective_decision, "UNMANAGED");
        assert_eq!(unmanaged.revision, 0);

        let created = store
            .create_policy(801, 8102, policy_request("PROHIBITED"))
            .await
            .unwrap();
        assert!(created.created);
        let before_activation = store
            .evaluate(801, 8102, evaluation_request())
            .await
            .unwrap();
        assert_eq!(before_activation.effective_decision, "UNMANAGED");

        let active = store
            .activate_policy(
                801,
                8102,
                created.policy.id,
                transition(created.policy.revision, "Approved governance review"),
            )
            .await
            .unwrap();
        let prohibited = store
            .evaluate(801, 8102, evaluation_request())
            .await
            .unwrap();
        assert_eq!(prohibited.effective_decision, "PROHIBITED");
        assert_eq!(prohibited.policy_ids, vec![active.id]);

        let starts = (Utc::now() - Duration::minutes(1)).to_rfc3339_opts(SecondsFormat::Secs, true);
        let expires = (Utc::now() + Duration::hours(2)).to_rfc3339_opts(SecondsFormat::Secs, true);
        let exception = store
            .create_exception(
                801,
                8101,
                SoftwareExceptionCreateRequest {
                    policy_id: active.id,
                    justification: "Temporary compatibility requirement".to_string(),
                    compensating_controls: Some("Restricted network segment".to_string()),
                    requested_valid_from: starts,
                    expires_at: expires,
                },
            )
            .await
            .unwrap()
            .exception;
        let pending = store
            .submit_exception(
                801,
                8101,
                exception.id,
                exception_transition(exception.revision, "Submit for independent review"),
            )
            .await
            .unwrap();
        let self_approval = store
            .approve_exception(
                801,
                8101,
                pending.id,
                exception_transition(pending.revision, "Self approval must fail"),
            )
            .await
            .unwrap_err();
        assert_eq!(self_approval.kind(), SoftwarePolicyErrorKind::Conflict);
        assert_eq!(
            self_approval.code(),
            "software_exception_self_approval_denied"
        );

        let approved = store
            .approve_exception(
                801,
                8102,
                pending.id,
                exception_transition(pending.revision, "Independent time-bounded approval"),
            )
            .await
            .unwrap();
        let excepted = store
            .evaluate(801, 8102, evaluation_request())
            .await
            .unwrap();
        assert_eq!(excepted.effective_decision, "EXCEPTION_ACTIVE");
        assert_eq!(excepted.exception_id, Some(approved.id));
        assert_eq!(
            store.get_policy(801, active.id).await.unwrap().decision,
            "PROHIBITED"
        );

        assert!(store.get_policy(802, active.id).await.is_err());
        assert!(store
            .create_exception(
                802,
                8201,
                SoftwareExceptionCreateRequest {
                    policy_id: active.id,
                    justification: "Cross tenant request".to_string(),
                    compensating_controls: None,
                    requested_valid_from: (Utc::now() - Duration::minutes(1))
                        .to_rfc3339_opts(SecondsFormat::Secs, true),
                    expires_at: (Utc::now() + Duration::hours(1))
                        .to_rfc3339_opts(SecondsFormat::Secs, true),
                },
            )
            .await
            .is_err());

        let revoked = store
            .revoke_exception(
                801,
                8102,
                approved.id,
                exception_transition(approved.revision, "Temporary need ended"),
            )
            .await
            .unwrap();
        assert_eq!(revoked.status, "REVOKED");
        let restored = store
            .evaluate(801, 8102, evaluation_request())
            .await
            .unwrap();
        assert_eq!(restored.effective_decision, "PROHIBITED");

        let events = store.list_audit_events(801, 50, 0).await.unwrap();
        for expected in [
            "policy_created",
            "policy_activated",
            "exception_created",
            "exception_submitted",
            "exception_approved",
            "exception_revoked",
            "effective_decision_changed",
        ] {
            assert!(events.iter().any(|event| event.event_type == expected));
        }
        assert_eq!(side_effect_counts(&pool).await, baseline);
    }

    #[tokio::test]
    async fn sqlite_expiry_is_enforced_without_scheduler() {
        let (store, pool) = sqlite_fixture().await;
        let policy = store
            .create_policy(801, 8102, policy_request("RESTRICTED"))
            .await
            .unwrap()
            .policy;
        let active = store
            .activate_policy(
                801,
                8102,
                policy.id,
                transition(policy.revision, "Activate"),
            )
            .await
            .unwrap();
        let request = store
            .create_exception(
                801,
                8101,
                SoftwareExceptionCreateRequest {
                    policy_id: active.id,
                    justification: "Expiry test".to_string(),
                    compensating_controls: None,
                    requested_valid_from: (Utc::now() - Duration::hours(2))
                        .to_rfc3339_opts(SecondsFormat::Secs, true),
                    expires_at: (Utc::now() + Duration::hours(1))
                        .to_rfc3339_opts(SecondsFormat::Secs, true),
                },
            )
            .await
            .unwrap()
            .exception;
        let pending = store
            .submit_exception(
                801,
                8101,
                request.id,
                exception_transition(request.revision, "Submit"),
            )
            .await
            .unwrap();
        let approved = store
            .approve_exception(
                801,
                8102,
                pending.id,
                exception_transition(pending.revision, "Approve"),
            )
            .await
            .unwrap();
        sqlx::query(
            "UPDATE software_policy_exception SET expires_at=?1 WHERE tenant_id=801 AND id=?2",
        )
        .bind((Utc::now() - Duration::minutes(1)).to_rfc3339_opts(SecondsFormat::Secs, true))
        .bind(approved.id)
        .execute(&pool)
        .await
        .unwrap();
        let current = store
            .get_evaluation(
                801,
                SoftwarePolicyTarget {
                    target_type: "PRODUCT".to_string(),
                    target_id: 8301,
                },
            )
            .await
            .unwrap();
        assert_eq!(current.effective_decision, "RESTRICTED");
        let listed = store.list_exceptions(801, 10, 0).await.unwrap();
        assert_eq!(listed[0].status, "EXPIRED");

        let result = store
            .evaluate(801, 8102, evaluation_request())
            .await
            .unwrap();
        assert_eq!(result.effective_decision, "RESTRICTED");
        let status: String = sqlx::query_scalar(
            "SELECT status FROM software_policy_exception WHERE tenant_id=801 AND id=?1",
        )
        .bind(approved.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(status, "EXPIRED");
    }

    #[tokio::test]
    async fn sqlite_parallel_create_and_stale_revision_do_not_duplicate() {
        let (store, pool) = sqlite_fixture().await;
        let first = {
            let store = store.clone();
            tokio::spawn(async move {
                store
                    .create_policy(801, 8102, policy_request("PROHIBITED"))
                    .await
            })
        };
        let second = {
            let store = store.clone();
            tokio::spawn(async move {
                store
                    .create_policy(801, 8102, policy_request("PROHIBITED"))
                    .await
            })
        };
        let first = first.await.unwrap().unwrap();
        let second = second.await.unwrap().unwrap();
        assert_ne!(first.created, second.created);
        assert_eq!(first.policy.id, second.policy.id);
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM software_approval_policy WHERE tenant_id=801")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count, 1);
        let audit_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM software_policy_audit_event
             WHERE tenant_id=801 AND event_type='policy_created'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(audit_count, 1);

        let active = store
            .activate_policy(
                801,
                8102,
                first.policy.id,
                transition(first.policy.revision, "Activate once"),
            )
            .await
            .unwrap();
        let stale = store
            .archive_policy(
                801,
                8102,
                active.id,
                transition(first.policy.revision, "Stale archive"),
            )
            .await
            .unwrap_err();
        assert_eq!(stale.code(), "stale_software_policy_revision");
    }

    #[tokio::test]
    async fn sqlite_parallel_update_archive_and_duplicate_exception_request_are_serialized() {
        let (store, pool) = sqlite_fixture().await;
        let policy = store
            .create_policy(801, 8102, policy_request("PROHIBITED"))
            .await
            .unwrap()
            .policy;

        let update = {
            let store = store.clone();
            let policy = policy.clone();
            tokio::spawn(async move {
                store
                    .update_policy(
                        801,
                        8102,
                        policy.id,
                        policy_update(policy.revision, "Concurrent updated policy"),
                    )
                    .await
            })
        };
        let archive = {
            let store = store.clone();
            let policy = policy.clone();
            tokio::spawn(async move {
                store
                    .archive_policy(
                        801,
                        8102,
                        policy.id,
                        transition(policy.revision, "Concurrent archive"),
                    )
                    .await
            })
        };
        let results = [update.await.unwrap(), archive.await.unwrap()];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
        let current = store.get_policy(801, policy.id).await.unwrap();
        assert_eq!(current.revision, policy.revision + 1);
        assert!(
            (current.status == "DRAFT" && current.name == "Concurrent updated policy")
                || (current.status == "ARCHIVED" && current.name == policy.name)
        );
        let mutation_audits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM software_policy_audit_event
             WHERE tenant_id=801 AND object_type='POLICY' AND object_id=?1
               AND event_type IN ('policy_updated','policy_archived')",
        )
        .bind(policy.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(mutation_audits, 1);

        let exception_policy = store
            .create_policy(801, 8102, policy_request("RESTRICTED"))
            .await
            .unwrap()
            .policy;
        let exception_policy = store
            .activate_policy(
                801,
                8102,
                exception_policy.id,
                transition(exception_policy.revision, "Activate exception policy"),
            )
            .await
            .unwrap();
        let starts = (Utc::now() - Duration::minutes(1)).to_rfc3339_opts(SecondsFormat::Secs, true);
        let expires = (Utc::now() + Duration::hours(1)).to_rfc3339_opts(SecondsFormat::Secs, true);
        let policy_id = exception_policy.id;
        let first = {
            let store = store.clone();
            let starts = starts.clone();
            let expires = expires.clone();
            tokio::spawn(async move {
                store
                    .create_exception(
                        801,
                        8101,
                        SoftwareExceptionCreateRequest {
                            policy_id,
                            justification: "Identical parallel exception request".to_string(),
                            compensating_controls: Some("Tenant-bound review".to_string()),
                            requested_valid_from: starts,
                            expires_at: expires,
                        },
                    )
                    .await
            })
        };
        let second = {
            let store = store.clone();
            tokio::spawn(async move {
                store
                    .create_exception(
                        801,
                        8101,
                        SoftwareExceptionCreateRequest {
                            policy_id,
                            justification: "Identical parallel exception request".to_string(),
                            compensating_controls: Some("Tenant-bound review".to_string()),
                            requested_valid_from: starts,
                            expires_at: expires,
                        },
                    )
                    .await
            })
        };
        let first = first.await.unwrap().unwrap();
        let second = second.await.unwrap().unwrap();
        assert_ne!(first.created, second.created);
        assert_eq!(first.exception.id, second.exception.id);
        let exception_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM software_policy_exception
             WHERE tenant_id=801 AND policy_id=?1",
        )
        .bind(exception_policy.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let audit_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM software_policy_audit_event
             WHERE tenant_id=801 AND object_type='EXCEPTION'
               AND object_id=?1 AND event_type='exception_created'",
        )
        .bind(first.exception.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!((exception_count, audit_count), (1, 1));
    }

    #[tokio::test]
    async fn sqlite_rejection_and_policy_archive_race_remain_fail_closed() {
        let (store, pool) = sqlite_fixture().await;
        let policy = store
            .create_policy(801, 8102, policy_request("RESTRICTED"))
            .await
            .unwrap()
            .policy;
        let active = store
            .activate_policy(
                801,
                8102,
                policy.id,
                transition(policy.revision, "Activate"),
            )
            .await
            .unwrap();
        let starts = (Utc::now() - Duration::minutes(1)).to_rfc3339_opts(SecondsFormat::Secs, true);
        let rejected_request = store
            .create_exception(
                801,
                8101,
                SoftwareExceptionCreateRequest {
                    policy_id: active.id,
                    justification: "Rejected exception".to_string(),
                    compensating_controls: None,
                    requested_valid_from: starts.clone(),
                    expires_at: (Utc::now() + Duration::hours(1))
                        .to_rfc3339_opts(SecondsFormat::Secs, true),
                },
            )
            .await
            .unwrap()
            .exception;
        let rejected_request = store
            .submit_exception(
                801,
                8101,
                rejected_request.id,
                exception_transition(rejected_request.revision, "Submit rejected request"),
            )
            .await
            .unwrap();
        let rejected = store
            .reject_exception(
                801,
                8102,
                rejected_request.id,
                exception_transition(rejected_request.revision, "Independent rejection"),
            )
            .await
            .unwrap();
        assert_eq!(rejected.status, "REJECTED");
        assert_eq!(
            store
                .evaluate(801, 8102, evaluation_request())
                .await
                .unwrap()
                .effective_decision,
            "RESTRICTED"
        );

        let race_request = store
            .create_exception(
                801,
                8101,
                SoftwareExceptionCreateRequest {
                    policy_id: active.id,
                    justification: "Archive race exception".to_string(),
                    compensating_controls: Some("Isolated execution".to_string()),
                    requested_valid_from: starts,
                    expires_at: (Utc::now() + Duration::hours(2))
                        .to_rfc3339_opts(SecondsFormat::Secs, true),
                },
            )
            .await
            .unwrap()
            .exception;
        let pending = store
            .submit_exception(
                801,
                8101,
                race_request.id,
                exception_transition(race_request.revision, "Submit archive race"),
            )
            .await
            .unwrap();
        let approve = {
            let store = store.clone();
            let pending = pending.clone();
            tokio::spawn(async move {
                store
                    .approve_exception(
                        801,
                        8102,
                        pending.id,
                        exception_transition(pending.revision, "Concurrent approval"),
                    )
                    .await
            })
        };
        let archive = {
            let store = store.clone();
            let active = active.clone();
            tokio::spawn(async move {
                store
                    .archive_policy(
                        801,
                        8102,
                        active.id,
                        transition(active.revision, "Concurrent archive"),
                    )
                    .await
            })
        };
        let approval_result = approve.await.unwrap();
        let archived = archive.await.unwrap().unwrap();
        assert_eq!(archived.status, "ARCHIVED");
        if let Err(error) = approval_result {
            assert_eq!(error.kind(), SoftwarePolicyErrorKind::Conflict);
        }
        assert_eq!(
            store
                .evaluate(801, 8102, evaluation_request())
                .await
                .unwrap()
                .effective_decision,
            "UNMANAGED"
        );
        let request_for_archived = store
            .create_exception(
                801,
                8101,
                SoftwareExceptionCreateRequest {
                    policy_id: active.id,
                    justification: "Archived policy request".to_string(),
                    compensating_controls: None,
                    requested_valid_from: (Utc::now() - Duration::minutes(1))
                        .to_rfc3339_opts(SecondsFormat::Secs, true),
                    expires_at: (Utc::now() + Duration::hours(1))
                        .to_rfc3339_opts(SecondsFormat::Secs, true),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(request_for_archived.code(), "software_policy_archived");
        assert_eq!(side_effect_counts(&pool).await, vec![0, 0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn sqlite_parallel_exception_approval_is_single_and_scope_specific() {
        let (store, pool) = sqlite_fixture().await;
        let prohibited = store
            .create_policy(801, 8102, policy_request("PROHIBITED"))
            .await
            .unwrap()
            .policy;
        let prohibited = store
            .activate_policy(
                801,
                8102,
                prohibited.id,
                transition(prohibited.revision, "Activate prohibited policy"),
            )
            .await
            .unwrap();
        let restricted = store
            .create_policy(801, 8102, policy_request("RESTRICTED"))
            .await
            .unwrap()
            .policy;
        let restricted = store
            .activate_policy(
                801,
                8102,
                restricted.id,
                transition(restricted.revision, "Activate restricted policy"),
            )
            .await
            .unwrap();
        let exception = store
            .create_exception(
                801,
                8101,
                SoftwareExceptionCreateRequest {
                    policy_id: prohibited.id,
                    justification: "Parallel decision test".to_string(),
                    compensating_controls: Some("Isolated execution".to_string()),
                    requested_valid_from: (Utc::now() - Duration::minutes(1))
                        .to_rfc3339_opts(SecondsFormat::Secs, true),
                    expires_at: (Utc::now() + Duration::hours(1))
                        .to_rfc3339_opts(SecondsFormat::Secs, true),
                },
            )
            .await
            .unwrap()
            .exception;
        let pending = store
            .submit_exception(
                801,
                8101,
                exception.id,
                exception_transition(exception.revision, "Submit"),
            )
            .await
            .unwrap();

        let first = {
            let store = store.clone();
            let pending = pending.clone();
            tokio::spawn(async move {
                store
                    .approve_exception(
                        801,
                        8102,
                        pending.id,
                        exception_transition(pending.revision, "Parallel approval"),
                    )
                    .await
            })
        };
        let second = {
            let store = store.clone();
            let pending = pending.clone();
            tokio::spawn(async move {
                store
                    .approve_exception(
                        801,
                        8102,
                        pending.id,
                        exception_transition(pending.revision, "Parallel approval"),
                    )
                    .await
            })
        };
        let results = [first.await.unwrap(), second.await.unwrap()];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);

        let approved_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM software_policy_exception
             WHERE tenant_id=801 AND policy_id=?1 AND status='APPROVED'",
        )
        .bind(prohibited.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let approval_audit_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM software_policy_audit_event
             WHERE tenant_id=801 AND object_type='EXCEPTION'
               AND event_type='exception_approved'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!((approved_count, approval_audit_count), (1, 1));

        let result = store
            .evaluate(801, 8102, evaluation_request())
            .await
            .unwrap();
        assert_eq!(result.effective_decision, "RESTRICTED");
        assert_eq!(result.policy_ids, vec![prohibited.id, restricted.id]);
        assert_eq!(result.exception_id, None);
    }

    #[tokio::test]
    async fn sqlite_audit_failure_rolls_back_policy_transition() {
        let (store, pool) = sqlite_fixture().await;
        let policy = store
            .create_policy(801, 8102, policy_request("PROHIBITED"))
            .await
            .unwrap()
            .policy;
        sqlx::query(
            "INSERT INTO software_policy_audit_event (
                tenant_id,object_type,object_id,event_type,actor_id,
                previous_state,new_state,reason,revision,detail_json
             ) VALUES (801,'POLICY',?1,'policy_activated',8102,
                       'DRAFT','ACTIVE','Injected rollback fixture',2,'{}')",
        )
        .bind(policy.id)
        .execute(&pool)
        .await
        .unwrap();

        let failed = store
            .activate_policy(
                801,
                8102,
                policy.id,
                transition(policy.revision, "Must roll back"),
            )
            .await
            .unwrap_err();
        assert_eq!(failed.kind(), SoftwarePolicyErrorKind::Database);
        let unchanged = store.get_policy(801, policy.id).await.unwrap();
        assert_eq!(unchanged.status, "DRAFT");
        assert_eq!(unchanged.revision, policy.revision);

        sqlx::query(
            "DELETE FROM software_policy_audit_event
             WHERE tenant_id=801 AND object_type='POLICY' AND object_id=?1
               AND event_type='policy_activated' AND revision=2",
        )
        .bind(policy.id)
        .execute(&pool)
        .await
        .unwrap();
        let active = store
            .activate_policy(
                801,
                8102,
                policy.id,
                transition(policy.revision, "Activate after rollback check"),
            )
            .await
            .unwrap();
        let exception = store
            .create_exception(
                801,
                8101,
                SoftwareExceptionCreateRequest {
                    policy_id: active.id,
                    justification: "Approval rollback fixture".to_string(),
                    compensating_controls: None,
                    requested_valid_from: (Utc::now() - Duration::minutes(1))
                        .to_rfc3339_opts(SecondsFormat::Secs, true),
                    expires_at: (Utc::now() + Duration::hours(1))
                        .to_rfc3339_opts(SecondsFormat::Secs, true),
                },
            )
            .await
            .unwrap()
            .exception;
        let pending = store
            .submit_exception(
                801,
                8101,
                exception.id,
                exception_transition(exception.revision, "Submit rollback fixture"),
            )
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO software_policy_audit_event (
                tenant_id,object_type,object_id,event_type,actor_id,
                previous_state,new_state,reason,revision,detail_json
             ) VALUES (801,'EXCEPTION',?1,'exception_approved',8102,
                       'PENDING_REVIEW','APPROVED','Injected rollback fixture',?2,'{}')",
        )
        .bind(pending.id)
        .bind(pending.revision + 1)
        .execute(&pool)
        .await
        .unwrap();
        let failed = store
            .approve_exception(
                801,
                8102,
                pending.id,
                exception_transition(pending.revision, "Approval must roll back"),
            )
            .await
            .unwrap_err();
        assert_eq!(failed.kind(), SoftwarePolicyErrorKind::Database);
        let unchanged: (String, i64) = sqlx::query_as(
            "SELECT status,revision FROM software_policy_exception
             WHERE tenant_id=801 AND id=?1",
        )
        .bind(pending.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(unchanged, ("PENDING_REVIEW".to_string(), pending.revision));

        let evaluation = store
            .evaluate(801, 8102, evaluation_request())
            .await
            .unwrap();
        assert_eq!(evaluation.effective_decision, "PROHIBITED");
        let archived = store
            .archive_policy(
                801,
                8102,
                active.id,
                transition(active.revision, "Archive for evaluation rollback"),
            )
            .await
            .unwrap();
        assert_eq!(archived.status, "ARCHIVED");
        sqlx::query(
            "INSERT INTO software_policy_audit_event (
                tenant_id,object_type,object_id,event_type,actor_id,
                previous_state,new_state,reason,revision,detail_json
             ) VALUES (801,'EVALUATION',?1,'effective_decision_changed',8102,
                       'PROHIBITED','UNMANAGED','Injected rollback fixture',?2,'{}')",
        )
        .bind(evaluation.id)
        .bind(evaluation.revision + 1)
        .execute(&pool)
        .await
        .unwrap();
        let failed = store
            .evaluate(801, 8102, evaluation_request())
            .await
            .unwrap_err();
        assert_eq!(failed.kind(), SoftwarePolicyErrorKind::Database);
        let unchanged: (String, i64) = sqlx::query_as(
            "SELECT effective_decision,revision FROM software_policy_evaluation
             WHERE tenant_id=801 AND id=?1",
        )
        .bind(evaluation.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(unchanged, ("PROHIBITED".to_string(), evaluation.revision));
    }

    #[tokio::test]
    #[ignore = "requires an explicit disposable ISCY_TEST_POSTGRES_URL"]
    async fn postgres_vertical_slice_uses_real_transactions_and_constraints() {
        let database_url = disposable_postgres_url();
        run_db_admin_action(&database_url, DbAdminAction::Migrate)
            .await
            .unwrap();
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .unwrap();
        sqlx::query("DELETE FROM organizations_tenant WHERE id IN (9801,9802)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO organizations_tenant (id,name,slug) VALUES
             (9801,'PG Policy A','pg-policy-a'),(9802,'PG Policy B','pg-policy-b')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO accounts_user (
                id,username,email,tenant_id,role,is_active,is_staff,is_superuser
             ) VALUES
             (9811,'pg-policy-applicant','a@example.invalid',9801,'SOC_ANALYST',TRUE,FALSE,FALSE),
             (9812,'pg-policy-reviewer','r@example.invalid',9801,'SECURITY_ADMIN',TRUE,FALSE,FALSE)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO product_security_product (id,tenant_id,name,code)
             VALUES (9831,9801,'PG Policy Product','PG-POL')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let store = SoftwarePolicyStore::Postgres(pool.clone());
        let mut request = policy_request("PROHIBITED");
        request.target.target_id = 9831;
        request.owner_id = Some(9812);
        let created = store.create_policy(9801, 9812, request).await.unwrap();
        let active = store
            .activate_policy(
                9801,
                9812,
                created.policy.id,
                transition(created.policy.revision, "PG activation"),
            )
            .await
            .unwrap();
        let result = store
            .evaluate(
                9801,
                9812,
                SoftwarePolicyEvaluationRequest {
                    target: active.target.clone(),
                },
            )
            .await
            .unwrap();
        assert_eq!(result.effective_decision, "PROHIBITED");
        let exception = store
            .create_exception(
                9801,
                9811,
                SoftwareExceptionCreateRequest {
                    policy_id: active.id,
                    justification: "PG parallel exception".to_string(),
                    compensating_controls: Some("PG transaction boundary".to_string()),
                    requested_valid_from: (Utc::now() - Duration::minutes(1))
                        .to_rfc3339_opts(SecondsFormat::Secs, true),
                    expires_at: (Utc::now() + Duration::hours(1))
                        .to_rfc3339_opts(SecondsFormat::Secs, true),
                },
            )
            .await
            .unwrap()
            .exception;
        let pending = store
            .submit_exception(
                9801,
                9811,
                exception.id,
                exception_transition(exception.revision, "PG submit"),
            )
            .await
            .unwrap();
        let first = {
            let store = store.clone();
            let pending = pending.clone();
            tokio::spawn(async move {
                store
                    .approve_exception(
                        9801,
                        9812,
                        pending.id,
                        exception_transition(pending.revision, "PG parallel approval"),
                    )
                    .await
            })
        };
        let second = {
            let store = store.clone();
            let pending = pending.clone();
            tokio::spawn(async move {
                store
                    .approve_exception(
                        9801,
                        9812,
                        pending.id,
                        exception_transition(pending.revision, "PG parallel approval"),
                    )
                    .await
            })
        };
        let approvals = [first.await.unwrap(), second.await.unwrap()];
        assert_eq!(approvals.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(approvals.iter().filter(|result| result.is_err()).count(), 1);
        let result = store
            .evaluate(
                9801,
                9812,
                SoftwarePolicyEvaluationRequest {
                    target: active.target.clone(),
                },
            )
            .await
            .unwrap();
        assert_eq!(result.effective_decision, "EXCEPTION_ACTIVE");
        let archived = store
            .archive_policy(
                9801,
                9812,
                active.id,
                transition(active.revision, "PG archive"),
            )
            .await
            .unwrap();
        assert_eq!(archived.status, "ARCHIVED");
        let result = store
            .evaluate(
                9801,
                9812,
                SoftwarePolicyEvaluationRequest {
                    target: active.target,
                },
            )
            .await
            .unwrap();
        assert_eq!(result.effective_decision, "UNMANAGED");
        let approval_audits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM software_policy_audit_event
             WHERE tenant_id=9801 AND object_type='EXCEPTION'
               AND object_id=$1 AND event_type='exception_approved'",
        )
        .bind(pending.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(approval_audits, 1);
        sqlx::query("DELETE FROM organizations_tenant WHERE id IN (9801,9802)")
            .execute(&pool)
            .await
            .unwrap();
    }

    async fn side_effect_counts(pool: &sqlx::SqlitePool) -> Vec<i64> {
        let mut counts = Vec::new();
        for table in [
            "incidents_incident",
            "evidence_evidenceitem",
            "risks_risk",
            "product_security_vulnerability",
            "security_observation",
        ] {
            let sql = format!("SELECT COUNT(*) AS count FROM {table}");
            let row = sqlx::query(&sql).fetch_one(pool).await.unwrap();
            counts.push(row.get("count"));
        }
        counts
    }

    fn disposable_postgres_url() -> String {
        let database_url = std::env::var("ISCY_TEST_POSTGRES_URL")
            .expect("ISCY_TEST_POSTGRES_URL must name a disposable PostgreSQL database");
        let database_name = database_url
            .rsplit_once('/')
            .map(|(_, value)| value)
            .and_then(|value| value.split('?').next())
            .unwrap_or_default();
        assert!(
            (database_url.starts_with("postgres://") || database_url.starts_with("postgresql://"))
                && database_name.starts_with("iscy_test_"),
            "ISCY_TEST_POSTGRES_URL must use a database named iscy_test_*"
        );
        database_url
    }
}
