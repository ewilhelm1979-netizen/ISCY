use std::{error::Error, fmt, str::FromStr};

use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions, SqliteRow},
    Row,
};

use crate::cve_store::normalize_database_url;

pub const CANONICAL_ROLLOUT_RINGS: [(&str, i64); 5] = [
    ("lab", 10),
    ("canary", 20),
    ("pilot", 30),
    ("production", 40),
    ("critical", 50),
];

const ROLLOUT_STATUSES: &[&str] = &[
    "draft",
    "ready",
    "active",
    "paused",
    "completed",
    "aborted",
    "rollback_required",
    "rolled_back",
];
const RING_STATUSES: &[&str] = &[
    "pending",
    "ready",
    "active",
    "observing",
    "passed",
    "failed",
    "not_applicable",
    "rollback_required",
    "rolled_back",
];
const TARGET_STATUSES: &[&str] = &[
    "pending",
    "eligible",
    "blocked",
    "scheduled",
    "in_progress",
    "succeeded",
    "failed",
    "excluded",
    "rollback_required",
    "rolled_back",
];
const SIGNATURE_REQUIREMENTS: &[&str] = &["not_required", "metadata_only", "verified_required"];
const CERTIFICATE_REQUIREMENTS: &[&str] =
    &["not_required", "active_required", "mtls_bound_required"];

#[derive(Clone)]
pub enum AgentRolloutStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentRolloutErrorKind {
    InvalidInput,
    NotFound,
    ForeignReference,
    InvalidTransition,
    ConcurrentChange,
    GateBlocked,
    Database,
}

#[derive(Debug)]
pub struct AgentRolloutError {
    pub kind: AgentRolloutErrorKind,
    pub safe_message: String,
}

impl AgentRolloutError {
    fn new(kind: AgentRolloutErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            safe_message: message.into(),
        }
    }

    fn database(context: &'static str, error: sqlx::Error) -> Self {
        eprintln!("ISCY Agent-Rollout-Store: {context}: {error}");
        Self::new(
            AgentRolloutErrorKind::Database,
            "Die Rollout-Daten konnten nicht verarbeitet werden.",
        )
    }
}

impl fmt::Display for AgentRolloutError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.safe_message)
    }
}

impl Error for AgentRolloutError {}

pub type AgentRolloutResult<T> = Result<T, AgentRolloutError>;

#[derive(Debug, Clone, Deserialize)]
pub struct AgentRolloutWriteRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(alias = "target_version")]
    pub target_agent_version: String,
    pub rollback_plan: String,
    #[serde(default)]
    pub artifact_id: Option<String>,
    #[serde(default)]
    pub policy_profile_id: Option<i64>,
    #[serde(default)]
    pub owner_id: Option<i64>,
    #[serde(default)]
    #[serde(alias = "os_filter")]
    pub os_family_filter: String,
    #[serde(default)]
    pub deployment_channel_filter: String,
    #[serde(default = "default_minimum_score")]
    pub minimum_zero_trust_score: i64,
    #[serde(default = "default_heartbeat_freshness_minutes")]
    pub heartbeat_freshness_minutes: i64,
    #[serde(default)]
    pub maximum_critical_findings: i64,
    #[serde(default = "default_true")]
    pub require_verified_artifact_checksum: bool,
    #[serde(default = "default_signature_requirement")]
    pub signature_requirement: String,
    #[serde(default = "default_certificate_requirement")]
    pub certificate_requirement: String,
    #[serde(default = "default_success_percent")]
    pub minimum_success_percent: i64,
    #[serde(default = "default_observation_minutes")]
    pub observation_minutes: i64,
    #[serde(default)]
    pub max_failed_targets: i64,
    #[serde(default)]
    pub ring_overrides: Vec<AgentRolloutRingConfigRequest>,
    #[serde(default)]
    pub not_applicable_rings: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentRolloutRingConfigRequest {
    pub ring_name: String,
    #[serde(default = "default_success_percent")]
    pub minimum_success_percent: i64,
    #[serde(default = "default_observation_minutes")]
    pub observation_minutes: i64,
    #[serde(default)]
    pub max_failed_targets: i64,
    #[serde(default = "default_minimum_target_count")]
    pub minimum_target_count: i64,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AgentRolloutListFilter {
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub active_ring: Option<String>,
    #[serde(default)]
    pub policy_profile_id: Option<i64>,
    #[serde(default)]
    pub os_family: Option<String>,
    #[serde(default)]
    pub deployment_channel: Option<String>,
    #[serde(default)]
    pub owner_id: Option<i64>,
    #[serde(default)]
    pub has_failures: Option<bool>,
    #[serde(default)]
    pub rollback_required: Option<bool>,
    #[serde(default)]
    pub limit: Option<i64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AgentRolloutTargetPreviewRequest {
    #[serde(default)]
    pub ring_name: Option<String>,
    #[serde(default)]
    pub device_ids: Vec<i64>,
    #[serde(default)]
    pub os_family: Option<String>,
    #[serde(default)]
    pub deployment_channel: Option<String>,
    #[serde(default)]
    pub policy_profile_id: Option<i64>,
    #[serde(default)]
    pub minimum_zero_trust_score: Option<i64>,
    #[serde(default)]
    pub maximum_critical_findings: Option<i64>,
    #[serde(default)]
    pub heartbeat_freshness_minutes: Option<i64>,
    #[serde(default)]
    pub enrollment_status: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentRolloutTargetAssignmentRequest {
    pub assignments: Vec<AgentRolloutTargetAssignment>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentRolloutTargetAssignment {
    pub device_id: i64,
    pub ring_name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentRolloutConfirmationRequest {
    pub confirmed: bool,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentRolloutDeploymentResultRequest {
    #[serde(alias = "result")]
    pub status: String,
    #[serde(default, alias = "observed_agent_version")]
    pub observed_version: String,
    #[serde(default)]
    pub error_class: String,
    #[serde(default)]
    pub operator_note: String,
    #[serde(default)]
    pub observed_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentRolloutRollbackRequest {
    pub confirmed: bool,
    pub reason: String,
    #[serde(default)]
    pub ring_name: Option<String>,
    #[serde(default)]
    pub target_ids: Vec<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentRolloutRollbackCompleteRequest {
    pub confirmed: bool,
    #[serde(default)]
    pub results: Vec<AgentRolloutRollbackTargetResult>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentRolloutRollbackTargetResult {
    pub target_id: i64,
    pub status: String,
    #[serde(default)]
    pub observed_version: String,
    #[serde(default)]
    pub summary: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentRollout {
    pub id: i64,
    pub tenant_id: i64,
    pub name: String,
    pub description: String,
    pub target_agent_version: String,
    pub rollback_plan: String,
    pub artifact_id: Option<String>,
    pub policy_profile_id: Option<i64>,
    pub owner_id: Option<i64>,
    pub status: String,
    pub active_ring_name: Option<String>,
    pub os_family_filter: String,
    pub deployment_channel_filter: String,
    pub minimum_zero_trust_score: i64,
    pub heartbeat_freshness_minutes: i64,
    pub maximum_critical_findings: i64,
    pub require_verified_artifact_checksum: bool,
    pub signature_requirement: String,
    pub certificate_requirement: String,
    pub minimum_success_percent: i64,
    pub observation_minutes: i64,
    pub max_failed_targets: i64,
    pub rollback_status: String,
    pub rollback_reason: String,
    pub created_by_id: Option<i64>,
    pub approved_by_id: Option<i64>,
    pub approved_at: Option<String>,
    pub paused_at: Option<String>,
    pub completed_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentRolloutRing {
    pub id: i64,
    pub rollout_id: i64,
    pub ring_name: String,
    pub sequence_number: i64,
    pub status: String,
    pub minimum_success_percent: i64,
    pub observation_minutes: i64,
    pub max_failed_targets: i64,
    pub minimum_target_count: i64,
    pub started_at: Option<String>,
    pub observation_started_at: Option<String>,
    pub evaluated_at: Option<String>,
    pub approved_by_id: Option<i64>,
    pub approved_at: Option<String>,
    pub completed_at: Option<String>,
    pub failure_reason: String,
    pub target_count: i64,
    pub succeeded_count: i64,
    pub failed_count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentRolloutTarget {
    pub id: i64,
    pub rollout_id: i64,
    pub ring_id: i64,
    pub ring_name: String,
    pub device_id: i64,
    pub hostname: String,
    pub os_family: String,
    pub current_agent_version: String,
    pub status: String,
    pub eligibility_reason: String,
    pub preflight_status: String,
    pub postflight_status: String,
    pub deployment_status: String,
    pub previous_agent_version: String,
    pub expected_agent_version: String,
    pub observed_agent_version: String,
    pub deployment_reference: String,
    pub result_summary: String,
    pub eligibility_status: String,
    pub rollback_status: String,
    pub error_class: String,
    pub operator_note: String,
    pub rollback_requested_at: Option<String>,
    pub rollback_completed_at: Option<String>,
    pub deployment_recorded_at: Option<String>,
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentRolloutCheck {
    pub id: i64,
    pub rollout_id: i64,
    pub ring_id: Option<i64>,
    pub target_id: Option<i64>,
    pub phase: String,
    pub check_type: String,
    pub status: String,
    pub source: String,
    pub summary: String,
    pub detail: Value,
    pub observed_at: String,
    pub actor_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentRolloutEvent {
    pub id: i64,
    pub rollout_id: i64,
    pub ring_id: Option<i64>,
    pub target_id: Option<i64>,
    pub device_id: Option<i64>,
    pub event_type: String,
    pub from_status: String,
    pub to_status: String,
    pub actor_id: Option<i64>,
    pub summary: String,
    pub detail: Value,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentRolloutDetail {
    pub rollout: AgentRollout,
    pub rings: Vec<AgentRolloutRing>,
    pub targets: Vec<AgentRolloutTarget>,
    pub checks: Vec<AgentRolloutCheck>,
    pub events: Vec<AgentRolloutEvent>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentRolloutValidation {
    pub valid: bool,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
    pub detail: AgentRolloutDetail,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentRolloutTargetPreview {
    pub device_id: i64,
    pub hostname: String,
    pub os_family: String,
    pub deployment_channel: String,
    pub agent_version: String,
    pub zero_trust_score: i64,
    pub eligible: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AgentRolloutOperationsSummary {
    pub active_rollouts: i64,
    pub paused_rollouts: i64,
    pub rollback_required_rollouts: i64,
    pub blocked_rings: i64,
    pub failed_targets: i64,
}

#[derive(Debug, Clone)]
struct DeviceFacts {
    id: i64,
    hostname: String,
    os_family: String,
    deployment_channel: String,
    agent_version: String,
    enrollment_status: String,
    zero_trust_score: i64,
    last_seen_at: Option<String>,
    policy_profile_id: Option<i64>,
    critical_findings: i64,
    high_findings: i64,
    certificate_status: String,
    mtls_binding_status: String,
    other_active_rollouts: i64,
}

#[derive(Debug, Clone)]
struct EvaluatedCheck {
    key: &'static str,
    status: &'static str,
    summary: String,
    detail: Value,
}

fn default_minimum_score() -> i64 {
    80
}

fn default_heartbeat_freshness_minutes() -> i64 {
    1_440
}

fn default_true() -> bool {
    true
}

fn default_signature_requirement() -> String {
    "metadata_only".to_string()
}

fn default_certificate_requirement() -> String {
    "not_required".to_string()
}

fn default_success_percent() -> i64 {
    95
}

fn default_observation_minutes() -> i64 {
    30
}

fn default_minimum_target_count() -> i64 {
    1
}

impl AgentRolloutStore {
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let normalized = normalize_database_url(database_url);
        if normalized.starts_with("postgres://") || normalized.starts_with("postgresql://") {
            return Ok(Self::Postgres(
                PgPoolOptions::new()
                    .max_connections(10)
                    .connect(&normalized)
                    .await?,
            ));
        }
        let options = SqliteConnectOptions::from_str(&normalized)?.create_if_missing(true);
        Ok(Self::Sqlite(
            SqlitePoolOptions::new()
                .max_connections(5)
                .connect_with(options)
                .await?,
        ))
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub fn from_postgres_pool(pool: PgPool) -> Self {
        Self::Postgres(pool)
    }

    pub async fn create_rollout(
        &self,
        tenant_id: i64,
        actor_id: i64,
        payload: AgentRolloutWriteRequest,
    ) -> AgentRolloutResult<AgentRolloutDetail> {
        let normalized = validate_write_request(payload)?;
        self.validate_references(tenant_id, &normalized).await?;
        let rollout_id = match self {
            Self::Sqlite(pool) => {
                create_rollout_sqlite(pool, tenant_id, actor_id, &normalized).await?
            }
            Self::Postgres(pool) => {
                create_rollout_postgres(pool, tenant_id, actor_id, &normalized).await?
            }
        };
        self.detail(tenant_id, rollout_id).await
    }

    pub async fn update_rollout(
        &self,
        tenant_id: i64,
        rollout_id: i64,
        actor_id: i64,
        payload: AgentRolloutWriteRequest,
    ) -> AgentRolloutResult<AgentRolloutDetail> {
        let normalized = validate_write_request(payload)?;
        self.validate_references(tenant_id, &normalized).await?;
        let current = self.rollout(tenant_id, rollout_id).await?;
        ensure_rollout_transition(&current.status, "draft")?;
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin().await.map_err(|error| {
                    AgentRolloutError::database(
                        "SQLite-Rollout-Aktualisierung konnte nicht gestartet werden",
                        error,
                    )
                })?;
                let result = sqlx::query(
                    r#"UPDATE zero_trust_agent_rollout SET
                        name=?1, description=?2, target_agent_version=?3, rollback_plan=?4,
                        artifact_id=?5, policy_profile_id=?6, owner_id=?7, os_family_filter=?8,
                        deployment_channel_filter=?9, minimum_zero_trust_score=?10,
                        heartbeat_freshness_minutes=?11, maximum_critical_findings=?12,
                        require_mtls=?13, require_pki_ready=?14,
                        require_verified_artifact_checksum=?15, signature_policy=?16,
                        certificate_requirement=?17, minimum_success_percent=?18,
                        observation_minutes=?19, max_failed_targets=?20, updated_at=CURRENT_TIMESTAMP
                       WHERE tenant_id=?21 AND id=?22 AND status='draft'"#,
                )
                .bind(&normalized.name).bind(&normalized.description).bind(&normalized.target_agent_version)
                .bind(&normalized.rollback_plan).bind(normalized.artifact_id.as_deref()).bind(normalized.policy_profile_id)
                .bind(normalized.owner_id).bind(&normalized.os_family_filter)
                .bind(&normalized.deployment_channel_filter).bind(normalized.minimum_zero_trust_score)
                .bind(normalized.heartbeat_freshness_minutes).bind(normalized.maximum_critical_findings)
                .bind(normalized.certificate_requirement == "mtls_bound_required")
                .bind(normalized.certificate_requirement != "not_required")
                .bind(normalized.require_verified_artifact_checksum).bind(&normalized.signature_requirement)
                .bind(&normalized.certificate_requirement).bind(normalized.minimum_success_percent)
                .bind(normalized.observation_minutes).bind(normalized.max_failed_targets)
                .bind(tenant_id).bind(rollout_id).execute(&mut *tx).await
                .map_err(|error| AgentRolloutError::database("SQLite-Rollout konnte nicht aktualisiert werden", error))?;
                if result.rows_affected() != 1 {
                    return Err(concurrent_change());
                }
                replace_ring_configuration_sqlite(&mut tx, tenant_id, rollout_id, &normalized)
                    .await?;
                insert_event_sqlite(
                    &mut tx,
                    RolloutEventInput {
                        tenant_id,
                        rollout_id,
                        ring_id: None,
                        target_id: None,
                        event_type: "rollout_updated",
                        from_status: "draft",
                        to_status: "draft",
                        actor_id,
                        summary: "Rollout-Konfiguration aktualisiert",
                        detail: json!({}),
                    },
                )
                .await?;
                tx.commit().await.map_err(|error| {
                    AgentRolloutError::database(
                        "SQLite-Rollout-Aktualisierung konnte nicht bestaetigt werden",
                        error,
                    )
                })?;
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await.map_err(|error| {
                    AgentRolloutError::database(
                        "PostgreSQL-Rollout-Aktualisierung konnte nicht gestartet werden",
                        error,
                    )
                })?;
                let result = sqlx::query(
                    r#"UPDATE zero_trust_agent_rollout SET
                        name=$1, description=$2, target_agent_version=$3, rollback_plan=$4,
                        artifact_id=$5, policy_profile_id=$6, owner_id=$7, os_family_filter=$8,
                        deployment_channel_filter=$9, minimum_zero_trust_score=$10,
                        heartbeat_freshness_minutes=$11, maximum_critical_findings=$12,
                        require_mtls=$13, require_pki_ready=$14,
                        require_verified_artifact_checksum=$15, signature_policy=$16,
                        certificate_requirement=$17, minimum_success_percent=$18,
                        observation_minutes=$19, max_failed_targets=$20,
                        updated_at=(CURRENT_TIMESTAMP)::text
                       WHERE tenant_id=$21 AND id=$22 AND status='draft'"#,
                )
                .bind(&normalized.name)
                .bind(&normalized.description)
                .bind(&normalized.target_agent_version)
                .bind(&normalized.rollback_plan)
                .bind(normalized.artifact_id.as_deref())
                .bind(normalized.policy_profile_id)
                .bind(normalized.owner_id)
                .bind(&normalized.os_family_filter)
                .bind(&normalized.deployment_channel_filter)
                .bind(normalized.minimum_zero_trust_score)
                .bind(normalized.heartbeat_freshness_minutes)
                .bind(normalized.maximum_critical_findings)
                .bind(normalized.certificate_requirement == "mtls_bound_required")
                .bind(normalized.certificate_requirement != "not_required")
                .bind(normalized.require_verified_artifact_checksum)
                .bind(&normalized.signature_requirement)
                .bind(&normalized.certificate_requirement)
                .bind(normalized.minimum_success_percent)
                .bind(normalized.observation_minutes)
                .bind(normalized.max_failed_targets)
                .bind(tenant_id)
                .bind(rollout_id)
                .execute(&mut *tx)
                .await
                .map_err(|error| {
                    AgentRolloutError::database(
                        "PostgreSQL-Rollout konnte nicht aktualisiert werden",
                        error,
                    )
                })?;
                if result.rows_affected() != 1 {
                    return Err(concurrent_change());
                }
                replace_ring_configuration_postgres(&mut tx, tenant_id, rollout_id, &normalized)
                    .await?;
                insert_event_postgres(
                    &mut tx,
                    RolloutEventInput {
                        tenant_id,
                        rollout_id,
                        ring_id: None,
                        target_id: None,
                        event_type: "rollout_updated",
                        from_status: "draft",
                        to_status: "draft",
                        actor_id,
                        summary: "Rollout-Konfiguration aktualisiert",
                        detail: json!({}),
                    },
                )
                .await?;
                tx.commit().await.map_err(|error| {
                    AgentRolloutError::database(
                        "PostgreSQL-Rollout-Aktualisierung konnte nicht bestaetigt werden",
                        error,
                    )
                })?;
            }
        }
        self.detail(tenant_id, rollout_id).await
    }

    pub async fn list(
        &self,
        tenant_id: i64,
        mut filter: AgentRolloutListFilter,
    ) -> AgentRolloutResult<Vec<AgentRollout>> {
        if let Some(status) = filter.status.as_mut() {
            *status = status.trim().to_ascii_lowercase();
            validate_member("Rollout-Status", status, ROLLOUT_STATUSES)?;
        }
        if let Some(ring_name) = filter.active_ring.as_mut() {
            *ring_name = ring_name.trim().to_ascii_lowercase();
            validate_ring_name(ring_name)?;
        }
        if let Some(os_family) = filter.os_family.as_mut() {
            *os_family = os_family.trim().to_ascii_uppercase();
            validate_os_filter(os_family)?;
        }
        if let Some(channel) = filter.deployment_channel.as_mut() {
            *channel = channel.trim().to_ascii_lowercase();
            validate_deployment_channel(channel)?;
        }
        let limit = filter.limit.unwrap_or(100);
        validate_range("Das Listenlimit", limit, 1, 500)?;
        match self {
            Self::Sqlite(pool) => {
                let rows = sqlx::query(
                    r#"SELECT * FROM zero_trust_agent_rollout
                       WHERE tenant_id=?1 AND (?2 IS NULL OR status=?2)
                         AND (?3 IS NULL OR owner_id=?3)
                         AND (?4 IS NULL OR active_ring_name=?4)
                         AND (?5 IS NULL OR policy_profile_id=?5)
                         AND (?6 IS NULL OR os_family_filter=?6)
                         AND (?7 IS NULL OR deployment_channel_filter=?7)
                         AND (?8 IS NULL OR (?8=1 AND EXISTS (
                               SELECT 1 FROM zero_trust_agent_rollout_target target
                               WHERE target.tenant_id=zero_trust_agent_rollout.tenant_id
                                 AND target.rollout_id=zero_trust_agent_rollout.id
                                 AND target.status='failed'
                             )) OR (?8=0 AND NOT EXISTS (
                               SELECT 1 FROM zero_trust_agent_rollout_target target
                               WHERE target.tenant_id=zero_trust_agent_rollout.tenant_id
                                 AND target.rollout_id=zero_trust_agent_rollout.id
                                 AND target.status='failed'
                             )))
                         AND (?9 IS NULL OR (?9=1 AND status='rollback_required')
                              OR (?9=0 AND status<>'rollback_required'))
                       ORDER BY updated_at DESC, id DESC LIMIT ?10"#,
                )
                .bind(tenant_id)
                .bind(filter.status.as_deref())
                .bind(filter.owner_id)
                .bind(filter.active_ring.as_deref())
                .bind(filter.policy_profile_id)
                .bind(filter.os_family.as_deref())
                .bind(filter.deployment_channel.as_deref())
                .bind(filter.has_failures)
                .bind(filter.rollback_required)
                .bind(limit)
                .fetch_all(pool)
                .await
                .map_err(|error| {
                    AgentRolloutError::database(
                        "SQLite-Rollouts konnten nicht gelesen werden",
                        error,
                    )
                })?;
                rows.into_iter().map(rollout_from_sqlite_row).collect()
            }
            Self::Postgres(pool) => {
                let rows = sqlx::query(
                    r#"SELECT * FROM zero_trust_agent_rollout
                       WHERE tenant_id=$1 AND ($2::text IS NULL OR status=$2)
                         AND ($3::bigint IS NULL OR owner_id=$3)
                         AND ($4::text IS NULL OR active_ring_name=$4)
                         AND ($5::bigint IS NULL OR policy_profile_id=$5)
                         AND ($6::text IS NULL OR os_family_filter=$6)
                         AND ($7::text IS NULL OR deployment_channel_filter=$7)
                         AND ($8::boolean IS NULL OR ($8 AND EXISTS (
                               SELECT 1 FROM zero_trust_agent_rollout_target target
                               WHERE target.tenant_id=zero_trust_agent_rollout.tenant_id
                                 AND target.rollout_id=zero_trust_agent_rollout.id
                                 AND target.status='failed'
                             )) OR (NOT $8 AND NOT EXISTS (
                               SELECT 1 FROM zero_trust_agent_rollout_target target
                               WHERE target.tenant_id=zero_trust_agent_rollout.tenant_id
                                 AND target.rollout_id=zero_trust_agent_rollout.id
                                 AND target.status='failed'
                             )))
                         AND ($9::boolean IS NULL OR ($9 AND status='rollback_required')
                              OR (NOT $9 AND status<>'rollback_required'))
                       ORDER BY updated_at DESC, id DESC LIMIT $10"#,
                )
                .bind(tenant_id)
                .bind(filter.status.as_deref())
                .bind(filter.owner_id)
                .bind(filter.active_ring.as_deref())
                .bind(filter.policy_profile_id)
                .bind(filter.os_family.as_deref())
                .bind(filter.deployment_channel.as_deref())
                .bind(filter.has_failures)
                .bind(filter.rollback_required)
                .bind(limit)
                .fetch_all(pool)
                .await
                .map_err(|error| {
                    AgentRolloutError::database(
                        "PostgreSQL-Rollouts konnten nicht gelesen werden",
                        error,
                    )
                })?;
                rows.into_iter().map(rollout_from_postgres_row).collect()
            }
        }
    }

    pub async fn detail(
        &self,
        tenant_id: i64,
        rollout_id: i64,
    ) -> AgentRolloutResult<AgentRolloutDetail> {
        let rollout = self.rollout(tenant_id, rollout_id).await?;
        let (rings, targets, checks, events) = match self {
            Self::Sqlite(pool) => (
                list_rings_sqlite(pool, tenant_id, rollout_id).await?,
                list_targets_sqlite(pool, tenant_id, rollout_id).await?,
                list_checks_sqlite(pool, tenant_id, rollout_id).await?,
                list_events_sqlite(pool, tenant_id, rollout_id).await?,
            ),
            Self::Postgres(pool) => (
                list_rings_postgres(pool, tenant_id, rollout_id).await?,
                list_targets_postgres(pool, tenant_id, rollout_id).await?,
                list_checks_postgres(pool, tenant_id, rollout_id).await?,
                list_events_postgres(pool, tenant_id, rollout_id).await?,
            ),
        };
        Ok(AgentRolloutDetail {
            rollout,
            rings,
            targets,
            checks,
            events,
        })
    }

    pub async fn target_preview(
        &self,
        tenant_id: i64,
        rollout_id: i64,
        mut request: AgentRolloutTargetPreviewRequest,
    ) -> AgentRolloutResult<Vec<AgentRolloutTargetPreview>> {
        let rollout = self.rollout(tenant_id, rollout_id).await?;
        let limit = request.limit.unwrap_or(100);
        validate_range("Das Vorschau-Limit", limit, 1, 500)?;
        if request.device_ids.len() > 500 {
            return Err(invalid_input(
                "Eine Zielvorschau darf hoechstens 500 Device-IDs enthalten.",
            ));
        }
        request.device_ids.sort_unstable();
        request.device_ids.dedup();
        if let Some(ring_name) = request.ring_name.as_mut() {
            *ring_name = ring_name.trim().to_ascii_lowercase();
            validate_ring_name(ring_name)?;
        }
        let os_filter = request.os_family.as_mut().map_or_else(
            || rollout.os_family_filter.clone(),
            |value| {
                *value = value.trim().to_ascii_uppercase();
                value.clone()
            },
        );
        validate_os_filter(&os_filter)?;
        let channel_filter = request.deployment_channel.as_mut().map_or_else(
            || rollout.deployment_channel_filter.clone(),
            |value| {
                *value = value.trim().to_ascii_lowercase();
                value.clone()
            },
        );
        validate_deployment_channel(&channel_filter)?;
        if let Some(minimum_score) = request.minimum_zero_trust_score {
            validate_range("Der minimale Zero-Trust-Score", minimum_score, 0, 100)?;
        }
        if let Some(maximum_critical) = request.maximum_critical_findings {
            validate_range(
                "Die Zahl maximaler kritischer Findings",
                maximum_critical,
                0,
                100_000,
            )?;
        }
        if let Some(heartbeat_minutes) = request.heartbeat_freshness_minutes {
            validate_range("Das Heartbeat-Zeitfenster", heartbeat_minutes, 1, 525_600)?;
        }
        if let Some(status) = request.enrollment_status.as_mut() {
            *status = status.trim().to_ascii_uppercase();
            validate_member(
                "Enrollment-Status",
                status,
                &["ACTIVE", "REVOKED", "PENDING"],
            )?;
        }
        let mut facts = if request.device_ids.is_empty() {
            self.device_facts(tenant_id, rollout_id, &os_filter, &channel_filter, 500)
                .await?
        } else {
            let existing_target_ids: Vec<i64> = self
                .detail(tenant_id, rollout_id)
                .await?
                .targets
                .into_iter()
                .map(|target| target.device_id)
                .collect();
            let mut selected = Vec::new();
            for device_id in &request.device_ids {
                if existing_target_ids.contains(device_id) {
                    continue;
                }
                match self
                    .device_facts_by_id(tenant_id, rollout_id, *device_id)
                    .await
                {
                    Ok(facts) => selected.push(facts),
                    Err(error) if error.kind == AgentRolloutErrorKind::ForeignReference => {}
                    Err(error) => return Err(error),
                }
            }
            selected
        };
        facts.retain(|facts| {
            (os_filter.is_empty() || facts.os_family == os_filter)
                && (channel_filter.is_empty() || facts.deployment_channel == channel_filter)
                && request
                    .policy_profile_id
                    .is_none_or(|policy_id| facts.policy_profile_id == Some(policy_id))
                && request
                    .minimum_zero_trust_score
                    .is_none_or(|score| facts.zero_trust_score >= score)
                && request
                    .maximum_critical_findings
                    .is_none_or(|count| facts.critical_findings <= count)
                && request
                    .enrollment_status
                    .as_deref()
                    .is_none_or(|status| facts.enrollment_status == status)
                && request.heartbeat_freshness_minutes.is_none_or(|minutes| {
                    facts
                        .last_seen_at
                        .as_deref()
                        .and_then(parse_timestamp)
                        .is_some_and(|seen| {
                            let age = Utc::now().signed_duration_since(seen).num_minutes();
                            age >= 0 && age <= minutes
                        })
                })
        });
        facts.truncate(limit as usize);
        let artifact = self
            .artifact_status(tenant_id, rollout.artifact_id.as_deref())
            .await?;
        Ok(facts
            .into_iter()
            .map(|facts| {
                let checks = evaluate_preflight(&rollout, &facts, artifact.as_ref());
                let reasons: Vec<String> = checks
                    .iter()
                    .filter(|check| check.status == "failed")
                    .map(|check| check.summary.clone())
                    .collect();
                AgentRolloutTargetPreview {
                    device_id: facts.id,
                    hostname: facts.hostname,
                    os_family: facts.os_family,
                    deployment_channel: facts.deployment_channel,
                    agent_version: facts.agent_version,
                    zero_trust_score: facts.zero_trust_score,
                    eligible: reasons.is_empty(),
                    reasons,
                }
            })
            .collect())
    }

    async fn rollout(&self, tenant_id: i64, rollout_id: i64) -> AgentRolloutResult<AgentRollout> {
        let rollout =
            match self {
                Self::Sqlite(pool) => sqlx::query(
                    "SELECT * FROM zero_trust_agent_rollout WHERE tenant_id=?1 AND id=?2",
                )
                .bind(tenant_id)
                .bind(rollout_id)
                .fetch_optional(pool)
                .await
                .map_err(|error| {
                    AgentRolloutError::database("SQLite-Rollout konnte nicht gelesen werden", error)
                })?
                .map(rollout_from_sqlite_row)
                .transpose()?,
                Self::Postgres(pool) => sqlx::query(
                    "SELECT * FROM zero_trust_agent_rollout WHERE tenant_id=$1 AND id=$2",
                )
                .bind(tenant_id)
                .bind(rollout_id)
                .fetch_optional(pool)
                .await
                .map_err(|error| {
                    AgentRolloutError::database(
                        "PostgreSQL-Rollout konnte nicht gelesen werden",
                        error,
                    )
                })?
                .map(rollout_from_postgres_row)
                .transpose()?,
            };
        rollout.ok_or_else(|| {
            AgentRolloutError::new(
                AgentRolloutErrorKind::NotFound,
                "Der Rollout wurde nicht gefunden.",
            )
        })
    }

    async fn validate_references(
        &self,
        tenant_id: i64,
        payload: &AgentRolloutWriteRequest,
    ) -> AgentRolloutResult<()> {
        if let Some(policy_id) = payload.policy_profile_id {
            let exists: bool = match self {
                Self::Sqlite(pool) => sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM zero_trust_agent_policy_profile WHERE tenant_id=?1 AND id=?2 AND enabled=1)").bind(tenant_id).bind(policy_id).fetch_one(pool).await,
                Self::Postgres(pool) => sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM zero_trust_agent_policy_profile WHERE tenant_id=$1 AND id=$2 AND enabled=TRUE)").bind(tenant_id).bind(policy_id).fetch_one(pool).await,
            }.map_err(|error| AgentRolloutError::database("Rollout-Policy konnte nicht geprueft werden", error))?;
            if !exists {
                return Err(foreign_reference(
                    "Das Policy-Profil ist fuer diesen Mandanten nicht verfuegbar.",
                ));
            }
        }
        if let Some(artifact_id) = payload.artifact_id.as_deref() {
            let exists: bool = match self {
                Self::Sqlite(pool) => sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM agent_release_artifact WHERE tenant_id=?1 AND artifact_id=?2)").bind(tenant_id).bind(artifact_id).fetch_one(pool).await,
                Self::Postgres(pool) => sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM agent_release_artifact WHERE tenant_id=$1 AND artifact_id=$2)").bind(tenant_id).bind(artifact_id).fetch_one(pool).await,
            }.map_err(|error| AgentRolloutError::database("Rollout-Artefakt konnte nicht geprueft werden", error))?;
            if !exists {
                return Err(foreign_reference(
                    "Das Release-Artefakt ist fuer diesen Mandanten nicht verfuegbar.",
                ));
            }
        }
        if let Some(owner_id) = payload.owner_id {
            let exists: bool = match self {
                Self::Sqlite(pool) => sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM accounts_user WHERE tenant_id=?1 AND id=?2 AND is_active=1)").bind(tenant_id).bind(owner_id).fetch_one(pool).await,
                Self::Postgres(pool) => sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM accounts_user WHERE tenant_id=$1 AND id=$2 AND is_active=TRUE)").bind(tenant_id).bind(owner_id).fetch_one(pool).await,
            }.map_err(|error| AgentRolloutError::database("Rollout-Owner konnte nicht geprueft werden", error))?;
            if !exists {
                return Err(foreign_reference(
                    "Der Owner ist fuer diesen Mandanten nicht verfuegbar.",
                ));
            }
        }
        Ok(())
    }

    async fn artifact_status(
        &self,
        tenant_id: i64,
        artifact_id: Option<&str>,
    ) -> AgentRolloutResult<Option<(String, String, String)>> {
        let Some(artifact_id) = artifact_id else {
            return Ok(None);
        };
        match self {
            Self::Sqlite(pool) => sqlx::query("SELECT sha256, signature_status, verification_status FROM agent_release_artifact WHERE tenant_id=?1 AND artifact_id=?2")
                .bind(tenant_id).bind(artifact_id).fetch_optional(pool).await
                .map_err(|error| AgentRolloutError::database("SQLite-Artefaktstatus konnte nicht gelesen werden", error))?
                .map(|row| Ok((row.try_get("sha256")?, row.try_get("signature_status")?, row.try_get("verification_status")?))).transpose()
                .map_err(|error: sqlx::Error| AgentRolloutError::database("SQLite-Artefaktstatus ist unlesbar", error)),
            Self::Postgres(pool) => sqlx::query("SELECT sha256, signature_status, verification_status FROM agent_release_artifact WHERE tenant_id=$1 AND artifact_id=$2")
                .bind(tenant_id).bind(artifact_id).fetch_optional(pool).await
                .map_err(|error| AgentRolloutError::database("PostgreSQL-Artefaktstatus konnte nicht gelesen werden", error))?
                .map(|row| Ok((row.try_get("sha256")?, row.try_get("signature_status")?, row.try_get("verification_status")?))).transpose()
                .map_err(|error: sqlx::Error| AgentRolloutError::database("PostgreSQL-Artefaktstatus ist unlesbar", error)),
        }
    }
}

async fn abort_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    rollout_id: i64,
    actor_id: i64,
    from_status: &str,
    reason: &str,
) -> AgentRolloutResult<()> {
    let mut tx = pool.begin().await.map_err(|error| {
        AgentRolloutError::database(
            "SQLite-Rollout-Abbruch konnte nicht gestartet werden",
            error,
        )
    })?;
    let result=sqlx::query("UPDATE zero_trust_agent_rollout SET status='aborted',active_ring_name=NULL,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?1 AND id=?2 AND status=?3").bind(tenant_id).bind(rollout_id).bind(from_status).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("SQLite-Rollout konnte nicht abgebrochen werden",error))?;
    if result.rows_affected() != 1 {
        return Err(concurrent_change());
    }
    sqlx::query("UPDATE zero_trust_agent_rollout_target SET status='excluded',deployment_status='excluded',result_summary='Rollout abgebrochen',completed_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?1 AND rollout_id=?2 AND status IN ('pending','eligible','blocked','scheduled','in_progress')").bind(tenant_id).bind(rollout_id).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("SQLite-offene Rollout-Ziele konnten nicht geschlossen werden",error))?;
    insert_event_sqlite(
        &mut tx,
        RolloutEventInput {
            tenant_id,
            rollout_id,
            ring_id: None,
            target_id: None,
            event_type: "rollout_aborted",
            from_status,
            to_status: "aborted",
            actor_id,
            summary: "Rollout manuell abgebrochen",
            detail: json!({"reason":reason.trim()}),
        },
    )
    .await?;
    tx.commit().await.map_err(|error| {
        AgentRolloutError::database(
            "SQLite-Rollout-Abbruch konnte nicht bestaetigt werden",
            error,
        )
    })?;
    Ok(())
}

async fn abort_postgres(
    pool: &PgPool,
    tenant_id: i64,
    rollout_id: i64,
    actor_id: i64,
    from_status: &str,
    reason: &str,
) -> AgentRolloutResult<()> {
    let mut tx = pool.begin().await.map_err(|error| {
        AgentRolloutError::database(
            "PostgreSQL-Rollout-Abbruch konnte nicht gestartet werden",
            error,
        )
    })?;
    let result=sqlx::query("UPDATE zero_trust_agent_rollout SET status='aborted',active_ring_name=NULL,updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$1 AND id=$2 AND status=$3").bind(tenant_id).bind(rollout_id).bind(from_status).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("PostgreSQL-Rollout konnte nicht abgebrochen werden",error))?;
    if result.rows_affected() != 1 {
        return Err(concurrent_change());
    }
    sqlx::query("UPDATE zero_trust_agent_rollout_target SET status='excluded',deployment_status='excluded',result_summary='Rollout abgebrochen',completed_at=(CURRENT_TIMESTAMP)::text,updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$1 AND rollout_id=$2 AND status IN ('pending','eligible','blocked','scheduled','in_progress')").bind(tenant_id).bind(rollout_id).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("PostgreSQL-offene Rollout-Ziele konnten nicht geschlossen werden",error))?;
    insert_event_postgres(
        &mut tx,
        RolloutEventInput {
            tenant_id,
            rollout_id,
            ring_id: None,
            target_id: None,
            event_type: "rollout_aborted",
            from_status,
            to_status: "aborted",
            actor_id,
            summary: "Rollout manuell abgebrochen",
            detail: json!({"reason":reason.trim()}),
        },
    )
    .await?;
    tx.commit().await.map_err(|error| {
        AgentRolloutError::database(
            "PostgreSQL-Rollout-Abbruch konnte nicht bestaetigt werden",
            error,
        )
    })?;
    Ok(())
}

fn select_rollback_targets<'a>(
    detail: &'a AgentRolloutDetail,
    request: &AgentRolloutRollbackRequest,
) -> AgentRolloutResult<Vec<&'a AgentRolloutTarget>> {
    if let Some(ring_name) = request.ring_name.as_deref() {
        validate_ring_name(ring_name)?;
    }
    if request.target_ids.len() > 500 {
        return Err(invalid_input(
            "Ein Rollback darf hoechstens 500 Ziele enthalten.",
        ));
    }
    let selected: Vec<_> = detail
        .targets
        .iter()
        .filter(|target| {
            let by_ids = !request.target_ids.is_empty() && request.target_ids.contains(&target.id);
            let by_ring = request
                .ring_name
                .as_deref()
                .is_some_and(|name| target.ring_name == name);
            let by_active = request.target_ids.is_empty()
                && request.ring_name.is_none()
                && detail
                    .rollout
                    .active_ring_name
                    .as_deref()
                    .is_some_and(|name| target.ring_name == name);
            (by_ids || by_ring || by_active)
                && matches!(
                    target.status.as_str(),
                    "scheduled" | "in_progress" | "succeeded" | "failed" | "rollback_required"
                )
        })
        .collect();
    if !request
        .target_ids
        .iter()
        .all(|id| selected.iter().any(|target| target.id == *id))
    {
        return Err(foreign_reference(
            "Mindestens ein Rollback-Ziel ist nicht tenant-sicher verfuegbar.",
        ));
    }
    Ok(selected)
}

async fn request_rollback_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    rollout_id: i64,
    actor_id: i64,
    detail: &AgentRolloutDetail,
    targets: Vec<&AgentRolloutTarget>,
    reason: &str,
) -> AgentRolloutResult<()> {
    let mut tx = pool.begin().await.map_err(|error| {
        AgentRolloutError::database(
            "SQLite-Rollback-Anforderung konnte nicht gestartet werden",
            error,
        )
    })?;
    let result=sqlx::query("UPDATE zero_trust_agent_rollout SET status='rollback_required',rollback_status='requested',rollback_reason=?1,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?2 AND id=?3 AND status=?4").bind(reason).bind(tenant_id).bind(rollout_id).bind(&detail.rollout.status).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("SQLite-Rollback-Anforderung konnte nicht gespeichert werden",error))?;
    if result.rows_affected() != 1 {
        return Err(concurrent_change());
    }
    let mut ring_ids = Vec::new();
    for target in targets {
        let result=sqlx::query("UPDATE zero_trust_agent_rollout_target SET status='rollback_required',deployment_status='rollback_required',rollback_status='requested',rollback_requested_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?1 AND rollout_id=?2 AND id=?3 AND status=?4").bind(tenant_id).bind(rollout_id).bind(target.id).bind(&target.status).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("SQLite-Rollback-Ziel konnte nicht markiert werden",error))?;
        if result.rows_affected() != 1 {
            return Err(concurrent_change());
        }
        if !ring_ids.contains(&target.ring_id) {
            ring_ids.push(target.ring_id);
        }
        insert_event_sqlite(
            &mut tx,
            RolloutEventInput {
                tenant_id,
                rollout_id,
                ring_id: Some(target.ring_id),
                target_id: Some(target.id),
                event_type: "target_rollback_requested",
                from_status: &target.status,
                to_status: "rollback_required",
                actor_id,
                summary: "Rollback fuer Agent-Ziel angefordert",
                detail: json!({"reason":reason}),
            },
        )
        .await?;
    }
    for ring_id in ring_ids {
        sqlx::query("UPDATE zero_trust_agent_rollout_ring SET status='rollback_required',updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?1 AND rollout_id=?2 AND id=?3 AND status IN ('active','observing','passed','failed','rollback_required')").bind(tenant_id).bind(rollout_id).bind(ring_id).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("SQLite-Rollback-Ring konnte nicht markiert werden",error))?;
    }
    insert_event_sqlite(
        &mut tx,
        RolloutEventInput {
            tenant_id,
            rollout_id,
            ring_id: None,
            target_id: None,
            event_type: "rollback_requested",
            from_status: &detail.rollout.status,
            to_status: "rollback_required",
            actor_id,
            summary:
                "Kontrollierter Rollback angefordert; externe Ausfuehrung bleibt ausserhalb ISCY",
            detail: json!({"reason":reason,"remote_execution":false}),
        },
    )
    .await?;
    tx.commit().await.map_err(|error| {
        AgentRolloutError::database(
            "SQLite-Rollback-Anforderung konnte nicht bestaetigt werden",
            error,
        )
    })?;
    Ok(())
}

async fn request_rollback_postgres(
    pool: &PgPool,
    tenant_id: i64,
    rollout_id: i64,
    actor_id: i64,
    detail: &AgentRolloutDetail,
    targets: Vec<&AgentRolloutTarget>,
    reason: &str,
) -> AgentRolloutResult<()> {
    let mut tx = pool.begin().await.map_err(|error| {
        AgentRolloutError::database(
            "PostgreSQL-Rollback-Anforderung konnte nicht gestartet werden",
            error,
        )
    })?;
    let result=sqlx::query("UPDATE zero_trust_agent_rollout SET status='rollback_required',rollback_status='requested',rollback_reason=$1,updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$2 AND id=$3 AND status=$4").bind(reason).bind(tenant_id).bind(rollout_id).bind(&detail.rollout.status).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("PostgreSQL-Rollback-Anforderung konnte nicht gespeichert werden",error))?;
    if result.rows_affected() != 1 {
        return Err(concurrent_change());
    }
    let mut ring_ids = Vec::new();
    for target in targets {
        let result=sqlx::query("UPDATE zero_trust_agent_rollout_target SET status='rollback_required',deployment_status='rollback_required',rollback_status='requested',rollback_requested_at=(CURRENT_TIMESTAMP)::text,updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$1 AND rollout_id=$2 AND id=$3 AND status=$4").bind(tenant_id).bind(rollout_id).bind(target.id).bind(&target.status).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("PostgreSQL-Rollback-Ziel konnte nicht markiert werden",error))?;
        if result.rows_affected() != 1 {
            return Err(concurrent_change());
        }
        if !ring_ids.contains(&target.ring_id) {
            ring_ids.push(target.ring_id);
        }
        insert_event_postgres(
            &mut tx,
            RolloutEventInput {
                tenant_id,
                rollout_id,
                ring_id: Some(target.ring_id),
                target_id: Some(target.id),
                event_type: "target_rollback_requested",
                from_status: &target.status,
                to_status: "rollback_required",
                actor_id,
                summary: "Rollback fuer Agent-Ziel angefordert",
                detail: json!({"reason":reason}),
            },
        )
        .await?;
    }
    for ring_id in ring_ids {
        sqlx::query("UPDATE zero_trust_agent_rollout_ring SET status='rollback_required',updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$1 AND rollout_id=$2 AND id=$3 AND status IN ('active','observing','passed','failed','rollback_required')").bind(tenant_id).bind(rollout_id).bind(ring_id).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("PostgreSQL-Rollback-Ring konnte nicht markiert werden",error))?;
    }
    insert_event_postgres(
        &mut tx,
        RolloutEventInput {
            tenant_id,
            rollout_id,
            ring_id: None,
            target_id: None,
            event_type: "rollback_requested",
            from_status: &detail.rollout.status,
            to_status: "rollback_required",
            actor_id,
            summary:
                "Kontrollierter Rollback angefordert; externe Ausfuehrung bleibt ausserhalb ISCY",
            detail: json!({"reason":reason,"remote_execution":false}),
        },
    )
    .await?;
    tx.commit().await.map_err(|error| {
        AgentRolloutError::database(
            "PostgreSQL-Rollback-Anforderung konnte nicht bestaetigt werden",
            error,
        )
    })?;
    Ok(())
}

async fn complete_rollback_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    rollout_id: i64,
    actor_id: i64,
    request: &AgentRolloutRollbackCompleteRequest,
) -> AgentRolloutResult<()> {
    let mut tx = pool.begin().await.map_err(|error| {
        AgentRolloutError::database(
            "SQLite-Rollback-Abschluss konnte nicht gestartet werden",
            error,
        )
    })?;
    for item in &request.results {
        let result=sqlx::query("UPDATE zero_trust_agent_rollout_target SET status=?1,deployment_status=?1,rollback_status=CASE WHEN ?1='rolled_back' THEN 'completed' ELSE 'failed' END,observed_agent_version=?2,result_summary=?3,rollback_completed_at=CURRENT_TIMESTAMP,completed_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?4 AND rollout_id=?5 AND id=?6 AND status='rollback_required'")
            .bind(&item.status).bind(item.observed_version.trim()).bind(item.summary.trim()).bind(tenant_id).bind(rollout_id).bind(item.target_id).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("SQLite-Rollback-Ergebnis konnte nicht gespeichert werden",error))?;
        if result.rows_affected() != 1 {
            return Err(concurrent_change());
        }
        insert_event_sqlite(
            &mut tx,
            RolloutEventInput {
                tenant_id,
                rollout_id,
                ring_id: None,
                target_id: Some(item.target_id),
                event_type: "rollback_result_recorded",
                from_status: "rollback_required",
                to_status: &item.status,
                actor_id,
                summary: "Externes Rollback-Ergebnis dokumentiert",
                detail: json!({"observed_version":item.observed_version}),
            },
        )
        .await?;
    }
    finalize_rollback_sqlite(&mut tx, tenant_id, rollout_id, actor_id).await?;
    tx.commit().await.map_err(|error| {
        AgentRolloutError::database(
            "SQLite-Rollback-Abschluss konnte nicht bestaetigt werden",
            error,
        )
    })?;
    Ok(())
}

async fn complete_rollback_postgres(
    pool: &PgPool,
    tenant_id: i64,
    rollout_id: i64,
    actor_id: i64,
    request: &AgentRolloutRollbackCompleteRequest,
) -> AgentRolloutResult<()> {
    let mut tx = pool.begin().await.map_err(|error| {
        AgentRolloutError::database(
            "PostgreSQL-Rollback-Abschluss konnte nicht gestartet werden",
            error,
        )
    })?;
    for item in &request.results {
        let result=sqlx::query("UPDATE zero_trust_agent_rollout_target SET status=$1,deployment_status=$1,rollback_status=CASE WHEN $1='rolled_back' THEN 'completed' ELSE 'failed' END,observed_agent_version=$2,result_summary=$3,rollback_completed_at=(CURRENT_TIMESTAMP)::text,completed_at=(CURRENT_TIMESTAMP)::text,updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$4 AND rollout_id=$5 AND id=$6 AND status='rollback_required'")
            .bind(&item.status).bind(item.observed_version.trim()).bind(item.summary.trim()).bind(tenant_id).bind(rollout_id).bind(item.target_id).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("PostgreSQL-Rollback-Ergebnis konnte nicht gespeichert werden",error))?;
        if result.rows_affected() != 1 {
            return Err(concurrent_change());
        }
        insert_event_postgres(
            &mut tx,
            RolloutEventInput {
                tenant_id,
                rollout_id,
                ring_id: None,
                target_id: Some(item.target_id),
                event_type: "rollback_result_recorded",
                from_status: "rollback_required",
                to_status: &item.status,
                actor_id,
                summary: "Externes Rollback-Ergebnis dokumentiert",
                detail: json!({"observed_version":item.observed_version}),
            },
        )
        .await?;
    }
    finalize_rollback_postgres(&mut tx, tenant_id, rollout_id, actor_id).await?;
    tx.commit().await.map_err(|error| {
        AgentRolloutError::database(
            "PostgreSQL-Rollback-Abschluss konnte nicht bestaetigt werden",
            error,
        )
    })?;
    Ok(())
}

async fn finalize_rollback_sqlite(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    tenant_id: i64,
    rollout_id: i64,
    actor_id: i64,
) -> AgentRolloutResult<()> {
    let remaining:i64=sqlx::query_scalar("SELECT COUNT(*) FROM zero_trust_agent_rollout_target WHERE tenant_id=?1 AND rollout_id=?2 AND status='rollback_required'").bind(tenant_id).bind(rollout_id).fetch_one(&mut **tx).await.map_err(|error|AgentRolloutError::database("SQLite-offene Rollback-Ziele konnten nicht geprueft werden",error))?;
    let failed:i64=sqlx::query_scalar("SELECT COUNT(*) FROM zero_trust_agent_rollout_target WHERE tenant_id=?1 AND rollout_id=?2 AND rollback_status='failed'").bind(tenant_id).bind(rollout_id).fetch_one(&mut **tx).await.map_err(|error|AgentRolloutError::database("SQLite-fehlgeschlagene Rollbacks konnten nicht geprueft werden",error))?;
    if remaining == 0 {
        let (rollout_status, rollback_status) = if failed == 0 {
            ("rolled_back", "completed")
        } else {
            ("rollback_required", "failed")
        };
        sqlx::query("UPDATE zero_trust_agent_rollout SET status=?1,rollback_status=?2,active_ring_name=NULL,completed_at=CASE WHEN ?1='rolled_back' THEN CURRENT_TIMESTAMP ELSE completed_at END,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?3 AND id=?4 AND status='rollback_required'").bind(rollout_status).bind(rollback_status).bind(tenant_id).bind(rollout_id).execute(&mut **tx).await.map_err(|error|AgentRolloutError::database("SQLite-Rollback-Gesamtstatus konnte nicht gespeichert werden",error))?;
        if failed == 0 {
            sqlx::query("UPDATE zero_trust_agent_rollout_ring SET status='rolled_back',completed_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?1 AND rollout_id=?2 AND status='rollback_required'").bind(tenant_id).bind(rollout_id).execute(&mut **tx).await.map_err(|error|AgentRolloutError::database("SQLite-Rollback-Ringstatus konnte nicht gespeichert werden",error))?;
        }
        insert_event_sqlite(
            tx,
            RolloutEventInput {
                tenant_id,
                rollout_id,
                ring_id: None,
                target_id: None,
                event_type: "rollback_completed",
                from_status: "rollback_required",
                to_status: rollout_status,
                actor_id,
                summary: if failed == 0 {
                    "Rollback vollstaendig dokumentiert"
                } else {
                    "Rollback mit Fehlern dokumentiert"
                },
                detail: json!({"failed_targets":failed}),
            },
        )
        .await?;
    } else {
        sqlx::query("UPDATE zero_trust_agent_rollout SET rollback_status='in_progress',updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?1 AND id=?2").bind(tenant_id).bind(rollout_id).execute(&mut **tx).await.map_err(|error|AgentRolloutError::database("SQLite-Rollback-Fortschritt konnte nicht gespeichert werden",error))?;
    }
    Ok(())
}

async fn finalize_rollback_postgres(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    rollout_id: i64,
    actor_id: i64,
) -> AgentRolloutResult<()> {
    let remaining:i64=sqlx::query_scalar("SELECT COUNT(*)::bigint FROM zero_trust_agent_rollout_target WHERE tenant_id=$1 AND rollout_id=$2 AND status='rollback_required'").bind(tenant_id).bind(rollout_id).fetch_one(&mut **tx).await.map_err(|error|AgentRolloutError::database("PostgreSQL-offene Rollback-Ziele konnten nicht geprueft werden",error))?;
    let failed:i64=sqlx::query_scalar("SELECT COUNT(*)::bigint FROM zero_trust_agent_rollout_target WHERE tenant_id=$1 AND rollout_id=$2 AND rollback_status='failed'").bind(tenant_id).bind(rollout_id).fetch_one(&mut **tx).await.map_err(|error|AgentRolloutError::database("PostgreSQL-fehlgeschlagene Rollbacks konnten nicht geprueft werden",error))?;
    if remaining == 0 {
        let (rollout_status, rollback_status) = if failed == 0 {
            ("rolled_back", "completed")
        } else {
            ("rollback_required", "failed")
        };
        sqlx::query("UPDATE zero_trust_agent_rollout SET status=$1,rollback_status=$2,active_ring_name=NULL,completed_at=CASE WHEN $1='rolled_back' THEN (CURRENT_TIMESTAMP)::text ELSE completed_at END,updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$3 AND id=$4 AND status='rollback_required'").bind(rollout_status).bind(rollback_status).bind(tenant_id).bind(rollout_id).execute(&mut **tx).await.map_err(|error|AgentRolloutError::database("PostgreSQL-Rollback-Gesamtstatus konnte nicht gespeichert werden",error))?;
        if failed == 0 {
            sqlx::query("UPDATE zero_trust_agent_rollout_ring SET status='rolled_back',completed_at=(CURRENT_TIMESTAMP)::text,updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$1 AND rollout_id=$2 AND status='rollback_required'").bind(tenant_id).bind(rollout_id).execute(&mut **tx).await.map_err(|error|AgentRolloutError::database("PostgreSQL-Rollback-Ringstatus konnte nicht gespeichert werden",error))?;
        }
        insert_event_postgres(
            tx,
            RolloutEventInput {
                tenant_id,
                rollout_id,
                ring_id: None,
                target_id: None,
                event_type: "rollback_completed",
                from_status: "rollback_required",
                to_status: rollout_status,
                actor_id,
                summary: if failed == 0 {
                    "Rollback vollstaendig dokumentiert"
                } else {
                    "Rollback mit Fehlern dokumentiert"
                },
                detail: json!({"failed_targets":failed}),
            },
        )
        .await?;
    } else {
        sqlx::query("UPDATE zero_trust_agent_rollout SET rollback_status='in_progress',updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$1 AND id=$2").bind(tenant_id).bind(rollout_id).execute(&mut **tx).await.map_err(|error|AgentRolloutError::database("PostgreSQL-Rollback-Fortschritt konnte nicht gespeichert werden",error))?;
    }
    Ok(())
}

async fn apply_preflight_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    rollout_id: i64,
    actor_id: i64,
    detail: &AgentRolloutDetail,
    evaluations: Vec<(AgentRolloutTarget, Vec<EvaluatedCheck>)>,
) -> AgentRolloutResult<()> {
    let mut tx = pool.begin().await.map_err(|error| {
        AgentRolloutError::database("SQLite-Preflight konnte nicht gestartet werden", error)
    })?;
    let mut passed_targets = 0_i64;
    for (target, checks) in &evaluations {
        let blocked = checks.iter().any(|check| check.status == "failed");
        let new_status = if blocked { "blocked" } else { "eligible" };
        ensure_target_transition(&target.status, new_status)?;
        for check in checks {
            sqlx::query("INSERT INTO zero_trust_agent_rollout_check (tenant_id,rollout_id,ring_id,target_id,phase,check_type,status,source,summary,safe_detail_json,actor_id) VALUES (?1,?2,?3,?4,'preflight',?5,?6,'computed',?7,?8,?9)")
                .bind(tenant_id).bind(rollout_id).bind(target.ring_id).bind(target.id).bind(check.key).bind(check.status).bind(&check.summary).bind(check.detail.to_string()).bind(actor_id)
                .execute(&mut *tx).await.map_err(|error| AgentRolloutError::database("SQLite-Preflight-Pruefung konnte nicht gespeichert werden", error))?;
        }
        let result = sqlx::query("UPDATE zero_trust_agent_rollout_target SET status=?1,eligibility_status=?1,preflight_status=?2,eligibility_reason=?3,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?4 AND rollout_id=?5 AND id=?6 AND status=?7")
            .bind(new_status).bind(if blocked { "failed" } else { "passed" })
            .bind(checks.iter().filter(|check| check.status == "failed").map(|check| check.summary.as_str()).collect::<Vec<_>>().join(" "))
            .bind(tenant_id).bind(rollout_id).bind(target.id).bind(&target.status).execute(&mut *tx).await
            .map_err(|error| AgentRolloutError::database("SQLite-Preflight-Zielstatus konnte nicht gespeichert werden", error))?;
        if result.rows_affected() != 1 {
            return Err(concurrent_change());
        }
        if !blocked {
            passed_targets += 1;
        }
    }
    update_ring_readiness_sqlite(&mut tx, tenant_id, rollout_id, detail, &evaluations).await?;
    insert_event_sqlite(&mut tx, RolloutEventInput { tenant_id,rollout_id,ring_id:None,target_id:None,event_type:"preflight_evaluated",from_status:&detail.rollout.status,to_status:&detail.rollout.status,actor_id,summary:"Preflight-Gates aus vorhandenen ISCY-Agentdaten ausgewertet",detail:json!({"targets":evaluations.len(),"passed_targets":passed_targets,"checks_per_target":18}) }).await?;
    tx.commit().await.map_err(|error| {
        AgentRolloutError::database("SQLite-Preflight konnte nicht bestaetigt werden", error)
    })?;
    Ok(())
}

async fn apply_preflight_postgres(
    pool: &PgPool,
    tenant_id: i64,
    rollout_id: i64,
    actor_id: i64,
    detail: &AgentRolloutDetail,
    evaluations: Vec<(AgentRolloutTarget, Vec<EvaluatedCheck>)>,
) -> AgentRolloutResult<()> {
    let mut tx = pool.begin().await.map_err(|error| {
        AgentRolloutError::database("PostgreSQL-Preflight konnte nicht gestartet werden", error)
    })?;
    let mut passed_targets = 0_i64;
    for (target, checks) in &evaluations {
        let blocked = checks.iter().any(|check| check.status == "failed");
        let new_status = if blocked { "blocked" } else { "eligible" };
        ensure_target_transition(&target.status, new_status)?;
        for check in checks {
            sqlx::query("INSERT INTO zero_trust_agent_rollout_check (tenant_id,rollout_id,ring_id,target_id,phase,check_type,status,source,summary,safe_detail_json,actor_id) VALUES ($1,$2,$3,$4,'preflight',$5,$6,'computed',$7,$8::jsonb,$9)")
                .bind(tenant_id).bind(rollout_id).bind(target.ring_id).bind(target.id).bind(check.key).bind(check.status).bind(&check.summary).bind(check.detail.to_string()).bind(actor_id)
                .execute(&mut *tx).await.map_err(|error| AgentRolloutError::database("PostgreSQL-Preflight-Pruefung konnte nicht gespeichert werden", error))?;
        }
        let result = sqlx::query("UPDATE zero_trust_agent_rollout_target SET status=$1,eligibility_status=$1,preflight_status=$2,eligibility_reason=$3,updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$4 AND rollout_id=$5 AND id=$6 AND status=$7")
            .bind(new_status).bind(if blocked { "failed" } else { "passed" })
            .bind(checks.iter().filter(|check| check.status == "failed").map(|check| check.summary.as_str()).collect::<Vec<_>>().join(" "))
            .bind(tenant_id).bind(rollout_id).bind(target.id).bind(&target.status).execute(&mut *tx).await
            .map_err(|error| AgentRolloutError::database("PostgreSQL-Preflight-Zielstatus konnte nicht gespeichert werden", error))?;
        if result.rows_affected() != 1 {
            return Err(concurrent_change());
        }
        if !blocked {
            passed_targets += 1;
        }
    }
    update_ring_readiness_postgres(&mut tx, tenant_id, rollout_id, detail, &evaluations).await?;
    insert_event_postgres(&mut tx, RolloutEventInput { tenant_id,rollout_id,ring_id:None,target_id:None,event_type:"preflight_evaluated",from_status:&detail.rollout.status,to_status:&detail.rollout.status,actor_id,summary:"Preflight-Gates aus vorhandenen ISCY-Agentdaten ausgewertet",detail:json!({"targets":evaluations.len(),"passed_targets":passed_targets,"checks_per_target":18}) }).await?;
    tx.commit().await.map_err(|error| {
        AgentRolloutError::database("PostgreSQL-Preflight konnte nicht bestaetigt werden", error)
    })?;
    Ok(())
}

async fn update_ring_readiness_sqlite(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    tenant_id: i64,
    rollout_id: i64,
    detail: &AgentRolloutDetail,
    evaluations: &[(AgentRolloutTarget, Vec<EvaluatedCheck>)],
) -> AgentRolloutResult<()> {
    for ring in &detail.rings {
        if ring.status == "not_applicable" {
            continue;
        }
        let ring_evaluations: Vec<_> = evaluations
            .iter()
            .filter(|(target, _)| target.ring_id == ring.id)
            .collect();
        if ring_evaluations.is_empty() {
            continue;
        }
        let ready = !ring_evaluations.is_empty()
            && ring_evaluations
                .iter()
                .all(|(_, checks)| !checks.iter().any(|check| check.status == "failed"));
        let desired = if ready { "ready" } else { "pending" };
        if ring.status != desired {
            ensure_ring_transition(&ring.status, desired)?;
            let result = sqlx::query("UPDATE zero_trust_agent_rollout_ring SET status=?1,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?2 AND rollout_id=?3 AND id=?4 AND status=?5")
                .bind(desired).bind(tenant_id).bind(rollout_id).bind(ring.id).bind(&ring.status).execute(&mut **tx).await
                .map_err(|error| AgentRolloutError::database("SQLite-Ring-Bereitschaft konnte nicht gespeichert werden", error))?;
            if result.rows_affected() != 1 {
                return Err(concurrent_change());
            }
        }
    }
    Ok(())
}

async fn update_ring_readiness_postgres(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    rollout_id: i64,
    detail: &AgentRolloutDetail,
    evaluations: &[(AgentRolloutTarget, Vec<EvaluatedCheck>)],
) -> AgentRolloutResult<()> {
    for ring in &detail.rings {
        if ring.status == "not_applicable" {
            continue;
        }
        let ring_evaluations: Vec<_> = evaluations
            .iter()
            .filter(|(target, _)| target.ring_id == ring.id)
            .collect();
        if ring_evaluations.is_empty() {
            continue;
        }
        let ready = !ring_evaluations.is_empty()
            && ring_evaluations
                .iter()
                .all(|(_, checks)| !checks.iter().any(|check| check.status == "failed"));
        let desired = if ready { "ready" } else { "pending" };
        if ring.status != desired {
            ensure_ring_transition(&ring.status, desired)?;
            let result = sqlx::query("UPDATE zero_trust_agent_rollout_ring SET status=$1,updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$2 AND rollout_id=$3 AND id=$4 AND status=$5")
                .bind(desired).bind(tenant_id).bind(rollout_id).bind(ring.id).bind(&ring.status).execute(&mut **tx).await
                .map_err(|error| AgentRolloutError::database("PostgreSQL-Ring-Bereitschaft konnte nicht gespeichert werden", error))?;
            if result.rows_affected() != 1 {
                return Err(concurrent_change());
            }
        }
    }
    Ok(())
}

fn validate_write_request(
    mut payload: AgentRolloutWriteRequest,
) -> AgentRolloutResult<AgentRolloutWriteRequest> {
    payload.name = payload.name.trim().to_string();
    payload.description = payload.description.trim().to_string();
    payload.target_agent_version = payload.target_agent_version.trim().to_string();
    payload.rollback_plan = payload.rollback_plan.trim().to_string();
    payload.artifact_id = payload.artifact_id.and_then(|value| {
        let value = value.trim().to_string();
        (!value.is_empty()).then_some(value)
    });
    payload.os_family_filter = payload.os_family_filter.trim().to_ascii_uppercase();
    payload.deployment_channel_filter = payload
        .deployment_channel_filter
        .trim()
        .to_ascii_lowercase();
    payload.signature_requirement = payload.signature_requirement.trim().to_ascii_lowercase();
    payload.certificate_requirement = payload.certificate_requirement.trim().to_ascii_lowercase();
    if payload.name.is_empty() || payload.name.len() > 160 {
        return Err(invalid_input(
            "Der Rollout-Name muss 1 bis 160 Zeichen enthalten.",
        ));
    }
    if payload.target_agent_version.is_empty() || payload.target_agent_version.len() > 64 {
        return Err(invalid_input(
            "Die Zielversion muss 1 bis 64 Zeichen enthalten.",
        ));
    }
    if !valid_version(&payload.target_agent_version) {
        return Err(invalid_input(
            "Die Zielversion enthaelt unzulaessige Zeichen.",
        ));
    }
    validate_rollback_plan(&payload.rollback_plan)?;
    if payload.description.len() > 10_000 {
        return Err(invalid_input("Die Beschreibung ist zu lang."));
    }
    validate_os_filter(&payload.os_family_filter)?;
    validate_deployment_channel(&payload.deployment_channel_filter)?;
    validate_range(
        "Der minimale Zero-Trust-Score",
        payload.minimum_zero_trust_score,
        0,
        100,
    )?;
    validate_range(
        "Das Heartbeat-Zeitfenster",
        payload.heartbeat_freshness_minutes,
        1,
        525_600,
    )?;
    validate_range(
        "Die Zahl maximaler kritischer Findings",
        payload.maximum_critical_findings,
        0,
        100_000,
    )?;
    validate_range("Die Erfolgsquote", payload.minimum_success_percent, 1, 100)?;
    validate_range(
        "Die Beobachtungszeit",
        payload.observation_minutes,
        0,
        10_080,
    )?;
    validate_range(
        "Die Zahl tolerierter Fehler",
        payload.max_failed_targets,
        0,
        100_000,
    )?;
    validate_member(
        "Signaturanforderung",
        &payload.signature_requirement,
        SIGNATURE_REQUIREMENTS,
    )?;
    validate_member(
        "Zertifikatsanforderung",
        &payload.certificate_requirement,
        CERTIFICATE_REQUIREMENTS,
    )?;
    if payload.ring_overrides.len() > CANONICAL_ROLLOUT_RINGS.len() {
        return Err(invalid_input(
            "Es sind nur die fuenf kanonischen Rollout-Ringe erlaubt.",
        ));
    }
    let mut seen = Vec::new();
    for override_config in &mut payload.ring_overrides {
        override_config.ring_name = override_config.ring_name.trim().to_ascii_lowercase();
        validate_ring_name(&override_config.ring_name)?;
        if seen.contains(&override_config.ring_name) {
            return Err(invalid_input(
                "Ein Rollout-Ring wurde mehrfach konfiguriert.",
            ));
        }
        seen.push(override_config.ring_name.clone());
        validate_range(
            "Die Ring-Erfolgsquote",
            override_config.minimum_success_percent,
            1,
            100,
        )?;
        validate_range(
            "Die Ring-Beobachtungszeit",
            override_config.observation_minutes,
            0,
            10_080,
        )?;
        validate_range(
            "Die Ring-Fehlertoleranz",
            override_config.max_failed_targets,
            0,
            100_000,
        )?;
        validate_range(
            "Die minimale Ring-Zielzahl",
            override_config.minimum_target_count,
            1,
            100_000,
        )?;
    }
    for ring_name in &mut payload.not_applicable_rings {
        *ring_name = ring_name.trim().to_ascii_lowercase();
        validate_ring_name(ring_name)?;
    }
    payload.not_applicable_rings.sort();
    payload.not_applicable_rings.dedup();
    if payload.not_applicable_rings.len() == CANONICAL_ROLLOUT_RINGS.len() {
        return Err(invalid_input(
            "Mindestens ein Rollout-Ring muss anwendbar bleiben.",
        ));
    }
    Ok(payload)
}

fn validate_os_filter(value: &str) -> AgentRolloutResult<()> {
    let normalized = value.trim().to_ascii_uppercase();
    if normalized.is_empty() || matches!(normalized.as_str(), "WINDOWS" | "LINUX" | "MACOS") {
        return Ok(());
    }
    Err(invalid_input(
        "Der OS-Filter muss WINDOWS, LINUX, MACOS oder leer sein.",
    ))
}

fn validate_deployment_channel(value: &str) -> AgentRolloutResult<()> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty()
        || matches!(
            normalized.as_str(),
            "manual" | "systemd" | "nixos" | "intune" | "jamf" | "other"
        )
    {
        return Ok(());
    }
    Err(invalid_input(
        "Der Deployment-Kanal ist nicht unterstuetzt.",
    ))
}

fn valid_version(value: &str) -> bool {
    value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+'))
}

fn validate_rollback_plan(value: &str) -> AgentRolloutResult<()> {
    if value.is_empty() || value.len() > 10_000 {
        return Err(invalid_input(
            "Der Rollback-Plan muss 1 bis 10000 Zeichen enthalten.",
        ));
    }
    let lower = value.to_ascii_lowercase();
    let executable_markers = [
        "```",
        "://",
        "curl ",
        "wget ",
        "sudo ",
        "powershell",
        "cmd.exe",
        "bash -",
        "sh -",
        "&&",
        "||",
        ";",
    ];
    if value
        .chars()
        .any(|value| value.is_control() && !matches!(value, '\n' | '\r' | '\t'))
        || executable_markers
            .iter()
            .any(|marker| lower.contains(marker))
    {
        return Err(invalid_input(
            "Der Rollback-Plan darf keine URLs, Skripte oder ausfuehrbaren Befehle enthalten.",
        ));
    }
    Ok(())
}

fn safe_operator_text(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    !value
        .chars()
        .any(|value| value.is_control() && !matches!(value, '\n' | '\r' | '\t'))
        && ![
            "authorization:",
            "bearer ",
            "token=",
            "password=",
            "://",
            "../",
            "/home/",
        ]
        .iter()
        .any(|marker| lower.contains(marker))
}

fn validate_ring_name(value: &str) -> AgentRolloutResult<()> {
    if CANONICAL_ROLLOUT_RINGS
        .iter()
        .any(|(name, _)| *name == value)
    {
        Ok(())
    } else {
        Err(invalid_input("Unbekannter Rollout-Ring."))
    }
}

fn validate_member(label: &str, value: &str, allowed: &[&str]) -> AgentRolloutResult<()> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(invalid_input(format!("{label} ist nicht unterstuetzt.")))
    }
}

fn validate_range(label: &str, value: i64, minimum: i64, maximum: i64) -> AgentRolloutResult<()> {
    if (minimum..=maximum).contains(&value) {
        Ok(())
    } else {
        Err(invalid_input(format!(
            "{label} muss zwischen {minimum} und {maximum} liegen."
        )))
    }
}

fn invalid_input(message: impl Into<String>) -> AgentRolloutError {
    AgentRolloutError::new(AgentRolloutErrorKind::InvalidInput, message)
}

fn foreign_reference(message: impl Into<String>) -> AgentRolloutError {
    AgentRolloutError::new(AgentRolloutErrorKind::ForeignReference, message)
}

fn invalid_transition(message: impl Into<String>) -> AgentRolloutError {
    AgentRolloutError::new(AgentRolloutErrorKind::InvalidTransition, message)
}

fn concurrent_change() -> AgentRolloutError {
    AgentRolloutError::new(
        AgentRolloutErrorKind::ConcurrentChange,
        "Der Rollout wurde parallel geaendert. Bitte laden Sie den aktuellen Stand neu.",
    )
}

fn gate_blocked(message: impl Into<String>) -> AgentRolloutError {
    AgentRolloutError::new(AgentRolloutErrorKind::GateBlocked, message)
}

pub fn rollout_transition_allowed(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        ("draft", "ready")
            | ("draft", "aborted")
            | ("ready", "draft")
            | ("ready", "active")
            | ("ready", "aborted")
            | ("active", "paused")
            | ("active", "completed")
            | ("active", "aborted")
            | ("active", "rollback_required")
            | ("paused", "active")
            | ("paused", "aborted")
            | ("paused", "rollback_required")
            | ("rollback_required", "rolled_back")
            | ("rollback_required", "aborted")
    ) || from == to
}

pub fn ring_transition_allowed(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        ("pending", "ready")
            | ("pending", "not_applicable")
            | ("ready", "pending")
            | ("ready", "active")
            | ("active", "observing")
            | ("active", "failed")
            | ("active", "rollback_required")
            | ("observing", "passed")
            | ("observing", "failed")
            | ("observing", "rollback_required")
            | ("passed", "rollback_required")
            | ("failed", "rollback_required")
            | ("rollback_required", "rolled_back")
    ) || from == to
}

pub fn target_transition_allowed(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        ("pending", "eligible")
            | ("pending", "blocked")
            | ("pending", "excluded")
            | ("eligible", "scheduled")
            | ("eligible", "blocked")
            | ("eligible", "excluded")
            | ("blocked", "eligible")
            | ("blocked", "excluded")
            | ("scheduled", "in_progress")
            | ("scheduled", "failed")
            | ("scheduled", "rollback_required")
            | ("in_progress", "succeeded")
            | ("in_progress", "failed")
            | ("in_progress", "rollback_required")
            | ("succeeded", "rollback_required")
            | ("failed", "rollback_required")
            | ("rollback_required", "rolled_back")
            | ("rollback_required", "failed")
    ) || from == to
}

fn ensure_rollout_transition(from: &str, to: &str) -> AgentRolloutResult<()> {
    validate_member("Rollout-Status", from, ROLLOUT_STATUSES)?;
    validate_member("Rollout-Zielstatus", to, ROLLOUT_STATUSES)?;
    if rollout_transition_allowed(from, to) {
        Ok(())
    } else {
        Err(invalid_transition(
            "Dieser Rollout-Statuswechsel ist nicht erlaubt.",
        ))
    }
}

fn ensure_ring_transition(from: &str, to: &str) -> AgentRolloutResult<()> {
    validate_member("Ring-Status", from, RING_STATUSES)?;
    validate_member("Ring-Zielstatus", to, RING_STATUSES)?;
    if ring_transition_allowed(from, to) {
        Ok(())
    } else {
        Err(invalid_transition(
            "Dieser Ring-Statuswechsel ist nicht erlaubt.",
        ))
    }
}

fn ensure_target_transition(from: &str, to: &str) -> AgentRolloutResult<()> {
    validate_member("Ziel-Status", from, TARGET_STATUSES)?;
    validate_member("Ziel-Zielstatus", to, TARGET_STATUSES)?;
    if target_transition_allowed(from, to) {
        Ok(())
    } else {
        Err(invalid_transition(
            "Dieser Ziel-Statuswechsel ist nicht erlaubt.",
        ))
    }
}

fn ring_configuration(
    payload: &AgentRolloutWriteRequest,
    ring_name: &str,
) -> (i64, i64, i64, i64, &'static str) {
    let override_config = payload
        .ring_overrides
        .iter()
        .find(|config| config.ring_name == ring_name);
    let success = override_config
        .map(|config| config.minimum_success_percent)
        .unwrap_or(payload.minimum_success_percent);
    let observation = override_config
        .map(|config| config.observation_minutes)
        .unwrap_or(payload.observation_minutes);
    let failed = override_config
        .map(|config| config.max_failed_targets)
        .unwrap_or(payload.max_failed_targets);
    let minimum_targets = override_config
        .map(|config| config.minimum_target_count)
        .unwrap_or(1);
    let status = if payload
        .not_applicable_rings
        .iter()
        .any(|value| value == ring_name)
    {
        "not_applicable"
    } else {
        "pending"
    };
    (success, observation, failed, minimum_targets, status)
}

async fn create_rollout_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    actor_id: i64,
    payload: &AgentRolloutWriteRequest,
) -> AgentRolloutResult<i64> {
    let mut tx = pool.begin().await.map_err(|error| {
        AgentRolloutError::database(
            "SQLite-Rollout-Erstellung konnte nicht gestartet werden",
            error,
        )
    })?;
    let row = sqlx::query(
        r#"INSERT INTO zero_trust_agent_rollout (
            tenant_id,name,description,target_agent_version,rollback_plan,artifact_id,policy_profile_id,owner_id,
            os_family_filter,deployment_channel_filter,minimum_zero_trust_score,heartbeat_freshness_minutes,
            maximum_critical_findings,require_mtls,require_pki_ready,require_verified_artifact_checksum,
            signature_policy,certificate_requirement,minimum_success_percent,
            observation_minutes,max_failed_targets,created_by_id
        ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22)
        RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(&payload.name)
    .bind(&payload.description)
    .bind(&payload.target_agent_version)
    .bind(&payload.rollback_plan)
    .bind(payload.artifact_id.as_deref())
    .bind(payload.policy_profile_id)
    .bind(payload.owner_id)
    .bind(&payload.os_family_filter)
    .bind(&payload.deployment_channel_filter)
    .bind(payload.minimum_zero_trust_score)
    .bind(payload.heartbeat_freshness_minutes)
    .bind(payload.maximum_critical_findings)
    .bind(payload.certificate_requirement == "mtls_bound_required")
    .bind(payload.certificate_requirement != "not_required")
    .bind(payload.require_verified_artifact_checksum)
    .bind(&payload.signature_requirement)
    .bind(&payload.certificate_requirement)
    .bind(payload.minimum_success_percent)
    .bind(payload.observation_minutes)
    .bind(payload.max_failed_targets)
    .bind(actor_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| {
        AgentRolloutError::database("SQLite-Rollout konnte nicht erstellt werden", error)
    })?;
    let rollout_id: i64 = row
        .try_get("id")
        .map_err(|error| AgentRolloutError::database("SQLite-Rollout-ID ist unlesbar", error))?;
    insert_rings_sqlite(&mut tx, tenant_id, rollout_id, payload).await?;
    insert_event_sqlite(
        &mut tx,
        RolloutEventInput {
            tenant_id,
            rollout_id,
            ring_id: None,
            target_id: None,
            event_type: "rollout_created",
            from_status: "",
            to_status: "draft",
            actor_id,
            summary: "Rollout mit fuenf kontrollierten Ringen erstellt",
            detail: json!({}),
        },
    )
    .await?;
    tx.commit().await.map_err(|error| {
        AgentRolloutError::database(
            "SQLite-Rollout-Erstellung konnte nicht bestaetigt werden",
            error,
        )
    })?;
    Ok(rollout_id)
}

async fn create_rollout_postgres(
    pool: &PgPool,
    tenant_id: i64,
    actor_id: i64,
    payload: &AgentRolloutWriteRequest,
) -> AgentRolloutResult<i64> {
    let mut tx = pool.begin().await.map_err(|error| {
        AgentRolloutError::database(
            "PostgreSQL-Rollout-Erstellung konnte nicht gestartet werden",
            error,
        )
    })?;
    let row = sqlx::query(
        r#"INSERT INTO zero_trust_agent_rollout (
            tenant_id,name,description,target_agent_version,rollback_plan,artifact_id,policy_profile_id,owner_id,
            os_family_filter,deployment_channel_filter,minimum_zero_trust_score,heartbeat_freshness_minutes,
            maximum_critical_findings,require_mtls,require_pki_ready,require_verified_artifact_checksum,
            signature_policy,certificate_requirement,minimum_success_percent,
            observation_minutes,max_failed_targets,created_by_id
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
        RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(&payload.name)
    .bind(&payload.description)
    .bind(&payload.target_agent_version)
    .bind(&payload.rollback_plan)
    .bind(payload.artifact_id.as_deref())
    .bind(payload.policy_profile_id)
    .bind(payload.owner_id)
    .bind(&payload.os_family_filter)
    .bind(&payload.deployment_channel_filter)
    .bind(payload.minimum_zero_trust_score)
    .bind(payload.heartbeat_freshness_minutes)
    .bind(payload.maximum_critical_findings)
    .bind(payload.certificate_requirement == "mtls_bound_required")
    .bind(payload.certificate_requirement != "not_required")
    .bind(payload.require_verified_artifact_checksum)
    .bind(&payload.signature_requirement)
    .bind(&payload.certificate_requirement)
    .bind(payload.minimum_success_percent)
    .bind(payload.observation_minutes)
    .bind(payload.max_failed_targets)
    .bind(actor_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| {
        AgentRolloutError::database("PostgreSQL-Rollout konnte nicht erstellt werden", error)
    })?;
    let rollout_id: i64 = row.try_get("id").map_err(|error| {
        AgentRolloutError::database("PostgreSQL-Rollout-ID ist unlesbar", error)
    })?;
    insert_rings_postgres(&mut tx, tenant_id, rollout_id, payload).await?;
    insert_event_postgres(
        &mut tx,
        RolloutEventInput {
            tenant_id,
            rollout_id,
            ring_id: None,
            target_id: None,
            event_type: "rollout_created",
            from_status: "",
            to_status: "draft",
            actor_id,
            summary: "Rollout mit fuenf kontrollierten Ringen erstellt",
            detail: json!({}),
        },
    )
    .await?;
    tx.commit().await.map_err(|error| {
        AgentRolloutError::database(
            "PostgreSQL-Rollout-Erstellung konnte nicht bestaetigt werden",
            error,
        )
    })?;
    Ok(rollout_id)
}

async fn insert_rings_sqlite(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    tenant_id: i64,
    rollout_id: i64,
    payload: &AgentRolloutWriteRequest,
) -> AgentRolloutResult<()> {
    for (ring_name, sequence_number) in CANONICAL_ROLLOUT_RINGS {
        let (success, observation, failed, minimum_targets, status) =
            ring_configuration(payload, ring_name);
        sqlx::query("INSERT INTO zero_trust_agent_rollout_ring (tenant_id,rollout_id,ring_name,sequence_number,status,minimum_success_percent,observation_minutes,max_failed_targets,minimum_target_count) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)")
            .bind(tenant_id).bind(rollout_id).bind(ring_name).bind(sequence_number).bind(status).bind(success).bind(observation).bind(failed).bind(minimum_targets)
            .execute(&mut **tx).await.map_err(|error| AgentRolloutError::database("SQLite-Rollout-Ringe konnten nicht erstellt werden", error))?;
    }
    Ok(())
}

async fn insert_rings_postgres(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    rollout_id: i64,
    payload: &AgentRolloutWriteRequest,
) -> AgentRolloutResult<()> {
    for (ring_name, sequence_number) in CANONICAL_ROLLOUT_RINGS {
        let (success, observation, failed, minimum_targets, status) =
            ring_configuration(payload, ring_name);
        sqlx::query("INSERT INTO zero_trust_agent_rollout_ring (tenant_id,rollout_id,ring_name,sequence_number,status,minimum_success_percent,observation_minutes,max_failed_targets,minimum_target_count) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind(tenant_id).bind(rollout_id).bind(ring_name).bind(sequence_number).bind(status).bind(success).bind(observation).bind(failed).bind(minimum_targets)
            .execute(&mut **tx).await.map_err(|error| AgentRolloutError::database("PostgreSQL-Rollout-Ringe konnten nicht erstellt werden", error))?;
    }
    Ok(())
}

async fn replace_ring_configuration_sqlite(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    tenant_id: i64,
    rollout_id: i64,
    payload: &AgentRolloutWriteRequest,
) -> AgentRolloutResult<()> {
    for (ring_name, _) in CANONICAL_ROLLOUT_RINGS {
        let (success, observation, failed, minimum_targets, status) =
            ring_configuration(payload, ring_name);
        let result = sqlx::query("UPDATE zero_trust_agent_rollout_ring SET status=?1,minimum_success_percent=?2,observation_minutes=?3,max_failed_targets=?4,minimum_target_count=?5,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?6 AND rollout_id=?7 AND ring_name=?8 AND status IN ('pending','not_applicable')")
            .bind(status).bind(success).bind(observation).bind(failed).bind(minimum_targets).bind(tenant_id).bind(rollout_id).bind(ring_name)
            .execute(&mut **tx).await.map_err(|error| AgentRolloutError::database("SQLite-Ringkonfiguration konnte nicht aktualisiert werden", error))?;
        if result.rows_affected() != 1 {
            return Err(concurrent_change());
        }
    }
    Ok(())
}

async fn replace_ring_configuration_postgres(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    rollout_id: i64,
    payload: &AgentRolloutWriteRequest,
) -> AgentRolloutResult<()> {
    for (ring_name, _) in CANONICAL_ROLLOUT_RINGS {
        let (success, observation, failed, minimum_targets, status) =
            ring_configuration(payload, ring_name);
        let result = sqlx::query("UPDATE zero_trust_agent_rollout_ring SET status=$1,minimum_success_percent=$2,observation_minutes=$3,max_failed_targets=$4,minimum_target_count=$5,updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$6 AND rollout_id=$7 AND ring_name=$8 AND status IN ('pending','not_applicable')")
            .bind(status).bind(success).bind(observation).bind(failed).bind(minimum_targets).bind(tenant_id).bind(rollout_id).bind(ring_name)
            .execute(&mut **tx).await.map_err(|error| AgentRolloutError::database("PostgreSQL-Ringkonfiguration konnte nicht aktualisiert werden", error))?;
        if result.rows_affected() != 1 {
            return Err(concurrent_change());
        }
    }
    Ok(())
}

struct RolloutEventInput<'a> {
    tenant_id: i64,
    rollout_id: i64,
    ring_id: Option<i64>,
    target_id: Option<i64>,
    event_type: &'a str,
    from_status: &'a str,
    to_status: &'a str,
    actor_id: i64,
    summary: &'a str,
    detail: Value,
}

async fn insert_event_sqlite(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    event: RolloutEventInput<'_>,
) -> AgentRolloutResult<()> {
    sqlx::query(
        "INSERT INTO zero_trust_agent_rollout_event (tenant_id,rollout_id,ring_id,target_id,device_id,event_type,from_status,to_status,actor_id,summary,safe_detail_json) VALUES (?1,?2,?3,?4,(SELECT device_id FROM zero_trust_agent_rollout_target WHERE tenant_id=?1 AND rollout_id=?2 AND id=?4),?5,?6,?7,?8,?9,?10)",
    )
    .bind(event.tenant_id).bind(event.rollout_id).bind(event.ring_id).bind(event.target_id).bind(event.event_type)
    .bind(event.from_status).bind(event.to_status).bind(event.actor_id).bind(event.summary).bind(event.detail.to_string())
    .execute(&mut **tx).await
    .map_err(|error| AgentRolloutError::database("SQLite-Rollout-Ereignis konnte nicht gespeichert werden", error))?;
    Ok(())
}

async fn insert_event_postgres(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    event: RolloutEventInput<'_>,
) -> AgentRolloutResult<()> {
    sqlx::query(
        "INSERT INTO zero_trust_agent_rollout_event (tenant_id,rollout_id,ring_id,target_id,device_id,event_type,from_status,to_status,actor_id,summary,safe_detail_json) VALUES ($1,$2,$3,$4,(SELECT device_id FROM zero_trust_agent_rollout_target WHERE tenant_id=$1 AND rollout_id=$2 AND id=$4),$5,$6,$7,$8,$9,$10::jsonb)",
    )
    .bind(event.tenant_id).bind(event.rollout_id).bind(event.ring_id).bind(event.target_id).bind(event.event_type)
    .bind(event.from_status).bind(event.to_status).bind(event.actor_id).bind(event.summary).bind(event.detail.to_string())
    .execute(&mut **tx).await
    .map_err(|error| AgentRolloutError::database("PostgreSQL-Rollout-Ereignis konnte nicht gespeichert werden", error))?;
    Ok(())
}

fn rollout_from_sqlite_row(row: SqliteRow) -> AgentRolloutResult<AgentRollout> {
    Ok(AgentRollout {
        id: get_sqlite(&row, "id")?,
        tenant_id: get_sqlite(&row, "tenant_id")?,
        name: get_sqlite(&row, "name")?,
        description: get_sqlite(&row, "description")?,
        target_agent_version: get_sqlite(&row, "target_agent_version")?,
        rollback_plan: get_sqlite(&row, "rollback_plan")?,
        artifact_id: get_sqlite(&row, "artifact_id")?,
        policy_profile_id: get_sqlite(&row, "policy_profile_id")?,
        owner_id: get_sqlite(&row, "owner_id")?,
        status: get_sqlite(&row, "status")?,
        active_ring_name: get_sqlite(&row, "active_ring_name")?,
        os_family_filter: get_sqlite(&row, "os_family_filter")?,
        deployment_channel_filter: get_sqlite(&row, "deployment_channel_filter")?,
        minimum_zero_trust_score: get_sqlite(&row, "minimum_zero_trust_score")?,
        heartbeat_freshness_minutes: get_sqlite(&row, "heartbeat_freshness_minutes")?,
        maximum_critical_findings: get_sqlite(&row, "maximum_critical_findings")?,
        require_verified_artifact_checksum: get_sqlite(&row, "require_verified_artifact_checksum")?,
        signature_requirement: get_sqlite(&row, "signature_policy")?,
        certificate_requirement: get_sqlite(&row, "certificate_requirement")?,
        minimum_success_percent: get_sqlite(&row, "minimum_success_percent")?,
        observation_minutes: get_sqlite(&row, "observation_minutes")?,
        max_failed_targets: get_sqlite(&row, "max_failed_targets")?,
        rollback_status: get_sqlite(&row, "rollback_status")?,
        rollback_reason: get_sqlite(&row, "rollback_reason")?,
        created_by_id: get_sqlite(&row, "created_by_id")?,
        approved_by_id: get_sqlite(&row, "approved_by_id")?,
        approved_at: get_sqlite(&row, "approved_at")?,
        paused_at: get_sqlite(&row, "paused_at")?,
        completed_at: get_sqlite(&row, "completed_at")?,
        created_at: get_sqlite(&row, "created_at")?,
        updated_at: get_sqlite(&row, "updated_at")?,
    })
}

fn rollout_from_postgres_row(row: PgRow) -> AgentRolloutResult<AgentRollout> {
    Ok(AgentRollout {
        id: get_postgres(&row, "id")?,
        tenant_id: get_postgres(&row, "tenant_id")?,
        name: get_postgres(&row, "name")?,
        description: get_postgres(&row, "description")?,
        target_agent_version: get_postgres(&row, "target_agent_version")?,
        rollback_plan: get_postgres(&row, "rollback_plan")?,
        artifact_id: get_postgres(&row, "artifact_id")?,
        policy_profile_id: get_postgres(&row, "policy_profile_id")?,
        owner_id: get_postgres(&row, "owner_id")?,
        status: get_postgres(&row, "status")?,
        active_ring_name: get_postgres(&row, "active_ring_name")?,
        os_family_filter: get_postgres(&row, "os_family_filter")?,
        deployment_channel_filter: get_postgres(&row, "deployment_channel_filter")?,
        minimum_zero_trust_score: get_postgres_integer(&row, "minimum_zero_trust_score")?,
        heartbeat_freshness_minutes: get_postgres_integer(&row, "heartbeat_freshness_minutes")?,
        maximum_critical_findings: get_postgres_integer(&row, "maximum_critical_findings")?,
        require_verified_artifact_checksum: get_postgres(
            &row,
            "require_verified_artifact_checksum",
        )?,
        signature_requirement: get_postgres(&row, "signature_policy")?,
        certificate_requirement: get_postgres(&row, "certificate_requirement")?,
        minimum_success_percent: get_postgres_integer(&row, "minimum_success_percent")?,
        observation_minutes: get_postgres_integer(&row, "observation_minutes")?,
        max_failed_targets: get_postgres_integer(&row, "max_failed_targets")?,
        rollback_status: get_postgres(&row, "rollback_status")?,
        rollback_reason: get_postgres(&row, "rollback_reason")?,
        created_by_id: get_postgres(&row, "created_by_id")?,
        approved_by_id: get_postgres(&row, "approved_by_id")?,
        approved_at: get_postgres(&row, "approved_at")?,
        paused_at: get_postgres(&row, "paused_at")?,
        completed_at: get_postgres(&row, "completed_at")?,
        created_at: get_postgres(&row, "created_at")?,
        updated_at: get_postgres(&row, "updated_at")?,
    })
}

fn get_sqlite<T>(row: &SqliteRow, column: &'static str) -> AgentRolloutResult<T>
where
    T: for<'r> sqlx::Decode<'r, sqlx::Sqlite> + sqlx::Type<sqlx::Sqlite>,
{
    row.try_get(column).map_err(|error| {
        AgentRolloutError::database("SQLite-Rollout-Datensatz ist unlesbar", error)
    })
}

fn get_postgres<T>(row: &PgRow, column: &'static str) -> AgentRolloutResult<T>
where
    T: for<'r> sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    row.try_get(column).map_err(|error| {
        AgentRolloutError::database("PostgreSQL-Rollout-Datensatz ist unlesbar", error)
    })
}

fn widen_postgres_integer(value: i32) -> i64 {
    i64::from(value)
}

fn get_postgres_integer(row: &PgRow, column: &'static str) -> AgentRolloutResult<i64> {
    get_postgres::<i32>(row, column).map(widen_postgres_integer)
}

const RING_SELECT: &str = r#"
SELECT r.*,
       COUNT(t.id) AS target_count,
       COALESCE(SUM(CASE WHEN t.status='succeeded' THEN 1 ELSE 0 END),0) AS succeeded_count,
       COALESCE(SUM(CASE WHEN t.status='failed' THEN 1 ELSE 0 END),0) AS failed_count
FROM zero_trust_agent_rollout_ring r
LEFT JOIN zero_trust_agent_rollout_target t
  ON t.tenant_id=r.tenant_id AND t.rollout_id=r.rollout_id AND t.ring_id=r.id
WHERE r.tenant_id={tenant} AND r.rollout_id={rollout}
GROUP BY r.id
ORDER BY r.sequence_number
"#;

async fn list_rings_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    rollout_id: i64,
) -> AgentRolloutResult<Vec<AgentRolloutRing>> {
    let sql = RING_SELECT
        .replace("{tenant}", "?1")
        .replace("{rollout}", "?2");
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(rollout_id)
        .fetch_all(pool)
        .await
        .map_err(|error| {
            AgentRolloutError::database("SQLite-Rollout-Ringe konnten nicht gelesen werden", error)
        })?;
    rows.into_iter().map(ring_from_sqlite_row).collect()
}

async fn list_rings_postgres(
    pool: &PgPool,
    tenant_id: i64,
    rollout_id: i64,
) -> AgentRolloutResult<Vec<AgentRolloutRing>> {
    let sql = RING_SELECT
        .replace("{tenant}", "$1")
        .replace("{rollout}", "$2");
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(rollout_id)
        .fetch_all(pool)
        .await
        .map_err(|error| {
            AgentRolloutError::database(
                "PostgreSQL-Rollout-Ringe konnten nicht gelesen werden",
                error,
            )
        })?;
    rows.into_iter().map(ring_from_postgres_row).collect()
}

fn ring_from_sqlite_row(row: SqliteRow) -> AgentRolloutResult<AgentRolloutRing> {
    Ok(AgentRolloutRing {
        id: get_sqlite(&row, "id")?,
        rollout_id: get_sqlite(&row, "rollout_id")?,
        ring_name: get_sqlite(&row, "ring_name")?,
        sequence_number: get_sqlite(&row, "sequence_number")?,
        status: get_sqlite(&row, "status")?,
        minimum_success_percent: get_sqlite(&row, "minimum_success_percent")?,
        observation_minutes: get_sqlite(&row, "observation_minutes")?,
        max_failed_targets: get_sqlite(&row, "max_failed_targets")?,
        minimum_target_count: get_sqlite(&row, "minimum_target_count")?,
        started_at: get_sqlite(&row, "started_at")?,
        observation_started_at: get_sqlite(&row, "observation_started_at")?,
        evaluated_at: get_sqlite(&row, "evaluated_at")?,
        approved_by_id: get_sqlite(&row, "approved_by_id")?,
        approved_at: get_sqlite(&row, "approved_at")?,
        completed_at: get_sqlite(&row, "completed_at")?,
        failure_reason: get_sqlite(&row, "failure_reason")?,
        target_count: get_sqlite(&row, "target_count")?,
        succeeded_count: get_sqlite(&row, "succeeded_count")?,
        failed_count: get_sqlite(&row, "failed_count")?,
    })
}

fn ring_from_postgres_row(row: PgRow) -> AgentRolloutResult<AgentRolloutRing> {
    Ok(AgentRolloutRing {
        id: get_postgres(&row, "id")?,
        rollout_id: get_postgres(&row, "rollout_id")?,
        ring_name: get_postgres(&row, "ring_name")?,
        sequence_number: get_postgres_integer(&row, "sequence_number")?,
        status: get_postgres(&row, "status")?,
        minimum_success_percent: get_postgres_integer(&row, "minimum_success_percent")?,
        observation_minutes: get_postgres_integer(&row, "observation_minutes")?,
        max_failed_targets: get_postgres_integer(&row, "max_failed_targets")?,
        minimum_target_count: get_postgres_integer(&row, "minimum_target_count")?,
        started_at: get_postgres(&row, "started_at")?,
        observation_started_at: get_postgres(&row, "observation_started_at")?,
        evaluated_at: get_postgres(&row, "evaluated_at")?,
        approved_by_id: get_postgres(&row, "approved_by_id")?,
        approved_at: get_postgres(&row, "approved_at")?,
        completed_at: get_postgres(&row, "completed_at")?,
        failure_reason: get_postgres(&row, "failure_reason")?,
        target_count: get_postgres(&row, "target_count")?,
        succeeded_count: get_postgres(&row, "succeeded_count")?,
        failed_count: get_postgres(&row, "failed_count")?,
    })
}

const TARGET_SELECT: &str = r#"
SELECT t.*, r.ring_name, d.hostname, d.os_family, d.agent_version AS current_agent_version
FROM zero_trust_agent_rollout_target t
JOIN zero_trust_agent_rollout_ring r
  ON r.tenant_id=t.tenant_id AND r.rollout_id=t.rollout_id AND r.id=t.ring_id
JOIN zero_trust_agent_device d
  ON d.tenant_id=t.tenant_id AND d.id=t.device_id
WHERE t.tenant_id={tenant} AND t.rollout_id={rollout}
ORDER BY r.sequence_number, d.hostname, t.id
"#;

async fn list_targets_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    rollout_id: i64,
) -> AgentRolloutResult<Vec<AgentRolloutTarget>> {
    let sql = TARGET_SELECT
        .replace("{tenant}", "?1")
        .replace("{rollout}", "?2");
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(rollout_id)
        .fetch_all(pool)
        .await
        .map_err(|error| {
            AgentRolloutError::database("SQLite-Rollout-Ziele konnten nicht gelesen werden", error)
        })?;
    rows.into_iter().map(target_from_sqlite_row).collect()
}

async fn list_targets_postgres(
    pool: &PgPool,
    tenant_id: i64,
    rollout_id: i64,
) -> AgentRolloutResult<Vec<AgentRolloutTarget>> {
    let sql = TARGET_SELECT
        .replace("{tenant}", "$1")
        .replace("{rollout}", "$2");
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(rollout_id)
        .fetch_all(pool)
        .await
        .map_err(|error| {
            AgentRolloutError::database(
                "PostgreSQL-Rollout-Ziele konnten nicht gelesen werden",
                error,
            )
        })?;
    rows.into_iter().map(target_from_postgres_row).collect()
}

fn target_from_sqlite_row(row: SqliteRow) -> AgentRolloutResult<AgentRolloutTarget> {
    Ok(AgentRolloutTarget {
        id: get_sqlite(&row, "id")?,
        rollout_id: get_sqlite(&row, "rollout_id")?,
        ring_id: get_sqlite(&row, "ring_id")?,
        ring_name: get_sqlite(&row, "ring_name")?,
        device_id: get_sqlite(&row, "device_id")?,
        hostname: get_sqlite(&row, "hostname")?,
        os_family: get_sqlite(&row, "os_family")?,
        current_agent_version: get_sqlite(&row, "current_agent_version")?,
        status: get_sqlite(&row, "status")?,
        eligibility_reason: get_sqlite(&row, "eligibility_reason")?,
        preflight_status: get_sqlite(&row, "preflight_status")?,
        postflight_status: get_sqlite(&row, "postflight_status")?,
        deployment_status: get_sqlite(&row, "deployment_status")?,
        previous_agent_version: get_sqlite(&row, "previous_agent_version")?,
        expected_agent_version: get_sqlite(&row, "expected_agent_version")?,
        observed_agent_version: get_sqlite(&row, "observed_agent_version")?,
        deployment_reference: get_sqlite(&row, "deployment_reference")?,
        result_summary: get_sqlite(&row, "result_summary")?,
        eligibility_status: get_sqlite(&row, "eligibility_status")?,
        rollback_status: get_sqlite(&row, "rollback_status")?,
        error_class: get_sqlite(&row, "error_class")?,
        operator_note: get_sqlite(&row, "operator_note")?,
        rollback_requested_at: get_sqlite(&row, "rollback_requested_at")?,
        rollback_completed_at: get_sqlite(&row, "rollback_completed_at")?,
        deployment_recorded_at: get_sqlite(&row, "deployment_recorded_at")?,
        completed_at: get_sqlite(&row, "completed_at")?,
    })
}

fn target_from_postgres_row(row: PgRow) -> AgentRolloutResult<AgentRolloutTarget> {
    Ok(AgentRolloutTarget {
        id: get_postgres(&row, "id")?,
        rollout_id: get_postgres(&row, "rollout_id")?,
        ring_id: get_postgres(&row, "ring_id")?,
        ring_name: get_postgres(&row, "ring_name")?,
        device_id: get_postgres(&row, "device_id")?,
        hostname: get_postgres(&row, "hostname")?,
        os_family: get_postgres(&row, "os_family")?,
        current_agent_version: get_postgres(&row, "current_agent_version")?,
        status: get_postgres(&row, "status")?,
        eligibility_reason: get_postgres(&row, "eligibility_reason")?,
        preflight_status: get_postgres(&row, "preflight_status")?,
        postflight_status: get_postgres(&row, "postflight_status")?,
        deployment_status: get_postgres(&row, "deployment_status")?,
        previous_agent_version: get_postgres(&row, "previous_agent_version")?,
        expected_agent_version: get_postgres(&row, "expected_agent_version")?,
        observed_agent_version: get_postgres(&row, "observed_agent_version")?,
        deployment_reference: get_postgres(&row, "deployment_reference")?,
        result_summary: get_postgres(&row, "result_summary")?,
        eligibility_status: get_postgres(&row, "eligibility_status")?,
        rollback_status: get_postgres(&row, "rollback_status")?,
        error_class: get_postgres(&row, "error_class")?,
        operator_note: get_postgres(&row, "operator_note")?,
        rollback_requested_at: get_postgres(&row, "rollback_requested_at")?,
        rollback_completed_at: get_postgres(&row, "rollback_completed_at")?,
        deployment_recorded_at: get_postgres(&row, "deployment_recorded_at")?,
        completed_at: get_postgres(&row, "completed_at")?,
    })
}

async fn list_checks_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    rollout_id: i64,
) -> AgentRolloutResult<Vec<AgentRolloutCheck>> {
    let rows = sqlx::query("SELECT * FROM zero_trust_agent_rollout_check WHERE tenant_id=?1 AND rollout_id=?2 ORDER BY observed_at DESC,id DESC LIMIT 1000")
        .bind(tenant_id).bind(rollout_id).fetch_all(pool).await
        .map_err(|error| AgentRolloutError::database("SQLite-Rollout-Pruefungen konnten nicht gelesen werden", error))?;
    rows.into_iter().map(check_from_sqlite_row).collect()
}

async fn list_checks_postgres(
    pool: &PgPool,
    tenant_id: i64,
    rollout_id: i64,
) -> AgentRolloutResult<Vec<AgentRolloutCheck>> {
    let rows = sqlx::query("SELECT * FROM zero_trust_agent_rollout_check WHERE tenant_id=$1 AND rollout_id=$2 ORDER BY observed_at DESC,id DESC LIMIT 1000")
        .bind(tenant_id).bind(rollout_id).fetch_all(pool).await
        .map_err(|error| AgentRolloutError::database("PostgreSQL-Rollout-Pruefungen konnten nicht gelesen werden", error))?;
    rows.into_iter().map(check_from_postgres_row).collect()
}

fn check_from_sqlite_row(row: SqliteRow) -> AgentRolloutResult<AgentRolloutCheck> {
    let raw: String = get_sqlite(&row, "safe_detail_json")?;
    Ok(AgentRolloutCheck {
        id: get_sqlite(&row, "id")?,
        rollout_id: get_sqlite(&row, "rollout_id")?,
        ring_id: get_sqlite(&row, "ring_id")?,
        target_id: get_sqlite(&row, "target_id")?,
        phase: get_sqlite(&row, "phase")?,
        check_type: get_sqlite(&row, "check_type")?,
        status: get_sqlite(&row, "status")?,
        source: get_sqlite(&row, "source")?,
        summary: get_sqlite(&row, "summary")?,
        detail: serde_json::from_str(&raw).unwrap_or_else(|_| json!({})),
        observed_at: get_sqlite(&row, "observed_at")?,
        actor_id: get_sqlite(&row, "actor_id")?,
    })
}

fn check_from_postgres_row(row: PgRow) -> AgentRolloutResult<AgentRolloutCheck> {
    Ok(AgentRolloutCheck {
        id: get_postgres(&row, "id")?,
        rollout_id: get_postgres(&row, "rollout_id")?,
        ring_id: get_postgres(&row, "ring_id")?,
        target_id: get_postgres(&row, "target_id")?,
        phase: get_postgres(&row, "phase")?,
        check_type: get_postgres(&row, "check_type")?,
        status: get_postgres(&row, "status")?,
        source: get_postgres(&row, "source")?,
        summary: get_postgres(&row, "summary")?,
        detail: get_postgres(&row, "safe_detail_json")?,
        observed_at: get_postgres(&row, "observed_at")?,
        actor_id: get_postgres(&row, "actor_id")?,
    })
}

async fn list_events_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    rollout_id: i64,
) -> AgentRolloutResult<Vec<AgentRolloutEvent>> {
    let rows = sqlx::query("SELECT * FROM zero_trust_agent_rollout_event WHERE tenant_id=?1 AND rollout_id=?2 ORDER BY created_at DESC,id DESC LIMIT 500")
        .bind(tenant_id).bind(rollout_id).fetch_all(pool).await
        .map_err(|error| AgentRolloutError::database("SQLite-Rollout-Ereignisse konnten nicht gelesen werden", error))?;
    rows.into_iter().map(event_from_sqlite_row).collect()
}

async fn list_events_postgres(
    pool: &PgPool,
    tenant_id: i64,
    rollout_id: i64,
) -> AgentRolloutResult<Vec<AgentRolloutEvent>> {
    let rows = sqlx::query("SELECT * FROM zero_trust_agent_rollout_event WHERE tenant_id=$1 AND rollout_id=$2 ORDER BY created_at DESC,id DESC LIMIT 500")
        .bind(tenant_id).bind(rollout_id).fetch_all(pool).await
        .map_err(|error| AgentRolloutError::database("PostgreSQL-Rollout-Ereignisse konnten nicht gelesen werden", error))?;
    rows.into_iter().map(event_from_postgres_row).collect()
}

fn event_from_sqlite_row(row: SqliteRow) -> AgentRolloutResult<AgentRolloutEvent> {
    let raw: String = get_sqlite(&row, "safe_detail_json")?;
    Ok(AgentRolloutEvent {
        id: get_sqlite(&row, "id")?,
        rollout_id: get_sqlite(&row, "rollout_id")?,
        ring_id: get_sqlite(&row, "ring_id")?,
        target_id: get_sqlite(&row, "target_id")?,
        device_id: get_sqlite(&row, "device_id")?,
        event_type: get_sqlite(&row, "event_type")?,
        from_status: get_sqlite(&row, "from_status")?,
        to_status: get_sqlite(&row, "to_status")?,
        actor_id: get_sqlite(&row, "actor_id")?,
        summary: get_sqlite(&row, "summary")?,
        detail: serde_json::from_str(&raw).unwrap_or_else(|_| json!({})),
        created_at: get_sqlite(&row, "created_at")?,
    })
}

fn event_from_postgres_row(row: PgRow) -> AgentRolloutResult<AgentRolloutEvent> {
    Ok(AgentRolloutEvent {
        id: get_postgres(&row, "id")?,
        rollout_id: get_postgres(&row, "rollout_id")?,
        ring_id: get_postgres(&row, "ring_id")?,
        target_id: get_postgres(&row, "target_id")?,
        device_id: get_postgres(&row, "device_id")?,
        event_type: get_postgres(&row, "event_type")?,
        from_status: get_postgres(&row, "from_status")?,
        to_status: get_postgres(&row, "to_status")?,
        actor_id: get_postgres(&row, "actor_id")?,
        summary: get_postgres(&row, "summary")?,
        detail: get_postgres(&row, "safe_detail_json")?,
        created_at: get_postgres(&row, "created_at")?,
    })
}

impl AgentRolloutStore {
    async fn device_facts(
        &self,
        tenant_id: i64,
        rollout_id: i64,
        os_filter: &str,
        channel_filter: &str,
        limit: i64,
    ) -> AgentRolloutResult<Vec<DeviceFacts>> {
        match self {
            Self::Sqlite(pool) => {
                let rows = sqlx::query(
                    r#"SELECT d.*,
                        (SELECT COUNT(*) FROM zero_trust_agent_finding f WHERE f.tenant_id=d.tenant_id AND f.device_id=d.id AND f.status='OPEN' AND f.severity='CRITICAL') AS critical_findings,
                        (SELECT COUNT(*) FROM zero_trust_agent_finding f WHERE f.tenant_id=d.tenant_id AND f.device_id=d.id AND f.status='OPEN' AND f.severity='HIGH') AS high_findings,
                        COALESCE((SELECT c.certificate_status FROM agent_certificate_status c WHERE c.tenant_id=d.tenant_id AND c.agent_id=d.id ORDER BY c.updated_at DESC,c.id DESC LIMIT 1),'not_configured') AS certificate_status,
                        COALESCE((SELECT c.mtls_binding_status FROM agent_certificate_status c WHERE c.tenant_id=d.tenant_id AND c.agent_id=d.id ORDER BY c.updated_at DESC,c.id DESC LIMIT 1),'not_configured') AS mtls_binding_status,
                        (SELECT COUNT(*) FROM zero_trust_agent_rollout_target ot JOIN zero_trust_agent_rollout oro ON oro.tenant_id=ot.tenant_id AND oro.id=ot.rollout_id WHERE ot.tenant_id=d.tenant_id AND ot.device_id=d.id AND ot.rollout_id<>?2 AND oro.status IN ('ready','active','paused','rollback_required') AND ot.status NOT IN ('excluded','rolled_back')) AS other_active_rollouts
                       FROM zero_trust_agent_device d
                       WHERE d.tenant_id=?1 AND (?3='' OR d.os_family=?3) AND (?4='' OR d.deployment_channel=?4)
                         AND NOT EXISTS (SELECT 1 FROM zero_trust_agent_rollout_target et WHERE et.tenant_id=d.tenant_id AND et.rollout_id=?2 AND et.device_id=d.id)
                       ORDER BY d.hostname,d.id LIMIT ?5"#,
                ).bind(tenant_id).bind(rollout_id).bind(os_filter).bind(channel_filter).bind(limit)
                .fetch_all(pool).await.map_err(|error| AgentRolloutError::database("SQLite-Agent-Zielvorschau konnte nicht erstellt werden", error))?;
                rows.into_iter().map(device_facts_from_sqlite_row).collect()
            }
            Self::Postgres(pool) => {
                let rows = sqlx::query(
                    r#"SELECT d.*,
                        (SELECT COUNT(*)::bigint FROM zero_trust_agent_finding f WHERE f.tenant_id=d.tenant_id AND f.device_id=d.id AND f.status='OPEN' AND f.severity='CRITICAL') AS critical_findings,
                        (SELECT COUNT(*)::bigint FROM zero_trust_agent_finding f WHERE f.tenant_id=d.tenant_id AND f.device_id=d.id AND f.status='OPEN' AND f.severity='HIGH') AS high_findings,
                        COALESCE((SELECT c.certificate_status FROM agent_certificate_status c WHERE c.tenant_id=d.tenant_id AND c.agent_id=d.id ORDER BY c.updated_at DESC,c.id DESC LIMIT 1),'not_configured') AS certificate_status,
                        COALESCE((SELECT c.mtls_binding_status FROM agent_certificate_status c WHERE c.tenant_id=d.tenant_id AND c.agent_id=d.id ORDER BY c.updated_at DESC,c.id DESC LIMIT 1),'not_configured') AS mtls_binding_status,
                        (SELECT COUNT(*)::bigint FROM zero_trust_agent_rollout_target ot JOIN zero_trust_agent_rollout oro ON oro.tenant_id=ot.tenant_id AND oro.id=ot.rollout_id WHERE ot.tenant_id=d.tenant_id AND ot.device_id=d.id AND ot.rollout_id<>$2 AND oro.status IN ('ready','active','paused','rollback_required') AND ot.status NOT IN ('excluded','rolled_back')) AS other_active_rollouts
                       FROM zero_trust_agent_device d
                       WHERE d.tenant_id=$1 AND ($3='' OR d.os_family=$3) AND ($4='' OR d.deployment_channel=$4)
                         AND NOT EXISTS (SELECT 1 FROM zero_trust_agent_rollout_target et WHERE et.tenant_id=d.tenant_id AND et.rollout_id=$2 AND et.device_id=d.id)
                       ORDER BY d.hostname,d.id LIMIT $5"#,
                ).bind(tenant_id).bind(rollout_id).bind(os_filter).bind(channel_filter).bind(limit)
                .fetch_all(pool).await.map_err(|error| AgentRolloutError::database("PostgreSQL-Agent-Zielvorschau konnte nicht erstellt werden", error))?;
                rows.into_iter()
                    .map(device_facts_from_postgres_row)
                    .collect()
            }
        }
    }

    async fn device_facts_by_id(
        &self,
        tenant_id: i64,
        rollout_id: i64,
        device_id: i64,
    ) -> AgentRolloutResult<DeviceFacts> {
        let row = match self {
            Self::Sqlite(pool) => sqlx::query(
                r#"SELECT d.*,
                    (SELECT COUNT(*) FROM zero_trust_agent_finding f WHERE f.tenant_id=d.tenant_id AND f.device_id=d.id AND f.status='OPEN' AND f.severity='CRITICAL') AS critical_findings,
                    (SELECT COUNT(*) FROM zero_trust_agent_finding f WHERE f.tenant_id=d.tenant_id AND f.device_id=d.id AND f.status='OPEN' AND f.severity='HIGH') AS high_findings,
                    COALESCE((SELECT c.certificate_status FROM agent_certificate_status c WHERE c.tenant_id=d.tenant_id AND c.agent_id=d.id ORDER BY c.updated_at DESC,c.id DESC LIMIT 1),'not_configured') AS certificate_status,
                    COALESCE((SELECT c.mtls_binding_status FROM agent_certificate_status c WHERE c.tenant_id=d.tenant_id AND c.agent_id=d.id ORDER BY c.updated_at DESC,c.id DESC LIMIT 1),'not_configured') AS mtls_binding_status,
                    (SELECT COUNT(*) FROM zero_trust_agent_rollout_target ot JOIN zero_trust_agent_rollout oro ON oro.tenant_id=ot.tenant_id AND oro.id=ot.rollout_id WHERE ot.tenant_id=d.tenant_id AND ot.device_id=d.id AND ot.rollout_id<>?2 AND oro.status IN ('ready','active','paused','rollback_required') AND ot.status NOT IN ('excluded','rolled_back')) AS other_active_rollouts
                   FROM zero_trust_agent_device d WHERE d.tenant_id=?1 AND d.id=?3"#,
            ).bind(tenant_id).bind(rollout_id).bind(device_id).fetch_optional(pool).await
                .map_err(|error| AgentRolloutError::database("SQLite-Agent-Zieldaten konnten nicht gelesen werden", error))?
                .map(device_facts_from_sqlite_row).transpose()?,
            Self::Postgres(pool) => sqlx::query(
                r#"SELECT d.*,
                    (SELECT COUNT(*)::bigint FROM zero_trust_agent_finding f WHERE f.tenant_id=d.tenant_id AND f.device_id=d.id AND f.status='OPEN' AND f.severity='CRITICAL') AS critical_findings,
                    (SELECT COUNT(*)::bigint FROM zero_trust_agent_finding f WHERE f.tenant_id=d.tenant_id AND f.device_id=d.id AND f.status='OPEN' AND f.severity='HIGH') AS high_findings,
                    COALESCE((SELECT c.certificate_status FROM agent_certificate_status c WHERE c.tenant_id=d.tenant_id AND c.agent_id=d.id ORDER BY c.updated_at DESC,c.id DESC LIMIT 1),'not_configured') AS certificate_status,
                    COALESCE((SELECT c.mtls_binding_status FROM agent_certificate_status c WHERE c.tenant_id=d.tenant_id AND c.agent_id=d.id ORDER BY c.updated_at DESC,c.id DESC LIMIT 1),'not_configured') AS mtls_binding_status,
                    (SELECT COUNT(*)::bigint FROM zero_trust_agent_rollout_target ot JOIN zero_trust_agent_rollout oro ON oro.tenant_id=ot.tenant_id AND oro.id=ot.rollout_id WHERE ot.tenant_id=d.tenant_id AND ot.device_id=d.id AND ot.rollout_id<>$2 AND oro.status IN ('ready','active','paused','rollback_required') AND ot.status NOT IN ('excluded','rolled_back')) AS other_active_rollouts
                   FROM zero_trust_agent_device d WHERE d.tenant_id=$1 AND d.id=$3"#,
            ).bind(tenant_id).bind(rollout_id).bind(device_id).fetch_optional(pool).await
                .map_err(|error| AgentRolloutError::database("PostgreSQL-Agent-Zieldaten konnten nicht gelesen werden", error))?
                .map(device_facts_from_postgres_row).transpose()?,
        };
        row.ok_or_else(|| {
            foreign_reference("Das Agent-Ziel ist fuer diesen Mandanten nicht verfuegbar.")
        })
    }

    pub async fn assign_targets(
        &self,
        tenant_id: i64,
        rollout_id: i64,
        actor_id: i64,
        request: AgentRolloutTargetAssignmentRequest,
    ) -> AgentRolloutResult<AgentRolloutDetail> {
        let rollout = self.rollout(tenant_id, rollout_id).await?;
        if rollout.status != "draft" {
            return Err(invalid_transition(
                "Ziele koennen nur einem Rollout im Entwurfsstatus zugeordnet werden.",
            ));
        }
        if request.assignments.is_empty() || request.assignments.len() > 500 {
            return Err(invalid_input(
                "Es muessen 1 bis 500 Agent-Ziele angegeben werden.",
            ));
        }
        let mut seen = Vec::new();
        let mut prepared = Vec::new();
        let rings = self.detail(tenant_id, rollout_id).await?.rings;
        for assignment in request.assignments {
            let ring_name = assignment.ring_name.trim().to_ascii_lowercase();
            validate_ring_name(&ring_name)?;
            if seen.contains(&assignment.device_id) {
                return Err(invalid_input("Ein Agent-Ziel wurde mehrfach angegeben."));
            }
            seen.push(assignment.device_id);
            let ring = rings
                .iter()
                .find(|ring| ring.ring_name == ring_name)
                .ok_or_else(|| foreign_reference("Der Rollout-Ring wurde nicht gefunden."))?;
            if ring.status == "not_applicable" {
                return Err(invalid_input(
                    "Einem nicht anwendbaren Ring koennen keine Ziele zugeordnet werden.",
                ));
            }
            let facts = self
                .device_facts_by_id(tenant_id, rollout_id, assignment.device_id)
                .await?;
            if (!rollout.os_family_filter.is_empty() && rollout.os_family_filter != facts.os_family)
                || (!rollout.deployment_channel_filter.is_empty()
                    && rollout.deployment_channel_filter != facts.deployment_channel)
                || rollout
                    .policy_profile_id
                    .is_some_and(|policy_id| facts.policy_profile_id != Some(policy_id))
            {
                return Err(AgentRolloutError::new(
                    AgentRolloutErrorKind::GateBlocked,
                    "Ein Agent-Ziel liegt ausserhalb des Rollout-Scopes.",
                ));
            }
            prepared.push((assignment.device_id, ring.id, facts.agent_version));
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin().await.map_err(|error| {
                    AgentRolloutError::database(
                        "SQLite-Zielzuordnung konnte nicht gestartet werden",
                        error,
                    )
                })?;
                for (device_id, ring_id, previous_version) in prepared {
                    let row = sqlx::query("INSERT INTO zero_trust_agent_rollout_target (tenant_id,rollout_id,ring_id,device_id,previous_agent_version,expected_agent_version) SELECT ?1,?2,?3,?4,?5,?6 WHERE EXISTS (SELECT 1 FROM zero_trust_agent_rollout WHERE tenant_id=?1 AND id=?2 AND status='draft') RETURNING id")
                        .bind(tenant_id).bind(rollout_id).bind(ring_id).bind(device_id).bind(&previous_version).bind(&rollout.target_agent_version)
                        .fetch_optional(&mut *tx).await.map_err(|error| AgentRolloutError::database("SQLite-Agent-Ziel konnte nicht zugeordnet werden", error))?
                        .ok_or_else(concurrent_change)?;
                    let target_id: i64 = row.try_get("id").map_err(|error| {
                        AgentRolloutError::database("SQLite-Ziel-ID ist unlesbar", error)
                    })?;
                    insert_event_sqlite(
                        &mut tx,
                        RolloutEventInput {
                            tenant_id,
                            rollout_id,
                            ring_id: Some(ring_id),
                            target_id: Some(target_id),
                            event_type: "target_assigned",
                            from_status: "",
                            to_status: "pending",
                            actor_id,
                            summary: "Agent-Ziel einem kontrollierten Rollout-Ring zugeordnet",
                            detail: json!({"device_id":device_id}),
                        },
                    )
                    .await?;
                }
                tx.commit().await.map_err(|error| {
                    AgentRolloutError::database(
                        "SQLite-Zielzuordnung konnte nicht bestaetigt werden",
                        error,
                    )
                })?;
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await.map_err(|error| {
                    AgentRolloutError::database(
                        "PostgreSQL-Zielzuordnung konnte nicht gestartet werden",
                        error,
                    )
                })?;
                for (device_id, ring_id, previous_version) in prepared {
                    let row = sqlx::query("INSERT INTO zero_trust_agent_rollout_target (tenant_id,rollout_id,ring_id,device_id,previous_agent_version,expected_agent_version) SELECT $1,$2,$3,$4,$5,$6 WHERE EXISTS (SELECT 1 FROM zero_trust_agent_rollout WHERE tenant_id=$1 AND id=$2 AND status='draft') RETURNING id")
                        .bind(tenant_id).bind(rollout_id).bind(ring_id).bind(device_id).bind(&previous_version).bind(&rollout.target_agent_version)
                        .fetch_optional(&mut *tx).await.map_err(|error| AgentRolloutError::database("PostgreSQL-Agent-Ziel konnte nicht zugeordnet werden", error))?
                        .ok_or_else(concurrent_change)?;
                    let target_id: i64 = row.try_get("id").map_err(|error| {
                        AgentRolloutError::database("PostgreSQL-Ziel-ID ist unlesbar", error)
                    })?;
                    insert_event_postgres(
                        &mut tx,
                        RolloutEventInput {
                            tenant_id,
                            rollout_id,
                            ring_id: Some(ring_id),
                            target_id: Some(target_id),
                            event_type: "target_assigned",
                            from_status: "",
                            to_status: "pending",
                            actor_id,
                            summary: "Agent-Ziel einem kontrollierten Rollout-Ring zugeordnet",
                            detail: json!({"device_id":device_id}),
                        },
                    )
                    .await?;
                }
                tx.commit().await.map_err(|error| {
                    AgentRolloutError::database(
                        "PostgreSQL-Zielzuordnung konnte nicht bestaetigt werden",
                        error,
                    )
                })?;
            }
        }
        self.detail(tenant_id, rollout_id).await
    }

    pub async fn run_preflight(
        &self,
        tenant_id: i64,
        rollout_id: i64,
        ring_name: &str,
        actor_id: i64,
    ) -> AgentRolloutResult<AgentRolloutDetail> {
        validate_ring_name(ring_name)?;
        let detail = self.detail(tenant_id, rollout_id).await?;
        if !matches!(detail.rollout.status.as_str(), "draft" | "ready") {
            return Err(invalid_transition(
                "Preflight-Pruefungen sind nur vor dem Rollout-Start moeglich.",
            ));
        }
        let ring = detail
            .rings
            .iter()
            .find(|ring| ring.ring_name == ring_name)
            .ok_or_else(|| foreign_reference("Der Rollout-Ring wurde nicht gefunden."))?;
        if ring.status == "not_applicable" {
            return Err(invalid_transition(
                "Ein nicht anwendbarer Ring kann nicht geprueft werden.",
            ));
        }
        let ring_targets: Vec<_> = detail
            .targets
            .iter()
            .filter(|target| target.ring_id == ring.id)
            .collect();
        if ring_targets.is_empty() {
            return Err(gate_blocked(
                "Vor dem Preflight muss dem Ring mindestens ein Agent-Ziel zugeordnet werden.",
            ));
        }
        let artifact = self
            .artifact_status(tenant_id, detail.rollout.artifact_id.as_deref())
            .await?;
        let mut evaluations = Vec::new();
        for target in ring_targets {
            if !matches!(target.status.as_str(), "pending" | "eligible" | "blocked") {
                return Err(invalid_transition(
                    "Der Preflight kann fuer bereits gestartete Ziele nicht wiederholt werden.",
                ));
            }
            let facts = self
                .device_facts_by_id(tenant_id, rollout_id, target.device_id)
                .await?;
            evaluations.push((
                target.clone(),
                evaluate_preflight(&detail.rollout, &facts, artifact.as_ref()),
            ));
        }
        match self {
            Self::Sqlite(pool) => {
                apply_preflight_sqlite(pool, tenant_id, rollout_id, actor_id, &detail, evaluations)
                    .await?
            }
            Self::Postgres(pool) => {
                apply_preflight_postgres(
                    pool,
                    tenant_id,
                    rollout_id,
                    actor_id,
                    &detail,
                    evaluations,
                )
                .await?
            }
        }
        self.detail(tenant_id, rollout_id).await
    }

    pub async fn validate_rollout(
        &self,
        tenant_id: i64,
        rollout_id: i64,
        actor_id: i64,
    ) -> AgentRolloutResult<AgentRolloutValidation> {
        let detail = self.detail(tenant_id, rollout_id).await?;
        if !matches!(detail.rollout.status.as_str(), "draft" | "ready") {
            return Err(invalid_transition(
                "Nur ein Rollout vor dem Start kann validiert werden.",
            ));
        }
        let mut blockers = Vec::new();
        let mut warnings = Vec::new();
        if detail.targets.is_empty() {
            blockers.push("Mindestens ein Agent-Ziel ist erforderlich.".to_string());
        }
        for ring in &detail.rings {
            let count = detail
                .targets
                .iter()
                .filter(|target| target.ring_id == ring.id)
                .count() as i64;
            if ring.status == "not_applicable" && count > 0 {
                blockers.push(format!(
                    "Der Ring {} ist nicht anwendbar, enthaelt aber Ziele.",
                    ring.ring_name
                ));
            }
            if ring.status != "not_applicable" && count == 0 {
                blockers.push(format!(
                    "Der Ring {} benoetigt Ziele oder muss als nicht anwendbar markiert werden.",
                    ring.ring_name
                ));
            }
            if count > 0 && count < ring.minimum_target_count {
                blockers.push(format!(
                    "Der Ring {} unterschreitet seine Mindestzielzahl.",
                    ring.ring_name
                ));
            }
        }
        let first = detail
            .rings
            .iter()
            .find(|ring| ring.status != "not_applicable");
        if first.is_none_or(|ring| ring.status != "ready") {
            blockers.push(
                "Der erste anwendbare Ring hat den Preflight noch nicht vollstaendig bestanden."
                    .to_string(),
            );
        }
        if detail.rollout.artifact_id.is_none()
            && (detail.rollout.require_verified_artifact_checksum
                || detail.rollout.signature_requirement != "not_required")
        {
            blockers.push(
                "Die Artefakt-Policy erfordert ein tenant-gebundenes Release-Artefakt.".to_string(),
            );
        }
        if detail.rollout.signature_requirement == "verified_required" {
            warnings.push("Produktive Agent-Paketsignierung ist nicht automatisch verfuegbar; der Preflight blockiert ohne echten verifizierten Status.".to_string());
        }
        let valid = blockers.is_empty();
        if valid && detail.rollout.status == "draft" {
            self.mark_ready(tenant_id, rollout_id, actor_id).await?;
        }
        Ok(AgentRolloutValidation {
            valid,
            blockers,
            warnings,
            detail: self.detail(tenant_id, rollout_id).await?,
        })
    }

    async fn mark_ready(
        &self,
        tenant_id: i64,
        rollout_id: i64,
        actor_id: i64,
    ) -> AgentRolloutResult<()> {
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin().await.map_err(|error| {
                    AgentRolloutError::database(
                        "SQLite-Rollout-Validierung konnte nicht gestartet werden",
                        error,
                    )
                })?;
                let result = sqlx::query("UPDATE zero_trust_agent_rollout SET status='ready',updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?1 AND id=?2 AND status='draft'").bind(tenant_id).bind(rollout_id).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("SQLite-Rollout konnte nicht als bereit markiert werden",error))?;
                if result.rows_affected() != 1 {
                    return Err(concurrent_change());
                }
                insert_event_sqlite(
                    &mut tx,
                    RolloutEventInput {
                        tenant_id,
                        rollout_id,
                        ring_id: None,
                        target_id: None,
                        event_type: "rollout_validated",
                        from_status: "draft",
                        to_status: "ready",
                        actor_id,
                        summary: "Rollout-Readiness vollstaendig validiert",
                        detail: json!({}),
                    },
                )
                .await?;
                tx.commit().await.map_err(|error| {
                    AgentRolloutError::database(
                        "SQLite-Rollout-Validierung konnte nicht bestaetigt werden",
                        error,
                    )
                })?;
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await.map_err(|error| {
                    AgentRolloutError::database(
                        "PostgreSQL-Rollout-Validierung konnte nicht gestartet werden",
                        error,
                    )
                })?;
                let result = sqlx::query("UPDATE zero_trust_agent_rollout SET status='ready',updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$1 AND id=$2 AND status='draft'").bind(tenant_id).bind(rollout_id).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("PostgreSQL-Rollout konnte nicht als bereit markiert werden",error))?;
                if result.rows_affected() != 1 {
                    return Err(concurrent_change());
                }
                insert_event_postgres(
                    &mut tx,
                    RolloutEventInput {
                        tenant_id,
                        rollout_id,
                        ring_id: None,
                        target_id: None,
                        event_type: "rollout_validated",
                        from_status: "draft",
                        to_status: "ready",
                        actor_id,
                        summary: "Rollout-Readiness vollstaendig validiert",
                        detail: json!({}),
                    },
                )
                .await?;
                tx.commit().await.map_err(|error| {
                    AgentRolloutError::database(
                        "PostgreSQL-Rollout-Validierung konnte nicht bestaetigt werden",
                        error,
                    )
                })?;
            }
        }
        Ok(())
    }

    pub async fn start_ring(
        &self,
        tenant_id: i64,
        rollout_id: i64,
        ring_name: &str,
        actor_id: i64,
        confirmation: AgentRolloutConfirmationRequest,
    ) -> AgentRolloutResult<AgentRolloutDetail> {
        require_confirmation(
            &confirmation,
            "Der Ring-Start muss ausdruecklich bestaetigt werden.",
        )?;
        validate_ring_name(ring_name)?;
        let detail = self.detail(tenant_id, rollout_id).await?;
        if !matches!(detail.rollout.status.as_str(), "ready" | "active") {
            return Err(invalid_transition(
                "Der Rollout ist nicht fuer einen Ring-Start bereit.",
            ));
        }
        if detail.rollout.active_ring_name.is_some() {
            return Err(gate_blocked("Ein anderer Rollout-Ring ist bereits aktiv."));
        }
        let ring = detail
            .rings
            .iter()
            .find(|ring| ring.ring_name == ring_name)
            .ok_or_else(|| foreign_reference("Der Rollout-Ring wurde nicht gefunden."))?;
        if ring.status != "ready" {
            return Err(gate_blocked(
                "Der Ring hat die Preflight-Gates noch nicht bestanden.",
            ));
        }
        let targets: Vec<_> = detail
            .targets
            .iter()
            .filter(|target| target.ring_id == ring.id)
            .collect();
        if targets.is_empty() || targets.iter().any(|target| target.status != "eligible") {
            return Err(gate_blocked(
                "Alle Ziele dieses Rings muessen den Preflight bestanden haben.",
            ));
        }
        let artifact = self
            .artifact_status(tenant_id, detail.rollout.artifact_id.as_deref())
            .await?;
        for target in &targets {
            let facts = self
                .device_facts_by_id(tenant_id, rollout_id, target.device_id)
                .await?;
            if evaluate_preflight(&detail.rollout, &facts, artifact.as_ref())
                .iter()
                .any(|check| check.status == "failed")
            {
                return Err(gate_blocked(
                    "Mindestens ein Ziel hat einen neuen kritischen Preflight-Blocker.",
                ));
            }
        }
        let previous_incomplete = detail.rings.iter().any(|candidate| {
            candidate.sequence_number < ring.sequence_number
                && !matches!(candidate.status.as_str(), "passed" | "not_applicable")
        });
        if previous_incomplete {
            return Err(gate_blocked(
                "Der vorherige anwendbare Ring wurde noch nicht freigegeben.",
            ));
        }
        ensure_ring_transition(&ring.status, "active")?;
        let start = RingStart {
            tenant_id,
            rollout_id,
            ring,
            targets: &targets,
            actor_id,
            reason: &confirmation.reason,
            rollout_status: &detail.rollout.status,
        };
        match self {
            Self::Sqlite(pool) => start_ring_sqlite(pool, &start).await?,
            Self::Postgres(pool) => start_ring_postgres(pool, &start).await?,
        }
        self.detail(tenant_id, rollout_id).await
    }

    pub async fn record_deployment_result(
        &self,
        tenant_id: i64,
        rollout_id: i64,
        target_id: i64,
        actor_id: i64,
        mut request: AgentRolloutDeploymentResultRequest,
    ) -> AgentRolloutResult<AgentRolloutDetail> {
        request.status = request.status.trim().to_ascii_lowercase();
        if !matches!(
            request.status.as_str(),
            "in_progress" | "succeeded" | "failed"
        ) {
            return Err(invalid_input(
                "Der Deployment-Status muss in_progress, succeeded oder failed sein.",
            ));
        }
        request.observed_version = request.observed_version.trim().to_string();
        request.error_class = request.error_class.trim().to_ascii_lowercase();
        request.operator_note = request.operator_note.trim().to_string();
        validate_member(
            "Deployment-Fehlerklasse",
            &request.error_class,
            &[
                "",
                "network",
                "package",
                "verification",
                "policy",
                "timeout",
                "unknown",
            ],
        )?;
        if request.operator_note.len() > 4_000
            || request.observed_version.len() > 64
            || !safe_operator_text(&request.operator_note)
        {
            return Err(invalid_input(
                "Die Deployment-Rueckmeldung ueberschreitet die erlaubte Laenge.",
            ));
        }
        request.observed_at = request
            .observed_at
            .as_deref()
            .map(|value| {
                DateTime::parse_from_rfc3339(value.trim())
                    .map(|value| value.with_timezone(&Utc).to_rfc3339())
                    .map_err(|_| invalid_input("observed_at muss ein RFC-3339-Zeitpunkt sein."))
            })
            .transpose()?;
        let detail = self.detail(tenant_id, rollout_id).await?;
        if detail.rollout.status != "active" {
            return Err(invalid_transition(
                "Deployment-Ergebnisse koennen nur fuer einen aktiven Rollout erfasst werden.",
            ));
        }
        let target = detail
            .targets
            .iter()
            .find(|target| target.id == target_id)
            .ok_or_else(|| foreign_reference("Das Rollout-Ziel wurde nicht gefunden."))?;
        let ring = detail
            .rings
            .iter()
            .find(|ring| ring.id == target.ring_id)
            .ok_or_else(|| foreign_reference("Der Rollout-Ring wurde nicht gefunden."))?;
        if !matches!(ring.status.as_str(), "active" | "observing") {
            return Err(invalid_transition(
                "Der zugehoerige Rollout-Ring ist nicht aktiv.",
            ));
        }
        if !matches!(target.status.as_str(), "scheduled" | "in_progress") {
            return Err(invalid_transition(
                "Fuer dieses Ziel kann kein Deployment-Ergebnis mehr erfasst werden.",
            ));
        }
        if target.deployment_status == request.status
            && target.observed_agent_version == request.observed_version
            && target.error_class == request.error_class
            && target.operator_note == request.operator_note
        {
            return Ok(detail);
        }
        let new_target_status = if request.status == "failed" {
            "failed"
        } else {
            "in_progress"
        };
        ensure_target_transition(&target.status, new_target_status)?;
        match self {
            Self::Sqlite(pool) => {
                record_result_sqlite(
                    pool,
                    tenant_id,
                    rollout_id,
                    target,
                    actor_id,
                    &request,
                    new_target_status,
                )
                .await?
            }
            Self::Postgres(pool) => {
                record_result_postgres(
                    pool,
                    tenant_id,
                    rollout_id,
                    target,
                    actor_id,
                    &request,
                    new_target_status,
                )
                .await?
            }
        }
        self.detail(tenant_id, rollout_id).await
    }

    pub async fn run_postflight(
        &self,
        tenant_id: i64,
        rollout_id: i64,
        ring_name: &str,
        actor_id: i64,
    ) -> AgentRolloutResult<AgentRolloutDetail> {
        validate_ring_name(ring_name)?;
        let detail = self.detail(tenant_id, rollout_id).await?;
        if detail.rollout.status != "active" {
            return Err(invalid_transition(
                "Postflight-Pruefungen erfordern einen aktiven Rollout.",
            ));
        }
        let ring = detail
            .rings
            .iter()
            .find(|ring| ring.ring_name == ring_name)
            .ok_or_else(|| foreign_reference("Der Rollout-Ring wurde nicht gefunden."))?;
        if !matches!(ring.status.as_str(), "active" | "observing") {
            return Err(invalid_transition(
                "Der Ring ist nicht fuer Postflight-Pruefungen bereit.",
            ));
        }
        let targets: Vec<_> = detail
            .targets
            .iter()
            .filter(|target| target.ring_id == ring.id)
            .cloned()
            .collect();
        if targets.is_empty()
            || targets
                .iter()
                .any(|target| !matches!(target.deployment_status.as_str(), "succeeded" | "failed"))
        {
            return Err(gate_blocked("Fuer alle Ring-Ziele muss zuerst ein abschliessendes Deployment-Ergebnis vorliegen."));
        }
        let mut evaluations = Vec::new();
        for target in targets {
            let facts = self
                .device_facts_by_id(tenant_id, rollout_id, target.device_id)
                .await?;
            evaluations.push((
                target.clone(),
                evaluate_postflight(&detail.rollout, &target, &facts),
            ));
        }
        match self {
            Self::Sqlite(pool) => {
                apply_postflight_sqlite(pool, tenant_id, rollout_id, actor_id, ring, evaluations)
                    .await?
            }
            Self::Postgres(pool) => {
                apply_postflight_postgres(pool, tenant_id, rollout_id, actor_id, ring, evaluations)
                    .await?
            }
        }
        self.detail(tenant_id, rollout_id).await
    }

    pub async fn evaluate_ring(
        &self,
        tenant_id: i64,
        rollout_id: i64,
        ring_name: &str,
        actor_id: i64,
    ) -> AgentRolloutResult<AgentRolloutDetail> {
        validate_ring_name(ring_name)?;
        let detail = self.detail(tenant_id, rollout_id).await?;
        let ring = detail
            .rings
            .iter()
            .find(|ring| ring.ring_name == ring_name)
            .ok_or_else(|| foreign_reference("Der Rollout-Ring wurde nicht gefunden."))?;
        if ring.status != "observing" {
            return Err(invalid_transition(
                "Der Rollout-Ring befindet sich nicht in der Beobachtungsphase.",
            ));
        }
        let observation_started = ring
            .observation_started_at
            .as_deref()
            .and_then(parse_timestamp)
            .ok_or_else(|| {
                gate_blocked("Der Beginn der Beobachtungsphase ist nicht dokumentiert.")
            })?;
        if Utc::now() < observation_started + Duration::minutes(ring.observation_minutes) {
            return Err(gate_blocked(
                "Die konfigurierte Beobachtungszeit ist noch nicht abgelaufen.",
            ));
        }
        let targets: Vec<_> = detail
            .targets
            .iter()
            .filter(|target| target.ring_id == ring.id)
            .collect();
        if targets.is_empty() {
            return Err(gate_blocked("Der Ring enthaelt keine Ziele."));
        }
        let mut security_blocker = targets
            .iter()
            .any(|target| target.rollback_status != "not_required");
        for target in &targets {
            let facts = self
                .device_facts_by_id(tenant_id, rollout_id, target.device_id)
                .await?;
            let heartbeat_fresh = facts
                .last_seen_at
                .as_deref()
                .and_then(parse_timestamp)
                .is_some_and(|seen| {
                    let age = Utc::now().signed_duration_since(seen).num_minutes();
                    age >= 0 && age <= detail.rollout.heartbeat_freshness_minutes
                });
            security_blocker |= facts.critical_findings > detail.rollout.maximum_critical_findings
                || !heartbeat_fresh;
        }
        let succeeded = targets
            .iter()
            .filter(|target| target.status == "succeeded")
            .count() as i64;
        let failed = targets
            .iter()
            .filter(|target| target.status == "failed")
            .count() as i64;
        let success_percent = succeeded * 100 / targets.len() as i64;
        let next_status = if security_blocker || failed > ring.max_failed_targets {
            "rollback_required"
        } else if targets.len() as i64 >= ring.minimum_target_count
            && success_percent >= ring.minimum_success_percent
        {
            "passed"
        } else {
            "failed"
        };
        ensure_ring_transition(&ring.status, next_status)?;
        let evaluation = RingEvaluation {
            tenant_id,
            rollout_id,
            actor_id,
            ring,
            next_status,
            succeeded,
            failed,
            success_percent,
        };
        match self {
            Self::Sqlite(pool) => evaluate_ring_sqlite(pool, &evaluation).await?,
            Self::Postgres(pool) => evaluate_ring_postgres(pool, &evaluation).await?,
        }
        self.detail(tenant_id, rollout_id).await
    }

    pub async fn promote_ring(
        &self,
        tenant_id: i64,
        rollout_id: i64,
        ring_name: &str,
        actor_id: i64,
        confirmation: AgentRolloutConfirmationRequest,
    ) -> AgentRolloutResult<AgentRolloutDetail> {
        require_confirmation(
            &confirmation,
            "Die Ring-Freigabe muss ausdruecklich bestaetigt werden.",
        )?;
        validate_ring_name(ring_name)?;
        let detail = self.detail(tenant_id, rollout_id).await?;
        if detail.rollout.status != "active" {
            return Err(invalid_transition(
                "Nur ein aktiver Rollout kann freigegeben werden.",
            ));
        }
        let ring = detail
            .rings
            .iter()
            .find(|ring| ring.ring_name == ring_name)
            .ok_or_else(|| foreign_reference("Der Rollout-Ring wurde nicht gefunden."))?;
        if ring.status != "passed" {
            return Err(gate_blocked(
                "Nur ein bestandener Ring kann manuell freigegeben werden.",
            ));
        }
        let next_ring = detail.rings.iter().find(|candidate| {
            candidate.sequence_number > ring.sequence_number && candidate.status != "not_applicable"
        });
        if let Some(next) = next_ring {
            if next.status != "ready" {
                return Err(gate_blocked(
                    "Der naechste Ring hat seine Preflight-Gates noch nicht bestanden.",
                ));
            }
            let artifact = self
                .artifact_status(tenant_id, detail.rollout.artifact_id.as_deref())
                .await?;
            for target in detail
                .targets
                .iter()
                .filter(|target| target.ring_id == next.id)
            {
                let facts = self
                    .device_facts_by_id(tenant_id, rollout_id, target.device_id)
                    .await?;
                if evaluate_preflight(&detail.rollout, &facts, artifact.as_ref())
                    .iter()
                    .any(|check| check.status == "failed")
                {
                    return Err(gate_blocked(
                        "Der naechste Ring hat einen neuen kritischen Preflight-Blocker.",
                    ));
                }
            }
        }
        match self {
            Self::Sqlite(pool) => {
                promote_ring_sqlite(
                    pool,
                    tenant_id,
                    rollout_id,
                    actor_id,
                    ring,
                    next_ring,
                    &confirmation.reason,
                )
                .await?
            }
            Self::Postgres(pool) => {
                promote_ring_postgres(
                    pool,
                    tenant_id,
                    rollout_id,
                    actor_id,
                    ring,
                    next_ring,
                    &confirmation.reason,
                )
                .await?
            }
        }
        self.detail(tenant_id, rollout_id).await
    }
}

fn require_confirmation(
    request: &AgentRolloutConfirmationRequest,
    message: &str,
) -> AgentRolloutResult<()> {
    if request.confirmed && !request.reason.trim().is_empty() {
        Ok(())
    } else {
        Err(invalid_input(message))
    }
}

struct RingStart<'a> {
    tenant_id: i64,
    rollout_id: i64,
    ring: &'a AgentRolloutRing,
    targets: &'a [&'a AgentRolloutTarget],
    actor_id: i64,
    reason: &'a str,
    rollout_status: &'a str,
}

async fn start_ring_sqlite(pool: &SqlitePool, start: &RingStart<'_>) -> AgentRolloutResult<()> {
    let tenant_id = start.tenant_id;
    let rollout_id = start.rollout_id;
    let ring = start.ring;
    let targets = start.targets;
    let actor_id = start.actor_id;
    let reason = start.reason;
    let rollout_status = start.rollout_status;
    let mut tx = pool.begin().await.map_err(|error| {
        AgentRolloutError::database("SQLite-Ring-Start konnte nicht gestartet werden", error)
    })?;
    let rollout=sqlx::query("UPDATE zero_trust_agent_rollout SET status='active',active_ring_name=?1,approved_by_id=?2,approved_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?3 AND id=?4 AND status=?5 AND active_ring_name IS NULL")
        .bind(&ring.ring_name).bind(actor_id).bind(tenant_id).bind(rollout_id).bind(rollout_status).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("SQLite-Rollout konnte nicht aktiviert werden",error))?;
    if rollout.rows_affected() != 1 {
        return Err(concurrent_change());
    }
    let result=sqlx::query("UPDATE zero_trust_agent_rollout_ring SET status='active',started_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?1 AND rollout_id=?2 AND id=?3 AND status='ready'")
        .bind(tenant_id).bind(rollout_id).bind(ring.id).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("SQLite-Ring konnte nicht gestartet werden",error))?;
    if result.rows_affected() != 1 {
        return Err(concurrent_change());
    }
    for target in targets {
        let result=sqlx::query("UPDATE zero_trust_agent_rollout_target SET status='scheduled',deployment_status='scheduled',scheduled_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?1 AND rollout_id=?2 AND id=?3 AND status='eligible'")
            .bind(tenant_id).bind(rollout_id).bind(target.id).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("SQLite-Rollout-Ziel konnte nicht eingeplant werden",error))?;
        if result.rows_affected() != 1 {
            return Err(concurrent_change());
        }
        insert_event_sqlite(
            &mut tx,
            RolloutEventInput {
                tenant_id,
                rollout_id,
                ring_id: Some(ring.id),
                target_id: Some(target.id),
                event_type: "target_scheduled",
                from_status: "eligible",
                to_status: "scheduled",
                actor_id,
                summary: "Agent-Ziel fuer externes Deployment eingeplant",
                detail: json!({"remote_execution":false}),
            },
        )
        .await?;
    }
    insert_event_sqlite(
        &mut tx,
        RolloutEventInput {
            tenant_id,
            rollout_id,
            ring_id: Some(ring.id),
            target_id: None,
            event_type: "ring_started",
            from_status: "ready",
            to_status: "active",
            actor_id,
            summary: "Rollout-Ring nach manueller Freigabe gestartet",
            detail: json!({"reason":reason.trim(),"remote_execution":false}),
        },
    )
    .await?;
    tx.commit().await.map_err(|error| {
        AgentRolloutError::database("SQLite-Ring-Start konnte nicht bestaetigt werden", error)
    })?;
    Ok(())
}

async fn start_ring_postgres(pool: &PgPool, start: &RingStart<'_>) -> AgentRolloutResult<()> {
    let tenant_id = start.tenant_id;
    let rollout_id = start.rollout_id;
    let ring = start.ring;
    let targets = start.targets;
    let actor_id = start.actor_id;
    let reason = start.reason;
    let rollout_status = start.rollout_status;
    let mut tx = pool.begin().await.map_err(|error| {
        AgentRolloutError::database("PostgreSQL-Ring-Start konnte nicht gestartet werden", error)
    })?;
    let rollout=sqlx::query("UPDATE zero_trust_agent_rollout SET status='active',active_ring_name=$1,approved_by_id=$2,approved_at=(CURRENT_TIMESTAMP)::text,updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$3 AND id=$4 AND status=$5 AND active_ring_name IS NULL")
        .bind(&ring.ring_name).bind(actor_id).bind(tenant_id).bind(rollout_id).bind(rollout_status).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("PostgreSQL-Rollout konnte nicht aktiviert werden",error))?;
    if rollout.rows_affected() != 1 {
        return Err(concurrent_change());
    }
    let result=sqlx::query("UPDATE zero_trust_agent_rollout_ring SET status='active',started_at=(CURRENT_TIMESTAMP)::text,updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$1 AND rollout_id=$2 AND id=$3 AND status='ready'")
        .bind(tenant_id).bind(rollout_id).bind(ring.id).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("PostgreSQL-Ring konnte nicht gestartet werden",error))?;
    if result.rows_affected() != 1 {
        return Err(concurrent_change());
    }
    for target in targets {
        let result=sqlx::query("UPDATE zero_trust_agent_rollout_target SET status='scheduled',deployment_status='scheduled',scheduled_at=(CURRENT_TIMESTAMP)::text,updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$1 AND rollout_id=$2 AND id=$3 AND status='eligible'")
            .bind(tenant_id).bind(rollout_id).bind(target.id).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("PostgreSQL-Rollout-Ziel konnte nicht eingeplant werden",error))?;
        if result.rows_affected() != 1 {
            return Err(concurrent_change());
        }
        insert_event_postgres(
            &mut tx,
            RolloutEventInput {
                tenant_id,
                rollout_id,
                ring_id: Some(ring.id),
                target_id: Some(target.id),
                event_type: "target_scheduled",
                from_status: "eligible",
                to_status: "scheduled",
                actor_id,
                summary: "Agent-Ziel fuer externes Deployment eingeplant",
                detail: json!({"remote_execution":false}),
            },
        )
        .await?;
    }
    insert_event_postgres(
        &mut tx,
        RolloutEventInput {
            tenant_id,
            rollout_id,
            ring_id: Some(ring.id),
            target_id: None,
            event_type: "ring_started",
            from_status: "ready",
            to_status: "active",
            actor_id,
            summary: "Rollout-Ring nach manueller Freigabe gestartet",
            detail: json!({"reason":reason.trim(),"remote_execution":false}),
        },
    )
    .await?;
    tx.commit().await.map_err(|error| {
        AgentRolloutError::database(
            "PostgreSQL-Ring-Start konnte nicht bestaetigt werden",
            error,
        )
    })?;
    Ok(())
}

async fn record_result_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    rollout_id: i64,
    target: &AgentRolloutTarget,
    actor_id: i64,
    request: &AgentRolloutDeploymentResultRequest,
    new_status: &str,
) -> AgentRolloutResult<()> {
    let mut tx = pool.begin().await.map_err(|error| {
        AgentRolloutError::database(
            "SQLite-Deployment-Rueckmeldung konnte nicht gestartet werden",
            error,
        )
    })?;
    let result=sqlx::query("UPDATE zero_trust_agent_rollout_target SET status=?1,deployment_status=?2,observed_agent_version=?3,error_class=?4,operator_note=?5,result_summary='Externes Deployment-Ergebnis dokumentiert',deployment_started_at=CASE WHEN deployment_started_at IS NULL THEN COALESCE(?6,CURRENT_TIMESTAMP) ELSE deployment_started_at END,deployment_recorded_at=COALESCE(?6,CURRENT_TIMESTAMP),completed_at=CASE WHEN ?2='failed' THEN COALESCE(?6,CURRENT_TIMESTAMP) ELSE completed_at END,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?7 AND rollout_id=?8 AND id=?9 AND status=?10")
        .bind(new_status).bind(&request.status).bind(&request.observed_version).bind(&request.error_class).bind(&request.operator_note).bind(request.observed_at.as_deref()).bind(tenant_id).bind(rollout_id).bind(target.id).bind(&target.status)
        .execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("SQLite-Deployment-Rueckmeldung konnte nicht gespeichert werden",error))?;
    if result.rows_affected() != 1 {
        return Err(concurrent_change());
    }
    insert_event_sqlite(&mut tx,RolloutEventInput{tenant_id,rollout_id,ring_id:Some(target.ring_id),target_id:Some(target.id),event_type:"deployment_result_recorded",from_status:&target.status,to_status:new_status,actor_id,summary:"Externes Deployment-Ergebnis dokumentiert",detail:json!({"deployment_status":request.status,"observed_version":request.observed_version})}).await?;
    tx.commit().await.map_err(|error| {
        AgentRolloutError::database(
            "SQLite-Deployment-Rueckmeldung konnte nicht bestaetigt werden",
            error,
        )
    })?;
    Ok(())
}

async fn record_result_postgres(
    pool: &PgPool,
    tenant_id: i64,
    rollout_id: i64,
    target: &AgentRolloutTarget,
    actor_id: i64,
    request: &AgentRolloutDeploymentResultRequest,
    new_status: &str,
) -> AgentRolloutResult<()> {
    let mut tx = pool.begin().await.map_err(|error| {
        AgentRolloutError::database(
            "PostgreSQL-Deployment-Rueckmeldung konnte nicht gestartet werden",
            error,
        )
    })?;
    let result=sqlx::query("UPDATE zero_trust_agent_rollout_target SET status=$1,deployment_status=$2,observed_agent_version=$3,error_class=$4,operator_note=$5,result_summary='Externes Deployment-Ergebnis dokumentiert',deployment_started_at=CASE WHEN deployment_started_at IS NULL THEN COALESCE($6::text,(CURRENT_TIMESTAMP)::text) ELSE deployment_started_at END,deployment_recorded_at=COALESCE($6::text,(CURRENT_TIMESTAMP)::text),completed_at=CASE WHEN $2='failed' THEN COALESCE($6::text,(CURRENT_TIMESTAMP)::text) ELSE completed_at END,updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$7 AND rollout_id=$8 AND id=$9 AND status=$10")
        .bind(new_status).bind(&request.status).bind(&request.observed_version).bind(&request.error_class).bind(&request.operator_note).bind(request.observed_at.as_deref()).bind(tenant_id).bind(rollout_id).bind(target.id).bind(&target.status)
        .execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("PostgreSQL-Deployment-Rueckmeldung konnte nicht gespeichert werden",error))?;
    if result.rows_affected() != 1 {
        return Err(concurrent_change());
    }
    insert_event_postgres(&mut tx,RolloutEventInput{tenant_id,rollout_id,ring_id:Some(target.ring_id),target_id:Some(target.id),event_type:"deployment_result_recorded",from_status:&target.status,to_status:new_status,actor_id,summary:"Externes Deployment-Ergebnis dokumentiert",detail:json!({"deployment_status":request.status,"observed_version":request.observed_version})}).await?;
    tx.commit().await.map_err(|error| {
        AgentRolloutError::database(
            "PostgreSQL-Deployment-Rueckmeldung konnte nicht bestaetigt werden",
            error,
        )
    })?;
    Ok(())
}

fn evaluate_postflight(
    rollout: &AgentRollout,
    target: &AgentRolloutTarget,
    device: &DeviceFacts,
) -> Vec<EvaluatedCheck> {
    let deployment_at = target
        .deployment_recorded_at
        .as_deref()
        .and_then(parse_timestamp);
    let last_seen = device.last_seen_at.as_deref().and_then(parse_timestamp);
    let heartbeat_after = deployment_at
        .zip(last_seen)
        .is_some_and(|(deployment, heartbeat)| heartbeat >= deployment);
    let heartbeat_fresh = last_seen.is_some_and(|seen| {
        let age = Utc::now().signed_duration_since(seen).num_minutes();
        age >= 0 && age <= rollout.heartbeat_freshness_minutes
    });
    let cert_ok = match rollout.certificate_requirement.as_str() {
        "not_required" => true,
        "active_required" => device.certificate_status == "active",
        "mtls_bound_required" => {
            device.certificate_status == "active" && device.mtls_binding_status == "bound"
        }
        _ => false,
    };
    let mut checks = vec![
        bool_check(
            "deployment.succeeded",
            target.deployment_status == "succeeded",
            "Das externe Deployment wurde als erfolgreich dokumentiert.",
            "Das externe Deployment war nicht erfolgreich.",
        ),
        bool_check(
            "version.target_observed",
            device.agent_version == rollout.target_agent_version
                || target.observed_agent_version == rollout.target_agent_version,
            "Die Zielversion wurde beobachtet.",
            "Die Zielversion wurde noch nicht beobachtet.",
        ),
        bool_check(
            "heartbeat.after_deployment",
            heartbeat_after,
            "Ein Heartbeat nach dem Deployment liegt vor.",
            "Ein Heartbeat nach dem Deployment fehlt.",
        ),
        bool_check(
            "heartbeat.fresh",
            heartbeat_fresh,
            "Der Postflight-Heartbeat ist frisch.",
            "Der Postflight-Heartbeat ist zu alt.",
        ),
        bool_check(
            "posture.minimum_score",
            device.zero_trust_score >= rollout.minimum_zero_trust_score,
            "Der Zero-Trust-Score bleibt innerhalb des Gates.",
            "Der Zero-Trust-Score unterschreitet das Gate.",
        ),
        bool_check(
            "findings.no_critical",
            device.critical_findings <= rollout.maximum_critical_findings,
            "Die kritischen Findings liegen innerhalb des Grenzwerts.",
            "Kritische Findings ueberschreiten das Gate.",
        ),
        warning_check(
            "findings.high",
            device.high_findings == 0,
            "Keine offenen hohen Findings.",
            "Hohe Findings erfordern weitere Beobachtung.",
        ),
        bool_check(
            "enrollment.active",
            device.enrollment_status == "ACTIVE",
            "Die Agent-Einschreibung bleibt aktiv.",
            "Die Agent-Einschreibung ist nicht aktiv.",
        ),
        bool_or_na_check(
            "pki.certificate",
            rollout.certificate_requirement != "not_required",
            cert_ok,
            "Die Zertifikatsanforderung bleibt erfuellt.",
            "Die Zertifikatsanforderung ist nicht erfuellt.",
        ),
        bool_or_na_check(
            "pki.mtls_binding",
            rollout.certificate_requirement == "mtls_bound_required",
            device.mtls_binding_status == "bound",
            "Die mTLS-Bindung bleibt aktiv.",
            "Die mTLS-Bindung ist nicht aktiv.",
        ),
    ];
    if last_seen.is_none() {
        for check in &mut checks {
            if matches!(check.key, "heartbeat.after_deployment" | "heartbeat.fresh") {
                check.status = "warning";
                check.summary = "Aktuelle Heartbeat-Daten stehen noch aus.".to_string();
                check.detail = json!({"pending": true});
            }
        }
    }
    if device.agent_version.trim().is_empty() && target.observed_agent_version.trim().is_empty() {
        if let Some(check) = checks
            .iter_mut()
            .find(|check| check.key == "version.target_observed")
        {
            check.status = "warning";
            check.summary = "Eine aktuelle Agent-Version steht noch aus.".to_string();
            check.detail = json!({"pending": true});
        }
    }
    checks
}

async fn apply_postflight_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    rollout_id: i64,
    actor_id: i64,
    ring: &AgentRolloutRing,
    evaluations: Vec<(AgentRolloutTarget, Vec<EvaluatedCheck>)>,
) -> AgentRolloutResult<()> {
    let mut tx = pool.begin().await.map_err(|error| {
        AgentRolloutError::database("SQLite-Postflight konnte nicht gestartet werden", error)
    })?;
    let all_terminal = evaluations.iter().all(|(_, checks)| {
        !checks
            .iter()
            .any(|check| check.detail.get("pending") == Some(&Value::Bool(true)))
    });
    for (target, checks) in &evaluations {
        let failed = checks.iter().any(|check| check.status == "failed");
        let pending = checks
            .iter()
            .any(|check| check.detail.get("pending") == Some(&Value::Bool(true)));
        let new_status = if pending {
            "in_progress"
        } else if failed {
            "failed"
        } else {
            "succeeded"
        };
        ensure_target_transition(&target.status, new_status)?;
        for check in checks {
            sqlx::query("INSERT INTO zero_trust_agent_rollout_check (tenant_id,rollout_id,ring_id,target_id,phase,check_type,status,source,summary,safe_detail_json,actor_id) VALUES (?1,?2,?3,?4,'postflight',?5,?6,'computed',?7,?8,?9)")
                .bind(tenant_id).bind(rollout_id).bind(ring.id).bind(target.id).bind(check.key).bind(check.status).bind(&check.summary).bind(check.detail.to_string()).bind(actor_id).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("SQLite-Postflight-Pruefung konnte nicht gespeichert werden",error))?;
        }
        let result=sqlx::query("UPDATE zero_trust_agent_rollout_target SET status=?1,postflight_status=?2,completed_at=CASE WHEN ?2='pending' THEN NULL ELSE CURRENT_TIMESTAMP END,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?3 AND rollout_id=?4 AND id=?5 AND status=?6")
            .bind(new_status).bind(if pending{"pending"}else if failed{"failed"}else{"passed"}).bind(tenant_id).bind(rollout_id).bind(target.id).bind(&target.status).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("SQLite-Postflight-Zielstatus konnte nicht gespeichert werden",error))?;
        if result.rows_affected() != 1 {
            return Err(concurrent_change());
        }
    }
    if all_terminal && ring.status == "active" {
        let result=sqlx::query("UPDATE zero_trust_agent_rollout_ring SET status='observing',observation_started_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?1 AND rollout_id=?2 AND id=?3 AND status='active'")
            .bind(tenant_id).bind(rollout_id).bind(ring.id).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("SQLite-Beobachtungsphase konnte nicht gestartet werden",error))?;
        if result.rows_affected() != 1 {
            return Err(concurrent_change());
        }
    }
    insert_event_sqlite(
        &mut tx,
        RolloutEventInput {
            tenant_id,
            rollout_id,
            ring_id: Some(ring.id),
            target_id: None,
            event_type: "postflight_evaluated",
            from_status: &ring.status,
            to_status: if all_terminal { "observing" } else { &ring.status },
            actor_id,
            summary: if all_terminal { "Postflight-Gates ausgewertet und Beobachtungsphase gestartet" } else { "Postflight-Gates ausgewertet; aktuelle Agentdaten stehen noch aus" },
            detail: json!({"targets":evaluations.len(),"checks_per_target":10,"all_terminal":all_terminal}),
        },
    )
    .await?;
    tx.commit().await.map_err(|error| {
        AgentRolloutError::database("SQLite-Postflight konnte nicht bestaetigt werden", error)
    })?;
    Ok(())
}

async fn apply_postflight_postgres(
    pool: &PgPool,
    tenant_id: i64,
    rollout_id: i64,
    actor_id: i64,
    ring: &AgentRolloutRing,
    evaluations: Vec<(AgentRolloutTarget, Vec<EvaluatedCheck>)>,
) -> AgentRolloutResult<()> {
    let mut tx = pool.begin().await.map_err(|error| {
        AgentRolloutError::database("PostgreSQL-Postflight konnte nicht gestartet werden", error)
    })?;
    let all_terminal = evaluations.iter().all(|(_, checks)| {
        !checks
            .iter()
            .any(|check| check.detail.get("pending") == Some(&Value::Bool(true)))
    });
    for (target, checks) in &evaluations {
        let failed = checks.iter().any(|check| check.status == "failed");
        let pending = checks
            .iter()
            .any(|check| check.detail.get("pending") == Some(&Value::Bool(true)));
        let new_status = if pending {
            "in_progress"
        } else if failed {
            "failed"
        } else {
            "succeeded"
        };
        ensure_target_transition(&target.status, new_status)?;
        for check in checks {
            sqlx::query("INSERT INTO zero_trust_agent_rollout_check (tenant_id,rollout_id,ring_id,target_id,phase,check_type,status,source,summary,safe_detail_json,actor_id) VALUES ($1,$2,$3,$4,'postflight',$5,$6,'computed',$7,$8::jsonb,$9)")
                .bind(tenant_id).bind(rollout_id).bind(ring.id).bind(target.id).bind(check.key).bind(check.status).bind(&check.summary).bind(check.detail.to_string()).bind(actor_id).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("PostgreSQL-Postflight-Pruefung konnte nicht gespeichert werden",error))?;
        }
        let result=sqlx::query("UPDATE zero_trust_agent_rollout_target SET status=$1,postflight_status=$2,completed_at=CASE WHEN $2='pending' THEN NULL ELSE (CURRENT_TIMESTAMP)::text END,updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$3 AND rollout_id=$4 AND id=$5 AND status=$6")
            .bind(new_status).bind(if pending{"pending"}else if failed{"failed"}else{"passed"}).bind(tenant_id).bind(rollout_id).bind(target.id).bind(&target.status).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("PostgreSQL-Postflight-Zielstatus konnte nicht gespeichert werden",error))?;
        if result.rows_affected() != 1 {
            return Err(concurrent_change());
        }
    }
    if all_terminal && ring.status == "active" {
        let result=sqlx::query("UPDATE zero_trust_agent_rollout_ring SET status='observing',observation_started_at=(CURRENT_TIMESTAMP)::text,updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$1 AND rollout_id=$2 AND id=$3 AND status='active'")
            .bind(tenant_id).bind(rollout_id).bind(ring.id).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("PostgreSQL-Beobachtungsphase konnte nicht gestartet werden",error))?;
        if result.rows_affected() != 1 {
            return Err(concurrent_change());
        }
    }
    insert_event_postgres(
        &mut tx,
        RolloutEventInput {
            tenant_id,
            rollout_id,
            ring_id: Some(ring.id),
            target_id: None,
            event_type: "postflight_evaluated",
            from_status: &ring.status,
            to_status: if all_terminal { "observing" } else { &ring.status },
            actor_id,
            summary: if all_terminal { "Postflight-Gates ausgewertet und Beobachtungsphase gestartet" } else { "Postflight-Gates ausgewertet; aktuelle Agentdaten stehen noch aus" },
            detail: json!({"targets":evaluations.len(),"checks_per_target":10,"all_terminal":all_terminal}),
        },
    )
    .await?;
    tx.commit().await.map_err(|error| {
        AgentRolloutError::database(
            "PostgreSQL-Postflight konnte nicht bestaetigt werden",
            error,
        )
    })?;
    Ok(())
}

struct RingEvaluation<'a> {
    tenant_id: i64,
    rollout_id: i64,
    actor_id: i64,
    ring: &'a AgentRolloutRing,
    next_status: &'a str,
    succeeded: i64,
    failed: i64,
    success_percent: i64,
}

async fn evaluate_ring_sqlite(
    pool: &SqlitePool,
    evaluation: &RingEvaluation<'_>,
) -> AgentRolloutResult<()> {
    let tenant_id = evaluation.tenant_id;
    let rollout_id = evaluation.rollout_id;
    let actor_id = evaluation.actor_id;
    let ring = evaluation.ring;
    let mut tx = pool.begin().await.map_err(|error| {
        AgentRolloutError::database(
            "SQLite-Ring-Auswertung konnte nicht gestartet werden",
            error,
        )
    })?;
    let result=sqlx::query("UPDATE zero_trust_agent_rollout_ring SET status=?1,evaluated_at=CURRENT_TIMESTAMP,completed_at=CASE WHEN ?1 IN ('passed','failed') THEN CURRENT_TIMESTAMP ELSE completed_at END,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?2 AND rollout_id=?3 AND id=?4 AND status='observing'")
        .bind(evaluation.next_status).bind(tenant_id).bind(rollout_id).bind(ring.id).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("SQLite-Ring-Auswertung konnte nicht gespeichert werden",error))?;
    if result.rows_affected() != 1 {
        return Err(concurrent_change());
    }
    if evaluation.next_status == "rollback_required" {
        let result=sqlx::query("UPDATE zero_trust_agent_rollout SET status='rollback_required',rollback_status='prepared',rollback_reason='Ring-Gates ueberschritten',updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?1 AND id=?2 AND status='active'").bind(tenant_id).bind(rollout_id).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("SQLite-Rollback-Bedarf konnte nicht gespeichert werden",error))?;
        if result.rows_affected() != 1 {
            return Err(concurrent_change());
        }
        sqlx::query("UPDATE zero_trust_agent_rollout_target SET status='rollback_required',deployment_status='rollback_required',rollback_status='prepared',updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?1 AND rollout_id=?2 AND ring_id=?3 AND status='succeeded'").bind(tenant_id).bind(rollout_id).bind(ring.id).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("SQLite-Rollback-Ziele konnten nicht markiert werden",error))?;
    } else {
        sqlx::query("UPDATE zero_trust_agent_rollout SET active_ring_name=NULL,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?1 AND id=?2 AND active_ring_name=?3").bind(tenant_id).bind(rollout_id).bind(&ring.ring_name).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("SQLite-aktiver Ring konnte nicht abgeschlossen werden",error))?;
    }
    insert_event_sqlite(&mut tx,RolloutEventInput{tenant_id,rollout_id,ring_id:Some(ring.id),target_id:None,event_type:"ring_evaluated",from_status:"observing",to_status:evaluation.next_status,actor_id,summary:"Beobachtungsphase gegen Ring-Gates ausgewertet",detail:json!({"succeeded":evaluation.succeeded,"failed":evaluation.failed,"success_percent":evaluation.success_percent})}).await?;
    tx.commit().await.map_err(|error| {
        AgentRolloutError::database(
            "SQLite-Ring-Auswertung konnte nicht bestaetigt werden",
            error,
        )
    })?;
    Ok(())
}

async fn evaluate_ring_postgres(
    pool: &PgPool,
    evaluation: &RingEvaluation<'_>,
) -> AgentRolloutResult<()> {
    let tenant_id = evaluation.tenant_id;
    let rollout_id = evaluation.rollout_id;
    let actor_id = evaluation.actor_id;
    let ring = evaluation.ring;
    let mut tx = pool.begin().await.map_err(|error| {
        AgentRolloutError::database(
            "PostgreSQL-Ring-Auswertung konnte nicht gestartet werden",
            error,
        )
    })?;
    let result=sqlx::query("UPDATE zero_trust_agent_rollout_ring SET status=$1,evaluated_at=(CURRENT_TIMESTAMP)::text,completed_at=CASE WHEN $1 IN ('passed','failed') THEN (CURRENT_TIMESTAMP)::text ELSE completed_at END,updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$2 AND rollout_id=$3 AND id=$4 AND status='observing'")
        .bind(evaluation.next_status).bind(tenant_id).bind(rollout_id).bind(ring.id).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("PostgreSQL-Ring-Auswertung konnte nicht gespeichert werden",error))?;
    if result.rows_affected() != 1 {
        return Err(concurrent_change());
    }
    if evaluation.next_status == "rollback_required" {
        let result=sqlx::query("UPDATE zero_trust_agent_rollout SET status='rollback_required',rollback_status='prepared',rollback_reason='Ring-Gates ueberschritten',updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$1 AND id=$2 AND status='active'").bind(tenant_id).bind(rollout_id).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("PostgreSQL-Rollback-Bedarf konnte nicht gespeichert werden",error))?;
        if result.rows_affected() != 1 {
            return Err(concurrent_change());
        }
        sqlx::query("UPDATE zero_trust_agent_rollout_target SET status='rollback_required',deployment_status='rollback_required',rollback_status='prepared',updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$1 AND rollout_id=$2 AND ring_id=$3 AND status='succeeded'").bind(tenant_id).bind(rollout_id).bind(ring.id).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("PostgreSQL-Rollback-Ziele konnten nicht markiert werden",error))?;
    } else {
        sqlx::query("UPDATE zero_trust_agent_rollout SET active_ring_name=NULL,updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$1 AND id=$2 AND active_ring_name=$3").bind(tenant_id).bind(rollout_id).bind(&ring.ring_name).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("PostgreSQL-aktiver Ring konnte nicht abgeschlossen werden",error))?;
    }
    insert_event_postgres(&mut tx,RolloutEventInput{tenant_id,rollout_id,ring_id:Some(ring.id),target_id:None,event_type:"ring_evaluated",from_status:"observing",to_status:evaluation.next_status,actor_id,summary:"Beobachtungsphase gegen Ring-Gates ausgewertet",detail:json!({"succeeded":evaluation.succeeded,"failed":evaluation.failed,"success_percent":evaluation.success_percent})}).await?;
    tx.commit().await.map_err(|error| {
        AgentRolloutError::database(
            "PostgreSQL-Ring-Auswertung konnte nicht bestaetigt werden",
            error,
        )
    })?;
    Ok(())
}

async fn promote_ring_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    rollout_id: i64,
    actor_id: i64,
    ring: &AgentRolloutRing,
    next_ring: Option<&AgentRolloutRing>,
    reason: &str,
) -> AgentRolloutResult<()> {
    let mut tx = pool.begin().await.map_err(|error| {
        AgentRolloutError::database("SQLite-Ring-Freigabe konnte nicht gestartet werden", error)
    })?;
    let approval=sqlx::query("UPDATE zero_trust_agent_rollout_ring SET approved_by_id=?1,approved_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?2 AND rollout_id=?3 AND id=?4 AND status='passed' AND approved_at IS NULL").bind(actor_id).bind(tenant_id).bind(rollout_id).bind(ring.id).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("SQLite-Ring-Freigabe konnte nicht dokumentiert werden",error))?;
    if approval.rows_affected() != 1 {
        return Err(concurrent_change());
    }
    let (to_status, summary) = if next_ring.is_some() {
        (
            "active",
            "Bestandenen Ring manuell fuer den naechsten Ring freigegeben",
        )
    } else {
        let result=sqlx::query("UPDATE zero_trust_agent_rollout SET status='completed',completed_at=CURRENT_TIMESTAMP,approved_by_id=?1,approved_at=CURRENT_TIMESTAMP,active_ring_name=NULL,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?2 AND id=?3 AND status='active'").bind(actor_id).bind(tenant_id).bind(rollout_id).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("SQLite-Rollout konnte nicht abgeschlossen werden",error))?;
        if result.rows_affected() != 1 {
            return Err(concurrent_change());
        }
        (
            "completed",
            "Letzten anwendbaren Ring freigegeben und Rollout abgeschlossen",
        )
    };
    if next_ring.is_some() {
        let result=sqlx::query("UPDATE zero_trust_agent_rollout SET approved_by_id=?1,approved_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?2 AND id=?3 AND status='active'").bind(actor_id).bind(tenant_id).bind(rollout_id).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("SQLite-Ring-Freigabe konnte nicht gespeichert werden",error))?;
        if result.rows_affected() != 1 {
            return Err(concurrent_change());
        }
    }
    insert_event_sqlite(&mut tx,RolloutEventInput{tenant_id,rollout_id,ring_id:Some(ring.id),target_id:None,event_type:"ring_promoted",from_status:"passed",to_status,actor_id,summary,detail:json!({"reason":reason.trim(),"next_ring":next_ring.map(|value|value.ring_name.as_str())})}).await?;
    tx.commit().await.map_err(|error| {
        AgentRolloutError::database("SQLite-Ring-Freigabe konnte nicht bestaetigt werden", error)
    })?;
    Ok(())
}

async fn promote_ring_postgres(
    pool: &PgPool,
    tenant_id: i64,
    rollout_id: i64,
    actor_id: i64,
    ring: &AgentRolloutRing,
    next_ring: Option<&AgentRolloutRing>,
    reason: &str,
) -> AgentRolloutResult<()> {
    let mut tx = pool.begin().await.map_err(|error| {
        AgentRolloutError::database(
            "PostgreSQL-Ring-Freigabe konnte nicht gestartet werden",
            error,
        )
    })?;
    let approval=sqlx::query("UPDATE zero_trust_agent_rollout_ring SET approved_by_id=$1,approved_at=(CURRENT_TIMESTAMP)::text,updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$2 AND rollout_id=$3 AND id=$4 AND status='passed' AND approved_at IS NULL").bind(actor_id).bind(tenant_id).bind(rollout_id).bind(ring.id).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("PostgreSQL-Ring-Freigabe konnte nicht dokumentiert werden",error))?;
    if approval.rows_affected() != 1 {
        return Err(concurrent_change());
    }
    let (to_status, summary) = if next_ring.is_some() {
        (
            "active",
            "Bestandenen Ring manuell fuer den naechsten Ring freigegeben",
        )
    } else {
        let result=sqlx::query("UPDATE zero_trust_agent_rollout SET status='completed',completed_at=(CURRENT_TIMESTAMP)::text,approved_by_id=$1,approved_at=(CURRENT_TIMESTAMP)::text,active_ring_name=NULL,updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$2 AND id=$3 AND status='active'").bind(actor_id).bind(tenant_id).bind(rollout_id).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("PostgreSQL-Rollout konnte nicht abgeschlossen werden",error))?;
        if result.rows_affected() != 1 {
            return Err(concurrent_change());
        }
        (
            "completed",
            "Letzten anwendbaren Ring freigegeben und Rollout abgeschlossen",
        )
    };
    if next_ring.is_some() {
        let result=sqlx::query("UPDATE zero_trust_agent_rollout SET approved_by_id=$1,approved_at=(CURRENT_TIMESTAMP)::text,updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$2 AND id=$3 AND status='active'").bind(actor_id).bind(tenant_id).bind(rollout_id).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("PostgreSQL-Ring-Freigabe konnte nicht gespeichert werden",error))?;
        if result.rows_affected() != 1 {
            return Err(concurrent_change());
        }
    }
    insert_event_postgres(&mut tx,RolloutEventInput{tenant_id,rollout_id,ring_id:Some(ring.id),target_id:None,event_type:"ring_promoted",from_status:"passed",to_status,actor_id,summary,detail:json!({"reason":reason.trim(),"next_ring":next_ring.map(|value|value.ring_name.as_str())})}).await?;
    tx.commit().await.map_err(|error| {
        AgentRolloutError::database(
            "PostgreSQL-Ring-Freigabe konnte nicht bestaetigt werden",
            error,
        )
    })?;
    Ok(())
}

struct RolloutStateChange<'a> {
    tenant_id: i64,
    rollout_id: i64,
    actor_id: i64,
    from: &'a str,
    to: &'a str,
    event_type: &'a str,
    reason: &'a str,
}

impl AgentRolloutStore {
    pub async fn pause(
        &self,
        tenant_id: i64,
        rollout_id: i64,
        actor_id: i64,
        request: AgentRolloutConfirmationRequest,
    ) -> AgentRolloutResult<AgentRolloutDetail> {
        require_confirmation(
            &request,
            "Das Pausieren muss mit einer Begruendung bestaetigt werden.",
        )?;
        self.change_rollout_state(RolloutStateChange {
            tenant_id,
            rollout_id,
            actor_id,
            from: "active",
            to: "paused",
            event_type: "rollout_paused",
            reason: &request.reason,
        })
        .await?;
        self.detail(tenant_id, rollout_id).await
    }

    pub async fn resume(
        &self,
        tenant_id: i64,
        rollout_id: i64,
        actor_id: i64,
        request: AgentRolloutConfirmationRequest,
    ) -> AgentRolloutResult<AgentRolloutDetail> {
        require_confirmation(
            &request,
            "Das Fortsetzen muss mit einer Begruendung bestaetigt werden.",
        )?;
        self.change_rollout_state(RolloutStateChange {
            tenant_id,
            rollout_id,
            actor_id,
            from: "paused",
            to: "active",
            event_type: "rollout_resumed",
            reason: &request.reason,
        })
        .await?;
        self.detail(tenant_id, rollout_id).await
    }

    pub async fn abort(
        &self,
        tenant_id: i64,
        rollout_id: i64,
        actor_id: i64,
        request: AgentRolloutConfirmationRequest,
    ) -> AgentRolloutResult<AgentRolloutDetail> {
        require_confirmation(
            &request,
            "Der Abbruch muss mit einer Begruendung bestaetigt werden.",
        )?;
        let current = self.rollout(tenant_id, rollout_id).await?;
        if !matches!(
            current.status.as_str(),
            "draft" | "ready" | "active" | "paused" | "rollback_required"
        ) {
            return Err(invalid_transition(
                "Dieser Rollout kann nicht abgebrochen werden.",
            ));
        }
        ensure_rollout_transition(&current.status, "aborted")?;
        match self {
            Self::Sqlite(pool) => {
                abort_sqlite(
                    pool,
                    tenant_id,
                    rollout_id,
                    actor_id,
                    &current.status,
                    &request.reason,
                )
                .await?
            }
            Self::Postgres(pool) => {
                abort_postgres(
                    pool,
                    tenant_id,
                    rollout_id,
                    actor_id,
                    &current.status,
                    &request.reason,
                )
                .await?
            }
        }
        self.detail(tenant_id, rollout_id).await
    }

    async fn change_rollout_state(&self, change: RolloutStateChange<'_>) -> AgentRolloutResult<()> {
        let RolloutStateChange {
            tenant_id,
            rollout_id,
            actor_id,
            from,
            to,
            event_type,
            reason,
        } = change;
        let current = self.rollout(tenant_id, rollout_id).await?;
        if current.status != from {
            return Err(invalid_transition(
                "Der Rollout befindet sich nicht im erwarteten Ausgangsstatus.",
            ));
        }
        ensure_rollout_transition(from, to)?;
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin().await.map_err(|error| {
                    AgentRolloutError::database(
                        "SQLite-Statuswechsel konnte nicht gestartet werden",
                        error,
                    )
                })?;
                let result=sqlx::query("UPDATE zero_trust_agent_rollout SET status=?1,paused_at=CASE WHEN ?1='paused' THEN CURRENT_TIMESTAMP ELSE paused_at END,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?2 AND id=?3 AND status=?4").bind(to).bind(tenant_id).bind(rollout_id).bind(from).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("SQLite-Statuswechsel konnte nicht gespeichert werden",error))?;
                if result.rows_affected() != 1 {
                    return Err(concurrent_change());
                }
                insert_event_sqlite(
                    &mut tx,
                    RolloutEventInput {
                        tenant_id,
                        rollout_id,
                        ring_id: None,
                        target_id: None,
                        event_type,
                        from_status: from,
                        to_status: to,
                        actor_id,
                        summary: "Rollout-Status manuell geaendert",
                        detail: json!({"reason":reason.trim()}),
                    },
                )
                .await?;
                tx.commit().await.map_err(|error| {
                    AgentRolloutError::database(
                        "SQLite-Statuswechsel konnte nicht bestaetigt werden",
                        error,
                    )
                })?;
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await.map_err(|error| {
                    AgentRolloutError::database(
                        "PostgreSQL-Statuswechsel konnte nicht gestartet werden",
                        error,
                    )
                })?;
                let result=sqlx::query("UPDATE zero_trust_agent_rollout SET status=$1,paused_at=CASE WHEN $1='paused' THEN (CURRENT_TIMESTAMP)::text ELSE paused_at END,updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$2 AND id=$3 AND status=$4").bind(to).bind(tenant_id).bind(rollout_id).bind(from).execute(&mut *tx).await.map_err(|error|AgentRolloutError::database("PostgreSQL-Statuswechsel konnte nicht gespeichert werden",error))?;
                if result.rows_affected() != 1 {
                    return Err(concurrent_change());
                }
                insert_event_postgres(
                    &mut tx,
                    RolloutEventInput {
                        tenant_id,
                        rollout_id,
                        ring_id: None,
                        target_id: None,
                        event_type,
                        from_status: from,
                        to_status: to,
                        actor_id,
                        summary: "Rollout-Status manuell geaendert",
                        detail: json!({"reason":reason.trim()}),
                    },
                )
                .await?;
                tx.commit().await.map_err(|error| {
                    AgentRolloutError::database(
                        "PostgreSQL-Statuswechsel konnte nicht bestaetigt werden",
                        error,
                    )
                })?;
            }
        }
        Ok(())
    }

    pub async fn request_rollback(
        &self,
        tenant_id: i64,
        rollout_id: i64,
        actor_id: i64,
        mut request: AgentRolloutRollbackRequest,
    ) -> AgentRolloutResult<AgentRolloutDetail> {
        if !request.confirmed || request.reason.trim().is_empty() {
            return Err(invalid_input(
                "Der Rollback muss mit einer Begruendung bestaetigt werden.",
            ));
        }
        request.reason = request.reason.trim().to_string();
        let detail = self.detail(tenant_id, rollout_id).await?;
        if !matches!(
            detail.rollout.status.as_str(),
            "active" | "paused" | "rollback_required"
        ) {
            return Err(invalid_transition(
                "Fuer diesen Rollout kann kein Rollback angefordert werden.",
            ));
        }
        let selected = select_rollback_targets(&detail, &request)?;
        if selected.is_empty() {
            return Err(gate_blocked(
                "Es wurden keine rollback-faehigen Ziele ausgewaehlt.",
            ));
        }
        match self {
            Self::Sqlite(pool) => {
                request_rollback_sqlite(
                    pool,
                    tenant_id,
                    rollout_id,
                    actor_id,
                    &detail,
                    selected,
                    &request.reason,
                )
                .await?
            }
            Self::Postgres(pool) => {
                request_rollback_postgres(
                    pool,
                    tenant_id,
                    rollout_id,
                    actor_id,
                    &detail,
                    selected,
                    &request.reason,
                )
                .await?
            }
        }
        self.detail(tenant_id, rollout_id).await
    }

    pub async fn complete_rollback(
        &self,
        tenant_id: i64,
        rollout_id: i64,
        actor_id: i64,
        request: AgentRolloutRollbackCompleteRequest,
    ) -> AgentRolloutResult<AgentRolloutDetail> {
        if !request.confirmed || request.results.is_empty() {
            return Err(invalid_input(
                "Rollback-Ergebnisse muessen ausdruecklich bestaetigt werden.",
            ));
        }
        let detail = self.detail(tenant_id, rollout_id).await?;
        if detail.rollout.status != "rollback_required"
            || !matches!(
                detail.rollout.rollback_status.as_str(),
                "requested" | "in_progress"
            )
        {
            return Err(invalid_transition(
                "Der Rollout erwartet derzeit keine Rollback-Ergebnisse.",
            ));
        }
        for result in &request.results {
            if !matches!(result.status.as_str(), "rolled_back" | "failed") {
                return Err(invalid_input(
                    "Ein Rollback-Ergebnis muss rolled_back oder failed sein.",
                ));
            }
            let target = detail
                .targets
                .iter()
                .find(|target| target.id == result.target_id)
                .ok_or_else(|| foreign_reference("Ein Rollback-Ziel wurde nicht gefunden."))?;
            if target.status != "rollback_required" {
                return Err(invalid_transition(
                    "Ein ausgewaehltes Ziel erwartet keinen Rollback.",
                ));
            }
        }
        match self {
            Self::Sqlite(pool) => {
                complete_rollback_sqlite(pool, tenant_id, rollout_id, actor_id, &request).await?
            }
            Self::Postgres(pool) => {
                complete_rollback_postgres(pool, tenant_id, rollout_id, actor_id, &request).await?
            }
        }
        self.detail(tenant_id, rollout_id).await
    }

    pub async fn operations_summary(
        &self,
        tenant_id: i64,
    ) -> AgentRolloutResult<AgentRolloutOperationsSummary> {
        match self {
            Self::Sqlite(pool) => {
                let row=sqlx::query(r#"SELECT
                    (SELECT COUNT(*) FROM zero_trust_agent_rollout WHERE tenant_id=?1 AND status='active') active_rollouts,
                    (SELECT COUNT(*) FROM zero_trust_agent_rollout WHERE tenant_id=?1 AND status='paused') paused_rollouts,
                    (SELECT COUNT(*) FROM zero_trust_agent_rollout WHERE tenant_id=?1 AND status='rollback_required') rollback_required_rollouts,
                    (SELECT COUNT(*) FROM zero_trust_agent_rollout_ring WHERE tenant_id=?1 AND status IN ('failed','rollback_required')) blocked_rings,
                    (SELECT COUNT(*) FROM zero_trust_agent_rollout_target WHERE tenant_id=?1 AND status='failed') failed_targets"#).bind(tenant_id).fetch_one(pool).await.map_err(|error|AgentRolloutError::database("SQLite-Rollout-Betriebsstatus konnte nicht gelesen werden",error))?;
                Ok(AgentRolloutOperationsSummary {
                    active_rollouts: get_sqlite(&row, "active_rollouts")?,
                    paused_rollouts: get_sqlite(&row, "paused_rollouts")?,
                    rollback_required_rollouts: get_sqlite(&row, "rollback_required_rollouts")?,
                    blocked_rings: get_sqlite(&row, "blocked_rings")?,
                    failed_targets: get_sqlite(&row, "failed_targets")?,
                })
            }
            Self::Postgres(pool) => {
                let row=sqlx::query(r#"SELECT
                    (SELECT COUNT(*)::bigint FROM zero_trust_agent_rollout WHERE tenant_id=$1 AND status='active') active_rollouts,
                    (SELECT COUNT(*)::bigint FROM zero_trust_agent_rollout WHERE tenant_id=$1 AND status='paused') paused_rollouts,
                    (SELECT COUNT(*)::bigint FROM zero_trust_agent_rollout WHERE tenant_id=$1 AND status='rollback_required') rollback_required_rollouts,
                    (SELECT COUNT(*)::bigint FROM zero_trust_agent_rollout_ring WHERE tenant_id=$1 AND status IN ('failed','rollback_required')) blocked_rings,
                    (SELECT COUNT(*)::bigint FROM zero_trust_agent_rollout_target WHERE tenant_id=$1 AND status='failed') failed_targets"#).bind(tenant_id).fetch_one(pool).await.map_err(|error|AgentRolloutError::database("PostgreSQL-Rollout-Betriebsstatus konnte nicht gelesen werden",error))?;
                Ok(AgentRolloutOperationsSummary {
                    active_rollouts: get_postgres(&row, "active_rollouts")?,
                    paused_rollouts: get_postgres(&row, "paused_rollouts")?,
                    rollback_required_rollouts: get_postgres(&row, "rollback_required_rollouts")?,
                    blocked_rings: get_postgres(&row, "blocked_rings")?,
                    failed_targets: get_postgres(&row, "failed_targets")?,
                })
            }
        }
    }
}

fn device_facts_from_sqlite_row(row: SqliteRow) -> AgentRolloutResult<DeviceFacts> {
    Ok(DeviceFacts {
        id: get_sqlite(&row, "id")?,
        hostname: get_sqlite(&row, "hostname")?,
        os_family: get_sqlite(&row, "os_family")?,
        deployment_channel: get_sqlite(&row, "deployment_channel")?,
        agent_version: get_sqlite(&row, "agent_version")?,
        enrollment_status: get_sqlite(&row, "enrollment_status")?,
        zero_trust_score: get_sqlite(&row, "zero_trust_score")?,
        last_seen_at: get_sqlite(&row, "last_seen_at")?,
        policy_profile_id: get_sqlite(&row, "policy_profile_id")?,
        critical_findings: get_sqlite(&row, "critical_findings")?,
        high_findings: get_sqlite(&row, "high_findings")?,
        certificate_status: get_sqlite(&row, "certificate_status")?,
        mtls_binding_status: get_sqlite(&row, "mtls_binding_status")?,
        other_active_rollouts: get_sqlite(&row, "other_active_rollouts")?,
    })
}

fn device_facts_from_postgres_row(row: PgRow) -> AgentRolloutResult<DeviceFacts> {
    Ok(DeviceFacts {
        id: get_postgres(&row, "id")?,
        hostname: get_postgres(&row, "hostname")?,
        os_family: get_postgres(&row, "os_family")?,
        deployment_channel: get_postgres(&row, "deployment_channel")?,
        agent_version: get_postgres(&row, "agent_version")?,
        enrollment_status: get_postgres(&row, "enrollment_status")?,
        zero_trust_score: get_postgres_integer(&row, "zero_trust_score")?,
        last_seen_at: get_postgres(&row, "last_seen_at")?,
        policy_profile_id: get_postgres(&row, "policy_profile_id")?,
        critical_findings: get_postgres(&row, "critical_findings")?,
        high_findings: get_postgres(&row, "high_findings")?,
        certificate_status: get_postgres(&row, "certificate_status")?,
        mtls_binding_status: get_postgres(&row, "mtls_binding_status")?,
        other_active_rollouts: get_postgres(&row, "other_active_rollouts")?,
    })
}

fn evaluate_preflight(
    rollout: &AgentRollout,
    device: &DeviceFacts,
    artifact: Option<&(String, String, String)>,
) -> Vec<EvaluatedCheck> {
    let heartbeat_age = device
        .last_seen_at
        .as_deref()
        .and_then(parse_timestamp)
        .map(|seen| Utc::now().signed_duration_since(seen).num_minutes());
    let artifact_present = artifact.is_some();
    let checksum_present = artifact.is_some_and(|value| {
        value.0.len() == 64 && value.0.bytes().all(|byte| byte.is_ascii_hexdigit())
    });
    let checksum_verified = artifact.is_some_and(|value| value.2 == "verified");
    let signature_ok = match rollout.signature_requirement.as_str() {
        "not_required" => true,
        "metadata_only" => {
            artifact.is_none() || artifact.is_some_and(|value| !value.1.trim().is_empty())
        }
        "verified_required" => {
            artifact.is_some_and(|value| matches!(value.1.as_str(), "verified" | "valid"))
        }
        _ => false,
    };
    let certificate_ok = match rollout.certificate_requirement.as_str() {
        "not_required" => true,
        "active_required" => device.certificate_status == "active",
        "mtls_bound_required" => {
            device.certificate_status == "active" && device.mtls_binding_status == "bound"
        }
        _ => false,
    };
    let mtls_ok = rollout.certificate_requirement != "mtls_bound_required"
        || device.mtls_binding_status == "bound";
    vec![
        bool_check(
            "enrollment.active",
            device.enrollment_status == "ACTIVE",
            "Agent ist aktiv eingeschrieben.",
            "Agent ist nicht aktiv eingeschrieben.",
        ),
        bool_check(
            "scope.os",
            rollout.os_family_filter.is_empty() || rollout.os_family_filter == device.os_family,
            "Betriebssystem passt zum Rollout-Scope.",
            "Betriebssystem liegt ausserhalb des Rollout-Scopes.",
        ),
        bool_check(
            "scope.channel",
            rollout.deployment_channel_filter.is_empty()
                || rollout.deployment_channel_filter == device.deployment_channel,
            "Deployment-Kanal passt zum Scope.",
            "Deployment-Kanal liegt ausserhalb des Rollout-Scopes.",
        ),
        bool_check(
            "policy.assignment",
            rollout.policy_profile_id.is_none()
                || rollout.policy_profile_id == device.policy_profile_id,
            "Policy-Profil passt zum Ziel.",
            "Policy-Profil passt nicht zum Ziel.",
        ),
        bool_check(
            "heartbeat.present",
            device.last_seen_at.is_some(),
            "Ein Agent-Heartbeat ist vorhanden.",
            "Es ist kein Agent-Heartbeat vorhanden.",
        ),
        bool_check(
            "heartbeat.fresh",
            heartbeat_age.is_some_and(|minutes| {
                minutes >= 0 && minutes <= rollout.heartbeat_freshness_minutes
            }),
            "Der Agent-Heartbeat ist frisch.",
            "Der Agent-Heartbeat ist zu alt oder ungueltig.",
        ),
        bool_check(
            "posture.minimum_score",
            device.zero_trust_score >= rollout.minimum_zero_trust_score,
            "Der Zero-Trust-Score erreicht den Mindestwert.",
            "Der Zero-Trust-Score unterschreitet den Mindestwert.",
        ),
        bool_check(
            "findings.critical_threshold",
            device.critical_findings <= rollout.maximum_critical_findings,
            "Die kritischen Findings liegen innerhalb des Grenzwerts.",
            "Kritische Findings ueberschreiten den Rollout-Grenzwert.",
        ),
        bool_check(
            "rollback.none",
            rollout.rollback_status == "not_required",
            "Keine offene Rollback-Pflicht fuer diesen Rollout.",
            "Eine offene Rollback-Pflicht blockiert das Ziel.",
        ),
        bool_check(
            "version.current_known",
            !device.agent_version.trim().is_empty(),
            "Die aktuelle Agent-Version ist bekannt.",
            "Die aktuelle Agent-Version ist nicht bekannt.",
        ),
        bool_check(
            "version.change_required",
            device.agent_version != rollout.target_agent_version,
            "Die Zielversion unterscheidet sich von der Ist-Version.",
            "Die Zielversion ist bereits installiert.",
        ),
        bool_or_na_check(
            "artifact.available",
            rollout.artifact_id.is_some()
                || rollout.require_verified_artifact_checksum
                || rollout.signature_requirement != "not_required",
            artifact_present,
            "Das konfigurierte Release-Artefakt ist vorhanden.",
            "Das konfigurierte Release-Artefakt fehlt.",
        ),
        bool_or_na_check(
            "artifact.checksum_present",
            rollout.require_verified_artifact_checksum,
            checksum_present,
            "Ein SHA-256-Pruefwert ist vorhanden.",
            "Der SHA-256-Pruefwert fehlt oder ist ungueltig.",
        ),
        bool_or_na_check(
            "artifact.checksum_verified",
            rollout.require_verified_artifact_checksum,
            checksum_verified,
            "Der Artefakt-Pruefstatus ist verwendbar.",
            "Der Artefakt-Pruefstatus blockiert den Rollout.",
        ),
        bool_or_na_check(
            "artifact.signature",
            rollout.signature_requirement != "not_required",
            signature_ok,
            "Die konfigurierte Signaturanforderung ist erfuellt.",
            "Die konfigurierte Signaturanforderung ist nicht erfuellt.",
        ),
        bool_or_na_check(
            "pki.certificate",
            rollout.certificate_requirement != "not_required",
            certificate_ok,
            "Die Zertifikatsanforderung ist erfuellt.",
            "Die Zertifikatsanforderung ist nicht erfuellt.",
        ),
        bool_or_na_check(
            "pki.mtls_binding",
            rollout.certificate_requirement == "mtls_bound_required",
            mtls_ok,
            "Die mTLS-Bindung ist aktiv.",
            "Die mTLS-Bindung ist nicht aktiv.",
        ),
        bool_check(
            "rollout.exclusive",
            device.other_active_rollouts == 0,
            "Das Ziel ist keinem konkurrierenden aktiven Rollout zugeordnet.",
            "Ein konkurrierender aktiver Rollout blockiert dieses Ziel.",
        ),
    ]
}

fn bool_check(
    key: &'static str,
    passed: bool,
    pass_summary: &str,
    fail_summary: &str,
) -> EvaluatedCheck {
    EvaluatedCheck {
        key,
        status: if passed { "passed" } else { "failed" },
        summary: if passed { pass_summary } else { fail_summary }.to_string(),
        detail: json!({}),
    }
}

fn warning_check(
    key: &'static str,
    passed: bool,
    pass_summary: &str,
    warning_summary: &str,
) -> EvaluatedCheck {
    EvaluatedCheck {
        key,
        status: if passed { "passed" } else { "warning" },
        summary: if passed {
            pass_summary
        } else {
            warning_summary
        }
        .to_string(),
        detail: json!({}),
    }
}

fn bool_or_na_check(
    key: &'static str,
    applicable: bool,
    passed: bool,
    pass_summary: &str,
    fail_summary: &str,
) -> EvaluatedCheck {
    if applicable {
        bool_check(key, passed, pass_summary, fail_summary)
    } else {
        EvaluatedCheck {
            key,
            status: "not_applicable",
            summary: "Diese Pruefung ist fuer den Rollout nicht anwendbar.".to_string(),
            detail: json!({}),
        }
    }
}

fn parse_timestamp(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
        .or_else(|| {
            DateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f%#z")
                .ok()
                .map(|value| value.with_timezone(&Utc))
        })
        .or_else(|| {
            NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f")
                .ok()
                .map(|value| value.and_utc())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rollout_fixture() -> AgentRollout {
        AgentRollout {
            id: 1,
            tenant_id: 1,
            name: "Rollout fixture".to_string(),
            description: String::new(),
            target_agent_version: "1.4.0".to_string(),
            rollback_plan: "Operator follows the approved recovery procedure.".to_string(),
            artifact_id: None,
            policy_profile_id: None,
            owner_id: Some(1),
            status: "draft".to_string(),
            active_ring_name: None,
            os_family_filter: "LINUX".to_string(),
            deployment_channel_filter: "systemd".to_string(),
            minimum_zero_trust_score: 80,
            heartbeat_freshness_minutes: 60,
            maximum_critical_findings: 0,
            require_verified_artifact_checksum: false,
            signature_requirement: "not_required".to_string(),
            certificate_requirement: "not_required".to_string(),
            minimum_success_percent: 95,
            observation_minutes: 30,
            max_failed_targets: 0,
            rollback_status: "not_required".to_string(),
            rollback_reason: String::new(),
            created_by_id: Some(1),
            approved_by_id: None,
            approved_at: None,
            paused_at: None,
            completed_at: None,
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
        }
    }

    fn device_fixture() -> DeviceFacts {
        DeviceFacts {
            id: 1,
            hostname: "rollout-fixture".to_string(),
            os_family: "LINUX".to_string(),
            deployment_channel: "systemd".to_string(),
            agent_version: "1.3.0".to_string(),
            enrollment_status: "ACTIVE".to_string(),
            zero_trust_score: 95,
            last_seen_at: Some(Utc::now().to_rfc3339()),
            policy_profile_id: None,
            critical_findings: 0,
            high_findings: 0,
            certificate_status: String::new(),
            mtls_binding_status: String::new(),
            other_active_rollouts: 0,
        }
    }

    fn target_fixture() -> AgentRolloutTarget {
        AgentRolloutTarget {
            id: 1,
            rollout_id: 1,
            ring_id: 1,
            ring_name: "lab".to_string(),
            device_id: 1,
            hostname: "rollout-fixture".to_string(),
            os_family: "LINUX".to_string(),
            current_agent_version: "1.3.0".to_string(),
            status: "in_progress".to_string(),
            eligibility_reason: String::new(),
            preflight_status: "passed".to_string(),
            postflight_status: "pending".to_string(),
            deployment_status: "succeeded".to_string(),
            previous_agent_version: "1.3.0".to_string(),
            expected_agent_version: "1.4.0".to_string(),
            observed_agent_version: "1.4.0".to_string(),
            deployment_reference: String::new(),
            result_summary: String::new(),
            eligibility_status: "eligible".to_string(),
            rollback_status: "not_required".to_string(),
            error_class: String::new(),
            operator_note: String::new(),
            rollback_requested_at: None,
            rollback_completed_at: None,
            deployment_recorded_at: Some(Utc::now().to_rfc3339()),
            completed_at: None,
        }
    }

    fn check_status<'a>(checks: &'a [EvaluatedCheck], key: &str) -> &'a str {
        checks
            .iter()
            .find(|check| check.key == key)
            .map(|check| check.status)
            .expect("expected gate check")
    }

    #[test]
    fn canonical_rings_and_transition_matrices_are_closed() {
        assert_eq!(
            CANONICAL_ROLLOUT_RINGS,
            [
                ("lab", 10),
                ("canary", 20),
                ("pilot", 30),
                ("production", 40),
                ("critical", 50)
            ]
        );
        assert!(rollout_transition_allowed("draft", "ready"));
        assert!(!rollout_transition_allowed("draft", "completed"));
        assert!(ring_transition_allowed("observing", "passed"));
        assert!(!ring_transition_allowed("pending", "passed"));
        assert!(target_transition_allowed("scheduled", "in_progress"));
        assert!(!target_transition_allowed("pending", "succeeded"));
    }

    #[test]
    fn postgres_integer_values_widen_without_loss() {
        assert_eq!(widen_postgres_integer(i32::MIN), i64::from(i32::MIN));
        assert_eq!(widen_postgres_integer(0), 0);
        assert_eq!(widen_postgres_integer(i32::MAX), i64::from(i32::MAX));
    }

    #[test]
    fn postgres_text_timestamps_round_trip_through_rollout_gates() {
        let timestamp = parse_timestamp("2026-07-17 22:08:49.829836+00")
            .expect("PostgreSQL timestamp text must be readable");
        assert_eq!(timestamp.to_rfc3339(), "2026-07-17T22:08:49.829836+00:00");
        assert!(parse_timestamp("2026-07-17 22:08:49.829836").is_some());
    }

    #[test]
    fn write_validation_rejects_unknown_ring_and_status_inputs() {
        assert!(validate_ring_name("wave-1").is_err());
        assert!(validate_member("Status", "executing", ROLLOUT_STATUSES).is_err());
        assert!(validate_os_filter("solaris").is_err());
        assert!(!safe_operator_text("Authorization: Bearer secret"));
        let unsafe_local_path = ["/", "home", "/", "operator", "/", "raw.log"].concat();
        assert!(!safe_operator_text(&unsafe_local_path));
        assert!(safe_operator_text("Externes Ergebnis geprueft."));
    }

    #[test]
    fn preflight_gates_fail_closed_for_each_existing_agent_signal() {
        let rollout = rollout_fixture();
        let mut device = device_fixture();
        let passed = evaluate_preflight(&rollout, &device, None);
        assert_eq!(passed.len(), 18);
        assert!(!passed.iter().any(|check| check.status == "failed"));

        device.last_seen_at = Some((Utc::now() - Duration::hours(2)).to_rfc3339());
        assert_eq!(
            check_status(
                &evaluate_preflight(&rollout, &device, None),
                "heartbeat.fresh"
            ),
            "failed"
        );
        device = device_fixture();
        device.zero_trust_score = 79;
        assert_eq!(
            check_status(
                &evaluate_preflight(&rollout, &device, None),
                "posture.minimum_score"
            ),
            "failed"
        );
        device = device_fixture();
        device.critical_findings = 1;
        assert_eq!(
            check_status(
                &evaluate_preflight(&rollout, &device, None),
                "findings.critical_threshold"
            ),
            "failed"
        );
        device = device_fixture();
        device.os_family = "WINDOWS".to_string();
        assert_eq!(
            check_status(&evaluate_preflight(&rollout, &device, None), "scope.os"),
            "failed"
        );
        device = device_fixture();
        device.deployment_channel = "manual".to_string();
        assert_eq!(
            check_status(
                &evaluate_preflight(&rollout, &device, None),
                "scope.channel"
            ),
            "failed"
        );

        let mut governed = rollout_fixture();
        governed.policy_profile_id = Some(7);
        assert_eq!(
            check_status(
                &evaluate_preflight(&governed, &device_fixture(), None),
                "policy.assignment"
            ),
            "failed"
        );
        governed.policy_profile_id = None;
        governed.artifact_id = Some("artifact-1".to_string());
        governed.require_verified_artifact_checksum = true;
        governed.signature_requirement = "verified_required".to_string();
        let invalid_artifact = (
            "bad-checksum".to_string(),
            "unsigned".to_string(),
            "failed".to_string(),
        );
        let artifact_checks =
            evaluate_preflight(&governed, &device_fixture(), Some(&invalid_artifact));
        for key in [
            "artifact.checksum_present",
            "artifact.checksum_verified",
            "artifact.signature",
        ] {
            assert_eq!(check_status(&artifact_checks, key), "failed", "{key}");
        }

        governed.require_verified_artifact_checksum = false;
        governed.signature_requirement = "not_required".to_string();
        governed.certificate_requirement = "mtls_bound_required".to_string();
        let pki_checks = evaluate_preflight(&governed, &device_fixture(), None);
        assert_eq!(check_status(&pki_checks, "pki.certificate"), "failed");
        assert_eq!(check_status(&pki_checks, "pki.mtls_binding"), "failed");

        let mut exclusive = device_fixture();
        exclusive.other_active_rollouts = 1;
        assert_eq!(
            check_status(
                &evaluate_preflight(&rollout, &exclusive, None),
                "rollout.exclusive"
            ),
            "failed"
        );
    }

    #[test]
    fn postflight_requires_current_heartbeat_and_target_version() {
        let rollout = rollout_fixture();
        let target = target_fixture();
        let mut device = device_fixture();
        device.agent_version = "1.4.0".to_string();
        device.last_seen_at = target.deployment_recorded_at.clone();
        let passed = evaluate_postflight(&rollout, &target, &device);
        assert_eq!(passed.len(), 10);
        assert!(!passed.iter().any(|check| check.status == "failed"));

        device.last_seen_at = None;
        let pending = evaluate_postflight(&rollout, &target, &device);
        assert_eq!(
            check_status(&pending, "heartbeat.after_deployment"),
            "warning"
        );
        assert!(pending
            .iter()
            .find(|check| check.key == "heartbeat.after_deployment")
            .and_then(|check| check.detail.get("pending"))
            .is_some_and(|value| value == &Value::Bool(true)));

        device = device_fixture();
        let mut no_observed_version = target_fixture();
        no_observed_version.observed_agent_version.clear();
        let wrong_version = evaluate_postflight(&rollout, &no_observed_version, &device);
        assert_eq!(
            check_status(&wrong_version, "version.target_observed"),
            "failed"
        );
    }
}
