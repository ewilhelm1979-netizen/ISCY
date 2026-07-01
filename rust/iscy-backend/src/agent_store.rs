use anyhow::{bail, Context};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Postgres, Row, Sqlite, Transaction,
};

use crate::cve_store::normalize_database_url;

const AGENT_OS_FAMILIES: &[&str] = &["WINDOWS", "LINUX", "MACOS"];
const ONBOARDING_OS_FAMILIES: &[&str] = &["WINDOWS", "LINUX", "MACOS", "NIXOS"];
const AGENT_DEPLOYMENT_CHANNELS: &[&str] =
    &["manual", "systemd", "nixos", "intune", "jamf", "other"];

#[derive(Clone)]
pub enum AgentStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentEnrollRequest {
    pub asset_id: Option<i64>,
    pub stable_device_id: String,
    pub hostname: String,
    pub os_family: String,
    pub os_version: String,
    pub architecture: String,
    pub agent_version: String,
    pub deployment_channel: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentEnrollmentTokenCreateRequest {
    pub label: Option<String>,
    pub rollout_os_family: Option<String>,
    pub allowed_os_families: Option<Vec<String>>,
    pub allowed_deployment_channel: Option<String>,
    pub policy_profile_id: Option<i64>,
    pub mtls_fingerprint: Option<String>,
    pub expires_at: Option<String>,
    pub uses_remaining: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentEnrollmentTokenCreateResult {
    pub token: String,
    pub enrollment: AgentEnrollmentTokenSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentEnrollmentTokenSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub label: String,
    pub token_hint: String,
    pub status: String,
    pub rollout_os_family: String,
    pub allowed_os_families: Vec<String>,
    pub allowed_deployment_channel: String,
    pub policy_profile_id: Option<i64>,
    pub policy_name: Option<String>,
    pub mtls_fingerprint: String,
    pub expires_at: Option<String>,
    pub max_uses: i64,
    pub uses_count: i64,
    pub uses_remaining: Option<i64>,
    pub created_by_id: Option<i64>,
    pub last_attempt_at: Option<String>,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentEnrollWithSecret {
    pub device: AgentDeviceSummary,
    pub agent_secret: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentSecretRotationResult {
    pub device: AgentDeviceSummary,
    pub agent_secret: String,
}

#[derive(Debug, Clone)]
struct EnrollmentTokenGrant {
    id: i64,
    policy_profile_id: Option<i64>,
    mtls_fingerprint: String,
    status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentEnrollmentAuditEvent {
    pub id: i64,
    pub tenant_id: i64,
    pub token_id: Option<i64>,
    pub device_id: Option<i64>,
    pub event_type: String,
    pub actor_id: Option<i64>,
    pub detail: Value,
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentHeartbeatRequest {
    pub observed_at: Option<String>,
    pub agent_version: Option<String>,
    pub status: Option<String>,
    pub summary: Option<Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentFindingsRequest {
    pub findings: Vec<AgentFindingInput>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentFindingInput {
    pub check_id: String,
    pub pillar: String,
    pub severity: String,
    pub status: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub recommendation: Option<String>,
    pub evidence: Option<Value>,
    pub observed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentDeviceSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub asset_id: Option<i64>,
    pub stable_device_id: String,
    pub hostname: String,
    pub os_family: String,
    pub os_version: String,
    pub architecture: String,
    pub agent_version: String,
    pub deployment_channel: String,
    pub enrollment_status: String,
    pub policy_profile_id: Option<i64>,
    pub policy_name: Option<String>,
    pub enrollment_token_id: Option<i64>,
    pub last_enrolled_at: Option<String>,
    pub mtls_bound: bool,
    pub zero_trust_score: i64,
    pub last_seen_at: Option<String>,
    pub open_finding_count: i64,
    pub critical_finding_count: i64,
    pub high_finding_count: i64,
    pub finding_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentFindingSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub device_id: i64,
    pub hostname: Option<String>,
    pub check_id: String,
    pub pillar: String,
    pub severity: String,
    pub severity_label: String,
    pub status: String,
    pub status_label: String,
    pub title: String,
    pub description: String,
    pub recommendation: String,
    pub evidence: Value,
    pub risk_id: Option<i64>,
    pub evidence_item_id: Option<i64>,
    pub observed_at: String,
    pub resolved_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentHeartbeatSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub device_id: i64,
    pub observed_at: String,
    pub agent_version: String,
    pub status: String,
    pub summary: Value,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentCheckCatalogItem {
    pub check_id: String,
    pub pillar: String,
    pub title: String,
    pub description: String,
    pub platform_scope: String,
    pub severity: String,
    pub recommendation: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentPillarScore {
    pub pillar: String,
    pub score: i64,
    pub open_finding_count: i64,
    pub critical_finding_count: i64,
    pub high_finding_count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentPostureOverview {
    pub tenant_id: i64,
    pub device_count: i64,
    pub active_device_count: i64,
    pub stale_device_count: i64,
    pub open_finding_count: i64,
    pub critical_finding_count: i64,
    pub high_finding_count: i64,
    pub average_zero_trust_score: i64,
    pub pillar_scores: Vec<AgentPillarScore>,
    pub recent_devices: Vec<AgentDeviceSummary>,
    pub open_findings: Vec<AgentFindingSummary>,
    pub check_catalog: Vec<AgentCheckCatalogItem>,
}

impl AgentStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Agent-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Agent-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-Agent-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn create_enrollment_token(
        &self,
        tenant_id: i64,
        created_by_id: Option<i64>,
        payload: AgentEnrollmentTokenCreateRequest,
    ) -> anyhow::Result<AgentEnrollmentTokenCreateResult> {
        validate_enrollment_token_payload(&payload)?;
        let token = random_secret("iscy_enroll")?;
        let token_hash = sha256_hex(&token);
        let token_hint = secret_hint(&token);
        let label = normalized_or_default(payload.label.as_deref(), "Agent enrollment");
        let rollout_os_family = normalized_onboarding_os_family(
            payload.rollout_os_family.as_deref().unwrap_or("LINUX"),
        )?;
        let allowed_os_families =
            normalized_allowed_os_families(payload.allowed_os_families.unwrap_or_default());
        let allowed_os_families_json = serde_json::to_string(&allowed_os_families)
            .context("Agent-Enrollment-Token OS-Familien konnten nicht serialisiert werden")?;
        let allowed_deployment_channel =
            normalize_optional_deployment_channel(payload.allowed_deployment_channel.as_deref())?;
        let mtls_fingerprint =
            normalize_optional_fingerprint(payload.mtls_fingerprint.as_deref()).unwrap_or_default();
        let expires_at = normalize_optional_rfc3339(payload.expires_at.as_deref())?;
        let max_uses = payload.uses_remaining.unwrap_or(1);

        match self {
            Self::Postgres(pool) => {
                create_enrollment_token_postgres(
                    pool,
                    tenant_id,
                    created_by_id,
                    &label,
                    &token_hash,
                    &token_hint,
                    &rollout_os_family,
                    &allowed_os_families_json,
                    &allowed_deployment_channel,
                    payload.policy_profile_id,
                    &mtls_fingerprint,
                    expires_at.as_deref(),
                    max_uses,
                )
                .await
            }
            Self::Sqlite(pool) => {
                create_enrollment_token_sqlite(
                    pool,
                    tenant_id,
                    created_by_id,
                    &label,
                    &token_hash,
                    &token_hint,
                    &rollout_os_family,
                    &allowed_os_families_json,
                    &allowed_deployment_channel,
                    payload.policy_profile_id,
                    &mtls_fingerprint,
                    expires_at.as_deref(),
                    max_uses,
                )
                .await
            }
        }
        .map(|enrollment| AgentEnrollmentTokenCreateResult { token, enrollment })
    }

    pub async fn list_enrollment_tokens(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<AgentEnrollmentTokenSummary>> {
        match self {
            Self::Postgres(pool) => list_enrollment_tokens_postgres(pool, tenant_id, limit).await,
            Self::Sqlite(pool) => list_enrollment_tokens_sqlite(pool, tenant_id, limit).await,
        }
    }

    pub async fn list_enrollment_audit(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<AgentEnrollmentAuditEvent>> {
        match self {
            Self::Postgres(pool) => list_enrollment_audit_postgres(pool, tenant_id, limit).await,
            Self::Sqlite(pool) => list_enrollment_audit_sqlite(pool, tenant_id, limit).await,
        }
    }

    pub async fn revoke_enrollment_token(
        &self,
        tenant_id: i64,
        token_id: i64,
        actor_id: i64,
    ) -> anyhow::Result<Option<AgentEnrollmentTokenSummary>> {
        match self {
            Self::Postgres(pool) => {
                revoke_enrollment_token_postgres(pool, tenant_id, token_id, actor_id).await
            }
            Self::Sqlite(pool) => {
                revoke_enrollment_token_sqlite(pool, tenant_id, token_id, actor_id).await
            }
        }
    }

    pub async fn enroll_device(
        &self,
        tenant_id: i64,
        payload: AgentEnrollRequest,
    ) -> anyhow::Result<AgentDeviceSummary> {
        validate_enroll_payload(&payload)?;
        match self {
            Self::Postgres(pool) => enroll_device_postgres(pool, tenant_id, payload).await,
            Self::Sqlite(pool) => enroll_device_sqlite(pool, tenant_id, payload).await,
        }
    }

    pub async fn enroll_device_with_token(
        &self,
        tenant_id: i64,
        payload: AgentEnrollRequest,
        enrollment_token: &str,
        mtls_fingerprint: Option<&str>,
    ) -> anyhow::Result<Option<AgentEnrollWithSecret>> {
        validate_enroll_payload(&payload)?;
        let normalized_token = enrollment_token.trim();
        if normalized_token.is_empty() {
            return Ok(None);
        }
        let token_hash = sha256_hex(normalized_token);
        let supplied_mtls = normalize_optional_fingerprint(mtls_fingerprint);
        let agent_secret = random_secret("iscy_agent")?;
        let agent_secret_hash = sha256_hex(&agent_secret);
        let device = match self {
            Self::Postgres(pool) => {
                enroll_device_with_token_postgres(
                    pool,
                    tenant_id,
                    payload,
                    &token_hash,
                    &agent_secret_hash,
                    supplied_mtls.as_deref(),
                )
                .await?
            }
            Self::Sqlite(pool) => {
                enroll_device_with_token_sqlite(
                    pool,
                    tenant_id,
                    payload,
                    &token_hash,
                    &agent_secret_hash,
                    supplied_mtls.as_deref(),
                )
                .await?
            }
        };
        let Some(device) = device else {
            return Ok(None);
        };

        Ok(Some(AgentEnrollWithSecret {
            device,
            agent_secret,
        }))
    }

    pub async fn verify_agent_secret(
        &self,
        tenant_id: i64,
        device_id: i64,
        agent_secret: &str,
        mtls_fingerprint: Option<&str>,
    ) -> anyhow::Result<bool> {
        let normalized_secret = agent_secret.trim();
        if normalized_secret.is_empty() {
            return Ok(false);
        }
        let supplied_secret_hash = sha256_hex(normalized_secret);
        let supplied_mtls = normalize_optional_fingerprint(mtls_fingerprint);
        match self {
            Self::Postgres(pool) => {
                verify_agent_secret_postgres(
                    pool,
                    tenant_id,
                    device_id,
                    &supplied_secret_hash,
                    supplied_mtls.as_deref(),
                )
                .await
            }
            Self::Sqlite(pool) => {
                verify_agent_secret_sqlite(
                    pool,
                    tenant_id,
                    device_id,
                    &supplied_secret_hash,
                    supplied_mtls.as_deref(),
                )
                .await
            }
        }
    }

    pub async fn rotate_agent_secret(
        &self,
        tenant_id: i64,
        device_id: i64,
    ) -> anyhow::Result<Option<AgentSecretRotationResult>> {
        let agent_secret = random_secret("iscy_agent")?;
        let agent_secret_hash = sha256_hex(&agent_secret);
        let updated = match self {
            Self::Postgres(pool) => {
                rotate_agent_secret_postgres(pool, tenant_id, device_id, &agent_secret_hash).await?
            }
            Self::Sqlite(pool) => {
                rotate_agent_secret_sqlite(pool, tenant_id, device_id, &agent_secret_hash).await?
            }
        };
        Ok(updated.map(|device| AgentSecretRotationResult {
            device,
            agent_secret,
        }))
    }

    pub async fn record_heartbeat(
        &self,
        tenant_id: i64,
        device_id: i64,
        payload: AgentHeartbeatRequest,
    ) -> anyhow::Result<Option<AgentHeartbeatSummary>> {
        match self {
            Self::Postgres(pool) => {
                record_heartbeat_postgres(pool, tenant_id, device_id, payload).await
            }
            Self::Sqlite(pool) => {
                record_heartbeat_sqlite(pool, tenant_id, device_id, payload).await
            }
        }
    }

    pub async fn record_findings(
        &self,
        tenant_id: i64,
        device_id: i64,
        payload: AgentFindingsRequest,
    ) -> anyhow::Result<Option<(AgentDeviceSummary, Vec<AgentFindingSummary>)>> {
        if payload.findings.len() > 100 {
            bail!("Agent-Finding-Payload darf maximal 100 Findings enthalten");
        }
        for finding in &payload.findings {
            validate_finding(finding)?;
        }
        match self {
            Self::Postgres(pool) => {
                record_findings_postgres(pool, tenant_id, device_id, payload).await
            }
            Self::Sqlite(pool) => record_findings_sqlite(pool, tenant_id, device_id, payload).await,
        }
    }

    pub async fn posture_overview(&self, tenant_id: i64) -> anyhow::Result<AgentPostureOverview> {
        match self {
            Self::Postgres(pool) => posture_overview_postgres(pool, tenant_id).await,
            Self::Sqlite(pool) => posture_overview_sqlite(pool, tenant_id).await,
        }
    }

    pub async fn list_devices(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<AgentDeviceSummary>> {
        match self {
            Self::Postgres(pool) => list_devices_postgres(pool, tenant_id, limit).await,
            Self::Sqlite(pool) => list_devices_sqlite(pool, tenant_id, limit).await,
        }
    }

    pub async fn list_device_findings(
        &self,
        tenant_id: i64,
        device_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<AgentFindingSummary>> {
        match self {
            Self::Postgres(pool) => {
                list_device_findings_postgres(pool, tenant_id, device_id, limit).await
            }
            Self::Sqlite(pool) => {
                list_device_findings_sqlite(pool, tenant_id, device_id, limit).await
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn create_enrollment_token_postgres(
    pool: &PgPool,
    tenant_id: i64,
    created_by_id: Option<i64>,
    label: &str,
    token_hash: &str,
    token_hint: &str,
    rollout_os_family: &str,
    allowed_os_families_json: &str,
    allowed_deployment_channel: &str,
    policy_profile_id: Option<i64>,
    mtls_fingerprint: &str,
    expires_at: Option<&str>,
    max_uses: i64,
) -> anyhow::Result<AgentEnrollmentTokenSummary> {
    let mut transaction = pool
        .begin()
        .await
        .context("PostgreSQL-Agent-Enrollment-Token-Transaktion konnte nicht gestartet werden")?;
    ensure_policy_for_tenant_postgres(&mut transaction, tenant_id, policy_profile_id).await?;
    let row = sqlx::query(
        r#"
        INSERT INTO zero_trust_agent_enrollment_token (
            tenant_id, label, token_hash, token_hint, status, allowed_os_families,
            mtls_fingerprint, expires_at, uses_remaining, created_by_id,
            rollout_os_family, allowed_deployment_channel, policy_profile_id,
            max_uses, uses_count, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7, $8, $9,
            $10, $11, $12, $13, 0, CURRENT_TIMESTAMP::text, CURRENT_TIMESTAMP::text)
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(label)
    .bind(token_hash)
    .bind(token_hint)
    .bind(allowed_os_families_json)
    .bind(mtls_fingerprint)
    .bind(expires_at)
    .bind(max_uses)
    .bind(created_by_id)
    .bind(rollout_os_family)
    .bind(allowed_deployment_channel)
    .bind(policy_profile_id)
    .bind(max_uses)
    .fetch_one(&mut *transaction)
    .await
    .context("PostgreSQL-Agent-Enrollment-Token konnte nicht erstellt werden")?;
    let token_id: i64 = row.try_get("id")?;
    insert_enrollment_audit_postgres(
        &mut transaction,
        tenant_id,
        Some(token_id),
        None,
        "token_created",
        created_by_id,
        json!({
            "max_uses": max_uses,
            "rollout_os_family": rollout_os_family,
            "allowed_os_families": parse_allowed_os_families(allowed_os_families_json),
            "allowed_deployment_channel": allowed_deployment_channel,
            "policy_profile_id": policy_profile_id,
            "mtls_bound": !mtls_fingerprint.is_empty()
        }),
    )
    .await?;
    let row = sqlx::query(enrollment_token_detail_postgres_sql())
        .bind(tenant_id)
        .bind(token_id)
        .fetch_one(&mut *transaction)
        .await
        .context("PostgreSQL-Agent-Enrollment-Token konnte nicht gelesen werden")?;
    let enrollment = enrollment_token_from_pg_row(row)?;
    transaction
        .commit()
        .await
        .context("PostgreSQL-Agent-Enrollment-Token konnte nicht gespeichert werden")?;
    Ok(enrollment)
}

#[allow(clippy::too_many_arguments)]
async fn create_enrollment_token_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    created_by_id: Option<i64>,
    label: &str,
    token_hash: &str,
    token_hint: &str,
    rollout_os_family: &str,
    allowed_os_families_json: &str,
    allowed_deployment_channel: &str,
    policy_profile_id: Option<i64>,
    mtls_fingerprint: &str,
    expires_at: Option<&str>,
    max_uses: i64,
) -> anyhow::Result<AgentEnrollmentTokenSummary> {
    let mut transaction = pool
        .begin()
        .await
        .context("SQLite-Agent-Enrollment-Token-Transaktion konnte nicht gestartet werden")?;
    ensure_policy_for_tenant_sqlite(&mut transaction, tenant_id, policy_profile_id).await?;
    let row = sqlx::query(
        r#"
        INSERT INTO zero_trust_agent_enrollment_token (
            tenant_id, label, token_hash, token_hint, status, allowed_os_families,
            mtls_fingerprint, expires_at, uses_remaining, created_by_id,
            rollout_os_family, allowed_deployment_channel, policy_profile_id,
            max_uses, uses_count, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, 'pending', ?5, ?6, ?7, ?8, ?9,
            ?10, ?11, ?12, ?13, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(label)
    .bind(token_hash)
    .bind(token_hint)
    .bind(allowed_os_families_json)
    .bind(mtls_fingerprint)
    .bind(expires_at)
    .bind(max_uses)
    .bind(created_by_id)
    .bind(rollout_os_family)
    .bind(allowed_deployment_channel)
    .bind(policy_profile_id)
    .bind(max_uses)
    .fetch_one(&mut *transaction)
    .await
    .context("SQLite-Agent-Enrollment-Token konnte nicht erstellt werden")?;
    let token_id: i64 = row.try_get("id")?;
    insert_enrollment_audit_sqlite(
        &mut transaction,
        tenant_id,
        Some(token_id),
        None,
        "token_created",
        created_by_id,
        json!({
            "max_uses": max_uses,
            "rollout_os_family": rollout_os_family,
            "allowed_os_families": parse_allowed_os_families(allowed_os_families_json),
            "allowed_deployment_channel": allowed_deployment_channel,
            "policy_profile_id": policy_profile_id,
            "mtls_bound": !mtls_fingerprint.is_empty()
        }),
    )
    .await?;
    let row = sqlx::query(enrollment_token_detail_sqlite_sql())
        .bind(tenant_id)
        .bind(token_id)
        .fetch_one(&mut *transaction)
        .await
        .context("SQLite-Agent-Enrollment-Token konnte nicht gelesen werden")?;
    let enrollment = enrollment_token_from_sqlite_row(row)?;
    transaction
        .commit()
        .await
        .context("SQLite-Agent-Enrollment-Token konnte nicht gespeichert werden")?;
    Ok(enrollment)
}

async fn enroll_device_with_token_postgres(
    pool: &PgPool,
    tenant_id: i64,
    payload: AgentEnrollRequest,
    token_hash: &str,
    agent_secret_hash: &str,
    supplied_mtls: Option<&str>,
) -> anyhow::Result<Option<AgentDeviceSummary>> {
    let os_family = normalized_upper(&payload.os_family);
    let deployment_channel =
        normalized_or_default(payload.deployment_channel.as_deref(), "manual").to_ascii_lowercase();
    let supplied_mtls = supplied_mtls.unwrap_or("");
    let mut transaction = pool
        .begin()
        .await
        .context("PostgreSQL-Agent-Enrollment-Transaktion konnte nicht gestartet werden")?;
    let row = sqlx::query(
        r#"
        UPDATE zero_trust_agent_enrollment_token token
        SET uses_remaining = token.uses_remaining - 1,
            uses_count = token.uses_count + 1,
            status = CASE WHEN token.uses_remaining - 1 <= 0 THEN 'consumed' ELSE 'partially_used' END,
            last_attempt_at = CURRENT_TIMESTAMP::text,
            last_used_at = CURRENT_TIMESTAMP::text,
            updated_at = CURRENT_TIMESTAMP::text
        WHERE token.tenant_id = $1
          AND token.token_hash = $2
          AND token.status IN ('pending', 'partially_used', 'ACTIVE')
          AND token.revoked_at IS NULL
          AND COALESCE(token.uses_remaining, 0) > 0
          AND (token.expires_at IS NULL OR token.expires_at = '' OR token.expires_at::timestamptz > CURRENT_TIMESTAMP)
          AND (
              token.allowed_os_families = '[]'
              OR EXISTS (
                  SELECT 1 FROM jsonb_array_elements_text(token.allowed_os_families::jsonb) allowed(value)
                  WHERE UPPER(allowed.value) = $3
              )
          )
          AND (token.allowed_deployment_channel = '' OR token.allowed_deployment_channel = $4)
          AND (token.mtls_fingerprint = '' OR token.mtls_fingerprint = $5)
          AND (
              token.policy_profile_id IS NULL
              OR EXISTS (
                  SELECT 1 FROM zero_trust_agent_policy_profile policy
                  WHERE policy.tenant_id = token.tenant_id AND policy.id = token.policy_profile_id
              )
          )
        RETURNING token.id, token.policy_profile_id, token.allowed_os_families,
            token.allowed_deployment_channel, token.mtls_fingerprint, token.status
        "#,
    )
    .bind(tenant_id)
    .bind(token_hash)
    .bind(&os_family)
    .bind(&deployment_channel)
    .bind(supplied_mtls)
    .fetch_optional(&mut *transaction)
    .await
    .context("PostgreSQL-Agent-Enrollment-Token konnte nicht atomar verwendet werden")?;
    let Some(row) = row else {
        audit_failed_enrollment_postgres(&mut transaction, tenant_id, token_hash).await?;
        transaction.commit().await.context(
            "PostgreSQL-fehlgeschlagenes Agent-Enrollment konnte nicht auditiert werden",
        )?;
        return Ok(None);
    };
    let grant = enrollment_token_grant_from_pg_row(row)?;
    let bound_mtls = if supplied_mtls.is_empty() {
        grant.mtls_fingerprint.as_str()
    } else {
        supplied_mtls
    };
    let device_id = upsert_enrolled_device_postgres(
        &mut transaction,
        tenant_id,
        &payload,
        &deployment_channel,
        grant.policy_profile_id,
        grant.id,
        agent_secret_hash,
        bound_mtls,
    )
    .await?;
    insert_enrollment_audit_postgres(
        &mut transaction,
        tenant_id,
        Some(grant.id),
        Some(device_id),
        "token_used",
        None,
        json!({"status": grant.status, "os_family": os_family, "deployment_channel": deployment_channel}),
    )
    .await?;
    let lifecycle_event = if grant.status == "consumed" {
        "token_consumed"
    } else {
        "token_partially_used"
    };
    insert_enrollment_audit_postgres(
        &mut transaction,
        tenant_id,
        Some(grant.id),
        Some(device_id),
        lifecycle_event,
        None,
        json!({}),
    )
    .await?;
    let row = sqlx::query(device_detail_postgres_sql())
        .bind(tenant_id)
        .bind(device_id)
        .fetch_one(&mut *transaction)
        .await
        .context("PostgreSQL-Agent-Device nach Enrollment nicht gefunden")?;
    let device = device_from_pg_row(row)?;
    transaction
        .commit()
        .await
        .context("PostgreSQL-Agent-Enrollment konnte nicht gespeichert werden")?;
    Ok(Some(device))
}

async fn enroll_device_with_token_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    payload: AgentEnrollRequest,
    token_hash: &str,
    agent_secret_hash: &str,
    supplied_mtls: Option<&str>,
) -> anyhow::Result<Option<AgentDeviceSummary>> {
    let os_family = normalized_upper(&payload.os_family);
    let deployment_channel =
        normalized_or_default(payload.deployment_channel.as_deref(), "manual").to_ascii_lowercase();
    let supplied_mtls = supplied_mtls.unwrap_or("");
    let mut transaction = pool
        .begin()
        .await
        .context("SQLite-Agent-Enrollment-Transaktion konnte nicht gestartet werden")?;
    let row = sqlx::query(
        r#"
        UPDATE zero_trust_agent_enrollment_token
        SET uses_remaining = uses_remaining - 1,
            uses_count = uses_count + 1,
            status = CASE WHEN uses_remaining - 1 <= 0 THEN 'consumed' ELSE 'partially_used' END,
            last_attempt_at = CURRENT_TIMESTAMP,
            last_used_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE tenant_id = ?1
          AND token_hash = ?2
          AND status IN ('pending', 'partially_used', 'ACTIVE')
          AND revoked_at IS NULL
          AND COALESCE(uses_remaining, 0) > 0
          AND (expires_at IS NULL OR expires_at = '' OR julianday(expires_at) > julianday('now'))
          AND (
              allowed_os_families = '[]'
              OR EXISTS (
                  SELECT 1 FROM json_each(allowed_os_families) allowed
                  WHERE UPPER(allowed.value) = ?3
              )
          )
          AND (allowed_deployment_channel = '' OR allowed_deployment_channel = ?4)
          AND (mtls_fingerprint = '' OR mtls_fingerprint = ?5)
          AND (
              policy_profile_id IS NULL
              OR EXISTS (
                  SELECT 1 FROM zero_trust_agent_policy_profile policy
                  WHERE policy.tenant_id = zero_trust_agent_enrollment_token.tenant_id
                    AND policy.id = zero_trust_agent_enrollment_token.policy_profile_id
              )
          )
        RETURNING id, policy_profile_id, allowed_os_families,
            allowed_deployment_channel, mtls_fingerprint, status
        "#,
    )
    .bind(tenant_id)
    .bind(token_hash)
    .bind(&os_family)
    .bind(&deployment_channel)
    .bind(supplied_mtls)
    .fetch_optional(&mut *transaction)
    .await
    .context("SQLite-Agent-Enrollment-Token konnte nicht atomar verwendet werden")?;
    let Some(row) = row else {
        audit_failed_enrollment_sqlite(&mut transaction, tenant_id, token_hash).await?;
        transaction
            .commit()
            .await
            .context("SQLite-fehlgeschlagenes Agent-Enrollment konnte nicht auditiert werden")?;
        return Ok(None);
    };
    let grant = enrollment_token_grant_from_sqlite_row(row)?;
    let bound_mtls = if supplied_mtls.is_empty() {
        grant.mtls_fingerprint.as_str()
    } else {
        supplied_mtls
    };
    let device_id = upsert_enrolled_device_sqlite(
        &mut transaction,
        tenant_id,
        &payload,
        &deployment_channel,
        grant.policy_profile_id,
        grant.id,
        agent_secret_hash,
        bound_mtls,
    )
    .await?;
    insert_enrollment_audit_sqlite(
        &mut transaction,
        tenant_id,
        Some(grant.id),
        Some(device_id),
        "token_used",
        None,
        json!({"status": grant.status, "os_family": os_family, "deployment_channel": deployment_channel}),
    )
    .await?;
    let lifecycle_event = if grant.status == "consumed" {
        "token_consumed"
    } else {
        "token_partially_used"
    };
    insert_enrollment_audit_sqlite(
        &mut transaction,
        tenant_id,
        Some(grant.id),
        Some(device_id),
        lifecycle_event,
        None,
        json!({}),
    )
    .await?;
    let row = sqlx::query(device_detail_sqlite_sql())
        .bind(tenant_id)
        .bind(device_id)
        .fetch_one(&mut *transaction)
        .await
        .context("SQLite-Agent-Device nach Enrollment nicht gefunden")?;
    let device = device_from_sqlite_row(row)?;
    transaction
        .commit()
        .await
        .context("SQLite-Agent-Enrollment konnte nicht gespeichert werden")?;
    Ok(Some(device))
}

#[allow(clippy::too_many_arguments)]
async fn upsert_enrolled_device_postgres(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    payload: &AgentEnrollRequest,
    deployment_channel: &str,
    policy_profile_id: Option<i64>,
    token_id: i64,
    agent_secret_hash: &str,
    mtls_fingerprint: &str,
) -> anyhow::Result<i64> {
    let row = sqlx::query(
        r#"
        INSERT INTO zero_trust_agent_device (
            tenant_id, asset_id, stable_device_id, hostname, os_family, os_version,
            architecture, agent_version, deployment_channel, enrollment_status,
            agent_secret_hash, mtls_fingerprint, auth_model, last_auth_at,
            policy_profile_id, enrollment_token_id, last_enrolled_at,
            last_seen_at, created_at, updated_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, 'ACTIVE',
            $10, $11, 'enrollment_token', CURRENT_TIMESTAMP::text,
            $12, $13, CURRENT_TIMESTAMP::text,
            CURRENT_TIMESTAMP::text, CURRENT_TIMESTAMP::text, CURRENT_TIMESTAMP::text
        )
        ON CONFLICT (tenant_id, stable_device_id) DO UPDATE SET
            asset_id = EXCLUDED.asset_id,
            hostname = EXCLUDED.hostname,
            os_family = EXCLUDED.os_family,
            os_version = EXCLUDED.os_version,
            architecture = EXCLUDED.architecture,
            agent_version = EXCLUDED.agent_version,
            deployment_channel = EXCLUDED.deployment_channel,
            enrollment_status = 'ACTIVE',
            agent_secret_hash = EXCLUDED.agent_secret_hash,
            mtls_fingerprint = EXCLUDED.mtls_fingerprint,
            auth_model = 'enrollment_token',
            last_auth_at = CURRENT_TIMESTAMP::text,
            policy_profile_id = EXCLUDED.policy_profile_id,
            enrollment_token_id = EXCLUDED.enrollment_token_id,
            last_enrolled_at = CURRENT_TIMESTAMP::text,
            last_seen_at = CURRENT_TIMESTAMP::text,
            updated_at = CURRENT_TIMESTAMP::text
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(payload.asset_id)
    .bind(normalized(&payload.stable_device_id))
    .bind(normalized(&payload.hostname))
    .bind(normalized_upper(&payload.os_family))
    .bind(normalized(&payload.os_version))
    .bind(normalized(&payload.architecture))
    .bind(normalized(&payload.agent_version))
    .bind(deployment_channel)
    .bind(agent_secret_hash)
    .bind(mtls_fingerprint)
    .bind(policy_profile_id)
    .bind(token_id)
    .fetch_one(&mut **transaction)
    .await
    .context("PostgreSQL-Agent-Device konnte nicht atomar enrollt werden")?;
    row.try_get("id").map_err(Into::into)
}

#[allow(clippy::too_many_arguments)]
async fn upsert_enrolled_device_sqlite(
    transaction: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    payload: &AgentEnrollRequest,
    deployment_channel: &str,
    policy_profile_id: Option<i64>,
    token_id: i64,
    agent_secret_hash: &str,
    mtls_fingerprint: &str,
) -> anyhow::Result<i64> {
    let row = sqlx::query(
        r#"
        INSERT INTO zero_trust_agent_device (
            tenant_id, asset_id, stable_device_id, hostname, os_family, os_version,
            architecture, agent_version, deployment_channel, enrollment_status,
            agent_secret_hash, mtls_fingerprint, auth_model, last_auth_at,
            policy_profile_id, enrollment_token_id, last_enrolled_at,
            last_seen_at, created_at, updated_at
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'ACTIVE',
            ?10, ?11, 'enrollment_token', CURRENT_TIMESTAMP,
            ?12, ?13, CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
        )
        ON CONFLICT (tenant_id, stable_device_id) DO UPDATE SET
            asset_id = excluded.asset_id,
            hostname = excluded.hostname,
            os_family = excluded.os_family,
            os_version = excluded.os_version,
            architecture = excluded.architecture,
            agent_version = excluded.agent_version,
            deployment_channel = excluded.deployment_channel,
            enrollment_status = 'ACTIVE',
            agent_secret_hash = excluded.agent_secret_hash,
            mtls_fingerprint = excluded.mtls_fingerprint,
            auth_model = 'enrollment_token',
            last_auth_at = CURRENT_TIMESTAMP,
            policy_profile_id = excluded.policy_profile_id,
            enrollment_token_id = excluded.enrollment_token_id,
            last_enrolled_at = CURRENT_TIMESTAMP,
            last_seen_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(payload.asset_id)
    .bind(normalized(&payload.stable_device_id))
    .bind(normalized(&payload.hostname))
    .bind(normalized_upper(&payload.os_family))
    .bind(normalized(&payload.os_version))
    .bind(normalized(&payload.architecture))
    .bind(normalized(&payload.agent_version))
    .bind(deployment_channel)
    .bind(agent_secret_hash)
    .bind(mtls_fingerprint)
    .bind(policy_profile_id)
    .bind(token_id)
    .fetch_one(&mut **transaction)
    .await
    .context("SQLite-Agent-Device konnte nicht atomar enrollt werden")?;
    row.try_get("id").map_err(Into::into)
}

#[allow(clippy::too_many_arguments)]
async fn insert_enrollment_audit_postgres(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    token_id: Option<i64>,
    device_id: Option<i64>,
    event_type: &str,
    actor_id: Option<i64>,
    detail: Value,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO zero_trust_agent_enrollment_audit
            (tenant_id, token_id, device_id, event_type, actor_id, detail_json, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP::text)
        "#,
    )
    .bind(tenant_id)
    .bind(token_id)
    .bind(device_id)
    .bind(event_type)
    .bind(actor_id)
    .bind(sqlx::types::Json(detail))
    .execute(&mut **transaction)
    .await
    .context("PostgreSQL-Agent-Enrollment-Audit konnte nicht gespeichert werden")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn insert_enrollment_audit_sqlite(
    transaction: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    token_id: Option<i64>,
    device_id: Option<i64>,
    event_type: &str,
    actor_id: Option<i64>,
    detail: Value,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO zero_trust_agent_enrollment_audit
            (tenant_id, token_id, device_id, event_type, actor_id, detail_json, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, CURRENT_TIMESTAMP)
        "#,
    )
    .bind(tenant_id)
    .bind(token_id)
    .bind(device_id)
    .bind(event_type)
    .bind(actor_id)
    .bind(detail.to_string())
    .execute(&mut **transaction)
    .await
    .context("SQLite-Agent-Enrollment-Audit konnte nicht gespeichert werden")?;
    Ok(())
}

async fn ensure_policy_for_tenant_postgres(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    policy_profile_id: Option<i64>,
) -> anyhow::Result<()> {
    let Some(policy_profile_id) = policy_profile_id else {
        return Ok(());
    };
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM zero_trust_agent_policy_profile WHERE tenant_id = $1 AND id = $2)",
    )
    .bind(tenant_id)
    .bind(policy_profile_id)
    .fetch_one(&mut **transaction)
    .await
    .context("PostgreSQL-Agent-Policy konnte nicht geprueft werden")?;
    if !exists {
        bail!("Agent-Policy-Profil wurde im aktiven Tenant nicht gefunden");
    }
    Ok(())
}

async fn ensure_policy_for_tenant_sqlite(
    transaction: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    policy_profile_id: Option<i64>,
) -> anyhow::Result<()> {
    let Some(policy_profile_id) = policy_profile_id else {
        return Ok(());
    };
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM zero_trust_agent_policy_profile WHERE tenant_id = ?1 AND id = ?2",
    )
    .bind(tenant_id)
    .bind(policy_profile_id)
    .fetch_one(&mut **transaction)
    .await
    .context("SQLite-Agent-Policy konnte nicht geprueft werden")?;
    if exists == 0 {
        bail!("Agent-Policy-Profil wurde im aktiven Tenant nicht gefunden");
    }
    Ok(())
}

async fn audit_failed_enrollment_postgres(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    token_hash: &str,
) -> anyhow::Result<()> {
    let row = sqlx::query(
        r#"
        SELECT id, status, expires_at
        FROM zero_trust_agent_enrollment_token
        WHERE tenant_id = $1 AND token_hash = $2
        FOR UPDATE
        "#,
    )
    .bind(tenant_id)
    .bind(token_hash)
    .fetch_optional(&mut **transaction)
    .await
    .context("PostgreSQL-fehlgeschlagenes Agent-Enrollment konnte nicht geprueft werden")?;
    let Some(row) = row else {
        return Ok(());
    };
    let token_id: i64 = row.try_get("id")?;
    let status: String = row.try_get("status")?;
    let expires_at: Option<String> = row.try_get("expires_at")?;
    let expired = expires_at.as_deref().is_some_and(timestamp_is_expired);
    if expired && !matches!(status.as_str(), "expired" | "revoked" | "consumed") {
        sqlx::query(
            "UPDATE zero_trust_agent_enrollment_token SET status = 'expired', last_attempt_at = CURRENT_TIMESTAMP::text, updated_at = CURRENT_TIMESTAMP::text WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(token_id)
        .execute(&mut **transaction)
        .await?;
        insert_enrollment_audit_postgres(
            transaction,
            tenant_id,
            Some(token_id),
            None,
            "token_expired",
            None,
            json!({}),
        )
        .await?;
    } else {
        sqlx::query(
            "UPDATE zero_trust_agent_enrollment_token SET last_attempt_at = CURRENT_TIMESTAMP::text, updated_at = CURRENT_TIMESTAMP::text WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(token_id)
        .execute(&mut **transaction)
        .await?;
    }
    insert_enrollment_audit_postgres(
        transaction,
        tenant_id,
        Some(token_id),
        None,
        "enrollment_failed",
        None,
        json!({"reason": "token_constraint_or_lifecycle"}),
    )
    .await
}

async fn audit_failed_enrollment_sqlite(
    transaction: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    token_hash: &str,
) -> anyhow::Result<()> {
    let row = sqlx::query(
        r#"
        SELECT id, status, expires_at
        FROM zero_trust_agent_enrollment_token
        WHERE tenant_id = ?1 AND token_hash = ?2
        "#,
    )
    .bind(tenant_id)
    .bind(token_hash)
    .fetch_optional(&mut **transaction)
    .await
    .context("SQLite-fehlgeschlagenes Agent-Enrollment konnte nicht geprueft werden")?;
    let Some(row) = row else {
        return Ok(());
    };
    let token_id: i64 = row.try_get("id")?;
    let status: String = row.try_get("status")?;
    let expires_at: Option<String> = row.try_get("expires_at")?;
    let expired = expires_at.as_deref().is_some_and(timestamp_is_expired);
    if expired && !matches!(status.as_str(), "expired" | "revoked" | "consumed") {
        sqlx::query(
            "UPDATE zero_trust_agent_enrollment_token SET status = 'expired', last_attempt_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE tenant_id = ?1 AND id = ?2",
        )
        .bind(tenant_id)
        .bind(token_id)
        .execute(&mut **transaction)
        .await?;
        insert_enrollment_audit_sqlite(
            transaction,
            tenant_id,
            Some(token_id),
            None,
            "token_expired",
            None,
            json!({}),
        )
        .await?;
    } else {
        sqlx::query(
            "UPDATE zero_trust_agent_enrollment_token SET last_attempt_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE tenant_id = ?1 AND id = ?2",
        )
        .bind(tenant_id)
        .bind(token_id)
        .execute(&mut **transaction)
        .await?;
    }
    insert_enrollment_audit_sqlite(
        transaction,
        tenant_id,
        Some(token_id),
        None,
        "enrollment_failed",
        None,
        json!({"reason": "token_constraint_or_lifecycle"}),
    )
    .await
}

async fn list_enrollment_tokens_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AgentEnrollmentTokenSummary>> {
    refresh_expired_tokens_postgres(pool, tenant_id).await?;
    let rows = sqlx::query(enrollment_token_list_postgres_sql())
        .bind(tenant_id)
        .bind(limit.clamp(1, 500))
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Agent-Enrollment-Tokens konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(enrollment_token_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_enrollment_tokens_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AgentEnrollmentTokenSummary>> {
    refresh_expired_tokens_sqlite(pool, tenant_id).await?;
    let rows = sqlx::query(enrollment_token_list_sqlite_sql())
        .bind(tenant_id)
        .bind(limit.clamp(1, 500))
        .fetch_all(pool)
        .await
        .context("SQLite-Agent-Enrollment-Tokens konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(enrollment_token_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn revoke_enrollment_token_postgres(
    pool: &PgPool,
    tenant_id: i64,
    token_id: i64,
    actor_id: i64,
) -> anyhow::Result<Option<AgentEnrollmentTokenSummary>> {
    let mut transaction = pool
        .begin()
        .await
        .context("PostgreSQL-Token-Widerruf konnte nicht gestartet werden")?;
    let row = sqlx::query(
        r#"
        UPDATE zero_trust_agent_enrollment_token
        SET status = 'revoked', revoked_at = CURRENT_TIMESTAMP::text, updated_at = CURRENT_TIMESTAMP::text
        WHERE tenant_id = $1 AND id = $2 AND status IN ('pending', 'partially_used', 'ACTIVE')
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(token_id)
    .fetch_optional(&mut *transaction)
    .await
    .context("PostgreSQL-Agent-Enrollment-Token konnte nicht widerrufen werden")?;
    if row.is_some() {
        insert_enrollment_audit_postgres(
            &mut transaction,
            tenant_id,
            Some(token_id),
            None,
            "token_revoked",
            Some(actor_id),
            json!({}),
        )
        .await?;
    }
    let row = sqlx::query(enrollment_token_detail_postgres_sql())
        .bind(tenant_id)
        .bind(token_id)
        .fetch_optional(&mut *transaction)
        .await
        .context("PostgreSQL-Agent-Enrollment-Token konnte nach Widerruf nicht gelesen werden")?;
    let token = row.map(enrollment_token_from_pg_row).transpose()?;
    transaction
        .commit()
        .await
        .context("PostgreSQL-Token-Widerruf konnte nicht gespeichert werden")?;
    Ok(token)
}

async fn revoke_enrollment_token_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    token_id: i64,
    actor_id: i64,
) -> anyhow::Result<Option<AgentEnrollmentTokenSummary>> {
    let mut transaction = pool
        .begin()
        .await
        .context("SQLite-Token-Widerruf konnte nicht gestartet werden")?;
    let row = sqlx::query(
        r#"
        UPDATE zero_trust_agent_enrollment_token
        SET status = 'revoked', revoked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
        WHERE tenant_id = ?1 AND id = ?2 AND status IN ('pending', 'partially_used', 'ACTIVE')
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(token_id)
    .fetch_optional(&mut *transaction)
    .await
    .context("SQLite-Agent-Enrollment-Token konnte nicht widerrufen werden")?;
    if row.is_some() {
        insert_enrollment_audit_sqlite(
            &mut transaction,
            tenant_id,
            Some(token_id),
            None,
            "token_revoked",
            Some(actor_id),
            json!({}),
        )
        .await?;
    }
    let row = sqlx::query(enrollment_token_detail_sqlite_sql())
        .bind(tenant_id)
        .bind(token_id)
        .fetch_optional(&mut *transaction)
        .await
        .context("SQLite-Agent-Enrollment-Token konnte nach Widerruf nicht gelesen werden")?;
    let token = row.map(enrollment_token_from_sqlite_row).transpose()?;
    transaction
        .commit()
        .await
        .context("SQLite-Token-Widerruf konnte nicht gespeichert werden")?;
    Ok(token)
}

async fn refresh_expired_tokens_postgres(pool: &PgPool, tenant_id: i64) -> anyhow::Result<()> {
    let mut transaction = pool
        .begin()
        .await
        .context("PostgreSQL-Token-Ablaufpruefung konnte nicht gestartet werden")?;
    let rows = sqlx::query(
        r#"
        UPDATE zero_trust_agent_enrollment_token
        SET status = 'expired', updated_at = CURRENT_TIMESTAMP::text
        WHERE tenant_id = $1
          AND status IN ('pending', 'partially_used', 'ACTIVE')
          AND expires_at IS NOT NULL AND expires_at <> ''
          AND expires_at::timestamptz <= CURRENT_TIMESTAMP
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .fetch_all(&mut *transaction)
    .await
    .context("PostgreSQL-abgelaufene Agent-Tokens konnten nicht aktualisiert werden")?;
    for row in rows {
        insert_enrollment_audit_postgres(
            &mut transaction,
            tenant_id,
            Some(row.try_get("id")?),
            None,
            "token_expired",
            None,
            json!({}),
        )
        .await?;
    }
    transaction
        .commit()
        .await
        .context("PostgreSQL-Token-Ablaufpruefung konnte nicht gespeichert werden")
}

async fn refresh_expired_tokens_sqlite(pool: &SqlitePool, tenant_id: i64) -> anyhow::Result<()> {
    let mut transaction = pool
        .begin()
        .await
        .context("SQLite-Token-Ablaufpruefung konnte nicht gestartet werden")?;
    let rows = sqlx::query(
        r#"
        UPDATE zero_trust_agent_enrollment_token
        SET status = 'expired', updated_at = CURRENT_TIMESTAMP
        WHERE tenant_id = ?1
          AND status IN ('pending', 'partially_used', 'ACTIVE')
          AND expires_at IS NOT NULL AND expires_at <> ''
          AND julianday(expires_at) <= julianday('now')
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .fetch_all(&mut *transaction)
    .await
    .context("SQLite-abgelaufene Agent-Tokens konnten nicht aktualisiert werden")?;
    for row in rows {
        insert_enrollment_audit_sqlite(
            &mut transaction,
            tenant_id,
            Some(row.try_get("id")?),
            None,
            "token_expired",
            None,
            json!({}),
        )
        .await?;
    }
    transaction
        .commit()
        .await
        .context("SQLite-Token-Ablaufpruefung konnte nicht gespeichert werden")
}

async fn list_enrollment_audit_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AgentEnrollmentAuditEvent>> {
    let rows = sqlx::query(enrollment_audit_postgres_sql())
        .bind(tenant_id)
        .bind(limit.clamp(1, 500))
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Agent-Enrollment-Audit konnte nicht gelesen werden")?;
    rows.into_iter()
        .map(enrollment_audit_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_enrollment_audit_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AgentEnrollmentAuditEvent>> {
    let rows = sqlx::query(enrollment_audit_sqlite_sql())
        .bind(tenant_id)
        .bind(limit.clamp(1, 500))
        .fetch_all(pool)
        .await
        .context("SQLite-Agent-Enrollment-Audit konnte nicht gelesen werden")?;
    rows.into_iter()
        .map(enrollment_audit_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn rotate_agent_secret_postgres(
    pool: &PgPool,
    tenant_id: i64,
    device_id: i64,
    agent_secret_hash: &str,
) -> anyhow::Result<Option<AgentDeviceSummary>> {
    let mut transaction = pool
        .begin()
        .await
        .context("PostgreSQL-Agent-Secret-Transaktion konnte nicht gestartet werden")?;
    let result = sqlx::query(
        r#"
        UPDATE zero_trust_agent_device
        SET agent_secret_hash = $1,
            auth_model = 'enrollment_token',
            updated_at = CURRENT_TIMESTAMP::text
        WHERE tenant_id = $2 AND id = $3 AND enrollment_status = 'ACTIVE'
        "#,
    )
    .bind(agent_secret_hash)
    .bind(tenant_id)
    .bind(device_id)
    .execute(&mut *transaction)
    .await
    .context("PostgreSQL-Agent-Secret konnte nicht rotiert werden")?;
    if result.rows_affected() == 0 {
        transaction
            .rollback()
            .await
            .context("PostgreSQL-Agent-Secret-Transaktion konnte nicht verworfen werden")?;
        return Ok(None);
    }
    let row = sqlx::query(device_detail_postgres_sql())
        .bind(tenant_id)
        .bind(device_id)
        .fetch_one(&mut *transaction)
        .await
        .context("PostgreSQL-Agent-Device konnte nach Rotation nicht gelesen werden")?;
    let device = device_from_pg_row(row)?;
    transaction
        .commit()
        .await
        .context("PostgreSQL-Agent-Secret-Rotation konnte nicht gespeichert werden")?;
    Ok(Some(device))
}

async fn rotate_agent_secret_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    device_id: i64,
    agent_secret_hash: &str,
) -> anyhow::Result<Option<AgentDeviceSummary>> {
    let mut transaction = pool
        .begin()
        .await
        .context("SQLite-Agent-Secret-Transaktion konnte nicht gestartet werden")?;
    let result = sqlx::query(
        r#"
        UPDATE zero_trust_agent_device
        SET agent_secret_hash = ?1,
            auth_model = 'enrollment_token',
            updated_at = CURRENT_TIMESTAMP
        WHERE tenant_id = ?2 AND id = ?3 AND enrollment_status = 'ACTIVE'
        "#,
    )
    .bind(agent_secret_hash)
    .bind(tenant_id)
    .bind(device_id)
    .execute(&mut *transaction)
    .await
    .context("SQLite-Agent-Secret konnte nicht rotiert werden")?;
    if result.rows_affected() == 0 {
        transaction
            .rollback()
            .await
            .context("SQLite-Agent-Secret-Transaktion konnte nicht verworfen werden")?;
        return Ok(None);
    }
    let row = sqlx::query(device_detail_sqlite_sql())
        .bind(tenant_id)
        .bind(device_id)
        .fetch_one(&mut *transaction)
        .await
        .context("SQLite-Agent-Device konnte nach Rotation nicht gelesen werden")?;
    let device = device_from_sqlite_row(row)?;
    transaction
        .commit()
        .await
        .context("SQLite-Agent-Secret-Rotation konnte nicht gespeichert werden")?;
    Ok(Some(device))
}

async fn verify_agent_secret_postgres(
    pool: &PgPool,
    tenant_id: i64,
    device_id: i64,
    supplied_secret_hash: &str,
    supplied_mtls: Option<&str>,
) -> anyhow::Result<bool> {
    let row = sqlx::query(
        r#"
        SELECT agent_secret_hash, mtls_fingerprint
        FROM zero_trust_agent_device
        WHERE tenant_id = $1 AND id = $2 AND enrollment_status = 'ACTIVE'
        "#,
    )
    .bind(tenant_id)
    .bind(device_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-Agent-Secret konnte nicht geprueft werden")?;
    let Some(row) = row else {
        return Ok(false);
    };
    let stored_hash: String = row.try_get("agent_secret_hash")?;
    let stored_mtls: String = row.try_get("mtls_fingerprint")?;
    if !agent_credentials_match(
        &stored_hash,
        supplied_secret_hash,
        &stored_mtls,
        supplied_mtls,
    ) {
        return Ok(false);
    }
    sqlx::query(
        "UPDATE zero_trust_agent_device SET last_auth_at = CURRENT_TIMESTAMP::text, updated_at = CURRENT_TIMESTAMP::text WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(device_id)
    .execute(pool)
    .await
    .context("PostgreSQL-Agent-Auth-Zeitpunkt konnte nicht gespeichert werden")?;
    Ok(true)
}

async fn verify_agent_secret_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    device_id: i64,
    supplied_secret_hash: &str,
    supplied_mtls: Option<&str>,
) -> anyhow::Result<bool> {
    let row = sqlx::query(
        r#"
        SELECT agent_secret_hash, mtls_fingerprint
        FROM zero_trust_agent_device
        WHERE tenant_id = ?1 AND id = ?2 AND enrollment_status = 'ACTIVE'
        "#,
    )
    .bind(tenant_id)
    .bind(device_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-Agent-Secret konnte nicht geprueft werden")?;
    let Some(row) = row else {
        return Ok(false);
    };
    let stored_hash: String = row.try_get("agent_secret_hash")?;
    let stored_mtls: String = row.try_get("mtls_fingerprint")?;
    if !agent_credentials_match(
        &stored_hash,
        supplied_secret_hash,
        &stored_mtls,
        supplied_mtls,
    ) {
        return Ok(false);
    }
    sqlx::query(
        "UPDATE zero_trust_agent_device SET last_auth_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE tenant_id = ?1 AND id = ?2",
    )
    .bind(tenant_id)
    .bind(device_id)
    .execute(pool)
    .await
    .context("SQLite-Agent-Auth-Zeitpunkt konnte nicht gespeichert werden")?;
    Ok(true)
}

async fn enroll_device_postgres(
    pool: &PgPool,
    tenant_id: i64,
    payload: AgentEnrollRequest,
) -> anyhow::Result<AgentDeviceSummary> {
    let deployment_channel = normalized_or_default(payload.deployment_channel.as_deref(), "manual");
    let row = sqlx::query(
        r#"
        INSERT INTO zero_trust_agent_device (
            tenant_id, asset_id, stable_device_id, hostname, os_family, os_version,
            architecture, agent_version, deployment_channel, enrollment_status,
            last_seen_at, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'ACTIVE', CURRENT_TIMESTAMP::text, CURRENT_TIMESTAMP::text, CURRENT_TIMESTAMP::text)
        ON CONFLICT (tenant_id, stable_device_id) DO UPDATE SET
            asset_id = EXCLUDED.asset_id,
            hostname = EXCLUDED.hostname,
            os_family = EXCLUDED.os_family,
            os_version = EXCLUDED.os_version,
            architecture = EXCLUDED.architecture,
            agent_version = EXCLUDED.agent_version,
            deployment_channel = EXCLUDED.deployment_channel,
            enrollment_status = 'ACTIVE',
            last_seen_at = CURRENT_TIMESTAMP::text,
            updated_at = CURRENT_TIMESTAMP::text
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(payload.asset_id)
    .bind(normalized(&payload.stable_device_id))
    .bind(normalized(&payload.hostname))
    .bind(normalized_upper(&payload.os_family))
    .bind(normalized(&payload.os_version))
    .bind(normalized(&payload.architecture))
    .bind(normalized(&payload.agent_version))
    .bind(deployment_channel)
    .fetch_one(pool)
    .await
    .context("PostgreSQL-Agent-Device konnte nicht enrollt werden")?;
    let device_id: i64 = row.try_get("id")?;
    refresh_device_score_postgres(pool, tenant_id, device_id).await?;
    device_detail_postgres(pool, tenant_id, device_id)
        .await?
        .context("PostgreSQL-Agent-Device nach Enrollment nicht gefunden")
}

async fn enroll_device_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    payload: AgentEnrollRequest,
) -> anyhow::Result<AgentDeviceSummary> {
    let deployment_channel = normalized_or_default(payload.deployment_channel.as_deref(), "manual");
    let stable_device_id = normalized(&payload.stable_device_id);
    sqlx::query(
        r#"
        INSERT INTO zero_trust_agent_device (
            tenant_id, asset_id, stable_device_id, hostname, os_family, os_version,
            architecture, agent_version, deployment_channel, enrollment_status,
            last_seen_at, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'ACTIVE', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ON CONFLICT (tenant_id, stable_device_id) DO UPDATE SET
            asset_id = excluded.asset_id,
            hostname = excluded.hostname,
            os_family = excluded.os_family,
            os_version = excluded.os_version,
            architecture = excluded.architecture,
            agent_version = excluded.agent_version,
            deployment_channel = excluded.deployment_channel,
            enrollment_status = 'ACTIVE',
            last_seen_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        "#,
    )
    .bind(tenant_id)
    .bind(payload.asset_id)
    .bind(&stable_device_id)
    .bind(normalized(&payload.hostname))
    .bind(normalized_upper(&payload.os_family))
    .bind(normalized(&payload.os_version))
    .bind(normalized(&payload.architecture))
    .bind(normalized(&payload.agent_version))
    .bind(deployment_channel)
    .execute(pool)
    .await
    .context("SQLite-Agent-Device konnte nicht enrollt werden")?;
    let row = sqlx::query(
        "SELECT id FROM zero_trust_agent_device WHERE tenant_id = ?1 AND stable_device_id = ?2",
    )
    .bind(tenant_id)
    .bind(&stable_device_id)
    .fetch_one(pool)
    .await
    .context("SQLite-Agent-Device nach Enrollment konnte nicht gelesen werden")?;
    let device_id: i64 = row.try_get("id")?;
    refresh_device_score_sqlite(pool, tenant_id, device_id).await?;
    device_detail_sqlite(pool, tenant_id, device_id)
        .await?
        .context("SQLite-Agent-Device nach Enrollment nicht gefunden")
}

async fn record_heartbeat_postgres(
    pool: &PgPool,
    tenant_id: i64,
    device_id: i64,
    payload: AgentHeartbeatRequest,
) -> anyhow::Result<Option<AgentHeartbeatSummary>> {
    if device_detail_postgres(pool, tenant_id, device_id)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    let observed_at = normalized_or_default(payload.observed_at.as_deref(), "now");
    let status = normalized_or_default(payload.status.as_deref(), "OK").to_uppercase();
    let agent_version = normalized_or_default(payload.agent_version.as_deref(), "");
    let summary = payload.summary.unwrap_or_else(|| serde_json::json!({}));
    let row = sqlx::query(
        r#"
        INSERT INTO zero_trust_agent_heartbeat
            (tenant_id, device_id, observed_at, agent_version, status, summary_json, created_at)
        VALUES ($1, $2, CASE WHEN $3 = 'now' THEN CURRENT_TIMESTAMP::text ELSE $3 END, $4, $5, $6, CURRENT_TIMESTAMP::text)
        RETURNING id, tenant_id, device_id, observed_at, agent_version, status, summary_json, created_at
        "#,
    )
    .bind(tenant_id)
    .bind(device_id)
    .bind(observed_at)
    .bind(agent_version)
    .bind(status)
    .bind(summary.to_string())
    .fetch_one(pool)
    .await
    .context("PostgreSQL-Agent-Heartbeat konnte nicht gespeichert werden")?;
    sqlx::query(
        r#"
        UPDATE zero_trust_agent_device
        SET last_seen_at = $1, agent_version = COALESCE(NULLIF($2, ''), agent_version), updated_at = CURRENT_TIMESTAMP::text
        WHERE tenant_id = $3 AND id = $4
        "#,
    )
    .bind(row.try_get::<String, _>("observed_at")?)
    .bind(row.try_get::<String, _>("agent_version")?)
    .bind(tenant_id)
    .bind(device_id)
    .execute(pool)
    .await
    .context("PostgreSQL-Agent-Device konnte nach Heartbeat nicht aktualisiert werden")?;
    heartbeat_from_pg_row(row).map(Some).map_err(Into::into)
}

async fn record_heartbeat_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    device_id: i64,
    payload: AgentHeartbeatRequest,
) -> anyhow::Result<Option<AgentHeartbeatSummary>> {
    if device_detail_sqlite(pool, tenant_id, device_id)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    let observed_at = payload.observed_at.unwrap_or_else(|| "now".to_string());
    let status = normalized_or_default(payload.status.as_deref(), "OK").to_uppercase();
    let agent_version = normalized_or_default(payload.agent_version.as_deref(), "");
    let summary = payload.summary.unwrap_or_else(|| serde_json::json!({}));
    sqlx::query(
        r#"
        INSERT INTO zero_trust_agent_heartbeat
            (tenant_id, device_id, observed_at, agent_version, status, summary_json, created_at)
        VALUES (?1, ?2, CASE WHEN ?3 = 'now' THEN CURRENT_TIMESTAMP ELSE ?3 END, ?4, ?5, ?6, CURRENT_TIMESTAMP)
        "#,
    )
    .bind(tenant_id)
    .bind(device_id)
    .bind(normalized_or_default(Some(&observed_at), "now"))
    .bind(agent_version)
    .bind(status)
    .bind(summary.to_string())
    .execute(pool)
    .await
    .context("SQLite-Agent-Heartbeat konnte nicht gespeichert werden")?;
    let row = sqlx::query(
        r#"
        SELECT id, tenant_id, device_id, observed_at, agent_version, status, summary_json, created_at
        FROM zero_trust_agent_heartbeat
        WHERE tenant_id = ?1 AND device_id = ?2
        ORDER BY id DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(device_id)
    .fetch_one(pool)
    .await
    .context("SQLite-Agent-Heartbeat konnte nicht gelesen werden")?;
    sqlx::query(
        r#"
        UPDATE zero_trust_agent_device
        SET last_seen_at = ?1, agent_version = COALESCE(NULLIF(?2, ''), agent_version), updated_at = CURRENT_TIMESTAMP
        WHERE tenant_id = ?3 AND id = ?4
        "#,
    )
    .bind(row.try_get::<String, _>("observed_at")?)
    .bind(row.try_get::<String, _>("agent_version")?)
    .bind(tenant_id)
    .bind(device_id)
    .execute(pool)
    .await
    .context("SQLite-Agent-Device konnte nach Heartbeat nicht aktualisiert werden")?;
    heartbeat_from_sqlite_row(row).map(Some).map_err(Into::into)
}

async fn record_findings_postgres(
    pool: &PgPool,
    tenant_id: i64,
    device_id: i64,
    payload: AgentFindingsRequest,
) -> anyhow::Result<Option<(AgentDeviceSummary, Vec<AgentFindingSummary>)>> {
    if device_detail_postgres(pool, tenant_id, device_id)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    let mut created = Vec::new();
    for finding in payload.findings {
        let row = sqlx::query(
            r#"
            INSERT INTO zero_trust_agent_finding (
                tenant_id, device_id, check_id, pillar, severity, status, title,
                description, recommendation, evidence_json, observed_at, created_at, updated_at
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7,
                $8, $9, $10,
                COALESCE(NULLIF($11, ''), CURRENT_TIMESTAMP::text),
                CURRENT_TIMESTAMP::text, CURRENT_TIMESTAMP::text
            )
            RETURNING
                id, tenant_id, device_id, check_id, pillar, severity, status, title,
                description, recommendation, evidence_json, risk_id, evidence_item_id,
                observed_at, resolved_at, created_at, updated_at,
                NULL::text AS hostname
            "#,
        )
        .bind(tenant_id)
        .bind(device_id)
        .bind(normalized(&finding.check_id))
        .bind(normalized_pillar(&finding.pillar))
        .bind(normalized_severity(&finding.severity))
        .bind(normalized_status(finding.status.as_deref()))
        .bind(normalized(&finding.title))
        .bind(normalized_or_default(finding.description.as_deref(), ""))
        .bind(normalized_or_default(finding.recommendation.as_deref(), ""))
        .bind(
            finding
                .evidence
                .unwrap_or_else(|| serde_json::json!({}))
                .to_string(),
        )
        .bind(normalized_or_default(finding.observed_at.as_deref(), ""))
        .fetch_one(pool)
        .await
        .context("PostgreSQL-Agent-Finding konnte nicht gespeichert werden")?;
        created.push(finding_from_pg_row(row)?);
    }
    refresh_device_score_postgres(pool, tenant_id, device_id).await?;
    let device = device_detail_postgres(pool, tenant_id, device_id)
        .await?
        .context("PostgreSQL-Agent-Device nach Findings nicht gefunden")?;
    Ok(Some((device, created)))
}

async fn record_findings_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    device_id: i64,
    payload: AgentFindingsRequest,
) -> anyhow::Result<Option<(AgentDeviceSummary, Vec<AgentFindingSummary>)>> {
    if device_detail_sqlite(pool, tenant_id, device_id)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    let mut created = Vec::new();
    for finding in payload.findings {
        let row = sqlx::query(
            r#"
            INSERT INTO zero_trust_agent_finding (
                tenant_id, device_id, check_id, pillar, severity, status, title,
                description, recommendation, evidence_json, observed_at, created_at, updated_at
            )
            VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7,
                ?8, ?9, ?10,
                COALESCE(NULLIF(?11, ''), CURRENT_TIMESTAMP),
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            )
            RETURNING
                id, tenant_id, device_id, check_id, pillar, severity, status, title,
                description, recommendation, evidence_json, risk_id, evidence_item_id,
                observed_at, resolved_at, created_at, updated_at,
                NULL AS hostname
            "#,
        )
        .bind(tenant_id)
        .bind(device_id)
        .bind(normalized(&finding.check_id))
        .bind(normalized_pillar(&finding.pillar))
        .bind(normalized_severity(&finding.severity))
        .bind(normalized_status(finding.status.as_deref()))
        .bind(normalized(&finding.title))
        .bind(normalized_or_default(finding.description.as_deref(), ""))
        .bind(normalized_or_default(finding.recommendation.as_deref(), ""))
        .bind(
            finding
                .evidence
                .unwrap_or_else(|| serde_json::json!({}))
                .to_string(),
        )
        .bind(normalized_or_default(finding.observed_at.as_deref(), ""))
        .fetch_one(pool)
        .await
        .context("SQLite-Agent-Finding konnte nicht gespeichert werden")?;
        created.push(finding_from_sqlite_row(row)?);
    }
    refresh_device_score_sqlite(pool, tenant_id, device_id).await?;
    let device = device_detail_sqlite(pool, tenant_id, device_id)
        .await?
        .context("SQLite-Agent-Device nach Findings nicht gefunden")?;
    Ok(Some((device, created)))
}

async fn posture_overview_postgres(
    pool: &PgPool,
    tenant_id: i64,
) -> anyhow::Result<AgentPostureOverview> {
    let counts = sqlx::query(
        r#"
        SELECT
            (SELECT COUNT(*) FROM zero_trust_agent_device WHERE tenant_id = $1)::bigint AS device_count,
            (SELECT COUNT(*) FROM zero_trust_agent_device WHERE tenant_id = $1 AND enrollment_status = 'ACTIVE')::bigint AS active_device_count,
            (SELECT COUNT(*) FROM zero_trust_agent_device WHERE tenant_id = $1 AND (last_seen_at IS NULL OR last_seen_at < (CURRENT_TIMESTAMP - interval '14 days')::text))::bigint AS stale_device_count,
            (SELECT COUNT(*) FROM zero_trust_agent_finding WHERE tenant_id = $1 AND status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED'))::bigint AS open_finding_count,
            (SELECT COUNT(*) FROM zero_trust_agent_finding WHERE tenant_id = $1 AND status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED') AND severity = 'CRITICAL')::bigint AS critical_finding_count,
            (SELECT COUNT(*) FROM zero_trust_agent_finding WHERE tenant_id = $1 AND status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED') AND severity = 'HIGH')::bigint AS high_finding_count,
            COALESCE(ROUND(AVG(zero_trust_score)), 100)::bigint AS average_zero_trust_score
        FROM zero_trust_agent_device
        WHERE tenant_id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .context("PostgreSQL-Agent-Posture-Overview konnte nicht gelesen werden")?;
    Ok(AgentPostureOverview {
        tenant_id,
        device_count: counts.try_get("device_count")?,
        active_device_count: counts.try_get("active_device_count")?,
        stale_device_count: counts.try_get("stale_device_count")?,
        open_finding_count: counts.try_get("open_finding_count")?,
        critical_finding_count: counts.try_get("critical_finding_count")?,
        high_finding_count: counts.try_get("high_finding_count")?,
        average_zero_trust_score: counts.try_get("average_zero_trust_score")?,
        pillar_scores: list_pillar_scores_postgres(pool, tenant_id).await?,
        recent_devices: list_devices_postgres(pool, tenant_id, 10).await?,
        open_findings: list_open_findings_postgres(pool, tenant_id, 25).await?,
        check_catalog: list_check_catalog_postgres(pool).await?,
    })
}

async fn posture_overview_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
) -> anyhow::Result<AgentPostureOverview> {
    let counts = sqlx::query(
        r#"
        SELECT
            (SELECT COUNT(*) FROM zero_trust_agent_device WHERE tenant_id = ?1) AS device_count,
            (SELECT COUNT(*) FROM zero_trust_agent_device WHERE tenant_id = ?1 AND enrollment_status = 'ACTIVE') AS active_device_count,
            (SELECT COUNT(*) FROM zero_trust_agent_device WHERE tenant_id = ?1 AND (last_seen_at IS NULL OR last_seen_at < datetime('now', '-14 days'))) AS stale_device_count,
            (SELECT COUNT(*) FROM zero_trust_agent_finding WHERE tenant_id = ?1 AND status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED')) AS open_finding_count,
            (SELECT COUNT(*) FROM zero_trust_agent_finding WHERE tenant_id = ?1 AND status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED') AND severity = 'CRITICAL') AS critical_finding_count,
            (SELECT COUNT(*) FROM zero_trust_agent_finding WHERE tenant_id = ?1 AND status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED') AND severity = 'HIGH') AS high_finding_count,
            CAST(COALESCE(ROUND(AVG(zero_trust_score)), 100) AS INTEGER) AS average_zero_trust_score
        FROM zero_trust_agent_device
        WHERE tenant_id = ?1
        "#,
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .context("SQLite-Agent-Posture-Overview konnte nicht gelesen werden")?;
    Ok(AgentPostureOverview {
        tenant_id,
        device_count: counts.try_get("device_count")?,
        active_device_count: counts.try_get("active_device_count")?,
        stale_device_count: counts.try_get("stale_device_count")?,
        open_finding_count: counts.try_get("open_finding_count")?,
        critical_finding_count: counts.try_get("critical_finding_count")?,
        high_finding_count: counts.try_get("high_finding_count")?,
        average_zero_trust_score: counts.try_get("average_zero_trust_score")?,
        pillar_scores: list_pillar_scores_sqlite(pool, tenant_id).await?,
        recent_devices: list_devices_sqlite(pool, tenant_id, 10).await?,
        open_findings: list_open_findings_sqlite(pool, tenant_id, 25).await?,
        check_catalog: list_check_catalog_sqlite(pool).await?,
    })
}

async fn list_devices_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AgentDeviceSummary>> {
    let rows = sqlx::query(device_list_postgres_sql())
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Agent-Devices konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(device_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_devices_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AgentDeviceSummary>> {
    let rows = sqlx::query(device_list_sqlite_sql())
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("SQLite-Agent-Devices konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(device_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn device_detail_postgres(
    pool: &PgPool,
    tenant_id: i64,
    device_id: i64,
) -> anyhow::Result<Option<AgentDeviceSummary>> {
    let row = sqlx::query(device_detail_postgres_sql())
        .bind(tenant_id)
        .bind(device_id)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-Agent-Device konnte nicht gelesen werden")?;
    row.map(device_from_pg_row).transpose().map_err(Into::into)
}

async fn device_detail_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    device_id: i64,
) -> anyhow::Result<Option<AgentDeviceSummary>> {
    let row = sqlx::query(device_detail_sqlite_sql())
        .bind(tenant_id)
        .bind(device_id)
        .fetch_optional(pool)
        .await
        .context("SQLite-Agent-Device konnte nicht gelesen werden")?;
    row.map(device_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

async fn list_device_findings_postgres(
    pool: &PgPool,
    tenant_id: i64,
    device_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AgentFindingSummary>> {
    let sql = finding_list_postgres_sql("finding.device_id = $2", "$3");
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(device_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Agent-Findings konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(finding_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_device_findings_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    device_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AgentFindingSummary>> {
    let sql = finding_list_sqlite_sql("finding.device_id = ?2", "?3");
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(device_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("SQLite-Agent-Findings konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(finding_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_open_findings_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AgentFindingSummary>> {
    let sql = finding_list_postgres_sql(
        "finding.status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED')",
        "$2",
    );
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Agent-Open-Findings konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(finding_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_open_findings_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AgentFindingSummary>> {
    let sql = finding_list_sqlite_sql(
        "finding.status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED')",
        "?2",
    );
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("SQLite-Agent-Open-Findings konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(finding_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_pillar_scores_postgres(
    pool: &PgPool,
    tenant_id: i64,
) -> anyhow::Result<Vec<AgentPillarScore>> {
    let rows = sqlx::query(pillar_scores_postgres_sql())
        .bind(tenant_id)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Agent-Pillar-Scores konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(pillar_score_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_pillar_scores_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
) -> anyhow::Result<Vec<AgentPillarScore>> {
    let rows = sqlx::query(pillar_scores_sqlite_sql())
        .bind(tenant_id)
        .fetch_all(pool)
        .await
        .context("SQLite-Agent-Pillar-Scores konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(pillar_score_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_check_catalog_postgres(pool: &PgPool) -> anyhow::Result<Vec<AgentCheckCatalogItem>> {
    let rows = sqlx::query(check_catalog_sql())
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Agent-Check-Catalog konnte nicht gelesen werden")?;
    rows.into_iter()
        .map(check_catalog_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_check_catalog_sqlite(
    pool: &SqlitePool,
) -> anyhow::Result<Vec<AgentCheckCatalogItem>> {
    let rows = sqlx::query(check_catalog_sql())
        .fetch_all(pool)
        .await
        .context("SQLite-Agent-Check-Catalog konnte nicht gelesen werden")?;
    rows.into_iter()
        .map(check_catalog_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn refresh_device_score_postgres(
    pool: &PgPool,
    tenant_id: i64,
    device_id: i64,
) -> anyhow::Result<()> {
    let penalty: i64 = sqlx::query_scalar(
        r#"
        SELECT COALESCE(SUM(
            CASE severity
                WHEN 'CRITICAL' THEN 30
                WHEN 'HIGH' THEN 20
                WHEN 'MEDIUM' THEN 10
                WHEN 'LOW' THEN 5
                ELSE 0
            END
        ), 0)::bigint
        FROM zero_trust_agent_finding
        WHERE tenant_id = $1 AND device_id = $2 AND status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED')
        "#,
    )
    .bind(tenant_id)
    .bind(device_id)
    .fetch_one(pool)
    .await
    .context("PostgreSQL-Agent-Score konnte nicht berechnet werden")?;
    let score = (100 - penalty).clamp(0, 100);
    sqlx::query(
        "UPDATE zero_trust_agent_device SET zero_trust_score = $1, updated_at = CURRENT_TIMESTAMP::text WHERE tenant_id = $2 AND id = $3",
    )
    .bind(score)
    .bind(tenant_id)
    .bind(device_id)
    .execute(pool)
    .await
    .context("PostgreSQL-Agent-Score konnte nicht gespeichert werden")?;
    Ok(())
}

async fn refresh_device_score_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    device_id: i64,
) -> anyhow::Result<()> {
    let penalty: i64 = sqlx::query_scalar(
        r#"
        SELECT COALESCE(SUM(
            CASE severity
                WHEN 'CRITICAL' THEN 30
                WHEN 'HIGH' THEN 20
                WHEN 'MEDIUM' THEN 10
                WHEN 'LOW' THEN 5
                ELSE 0
            END
        ), 0)
        FROM zero_trust_agent_finding
        WHERE tenant_id = ?1 AND device_id = ?2 AND status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED')
        "#,
    )
    .bind(tenant_id)
    .bind(device_id)
    .fetch_one(pool)
    .await
    .context("SQLite-Agent-Score konnte nicht berechnet werden")?;
    let score = (100 - penalty).clamp(0, 100);
    sqlx::query(
        "UPDATE zero_trust_agent_device SET zero_trust_score = ?1, updated_at = CURRENT_TIMESTAMP WHERE tenant_id = ?2 AND id = ?3",
    )
    .bind(score)
    .bind(tenant_id)
    .bind(device_id)
    .execute(pool)
    .await
    .context("SQLite-Agent-Score konnte nicht gespeichert werden")?;
    Ok(())
}

fn device_list_postgres_sql() -> &'static str {
    r#"
    SELECT
        device.id, device.tenant_id, device.asset_id, device.stable_device_id,
        device.hostname, device.os_family, device.os_version, device.architecture,
        device.agent_version, device.deployment_channel, device.enrollment_status,
        device.policy_profile_id, policy.name AS policy_name,
        device.enrollment_token_id, device.last_enrolled_at,
        (device.mtls_fingerprint <> '') AS mtls_bound,
        device.zero_trust_score::bigint AS zero_trust_score,
        device.last_seen_at, device.created_at, device.updated_at,
        (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id)::bigint AS finding_count,
        (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id AND finding.status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED'))::bigint AS open_finding_count,
        (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id AND finding.status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED') AND finding.severity = 'CRITICAL')::bigint AS critical_finding_count,
        (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id AND finding.status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED') AND finding.severity = 'HIGH')::bigint AS high_finding_count
    FROM zero_trust_agent_device device
    LEFT JOIN zero_trust_agent_policy_profile policy
      ON policy.tenant_id = device.tenant_id AND policy.id = device.policy_profile_id
    WHERE device.tenant_id = $1
    ORDER BY COALESCE(device.last_seen_at, device.created_at) DESC, device.id DESC
    LIMIT $2
    "#
}

fn device_list_sqlite_sql() -> &'static str {
    r#"
    SELECT
        device.id, device.tenant_id, device.asset_id, device.stable_device_id,
        device.hostname, device.os_family, device.os_version, device.architecture,
        device.agent_version, device.deployment_channel, device.enrollment_status,
        device.policy_profile_id, policy.name AS policy_name,
        device.enrollment_token_id, device.last_enrolled_at,
        CASE WHEN device.mtls_fingerprint <> '' THEN 1 ELSE 0 END AS mtls_bound,
        device.zero_trust_score, device.last_seen_at, device.created_at, device.updated_at,
        (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id) AS finding_count,
        (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id AND finding.status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED')) AS open_finding_count,
        (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id AND finding.status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED') AND finding.severity = 'CRITICAL') AS critical_finding_count,
        (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id AND finding.status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED') AND finding.severity = 'HIGH') AS high_finding_count
    FROM zero_trust_agent_device device
    LEFT JOIN zero_trust_agent_policy_profile policy
      ON policy.tenant_id = device.tenant_id AND policy.id = device.policy_profile_id
    WHERE device.tenant_id = ?1
    ORDER BY COALESCE(device.last_seen_at, device.created_at) DESC, device.id DESC
    LIMIT ?2
    "#
}

fn device_detail_postgres_sql() -> &'static str {
    r#"
    SELECT * FROM (
        SELECT
            device.id, device.tenant_id, device.asset_id, device.stable_device_id,
            device.hostname, device.os_family, device.os_version, device.architecture,
            device.agent_version, device.deployment_channel, device.enrollment_status,
            device.policy_profile_id, policy.name AS policy_name,
            device.enrollment_token_id, device.last_enrolled_at,
            (device.mtls_fingerprint <> '') AS mtls_bound,
            device.zero_trust_score::bigint AS zero_trust_score,
            device.last_seen_at, device.created_at, device.updated_at,
            (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id)::bigint AS finding_count,
            (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id AND finding.status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED'))::bigint AS open_finding_count,
            (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id AND finding.status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED') AND finding.severity = 'CRITICAL')::bigint AS critical_finding_count,
            (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id AND finding.status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED') AND finding.severity = 'HIGH')::bigint AS high_finding_count
        FROM zero_trust_agent_device device
        LEFT JOIN zero_trust_agent_policy_profile policy
          ON policy.tenant_id = device.tenant_id AND policy.id = device.policy_profile_id
        WHERE device.tenant_id = $1 AND device.id = $2
    ) device_detail
    "#
}

fn device_detail_sqlite_sql() -> &'static str {
    r#"
    SELECT * FROM (
        SELECT
            device.id, device.tenant_id, device.asset_id, device.stable_device_id,
            device.hostname, device.os_family, device.os_version, device.architecture,
            device.agent_version, device.deployment_channel, device.enrollment_status,
            device.policy_profile_id, policy.name AS policy_name,
            device.enrollment_token_id, device.last_enrolled_at,
            CASE WHEN device.mtls_fingerprint <> '' THEN 1 ELSE 0 END AS mtls_bound,
            device.zero_trust_score, device.last_seen_at, device.created_at, device.updated_at,
            (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id) AS finding_count,
            (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id AND finding.status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED')) AS open_finding_count,
            (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id AND finding.status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED') AND finding.severity = 'CRITICAL') AS critical_finding_count,
            (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id AND finding.status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED') AND finding.severity = 'HIGH') AS high_finding_count
        FROM zero_trust_agent_device device
        LEFT JOIN zero_trust_agent_policy_profile policy
          ON policy.tenant_id = device.tenant_id AND policy.id = device.policy_profile_id
        WHERE device.tenant_id = ?1 AND device.id = ?2
    ) device_detail
    "#
}

fn finding_list_postgres_sql(where_clause: &str, limit_placeholder: &str) -> String {
    format!(
        r#"
        SELECT
            finding.id, finding.tenant_id, finding.device_id, device.hostname,
            finding.check_id, finding.pillar, finding.severity, finding.status,
            finding.title, finding.description, finding.recommendation,
            finding.evidence_json, finding.risk_id, finding.evidence_item_id,
            finding.observed_at, finding.resolved_at, finding.created_at, finding.updated_at
        FROM zero_trust_agent_finding finding
        JOIN zero_trust_agent_device device ON device.id = finding.device_id
        WHERE finding.tenant_id = $1 AND {where_clause}
        ORDER BY
            CASE finding.severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END,
            finding.observed_at DESC,
            finding.id DESC
        LIMIT {limit_placeholder}
        "#
    )
}

fn finding_list_sqlite_sql(where_clause: &str, limit_placeholder: &str) -> String {
    format!(
        r#"
        SELECT
            finding.id, finding.tenant_id, finding.device_id, device.hostname,
            finding.check_id, finding.pillar, finding.severity, finding.status,
            finding.title, finding.description, finding.recommendation,
            finding.evidence_json, finding.risk_id, finding.evidence_item_id,
            finding.observed_at, finding.resolved_at, finding.created_at, finding.updated_at
        FROM zero_trust_agent_finding finding
        JOIN zero_trust_agent_device device ON device.id = finding.device_id
        WHERE finding.tenant_id = ?1 AND {where_clause}
        ORDER BY
            CASE finding.severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END,
            finding.observed_at DESC,
            finding.id DESC
        LIMIT {limit_placeholder}
        "#
    )
}

fn pillar_scores_postgres_sql() -> &'static str {
    r#"
    SELECT
        pillar,
        GREATEST(0, 100 - COALESCE(SUM(
            CASE severity
                WHEN 'CRITICAL' THEN 30
                WHEN 'HIGH' THEN 20
                WHEN 'MEDIUM' THEN 10
                WHEN 'LOW' THEN 5
                ELSE 0
            END
        ), 0))::bigint AS score,
        COUNT(*) FILTER (WHERE status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED'))::bigint AS open_finding_count,
        COUNT(*) FILTER (WHERE status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED') AND severity = 'CRITICAL')::bigint AS critical_finding_count,
        COUNT(*) FILTER (WHERE status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED') AND severity = 'HIGH')::bigint AS high_finding_count
    FROM zero_trust_agent_finding
    WHERE tenant_id = $1 AND status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED')
    GROUP BY pillar
    ORDER BY pillar
    "#
}

fn pillar_scores_sqlite_sql() -> &'static str {
    r#"
    SELECT
        pillar,
        MAX(0, 100 - COALESCE(SUM(
            CASE severity
                WHEN 'CRITICAL' THEN 30
                WHEN 'HIGH' THEN 20
                WHEN 'MEDIUM' THEN 10
                WHEN 'LOW' THEN 5
                ELSE 0
            END
        ), 0)) AS score,
        COUNT(*) AS open_finding_count,
        SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_finding_count,
        SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) AS high_finding_count
    FROM zero_trust_agent_finding
    WHERE tenant_id = ?1 AND status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED')
    GROUP BY pillar
    ORDER BY pillar
    "#
}

fn check_catalog_sql() -> &'static str {
    r#"
    SELECT check_id, pillar, title, description, platform_scope, severity, recommendation, enabled
    FROM zero_trust_agent_check_catalog
    ORDER BY pillar, check_id
    "#
}

fn device_from_pg_row(row: PgRow) -> Result<AgentDeviceSummary, sqlx::Error> {
    Ok(AgentDeviceSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        asset_id: row.try_get("asset_id")?,
        stable_device_id: row.try_get("stable_device_id")?,
        hostname: row.try_get("hostname")?,
        os_family: row.try_get("os_family")?,
        os_version: row.try_get("os_version")?,
        architecture: row.try_get("architecture")?,
        agent_version: row.try_get("agent_version")?,
        deployment_channel: row.try_get("deployment_channel")?,
        enrollment_status: row.try_get("enrollment_status")?,
        policy_profile_id: row.try_get("policy_profile_id")?,
        policy_name: row.try_get("policy_name")?,
        enrollment_token_id: row.try_get("enrollment_token_id")?,
        last_enrolled_at: row.try_get("last_enrolled_at")?,
        mtls_bound: row.try_get("mtls_bound")?,
        zero_trust_score: row.try_get("zero_trust_score")?,
        last_seen_at: row.try_get("last_seen_at")?,
        open_finding_count: row.try_get("open_finding_count")?,
        critical_finding_count: row.try_get("critical_finding_count")?,
        high_finding_count: row.try_get("high_finding_count")?,
        finding_count: row.try_get("finding_count")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn device_from_sqlite_row(row: SqliteRow) -> Result<AgentDeviceSummary, sqlx::Error> {
    Ok(AgentDeviceSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        asset_id: row.try_get("asset_id")?,
        stable_device_id: row.try_get("stable_device_id")?,
        hostname: row.try_get("hostname")?,
        os_family: row.try_get("os_family")?,
        os_version: row.try_get("os_version")?,
        architecture: row.try_get("architecture")?,
        agent_version: row.try_get("agent_version")?,
        deployment_channel: row.try_get("deployment_channel")?,
        enrollment_status: row.try_get("enrollment_status")?,
        policy_profile_id: row.try_get("policy_profile_id")?,
        policy_name: row.try_get("policy_name")?,
        enrollment_token_id: row.try_get("enrollment_token_id")?,
        last_enrolled_at: row.try_get("last_enrolled_at")?,
        mtls_bound: row.try_get::<i64, _>("mtls_bound")? != 0,
        zero_trust_score: row.try_get("zero_trust_score")?,
        last_seen_at: row.try_get("last_seen_at")?,
        open_finding_count: row.try_get("open_finding_count")?,
        critical_finding_count: row.try_get("critical_finding_count")?,
        high_finding_count: row.try_get("high_finding_count")?,
        finding_count: row.try_get("finding_count")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn finding_from_pg_row(row: PgRow) -> Result<AgentFindingSummary, sqlx::Error> {
    let severity: String = row.try_get("severity")?;
    let status: String = row.try_get("status")?;
    Ok(AgentFindingSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        device_id: row.try_get("device_id")?,
        hostname: row.try_get("hostname")?,
        check_id: row.try_get("check_id")?,
        pillar: row.try_get("pillar")?,
        severity_label: severity_label(&severity).to_string(),
        severity,
        status_label: status_label(&status).to_string(),
        status,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        recommendation: row.try_get("recommendation")?,
        evidence: json_from_row_text(row.try_get("evidence_json")?),
        risk_id: row.try_get("risk_id")?,
        evidence_item_id: row.try_get("evidence_item_id")?,
        observed_at: row.try_get("observed_at")?,
        resolved_at: row.try_get("resolved_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn finding_from_sqlite_row(row: SqliteRow) -> Result<AgentFindingSummary, sqlx::Error> {
    let severity: String = row.try_get("severity")?;
    let status: String = row.try_get("status")?;
    Ok(AgentFindingSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        device_id: row.try_get("device_id")?,
        hostname: row.try_get("hostname")?,
        check_id: row.try_get("check_id")?,
        pillar: row.try_get("pillar")?,
        severity_label: severity_label(&severity).to_string(),
        severity,
        status_label: status_label(&status).to_string(),
        status,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        recommendation: row.try_get("recommendation")?,
        evidence: json_from_row_text(row.try_get("evidence_json")?),
        risk_id: row.try_get("risk_id")?,
        evidence_item_id: row.try_get("evidence_item_id")?,
        observed_at: row.try_get("observed_at")?,
        resolved_at: row.try_get("resolved_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn heartbeat_from_pg_row(row: PgRow) -> Result<AgentHeartbeatSummary, sqlx::Error> {
    Ok(AgentHeartbeatSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        device_id: row.try_get("device_id")?,
        observed_at: row.try_get("observed_at")?,
        agent_version: row.try_get("agent_version")?,
        status: row.try_get("status")?,
        summary: json_from_row_text(row.try_get("summary_json")?),
        created_at: row.try_get("created_at")?,
    })
}

fn heartbeat_from_sqlite_row(row: SqliteRow) -> Result<AgentHeartbeatSummary, sqlx::Error> {
    Ok(AgentHeartbeatSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        device_id: row.try_get("device_id")?,
        observed_at: row.try_get("observed_at")?,
        agent_version: row.try_get("agent_version")?,
        status: row.try_get("status")?,
        summary: json_from_row_text(row.try_get("summary_json")?),
        created_at: row.try_get("created_at")?,
    })
}

fn pillar_score_from_pg_row(row: PgRow) -> Result<AgentPillarScore, sqlx::Error> {
    Ok(AgentPillarScore {
        pillar: row.try_get("pillar")?,
        score: row.try_get("score")?,
        open_finding_count: row.try_get("open_finding_count")?,
        critical_finding_count: row.try_get("critical_finding_count")?,
        high_finding_count: row.try_get("high_finding_count")?,
    })
}

fn pillar_score_from_sqlite_row(row: SqliteRow) -> Result<AgentPillarScore, sqlx::Error> {
    Ok(AgentPillarScore {
        pillar: row.try_get("pillar")?,
        score: row.try_get("score")?,
        open_finding_count: row.try_get("open_finding_count")?,
        critical_finding_count: row.try_get("critical_finding_count")?,
        high_finding_count: row.try_get("high_finding_count")?,
    })
}

fn check_catalog_from_pg_row(row: PgRow) -> Result<AgentCheckCatalogItem, sqlx::Error> {
    Ok(AgentCheckCatalogItem {
        check_id: row.try_get("check_id")?,
        pillar: row.try_get("pillar")?,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        platform_scope: row.try_get("platform_scope")?,
        severity: row.try_get("severity")?,
        recommendation: row.try_get("recommendation")?,
        enabled: row.try_get("enabled")?,
    })
}

fn check_catalog_from_sqlite_row(row: SqliteRow) -> Result<AgentCheckCatalogItem, sqlx::Error> {
    let enabled: i64 = row.try_get("enabled")?;
    Ok(AgentCheckCatalogItem {
        check_id: row.try_get("check_id")?,
        pillar: row.try_get("pillar")?,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        platform_scope: row.try_get("platform_scope")?,
        severity: row.try_get("severity")?,
        recommendation: row.try_get("recommendation")?,
        enabled: enabled != 0,
    })
}

fn enrollment_token_list_postgres_sql() -> &'static str {
    r#"
    SELECT token.id, token.tenant_id, token.label, token.token_hint, token.status,
        token.rollout_os_family, token.allowed_os_families,
        token.allowed_deployment_channel, token.policy_profile_id,
        policy.name AS policy_name, token.mtls_fingerprint, token.expires_at,
        token.max_uses, token.uses_count, token.uses_remaining, token.created_by_id,
        token.last_attempt_at, token.last_used_at, token.revoked_at,
        token.created_at, token.updated_at
    FROM zero_trust_agent_enrollment_token token
    LEFT JOIN zero_trust_agent_policy_profile policy
      ON policy.tenant_id = token.tenant_id AND policy.id = token.policy_profile_id
    WHERE token.tenant_id = $1
    ORDER BY token.created_at DESC, token.id DESC
    LIMIT $2
    "#
}

fn enrollment_token_list_sqlite_sql() -> &'static str {
    r#"
    SELECT token.id, token.tenant_id, token.label, token.token_hint, token.status,
        token.rollout_os_family, token.allowed_os_families,
        token.allowed_deployment_channel, token.policy_profile_id,
        policy.name AS policy_name, token.mtls_fingerprint, token.expires_at,
        token.max_uses, token.uses_count, token.uses_remaining, token.created_by_id,
        token.last_attempt_at, token.last_used_at, token.revoked_at,
        token.created_at, token.updated_at
    FROM zero_trust_agent_enrollment_token token
    LEFT JOIN zero_trust_agent_policy_profile policy
      ON policy.tenant_id = token.tenant_id AND policy.id = token.policy_profile_id
    WHERE token.tenant_id = ?1
    ORDER BY token.created_at DESC, token.id DESC
    LIMIT ?2
    "#
}

fn enrollment_token_detail_postgres_sql() -> &'static str {
    r#"
    SELECT token.id, token.tenant_id, token.label, token.token_hint, token.status,
        token.rollout_os_family, token.allowed_os_families,
        token.allowed_deployment_channel, token.policy_profile_id,
        policy.name AS policy_name, token.mtls_fingerprint, token.expires_at,
        token.max_uses, token.uses_count, token.uses_remaining, token.created_by_id,
        token.last_attempt_at, token.last_used_at, token.revoked_at,
        token.created_at, token.updated_at
    FROM zero_trust_agent_enrollment_token token
    LEFT JOIN zero_trust_agent_policy_profile policy
      ON policy.tenant_id = token.tenant_id AND policy.id = token.policy_profile_id
    WHERE token.tenant_id = $1 AND token.id = $2
    "#
}

fn enrollment_token_detail_sqlite_sql() -> &'static str {
    r#"
    SELECT token.id, token.tenant_id, token.label, token.token_hint, token.status,
        token.rollout_os_family, token.allowed_os_families,
        token.allowed_deployment_channel, token.policy_profile_id,
        policy.name AS policy_name, token.mtls_fingerprint, token.expires_at,
        token.max_uses, token.uses_count, token.uses_remaining, token.created_by_id,
        token.last_attempt_at, token.last_used_at, token.revoked_at,
        token.created_at, token.updated_at
    FROM zero_trust_agent_enrollment_token token
    LEFT JOIN zero_trust_agent_policy_profile policy
      ON policy.tenant_id = token.tenant_id AND policy.id = token.policy_profile_id
    WHERE token.tenant_id = ?1 AND token.id = ?2
    "#
}

fn enrollment_audit_postgres_sql() -> &'static str {
    r#"
    SELECT id, tenant_id, token_id, device_id, event_type, actor_id, detail_json, created_at
    FROM zero_trust_agent_enrollment_audit
    WHERE tenant_id = $1
    ORDER BY created_at DESC, id DESC
    LIMIT $2
    "#
}

fn enrollment_audit_sqlite_sql() -> &'static str {
    r#"
    SELECT id, tenant_id, token_id, device_id, event_type, actor_id, detail_json, created_at
    FROM zero_trust_agent_enrollment_audit
    WHERE tenant_id = ?1
    ORDER BY created_at DESC, id DESC
    LIMIT ?2
    "#
}

fn enrollment_token_from_pg_row(row: PgRow) -> Result<AgentEnrollmentTokenSummary, sqlx::Error> {
    let allowed_raw: String = row.try_get("allowed_os_families")?;
    Ok(AgentEnrollmentTokenSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        label: row.try_get("label")?,
        token_hint: row.try_get("token_hint")?,
        status: row.try_get("status")?,
        rollout_os_family: row.try_get("rollout_os_family")?,
        allowed_os_families: parse_allowed_os_families(&allowed_raw),
        allowed_deployment_channel: row.try_get("allowed_deployment_channel")?,
        policy_profile_id: row.try_get("policy_profile_id")?,
        policy_name: row.try_get("policy_name")?,
        mtls_fingerprint: row.try_get("mtls_fingerprint")?,
        expires_at: row.try_get("expires_at")?,
        max_uses: row.try_get("max_uses")?,
        uses_count: row.try_get("uses_count")?,
        uses_remaining: row.try_get("uses_remaining")?,
        created_by_id: row.try_get("created_by_id")?,
        last_attempt_at: row.try_get("last_attempt_at")?,
        last_used_at: row.try_get("last_used_at")?,
        revoked_at: row.try_get("revoked_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn enrollment_token_from_sqlite_row(
    row: SqliteRow,
) -> Result<AgentEnrollmentTokenSummary, sqlx::Error> {
    let allowed_raw: String = row.try_get("allowed_os_families")?;
    Ok(AgentEnrollmentTokenSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        label: row.try_get("label")?,
        token_hint: row.try_get("token_hint")?,
        status: row.try_get("status")?,
        rollout_os_family: row.try_get("rollout_os_family")?,
        allowed_os_families: parse_allowed_os_families(&allowed_raw),
        allowed_deployment_channel: row.try_get("allowed_deployment_channel")?,
        policy_profile_id: row.try_get("policy_profile_id")?,
        policy_name: row.try_get("policy_name")?,
        mtls_fingerprint: row.try_get("mtls_fingerprint")?,
        expires_at: row.try_get("expires_at")?,
        max_uses: row.try_get("max_uses")?,
        uses_count: row.try_get("uses_count")?,
        uses_remaining: row.try_get("uses_remaining")?,
        created_by_id: row.try_get("created_by_id")?,
        last_attempt_at: row.try_get("last_attempt_at")?,
        last_used_at: row.try_get("last_used_at")?,
        revoked_at: row.try_get("revoked_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn enrollment_token_grant_from_pg_row(row: PgRow) -> Result<EnrollmentTokenGrant, sqlx::Error> {
    Ok(EnrollmentTokenGrant {
        id: row.try_get("id")?,
        policy_profile_id: row.try_get("policy_profile_id")?,
        mtls_fingerprint: row.try_get("mtls_fingerprint")?,
        status: row.try_get("status")?,
    })
}

fn enrollment_token_grant_from_sqlite_row(
    row: SqliteRow,
) -> Result<EnrollmentTokenGrant, sqlx::Error> {
    Ok(EnrollmentTokenGrant {
        id: row.try_get("id")?,
        policy_profile_id: row.try_get("policy_profile_id")?,
        mtls_fingerprint: row.try_get("mtls_fingerprint")?,
        status: row.try_get("status")?,
    })
}

fn enrollment_audit_from_pg_row(row: PgRow) -> Result<AgentEnrollmentAuditEvent, sqlx::Error> {
    let detail: sqlx::types::Json<Value> = row.try_get("detail_json")?;
    Ok(AgentEnrollmentAuditEvent {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        token_id: row.try_get("token_id")?,
        device_id: row.try_get("device_id")?,
        event_type: row.try_get("event_type")?,
        actor_id: row.try_get("actor_id")?,
        detail: detail.0,
        created_at: row.try_get("created_at")?,
    })
}

fn enrollment_audit_from_sqlite_row(
    row: SqliteRow,
) -> Result<AgentEnrollmentAuditEvent, sqlx::Error> {
    let detail_raw: String = row.try_get("detail_json")?;
    Ok(AgentEnrollmentAuditEvent {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        token_id: row.try_get("token_id")?,
        device_id: row.try_get("device_id")?,
        event_type: row.try_get("event_type")?,
        actor_id: row.try_get("actor_id")?,
        detail: json_from_row_text(detail_raw),
        created_at: row.try_get("created_at")?,
    })
}

fn validate_enroll_payload(payload: &AgentEnrollRequest) -> anyhow::Result<()> {
    for (field_name, value) in [
        ("stable_device_id", payload.stable_device_id.as_str()),
        ("hostname", payload.hostname.as_str()),
        ("os_family", payload.os_family.as_str()),
        ("architecture", payload.architecture.as_str()),
        ("agent_version", payload.agent_version.as_str()),
    ] {
        if value.trim().is_empty() {
            bail!("Agent-Enrollment-Feld '{field_name}' darf nicht leer sein");
        }
    }
    if payload.stable_device_id.len() > 128 {
        bail!("Agent-Enrollment-Feld 'stable_device_id' darf maximal 128 Zeichen enthalten");
    }
    let os_family = normalized_upper(&payload.os_family);
    if !AGENT_OS_FAMILIES.contains(&os_family.as_str()) {
        bail!("Agent-Enrollment-Feld 'os_family' ist nicht unterstuetzt");
    }
    let deployment_channel =
        normalized_or_default(payload.deployment_channel.as_deref(), "manual").to_ascii_lowercase();
    if !AGENT_DEPLOYMENT_CHANNELS.contains(&deployment_channel.as_str()) {
        bail!("Agent-Enrollment-Feld 'deployment_channel' ist nicht unterstuetzt");
    }
    Ok(())
}

fn validate_enrollment_token_payload(
    payload: &AgentEnrollmentTokenCreateRequest,
) -> anyhow::Result<()> {
    if let Some(uses_remaining) = payload.uses_remaining {
        if !(1..=10_000).contains(&uses_remaining) {
            bail!("Agent-Enrollment-Token uses_remaining muss zwischen 1 und 10000 liegen");
        }
    }
    if let Some(expires_at) = payload.expires_at.as_deref() {
        let expires_at = normalize_optional_rfc3339(Some(expires_at))?
            .context("Agent-Enrollment-Token expires_at fehlt")?;
        if timestamp_is_expired(&expires_at) {
            bail!("Agent-Enrollment-Token expires_at muss in der Zukunft liegen");
        }
    }
    if let Some(allowed_os_families) = payload.allowed_os_families.as_ref() {
        if allowed_os_families.len() > 20 {
            bail!("Agent-Enrollment-Token darf maximal 20 OS-Familien einschraenken");
        }
        for os_family in allowed_os_families {
            let os_family = normalized_upper(os_family);
            if !ONBOARDING_OS_FAMILIES.contains(&os_family.as_str()) {
                bail!("Agent-Enrollment-Token enthaelt eine nicht unterstuetzte OS-Familie");
            }
        }
    }
    if let Some(rollout_os_family) = payload.rollout_os_family.as_deref() {
        normalized_onboarding_os_family(rollout_os_family)?;
    }
    if let Some(deployment_channel) = payload.allowed_deployment_channel.as_deref() {
        normalize_optional_deployment_channel(Some(deployment_channel))?;
    }
    if payload
        .policy_profile_id
        .is_some_and(|policy_id| policy_id <= 0)
    {
        bail!("Agent-Policy-Profil-ID muss positiv sein");
    }
    Ok(())
}

fn validate_finding(finding: &AgentFindingInput) -> anyhow::Result<()> {
    for (field_name, value) in [
        ("check_id", finding.check_id.as_str()),
        ("pillar", finding.pillar.as_str()),
        ("severity", finding.severity.as_str()),
        ("title", finding.title.as_str()),
    ] {
        if value.trim().is_empty() {
            bail!("Agent-Finding-Feld '{field_name}' darf nicht leer sein");
        }
    }
    Ok(())
}

fn normalized(value: &str) -> String {
    value.trim().chars().take(255).collect()
}

fn normalized_upper(value: &str) -> String {
    normalized(value).to_ascii_uppercase()
}

fn normalized_allowed_os_families(values: Vec<String>) -> Vec<String> {
    let mut normalized_values = Vec::new();
    for value in values {
        let value = match normalized_upper(&value).as_str() {
            "NIXOS" => "LINUX".to_string(),
            other => other.to_string(),
        };
        if !value.is_empty() && !normalized_values.contains(&value) {
            normalized_values.push(value);
        }
    }
    normalized_values
}

fn normalized_or_default(value: Option<&str>, default_value: &str) -> String {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(default_value)
        .chars()
        .take(512)
        .collect()
}

fn normalize_optional_fingerprint(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase().chars().take(255).collect())
}

fn normalized_onboarding_os_family(value: &str) -> anyhow::Result<String> {
    let value = normalized_upper(value);
    if !ONBOARDING_OS_FAMILIES.contains(&value.as_str()) {
        bail!("Agent-Onboarding OS-Familie ist nicht unterstuetzt");
    }
    Ok(value)
}

fn normalize_optional_deployment_channel(value: Option<&str>) -> anyhow::Result<String> {
    let value = value.unwrap_or("").trim().to_ascii_lowercase();
    if value.is_empty() {
        return Ok(String::new());
    }
    if !AGENT_DEPLOYMENT_CHANNELS.contains(&value.as_str()) {
        bail!("Agent-Deployment-Kanal ist nicht unterstuetzt");
    }
    Ok(value)
}

fn normalize_optional_rfc3339(value: Option<&str>) -> anyhow::Result<Option<String>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    DateTime::parse_from_rfc3339(value)
        .with_context(|| "Agent-Enrollment-Token expires_at muss RFC3339 sein")?;
    Ok(Some(value.to_string()))
}

fn timestamp_is_expired(value: &str) -> bool {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc) <= Utc::now())
        .unwrap_or(true)
}

fn normalized_pillar(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "identity" | "identities" => "IDENTITY",
        "device" | "devices" => "DEVICES",
        "network" | "networks" => "NETWORKS",
        "application" | "applications" | "workload" | "workloads" => "APPLICATIONS_WORKLOADS",
        "data" => "DATA",
        "visibility" | "analytics" | "visibility_analytics" => "VISIBILITY_ANALYTICS",
        "automation" | "orchestration" | "automation_orchestration" => "AUTOMATION_ORCHESTRATION",
        "governance" => "GOVERNANCE",
        _ => "DEVICES",
    }
    .to_string()
}

fn normalized_severity(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "critical" => "CRITICAL",
        "high" => "HIGH",
        "medium" => "MEDIUM",
        "low" => "LOW",
        "info" | "informational" | "observed" => "INFO",
        _ => "MEDIUM",
    }
    .to_string()
}

fn normalized_status(value: Option<&str>) -> String {
    match value.unwrap_or("OPEN").trim().to_ascii_lowercase().as_str() {
        "resolved" | "closed" | "done" => "RESOLVED",
        "accepted" | "risk_accepted" => "ACCEPTED",
        "observed" | "evidence" | "info" => "OBSERVED",
        "suppressed" => "SUPPRESSED",
        _ => "OPEN",
    }
    .to_string()
}

fn severity_label(value: &str) -> &'static str {
    match value {
        "CRITICAL" => "Kritisch",
        "HIGH" => "Hoch",
        "MEDIUM" => "Mittel",
        "LOW" => "Niedrig",
        "INFO" => "Info",
        _ => "Mittel",
    }
}

fn status_label(value: &str) -> &'static str {
    match value {
        "OPEN" => "Offen",
        "RESOLVED" => "Geloest",
        "ACCEPTED" => "Akzeptiert",
        "OBSERVED" => "Beobachtet",
        "SUPPRESSED" => "Unterdrueckt",
        _ => "Offen",
    }
}

fn json_from_row_text(raw: String) -> Value {
    serde_json::from_str(&raw).unwrap_or_else(|_| serde_json::json!({}))
}

fn parse_allowed_os_families(raw: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(raw)
        .map(normalized_allowed_os_families)
        .unwrap_or_default()
}

fn random_secret(prefix: &str) -> anyhow::Result<String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|err| anyhow::anyhow!("Agent-Secret konnte nicht erzeugt werden: {err}"))?;
    Ok(format!("{prefix}_{}", bytes_to_hex(&bytes)))
}

fn sha256_hex(value: &str) -> String {
    bytes_to_hex(&Sha256::digest(value.as_bytes()))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn secret_hint(secret: &str) -> String {
    let suffix = secret
        .chars()
        .rev()
        .take(8)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();
    format!("...{suffix}")
}

fn agent_credentials_match(
    stored_hash: &str,
    supplied_hash: &str,
    stored_mtls: &str,
    supplied_mtls: Option<&str>,
) -> bool {
    let stored_hash = stored_hash.trim();
    if stored_hash.is_empty() || !constant_time_eq(stored_hash.as_bytes(), supplied_hash.as_bytes())
    {
        return false;
    }
    let stored_mtls = stored_mtls.trim();
    if stored_mtls.is_empty() {
        return true;
    }
    supplied_mtls
        .map(|value| constant_time_eq(stored_mtls.as_bytes(), value.as_bytes()))
        .unwrap_or(false)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (left, right) in left.iter().zip(right.iter()) {
        diff |= *left ^ *right;
    }
    diff == 0
}
