use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Row,
};

use crate::cve_store::normalize_database_url;

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
        device.zero_trust_score, device.last_seen_at, device.created_at, device.updated_at,
        (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id)::bigint AS finding_count,
        (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id AND finding.status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED'))::bigint AS open_finding_count,
        (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id AND finding.status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED') AND finding.severity = 'CRITICAL')::bigint AS critical_finding_count,
        (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id AND finding.status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED') AND finding.severity = 'HIGH')::bigint AS high_finding_count
    FROM zero_trust_agent_device device
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
        device.zero_trust_score, device.last_seen_at, device.created_at, device.updated_at,
        (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id) AS finding_count,
        (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id AND finding.status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED')) AS open_finding_count,
        (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id AND finding.status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED') AND finding.severity = 'CRITICAL') AS critical_finding_count,
        (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id AND finding.status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED') AND finding.severity = 'HIGH') AS high_finding_count
    FROM zero_trust_agent_device device
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
            device.zero_trust_score, device.last_seen_at, device.created_at, device.updated_at,
            (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id)::bigint AS finding_count,
            (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id AND finding.status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED'))::bigint AS open_finding_count,
            (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id AND finding.status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED') AND finding.severity = 'CRITICAL')::bigint AS critical_finding_count,
            (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id AND finding.status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED') AND finding.severity = 'HIGH')::bigint AS high_finding_count
        FROM zero_trust_agent_device device
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
            device.zero_trust_score, device.last_seen_at, device.created_at, device.updated_at,
            (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id) AS finding_count,
            (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id AND finding.status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED')) AS open_finding_count,
            (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id AND finding.status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED') AND finding.severity = 'CRITICAL') AS critical_finding_count,
            (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.device_id = device.id AND finding.status NOT IN ('RESOLVED', 'ACCEPTED', 'OBSERVED') AND finding.severity = 'HIGH') AS high_finding_count
        FROM zero_trust_agent_device device
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

fn normalized_or_default(value: Option<&str>, default_value: &str) -> String {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(default_value)
        .chars()
        .take(512)
        .collect()
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
