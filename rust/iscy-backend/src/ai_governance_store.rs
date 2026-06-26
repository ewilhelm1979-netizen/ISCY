use anyhow::{bail, Context};
use chrono::{NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Row,
};

use crate::cve_store::normalize_database_url;

#[derive(Clone)]
pub enum AiGovernanceStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Serialize)]
pub struct AiGovernanceOverview {
    pub tenant_id: i64,
    pub summary: AiGovernanceSummary,
    pub systems: Vec<AiGovernanceSystemSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiGovernanceSummary {
    pub total_systems: i64,
    pub high_risk_systems: i64,
    pub not_assessed_systems: i64,
    pub review_due_systems: i64,
    pub evidence_missing: i64,
    pub open_governance_gaps: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiGovernanceSystemSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub product_id: Option<i64>,
    pub product_name: Option<String>,
    pub owner_id: Option<i64>,
    pub owner_display: Option<String>,
    pub name: String,
    pub purpose: String,
    pub model_provider: String,
    pub model_name: String,
    pub model_version: String,
    pub deployment_context: String,
    pub data_categories: String,
    pub decision_impact: String,
    pub human_oversight: String,
    pub ai_act_classification: String,
    pub ai_act_classification_label: String,
    pub criticality: String,
    pub criticality_label: String,
    pub status: String,
    pub status_label: String,
    pub logging_required: bool,
    pub transparency_required: bool,
    pub cybersecurity_required: bool,
    pub monitoring_plan: String,
    pub evidence_key: String,
    pub risk_summary: String,
    pub next_review_due_at: Option<String>,
    pub notes: String,
    pub evidence_count: i64,
    pub approved_evidence_count: i64,
    pub open_requirement_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiGovernanceSystemDetail {
    pub system: AiGovernanceSystemSummary,
    pub requirements: Vec<AiGovernanceRequirementSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiGovernanceRequirementSummary {
    pub key: String,
    pub label: String,
    pub status: String,
    pub status_label: String,
    pub detail: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AiGovernanceSystemCreateRequest {
    pub product_id: Option<i64>,
    pub owner_id: Option<i64>,
    pub name: String,
    #[serde(default)]
    pub purpose: String,
    #[serde(default)]
    pub model_provider: String,
    #[serde(default)]
    pub model_name: String,
    #[serde(default)]
    pub model_version: String,
    #[serde(default)]
    pub deployment_context: String,
    #[serde(default)]
    pub data_categories: String,
    #[serde(default)]
    pub decision_impact: String,
    #[serde(default)]
    pub human_oversight: String,
    pub ai_act_classification: Option<String>,
    pub criticality: Option<String>,
    pub status: Option<String>,
    pub logging_required: Option<bool>,
    pub transparency_required: Option<bool>,
    pub cybersecurity_required: Option<bool>,
    #[serde(default)]
    pub monitoring_plan: String,
    pub evidence_key: Option<String>,
    #[serde(default)]
    pub risk_summary: String,
    pub next_review_due_at: Option<String>,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AiGovernanceSystemUpdateRequest {
    pub product_id: Option<i64>,
    pub owner_id: Option<i64>,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub model_provider: Option<String>,
    pub model_name: Option<String>,
    pub model_version: Option<String>,
    pub deployment_context: Option<String>,
    pub data_categories: Option<String>,
    pub decision_impact: Option<String>,
    pub human_oversight: Option<String>,
    pub ai_act_classification: Option<String>,
    pub criticality: Option<String>,
    pub status: Option<String>,
    pub logging_required: Option<bool>,
    pub transparency_required: Option<bool>,
    pub cybersecurity_required: Option<bool>,
    pub monitoring_plan: Option<String>,
    pub evidence_key: Option<String>,
    pub risk_summary: Option<String>,
    pub next_review_due_at: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiGovernanceSystemWriteResult {
    pub system: AiGovernanceSystemSummary,
    pub requirements: Vec<AiGovernanceRequirementSummary>,
}

impl AiGovernanceStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer AI-Governance-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer AI-Governance-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-AI-Governance-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn overview(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<AiGovernanceOverview> {
        let systems = match self {
            Self::Postgres(pool) => list_systems_postgres(pool, tenant_id, limit).await?,
            Self::Sqlite(pool) => list_systems_sqlite(pool, tenant_id, limit).await?,
        };
        let summary = ai_governance_summary(&systems);
        Ok(AiGovernanceOverview {
            tenant_id,
            summary,
            systems,
        })
    }

    pub async fn detail(
        &self,
        tenant_id: i64,
        system_id: i64,
    ) -> anyhow::Result<Option<AiGovernanceSystemDetail>> {
        let system = match self {
            Self::Postgres(pool) => system_detail_postgres(pool, tenant_id, system_id).await?,
            Self::Sqlite(pool) => system_detail_sqlite(pool, tenant_id, system_id).await?,
        };
        Ok(system.map(|system| AiGovernanceSystemDetail {
            requirements: ai_governance_requirements(&system),
            system,
        }))
    }

    pub async fn create_system(
        &self,
        tenant_id: i64,
        payload: AiGovernanceSystemCreateRequest,
    ) -> anyhow::Result<AiGovernanceSystemWriteResult> {
        let name = clean_required(&payload.name, "AI-System-Name")?;
        let ai_act_classification = normalize_ai_act_classification(
            payload
                .ai_act_classification
                .as_deref()
                .unwrap_or("NOT_ASSESSED"),
        );
        let criticality = normalize_criticality(payload.criticality.as_deref().unwrap_or("MEDIUM"));
        let status = normalize_status(payload.status.as_deref().unwrap_or("IN_REVIEW"));
        let evidence_key = payload
            .evidence_key
            .as_deref()
            .map(clean_text)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| format!("AI-GOV:SYSTEM:{}", slug_key(&name)));
        let system_id = match self {
            Self::Postgres(pool) => {
                create_system_postgres(
                    pool,
                    tenant_id,
                    &payload,
                    &name,
                    &ai_act_classification,
                    &criticality,
                    &status,
                    &evidence_key,
                )
                .await?
            }
            Self::Sqlite(pool) => {
                create_system_sqlite(
                    pool,
                    tenant_id,
                    &payload,
                    &name,
                    &ai_act_classification,
                    &criticality,
                    &status,
                    &evidence_key,
                )
                .await?
            }
        };
        self.detail(tenant_id, system_id)
            .await?
            .map(|detail| AiGovernanceSystemWriteResult {
                system: detail.system,
                requirements: detail.requirements,
            })
            .context("Angelegtes AI-Governance-System konnte nicht gelesen werden")
    }

    pub async fn update_system(
        &self,
        tenant_id: i64,
        system_id: i64,
        payload: AiGovernanceSystemUpdateRequest,
    ) -> anyhow::Result<Option<AiGovernanceSystemWriteResult>> {
        let Some(existing) = self
            .detail(tenant_id, system_id)
            .await?
            .map(|detail| detail.system)
        else {
            return Ok(None);
        };
        let next = merged_update(existing, payload)?;
        match self {
            Self::Postgres(pool) => update_system_postgres(pool, &next).await?,
            Self::Sqlite(pool) => update_system_sqlite(pool, &next).await?,
        };
        Ok(self
            .detail(tenant_id, system_id)
            .await?
            .map(|detail| AiGovernanceSystemWriteResult {
                system: detail.system,
                requirements: detail.requirements,
            }))
    }
}

async fn list_systems_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AiGovernanceSystemSummary>> {
    let query = format!(
        "{POSTGRES_AI_GOVERNANCE_SELECT}
WHERE system.tenant_id = $1
ORDER BY
    CASE UPPER(system.ai_act_classification)
        WHEN 'PROHIBITED' THEN 6
        WHEN 'HIGH_RISK' THEN 5
        WHEN 'NOT_ASSESSED' THEN 4
        WHEN 'LIMITED_RISK' THEN 3
        WHEN 'MINIMAL_RISK' THEN 2
        ELSE 1
    END DESC,
    COALESCE(system.next_review_due_at, '9999-12-31') ASC,
    system.name ASC
LIMIT $2"
    );
    let rows = sqlx::query(&query)
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-AI-Governance-Register konnte nicht gelesen werden")?;
    rows.into_iter()
        .map(ai_system_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_systems_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AiGovernanceSystemSummary>> {
    let query = format!(
        "{SQLITE_AI_GOVERNANCE_SELECT}
WHERE system.tenant_id = ?
ORDER BY
    CASE UPPER(system.ai_act_classification)
        WHEN 'PROHIBITED' THEN 6
        WHEN 'HIGH_RISK' THEN 5
        WHEN 'NOT_ASSESSED' THEN 4
        WHEN 'LIMITED_RISK' THEN 3
        WHEN 'MINIMAL_RISK' THEN 2
        ELSE 1
    END DESC,
    COALESCE(system.next_review_due_at, '9999-12-31') ASC,
    system.name ASC
LIMIT ?"
    );
    let rows = sqlx::query(&query)
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("SQLite-AI-Governance-Register konnte nicht gelesen werden")?;
    rows.into_iter()
        .map(ai_system_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn system_detail_postgres(
    pool: &PgPool,
    tenant_id: i64,
    system_id: i64,
) -> anyhow::Result<Option<AiGovernanceSystemSummary>> {
    let query =
        format!("{POSTGRES_AI_GOVERNANCE_SELECT}\nWHERE system.tenant_id = $1 AND system.id = $2");
    let row = sqlx::query(&query)
        .bind(tenant_id)
        .bind(system_id)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-AI-Governance-Detail konnte nicht gelesen werden")?;
    row.map(ai_system_from_pg_row)
        .transpose()
        .map_err(Into::into)
}

async fn system_detail_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    system_id: i64,
) -> anyhow::Result<Option<AiGovernanceSystemSummary>> {
    let query =
        format!("{SQLITE_AI_GOVERNANCE_SELECT}\nWHERE system.tenant_id = ? AND system.id = ?");
    let row = sqlx::query(&query)
        .bind(tenant_id)
        .bind(system_id)
        .fetch_optional(pool)
        .await
        .context("SQLite-AI-Governance-Detail konnte nicht gelesen werden")?;
    row.map(ai_system_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

#[allow(clippy::too_many_arguments)]
async fn create_system_postgres(
    pool: &PgPool,
    tenant_id: i64,
    payload: &AiGovernanceSystemCreateRequest,
    name: &str,
    ai_act_classification: &str,
    criticality: &str,
    status: &str,
    evidence_key: &str,
) -> anyhow::Result<i64> {
    sqlx::query_scalar(
        r#"
        INSERT INTO ai_governance_system (
            tenant_id, product_id, owner_id, name, purpose, model_provider, model_name,
            model_version, deployment_context, data_categories, decision_impact,
            human_oversight, ai_act_classification, criticality, status, logging_required,
            transparency_required, cybersecurity_required, monitoring_plan, evidence_key,
            risk_summary, next_review_due_at, notes, created_at, updated_at
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
            $17, $18, $19, $20, $21, $22, $23, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
        )
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(payload.product_id)
    .bind(payload.owner_id)
    .bind(name)
    .bind(clean_text(&payload.purpose))
    .bind(clean_text(&payload.model_provider))
    .bind(clean_text(&payload.model_name))
    .bind(clean_text(&payload.model_version))
    .bind(clean_text(&payload.deployment_context))
    .bind(clean_text(&payload.data_categories))
    .bind(clean_text(&payload.decision_impact))
    .bind(clean_text(&payload.human_oversight))
    .bind(ai_act_classification)
    .bind(criticality)
    .bind(status)
    .bind(payload.logging_required.unwrap_or(false))
    .bind(payload.transparency_required.unwrap_or(false))
    .bind(payload.cybersecurity_required.unwrap_or(true))
    .bind(clean_text(&payload.monitoring_plan))
    .bind(evidence_key)
    .bind(clean_text(&payload.risk_summary))
    .bind(clean_optional_date(&payload.next_review_due_at))
    .bind(clean_text(&payload.notes))
    .fetch_one(pool)
    .await
    .context("PostgreSQL-AI-Governance-System konnte nicht angelegt werden")
}

#[allow(clippy::too_many_arguments)]
async fn create_system_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    payload: &AiGovernanceSystemCreateRequest,
    name: &str,
    ai_act_classification: &str,
    criticality: &str,
    status: &str,
    evidence_key: &str,
) -> anyhow::Result<i64> {
    sqlx::query(
        r#"
        INSERT INTO ai_governance_system (
            tenant_id, product_id, owner_id, name, purpose, model_provider, model_name,
            model_version, deployment_context, data_categories, decision_impact,
            human_oversight, ai_act_classification, criticality, status, logging_required,
            transparency_required, cybersecurity_required, monitoring_plan, evidence_key,
            risk_summary, next_review_due_at, notes, created_at, updated_at
        )
        VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
        )
        "#,
    )
    .bind(tenant_id)
    .bind(payload.product_id)
    .bind(payload.owner_id)
    .bind(name)
    .bind(clean_text(&payload.purpose))
    .bind(clean_text(&payload.model_provider))
    .bind(clean_text(&payload.model_name))
    .bind(clean_text(&payload.model_version))
    .bind(clean_text(&payload.deployment_context))
    .bind(clean_text(&payload.data_categories))
    .bind(clean_text(&payload.decision_impact))
    .bind(clean_text(&payload.human_oversight))
    .bind(ai_act_classification)
    .bind(criticality)
    .bind(status)
    .bind(payload.logging_required.unwrap_or(false))
    .bind(payload.transparency_required.unwrap_or(false))
    .bind(payload.cybersecurity_required.unwrap_or(true))
    .bind(clean_text(&payload.monitoring_plan))
    .bind(evidence_key)
    .bind(clean_text(&payload.risk_summary))
    .bind(clean_optional_date(&payload.next_review_due_at))
    .bind(clean_text(&payload.notes))
    .execute(pool)
    .await
    .context("SQLite-AI-Governance-System konnte nicht angelegt werden")?;

    sqlx::query_scalar("SELECT last_insert_rowid()")
        .fetch_one(pool)
        .await
        .context("SQLite-ID fuer AI-Governance-System konnte nicht gelesen werden")
}

async fn update_system_postgres(
    pool: &PgPool,
    system: &AiGovernanceSystemSummary,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        UPDATE ai_governance_system
        SET product_id = $3,
            owner_id = $4,
            name = $5,
            purpose = $6,
            model_provider = $7,
            model_name = $8,
            model_version = $9,
            deployment_context = $10,
            data_categories = $11,
            decision_impact = $12,
            human_oversight = $13,
            ai_act_classification = $14,
            criticality = $15,
            status = $16,
            logging_required = $17,
            transparency_required = $18,
            cybersecurity_required = $19,
            monitoring_plan = $20,
            evidence_key = $21,
            risk_summary = $22,
            next_review_due_at = $23,
            notes = $24,
            updated_at = CURRENT_TIMESTAMP
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(system.tenant_id)
    .bind(system.id)
    .bind(system.product_id)
    .bind(system.owner_id)
    .bind(&system.name)
    .bind(&system.purpose)
    .bind(&system.model_provider)
    .bind(&system.model_name)
    .bind(&system.model_version)
    .bind(&system.deployment_context)
    .bind(&system.data_categories)
    .bind(&system.decision_impact)
    .bind(&system.human_oversight)
    .bind(&system.ai_act_classification)
    .bind(&system.criticality)
    .bind(&system.status)
    .bind(system.logging_required)
    .bind(system.transparency_required)
    .bind(system.cybersecurity_required)
    .bind(&system.monitoring_plan)
    .bind(&system.evidence_key)
    .bind(&system.risk_summary)
    .bind(&system.next_review_due_at)
    .bind(&system.notes)
    .execute(pool)
    .await
    .context("PostgreSQL-AI-Governance-System konnte nicht aktualisiert werden")?;
    Ok(())
}

async fn update_system_sqlite(
    pool: &SqlitePool,
    system: &AiGovernanceSystemSummary,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        UPDATE ai_governance_system
        SET product_id = ?3,
            owner_id = ?4,
            name = ?5,
            purpose = ?6,
            model_provider = ?7,
            model_name = ?8,
            model_version = ?9,
            deployment_context = ?10,
            data_categories = ?11,
            decision_impact = ?12,
            human_oversight = ?13,
            ai_act_classification = ?14,
            criticality = ?15,
            status = ?16,
            logging_required = ?17,
            transparency_required = ?18,
            cybersecurity_required = ?19,
            monitoring_plan = ?20,
            evidence_key = ?21,
            risk_summary = ?22,
            next_review_due_at = ?23,
            notes = ?24,
            updated_at = CURRENT_TIMESTAMP
        WHERE tenant_id = ?1 AND id = ?2
        "#,
    )
    .bind(system.tenant_id)
    .bind(system.id)
    .bind(system.product_id)
    .bind(system.owner_id)
    .bind(&system.name)
    .bind(&system.purpose)
    .bind(&system.model_provider)
    .bind(&system.model_name)
    .bind(&system.model_version)
    .bind(&system.deployment_context)
    .bind(&system.data_categories)
    .bind(&system.decision_impact)
    .bind(&system.human_oversight)
    .bind(&system.ai_act_classification)
    .bind(&system.criticality)
    .bind(&system.status)
    .bind(system.logging_required)
    .bind(system.transparency_required)
    .bind(system.cybersecurity_required)
    .bind(&system.monitoring_plan)
    .bind(&system.evidence_key)
    .bind(&system.risk_summary)
    .bind(&system.next_review_due_at)
    .bind(&system.notes)
    .execute(pool)
    .await
    .context("SQLite-AI-Governance-System konnte nicht aktualisiert werden")?;
    Ok(())
}

const POSTGRES_AI_GOVERNANCE_SELECT: &str = r#"
SELECT
    system.id,
    system.tenant_id,
    system.product_id,
    product.name AS product_name,
    system.owner_id,
    COALESCE(
        NULLIF(BTRIM(CONCAT(COALESCE(owner.first_name, ''), ' ', COALESCE(owner.last_name, ''))), ''),
        owner.username
    ) AS owner_display,
    system.name,
    system.purpose,
    system.model_provider,
    system.model_name,
    system.model_version,
    system.deployment_context,
    system.data_categories,
    system.decision_impact,
    system.human_oversight,
    system.ai_act_classification,
    system.criticality,
    system.status,
    system.logging_required,
    system.transparency_required,
    system.cybersecurity_required,
    system.monitoring_plan,
    system.evidence_key,
    system.risk_summary,
    system.next_review_due_at,
    system.notes,
    system.created_at::text AS created_at,
    system.updated_at::text AS updated_at,
    COALESCE(evidence_stats.evidence_count, 0) AS evidence_count,
    COALESCE(evidence_stats.approved_evidence_count, 0) AS approved_evidence_count
FROM ai_governance_system system
LEFT JOIN product_security_product product
    ON product.id = system.product_id AND product.tenant_id = system.tenant_id
LEFT JOIN accounts_user owner
    ON owner.id = system.owner_id
LEFT JOIN (
    SELECT
        tenant_id,
        linked_requirement,
        COUNT(*) AS evidence_count,
        SUM(CASE WHEN UPPER(status) = 'APPROVED' THEN 1 ELSE 0 END) AS approved_evidence_count
    FROM evidence_evidenceitem
    GROUP BY tenant_id, linked_requirement
) evidence_stats
    ON evidence_stats.tenant_id = system.tenant_id
    AND evidence_stats.linked_requirement = system.evidence_key
"#;

const SQLITE_AI_GOVERNANCE_SELECT: &str = r#"
SELECT
    system.id,
    system.tenant_id,
    system.product_id,
    product.name AS product_name,
    system.owner_id,
    COALESCE(
        NULLIF(TRIM(COALESCE(owner.first_name, '') || ' ' || COALESCE(owner.last_name, '')), ''),
        owner.username
    ) AS owner_display,
    system.name,
    system.purpose,
    system.model_provider,
    system.model_name,
    system.model_version,
    system.deployment_context,
    system.data_categories,
    system.decision_impact,
    system.human_oversight,
    system.ai_act_classification,
    system.criticality,
    system.status,
    system.logging_required,
    system.transparency_required,
    system.cybersecurity_required,
    system.monitoring_plan,
    system.evidence_key,
    system.risk_summary,
    system.next_review_due_at,
    system.notes,
    CAST(system.created_at AS TEXT) AS created_at,
    CAST(system.updated_at AS TEXT) AS updated_at,
    COALESCE(evidence_stats.evidence_count, 0) AS evidence_count,
    COALESCE(evidence_stats.approved_evidence_count, 0) AS approved_evidence_count
FROM ai_governance_system system
LEFT JOIN product_security_product product
    ON product.id = system.product_id AND product.tenant_id = system.tenant_id
LEFT JOIN accounts_user owner
    ON owner.id = system.owner_id
LEFT JOIN (
    SELECT
        tenant_id,
        linked_requirement,
        COUNT(*) AS evidence_count,
        SUM(CASE WHEN UPPER(status) = 'APPROVED' THEN 1 ELSE 0 END) AS approved_evidence_count
    FROM evidence_evidenceitem
    GROUP BY tenant_id, linked_requirement
) evidence_stats
    ON evidence_stats.tenant_id = system.tenant_id
    AND evidence_stats.linked_requirement = system.evidence_key
"#;

fn ai_system_from_pg_row(row: PgRow) -> Result<AiGovernanceSystemSummary, sqlx::Error> {
    let ai_act_classification: String = row.try_get("ai_act_classification")?;
    let criticality: String = row.try_get("criticality")?;
    let status: String = row.try_get("status")?;
    let mut system = AiGovernanceSystemSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        product_name: row.try_get("product_name")?,
        owner_id: row.try_get("owner_id")?,
        owner_display: row.try_get("owner_display")?,
        name: row.try_get("name")?,
        purpose: row.try_get("purpose")?,
        model_provider: row.try_get("model_provider")?,
        model_name: row.try_get("model_name")?,
        model_version: row.try_get("model_version")?,
        deployment_context: row.try_get("deployment_context")?,
        data_categories: row.try_get("data_categories")?,
        decision_impact: row.try_get("decision_impact")?,
        human_oversight: row.try_get("human_oversight")?,
        ai_act_classification_label: ai_act_classification_label(&ai_act_classification),
        ai_act_classification,
        criticality_label: criticality_label(&criticality),
        criticality,
        status_label: status_label(&status),
        status,
        logging_required: row.try_get("logging_required")?,
        transparency_required: row.try_get("transparency_required")?,
        cybersecurity_required: row.try_get("cybersecurity_required")?,
        monitoring_plan: row.try_get("monitoring_plan")?,
        evidence_key: row.try_get("evidence_key")?,
        risk_summary: row.try_get("risk_summary")?,
        next_review_due_at: row.try_get("next_review_due_at")?,
        notes: row.try_get("notes")?,
        evidence_count: row.try_get("evidence_count")?,
        approved_evidence_count: row.try_get("approved_evidence_count")?,
        open_requirement_count: 0,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    };
    system.open_requirement_count = ai_governance_requirements(&system)
        .iter()
        .filter(|requirement| requirement.status == "GAP")
        .count() as i64;
    Ok(system)
}

fn ai_system_from_sqlite_row(row: SqliteRow) -> Result<AiGovernanceSystemSummary, sqlx::Error> {
    let ai_act_classification: String = row.try_get("ai_act_classification")?;
    let criticality: String = row.try_get("criticality")?;
    let status: String = row.try_get("status")?;
    let mut system = AiGovernanceSystemSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        product_name: row.try_get("product_name")?,
        owner_id: row.try_get("owner_id")?,
        owner_display: row.try_get("owner_display")?,
        name: row.try_get("name")?,
        purpose: row.try_get("purpose")?,
        model_provider: row.try_get("model_provider")?,
        model_name: row.try_get("model_name")?,
        model_version: row.try_get("model_version")?,
        deployment_context: row.try_get("deployment_context")?,
        data_categories: row.try_get("data_categories")?,
        decision_impact: row.try_get("decision_impact")?,
        human_oversight: row.try_get("human_oversight")?,
        ai_act_classification_label: ai_act_classification_label(&ai_act_classification),
        ai_act_classification,
        criticality_label: criticality_label(&criticality),
        criticality,
        status_label: status_label(&status),
        status,
        logging_required: row.try_get("logging_required")?,
        transparency_required: row.try_get("transparency_required")?,
        cybersecurity_required: row.try_get("cybersecurity_required")?,
        monitoring_plan: row.try_get("monitoring_plan")?,
        evidence_key: row.try_get("evidence_key")?,
        risk_summary: row.try_get("risk_summary")?,
        next_review_due_at: row.try_get("next_review_due_at")?,
        notes: row.try_get("notes")?,
        evidence_count: row.try_get("evidence_count")?,
        approved_evidence_count: row.try_get("approved_evidence_count")?,
        open_requirement_count: 0,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    };
    system.open_requirement_count = ai_governance_requirements(&system)
        .iter()
        .filter(|requirement| requirement.status == "GAP")
        .count() as i64;
    Ok(system)
}

fn ai_governance_summary(systems: &[AiGovernanceSystemSummary]) -> AiGovernanceSummary {
    AiGovernanceSummary {
        total_systems: systems.len() as i64,
        high_risk_systems: systems
            .iter()
            .filter(|system| {
                matches!(
                    system.ai_act_classification.as_str(),
                    "HIGH_RISK" | "PROHIBITED"
                )
            })
            .count() as i64,
        not_assessed_systems: systems
            .iter()
            .filter(|system| system.ai_act_classification == "NOT_ASSESSED")
            .count() as i64,
        review_due_systems: systems.iter().filter(|system| review_due(system)).count() as i64,
        evidence_missing: systems
            .iter()
            .filter(|system| system.evidence_count == 0)
            .count() as i64,
        open_governance_gaps: systems
            .iter()
            .map(|system| system.open_requirement_count)
            .sum(),
    }
}

pub fn ai_governance_requirements(
    system: &AiGovernanceSystemSummary,
) -> Vec<AiGovernanceRequirementSummary> {
    let high_risk = matches!(
        system.ai_act_classification.as_str(),
        "HIGH_RISK" | "PROHIBITED"
    );
    let limited_or_high = matches!(
        system.ai_act_classification.as_str(),
        "LIMITED_RISK" | "HIGH_RISK" | "PROHIBITED"
    );
    vec![
        requirement(
            "classification",
            "AI-Act-Einstufung",
            if system.ai_act_classification == "NOT_ASSESSED" {
                "GAP"
            } else {
                "OK"
            },
            if system.ai_act_classification == "NOT_ASSESSED" {
                "Einstufung offen; Scope, Zweck, Betroffenheit und Ausnahmen bewerten."
            } else {
                "Einstufung dokumentiert."
            },
        ),
        requirement(
            "risk_management",
            "Risikomanagement",
            if system.risk_summary.trim().is_empty() {
                "GAP"
            } else {
                "OK"
            },
            if system.risk_summary.trim().is_empty() {
                "Risikoannahmen, Fehlgebrauch und Auswirkungen sind noch nicht zusammengefasst."
            } else {
                "Risikosummary vorhanden."
            },
        ),
        requirement(
            "human_oversight",
            "Human Oversight",
            if high_risk && system.human_oversight.trim().is_empty() {
                "GAP"
            } else if system.human_oversight.trim().is_empty() {
                "WATCH"
            } else {
                "OK"
            },
            if system.human_oversight.trim().is_empty() {
                "Oversight-Modell, Eskalation und Verantwortlichkeit ergaenzen."
            } else {
                "Oversight-Modell dokumentiert."
            },
        ),
        requirement(
            "logging",
            "Logging & Nachvollziehbarkeit",
            if high_risk && !system.logging_required {
                "GAP"
            } else if system.logging_required {
                "OK"
            } else {
                "WATCH"
            },
            if system.logging_required {
                "Logging-Anforderung gesetzt."
            } else {
                "Logging-Bedarf fuer Betrieb, Audit und Incident-Kontext bewerten."
            },
        ),
        requirement(
            "transparency",
            "Transparenz",
            if limited_or_high && !system.transparency_required {
                "GAP"
            } else if system.transparency_required {
                "OK"
            } else {
                "WATCH"
            },
            if system.transparency_required {
                "Transparenzanforderung gesetzt."
            } else {
                "Nutzerinformation, Zweck und Grenzen des Systems pruefen."
            },
        ),
        requirement(
            "cybersecurity",
            "Cybersecurity & Robustheit",
            if high_risk && !system.cybersecurity_required {
                "GAP"
            } else if system.cybersecurity_required {
                "OK"
            } else {
                "WATCH"
            },
            if system.cybersecurity_required {
                "Cybersecurity-Anforderung gesetzt."
            } else {
                "Robustheit, Missbrauchsschutz und Manipulationsresistenz bewerten."
            },
        ),
        requirement(
            "monitoring",
            "Monitoring & Evidence",
            if system.monitoring_plan.trim().is_empty() || system.evidence_count == 0 {
                "GAP"
            } else {
                "OK"
            },
            if system.evidence_count == 0 {
                "Monitoringplan oder Evidence fehlen; Nachweis mit Evidence-Key verknuepfen."
            } else {
                "Evidence-Spur vorhanden."
            },
        ),
    ]
}

fn requirement(
    key: &str,
    label: &str,
    status: &str,
    detail: &str,
) -> AiGovernanceRequirementSummary {
    AiGovernanceRequirementSummary {
        key: key.to_string(),
        label: label.to_string(),
        status: status.to_string(),
        status_label: requirement_status_label(status).to_string(),
        detail: detail.to_string(),
    }
}

fn merged_update(
    mut existing: AiGovernanceSystemSummary,
    payload: AiGovernanceSystemUpdateRequest,
) -> anyhow::Result<AiGovernanceSystemSummary> {
    if let Some(name) = payload.name {
        existing.name = clean_required(&name, "AI-System-Name")?;
    }
    if let Some(product_id) = payload.product_id {
        existing.product_id = (product_id > 0).then_some(product_id);
    }
    if let Some(owner_id) = payload.owner_id {
        existing.owner_id = (owner_id > 0).then_some(owner_id);
    }
    if let Some(value) = payload.purpose {
        existing.purpose = clean_text(&value);
    }
    if let Some(value) = payload.model_provider {
        existing.model_provider = clean_text(&value);
    }
    if let Some(value) = payload.model_name {
        existing.model_name = clean_text(&value);
    }
    if let Some(value) = payload.model_version {
        existing.model_version = clean_text(&value);
    }
    if let Some(value) = payload.deployment_context {
        existing.deployment_context = clean_text(&value);
    }
    if let Some(value) = payload.data_categories {
        existing.data_categories = clean_text(&value);
    }
    if let Some(value) = payload.decision_impact {
        existing.decision_impact = clean_text(&value);
    }
    if let Some(value) = payload.human_oversight {
        existing.human_oversight = clean_text(&value);
    }
    if let Some(value) = payload.ai_act_classification {
        existing.ai_act_classification = normalize_ai_act_classification(&value);
        existing.ai_act_classification_label =
            ai_act_classification_label(&existing.ai_act_classification);
    }
    if let Some(value) = payload.criticality {
        existing.criticality = normalize_criticality(&value);
        existing.criticality_label = criticality_label(&existing.criticality);
    }
    if let Some(value) = payload.status {
        existing.status = normalize_status(&value);
        existing.status_label = status_label(&existing.status);
    }
    if let Some(value) = payload.logging_required {
        existing.logging_required = value;
    }
    if let Some(value) = payload.transparency_required {
        existing.transparency_required = value;
    }
    if let Some(value) = payload.cybersecurity_required {
        existing.cybersecurity_required = value;
    }
    if let Some(value) = payload.monitoring_plan {
        existing.monitoring_plan = clean_text(&value);
    }
    if let Some(value) = payload.evidence_key {
        existing.evidence_key = clean_text(&value);
    }
    if let Some(value) = payload.risk_summary {
        existing.risk_summary = clean_text(&value);
    }
    if let Some(value) = payload.next_review_due_at {
        existing.next_review_due_at = clean_optional_date(&Some(value));
    }
    if let Some(value) = payload.notes {
        existing.notes = clean_text(&value);
    }
    Ok(existing)
}

fn review_due(system: &AiGovernanceSystemSummary) -> bool {
    let Some(value) = system.next_review_due_at.as_deref() else {
        return false;
    };
    let date_part = value.get(..10).unwrap_or(value);
    let Ok(review_date) = NaiveDate::parse_from_str(date_part, "%Y-%m-%d") else {
        return false;
    };
    review_date <= Utc::now().date_naive()
}

fn clean_required(value: &str, label: &str) -> anyhow::Result<String> {
    let value = clean_text(value);
    if value.is_empty() {
        bail!("{label} darf nicht leer sein");
    }
    Ok(value)
}

fn clean_text(value: &str) -> String {
    value.trim().to_string()
}

fn clean_optional_date(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(clean_text)
        .filter(|value| !value.is_empty())
}

fn normalize_ai_act_classification(value: &str) -> String {
    match value.trim().to_ascii_uppercase().replace('-', "_").as_str() {
        "PROHIBITED" | "UNACCEPTABLE" => "PROHIBITED",
        "HIGH" | "HIGH_RISK" => "HIGH_RISK",
        "LIMITED" | "LIMITED_RISK" => "LIMITED_RISK",
        "LOW" | "MINIMAL" | "MINIMAL_RISK" => "MINIMAL_RISK",
        "OUT_OF_SCOPE" | "NOT_IN_SCOPE" => "NOT_IN_SCOPE",
        _ => "NOT_ASSESSED",
    }
    .to_string()
}

fn normalize_criticality(value: &str) -> String {
    match value.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => "CRITICAL",
        "HIGH" => "HIGH",
        "LOW" => "LOW",
        _ => "MEDIUM",
    }
    .to_string()
}

fn normalize_status(value: &str) -> String {
    match value.trim().to_ascii_uppercase().replace('-', "_").as_str() {
        "DRAFT" => "DRAFT",
        "APPROVED" => "APPROVED",
        "RETIRED" => "RETIRED",
        _ => "IN_REVIEW",
    }
    .to_string()
}

fn ai_act_classification_label(value: &str) -> String {
    match value {
        "PROHIBITED" => "Verboten / nicht freigegeben",
        "HIGH_RISK" => "High Risk",
        "LIMITED_RISK" => "Limited Risk",
        "MINIMAL_RISK" => "Minimal Risk",
        "NOT_IN_SCOPE" => "Nicht im Scope",
        _ => "Nicht bewertet",
    }
    .to_string()
}

fn criticality_label(value: &str) -> String {
    match value {
        "CRITICAL" => "Kritisch",
        "HIGH" => "Hoch",
        "LOW" => "Niedrig",
        _ => "Mittel",
    }
    .to_string()
}

fn status_label(value: &str) -> String {
    match value {
        "DRAFT" => "Entwurf",
        "APPROVED" => "Freigegeben",
        "RETIRED" => "Stillgelegt",
        _ => "In Review",
    }
    .to_string()
}

fn requirement_status_label(value: &str) -> &'static str {
    match value {
        "OK" => "OK",
        "WATCH" => "Pruefen",
        _ => "Gap",
    }
}

fn slug_key(value: &str) -> String {
    let mut key = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    while key.contains("--") {
        key = key.replace("--", "-");
    }
    key.trim_matches('-').to_string()
}
