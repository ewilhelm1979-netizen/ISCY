use anyhow::{bail, Context};
use serde::Serialize;
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Row,
};

use crate::cve_store::normalize_database_url;

#[derive(Clone)]
pub enum RiskStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Serialize)]
pub struct RiskSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub category_id: Option<i64>,
    pub category_name: Option<String>,
    pub process_id: Option<i64>,
    pub process_name: Option<String>,
    pub asset_id: Option<i64>,
    pub asset_name: Option<String>,
    pub owner_id: Option<i64>,
    pub owner_display: Option<String>,
    pub title: String,
    pub description: String,
    pub threat: String,
    pub vulnerability: String,
    pub impact: i64,
    pub impact_label: String,
    pub likelihood: i64,
    pub likelihood_label: String,
    pub residual_impact: Option<i64>,
    pub residual_impact_label: Option<String>,
    pub residual_likelihood: Option<i64>,
    pub residual_likelihood_label: Option<String>,
    pub status: String,
    pub status_label: String,
    pub treatment_strategy: String,
    pub treatment_strategy_label: String,
    pub treatment_plan: String,
    pub treatment_due_date: Option<String>,
    pub accepted_by_id: Option<i64>,
    pub accepted_by_display: Option<String>,
    pub accepted_at: Option<String>,
    pub review_date: Option<String>,
    pub score: i64,
    pub residual_score: Option<i64>,
    pub risk_level: String,
    pub risk_level_label: String,
    pub created_at: String,
    pub updated_at: String,
}

impl RiskStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Risk-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Risk-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-Risk-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn list_risks(&self, tenant_id: i64, limit: i64) -> anyhow::Result<Vec<RiskSummary>> {
        match self {
            Self::Postgres(pool) => list_risks_postgres(pool, tenant_id, limit).await,
            Self::Sqlite(pool) => list_risks_sqlite(pool, tenant_id, limit).await,
        }
    }

    pub async fn risk_detail(
        &self,
        tenant_id: i64,
        risk_id: i64,
    ) -> anyhow::Result<Option<RiskSummary>> {
        match self {
            Self::Postgres(pool) => risk_detail_postgres(pool, tenant_id, risk_id).await,
            Self::Sqlite(pool) => risk_detail_sqlite(pool, tenant_id, risk_id).await,
        }
    }
}

async fn list_risks_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<RiskSummary>> {
    let rows = sqlx::query(risk_list_postgres_sql())
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Risikoliste konnte nicht gelesen werden")?;

    rows.into_iter()
        .map(summary_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_risks_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<RiskSummary>> {
    let rows = sqlx::query(risk_list_sqlite_sql())
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("SQLite-Risikoliste konnte nicht gelesen werden")?;

    rows.into_iter()
        .map(summary_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn risk_detail_postgres(
    pool: &PgPool,
    tenant_id: i64,
    risk_id: i64,
) -> anyhow::Result<Option<RiskSummary>> {
    let row = sqlx::query(risk_detail_postgres_sql())
        .bind(tenant_id)
        .bind(risk_id)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-Risikodetail konnte nicht gelesen werden")?;

    row.map(summary_from_pg_row).transpose().map_err(Into::into)
}

async fn risk_detail_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    risk_id: i64,
) -> anyhow::Result<Option<RiskSummary>> {
    let row = sqlx::query(risk_detail_sqlite_sql())
        .bind(tenant_id)
        .bind(risk_id)
        .fetch_optional(pool)
        .await
        .context("SQLite-Risikodetail konnte nicht gelesen werden")?;

    row.map(summary_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

fn summary_from_pg_row(row: PgRow) -> Result<RiskSummary, sqlx::Error> {
    let impact: i64 = row.try_get("impact")?;
    let likelihood: i64 = row.try_get("likelihood")?;
    let residual_impact: Option<i64> = row.try_get("residual_impact")?;
    let residual_likelihood: Option<i64> = row.try_get("residual_likelihood")?;
    let status: String = row.try_get("status")?;
    let treatment_strategy: String = row.try_get("treatment_strategy")?;
    let score = impact * likelihood;
    let residual_score = residual_impact.zip(residual_likelihood).map(|(i, l)| i * l);
    let risk_level = risk_level(score);
    Ok(RiskSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        category_id: row.try_get("category_id")?,
        category_name: row.try_get("category_name")?,
        process_id: row.try_get("process_id")?,
        process_name: row.try_get("process_name")?,
        asset_id: row.try_get("asset_id")?,
        asset_name: row.try_get("asset_name")?,
        owner_id: row.try_get("owner_id")?,
        owner_display: row.try_get("owner_display")?,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        threat: row.try_get("threat")?,
        vulnerability: row.try_get("vulnerability")?,
        impact,
        impact_label: impact_label(impact).to_string(),
        likelihood,
        likelihood_label: likelihood_label(likelihood).to_string(),
        residual_impact,
        residual_impact_label: residual_impact.map(|value| impact_label(value).to_string()),
        residual_likelihood,
        residual_likelihood_label: residual_likelihood
            .map(|value| likelihood_label(value).to_string()),
        status_label: status_label(&status).to_string(),
        status,
        treatment_strategy_label: treatment_label(&treatment_strategy).to_string(),
        treatment_strategy,
        treatment_plan: row.try_get("treatment_plan")?,
        treatment_due_date: row.try_get("treatment_due_date")?,
        accepted_by_id: row.try_get("accepted_by_id")?,
        accepted_by_display: row.try_get("accepted_by_display")?,
        accepted_at: row.try_get("accepted_at")?,
        review_date: row.try_get("review_date")?,
        score,
        residual_score,
        risk_level: risk_level.to_string(),
        risk_level_label: risk_level_label(risk_level).to_string(),
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn summary_from_sqlite_row(row: SqliteRow) -> Result<RiskSummary, sqlx::Error> {
    let impact: i64 = row.try_get("impact")?;
    let likelihood: i64 = row.try_get("likelihood")?;
    let residual_impact: Option<i64> = row.try_get("residual_impact")?;
    let residual_likelihood: Option<i64> = row.try_get("residual_likelihood")?;
    let status: String = row.try_get("status")?;
    let treatment_strategy: String = row.try_get("treatment_strategy")?;
    let score = impact * likelihood;
    let residual_score = residual_impact.zip(residual_likelihood).map(|(i, l)| i * l);
    let risk_level = risk_level(score);
    Ok(RiskSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        category_id: row.try_get("category_id")?,
        category_name: row.try_get("category_name")?,
        process_id: row.try_get("process_id")?,
        process_name: row.try_get("process_name")?,
        asset_id: row.try_get("asset_id")?,
        asset_name: row.try_get("asset_name")?,
        owner_id: row.try_get("owner_id")?,
        owner_display: row.try_get("owner_display")?,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        threat: row.try_get("threat")?,
        vulnerability: row.try_get("vulnerability")?,
        impact,
        impact_label: impact_label(impact).to_string(),
        likelihood,
        likelihood_label: likelihood_label(likelihood).to_string(),
        residual_impact,
        residual_impact_label: residual_impact.map(|value| impact_label(value).to_string()),
        residual_likelihood,
        residual_likelihood_label: residual_likelihood
            .map(|value| likelihood_label(value).to_string()),
        status_label: status_label(&status).to_string(),
        status,
        treatment_strategy_label: treatment_label(&treatment_strategy).to_string(),
        treatment_strategy,
        treatment_plan: row.try_get("treatment_plan")?,
        treatment_due_date: row.try_get("treatment_due_date")?,
        accepted_by_id: row.try_get("accepted_by_id")?,
        accepted_by_display: row.try_get("accepted_by_display")?,
        accepted_at: row.try_get("accepted_at")?,
        review_date: row.try_get("review_date")?,
        score,
        residual_score,
        risk_level: risk_level.to_string(),
        risk_level_label: risk_level_label(risk_level).to_string(),
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn risk_list_postgres_sql() -> &'static str {
    r#"
    SELECT
        risk.id,
        risk.tenant_id,
        risk.category_id,
        category.name AS category_name,
        risk.process_id,
        process.name AS process_name,
        risk.asset_id,
        asset.name AS asset_name,
        risk.owner_id,
        COALESCE(
            NULLIF(BTRIM(CONCAT(COALESCE(owner.first_name, ''), ' ', COALESCE(owner.last_name, ''))), ''),
            owner.username
        ) AS owner_display,
        risk.title,
        risk.description,
        risk.threat,
        risk.vulnerability,
        risk.impact::bigint AS impact,
        risk.likelihood::bigint AS likelihood,
        risk.residual_impact::bigint AS residual_impact,
        risk.residual_likelihood::bigint AS residual_likelihood,
        risk.status,
        risk.treatment_strategy,
        risk.treatment_plan,
        risk.treatment_due_date::text AS treatment_due_date,
        risk.accepted_by_id,
        COALESCE(
            NULLIF(BTRIM(CONCAT(COALESCE(accepted.first_name, ''), ' ', COALESCE(accepted.last_name, ''))), ''),
            accepted.username
        ) AS accepted_by_display,
        risk.accepted_at::text AS accepted_at,
        risk.review_date::text AS review_date,
        risk.created_at::text AS created_at,
        risk.updated_at::text AS updated_at
    FROM risks_risk risk
    LEFT JOIN risks_riskcategory category
        ON category.id = risk.category_id AND category.tenant_id = risk.tenant_id
    LEFT JOIN processes_process process
        ON process.id = risk.process_id AND process.tenant_id = risk.tenant_id
    LEFT JOIN assets_app_informationasset asset
        ON asset.id = risk.asset_id AND asset.tenant_id = risk.tenant_id
    LEFT JOIN accounts_user owner
        ON owner.id = risk.owner_id AND owner.tenant_id = risk.tenant_id
    LEFT JOIN accounts_user accepted
        ON accepted.id = risk.accepted_by_id AND accepted.tenant_id = risk.tenant_id
    WHERE risk.tenant_id = $1
    ORDER BY risk.impact DESC, risk.likelihood DESC, risk.title ASC, risk.id ASC
    LIMIT $2
    "#
}

fn risk_list_sqlite_sql() -> &'static str {
    r#"
    SELECT
        risk.id,
        risk.tenant_id,
        risk.category_id,
        category.name AS category_name,
        risk.process_id,
        process.name AS process_name,
        risk.asset_id,
        asset.name AS asset_name,
        risk.owner_id,
        COALESCE(
            NULLIF(TRIM(COALESCE(owner.first_name, '') || ' ' || COALESCE(owner.last_name, '')), ''),
            owner.username
        ) AS owner_display,
        risk.title,
        risk.description,
        risk.threat,
        risk.vulnerability,
        risk.impact,
        risk.likelihood,
        risk.residual_impact,
        risk.residual_likelihood,
        risk.status,
        risk.treatment_strategy,
        risk.treatment_plan,
        CAST(risk.treatment_due_date AS TEXT) AS treatment_due_date,
        risk.accepted_by_id,
        COALESCE(
            NULLIF(TRIM(COALESCE(accepted.first_name, '') || ' ' || COALESCE(accepted.last_name, '')), ''),
            accepted.username
        ) AS accepted_by_display,
        CAST(risk.accepted_at AS TEXT) AS accepted_at,
        CAST(risk.review_date AS TEXT) AS review_date,
        CAST(risk.created_at AS TEXT) AS created_at,
        CAST(risk.updated_at AS TEXT) AS updated_at
    FROM risks_risk risk
    LEFT JOIN risks_riskcategory category
        ON category.id = risk.category_id AND category.tenant_id = risk.tenant_id
    LEFT JOIN processes_process process
        ON process.id = risk.process_id AND process.tenant_id = risk.tenant_id
    LEFT JOIN assets_app_informationasset asset
        ON asset.id = risk.asset_id AND asset.tenant_id = risk.tenant_id
    LEFT JOIN accounts_user owner
        ON owner.id = risk.owner_id AND owner.tenant_id = risk.tenant_id
    LEFT JOIN accounts_user accepted
        ON accepted.id = risk.accepted_by_id AND accepted.tenant_id = risk.tenant_id
    WHERE risk.tenant_id = ?
    ORDER BY risk.impact DESC, risk.likelihood DESC, risk.title ASC, risk.id ASC
    LIMIT ?
    "#
}

fn risk_detail_postgres_sql() -> &'static str {
    r#"
    SELECT
        risk.id,
        risk.tenant_id,
        risk.category_id,
        category.name AS category_name,
        risk.process_id,
        process.name AS process_name,
        risk.asset_id,
        asset.name AS asset_name,
        risk.owner_id,
        COALESCE(
            NULLIF(BTRIM(CONCAT(COALESCE(owner.first_name, ''), ' ', COALESCE(owner.last_name, ''))), ''),
            owner.username
        ) AS owner_display,
        risk.title,
        risk.description,
        risk.threat,
        risk.vulnerability,
        risk.impact::bigint AS impact,
        risk.likelihood::bigint AS likelihood,
        risk.residual_impact::bigint AS residual_impact,
        risk.residual_likelihood::bigint AS residual_likelihood,
        risk.status,
        risk.treatment_strategy,
        risk.treatment_plan,
        risk.treatment_due_date::text AS treatment_due_date,
        risk.accepted_by_id,
        COALESCE(
            NULLIF(BTRIM(CONCAT(COALESCE(accepted.first_name, ''), ' ', COALESCE(accepted.last_name, ''))), ''),
            accepted.username
        ) AS accepted_by_display,
        risk.accepted_at::text AS accepted_at,
        risk.review_date::text AS review_date,
        risk.created_at::text AS created_at,
        risk.updated_at::text AS updated_at
    FROM risks_risk risk
    LEFT JOIN risks_riskcategory category
        ON category.id = risk.category_id AND category.tenant_id = risk.tenant_id
    LEFT JOIN processes_process process
        ON process.id = risk.process_id AND process.tenant_id = risk.tenant_id
    LEFT JOIN assets_app_informationasset asset
        ON asset.id = risk.asset_id AND asset.tenant_id = risk.tenant_id
    LEFT JOIN accounts_user owner
        ON owner.id = risk.owner_id AND owner.tenant_id = risk.tenant_id
    LEFT JOIN accounts_user accepted
        ON accepted.id = risk.accepted_by_id AND accepted.tenant_id = risk.tenant_id
    WHERE risk.tenant_id = $1 AND risk.id = $2
    "#
}

fn risk_detail_sqlite_sql() -> &'static str {
    r#"
    SELECT
        risk.id,
        risk.tenant_id,
        risk.category_id,
        category.name AS category_name,
        risk.process_id,
        process.name AS process_name,
        risk.asset_id,
        asset.name AS asset_name,
        risk.owner_id,
        COALESCE(
            NULLIF(TRIM(COALESCE(owner.first_name, '') || ' ' || COALESCE(owner.last_name, '')), ''),
            owner.username
        ) AS owner_display,
        risk.title,
        risk.description,
        risk.threat,
        risk.vulnerability,
        risk.impact,
        risk.likelihood,
        risk.residual_impact,
        risk.residual_likelihood,
        risk.status,
        risk.treatment_strategy,
        risk.treatment_plan,
        CAST(risk.treatment_due_date AS TEXT) AS treatment_due_date,
        risk.accepted_by_id,
        COALESCE(
            NULLIF(TRIM(COALESCE(accepted.first_name, '') || ' ' || COALESCE(accepted.last_name, '')), ''),
            accepted.username
        ) AS accepted_by_display,
        CAST(risk.accepted_at AS TEXT) AS accepted_at,
        CAST(risk.review_date AS TEXT) AS review_date,
        CAST(risk.created_at AS TEXT) AS created_at,
        CAST(risk.updated_at AS TEXT) AS updated_at
    FROM risks_risk risk
    LEFT JOIN risks_riskcategory category
        ON category.id = risk.category_id AND category.tenant_id = risk.tenant_id
    LEFT JOIN processes_process process
        ON process.id = risk.process_id AND process.tenant_id = risk.tenant_id
    LEFT JOIN assets_app_informationasset asset
        ON asset.id = risk.asset_id AND asset.tenant_id = risk.tenant_id
    LEFT JOIN accounts_user owner
        ON owner.id = risk.owner_id AND owner.tenant_id = risk.tenant_id
    LEFT JOIN accounts_user accepted
        ON accepted.id = risk.accepted_by_id AND accepted.tenant_id = risk.tenant_id
    WHERE risk.tenant_id = ? AND risk.id = ?
    "#
}

fn impact_label(value: i64) -> &'static str {
    match value {
        1 => "1 – Unerheblich",
        2 => "2 – Gering",
        3 => "3 – Mittel",
        4 => "4 – Hoch",
        5 => "5 – Kritisch",
        _ => "3 – Mittel",
    }
}

fn likelihood_label(value: i64) -> &'static str {
    match value {
        1 => "1 – Unwahrscheinlich",
        2 => "2 – Selten",
        3 => "3 – Moeglich",
        4 => "4 – Wahrscheinlich",
        5 => "5 – Sehr wahrscheinlich",
        _ => "3 – Moeglich",
    }
}

fn status_label(value: &str) -> &'static str {
    match value {
        "IDENTIFIED" => "Identifiziert",
        "ANALYZING" => "In Analyse",
        "TREATING" => "In Behandlung",
        "ACCEPTED" => "Akzeptiert",
        "MITIGATED" => "Gemindert",
        "TRANSFERRED" => "Transferiert",
        "AVOIDED" => "Vermieden",
        "CLOSED" => "Geschlossen",
        _ => "Identifiziert",
    }
}

fn treatment_label(value: &str) -> &'static str {
    match value {
        "MITIGATE" => "Mindern",
        "ACCEPT" => "Akzeptieren",
        "TRANSFER" => "Transferieren",
        "AVOID" => "Vermeiden",
        _ => "",
    }
}

fn risk_level(score: i64) -> &'static str {
    if score >= 20 {
        "CRITICAL"
    } else if score >= 12 {
        "HIGH"
    } else if score >= 6 {
        "MEDIUM"
    } else {
        "LOW"
    }
}

fn risk_level_label(value: &str) -> &'static str {
    match value {
        "CRITICAL" => "Kritisch",
        "HIGH" => "Hoch",
        "MEDIUM" => "Mittel",
        "LOW" => "Niedrig",
        _ => "–",
    }
}
