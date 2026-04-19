use anyhow::{bail, Context};
use serde::{Deserialize, Deserializer, Serialize};
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

#[derive(Debug, Clone, Deserialize)]
pub struct RiskWriteRequest {
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub category_id: Option<Option<i64>>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub process_id: Option<Option<i64>>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub asset_id: Option<Option<i64>>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub owner_id: Option<Option<i64>>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub threat: Option<String>,
    pub vulnerability: Option<String>,
    pub impact: Option<i64>,
    pub likelihood: Option<i64>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub residual_impact: Option<Option<i64>>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub residual_likelihood: Option<Option<i64>>,
    pub status: Option<String>,
    pub treatment_strategy: Option<String>,
    pub treatment_plan: Option<String>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub treatment_due_date: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub review_date: Option<Option<String>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RiskWriteResult {
    pub risk: RiskSummary,
}

#[derive(Debug, Clone, Copy)]
enum TenantRelation {
    Category,
    Process,
    Asset,
    User,
}

fn deserialize_double_option<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
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

    pub async fn create_risk(
        &self,
        tenant_id: i64,
        payload: RiskWriteRequest,
    ) -> anyhow::Result<RiskWriteResult> {
        match self {
            Self::Postgres(pool) => create_risk_postgres(pool, tenant_id, payload).await,
            Self::Sqlite(pool) => create_risk_sqlite(pool, tenant_id, payload).await,
        }
    }

    pub async fn update_risk(
        &self,
        tenant_id: i64,
        risk_id: i64,
        payload: RiskWriteRequest,
    ) -> anyhow::Result<Option<RiskWriteResult>> {
        match self {
            Self::Postgres(pool) => update_risk_postgres(pool, tenant_id, risk_id, payload).await,
            Self::Sqlite(pool) => update_risk_sqlite(pool, tenant_id, risk_id, payload).await,
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

async fn create_risk_postgres(
    pool: &PgPool,
    tenant_id: i64,
    payload: RiskWriteRequest,
) -> anyhow::Result<RiskWriteResult> {
    let RiskWriteRequest {
        category_id,
        process_id,
        asset_id,
        owner_id,
        title,
        description,
        threat,
        vulnerability,
        impact,
        likelihood,
        residual_impact,
        residual_likelihood,
        status,
        treatment_strategy,
        treatment_plan,
        treatment_due_date,
        review_date,
    } = payload;

    let category_id = tenant_relation_id_postgres(
        pool,
        TenantRelation::Category,
        tenant_id,
        category_id.unwrap_or(None),
    )
    .await?;
    let process_id = tenant_relation_id_postgres(
        pool,
        TenantRelation::Process,
        tenant_id,
        process_id.unwrap_or(None),
    )
    .await?;
    let asset_id = tenant_relation_id_postgres(
        pool,
        TenantRelation::Asset,
        tenant_id,
        asset_id.unwrap_or(None),
    )
    .await?;
    let owner_id = tenant_relation_id_postgres(
        pool,
        TenantRelation::User,
        tenant_id,
        owner_id.unwrap_or(None),
    )
    .await?;
    let title = normalize_title(title, None);
    let description = normalize_text(description, "");
    let threat = normalize_text(threat, "");
    let vulnerability = normalize_text(vulnerability, "");
    let impact = normalize_matrix_value(impact, 3);
    let likelihood = normalize_matrix_value(likelihood, 3);
    let residual_impact = normalize_nullable_matrix_value(residual_impact.unwrap_or(None));
    let residual_likelihood = normalize_nullable_matrix_value(residual_likelihood.unwrap_or(None));
    let status = normalize_status(status.as_deref(), "IDENTIFIED").to_string();
    let treatment_strategy =
        normalize_treatment_strategy(treatment_strategy.as_deref(), "").to_string();
    let treatment_plan = normalize_text(treatment_plan, "");
    let treatment_due_date = normalize_optional_date_text(treatment_due_date.unwrap_or(None));
    let review_date = normalize_optional_date_text(review_date.unwrap_or(None));

    let risk_id: i64 = sqlx::query_scalar(
        r#"
        INSERT INTO risks_risk (
            tenant_id,
            category_id,
            process_id,
            asset_id,
            owner_id,
            title,
            description,
            threat,
            vulnerability,
            impact,
            likelihood,
            residual_impact,
            residual_likelihood,
            status,
            treatment_strategy,
            treatment_plan,
            treatment_due_date,
            accepted_by_id,
            accepted_at,
            review_date,
            created_at,
            updated_at
        )
        VALUES (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8,
            $9,
            $10::integer,
            $11::integer,
            $12::integer,
            $13::integer,
            $14,
            $15,
            $16,
            $17::date,
            NULL,
            NULL,
            $18::date,
            NOW(),
            NOW()
        )
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(category_id)
    .bind(process_id)
    .bind(asset_id)
    .bind(owner_id)
    .bind(title)
    .bind(description)
    .bind(threat)
    .bind(vulnerability)
    .bind(impact)
    .bind(likelihood)
    .bind(residual_impact)
    .bind(residual_likelihood)
    .bind(status)
    .bind(treatment_strategy)
    .bind(treatment_plan)
    .bind(treatment_due_date)
    .bind(review_date)
    .fetch_one(pool)
    .await
    .context("PostgreSQL-Risiko konnte nicht erstellt werden")?;

    let risk = risk_detail_postgres(pool, tenant_id, risk_id)
        .await?
        .context("Erstelltes Risiko wurde nicht gefunden")?;
    Ok(RiskWriteResult { risk })
}

async fn create_risk_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    payload: RiskWriteRequest,
) -> anyhow::Result<RiskWriteResult> {
    let RiskWriteRequest {
        category_id,
        process_id,
        asset_id,
        owner_id,
        title,
        description,
        threat,
        vulnerability,
        impact,
        likelihood,
        residual_impact,
        residual_likelihood,
        status,
        treatment_strategy,
        treatment_plan,
        treatment_due_date,
        review_date,
    } = payload;

    let category_id = tenant_relation_id_sqlite(
        pool,
        TenantRelation::Category,
        tenant_id,
        category_id.unwrap_or(None),
    )
    .await?;
    let process_id = tenant_relation_id_sqlite(
        pool,
        TenantRelation::Process,
        tenant_id,
        process_id.unwrap_or(None),
    )
    .await?;
    let asset_id = tenant_relation_id_sqlite(
        pool,
        TenantRelation::Asset,
        tenant_id,
        asset_id.unwrap_or(None),
    )
    .await?;
    let owner_id = tenant_relation_id_sqlite(
        pool,
        TenantRelation::User,
        tenant_id,
        owner_id.unwrap_or(None),
    )
    .await?;
    let title = normalize_title(title, None);
    let description = normalize_text(description, "");
    let threat = normalize_text(threat, "");
    let vulnerability = normalize_text(vulnerability, "");
    let impact = normalize_matrix_value(impact, 3);
    let likelihood = normalize_matrix_value(likelihood, 3);
    let residual_impact = normalize_nullable_matrix_value(residual_impact.unwrap_or(None));
    let residual_likelihood = normalize_nullable_matrix_value(residual_likelihood.unwrap_or(None));
    let status = normalize_status(status.as_deref(), "IDENTIFIED").to_string();
    let treatment_strategy =
        normalize_treatment_strategy(treatment_strategy.as_deref(), "").to_string();
    let treatment_plan = normalize_text(treatment_plan, "");
    let treatment_due_date = normalize_optional_date_text(treatment_due_date.unwrap_or(None));
    let review_date = normalize_optional_date_text(review_date.unwrap_or(None));

    sqlx::query(
        r#"
        INSERT INTO risks_risk (
            tenant_id,
            category_id,
            process_id,
            asset_id,
            owner_id,
            title,
            description,
            threat,
            vulnerability,
            impact,
            likelihood,
            residual_impact,
            residual_likelihood,
            status,
            treatment_strategy,
            treatment_plan,
            treatment_due_date,
            accepted_by_id,
            accepted_at,
            review_date,
            created_at,
            updated_at
        )
        VALUES (
            ?1,
            ?2,
            ?3,
            ?4,
            ?5,
            ?6,
            ?7,
            ?8,
            ?9,
            ?10,
            ?11,
            ?12,
            ?13,
            ?14,
            ?15,
            ?16,
            ?17,
            NULL,
            NULL,
            ?18,
            datetime('now'),
            datetime('now')
        )
        "#,
    )
    .bind(tenant_id)
    .bind(category_id)
    .bind(process_id)
    .bind(asset_id)
    .bind(owner_id)
    .bind(title)
    .bind(description)
    .bind(threat)
    .bind(vulnerability)
    .bind(impact)
    .bind(likelihood)
    .bind(residual_impact)
    .bind(residual_likelihood)
    .bind(status)
    .bind(treatment_strategy)
    .bind(treatment_plan)
    .bind(treatment_due_date)
    .bind(review_date)
    .execute(pool)
    .await
    .context("SQLite-Risiko konnte nicht erstellt werden")?;

    let risk_id: i64 = sqlx::query_scalar("SELECT last_insert_rowid()")
        .fetch_one(pool)
        .await
        .context("SQLite-Risiko-ID konnte nicht gelesen werden")?;
    let risk = risk_detail_sqlite(pool, tenant_id, risk_id)
        .await?
        .context("Erstelltes Risiko wurde nicht gefunden")?;
    Ok(RiskWriteResult { risk })
}

async fn update_risk_postgres(
    pool: &PgPool,
    tenant_id: i64,
    risk_id: i64,
    payload: RiskWriteRequest,
) -> anyhow::Result<Option<RiskWriteResult>> {
    let Some(current) = risk_detail_postgres(pool, tenant_id, risk_id).await? else {
        return Ok(None);
    };
    let RiskWriteRequest {
        category_id,
        process_id,
        asset_id,
        owner_id,
        title,
        description,
        threat,
        vulnerability,
        impact,
        likelihood,
        residual_impact,
        residual_likelihood,
        status,
        treatment_strategy,
        treatment_plan,
        treatment_due_date,
        review_date,
    } = payload;

    let category_id = match category_id {
        Some(value) => {
            tenant_relation_id_postgres(pool, TenantRelation::Category, tenant_id, value).await?
        }
        None => current.category_id,
    };
    let process_id = match process_id {
        Some(value) => {
            tenant_relation_id_postgres(pool, TenantRelation::Process, tenant_id, value).await?
        }
        None => current.process_id,
    };
    let asset_id = match asset_id {
        Some(value) => {
            tenant_relation_id_postgres(pool, TenantRelation::Asset, tenant_id, value).await?
        }
        None => current.asset_id,
    };
    let owner_id = match owner_id {
        Some(value) => {
            tenant_relation_id_postgres(pool, TenantRelation::User, tenant_id, value).await?
        }
        None => current.owner_id,
    };
    let title = normalize_title(title, Some(&current.title));
    let description = normalize_text(description, &current.description);
    let threat = normalize_text(threat, &current.threat);
    let vulnerability = normalize_text(vulnerability, &current.vulnerability);
    let impact = normalize_matrix_value(impact, current.impact);
    let likelihood = normalize_matrix_value(likelihood, current.likelihood);
    let residual_impact = match residual_impact {
        Some(value) => normalize_nullable_matrix_value(value),
        None => current.residual_impact,
    };
    let residual_likelihood = match residual_likelihood {
        Some(value) => normalize_nullable_matrix_value(value),
        None => current.residual_likelihood,
    };
    let status = normalize_status(status.as_deref(), &current.status).to_string();
    let treatment_strategy =
        normalize_treatment_strategy(treatment_strategy.as_deref(), &current.treatment_strategy)
            .to_string();
    let treatment_plan = normalize_text(treatment_plan, &current.treatment_plan);
    let treatment_due_date = match treatment_due_date {
        Some(value) => normalize_optional_date_text(value),
        None => current.treatment_due_date,
    };
    let review_date = match review_date {
        Some(value) => normalize_optional_date_text(value),
        None => current.review_date,
    };

    sqlx::query(
        r#"
        UPDATE risks_risk
        SET category_id = $2,
            process_id = $3,
            asset_id = $4,
            owner_id = $5,
            title = $6,
            description = $7,
            threat = $8,
            vulnerability = $9,
            impact = $10::integer,
            likelihood = $11::integer,
            residual_impact = $12::integer,
            residual_likelihood = $13::integer,
            status = $14,
            treatment_strategy = $15,
            treatment_plan = $16,
            treatment_due_date = $17::date,
            review_date = $18::date,
            updated_at = NOW()
        WHERE id = $1 AND tenant_id = $19
        "#,
    )
    .bind(risk_id)
    .bind(category_id)
    .bind(process_id)
    .bind(asset_id)
    .bind(owner_id)
    .bind(title)
    .bind(description)
    .bind(threat)
    .bind(vulnerability)
    .bind(impact)
    .bind(likelihood)
    .bind(residual_impact)
    .bind(residual_likelihood)
    .bind(status)
    .bind(treatment_strategy)
    .bind(treatment_plan)
    .bind(treatment_due_date)
    .bind(review_date)
    .bind(tenant_id)
    .execute(pool)
    .await
    .context("PostgreSQL-Risiko konnte nicht aktualisiert werden")?;

    let risk = risk_detail_postgres(pool, tenant_id, risk_id)
        .await?
        .context("Aktualisiertes Risiko wurde nicht gefunden")?;
    Ok(Some(RiskWriteResult { risk }))
}

async fn update_risk_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    risk_id: i64,
    payload: RiskWriteRequest,
) -> anyhow::Result<Option<RiskWriteResult>> {
    let Some(current) = risk_detail_sqlite(pool, tenant_id, risk_id).await? else {
        return Ok(None);
    };
    let RiskWriteRequest {
        category_id,
        process_id,
        asset_id,
        owner_id,
        title,
        description,
        threat,
        vulnerability,
        impact,
        likelihood,
        residual_impact,
        residual_likelihood,
        status,
        treatment_strategy,
        treatment_plan,
        treatment_due_date,
        review_date,
    } = payload;

    let category_id = match category_id {
        Some(value) => {
            tenant_relation_id_sqlite(pool, TenantRelation::Category, tenant_id, value).await?
        }
        None => current.category_id,
    };
    let process_id = match process_id {
        Some(value) => {
            tenant_relation_id_sqlite(pool, TenantRelation::Process, tenant_id, value).await?
        }
        None => current.process_id,
    };
    let asset_id = match asset_id {
        Some(value) => {
            tenant_relation_id_sqlite(pool, TenantRelation::Asset, tenant_id, value).await?
        }
        None => current.asset_id,
    };
    let owner_id = match owner_id {
        Some(value) => {
            tenant_relation_id_sqlite(pool, TenantRelation::User, tenant_id, value).await?
        }
        None => current.owner_id,
    };
    let title = normalize_title(title, Some(&current.title));
    let description = normalize_text(description, &current.description);
    let threat = normalize_text(threat, &current.threat);
    let vulnerability = normalize_text(vulnerability, &current.vulnerability);
    let impact = normalize_matrix_value(impact, current.impact);
    let likelihood = normalize_matrix_value(likelihood, current.likelihood);
    let residual_impact = match residual_impact {
        Some(value) => normalize_nullable_matrix_value(value),
        None => current.residual_impact,
    };
    let residual_likelihood = match residual_likelihood {
        Some(value) => normalize_nullable_matrix_value(value),
        None => current.residual_likelihood,
    };
    let status = normalize_status(status.as_deref(), &current.status).to_string();
    let treatment_strategy =
        normalize_treatment_strategy(treatment_strategy.as_deref(), &current.treatment_strategy)
            .to_string();
    let treatment_plan = normalize_text(treatment_plan, &current.treatment_plan);
    let treatment_due_date = match treatment_due_date {
        Some(value) => normalize_optional_date_text(value),
        None => current.treatment_due_date,
    };
    let review_date = match review_date {
        Some(value) => normalize_optional_date_text(value),
        None => current.review_date,
    };

    sqlx::query(
        r#"
        UPDATE risks_risk
        SET category_id = ?2,
            process_id = ?3,
            asset_id = ?4,
            owner_id = ?5,
            title = ?6,
            description = ?7,
            threat = ?8,
            vulnerability = ?9,
            impact = ?10,
            likelihood = ?11,
            residual_impact = ?12,
            residual_likelihood = ?13,
            status = ?14,
            treatment_strategy = ?15,
            treatment_plan = ?16,
            treatment_due_date = ?17,
            review_date = ?18,
            updated_at = datetime('now')
        WHERE id = ?1 AND tenant_id = ?19
        "#,
    )
    .bind(risk_id)
    .bind(category_id)
    .bind(process_id)
    .bind(asset_id)
    .bind(owner_id)
    .bind(title)
    .bind(description)
    .bind(threat)
    .bind(vulnerability)
    .bind(impact)
    .bind(likelihood)
    .bind(residual_impact)
    .bind(residual_likelihood)
    .bind(status)
    .bind(treatment_strategy)
    .bind(treatment_plan)
    .bind(treatment_due_date)
    .bind(review_date)
    .bind(tenant_id)
    .execute(pool)
    .await
    .context("SQLite-Risiko konnte nicht aktualisiert werden")?;

    let risk = risk_detail_sqlite(pool, tenant_id, risk_id)
        .await?
        .context("Aktualisiertes Risiko wurde nicht gefunden")?;
    Ok(Some(RiskWriteResult { risk }))
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

async fn tenant_relation_id_postgres(
    pool: &PgPool,
    relation: TenantRelation,
    tenant_id: i64,
    value: Option<i64>,
) -> anyhow::Result<Option<i64>> {
    let Some(candidate_id) = value.filter(|candidate_id| *candidate_id > 0) else {
        return Ok(None);
    };
    let query = match relation {
        TenantRelation::Category => {
            "SELECT id FROM risks_riskcategory WHERE tenant_id = $1 AND id = $2"
        }
        TenantRelation::Process => {
            "SELECT id FROM processes_process WHERE tenant_id = $1 AND id = $2"
        }
        TenantRelation::Asset => {
            "SELECT id FROM assets_app_informationasset WHERE tenant_id = $1 AND id = $2"
        }
        TenantRelation::User => "SELECT id FROM accounts_user WHERE tenant_id = $1 AND id = $2",
    };
    sqlx::query_scalar::<_, i64>(query)
        .bind(tenant_id)
        .bind(candidate_id)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-Risiko-Relation konnte nicht validiert werden")
}

async fn tenant_relation_id_sqlite(
    pool: &SqlitePool,
    relation: TenantRelation,
    tenant_id: i64,
    value: Option<i64>,
) -> anyhow::Result<Option<i64>> {
    let Some(candidate_id) = value.filter(|candidate_id| *candidate_id > 0) else {
        return Ok(None);
    };
    let query = match relation {
        TenantRelation::Category => {
            "SELECT id FROM risks_riskcategory WHERE tenant_id = ?1 AND id = ?2"
        }
        TenantRelation::Process => {
            "SELECT id FROM processes_process WHERE tenant_id = ?1 AND id = ?2"
        }
        TenantRelation::Asset => {
            "SELECT id FROM assets_app_informationasset WHERE tenant_id = ?1 AND id = ?2"
        }
        TenantRelation::User => "SELECT id FROM accounts_user WHERE tenant_id = ?1 AND id = ?2",
    };
    sqlx::query_scalar::<_, i64>(query)
        .bind(tenant_id)
        .bind(candidate_id)
        .fetch_optional(pool)
        .await
        .context("SQLite-Risiko-Relation konnte nicht validiert werden")
}

fn normalize_title(value: Option<String>, default: Option<&str>) -> String {
    let raw = value
        .or_else(|| default.map(ToString::to_string))
        .unwrap_or_else(|| "Unbenanntes Risiko".to_string());
    let cleaned = raw.trim();
    if cleaned.is_empty() {
        "Unbenanntes Risiko".to_string()
    } else {
        cleaned.to_string()
    }
}

fn normalize_text(value: Option<String>, default: &str) -> String {
    value.unwrap_or_else(|| default.to_string())
}

fn normalize_optional_date_text(value: Option<String>) -> Option<String> {
    value
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
}

fn normalize_matrix_value(value: Option<i64>, default: i64) -> i64 {
    match value {
        Some(candidate) if (1..=5).contains(&candidate) => candidate,
        _ if (1..=5).contains(&default) => default,
        _ => 3,
    }
}

fn normalize_nullable_matrix_value(value: Option<i64>) -> Option<i64> {
    value.filter(|candidate| (1..=5).contains(candidate))
}

fn normalize_status(value: Option<&str>, default: &str) -> &'static str {
    match value.map(str::trim).map(str::to_ascii_uppercase).as_deref() {
        Some("IDENTIFIED") => "IDENTIFIED",
        Some("ANALYZING") => "ANALYZING",
        Some("TREATING") => "TREATING",
        Some("ACCEPTED") => "ACCEPTED",
        Some("MITIGATED") => "MITIGATED",
        Some("TRANSFERRED") => "TRANSFERRED",
        Some("AVOIDED") => "AVOIDED",
        Some("CLOSED") => "CLOSED",
        _ => match default {
            "ANALYZING" => "ANALYZING",
            "TREATING" => "TREATING",
            "ACCEPTED" => "ACCEPTED",
            "MITIGATED" => "MITIGATED",
            "TRANSFERRED" => "TRANSFERRED",
            "AVOIDED" => "AVOIDED",
            "CLOSED" => "CLOSED",
            _ => "IDENTIFIED",
        },
    }
}

fn normalize_treatment_strategy(value: Option<&str>, default: &str) -> &'static str {
    match value.map(str::trim).map(str::to_ascii_uppercase).as_deref() {
        Some("MITIGATE") => "MITIGATE",
        Some("ACCEPT") => "ACCEPT",
        Some("TRANSFER") => "TRANSFER",
        Some("AVOID") => "AVOID",
        Some("") => "",
        _ => match default {
            "MITIGATE" => "MITIGATE",
            "ACCEPT" => "ACCEPT",
            "TRANSFER" => "TRANSFER",
            "AVOID" => "AVOID",
            _ => "",
        },
    }
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
