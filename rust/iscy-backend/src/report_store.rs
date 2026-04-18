use anyhow::{bail, Context};
use serde::Serialize;
use serde_json::Value;
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Row,
};

use crate::cve_store::normalize_database_url;

#[derive(Clone)]
pub enum ReportStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportSnapshotSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub session_id: i64,
    pub title: String,
    pub applicability_result: String,
    pub iso_readiness_percent: i64,
    pub nis2_readiness_percent: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportSnapshotDetail {
    pub id: i64,
    pub tenant_id: i64,
    pub session_id: i64,
    pub title: String,
    pub executive_summary: String,
    pub applicability_result: String,
    pub iso_readiness_percent: i64,
    pub nis2_readiness_percent: i64,
    pub kritis_readiness_percent: i64,
    pub cra_readiness_percent: i64,
    pub ai_act_readiness_percent: i64,
    pub iec62443_readiness_percent: i64,
    pub iso_sae_21434_readiness_percent: i64,
    pub regulatory_matrix_json: Value,
    pub compliance_versions_json: Value,
    pub product_security_json: Value,
    pub top_gaps_json: Value,
    pub top_measures_json: Value,
    pub roadmap_summary: Value,
    pub domain_scores_json: Value,
    pub next_steps_json: Value,
    pub created_at: String,
    pub updated_at: String,
}

impl ReportStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Report-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Report-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-Report-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn list_snapshots(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<ReportSnapshotSummary>> {
        match self {
            Self::Postgres(pool) => list_snapshots_postgres(pool, tenant_id, limit).await,
            Self::Sqlite(pool) => list_snapshots_sqlite(pool, tenant_id, limit).await,
        }
    }

    pub async fn snapshot_detail(
        &self,
        tenant_id: i64,
        report_id: i64,
    ) -> anyhow::Result<Option<ReportSnapshotDetail>> {
        match self {
            Self::Postgres(pool) => snapshot_detail_postgres(pool, tenant_id, report_id).await,
            Self::Sqlite(pool) => snapshot_detail_sqlite(pool, tenant_id, report_id).await,
        }
    }
}

async fn list_snapshots_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<ReportSnapshotSummary>> {
    let rows = sqlx::query(
        r#"
        SELECT
            id,
            tenant_id,
            session_id,
            title,
            applicability_result,
            iso_readiness_percent::bigint AS iso_readiness_percent,
            nis2_readiness_percent::bigint AS nis2_readiness_percent,
            created_at::text AS created_at,
            updated_at::text AS updated_at
        FROM reports_reportsnapshot
        WHERE tenant_id = $1
        ORDER BY created_at DESC, id DESC
        LIMIT $2
        "#,
    )
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("PostgreSQL-Reportliste konnte nicht gelesen werden")?;

    rows.into_iter()
        .map(summary_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_snapshots_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<ReportSnapshotSummary>> {
    let rows = sqlx::query(
        r#"
        SELECT
            id,
            tenant_id,
            session_id,
            title,
            applicability_result,
            iso_readiness_percent,
            nis2_readiness_percent,
            CAST(created_at AS TEXT) AS created_at,
            CAST(updated_at AS TEXT) AS updated_at
        FROM reports_reportsnapshot
        WHERE tenant_id = ?
        ORDER BY created_at DESC, id DESC
        LIMIT ?
        "#,
    )
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("SQLite-Reportliste konnte nicht gelesen werden")?;

    rows.into_iter()
        .map(summary_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn snapshot_detail_postgres(
    pool: &PgPool,
    tenant_id: i64,
    report_id: i64,
) -> anyhow::Result<Option<ReportSnapshotDetail>> {
    let row = sqlx::query(detail_postgres_sql())
        .bind(tenant_id)
        .bind(report_id)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-Reportdetail konnte nicht gelesen werden")?;

    row.map(detail_from_pg_row).transpose().map_err(Into::into)
}

async fn snapshot_detail_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    report_id: i64,
) -> anyhow::Result<Option<ReportSnapshotDetail>> {
    let row = sqlx::query(detail_sqlite_sql())
        .bind(tenant_id)
        .bind(report_id)
        .fetch_optional(pool)
        .await
        .context("SQLite-Reportdetail konnte nicht gelesen werden")?;

    row.map(detail_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

fn summary_from_pg_row(row: PgRow) -> Result<ReportSnapshotSummary, sqlx::Error> {
    Ok(ReportSnapshotSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        session_id: row.try_get("session_id")?,
        title: row.try_get("title")?,
        applicability_result: row.try_get("applicability_result")?,
        iso_readiness_percent: row.try_get("iso_readiness_percent")?,
        nis2_readiness_percent: row.try_get("nis2_readiness_percent")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn summary_from_sqlite_row(row: SqliteRow) -> Result<ReportSnapshotSummary, sqlx::Error> {
    Ok(ReportSnapshotSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        session_id: row.try_get("session_id")?,
        title: row.try_get("title")?,
        applicability_result: row.try_get("applicability_result")?,
        iso_readiness_percent: row.try_get("iso_readiness_percent")?,
        nis2_readiness_percent: row.try_get("nis2_readiness_percent")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn detail_from_pg_row(row: PgRow) -> Result<ReportSnapshotDetail, sqlx::Error> {
    Ok(ReportSnapshotDetail {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        session_id: row.try_get("session_id")?,
        title: row.try_get("title")?,
        executive_summary: row.try_get("executive_summary")?,
        applicability_result: row.try_get("applicability_result")?,
        iso_readiness_percent: row.try_get("iso_readiness_percent")?,
        nis2_readiness_percent: row.try_get("nis2_readiness_percent")?,
        kritis_readiness_percent: row.try_get("kritis_readiness_percent")?,
        cra_readiness_percent: row.try_get("cra_readiness_percent")?,
        ai_act_readiness_percent: row.try_get("ai_act_readiness_percent")?,
        iec62443_readiness_percent: row.try_get("iec62443_readiness_percent")?,
        iso_sae_21434_readiness_percent: row.try_get("iso_sae_21434_readiness_percent")?,
        regulatory_matrix_json: parse_json_object(row.try_get("regulatory_matrix_json_text")?),
        compliance_versions_json: parse_json_object(row.try_get("compliance_versions_json_text")?),
        product_security_json: parse_json_object(row.try_get("product_security_json_text")?),
        top_gaps_json: parse_json_array(row.try_get("top_gaps_json_text")?),
        top_measures_json: parse_json_array(row.try_get("top_measures_json_text")?),
        roadmap_summary: parse_json_array(row.try_get("roadmap_summary_text")?),
        domain_scores_json: parse_json_array(row.try_get("domain_scores_json_text")?),
        next_steps_json: parse_json_object(row.try_get("next_steps_json_text")?),
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn detail_from_sqlite_row(row: SqliteRow) -> Result<ReportSnapshotDetail, sqlx::Error> {
    Ok(ReportSnapshotDetail {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        session_id: row.try_get("session_id")?,
        title: row.try_get("title")?,
        executive_summary: row.try_get("executive_summary")?,
        applicability_result: row.try_get("applicability_result")?,
        iso_readiness_percent: row.try_get("iso_readiness_percent")?,
        nis2_readiness_percent: row.try_get("nis2_readiness_percent")?,
        kritis_readiness_percent: row.try_get("kritis_readiness_percent")?,
        cra_readiness_percent: row.try_get("cra_readiness_percent")?,
        ai_act_readiness_percent: row.try_get("ai_act_readiness_percent")?,
        iec62443_readiness_percent: row.try_get("iec62443_readiness_percent")?,
        iso_sae_21434_readiness_percent: row.try_get("iso_sae_21434_readiness_percent")?,
        regulatory_matrix_json: parse_json_object(row.try_get("regulatory_matrix_json_text")?),
        compliance_versions_json: parse_json_object(row.try_get("compliance_versions_json_text")?),
        product_security_json: parse_json_object(row.try_get("product_security_json_text")?),
        top_gaps_json: parse_json_array(row.try_get("top_gaps_json_text")?),
        top_measures_json: parse_json_array(row.try_get("top_measures_json_text")?),
        roadmap_summary: parse_json_array(row.try_get("roadmap_summary_text")?),
        domain_scores_json: parse_json_array(row.try_get("domain_scores_json_text")?),
        next_steps_json: parse_json_object(row.try_get("next_steps_json_text")?),
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn detail_postgres_sql() -> &'static str {
    r#"
    SELECT
        id,
        tenant_id,
        session_id,
        title,
        executive_summary,
        applicability_result,
        iso_readiness_percent::bigint AS iso_readiness_percent,
        nis2_readiness_percent::bigint AS nis2_readiness_percent,
        kritis_readiness_percent::bigint AS kritis_readiness_percent,
        cra_readiness_percent::bigint AS cra_readiness_percent,
        ai_act_readiness_percent::bigint AS ai_act_readiness_percent,
        iec62443_readiness_percent::bigint AS iec62443_readiness_percent,
        iso_sae_21434_readiness_percent::bigint AS iso_sae_21434_readiness_percent,
        COALESCE(regulatory_matrix_json::text, '{}') AS regulatory_matrix_json_text,
        COALESCE(compliance_versions_json::text, '{}') AS compliance_versions_json_text,
        COALESCE(product_security_json::text, '{}') AS product_security_json_text,
        COALESCE(top_gaps_json::text, '[]') AS top_gaps_json_text,
        COALESCE(top_measures_json::text, '[]') AS top_measures_json_text,
        COALESCE(roadmap_summary::text, '[]') AS roadmap_summary_text,
        COALESCE(domain_scores_json::text, '[]') AS domain_scores_json_text,
        COALESCE(next_steps_json::text, '{}') AS next_steps_json_text,
        created_at::text AS created_at,
        updated_at::text AS updated_at
    FROM reports_reportsnapshot
    WHERE tenant_id = $1 AND id = $2
    "#
}

fn detail_sqlite_sql() -> &'static str {
    r#"
    SELECT
        id,
        tenant_id,
        session_id,
        title,
        executive_summary,
        applicability_result,
        iso_readiness_percent,
        nis2_readiness_percent,
        kritis_readiness_percent,
        cra_readiness_percent,
        ai_act_readiness_percent,
        iec62443_readiness_percent,
        iso_sae_21434_readiness_percent,
        COALESCE(CAST(regulatory_matrix_json AS TEXT), '{}') AS regulatory_matrix_json_text,
        COALESCE(CAST(compliance_versions_json AS TEXT), '{}') AS compliance_versions_json_text,
        COALESCE(CAST(product_security_json AS TEXT), '{}') AS product_security_json_text,
        COALESCE(CAST(top_gaps_json AS TEXT), '[]') AS top_gaps_json_text,
        COALESCE(CAST(top_measures_json AS TEXT), '[]') AS top_measures_json_text,
        COALESCE(CAST(roadmap_summary AS TEXT), '[]') AS roadmap_summary_text,
        COALESCE(CAST(domain_scores_json AS TEXT), '[]') AS domain_scores_json_text,
        COALESCE(CAST(next_steps_json AS TEXT), '{}') AS next_steps_json_text,
        CAST(created_at AS TEXT) AS created_at,
        CAST(updated_at AS TEXT) AS updated_at
    FROM reports_reportsnapshot
    WHERE tenant_id = ? AND id = ?
    "#
}

fn parse_json_object(raw: String) -> Value {
    serde_json::from_str(&raw).unwrap_or_else(|_| serde_json::json!({}))
}

fn parse_json_array(raw: String) -> Value {
    serde_json::from_str(&raw).unwrap_or_else(|_| serde_json::json!([]))
}
