use anyhow::{bail, Context};
use serde::Serialize;
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Row,
};

use crate::cve_store::normalize_database_url;

#[derive(Clone)]
pub enum DashboardStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Serialize)]
pub struct DashboardLatestReport {
    pub id: i64,
    pub title: String,
    pub iso_readiness_percent: i64,
    pub nis2_readiness_percent: i64,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DashboardSummary {
    pub tenant_id: i64,
    pub process_count: i64,
    pub asset_count: i64,
    pub open_risk_count: i64,
    pub evidence_count: i64,
    pub open_task_count: i64,
    pub latest_report: Option<DashboardLatestReport>,
}

impl DashboardStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Dashboard-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Dashboard-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-Dashboard-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn dashboard_summary(&self, tenant_id: i64) -> anyhow::Result<DashboardSummary> {
        match self {
            Self::Postgres(pool) => dashboard_summary_postgres(pool, tenant_id).await,
            Self::Sqlite(pool) => dashboard_summary_sqlite(pool, tenant_id).await,
        }
    }
}

async fn dashboard_summary_postgres(
    pool: &PgPool,
    tenant_id: i64,
) -> anyhow::Result<DashboardSummary> {
    let counts = sqlx::query(
        r#"
        SELECT
            (SELECT COUNT(*) FROM processes_process WHERE tenant_id = $1)::bigint AS process_count,
            (SELECT COUNT(*) FROM assets_app_informationasset WHERE tenant_id = $1)::bigint AS asset_count,
            (SELECT COUNT(*) FROM risks_risk WHERE tenant_id = $1 AND status <> 'CLOSED')::bigint AS open_risk_count,
            (SELECT COUNT(*) FROM evidence_evidenceitem WHERE tenant_id = $1)::bigint AS evidence_count,
            (
                SELECT COUNT(*)
                FROM roadmap_roadmaptask task
                JOIN roadmap_roadmapphase phase ON task.phase_id = phase.id
                JOIN roadmap_roadmapplan plan ON phase.plan_id = plan.id
                WHERE plan.tenant_id = $1 AND task.status <> 'DONE'
            )::bigint AS open_task_count
        "#,
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .context("PostgreSQL-Dashboard-Zaehler konnten nicht gelesen werden")?;

    let latest_report = sqlx::query(
        r#"
        SELECT
            id,
            title,
            iso_readiness_percent::bigint AS iso_readiness_percent,
            nis2_readiness_percent::bigint AS nis2_readiness_percent,
            created_at::text AS created_at
        FROM reports_reportsnapshot
        WHERE tenant_id = $1
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-Dashboard-Report konnte nicht gelesen werden")?
    .map(latest_report_from_pg_row)
    .transpose()?;

    summary_from_pg_row(counts, tenant_id, latest_report).map_err(Into::into)
}

async fn dashboard_summary_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
) -> anyhow::Result<DashboardSummary> {
    let counts = sqlx::query(
        r#"
        SELECT
            (SELECT COUNT(*) FROM processes_process WHERE tenant_id = ?1) AS process_count,
            (SELECT COUNT(*) FROM assets_app_informationasset WHERE tenant_id = ?1) AS asset_count,
            (SELECT COUNT(*) FROM risks_risk WHERE tenant_id = ?1 AND status <> 'CLOSED') AS open_risk_count,
            (SELECT COUNT(*) FROM evidence_evidenceitem WHERE tenant_id = ?1) AS evidence_count,
            (
                SELECT COUNT(*)
                FROM roadmap_roadmaptask task
                JOIN roadmap_roadmapphase phase ON task.phase_id = phase.id
                JOIN roadmap_roadmapplan plan ON phase.plan_id = plan.id
                WHERE plan.tenant_id = ?1 AND task.status <> 'DONE'
            ) AS open_task_count
        "#,
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .context("SQLite-Dashboard-Zaehler konnten nicht gelesen werden")?;

    let latest_report = sqlx::query(
        r#"
        SELECT
            id,
            title,
            iso_readiness_percent,
            nis2_readiness_percent,
            CAST(created_at AS TEXT) AS created_at
        FROM reports_reportsnapshot
        WHERE tenant_id = ?
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-Dashboard-Report konnte nicht gelesen werden")?
    .map(latest_report_from_sqlite_row)
    .transpose()?;

    summary_from_sqlite_row(counts, tenant_id, latest_report).map_err(Into::into)
}

fn summary_from_pg_row(
    row: PgRow,
    tenant_id: i64,
    latest_report: Option<DashboardLatestReport>,
) -> Result<DashboardSummary, sqlx::Error> {
    Ok(DashboardSummary {
        tenant_id,
        process_count: row.try_get("process_count")?,
        asset_count: row.try_get("asset_count")?,
        open_risk_count: row.try_get("open_risk_count")?,
        evidence_count: row.try_get("evidence_count")?,
        open_task_count: row.try_get("open_task_count")?,
        latest_report,
    })
}

fn summary_from_sqlite_row(
    row: SqliteRow,
    tenant_id: i64,
    latest_report: Option<DashboardLatestReport>,
) -> Result<DashboardSummary, sqlx::Error> {
    Ok(DashboardSummary {
        tenant_id,
        process_count: row.try_get("process_count")?,
        asset_count: row.try_get("asset_count")?,
        open_risk_count: row.try_get("open_risk_count")?,
        evidence_count: row.try_get("evidence_count")?,
        open_task_count: row.try_get("open_task_count")?,
        latest_report,
    })
}

fn latest_report_from_pg_row(row: PgRow) -> Result<DashboardLatestReport, sqlx::Error> {
    Ok(DashboardLatestReport {
        id: row.try_get("id")?,
        title: row.try_get("title")?,
        iso_readiness_percent: row.try_get("iso_readiness_percent")?,
        nis2_readiness_percent: row.try_get("nis2_readiness_percent")?,
        created_at: row.try_get("created_at")?,
    })
}

fn latest_report_from_sqlite_row(row: SqliteRow) -> Result<DashboardLatestReport, sqlx::Error> {
    Ok(DashboardLatestReport {
        id: row.try_get("id")?,
        title: row.try_get("title")?,
        iso_readiness_percent: row.try_get("iso_readiness_percent")?,
        nis2_readiness_percent: row.try_get("nis2_readiness_percent")?,
        created_at: row.try_get("created_at")?,
    })
}
