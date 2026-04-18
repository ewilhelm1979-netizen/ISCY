use anyhow::{bail, Context};
use serde::Serialize;
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Row,
};

use crate::cve_store::normalize_database_url;

#[derive(Clone)]
pub enum ProcessStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub business_unit_id: Option<i64>,
    pub business_unit_name: Option<String>,
    pub owner_id: Option<i64>,
    pub owner_display: Option<String>,
    pub name: String,
    pub scope: String,
    pub description: String,
    pub status: String,
    pub status_label: String,
    pub documented: bool,
    pub approved: bool,
    pub communicated: bool,
    pub implemented: bool,
    pub effective: bool,
    pub evidenced: bool,
    pub reviewed_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl ProcessStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Process-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Process-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-Process-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn list_processes(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<ProcessSummary>> {
        match self {
            Self::Postgres(pool) => list_processes_postgres(pool, tenant_id, limit).await,
            Self::Sqlite(pool) => list_processes_sqlite(pool, tenant_id, limit).await,
        }
    }

    pub async fn process_detail(
        &self,
        tenant_id: i64,
        process_id: i64,
    ) -> anyhow::Result<Option<ProcessSummary>> {
        match self {
            Self::Postgres(pool) => process_detail_postgres(pool, tenant_id, process_id).await,
            Self::Sqlite(pool) => process_detail_sqlite(pool, tenant_id, process_id).await,
        }
    }
}

async fn list_processes_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<ProcessSummary>> {
    let rows = sqlx::query(process_list_postgres_sql())
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Prozessliste konnte nicht gelesen werden")?;

    rows.into_iter()
        .map(summary_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_processes_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<ProcessSummary>> {
    let rows = sqlx::query(process_list_sqlite_sql())
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("SQLite-Prozessliste konnte nicht gelesen werden")?;

    rows.into_iter()
        .map(summary_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn process_detail_postgres(
    pool: &PgPool,
    tenant_id: i64,
    process_id: i64,
) -> anyhow::Result<Option<ProcessSummary>> {
    let row = sqlx::query(process_detail_postgres_sql())
        .bind(tenant_id)
        .bind(process_id)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-Prozessdetail konnte nicht gelesen werden")?;

    row.map(summary_from_pg_row).transpose().map_err(Into::into)
}

async fn process_detail_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    process_id: i64,
) -> anyhow::Result<Option<ProcessSummary>> {
    let row = sqlx::query(process_detail_sqlite_sql())
        .bind(tenant_id)
        .bind(process_id)
        .fetch_optional(pool)
        .await
        .context("SQLite-Prozessdetail konnte nicht gelesen werden")?;

    row.map(summary_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

fn summary_from_pg_row(row: PgRow) -> Result<ProcessSummary, sqlx::Error> {
    let status: String = row.try_get("status")?;
    Ok(ProcessSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        business_unit_id: row.try_get("business_unit_id")?,
        business_unit_name: row.try_get("business_unit_name")?,
        owner_id: row.try_get("owner_id")?,
        owner_display: row.try_get("owner_display")?,
        name: row.try_get("name")?,
        scope: row.try_get("scope")?,
        description: row.try_get("description")?,
        status_label: status_label(&status).to_string(),
        status,
        documented: row.try_get("documented")?,
        approved: row.try_get("approved")?,
        communicated: row.try_get("communicated")?,
        implemented: row.try_get("implemented")?,
        effective: row.try_get("effective")?,
        evidenced: row.try_get("evidenced")?,
        reviewed_at: row.try_get("reviewed_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn summary_from_sqlite_row(row: SqliteRow) -> Result<ProcessSummary, sqlx::Error> {
    let status: String = row.try_get("status")?;
    Ok(ProcessSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        business_unit_id: row.try_get("business_unit_id")?,
        business_unit_name: row.try_get("business_unit_name")?,
        owner_id: row.try_get("owner_id")?,
        owner_display: row.try_get("owner_display")?,
        name: row.try_get("name")?,
        scope: row.try_get("scope")?,
        description: row.try_get("description")?,
        status_label: status_label(&status).to_string(),
        status,
        documented: row.try_get("documented")?,
        approved: row.try_get("approved")?,
        communicated: row.try_get("communicated")?,
        implemented: row.try_get("implemented")?,
        effective: row.try_get("effective")?,
        evidenced: row.try_get("evidenced")?,
        reviewed_at: row.try_get("reviewed_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn process_list_postgres_sql() -> &'static str {
    r#"
    SELECT
        proc.id,
        proc.tenant_id,
        proc.business_unit_id,
        bu.name AS business_unit_name,
        proc.owner_id,
        COALESCE(
            NULLIF(BTRIM(CONCAT(COALESCE(owner.first_name, ''), ' ', COALESCE(owner.last_name, ''))), ''),
            owner.username
        ) AS owner_display,
        proc.name,
        proc.scope,
        proc.description,
        proc.status,
        proc.documented,
        proc.approved,
        proc.communicated,
        proc.implemented,
        proc.effective,
        proc.evidenced,
        proc.reviewed_at::text AS reviewed_at,
        proc.created_at::text AS created_at,
        proc.updated_at::text AS updated_at
    FROM processes_process proc
    LEFT JOIN organizations_businessunit bu
        ON bu.id = proc.business_unit_id AND bu.tenant_id = proc.tenant_id
    LEFT JOIN accounts_user owner
        ON owner.id = proc.owner_id AND owner.tenant_id = proc.tenant_id
    WHERE proc.tenant_id = $1
    ORDER BY proc.name ASC, proc.id ASC
    LIMIT $2
    "#
}

fn process_list_sqlite_sql() -> &'static str {
    r#"
    SELECT
        proc.id,
        proc.tenant_id,
        proc.business_unit_id,
        bu.name AS business_unit_name,
        proc.owner_id,
        COALESCE(
            NULLIF(TRIM(COALESCE(owner.first_name, '') || ' ' || COALESCE(owner.last_name, '')), ''),
            owner.username
        ) AS owner_display,
        proc.name,
        proc.scope,
        proc.description,
        proc.status,
        proc.documented,
        proc.approved,
        proc.communicated,
        proc.implemented,
        proc.effective,
        proc.evidenced,
        CAST(proc.reviewed_at AS TEXT) AS reviewed_at,
        CAST(proc.created_at AS TEXT) AS created_at,
        CAST(proc.updated_at AS TEXT) AS updated_at
    FROM processes_process proc
    LEFT JOIN organizations_businessunit bu
        ON bu.id = proc.business_unit_id AND bu.tenant_id = proc.tenant_id
    LEFT JOIN accounts_user owner
        ON owner.id = proc.owner_id AND owner.tenant_id = proc.tenant_id
    WHERE proc.tenant_id = ?
    ORDER BY proc.name ASC, proc.id ASC
    LIMIT ?
    "#
}

fn process_detail_postgres_sql() -> &'static str {
    r#"
    SELECT
        proc.id,
        proc.tenant_id,
        proc.business_unit_id,
        bu.name AS business_unit_name,
        proc.owner_id,
        COALESCE(
            NULLIF(BTRIM(CONCAT(COALESCE(owner.first_name, ''), ' ', COALESCE(owner.last_name, ''))), ''),
            owner.username
        ) AS owner_display,
        proc.name,
        proc.scope,
        proc.description,
        proc.status,
        proc.documented,
        proc.approved,
        proc.communicated,
        proc.implemented,
        proc.effective,
        proc.evidenced,
        proc.reviewed_at::text AS reviewed_at,
        proc.created_at::text AS created_at,
        proc.updated_at::text AS updated_at
    FROM processes_process proc
    LEFT JOIN organizations_businessunit bu
        ON bu.id = proc.business_unit_id AND bu.tenant_id = proc.tenant_id
    LEFT JOIN accounts_user owner
        ON owner.id = proc.owner_id AND owner.tenant_id = proc.tenant_id
    WHERE proc.tenant_id = $1 AND proc.id = $2
    "#
}

fn process_detail_sqlite_sql() -> &'static str {
    r#"
    SELECT
        proc.id,
        proc.tenant_id,
        proc.business_unit_id,
        bu.name AS business_unit_name,
        proc.owner_id,
        COALESCE(
            NULLIF(TRIM(COALESCE(owner.first_name, '') || ' ' || COALESCE(owner.last_name, '')), ''),
            owner.username
        ) AS owner_display,
        proc.name,
        proc.scope,
        proc.description,
        proc.status,
        proc.documented,
        proc.approved,
        proc.communicated,
        proc.implemented,
        proc.effective,
        proc.evidenced,
        CAST(proc.reviewed_at AS TEXT) AS reviewed_at,
        CAST(proc.created_at AS TEXT) AS created_at,
        CAST(proc.updated_at AS TEXT) AS updated_at
    FROM processes_process proc
    LEFT JOIN organizations_businessunit bu
        ON bu.id = proc.business_unit_id AND bu.tenant_id = proc.tenant_id
    LEFT JOIN accounts_user owner
        ON owner.id = proc.owner_id AND owner.tenant_id = proc.tenant_id
    WHERE proc.tenant_id = ? AND proc.id = ?
    "#
}

fn status_label(value: &str) -> &'static str {
    match value {
        "SUFFICIENT" => "Vorhanden und ausreichend",
        "PARTIAL" => "Vorhanden, aber unvollständig",
        "INFORMAL" => "Informal vorhanden",
        "DOCUMENTED_NOT_IMPLEMENTED" => "Dokumentiert, aber nicht umgesetzt",
        "IMPLEMENTED_NO_EVIDENCE" => "Umgesetzt, aber nicht nachweisbar",
        "MISSING" => "Fehlt vollständig",
        _ => "Fehlt vollständig",
    }
}
