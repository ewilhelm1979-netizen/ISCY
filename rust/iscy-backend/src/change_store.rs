use anyhow::{bail, Context};
use chrono::{DateTime, NaiveDate};
use serde::{Deserialize, Serialize};
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Row,
};

use crate::cve_store::normalize_database_url;

#[derive(Clone)]
pub enum ChangeStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Serialize)]
pub struct ChangeSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub owner_id: Option<i64>,
    pub owner_display: Option<String>,
    pub title: String,
    pub description: String,
    pub change_type: String,
    pub change_type_label: String,
    pub status: String,
    pub status_label: String,
    pub planned_at: Option<String>,
    pub implemented_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChangeWriteRequest {
    pub owner_id: Option<i64>,
    pub title: String,
    #[serde(default)]
    pub description: String,
    pub change_type: Option<String>,
    pub status: Option<String>,
    pub planned_at: Option<String>,
    pub implemented_at: Option<String>,
}

impl ChangeStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Change-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Change-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-Change-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn list_changes(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<ChangeSummary>> {
        match self {
            Self::Postgres(pool) => list_changes_postgres(pool, tenant_id, limit).await,
            Self::Sqlite(pool) => list_changes_sqlite(pool, tenant_id, limit).await,
        }
    }

    pub async fn detail(
        &self,
        tenant_id: i64,
        change_id: i64,
    ) -> anyhow::Result<Option<ChangeSummary>> {
        match self {
            Self::Postgres(pool) => detail_postgres(pool, tenant_id, change_id).await,
            Self::Sqlite(pool) => detail_sqlite(pool, tenant_id, change_id).await,
        }
    }

    pub async fn create_change(
        &self,
        tenant_id: i64,
        payload: ChangeWriteRequest,
    ) -> anyhow::Result<ChangeSummary> {
        let title = clean_required(&payload.title, "Change-Titel")?;
        let change_type =
            normalize_change_type(payload.change_type.as_deref().unwrap_or("STANDARD"))?;
        let status = normalize_status(payload.status.as_deref().unwrap_or("PLANNED"))?;
        let owner_id = payload.owner_id.filter(|id| *id > 0);
        let description = clean_text(&payload.description);
        let planned_at = normalize_change_datetime(payload.planned_at, "Geplanter Zeitpunkt")?;
        let implemented_at =
            normalize_change_datetime(payload.implemented_at, "Umsetzungszeitpunkt")?;
        let change_id = match self {
            Self::Postgres(pool) => {
                ensure_owner_postgres(pool, tenant_id, owner_id).await?;
                sqlx::query_scalar(
                    r#"
                    INSERT INTO changes_change (
                        tenant_id, owner_id, title, description, change_type, status,
                        planned_at, implemented_at, created_at, updated_at
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    RETURNING id
                    "#,
                )
                .bind(tenant_id)
                .bind(owner_id)
                .bind(&title)
                .bind(&description)
                .bind(&change_type)
                .bind(&status)
                .bind(&planned_at)
                .bind(&implemented_at)
                .fetch_one(pool)
                .await
                .context("PostgreSQL-Change konnte nicht angelegt werden")?
            }
            Self::Sqlite(pool) => {
                ensure_owner_sqlite(pool, tenant_id, owner_id).await?;
                let result = sqlx::query(
                    r#"
                    INSERT INTO changes_change (
                        tenant_id, owner_id, title, description, change_type, status,
                        planned_at, implemented_at, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    "#,
                )
                .bind(tenant_id)
                .bind(owner_id)
                .bind(&title)
                .bind(&description)
                .bind(&change_type)
                .bind(&status)
                .bind(&planned_at)
                .bind(&implemented_at)
                .execute(pool)
                .await
                .context("SQLite-Change konnte nicht angelegt werden")?;
                result.last_insert_rowid()
            }
        };
        self.detail(tenant_id, change_id)
            .await?
            .context("Angelegter Change konnte nicht tenantgebunden gelesen werden")
    }
}

async fn list_changes_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<ChangeSummary>> {
    let rows = sqlx::query(&format!(
        "{POSTGRES_CHANGE_SELECT} WHERE change.tenant_id = $1 ORDER BY change.updated_at DESC, change.id DESC LIMIT $2"
    ))
    .bind(tenant_id)
    .bind(limit.clamp(1, 500))
    .fetch_all(pool)
    .await
    .context("PostgreSQL-Change-Register konnte nicht gelesen werden")?;
    rows.into_iter()
        .map(change_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_changes_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<ChangeSummary>> {
    let rows = sqlx::query(&format!(
        "{SQLITE_CHANGE_SELECT} WHERE change.tenant_id = ? ORDER BY change.updated_at DESC, change.id DESC LIMIT ?"
    ))
    .bind(tenant_id)
    .bind(limit.clamp(1, 500))
    .fetch_all(pool)
    .await
    .context("SQLite-Change-Register konnte nicht gelesen werden")?;
    rows.into_iter()
        .map(change_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn detail_postgres(
    pool: &PgPool,
    tenant_id: i64,
    change_id: i64,
) -> anyhow::Result<Option<ChangeSummary>> {
    let row = sqlx::query(&format!(
        "{POSTGRES_CHANGE_SELECT} WHERE change.tenant_id = $1 AND change.id = $2"
    ))
    .bind(tenant_id)
    .bind(change_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-Change-Detail konnte nicht gelesen werden")?;
    row.map(change_from_pg_row).transpose().map_err(Into::into)
}

async fn detail_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    change_id: i64,
) -> anyhow::Result<Option<ChangeSummary>> {
    let row = sqlx::query(&format!(
        "{SQLITE_CHANGE_SELECT} WHERE change.tenant_id = ? AND change.id = ?"
    ))
    .bind(tenant_id)
    .bind(change_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-Change-Detail konnte nicht gelesen werden")?;
    row.map(change_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

async fn ensure_owner_postgres(
    pool: &PgPool,
    tenant_id: i64,
    owner_id: Option<i64>,
) -> anyhow::Result<()> {
    let Some(owner_id) = owner_id else {
        return Ok(());
    };
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM accounts_user WHERE tenant_id = $1 AND id = $2)",
    )
    .bind(tenant_id)
    .bind(owner_id)
    .fetch_one(pool)
    .await?;
    if !exists {
        bail!("Change-Owner wurde fuer diesen Tenant nicht gefunden");
    }
    Ok(())
}

async fn ensure_owner_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    owner_id: Option<i64>,
) -> anyhow::Result<()> {
    let Some(owner_id) = owner_id else {
        return Ok(());
    };
    let exists: i64 = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM accounts_user WHERE tenant_id = ? AND id = ?)",
    )
    .bind(tenant_id)
    .bind(owner_id)
    .fetch_one(pool)
    .await?;
    if exists == 0 {
        bail!("Change-Owner wurde fuer diesen Tenant nicht gefunden");
    }
    Ok(())
}

fn change_from_pg_row(row: PgRow) -> Result<ChangeSummary, sqlx::Error> {
    let change_type: String = row.try_get("change_type")?;
    let status: String = row.try_get("status")?;
    Ok(ChangeSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        owner_id: row.try_get("owner_id")?,
        owner_display: row.try_get("owner_display")?,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        change_type_label: change_type_label(&change_type).to_string(),
        change_type,
        status_label: status_label(&status).to_string(),
        status,
        planned_at: row.try_get("planned_at")?,
        implemented_at: row.try_get("implemented_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn change_from_sqlite_row(row: SqliteRow) -> Result<ChangeSummary, sqlx::Error> {
    let change_type: String = row.try_get("change_type")?;
    let status: String = row.try_get("status")?;
    Ok(ChangeSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        owner_id: row.try_get("owner_id")?,
        owner_display: row.try_get("owner_display")?,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        change_type_label: change_type_label(&change_type).to_string(),
        change_type,
        status_label: status_label(&status).to_string(),
        status,
        planned_at: row.try_get("planned_at")?,
        implemented_at: row.try_get("implemented_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

const POSTGRES_CHANGE_SELECT: &str = r#"
SELECT
    change.id,
    change.tenant_id,
    change.owner_id,
    COALESCE(
        NULLIF(BTRIM(CONCAT(COALESCE(owner.first_name, ''), ' ', COALESCE(owner.last_name, ''))), ''),
        owner.username
    ) AS owner_display,
    change.title,
    change.description,
    change.change_type,
    change.status,
    change.planned_at,
    change.implemented_at,
    change.created_at,
    change.updated_at
FROM changes_change change
LEFT JOIN accounts_user owner
    ON owner.id = change.owner_id AND owner.tenant_id = change.tenant_id
"#;

const SQLITE_CHANGE_SELECT: &str = r#"
SELECT
    change.id,
    change.tenant_id,
    change.owner_id,
    COALESCE(
        NULLIF(TRIM(COALESCE(owner.first_name, '') || ' ' || COALESCE(owner.last_name, '')), ''),
        owner.username
    ) AS owner_display,
    change.title,
    change.description,
    change.change_type,
    change.status,
    CAST(change.planned_at AS TEXT) AS planned_at,
    CAST(change.implemented_at AS TEXT) AS implemented_at,
    CAST(change.created_at AS TEXT) AS created_at,
    CAST(change.updated_at AS TEXT) AS updated_at
FROM changes_change change
LEFT JOIN accounts_user owner
    ON owner.id = change.owner_id AND owner.tenant_id = change.tenant_id
"#;

fn clean_required(value: &str, label: &str) -> anyhow::Result<String> {
    let value = clean_text(value);
    if value.is_empty() {
        bail!("{label} darf nicht leer sein");
    }
    if value.chars().count() > 255 {
        bail!("{label} darf hoechstens 255 Zeichen enthalten");
    }
    Ok(value)
}

fn clean_text(value: &str) -> String {
    value.trim().to_string()
}

fn normalize_change_datetime(value: Option<String>, label: &str) -> anyhow::Result<Option<String>> {
    let Some(value) = value
        .map(|value| clean_text(&value))
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    if NaiveDate::parse_from_str(&value, "%Y-%m-%d").is_ok()
        || DateTime::parse_from_rfc3339(&value).is_ok()
    {
        return Ok(Some(value));
    }
    bail!("{label} muss YYYY-MM-DD oder ein RFC-3339-Zeitpunkt sein")
}

fn normalize_change_type(value: &str) -> anyhow::Result<String> {
    let normalized = value.trim().to_ascii_uppercase().replace('-', "_");
    match normalized.as_str() {
        "STANDARD" | "NORMAL" | "EMERGENCY" => Ok(normalized),
        _ => bail!("Change-Typ muss STANDARD, NORMAL oder EMERGENCY sein"),
    }
}

fn normalize_status(value: &str) -> anyhow::Result<String> {
    let normalized = value.trim().to_ascii_uppercase().replace('-', "_");
    match normalized.as_str() {
        "PLANNED" | "IN_REVIEW" | "APPROVED" | "IMPLEMENTED" | "FAILED"
        | "ROLLED_BACK" | "CANCELLED" => Ok(normalized),
        _ => bail!(
            "Change-Status muss PLANNED, IN_REVIEW, APPROVED, IMPLEMENTED, FAILED, ROLLED_BACK oder CANCELLED sein"
        ),
    }
}

fn change_type_label(value: &str) -> &'static str {
    match value {
        "EMERGENCY" => "Emergency",
        "NORMAL" => "Normal",
        _ => "Standard",
    }
}

fn status_label(value: &str) -> &'static str {
    match value {
        "IN_REVIEW" => "In Review",
        "APPROVED" => "Freigegeben",
        "IMPLEMENTED" => "Umgesetzt",
        "FAILED" => "Fehlgeschlagen",
        "ROLLED_BACK" => "Zurueckgerollt",
        "CANCELLED" => "Abgebrochen",
        _ => "Geplant",
    }
}
