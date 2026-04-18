use std::collections::HashMap;

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{
    postgres::{PgPool, PgPoolOptions},
    sqlite::{SqlitePool, SqlitePoolOptions},
    Row,
};

use crate::cve_store::normalize_database_url;

#[derive(Clone)]
pub enum ImportStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImportJobRequest {
    pub import_type: String,
    pub replace_existing: bool,
    pub rows: Vec<HashMap<String, Value>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportJobResult {
    pub tenant_id: i64,
    pub import_type: String,
    pub row_count: i64,
    pub created: i64,
    pub updated: i64,
    pub skipped: i64,
}

#[derive(Debug, Default)]
struct ImportCounter {
    created: i64,
    updated: i64,
    skipped: i64,
}

impl ImportStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Import-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Import-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-Import-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn apply_job(
        &self,
        tenant_id: i64,
        job: ImportJobRequest,
    ) -> anyhow::Result<ImportJobResult> {
        let import_type = normalize_import_type(&job.import_type)?;
        let row_count = job.rows.len() as i64;
        let counter = match self {
            Self::Postgres(pool) => apply_postgres(pool, tenant_id, import_type, &job).await?,
            Self::Sqlite(pool) => apply_sqlite(pool, tenant_id, import_type, &job).await?,
        };

        Ok(ImportJobResult {
            tenant_id,
            import_type: import_type.to_string(),
            row_count,
            created: counter.created,
            updated: counter.updated,
            skipped: counter.skipped,
        })
    }
}

async fn apply_postgres(
    pool: &PgPool,
    tenant_id: i64,
    import_type: &str,
    job: &ImportJobRequest,
) -> anyhow::Result<ImportCounter> {
    if job.replace_existing {
        delete_existing_postgres(pool, tenant_id, import_type).await?;
    }

    match import_type {
        "business_units" => import_business_units_postgres(pool, tenant_id, &job.rows).await,
        "processes" => import_processes_postgres(pool, tenant_id, &job.rows).await,
        "suppliers" => import_suppliers_postgres(pool, tenant_id, &job.rows).await,
        "assets" => import_assets_postgres(pool, tenant_id, &job.rows).await,
        _ => unreachable!("import_type is normalized before dispatch"),
    }
}

async fn apply_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    import_type: &str,
    job: &ImportJobRequest,
) -> anyhow::Result<ImportCounter> {
    if job.replace_existing {
        delete_existing_sqlite(pool, tenant_id, import_type).await?;
    }

    match import_type {
        "business_units" => import_business_units_sqlite(pool, tenant_id, &job.rows).await,
        "processes" => import_processes_sqlite(pool, tenant_id, &job.rows).await,
        "suppliers" => import_suppliers_sqlite(pool, tenant_id, &job.rows).await,
        "assets" => import_assets_sqlite(pool, tenant_id, &job.rows).await,
        _ => unreachable!("import_type is normalized before dispatch"),
    }
}

async fn delete_existing_postgres(
    pool: &PgPool,
    tenant_id: i64,
    import_type: &str,
) -> anyhow::Result<()> {
    let sql = match import_type {
        "business_units" => "DELETE FROM organizations_businessunit WHERE tenant_id = $1",
        "processes" => "DELETE FROM processes_process WHERE tenant_id = $1",
        "suppliers" => "DELETE FROM organizations_supplier WHERE tenant_id = $1",
        "assets" => "DELETE FROM assets_app_informationasset WHERE tenant_id = $1",
        _ => unreachable!("import_type is normalized before dispatch"),
    };
    sqlx::query(sql).bind(tenant_id).execute(pool).await?;
    Ok(())
}

async fn delete_existing_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    import_type: &str,
) -> anyhow::Result<()> {
    let sql = match import_type {
        "business_units" => "DELETE FROM organizations_businessunit WHERE tenant_id = ?",
        "processes" => "DELETE FROM processes_process WHERE tenant_id = ?",
        "suppliers" => "DELETE FROM organizations_supplier WHERE tenant_id = ?",
        "assets" => "DELETE FROM assets_app_informationasset WHERE tenant_id = ?",
        _ => unreachable!("import_type is normalized before dispatch"),
    };
    sqlx::query(sql).bind(tenant_id).execute(pool).await?;
    Ok(())
}

async fn import_business_units_postgres(
    pool: &PgPool,
    tenant_id: i64,
    rows: &[HashMap<String, Value>],
) -> anyhow::Result<ImportCounter> {
    let mut counter = ImportCounter::default();
    for row in rows {
        let name = row_text(row, &["name", "Name"]);
        if name.is_empty() {
            counter.skipped += 1;
            continue;
        }
        if let Some(id) = find_business_unit_postgres(pool, tenant_id, &name).await? {
            sqlx::query("UPDATE organizations_businessunit SET updated_at = NOW() WHERE id = $1")
                .bind(id)
                .execute(pool)
                .await?;
            counter.updated += 1;
        } else {
            insert_business_unit_postgres(pool, tenant_id, &name).await?;
            counter.created += 1;
        }
    }
    Ok(counter)
}

async fn import_business_units_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    rows: &[HashMap<String, Value>],
) -> anyhow::Result<ImportCounter> {
    let mut counter = ImportCounter::default();
    for row in rows {
        let name = row_text(row, &["name", "Name"]);
        if name.is_empty() {
            counter.skipped += 1;
            continue;
        }
        if let Some(id) = find_business_unit_sqlite(pool, tenant_id, &name).await? {
            sqlx::query(
                "UPDATE organizations_businessunit SET updated_at = datetime('now') WHERE id = ?",
            )
            .bind(id)
            .execute(pool)
            .await?;
            counter.updated += 1;
        } else {
            insert_business_unit_sqlite(pool, tenant_id, &name).await?;
            counter.created += 1;
        }
    }
    Ok(counter)
}

async fn import_processes_postgres(
    pool: &PgPool,
    tenant_id: i64,
    rows: &[HashMap<String, Value>],
) -> anyhow::Result<ImportCounter> {
    let mut counter = ImportCounter::default();
    for row in rows {
        let name = row_text(row, &["name", "Name"]);
        if name.is_empty() {
            counter.skipped += 1;
            continue;
        }
        let business_unit_id = business_unit_for_row_postgres(pool, tenant_id, row).await?;
        let status = process_status(&row_text(row, &["status", "Status"]));
        let documented = row_bool(row, &["documented"]);
        let approved = row_bool(row, &["approved"]);
        let communicated = row_bool(row, &["communicated"]);
        let implemented = row_bool(row, &["implemented"]);
        let effective = row_bool(row, &["effective"]);
        let evidenced = row_bool(row, &["evidenced"]);
        let scope = row_text(row, &["scope", "Scope"]);
        let description = row_text(row, &["description", "service_description"]);

        if let Some(id) = find_named_postgres(pool, "processes_process", tenant_id, &name).await? {
            sqlx::query(
                r#"
                UPDATE processes_process
                SET business_unit_id = $2,
                    scope = $3,
                    description = $4,
                    status = $5,
                    documented = $6,
                    approved = $7,
                    communicated = $8,
                    implemented = $9,
                    effective = $10,
                    evidenced = $11,
                    updated_at = NOW()
                WHERE id = $1
                "#,
            )
            .bind(id)
            .bind(business_unit_id)
            .bind(&scope)
            .bind(&description)
            .bind(status)
            .bind(documented)
            .bind(approved)
            .bind(communicated)
            .bind(implemented)
            .bind(effective)
            .bind(evidenced)
            .execute(pool)
            .await?;
            counter.updated += 1;
        } else {
            sqlx::query(
                r#"
                INSERT INTO processes_process (
                    tenant_id,
                    business_unit_id,
                    owner_id,
                    name,
                    scope,
                    description,
                    status,
                    documented,
                    approved,
                    communicated,
                    implemented,
                    effective,
                    evidenced,
                    reviewed_at,
                    created_at,
                    updated_at
                )
                VALUES ($1, $2, NULL, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NULL, NOW(), NOW())
                "#,
            )
            .bind(tenant_id)
            .bind(business_unit_id)
            .bind(&name)
            .bind(&scope)
            .bind(&description)
            .bind(status)
            .bind(documented)
            .bind(approved)
            .bind(communicated)
            .bind(implemented)
            .bind(effective)
            .bind(evidenced)
            .execute(pool)
            .await?;
            counter.created += 1;
        }
    }
    Ok(counter)
}

async fn import_processes_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    rows: &[HashMap<String, Value>],
) -> anyhow::Result<ImportCounter> {
    let mut counter = ImportCounter::default();
    for row in rows {
        let name = row_text(row, &["name", "Name"]);
        if name.is_empty() {
            counter.skipped += 1;
            continue;
        }
        let business_unit_id = business_unit_for_row_sqlite(pool, tenant_id, row).await?;
        let status = process_status(&row_text(row, &["status", "Status"]));
        let documented = row_bool(row, &["documented"]);
        let approved = row_bool(row, &["approved"]);
        let communicated = row_bool(row, &["communicated"]);
        let implemented = row_bool(row, &["implemented"]);
        let effective = row_bool(row, &["effective"]);
        let evidenced = row_bool(row, &["evidenced"]);
        let scope = row_text(row, &["scope", "Scope"]);
        let description = row_text(row, &["description", "service_description"]);

        if let Some(id) = find_named_sqlite(pool, "processes_process", tenant_id, &name).await? {
            sqlx::query(
                r#"
                UPDATE processes_process
                SET business_unit_id = ?2,
                    scope = ?3,
                    description = ?4,
                    status = ?5,
                    documented = ?6,
                    approved = ?7,
                    communicated = ?8,
                    implemented = ?9,
                    effective = ?10,
                    evidenced = ?11,
                    updated_at = datetime('now')
                WHERE id = ?1
                "#,
            )
            .bind(id)
            .bind(business_unit_id)
            .bind(&scope)
            .bind(&description)
            .bind(status)
            .bind(documented)
            .bind(approved)
            .bind(communicated)
            .bind(implemented)
            .bind(effective)
            .bind(evidenced)
            .execute(pool)
            .await?;
            counter.updated += 1;
        } else {
            sqlx::query(
                r#"
                INSERT INTO processes_process (
                    tenant_id,
                    business_unit_id,
                    owner_id,
                    name,
                    scope,
                    description,
                    status,
                    documented,
                    approved,
                    communicated,
                    implemented,
                    effective,
                    evidenced,
                    reviewed_at,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, datetime('now'), datetime('now'))
                "#,
            )
            .bind(tenant_id)
            .bind(business_unit_id)
            .bind(&name)
            .bind(&scope)
            .bind(&description)
            .bind(status)
            .bind(documented)
            .bind(approved)
            .bind(communicated)
            .bind(implemented)
            .bind(effective)
            .bind(evidenced)
            .execute(pool)
            .await?;
            counter.created += 1;
        }
    }
    Ok(counter)
}

async fn import_suppliers_postgres(
    pool: &PgPool,
    tenant_id: i64,
    rows: &[HashMap<String, Value>],
) -> anyhow::Result<ImportCounter> {
    let mut counter = ImportCounter::default();
    for row in rows {
        let name = row_text(row, &["name", "Name"]);
        if name.is_empty() {
            counter.skipped += 1;
            continue;
        }
        let service_description = row_text(row, &["service_description", "description"]);
        let criticality = supplier_criticality(&row_text(row, &["criticality"]));
        if let Some(id) =
            find_named_postgres(pool, "organizations_supplier", tenant_id, &name).await?
        {
            sqlx::query(
                r#"
                UPDATE organizations_supplier
                SET service_description = $2,
                    criticality = $3,
                    updated_at = NOW()
                WHERE id = $1
                "#,
            )
            .bind(id)
            .bind(&service_description)
            .bind(criticality)
            .execute(pool)
            .await?;
            counter.updated += 1;
        } else {
            sqlx::query(
                r#"
                INSERT INTO organizations_supplier (
                    tenant_id,
                    name,
                    service_description,
                    criticality,
                    owner_id,
                    created_at,
                    updated_at
                )
                VALUES ($1, $2, $3, $4, NULL, NOW(), NOW())
                "#,
            )
            .bind(tenant_id)
            .bind(&name)
            .bind(&service_description)
            .bind(criticality)
            .execute(pool)
            .await?;
            counter.created += 1;
        }
    }
    Ok(counter)
}

async fn import_suppliers_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    rows: &[HashMap<String, Value>],
) -> anyhow::Result<ImportCounter> {
    let mut counter = ImportCounter::default();
    for row in rows {
        let name = row_text(row, &["name", "Name"]);
        if name.is_empty() {
            counter.skipped += 1;
            continue;
        }
        let service_description = row_text(row, &["service_description", "description"]);
        let criticality = supplier_criticality(&row_text(row, &["criticality"]));
        if let Some(id) =
            find_named_sqlite(pool, "organizations_supplier", tenant_id, &name).await?
        {
            sqlx::query(
                r#"
                UPDATE organizations_supplier
                SET service_description = ?2,
                    criticality = ?3,
                    updated_at = datetime('now')
                WHERE id = ?1
                "#,
            )
            .bind(id)
            .bind(&service_description)
            .bind(criticality)
            .execute(pool)
            .await?;
            counter.updated += 1;
        } else {
            sqlx::query(
                r#"
                INSERT INTO organizations_supplier (
                    tenant_id,
                    name,
                    service_description,
                    criticality,
                    owner_id,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, NULL, datetime('now'), datetime('now'))
                "#,
            )
            .bind(tenant_id)
            .bind(&name)
            .bind(&service_description)
            .bind(criticality)
            .execute(pool)
            .await?;
            counter.created += 1;
        }
    }
    Ok(counter)
}

async fn import_assets_postgres(
    pool: &PgPool,
    tenant_id: i64,
    rows: &[HashMap<String, Value>],
) -> anyhow::Result<ImportCounter> {
    let mut counter = ImportCounter::default();
    for row in rows {
        let name = row_text(row, &["name", "Name"]);
        if name.is_empty() {
            counter.skipped += 1;
            continue;
        }
        let business_unit_id = business_unit_for_row_postgres(pool, tenant_id, row).await?;
        let asset_type = asset_type(&row_text(row, &["asset_type"]));
        let criticality = asset_criticality(&row_text(row, &["criticality"]));
        let description = row_text(row, &["description", "service_description"]);
        let confidentiality = row_text(row, &["confidentiality"]);
        let integrity = row_text(row, &["integrity"]);
        let availability = row_text(row, &["availability"]);
        let lifecycle_status = row_text(row, &["lifecycle_status"]);
        let is_in_scope = !matches!(
            row_text(row, &["in_scope"]).to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "nein"
        );

        if let Some(id) =
            find_named_postgres(pool, "assets_app_informationasset", tenant_id, &name).await?
        {
            sqlx::query(
                r#"
                UPDATE assets_app_informationasset
                SET business_unit_id = $2,
                    asset_type = $3,
                    criticality = $4,
                    description = $5,
                    confidentiality = $6,
                    integrity = $7,
                    availability = $8,
                    lifecycle_status = $9,
                    is_in_scope = $10,
                    updated_at = NOW()
                WHERE id = $1
                "#,
            )
            .bind(id)
            .bind(business_unit_id)
            .bind(asset_type)
            .bind(criticality)
            .bind(&description)
            .bind(&confidentiality)
            .bind(&integrity)
            .bind(&availability)
            .bind(&lifecycle_status)
            .bind(is_in_scope)
            .execute(pool)
            .await?;
            counter.updated += 1;
        } else {
            sqlx::query(
                r#"
                INSERT INTO assets_app_informationasset (
                    tenant_id,
                    business_unit_id,
                    owner_id,
                    name,
                    asset_type,
                    criticality,
                    description,
                    confidentiality,
                    integrity,
                    availability,
                    lifecycle_status,
                    is_in_scope,
                    created_at,
                    updated_at
                )
                VALUES ($1, $2, NULL, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW())
                "#,
            )
            .bind(tenant_id)
            .bind(business_unit_id)
            .bind(&name)
            .bind(asset_type)
            .bind(criticality)
            .bind(&description)
            .bind(&confidentiality)
            .bind(&integrity)
            .bind(&availability)
            .bind(&lifecycle_status)
            .bind(is_in_scope)
            .execute(pool)
            .await?;
            counter.created += 1;
        }
    }
    Ok(counter)
}

async fn import_assets_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    rows: &[HashMap<String, Value>],
) -> anyhow::Result<ImportCounter> {
    let mut counter = ImportCounter::default();
    for row in rows {
        let name = row_text(row, &["name", "Name"]);
        if name.is_empty() {
            counter.skipped += 1;
            continue;
        }
        let business_unit_id = business_unit_for_row_sqlite(pool, tenant_id, row).await?;
        let asset_type = asset_type(&row_text(row, &["asset_type"]));
        let criticality = asset_criticality(&row_text(row, &["criticality"]));
        let description = row_text(row, &["description", "service_description"]);
        let confidentiality = row_text(row, &["confidentiality"]);
        let integrity = row_text(row, &["integrity"]);
        let availability = row_text(row, &["availability"]);
        let lifecycle_status = row_text(row, &["lifecycle_status"]);
        let is_in_scope = !matches!(
            row_text(row, &["in_scope"]).to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "nein"
        );

        if let Some(id) =
            find_named_sqlite(pool, "assets_app_informationasset", tenant_id, &name).await?
        {
            sqlx::query(
                r#"
                UPDATE assets_app_informationasset
                SET business_unit_id = ?2,
                    asset_type = ?3,
                    criticality = ?4,
                    description = ?5,
                    confidentiality = ?6,
                    integrity = ?7,
                    availability = ?8,
                    lifecycle_status = ?9,
                    is_in_scope = ?10,
                    updated_at = datetime('now')
                WHERE id = ?1
                "#,
            )
            .bind(id)
            .bind(business_unit_id)
            .bind(asset_type)
            .bind(criticality)
            .bind(&description)
            .bind(&confidentiality)
            .bind(&integrity)
            .bind(&availability)
            .bind(&lifecycle_status)
            .bind(is_in_scope)
            .execute(pool)
            .await?;
            counter.updated += 1;
        } else {
            sqlx::query(
                r#"
                INSERT INTO assets_app_informationasset (
                    tenant_id,
                    business_unit_id,
                    owner_id,
                    name,
                    asset_type,
                    criticality,
                    description,
                    confidentiality,
                    integrity,
                    availability,
                    lifecycle_status,
                    is_in_scope,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
                "#,
            )
            .bind(tenant_id)
            .bind(business_unit_id)
            .bind(&name)
            .bind(asset_type)
            .bind(criticality)
            .bind(&description)
            .bind(&confidentiality)
            .bind(&integrity)
            .bind(&availability)
            .bind(&lifecycle_status)
            .bind(is_in_scope)
            .execute(pool)
            .await?;
            counter.created += 1;
        }
    }
    Ok(counter)
}

async fn business_unit_for_row_postgres(
    pool: &PgPool,
    tenant_id: i64,
    row: &HashMap<String, Value>,
) -> anyhow::Result<Option<i64>> {
    let name = row_text(row, &["business_unit", "BusinessUnit"]);
    if name.is_empty() {
        return Ok(None);
    }
    if let Some(id) = find_business_unit_postgres(pool, tenant_id, &name).await? {
        return Ok(Some(id));
    }
    insert_business_unit_postgres(pool, tenant_id, &name)
        .await
        .map(Some)
}

async fn business_unit_for_row_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    row: &HashMap<String, Value>,
) -> anyhow::Result<Option<i64>> {
    let name = row_text(row, &["business_unit", "BusinessUnit"]);
    if name.is_empty() {
        return Ok(None);
    }
    if let Some(id) = find_business_unit_sqlite(pool, tenant_id, &name).await? {
        return Ok(Some(id));
    }
    insert_business_unit_sqlite(pool, tenant_id, &name)
        .await
        .map(Some)
}

async fn find_business_unit_postgres(
    pool: &PgPool,
    tenant_id: i64,
    name: &str,
) -> anyhow::Result<Option<i64>> {
    find_named_postgres(pool, "organizations_businessunit", tenant_id, name).await
}

async fn find_business_unit_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    name: &str,
) -> anyhow::Result<Option<i64>> {
    find_named_sqlite(pool, "organizations_businessunit", tenant_id, name).await
}

async fn insert_business_unit_postgres(
    pool: &PgPool,
    tenant_id: i64,
    name: &str,
) -> anyhow::Result<i64> {
    let row = sqlx::query(
        r#"
        INSERT INTO organizations_businessunit (tenant_id, name, owner_id, created_at, updated_at)
        VALUES ($1, $2, NULL, NOW(), NOW())
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(name)
    .fetch_one(pool)
    .await?;
    Ok(row.try_get("id")?)
}

async fn insert_business_unit_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    name: &str,
) -> anyhow::Result<i64> {
    let result = sqlx::query(
        r#"
        INSERT INTO organizations_businessunit (tenant_id, name, owner_id, created_at, updated_at)
        VALUES (?, ?, NULL, datetime('now'), datetime('now'))
        "#,
    )
    .bind(tenant_id)
    .bind(name)
    .execute(pool)
    .await?;
    Ok(result.last_insert_rowid())
}

async fn find_named_postgres(
    pool: &PgPool,
    table: &str,
    tenant_id: i64,
    name: &str,
) -> anyhow::Result<Option<i64>> {
    let sql = format!(
        "SELECT id FROM {table} WHERE tenant_id = $1 AND name = $2 ORDER BY id ASC LIMIT 1"
    );
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await?;
    row.map(|row| row.try_get("id"))
        .transpose()
        .map_err(Into::into)
}

async fn find_named_sqlite(
    pool: &SqlitePool,
    table: &str,
    tenant_id: i64,
    name: &str,
) -> anyhow::Result<Option<i64>> {
    let sql =
        format!("SELECT id FROM {table} WHERE tenant_id = ? AND name = ? ORDER BY id ASC LIMIT 1");
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await?;
    row.map(|row| row.try_get("id"))
        .transpose()
        .map_err(Into::into)
}

fn normalize_import_type(value: &str) -> anyhow::Result<&'static str> {
    match value.trim() {
        "business_units" => Ok("business_units"),
        "processes" => Ok("processes"),
        "suppliers" => Ok("suppliers"),
        "assets" => Ok("assets"),
        other => bail!("Nicht unterstuetzter Importtyp: {other}"),
    }
}

fn row_text(row: &HashMap<String, Value>, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| row.get(*key).map(value_to_text))
        .unwrap_or_default()
}

fn value_to_text(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(value) => value.trim().to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        other => other.to_string(),
    }
}

fn row_bool(row: &HashMap<String, Value>, keys: &[&str]) -> bool {
    matches!(
        row_text(row, keys).to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "ja" | "y"
    )
}

fn process_status(value: &str) -> &'static str {
    match value.trim().to_ascii_uppercase().as_str() {
        "SUFFICIENT" => "SUFFICIENT",
        "PARTIAL" => "PARTIAL",
        "INFORMAL" => "INFORMAL",
        "DOCUMENTED_NOT_IMPLEMENTED" => "DOCUMENTED_NOT_IMPLEMENTED",
        "IMPLEMENTED_NO_EVIDENCE" => "IMPLEMENTED_NO_EVIDENCE",
        "MISSING" => "MISSING",
        _ => "MISSING",
    }
}

fn supplier_criticality(value: &str) -> String {
    let normalized = value.trim().to_ascii_uppercase();
    if normalized.is_empty() {
        "MEDIUM".to_string()
    } else {
        normalized
    }
}

fn asset_type(value: &str) -> &'static str {
    match value.trim().to_ascii_uppercase().as_str() {
        "APPLICATION" => "APPLICATION",
        "DATA" => "DATA",
        "INFRASTRUCTURE" => "INFRASTRUCTURE",
        "SERVICE" => "SERVICE",
        "DOCUMENT" => "DOCUMENT",
        "OTHER" => "OTHER",
        _ => "APPLICATION",
    }
}

fn asset_criticality(value: &str) -> &'static str {
    match value.trim().to_ascii_uppercase().as_str() {
        "VERY_HIGH" => "VERY_HIGH",
        "HIGH" => "HIGH",
        "MEDIUM" => "MEDIUM",
        "LOW" => "LOW",
        _ => "MEDIUM",
    }
}
