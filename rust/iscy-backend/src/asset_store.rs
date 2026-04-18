use anyhow::{bail, Context};
use serde::Serialize;
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Row,
};

use crate::cve_store::normalize_database_url;

#[derive(Clone)]
pub enum AssetStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Serialize)]
pub struct InformationAssetSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub business_unit_id: Option<i64>,
    pub business_unit_name: Option<String>,
    pub owner_id: Option<i64>,
    pub owner_display: Option<String>,
    pub name: String,
    pub asset_type: String,
    pub asset_type_label: String,
    pub criticality: String,
    pub criticality_label: String,
    pub description: String,
    pub confidentiality: String,
    pub integrity: String,
    pub availability: String,
    pub lifecycle_status: String,
    pub is_in_scope: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl AssetStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Asset-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Asset-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-Asset-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn list_information_assets(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<InformationAssetSummary>> {
        match self {
            Self::Postgres(pool) => list_information_assets_postgres(pool, tenant_id, limit).await,
            Self::Sqlite(pool) => list_information_assets_sqlite(pool, tenant_id, limit).await,
        }
    }
}

async fn list_information_assets_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<InformationAssetSummary>> {
    let rows = sqlx::query(
        r#"
        SELECT
            asset.id,
            asset.tenant_id,
            asset.business_unit_id,
            bu.name AS business_unit_name,
            asset.owner_id,
            COALESCE(
                NULLIF(BTRIM(CONCAT(COALESCE(owner.first_name, ''), ' ', COALESCE(owner.last_name, ''))), ''),
                owner.username
            ) AS owner_display,
            asset.name,
            asset.asset_type,
            asset.criticality,
            asset.description,
            asset.confidentiality,
            asset.integrity,
            asset.availability,
            asset.lifecycle_status,
            asset.is_in_scope,
            asset.created_at::text AS created_at,
            asset.updated_at::text AS updated_at
        FROM assets_app_informationasset asset
        LEFT JOIN organizations_businessunit bu
            ON bu.id = asset.business_unit_id AND bu.tenant_id = asset.tenant_id
        LEFT JOIN accounts_user owner
            ON owner.id = asset.owner_id AND owner.tenant_id = asset.tenant_id
        WHERE asset.tenant_id = $1
        ORDER BY asset.name ASC, asset.id ASC
        LIMIT $2
        "#,
    )
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("PostgreSQL-Assetliste konnte nicht gelesen werden")?;

    rows.into_iter()
        .map(summary_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_information_assets_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<InformationAssetSummary>> {
    let rows = sqlx::query(
        r#"
        SELECT
            asset.id,
            asset.tenant_id,
            asset.business_unit_id,
            bu.name AS business_unit_name,
            asset.owner_id,
            COALESCE(
                NULLIF(TRIM(COALESCE(owner.first_name, '') || ' ' || COALESCE(owner.last_name, '')), ''),
                owner.username
            ) AS owner_display,
            asset.name,
            asset.asset_type,
            asset.criticality,
            asset.description,
            asset.confidentiality,
            asset.integrity,
            asset.availability,
            asset.lifecycle_status,
            asset.is_in_scope,
            CAST(asset.created_at AS TEXT) AS created_at,
            CAST(asset.updated_at AS TEXT) AS updated_at
        FROM assets_app_informationasset asset
        LEFT JOIN organizations_businessunit bu
            ON bu.id = asset.business_unit_id AND bu.tenant_id = asset.tenant_id
        LEFT JOIN accounts_user owner
            ON owner.id = asset.owner_id AND owner.tenant_id = asset.tenant_id
        WHERE asset.tenant_id = ?
        ORDER BY asset.name ASC, asset.id ASC
        LIMIT ?
        "#,
    )
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("SQLite-Assetliste konnte nicht gelesen werden")?;

    rows.into_iter()
        .map(summary_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn summary_from_pg_row(row: PgRow) -> Result<InformationAssetSummary, sqlx::Error> {
    let asset_type: String = row.try_get("asset_type")?;
    let criticality: String = row.try_get("criticality")?;
    Ok(InformationAssetSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        business_unit_id: row.try_get("business_unit_id")?,
        business_unit_name: row.try_get("business_unit_name")?,
        owner_id: row.try_get("owner_id")?,
        owner_display: row.try_get("owner_display")?,
        name: row.try_get("name")?,
        asset_type_label: asset_type_label(&asset_type).to_string(),
        asset_type,
        criticality_label: criticality_label(&criticality).to_string(),
        criticality,
        description: row.try_get("description")?,
        confidentiality: row.try_get("confidentiality")?,
        integrity: row.try_get("integrity")?,
        availability: row.try_get("availability")?,
        lifecycle_status: row.try_get("lifecycle_status")?,
        is_in_scope: row.try_get("is_in_scope")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn summary_from_sqlite_row(row: SqliteRow) -> Result<InformationAssetSummary, sqlx::Error> {
    let asset_type: String = row.try_get("asset_type")?;
    let criticality: String = row.try_get("criticality")?;
    Ok(InformationAssetSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        business_unit_id: row.try_get("business_unit_id")?,
        business_unit_name: row.try_get("business_unit_name")?,
        owner_id: row.try_get("owner_id")?,
        owner_display: row.try_get("owner_display")?,
        name: row.try_get("name")?,
        asset_type_label: asset_type_label(&asset_type).to_string(),
        asset_type,
        criticality_label: criticality_label(&criticality).to_string(),
        criticality,
        description: row.try_get("description")?,
        confidentiality: row.try_get("confidentiality")?,
        integrity: row.try_get("integrity")?,
        availability: row.try_get("availability")?,
        lifecycle_status: row.try_get("lifecycle_status")?,
        is_in_scope: row.try_get("is_in_scope")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn asset_type_label(value: &str) -> &'static str {
    match value {
        "APPLICATION" => "Anwendung",
        "DATA" => "Datenbestand",
        "INFRASTRUCTURE" => "Infrastruktur",
        "SERVICE" => "Service / Plattform",
        "DOCUMENT" => "Dokumentation",
        "OTHER" => "Sonstiges",
        _ => "Sonstiges",
    }
}

fn criticality_label(value: &str) -> &'static str {
    match value {
        "VERY_HIGH" => "Sehr hoch",
        "HIGH" => "Hoch",
        "MEDIUM" => "Mittel",
        "LOW" => "Niedrig",
        _ => "Mittel",
    }
}
