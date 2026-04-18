use anyhow::{bail, Context};
use serde::Serialize;
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Row,
};

use crate::cve_store::normalize_database_url;

#[derive(Clone)]
pub enum TenantStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Serialize)]
pub struct TenantProfile {
    pub id: i64,
    pub name: String,
    pub slug: String,
    pub country: String,
    pub operation_countries: Vec<String>,
    pub description: String,
    pub sector: String,
    pub employee_count: i64,
    pub annual_revenue_million: String,
    pub balance_sheet_million: String,
    pub critical_services: String,
    pub supply_chain_role: String,
    pub nis2_relevant: bool,
    pub kritis_relevant: bool,
    pub develops_digital_products: bool,
    pub uses_ai_systems: bool,
    pub ot_iacs_scope: bool,
    pub automotive_scope: bool,
    pub psirt_defined: bool,
    pub sbom_required: bool,
    pub product_security_scope: String,
}

impl TenantStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Tenant-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Tenant-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-Tenant-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn tenant_profile(&self, tenant_id: i64) -> anyhow::Result<Option<TenantProfile>> {
        match self {
            Self::Postgres(pool) => tenant_profile_postgres(pool, tenant_id).await,
            Self::Sqlite(pool) => tenant_profile_sqlite(pool, tenant_id).await,
        }
    }
}

async fn tenant_profile_postgres(
    pool: &PgPool,
    tenant_id: i64,
) -> anyhow::Result<Option<TenantProfile>> {
    let row = sqlx::query(
        r#"
        SELECT
            id,
            name,
            slug,
            country,
            operation_countries::text AS operation_countries_json,
            description,
            sector,
            employee_count::bigint AS employee_count,
            annual_revenue_million::text AS annual_revenue_million_text,
            balance_sheet_million::text AS balance_sheet_million_text,
            critical_services,
            supply_chain_role,
            nis2_relevant,
            kritis_relevant,
            develops_digital_products,
            uses_ai_systems,
            ot_iacs_scope,
            automotive_scope,
            psirt_defined,
            sbom_required,
            product_security_scope
        FROM organizations_tenant
        WHERE id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-Tenant-Profil konnte nicht gelesen werden")?;

    row.map(tenant_profile_from_pg_row)
        .transpose()
        .map_err(Into::into)
}

async fn tenant_profile_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
) -> anyhow::Result<Option<TenantProfile>> {
    let row = sqlx::query(
        r#"
        SELECT
            id,
            name,
            slug,
            country,
            operation_countries AS operation_countries_json,
            description,
            sector,
            employee_count,
            CAST(annual_revenue_million AS TEXT) AS annual_revenue_million_text,
            CAST(balance_sheet_million AS TEXT) AS balance_sheet_million_text,
            critical_services,
            supply_chain_role,
            nis2_relevant,
            kritis_relevant,
            develops_digital_products,
            uses_ai_systems,
            ot_iacs_scope,
            automotive_scope,
            psirt_defined,
            sbom_required,
            product_security_scope
        FROM organizations_tenant
        WHERE id = ?
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-Tenant-Profil konnte nicht gelesen werden")?;

    row.map(tenant_profile_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

fn tenant_profile_from_pg_row(row: PgRow) -> Result<TenantProfile, sqlx::Error> {
    Ok(TenantProfile {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        slug: row.try_get("slug")?,
        country: row.try_get("country")?,
        operation_countries: parse_operation_countries(row.try_get("operation_countries_json")?),
        description: row.try_get("description")?,
        sector: row.try_get("sector")?,
        employee_count: row.try_get("employee_count")?,
        annual_revenue_million: row.try_get("annual_revenue_million_text")?,
        balance_sheet_million: row.try_get("balance_sheet_million_text")?,
        critical_services: row.try_get("critical_services")?,
        supply_chain_role: row.try_get("supply_chain_role")?,
        nis2_relevant: row.try_get("nis2_relevant")?,
        kritis_relevant: row.try_get("kritis_relevant")?,
        develops_digital_products: row.try_get("develops_digital_products")?,
        uses_ai_systems: row.try_get("uses_ai_systems")?,
        ot_iacs_scope: row.try_get("ot_iacs_scope")?,
        automotive_scope: row.try_get("automotive_scope")?,
        psirt_defined: row.try_get("psirt_defined")?,
        sbom_required: row.try_get("sbom_required")?,
        product_security_scope: row.try_get("product_security_scope")?,
    })
}

fn tenant_profile_from_sqlite_row(row: SqliteRow) -> Result<TenantProfile, sqlx::Error> {
    Ok(TenantProfile {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        slug: row.try_get("slug")?,
        country: row.try_get("country")?,
        operation_countries: parse_operation_countries(row.try_get("operation_countries_json")?),
        description: row.try_get("description")?,
        sector: row.try_get("sector")?,
        employee_count: row.try_get("employee_count")?,
        annual_revenue_million: row.try_get("annual_revenue_million_text")?,
        balance_sheet_million: row.try_get("balance_sheet_million_text")?,
        critical_services: row.try_get("critical_services")?,
        supply_chain_role: row.try_get("supply_chain_role")?,
        nis2_relevant: row.try_get("nis2_relevant")?,
        kritis_relevant: row.try_get("kritis_relevant")?,
        develops_digital_products: row.try_get("develops_digital_products")?,
        uses_ai_systems: row.try_get("uses_ai_systems")?,
        ot_iacs_scope: row.try_get("ot_iacs_scope")?,
        automotive_scope: row.try_get("automotive_scope")?,
        psirt_defined: row.try_get("psirt_defined")?,
        sbom_required: row.try_get("sbom_required")?,
        product_security_scope: row.try_get("product_security_scope")?,
    })
}

fn parse_operation_countries(raw: String) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(&raw).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::parse_operation_countries;

    #[test]
    fn parse_operation_countries_reads_json_list() {
        assert_eq!(
            parse_operation_countries(r#"["DE","FR"]"#.to_string()),
            vec!["DE".to_string(), "FR".to_string()]
        );
    }

    #[test]
    fn parse_operation_countries_tolerates_invalid_json() {
        assert!(parse_operation_countries("not-json".to_string()).is_empty());
    }
}
