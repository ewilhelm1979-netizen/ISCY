use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
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
    pub dora_relevant: bool,
    pub dora_financial_entity: bool,
    pub dora_ict_third_party_provider: bool,
    pub processes_personal_data: bool,
    pub gdpr_controller: bool,
    pub gdpr_processor: bool,
    pub gdpr_special_categories: bool,
    pub cra_relevant: bool,
    pub ai_act_profile: String,
    pub ai_act_high_risk: bool,
    pub tisax_relevant: bool,
    pub iso27001_target: String,
    pub regulatory_profile_notes: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TenantRegulatoryProfileUpdateRequest {
    pub country: Option<String>,
    pub operation_countries: Option<Vec<String>>,
    pub description: Option<String>,
    pub sector: Option<String>,
    pub employee_count: Option<i64>,
    pub annual_revenue_million: Option<String>,
    pub balance_sheet_million: Option<String>,
    pub critical_services: Option<String>,
    pub supply_chain_role: Option<String>,
    pub nis2_relevant: Option<bool>,
    pub kritis_relevant: Option<bool>,
    pub develops_digital_products: Option<bool>,
    pub uses_ai_systems: Option<bool>,
    pub ot_iacs_scope: Option<bool>,
    pub automotive_scope: Option<bool>,
    pub psirt_defined: Option<bool>,
    pub sbom_required: Option<bool>,
    pub product_security_scope: Option<String>,
    pub dora_relevant: Option<bool>,
    pub dora_financial_entity: Option<bool>,
    pub dora_ict_third_party_provider: Option<bool>,
    pub processes_personal_data: Option<bool>,
    pub gdpr_controller: Option<bool>,
    pub gdpr_processor: Option<bool>,
    pub gdpr_special_categories: Option<bool>,
    pub cra_relevant: Option<bool>,
    pub ai_act_profile: Option<String>,
    pub ai_act_high_risk: Option<bool>,
    pub tisax_relevant: Option<bool>,
    pub iso27001_target: Option<String>,
    pub regulatory_profile_notes: Option<String>,
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

    pub async fn update_product_security_scope(
        &self,
        tenant_id: i64,
        product_security_scope: &str,
    ) -> anyhow::Result<Option<TenantProfile>> {
        match self {
            Self::Postgres(pool) => {
                update_product_security_scope_postgres(pool, tenant_id, product_security_scope)
                    .await
            }
            Self::Sqlite(pool) => {
                update_product_security_scope_sqlite(pool, tenant_id, product_security_scope).await
            }
        }
    }

    pub async fn update_regulatory_profile(
        &self,
        tenant_id: i64,
        request: TenantRegulatoryProfileUpdateRequest,
    ) -> anyhow::Result<Option<TenantProfile>> {
        match self {
            Self::Postgres(pool) => {
                update_regulatory_profile_postgres(pool, tenant_id, request).await
            }
            Self::Sqlite(pool) => update_regulatory_profile_sqlite(pool, tenant_id, request).await,
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
            product_security_scope,
            dora_relevant,
            dora_financial_entity,
            dora_ict_third_party_provider,
            processes_personal_data,
            gdpr_controller,
            gdpr_processor,
            gdpr_special_categories,
            cra_relevant,
            ai_act_profile,
            ai_act_high_risk,
            tisax_relevant,
            iso27001_target,
            regulatory_profile_notes
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
            product_security_scope,
            dora_relevant,
            dora_financial_entity,
            dora_ict_third_party_provider,
            processes_personal_data,
            gdpr_controller,
            gdpr_processor,
            gdpr_special_categories,
            cra_relevant,
            ai_act_profile,
            ai_act_high_risk,
            tisax_relevant,
            iso27001_target,
            regulatory_profile_notes
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

async fn update_product_security_scope_postgres(
    pool: &PgPool,
    tenant_id: i64,
    product_security_scope: &str,
) -> anyhow::Result<Option<TenantProfile>> {
    let result = sqlx::query(
        r#"
        UPDATE organizations_tenant
        SET product_security_scope = $2, updated_at = NOW()::text
        WHERE id = $1
        "#,
    )
    .bind(tenant_id)
    .bind(product_security_scope.trim())
    .execute(pool)
    .await
    .context("PostgreSQL-Product-Security-Scope konnte nicht aktualisiert werden")?;
    if result.rows_affected() == 0 {
        return Ok(None);
    }
    tenant_profile_postgres(pool, tenant_id).await
}

async fn update_product_security_scope_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    product_security_scope: &str,
) -> anyhow::Result<Option<TenantProfile>> {
    let result = sqlx::query(
        r#"
        UPDATE organizations_tenant
        SET product_security_scope = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        "#,
    )
    .bind(product_security_scope.trim())
    .bind(tenant_id)
    .execute(pool)
    .await
    .context("SQLite-Product-Security-Scope konnte nicht aktualisiert werden")?;
    if result.rows_affected() == 0 {
        return Ok(None);
    }
    tenant_profile_sqlite(pool, tenant_id).await
}

async fn update_regulatory_profile_postgres(
    pool: &PgPool,
    tenant_id: i64,
    request: TenantRegulatoryProfileUpdateRequest,
) -> anyhow::Result<Option<TenantProfile>> {
    let Some(profile) = tenant_profile_postgres(pool, tenant_id).await? else {
        return Ok(None);
    };
    let fields = TenantRegulatoryProfileFields::from_request(profile, request)?;
    let operation_countries = serde_json::to_string(&fields.operation_countries)?;
    let result = sqlx::query(
        r#"
        UPDATE organizations_tenant
        SET
            country = $2,
            operation_countries = $3,
            description = $4,
            sector = $5,
            employee_count = $6,
            annual_revenue_million = $7,
            balance_sheet_million = $8,
            critical_services = $9,
            supply_chain_role = $10,
            nis2_relevant = $11,
            kritis_relevant = $12,
            develops_digital_products = $13,
            uses_ai_systems = $14,
            ot_iacs_scope = $15,
            automotive_scope = $16,
            psirt_defined = $17,
            sbom_required = $18,
            product_security_scope = $19,
            dora_relevant = $20,
            dora_financial_entity = $21,
            dora_ict_third_party_provider = $22,
            processes_personal_data = $23,
            gdpr_controller = $24,
            gdpr_processor = $25,
            gdpr_special_categories = $26,
            cra_relevant = $27,
            ai_act_profile = $28,
            ai_act_high_risk = $29,
            tisax_relevant = $30,
            iso27001_target = $31,
            regulatory_profile_notes = $32,
            updated_at = NOW()::text
        WHERE id = $1
        "#,
    )
    .bind(tenant_id)
    .bind(&fields.country)
    .bind(operation_countries)
    .bind(&fields.description)
    .bind(&fields.sector)
    .bind(fields.employee_count)
    .bind(&fields.annual_revenue_million)
    .bind(&fields.balance_sheet_million)
    .bind(&fields.critical_services)
    .bind(&fields.supply_chain_role)
    .bind(fields.nis2_relevant)
    .bind(fields.kritis_relevant)
    .bind(fields.develops_digital_products)
    .bind(fields.uses_ai_systems)
    .bind(fields.ot_iacs_scope)
    .bind(fields.automotive_scope)
    .bind(fields.psirt_defined)
    .bind(fields.sbom_required)
    .bind(&fields.product_security_scope)
    .bind(fields.dora_relevant)
    .bind(fields.dora_financial_entity)
    .bind(fields.dora_ict_third_party_provider)
    .bind(fields.processes_personal_data)
    .bind(fields.gdpr_controller)
    .bind(fields.gdpr_processor)
    .bind(fields.gdpr_special_categories)
    .bind(fields.cra_relevant)
    .bind(&fields.ai_act_profile)
    .bind(fields.ai_act_high_risk)
    .bind(fields.tisax_relevant)
    .bind(&fields.iso27001_target)
    .bind(&fields.regulatory_profile_notes)
    .execute(pool)
    .await
    .context("PostgreSQL-Regulierungsprofil konnte nicht aktualisiert werden")?;
    if result.rows_affected() == 0 {
        return Ok(None);
    }
    tenant_profile_postgres(pool, tenant_id).await
}

async fn update_regulatory_profile_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    request: TenantRegulatoryProfileUpdateRequest,
) -> anyhow::Result<Option<TenantProfile>> {
    let Some(profile) = tenant_profile_sqlite(pool, tenant_id).await? else {
        return Ok(None);
    };
    let fields = TenantRegulatoryProfileFields::from_request(profile, request)?;
    let operation_countries = serde_json::to_string(&fields.operation_countries)?;
    let result = sqlx::query(
        r#"
        UPDATE organizations_tenant
        SET
            country = ?,
            operation_countries = ?,
            description = ?,
            sector = ?,
            employee_count = ?,
            annual_revenue_million = ?,
            balance_sheet_million = ?,
            critical_services = ?,
            supply_chain_role = ?,
            nis2_relevant = ?,
            kritis_relevant = ?,
            develops_digital_products = ?,
            uses_ai_systems = ?,
            ot_iacs_scope = ?,
            automotive_scope = ?,
            psirt_defined = ?,
            sbom_required = ?,
            product_security_scope = ?,
            dora_relevant = ?,
            dora_financial_entity = ?,
            dora_ict_third_party_provider = ?,
            processes_personal_data = ?,
            gdpr_controller = ?,
            gdpr_processor = ?,
            gdpr_special_categories = ?,
            cra_relevant = ?,
            ai_act_profile = ?,
            ai_act_high_risk = ?,
            tisax_relevant = ?,
            iso27001_target = ?,
            regulatory_profile_notes = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        "#,
    )
    .bind(&fields.country)
    .bind(operation_countries)
    .bind(&fields.description)
    .bind(&fields.sector)
    .bind(fields.employee_count)
    .bind(&fields.annual_revenue_million)
    .bind(&fields.balance_sheet_million)
    .bind(&fields.critical_services)
    .bind(&fields.supply_chain_role)
    .bind(fields.nis2_relevant)
    .bind(fields.kritis_relevant)
    .bind(fields.develops_digital_products)
    .bind(fields.uses_ai_systems)
    .bind(fields.ot_iacs_scope)
    .bind(fields.automotive_scope)
    .bind(fields.psirt_defined)
    .bind(fields.sbom_required)
    .bind(&fields.product_security_scope)
    .bind(fields.dora_relevant)
    .bind(fields.dora_financial_entity)
    .bind(fields.dora_ict_third_party_provider)
    .bind(fields.processes_personal_data)
    .bind(fields.gdpr_controller)
    .bind(fields.gdpr_processor)
    .bind(fields.gdpr_special_categories)
    .bind(fields.cra_relevant)
    .bind(&fields.ai_act_profile)
    .bind(fields.ai_act_high_risk)
    .bind(fields.tisax_relevant)
    .bind(&fields.iso27001_target)
    .bind(&fields.regulatory_profile_notes)
    .bind(tenant_id)
    .execute(pool)
    .await
    .context("SQLite-Regulierungsprofil konnte nicht aktualisiert werden")?;
    if result.rows_affected() == 0 {
        return Ok(None);
    }
    tenant_profile_sqlite(pool, tenant_id).await
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
        dora_relevant: row.try_get("dora_relevant")?,
        dora_financial_entity: row.try_get("dora_financial_entity")?,
        dora_ict_third_party_provider: row.try_get("dora_ict_third_party_provider")?,
        processes_personal_data: row.try_get("processes_personal_data")?,
        gdpr_controller: row.try_get("gdpr_controller")?,
        gdpr_processor: row.try_get("gdpr_processor")?,
        gdpr_special_categories: row.try_get("gdpr_special_categories")?,
        cra_relevant: row.try_get("cra_relevant")?,
        ai_act_profile: row.try_get("ai_act_profile")?,
        ai_act_high_risk: row.try_get("ai_act_high_risk")?,
        tisax_relevant: row.try_get("tisax_relevant")?,
        iso27001_target: row.try_get("iso27001_target")?,
        regulatory_profile_notes: row.try_get("regulatory_profile_notes")?,
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
        dora_relevant: row.try_get("dora_relevant")?,
        dora_financial_entity: row.try_get("dora_financial_entity")?,
        dora_ict_third_party_provider: row.try_get("dora_ict_third_party_provider")?,
        processes_personal_data: row.try_get("processes_personal_data")?,
        gdpr_controller: row.try_get("gdpr_controller")?,
        gdpr_processor: row.try_get("gdpr_processor")?,
        gdpr_special_categories: row.try_get("gdpr_special_categories")?,
        cra_relevant: row.try_get("cra_relevant")?,
        ai_act_profile: row.try_get("ai_act_profile")?,
        ai_act_high_risk: row.try_get("ai_act_high_risk")?,
        tisax_relevant: row.try_get("tisax_relevant")?,
        iso27001_target: row.try_get("iso27001_target")?,
        regulatory_profile_notes: row.try_get("regulatory_profile_notes")?,
    })
}

struct TenantRegulatoryProfileFields {
    country: String,
    operation_countries: Vec<String>,
    description: String,
    sector: String,
    employee_count: i64,
    annual_revenue_million: String,
    balance_sheet_million: String,
    critical_services: String,
    supply_chain_role: String,
    nis2_relevant: bool,
    kritis_relevant: bool,
    develops_digital_products: bool,
    uses_ai_systems: bool,
    ot_iacs_scope: bool,
    automotive_scope: bool,
    psirt_defined: bool,
    sbom_required: bool,
    product_security_scope: String,
    dora_relevant: bool,
    dora_financial_entity: bool,
    dora_ict_third_party_provider: bool,
    processes_personal_data: bool,
    gdpr_controller: bool,
    gdpr_processor: bool,
    gdpr_special_categories: bool,
    cra_relevant: bool,
    ai_act_profile: String,
    ai_act_high_risk: bool,
    tisax_relevant: bool,
    iso27001_target: String,
    regulatory_profile_notes: String,
}

impl TenantRegulatoryProfileFields {
    fn from_request(
        profile: TenantProfile,
        request: TenantRegulatoryProfileUpdateRequest,
    ) -> anyhow::Result<Self> {
        let employee_count = request.employee_count.unwrap_or(profile.employee_count);
        if employee_count < 0 {
            bail!("Mitarbeitende duerfen nicht negativ sein");
        }
        Ok(Self {
            country: clean_text(request.country, &profile.country, 100),
            operation_countries: request
                .operation_countries
                .map(normalize_country_list)
                .unwrap_or(profile.operation_countries),
            description: clean_text(request.description, &profile.description, 4000),
            sector: clean_code(request.sector, &profile.sector, 64),
            employee_count,
            annual_revenue_million: clean_text(
                request.annual_revenue_million,
                &profile.annual_revenue_million,
                64,
            ),
            balance_sheet_million: clean_text(
                request.balance_sheet_million,
                &profile.balance_sheet_million,
                64,
            ),
            critical_services: clean_text(
                request.critical_services,
                &profile.critical_services,
                4000,
            ),
            supply_chain_role: clean_text(
                request.supply_chain_role,
                &profile.supply_chain_role,
                255,
            ),
            nis2_relevant: request.nis2_relevant.unwrap_or(profile.nis2_relevant),
            kritis_relevant: request.kritis_relevant.unwrap_or(profile.kritis_relevant),
            develops_digital_products: request
                .develops_digital_products
                .unwrap_or(profile.develops_digital_products),
            uses_ai_systems: request.uses_ai_systems.unwrap_or(profile.uses_ai_systems),
            ot_iacs_scope: request.ot_iacs_scope.unwrap_or(profile.ot_iacs_scope),
            automotive_scope: request.automotive_scope.unwrap_or(profile.automotive_scope),
            psirt_defined: request.psirt_defined.unwrap_or(profile.psirt_defined),
            sbom_required: request.sbom_required.unwrap_or(profile.sbom_required),
            product_security_scope: clean_text(
                request.product_security_scope,
                &profile.product_security_scope,
                4000,
            ),
            dora_relevant: request.dora_relevant.unwrap_or(profile.dora_relevant),
            dora_financial_entity: request
                .dora_financial_entity
                .unwrap_or(profile.dora_financial_entity),
            dora_ict_third_party_provider: request
                .dora_ict_third_party_provider
                .unwrap_or(profile.dora_ict_third_party_provider),
            processes_personal_data: request
                .processes_personal_data
                .unwrap_or(profile.processes_personal_data),
            gdpr_controller: request.gdpr_controller.unwrap_or(profile.gdpr_controller),
            gdpr_processor: request.gdpr_processor.unwrap_or(profile.gdpr_processor),
            gdpr_special_categories: request
                .gdpr_special_categories
                .unwrap_or(profile.gdpr_special_categories),
            cra_relevant: request.cra_relevant.unwrap_or(profile.cra_relevant),
            ai_act_profile: clean_code(request.ai_act_profile, &profile.ai_act_profile, 64),
            ai_act_high_risk: request.ai_act_high_risk.unwrap_or(profile.ai_act_high_risk),
            tisax_relevant: request.tisax_relevant.unwrap_or(profile.tisax_relevant),
            iso27001_target: clean_code(request.iso27001_target, &profile.iso27001_target, 64),
            regulatory_profile_notes: clean_text(
                request.regulatory_profile_notes,
                &profile.regulatory_profile_notes,
                4000,
            ),
        })
    }
}

fn parse_operation_countries(raw: String) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(&raw).unwrap_or_default()
}

fn clean_text(value: Option<String>, fallback: &str, max_len: usize) -> String {
    value
        .map(|value| value.trim().chars().take(max_len).collect::<String>())
        .unwrap_or_else(|| fallback.to_string())
}

fn clean_code(value: Option<String>, fallback: &str, max_len: usize) -> String {
    value
        .map(|value| {
            value
                .trim()
                .chars()
                .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | ' '))
                .take(max_len)
                .collect::<String>()
                .trim()
                .to_ascii_uppercase()
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

fn normalize_country_list(values: Vec<String>) -> Vec<String> {
    let mut countries = Vec::new();
    for value in values {
        let normalized = value.trim().to_ascii_uppercase();
        if normalized.is_empty() || countries.contains(&normalized) {
            continue;
        }
        countries.push(normalized.chars().take(16).collect());
    }
    countries
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
