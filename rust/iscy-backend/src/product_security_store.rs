use anyhow::{bail, Context};
use serde::Serialize;
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Row,
};

use crate::cve_store::normalize_database_url;

#[derive(Clone)]
pub enum ProductSecurityStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityMatrixItem {
    pub applicable: bool,
    pub label: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityMatrix {
    pub cra: ProductSecurityMatrixItem,
    pub ai_act: ProductSecurityMatrixItem,
    pub iec62443: ProductSecurityMatrixItem,
    pub iso_sae_21434: ProductSecurityMatrixItem,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityPosture {
    pub products: i64,
    pub active_releases: i64,
    pub threat_models: i64,
    pub taras: i64,
    pub open_vulnerabilities: i64,
    pub critical_open_vulnerabilities: i64,
    pub psirt_cases_open: i64,
    pub published_advisories: i64,
    pub avg_threat_model_coverage: i64,
    pub avg_psirt_readiness: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductListItem {
    pub id: i64,
    pub tenant_id: i64,
    pub family_id: Option<i64>,
    pub family_name: Option<String>,
    pub name: String,
    pub code: String,
    pub description: String,
    pub has_digital_elements: bool,
    pub includes_ai: bool,
    pub ot_iacs_context: bool,
    pub automotive_context: bool,
    pub support_window_months: i64,
    pub release_count: i64,
    pub threat_model_count: i64,
    pub tara_count: i64,
    pub vulnerability_count: i64,
    pub psirt_case_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecuritySnapshotSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub product_id: i64,
    pub product_name: String,
    pub cra_applicable: bool,
    pub ai_act_applicable: bool,
    pub iec62443_applicable: bool,
    pub iso_sae_21434_applicable: bool,
    pub cra_readiness_percent: i64,
    pub ai_act_readiness_percent: i64,
    pub iec62443_readiness_percent: i64,
    pub iso_sae_21434_readiness_percent: i64,
    pub threat_model_coverage_percent: i64,
    pub psirt_readiness_percent: i64,
    pub open_vulnerability_count: i64,
    pub critical_vulnerability_count: i64,
    pub summary: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityOverview {
    pub tenant_id: i64,
    pub matrix: ProductSecurityMatrix,
    pub posture: ProductSecurityPosture,
    pub products: Vec<ProductListItem>,
    pub snapshots: Vec<ProductSecuritySnapshotSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductReleaseSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub product_id: i64,
    pub version: String,
    pub status: String,
    pub status_label: String,
    pub release_date: Option<String>,
    pub support_end_date: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductComponentSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub product_id: i64,
    pub supplier_id: Option<i64>,
    pub supplier_name: Option<String>,
    pub name: String,
    pub component_type: String,
    pub component_type_label: String,
    pub version: String,
    pub is_open_source: bool,
    pub has_sbom: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreatModelSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub product_id: i64,
    pub release_id: Option<i64>,
    pub release_version: Option<String>,
    pub name: String,
    pub methodology: String,
    pub summary: String,
    pub status: String,
    pub status_label: String,
    pub scenario_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TaraSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub product_id: i64,
    pub release_id: Option<i64>,
    pub release_version: Option<String>,
    pub scenario_id: Option<i64>,
    pub scenario_title: Option<String>,
    pub name: String,
    pub summary: String,
    pub attack_feasibility: i64,
    pub impact_score: i64,
    pub risk_score: i64,
    pub status: String,
    pub status_label: String,
    pub treatment_decision: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VulnerabilitySummary {
    pub id: i64,
    pub tenant_id: i64,
    pub product_id: i64,
    pub release_id: Option<i64>,
    pub release_version: Option<String>,
    pub component_id: Option<i64>,
    pub component_name: Option<String>,
    pub title: String,
    pub cve: String,
    pub severity: String,
    pub severity_label: String,
    pub status: String,
    pub status_label: String,
    pub remediation_due: Option<String>,
    pub summary: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiSystemSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub product_id: Option<i64>,
    pub product_name: Option<String>,
    pub name: String,
    pub use_case: String,
    pub provider: String,
    pub risk_classification: String,
    pub risk_classification_label: String,
    pub in_scope: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PsirtCaseSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub product_id: i64,
    pub release_id: Option<i64>,
    pub release_version: Option<String>,
    pub vulnerability_id: Option<i64>,
    pub vulnerability_title: Option<String>,
    pub case_id: String,
    pub title: String,
    pub severity: String,
    pub severity_label: String,
    pub status: String,
    pub status_label: String,
    pub disclosure_due: Option<String>,
    pub summary: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityAdvisorySummary {
    pub id: i64,
    pub tenant_id: i64,
    pub product_id: i64,
    pub release_id: Option<i64>,
    pub release_version: Option<String>,
    pub psirt_case_id: Option<i64>,
    pub psirt_case_identifier: Option<String>,
    pub advisory_id: String,
    pub title: String,
    pub status: String,
    pub status_label: String,
    pub published_on: Option<String>,
    pub summary: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityRoadmapSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub product_id: i64,
    pub title: String,
    pub summary: String,
    pub generated_from_snapshot_id: Option<i64>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityRoadmapTaskSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub roadmap_id: i64,
    pub related_release_id: Option<i64>,
    pub related_release_version: Option<String>,
    pub related_vulnerability_id: Option<i64>,
    pub related_vulnerability_title: Option<String>,
    pub phase: String,
    pub phase_label: String,
    pub title: String,
    pub description: String,
    pub priority: String,
    pub owner_role: String,
    pub due_in_days: i64,
    pub dependency_text: String,
    pub status: String,
    pub status_label: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityDetail {
    pub product: ProductListItem,
    pub releases: Vec<ProductReleaseSummary>,
    pub components: Vec<ProductComponentSummary>,
    pub threat_models: Vec<ThreatModelSummary>,
    pub threat_scenarios: i64,
    pub taras: Vec<TaraSummary>,
    pub vulnerabilities: Vec<VulnerabilitySummary>,
    pub ai_systems: Vec<AiSystemSummary>,
    pub psirt_cases: Vec<PsirtCaseSummary>,
    pub advisories: Vec<SecurityAdvisorySummary>,
    pub snapshot: Option<ProductSecuritySnapshotSummary>,
    pub roadmap: Option<ProductSecurityRoadmapSummary>,
    pub roadmap_tasks: Vec<ProductSecurityRoadmapTaskSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityRoadmapDetail {
    pub product: ProductListItem,
    pub roadmap: ProductSecurityRoadmapSummary,
    pub tasks: Vec<ProductSecurityRoadmapTaskSummary>,
    pub snapshot: Option<ProductSecuritySnapshotSummary>,
}

#[derive(Debug, Clone)]
struct TenantProductSecurityContext {
    sector: String,
    develops_digital_products: bool,
    uses_ai_systems: bool,
    ot_iacs_scope: bool,
    automotive_scope: bool,
}

impl ProductSecurityStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Product-Security-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Product-Security-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-Product-Security-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn overview(
        &self,
        tenant_id: i64,
        product_limit: i64,
        snapshot_limit: i64,
    ) -> anyhow::Result<Option<ProductSecurityOverview>> {
        match self {
            Self::Postgres(pool) => {
                overview_postgres(pool, tenant_id, product_limit, snapshot_limit).await
            }
            Self::Sqlite(pool) => {
                overview_sqlite(pool, tenant_id, product_limit, snapshot_limit).await
            }
        }
    }

    pub async fn detail(
        &self,
        tenant_id: i64,
        product_id: i64,
    ) -> anyhow::Result<Option<ProductSecurityDetail>> {
        match self {
            Self::Postgres(pool) => detail_postgres(pool, tenant_id, product_id).await,
            Self::Sqlite(pool) => detail_sqlite(pool, tenant_id, product_id).await,
        }
    }

    pub async fn roadmap_detail(
        &self,
        tenant_id: i64,
        product_id: i64,
    ) -> anyhow::Result<Option<ProductSecurityRoadmapDetail>> {
        match self {
            Self::Postgres(pool) => roadmap_detail_postgres(pool, tenant_id, product_id).await,
            Self::Sqlite(pool) => roadmap_detail_sqlite(pool, tenant_id, product_id).await,
        }
    }
}

async fn overview_postgres(
    pool: &PgPool,
    tenant_id: i64,
    product_limit: i64,
    snapshot_limit: i64,
) -> anyhow::Result<Option<ProductSecurityOverview>> {
    let Some(context) = sqlx::query(
        r#"
        SELECT sector, develops_digital_products, uses_ai_systems, ot_iacs_scope, automotive_scope
        FROM organizations_tenant
        WHERE id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-Product-Security-Tenantkontext konnte nicht gelesen werden")?
    .map(tenant_context_from_pg_row)
    .transpose()?
    else {
        return Ok(None);
    };

    let products = sqlx::query(product_list_postgres_sql())
        .bind(tenant_id)
        .bind(product_limit)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Produktliste konnte nicht gelesen werden")?
        .into_iter()
        .map(product_from_pg_row)
        .collect::<Result<Vec<_>, _>>()?;

    let snapshots = sqlx::query(snapshot_list_postgres_sql())
        .bind(tenant_id)
        .bind(snapshot_limit)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Product-Security-Snapshots konnten nicht gelesen werden")?
        .into_iter()
        .map(snapshot_from_pg_row)
        .collect::<Result<Vec<_>, _>>()?;

    let posture = sqlx::query(posture_postgres_sql())
        .bind(tenant_id)
        .fetch_one(pool)
        .await
        .context("PostgreSQL-Product-Security-Posture konnte nicht gelesen werden")
        .and_then(posture_from_pg_row)?;

    Ok(Some(ProductSecurityOverview {
        tenant_id,
        matrix: build_matrix(&context),
        posture,
        products,
        snapshots,
    }))
}

async fn overview_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    product_limit: i64,
    snapshot_limit: i64,
) -> anyhow::Result<Option<ProductSecurityOverview>> {
    let Some(context) = sqlx::query(
        r#"
        SELECT sector, develops_digital_products, uses_ai_systems, ot_iacs_scope, automotive_scope
        FROM organizations_tenant
        WHERE id = ?
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-Product-Security-Tenantkontext konnte nicht gelesen werden")?
    .map(tenant_context_from_sqlite_row)
    .transpose()?
    else {
        return Ok(None);
    };

    let products = sqlx::query(product_list_sqlite_sql())
        .bind(tenant_id)
        .bind(product_limit)
        .fetch_all(pool)
        .await
        .context("SQLite-Produktliste konnte nicht gelesen werden")?
        .into_iter()
        .map(product_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()?;

    let snapshots = sqlx::query(snapshot_list_sqlite_sql())
        .bind(tenant_id)
        .bind(snapshot_limit)
        .fetch_all(pool)
        .await
        .context("SQLite-Product-Security-Snapshots konnten nicht gelesen werden")?
        .into_iter()
        .map(snapshot_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()?;

    let posture = sqlx::query(posture_sqlite_sql())
        .bind(tenant_id)
        .bind(tenant_id)
        .bind(tenant_id)
        .bind(tenant_id)
        .bind(tenant_id)
        .bind(tenant_id)
        .bind(tenant_id)
        .bind(tenant_id)
        .bind(tenant_id)
        .bind(tenant_id)
        .fetch_one(pool)
        .await
        .context("SQLite-Product-Security-Posture konnte nicht gelesen werden")
        .and_then(posture_from_sqlite_row)?;

    Ok(Some(ProductSecurityOverview {
        tenant_id,
        matrix: build_matrix(&context),
        posture,
        products,
        snapshots,
    }))
}

async fn detail_postgres(
    pool: &PgPool,
    tenant_id: i64,
    product_id: i64,
) -> anyhow::Result<Option<ProductSecurityDetail>> {
    let Some(product) = load_product_postgres(pool, tenant_id, product_id).await? else {
        return Ok(None);
    };

    let releases = sqlx::query(releases_postgres_sql())
        .bind(tenant_id)
        .bind(product_id)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Product-Security-Releases konnten nicht gelesen werden")?
        .into_iter()
        .map(release_from_pg_row)
        .collect::<Result<Vec<_>, _>>()?;
    let components = sqlx::query(components_postgres_sql())
        .bind(tenant_id)
        .bind(product_id)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Product-Security-Komponenten konnten nicht gelesen werden")?
        .into_iter()
        .map(component_from_pg_row)
        .collect::<Result<Vec<_>, _>>()?;
    let threat_models = sqlx::query(threat_models_postgres_sql())
        .bind(tenant_id)
        .bind(product_id)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Product-Security-Threat-Models konnten nicht gelesen werden")?
        .into_iter()
        .map(threat_model_from_pg_row)
        .collect::<Result<Vec<_>, _>>()?;
    let taras = sqlx::query(taras_postgres_sql())
        .bind(tenant_id)
        .bind(product_id)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Product-Security-TARAs konnten nicht gelesen werden")?
        .into_iter()
        .map(tara_from_pg_row)
        .collect::<Result<Vec<_>, _>>()?;
    let vulnerabilities = sqlx::query(vulnerabilities_postgres_sql())
        .bind(tenant_id)
        .bind(product_id)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Product-Security-Schwachstellen konnten nicht gelesen werden")?
        .into_iter()
        .map(vulnerability_from_pg_row)
        .collect::<Result<Vec<_>, _>>()?;
    let ai_systems = sqlx::query(ai_systems_postgres_sql())
        .bind(tenant_id)
        .bind(product_id)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Product-Security-AI-Systeme konnten nicht gelesen werden")?
        .into_iter()
        .map(ai_system_from_pg_row)
        .collect::<Result<Vec<_>, _>>()?;
    let psirt_cases = sqlx::query(psirt_cases_postgres_sql())
        .bind(tenant_id)
        .bind(product_id)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Product-Security-PSIRT-Cases konnten nicht gelesen werden")?
        .into_iter()
        .map(psirt_case_from_pg_row)
        .collect::<Result<Vec<_>, _>>()?;
    let advisories = sqlx::query(advisories_postgres_sql())
        .bind(tenant_id)
        .bind(product_id)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Product-Security-Advisories konnten nicht gelesen werden")?
        .into_iter()
        .map(advisory_from_pg_row)
        .collect::<Result<Vec<_>, _>>()?;
    let snapshot = load_latest_snapshot_postgres(pool, tenant_id, product_id).await?;
    let roadmap = load_latest_roadmap_postgres(pool, tenant_id, product_id).await?;
    let roadmap_tasks = match roadmap.as_ref() {
        Some(roadmap) => load_roadmap_tasks_postgres(pool, tenant_id, roadmap.id).await?,
        None => Vec::new(),
    };
    let threat_scenarios = threat_models.iter().map(|item| item.scenario_count).sum();

    Ok(Some(ProductSecurityDetail {
        product,
        releases,
        components,
        threat_models,
        threat_scenarios,
        taras,
        vulnerabilities,
        ai_systems,
        psirt_cases,
        advisories,
        snapshot,
        roadmap,
        roadmap_tasks,
    }))
}

async fn detail_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    product_id: i64,
) -> anyhow::Result<Option<ProductSecurityDetail>> {
    let Some(product) = load_product_sqlite(pool, tenant_id, product_id).await? else {
        return Ok(None);
    };

    let releases = sqlx::query(releases_sqlite_sql())
        .bind(tenant_id)
        .bind(product_id)
        .fetch_all(pool)
        .await
        .context("SQLite-Product-Security-Releases konnten nicht gelesen werden")?
        .into_iter()
        .map(release_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()?;
    let components = sqlx::query(components_sqlite_sql())
        .bind(tenant_id)
        .bind(product_id)
        .fetch_all(pool)
        .await
        .context("SQLite-Product-Security-Komponenten konnten nicht gelesen werden")?
        .into_iter()
        .map(component_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()?;
    let threat_models = sqlx::query(threat_models_sqlite_sql())
        .bind(tenant_id)
        .bind(product_id)
        .fetch_all(pool)
        .await
        .context("SQLite-Product-Security-Threat-Models konnten nicht gelesen werden")?
        .into_iter()
        .map(threat_model_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()?;
    let taras = sqlx::query(taras_sqlite_sql())
        .bind(tenant_id)
        .bind(product_id)
        .fetch_all(pool)
        .await
        .context("SQLite-Product-Security-TARAs konnten nicht gelesen werden")?
        .into_iter()
        .map(tara_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()?;
    let vulnerabilities = sqlx::query(vulnerabilities_sqlite_sql())
        .bind(tenant_id)
        .bind(product_id)
        .fetch_all(pool)
        .await
        .context("SQLite-Product-Security-Schwachstellen konnten nicht gelesen werden")?
        .into_iter()
        .map(vulnerability_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()?;
    let ai_systems = sqlx::query(ai_systems_sqlite_sql())
        .bind(tenant_id)
        .bind(product_id)
        .fetch_all(pool)
        .await
        .context("SQLite-Product-Security-AI-Systeme konnten nicht gelesen werden")?
        .into_iter()
        .map(ai_system_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()?;
    let psirt_cases = sqlx::query(psirt_cases_sqlite_sql())
        .bind(tenant_id)
        .bind(product_id)
        .fetch_all(pool)
        .await
        .context("SQLite-Product-Security-PSIRT-Cases konnten nicht gelesen werden")?
        .into_iter()
        .map(psirt_case_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()?;
    let advisories = sqlx::query(advisories_sqlite_sql())
        .bind(tenant_id)
        .bind(product_id)
        .fetch_all(pool)
        .await
        .context("SQLite-Product-Security-Advisories konnten nicht gelesen werden")?
        .into_iter()
        .map(advisory_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()?;
    let snapshot = load_latest_snapshot_sqlite(pool, tenant_id, product_id).await?;
    let roadmap = load_latest_roadmap_sqlite(pool, tenant_id, product_id).await?;
    let roadmap_tasks = match roadmap.as_ref() {
        Some(roadmap) => load_roadmap_tasks_sqlite(pool, tenant_id, roadmap.id).await?,
        None => Vec::new(),
    };
    let threat_scenarios = threat_models.iter().map(|item| item.scenario_count).sum();

    Ok(Some(ProductSecurityDetail {
        product,
        releases,
        components,
        threat_models,
        threat_scenarios,
        taras,
        vulnerabilities,
        ai_systems,
        psirt_cases,
        advisories,
        snapshot,
        roadmap,
        roadmap_tasks,
    }))
}

async fn roadmap_detail_postgres(
    pool: &PgPool,
    tenant_id: i64,
    product_id: i64,
) -> anyhow::Result<Option<ProductSecurityRoadmapDetail>> {
    let Some(product) = load_product_postgres(pool, tenant_id, product_id).await? else {
        return Ok(None);
    };
    let Some(roadmap) = load_latest_roadmap_postgres(pool, tenant_id, product_id).await? else {
        return Ok(None);
    };
    let tasks = load_roadmap_tasks_postgres(pool, tenant_id, roadmap.id).await?;
    let snapshot = load_latest_snapshot_postgres(pool, tenant_id, product_id).await?;
    Ok(Some(ProductSecurityRoadmapDetail {
        product,
        roadmap,
        tasks,
        snapshot,
    }))
}

async fn roadmap_detail_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    product_id: i64,
) -> anyhow::Result<Option<ProductSecurityRoadmapDetail>> {
    let Some(product) = load_product_sqlite(pool, tenant_id, product_id).await? else {
        return Ok(None);
    };
    let Some(roadmap) = load_latest_roadmap_sqlite(pool, tenant_id, product_id).await? else {
        return Ok(None);
    };
    let tasks = load_roadmap_tasks_sqlite(pool, tenant_id, roadmap.id).await?;
    let snapshot = load_latest_snapshot_sqlite(pool, tenant_id, product_id).await?;
    Ok(Some(ProductSecurityRoadmapDetail {
        product,
        roadmap,
        tasks,
        snapshot,
    }))
}

async fn load_product_postgres(
    pool: &PgPool,
    tenant_id: i64,
    product_id: i64,
) -> anyhow::Result<Option<ProductListItem>> {
    sqlx::query(product_detail_postgres_sql())
        .bind(tenant_id)
        .bind(product_id)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-Product-Security-Produkt konnte nicht gelesen werden")?
        .map(product_from_pg_row)
        .transpose()
        .map_err(Into::into)
}

async fn load_product_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    product_id: i64,
) -> anyhow::Result<Option<ProductListItem>> {
    sqlx::query(product_detail_sqlite_sql())
        .bind(tenant_id)
        .bind(product_id)
        .fetch_optional(pool)
        .await
        .context("SQLite-Product-Security-Produkt konnte nicht gelesen werden")?
        .map(product_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

async fn load_latest_snapshot_postgres(
    pool: &PgPool,
    tenant_id: i64,
    product_id: i64,
) -> anyhow::Result<Option<ProductSecuritySnapshotSummary>> {
    sqlx::query(snapshot_detail_postgres_sql())
        .bind(tenant_id)
        .bind(product_id)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-Product-Security-Snapshot konnte nicht gelesen werden")?
        .map(snapshot_from_pg_row)
        .transpose()
        .map_err(Into::into)
}

async fn load_latest_snapshot_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    product_id: i64,
) -> anyhow::Result<Option<ProductSecuritySnapshotSummary>> {
    sqlx::query(snapshot_detail_sqlite_sql())
        .bind(tenant_id)
        .bind(product_id)
        .fetch_optional(pool)
        .await
        .context("SQLite-Product-Security-Snapshot konnte nicht gelesen werden")?
        .map(snapshot_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

async fn load_latest_roadmap_postgres(
    pool: &PgPool,
    tenant_id: i64,
    product_id: i64,
) -> anyhow::Result<Option<ProductSecurityRoadmapSummary>> {
    sqlx::query(roadmap_detail_postgres_sql())
        .bind(tenant_id)
        .bind(product_id)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-Product-Security-Roadmap konnte nicht gelesen werden")?
        .map(roadmap_from_pg_row)
        .transpose()
        .map_err(Into::into)
}

async fn load_latest_roadmap_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    product_id: i64,
) -> anyhow::Result<Option<ProductSecurityRoadmapSummary>> {
    sqlx::query(roadmap_detail_sqlite_sql())
        .bind(tenant_id)
        .bind(product_id)
        .fetch_optional(pool)
        .await
        .context("SQLite-Product-Security-Roadmap konnte nicht gelesen werden")?
        .map(roadmap_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

async fn load_roadmap_tasks_postgres(
    pool: &PgPool,
    tenant_id: i64,
    roadmap_id: i64,
) -> anyhow::Result<Vec<ProductSecurityRoadmapTaskSummary>> {
    sqlx::query(roadmap_tasks_postgres_sql())
        .bind(tenant_id)
        .bind(roadmap_id)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Product-Security-Roadmaptasks konnten nicht gelesen werden")?
        .into_iter()
        .map(roadmap_task_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn load_roadmap_tasks_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    roadmap_id: i64,
) -> anyhow::Result<Vec<ProductSecurityRoadmapTaskSummary>> {
    sqlx::query(roadmap_tasks_sqlite_sql())
        .bind(tenant_id)
        .bind(roadmap_id)
        .fetch_all(pool)
        .await
        .context("SQLite-Product-Security-Roadmaptasks konnten nicht gelesen werden")?
        .into_iter()
        .map(roadmap_task_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn product_list_postgres_sql() -> &'static str {
    r#"
    SELECT
        product.id,
        product.tenant_id,
        product.family_id,
        family.name AS family_name,
        product.name,
        product.code,
        product.description,
        product.has_digital_elements,
        product.includes_ai,
        product.ot_iacs_context,
        product.automotive_context,
        product.support_window_months,
        (SELECT COUNT(*) FROM product_security_productrelease rel WHERE rel.product_id = product.id AND rel.tenant_id = product.tenant_id) AS release_count,
        (SELECT COUNT(*) FROM product_security_threatmodel tm WHERE tm.product_id = product.id AND tm.tenant_id = product.tenant_id) AS threat_model_count,
        (SELECT COUNT(*) FROM product_security_tara tara WHERE tara.product_id = product.id AND tara.tenant_id = product.tenant_id) AS tara_count,
        (SELECT COUNT(*) FROM product_security_vulnerability vuln WHERE vuln.product_id = product.id AND vuln.tenant_id = product.tenant_id) AS vulnerability_count,
        (SELECT COUNT(*) FROM product_security_psirtcase psirt WHERE psirt.product_id = product.id AND psirt.tenant_id = product.tenant_id) AS psirt_case_count,
        product.created_at::text AS created_at,
        product.updated_at::text AS updated_at
    FROM product_security_product product
    LEFT JOIN product_security_productfamily family
        ON family.id = product.family_id AND family.tenant_id = product.tenant_id
    WHERE product.tenant_id = $1
    ORDER BY product.name ASC, product.id ASC
    LIMIT $2
    "#
}

fn product_list_sqlite_sql() -> &'static str {
    r#"
    SELECT
        product.id,
        product.tenant_id,
        product.family_id,
        family.name AS family_name,
        product.name,
        product.code,
        product.description,
        product.has_digital_elements,
        product.includes_ai,
        product.ot_iacs_context,
        product.automotive_context,
        product.support_window_months,
        (SELECT COUNT(*) FROM product_security_productrelease rel WHERE rel.product_id = product.id AND rel.tenant_id = product.tenant_id) AS release_count,
        (SELECT COUNT(*) FROM product_security_threatmodel tm WHERE tm.product_id = product.id AND tm.tenant_id = product.tenant_id) AS threat_model_count,
        (SELECT COUNT(*) FROM product_security_tara tara WHERE tara.product_id = product.id AND tara.tenant_id = product.tenant_id) AS tara_count,
        (SELECT COUNT(*) FROM product_security_vulnerability vuln WHERE vuln.product_id = product.id AND vuln.tenant_id = product.tenant_id) AS vulnerability_count,
        (SELECT COUNT(*) FROM product_security_psirtcase psirt WHERE psirt.product_id = product.id AND psirt.tenant_id = product.tenant_id) AS psirt_case_count,
        CAST(product.created_at AS TEXT) AS created_at,
        CAST(product.updated_at AS TEXT) AS updated_at
    FROM product_security_product product
    LEFT JOIN product_security_productfamily family
        ON family.id = product.family_id AND family.tenant_id = product.tenant_id
    WHERE product.tenant_id = ?
    ORDER BY product.name ASC, product.id ASC
    LIMIT ?
    "#
}

fn product_detail_postgres_sql() -> &'static str {
    r#"
    SELECT
        product.id,
        product.tenant_id,
        product.family_id,
        family.name AS family_name,
        product.name,
        product.code,
        product.description,
        product.has_digital_elements,
        product.includes_ai,
        product.ot_iacs_context,
        product.automotive_context,
        product.support_window_months,
        (SELECT COUNT(*) FROM product_security_productrelease rel WHERE rel.product_id = product.id AND rel.tenant_id = product.tenant_id) AS release_count,
        (SELECT COUNT(*) FROM product_security_threatmodel tm WHERE tm.product_id = product.id AND tm.tenant_id = product.tenant_id) AS threat_model_count,
        (SELECT COUNT(*) FROM product_security_tara tara WHERE tara.product_id = product.id AND tara.tenant_id = product.tenant_id) AS tara_count,
        (SELECT COUNT(*) FROM product_security_vulnerability vuln WHERE vuln.product_id = product.id AND vuln.tenant_id = product.tenant_id) AS vulnerability_count,
        (SELECT COUNT(*) FROM product_security_psirtcase psirt WHERE psirt.product_id = product.id AND psirt.tenant_id = product.tenant_id) AS psirt_case_count,
        product.created_at::text AS created_at,
        product.updated_at::text AS updated_at
    FROM product_security_product product
    LEFT JOIN product_security_productfamily family
        ON family.id = product.family_id AND family.tenant_id = product.tenant_id
    WHERE product.tenant_id = $1 AND product.id = $2
    "#
}

fn product_detail_sqlite_sql() -> &'static str {
    r#"
    SELECT
        product.id,
        product.tenant_id,
        product.family_id,
        family.name AS family_name,
        product.name,
        product.code,
        product.description,
        product.has_digital_elements,
        product.includes_ai,
        product.ot_iacs_context,
        product.automotive_context,
        product.support_window_months,
        (SELECT COUNT(*) FROM product_security_productrelease rel WHERE rel.product_id = product.id AND rel.tenant_id = product.tenant_id) AS release_count,
        (SELECT COUNT(*) FROM product_security_threatmodel tm WHERE tm.product_id = product.id AND tm.tenant_id = product.tenant_id) AS threat_model_count,
        (SELECT COUNT(*) FROM product_security_tara tara WHERE tara.product_id = product.id AND tara.tenant_id = product.tenant_id) AS tara_count,
        (SELECT COUNT(*) FROM product_security_vulnerability vuln WHERE vuln.product_id = product.id AND vuln.tenant_id = product.tenant_id) AS vulnerability_count,
        (SELECT COUNT(*) FROM product_security_psirtcase psirt WHERE psirt.product_id = product.id AND psirt.tenant_id = product.tenant_id) AS psirt_case_count,
        CAST(product.created_at AS TEXT) AS created_at,
        CAST(product.updated_at AS TEXT) AS updated_at
    FROM product_security_product product
    LEFT JOIN product_security_productfamily family
        ON family.id = product.family_id AND family.tenant_id = product.tenant_id
    WHERE product.tenant_id = ? AND product.id = ?
    "#
}

fn releases_postgres_sql() -> &'static str {
    r#"
    SELECT
        id,
        tenant_id,
        product_id,
        version,
        status,
        release_date::text AS release_date,
        support_end_date::text AS support_end_date,
        created_at::text AS created_at,
        updated_at::text AS updated_at
    FROM product_security_productrelease
    WHERE tenant_id = $1 AND product_id = $2
    ORDER BY product_id ASC, release_date DESC NULLS LAST, created_at DESC, id ASC
    "#
}

fn releases_sqlite_sql() -> &'static str {
    r#"
    SELECT
        id,
        tenant_id,
        product_id,
        version,
        status,
        CAST(release_date AS TEXT) AS release_date,
        CAST(support_end_date AS TEXT) AS support_end_date,
        CAST(created_at AS TEXT) AS created_at,
        CAST(updated_at AS TEXT) AS updated_at
    FROM product_security_productrelease
    WHERE tenant_id = ? AND product_id = ?
    ORDER BY product_id ASC, release_date DESC, created_at DESC, id ASC
    "#
}

fn components_postgres_sql() -> &'static str {
    r#"
    SELECT
        component.id,
        component.tenant_id,
        component.product_id,
        component.supplier_id,
        supplier.name AS supplier_name,
        component.name,
        component.component_type,
        component.version,
        component.is_open_source,
        component.has_sbom,
        component.created_at::text AS created_at,
        component.updated_at::text AS updated_at
    FROM product_security_component component
    LEFT JOIN organizations_supplier supplier
        ON supplier.id = component.supplier_id AND supplier.tenant_id = component.tenant_id
    WHERE component.tenant_id = $1 AND component.product_id = $2
    ORDER BY component.name ASC, component.id ASC
    "#
}

fn components_sqlite_sql() -> &'static str {
    r#"
    SELECT
        component.id,
        component.tenant_id,
        component.product_id,
        component.supplier_id,
        supplier.name AS supplier_name,
        component.name,
        component.component_type,
        component.version,
        component.is_open_source,
        component.has_sbom,
        CAST(component.created_at AS TEXT) AS created_at,
        CAST(component.updated_at AS TEXT) AS updated_at
    FROM product_security_component component
    LEFT JOIN organizations_supplier supplier
        ON supplier.id = component.supplier_id AND supplier.tenant_id = component.tenant_id
    WHERE component.tenant_id = ? AND component.product_id = ?
    ORDER BY component.name ASC, component.id ASC
    "#
}

fn threat_models_postgres_sql() -> &'static str {
    r#"
    SELECT
        model.id,
        model.tenant_id,
        model.product_id,
        model.release_id,
        release.version AS release_version,
        model.name,
        model.methodology,
        model.summary,
        model.status,
        (SELECT COUNT(*) FROM product_security_threatscenario scenario WHERE scenario.threat_model_id = model.id AND scenario.tenant_id = model.tenant_id) AS scenario_count,
        model.created_at::text AS created_at,
        model.updated_at::text AS updated_at
    FROM product_security_threatmodel model
    LEFT JOIN product_security_productrelease release
        ON release.id = model.release_id AND release.tenant_id = model.tenant_id
    WHERE model.tenant_id = $1 AND model.product_id = $2
    ORDER BY model.name ASC, model.id ASC
    "#
}

fn threat_models_sqlite_sql() -> &'static str {
    r#"
    SELECT
        model.id,
        model.tenant_id,
        model.product_id,
        model.release_id,
        release.version AS release_version,
        model.name,
        model.methodology,
        model.summary,
        model.status,
        (SELECT COUNT(*) FROM product_security_threatscenario scenario WHERE scenario.threat_model_id = model.id AND scenario.tenant_id = model.tenant_id) AS scenario_count,
        CAST(model.created_at AS TEXT) AS created_at,
        CAST(model.updated_at AS TEXT) AS updated_at
    FROM product_security_threatmodel model
    LEFT JOIN product_security_productrelease release
        ON release.id = model.release_id AND release.tenant_id = model.tenant_id
    WHERE model.tenant_id = ? AND model.product_id = ?
    ORDER BY model.name ASC, model.id ASC
    "#
}

fn taras_postgres_sql() -> &'static str {
    r#"
    SELECT
        tara.id,
        tara.tenant_id,
        tara.product_id,
        tara.release_id,
        release.version AS release_version,
        tara.scenario_id,
        scenario.title AS scenario_title,
        tara.name,
        tara.summary,
        tara.attack_feasibility,
        tara.impact_score,
        tara.risk_score,
        tara.status,
        tara.treatment_decision,
        tara.created_at::text AS created_at,
        tara.updated_at::text AS updated_at
    FROM product_security_tara tara
    LEFT JOIN product_security_productrelease release
        ON release.id = tara.release_id AND release.tenant_id = tara.tenant_id
    LEFT JOIN product_security_threatscenario scenario
        ON scenario.id = tara.scenario_id AND scenario.tenant_id = tara.tenant_id
    WHERE tara.tenant_id = $1 AND tara.product_id = $2
    ORDER BY tara.product_id ASC, tara.risk_score DESC, tara.name ASC, tara.id ASC
    "#
}

fn taras_sqlite_sql() -> &'static str {
    r#"
    SELECT
        tara.id,
        tara.tenant_id,
        tara.product_id,
        tara.release_id,
        release.version AS release_version,
        tara.scenario_id,
        scenario.title AS scenario_title,
        tara.name,
        tara.summary,
        tara.attack_feasibility,
        tara.impact_score,
        tara.risk_score,
        tara.status,
        tara.treatment_decision,
        CAST(tara.created_at AS TEXT) AS created_at,
        CAST(tara.updated_at AS TEXT) AS updated_at
    FROM product_security_tara tara
    LEFT JOIN product_security_productrelease release
        ON release.id = tara.release_id AND release.tenant_id = tara.tenant_id
    LEFT JOIN product_security_threatscenario scenario
        ON scenario.id = tara.scenario_id AND scenario.tenant_id = tara.tenant_id
    WHERE tara.tenant_id = ? AND tara.product_id = ?
    ORDER BY tara.product_id ASC, tara.risk_score DESC, tara.name ASC, tara.id ASC
    "#
}

fn vulnerabilities_postgres_sql() -> &'static str {
    r#"
    SELECT
        vuln.id,
        vuln.tenant_id,
        vuln.product_id,
        vuln.release_id,
        release.version AS release_version,
        vuln.component_id,
        component.name AS component_name,
        vuln.title,
        vuln.cve,
        vuln.severity,
        vuln.status,
        vuln.remediation_due::text AS remediation_due,
        vuln.summary,
        vuln.created_at::text AS created_at,
        vuln.updated_at::text AS updated_at
    FROM product_security_vulnerability vuln
    LEFT JOIN product_security_productrelease release
        ON release.id = vuln.release_id AND release.tenant_id = vuln.tenant_id
    LEFT JOIN product_security_component component
        ON component.id = vuln.component_id AND component.tenant_id = vuln.tenant_id
    WHERE vuln.tenant_id = $1 AND vuln.product_id = $2
    ORDER BY vuln.product_id ASC, vuln.severity ASC, vuln.title ASC, vuln.id ASC
    "#
}

fn vulnerabilities_sqlite_sql() -> &'static str {
    r#"
    SELECT
        vuln.id,
        vuln.tenant_id,
        vuln.product_id,
        vuln.release_id,
        release.version AS release_version,
        vuln.component_id,
        component.name AS component_name,
        vuln.title,
        vuln.cve,
        vuln.severity,
        vuln.status,
        CAST(vuln.remediation_due AS TEXT) AS remediation_due,
        vuln.summary,
        CAST(vuln.created_at AS TEXT) AS created_at,
        CAST(vuln.updated_at AS TEXT) AS updated_at
    FROM product_security_vulnerability vuln
    LEFT JOIN product_security_productrelease release
        ON release.id = vuln.release_id AND release.tenant_id = vuln.tenant_id
    LEFT JOIN product_security_component component
        ON component.id = vuln.component_id AND component.tenant_id = vuln.tenant_id
    WHERE vuln.tenant_id = ? AND vuln.product_id = ?
    ORDER BY vuln.product_id ASC, vuln.severity ASC, vuln.title ASC, vuln.id ASC
    "#
}

fn ai_systems_postgres_sql() -> &'static str {
    r#"
    SELECT
        ai.id,
        ai.tenant_id,
        ai.product_id,
        product.name AS product_name,
        ai.name,
        ai.use_case,
        ai.provider,
        ai.risk_classification,
        ai.in_scope,
        ai.created_at::text AS created_at,
        ai.updated_at::text AS updated_at
    FROM product_security_aisystem ai
    LEFT JOIN product_security_product product
        ON product.id = ai.product_id AND product.tenant_id = ai.tenant_id
    WHERE ai.tenant_id = $1 AND ai.product_id = $2
    ORDER BY ai.name ASC, ai.id ASC
    "#
}

fn ai_systems_sqlite_sql() -> &'static str {
    r#"
    SELECT
        ai.id,
        ai.tenant_id,
        ai.product_id,
        product.name AS product_name,
        ai.name,
        ai.use_case,
        ai.provider,
        ai.risk_classification,
        ai.in_scope,
        CAST(ai.created_at AS TEXT) AS created_at,
        CAST(ai.updated_at AS TEXT) AS updated_at
    FROM product_security_aisystem ai
    LEFT JOIN product_security_product product
        ON product.id = ai.product_id AND product.tenant_id = ai.tenant_id
    WHERE ai.tenant_id = ? AND ai.product_id = ?
    ORDER BY ai.name ASC, ai.id ASC
    "#
}

fn psirt_cases_postgres_sql() -> &'static str {
    r#"
    SELECT
        psirt.id,
        psirt.tenant_id,
        psirt.product_id,
        psirt.release_id,
        release.version AS release_version,
        psirt.vulnerability_id,
        vuln.title AS vulnerability_title,
        psirt.case_id,
        psirt.title,
        psirt.severity,
        psirt.status,
        psirt.disclosure_due::text AS disclosure_due,
        psirt.summary,
        psirt.created_at::text AS created_at,
        psirt.updated_at::text AS updated_at
    FROM product_security_psirtcase psirt
    LEFT JOIN product_security_productrelease release
        ON release.id = psirt.release_id AND release.tenant_id = psirt.tenant_id
    LEFT JOIN product_security_vulnerability vuln
        ON vuln.id = psirt.vulnerability_id AND vuln.tenant_id = psirt.tenant_id
    WHERE psirt.tenant_id = $1 AND psirt.product_id = $2
    ORDER BY psirt.product_id ASC, psirt.created_at DESC, psirt.id ASC
    "#
}

fn psirt_cases_sqlite_sql() -> &'static str {
    r#"
    SELECT
        psirt.id,
        psirt.tenant_id,
        psirt.product_id,
        psirt.release_id,
        release.version AS release_version,
        psirt.vulnerability_id,
        vuln.title AS vulnerability_title,
        psirt.case_id,
        psirt.title,
        psirt.severity,
        psirt.status,
        CAST(psirt.disclosure_due AS TEXT) AS disclosure_due,
        psirt.summary,
        CAST(psirt.created_at AS TEXT) AS created_at,
        CAST(psirt.updated_at AS TEXT) AS updated_at
    FROM product_security_psirtcase psirt
    LEFT JOIN product_security_productrelease release
        ON release.id = psirt.release_id AND release.tenant_id = psirt.tenant_id
    LEFT JOIN product_security_vulnerability vuln
        ON vuln.id = psirt.vulnerability_id AND vuln.tenant_id = psirt.tenant_id
    WHERE psirt.tenant_id = ? AND psirt.product_id = ?
    ORDER BY psirt.product_id ASC, psirt.created_at DESC, psirt.id ASC
    "#
}

fn advisories_postgres_sql() -> &'static str {
    r#"
    SELECT
        advisory.id,
        advisory.tenant_id,
        advisory.product_id,
        advisory.release_id,
        release.version AS release_version,
        advisory.psirt_case_id,
        psirt.case_id AS psirt_case_identifier,
        advisory.advisory_id,
        advisory.title,
        advisory.status,
        advisory.published_on::text AS published_on,
        advisory.summary,
        advisory.created_at::text AS created_at,
        advisory.updated_at::text AS updated_at
    FROM product_security_securityadvisory advisory
    LEFT JOIN product_security_productrelease release
        ON release.id = advisory.release_id AND release.tenant_id = advisory.tenant_id
    LEFT JOIN product_security_psirtcase psirt
        ON psirt.id = advisory.psirt_case_id AND psirt.tenant_id = advisory.tenant_id
    WHERE advisory.tenant_id = $1 AND advisory.product_id = $2
    ORDER BY advisory.product_id ASC, advisory.created_at DESC, advisory.id ASC
    "#
}

fn advisories_sqlite_sql() -> &'static str {
    r#"
    SELECT
        advisory.id,
        advisory.tenant_id,
        advisory.product_id,
        advisory.release_id,
        release.version AS release_version,
        advisory.psirt_case_id,
        psirt.case_id AS psirt_case_identifier,
        advisory.advisory_id,
        advisory.title,
        advisory.status,
        CAST(advisory.published_on AS TEXT) AS published_on,
        advisory.summary,
        CAST(advisory.created_at AS TEXT) AS created_at,
        CAST(advisory.updated_at AS TEXT) AS updated_at
    FROM product_security_securityadvisory advisory
    LEFT JOIN product_security_productrelease release
        ON release.id = advisory.release_id AND release.tenant_id = advisory.tenant_id
    LEFT JOIN product_security_psirtcase psirt
        ON psirt.id = advisory.psirt_case_id AND psirt.tenant_id = advisory.tenant_id
    WHERE advisory.tenant_id = ? AND advisory.product_id = ?
    ORDER BY advisory.product_id ASC, advisory.created_at DESC, advisory.id ASC
    "#
}

fn snapshot_list_postgres_sql() -> &'static str {
    r#"
    SELECT
        snapshot.id,
        snapshot.tenant_id,
        snapshot.product_id,
        product.name AS product_name,
        snapshot.cra_applicable,
        snapshot.ai_act_applicable,
        snapshot.iec62443_applicable,
        snapshot.iso_sae_21434_applicable,
        snapshot.cra_readiness_percent,
        snapshot.ai_act_readiness_percent,
        snapshot.iec62443_readiness_percent,
        snapshot.iso_sae_21434_readiness_percent,
        snapshot.threat_model_coverage_percent,
        snapshot.psirt_readiness_percent,
        snapshot.open_vulnerability_count,
        snapshot.critical_vulnerability_count,
        snapshot.summary,
        snapshot.created_at::text AS created_at,
        snapshot.updated_at::text AS updated_at
    FROM product_security_productsecuritysnapshot snapshot
    INNER JOIN product_security_product product
        ON product.id = snapshot.product_id AND product.tenant_id = snapshot.tenant_id
    WHERE snapshot.tenant_id = $1
    ORDER BY snapshot.created_at DESC, snapshot.id DESC
    LIMIT $2
    "#
}

fn snapshot_list_sqlite_sql() -> &'static str {
    r#"
    SELECT
        snapshot.id,
        snapshot.tenant_id,
        snapshot.product_id,
        product.name AS product_name,
        snapshot.cra_applicable,
        snapshot.ai_act_applicable,
        snapshot.iec62443_applicable,
        snapshot.iso_sae_21434_applicable,
        snapshot.cra_readiness_percent,
        snapshot.ai_act_readiness_percent,
        snapshot.iec62443_readiness_percent,
        snapshot.iso_sae_21434_readiness_percent,
        snapshot.threat_model_coverage_percent,
        snapshot.psirt_readiness_percent,
        snapshot.open_vulnerability_count,
        snapshot.critical_vulnerability_count,
        snapshot.summary,
        CAST(snapshot.created_at AS TEXT) AS created_at,
        CAST(snapshot.updated_at AS TEXT) AS updated_at
    FROM product_security_productsecuritysnapshot snapshot
    INNER JOIN product_security_product product
        ON product.id = snapshot.product_id AND product.tenant_id = snapshot.tenant_id
    WHERE snapshot.tenant_id = ?
    ORDER BY snapshot.created_at DESC, snapshot.id DESC
    LIMIT ?
    "#
}

fn snapshot_detail_postgres_sql() -> &'static str {
    r#"
    SELECT
        snapshot.id,
        snapshot.tenant_id,
        snapshot.product_id,
        product.name AS product_name,
        snapshot.cra_applicable,
        snapshot.ai_act_applicable,
        snapshot.iec62443_applicable,
        snapshot.iso_sae_21434_applicable,
        snapshot.cra_readiness_percent,
        snapshot.ai_act_readiness_percent,
        snapshot.iec62443_readiness_percent,
        snapshot.iso_sae_21434_readiness_percent,
        snapshot.threat_model_coverage_percent,
        snapshot.psirt_readiness_percent,
        snapshot.open_vulnerability_count,
        snapshot.critical_vulnerability_count,
        snapshot.summary,
        snapshot.created_at::text AS created_at,
        snapshot.updated_at::text AS updated_at
    FROM product_security_productsecuritysnapshot snapshot
    INNER JOIN product_security_product product
        ON product.id = snapshot.product_id AND product.tenant_id = snapshot.tenant_id
    WHERE snapshot.tenant_id = $1 AND snapshot.product_id = $2
    ORDER BY snapshot.created_at DESC, snapshot.id DESC
    LIMIT 1
    "#
}

fn snapshot_detail_sqlite_sql() -> &'static str {
    r#"
    SELECT
        snapshot.id,
        snapshot.tenant_id,
        snapshot.product_id,
        product.name AS product_name,
        snapshot.cra_applicable,
        snapshot.ai_act_applicable,
        snapshot.iec62443_applicable,
        snapshot.iso_sae_21434_applicable,
        snapshot.cra_readiness_percent,
        snapshot.ai_act_readiness_percent,
        snapshot.iec62443_readiness_percent,
        snapshot.iso_sae_21434_readiness_percent,
        snapshot.threat_model_coverage_percent,
        snapshot.psirt_readiness_percent,
        snapshot.open_vulnerability_count,
        snapshot.critical_vulnerability_count,
        snapshot.summary,
        CAST(snapshot.created_at AS TEXT) AS created_at,
        CAST(snapshot.updated_at AS TEXT) AS updated_at
    FROM product_security_productsecuritysnapshot snapshot
    INNER JOIN product_security_product product
        ON product.id = snapshot.product_id AND product.tenant_id = snapshot.tenant_id
    WHERE snapshot.tenant_id = ? AND snapshot.product_id = ?
    ORDER BY snapshot.created_at DESC, snapshot.id DESC
    LIMIT 1
    "#
}

fn roadmap_detail_postgres_sql() -> &'static str {
    r#"
    SELECT
        id,
        tenant_id,
        product_id,
        title,
        summary,
        generated_from_snapshot_id,
        created_at::text AS created_at,
        updated_at::text AS updated_at
    FROM product_security_productsecurityroadmap
    WHERE tenant_id = $1 AND product_id = $2
    ORDER BY created_at DESC, id DESC
    LIMIT 1
    "#
}

fn roadmap_detail_sqlite_sql() -> &'static str {
    r#"
    SELECT
        id,
        tenant_id,
        product_id,
        title,
        summary,
        generated_from_snapshot_id,
        CAST(created_at AS TEXT) AS created_at,
        CAST(updated_at AS TEXT) AS updated_at
    FROM product_security_productsecurityroadmap
    WHERE tenant_id = ? AND product_id = ?
    ORDER BY created_at DESC, id DESC
    LIMIT 1
    "#
}

fn roadmap_tasks_postgres_sql() -> &'static str {
    r#"
    SELECT
        task.id,
        task.tenant_id,
        task.roadmap_id,
        task.related_release_id,
        release.version AS related_release_version,
        task.related_vulnerability_id,
        vuln.title AS related_vulnerability_title,
        task.phase,
        task.title,
        task.description,
        task.priority,
        task.owner_role,
        task.due_in_days,
        task.dependency_text,
        task.status,
        task.created_at::text AS created_at,
        task.updated_at::text AS updated_at
    FROM product_security_productsecurityroadmaptask task
    LEFT JOIN product_security_productrelease release
        ON release.id = task.related_release_id AND release.tenant_id = task.tenant_id
    LEFT JOIN product_security_vulnerability vuln
        ON vuln.id = task.related_vulnerability_id AND vuln.tenant_id = task.tenant_id
    WHERE task.tenant_id = $1 AND task.roadmap_id = $2
    ORDER BY task.phase ASC, task.priority ASC, task.title ASC, task.id ASC
    "#
}

fn roadmap_tasks_sqlite_sql() -> &'static str {
    r#"
    SELECT
        task.id,
        task.tenant_id,
        task.roadmap_id,
        task.related_release_id,
        release.version AS related_release_version,
        task.related_vulnerability_id,
        vuln.title AS related_vulnerability_title,
        task.phase,
        task.title,
        task.description,
        task.priority,
        task.owner_role,
        task.due_in_days,
        task.dependency_text,
        task.status,
        CAST(task.created_at AS TEXT) AS created_at,
        CAST(task.updated_at AS TEXT) AS updated_at
    FROM product_security_productsecurityroadmaptask task
    LEFT JOIN product_security_productrelease release
        ON release.id = task.related_release_id AND release.tenant_id = task.tenant_id
    LEFT JOIN product_security_vulnerability vuln
        ON vuln.id = task.related_vulnerability_id AND vuln.tenant_id = task.tenant_id
    WHERE task.tenant_id = ? AND task.roadmap_id = ?
    ORDER BY task.phase ASC, task.priority ASC, task.title ASC, task.id ASC
    "#
}

fn posture_postgres_sql() -> &'static str {
    r#"
    SELECT
        (SELECT COUNT(*) FROM product_security_product WHERE tenant_id = $1) AS products,
        (SELECT COUNT(*) FROM product_security_productrelease WHERE tenant_id = $1 AND status = 'ACTIVE') AS active_releases,
        (SELECT COUNT(*) FROM product_security_threatmodel WHERE tenant_id = $1) AS threat_models,
        (SELECT COUNT(*) FROM product_security_tara WHERE tenant_id = $1) AS taras,
        (SELECT COUNT(*) FROM product_security_vulnerability WHERE tenant_id = $1 AND status NOT IN ('FIXED', 'ACCEPTED')) AS open_vulnerabilities,
        (SELECT COUNT(*) FROM product_security_vulnerability WHERE tenant_id = $1 AND status NOT IN ('FIXED', 'ACCEPTED') AND severity = 'CRITICAL') AS critical_open_vulnerabilities,
        (SELECT COUNT(*) FROM product_security_psirtcase WHERE tenant_id = $1 AND status <> 'CLOSED') AS psirt_cases_open,
        (SELECT COUNT(*) FROM product_security_securityadvisory WHERE tenant_id = $1 AND status = 'PUBLISHED') AS published_advisories,
        COALESCE((SELECT CAST(AVG(threat_model_coverage_percent) AS BIGINT) FROM product_security_productsecuritysnapshot WHERE tenant_id = $1), 0) AS avg_threat_model_coverage,
        COALESCE((SELECT CAST(AVG(psirt_readiness_percent) AS BIGINT) FROM product_security_productsecuritysnapshot WHERE tenant_id = $1), 0) AS avg_psirt_readiness
    "#
}

fn posture_sqlite_sql() -> &'static str {
    r#"
    SELECT
        (SELECT COUNT(*) FROM product_security_product WHERE tenant_id = ?) AS products,
        (SELECT COUNT(*) FROM product_security_productrelease WHERE tenant_id = ? AND status = 'ACTIVE') AS active_releases,
        (SELECT COUNT(*) FROM product_security_threatmodel WHERE tenant_id = ? ) AS threat_models,
        (SELECT COUNT(*) FROM product_security_tara WHERE tenant_id = ?) AS taras,
        (SELECT COUNT(*) FROM product_security_vulnerability WHERE tenant_id = ? AND status NOT IN ('FIXED', 'ACCEPTED')) AS open_vulnerabilities,
        (SELECT COUNT(*) FROM product_security_vulnerability WHERE tenant_id = ? AND status NOT IN ('FIXED', 'ACCEPTED') AND severity = 'CRITICAL') AS critical_open_vulnerabilities,
        (SELECT COUNT(*) FROM product_security_psirtcase WHERE tenant_id = ? AND status <> 'CLOSED') AS psirt_cases_open,
        (SELECT COUNT(*) FROM product_security_securityadvisory WHERE tenant_id = ? AND status = 'PUBLISHED') AS published_advisories,
        COALESCE((SELECT CAST(AVG(threat_model_coverage_percent) AS INTEGER) FROM product_security_productsecuritysnapshot WHERE tenant_id = ?), 0) AS avg_threat_model_coverage,
        COALESCE((SELECT CAST(AVG(psirt_readiness_percent) AS INTEGER) FROM product_security_productsecuritysnapshot WHERE tenant_id = ?), 0) AS avg_psirt_readiness
    "#
}

fn tenant_context_from_pg_row(row: PgRow) -> Result<TenantProductSecurityContext, sqlx::Error> {
    Ok(TenantProductSecurityContext {
        sector: row.try_get("sector")?,
        develops_digital_products: row.try_get("develops_digital_products")?,
        uses_ai_systems: row.try_get("uses_ai_systems")?,
        ot_iacs_scope: row.try_get("ot_iacs_scope")?,
        automotive_scope: row.try_get("automotive_scope")?,
    })
}

fn tenant_context_from_sqlite_row(
    row: SqliteRow,
) -> Result<TenantProductSecurityContext, sqlx::Error> {
    Ok(TenantProductSecurityContext {
        sector: row.try_get("sector")?,
        develops_digital_products: row.try_get("develops_digital_products")?,
        uses_ai_systems: row.try_get("uses_ai_systems")?,
        ot_iacs_scope: row.try_get("ot_iacs_scope")?,
        automotive_scope: row.try_get("automotive_scope")?,
    })
}

fn product_from_pg_row(row: PgRow) -> Result<ProductListItem, sqlx::Error> {
    Ok(ProductListItem {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        family_id: row.try_get("family_id")?,
        family_name: row.try_get("family_name")?,
        name: row.try_get("name")?,
        code: row.try_get("code")?,
        description: row.try_get("description")?,
        has_digital_elements: row.try_get("has_digital_elements")?,
        includes_ai: row.try_get("includes_ai")?,
        ot_iacs_context: row.try_get("ot_iacs_context")?,
        automotive_context: row.try_get("automotive_context")?,
        support_window_months: row.try_get("support_window_months")?,
        release_count: row.try_get("release_count")?,
        threat_model_count: row.try_get("threat_model_count")?,
        tara_count: row.try_get("tara_count")?,
        vulnerability_count: row.try_get("vulnerability_count")?,
        psirt_case_count: row.try_get("psirt_case_count")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn product_from_sqlite_row(row: SqliteRow) -> Result<ProductListItem, sqlx::Error> {
    Ok(ProductListItem {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        family_id: row.try_get("family_id")?,
        family_name: row.try_get("family_name")?,
        name: row.try_get("name")?,
        code: row.try_get("code")?,
        description: row.try_get("description")?,
        has_digital_elements: row.try_get("has_digital_elements")?,
        includes_ai: row.try_get("includes_ai")?,
        ot_iacs_context: row.try_get("ot_iacs_context")?,
        automotive_context: row.try_get("automotive_context")?,
        support_window_months: row.try_get("support_window_months")?,
        release_count: row.try_get("release_count")?,
        threat_model_count: row.try_get("threat_model_count")?,
        tara_count: row.try_get("tara_count")?,
        vulnerability_count: row.try_get("vulnerability_count")?,
        psirt_case_count: row.try_get("psirt_case_count")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn snapshot_from_pg_row(row: PgRow) -> Result<ProductSecuritySnapshotSummary, sqlx::Error> {
    Ok(ProductSecuritySnapshotSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        product_name: row.try_get("product_name")?,
        cra_applicable: row.try_get("cra_applicable")?,
        ai_act_applicable: row.try_get("ai_act_applicable")?,
        iec62443_applicable: row.try_get("iec62443_applicable")?,
        iso_sae_21434_applicable: row.try_get("iso_sae_21434_applicable")?,
        cra_readiness_percent: row.try_get("cra_readiness_percent")?,
        ai_act_readiness_percent: row.try_get("ai_act_readiness_percent")?,
        iec62443_readiness_percent: row.try_get("iec62443_readiness_percent")?,
        iso_sae_21434_readiness_percent: row.try_get("iso_sae_21434_readiness_percent")?,
        threat_model_coverage_percent: row.try_get("threat_model_coverage_percent")?,
        psirt_readiness_percent: row.try_get("psirt_readiness_percent")?,
        open_vulnerability_count: row.try_get("open_vulnerability_count")?,
        critical_vulnerability_count: row.try_get("critical_vulnerability_count")?,
        summary: row.try_get("summary")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn snapshot_from_sqlite_row(row: SqliteRow) -> Result<ProductSecuritySnapshotSummary, sqlx::Error> {
    Ok(ProductSecuritySnapshotSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        product_name: row.try_get("product_name")?,
        cra_applicable: row.try_get("cra_applicable")?,
        ai_act_applicable: row.try_get("ai_act_applicable")?,
        iec62443_applicable: row.try_get("iec62443_applicable")?,
        iso_sae_21434_applicable: row.try_get("iso_sae_21434_applicable")?,
        cra_readiness_percent: row.try_get("cra_readiness_percent")?,
        ai_act_readiness_percent: row.try_get("ai_act_readiness_percent")?,
        iec62443_readiness_percent: row.try_get("iec62443_readiness_percent")?,
        iso_sae_21434_readiness_percent: row.try_get("iso_sae_21434_readiness_percent")?,
        threat_model_coverage_percent: row.try_get("threat_model_coverage_percent")?,
        psirt_readiness_percent: row.try_get("psirt_readiness_percent")?,
        open_vulnerability_count: row.try_get("open_vulnerability_count")?,
        critical_vulnerability_count: row.try_get("critical_vulnerability_count")?,
        summary: row.try_get("summary")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn release_from_pg_row(row: PgRow) -> Result<ProductReleaseSummary, sqlx::Error> {
    let status: String = row.try_get("status")?;
    Ok(ProductReleaseSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        version: row.try_get("version")?,
        status_label: release_status_label(&status),
        status,
        release_date: row.try_get("release_date")?,
        support_end_date: row.try_get("support_end_date")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn release_from_sqlite_row(row: SqliteRow) -> Result<ProductReleaseSummary, sqlx::Error> {
    let status: String = row.try_get("status")?;
    Ok(ProductReleaseSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        version: row.try_get("version")?,
        status_label: release_status_label(&status),
        status,
        release_date: row.try_get("release_date")?,
        support_end_date: row.try_get("support_end_date")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn component_from_pg_row(row: PgRow) -> Result<ProductComponentSummary, sqlx::Error> {
    let component_type: String = row.try_get("component_type")?;
    Ok(ProductComponentSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        supplier_id: row.try_get("supplier_id")?,
        supplier_name: row.try_get("supplier_name")?,
        name: row.try_get("name")?,
        component_type_label: component_type_label(&component_type),
        component_type,
        version: row.try_get("version")?,
        is_open_source: row.try_get("is_open_source")?,
        has_sbom: row.try_get("has_sbom")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn component_from_sqlite_row(row: SqliteRow) -> Result<ProductComponentSummary, sqlx::Error> {
    let component_type: String = row.try_get("component_type")?;
    Ok(ProductComponentSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        supplier_id: row.try_get("supplier_id")?,
        supplier_name: row.try_get("supplier_name")?,
        name: row.try_get("name")?,
        component_type_label: component_type_label(&component_type),
        component_type,
        version: row.try_get("version")?,
        is_open_source: row.try_get("is_open_source")?,
        has_sbom: row.try_get("has_sbom")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn threat_model_from_pg_row(row: PgRow) -> Result<ThreatModelSummary, sqlx::Error> {
    let status: String = row.try_get("status")?;
    Ok(ThreatModelSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        release_id: row.try_get("release_id")?,
        release_version: row.try_get("release_version")?,
        name: row.try_get("name")?,
        methodology: row.try_get("methodology")?,
        summary: row.try_get("summary")?,
        status_label: threat_model_status_label(&status),
        status,
        scenario_count: row.try_get("scenario_count")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn threat_model_from_sqlite_row(row: SqliteRow) -> Result<ThreatModelSummary, sqlx::Error> {
    let status: String = row.try_get("status")?;
    Ok(ThreatModelSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        release_id: row.try_get("release_id")?,
        release_version: row.try_get("release_version")?,
        name: row.try_get("name")?,
        methodology: row.try_get("methodology")?,
        summary: row.try_get("summary")?,
        status_label: threat_model_status_label(&status),
        status,
        scenario_count: row.try_get("scenario_count")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn tara_from_pg_row(row: PgRow) -> Result<TaraSummary, sqlx::Error> {
    let status: String = row.try_get("status")?;
    Ok(TaraSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        release_id: row.try_get("release_id")?,
        release_version: row.try_get("release_version")?,
        scenario_id: row.try_get("scenario_id")?,
        scenario_title: row.try_get("scenario_title")?,
        name: row.try_get("name")?,
        summary: row.try_get("summary")?,
        attack_feasibility: row.try_get("attack_feasibility")?,
        impact_score: row.try_get("impact_score")?,
        risk_score: row.try_get("risk_score")?,
        status_label: tara_status_label(&status),
        status,
        treatment_decision: row.try_get("treatment_decision")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn tara_from_sqlite_row(row: SqliteRow) -> Result<TaraSummary, sqlx::Error> {
    let status: String = row.try_get("status")?;
    Ok(TaraSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        release_id: row.try_get("release_id")?,
        release_version: row.try_get("release_version")?,
        scenario_id: row.try_get("scenario_id")?,
        scenario_title: row.try_get("scenario_title")?,
        name: row.try_get("name")?,
        summary: row.try_get("summary")?,
        attack_feasibility: row.try_get("attack_feasibility")?,
        impact_score: row.try_get("impact_score")?,
        risk_score: row.try_get("risk_score")?,
        status_label: tara_status_label(&status),
        status,
        treatment_decision: row.try_get("treatment_decision")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn vulnerability_from_pg_row(row: PgRow) -> Result<VulnerabilitySummary, sqlx::Error> {
    let severity: String = row.try_get("severity")?;
    let status: String = row.try_get("status")?;
    Ok(VulnerabilitySummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        release_id: row.try_get("release_id")?,
        release_version: row.try_get("release_version")?,
        component_id: row.try_get("component_id")?,
        component_name: row.try_get("component_name")?,
        title: row.try_get("title")?,
        cve: row.try_get("cve")?,
        severity_label: severity_label(&severity),
        severity,
        status_label: vulnerability_status_label(&status),
        status,
        remediation_due: row.try_get("remediation_due")?,
        summary: row.try_get("summary")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn vulnerability_from_sqlite_row(row: SqliteRow) -> Result<VulnerabilitySummary, sqlx::Error> {
    let severity: String = row.try_get("severity")?;
    let status: String = row.try_get("status")?;
    Ok(VulnerabilitySummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        release_id: row.try_get("release_id")?,
        release_version: row.try_get("release_version")?,
        component_id: row.try_get("component_id")?,
        component_name: row.try_get("component_name")?,
        title: row.try_get("title")?,
        cve: row.try_get("cve")?,
        severity_label: severity_label(&severity),
        severity,
        status_label: vulnerability_status_label(&status),
        status,
        remediation_due: row.try_get("remediation_due")?,
        summary: row.try_get("summary")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn ai_system_from_pg_row(row: PgRow) -> Result<AiSystemSummary, sqlx::Error> {
    let risk_classification: String = row.try_get("risk_classification")?;
    Ok(AiSystemSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        product_name: row.try_get("product_name")?,
        name: row.try_get("name")?,
        use_case: row.try_get("use_case")?,
        provider: row.try_get("provider")?,
        risk_classification_label: ai_risk_label(&risk_classification),
        risk_classification,
        in_scope: row.try_get("in_scope")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn ai_system_from_sqlite_row(row: SqliteRow) -> Result<AiSystemSummary, sqlx::Error> {
    let risk_classification: String = row.try_get("risk_classification")?;
    Ok(AiSystemSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        product_name: row.try_get("product_name")?,
        name: row.try_get("name")?,
        use_case: row.try_get("use_case")?,
        provider: row.try_get("provider")?,
        risk_classification_label: ai_risk_label(&risk_classification),
        risk_classification,
        in_scope: row.try_get("in_scope")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn psirt_case_from_pg_row(row: PgRow) -> Result<PsirtCaseSummary, sqlx::Error> {
    let severity: String = row.try_get("severity")?;
    let status: String = row.try_get("status")?;
    Ok(PsirtCaseSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        release_id: row.try_get("release_id")?,
        release_version: row.try_get("release_version")?,
        vulnerability_id: row.try_get("vulnerability_id")?,
        vulnerability_title: row.try_get("vulnerability_title")?,
        case_id: row.try_get("case_id")?,
        title: row.try_get("title")?,
        severity_label: severity_label(&severity),
        severity,
        status_label: psirt_status_label(&status),
        status,
        disclosure_due: row.try_get("disclosure_due")?,
        summary: row.try_get("summary")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn psirt_case_from_sqlite_row(row: SqliteRow) -> Result<PsirtCaseSummary, sqlx::Error> {
    let severity: String = row.try_get("severity")?;
    let status: String = row.try_get("status")?;
    Ok(PsirtCaseSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        release_id: row.try_get("release_id")?,
        release_version: row.try_get("release_version")?,
        vulnerability_id: row.try_get("vulnerability_id")?,
        vulnerability_title: row.try_get("vulnerability_title")?,
        case_id: row.try_get("case_id")?,
        title: row.try_get("title")?,
        severity_label: severity_label(&severity),
        severity,
        status_label: psirt_status_label(&status),
        status,
        disclosure_due: row.try_get("disclosure_due")?,
        summary: row.try_get("summary")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn advisory_from_pg_row(row: PgRow) -> Result<SecurityAdvisorySummary, sqlx::Error> {
    let status: String = row.try_get("status")?;
    Ok(SecurityAdvisorySummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        release_id: row.try_get("release_id")?,
        release_version: row.try_get("release_version")?,
        psirt_case_id: row.try_get("psirt_case_id")?,
        psirt_case_identifier: row.try_get("psirt_case_identifier")?,
        advisory_id: row.try_get("advisory_id")?,
        title: row.try_get("title")?,
        status_label: advisory_status_label(&status),
        status,
        published_on: row.try_get("published_on")?,
        summary: row.try_get("summary")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn advisory_from_sqlite_row(row: SqliteRow) -> Result<SecurityAdvisorySummary, sqlx::Error> {
    let status: String = row.try_get("status")?;
    Ok(SecurityAdvisorySummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        release_id: row.try_get("release_id")?,
        release_version: row.try_get("release_version")?,
        psirt_case_id: row.try_get("psirt_case_id")?,
        psirt_case_identifier: row.try_get("psirt_case_identifier")?,
        advisory_id: row.try_get("advisory_id")?,
        title: row.try_get("title")?,
        status_label: advisory_status_label(&status),
        status,
        published_on: row.try_get("published_on")?,
        summary: row.try_get("summary")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn roadmap_from_pg_row(row: PgRow) -> Result<ProductSecurityRoadmapSummary, sqlx::Error> {
    Ok(ProductSecurityRoadmapSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        title: row.try_get("title")?,
        summary: row.try_get("summary")?,
        generated_from_snapshot_id: row.try_get("generated_from_snapshot_id")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn roadmap_from_sqlite_row(row: SqliteRow) -> Result<ProductSecurityRoadmapSummary, sqlx::Error> {
    Ok(ProductSecurityRoadmapSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        title: row.try_get("title")?,
        summary: row.try_get("summary")?,
        generated_from_snapshot_id: row.try_get("generated_from_snapshot_id")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn roadmap_task_from_pg_row(row: PgRow) -> Result<ProductSecurityRoadmapTaskSummary, sqlx::Error> {
    let phase: String = row.try_get("phase")?;
    let status: String = row.try_get("status")?;
    Ok(ProductSecurityRoadmapTaskSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        roadmap_id: row.try_get("roadmap_id")?,
        related_release_id: row.try_get("related_release_id")?,
        related_release_version: row.try_get("related_release_version")?,
        related_vulnerability_id: row.try_get("related_vulnerability_id")?,
        related_vulnerability_title: row.try_get("related_vulnerability_title")?,
        phase_label: roadmap_phase_label(&phase),
        phase,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        priority: row.try_get("priority")?,
        owner_role: row.try_get("owner_role")?,
        due_in_days: row.try_get("due_in_days")?,
        dependency_text: row.try_get("dependency_text")?,
        status_label: roadmap_task_status_label(&status),
        status,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn roadmap_task_from_sqlite_row(
    row: SqliteRow,
) -> Result<ProductSecurityRoadmapTaskSummary, sqlx::Error> {
    let phase: String = row.try_get("phase")?;
    let status: String = row.try_get("status")?;
    Ok(ProductSecurityRoadmapTaskSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        roadmap_id: row.try_get("roadmap_id")?,
        related_release_id: row.try_get("related_release_id")?,
        related_release_version: row.try_get("related_release_version")?,
        related_vulnerability_id: row.try_get("related_vulnerability_id")?,
        related_vulnerability_title: row.try_get("related_vulnerability_title")?,
        phase_label: roadmap_phase_label(&phase),
        phase,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        priority: row.try_get("priority")?,
        owner_role: row.try_get("owner_role")?,
        due_in_days: row.try_get("due_in_days")?,
        dependency_text: row.try_get("dependency_text")?,
        status_label: roadmap_task_status_label(&status),
        status,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn posture_from_pg_row(row: PgRow) -> anyhow::Result<ProductSecurityPosture> {
    Ok(ProductSecurityPosture {
        products: row.try_get("products")?,
        active_releases: row.try_get("active_releases")?,
        threat_models: row.try_get("threat_models")?,
        taras: row.try_get("taras")?,
        open_vulnerabilities: row.try_get("open_vulnerabilities")?,
        critical_open_vulnerabilities: row.try_get("critical_open_vulnerabilities")?,
        psirt_cases_open: row.try_get("psirt_cases_open")?,
        published_advisories: row.try_get("published_advisories")?,
        avg_threat_model_coverage: row.try_get("avg_threat_model_coverage")?,
        avg_psirt_readiness: row.try_get("avg_psirt_readiness")?,
    })
}

fn posture_from_sqlite_row(row: SqliteRow) -> anyhow::Result<ProductSecurityPosture> {
    Ok(ProductSecurityPosture {
        products: row.try_get("products")?,
        active_releases: row.try_get("active_releases")?,
        threat_models: row.try_get("threat_models")?,
        taras: row.try_get("taras")?,
        open_vulnerabilities: row.try_get("open_vulnerabilities")?,
        critical_open_vulnerabilities: row.try_get("critical_open_vulnerabilities")?,
        psirt_cases_open: row.try_get("psirt_cases_open")?,
        published_advisories: row.try_get("published_advisories")?,
        avg_threat_model_coverage: row.try_get("avg_threat_model_coverage")?,
        avg_psirt_readiness: row.try_get("avg_psirt_readiness")?,
    })
}

fn build_matrix(context: &TenantProductSecurityContext) -> ProductSecurityMatrix {
    let cra = context.develops_digital_products;
    let ai_act = context.uses_ai_systems;
    let iec62443 = context.ot_iacs_scope || is_industrial_sector(&context.sector);
    let iso_sae_21434 = context.automotive_scope;
    let active = [
        (cra, "CRA"),
        (ai_act, "AI Act"),
        (iec62443, "IEC 62443"),
        (iso_sae_21434, "ISO/SAE 21434"),
    ]
    .into_iter()
    .filter_map(|(enabled, label)| enabled.then_some(label))
    .collect::<Vec<_>>();

    ProductSecurityMatrix {
        cra: ProductSecurityMatrixItem {
            applicable: cra,
            label: "CRA".to_string(),
            reason: if cra {
                "Relevant fuer Produkte mit digitalen Elementen und deren Lifecycle.".to_string()
            } else {
                "Derzeit kein klarer Product-with-Digital-Elements-Fokus erkennbar.".to_string()
            },
        },
        ai_act: ProductSecurityMatrixItem {
            applicable: ai_act,
            label: "AI Act".to_string(),
            reason: if ai_act {
                "AI-Systeme/Modelle/Funktionen sind im Scope und erfordern Governance und Dokumentation.".to_string()
            } else {
                "Kein AI-System-/Modell-Scope angegeben.".to_string()
            },
        },
        iec62443: ProductSecurityMatrixItem {
            applicable: iec62443,
            label: "IEC 62443".to_string(),
            reason: if iec62443 {
                "OT-/IACS-/Industrie- oder kritische Anlagenkontexte im Scope.".to_string()
            } else {
                "Kein expliziter OT-/IACS-Kontext im Scope.".to_string()
            },
        },
        iso_sae_21434: ProductSecurityMatrixItem {
            applicable: iso_sae_21434,
            label: "ISO/SAE 21434".to_string(),
            reason: if iso_sae_21434 {
                "Automotive-/Fahrzeug-/E/E-Kontext angegeben.".to_string()
            } else {
                "Kein Automotive-/Fahrzeugkontext im Scope.".to_string()
            },
        },
        summary: if active.is_empty() {
            if context.develops_digital_products {
                "Es werden digitale Produkte entwickelt; mindestens CRA-/Secure-Development-Readiness sollte bewertet werden.".to_string()
            } else {
                "Kein ausgepraegter Product-Security-Scope angegeben. Fokus bleibt auf Enterprise-ISMS.".to_string()
            }
        } else {
            format!(
                "Product Security ist relevant. Aktive Regime/Standards: {}.",
                active.join(", ")
            )
        },
    }
}

fn is_industrial_sector(sector: &str) -> bool {
    matches!(
        sector,
        "ENERGY" | "HYDROGEN" | "DRINKING_WATER" | "WASTEWATER" | "CHEMICALS" | "MANUFACTURING"
    )
}

fn release_status_label(value: &str) -> String {
    match value {
        "PLANNED" => "Geplant",
        "ACTIVE" => "Aktiv",
        "MAINTENANCE" => "Wartung",
        "EOL" => "End of Life",
        _ => value,
    }
    .to_string()
}

fn component_type_label(value: &str) -> String {
    match value {
        "APPLICATION" => "Application",
        "LIBRARY" => "Library",
        "SERVICE" => "Service",
        "MODEL" => "AI Model",
        "FIRMWARE" => "Firmware",
        "OTHER" => "Other",
        _ => value,
    }
    .to_string()
}

fn threat_model_status_label(value: &str) -> String {
    match value {
        "DRAFT" => "Entwurf",
        "REVIEW" => "Im Review",
        "APPROVED" => "Freigegeben",
        _ => value,
    }
    .to_string()
}

fn tara_status_label(value: &str) -> String {
    match value {
        "OPEN" => "Offen",
        "IN_REVIEW" => "Im Review",
        "ACCEPTED" => "Akzeptiert",
        "MITIGATED" => "Mitigiert",
        _ => value,
    }
    .to_string()
}

fn severity_label(value: &str) -> String {
    match value {
        "CRITICAL" => "Kritisch",
        "HIGH" => "Hoch",
        "MEDIUM" => "Mittel",
        "LOW" => "Niedrig",
        _ => value,
    }
    .to_string()
}

fn vulnerability_status_label(value: &str) -> String {
    match value {
        "OPEN" => "Offen",
        "TRIAGED" => "Triagiert",
        "MITIGATED" => "Mitigiert",
        "FIXED" => "Behoben",
        "ACCEPTED" => "Akzeptiert",
        _ => value,
    }
    .to_string()
}

fn ai_risk_label(value: &str) -> String {
    match value {
        "NONE" => "Keine besondere AI-Risiko-Klasse",
        "LIMITED" => "Begrenztes Risiko",
        "HIGH" => "High-Risk / erhöhte Governance",
        "GPAI" => "General Purpose AI / Modellbezug",
        _ => value,
    }
    .to_string()
}

fn psirt_status_label(value: &str) -> String {
    match value {
        "NEW" => "Neu",
        "TRIAGE" => "Triage",
        "INVESTIGATING" => "In Analyse",
        "REMEDIATING" => "In Behebung",
        "ADVISORY" => "Advisory / Disclosure",
        "CLOSED" => "Abgeschlossen",
        _ => value,
    }
    .to_string()
}

fn advisory_status_label(value: &str) -> String {
    match value {
        "DRAFT" => "Entwurf",
        "REVIEW" => "Im Review",
        "PUBLISHED" => "Veröffentlicht",
        _ => value,
    }
    .to_string()
}

fn roadmap_phase_label(value: &str) -> String {
    match value {
        "GOVERNANCE" => "Governance",
        "MODELING" => "Threat Modeling / TARA",
        "DELIVERY" => "Secure Delivery",
        "RESPONSE" => "PSIRT / Response",
        "COMPLIANCE" => "Regulatory Readiness",
        _ => value,
    }
    .to_string()
}

fn roadmap_task_status_label(value: &str) -> String {
    match value {
        "OPEN" => "Offen",
        "PLANNED" => "Geplant",
        "IN_PROGRESS" => "In Umsetzung",
        "DONE" => "Erledigt",
        _ => value,
    }
    .to_string()
}
