use std::collections::BTreeSet;

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
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
    pub component_count: i64,
    pub sbom_component_count: i64,
    pub csaf_advisory_count: i64,
    pub threat_model_count: i64,
    pub tara_count: i64,
    pub vulnerability_count: i64,
    pub cve_count: i64,
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
    pub review_metrics: ProductSecurityReviewMetrics,
    pub trend_dashboard: ProductSecurityTrendDashboard,
    pub products: Vec<ProductListItem>,
    pub snapshots: Vec<ProductSecuritySnapshotSummary>,
    pub import_artifacts: Vec<ProductSecurityImportArtifactSummary>,
    pub cve_correlations: Vec<ProductSecurityCveCorrelationSummary>,
    pub cve_risk_review_queue: Vec<ProductSecurityCveRiskReviewSummary>,
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
    pub cpe23_uri: String,
    pub package_url: String,
    pub sbom_format: String,
    pub sbom_document_url: String,
    pub sbom_digest: String,
    pub sbom_generated_at: Option<String>,
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
    pub cpe23_uri: String,
    pub advisory_ids: Vec<String>,
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
    pub csaf_url: String,
    pub csaf_document_id: String,
    pub csaf_profile: String,
    pub csaf_tracking_status: String,
    pub csaf_revision: String,
    pub cve_list: Vec<String>,
    pub product_status: Value,
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

#[derive(Debug, Clone, Deserialize)]
pub struct ProductSecurityRoadmapTaskUpdateRequest {
    pub status: Option<String>,
    pub priority: Option<String>,
    pub owner_role: Option<String>,
    pub due_in_days: Option<i64>,
    pub dependency_text: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityRoadmapTaskUpdateResult {
    pub product_id: i64,
    pub roadmap_id: i64,
    pub task: ProductSecurityRoadmapTaskSummary,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProductSecurityVulnerabilityUpdateRequest {
    pub severity: Option<String>,
    pub status: Option<String>,
    pub remediation_due: Option<String>,
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityVulnerabilityUpdateResult {
    pub product_id: i64,
    pub vulnerability: VulnerabilitySummary,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProductSecurityArtifactImportRequest {
    pub product_id: Option<i64>,
    pub file_name: String,
    pub document: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityArtifactImportResult {
    pub artifact_id: i64,
    pub artifact_type: String,
    pub validation_status: String,
    pub validation_errors: Vec<String>,
    pub component_count: i64,
    pub matched_component_count: i64,
    pub cve_count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityImportArtifactSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub product_id: Option<i64>,
    pub product_name: Option<String>,
    pub artifact_type: String,
    pub file_name: String,
    pub document_id: String,
    pub format_name: String,
    pub format_version: String,
    pub validation_status: String,
    pub validation_errors: Vec<String>,
    pub component_count: i64,
    pub matched_component_count: i64,
    pub cve_count: i64,
    pub created_by_id: Option<i64>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityImportComponentSummary {
    pub id: i64,
    pub artifact_id: i64,
    pub tenant_id: i64,
    pub product_id: Option<i64>,
    pub product_name: Option<String>,
    pub component_id: Option<i64>,
    pub component_name: Option<String>,
    pub name: String,
    pub version: String,
    pub package_url: String,
    pub cpe23_uri: String,
    pub supplier_name: String,
    pub match_status: String,
    pub match_status_label: String,
    pub match_reason: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityImportArtifactDetail {
    pub artifact: ProductSecurityImportArtifactSummary,
    pub components: Vec<ProductSecurityImportComponentSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityCveCorrelationSummary {
    pub id: i64,
    pub cve: String,
    pub asset_id: Option<i64>,
    pub asset_name: Option<String>,
    pub product_id: Option<i64>,
    pub product_name: Option<String>,
    pub component_id: Option<i64>,
    pub component_name: Option<String>,
    pub match_type: String,
    pub match_value: String,
    pub confidence: i64,
    pub status: String,
    pub rationale: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityReviewMetrics {
    pub open_cve_reviews: i64,
    pub suggested_correlation_reviews: i64,
    pub open_risk_reviews: i64,
    pub evidence_missing: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityTrendDashboard {
    pub coverage: ProductSecurityCoverageTrend,
    pub import_validation: ProductSecurityImportValidationTrend,
    pub signals: Vec<ProductSecurityTrendSignal>,
    pub snapshot_points: Vec<ProductSecuritySnapshotTrendPoint>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityCoverageTrend {
    pub product_count: i64,
    pub component_count: i64,
    pub components_with_sbom: i64,
    pub products_with_csaf: i64,
    pub products_with_threat_tara: i64,
    pub sbom_coverage_percent: i64,
    pub csaf_coverage_percent: i64,
    pub threat_tara_coverage_percent: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityImportValidationTrend {
    pub total_imports: i64,
    pub valid_imports: i64,
    pub warning_imports: i64,
    pub invalid_imports: i64,
    pub validation_error_count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityTrendSignal {
    pub key: String,
    pub label: String,
    pub current: i64,
    pub previous: Option<i64>,
    pub delta: Option<i64>,
    pub direction: String,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecuritySnapshotTrendPoint {
    pub product_id: i64,
    pub product_name: String,
    pub created_at: String,
    pub cra_readiness_percent: i64,
    pub ai_act_readiness_percent: i64,
    pub threat_model_coverage_percent: i64,
    pub psirt_readiness_percent: i64,
    pub open_vulnerability_count: i64,
    pub critical_vulnerability_count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityCveRiskReviewSummary {
    pub correlation_id: i64,
    pub cve: String,
    pub asset_id: Option<i64>,
    pub asset_name: Option<String>,
    pub product_id: Option<i64>,
    pub product_name: Option<String>,
    pub component_id: Option<i64>,
    pub component_name: Option<String>,
    pub match_type: String,
    pub match_value: String,
    pub confidence: i64,
    pub evidence_key: String,
    pub risk_id: Option<i64>,
    pub risk_title: Option<String>,
    pub risk_status: Option<String>,
    pub risk_status_label: String,
    pub roadmap_task_id: Option<i64>,
    pub roadmap_task_title: Option<String>,
    pub roadmap_task_status: Option<String>,
    pub roadmap_task_status_label: String,
    pub evidence_count: i64,
    pub needs_review: bool,
    pub evidence_missing: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityCveCorrelationResult {
    pub created_suggestions: i64,
    pub existing_suggestions: i64,
    pub suggestions: Vec<ProductSecurityCveCorrelationSummary>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProductSecurityCveCorrelationDecisionRequest {
    pub status: String,
    pub rationale: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityCveCorrelationDecisionResult {
    pub correlation: ProductSecurityCveCorrelationSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityAcceptedCorrelationWorkResult {
    pub accepted_correlations: i64,
    pub created_risks: i64,
    pub existing_risks: i64,
    pub created_roadmap_tasks: i64,
    pub existing_roadmap_tasks: i64,
}

#[derive(Debug, Clone)]
struct TenantProductSecurityContext {
    sector: String,
    develops_digital_products: bool,
    uses_ai_systems: bool,
    ot_iacs_scope: bool,
    automotive_scope: bool,
}

struct ProductSecurityRoadmapTaskCurrent {
    product_id: i64,
    roadmap_id: i64,
    status: String,
    priority: String,
    owner_role: String,
    due_in_days: i64,
    dependency_text: String,
}

struct ProductSecurityVulnerabilityCurrent {
    product_id: i64,
    severity: String,
    status: String,
    remediation_due: Option<String>,
    summary: String,
}

struct ProductSecurityRiskLink {
    id: i64,
    title: String,
    status: String,
}

struct ProductSecurityRoadmapTaskLink {
    id: i64,
    title: String,
    status: String,
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

    pub async fn update_roadmap_task(
        &self,
        tenant_id: i64,
        task_id: i64,
        payload: ProductSecurityRoadmapTaskUpdateRequest,
    ) -> anyhow::Result<Option<ProductSecurityRoadmapTaskUpdateResult>> {
        match self {
            Self::Postgres(pool) => {
                update_roadmap_task_postgres(pool, tenant_id, task_id, payload).await
            }
            Self::Sqlite(pool) => {
                update_roadmap_task_sqlite(pool, tenant_id, task_id, payload).await
            }
        }
    }

    pub async fn update_vulnerability(
        &self,
        tenant_id: i64,
        vulnerability_id: i64,
        payload: ProductSecurityVulnerabilityUpdateRequest,
    ) -> anyhow::Result<Option<ProductSecurityVulnerabilityUpdateResult>> {
        match self {
            Self::Postgres(pool) => {
                update_vulnerability_postgres(pool, tenant_id, vulnerability_id, payload).await
            }
            Self::Sqlite(pool) => {
                update_vulnerability_sqlite(pool, tenant_id, vulnerability_id, payload).await
            }
        }
    }

    pub async fn import_csaf(
        &self,
        tenant_id: i64,
        user_id: i64,
        payload: ProductSecurityArtifactImportRequest,
    ) -> anyhow::Result<ProductSecurityArtifactImportResult> {
        match self {
            Self::Postgres(pool) => import_csaf_postgres(pool, tenant_id, user_id, payload).await,
            Self::Sqlite(pool) => import_csaf_sqlite(pool, tenant_id, user_id, payload).await,
        }
    }

    pub async fn import_sbom(
        &self,
        tenant_id: i64,
        user_id: i64,
        payload: ProductSecurityArtifactImportRequest,
    ) -> anyhow::Result<ProductSecurityArtifactImportResult> {
        match self {
            Self::Postgres(pool) => import_sbom_postgres(pool, tenant_id, user_id, payload).await,
            Self::Sqlite(pool) => import_sbom_sqlite(pool, tenant_id, user_id, payload).await,
        }
    }

    pub async fn suggest_cve_asset_correlations(
        &self,
        tenant_id: i64,
    ) -> anyhow::Result<ProductSecurityCveCorrelationResult> {
        match self {
            Self::Postgres(pool) => suggest_cve_asset_correlations_postgres(pool, tenant_id).await,
            Self::Sqlite(pool) => suggest_cve_asset_correlations_sqlite(pool, tenant_id).await,
        }
    }

    pub async fn import_history(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<ProductSecurityImportArtifactSummary>> {
        match self {
            Self::Postgres(pool) => load_import_artifacts_postgres(pool, tenant_id, limit).await,
            Self::Sqlite(pool) => load_import_artifacts_sqlite(pool, tenant_id, limit).await,
        }
    }

    pub async fn import_detail(
        &self,
        tenant_id: i64,
        artifact_id: i64,
    ) -> anyhow::Result<Option<ProductSecurityImportArtifactDetail>> {
        match self {
            Self::Postgres(pool) => load_import_detail_postgres(pool, tenant_id, artifact_id).await,
            Self::Sqlite(pool) => load_import_detail_sqlite(pool, tenant_id, artifact_id).await,
        }
    }

    pub async fn update_cve_correlation(
        &self,
        tenant_id: i64,
        correlation_id: i64,
        payload: ProductSecurityCveCorrelationDecisionRequest,
    ) -> anyhow::Result<Option<ProductSecurityCveCorrelationDecisionResult>> {
        match self {
            Self::Postgres(pool) => {
                update_cve_correlation_postgres(pool, tenant_id, correlation_id, payload).await
            }
            Self::Sqlite(pool) => {
                update_cve_correlation_sqlite(pool, tenant_id, correlation_id, payload).await
            }
        }
    }

    pub async fn generate_work_from_accepted_correlations(
        &self,
        tenant_id: i64,
    ) -> anyhow::Result<ProductSecurityAcceptedCorrelationWorkResult> {
        match self {
            Self::Postgres(pool) => {
                generate_work_from_accepted_correlations_postgres(pool, tenant_id).await
            }
            Self::Sqlite(pool) => {
                generate_work_from_accepted_correlations_sqlite(pool, tenant_id).await
            }
        }
    }

    pub async fn generate_work_for_accepted_correlation(
        &self,
        tenant_id: i64,
        correlation_id: i64,
    ) -> anyhow::Result<ProductSecurityAcceptedCorrelationWorkResult> {
        match self {
            Self::Postgres(pool) => {
                generate_work_for_accepted_correlation_postgres(pool, tenant_id, correlation_id)
                    .await
            }
            Self::Sqlite(pool) => {
                generate_work_for_accepted_correlation_sqlite(pool, tenant_id, correlation_id).await
            }
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
    let import_artifacts = load_import_artifacts_postgres(pool, tenant_id, 20).await?;
    let cve_correlations = load_cve_correlations_postgres(pool, tenant_id, 50).await?;
    let cve_risk_review_queue = load_cve_risk_review_queue_postgres(pool, tenant_id, 50).await?;
    let review_metrics = build_review_metrics(&cve_correlations, &cve_risk_review_queue);
    let trend_dashboard = build_trend_dashboard(
        &products,
        &snapshots,
        &import_artifacts,
        &review_metrics,
        &cve_risk_review_queue,
        &posture,
    );

    Ok(Some(ProductSecurityOverview {
        tenant_id,
        matrix: build_matrix(&context),
        posture,
        review_metrics,
        trend_dashboard,
        products,
        snapshots,
        import_artifacts,
        cve_correlations,
        cve_risk_review_queue,
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
    let import_artifacts = load_import_artifacts_sqlite(pool, tenant_id, 20).await?;
    let cve_correlations = load_cve_correlations_sqlite(pool, tenant_id, 50).await?;
    let cve_risk_review_queue = load_cve_risk_review_queue_sqlite(pool, tenant_id, 50).await?;
    let review_metrics = build_review_metrics(&cve_correlations, &cve_risk_review_queue);
    let trend_dashboard = build_trend_dashboard(
        &products,
        &snapshots,
        &import_artifacts,
        &review_metrics,
        &cve_risk_review_queue,
        &posture,
    );

    Ok(Some(ProductSecurityOverview {
        tenant_id,
        matrix: build_matrix(&context),
        posture,
        review_metrics,
        trend_dashboard,
        products,
        snapshots,
        import_artifacts,
        cve_correlations,
        cve_risk_review_queue,
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

async fn update_roadmap_task_postgres(
    pool: &PgPool,
    tenant_id: i64,
    task_id: i64,
    payload: ProductSecurityRoadmapTaskUpdateRequest,
) -> anyhow::Result<Option<ProductSecurityRoadmapTaskUpdateResult>> {
    let Some(current) = roadmap_task_current_postgres(pool, tenant_id, task_id).await? else {
        return Ok(None);
    };

    let status = payload
        .status
        .as_deref()
        .map(normalize_roadmap_task_status)
        .unwrap_or(current.status);
    let priority = payload
        .priority
        .as_deref()
        .map(normalize_roadmap_task_priority)
        .unwrap_or(current.priority);
    let owner_role = payload
        .owner_role
        .unwrap_or(current.owner_role)
        .trim()
        .to_string();
    let due_in_days = payload
        .due_in_days
        .map(|value| value.max(0))
        .unwrap_or(current.due_in_days);
    let dependency_text = payload.dependency_text.unwrap_or(current.dependency_text);

    sqlx::query(
        r#"
        UPDATE product_security_productsecurityroadmaptask
        SET status = $2,
            priority = $3,
            owner_role = $4,
            due_in_days = $5,
            dependency_text = $6,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(task_id)
    .bind(status)
    .bind(priority)
    .bind(owner_role)
    .bind(due_in_days)
    .bind(dependency_text)
    .execute(pool)
    .await
    .context("PostgreSQL-Product-Security-Roadmaptask konnte nicht aktualisiert werden")?;

    let task = roadmap_task_by_id_postgres(pool, tenant_id, task_id)
        .await?
        .context("Aktualisierter Product-Security-Roadmaptask wurde nicht gefunden")?;
    Ok(Some(ProductSecurityRoadmapTaskUpdateResult {
        product_id: current.product_id,
        roadmap_id: current.roadmap_id,
        task,
    }))
}

async fn update_roadmap_task_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    task_id: i64,
    payload: ProductSecurityRoadmapTaskUpdateRequest,
) -> anyhow::Result<Option<ProductSecurityRoadmapTaskUpdateResult>> {
    let Some(current) = roadmap_task_current_sqlite(pool, tenant_id, task_id).await? else {
        return Ok(None);
    };

    let status = payload
        .status
        .as_deref()
        .map(normalize_roadmap_task_status)
        .unwrap_or(current.status);
    let priority = payload
        .priority
        .as_deref()
        .map(normalize_roadmap_task_priority)
        .unwrap_or(current.priority);
    let owner_role = payload
        .owner_role
        .unwrap_or(current.owner_role)
        .trim()
        .to_string();
    let due_in_days = payload
        .due_in_days
        .map(|value| value.max(0))
        .unwrap_or(current.due_in_days);
    let dependency_text = payload.dependency_text.unwrap_or(current.dependency_text);

    sqlx::query(
        r#"
        UPDATE product_security_productsecurityroadmaptask
        SET status = ?2,
            priority = ?3,
            owner_role = ?4,
            due_in_days = ?5,
            dependency_text = ?6,
            updated_at = datetime('now')
        WHERE id = ?1
        "#,
    )
    .bind(task_id)
    .bind(status)
    .bind(priority)
    .bind(owner_role)
    .bind(due_in_days)
    .bind(dependency_text)
    .execute(pool)
    .await
    .context("SQLite-Product-Security-Roadmaptask konnte nicht aktualisiert werden")?;

    let task = roadmap_task_by_id_sqlite(pool, tenant_id, task_id)
        .await?
        .context("Aktualisierter Product-Security-Roadmaptask wurde nicht gefunden")?;
    Ok(Some(ProductSecurityRoadmapTaskUpdateResult {
        product_id: current.product_id,
        roadmap_id: current.roadmap_id,
        task,
    }))
}

async fn roadmap_task_current_postgres(
    pool: &PgPool,
    tenant_id: i64,
    task_id: i64,
) -> anyhow::Result<Option<ProductSecurityRoadmapTaskCurrent>> {
    sqlx::query(
        r#"
        SELECT
            roadmap.product_id,
            task.roadmap_id,
            task.status,
            task.priority,
            task.owner_role,
            task.due_in_days,
            task.dependency_text
        FROM product_security_productsecurityroadmaptask task
        INNER JOIN product_security_productsecurityroadmap roadmap
            ON roadmap.id = task.roadmap_id AND roadmap.tenant_id = task.tenant_id
        WHERE task.tenant_id = $1 AND task.id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(task_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-Product-Security-Roadmaptask konnte nicht gelesen werden")?
    .map(roadmap_task_current_from_pg_row)
    .transpose()
    .map_err(Into::into)
}

async fn roadmap_task_current_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    task_id: i64,
) -> anyhow::Result<Option<ProductSecurityRoadmapTaskCurrent>> {
    sqlx::query(
        r#"
        SELECT
            roadmap.product_id,
            task.roadmap_id,
            task.status,
            task.priority,
            task.owner_role,
            task.due_in_days,
            task.dependency_text
        FROM product_security_productsecurityroadmaptask task
        INNER JOIN product_security_productsecurityroadmap roadmap
            ON roadmap.id = task.roadmap_id AND roadmap.tenant_id = task.tenant_id
        WHERE task.tenant_id = ? AND task.id = ?
        "#,
    )
    .bind(tenant_id)
    .bind(task_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-Product-Security-Roadmaptask konnte nicht gelesen werden")?
    .map(roadmap_task_current_from_sqlite_row)
    .transpose()
    .map_err(Into::into)
}

async fn roadmap_task_by_id_postgres(
    pool: &PgPool,
    tenant_id: i64,
    task_id: i64,
) -> anyhow::Result<Option<ProductSecurityRoadmapTaskSummary>> {
    sqlx::query(roadmap_task_by_id_postgres_sql())
        .bind(tenant_id)
        .bind(task_id)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-Product-Security-Roadmaptask konnte nicht gelesen werden")?
        .map(roadmap_task_from_pg_row)
        .transpose()
        .map_err(Into::into)
}

async fn roadmap_task_by_id_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    task_id: i64,
) -> anyhow::Result<Option<ProductSecurityRoadmapTaskSummary>> {
    sqlx::query(roadmap_task_by_id_sqlite_sql())
        .bind(tenant_id)
        .bind(task_id)
        .fetch_optional(pool)
        .await
        .context("SQLite-Product-Security-Roadmaptask konnte nicht gelesen werden")?
        .map(roadmap_task_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

async fn update_vulnerability_postgres(
    pool: &PgPool,
    tenant_id: i64,
    vulnerability_id: i64,
    payload: ProductSecurityVulnerabilityUpdateRequest,
) -> anyhow::Result<Option<ProductSecurityVulnerabilityUpdateResult>> {
    let Some(current) = vulnerability_current_postgres(pool, tenant_id, vulnerability_id).await?
    else {
        return Ok(None);
    };

    let severity = payload
        .severity
        .as_deref()
        .map(normalize_vulnerability_severity)
        .unwrap_or_else(|| current.severity.clone());
    let status = payload
        .status
        .as_deref()
        .map(normalize_vulnerability_status)
        .unwrap_or_else(|| current.status.clone());
    let remediation_due = match payload.remediation_due.as_deref() {
        Some(value) => normalize_optional_date_text(value),
        None => current.remediation_due.clone(),
    };
    let summary = payload.summary.unwrap_or_else(|| current.summary.clone());

    sqlx::query(
        r#"
        UPDATE product_security_vulnerability
        SET severity = $2,
            status = $3,
            remediation_due = $4::date,
            summary = $5,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(vulnerability_id)
    .bind(severity)
    .bind(status)
    .bind(remediation_due)
    .bind(summary)
    .execute(pool)
    .await
    .context("PostgreSQL-Product-Security-Vulnerability konnte nicht aktualisiert werden")?;

    let vulnerability = vulnerability_by_id_postgres(pool, tenant_id, vulnerability_id)
        .await?
        .context("Aktualisierte Product-Security-Vulnerability wurde nicht gefunden")?;
    Ok(Some(ProductSecurityVulnerabilityUpdateResult {
        product_id: current.product_id,
        vulnerability,
    }))
}

async fn update_vulnerability_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    vulnerability_id: i64,
    payload: ProductSecurityVulnerabilityUpdateRequest,
) -> anyhow::Result<Option<ProductSecurityVulnerabilityUpdateResult>> {
    let Some(current) = vulnerability_current_sqlite(pool, tenant_id, vulnerability_id).await?
    else {
        return Ok(None);
    };

    let severity = payload
        .severity
        .as_deref()
        .map(normalize_vulnerability_severity)
        .unwrap_or_else(|| current.severity.clone());
    let status = payload
        .status
        .as_deref()
        .map(normalize_vulnerability_status)
        .unwrap_or_else(|| current.status.clone());
    let remediation_due = match payload.remediation_due.as_deref() {
        Some(value) => normalize_optional_date_text(value),
        None => current.remediation_due.clone(),
    };
    let summary = payload.summary.unwrap_or_else(|| current.summary.clone());

    sqlx::query(
        r#"
        UPDATE product_security_vulnerability
        SET severity = ?2,
            status = ?3,
            remediation_due = ?4,
            summary = ?5,
            updated_at = datetime('now')
        WHERE id = ?1
        "#,
    )
    .bind(vulnerability_id)
    .bind(severity)
    .bind(status)
    .bind(remediation_due)
    .bind(summary)
    .execute(pool)
    .await
    .context("SQLite-Product-Security-Vulnerability konnte nicht aktualisiert werden")?;

    let vulnerability = vulnerability_by_id_sqlite(pool, tenant_id, vulnerability_id)
        .await?
        .context("Aktualisierte Product-Security-Vulnerability wurde nicht gefunden")?;
    Ok(Some(ProductSecurityVulnerabilityUpdateResult {
        product_id: current.product_id,
        vulnerability,
    }))
}

async fn vulnerability_current_postgres(
    pool: &PgPool,
    tenant_id: i64,
    vulnerability_id: i64,
) -> anyhow::Result<Option<ProductSecurityVulnerabilityCurrent>> {
    sqlx::query(
        r#"
        SELECT
            product_id,
            severity,
            status,
            remediation_due::text AS remediation_due,
            summary
        FROM product_security_vulnerability
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(vulnerability_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-Product-Security-Vulnerability konnte nicht gelesen werden")?
    .map(vulnerability_current_from_pg_row)
    .transpose()
    .map_err(Into::into)
}

async fn vulnerability_current_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    vulnerability_id: i64,
) -> anyhow::Result<Option<ProductSecurityVulnerabilityCurrent>> {
    sqlx::query(
        r#"
        SELECT
            product_id,
            severity,
            status,
            CAST(remediation_due AS TEXT) AS remediation_due,
            summary
        FROM product_security_vulnerability
        WHERE tenant_id = ? AND id = ?
        "#,
    )
    .bind(tenant_id)
    .bind(vulnerability_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-Product-Security-Vulnerability konnte nicht gelesen werden")?
    .map(vulnerability_current_from_sqlite_row)
    .transpose()
    .map_err(Into::into)
}

async fn vulnerability_by_id_postgres(
    pool: &PgPool,
    tenant_id: i64,
    vulnerability_id: i64,
) -> anyhow::Result<Option<VulnerabilitySummary>> {
    sqlx::query(vulnerability_by_id_postgres_sql())
        .bind(tenant_id)
        .bind(vulnerability_id)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-Product-Security-Vulnerability konnte nicht gelesen werden")?
        .map(vulnerability_from_pg_row)
        .transpose()
        .map_err(Into::into)
}

async fn vulnerability_by_id_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    vulnerability_id: i64,
) -> anyhow::Result<Option<VulnerabilitySummary>> {
    sqlx::query(vulnerability_by_id_sqlite_sql())
        .bind(tenant_id)
        .bind(vulnerability_id)
        .fetch_optional(pool)
        .await
        .context("SQLite-Product-Security-Vulnerability konnte nicht gelesen werden")?
        .map(vulnerability_from_sqlite_row)
        .transpose()
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
        (SELECT COUNT(*) FROM product_security_component component WHERE component.product_id = product.id AND component.tenant_id = product.tenant_id) AS component_count,
        (SELECT COUNT(*) FROM product_security_component component WHERE component.product_id = product.id AND component.tenant_id = product.tenant_id AND component.has_sbom = TRUE) AS sbom_component_count,
        (SELECT COUNT(*) FROM product_security_securityadvisory advisory WHERE advisory.product_id = product.id AND advisory.tenant_id = product.tenant_id AND advisory.csaf_document_id <> '') AS csaf_advisory_count,
        (SELECT COUNT(*) FROM product_security_threatmodel tm WHERE tm.product_id = product.id AND tm.tenant_id = product.tenant_id) AS threat_model_count,
        (SELECT COUNT(*) FROM product_security_tara tara WHERE tara.product_id = product.id AND tara.tenant_id = product.tenant_id) AS tara_count,
        (SELECT COUNT(*) FROM product_security_vulnerability vuln WHERE vuln.product_id = product.id AND vuln.tenant_id = product.tenant_id) AS vulnerability_count,
        (SELECT COUNT(*) FROM product_security_vulnerability vuln WHERE vuln.product_id = product.id AND vuln.tenant_id = product.tenant_id AND vuln.cve <> '') AS cve_count,
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
        (SELECT COUNT(*) FROM product_security_component component WHERE component.product_id = product.id AND component.tenant_id = product.tenant_id) AS component_count,
        (SELECT COUNT(*) FROM product_security_component component WHERE component.product_id = product.id AND component.tenant_id = product.tenant_id AND component.has_sbom = 1) AS sbom_component_count,
        (SELECT COUNT(*) FROM product_security_securityadvisory advisory WHERE advisory.product_id = product.id AND advisory.tenant_id = product.tenant_id AND advisory.csaf_document_id <> '') AS csaf_advisory_count,
        (SELECT COUNT(*) FROM product_security_threatmodel tm WHERE tm.product_id = product.id AND tm.tenant_id = product.tenant_id) AS threat_model_count,
        (SELECT COUNT(*) FROM product_security_tara tara WHERE tara.product_id = product.id AND tara.tenant_id = product.tenant_id) AS tara_count,
        (SELECT COUNT(*) FROM product_security_vulnerability vuln WHERE vuln.product_id = product.id AND vuln.tenant_id = product.tenant_id) AS vulnerability_count,
        (SELECT COUNT(*) FROM product_security_vulnerability vuln WHERE vuln.product_id = product.id AND vuln.tenant_id = product.tenant_id AND vuln.cve <> '') AS cve_count,
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
        (SELECT COUNT(*) FROM product_security_component component WHERE component.product_id = product.id AND component.tenant_id = product.tenant_id) AS component_count,
        (SELECT COUNT(*) FROM product_security_component component WHERE component.product_id = product.id AND component.tenant_id = product.tenant_id AND component.has_sbom = TRUE) AS sbom_component_count,
        (SELECT COUNT(*) FROM product_security_securityadvisory advisory WHERE advisory.product_id = product.id AND advisory.tenant_id = product.tenant_id AND advisory.csaf_document_id <> '') AS csaf_advisory_count,
        (SELECT COUNT(*) FROM product_security_threatmodel tm WHERE tm.product_id = product.id AND tm.tenant_id = product.tenant_id) AS threat_model_count,
        (SELECT COUNT(*) FROM product_security_tara tara WHERE tara.product_id = product.id AND tara.tenant_id = product.tenant_id) AS tara_count,
        (SELECT COUNT(*) FROM product_security_vulnerability vuln WHERE vuln.product_id = product.id AND vuln.tenant_id = product.tenant_id) AS vulnerability_count,
        (SELECT COUNT(*) FROM product_security_vulnerability vuln WHERE vuln.product_id = product.id AND vuln.tenant_id = product.tenant_id AND vuln.cve <> '') AS cve_count,
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
        (SELECT COUNT(*) FROM product_security_component component WHERE component.product_id = product.id AND component.tenant_id = product.tenant_id) AS component_count,
        (SELECT COUNT(*) FROM product_security_component component WHERE component.product_id = product.id AND component.tenant_id = product.tenant_id AND component.has_sbom = 1) AS sbom_component_count,
        (SELECT COUNT(*) FROM product_security_securityadvisory advisory WHERE advisory.product_id = product.id AND advisory.tenant_id = product.tenant_id AND advisory.csaf_document_id <> '') AS csaf_advisory_count,
        (SELECT COUNT(*) FROM product_security_threatmodel tm WHERE tm.product_id = product.id AND tm.tenant_id = product.tenant_id) AS threat_model_count,
        (SELECT COUNT(*) FROM product_security_tara tara WHERE tara.product_id = product.id AND tara.tenant_id = product.tenant_id) AS tara_count,
        (SELECT COUNT(*) FROM product_security_vulnerability vuln WHERE vuln.product_id = product.id AND vuln.tenant_id = product.tenant_id) AS vulnerability_count,
        (SELECT COUNT(*) FROM product_security_vulnerability vuln WHERE vuln.product_id = product.id AND vuln.tenant_id = product.tenant_id AND vuln.cve <> '') AS cve_count,
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
        component.cpe23_uri,
        component.package_url,
        component.sbom_format,
        component.sbom_document_url,
        component.sbom_digest,
        component.sbom_generated_at::text AS sbom_generated_at,
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
        component.cpe23_uri,
        component.package_url,
        component.sbom_format,
        component.sbom_document_url,
        component.sbom_digest,
        CAST(component.sbom_generated_at AS TEXT) AS sbom_generated_at,
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
        vuln.cpe23_uri,
        vuln.advisory_ids_json,
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
        vuln.cpe23_uri,
        vuln.advisory_ids_json,
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

fn vulnerability_by_id_postgres_sql() -> &'static str {
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
        vuln.cpe23_uri,
        vuln.advisory_ids_json,
        vuln.created_at::text AS created_at,
        vuln.updated_at::text AS updated_at
    FROM product_security_vulnerability vuln
    LEFT JOIN product_security_productrelease release
        ON release.id = vuln.release_id AND release.tenant_id = vuln.tenant_id
    LEFT JOIN product_security_component component
        ON component.id = vuln.component_id AND component.tenant_id = vuln.tenant_id
    WHERE vuln.tenant_id = $1 AND vuln.id = $2
    "#
}

fn vulnerability_by_id_sqlite_sql() -> &'static str {
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
        vuln.cpe23_uri,
        vuln.advisory_ids_json,
        CAST(vuln.created_at AS TEXT) AS created_at,
        CAST(vuln.updated_at AS TEXT) AS updated_at
    FROM product_security_vulnerability vuln
    LEFT JOIN product_security_productrelease release
        ON release.id = vuln.release_id AND release.tenant_id = vuln.tenant_id
    LEFT JOIN product_security_component component
        ON component.id = vuln.component_id AND component.tenant_id = vuln.tenant_id
    WHERE vuln.tenant_id = ? AND vuln.id = ?
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
        advisory.csaf_url,
        advisory.csaf_document_id,
        advisory.csaf_profile,
        advisory.csaf_tracking_status,
        advisory.csaf_revision,
        advisory.cve_list_json,
        advisory.product_status_json,
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
        advisory.csaf_url,
        advisory.csaf_document_id,
        advisory.csaf_profile,
        advisory.csaf_tracking_status,
        advisory.csaf_revision,
        advisory.cve_list_json,
        advisory.product_status_json,
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

fn roadmap_task_by_id_postgres_sql() -> &'static str {
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
    WHERE task.tenant_id = $1 AND task.id = $2
    "#
}

fn roadmap_task_by_id_sqlite_sql() -> &'static str {
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
    WHERE task.tenant_id = ? AND task.id = ?
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

#[derive(Debug, Clone)]
struct CsafImportDocument {
    document_id: String,
    title: String,
    profile: String,
    tracking_status: String,
    revision: String,
    cves: Vec<String>,
    product_status: Value,
    validation_errors: Vec<String>,
}

#[derive(Debug, Clone)]
struct SbomImportDocument {
    format_name: String,
    format_version: String,
    document_id: String,
    components: Vec<SbomImportComponent>,
    validation_errors: Vec<String>,
}

#[derive(Debug, Clone)]
struct SbomImportComponent {
    name: String,
    version: String,
    package_url: String,
    cpe23_uri: String,
    supplier_name: String,
}

#[derive(Debug, Clone)]
struct MatchedSbomImportComponent {
    component: SbomImportComponent,
    component_id: Option<i64>,
    match_status: String,
    match_reason: String,
}

#[derive(Debug, Clone)]
struct CveCorrelationCandidate {
    cve: String,
    asset_id: Option<i64>,
    product_id: Option<i64>,
    component_id: Option<i64>,
    match_type: String,
    match_value: String,
    confidence: i64,
    rationale: String,
}

#[derive(Debug, Clone)]
struct AcceptedCorrelationWorkCandidate {
    correlation_id: i64,
    cve: String,
    asset_id: Option<i64>,
    asset_name: Option<String>,
    product_id: Option<i64>,
    product_name: Option<String>,
    component_id: Option<i64>,
    component_name: Option<String>,
    vulnerability_id: Option<i64>,
    severity: String,
    match_type: String,
    match_value: String,
    confidence: i64,
}

async fn import_csaf_postgres(
    pool: &PgPool,
    tenant_id: i64,
    user_id: i64,
    payload: ProductSecurityArtifactImportRequest,
) -> anyhow::Result<ProductSecurityArtifactImportResult> {
    validate_optional_product_postgres(pool, tenant_id, payload.product_id).await?;
    let document = parse_csaf_document(&payload.document);
    let validation_status = validation_status(&document.validation_errors);
    let artifact_id = insert_import_artifact_postgres(
        pool,
        tenant_id,
        user_id,
        payload.product_id,
        "CSAF",
        &payload.file_name,
        &document.document_id,
        "CSAF",
        "",
        validation_status,
        &document.validation_errors,
        0,
        0,
        document.cves.len() as i64,
    )
    .await?;
    if validation_status != "INVALID" {
        if let Some(product_id) = payload.product_id {
            upsert_csaf_advisory_postgres(
                pool,
                tenant_id,
                product_id,
                &payload.file_name,
                &document,
            )
            .await?;
        }
    }
    Ok(ProductSecurityArtifactImportResult {
        artifact_id,
        artifact_type: "CSAF".to_string(),
        validation_status: validation_status.to_string(),
        validation_errors: document.validation_errors,
        component_count: 0,
        matched_component_count: 0,
        cve_count: document.cves.len() as i64,
    })
}

async fn import_csaf_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    user_id: i64,
    payload: ProductSecurityArtifactImportRequest,
) -> anyhow::Result<ProductSecurityArtifactImportResult> {
    validate_optional_product_sqlite(pool, tenant_id, payload.product_id).await?;
    let document = parse_csaf_document(&payload.document);
    let validation_status = validation_status(&document.validation_errors);
    let artifact_id = insert_import_artifact_sqlite(
        pool,
        tenant_id,
        user_id,
        payload.product_id,
        "CSAF",
        &payload.file_name,
        &document.document_id,
        "CSAF",
        "",
        validation_status,
        &document.validation_errors,
        0,
        0,
        document.cves.len() as i64,
    )
    .await?;
    if validation_status != "INVALID" {
        if let Some(product_id) = payload.product_id {
            upsert_csaf_advisory_sqlite(pool, tenant_id, product_id, &payload.file_name, &document)
                .await?;
        }
    }
    Ok(ProductSecurityArtifactImportResult {
        artifact_id,
        artifact_type: "CSAF".to_string(),
        validation_status: validation_status.to_string(),
        validation_errors: document.validation_errors,
        component_count: 0,
        matched_component_count: 0,
        cve_count: document.cves.len() as i64,
    })
}

async fn import_sbom_postgres(
    pool: &PgPool,
    tenant_id: i64,
    user_id: i64,
    payload: ProductSecurityArtifactImportRequest,
) -> anyhow::Result<ProductSecurityArtifactImportResult> {
    validate_optional_product_postgres(pool, tenant_id, payload.product_id).await?;
    let document = parse_sbom_document(&payload.document);
    let validation_status = validation_status(&document.validation_errors);
    let mut matched_components = Vec::new();
    if validation_status != "INVALID" {
        for component in &document.components {
            let (component_id, match_reason) =
                find_component_match_postgres(pool, tenant_id, payload.product_id, component)
                    .await?;
            matched_components.push(MatchedSbomImportComponent {
                component: component.clone(),
                component_id,
                match_status: if component_id.is_some() {
                    "MATCHED".to_string()
                } else {
                    "UNMATCHED".to_string()
                },
                match_reason,
            });
        }
    }
    let matched_count = matched_components
        .iter()
        .filter(|component| component.component_id.is_some())
        .count() as i64;
    let artifact_id = insert_import_artifact_postgres(
        pool,
        tenant_id,
        user_id,
        payload.product_id,
        "SBOM",
        &payload.file_name,
        &document.document_id,
        &document.format_name,
        &document.format_version,
        validation_status,
        &document.validation_errors,
        document.components.len() as i64,
        matched_count,
        0,
    )
    .await?;
    for component in &matched_components {
        insert_import_component_postgres(
            pool,
            artifact_id,
            tenant_id,
            payload.product_id,
            component,
        )
        .await?;
        if let Some(component_id) = component.component_id {
            mark_component_sbom_postgres(
                pool,
                tenant_id,
                component_id,
                &document.format_name,
                &payload.file_name,
                &component.component,
            )
            .await?;
        }
    }
    Ok(ProductSecurityArtifactImportResult {
        artifact_id,
        artifact_type: "SBOM".to_string(),
        validation_status: validation_status.to_string(),
        validation_errors: document.validation_errors,
        component_count: document.components.len() as i64,
        matched_component_count: matched_count,
        cve_count: 0,
    })
}

async fn import_sbom_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    user_id: i64,
    payload: ProductSecurityArtifactImportRequest,
) -> anyhow::Result<ProductSecurityArtifactImportResult> {
    validate_optional_product_sqlite(pool, tenant_id, payload.product_id).await?;
    let document = parse_sbom_document(&payload.document);
    let validation_status = validation_status(&document.validation_errors);
    let mut matched_components = Vec::new();
    if validation_status != "INVALID" {
        for component in &document.components {
            let (component_id, match_reason) =
                find_component_match_sqlite(pool, tenant_id, payload.product_id, component).await?;
            matched_components.push(MatchedSbomImportComponent {
                component: component.clone(),
                component_id,
                match_status: if component_id.is_some() {
                    "MATCHED".to_string()
                } else {
                    "UNMATCHED".to_string()
                },
                match_reason,
            });
        }
    }
    let matched_count = matched_components
        .iter()
        .filter(|component| component.component_id.is_some())
        .count() as i64;
    let artifact_id = insert_import_artifact_sqlite(
        pool,
        tenant_id,
        user_id,
        payload.product_id,
        "SBOM",
        &payload.file_name,
        &document.document_id,
        &document.format_name,
        &document.format_version,
        validation_status,
        &document.validation_errors,
        document.components.len() as i64,
        matched_count,
        0,
    )
    .await?;
    for component in &matched_components {
        insert_import_component_sqlite(pool, artifact_id, tenant_id, payload.product_id, component)
            .await?;
        if let Some(component_id) = component.component_id {
            mark_component_sbom_sqlite(
                pool,
                tenant_id,
                component_id,
                &document.format_name,
                &payload.file_name,
                &component.component,
            )
            .await?;
        }
    }
    Ok(ProductSecurityArtifactImportResult {
        artifact_id,
        artifact_type: "SBOM".to_string(),
        validation_status: validation_status.to_string(),
        validation_errors: document.validation_errors,
        component_count: document.components.len() as i64,
        matched_component_count: matched_count,
        cve_count: 0,
    })
}

async fn validate_optional_product_postgres(
    pool: &PgPool,
    tenant_id: i64,
    product_id: Option<i64>,
) -> anyhow::Result<()> {
    let Some(product_id) = product_id else {
        return Ok(());
    };
    let exists: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM product_security_product WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(product_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-Produkt fuer Product-Security-Import konnte nicht validiert werden")?;
    if exists.is_none() {
        bail!("Produkt {product_id} wurde fuer diesen Tenant nicht gefunden.");
    }
    Ok(())
}

async fn validate_optional_product_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    product_id: Option<i64>,
) -> anyhow::Result<()> {
    let Some(product_id) = product_id else {
        return Ok(());
    };
    let exists: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM product_security_product WHERE tenant_id = ?1 AND id = ?2",
    )
    .bind(tenant_id)
    .bind(product_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-Produkt fuer Product-Security-Import konnte nicht validiert werden")?;
    if exists.is_none() {
        bail!("Produkt {product_id} wurde fuer diesen Tenant nicht gefunden.");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn insert_import_artifact_postgres(
    pool: &PgPool,
    tenant_id: i64,
    user_id: i64,
    product_id: Option<i64>,
    artifact_type: &str,
    file_name: &str,
    document_id: &str,
    format_name: &str,
    format_version: &str,
    validation_status: &str,
    validation_errors: &[String],
    component_count: i64,
    matched_component_count: i64,
    cve_count: i64,
) -> anyhow::Result<i64> {
    let validation_errors_json =
        serde_json::to_string(validation_errors).unwrap_or_else(|_| "[]".to_string());
    sqlx::query_scalar(
        r#"
        INSERT INTO product_security_importartifact (
            tenant_id, product_id, artifact_type, file_name, document_id,
            format_name, format_version, validation_status, validation_errors_json,
            component_count, matched_component_count, cve_count, created_by_id,
            created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW()::text, NOW()::text)
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(product_id)
    .bind(artifact_type)
    .bind(file_name.trim())
    .bind(document_id.trim())
    .bind(format_name.trim())
    .bind(format_version.trim())
    .bind(validation_status)
    .bind(validation_errors_json)
    .bind(component_count)
    .bind(matched_component_count)
    .bind(cve_count)
    .bind(user_id)
    .fetch_one(pool)
    .await
    .context("PostgreSQL-Product-Security-Importartefakt konnte nicht erstellt werden")
}

#[allow(clippy::too_many_arguments)]
async fn insert_import_artifact_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    user_id: i64,
    product_id: Option<i64>,
    artifact_type: &str,
    file_name: &str,
    document_id: &str,
    format_name: &str,
    format_version: &str,
    validation_status: &str,
    validation_errors: &[String],
    component_count: i64,
    matched_component_count: i64,
    cve_count: i64,
) -> anyhow::Result<i64> {
    let validation_errors_json =
        serde_json::to_string(validation_errors).unwrap_or_else(|_| "[]".to_string());
    let result = sqlx::query(
        r#"
        INSERT INTO product_security_importartifact (
            tenant_id, product_id, artifact_type, file_name, document_id,
            format_name, format_version, validation_status, validation_errors_json,
            component_count, matched_component_count, cve_count, created_by_id,
            created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, datetime('now'), datetime('now'))
        "#,
    )
    .bind(tenant_id)
    .bind(product_id)
    .bind(artifact_type)
    .bind(file_name.trim())
    .bind(document_id.trim())
    .bind(format_name.trim())
    .bind(format_version.trim())
    .bind(validation_status)
    .bind(validation_errors_json)
    .bind(component_count)
    .bind(matched_component_count)
    .bind(cve_count)
    .bind(user_id)
    .execute(pool)
    .await
    .context("SQLite-Product-Security-Importartefakt konnte nicht erstellt werden")?;
    Ok(result.last_insert_rowid())
}

async fn find_component_match_postgres(
    pool: &PgPool,
    tenant_id: i64,
    product_id: Option<i64>,
    component: &SbomImportComponent,
) -> anyhow::Result<(Option<i64>, String)> {
    if !component.package_url.is_empty() {
        if let Some(id) = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT id
            FROM product_security_component
            WHERE tenant_id = $1
              AND ($2::bigint IS NULL OR product_id = $2)
              AND package_url = $3
              AND package_url <> ''
            ORDER BY id ASC
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(product_id)
        .bind(&component.package_url)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-Komponentenmatch per PURL fehlgeschlagen")?
        {
            return Ok((Some(id), "PURL exact match".to_string()));
        }
    }
    if !component.cpe23_uri.is_empty() {
        if let Some(id) = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT id
            FROM product_security_component
            WHERE tenant_id = $1
              AND ($2::bigint IS NULL OR product_id = $2)
              AND cpe23_uri = $3
              AND cpe23_uri <> ''
            ORDER BY id ASC
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(product_id)
        .bind(&component.cpe23_uri)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-Komponentenmatch per CPE fehlgeschlagen")?
        {
            return Ok((Some(id), "CPE exact match".to_string()));
        }
    }
    if !component.name.is_empty() {
        if let Some(id) = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT id
            FROM product_security_component
            WHERE tenant_id = $1
              AND ($2::bigint IS NULL OR product_id = $2)
              AND LOWER(name) = LOWER($3)
              AND version = $4
            ORDER BY id ASC
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(product_id)
        .bind(&component.name)
        .bind(&component.version)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-Komponentenmatch per Name/Version fehlgeschlagen")?
        {
            return Ok((Some(id), "Name and version match".to_string()));
        }
    }
    Ok((None, "No component match".to_string()))
}

async fn find_component_match_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    product_id: Option<i64>,
    component: &SbomImportComponent,
) -> anyhow::Result<(Option<i64>, String)> {
    if !component.package_url.is_empty() {
        if let Some(id) = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT id
            FROM product_security_component
            WHERE tenant_id = ?1
              AND (?2 IS NULL OR product_id = ?2)
              AND package_url = ?3
              AND package_url <> ''
            ORDER BY id ASC
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(product_id)
        .bind(&component.package_url)
        .fetch_optional(pool)
        .await
        .context("SQLite-Komponentenmatch per PURL fehlgeschlagen")?
        {
            return Ok((Some(id), "PURL exact match".to_string()));
        }
    }
    if !component.cpe23_uri.is_empty() {
        if let Some(id) = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT id
            FROM product_security_component
            WHERE tenant_id = ?1
              AND (?2 IS NULL OR product_id = ?2)
              AND cpe23_uri = ?3
              AND cpe23_uri <> ''
            ORDER BY id ASC
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(product_id)
        .bind(&component.cpe23_uri)
        .fetch_optional(pool)
        .await
        .context("SQLite-Komponentenmatch per CPE fehlgeschlagen")?
        {
            return Ok((Some(id), "CPE exact match".to_string()));
        }
    }
    if !component.name.is_empty() {
        if let Some(id) = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT id
            FROM product_security_component
            WHERE tenant_id = ?1
              AND (?2 IS NULL OR product_id = ?2)
              AND LOWER(name) = LOWER(?3)
              AND version = ?4
            ORDER BY id ASC
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(product_id)
        .bind(&component.name)
        .bind(&component.version)
        .fetch_optional(pool)
        .await
        .context("SQLite-Komponentenmatch per Name/Version fehlgeschlagen")?
        {
            return Ok((Some(id), "Name and version match".to_string()));
        }
    }
    Ok((None, "No component match".to_string()))
}

async fn insert_import_component_postgres(
    pool: &PgPool,
    artifact_id: i64,
    tenant_id: i64,
    product_id: Option<i64>,
    component: &MatchedSbomImportComponent,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO product_security_importcomponent (
            artifact_id, tenant_id, product_id, component_id, name, version,
            package_url, cpe23_uri, supplier_name, match_status, match_reason,
            created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW()::text)
        "#,
    )
    .bind(artifact_id)
    .bind(tenant_id)
    .bind(product_id)
    .bind(component.component_id)
    .bind(&component.component.name)
    .bind(&component.component.version)
    .bind(&component.component.package_url)
    .bind(&component.component.cpe23_uri)
    .bind(&component.component.supplier_name)
    .bind(&component.match_status)
    .bind(&component.match_reason)
    .execute(pool)
    .await
    .context("PostgreSQL-SBOM-Importkomponente konnte nicht erstellt werden")?;
    Ok(())
}

async fn insert_import_component_sqlite(
    pool: &SqlitePool,
    artifact_id: i64,
    tenant_id: i64,
    product_id: Option<i64>,
    component: &MatchedSbomImportComponent,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO product_security_importcomponent (
            artifact_id, tenant_id, product_id, component_id, name, version,
            package_url, cpe23_uri, supplier_name, match_status, match_reason,
            created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, datetime('now'))
        "#,
    )
    .bind(artifact_id)
    .bind(tenant_id)
    .bind(product_id)
    .bind(component.component_id)
    .bind(&component.component.name)
    .bind(&component.component.version)
    .bind(&component.component.package_url)
    .bind(&component.component.cpe23_uri)
    .bind(&component.component.supplier_name)
    .bind(&component.match_status)
    .bind(&component.match_reason)
    .execute(pool)
    .await
    .context("SQLite-SBOM-Importkomponente konnte nicht erstellt werden")?;
    Ok(())
}

async fn mark_component_sbom_postgres(
    pool: &PgPool,
    tenant_id: i64,
    component_id: i64,
    format_name: &str,
    file_name: &str,
    component: &SbomImportComponent,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        UPDATE product_security_component
        SET has_sbom = TRUE,
            package_url = CASE WHEN package_url = '' THEN $3 ELSE package_url END,
            cpe23_uri = CASE WHEN cpe23_uri = '' THEN $4 ELSE cpe23_uri END,
            sbom_format = $5,
            sbom_document_url = $6,
            sbom_generated_at = NOW()::text,
            updated_at = NOW()::text
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(component_id)
    .bind(&component.package_url)
    .bind(&component.cpe23_uri)
    .bind(format_name)
    .bind(file_name)
    .execute(pool)
    .await
    .context("PostgreSQL-Komponente konnte nicht als SBOM-abgedeckt markiert werden")?;
    Ok(())
}

async fn mark_component_sbom_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    component_id: i64,
    format_name: &str,
    file_name: &str,
    component: &SbomImportComponent,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        UPDATE product_security_component
        SET has_sbom = 1,
            package_url = CASE WHEN package_url = '' THEN ?3 ELSE package_url END,
            cpe23_uri = CASE WHEN cpe23_uri = '' THEN ?4 ELSE cpe23_uri END,
            sbom_format = ?5,
            sbom_document_url = ?6,
            sbom_generated_at = datetime('now'),
            updated_at = datetime('now')
        WHERE tenant_id = ?1 AND id = ?2
        "#,
    )
    .bind(tenant_id)
    .bind(component_id)
    .bind(&component.package_url)
    .bind(&component.cpe23_uri)
    .bind(format_name)
    .bind(file_name)
    .execute(pool)
    .await
    .context("SQLite-Komponente konnte nicht als SBOM-abgedeckt markiert werden")?;
    Ok(())
}

async fn upsert_csaf_advisory_postgres(
    pool: &PgPool,
    tenant_id: i64,
    product_id: i64,
    file_name: &str,
    document: &CsafImportDocument,
) -> anyhow::Result<()> {
    let cve_list_json = serde_json::to_string(&document.cves).unwrap_or_else(|_| "[]".to_string());
    let product_status_json =
        serde_json::to_string(&document.product_status).unwrap_or_else(|_| "{}".to_string());
    if let Some(id) = sqlx::query_scalar::<_, i64>(
        "SELECT id FROM product_security_securityadvisory WHERE tenant_id = $1 AND csaf_document_id = $2 ORDER BY id ASC LIMIT 1",
    )
    .bind(tenant_id)
    .bind(&document.document_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-CSAF-Advisory konnte nicht gesucht werden")?
    {
        sqlx::query(
            r#"
            UPDATE product_security_securityadvisory
            SET title = $3,
                status = $4,
                summary = $5,
                csaf_url = $6,
                csaf_profile = $7,
                csaf_tracking_status = $8,
                csaf_revision = $9,
                cve_list_json = $10,
                product_status_json = $11,
                updated_at = NOW()::text
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&document.title)
        .bind(csaf_advisory_status(&document.tracking_status))
        .bind(format!("CSAF importiert mit {} CVEs.", document.cves.len()))
        .bind(file_name)
        .bind(&document.profile)
        .bind(&document.tracking_status)
        .bind(&document.revision)
        .bind(cve_list_json)
        .bind(product_status_json)
        .execute(pool)
        .await
        .context("PostgreSQL-CSAF-Advisory konnte nicht aktualisiert werden")?;
        return Ok(());
    }
    sqlx::query(
        r#"
        INSERT INTO product_security_securityadvisory (
            tenant_id, product_id, release_id, psirt_case_id, advisory_id,
            title, status, published_on, summary, csaf_url, csaf_document_id,
            csaf_profile, csaf_tracking_status, csaf_revision, cve_list_json,
            product_status_json, created_at, updated_at
        )
        VALUES ($1, $2, NULL, NULL, $3, $4, $5, NULL, $6, $7, $8, $9, $10, $11, $12, $13, NOW()::text, NOW()::text)
        "#,
    )
    .bind(tenant_id)
    .bind(product_id)
    .bind(&document.document_id)
    .bind(&document.title)
    .bind(csaf_advisory_status(&document.tracking_status))
    .bind(format!("CSAF importiert mit {} CVEs.", document.cves.len()))
    .bind(file_name)
    .bind(&document.document_id)
    .bind(&document.profile)
    .bind(&document.tracking_status)
    .bind(&document.revision)
    .bind(cve_list_json)
    .bind(product_status_json)
    .execute(pool)
    .await
    .context("PostgreSQL-CSAF-Advisory konnte nicht erstellt werden")?;
    Ok(())
}

async fn upsert_csaf_advisory_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    product_id: i64,
    file_name: &str,
    document: &CsafImportDocument,
) -> anyhow::Result<()> {
    let cve_list_json = serde_json::to_string(&document.cves).unwrap_or_else(|_| "[]".to_string());
    let product_status_json =
        serde_json::to_string(&document.product_status).unwrap_or_else(|_| "{}".to_string());
    if let Some(id) = sqlx::query_scalar::<_, i64>(
        "SELECT id FROM product_security_securityadvisory WHERE tenant_id = ?1 AND csaf_document_id = ?2 ORDER BY id ASC LIMIT 1",
    )
    .bind(tenant_id)
    .bind(&document.document_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-CSAF-Advisory konnte nicht gesucht werden")?
    {
        sqlx::query(
            r#"
            UPDATE product_security_securityadvisory
            SET title = ?3,
                status = ?4,
                summary = ?5,
                csaf_url = ?6,
                csaf_profile = ?7,
                csaf_tracking_status = ?8,
                csaf_revision = ?9,
                cve_list_json = ?10,
                product_status_json = ?11,
                updated_at = datetime('now')
            WHERE tenant_id = ?1 AND id = ?2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&document.title)
        .bind(csaf_advisory_status(&document.tracking_status))
        .bind(format!("CSAF importiert mit {} CVEs.", document.cves.len()))
        .bind(file_name)
        .bind(&document.profile)
        .bind(&document.tracking_status)
        .bind(&document.revision)
        .bind(cve_list_json)
        .bind(product_status_json)
        .execute(pool)
        .await
        .context("SQLite-CSAF-Advisory konnte nicht aktualisiert werden")?;
        return Ok(());
    }
    sqlx::query(
        r#"
        INSERT INTO product_security_securityadvisory (
            tenant_id, product_id, release_id, psirt_case_id, advisory_id,
            title, status, published_on, summary, csaf_url, csaf_document_id,
            csaf_profile, csaf_tracking_status, csaf_revision, cve_list_json,
            product_status_json, created_at, updated_at
        )
        VALUES (?1, ?2, NULL, NULL, ?3, ?4, ?5, NULL, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, datetime('now'), datetime('now'))
        "#,
    )
    .bind(tenant_id)
    .bind(product_id)
    .bind(&document.document_id)
    .bind(&document.title)
    .bind(csaf_advisory_status(&document.tracking_status))
    .bind(format!("CSAF importiert mit {} CVEs.", document.cves.len()))
    .bind(file_name)
    .bind(&document.document_id)
    .bind(&document.profile)
    .bind(&document.tracking_status)
    .bind(&document.revision)
    .bind(cve_list_json)
    .bind(product_status_json)
    .execute(pool)
    .await
    .context("SQLite-CSAF-Advisory konnte nicht erstellt werden")?;
    Ok(())
}

async fn suggest_cve_asset_correlations_postgres(
    pool: &PgPool,
    tenant_id: i64,
) -> anyhow::Result<ProductSecurityCveCorrelationResult> {
    let mut candidates = cve_correlation_candidates_by_cpe_postgres(pool, tenant_id).await?;
    candidates.extend(cve_correlation_candidates_by_purl_postgres(pool, tenant_id).await?);
    let mut created = 0_i64;
    let mut existing = 0_i64;
    for candidate in candidates {
        let result = sqlx::query(
            r#"
            INSERT INTO product_security_cvecorrelation (
                tenant_id, cve_record_id, cve, asset_id, product_id, component_id,
                match_type, match_value, confidence, status, rationale, created_at, updated_at
            )
            VALUES ($1, NULL, $2, $3, $4, $5, $6, $7, $8, 'SUGGESTED', $9, NOW()::text, NOW()::text)
            ON CONFLICT(tenant_id, cve, match_type, match_value) DO NOTHING
            "#,
        )
        .bind(tenant_id)
        .bind(&candidate.cve)
        .bind(candidate.asset_id)
        .bind(candidate.product_id)
        .bind(candidate.component_id)
        .bind(&candidate.match_type)
        .bind(&candidate.match_value)
        .bind(candidate.confidence)
        .bind(&candidate.rationale)
        .execute(pool)
        .await
        .context("PostgreSQL-CVE-Asset-Korrelation konnte nicht vorgeschlagen werden")?;
        if result.rows_affected() > 0 {
            created += 1;
        } else {
            existing += 1;
        }
    }
    Ok(ProductSecurityCveCorrelationResult {
        created_suggestions: created,
        existing_suggestions: existing,
        suggestions: load_cve_correlations_postgres(pool, tenant_id, 50).await?,
    })
}

async fn suggest_cve_asset_correlations_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
) -> anyhow::Result<ProductSecurityCveCorrelationResult> {
    let mut candidates = cve_correlation_candidates_by_cpe_sqlite(pool, tenant_id).await?;
    candidates.extend(cve_correlation_candidates_by_purl_sqlite(pool, tenant_id).await?);
    let mut created = 0_i64;
    let mut existing = 0_i64;
    for candidate in candidates {
        let result = sqlx::query(
            r#"
            INSERT OR IGNORE INTO product_security_cvecorrelation (
                tenant_id, cve_record_id, cve, asset_id, product_id, component_id,
                match_type, match_value, confidence, status, rationale, created_at, updated_at
            )
            VALUES (?1, NULL, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'SUGGESTED', ?9, datetime('now'), datetime('now'))
            "#,
        )
        .bind(tenant_id)
        .bind(&candidate.cve)
        .bind(candidate.asset_id)
        .bind(candidate.product_id)
        .bind(candidate.component_id)
        .bind(&candidate.match_type)
        .bind(&candidate.match_value)
        .bind(candidate.confidence)
        .bind(&candidate.rationale)
        .execute(pool)
        .await
        .context("SQLite-CVE-Asset-Korrelation konnte nicht vorgeschlagen werden")?;
        if result.rows_affected() > 0 {
            created += 1;
        } else {
            existing += 1;
        }
    }
    Ok(ProductSecurityCveCorrelationResult {
        created_suggestions: created,
        existing_suggestions: existing,
        suggestions: load_cve_correlations_sqlite(pool, tenant_id, 50).await?,
    })
}

async fn update_cve_correlation_postgres(
    pool: &PgPool,
    tenant_id: i64,
    correlation_id: i64,
    payload: ProductSecurityCveCorrelationDecisionRequest,
) -> anyhow::Result<Option<ProductSecurityCveCorrelationDecisionResult>> {
    let status = normalize_cve_correlation_status(&payload.status)?;
    let rationale = payload.rationale.unwrap_or_default();
    let result = sqlx::query(
        r#"
        UPDATE product_security_cvecorrelation
        SET status = $3,
            rationale = CASE WHEN $4 = '' THEN rationale ELSE $4 END,
            updated_at = NOW()::text
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(correlation_id)
    .bind(&status)
    .bind(rationale.trim())
    .execute(pool)
    .await
    .context("PostgreSQL-CVE-Asset-Korrelation konnte nicht aktualisiert werden")?;
    if result.rows_affected() == 0 {
        return Ok(None);
    }
    if status == "ACCEPTED" {
        generate_work_for_accepted_correlation_postgres(pool, tenant_id, correlation_id).await?;
    }
    let correlation = load_cve_correlation_postgres(pool, tenant_id, correlation_id).await?;
    Ok(correlation.map(|correlation| ProductSecurityCveCorrelationDecisionResult { correlation }))
}

async fn update_cve_correlation_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    correlation_id: i64,
    payload: ProductSecurityCveCorrelationDecisionRequest,
) -> anyhow::Result<Option<ProductSecurityCveCorrelationDecisionResult>> {
    let status = normalize_cve_correlation_status(&payload.status)?;
    let rationale = payload.rationale.unwrap_or_default();
    let result = sqlx::query(
        r#"
        UPDATE product_security_cvecorrelation
        SET status = ?3,
            rationale = CASE WHEN ?4 = '' THEN rationale ELSE ?4 END,
            updated_at = datetime('now')
        WHERE tenant_id = ?1 AND id = ?2
        "#,
    )
    .bind(tenant_id)
    .bind(correlation_id)
    .bind(&status)
    .bind(rationale.trim())
    .execute(pool)
    .await
    .context("SQLite-CVE-Asset-Korrelation konnte nicht aktualisiert werden")?;
    if result.rows_affected() == 0 {
        return Ok(None);
    }
    if status == "ACCEPTED" {
        generate_work_for_accepted_correlation_sqlite(pool, tenant_id, correlation_id).await?;
    }
    let correlation = load_cve_correlation_sqlite(pool, tenant_id, correlation_id).await?;
    Ok(correlation.map(|correlation| ProductSecurityCveCorrelationDecisionResult { correlation }))
}

async fn generate_work_from_accepted_correlations_postgres(
    pool: &PgPool,
    tenant_id: i64,
) -> anyhow::Result<ProductSecurityAcceptedCorrelationWorkResult> {
    let mut result = ProductSecurityAcceptedCorrelationWorkResult {
        accepted_correlations: 0,
        created_risks: 0,
        existing_risks: 0,
        created_roadmap_tasks: 0,
        existing_roadmap_tasks: 0,
    };
    for candidate in accepted_correlation_candidates_postgres(pool, tenant_id, None).await? {
        result.accepted_correlations += 1;
        let work = generate_work_for_candidate_postgres(pool, tenant_id, &candidate).await?;
        result.created_risks += work.created_risks;
        result.existing_risks += work.existing_risks;
        result.created_roadmap_tasks += work.created_roadmap_tasks;
        result.existing_roadmap_tasks += work.existing_roadmap_tasks;
    }
    Ok(result)
}

async fn generate_work_from_accepted_correlations_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
) -> anyhow::Result<ProductSecurityAcceptedCorrelationWorkResult> {
    let mut result = ProductSecurityAcceptedCorrelationWorkResult {
        accepted_correlations: 0,
        created_risks: 0,
        existing_risks: 0,
        created_roadmap_tasks: 0,
        existing_roadmap_tasks: 0,
    };
    for candidate in accepted_correlation_candidates_sqlite(pool, tenant_id, None).await? {
        result.accepted_correlations += 1;
        let work = generate_work_for_candidate_sqlite(pool, tenant_id, &candidate).await?;
        result.created_risks += work.created_risks;
        result.existing_risks += work.existing_risks;
        result.created_roadmap_tasks += work.created_roadmap_tasks;
        result.existing_roadmap_tasks += work.existing_roadmap_tasks;
    }
    Ok(result)
}

async fn generate_work_for_accepted_correlation_postgres(
    pool: &PgPool,
    tenant_id: i64,
    correlation_id: i64,
) -> anyhow::Result<ProductSecurityAcceptedCorrelationWorkResult> {
    let Some(candidate) =
        accepted_correlation_candidates_postgres(pool, tenant_id, Some(correlation_id))
            .await?
            .into_iter()
            .next()
    else {
        return Ok(ProductSecurityAcceptedCorrelationWorkResult {
            accepted_correlations: 0,
            created_risks: 0,
            existing_risks: 0,
            created_roadmap_tasks: 0,
            existing_roadmap_tasks: 0,
        });
    };
    let mut result = generate_work_for_candidate_postgres(pool, tenant_id, &candidate).await?;
    result.accepted_correlations = 1;
    Ok(result)
}

async fn generate_work_for_accepted_correlation_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    correlation_id: i64,
) -> anyhow::Result<ProductSecurityAcceptedCorrelationWorkResult> {
    let Some(candidate) =
        accepted_correlation_candidates_sqlite(pool, tenant_id, Some(correlation_id))
            .await?
            .into_iter()
            .next()
    else {
        return Ok(ProductSecurityAcceptedCorrelationWorkResult {
            accepted_correlations: 0,
            created_risks: 0,
            existing_risks: 0,
            created_roadmap_tasks: 0,
            existing_roadmap_tasks: 0,
        });
    };
    let mut result = generate_work_for_candidate_sqlite(pool, tenant_id, &candidate).await?;
    result.accepted_correlations = 1;
    Ok(result)
}

async fn generate_work_for_candidate_postgres(
    pool: &PgPool,
    tenant_id: i64,
    candidate: &AcceptedCorrelationWorkCandidate,
) -> anyhow::Result<ProductSecurityAcceptedCorrelationWorkResult> {
    let mut result = ProductSecurityAcceptedCorrelationWorkResult {
        accepted_correlations: 0,
        created_risks: 0,
        existing_risks: 0,
        created_roadmap_tasks: 0,
        existing_roadmap_tasks: 0,
    };
    if postgres_table_exists(pool, "public.risks_risk").await? {
        if insert_correlation_risk_postgres(pool, tenant_id, candidate).await? {
            result.created_risks += 1;
        } else {
            result.existing_risks += 1;
        }
    }
    if candidate.product_id.is_some()
        && postgres_table_exists(pool, "public.product_security_productsecurityroadmap").await?
        && postgres_table_exists(pool, "public.product_security_productsecurityroadmaptask").await?
    {
        if insert_correlation_roadmap_task_postgres(pool, tenant_id, candidate).await? {
            result.created_roadmap_tasks += 1;
        } else {
            result.existing_roadmap_tasks += 1;
        }
    }
    Ok(result)
}

async fn generate_work_for_candidate_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    candidate: &AcceptedCorrelationWorkCandidate,
) -> anyhow::Result<ProductSecurityAcceptedCorrelationWorkResult> {
    let mut result = ProductSecurityAcceptedCorrelationWorkResult {
        accepted_correlations: 0,
        created_risks: 0,
        existing_risks: 0,
        created_roadmap_tasks: 0,
        existing_roadmap_tasks: 0,
    };
    if sqlite_table_exists(pool, "risks_risk").await? {
        if insert_correlation_risk_sqlite(pool, tenant_id, candidate).await? {
            result.created_risks += 1;
        } else {
            result.existing_risks += 1;
        }
    }
    if candidate.product_id.is_some()
        && sqlite_table_exists(pool, "product_security_productsecurityroadmap").await?
        && sqlite_table_exists(pool, "product_security_productsecurityroadmaptask").await?
    {
        if insert_correlation_roadmap_task_sqlite(pool, tenant_id, candidate).await? {
            result.created_roadmap_tasks += 1;
        } else {
            result.existing_roadmap_tasks += 1;
        }
    }
    Ok(result)
}

async fn accepted_correlation_candidates_postgres(
    pool: &PgPool,
    tenant_id: i64,
    correlation_id: Option<i64>,
) -> anyhow::Result<Vec<AcceptedCorrelationWorkCandidate>> {
    let rows = sqlx::query(
        r#"
        SELECT
            corr.id AS correlation_id,
            corr.cve,
            corr.asset_id,
            asset.name AS asset_name,
            corr.product_id,
            product.name AS product_name,
            corr.component_id,
            component.name AS component_name,
            vuln.id AS vulnerability_id,
            COALESCE(vuln.severity, 'MEDIUM') AS severity,
            corr.match_type,
            corr.match_value,
            corr.confidence::bigint AS confidence
        FROM product_security_cvecorrelation corr
        LEFT JOIN assets_app_informationasset asset
            ON asset.id = corr.asset_id AND asset.tenant_id = corr.tenant_id
        LEFT JOIN product_security_product product
            ON product.id = corr.product_id AND product.tenant_id = corr.tenant_id
        LEFT JOIN product_security_component component
            ON component.id = corr.component_id AND component.tenant_id = corr.tenant_id
        LEFT JOIN product_security_vulnerability vuln
            ON vuln.tenant_id = corr.tenant_id
           AND vuln.cve = corr.cve
           AND (corr.product_id IS NULL OR vuln.product_id = corr.product_id)
           AND (corr.component_id IS NULL OR vuln.component_id = corr.component_id)
        WHERE corr.tenant_id = $1
          AND corr.status = 'ACCEPTED'
          AND ($2::bigint IS NULL OR corr.id = $2)
        ORDER BY corr.updated_at DESC, corr.id DESC
        "#,
    )
    .bind(tenant_id)
    .bind(correlation_id)
    .fetch_all(pool)
    .await
    .context("PostgreSQL-akzeptierte CVE-Korrelationen konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(accepted_correlation_candidate_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn accepted_correlation_candidates_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    correlation_id: Option<i64>,
) -> anyhow::Result<Vec<AcceptedCorrelationWorkCandidate>> {
    let rows = sqlx::query(
        r#"
        SELECT
            corr.id AS correlation_id,
            corr.cve,
            corr.asset_id,
            asset.name AS asset_name,
            corr.product_id,
            product.name AS product_name,
            corr.component_id,
            component.name AS component_name,
            vuln.id AS vulnerability_id,
            COALESCE(vuln.severity, 'MEDIUM') AS severity,
            corr.match_type,
            corr.match_value,
            corr.confidence AS confidence
        FROM product_security_cvecorrelation corr
        LEFT JOIN assets_app_informationasset asset
            ON asset.id = corr.asset_id AND asset.tenant_id = corr.tenant_id
        LEFT JOIN product_security_product product
            ON product.id = corr.product_id AND product.tenant_id = corr.tenant_id
        LEFT JOIN product_security_component component
            ON component.id = corr.component_id AND component.tenant_id = corr.tenant_id
        LEFT JOIN product_security_vulnerability vuln
            ON vuln.tenant_id = corr.tenant_id
           AND vuln.cve = corr.cve
           AND (corr.product_id IS NULL OR vuln.product_id = corr.product_id)
           AND (corr.component_id IS NULL OR vuln.component_id = corr.component_id)
        WHERE corr.tenant_id = ?1
          AND corr.status = 'ACCEPTED'
          AND (?2 IS NULL OR corr.id = ?2)
        ORDER BY corr.updated_at DESC, corr.id DESC
        "#,
    )
    .bind(tenant_id)
    .bind(correlation_id)
    .fetch_all(pool)
    .await
    .context("SQLite-akzeptierte CVE-Korrelationen konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(accepted_correlation_candidate_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn insert_correlation_risk_postgres(
    pool: &PgPool,
    tenant_id: i64,
    candidate: &AcceptedCorrelationWorkCandidate,
) -> anyhow::Result<bool> {
    let title = correlation_risk_title(candidate);
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM risks_risk WHERE tenant_id = $1 AND title = $2",
    )
    .bind(tenant_id)
    .bind(&title)
    .fetch_one(pool)
    .await
    .context("PostgreSQL-CVE-Korrelationsrisiko konnte nicht gesucht werden")?;
    if exists > 0 {
        return Ok(false);
    }
    let (impact, likelihood) = correlation_risk_matrix(candidate);
    sqlx::query(
        r#"
        INSERT INTO risks_risk (
            tenant_id, category_id, process_id, asset_id, owner_id, title,
            description, threat, vulnerability, impact, likelihood, status,
            treatment_strategy, treatment_plan, created_at, updated_at
        )
        VALUES ($1, NULL, NULL, $2, NULL, $3, $4, $5, $6, $7, $8, 'IDENTIFIED', 'MITIGATE', $9, NOW(), NOW())
        "#,
    )
    .bind(tenant_id)
    .bind(candidate.asset_id)
    .bind(&title)
    .bind(correlation_risk_description(candidate))
    .bind(format!("Ausnutzung von {} ueber betroffenes Asset.", candidate.cve))
    .bind(format!(
        "Akzeptierte {}-Korrelation {} mit {}% Confidence.",
        candidate.match_type, candidate.match_value, candidate.confidence
    ))
    .bind(impact)
    .bind(likelihood)
    .bind(correlation_treatment_plan(candidate))
    .execute(pool)
    .await
    .context("PostgreSQL-CVE-Korrelationsrisiko konnte nicht erstellt werden")?;
    Ok(true)
}

async fn insert_correlation_risk_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    candidate: &AcceptedCorrelationWorkCandidate,
) -> anyhow::Result<bool> {
    let title = correlation_risk_title(candidate);
    let exists: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM risks_risk WHERE tenant_id = ?1 AND title = ?2")
            .bind(tenant_id)
            .bind(&title)
            .fetch_one(pool)
            .await
            .context("SQLite-CVE-Korrelationsrisiko konnte nicht gesucht werden")?;
    if exists > 0 {
        return Ok(false);
    }
    let (impact, likelihood) = correlation_risk_matrix(candidate);
    sqlx::query(
        r#"
        INSERT INTO risks_risk (
            tenant_id, category_id, process_id, asset_id, owner_id, title,
            description, threat, vulnerability, impact, likelihood, status,
            treatment_strategy, treatment_plan, created_at, updated_at
        )
        VALUES (?1, NULL, NULL, ?2, NULL, ?3, ?4, ?5, ?6, ?7, ?8, 'IDENTIFIED', 'MITIGATE', ?9, datetime('now'), datetime('now'))
        "#,
    )
    .bind(tenant_id)
    .bind(candidate.asset_id)
    .bind(&title)
    .bind(correlation_risk_description(candidate))
    .bind(format!("Ausnutzung von {} ueber betroffenes Asset.", candidate.cve))
    .bind(format!(
        "Akzeptierte {}-Korrelation {} mit {}% Confidence.",
        candidate.match_type, candidate.match_value, candidate.confidence
    ))
    .bind(impact)
    .bind(likelihood)
    .bind(correlation_treatment_plan(candidate))
    .execute(pool)
    .await
    .context("SQLite-CVE-Korrelationsrisiko konnte nicht erstellt werden")?;
    Ok(true)
}

async fn insert_correlation_roadmap_task_postgres(
    pool: &PgPool,
    tenant_id: i64,
    candidate: &AcceptedCorrelationWorkCandidate,
) -> anyhow::Result<bool> {
    let product_id = candidate
        .product_id
        .context("Akzeptierte CVE-Korrelation hat keinen Produktbezug")?;
    let roadmap_id = ensure_correlation_roadmap_postgres(pool, tenant_id, product_id).await?;
    let title = correlation_roadmap_task_title(candidate);
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM product_security_productsecurityroadmaptask WHERE tenant_id = $1 AND roadmap_id = $2 AND title = $3",
    )
    .bind(tenant_id)
    .bind(roadmap_id)
    .bind(&title)
    .fetch_one(pool)
    .await
    .context("PostgreSQL-CVE-Korrelations-Roadmaptask konnte nicht gesucht werden")?;
    if exists > 0 {
        return Ok(false);
    }
    sqlx::query(
        r#"
        INSERT INTO product_security_productsecurityroadmaptask (
            tenant_id, roadmap_id, related_release_id, related_vulnerability_id, phase,
            title, description, priority, owner_role, due_in_days, dependency_text,
            status, created_at, updated_at
        )
        VALUES ($1, $2, NULL, $3, 'RESPONSE', $4, $5, $6, 'PSIRT', $7, $8, 'OPEN', NOW()::text, NOW()::text)
        "#,
    )
    .bind(tenant_id)
    .bind(roadmap_id)
    .bind(candidate.vulnerability_id)
    .bind(&title)
    .bind(correlation_roadmap_description(candidate))
    .bind(correlation_priority(candidate))
    .bind(correlation_due_days(candidate))
    .bind(format!("Akzeptierte Korrelation #{}", candidate.correlation_id))
    .execute(pool)
    .await
    .context("PostgreSQL-CVE-Korrelations-Roadmaptask konnte nicht erstellt werden")?;
    Ok(true)
}

async fn insert_correlation_roadmap_task_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    candidate: &AcceptedCorrelationWorkCandidate,
) -> anyhow::Result<bool> {
    let product_id = candidate
        .product_id
        .context("Akzeptierte CVE-Korrelation hat keinen Produktbezug")?;
    let roadmap_id = ensure_correlation_roadmap_sqlite(pool, tenant_id, product_id).await?;
    let title = correlation_roadmap_task_title(candidate);
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM product_security_productsecurityroadmaptask WHERE tenant_id = ?1 AND roadmap_id = ?2 AND title = ?3",
    )
    .bind(tenant_id)
    .bind(roadmap_id)
    .bind(&title)
    .fetch_one(pool)
    .await
    .context("SQLite-CVE-Korrelations-Roadmaptask konnte nicht gesucht werden")?;
    if exists > 0 {
        return Ok(false);
    }
    sqlx::query(
        r#"
        INSERT INTO product_security_productsecurityroadmaptask (
            tenant_id, roadmap_id, related_release_id, related_vulnerability_id, phase,
            title, description, priority, owner_role, due_in_days, dependency_text,
            status, created_at, updated_at
        )
        VALUES (?1, ?2, NULL, ?3, 'RESPONSE', ?4, ?5, ?6, 'PSIRT', ?7, ?8, 'OPEN', datetime('now'), datetime('now'))
        "#,
    )
    .bind(tenant_id)
    .bind(roadmap_id)
    .bind(candidate.vulnerability_id)
    .bind(&title)
    .bind(correlation_roadmap_description(candidate))
    .bind(correlation_priority(candidate))
    .bind(correlation_due_days(candidate))
    .bind(format!("Akzeptierte Korrelation #{}", candidate.correlation_id))
    .execute(pool)
    .await
    .context("SQLite-CVE-Korrelations-Roadmaptask konnte nicht erstellt werden")?;
    Ok(true)
}

async fn ensure_correlation_roadmap_postgres(
    pool: &PgPool,
    tenant_id: i64,
    product_id: i64,
) -> anyhow::Result<i64> {
    if let Some(id) = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT id
        FROM product_security_productsecurityroadmap
        WHERE tenant_id = $1 AND product_id = $2
        ORDER BY id ASC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(product_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-Product-Security-Roadmap konnte nicht gesucht werden")?
    {
        return Ok(id);
    }
    sqlx::query_scalar(
        r#"
        INSERT INTO product_security_productsecurityroadmap (
            tenant_id, product_id, title, summary, generated_from_snapshot_id, created_at, updated_at
        )
        VALUES ($1, $2, 'CVE Correlation Roadmap', 'Automatisch aus akzeptierten CVE-Asset-Korrelationen erzeugt.', NULL, NOW()::text, NOW()::text)
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(product_id)
    .fetch_one(pool)
    .await
    .context("PostgreSQL-Product-Security-Roadmap konnte nicht erstellt werden")
}

async fn ensure_correlation_roadmap_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    product_id: i64,
) -> anyhow::Result<i64> {
    if let Some(id) = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT id
        FROM product_security_productsecurityroadmap
        WHERE tenant_id = ?1 AND product_id = ?2
        ORDER BY id ASC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(product_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-Product-Security-Roadmap konnte nicht gesucht werden")?
    {
        return Ok(id);
    }
    let result = sqlx::query(
        r#"
        INSERT INTO product_security_productsecurityroadmap (
            tenant_id, product_id, title, summary, generated_from_snapshot_id, created_at, updated_at
        )
        VALUES (?1, ?2, 'CVE Correlation Roadmap', 'Automatisch aus akzeptierten CVE-Asset-Korrelationen erzeugt.', NULL, datetime('now'), datetime('now'))
        "#,
    )
    .bind(tenant_id)
    .bind(product_id)
    .execute(pool)
    .await
    .context("SQLite-Product-Security-Roadmap konnte nicht erstellt werden")?;
    Ok(result.last_insert_rowid())
}

async fn postgres_table_exists(pool: &PgPool, qualified_name: &str) -> anyhow::Result<bool> {
    sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(qualified_name)
        .fetch_one(pool)
        .await
        .context("PostgreSQL-Tabellenexistenz konnte nicht geprueft werden")
}

async fn sqlite_table_exists(pool: &SqlitePool, table_name: &str) -> anyhow::Result<bool> {
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1")
            .bind(table_name)
            .fetch_one(pool)
            .await
            .context("SQLite-Tabellenexistenz konnte nicht geprueft werden")?;
    Ok(count > 0)
}

async fn load_cve_risk_link_postgres(
    pool: &PgPool,
    tenant_id: i64,
    evidence_key: &str,
) -> anyhow::Result<Option<ProductSecurityRiskLink>> {
    let pattern = evidence_key_search_pattern(evidence_key);
    sqlx::query(
        r#"
        SELECT id, title, status
        FROM risks_risk
        WHERE tenant_id = $1 AND treatment_plan LIKE $2
        ORDER BY id DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(pattern)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-CVE-Risikolink konnte nicht gelesen werden")?
    .map(risk_link_from_pg_row)
    .transpose()
    .map_err(Into::into)
}

async fn load_cve_risk_link_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    evidence_key: &str,
) -> anyhow::Result<Option<ProductSecurityRiskLink>> {
    let pattern = evidence_key_search_pattern(evidence_key);
    sqlx::query(
        r#"
        SELECT id, title, status
        FROM risks_risk
        WHERE tenant_id = ?1 AND treatment_plan LIKE ?2
        ORDER BY id DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(pattern)
    .fetch_optional(pool)
    .await
    .context("SQLite-CVE-Risikolink konnte nicht gelesen werden")?
    .map(risk_link_from_sqlite_row)
    .transpose()
    .map_err(Into::into)
}

async fn load_cve_roadmap_task_link_postgres(
    pool: &PgPool,
    tenant_id: i64,
    evidence_key: &str,
) -> anyhow::Result<Option<ProductSecurityRoadmapTaskLink>> {
    let pattern = evidence_key_search_pattern(evidence_key);
    sqlx::query(
        r#"
        SELECT id, title, status
        FROM product_security_productsecurityroadmaptask
        WHERE tenant_id = $1 AND description LIKE $2
        ORDER BY id DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(pattern)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-CVE-Roadmaptask-Link konnte nicht gelesen werden")?
    .map(roadmap_task_link_from_pg_row)
    .transpose()
    .map_err(Into::into)
}

async fn load_cve_roadmap_task_link_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    evidence_key: &str,
) -> anyhow::Result<Option<ProductSecurityRoadmapTaskLink>> {
    let pattern = evidence_key_search_pattern(evidence_key);
    sqlx::query(
        r#"
        SELECT id, title, status
        FROM product_security_productsecurityroadmaptask
        WHERE tenant_id = ?1 AND description LIKE ?2
        ORDER BY id DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(pattern)
    .fetch_optional(pool)
    .await
    .context("SQLite-CVE-Roadmaptask-Link konnte nicht gelesen werden")?
    .map(roadmap_task_link_from_sqlite_row)
    .transpose()
    .map_err(Into::into)
}

async fn load_cve_evidence_count_postgres(
    pool: &PgPool,
    tenant_id: i64,
    evidence_key: &str,
) -> anyhow::Result<i64> {
    sqlx::query_scalar(
        r#"
        SELECT COUNT(*)::bigint
        FROM evidence_evidenceitem
        WHERE tenant_id = $1 AND linked_requirement = $2
        "#,
    )
    .bind(tenant_id)
    .bind(evidence_key)
    .fetch_one(pool)
    .await
    .context("PostgreSQL-CVE-Evidence-Anzahl konnte nicht gelesen werden")
}

async fn load_cve_evidence_count_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    evidence_key: &str,
) -> anyhow::Result<i64> {
    sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM evidence_evidenceitem
        WHERE tenant_id = ?1 AND linked_requirement = ?2
        "#,
    )
    .bind(tenant_id)
    .bind(evidence_key)
    .fetch_one(pool)
    .await
    .context("SQLite-CVE-Evidence-Anzahl konnte nicht gelesen werden")
}

fn accepted_correlation_candidate_from_pg_row(
    row: PgRow,
) -> Result<AcceptedCorrelationWorkCandidate, sqlx::Error> {
    Ok(AcceptedCorrelationWorkCandidate {
        correlation_id: row.try_get("correlation_id")?,
        cve: row.try_get("cve")?,
        asset_id: row.try_get("asset_id")?,
        asset_name: row.try_get("asset_name")?,
        product_id: row.try_get("product_id")?,
        product_name: row.try_get("product_name")?,
        component_id: row.try_get("component_id")?,
        component_name: row.try_get("component_name")?,
        vulnerability_id: row.try_get("vulnerability_id")?,
        severity: row.try_get("severity")?,
        match_type: row.try_get("match_type")?,
        match_value: row.try_get("match_value")?,
        confidence: row.try_get("confidence")?,
    })
}

fn accepted_correlation_candidate_from_sqlite_row(
    row: SqliteRow,
) -> Result<AcceptedCorrelationWorkCandidate, sqlx::Error> {
    Ok(AcceptedCorrelationWorkCandidate {
        correlation_id: row.try_get("correlation_id")?,
        cve: row.try_get("cve")?,
        asset_id: row.try_get("asset_id")?,
        asset_name: row.try_get("asset_name")?,
        product_id: row.try_get("product_id")?,
        product_name: row.try_get("product_name")?,
        component_id: row.try_get("component_id")?,
        component_name: row.try_get("component_name")?,
        vulnerability_id: row.try_get("vulnerability_id")?,
        severity: row.try_get("severity")?,
        match_type: row.try_get("match_type")?,
        match_value: row.try_get("match_value")?,
        confidence: row.try_get("confidence")?,
    })
}

fn correlation_risk_title(candidate: &AcceptedCorrelationWorkCandidate) -> String {
    let asset = candidate
        .asset_name
        .as_deref()
        .or(candidate.component_name.as_deref())
        .or(candidate.product_name.as_deref())
        .unwrap_or("unbekanntes Asset");
    truncate_text(&format!("{} betrifft {}", candidate.cve, asset), 255)
}

fn correlation_risk_description(candidate: &AcceptedCorrelationWorkCandidate) -> String {
    format!(
        "Akzeptierte CVE-Asset-Korrelation aus Product Security: {} matched ueber {} '{}' mit {}% Confidence. Produkt: {}. Komponente: {} (ID: {}).",
        candidate.cve,
        candidate.match_type,
        candidate.match_value,
        candidate.confidence,
        candidate.product_name.as_deref().unwrap_or("-"),
        candidate.component_name.as_deref().unwrap_or("-"),
        candidate
            .component_id
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string()),
    )
}

fn correlation_treatment_plan(candidate: &AcceptedCorrelationWorkCandidate) -> String {
    format!(
        "PSIRT-Triage durchfuehren, betroffene Versionen bestaetigen, Patch/Workaround fuer {} planen und Evidence aus SBOM/CSAF/Asset-Inventar verknuepfen. Evidence-Key: {}.",
        candidate.cve,
        correlation_evidence_key(candidate),
    )
}

fn correlation_roadmap_task_title(candidate: &AcceptedCorrelationWorkCandidate) -> String {
    truncate_text(
        &format!(
            "{} behandeln ({})",
            candidate.cve,
            candidate
                .component_name
                .as_deref()
                .or(candidate.asset_name.as_deref())
                .unwrap_or("Asset-Korrelation")
        ),
        255,
    )
}

fn correlation_roadmap_description(candidate: &AcceptedCorrelationWorkCandidate) -> String {
    format!(
        "Akzeptierte {}-Korrelation '{}' fuer {}. Risiko pruefen, Remediation-Owner festlegen, Fix oder Kompensation dokumentieren. Evidence-Key: {}.",
        candidate.match_type,
        candidate.match_value,
        candidate.cve,
        correlation_evidence_key(candidate),
    )
}

fn correlation_evidence_key(candidate: &AcceptedCorrelationWorkCandidate) -> String {
    format!(
        "PRODUCT-SECURITY:CVE:{}:CORRELATION:{}",
        candidate.cve, candidate.correlation_id
    )
}

fn correlation_risk_matrix(candidate: &AcceptedCorrelationWorkCandidate) -> (i64, i64) {
    match candidate.severity.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => (5, 4),
        "HIGH" => (4, 4),
        "MEDIUM" => (3, 3),
        "LOW" => (2, 2),
        _ => (3, 3),
    }
}

fn correlation_priority(candidate: &AcceptedCorrelationWorkCandidate) -> &'static str {
    match candidate.severity.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => "CRITICAL",
        "HIGH" => "HIGH",
        "LOW" => "LOW",
        _ => "MEDIUM",
    }
}

fn correlation_due_days(candidate: &AcceptedCorrelationWorkCandidate) -> i64 {
    match candidate.severity.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => 7,
        "HIGH" => 14,
        "MEDIUM" => 30,
        _ => 60,
    }
}

fn truncate_text(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

async fn cve_correlation_candidates_by_cpe_postgres(
    pool: &PgPool,
    tenant_id: i64,
) -> anyhow::Result<Vec<CveCorrelationCandidate>> {
    let rows = sqlx::query(
        r#"
        SELECT
            vuln.cve,
            asset.id AS asset_id,
            vuln.product_id,
            vuln.component_id,
            vuln.cpe23_uri AS match_value
        FROM product_security_vulnerability vuln
        INNER JOIN assets_app_informationasset asset
            ON asset.tenant_id = vuln.tenant_id
           AND asset.cpe23_uri = vuln.cpe23_uri
           AND asset.cpe23_uri <> ''
        WHERE vuln.tenant_id = $1
          AND vuln.cve <> ''
          AND vuln.cpe23_uri <> ''
        "#,
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .context("PostgreSQL-CVE-CPE-Kandidaten konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(|row| {
            let match_value: String = row.try_get("match_value")?;
            Ok(CveCorrelationCandidate {
                cve: row.try_get("cve")?,
                asset_id: row.try_get("asset_id")?,
                product_id: row.try_get("product_id")?,
                component_id: row.try_get("component_id")?,
                match_type: "CPE".to_string(),
                match_value: match_value.clone(),
                confidence: 95,
                rationale: format!("CVE und Asset teilen CPE {match_value}."),
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map_err(Into::into)
}

async fn cve_correlation_candidates_by_cpe_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
) -> anyhow::Result<Vec<CveCorrelationCandidate>> {
    let rows = sqlx::query(
        r#"
        SELECT
            vuln.cve,
            asset.id AS asset_id,
            vuln.product_id,
            vuln.component_id,
            vuln.cpe23_uri AS match_value
        FROM product_security_vulnerability vuln
        INNER JOIN assets_app_informationasset asset
            ON asset.tenant_id = vuln.tenant_id
           AND asset.cpe23_uri = vuln.cpe23_uri
           AND asset.cpe23_uri <> ''
        WHERE vuln.tenant_id = ?
          AND vuln.cve <> ''
          AND vuln.cpe23_uri <> ''
        "#,
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .context("SQLite-CVE-CPE-Kandidaten konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(|row| {
            let match_value: String = row.try_get("match_value")?;
            Ok(CveCorrelationCandidate {
                cve: row.try_get("cve")?,
                asset_id: row.try_get("asset_id")?,
                product_id: row.try_get("product_id")?,
                component_id: row.try_get("component_id")?,
                match_type: "CPE".to_string(),
                match_value: match_value.clone(),
                confidence: 95,
                rationale: format!("CVE und Asset teilen CPE {match_value}."),
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map_err(Into::into)
}

async fn cve_correlation_candidates_by_purl_postgres(
    pool: &PgPool,
    tenant_id: i64,
) -> anyhow::Result<Vec<CveCorrelationCandidate>> {
    let rows = sqlx::query(
        r#"
        SELECT
            vuln.cve,
            asset.id AS asset_id,
            vuln.product_id,
            component.id AS component_id,
            component.package_url AS match_value
        FROM product_security_vulnerability vuln
        INNER JOIN product_security_component component
            ON component.id = vuln.component_id
           AND component.tenant_id = vuln.tenant_id
           AND component.package_url <> ''
        INNER JOIN assets_app_informationasset asset
            ON asset.tenant_id = vuln.tenant_id
           AND asset.package_url = component.package_url
           AND asset.package_url <> ''
        WHERE vuln.tenant_id = $1
          AND vuln.cve <> ''
        "#,
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .context("PostgreSQL-CVE-PURL-Kandidaten konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(|row| {
            let match_value: String = row.try_get("match_value")?;
            Ok(CveCorrelationCandidate {
                cve: row.try_get("cve")?,
                asset_id: row.try_get("asset_id")?,
                product_id: row.try_get("product_id")?,
                component_id: row.try_get("component_id")?,
                match_type: "PURL".to_string(),
                match_value: match_value.clone(),
                confidence: 90,
                rationale: format!("CVE-Komponente und Asset teilen PURL {match_value}."),
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map_err(Into::into)
}

async fn cve_correlation_candidates_by_purl_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
) -> anyhow::Result<Vec<CveCorrelationCandidate>> {
    let rows = sqlx::query(
        r#"
        SELECT
            vuln.cve,
            asset.id AS asset_id,
            vuln.product_id,
            component.id AS component_id,
            component.package_url AS match_value
        FROM product_security_vulnerability vuln
        INNER JOIN product_security_component component
            ON component.id = vuln.component_id
           AND component.tenant_id = vuln.tenant_id
           AND component.package_url <> ''
        INNER JOIN assets_app_informationasset asset
            ON asset.tenant_id = vuln.tenant_id
           AND asset.package_url = component.package_url
           AND asset.package_url <> ''
        WHERE vuln.tenant_id = ?
          AND vuln.cve <> ''
        "#,
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .context("SQLite-CVE-PURL-Kandidaten konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(|row| {
            let match_value: String = row.try_get("match_value")?;
            Ok(CveCorrelationCandidate {
                cve: row.try_get("cve")?,
                asset_id: row.try_get("asset_id")?,
                product_id: row.try_get("product_id")?,
                component_id: row.try_get("component_id")?,
                match_type: "PURL".to_string(),
                match_value: match_value.clone(),
                confidence: 90,
                rationale: format!("CVE-Komponente und Asset teilen PURL {match_value}."),
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map_err(Into::into)
}

async fn load_cve_correlations_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<ProductSecurityCveCorrelationSummary>> {
    let rows = sqlx::query(cve_correlation_list_postgres_sql())
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-CVE-Asset-Korrelationen konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(cve_correlation_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn load_cve_risk_review_queue_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<ProductSecurityCveRiskReviewSummary>> {
    let has_risks = postgres_table_exists(pool, "public.risks_risk").await?;
    let has_roadmap_tasks =
        postgres_table_exists(pool, "public.product_security_productsecurityroadmaptask").await?;
    let has_evidence = postgres_table_exists(pool, "public.evidence_evidenceitem").await?;
    let candidates = accepted_correlation_candidates_postgres(pool, tenant_id, None).await?;
    let mut queue = Vec::new();
    for candidate in candidates.into_iter().take(limit.max(0) as usize) {
        let evidence_key = correlation_evidence_key(&candidate);
        let risk = if has_risks {
            load_cve_risk_link_postgres(pool, tenant_id, &evidence_key).await?
        } else {
            None
        };
        let roadmap_task = if has_roadmap_tasks {
            load_cve_roadmap_task_link_postgres(pool, tenant_id, &evidence_key).await?
        } else {
            None
        };
        let evidence_count = if has_evidence {
            load_cve_evidence_count_postgres(pool, tenant_id, &evidence_key).await?
        } else {
            0
        };
        queue.push(cve_risk_review_summary_from_candidate(
            candidate,
            evidence_key,
            risk,
            roadmap_task,
            evidence_count,
        ));
    }
    Ok(queue)
}

async fn load_import_artifacts_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<ProductSecurityImportArtifactSummary>> {
    let rows = sqlx::query(import_artifact_list_postgres_sql())
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Product-Security-Importhistorie konnte nicht gelesen werden")?;
    rows.into_iter()
        .map(import_artifact_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn load_import_artifacts_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<ProductSecurityImportArtifactSummary>> {
    let rows = sqlx::query(import_artifact_list_sqlite_sql())
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("SQLite-Product-Security-Importhistorie konnte nicht gelesen werden")?;
    rows.into_iter()
        .map(import_artifact_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn load_import_detail_postgres(
    pool: &PgPool,
    tenant_id: i64,
    artifact_id: i64,
) -> anyhow::Result<Option<ProductSecurityImportArtifactDetail>> {
    let Some(row) = sqlx::query(import_artifact_detail_postgres_sql())
        .bind(tenant_id)
        .bind(artifact_id)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-Product-Security-Importdetail konnte nicht gelesen werden")?
    else {
        return Ok(None);
    };
    let artifact = import_artifact_from_pg_row(row)?;
    let components = load_import_components_postgres(pool, tenant_id, artifact_id).await?;
    Ok(Some(ProductSecurityImportArtifactDetail {
        artifact,
        components,
    }))
}

async fn load_import_detail_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    artifact_id: i64,
) -> anyhow::Result<Option<ProductSecurityImportArtifactDetail>> {
    let Some(row) = sqlx::query(import_artifact_detail_sqlite_sql())
        .bind(tenant_id)
        .bind(artifact_id)
        .fetch_optional(pool)
        .await
        .context("SQLite-Product-Security-Importdetail konnte nicht gelesen werden")?
    else {
        return Ok(None);
    };
    let artifact = import_artifact_from_sqlite_row(row)?;
    let components = load_import_components_sqlite(pool, tenant_id, artifact_id).await?;
    Ok(Some(ProductSecurityImportArtifactDetail {
        artifact,
        components,
    }))
}

async fn load_import_components_postgres(
    pool: &PgPool,
    tenant_id: i64,
    artifact_id: i64,
) -> anyhow::Result<Vec<ProductSecurityImportComponentSummary>> {
    let rows = sqlx::query(import_component_list_postgres_sql())
        .bind(tenant_id)
        .bind(artifact_id)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Product-Security-Importkomponenten konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(import_component_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn load_import_components_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    artifact_id: i64,
) -> anyhow::Result<Vec<ProductSecurityImportComponentSummary>> {
    let rows = sqlx::query(import_component_list_sqlite_sql())
        .bind(tenant_id)
        .bind(artifact_id)
        .fetch_all(pool)
        .await
        .context("SQLite-Product-Security-Importkomponenten konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(import_component_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn load_cve_correlations_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<ProductSecurityCveCorrelationSummary>> {
    let rows = sqlx::query(cve_correlation_list_sqlite_sql())
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("SQLite-CVE-Asset-Korrelationen konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(cve_correlation_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn load_cve_risk_review_queue_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<ProductSecurityCveRiskReviewSummary>> {
    let has_risks = sqlite_table_exists(pool, "risks_risk").await?;
    let has_roadmap_tasks =
        sqlite_table_exists(pool, "product_security_productsecurityroadmaptask").await?;
    let has_evidence = sqlite_table_exists(pool, "evidence_evidenceitem").await?;
    let candidates = accepted_correlation_candidates_sqlite(pool, tenant_id, None).await?;
    let mut queue = Vec::new();
    for candidate in candidates.into_iter().take(limit.max(0) as usize) {
        let evidence_key = correlation_evidence_key(&candidate);
        let risk = if has_risks {
            load_cve_risk_link_sqlite(pool, tenant_id, &evidence_key).await?
        } else {
            None
        };
        let roadmap_task = if has_roadmap_tasks {
            load_cve_roadmap_task_link_sqlite(pool, tenant_id, &evidence_key).await?
        } else {
            None
        };
        let evidence_count = if has_evidence {
            load_cve_evidence_count_sqlite(pool, tenant_id, &evidence_key).await?
        } else {
            0
        };
        queue.push(cve_risk_review_summary_from_candidate(
            candidate,
            evidence_key,
            risk,
            roadmap_task,
            evidence_count,
        ));
    }
    Ok(queue)
}

async fn load_cve_correlation_postgres(
    pool: &PgPool,
    tenant_id: i64,
    correlation_id: i64,
) -> anyhow::Result<Option<ProductSecurityCveCorrelationSummary>> {
    sqlx::query(cve_correlation_detail_postgres_sql())
        .bind(tenant_id)
        .bind(correlation_id)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-CVE-Asset-Korrelation konnte nicht gelesen werden")?
        .map(cve_correlation_from_pg_row)
        .transpose()
        .map_err(Into::into)
}

async fn load_cve_correlation_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    correlation_id: i64,
) -> anyhow::Result<Option<ProductSecurityCveCorrelationSummary>> {
    sqlx::query(cve_correlation_detail_sqlite_sql())
        .bind(tenant_id)
        .bind(correlation_id)
        .fetch_optional(pool)
        .await
        .context("SQLite-CVE-Asset-Korrelation konnte nicht gelesen werden")?
        .map(cve_correlation_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

fn parse_csaf_document(document: &Value) -> CsafImportDocument {
    let document_id = json_pointer_string(document, "/document/tracking/id")
        .or_else(|| json_pointer_string(document, "/document/title"))
        .unwrap_or_default();
    let title = json_pointer_string(document, "/document/title")
        .or_else(|| json_pointer_string(document, "/document/tracking/id"))
        .unwrap_or_else(|| "CSAF Advisory".to_string());
    let profile = json_pointer_string(document, "/document/category").unwrap_or_default();
    let tracking_status =
        json_pointer_string(document, "/document/tracking/status").unwrap_or_default();
    let revision = document
        .pointer("/document/tracking/revision_history")
        .and_then(Value::as_array)
        .and_then(|items| items.last())
        .and_then(|value| value.get("number"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let mut cves = BTreeSet::new();
    let mut product_status = Value::Object(Default::default());
    if let Some(vulnerabilities) = document.get("vulnerabilities").and_then(Value::as_array) {
        for vulnerability in vulnerabilities {
            if let Some(cve) = vulnerability.get("cve").and_then(Value::as_str) {
                let cve = cve.trim().to_ascii_uppercase();
                if !cve.is_empty() {
                    cves.insert(cve);
                }
            }
            if let Some(status) = vulnerability.get("product_status") {
                product_status = status.clone();
            }
        }
    }
    let validation_errors = validate_csaf_schema_core(document);
    CsafImportDocument {
        document_id,
        title,
        profile,
        tracking_status,
        revision,
        cves: cves.into_iter().collect(),
        product_status,
        validation_errors,
    }
}

fn parse_sbom_document(document: &Value) -> SbomImportDocument {
    if document
        .get("bomFormat")
        .and_then(Value::as_str)
        .is_some_and(|format| format.eq_ignore_ascii_case("CycloneDX"))
    {
        return parse_cyclonedx_document(document);
    }
    if document
        .get("spdxVersion")
        .and_then(Value::as_str)
        .is_some()
    {
        return parse_spdx_document(document);
    }
    SbomImportDocument {
        format_name: "UNKNOWN".to_string(),
        format_version: String::new(),
        document_id: String::new(),
        components: Vec::new(),
        validation_errors: vec![
            "SBOM-Format wurde nicht als CycloneDX oder SPDX erkannt.".to_string()
        ],
    }
}

fn parse_cyclonedx_document(document: &Value) -> SbomImportDocument {
    let components = document
        .get("components")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|component| SbomImportComponent {
                    name: json_field_string(component, "name").unwrap_or_default(),
                    version: json_field_string(component, "version").unwrap_or_default(),
                    package_url: json_field_string(component, "purl").unwrap_or_default(),
                    cpe23_uri: json_field_string(component, "cpe").unwrap_or_default(),
                    supplier_name: component
                        .get("supplier")
                        .and_then(|supplier| {
                            supplier
                                .get("name")
                                .and_then(Value::as_str)
                                .or_else(|| supplier.as_str())
                        })
                        .unwrap_or("")
                        .trim()
                        .to_string(),
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let validation_errors = validate_cyclonedx_schema_core(document, &components);
    SbomImportDocument {
        format_name: "CycloneDX".to_string(),
        format_version: json_field_string(document, "specVersion").unwrap_or_default(),
        document_id: json_field_string(document, "serialNumber")
            .or_else(|| json_field_string(document, "bom-ref"))
            .unwrap_or_default(),
        components,
        validation_errors,
    }
}

fn parse_spdx_document(document: &Value) -> SbomImportDocument {
    let components = document
        .get("packages")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|package| {
                    let (package_url, cpe23_uri) = spdx_external_refs(package);
                    SbomImportComponent {
                        name: json_field_string(package, "name").unwrap_or_default(),
                        version: json_field_string(package, "versionInfo").unwrap_or_default(),
                        package_url,
                        cpe23_uri,
                        supplier_name: json_field_string(package, "supplier").unwrap_or_default(),
                    }
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let validation_errors = validate_spdx_schema_core(document, &components);
    SbomImportDocument {
        format_name: "SPDX".to_string(),
        format_version: json_field_string(document, "spdxVersion").unwrap_or_default(),
        document_id: json_field_string(document, "documentNamespace")
            .or_else(|| json_field_string(document, "SPDXID"))
            .unwrap_or_default(),
        components,
        validation_errors,
    }
}

fn spdx_external_refs(package: &Value) -> (String, String) {
    let mut package_url = String::new();
    let mut cpe23_uri = String::new();
    if let Some(refs) = package.get("externalRefs").and_then(Value::as_array) {
        for reference in refs {
            let reference_type = json_field_string(reference, "referenceType")
                .unwrap_or_default()
                .to_ascii_lowercase();
            let locator = json_field_string(reference, "referenceLocator").unwrap_or_default();
            if reference_type.contains("purl") || reference_type.contains("package-url") {
                package_url = locator;
            } else if reference_type.contains("cpe23") || reference_type.contains("cpe") {
                cpe23_uri = locator;
            }
        }
    }
    (package_url, cpe23_uri)
}

fn validate_csaf_schema_core(document: &Value) -> Vec<String> {
    let mut errors =
        validate_against_embedded_schema(&embedded_csaf_schema(), document, "CSAF 2.0 JSON Schema");
    if !document.is_object() {
        return vec!["CSAF-Dokument muss ein JSON-Objekt sein.".to_string()];
    }
    let Some(meta) = document.get("document") else {
        return vec!["CSAF document fehlt.".to_string()];
    };
    if !meta.is_object() {
        errors.push("CSAF document muss ein Objekt sein.".to_string());
        return errors;
    }
    require_string(meta, "category", "CSAF document.category", &mut errors);
    match json_field_string(meta, "csaf_version").as_deref() {
        Some("2.0") => {}
        Some(_) => errors.push("CSAF document.csaf_version muss '2.0' sein.".to_string()),
        None => errors.push("CSAF document.csaf_version fehlt.".to_string()),
    }
    require_string(meta, "title", "CSAF document.title", &mut errors);
    let publisher = meta.get("publisher");
    if let Some(publisher) = publisher.and_then(Value::as_object) {
        match publisher
            .get("category")
            .and_then(Value::as_str)
            .map(str::trim)
        {
            Some("coordinator" | "discoverer" | "other" | "translator" | "user" | "vendor") => {}
            Some(_) => errors
                .push("CSAF document.publisher.category ist kein erlaubter CSAF-Wert.".to_string()),
            None => errors.push("CSAF document.publisher.category fehlt.".to_string()),
        }
        require_string(
            meta.pointer("/publisher").unwrap_or(&Value::Null),
            "name",
            "CSAF document.publisher.name",
            &mut errors,
        );
        require_uri_string(
            meta.pointer("/publisher").unwrap_or(&Value::Null),
            "namespace",
            "CSAF document.publisher.namespace",
            &mut errors,
        );
    } else {
        errors.push("CSAF document.publisher fehlt oder ist kein Objekt.".to_string());
    }
    if let Some(tracking) = meta.get("tracking").and_then(Value::as_object) {
        for (field, label) in [
            ("id", "CSAF document.tracking.id"),
            ("version", "CSAF document.tracking.version"),
            (
                "initial_release_date",
                "CSAF document.tracking.initial_release_date",
            ),
            (
                "current_release_date",
                "CSAF document.tracking.current_release_date",
            ),
        ] {
            require_string(
                meta.pointer("/tracking").unwrap_or(&Value::Null),
                field,
                label,
                &mut errors,
            );
        }
        for field in ["initial_release_date", "current_release_date"] {
            if let Some(value) = tracking.get(field).and_then(Value::as_str) {
                validate_rfc3339_like(
                    value,
                    &format!("CSAF document.tracking.{field}"),
                    &mut errors,
                );
            }
        }
        match tracking
            .get("status")
            .and_then(Value::as_str)
            .map(str::trim)
        {
            Some("draft" | "final" | "interim") => {}
            Some(_) => errors
                .push("CSAF document.tracking.status ist kein erlaubter CSAF-Wert.".to_string()),
            None => errors.push("CSAF document.tracking.status fehlt.".to_string()),
        }
        match tracking.get("revision_history").and_then(Value::as_array) {
            Some(items) if !items.is_empty() => {
                for (index, item) in items.iter().enumerate() {
                    require_string(
                        item,
                        "number",
                        &format!("CSAF document.tracking.revision_history[{index}].number"),
                        &mut errors,
                    );
                    require_string(
                        item,
                        "date",
                        &format!("CSAF document.tracking.revision_history[{index}].date"),
                        &mut errors,
                    );
                    if let Some(value) = item.get("date").and_then(Value::as_str) {
                        validate_rfc3339_like(
                            value,
                            &format!("CSAF document.tracking.revision_history[{index}].date"),
                            &mut errors,
                        );
                    }
                    require_string(
                        item,
                        "summary",
                        &format!("CSAF document.tracking.revision_history[{index}].summary"),
                        &mut errors,
                    );
                }
            }
            _ => errors
                .push("CSAF document.tracking.revision_history fehlt oder ist leer.".to_string()),
        }
    } else {
        errors.push("CSAF document.tracking fehlt oder ist kein Objekt.".to_string());
    }
    match document.get("vulnerabilities").and_then(Value::as_array) {
        Some(vulnerabilities) if !vulnerabilities.is_empty() => {
            for (index, vulnerability) in vulnerabilities.iter().enumerate() {
                if let Some(cve) = vulnerability.get("cve").and_then(Value::as_str) {
                    validate_cve_like(
                        cve,
                        &format!("CSAF vulnerabilities[{index}].cve"),
                        &mut errors,
                    );
                }
                if !vulnerability
                    .get("product_status")
                    .is_some_and(|status| status.is_object())
                {
                    errors.push(format!(
                        "CSAF vulnerabilities[{index}].product_status fehlt oder ist kein Objekt."
                    ));
                }
            }
        }
        Some(_) => errors.push("CSAF vulnerabilities[] ist leer.".to_string()),
        None => errors.push("CSAF vulnerabilities[] fehlt oder ist kein Array.".to_string()),
    }
    errors
}

fn validate_cyclonedx_schema_core(
    document: &Value,
    components: &[SbomImportComponent],
) -> Vec<String> {
    let mut errors = validate_against_embedded_schema(
        &embedded_cyclonedx_schema(),
        document,
        "CycloneDX 1.6 JSON Schema",
    );
    if !document.is_object() {
        return vec!["CycloneDX-Dokument muss ein JSON-Objekt sein.".to_string()];
    }
    let allowed_top_level = [
        "$schema",
        "bomFormat",
        "specVersion",
        "serialNumber",
        "version",
        "metadata",
        "components",
        "services",
        "externalReferences",
        "dependencies",
        "compositions",
        "vulnerabilities",
        "annotations",
        "formulation",
        "declarations",
        "definitions",
        "properties",
    ];
    validate_allowed_top_level(document, &allowed_top_level, "CycloneDX", &mut errors);
    match json_field_string(document, "bomFormat").as_deref() {
        Some("CycloneDX") => {}
        Some(_) => errors.push("CycloneDX bomFormat muss 'CycloneDX' sein.".to_string()),
        None => errors.push("CycloneDX bomFormat fehlt.".to_string()),
    }
    match json_field_string(document, "specVersion").as_deref() {
        Some("1.6") => {}
        Some(_) => errors
            .push("CycloneDX specVersion muss fuer dieses ISCY-Profil '1.6' sein.".to_string()),
        None => errors.push("CycloneDX specVersion fehlt.".to_string()),
    }
    if let Some(serial) = json_field_string(document, "serialNumber") {
        validate_urn_uuid(&serial, "CycloneDX serialNumber", &mut errors);
    }
    if components.is_empty() {
        errors.push("CycloneDX components[] enthaelt keine Komponenten.".to_string());
    }
    if let Some(items) = document.get("components").and_then(Value::as_array) {
        for (index, item) in items.iter().enumerate() {
            require_string(
                item,
                "type",
                &format!("CycloneDX components[{index}].type"),
                &mut errors,
            );
            if let Some(component_type) = item.get("type").and_then(Value::as_str) {
                validate_cyclonedx_component_type(component_type, index, &mut errors);
            }
            require_string(
                item,
                "name",
                &format!("CycloneDX components[{index}].name"),
                &mut errors,
            );
            if let Some(purl) = item.get("purl").and_then(Value::as_str) {
                validate_purl(
                    purl,
                    &format!("CycloneDX components[{index}].purl"),
                    &mut errors,
                );
            }
            if let Some(cpe) = item.get("cpe").and_then(Value::as_str) {
                validate_cpe(
                    cpe,
                    &format!("CycloneDX components[{index}].cpe"),
                    &mut errors,
                );
            }
        }
    } else {
        errors.push("CycloneDX components[] fehlt oder ist kein Array.".to_string());
    }
    errors
}

fn validate_spdx_schema_core(document: &Value, components: &[SbomImportComponent]) -> Vec<String> {
    let mut errors =
        validate_against_embedded_schema(&embedded_spdx_schema(), document, "SPDX 2.3 JSON Schema");
    if !document.is_object() {
        return vec!["SPDX-Dokument muss ein JSON-Objekt sein.".to_string()];
    }
    let allowed_top_level = [
        "SPDXID",
        "annotations",
        "comment",
        "creationInfo",
        "dataLicense",
        "documentDescribes",
        "documentNamespace",
        "externalDocumentRefs",
        "files",
        "hasExtractedLicensingInfos",
        "name",
        "packages",
        "relationships",
        "revieweds",
        "snippets",
        "spdxVersion",
    ];
    validate_allowed_top_level(document, &allowed_top_level, "SPDX", &mut errors);
    require_string(document, "SPDXID", "SPDX SPDXID", &mut errors);
    require_string(document, "dataLicense", "SPDX dataLicense", &mut errors);
    require_string(document, "name", "SPDX name", &mut errors);
    match json_field_string(document, "spdxVersion").as_deref() {
        Some("SPDX-2.3") => {}
        Some(_) => errors.push("SPDX spdxVersion muss 'SPDX-2.3' sein.".to_string()),
        None => errors.push("SPDX spdxVersion fehlt.".to_string()),
    }
    if let Some(creation_info) = document.get("creationInfo") {
        require_string(
            creation_info,
            "created",
            "SPDX creationInfo.created",
            &mut errors,
        );
        if let Some(creators) = creation_info.get("creators").and_then(Value::as_array) {
            if creators.is_empty() {
                errors.push("SPDX creationInfo.creators ist leer.".to_string());
            }
        } else {
            errors.push("SPDX creationInfo.creators fehlt oder ist kein Array.".to_string());
        }
    } else {
        errors.push("SPDX creationInfo fehlt.".to_string());
    }
    if components.is_empty() {
        errors.push("SPDX packages[] enthaelt keine Komponenten.".to_string());
    }
    if let Some(packages) = document.get("packages").and_then(Value::as_array) {
        for (index, package) in packages.iter().enumerate() {
            require_string(
                package,
                "SPDXID",
                &format!("SPDX packages[{index}].SPDXID"),
                &mut errors,
            );
            require_string(
                package,
                "downloadLocation",
                &format!("SPDX packages[{index}].downloadLocation"),
                &mut errors,
            );
            require_string(
                package,
                "name",
                &format!("SPDX packages[{index}].name"),
                &mut errors,
            );
            if let Some(refs) = package.get("externalRefs").and_then(Value::as_array) {
                for (ref_index, reference) in refs.iter().enumerate() {
                    require_string(
                        reference,
                        "referenceCategory",
                        &format!(
                            "SPDX packages[{index}].externalRefs[{ref_index}].referenceCategory"
                        ),
                        &mut errors,
                    );
                    require_string(
                        reference,
                        "referenceType",
                        &format!("SPDX packages[{index}].externalRefs[{ref_index}].referenceType"),
                        &mut errors,
                    );
                    require_string(
                        reference,
                        "referenceLocator",
                        &format!(
                            "SPDX packages[{index}].externalRefs[{ref_index}].referenceLocator"
                        ),
                        &mut errors,
                    );
                    if let Some(locator) = reference.get("referenceLocator").and_then(Value::as_str)
                    {
                        let reference_type = reference
                            .get("referenceType")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_ascii_lowercase();
                        if reference_type.contains("purl") {
                            validate_purl(
                                locator,
                                &format!(
                                    "SPDX packages[{index}].externalRefs[{ref_index}].referenceLocator"
                                ),
                                &mut errors,
                            );
                        } else if reference_type.contains("cpe") {
                            validate_cpe(
                                locator,
                                &format!(
                                    "SPDX packages[{index}].externalRefs[{ref_index}].referenceLocator"
                                ),
                                &mut errors,
                            );
                        }
                    }
                }
            }
        }
    } else {
        errors.push("SPDX packages[] fehlt oder ist kein Array.".to_string());
    }
    errors
}

fn validate_against_embedded_schema(schema: &Value, document: &Value, label: &str) -> Vec<String> {
    let mut errors = Vec::new();
    validate_embedded_schema_node(schema, document, "$", label, &mut errors);
    errors
}

fn validate_embedded_schema_node(
    schema: &Value,
    document: &Value,
    path: &str,
    label: &str,
    errors: &mut Vec<String>,
) {
    if errors.len() >= 50 {
        return;
    }
    if let Some(one_of) = schema.get("oneOf").and_then(Value::as_array) {
        let matches = one_of
            .iter()
            .filter(|candidate| {
                let mut candidate_errors = Vec::new();
                validate_embedded_schema_node(
                    candidate,
                    document,
                    path,
                    label,
                    &mut candidate_errors,
                );
                candidate_errors.is_empty()
            })
            .count();
        if matches != 1 {
            push_schema_error(
                errors,
                label,
                path,
                "muss genau einem der erlaubten Schemas entsprechen",
            );
        }
        return;
    }
    if let Some(expected_type) = schema.get("type").and_then(Value::as_str) {
        if !embedded_schema_type_matches(expected_type, document) {
            push_schema_error(
                errors,
                label,
                path,
                &format!("muss vom Typ {expected_type} sein"),
            );
            return;
        }
    }
    if let Some(expected) = schema.get("const") {
        if document != expected {
            push_schema_error(
                errors,
                label,
                path,
                &format!(
                    "muss konstant {} sein",
                    embedded_schema_value_label(expected)
                ),
            );
        }
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        if !values.iter().any(|value| value == document) {
            let allowed = values
                .iter()
                .map(embedded_schema_value_label)
                .collect::<Vec<_>>()
                .join(", ");
            push_schema_error(
                errors,
                label,
                path,
                &format!("muss einer von {allowed} sein"),
            );
        }
    }
    if let Some(min_length) = schema.get("minLength").and_then(Value::as_u64) {
        if document
            .as_str()
            .is_some_and(|value| value.chars().count() < min_length as usize)
        {
            push_schema_error(
                errors,
                label,
                path,
                &format!("muss mindestens {min_length} Zeichen haben"),
            );
        }
    }
    if let Some(minimum) = schema.get("minimum").and_then(Value::as_i64) {
        if document.as_i64().is_some_and(|value| value < minimum) {
            push_schema_error(
                errors,
                label,
                path,
                &format!("muss mindestens {minimum} sein"),
            );
        }
    }
    if let Some(format) = schema.get("format").and_then(Value::as_str) {
        if let Some(value) = document.as_str() {
            if !embedded_schema_format_matches(format, value) {
                push_schema_error(
                    errors,
                    label,
                    path,
                    &format!("muss Format {format} erfuellen"),
                );
            }
        }
    }
    if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
        if let Some(value) = document.as_str() {
            if !embedded_schema_pattern_matches(pattern, value) {
                push_schema_error(
                    errors,
                    label,
                    path,
                    &format!("muss Pattern {pattern} erfuellen"),
                );
            }
        }
    }
    if let Some(min_items) = schema.get("minItems").and_then(Value::as_u64) {
        if document
            .as_array()
            .is_some_and(|values| values.len() < min_items as usize)
        {
            push_schema_error(
                errors,
                label,
                path,
                &format!("muss mindestens {min_items} Eintraege enthalten"),
            );
        }
    }
    if let Some(object) = document.as_object() {
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for field in required.iter().filter_map(Value::as_str) {
                if !object.contains_key(field) {
                    push_schema_error(
                        errors,
                        label,
                        &format!("{path}.{field}"),
                        "ist erforderlich",
                    );
                }
            }
        }
        if schema
            .get("additionalProperties")
            .and_then(Value::as_bool)
            .is_some_and(|allowed| !allowed)
        {
            let allowed = schema
                .get("properties")
                .and_then(Value::as_object)
                .map(|properties| properties.keys().cloned().collect::<BTreeSet<_>>())
                .unwrap_or_default();
            for key in object.keys() {
                if !allowed.contains(key) {
                    push_schema_error(
                        errors,
                        label,
                        &format!("{path}.{key}"),
                        "ist als zusaetzliche Eigenschaft nicht erlaubt",
                    );
                }
            }
        }
        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            for (field, field_schema) in properties {
                if let Some(value) = object.get(field) {
                    validate_embedded_schema_node(
                        field_schema,
                        value,
                        &format!("{path}.{field}"),
                        label,
                        errors,
                    );
                }
            }
        }
    }
    if let (Some(items_schema), Some(values)) = (schema.get("items"), document.as_array()) {
        for (index, item) in values.iter().enumerate() {
            validate_embedded_schema_node(
                items_schema,
                item,
                &format!("{path}[{index}]"),
                label,
                errors,
            );
        }
    }
}

fn push_schema_error(errors: &mut Vec<String>, label: &str, path: &str, message: &str) {
    if errors.len() < 50 {
        errors.push(format!("{label} {path}: {message}."));
    }
}

fn embedded_schema_type_matches(expected_type: &str, value: &Value) -> bool {
    match expected_type {
        "array" => value.is_array(),
        "boolean" => value.is_boolean(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "number" => value.is_number(),
        "object" => value.is_object(),
        "string" => value.is_string(),
        _ => true,
    }
}

fn embedded_schema_value_label(value: &Value) -> String {
    value
        .as_str()
        .map(|value| format!("'{value}'"))
        .unwrap_or_else(|| value.to_string())
}

fn embedded_schema_format_matches(format: &str, value: &str) -> bool {
    match format {
        "date-time" => {
            value.contains('T') && (value.ends_with('Z') || has_rfc3339_timezone_offset(value))
        }
        "uri" => {
            value.starts_with("http://")
                || value.starts_with("https://")
                || value.starts_with("urn:")
        }
        _ => true,
    }
}

fn has_rfc3339_timezone_offset(value: &str) -> bool {
    let Some(offset) = value.get(value.len().saturating_sub(6)..) else {
        return false;
    };
    let bytes = offset.as_bytes();
    bytes.len() == 6
        && matches!(bytes.first(), Some(b'+' | b'-'))
        && bytes.get(3) == Some(&b':')
        && bytes[1..3].iter().all(u8::is_ascii_digit)
        && bytes[4..6].iter().all(u8::is_ascii_digit)
}

fn embedded_schema_pattern_matches(pattern: &str, value: &str) -> bool {
    match pattern {
        "^CVE-[0-9]{4}-[0-9]{4,}$" => {
            let Some(rest) = value.strip_prefix("CVE-") else {
                return false;
            };
            let mut parts = rest.split('-');
            let Some(year) = parts.next() else {
                return false;
            };
            let Some(number) = parts.next() else {
                return false;
            };
            parts.next().is_none()
                && year.len() == 4
                && year.chars().all(|char| char.is_ascii_digit())
                && number.len() >= 4
                && number.chars().all(|char| char.is_ascii_digit())
        }
        "^urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$" => {
            let Some(uuid) = value.strip_prefix("urn:uuid:") else {
                return false;
            };
            let groups = uuid.split('-').collect::<Vec<_>>();
            groups.len() == 5
                && [8, 4, 4, 4, 12]
                    .into_iter()
                    .zip(groups)
                    .all(|(length, group)| {
                        group.len() == length && group.chars().all(|char| char.is_ascii_hexdigit())
                    })
        }
        "^pkg:.+/.+" => value.starts_with("pkg:") && value[4..].contains('/'),
        "^(cpe:2\\.3:|cpe:/).+" => value.starts_with("cpe:2.3:") || value.starts_with("cpe:/"),
        "^SPDXRef-.+" => value.starts_with("SPDXRef-") && value.len() > "SPDXRef-".len(),
        _ => true,
    }
}

fn embedded_csaf_schema() -> Value {
    json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "ISCY embedded CSAF 2.0 validation profile",
        "type": "object",
        "required": ["document", "vulnerabilities"],
        "additionalProperties": true,
        "properties": {
            "document": {
                "type": "object",
                "required": ["category", "csaf_version", "publisher", "title", "tracking"],
                "additionalProperties": true,
                "properties": {
                    "category": {"type": "string", "minLength": 1},
                    "csaf_version": {"const": "2.0"},
                    "title": {"type": "string", "minLength": 1},
                    "publisher": {
                        "type": "object",
                        "required": ["category", "name", "namespace"],
                        "additionalProperties": true,
                        "properties": {
                            "category": {
                                "type": "string",
                                "enum": ["coordinator", "discoverer", "other", "translator", "user", "vendor"]
                            },
                            "name": {"type": "string", "minLength": 1},
                            "namespace": {"type": "string", "format": "uri"}
                        }
                    },
                    "tracking": {
                        "type": "object",
                        "required": [
                            "current_release_date",
                            "id",
                            "initial_release_date",
                            "revision_history",
                            "status",
                            "version"
                        ],
                        "additionalProperties": true,
                        "properties": {
                            "current_release_date": {"type": "string", "format": "date-time"},
                            "id": {"type": "string", "minLength": 1},
                            "initial_release_date": {"type": "string", "format": "date-time"},
                            "revision_history": {
                                "type": "array",
                                "minItems": 1,
                                "items": {
                                    "type": "object",
                                    "required": ["date", "number", "summary"],
                                    "additionalProperties": true,
                                    "properties": {
                                        "date": {"type": "string", "format": "date-time"},
                                        "number": {"type": "string", "minLength": 1},
                                        "summary": {"type": "string", "minLength": 1}
                                    }
                                }
                            },
                            "status": {"type": "string", "enum": ["draft", "final", "interim"]},
                            "version": {"type": "string", "minLength": 1}
                        }
                    }
                }
            },
            "vulnerabilities": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "required": ["product_status"],
                    "additionalProperties": true,
                    "properties": {
                        "cve": {"type": "string", "pattern": "^CVE-[0-9]{4}-[0-9]{4,}$"},
                        "product_status": {"type": "object"}
                    }
                }
            }
        }
    })
}

fn embedded_cyclonedx_schema() -> Value {
    json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "ISCY embedded CycloneDX 1.6 validation profile",
        "type": "object",
        "required": ["bomFormat", "specVersion", "components"],
        "additionalProperties": false,
        "properties": {
            "$schema": {"type": "string"},
            "bomFormat": {"const": "CycloneDX"},
            "specVersion": {"const": "1.6"},
            "serialNumber": {
                "type": "string",
                "pattern": "^urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
            },
            "version": {"type": "integer", "minimum": 1},
            "metadata": {"type": "object"},
            "components": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "required": ["type", "name"],
                    "additionalProperties": true,
                    "properties": {
                        "type": {
                            "type": "string",
                            "enum": [
                                "application",
                                "framework",
                                "library",
                                "container",
                                "platform",
                                "operating-system",
                                "device",
                                "device-driver",
                                "firmware",
                                "file",
                                "machine-learning-model",
                                "data",
                                "cryptographic-asset"
                            ]
                        },
                        "name": {"type": "string", "minLength": 1},
                        "version": {"type": "string"},
                        "purl": {"type": "string", "pattern": "^pkg:.+/.+"},
                        "cpe": {"type": "string", "pattern": "^(cpe:2\\.3:|cpe:/).+"},
                        "supplier": {
                            "oneOf": [
                                {"type": "string"},
                                {"type": "object", "properties": {"name": {"type": "string"}}}
                            ]
                        }
                    }
                }
            },
            "services": {"type": "array"},
            "externalReferences": {"type": "array"},
            "dependencies": {"type": "array"},
            "compositions": {"type": "array"},
            "vulnerabilities": {"type": "array"},
            "annotations": {"type": "array"},
            "formulation": {"type": "array"},
            "declarations": {"type": "object"},
            "definitions": {"type": "object"},
            "properties": {"type": "array"},
            "signature": {"type": "object"}
        }
    })
}

fn embedded_spdx_schema() -> Value {
    json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "ISCY embedded SPDX 2.3 validation profile",
        "type": "object",
        "required": [
            "SPDXID",
            "creationInfo",
            "dataLicense",
            "documentNamespace",
            "name",
            "packages",
            "spdxVersion"
        ],
        "additionalProperties": false,
        "properties": {
            "SPDXID": {"type": "string", "pattern": "^SPDXRef-.+"},
            "annotations": {"type": "array"},
            "comment": {"type": "string"},
            "creationInfo": {
                "type": "object",
                "required": ["created", "creators"],
                "additionalProperties": true,
                "properties": {
                    "created": {"type": "string", "format": "date-time"},
                    "creators": {
                        "type": "array",
                        "minItems": 1,
                        "items": {"type": "string", "minLength": 1}
                    }
                }
            },
            "dataLicense": {"type": "string", "minLength": 1},
            "documentDescribes": {"type": "array"},
            "documentNamespace": {"type": "string", "format": "uri"},
            "externalDocumentRefs": {"type": "array"},
            "files": {"type": "array"},
            "hasExtractedLicensingInfos": {"type": "array"},
            "name": {"type": "string", "minLength": 1},
            "packages": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "required": ["SPDXID", "downloadLocation", "name"],
                    "additionalProperties": true,
                    "properties": {
                        "SPDXID": {"type": "string", "pattern": "^SPDXRef-.+"},
                        "downloadLocation": {"type": "string", "minLength": 1},
                        "externalRefs": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["referenceCategory", "referenceType", "referenceLocator"],
                                "additionalProperties": true,
                                "properties": {
                                    "referenceCategory": {"type": "string", "minLength": 1},
                                    "referenceType": {"type": "string", "minLength": 1},
                                    "referenceLocator": {"type": "string", "minLength": 1}
                                }
                            }
                        },
                        "name": {"type": "string", "minLength": 1},
                        "supplier": {"type": "string"},
                        "versionInfo": {"type": "string"}
                    }
                }
            },
            "relationships": {"type": "array"},
            "revieweds": {"type": "array"},
            "snippets": {"type": "array"},
            "spdxVersion": {"const": "SPDX-2.3"}
        }
    })
}

fn validate_allowed_top_level(
    document: &Value,
    allowed: &[&str],
    label: &str,
    errors: &mut Vec<String>,
) {
    if let Some(object) = document.as_object() {
        for key in object.keys() {
            if !allowed.contains(&key.as_str()) {
                errors.push(format!(
                    "{label} enthaelt ein nicht durch das ISCY-Schema-Profil erlaubtes Top-Level-Feld: {key}."
                ));
            }
        }
    }
}

fn require_string(value: &Value, field: &str, label: &str, errors: &mut Vec<String>) {
    if value
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .is_none_or(str::is_empty)
    {
        errors.push(format!("{label} fehlt oder ist leer."));
    }
}

fn require_uri_string(value: &Value, field: &str, label: &str, errors: &mut Vec<String>) {
    match value.get(field).and_then(Value::as_str).map(str::trim) {
        Some(uri) if uri.starts_with("https://") || uri.starts_with("http://") => {}
        Some(_) => errors.push(format!("{label} muss eine HTTP(S)-URI sein.")),
        None => errors.push(format!("{label} fehlt oder ist leer.")),
    }
}

fn validate_rfc3339_like(value: &str, label: &str, errors: &mut Vec<String>) {
    let trimmed = value.trim();
    if chrono::DateTime::parse_from_rfc3339(trimmed).is_err() {
        errors.push(format!(
            "{label} muss als RFC3339/ISO-8601 Date-Time angegeben sein."
        ));
    }
}

fn validate_cve_like(value: &str, label: &str, errors: &mut Vec<String>) {
    let parts = value.trim().split('-').collect::<Vec<_>>();
    let valid = parts.len() == 3
        && parts[0].eq_ignore_ascii_case("CVE")
        && parts[1].len() == 4
        && parts[1].chars().all(|ch| ch.is_ascii_digit())
        && parts[2].len() >= 4
        && parts[2].chars().all(|ch| ch.is_ascii_digit());
    if !valid {
        errors.push(format!("{label} ist keine gueltige CVE-ID."));
    }
}

fn validate_urn_uuid(value: &str, label: &str, errors: &mut Vec<String>) {
    let uuid = value.trim().strip_prefix("urn:uuid:");
    let valid = uuid.is_some_and(|uuid| {
        uuid.len() == 36
            && uuid.chars().enumerate().all(|(idx, ch)| {
                if [8, 13, 18, 23].contains(&idx) {
                    ch == '-'
                } else {
                    ch.is_ascii_hexdigit()
                }
            })
    });
    if !valid {
        errors.push(format!(
            "{label} muss dem Muster urn:uuid:<RFC4122-UUID> entsprechen."
        ));
    }
}

fn validate_purl(value: &str, label: &str, errors: &mut Vec<String>) {
    let trimmed = value.trim();
    if !(trimmed.starts_with("pkg:") && trimmed.contains('/')) {
        errors.push(format!(
            "{label} muss eine Package URL mit Prefix pkg: sein."
        ));
    }
}

fn validate_cpe(value: &str, label: &str, errors: &mut Vec<String>) {
    let trimmed = value.trim();
    if !(trimmed.starts_with("cpe:2.3:") || trimmed.starts_with("cpe:/")) {
        errors.push(format!("{label} muss CPE 2.3 oder Legacy-CPE-URI sein."));
    }
}

fn validate_cyclonedx_component_type(component_type: &str, index: usize, errors: &mut Vec<String>) {
    let allowed = [
        "application",
        "framework",
        "library",
        "container",
        "platform",
        "operating-system",
        "device",
        "device-driver",
        "firmware",
        "file",
        "machine-learning-model",
        "data",
        "cryptographic-asset",
    ];
    if !allowed.contains(&component_type.trim()) {
        errors.push(format!(
            "CycloneDX components[{index}].type ist kein erlaubter CycloneDX-1.6-Komponententyp."
        ));
    }
}

fn json_field_string(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn json_pointer_string(value: &Value, pointer: &str) -> Option<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn validation_status(errors: &[String]) -> &'static str {
    if errors.is_empty() {
        "VALID"
    } else {
        "INVALID"
    }
}

fn csaf_advisory_status(tracking_status: &str) -> &'static str {
    match tracking_status.trim().to_ascii_lowercase().as_str() {
        "final" => "PUBLISHED",
        "draft" => "DRAFT",
        _ => "DRAFT",
    }
}

fn import_artifact_list_postgres_sql() -> &'static str {
    r#"
    SELECT
        artifact.id,
        artifact.tenant_id,
        artifact.product_id,
        product.name AS product_name,
        artifact.artifact_type,
        artifact.file_name,
        artifact.document_id,
        artifact.format_name,
        artifact.format_version,
        artifact.validation_status,
        artifact.validation_errors_json,
        artifact.component_count::bigint AS component_count,
        artifact.matched_component_count::bigint AS matched_component_count,
        artifact.cve_count::bigint AS cve_count,
        artifact.created_by_id,
        artifact.created_at::text AS created_at,
        artifact.updated_at::text AS updated_at
    FROM product_security_importartifact artifact
    LEFT JOIN product_security_product product
        ON product.id = artifact.product_id AND product.tenant_id = artifact.tenant_id
    WHERE artifact.tenant_id = $1
    ORDER BY artifact.created_at DESC, artifact.id DESC
    LIMIT $2
    "#
}

fn import_artifact_list_sqlite_sql() -> &'static str {
    r#"
    SELECT
        artifact.id,
        artifact.tenant_id,
        artifact.product_id,
        product.name AS product_name,
        artifact.artifact_type,
        artifact.file_name,
        artifact.document_id,
        artifact.format_name,
        artifact.format_version,
        artifact.validation_status,
        artifact.validation_errors_json,
        artifact.component_count,
        artifact.matched_component_count,
        artifact.cve_count,
        artifact.created_by_id,
        CAST(artifact.created_at AS TEXT) AS created_at,
        CAST(artifact.updated_at AS TEXT) AS updated_at
    FROM product_security_importartifact artifact
    LEFT JOIN product_security_product product
        ON product.id = artifact.product_id AND product.tenant_id = artifact.tenant_id
    WHERE artifact.tenant_id = ?
    ORDER BY artifact.created_at DESC, artifact.id DESC
    LIMIT ?
    "#
}

fn import_artifact_detail_postgres_sql() -> &'static str {
    r#"
    SELECT
        artifact.id,
        artifact.tenant_id,
        artifact.product_id,
        product.name AS product_name,
        artifact.artifact_type,
        artifact.file_name,
        artifact.document_id,
        artifact.format_name,
        artifact.format_version,
        artifact.validation_status,
        artifact.validation_errors_json,
        artifact.component_count::bigint AS component_count,
        artifact.matched_component_count::bigint AS matched_component_count,
        artifact.cve_count::bigint AS cve_count,
        artifact.created_by_id,
        artifact.created_at::text AS created_at,
        artifact.updated_at::text AS updated_at
    FROM product_security_importartifact artifact
    LEFT JOIN product_security_product product
        ON product.id = artifact.product_id AND product.tenant_id = artifact.tenant_id
    WHERE artifact.tenant_id = $1 AND artifact.id = $2
    "#
}

fn import_artifact_detail_sqlite_sql() -> &'static str {
    r#"
    SELECT
        artifact.id,
        artifact.tenant_id,
        artifact.product_id,
        product.name AS product_name,
        artifact.artifact_type,
        artifact.file_name,
        artifact.document_id,
        artifact.format_name,
        artifact.format_version,
        artifact.validation_status,
        artifact.validation_errors_json,
        artifact.component_count,
        artifact.matched_component_count,
        artifact.cve_count,
        artifact.created_by_id,
        CAST(artifact.created_at AS TEXT) AS created_at,
        CAST(artifact.updated_at AS TEXT) AS updated_at
    FROM product_security_importartifact artifact
    LEFT JOIN product_security_product product
        ON product.id = artifact.product_id AND product.tenant_id = artifact.tenant_id
    WHERE artifact.tenant_id = ? AND artifact.id = ?
    "#
}

fn import_component_list_postgres_sql() -> &'static str {
    r#"
    SELECT
        import_component.id,
        import_component.artifact_id,
        import_component.tenant_id,
        import_component.product_id,
        product.name AS product_name,
        import_component.component_id,
        component.name AS component_name,
        import_component.name,
        import_component.version,
        import_component.package_url,
        import_component.cpe23_uri,
        import_component.supplier_name,
        import_component.match_status,
        import_component.match_reason,
        import_component.created_at::text AS created_at
    FROM product_security_importcomponent import_component
    LEFT JOIN product_security_product product
        ON product.id = import_component.product_id
       AND product.tenant_id = import_component.tenant_id
    LEFT JOIN product_security_component component
        ON component.id = import_component.component_id
       AND component.tenant_id = import_component.tenant_id
    WHERE import_component.tenant_id = $1
      AND import_component.artifact_id = $2
    ORDER BY import_component.match_status DESC, import_component.name ASC, import_component.id ASC
    "#
}

fn import_component_list_sqlite_sql() -> &'static str {
    r#"
    SELECT
        import_component.id,
        import_component.artifact_id,
        import_component.tenant_id,
        import_component.product_id,
        product.name AS product_name,
        import_component.component_id,
        component.name AS component_name,
        import_component.name,
        import_component.version,
        import_component.package_url,
        import_component.cpe23_uri,
        import_component.supplier_name,
        import_component.match_status,
        import_component.match_reason,
        CAST(import_component.created_at AS TEXT) AS created_at
    FROM product_security_importcomponent import_component
    LEFT JOIN product_security_product product
        ON product.id = import_component.product_id
       AND product.tenant_id = import_component.tenant_id
    LEFT JOIN product_security_component component
        ON component.id = import_component.component_id
       AND component.tenant_id = import_component.tenant_id
    WHERE import_component.tenant_id = ?
      AND import_component.artifact_id = ?
    ORDER BY import_component.match_status DESC, import_component.name ASC, import_component.id ASC
    "#
}

fn cve_correlation_list_postgres_sql() -> &'static str {
    r#"
    SELECT
        corr.id,
        corr.cve,
        corr.asset_id,
        asset.name AS asset_name,
        corr.product_id,
        product.name AS product_name,
        corr.component_id,
        component.name AS component_name,
        corr.match_type,
        corr.match_value,
        corr.confidence::bigint AS confidence,
        corr.status,
        corr.rationale,
        corr.created_at::text AS created_at,
        corr.updated_at::text AS updated_at
    FROM product_security_cvecorrelation corr
    LEFT JOIN assets_app_informationasset asset
        ON asset.id = corr.asset_id AND asset.tenant_id = corr.tenant_id
    LEFT JOIN product_security_product product
        ON product.id = corr.product_id AND product.tenant_id = corr.tenant_id
    LEFT JOIN product_security_component component
        ON component.id = corr.component_id AND component.tenant_id = corr.tenant_id
    WHERE corr.tenant_id = $1
    ORDER BY corr.created_at DESC, corr.id DESC
    LIMIT $2
    "#
}

fn cve_correlation_detail_postgres_sql() -> &'static str {
    r#"
    SELECT
        corr.id,
        corr.cve,
        corr.asset_id,
        asset.name AS asset_name,
        corr.product_id,
        product.name AS product_name,
        corr.component_id,
        component.name AS component_name,
        corr.match_type,
        corr.match_value,
        corr.confidence::bigint AS confidence,
        corr.status,
        corr.rationale,
        corr.created_at::text AS created_at,
        corr.updated_at::text AS updated_at
    FROM product_security_cvecorrelation corr
    LEFT JOIN assets_app_informationasset asset
        ON asset.id = corr.asset_id AND asset.tenant_id = corr.tenant_id
    LEFT JOIN product_security_product product
        ON product.id = corr.product_id AND product.tenant_id = corr.tenant_id
    LEFT JOIN product_security_component component
        ON component.id = corr.component_id AND component.tenant_id = corr.tenant_id
    WHERE corr.tenant_id = $1 AND corr.id = $2
    "#
}

fn cve_correlation_list_sqlite_sql() -> &'static str {
    r#"
    SELECT
        corr.id,
        corr.cve,
        corr.asset_id,
        asset.name AS asset_name,
        corr.product_id,
        product.name AS product_name,
        corr.component_id,
        component.name AS component_name,
        corr.match_type,
        corr.match_value,
        corr.confidence,
        corr.status,
        corr.rationale,
        CAST(corr.created_at AS TEXT) AS created_at,
        CAST(corr.updated_at AS TEXT) AS updated_at
    FROM product_security_cvecorrelation corr
    LEFT JOIN assets_app_informationasset asset
        ON asset.id = corr.asset_id AND asset.tenant_id = corr.tenant_id
    LEFT JOIN product_security_product product
        ON product.id = corr.product_id AND product.tenant_id = corr.tenant_id
    LEFT JOIN product_security_component component
        ON component.id = corr.component_id AND component.tenant_id = corr.tenant_id
    WHERE corr.tenant_id = ?
    ORDER BY corr.created_at DESC, corr.id DESC
    LIMIT ?
    "#
}

fn cve_correlation_detail_sqlite_sql() -> &'static str {
    r#"
    SELECT
        corr.id,
        corr.cve,
        corr.asset_id,
        asset.name AS asset_name,
        corr.product_id,
        product.name AS product_name,
        corr.component_id,
        component.name AS component_name,
        corr.match_type,
        corr.match_value,
        corr.confidence,
        corr.status,
        corr.rationale,
        CAST(corr.created_at AS TEXT) AS created_at,
        CAST(corr.updated_at AS TEXT) AS updated_at
    FROM product_security_cvecorrelation corr
    LEFT JOIN assets_app_informationasset asset
        ON asset.id = corr.asset_id AND asset.tenant_id = corr.tenant_id
    LEFT JOIN product_security_product product
        ON product.id = corr.product_id AND product.tenant_id = corr.tenant_id
    LEFT JOIN product_security_component component
        ON component.id = corr.component_id AND component.tenant_id = corr.tenant_id
    WHERE corr.tenant_id = ? AND corr.id = ?
    "#
}

fn import_artifact_from_pg_row(
    row: PgRow,
) -> Result<ProductSecurityImportArtifactSummary, sqlx::Error> {
    Ok(ProductSecurityImportArtifactSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        product_name: row.try_get("product_name")?,
        artifact_type: row.try_get("artifact_type")?,
        file_name: row.try_get("file_name")?,
        document_id: row.try_get("document_id")?,
        format_name: row.try_get("format_name")?,
        format_version: row.try_get("format_version")?,
        validation_status: row.try_get("validation_status")?,
        validation_errors: parse_json_string_array(row.try_get("validation_errors_json")?),
        component_count: row.try_get("component_count")?,
        matched_component_count: row.try_get("matched_component_count")?,
        cve_count: row.try_get("cve_count")?,
        created_by_id: row.try_get("created_by_id")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn import_artifact_from_sqlite_row(
    row: SqliteRow,
) -> Result<ProductSecurityImportArtifactSummary, sqlx::Error> {
    Ok(ProductSecurityImportArtifactSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        product_name: row.try_get("product_name")?,
        artifact_type: row.try_get("artifact_type")?,
        file_name: row.try_get("file_name")?,
        document_id: row.try_get("document_id")?,
        format_name: row.try_get("format_name")?,
        format_version: row.try_get("format_version")?,
        validation_status: row.try_get("validation_status")?,
        validation_errors: parse_json_string_array(row.try_get("validation_errors_json")?),
        component_count: row.try_get("component_count")?,
        matched_component_count: row.try_get("matched_component_count")?,
        cve_count: row.try_get("cve_count")?,
        created_by_id: row.try_get("created_by_id")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn import_component_from_pg_row(
    row: PgRow,
) -> Result<ProductSecurityImportComponentSummary, sqlx::Error> {
    let match_status: String = row.try_get("match_status")?;
    Ok(ProductSecurityImportComponentSummary {
        id: row.try_get("id")?,
        artifact_id: row.try_get("artifact_id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        product_name: row.try_get("product_name")?,
        component_id: row.try_get("component_id")?,
        component_name: row.try_get("component_name")?,
        name: row.try_get("name")?,
        version: row.try_get("version")?,
        package_url: row.try_get("package_url")?,
        cpe23_uri: row.try_get("cpe23_uri")?,
        supplier_name: row.try_get("supplier_name")?,
        match_status_label: import_component_match_status_label(&match_status).to_string(),
        match_status,
        match_reason: row.try_get("match_reason")?,
        created_at: row.try_get("created_at")?,
    })
}

fn import_component_from_sqlite_row(
    row: SqliteRow,
) -> Result<ProductSecurityImportComponentSummary, sqlx::Error> {
    let match_status: String = row.try_get("match_status")?;
    Ok(ProductSecurityImportComponentSummary {
        id: row.try_get("id")?,
        artifact_id: row.try_get("artifact_id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        product_name: row.try_get("product_name")?,
        component_id: row.try_get("component_id")?,
        component_name: row.try_get("component_name")?,
        name: row.try_get("name")?,
        version: row.try_get("version")?,
        package_url: row.try_get("package_url")?,
        cpe23_uri: row.try_get("cpe23_uri")?,
        supplier_name: row.try_get("supplier_name")?,
        match_status_label: import_component_match_status_label(&match_status).to_string(),
        match_status,
        match_reason: row.try_get("match_reason")?,
        created_at: row.try_get("created_at")?,
    })
}

fn import_component_match_status_label(status: &str) -> &'static str {
    match status.trim().to_ascii_uppercase().as_str() {
        "MATCHED" => "Gematcht",
        "UNMATCHED" => "Nicht gematcht",
        _ => "Unbekannt",
    }
}

fn cve_risk_review_summary_from_candidate(
    candidate: AcceptedCorrelationWorkCandidate,
    evidence_key: String,
    risk: Option<ProductSecurityRiskLink>,
    roadmap_task: Option<ProductSecurityRoadmapTaskLink>,
    evidence_count: i64,
) -> ProductSecurityCveRiskReviewSummary {
    let risk_status = risk.as_ref().map(|item| item.status.clone());
    let roadmap_task_status = roadmap_task.as_ref().map(|item| item.status.clone());
    let needs_review = risk_status
        .as_deref()
        .map(cve_risk_status_needs_review)
        .unwrap_or(true);
    ProductSecurityCveRiskReviewSummary {
        correlation_id: candidate.correlation_id,
        cve: candidate.cve,
        asset_id: candidate.asset_id,
        asset_name: candidate.asset_name,
        product_id: candidate.product_id,
        product_name: candidate.product_name,
        component_id: candidate.component_id,
        component_name: candidate.component_name,
        match_type: candidate.match_type,
        match_value: candidate.match_value,
        confidence: candidate.confidence,
        evidence_key,
        risk_id: risk.as_ref().map(|item| item.id),
        risk_title: risk.as_ref().map(|item| item.title.clone()),
        risk_status_label: risk_status
            .as_deref()
            .map(risk_status_label)
            .unwrap_or("Risiko fehlt")
            .to_string(),
        risk_status,
        roadmap_task_id: roadmap_task.as_ref().map(|item| item.id),
        roadmap_task_title: roadmap_task.as_ref().map(|item| item.title.clone()),
        roadmap_task_status_label: roadmap_task_status
            .as_deref()
            .map(roadmap_task_status_label)
            .unwrap_or_else(|| "Task fehlt".to_string()),
        roadmap_task_status,
        evidence_count,
        needs_review,
        evidence_missing: evidence_count == 0,
    }
}

fn build_review_metrics(
    correlations: &[ProductSecurityCveCorrelationSummary],
    queue: &[ProductSecurityCveRiskReviewSummary],
) -> ProductSecurityReviewMetrics {
    let suggested_correlation_reviews = correlations
        .iter()
        .filter(|item| item.status.eq_ignore_ascii_case("SUGGESTED"))
        .count() as i64;
    let open_risk_reviews = queue.iter().filter(|item| item.needs_review).count() as i64;
    let evidence_missing = queue.iter().filter(|item| item.evidence_missing).count() as i64;
    ProductSecurityReviewMetrics {
        open_cve_reviews: suggested_correlation_reviews + open_risk_reviews,
        suggested_correlation_reviews,
        open_risk_reviews,
        evidence_missing,
    }
}

fn build_trend_dashboard(
    products: &[ProductListItem],
    snapshots: &[ProductSecuritySnapshotSummary],
    import_artifacts: &[ProductSecurityImportArtifactSummary],
    review_metrics: &ProductSecurityReviewMetrics,
    queue: &[ProductSecurityCveRiskReviewSummary],
    posture: &ProductSecurityPosture,
) -> ProductSecurityTrendDashboard {
    let product_count = products.len() as i64;
    let component_count = products
        .iter()
        .map(|product| product.component_count)
        .sum::<i64>();
    let components_with_sbom = products
        .iter()
        .map(|product| product.sbom_component_count)
        .sum::<i64>();
    let products_with_csaf = products
        .iter()
        .filter(|product| product.csaf_advisory_count > 0)
        .count() as i64;
    let products_with_threat_tara = products
        .iter()
        .filter(|product| product.threat_model_count > 0 && product.tara_count > 0)
        .count() as i64;
    let coverage = ProductSecurityCoverageTrend {
        product_count,
        component_count,
        components_with_sbom,
        products_with_csaf,
        products_with_threat_tara,
        sbom_coverage_percent: product_security_ratio_percent(
            components_with_sbom,
            component_count,
        ),
        csaf_coverage_percent: product_security_ratio_percent(products_with_csaf, product_count),
        threat_tara_coverage_percent: product_security_ratio_percent(
            products_with_threat_tara,
            product_count,
        ),
    };

    let total_imports = import_artifacts.len() as i64;
    let valid_imports = import_artifacts
        .iter()
        .filter(|artifact| artifact.validation_status.eq_ignore_ascii_case("VALID"))
        .count() as i64;
    let warning_imports = import_artifacts
        .iter()
        .filter(|artifact| {
            artifact.validation_status.eq_ignore_ascii_case("WARNING")
                || artifact.validation_status.eq_ignore_ascii_case("WARN")
        })
        .count() as i64;
    let invalid_imports = import_artifacts
        .iter()
        .filter(|artifact| {
            let status = artifact.validation_status.trim().to_ascii_uppercase();
            !matches!(status.as_str(), "VALID" | "WARNING" | "WARN")
        })
        .count() as i64;
    let validation_error_count = import_artifacts
        .iter()
        .map(|artifact| artifact.validation_errors.len() as i64)
        .sum();
    let import_validation = ProductSecurityImportValidationTrend {
        total_imports,
        valid_imports,
        warning_imports,
        invalid_imports,
        validation_error_count,
    };

    let latest_snapshot = snapshots.first();
    let risk_missing = queue.iter().filter(|item| item.risk_id.is_none()).count() as i64;
    let signals = vec![
        product_security_trend_signal(
            "sbom_coverage",
            "SBOM Coverage",
            coverage.sbom_coverage_percent,
            None,
            false,
            if coverage.sbom_coverage_percent >= 80 || component_count == 0 {
                "ok"
            } else {
                "warn"
            },
            &format!(
                "{} von {} Komponenten mit SBOM",
                coverage.components_with_sbom, coverage.component_count
            ),
        ),
        product_security_trend_signal(
            "open_vulnerabilities",
            "Offene Schwachstellen",
            posture.open_vulnerabilities,
            latest_snapshot.map(|snapshot| snapshot.open_vulnerability_count),
            true,
            if posture.critical_open_vulnerabilities > 0 {
                "critical"
            } else if posture.open_vulnerabilities > 0 {
                "warn"
            } else {
                "ok"
            },
            "Offene Product-Security-Vulnerabilities aus Produktdaten",
        ),
        product_security_trend_signal(
            "open_cve_reviews",
            "Offene CVE-Reviews",
            review_metrics.open_cve_reviews,
            None,
            true,
            if review_metrics.open_cve_reviews > 0 {
                "warn"
            } else {
                "ok"
            },
            "Suggested Korrelationen plus offene CVE-Risiko-Reviews",
        ),
        product_security_trend_signal(
            "evidence_missing",
            "Evidence fehlt",
            review_metrics.evidence_missing,
            None,
            true,
            if review_metrics.evidence_missing > 0 {
                "warn"
            } else {
                "ok"
            },
            "Akzeptierte CVE-Korrelationen ohne verknuepfte Evidence",
        ),
        product_security_trend_signal(
            "risk_missing",
            "Risiko fehlt",
            risk_missing,
            None,
            true,
            if risk_missing > 0 { "warn" } else { "ok" },
            "Akzeptierte CVE-Korrelationen ohne erzeugtes Risiko",
        ),
        product_security_trend_signal(
            "invalid_imports",
            "Importvalidierung",
            import_validation.invalid_imports + import_validation.warning_imports,
            None,
            true,
            if import_validation.invalid_imports > 0 {
                "critical"
            } else if import_validation.warning_imports > 0 {
                "warn"
            } else {
                "ok"
            },
            "CSAF-/SBOM-Importe mit Warnungen oder Fehlern",
        ),
    ];

    let snapshot_points = snapshots
        .iter()
        .map(|snapshot| ProductSecuritySnapshotTrendPoint {
            product_id: snapshot.product_id,
            product_name: snapshot.product_name.clone(),
            created_at: snapshot.created_at.clone(),
            cra_readiness_percent: snapshot.cra_readiness_percent,
            ai_act_readiness_percent: snapshot.ai_act_readiness_percent,
            threat_model_coverage_percent: snapshot.threat_model_coverage_percent,
            psirt_readiness_percent: snapshot.psirt_readiness_percent,
            open_vulnerability_count: snapshot.open_vulnerability_count,
            critical_vulnerability_count: snapshot.critical_vulnerability_count,
        })
        .collect();

    ProductSecurityTrendDashboard {
        coverage,
        import_validation,
        signals,
        snapshot_points,
    }
}

fn product_security_ratio_percent(numerator: i64, denominator: i64) -> i64 {
    if denominator <= 0 {
        0
    } else {
        ((numerator * 100) / denominator).clamp(0, 100)
    }
}

fn product_security_trend_signal(
    key: &str,
    label: &str,
    current: i64,
    previous: Option<i64>,
    lower_is_better: bool,
    status: &str,
    detail: &str,
) -> ProductSecurityTrendSignal {
    let delta = previous.map(|previous| current - previous);
    let direction = match delta {
        Some(0) => "flat",
        Some(value) if lower_is_better && value < 0 => "better",
        Some(value) if lower_is_better && value > 0 => "worse",
        Some(value) if !lower_is_better && value > 0 => "better",
        Some(value) if !lower_is_better && value < 0 => "worse",
        Some(_) => "flat",
        None => "unknown",
    };
    ProductSecurityTrendSignal {
        key: key.to_string(),
        label: label.to_string(),
        current,
        previous,
        delta,
        direction: direction.to_string(),
        status: status.to_string(),
        detail: detail.to_string(),
    }
}

fn evidence_key_search_pattern(evidence_key: &str) -> String {
    format!("%Evidence-Key: {evidence_key}%")
}

fn cve_risk_status_needs_review(status: &str) -> bool {
    !matches!(
        status.trim().to_ascii_uppercase().as_str(),
        "ACCEPTED" | "MITIGATED" | "CLOSED"
    )
}

fn risk_status_label(status: &str) -> &'static str {
    match status.trim().to_ascii_uppercase().as_str() {
        "IDENTIFIED" => "Identifiziert",
        "ANALYZING" => "In Analyse",
        "TREATING" => "In Behandlung",
        "ACCEPTED" => "Akzeptiert",
        "MITIGATED" => "Mitigiert",
        "CLOSED" => "Geschlossen",
        _ => "Unbekannt",
    }
}

fn risk_link_from_pg_row(row: PgRow) -> Result<ProductSecurityRiskLink, sqlx::Error> {
    Ok(ProductSecurityRiskLink {
        id: row.try_get("id")?,
        title: row.try_get("title")?,
        status: row.try_get("status")?,
    })
}

fn risk_link_from_sqlite_row(row: SqliteRow) -> Result<ProductSecurityRiskLink, sqlx::Error> {
    Ok(ProductSecurityRiskLink {
        id: row.try_get("id")?,
        title: row.try_get("title")?,
        status: row.try_get("status")?,
    })
}

fn roadmap_task_link_from_pg_row(
    row: PgRow,
) -> Result<ProductSecurityRoadmapTaskLink, sqlx::Error> {
    Ok(ProductSecurityRoadmapTaskLink {
        id: row.try_get("id")?,
        title: row.try_get("title")?,
        status: row.try_get("status")?,
    })
}

fn roadmap_task_link_from_sqlite_row(
    row: SqliteRow,
) -> Result<ProductSecurityRoadmapTaskLink, sqlx::Error> {
    Ok(ProductSecurityRoadmapTaskLink {
        id: row.try_get("id")?,
        title: row.try_get("title")?,
        status: row.try_get("status")?,
    })
}

fn cve_correlation_from_pg_row(
    row: PgRow,
) -> Result<ProductSecurityCveCorrelationSummary, sqlx::Error> {
    Ok(ProductSecurityCveCorrelationSummary {
        id: row.try_get("id")?,
        cve: row.try_get("cve")?,
        asset_id: row.try_get("asset_id")?,
        asset_name: row.try_get("asset_name")?,
        product_id: row.try_get("product_id")?,
        product_name: row.try_get("product_name")?,
        component_id: row.try_get("component_id")?,
        component_name: row.try_get("component_name")?,
        match_type: row.try_get("match_type")?,
        match_value: row.try_get("match_value")?,
        confidence: row.try_get("confidence")?,
        status: row.try_get("status")?,
        rationale: row.try_get("rationale")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn cve_correlation_from_sqlite_row(
    row: SqliteRow,
) -> Result<ProductSecurityCveCorrelationSummary, sqlx::Error> {
    Ok(ProductSecurityCveCorrelationSummary {
        id: row.try_get("id")?,
        cve: row.try_get("cve")?,
        asset_id: row.try_get("asset_id")?,
        asset_name: row.try_get("asset_name")?,
        product_id: row.try_get("product_id")?,
        product_name: row.try_get("product_name")?,
        component_id: row.try_get("component_id")?,
        component_name: row.try_get("component_name")?,
        match_type: row.try_get("match_type")?,
        match_value: row.try_get("match_value")?,
        confidence: row.try_get("confidence")?,
        status: row.try_get("status")?,
        rationale: row.try_get("rationale")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
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
        component_count: row.try_get("component_count")?,
        sbom_component_count: row.try_get("sbom_component_count")?,
        csaf_advisory_count: row.try_get("csaf_advisory_count")?,
        threat_model_count: row.try_get("threat_model_count")?,
        tara_count: row.try_get("tara_count")?,
        vulnerability_count: row.try_get("vulnerability_count")?,
        cve_count: row.try_get("cve_count")?,
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
        component_count: row.try_get("component_count")?,
        sbom_component_count: row.try_get("sbom_component_count")?,
        csaf_advisory_count: row.try_get("csaf_advisory_count")?,
        threat_model_count: row.try_get("threat_model_count")?,
        tara_count: row.try_get("tara_count")?,
        vulnerability_count: row.try_get("vulnerability_count")?,
        cve_count: row.try_get("cve_count")?,
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
        cpe23_uri: row.try_get("cpe23_uri")?,
        package_url: row.try_get("package_url")?,
        sbom_format: row.try_get("sbom_format")?,
        sbom_document_url: row.try_get("sbom_document_url")?,
        sbom_digest: row.try_get("sbom_digest")?,
        sbom_generated_at: row.try_get("sbom_generated_at")?,
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
        cpe23_uri: row.try_get("cpe23_uri")?,
        package_url: row.try_get("package_url")?,
        sbom_format: row.try_get("sbom_format")?,
        sbom_document_url: row.try_get("sbom_document_url")?,
        sbom_digest: row.try_get("sbom_digest")?,
        sbom_generated_at: row.try_get("sbom_generated_at")?,
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
        cpe23_uri: row.try_get("cpe23_uri")?,
        advisory_ids: parse_json_string_array(row.try_get("advisory_ids_json")?),
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
        cpe23_uri: row.try_get("cpe23_uri")?,
        advisory_ids: parse_json_string_array(row.try_get("advisory_ids_json")?),
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
        csaf_url: row.try_get("csaf_url")?,
        csaf_document_id: row.try_get("csaf_document_id")?,
        csaf_profile: row.try_get("csaf_profile")?,
        csaf_tracking_status: row.try_get("csaf_tracking_status")?,
        csaf_revision: row.try_get("csaf_revision")?,
        cve_list: parse_json_string_array(row.try_get("cve_list_json")?),
        product_status: parse_json_value(row.try_get("product_status_json")?),
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
        csaf_url: row.try_get("csaf_url")?,
        csaf_document_id: row.try_get("csaf_document_id")?,
        csaf_profile: row.try_get("csaf_profile")?,
        csaf_tracking_status: row.try_get("csaf_tracking_status")?,
        csaf_revision: row.try_get("csaf_revision")?,
        cve_list: parse_json_string_array(row.try_get("cve_list_json")?),
        product_status: parse_json_value(row.try_get("product_status_json")?),
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

fn roadmap_task_current_from_pg_row(
    row: PgRow,
) -> Result<ProductSecurityRoadmapTaskCurrent, sqlx::Error> {
    Ok(ProductSecurityRoadmapTaskCurrent {
        product_id: row.try_get("product_id")?,
        roadmap_id: row.try_get("roadmap_id")?,
        status: row.try_get("status")?,
        priority: row.try_get("priority")?,
        owner_role: row.try_get("owner_role")?,
        due_in_days: row.try_get("due_in_days")?,
        dependency_text: row.try_get("dependency_text")?,
    })
}

fn roadmap_task_current_from_sqlite_row(
    row: SqliteRow,
) -> Result<ProductSecurityRoadmapTaskCurrent, sqlx::Error> {
    Ok(ProductSecurityRoadmapTaskCurrent {
        product_id: row.try_get("product_id")?,
        roadmap_id: row.try_get("roadmap_id")?,
        status: row.try_get("status")?,
        priority: row.try_get("priority")?,
        owner_role: row.try_get("owner_role")?,
        due_in_days: row.try_get("due_in_days")?,
        dependency_text: row.try_get("dependency_text")?,
    })
}

fn vulnerability_current_from_pg_row(
    row: PgRow,
) -> Result<ProductSecurityVulnerabilityCurrent, sqlx::Error> {
    Ok(ProductSecurityVulnerabilityCurrent {
        product_id: row.try_get("product_id")?,
        severity: row.try_get("severity")?,
        status: row.try_get("status")?,
        remediation_due: row.try_get("remediation_due")?,
        summary: row.try_get("summary")?,
    })
}

fn vulnerability_current_from_sqlite_row(
    row: SqliteRow,
) -> Result<ProductSecurityVulnerabilityCurrent, sqlx::Error> {
    Ok(ProductSecurityVulnerabilityCurrent {
        product_id: row.try_get("product_id")?,
        severity: row.try_get("severity")?,
        status: row.try_get("status")?,
        remediation_due: row.try_get("remediation_due")?,
        summary: row.try_get("summary")?,
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

fn normalize_roadmap_task_status(value: &str) -> String {
    match value.trim().to_ascii_uppercase().as_str() {
        "OPEN" => "OPEN",
        "PLANNED" => "PLANNED",
        "IN_PROGRESS" => "IN_PROGRESS",
        "DONE" => "DONE",
        _ => "OPEN",
    }
    .to_string()
}

fn normalize_roadmap_task_priority(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    match trimmed.to_ascii_uppercase().as_str() {
        "CRITICAL" => "CRITICAL".to_string(),
        "HIGH" => "HIGH".to_string(),
        "MEDIUM" => "MEDIUM".to_string(),
        "LOW" => "LOW".to_string(),
        _ => trimmed.to_string(),
    }
}

fn normalize_vulnerability_severity(value: &str) -> String {
    match value.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => "CRITICAL",
        "HIGH" => "HIGH",
        "MEDIUM" => "MEDIUM",
        "LOW" => "LOW",
        _ => "MEDIUM",
    }
    .to_string()
}

fn normalize_vulnerability_status(value: &str) -> String {
    match value.trim().to_ascii_uppercase().as_str() {
        "OPEN" => "OPEN",
        "TRIAGED" => "TRIAGED",
        "MITIGATED" => "MITIGATED",
        "FIXED" => "FIXED",
        "ACCEPTED" => "ACCEPTED",
        _ => "OPEN",
    }
    .to_string()
}

fn normalize_cve_correlation_status(value: &str) -> anyhow::Result<String> {
    match value.trim().to_ascii_uppercase().as_str() {
        "SUGGESTED" => Ok("SUGGESTED".to_string()),
        "ACCEPTED" => Ok("ACCEPTED".to_string()),
        "REJECTED" => Ok("REJECTED".to_string()),
        other => bail!(
            "CVE-Korrelationsstatus '{other}' ist ungueltig. Erlaubt sind SUGGESTED, ACCEPTED, REJECTED."
        ),
    }
}

fn normalize_optional_date_text(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn parse_json_string_array(value: String) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(&value).unwrap_or_default()
}

fn parse_json_value(value: String) -> Value {
    serde_json::from_str::<Value>(&value).unwrap_or(Value::Object(Default::default()))
}
