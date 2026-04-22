use axum::{
    extract::Query,
    extract::{Json, Path, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, patch, post},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod assessment_store;
pub mod asset_store;
pub mod catalog_store;
pub mod cve_store;
pub mod dashboard_store;
pub mod evidence_store;
pub mod import_store;
pub mod process_store;
pub mod product_security_store;
pub mod report_store;
pub mod request_context;
pub mod requirement_store;
pub mod risk_store;
pub mod roadmap_store;
pub mod tenant_store;
pub mod wizard_store;

use assessment_store::AssessmentStore;
use asset_store::AssetStore;
use catalog_store::CatalogStore;
use cve_store::{CveStore, NvdCveRecord};
use dashboard_store::DashboardStore;
use evidence_store::EvidenceStore;
use import_store::ImportStore;
use process_store::ProcessStore;
use product_security_store::ProductSecurityStore;
use report_store::ReportStore;
use request_context::RequestContext;
use requirement_store::RequirementStore;
use risk_store::RiskStore;
use roadmap_store::RoadmapStore;
use tenant_store::TenantStore;
use wizard_store::WizardStore;

#[derive(Clone, Default)]
pub struct AppState {
    pub asset_store: Option<AssetStore>,
    pub assessment_store: Option<AssessmentStore>,
    pub catalog_store: Option<CatalogStore>,
    pub cve_store: Option<CveStore>,
    pub dashboard_store: Option<DashboardStore>,
    pub evidence_store: Option<EvidenceStore>,
    pub import_store: Option<ImportStore>,
    pub process_store: Option<ProcessStore>,
    pub product_security_store: Option<ProductSecurityStore>,
    pub report_store: Option<ReportStore>,
    pub requirement_store: Option<RequirementStore>,
    pub risk_store: Option<RiskStore>,
    pub roadmap_store: Option<RoadmapStore>,
    pub tenant_store: Option<TenantStore>,
    pub wizard_store: Option<WizardStore>,
}

impl AppState {
    pub fn new(cve_store: Option<CveStore>) -> Self {
        Self {
            asset_store: None,
            assessment_store: None,
            catalog_store: None,
            cve_store,
            dashboard_store: None,
            evidence_store: None,
            import_store: None,
            process_store: None,
            product_security_store: None,
            report_store: None,
            requirement_store: None,
            risk_store: None,
            roadmap_store: None,
            tenant_store: None,
            wizard_store: None,
        }
    }

    pub fn with_stores(cve_store: Option<CveStore>, tenant_store: Option<TenantStore>) -> Self {
        Self {
            asset_store: None,
            assessment_store: None,
            catalog_store: None,
            cve_store,
            dashboard_store: None,
            evidence_store: None,
            import_store: None,
            process_store: None,
            product_security_store: None,
            report_store: None,
            requirement_store: None,
            risk_store: None,
            roadmap_store: None,
            tenant_store,
            wizard_store: None,
        }
    }

    pub fn with_dashboard_store(mut self, dashboard_store: Option<DashboardStore>) -> Self {
        self.dashboard_store = dashboard_store;
        self
    }

    pub fn with_evidence_store(mut self, evidence_store: Option<EvidenceStore>) -> Self {
        self.evidence_store = evidence_store;
        self
    }

    pub fn with_import_store(mut self, import_store: Option<ImportStore>) -> Self {
        self.import_store = import_store;
        self
    }

    pub fn with_asset_store(mut self, asset_store: Option<AssetStore>) -> Self {
        self.asset_store = asset_store;
        self
    }

    pub fn with_catalog_store(mut self, catalog_store: Option<CatalogStore>) -> Self {
        self.catalog_store = catalog_store;
        self
    }

    pub fn with_assessment_store(mut self, assessment_store: Option<AssessmentStore>) -> Self {
        self.assessment_store = assessment_store;
        self
    }

    pub fn with_report_store(mut self, report_store: Option<ReportStore>) -> Self {
        self.report_store = report_store;
        self
    }

    pub fn with_requirement_store(mut self, requirement_store: Option<RequirementStore>) -> Self {
        self.requirement_store = requirement_store;
        self
    }

    pub fn with_process_store(mut self, process_store: Option<ProcessStore>) -> Self {
        self.process_store = process_store;
        self
    }

    pub fn with_product_security_store(
        mut self,
        product_security_store: Option<ProductSecurityStore>,
    ) -> Self {
        self.product_security_store = product_security_store;
        self
    }

    pub fn with_risk_store(mut self, risk_store: Option<RiskStore>) -> Self {
        self.risk_store = risk_store;
        self
    }

    pub fn with_roadmap_store(mut self, roadmap_store: Option<RoadmapStore>) -> Self {
        self.roadmap_store = roadmap_store;
        self
    }

    pub fn with_wizard_store(mut self, wizard_store: Option<WizardStore>) -> Self {
        self.wizard_store = wizard_store;
        self
    }
}

#[derive(Debug, Deserialize)]
pub struct NvdImportRequest {
    pub cve_id: String,
}

#[derive(Debug, Serialize)]
pub struct NvdImportResponse {
    pub accepted: bool,
    pub api_version: &'static str,
    pub cve_id: String,
    pub source: &'static str,
}

#[derive(Debug, Deserialize)]
pub struct NvdPersistRequest {
    pub cve: Value,
    pub cve_id: Option<String>,
    pub raw_payload: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct NvdPersistResponse {
    pub accepted: bool,
    pub api_version: &'static str,
    pub cve_id: String,
    pub source: &'static str,
    pub persisted: bool,
}

#[derive(Debug, Serialize)]
pub struct ApiErrorResponse {
    pub accepted: bool,
    pub api_version: &'static str,
    pub error_code: &'static str,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct ContextWhoamiResponse {
    pub api_version: &'static str,
    pub authenticated: bool,
    pub tenant_id: Option<i64>,
    pub user_id: Option<i64>,
    pub user_email: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TenantContextResponse {
    pub api_version: &'static str,
    pub authenticated: bool,
    pub tenant_id: i64,
    pub user_id: i64,
    pub user_email: Option<String>,
    pub authorization_model: &'static str,
}

#[derive(Debug, Serialize)]
pub struct TenantProfileResponse {
    pub api_version: &'static str,
    pub tenant: tenant_store::TenantProfile,
}

#[derive(Debug, Serialize)]
pub struct DashboardSummaryResponse {
    pub api_version: &'static str,
    #[serde(flatten)]
    pub summary: dashboard_store::DashboardSummary,
}

#[derive(Debug, Serialize)]
pub struct AssetInventoryResponse {
    pub api_version: &'static str,
    pub tenant_id: i64,
    pub assets: Vec<asset_store::InformationAssetSummary>,
}

#[derive(Debug, Serialize)]
pub struct CatalogDomainsResponse {
    pub api_version: &'static str,
    #[serde(flatten)]
    pub library: catalog_store::CatalogDomainLibrary,
}

#[derive(Debug, Serialize)]
pub struct ProcessRegisterResponse {
    pub api_version: &'static str,
    pub tenant_id: i64,
    pub processes: Vec<process_store::ProcessSummary>,
}

#[derive(Debug, Serialize)]
pub struct ProcessDetailResponse {
    pub api_version: &'static str,
    pub process: process_store::ProcessSummary,
}

#[derive(Debug, Serialize)]
pub struct ProductSecurityOverviewResponse {
    pub api_version: &'static str,
    #[serde(flatten)]
    pub overview: product_security_store::ProductSecurityOverview,
}

#[derive(Debug, Serialize)]
pub struct ProductSecurityDetailResponse {
    pub api_version: &'static str,
    #[serde(flatten)]
    pub detail: product_security_store::ProductSecurityDetail,
}

#[derive(Debug, Serialize)]
pub struct ProductSecurityRoadmapDetailResponse {
    pub api_version: &'static str,
    #[serde(flatten)]
    pub detail: product_security_store::ProductSecurityRoadmapDetail,
}

#[derive(Debug, Serialize)]
pub struct ProductSecurityRoadmapTaskUpdateResponse {
    pub api_version: &'static str,
    #[serde(flatten)]
    pub result: product_security_store::ProductSecurityRoadmapTaskUpdateResult,
}

#[derive(Debug, Serialize)]
pub struct ProductSecurityVulnerabilityUpdateResponse {
    pub api_version: &'static str,
    #[serde(flatten)]
    pub result: product_security_store::ProductSecurityVulnerabilityUpdateResult,
}

#[derive(Debug, Serialize)]
pub struct RiskRegisterResponse {
    pub api_version: &'static str,
    pub tenant_id: i64,
    pub risks: Vec<risk_store::RiskSummary>,
}

#[derive(Debug, Serialize)]
pub struct RiskDetailResponse {
    pub api_version: &'static str,
    pub risk: risk_store::RiskSummary,
}

#[derive(Debug, Serialize)]
pub struct RiskWriteResponse {
    pub api_version: &'static str,
    #[serde(flatten)]
    pub result: risk_store::RiskWriteResult,
}

#[derive(Debug, Deserialize)]
pub struct EvidenceOverviewQuery {
    pub session_id: Option<i64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct WebContextQuery {
    pub tenant_id: Option<i64>,
    pub user_id: Option<i64>,
    pub user_email: Option<String>,
    pub session_id: Option<i64>,
}

#[derive(Debug, Clone)]
struct WebContext {
    tenant_id: i64,
    user_id: i64,
    user_email: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EvidenceOverviewResponse {
    pub api_version: &'static str,
    pub tenant_id: i64,
    pub session_id: Option<i64>,
    pub evidence_items: Vec<evidence_store::EvidenceItemSummary>,
    pub evidence_needs: Vec<evidence_store::RequirementEvidenceNeedSummary>,
    pub need_summary: evidence_store::EvidenceNeedSummary,
}

#[derive(Debug, Serialize)]
pub struct EvidenceNeedSyncResponse {
    pub accepted: bool,
    pub api_version: &'static str,
    #[serde(flatten)]
    pub result: evidence_store::EvidenceNeedSyncResult,
}

#[derive(Debug, Serialize)]
pub struct ImportJobResponse {
    pub accepted: bool,
    pub api_version: &'static str,
    pub result: import_store::ImportJobResult,
}

#[derive(Debug, Serialize)]
pub struct ApplicabilityAssessmentsResponse {
    pub api_version: &'static str,
    pub tenant_id: i64,
    pub items: Vec<assessment_store::ApplicabilityAssessmentSummary>,
}

#[derive(Debug, Serialize)]
pub struct AssessmentsResponse {
    pub api_version: &'static str,
    pub tenant_id: i64,
    pub items: Vec<assessment_store::AssessmentSummary>,
}

#[derive(Debug, Serialize)]
pub struct MeasuresResponse {
    pub api_version: &'static str,
    pub tenant_id: i64,
    pub items: Vec<assessment_store::MeasureSummary>,
}

#[derive(Debug, Serialize)]
pub struct RoadmapPlansResponse {
    pub api_version: &'static str,
    pub tenant_id: i64,
    pub plans: Vec<roadmap_store::RoadmapPlanSummary>,
}

#[derive(Debug, Serialize)]
pub struct RoadmapPlanDetailResponse {
    pub api_version: &'static str,
    #[serde(flatten)]
    pub detail: roadmap_store::RoadmapPlanDetail,
}

#[derive(Debug, Serialize)]
pub struct RoadmapTaskUpdateResponse {
    pub api_version: &'static str,
    #[serde(flatten)]
    pub result: roadmap_store::RoadmapTaskUpdateResult,
}

#[derive(Debug, Serialize)]
pub struct WizardSessionsResponse {
    pub api_version: &'static str,
    pub tenant_id: i64,
    pub sessions: Vec<wizard_store::WizardSessionSummary>,
}

#[derive(Debug, Serialize)]
pub struct WizardResultsResponse {
    pub api_version: &'static str,
    #[serde(flatten)]
    pub results: wizard_store::WizardResultsSummary,
}

#[derive(Debug, Serialize)]
pub struct ReportSnapshotsResponse {
    pub api_version: &'static str,
    pub tenant_id: i64,
    pub reports: Vec<report_store::ReportSnapshotSummary>,
}

#[derive(Debug, Serialize)]
pub struct ReportSnapshotDetailResponse {
    pub api_version: &'static str,
    pub report: report_store::ReportSnapshotDetail,
}

#[derive(Debug, Serialize)]
pub struct RequirementLibraryResponse {
    pub api_version: &'static str,
    #[serde(flatten)]
    pub library: requirement_store::RequirementLibrary,
}

#[derive(Debug, Deserialize)]
pub struct LlmGenerateRequest {
    pub prompt: String,
    pub max_tokens: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct LlmGenerateResponse {
    pub backend: &'static str,
    pub model: &'static str,
    pub result: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct RiskPriorityRequest {
    pub score: f64,
    pub exposure: String,
    pub criticality: String,
    pub epss_score: Option<f64>,
    pub in_kev_catalog: bool,
    pub exploit_maturity: String,
    pub affects_critical_service: bool,
    pub nis2_relevant: bool,
}

#[derive(Debug, Serialize)]
pub struct RiskPriorityResponse {
    pub priority: String,
    pub due_days: u16,
    pub effective_score: f64,
}

#[derive(Debug, Deserialize)]
pub struct GuidanceEvaluateRequest {
    pub description_present: bool,
    pub sector_present: bool,
    pub applicability_count: u32,
    pub process_count: u32,
    pub risk_count: u32,
    pub assessment_count: u32,
    pub measure_count: u32,
    pub measure_open_count: u32,
    pub requirement_count: u32,
}

#[derive(Debug, Serialize)]
pub struct GuidanceEvaluateResponse {
    pub current_step_code: Option<String>,
    pub summary: String,
    pub next_action_text: String,
    pub todo_items: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct CveSummaryRequest {
    pub total: u32,
    pub critical: u32,
    pub with_risk: u32,
    pub llm_generated: u32,
    pub nis2: u32,
    pub kev: u32,
}

#[derive(Debug, Serialize)]
pub struct CveSummaryResponse {
    pub total: u32,
    pub critical: u32,
    pub with_risk: u32,
    pub llm_generated: u32,
    pub nis2: u32,
    pub kev: u32,
    pub risk_hotspot_score: f64,
}

pub fn normalize_cve_id(input: &str) -> String {
    input.trim().to_uppercase()
}

pub fn is_valid_cve_id(input: &str) -> bool {
    let parts: Vec<&str> = input.split('-').collect();
    if parts.len() != 3 || parts[0] != "CVE" || parts[1].len() != 4 || parts[2].len() < 4 {
        return false;
    }
    parts[1].chars().all(|c| c.is_ascii_digit()) && parts[2].chars().all(|c| c.is_ascii_digit())
}

fn nvd_normalize_response(payload: NvdImportRequest) -> Response {
    let normalized = normalize_cve_id(&payload.cve_id);
    if normalized.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "empty_cve_id",
                message: "CVE-ID darf nicht leer sein.".to_string(),
            }),
        )
            .into_response();
    }
    if !is_valid_cve_id(&normalized) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "invalid_cve_id",
                message: format!(
                    "CVE-ID '{}' entspricht nicht dem erwarteten Format CVE-YYYY-NNNN.",
                    normalized
                ),
            }),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        Json(NvdImportResponse {
            accepted: true,
            api_version: "v1",
            cve_id: normalized,
            source: "NVD",
        }),
    )
        .into_response()
}

async fn health_live() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "service": "iscy-rust-backend" }))
}

async fn context_whoami(headers: HeaderMap) -> Response {
    match RequestContext::from_headers(&headers) {
        Ok(context) => (
            StatusCode::OK,
            Json(ContextWhoamiResponse {
                api_version: "v1",
                authenticated: context.authenticated,
                tenant_id: context.tenant_id,
                user_id: context.user_id,
                user_email: context.user_email,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: err.error_code(),
                message: err.message().to_string(),
            }),
        )
            .into_response(),
    }
}

async fn context_tenant(headers: HeaderMap) -> Response {
    match RequestContext::authenticated_tenant_from_headers(&headers) {
        Ok(context) => (
            StatusCode::OK,
            Json(TenantContextResponse {
                api_version: "v1",
                authenticated: true,
                tenant_id: context.tenant_id,
                user_id: context.user_id,
                user_email: context.user_email,
                authorization_model: "header-bridged-django-context-v1",
            }),
        )
            .into_response(),
        Err(err) => (
            err.status_code(),
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: err.error_code(),
                message: err.message().to_string(),
            }),
        )
            .into_response(),
    }
}

async fn organization_tenant_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let context = match RequestContext::authenticated_tenant_from_headers(&headers) {
        Ok(context) => context,
        Err(err) => {
            return (
                err.status_code(),
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: err.error_code(),
                    message: err.message().to_string(),
                }),
            )
                .into_response();
        }
    };

    let Some(store) = state.tenant_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Tenant-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.tenant_profile(context.tenant_id).await {
        Ok(Some(tenant)) => (
            StatusCode::OK,
            Json(TenantProfileResponse {
                api_version: "v1",
                tenant,
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "tenant_not_found",
                message: format!("Tenant {} wurde nicht gefunden.", context.tenant_id),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Tenant-Profil konnte nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn dashboard_summary(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let context = match RequestContext::authenticated_tenant_from_headers(&headers) {
        Ok(context) => context,
        Err(err) => {
            return (
                err.status_code(),
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: err.error_code(),
                    message: err.message().to_string(),
                }),
            )
                .into_response();
        }
    };

    let Some(store) = state.dashboard_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Dashboard-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.dashboard_summary(context.tenant_id).await {
        Ok(summary) => (
            StatusCode::OK,
            Json(DashboardSummaryResponse {
                api_version: "v1",
                summary,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Dashboard-Summary konnte nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn asset_inventory(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let context = match RequestContext::authenticated_tenant_from_headers(&headers) {
        Ok(context) => context,
        Err(err) => {
            return (
                err.status_code(),
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: err.error_code(),
                    message: err.message().to_string(),
                }),
            )
                .into_response();
        }
    };

    let Some(store) = state.asset_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Asset-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.list_information_assets(context.tenant_id, 200).await {
        Ok(assets) => (
            StatusCode::OK,
            Json(AssetInventoryResponse {
                api_version: "v1",
                tenant_id: context.tenant_id,
                assets,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Assetliste konnte nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn catalog_domains(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(err) = RequestContext::authenticated_tenant_from_headers(&headers) {
        return (
            err.status_code(),
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: err.error_code(),
                message: err.message().to_string(),
            }),
        )
            .into_response();
    }

    let Some(store) = state.catalog_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Catalog-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.domain_library().await {
        Ok(library) => (
            StatusCode::OK,
            Json(CatalogDomainsResponse {
                api_version: "v1",
                library,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Fragenkatalog konnte nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn process_register(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let context = match RequestContext::authenticated_tenant_from_headers(&headers) {
        Ok(context) => context,
        Err(err) => {
            return (
                err.status_code(),
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: err.error_code(),
                    message: err.message().to_string(),
                }),
            )
                .into_response();
        }
    };

    let Some(store) = state.process_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Process-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.list_processes(context.tenant_id, 200).await {
        Ok(processes) => (
            StatusCode::OK,
            Json(ProcessRegisterResponse {
                api_version: "v1",
                tenant_id: context.tenant_id,
                processes,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Prozessliste konnte nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn process_detail(
    Path(process_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let context = match RequestContext::authenticated_tenant_from_headers(&headers) {
        Ok(context) => context,
        Err(err) => {
            return (
                err.status_code(),
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: err.error_code(),
                    message: err.message().to_string(),
                }),
            )
                .into_response();
        }
    };

    let Some(store) = state.process_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Process-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.process_detail(context.tenant_id, process_id).await {
        Ok(Some(process)) => (
            StatusCode::OK,
            Json(ProcessDetailResponse {
                api_version: "v1",
                process,
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "process_not_found",
                message: format!("Prozess {} wurde nicht gefunden.", process_id),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Prozessdetail konnte nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn product_security_overview(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let context = match RequestContext::authenticated_tenant_from_headers(&headers) {
        Ok(context) => context,
        Err(err) => {
            return (
                err.status_code(),
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: err.error_code(),
                    message: err.message().to_string(),
                }),
            )
                .into_response();
        }
    };

    let Some(store) = state.product_security_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Product-Security-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.overview(context.tenant_id, 200, 10).await {
        Ok(Some(overview)) => (
            StatusCode::OK,
            Json(ProductSecurityOverviewResponse {
                api_version: "v1",
                overview,
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "tenant_not_found",
                message: "Tenant wurde fuer Product Security nicht gefunden.".to_string(),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Product-Security-Uebersicht konnte nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn product_security_product_detail(
    Path(product_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let context = match RequestContext::authenticated_tenant_from_headers(&headers) {
        Ok(context) => context,
        Err(err) => {
            return (
                err.status_code(),
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: err.error_code(),
                    message: err.message().to_string(),
                }),
            )
                .into_response();
        }
    };

    let Some(store) = state.product_security_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Product-Security-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.detail(context.tenant_id, product_id).await {
        Ok(Some(detail)) => (
            StatusCode::OK,
            Json(ProductSecurityDetailResponse {
                api_version: "v1",
                detail,
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "product_not_found",
                message: "Product-Security-Produkt wurde nicht gefunden.".to_string(),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Product-Security-Detail konnte nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn product_security_product_roadmap(
    Path(product_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let context = match RequestContext::authenticated_tenant_from_headers(&headers) {
        Ok(context) => context,
        Err(err) => {
            return (
                err.status_code(),
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: err.error_code(),
                    message: err.message().to_string(),
                }),
            )
                .into_response();
        }
    };

    let Some(store) = state.product_security_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Product-Security-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.roadmap_detail(context.tenant_id, product_id).await {
        Ok(Some(detail)) => (
            StatusCode::OK,
            Json(ProductSecurityRoadmapDetailResponse {
                api_version: "v1",
                detail,
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "roadmap_not_found",
                message: "Product-Security-Roadmap wurde nicht gefunden.".to_string(),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Product-Security-Roadmap konnte nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn product_security_roadmap_task_update(
    Path(task_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<product_security_store::ProductSecurityRoadmapTaskUpdateRequest>,
) -> Response {
    let context = match RequestContext::authenticated_tenant_from_headers(&headers) {
        Ok(context) => context,
        Err(err) => {
            return (
                err.status_code(),
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: err.error_code(),
                    message: err.message().to_string(),
                }),
            )
                .into_response();
        }
    };

    let Some(store) = state.product_security_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Product-Security-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store
        .update_roadmap_task(context.tenant_id, task_id, payload)
        .await
    {
        Ok(Some(result)) => (
            StatusCode::OK,
            Json(ProductSecurityRoadmapTaskUpdateResponse {
                api_version: "v1",
                result,
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "product_security_roadmap_task_not_found",
                message: "Product-Security-Roadmaptask wurde nicht gefunden.".to_string(),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!(
                    "Product-Security-Roadmaptask konnte nicht aktualisiert werden: {err}"
                ),
            }),
        )
            .into_response(),
    }
}

async fn product_security_vulnerability_update(
    Path(vulnerability_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<product_security_store::ProductSecurityVulnerabilityUpdateRequest>,
) -> Response {
    let context = match RequestContext::authenticated_tenant_from_headers(&headers) {
        Ok(context) => context,
        Err(err) => {
            return (
                err.status_code(),
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: err.error_code(),
                    message: err.message().to_string(),
                }),
            )
                .into_response();
        }
    };

    let Some(store) = state.product_security_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Product-Security-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store
        .update_vulnerability(context.tenant_id, vulnerability_id, payload)
        .await
    {
        Ok(Some(result)) => (
            StatusCode::OK,
            Json(ProductSecurityVulnerabilityUpdateResponse {
                api_version: "v1",
                result,
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "product_security_vulnerability_not_found",
                message: "Product-Security-Vulnerability wurde nicht gefunden.".to_string(),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!(
                    "Product-Security-Vulnerability konnte nicht aktualisiert werden: {err}"
                ),
            }),
        )
            .into_response(),
    }
}

async fn risk_register(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let context = match RequestContext::authenticated_tenant_from_headers(&headers) {
        Ok(context) => context,
        Err(err) => {
            return (
                err.status_code(),
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: err.error_code(),
                    message: err.message().to_string(),
                }),
            )
                .into_response();
        }
    };

    let Some(store) = state.risk_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Risk-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.list_risks(context.tenant_id, 200).await {
        Ok(risks) => (
            StatusCode::OK,
            Json(RiskRegisterResponse {
                api_version: "v1",
                tenant_id: context.tenant_id,
                risks,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Risikoliste konnte nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn risk_detail(
    Path(risk_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let context = match RequestContext::authenticated_tenant_from_headers(&headers) {
        Ok(context) => context,
        Err(err) => {
            return (
                err.status_code(),
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: err.error_code(),
                    message: err.message().to_string(),
                }),
            )
                .into_response();
        }
    };

    let Some(store) = state.risk_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Risk-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.risk_detail(context.tenant_id, risk_id).await {
        Ok(Some(risk)) => (
            StatusCode::OK,
            Json(RiskDetailResponse {
                api_version: "v1",
                risk,
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "risk_not_found",
                message: format!("Risiko {} wurde nicht gefunden.", risk_id),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Risikodetail konnte nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn risk_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<risk_store::RiskWriteRequest>,
) -> Response {
    let context = match RequestContext::authenticated_tenant_from_headers(&headers) {
        Ok(context) => context,
        Err(err) => {
            return (
                err.status_code(),
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: err.error_code(),
                    message: err.message().to_string(),
                }),
            )
                .into_response();
        }
    };

    let Some(store) = state.risk_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Risk-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.create_risk(context.tenant_id, payload).await {
        Ok(result) => (
            StatusCode::CREATED,
            Json(RiskWriteResponse {
                api_version: "v1",
                result,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Risiko konnte nicht erstellt werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn risk_update(
    Path(risk_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<risk_store::RiskWriteRequest>,
) -> Response {
    let context = match RequestContext::authenticated_tenant_from_headers(&headers) {
        Ok(context) => context,
        Err(err) => {
            return (
                err.status_code(),
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: err.error_code(),
                    message: err.message().to_string(),
                }),
            )
                .into_response();
        }
    };

    let Some(store) = state.risk_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Risk-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.update_risk(context.tenant_id, risk_id, payload).await {
        Ok(Some(result)) => (
            StatusCode::OK,
            Json(RiskWriteResponse {
                api_version: "v1",
                result,
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "risk_not_found",
                message: format!("Risiko {} wurde nicht gefunden.", risk_id),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Risiko konnte nicht aktualisiert werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn evidence_overview(
    Query(query): Query<EvidenceOverviewQuery>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let context = match RequestContext::authenticated_tenant_from_headers(&headers) {
        Ok(context) => context,
        Err(err) => {
            return (
                err.status_code(),
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: err.error_code(),
                    message: err.message().to_string(),
                }),
            )
                .into_response();
        }
    };

    let Some(store) = state.evidence_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Evidence-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store
        .evidence_overview(context.tenant_id, query.session_id, 200, 30)
        .await
    {
        Ok(overview) => (
            StatusCode::OK,
            Json(EvidenceOverviewResponse {
                api_version: "v1",
                tenant_id: context.tenant_id,
                session_id: query.session_id,
                evidence_items: overview.evidence_items,
                evidence_needs: overview.evidence_needs,
                need_summary: overview.need_summary,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Evidenzuebersicht konnte nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn evidence_need_sync(
    Path(session_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<evidence_store::EvidenceNeedSyncRequest>,
) -> Response {
    let context = match RequestContext::authenticated_tenant_from_headers(&headers) {
        Ok(context) => context,
        Err(err) => {
            return (
                err.status_code(),
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: err.error_code(),
                    message: err.message().to_string(),
                }),
            )
                .into_response();
        }
    };

    let Some(store) = state.evidence_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Evidence-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store
        .sync_evidence_needs(context.tenant_id, session_id, payload)
        .await
    {
        Ok(Some(result)) => (
            StatusCode::OK,
            Json(EvidenceNeedSyncResponse {
                accepted: true,
                api_version: "v1",
                result,
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "evidence_session_not_found",
                message: format!("Assessment-Session {} wurde nicht gefunden.", session_id),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Evidenzpflichten konnten nicht synchronisiert werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn import_center_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<import_store::ImportJobRequest>,
) -> Response {
    let context = match RequestContext::authenticated_tenant_from_headers(&headers) {
        Ok(context) => context,
        Err(err) => {
            return (
                err.status_code(),
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: err.error_code(),
                    message: err.message().to_string(),
                }),
            )
                .into_response();
        }
    };

    let Some(store) = state.import_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Import-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.apply_job(context.tenant_id, payload).await {
        Ok(result) => (
            StatusCode::OK,
            Json(ImportJobResponse {
                accepted: true,
                api_version: "v1",
                result,
            }),
        )
            .into_response(),
        Err(err) if err.to_string().contains("Importtyp") => (
            StatusCode::BAD_REQUEST,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "invalid_import_type",
                message: err.to_string(),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Importjob konnte nicht angewendet werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn applicability_assessments(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let context = match RequestContext::authenticated_tenant_from_headers(&headers) {
        Ok(context) => context,
        Err(err) => {
            return (
                err.status_code(),
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: err.error_code(),
                    message: err.message().to_string(),
                }),
            )
                .into_response();
        }
    };

    let Some(store) = state.assessment_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Assessment-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.list_applicability(context.tenant_id, 200).await {
        Ok(items) => (
            StatusCode::OK,
            Json(ApplicabilityAssessmentsResponse {
                api_version: "v1",
                tenant_id: context.tenant_id,
                items,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Betroffenheitsanalysen konnten nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn assessment_register(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let context = match RequestContext::authenticated_tenant_from_headers(&headers) {
        Ok(context) => context,
        Err(err) => {
            return (
                err.status_code(),
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: err.error_code(),
                    message: err.message().to_string(),
                }),
            )
                .into_response();
        }
    };

    let Some(store) = state.assessment_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Assessment-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.list_assessments(context.tenant_id, 200).await {
        Ok(items) => (
            StatusCode::OK,
            Json(AssessmentsResponse {
                api_version: "v1",
                tenant_id: context.tenant_id,
                items,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Assessments konnten nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn assessment_measures(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let context = match RequestContext::authenticated_tenant_from_headers(&headers) {
        Ok(context) => context,
        Err(err) => {
            return (
                err.status_code(),
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: err.error_code(),
                    message: err.message().to_string(),
                }),
            )
                .into_response();
        }
    };

    let Some(store) = state.assessment_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Assessment-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.list_measures(context.tenant_id, 200).await {
        Ok(items) => (
            StatusCode::OK,
            Json(MeasuresResponse {
                api_version: "v1",
                tenant_id: context.tenant_id,
                items,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Massnahmen konnten nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn roadmap_plans(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let context = match RequestContext::authenticated_tenant_from_headers(&headers) {
        Ok(context) => context,
        Err(err) => {
            return (
                err.status_code(),
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: err.error_code(),
                    message: err.message().to_string(),
                }),
            )
                .into_response();
        }
    };

    let Some(store) = state.roadmap_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Roadmap-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.list_plans(context.tenant_id, 100).await {
        Ok(plans) => (
            StatusCode::OK,
            Json(RoadmapPlansResponse {
                api_version: "v1",
                tenant_id: context.tenant_id,
                plans,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Roadmaps konnten nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn roadmap_plan_detail(
    State(state): State<AppState>,
    Path(plan_id): Path<i64>,
    headers: HeaderMap,
) -> Response {
    let context = match RequestContext::authenticated_tenant_from_headers(&headers) {
        Ok(context) => context,
        Err(err) => {
            return (
                err.status_code(),
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: err.error_code(),
                    message: err.message().to_string(),
                }),
            )
                .into_response();
        }
    };

    let Some(store) = state.roadmap_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Roadmap-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.plan_detail(context.tenant_id, plan_id).await {
        Ok(Some(detail)) => (
            StatusCode::OK,
            Json(RoadmapPlanDetailResponse {
                api_version: "v1",
                detail,
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "roadmap_not_found",
                message: "Roadmap wurde fuer diesen Tenant nicht gefunden.".to_string(),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Roadmap konnte nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn roadmap_task_update(
    State(state): State<AppState>,
    Path(task_id): Path<i64>,
    headers: HeaderMap,
    Json(payload): Json<roadmap_store::RoadmapTaskUpdateRequest>,
) -> Response {
    let context = match RequestContext::authenticated_tenant_from_headers(&headers) {
        Ok(context) => context,
        Err(err) => {
            return (
                err.status_code(),
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: err.error_code(),
                    message: err.message().to_string(),
                }),
            )
                .into_response();
        }
    };

    let Some(store) = state.roadmap_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Roadmap-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.update_task(context.tenant_id, task_id, payload).await {
        Ok(Some(result)) => (
            StatusCode::OK,
            Json(RoadmapTaskUpdateResponse {
                api_version: "v1",
                result,
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "roadmap_task_not_found",
                message: "Roadmaptask wurde fuer diesen Tenant nicht gefunden.".to_string(),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Roadmaptask konnte nicht aktualisiert werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn wizard_sessions(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let context = match RequestContext::authenticated_tenant_from_headers(&headers) {
        Ok(context) => context,
        Err(err) => {
            return (
                err.status_code(),
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: err.error_code(),
                    message: err.message().to_string(),
                }),
            )
                .into_response();
        }
    };

    let Some(store) = state.wizard_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Wizard-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.list_sessions(context.tenant_id, 50).await {
        Ok(sessions) => (
            StatusCode::OK,
            Json(WizardSessionsResponse {
                api_version: "v1",
                tenant_id: context.tenant_id,
                sessions,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Wizard-Sessions konnten nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn wizard_results(
    State(state): State<AppState>,
    Path(session_id): Path<i64>,
    headers: HeaderMap,
) -> Response {
    let context = match RequestContext::authenticated_tenant_from_headers(&headers) {
        Ok(context) => context,
        Err(err) => {
            return (
                err.status_code(),
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: err.error_code(),
                    message: err.message().to_string(),
                }),
            )
                .into_response();
        }
    };

    let Some(store) = state.wizard_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Wizard-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.results(context.tenant_id, session_id).await {
        Ok(Some(results)) => (
            StatusCode::OK,
            Json(WizardResultsResponse {
                api_version: "v1",
                results,
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "wizard_session_not_found",
                message: "Wizard-Session wurde fuer diesen Tenant nicht gefunden.".to_string(),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Wizard-Ergebnisse konnten nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn report_snapshots(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let context = match RequestContext::authenticated_tenant_from_headers(&headers) {
        Ok(context) => context,
        Err(err) => {
            return (
                err.status_code(),
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: err.error_code(),
                    message: err.message().to_string(),
                }),
            )
                .into_response();
        }
    };

    let Some(store) = state.report_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Report-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.list_snapshots(context.tenant_id, 50).await {
        Ok(reports) => (
            StatusCode::OK,
            Json(ReportSnapshotsResponse {
                api_version: "v1",
                tenant_id: context.tenant_id,
                reports,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Reportliste konnte nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn report_snapshot_detail(
    Path(report_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let context = match RequestContext::authenticated_tenant_from_headers(&headers) {
        Ok(context) => context,
        Err(err) => {
            return (
                err.status_code(),
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: err.error_code(),
                    message: err.message().to_string(),
                }),
            )
                .into_response();
        }
    };

    let Some(store) = state.report_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Report-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.snapshot_detail(context.tenant_id, report_id).await {
        Ok(Some(report)) => (
            StatusCode::OK,
            Json(ReportSnapshotDetailResponse {
                api_version: "v1",
                report,
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "report_not_found",
                message: format!("Report {} wurde nicht gefunden.", report_id),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Reportdetail konnte nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn requirement_library(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(err) = RequestContext::authenticated_tenant_from_headers(&headers) {
        return (
            err.status_code(),
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: err.error_code(),
                message: err.message().to_string(),
            }),
        )
            .into_response();
    }

    let Some(store) = state.requirement_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Requirement-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.library(500).await {
        Ok(library) => (
            StatusCode::OK,
            Json(RequirementLibraryResponse {
                api_version: "v1",
                library,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Requirement Library konnte nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn web_index(Query(query): Query<WebContextQuery>) -> Html<String> {
    let context = query.to_context();
    let body = format!(
        r#"
        <section class="hero">
          <h1>ISCY</h1>
          <p>Rust Core fuer ISMS, NIS2, KRITIS und Product Security.</p>
        </section>
        <section class="grid">
          {}
          {}
          {}
        </section>
        "#,
        web_link_card(
            "Dashboard",
            &web_path_with_context("/dashboard/", context.as_ref()),
            "KPI-Ueberblick"
        ),
        web_link_card(
            "Risks",
            &web_path_with_context("/risks/", context.as_ref()),
            "Aktive Risiken"
        ),
        web_link_card(
            "Evidence",
            &web_path_with_context("/evidence/", context.as_ref()),
            "Nachweise und Luecken"
        ),
    );
    web_page("ISCY", "/", context.as_ref(), &body)
}

async fn web_login(Query(query): Query<WebContextQuery>) -> Html<String> {
    let context = query.to_context();
    let body = format!(
        r#"
        <section class="panel form-panel">
          <h1>Login</h1>
          <form method="get" action="/dashboard/">
            <label>Tenant-ID<input name="tenant_id" type="number" min="1" required value="{}"></label>
            <label>User-ID<input name="user_id" type="number" min="1" required value="{}"></label>
            <label>E-Mail<input name="user_email" type="email" value="{}"></label>
            <button type="submit">Weiter</button>
          </form>
        </section>
        "#,
        query
            .tenant_id
            .map(|value| value.to_string())
            .unwrap_or_default(),
        query
            .user_id
            .map(|value| value.to_string())
            .unwrap_or_default(),
        html_escape(query.user_email.as_deref().unwrap_or_default()),
    );
    web_page("Login", "/login/", context.as_ref(), &body)
}

async fn web_dashboard(
    Query(query): Query<WebContextQuery>,
    State(state): State<AppState>,
) -> Html<String> {
    let Some(context) = query.to_context() else {
        return web_missing_context("Dashboard", "/dashboard/");
    };
    let Some(store) = state.dashboard_store else {
        return web_store_missing("Dashboard", "/dashboard/", &context, "Dashboard");
    };
    match store.dashboard_summary(context.tenant_id).await {
        Ok(summary) => {
            let latest_report = summary
                .latest_report
                .map(|report| {
                    format!(
                        r#"<article class="panel wide"><h2>{}</h2><p>ISO {}% · NIS2 {}%</p><p class="muted">{}</p></article>"#,
                        html_escape(&report.title),
                        report.iso_readiness_percent,
                        report.nis2_readiness_percent,
                        html_escape(&report.created_at),
                    )
                })
                .unwrap_or_else(|| {
                    r#"<article class="panel wide"><h2>Kein Report</h2><p>Noch kein Snapshot vorhanden.</p></article>"#.to_string()
                });
            let body = format!(
                r#"
                <section class="hero compact"><h1>Dashboard</h1><p>Tenant {}</p></section>
                <section class="metrics">
                  {}
                  {}
                  {}
                  {}
                  {}
                </section>
                <section class="grid">{}</section>
                "#,
                context.tenant_id,
                metric_card("Prozesse", summary.process_count),
                metric_card("Assets", summary.asset_count),
                metric_card("Offene Risiken", summary.open_risk_count),
                metric_card("Evidenzen", summary.evidence_count),
                metric_card("Offene Tasks", summary.open_task_count),
                latest_report,
            );
            web_page("Dashboard", "/dashboard/", Some(&context), &body)
        }
        Err(err) => web_error_page("Dashboard", "/dashboard/", &context, &err.to_string()),
    }
}

async fn web_risks(
    Query(query): Query<WebContextQuery>,
    State(state): State<AppState>,
) -> Html<String> {
    let Some(context) = query.to_context() else {
        return web_missing_context("Risks", "/risks/");
    };
    let Some(store) = state.risk_store else {
        return web_store_missing("Risks", "/risks/", &context, "Risk");
    };
    match store.list_risks(context.tenant_id, 50).await {
        Ok(risks) => {
            let rows = risks
                .iter()
                .map(|risk| {
                    format!(
                        r#"<tr><td><a href="{}">{}</a></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                        web_path_with_context(&format!("/api/v1/risks/{}", risk.id), Some(&context)),
                        html_escape(&risk.title),
                        risk.score,
                        html_escape(&risk.risk_level_label),
                        html_escape(&risk.status_label),
                        html_escape(risk.owner_display.as_deref().unwrap_or("-")),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let body = format!(
                r#"
                <section class="hero compact"><h1>Risks</h1><p>{} Risiken</p></section>
                <section class="panel wide">
                  <table>
                    <thead><tr><th>Titel</th><th>Score</th><th>Level</th><th>Status</th><th>Owner</th></tr></thead>
                    <tbody>{}</tbody>
                  </table>
                </section>
                "#,
                risks.len(),
                if rows.is_empty() {
                    r#"<tr><td colspan="5">Keine Risiken vorhanden.</td></tr>"#.to_string()
                } else {
                    rows
                },
            );
            web_page("Risks", "/risks/", Some(&context), &body)
        }
        Err(err) => web_error_page("Risks", "/risks/", &context, &err.to_string()),
    }
}

async fn web_evidence(
    Query(query): Query<WebContextQuery>,
    State(state): State<AppState>,
) -> Html<String> {
    let Some(context) = query.to_context() else {
        return web_missing_context("Evidence", "/evidence/");
    };
    let Some(store) = state.evidence_store else {
        return web_store_missing("Evidence", "/evidence/", &context, "Evidence");
    };
    match store
        .evidence_overview(context.tenant_id, query.session_id, 50, 20)
        .await
    {
        Ok(overview) => {
            let rows = overview
                .evidence_items
                .iter()
                .map(|item| {
                    format!(
                        r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                        html_escape(&item.title),
                        html_escape(&item.status_label),
                        html_escape(item.owner_display.as_deref().unwrap_or("-")),
                        html_escape(item.requirement_code.as_deref().unwrap_or("-")),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let body = format!(
                r#"
                <section class="hero compact"><h1>Evidence</h1><p>{} Nachweise · {} offene Needs</p></section>
                <section class="metrics">
                  {}
                  {}
                  {}
                </section>
                <section class="panel wide">
                  <table>
                    <thead><tr><th>Titel</th><th>Status</th><th>Owner</th><th>Requirement</th></tr></thead>
                    <tbody>{}</tbody>
                  </table>
                </section>
                "#,
                overview.evidence_items.len(),
                overview.need_summary.open,
                metric_card("Offen", overview.need_summary.open),
                metric_card("Teilweise", overview.need_summary.partial),
                metric_card("Abgedeckt", overview.need_summary.covered),
                if rows.is_empty() {
                    r#"<tr><td colspan="4">Keine Evidenzen vorhanden.</td></tr>"#.to_string()
                } else {
                    rows
                },
            );
            web_page("Evidence", "/evidence/", Some(&context), &body)
        }
        Err(err) => web_error_page("Evidence", "/evidence/", &context, &err.to_string()),
    }
}

async fn web_catalog(Query(query): Query<WebContextQuery>) -> Html<String> {
    web_static_section("Catalog", "/catalog/", query.to_context().as_ref())
}
async fn web_reports(Query(query): Query<WebContextQuery>) -> Html<String> {
    web_static_section("Reports", "/reports/", query.to_context().as_ref())
}
async fn web_roadmap(Query(query): Query<WebContextQuery>) -> Html<String> {
    web_static_section("Roadmap", "/roadmap/", query.to_context().as_ref())
}
async fn web_assets(Query(query): Query<WebContextQuery>) -> Html<String> {
    web_static_section("Assets", "/assets/", query.to_context().as_ref())
}
async fn web_imports(Query(query): Query<WebContextQuery>) -> Html<String> {
    web_static_section("Imports", "/imports/", query.to_context().as_ref())
}
async fn web_processes(Query(query): Query<WebContextQuery>) -> Html<String> {
    web_static_section("Processes", "/processes/", query.to_context().as_ref())
}
async fn web_requirements(Query(query): Query<WebContextQuery>) -> Html<String> {
    web_static_section(
        "Requirements",
        "/requirements/",
        query.to_context().as_ref(),
    )
}
async fn web_assessments(Query(query): Query<WebContextQuery>) -> Html<String> {
    web_static_section("Assessments", "/assessments/", query.to_context().as_ref())
}
async fn web_organizations(Query(query): Query<WebContextQuery>) -> Html<String> {
    web_static_section(
        "Organizations",
        "/organizations/",
        query.to_context().as_ref(),
    )
}
async fn web_product_security(Query(query): Query<WebContextQuery>) -> Html<String> {
    web_static_section(
        "Product Security",
        "/product-security/",
        query.to_context().as_ref(),
    )
}
async fn web_cves(Query(query): Query<WebContextQuery>) -> Html<String> {
    web_static_section(
        "Vulnerability Intelligence",
        "/cves/",
        query.to_context().as_ref(),
    )
}
async fn web_navigator(Query(query): Query<WebContextQuery>) -> Html<String> {
    web_static_section(
        "Guidance Navigator",
        "/navigator/",
        query.to_context().as_ref(),
    )
}

impl WebContextQuery {
    fn to_context(&self) -> Option<WebContext> {
        let tenant_id = self.tenant_id?;
        let user_id = self.user_id?;
        if tenant_id < 1 || user_id < 1 {
            return None;
        }
        Some(WebContext {
            tenant_id,
            user_id,
            user_email: self
                .user_email
                .clone()
                .filter(|value| !value.trim().is_empty()),
        })
    }
}

fn web_static_section(
    title: &'static str,
    path: &'static str,
    context: Option<&WebContext>,
) -> Html<String> {
    let body = format!(
        r#"<section class="hero compact"><h1>{}</h1><p>Rust-Webroute aktiv.</p></section>
        <section class="grid">
          {}
          {}
        </section>"#,
        html_escape(title),
        web_link_card(
            "JSON API",
            &web_path_with_context(&format!("/api/v1{}", path.trim_end_matches('/')), context),
            "Datenvertrag"
        ),
        web_link_card(
            "Dashboard",
            &web_path_with_context("/dashboard/", context),
            "Zurueck zur Uebersicht"
        ),
    );
    web_page(title, path, context, &body)
}

fn web_missing_context(title: &'static str, active_path: &'static str) -> Html<String> {
    let body = format!(
        r#"<section class="panel form-panel"><h1>{}</h1>
        <form method="get" action="{}">
          <label>Tenant-ID<input name="tenant_id" type="number" min="1" required></label>
          <label>User-ID<input name="user_id" type="number" min="1" required></label>
          <label>E-Mail<input name="user_email" type="email"></label>
          <button type="submit">Oeffnen</button>
        </form></section>"#,
        html_escape(title),
        html_escape(active_path),
    );
    web_page(title, active_path, None, &body)
}

fn web_store_missing(
    title: &'static str,
    active_path: &'static str,
    context: &WebContext,
    store_name: &'static str,
) -> Html<String> {
    let body = format!(
        r#"<section class="hero compact"><h1>{}</h1></section>
        <section class="panel wide"><h2>{}-Store nicht konfiguriert</h2><p>DATABASE_URL pruefen.</p></section>"#,
        html_escape(title),
        html_escape(store_name),
    );
    web_page(title, active_path, Some(context), &body)
}

fn web_error_page(
    title: &'static str,
    active_path: &'static str,
    context: &WebContext,
    message: &str,
) -> Html<String> {
    let body = format!(
        r#"<section class="hero compact"><h1>{}</h1></section>
        <section class="panel wide error"><h2>Fehler</h2><p>{}</p></section>"#,
        html_escape(title),
        html_escape(message),
    );
    web_page(title, active_path, Some(context), &body)
}

fn web_page(
    title: &str,
    active_path: &str,
    context: Option<&WebContext>,
    body: &str,
) -> Html<String> {
    let nav_items = [
        ("/dashboard/", "Dashboard"),
        ("/risks/", "Risks"),
        ("/evidence/", "Evidence"),
        ("/roadmap/", "Roadmap"),
        ("/reports/", "Reports"),
        ("/product-security/", "Product Security"),
    ]
    .iter()
    .map(|(path, label)| {
        let class_name = if *path == active_path { "active" } else { "" };
        format!(
            r#"<a class="{}" href="{}">{}</a>"#,
            class_name,
            web_path_with_context(path, context),
            html_escape(label),
        )
    })
    .collect::<Vec<_>>()
    .join("");
    let context_badge = context
        .map(|context| {
            format!(
                r#"<span>Tenant {}</span><span>User {}</span>{}"#,
                context.tenant_id,
                context.user_id,
                context
                    .user_email
                    .as_ref()
                    .map(|email| format!("<span>{}</span>", html_escape(email)))
                    .unwrap_or_default(),
            )
        })
        .unwrap_or_else(|| r#"<a href="/login/">Login</a>"#.to_string());
    Html(format!(
        r#"<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{}</title>
  <style>
    :root {{ color-scheme: light; --ink:#17202a; --muted:#617080; --line:#d8dee6; --bg:#f6f8fb; --panel:#ffffff; --accent:#0f766e; --warn:#b45309; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; font-family:Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color:var(--ink); background:var(--bg); }}
    header {{ display:flex; align-items:center; justify-content:space-between; gap:16px; padding:16px 24px; background:#ffffff; border-bottom:1px solid var(--line); position:sticky; top:0; z-index:1; }}
    .brand {{ font-weight:800; letter-spacing:0; color:var(--ink); text-decoration:none; }}
    nav {{ display:flex; flex-wrap:wrap; gap:8px; }}
    nav a, .context a {{ color:var(--ink); text-decoration:none; padding:8px 10px; border-radius:6px; border:1px solid transparent; }}
    nav a.active, nav a:hover, .context a:hover {{ border-color:var(--line); background:#eef6f4; }}
    .context {{ display:flex; flex-wrap:wrap; justify-content:flex-end; gap:6px; font-size:14px; color:var(--muted); }}
    .context span {{ padding:8px 10px; border:1px solid var(--line); border-radius:6px; background:#fff; }}
    main {{ width:min(1180px, 100%); margin:0 auto; padding:28px 20px 44px; }}
    .hero {{ padding:32px 0; }}
    .hero.compact {{ padding:16px 0 24px; }}
    h1 {{ margin:0 0 8px; font-size:40px; line-height:1.1; }}
    h2 {{ margin:0 0 10px; font-size:20px; }}
    p {{ margin:0 0 8px; color:var(--muted); }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(230px, 1fr)); gap:14px; }}
    .metrics {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(160px, 1fr)); gap:12px; margin-bottom:16px; }}
    .panel {{ background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:18px; box-shadow:0 1px 2px rgba(20, 30, 40, 0.04); }}
    .panel.wide {{ grid-column:1 / -1; }}
    .panel.error {{ border-color:#fed7aa; background:#fff7ed; }}
    .card-link {{ display:block; min-height:120px; color:var(--ink); text-decoration:none; }}
    .metric strong {{ display:block; font-size:30px; margin-top:6px; }}
    .muted {{ color:var(--muted); }}
    table {{ width:100%; border-collapse:collapse; }}
    th, td {{ padding:10px 8px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }}
    th {{ color:var(--muted); font-size:13px; text-transform:uppercase; }}
    td a {{ color:var(--accent); text-decoration:none; }}
    form {{ display:grid; gap:12px; }}
    label {{ display:grid; gap:6px; font-weight:600; }}
    input {{ width:100%; padding:10px 12px; border:1px solid var(--line); border-radius:6px; font:inherit; }}
    button {{ justify-self:start; border:0; border-radius:6px; background:var(--accent); color:#fff; padding:10px 14px; font-weight:700; cursor:pointer; }}
    @media (max-width: 720px) {{ header {{ align-items:flex-start; flex-direction:column; }} h1 {{ font-size:32px; }} .context {{ justify-content:flex-start; }} }}
  </style>
</head>
<body>
  <header>
    <a class="brand" href="{}">ISCY</a>
    <nav>{}</nav>
    <div class="context">{}</div>
  </header>
  <main>{}</main>
</body>
</html>"#,
        html_escape(title),
        web_path_with_context("/", context),
        nav_items,
        context_badge,
        body,
    ))
}

fn metric_card(label: &str, value: i64) -> String {
    format!(
        r#"<article class="panel metric"><span>{}</span><strong>{}</strong></article>"#,
        html_escape(label),
        value,
    )
}

fn web_link_card(title: &str, href: &str, subtitle: &str) -> String {
    format!(
        r#"<a class="panel card-link" href="{}"><h2>{}</h2><p>{}</p></a>"#,
        html_escape(href),
        html_escape(title),
        html_escape(subtitle),
    )
}

fn web_path_with_context(path: &str, context: Option<&WebContext>) -> String {
    let Some(context) = context else {
        return path.to_string();
    };
    let separator = if path.contains('?') { '&' } else { '?' };
    let email = context
        .user_email
        .as_ref()
        .map(|value| format!("&user_email={}", url_component(value)))
        .unwrap_or_default();
    format!(
        "{path}{separator}tenant_id={}&user_id={}{}",
        context.tenant_id, context.user_id, email
    )
}

fn url_component(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                vec![byte as char]
            }
            b' ' => vec!['+'],
            _ => {
                let encoded = format!("%{byte:02X}");
                encoded.chars().collect()
            }
        })
        .collect()
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

async fn nvd_normalize(Json(payload): Json<NvdImportRequest>) -> Response {
    nvd_normalize_response(payload)
}

async fn nvd_import(Json(payload): Json<NvdImportRequest>) -> Response {
    nvd_normalize_response(payload)
}

async fn nvd_upsert(
    State(state): State<AppState>,
    Json(payload): Json<NvdPersistRequest>,
) -> Response {
    let raw_payload = payload.raw_payload.unwrap_or_else(|| payload.cve.clone());
    let fallback_cve_id = payload.cve_id.as_deref().unwrap_or("");
    let record = NvdCveRecord::from_nvd_value(&payload.cve, &raw_payload, fallback_cve_id);
    let normalized = normalize_cve_id(&record.cve_id);

    if normalized.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "empty_cve_id",
                message: "CVE-ID darf nicht leer sein.".to_string(),
            }),
        )
            .into_response();
    }
    if !is_valid_cve_id(&normalized) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "invalid_cve_id",
                message: format!(
                    "CVE-ID '{}' entspricht nicht dem erwarteten Format CVE-YYYY-NNNN.",
                    normalized
                ),
            }),
        )
            .into_response();
    }

    let Some(store) = state.cve_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-CVE-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    let record = record.with_cve_id(normalized.clone());
    if let Err(err) = store.upsert_nvd_cve(&record).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("CVE konnte nicht persistiert werden: {err}"),
            }),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(NvdPersistResponse {
            accepted: true,
            api_version: "v1",
            cve_id: normalized,
            source: "NVD",
            persisted: true,
        }),
    )
        .into_response()
}

async fn llm_generate(Json(payload): Json<LlmGenerateRequest>) -> Json<LlmGenerateResponse> {
    let excerpt: String = payload.prompt.chars().take(240).collect();
    let max_tokens = payload.max_tokens.unwrap_or(900);
    Json(LlmGenerateResponse {
        backend: "rust_service",
        model: "iscy-rust-llm-stub-v1",
        result: serde_json::json!({
            "technical_summary": format!("Rust-LLM Stub analysed prompt excerpt: {}", excerpt),
            "business_impact": "Potential operational and compliance impact identified; verify with domain experts.",
            "attack_path": "Unknown until full threat-context and exploit chain are provided.",
            "management_summary": "Prioritize patching, compensating controls, and evidence collection.",
            "recommended_actions": [
                "Validate affected assets and versions",
                "Apply vendor patch or workaround",
                "Add detection rule and monitoring"
            ],
            "evidence_needed": [
                "Asset inventory with affected versions",
                "Patch deployment report",
                "SOC detection and incident logs"
            ],
            "confidence": "medium",
            "max_tokens_requested": max_tokens
        }),
    })
}

async fn risk_priority(Json(payload): Json<RiskPriorityRequest>) -> Json<RiskPriorityResponse> {
    let mut bump = 0.0_f64;
    if payload.exposure == "INTERNET" {
        bump += 1.5;
    } else if payload.exposure == "CUSTOMER" {
        bump += 1.0;
    }
    if payload.criticality == "CRITICAL" {
        bump += 1.5;
    } else if payload.criticality == "HIGH" {
        bump += 1.0;
    }
    if let Some(epss) = payload.epss_score {
        if epss >= 0.90 {
            bump += 2.0;
        } else if epss >= 0.50 {
            bump += 1.0;
        } else if epss >= 0.20 {
            bump += 0.5;
        }
    }
    if payload.in_kev_catalog {
        bump += 2.5;
    }
    if payload.exploit_maturity == "AUTOMATED" {
        bump += 2.0;
    } else if payload.exploit_maturity == "ACTIVE" {
        bump += 1.5;
    } else if payload.exploit_maturity == "POC" {
        bump += 0.5;
    }
    if payload.affects_critical_service {
        bump += 1.5;
    }
    if payload.nis2_relevant {
        bump += 1.0;
    }
    let effective = payload.score + bump;
    let (priority, due_days) = if effective >= 9.5 {
        ("CRITICAL".to_string(), 7)
    } else if effective >= 8.0 {
        ("HIGH".to_string(), 14)
    } else if effective >= 6.0 {
        ("MEDIUM".to_string(), 30)
    } else {
        ("LOW".to_string(), 60)
    };
    Json(RiskPriorityResponse {
        priority,
        due_days,
        effective_score: (effective * 100.0).round() / 100.0,
    })
}

async fn guidance_evaluate(
    Json(payload): Json<GuidanceEvaluateRequest>,
) -> Json<GuidanceEvaluateResponse> {
    let mut todo_items: Vec<String> = Vec::new();
    if payload.applicability_count == 0 {
        todo_items.push("Betroffenheitsanalyse anlegen".to_string());
    }
    if !payload.description_present {
        todo_items.push("ISMS-Scope und Unternehmensbeschreibung pflegen".to_string());
    }
    if payload.process_count < 3 {
        todo_items.push(format!(
            "Noch {} kritische Prozesse erfassen",
            3 - payload.process_count
        ));
    }
    if payload.risk_count < 1 {
        todo_items.push("Mindestens ein Risiko dokumentieren".to_string());
    }
    if payload.assessment_count < 1 {
        todo_items.push("Erstes Assessment durchführen".to_string());
    }
    if payload.measure_count < 1 {
        todo_items.push(
            "Mindestens eine Incident-nahe Maßnahme dokumentieren (SOC-Playbook)".to_string(),
        );
    }
    if payload.measure_open_count > 0 {
        todo_items.push(format!(
            "{} offene Maßnahmen nachverfolgen",
            payload.measure_open_count
        ));
    }

    let steps = [
        ("applicability_checked", payload.applicability_count >= 1),
        (
            "company_scope_defined",
            payload.description_present && payload.sector_present,
        ),
        ("requirements_available", payload.requirement_count >= 4),
        ("initial_processes_captured", payload.process_count >= 3),
        ("initial_risks_captured", payload.risk_count >= 1),
        ("initial_assessment_done", payload.assessment_count >= 1),
        ("soc_phishing_playbook_applied", payload.measure_count >= 1),
    ];

    let current_step_code = steps
        .iter()
        .find(|(_, done)| !*done)
        .map(|(code, _)| code.to_string());
    let (summary, next_action_text) = match current_step_code.as_deref() {
        Some("applicability_checked") => (
            "Starten Sie mit der Betroffenheitsanalyse. Erst damit wird klar, ob ISO-27001-Readiness ausreicht oder NIS2-/KRITIS-Nähe vertieft werden sollte.".to_string(),
            "Bewerten Sie Sektor, Größe, kritische Dienstleistungen und Lieferkettenrolle.".to_string(),
        ),
        Some("company_scope_defined") => (
            "Definieren Sie den Scope des ISMS. Ohne Scope sind spätere Bewertungen fachlich unscharf und für Audits schwer belastbar.".to_string(),
            "Pflegen Sie Beschreibung, Zielbild, Sektor und kritische Leistungen des Unternehmens.".to_string(),
        ),
        Some("requirements_available") => (
            "Es fehlen Requirement-Grundlagen. Ohne die ISCY Requirement Library ist kein belastbares Mapping gegen ISO 27001 oder NIS2 moeglich.".to_string(),
            "Stellen Sie sicher, dass die ISCY Requirement Library initial geladen wurde.".to_string(),
        ),
        Some("initial_processes_captured") => (
            format!("Derzeit sind {} Prozesse erfasst. Für einen belastbaren Einstieg sollten mindestens 3 kritische Prozesse dokumentiert werden.", payload.process_count),
            "Erfassen Sie die wichtigsten Geschäfts- oder IT-Prozesse inklusive Owner und Kritikalität.".to_string(),
        ),
        Some("initial_risks_captured") => (
            format!("Derzeit sind {} Risiken erfasst. Ohne erste Risiken bleibt die Ableitung von Maßnahmen zu flach.", payload.risk_count),
            "Erfassen Sie mindestens ein initiales Risiko zu einem kritischen Prozess oder Asset.".to_string(),
        ),
        Some("initial_assessment_done") => (
            format!("Es gibt aktuell {} Assessments und {} offene Maßnahmen. Erst Assessments zeigen, was ausreichend ist und wo echte Gaps bestehen.", payload.assessment_count, payload.measure_open_count),
            "Starten Sie die erste Prozess- oder Requirement-Bewertung.".to_string(),
        ),
        Some("soc_phishing_playbook_applied") => (
            format!("Für den Tenant sind bisher {} Maßnahmen dokumentiert. Das SOC-Playbook gilt als praktisch verankert, wenn mindestens eine Maßnahme als Incident-Reaktion nachvollziehbar erfasst ist.", payload.measure_count),
            "Erfassen Sie eine konkrete Incident-Maßnahme (z. B. Mail-Containment, Session-Entzug oder Konto-Absicherung) inklusive Priorität und Status.".to_string(),
        ),
        _ => (
            "Alle aktuell definierten Guided Steps sind abgeschlossen.".to_string(),
            "Nächster sinnvoller Schritt: Evidenzen, Reviews und Audit-Vorbereitung vertiefen.".to_string(),
        ),
    };

    Json(GuidanceEvaluateResponse {
        current_step_code,
        summary,
        next_action_text,
        todo_items,
    })
}

async fn report_cve_summary(Json(payload): Json<CveSummaryRequest>) -> Json<CveSummaryResponse> {
    let total = payload.total.max(1) as f64;
    let critical_ratio = payload.critical as f64 / total;
    let kev_ratio = payload.kev as f64 / total;
    let nis2_ratio = payload.nis2 as f64 / total;
    let score = ((critical_ratio * 0.5) + (kev_ratio * 0.3) + (nis2_ratio * 0.2)) * 100.0;
    Json(CveSummaryResponse {
        total: payload.total,
        critical: payload.critical,
        with_risk: payload.with_risk,
        llm_generated: payload.llm_generated,
        nis2: payload.nis2,
        kev: payload.kev,
        risk_hotspot_score: (score * 100.0).round() / 100.0,
    })
}

pub fn app_router() -> Router {
    app_router_with_state(AppState::default())
}

pub fn app_router_with_state(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_live))
        .route("/health/ready", get(health_live))
        .route("/health/live", get(health_live))
        .route("/api/v1/context/whoami", get(context_whoami))
        .route("/api/v1/context/tenant", get(context_tenant))
        .route(
            "/api/v1/organizations/tenant-profile",
            get(organization_tenant_profile),
        )
        .route("/api/v1/catalog/domains", get(catalog_domains))
        .route("/api/v1/dashboard/summary", get(dashboard_summary))
        .route("/api/v1/assets/information-assets", get(asset_inventory))
        .route("/api/v1/processes", get(process_register))
        .route("/api/v1/processes/{process_id}", get(process_detail))
        .route(
            "/api/v1/product-security/overview",
            get(product_security_overview),
        )
        .route(
            "/api/v1/product-security/products/{product_id}",
            get(product_security_product_detail),
        )
        .route(
            "/api/v1/product-security/products/{product_id}/roadmap",
            get(product_security_product_roadmap),
        )
        .route(
            "/api/v1/product-security/roadmap-tasks/{task_id}",
            patch(product_security_roadmap_task_update),
        )
        .route(
            "/api/v1/product-security/vulnerabilities/{vulnerability_id}",
            patch(product_security_vulnerability_update),
        )
        .route("/api/v1/risks", get(risk_register).post(risk_create))
        .route(
            "/api/v1/risks/{risk_id}",
            get(risk_detail).patch(risk_update),
        )
        .route("/api/v1/evidence", get(evidence_overview))
        .route(
            "/api/v1/evidence/sessions/{session_id}/needs/sync",
            post(evidence_need_sync),
        )
        .route("/api/v1/import-center/jobs", post(import_center_job))
        .route(
            "/api/v1/assessments/applicability",
            get(applicability_assessments),
        )
        .route("/api/v1/assessments", get(assessment_register))
        .route("/api/v1/assessments/measures", get(assessment_measures))
        .route("/api/v1/roadmap/plans", get(roadmap_plans))
        .route("/api/v1/roadmap/plans/{plan_id}", get(roadmap_plan_detail))
        .route(
            "/api/v1/roadmap/tasks/{task_id}",
            patch(roadmap_task_update),
        )
        .route("/api/v1/wizard/sessions", get(wizard_sessions))
        .route(
            "/api/v1/wizard/sessions/{session_id}/results",
            get(wizard_results),
        )
        .route("/api/v1/reports/snapshots", get(report_snapshots))
        .route(
            "/api/v1/reports/snapshots/{report_id}",
            get(report_snapshot_detail),
        )
        .route("/api/v1/requirements", get(requirement_library))
        .route("/", get(web_index))
        .route("/login/", get(web_login))
        .route("/navigator/", get(web_navigator))
        .route("/dashboard/", get(web_dashboard))
        .route("/catalog/", get(web_catalog))
        .route("/reports/", get(web_reports))
        .route("/roadmap/", get(web_roadmap))
        .route("/evidence/", get(web_evidence))
        .route("/assets/", get(web_assets))
        .route("/imports/", get(web_imports))
        .route("/processes/", get(web_processes))
        .route("/requirements/", get(web_requirements))
        .route("/risks/", get(web_risks))
        .route("/assessments/", get(web_assessments))
        .route("/organizations/", get(web_organizations))
        .route("/product-security/", get(web_product_security))
        .route("/cves/", get(web_cves))
        .route("/api/v1/nvd/normalize", post(nvd_normalize))
        .route("/api/v1/nvd/import", post(nvd_import))
        .route("/api/v1/nvd/upsert", post(nvd_upsert))
        .route("/api/v1/llm/generate", post(llm_generate))
        .route("/api/v1/risk/priority", post(risk_priority))
        .route("/api/v1/guidance/evaluate", post(guidance_evaluate))
        .route("/api/v1/reports/cve-summary", post(report_cve_summary))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::normalize_cve_id;

    #[test]
    fn normalize_cve_id_uppercases_and_trims() {
        assert_eq!(normalize_cve_id(" cve-2026-1234 "), "CVE-2026-1234");
    }
}
