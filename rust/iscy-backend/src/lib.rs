use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Json, Path, State},
    extract::{Form, Query},
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE},
        HeaderMap, HeaderValue, StatusCode,
    },
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, patch, post},
    Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use chrono::Datelike;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    fs,
    path::{Path as FsPath, PathBuf},
};

pub mod account_store;
pub mod assessment_store;
pub mod asset_store;
pub mod auth_store;
pub mod catalog_store;
pub mod cve_store;
pub mod dashboard_store;
pub mod db_admin;
pub mod evidence_store;
pub mod import_preview;
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

use account_store::AccountStore;
use assessment_store::AssessmentStore;
use asset_store::AssetStore;
use auth_store::AuthStore;
use catalog_store::CatalogStore;
use cve_store::{CveStore, NvdCveRecord};
use dashboard_store::DashboardStore;
use evidence_store::EvidenceStore;
use import_preview::{ImportPreview, ImportUploadFile};
use import_store::ImportStore;
use process_store::ProcessStore;
use product_security_store::ProductSecurityStore;
use report_store::ReportStore;
use request_context::{AuthenticatedTenantContext, RequestContext, RequiredTenantContextError};
use requirement_store::RequirementStore;
use risk_store::RiskStore;
use roadmap_store::RoadmapStore;
use tenant_store::TenantStore;
use wizard_store::WizardStore;

#[derive(Clone, Default)]
pub struct AppState {
    pub account_store: Option<AccountStore>,
    pub asset_store: Option<AssetStore>,
    pub assessment_store: Option<AssessmentStore>,
    pub auth_store: Option<AuthStore>,
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
    pub evidence_media_root: Option<PathBuf>,
}

impl AppState {
    pub fn new(cve_store: Option<CveStore>) -> Self {
        Self {
            account_store: None,
            asset_store: None,
            assessment_store: None,
            auth_store: None,
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
            evidence_media_root: None,
        }
    }

    pub fn with_stores(cve_store: Option<CveStore>, tenant_store: Option<TenantStore>) -> Self {
        Self {
            account_store: None,
            asset_store: None,
            assessment_store: None,
            auth_store: None,
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
            evidence_media_root: None,
        }
    }

    pub fn with_dashboard_store(mut self, dashboard_store: Option<DashboardStore>) -> Self {
        self.dashboard_store = dashboard_store;
        self
    }

    pub fn with_account_store(mut self, account_store: Option<AccountStore>) -> Self {
        self.account_store = account_store;
        self
    }

    pub fn with_auth_store(mut self, auth_store: Option<AuthStore>) -> Self {
        self.auth_store = auth_store;
        self
    }

    pub fn with_evidence_store(mut self, evidence_store: Option<EvidenceStore>) -> Self {
        self.evidence_store = evidence_store;
        self
    }

    pub fn with_evidence_media_root(mut self, evidence_media_root: Option<PathBuf>) -> Self {
        self.evidence_media_root = evidence_media_root;
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
    pub roles: Vec<String>,
    pub is_staff: bool,
    pub is_superuser: bool,
}

#[derive(Debug, Serialize)]
pub struct TenantContextResponse {
    pub api_version: &'static str,
    pub authenticated: bool,
    pub tenant_id: i64,
    pub user_id: i64,
    pub user_email: Option<String>,
    pub roles: Vec<String>,
    pub is_staff: bool,
    pub is_superuser: bool,
    pub authorization_model: &'static str,
}

#[derive(Debug, Deserialize)]
pub struct AuthSessionCreateRequest {
    pub tenant_id: Option<i64>,
    pub user_id: Option<i64>,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthSessionResponse {
    pub accepted: bool,
    pub api_version: &'static str,
    pub authenticated: bool,
    pub tenant_id: Option<i64>,
    pub user_id: Option<i64>,
    pub user_email: Option<String>,
    pub expires_at: Option<String>,
    pub authorization_model: &'static str,
    pub session_token: Option<String>,
    pub user: Option<auth_store::AuthUser>,
}

#[derive(Debug, Serialize)]
pub struct AccountUsersResponse {
    pub api_version: &'static str,
    pub tenant_id: i64,
    pub users: Vec<account_store::AccountUser>,
}

#[derive(Debug, Serialize)]
pub struct AccountRolesResponse {
    pub api_version: &'static str,
    pub roles: Vec<account_store::AccountRole>,
}

#[derive(Debug, Serialize)]
pub struct AccountGroupsResponse {
    pub api_version: &'static str,
    pub groups: Vec<account_store::AccountGroup>,
}

#[derive(Debug, Serialize)]
pub struct AccountPermissionsResponse {
    pub api_version: &'static str,
    pub permissions: Vec<account_store::AccountPermission>,
}

#[derive(Debug, Serialize)]
pub struct AccountUserWriteResponse {
    pub accepted: bool,
    pub api_version: &'static str,
    pub user: account_store::AccountUser,
}

#[derive(Debug, Deserialize)]
struct WebLoginForm {
    tenant_id: Option<i64>,
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct WebAccountUserCreateForm {
    username: String,
    password: String,
    first_name: Option<String>,
    last_name: Option<String>,
    email: Option<String>,
    role: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_form_list")]
    groups: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_optional_form_list")]
    permissions: Option<Vec<String>>,
    job_title: Option<String>,
    is_staff: Option<String>,
    is_superuser: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebAccountUserUpdateForm {
    username: String,
    password: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    email: Option<String>,
    role: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_form_list")]
    groups: Option<Vec<String>>,
    groups_present: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_form_list")]
    permissions: Option<Vec<String>>,
    permissions_present: Option<String>,
    job_title: Option<String>,
    is_active: Option<String>,
    is_staff: Option<String>,
    is_superuser: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebImportCsvForm {
    import_type: String,
    replace_existing: Option<String>,
    csv_data: String,
}

fn deserialize_optional_form_list<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }

    Ok(
        Option::<OneOrMany>::deserialize(deserializer)?.map(|value| match value {
            OneOrMany::One(value) => vec![value],
            OneOrMany::Many(values) => values,
        }),
    )
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

type ImportCsvRows = Vec<HashMap<String, Value>>;
type ParsedImportCsv = (Vec<String>, ImportCsvRows);
const EVIDENCE_MAX_UPLOAD_BYTES: usize = 25 * 1024 * 1024;
const MULTIPART_FORM_BODY_LIMIT_BYTES: usize = EVIDENCE_MAX_UPLOAD_BYTES + 1024 * 1024;
const EVIDENCE_ALLOWED_EXTENSIONS: &[&str] =
    &["pdf", "docx", "xlsx", "png", "jpg", "jpeg", "csv", "txt"];
const EVIDENCE_BLOCKED_CONTENT_TYPES: &[&str] = &[
    "application/x-executable",
    "application/x-msdos-program",
    "text/html",
];

#[derive(Debug, Clone)]
struct MultipartPart {
    name: String,
    filename: Option<String>,
    content_type: Option<String>,
    data: Vec<u8>,
}

#[derive(Debug, Clone)]
struct EvidenceUploadFormData {
    fields: HashMap<String, String>,
    file: Option<EvidenceUploadFile>,
}

#[derive(Debug, Clone)]
struct ImportUploadFormData {
    fields: HashMap<String, String>,
    file: Option<ImportUploadFile>,
}

#[derive(Debug, Clone)]
struct EvidenceUploadFile {
    filename: String,
    content_type: Option<String>,
    data: Vec<u8>,
}

#[derive(Debug, Clone)]
struct SavedEvidenceFile {
    relative_path: String,
    absolute_path: PathBuf,
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
pub struct EvidenceUploadResponse {
    pub accepted: bool,
    pub api_version: &'static str,
    pub item: evidence_store::EvidenceItemSummary,
    pub need_sync: Option<evidence_store::EvidenceNeedSyncResult>,
}

#[derive(Debug, Serialize)]
pub struct ImportJobResponse {
    pub accepted: bool,
    pub api_version: &'static str,
    pub result: import_store::ImportJobResult,
}

#[derive(Debug, Serialize)]
pub struct ImportPreviewResponse {
    pub accepted: bool,
    pub api_version: &'static str,
    pub preview: ImportPreview,
}

#[derive(Debug, Deserialize)]
pub struct ImportCsvRequest {
    pub import_type: String,
    #[serde(default)]
    pub replace_existing: bool,
    pub csv_data: String,
}

#[derive(Debug, Serialize)]
pub struct ImportCsvResponse {
    pub accepted: bool,
    pub api_version: &'static str,
    pub headers: Vec<String>,
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

#[derive(Clone, Copy)]
struct GuidanceStepDefinition {
    code: &'static str,
    title: &'static str,
    description: &'static str,
    path: &'static str,
    cta_label: &'static str,
}

const GUIDANCE_STEPS: [GuidanceStepDefinition; 7] = [
    GuidanceStepDefinition {
        code: "applicability_checked",
        title: "Betroffenheitsanalyse",
        description: "Sektor, Groesse und kritische Services bewerten.",
        path: "/assessments/",
        cta_label: "Zur Betroffenheitsanalyse",
    },
    GuidanceStepDefinition {
        code: "company_scope_defined",
        title: "Scope definieren",
        description: "Unternehmensprofil, Scope und Services schaerfen.",
        path: "/organizations/",
        cta_label: "Zum Organisationsprofil",
    },
    GuidanceStepDefinition {
        code: "requirements_available",
        title: "Requirements absichern",
        description: "Requirement Library und Mapping-Versionen verankern.",
        path: "/requirements/",
        cta_label: "Zur Requirement Library",
    },
    GuidanceStepDefinition {
        code: "initial_processes_captured",
        title: "Kritische Prozesse",
        description: "Kernprozesse mit Ownern und Scope erfassen.",
        path: "/processes/",
        cta_label: "Zu den Prozessen",
    },
    GuidanceStepDefinition {
        code: "initial_risks_captured",
        title: "Erste Risiken",
        description: "Initiale Risiken fuer Prozesse oder Assets dokumentieren.",
        path: "/risks/",
        cta_label: "Zum Risikoregister",
    },
    GuidanceStepDefinition {
        code: "initial_assessment_done",
        title: "Assessments starten",
        description: "Prozess- und Requirement-Bewertungen anlegen.",
        path: "/assessments/",
        cta_label: "Zu den Assessments",
    },
    GuidanceStepDefinition {
        code: "soc_phishing_playbook_applied",
        title: "Massnahmen verankern",
        description: "Mindestens eine Incident-nahe Massnahme nachverfolgbar machen.",
        path: "/assessments/",
        cta_label: "Zu Measures und Assessments",
    },
];

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

const ISCY_SESSION_COOKIE: &str = "iscy_session";

async fn authenticated_tenant_context(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedTenantContext, RequiredTenantContextError> {
    if let Some(token) = session_token_from_headers(headers) {
        let Some(store) = state.auth_store.as_ref() else {
            return Err(RequiredTenantContextError::InvalidSession);
        };
        return store
            .resolve_session(&token)
            .await
            .map_err(|_| RequiredTenantContextError::InvalidSession)?
            .map(|session| session.tenant_context())
            .ok_or(RequiredTenantContextError::InvalidSession);
    }
    RequestContext::authenticated_tenant_from_headers(headers)
}

fn write_permission_error(context: &AuthenticatedTenantContext) -> Option<Response> {
    if context.can_write() {
        return None;
    }
    Some(
        (
            StatusCode::FORBIDDEN,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "insufficient_role",
                message: "Diese Rust-Route benoetigt eine schreibende ISCY-Rolle.".to_string(),
            }),
        )
            .into_response(),
    )
}

fn admin_permission_error(context: &AuthenticatedTenantContext) -> Option<Response> {
    if context.is_superuser || context.is_staff || context.has_role("ADMIN") {
        return None;
    }
    Some(
        (
            StatusCode::FORBIDDEN,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "insufficient_admin_role",
                message: "Diese Rust-Route benoetigt eine Admin-Rolle.".to_string(),
            }),
        )
            .into_response(),
    )
}

fn account_payload_error(err: &anyhow::Error) -> bool {
    err.chain()
        .any(|cause| cause.to_string().contains("Account-Feld"))
}

fn account_store_error_response(err: anyhow::Error, action: &'static str) -> Response {
    let payload_error = account_payload_error(&err);
    let details = err
        .chain()
        .map(|cause| cause.to_string())
        .collect::<Vec<_>>()
        .join(": ");
    (
        if payload_error {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        },
        Json(ApiErrorResponse {
            accepted: false,
            api_version: "v1",
            error_code: if payload_error {
                "invalid_account_payload"
            } else {
                "database_error"
            },
            message: format!("{action}: {details}"),
        }),
    )
        .into_response()
}

async fn web_context_from_request(
    query: &WebContextQuery,
    headers: &HeaderMap,
    state: &AppState,
) -> Option<WebContext> {
    if let Some(token) = session_token_from_headers(headers) {
        if let Some(store) = state.auth_store.as_ref() {
            if let Ok(Some(session)) = store.resolve_session(&token).await {
                return Some(WebContext {
                    tenant_id: session.tenant_id,
                    user_id: session.user_id,
                    user_email: session.user_email,
                });
            }
        }
    }
    query.to_context()
}

fn session_token_from_headers(headers: &HeaderMap) -> Option<String> {
    bearer_token_from_headers(headers).or_else(|| session_cookie_from_headers(headers))
}

fn bearer_token_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get(AUTHORIZATION)
        .and_then(|raw| raw.to_str().ok())
        .map(str::trim)
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn session_cookie_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get(COOKIE)
        .and_then(|raw| raw.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|cookie| {
                let (name, value) = cookie.trim().split_once('=')?;
                (name == ISCY_SESSION_COOKIE && !value.trim().is_empty())
                    .then(|| value.trim().to_string())
            })
        })
}

fn session_cookie_value(token: &str) -> String {
    format!("{ISCY_SESSION_COOKIE}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800")
}

fn expired_session_cookie_value() -> &'static str {
    "iscy_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"
}

fn response_with_cookie(mut response: Response, cookie: &str) -> Response {
    if let Ok(value) = HeaderValue::from_str(cookie) {
        response.headers_mut().insert(SET_COOKIE, value);
    }
    response
}

fn redirect_with_cookie(location: &str, cookie: &str) -> Response {
    let mut response = Redirect::to(location).into_response();
    if let Ok(location_value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(LOCATION, location_value);
    }
    response_with_cookie(response, cookie)
}

async fn context_whoami(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(token) = session_token_from_headers(&headers) {
        if let Some(store) = state.auth_store.as_ref() {
            match store.resolve_session(&token).await {
                Ok(Some(session)) => {
                    return (
                        StatusCode::OK,
                        Json(ContextWhoamiResponse {
                            api_version: "v1",
                            authenticated: true,
                            tenant_id: Some(session.tenant_id),
                            user_id: Some(session.user_id),
                            user_email: session.user_email,
                            roles: session.user.roles,
                            is_staff: session.user.is_staff,
                            is_superuser: session.user.is_superuser,
                        }),
                    )
                        .into_response();
                }
                Ok(None) => {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(ApiErrorResponse {
                            accepted: false,
                            api_version: "v1",
                            error_code: "invalid_session",
                            message: "Rust-Session ist ungueltig oder abgelaufen.".to_string(),
                        }),
                    )
                        .into_response();
                }
                Err(err) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ApiErrorResponse {
                            accepted: false,
                            api_version: "v1",
                            error_code: "database_error",
                            message: format!("Rust-Session konnte nicht gelesen werden: {err}"),
                        }),
                    )
                        .into_response();
                }
            }
        }
    }
    match RequestContext::from_headers(&headers) {
        Ok(context) => (
            StatusCode::OK,
            Json(ContextWhoamiResponse {
                api_version: "v1",
                authenticated: context.authenticated,
                tenant_id: context.tenant_id,
                user_id: context.user_id,
                user_email: context.user_email,
                roles: context.roles,
                is_staff: context.is_staff,
                is_superuser: context.is_superuser,
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

async fn context_tenant(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => (
            StatusCode::OK,
            Json(TenantContextResponse {
                api_version: "v1",
                authenticated: true,
                tenant_id: context.tenant_id,
                user_id: context.user_id,
                user_email: context.user_email,
                roles: context.roles,
                is_staff: context.is_staff,
                is_superuser: context.is_superuser,
                authorization_model: "rust-session-or-header-context-v1",
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

async fn auth_session_create(
    State(state): State<AppState>,
    Json(payload): Json<AuthSessionCreateRequest>,
) -> Response {
    let Some(store) = state.auth_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Auth-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };
    let session_result = match (
        payload.username.as_deref(),
        payload.password.as_deref(),
        payload.tenant_id,
        payload.user_id,
    ) {
        (Some(username), Some(password), tenant_id, _) => {
            store
                .create_session_for_login(tenant_id, username, password)
                .await
        }
        (None, None, Some(tenant_id), Some(user_id)) => {
            store.create_session(tenant_id, user_id).await
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: "invalid_login_payload",
                    message: "Login benoetigt username/password oder tenant_id/user_id."
                        .to_string(),
                }),
            )
                .into_response();
        }
    };
    match session_result {
        Ok(Some(session)) => {
            let cookie = session_cookie_value(&session.token);
            response_with_cookie(
                (
                    StatusCode::CREATED,
                    Json(AuthSessionResponse {
                        accepted: true,
                        api_version: "v1",
                        authenticated: true,
                        tenant_id: Some(session.tenant_id),
                        user_id: Some(session.user_id),
                        user_email: session.user_email.clone(),
                        expires_at: Some(session.expires_at.clone()),
                        authorization_model: "rust-session-v1",
                        session_token: Some(session.token),
                        user: Some(session.user),
                    }),
                )
                    .into_response(),
                &cookie,
            )
        }
        Ok(None) => (
            StatusCode::UNAUTHORIZED,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "invalid_login_context",
                message: "Login-Daten sind fuer Rust-Session nicht gueltig.".to_string(),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Rust-Session konnte nicht erstellt werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn auth_session_current(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(token) = session_token_from_headers(&headers) else {
        return (
            StatusCode::OK,
            Json(AuthSessionResponse {
                accepted: true,
                api_version: "v1",
                authenticated: false,
                tenant_id: None,
                user_id: None,
                user_email: None,
                expires_at: None,
                authorization_model: "rust-session-v1",
                session_token: None,
                user: None,
            }),
        )
            .into_response();
    };
    let Some(store) = state.auth_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Auth-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };
    match store.resolve_session(&token).await {
        Ok(Some(session)) => (
            StatusCode::OK,
            Json(AuthSessionResponse {
                accepted: true,
                api_version: "v1",
                authenticated: true,
                tenant_id: Some(session.tenant_id),
                user_id: Some(session.user_id),
                user_email: session.user_email,
                expires_at: Some(session.expires_at),
                authorization_model: "rust-session-v1",
                session_token: None,
                user: Some(session.user),
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::UNAUTHORIZED,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "invalid_session",
                message: "Rust-Session ist ungueltig oder abgelaufen.".to_string(),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Rust-Session konnte nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn auth_logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let (Some(store), Some(token)) = (state.auth_store, session_token_from_headers(&headers)) {
        let _ = store.revoke_session(&token).await;
    }
    response_with_cookie(
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "accepted": true,
                "api_version": "v1",
                "authenticated": false
            })),
        )
            .into_response(),
        expired_session_cookie_value(),
    )
}

async fn account_users(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    if let Some(response) = admin_permission_error(&context) {
        return response;
    }

    let Some(store) = state.account_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Account-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.list_users(context.tenant_id).await {
        Ok(users) => (
            StatusCode::OK,
            Json(AccountUsersResponse {
                api_version: "v1",
                tenant_id: context.tenant_id,
                users,
            }),
        )
            .into_response(),
        Err(err) => account_store_error_response(err, "Account-User konnten nicht gelesen werden"),
    }
}

async fn account_roles(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    if let Some(response) = admin_permission_error(&context) {
        return response;
    }

    let Some(store) = state.account_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Account-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.list_roles().await {
        Ok(roles) => (
            StatusCode::OK,
            Json(AccountRolesResponse {
                api_version: "v1",
                roles,
            }),
        )
            .into_response(),
        Err(err) => {
            account_store_error_response(err, "Account-Rollen konnten nicht gelesen werden")
        }
    }
}

async fn account_groups(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    if let Some(response) = admin_permission_error(&context) {
        return response;
    }

    let Some(store) = state.account_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Account-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.list_groups().await {
        Ok(groups) => (
            StatusCode::OK,
            Json(AccountGroupsResponse {
                api_version: "v1",
                groups,
            }),
        )
            .into_response(),
        Err(err) => {
            account_store_error_response(err, "Account-Gruppen konnten nicht gelesen werden")
        }
    }
}

async fn account_permissions(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    if let Some(response) = admin_permission_error(&context) {
        return response;
    }

    let Some(store) = state.account_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Account-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.list_permissions().await {
        Ok(permissions) => (
            StatusCode::OK,
            Json(AccountPermissionsResponse {
                api_version: "v1",
                permissions,
            }),
        )
            .into_response(),
        Err(err) => {
            account_store_error_response(err, "Account-Permissions konnten nicht gelesen werden")
        }
    }
}

async fn account_user_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<account_store::AccountUserWriteRequest>,
) -> Response {
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    if let Some(response) = admin_permission_error(&context) {
        return response;
    }

    let Some(store) = state.account_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Account-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store
        .create_user(context.tenant_id, context.user_id, payload)
        .await
    {
        Ok(user) => (
            StatusCode::CREATED,
            Json(AccountUserWriteResponse {
                accepted: true,
                api_version: "v1",
                user,
            }),
        )
            .into_response(),
        Err(err) => account_store_error_response(err, "Account-User konnte nicht erstellt werden"),
    }
}

async fn account_user_update(
    Path(user_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<account_store::AccountUserWriteRequest>,
) -> Response {
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    if let Some(response) = admin_permission_error(&context) {
        return response;
    }

    let Some(store) = state.account_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Account-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store
        .update_user(context.tenant_id, user_id, context.user_id, payload)
        .await
    {
        Ok(Some(user)) => (
            StatusCode::OK,
            Json(AccountUserWriteResponse {
                accepted: true,
                api_version: "v1",
                user,
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "account_user_not_found",
                message: "Account-User wurde nicht gefunden.".to_string(),
            }),
        )
            .into_response(),
        Err(err) => {
            account_store_error_response(err, "Account-User konnte nicht aktualisiert werden")
        }
    }
}

async fn organization_tenant_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    if let Err(err) = authenticated_tenant_context(&state, &headers).await {
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
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    if let Some(response) = write_permission_error(&context) {
        return response;
    }

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
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    if let Some(response) = write_permission_error(&context) {
        return response;
    }

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
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    if let Some(response) = write_permission_error(&context) {
        return response;
    }

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
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    if let Some(response) = write_permission_error(&context) {
        return response;
    }

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
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    if let Some(response) = write_permission_error(&context) {
        return response;
    }

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

async fn evidence_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    if let Some(response) = write_permission_error(&context) {
        return response;
    }

    let Some(store) = state.evidence_store.clone() else {
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

    let form = match parse_evidence_upload_form(&headers, &body) {
        Ok(form) => form,
        Err(message) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: "invalid_evidence_upload",
                    message,
                }),
            )
                .into_response();
        }
    };
    let media_root = evidence_media_root(&state);
    let saved_file = match form
        .file
        .as_ref()
        .map(|file| save_evidence_upload(&media_root, file))
        .transpose()
    {
        Ok(file) => file,
        Err(message) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: "invalid_evidence_file",
                    message,
                }),
            )
                .into_response();
        }
    };
    let payload = evidence_store::EvidenceItemCreateRequest {
        session_id: optional_i64_form_field(&form.fields, "session_id"),
        domain_id: optional_i64_form_field(&form.fields, "domain_id"),
        measure_id: optional_i64_form_field(&form.fields, "measure_id"),
        requirement_id: optional_i64_form_field(&form.fields, "requirement_id"),
        title: form.fields.get("title").cloned().unwrap_or_default(),
        description: form.fields.get("description").cloned().unwrap_or_default(),
        linked_requirement: form
            .fields
            .get("linked_requirement")
            .cloned()
            .unwrap_or_default(),
        file_name: saved_file.as_ref().map(|file| file.relative_path.clone()),
        status: form.fields.get("status").cloned(),
        review_notes: form.fields.get("review_notes").cloned().unwrap_or_default(),
    };

    match store
        .create_evidence_item(context.tenant_id, context.user_id, payload)
        .await
    {
        Ok(item) => {
            let need_sync = if let Some(session_id) = item.session_id {
                store
                    .sync_evidence_needs(
                        context.tenant_id,
                        session_id,
                        evidence_store::EvidenceNeedSyncRequest {
                            covered_threshold: None,
                            partial_threshold: None,
                        },
                    )
                    .await
                    .ok()
                    .flatten()
            } else {
                None
            };
            (
                StatusCode::CREATED,
                Json(EvidenceUploadResponse {
                    accepted: true,
                    api_version: "v1",
                    item,
                    need_sync,
                }),
            )
                .into_response()
        }
        Err(err) => {
            if let Some(file) = saved_file.as_ref() {
                let _ = fs::remove_file(&file.absolute_path);
            }
            let message = err.to_string();
            let status = if message.contains("wurde nicht gefunden")
                || message.contains("darf nicht leer sein")
            {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (
                status,
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: if status == StatusCode::BAD_REQUEST {
                        "invalid_evidence_upload"
                    } else {
                        "database_error"
                    },
                    message: format!("Evidence konnte nicht erstellt werden: {message}"),
                }),
            )
                .into_response()
        }
    }
}

async fn import_center_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<import_store::ImportJobRequest>,
) -> Response {
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    if let Some(response) = write_permission_error(&context) {
        return response;
    }

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

async fn import_center_csv_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ImportCsvRequest>,
) -> Response {
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    if let Some(response) = write_permission_error(&context) {
        return response;
    }

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

    let (headers, rows) = match parse_import_csv(&payload.csv_data) {
        Ok(parsed) => parsed,
        Err(message) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: "invalid_import_csv",
                    message,
                }),
            )
                .into_response();
        }
    };

    let job = import_store::ImportJobRequest {
        import_type: payload.import_type,
        replace_existing: payload.replace_existing,
        rows,
    };
    match store.apply_job(context.tenant_id, job).await {
        Ok(result) => (
            StatusCode::OK,
            Json(ImportCsvResponse {
                accepted: true,
                api_version: "v1",
                headers,
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
                message: format!("CSV-Import konnte nicht angewendet werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn import_center_preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    if let Some(response) = write_permission_error(&context) {
        return response;
    }

    let form = match parse_import_upload_form(&headers, &body) {
        Ok(form) => form,
        Err(message) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: "invalid_import_upload",
                    message,
                }),
            )
                .into_response();
        }
    };
    let file = match import_upload_file_from_form(&form) {
        Ok(file) => file,
        Err(message) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: "invalid_import_upload",
                    message,
                }),
            )
                .into_response();
        }
    };
    let import_type = match required_import_type_field(&form.fields) {
        Ok(import_type) => import_type,
        Err(message) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: "invalid_import_type",
                    message,
                }),
            )
                .into_response();
        }
    };
    let selected_mapping =
        match import_preview::selected_mapping_from_fields(&import_type, &form.fields) {
            Ok(mapping) => mapping,
            Err(message) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ApiErrorResponse {
                        accepted: false,
                        api_version: "v1",
                        error_code: "invalid_import_type",
                        message,
                    }),
                )
                    .into_response();
            }
        };
    match import_preview::build_import_preview(
        &file,
        &import_type,
        form_bool_field(&form.fields, "replace_existing"),
        selected_mapping,
    ) {
        Ok(preview) => (
            StatusCode::OK,
            Json(ImportPreviewResponse {
                accepted: true,
                api_version: "v1",
                preview: preview.preview,
            }),
        )
            .into_response(),
        Err(message) => (
            StatusCode::BAD_REQUEST,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: if message.contains("Importtyp") {
                    "invalid_import_type"
                } else {
                    "invalid_import_upload"
                },
                message,
            }),
        )
            .into_response(),
    }
}

async fn applicability_assessments(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    if let Some(response) = write_permission_error(&context) {
        return response;
    }

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
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    let context = match authenticated_tenant_context(&state, &headers).await {
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
    if let Err(err) = authenticated_tenant_context(&state, &headers).await {
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

async fn web_index(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let context = web_context_from_request(&query, &headers, &state).await;
    let cards = [
        web_link_card(
            "Dashboard",
            &web_path_with_context("/dashboard/", context.as_ref()),
            "KPI-Ueberblick",
        ),
        web_link_card(
            "Risks",
            &web_path_with_context("/risks/", context.as_ref()),
            "Aktive Risiken",
        ),
        web_link_card(
            "Evidence",
            &web_path_with_context("/evidence/", context.as_ref()),
            "Nachweise und Luecken",
        ),
        web_link_card(
            "Reports",
            &web_path_with_context("/reports/", context.as_ref()),
            "Readiness-Snapshots",
        ),
        web_link_card(
            "Roadmap",
            &web_path_with_context("/roadmap/", context.as_ref()),
            "Plaene und offene Tasks",
        ),
        web_link_card(
            "Assets",
            &web_path_with_context("/assets/", context.as_ref()),
            "Informationswerte",
        ),
        web_link_card(
            "Processes",
            &web_path_with_context("/processes/", context.as_ref()),
            "Prozessregister",
        ),
    ]
    .join("");
    let body = format!(
        r#"
        <section class="hero">
          <h1>ISCY</h1>
          <p>Rust Core fuer ISMS, NIS2, KRITIS und Product Security.</p>
        </section>
        <section class="grid">
          {}
        </section>
        "#,
        cards,
    );
    web_page("ISCY", "/", context.as_ref(), &body)
}

async fn web_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let context = web_context_from_request(&query, &headers, &state).await;
    let body = format!(
        r#"
        <section class="panel form-panel">
          <h1>Login</h1>
          <form method="post" action="/login/">
            <label>Tenant-ID<input name="tenant_id" type="number" min="1" required value="{}"></label>
            <label>Benutzername<input name="username" type="text" autocomplete="username" required value="admin"></label>
            <label>Passwort<input name="password" type="password" autocomplete="current-password" required></label>
            <button type="submit">Weiter</button>
          </form>
        </section>
        "#,
        query
            .tenant_id
            .map(|value| value.to_string())
            .unwrap_or_else(|| "1".to_string()),
    );
    web_page("Login", "/login/", context.as_ref(), &body)
}

async fn web_login_submit(
    State(state): State<AppState>,
    Form(form): Form<WebLoginForm>,
) -> Response {
    let Some(store) = state.auth_store else {
        return web_page(
            "Login",
            "/login/",
            None,
            r#"<section class="panel form-panel error"><h1>Login</h1><p>Rust-Auth-Store ist nicht konfiguriert.</p></section>"#,
        )
        .into_response();
    };
    match store
        .create_session_for_login(form.tenant_id, &form.username, &form.password)
        .await
    {
        Ok(Some(session)) => redirect_with_cookie("/dashboard/", &session_cookie_value(&session.token)),
        Ok(None) => web_page(
            "Login",
            "/login/",
            None,
            r#"<section class="panel form-panel error"><h1>Login</h1><p>Benutzername oder Passwort ist nicht gueltig.</p></section>"#,
        )
        .into_response(),
        Err(err) => web_page(
            "Login",
            "/login/",
            None,
            &format!(
                r#"<section class="panel form-panel error"><h1>Login</h1><p>{}</p></section>"#,
                html_escape(&err.to_string())
            ),
        )
        .into_response(),
    }
}

async fn web_dashboard(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
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
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
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
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
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
                <section class="grid">
                  <article class="panel wide">
                    <table>
                      <thead><tr><th>Titel</th><th>Status</th><th>Owner</th><th>Requirement</th></tr></thead>
                      <tbody>{}</tbody>
                    </table>
                  </article>
                  <article class="panel wide">
                    <h2>Evidence hochladen</h2>
                    <form method="post" action="/evidence/" enctype="multipart/form-data">
                      <div class="form-grid">
                        <label>Titel<input name="title" type="text" required></label>
                        <label>Status<select name="status">{}</select></label>
                        <label>Session-ID<input name="session_id" type="number" min="1"></label>
                        <label>Requirement-ID<input name="requirement_id" type="number" min="1"></label>
                      </div>
                      <label>Linked Requirement<input name="linked_requirement" type="text"></label>
                      <label>Beschreibung<textarea name="description" rows="4"></textarea></label>
                      <label>Datei<input name="file" type="file" accept=".pdf,.docx,.xlsx,.png,.jpg,.jpeg,.csv,.txt"></label>
                      <button type="submit">Evidence speichern</button>
                    </form>
                  </article>
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
                evidence_status_options_for("SUBMITTED"),
            );
            web_page("Evidence", "/evidence/", Some(&context), &body)
        }
        Err(err) => web_error_page("Evidence", "/evidence/", &context, &err.to_string()),
    }
}

async fn web_evidence_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(_) => return web_missing_context("Evidence", "/evidence/").into_response(),
    };
    let context = WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    };
    if !auth_context.can_write() {
        return web_error_page(
            "Evidence",
            "/evidence/",
            &context,
            "Diese Rust-Webroute benoetigt eine schreibende ISCY-Rolle.",
        )
        .into_response();
    }
    let Some(store) = state.evidence_store.clone() else {
        return web_store_missing("Evidence", "/evidence/", &context, "Evidence").into_response();
    };
    let form = match parse_evidence_upload_form(&headers, &body) {
        Ok(form) => form,
        Err(message) => {
            return web_error_page("Evidence", "/evidence/", &context, &message).into_response();
        }
    };
    let media_root = evidence_media_root(&state);
    let saved_file = match form
        .file
        .as_ref()
        .map(|file| save_evidence_upload(&media_root, file))
        .transpose()
    {
        Ok(file) => file,
        Err(message) => {
            return web_error_page("Evidence", "/evidence/", &context, &message).into_response();
        }
    };
    let payload = evidence_store::EvidenceItemCreateRequest {
        session_id: optional_i64_form_field(&form.fields, "session_id"),
        domain_id: optional_i64_form_field(&form.fields, "domain_id"),
        measure_id: optional_i64_form_field(&form.fields, "measure_id"),
        requirement_id: optional_i64_form_field(&form.fields, "requirement_id"),
        title: form.fields.get("title").cloned().unwrap_or_default(),
        description: form.fields.get("description").cloned().unwrap_or_default(),
        linked_requirement: form
            .fields
            .get("linked_requirement")
            .cloned()
            .unwrap_or_default(),
        file_name: saved_file.as_ref().map(|file| file.relative_path.clone()),
        status: form.fields.get("status").cloned(),
        review_notes: form.fields.get("review_notes").cloned().unwrap_or_default(),
    };
    match store
        .create_evidence_item(auth_context.tenant_id, auth_context.user_id, payload)
        .await
    {
        Ok(item) => {
            if let Some(session_id) = item.session_id {
                let _ = store
                    .sync_evidence_needs(
                        auth_context.tenant_id,
                        session_id,
                        evidence_store::EvidenceNeedSyncRequest {
                            covered_threshold: None,
                            partial_threshold: None,
                        },
                    )
                    .await;
            }
            let body = format!(
                r#"<section class="hero compact"><h1>Evidence gespeichert</h1><p>{}</p></section>
                <section class="panel wide"><a href="{}">Zur Evidence-Uebersicht</a></section>"#,
                html_escape(&item.title),
                web_path_with_context("/evidence/", Some(&context)),
            );
            web_page("Evidence", "/evidence/", Some(&context), &body).into_response()
        }
        Err(err) => {
            if let Some(file) = saved_file.as_ref() {
                let _ = fs::remove_file(&file.absolute_path);
            }
            web_error_page("Evidence", "/evidence/", &context, &err.to_string()).into_response()
        }
    }
}

async fn web_catalog(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
        return web_missing_context("Catalog", "/catalog/");
    };
    let Some(store) = state.catalog_store else {
        return web_store_missing("Catalog", "/catalog/", &context, "Catalog");
    };
    match store.domain_library().await {
        Ok(library) => {
            let domain_cards = library
                .domains
                .iter()
                .map(|domain| {
                    let question_rows = domain
                        .questions
                        .iter()
                        .take(4)
                        .map(|question| {
                            format!(
                                r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                                html_escape(&question.code),
                                html_escape(&question.text),
                                html_escape(&question.question_kind_label),
                                html_escape(&question.wizard_step_label),
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("");
                    format!(
                        r#"
                        <article class="panel wide">
                          <h2>{}</h2>
                          <p>{}</p>
                          <p class="muted">Code {} · {} Fragen</p>
                          <table>
                            <thead><tr><th>Frage</th><th>Text</th><th>Typ</th><th>Wizard</th></tr></thead>
                            <tbody>{}</tbody>
                          </table>
                        </article>
                        "#,
                        html_escape(&domain.name),
                        html_escape(&domain.description),
                        html_escape(&domain.code),
                        domain.question_count,
                        if question_rows.is_empty() {
                            web_empty_row(4, "Keine Fragen vorhanden.")
                        } else {
                            question_rows
                        },
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let body = format!(
                r#"
                <section class="hero compact"><h1>Catalog</h1><p>{} Domaenen · {} Fragen</p></section>
                <section class="metrics">
                  {}
                  {}
                </section>
                <section class="grid">{}</section>
                "#,
                library.domains.len(),
                library.question_count,
                metric_card("Domaenen", library.domains.len() as i64),
                metric_card("Fragen", library.question_count),
                if domain_cards.is_empty() {
                    r#"<article class="panel wide"><p>Keine Domaenen vorhanden.</p></article>"#
                        .to_string()
                } else {
                    domain_cards
                },
            );
            web_page("Catalog", "/catalog/", Some(&context), &body)
        }
        Err(err) => web_error_page("Catalog", "/catalog/", &context, &err.to_string()),
    }
}
async fn web_reports(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
        return web_missing_context("Reports", "/reports/");
    };
    let Some(store) = state.report_store else {
        return web_store_missing("Reports", "/reports/", &context, "Report");
    };
    match store.list_snapshots(context.tenant_id, 50).await {
        Ok(reports) => {
            let rows = reports
                .iter()
                .map(|report| {
                    format!(
                        r#"<tr><td>{}</td><td>{}</td><td>{}%</td><td>{}%</td><td>{}</td></tr>"#,
                        html_escape(&report.title),
                        html_escape(&report.applicability_result),
                        report.iso_readiness_percent,
                        report.nis2_readiness_percent,
                        html_escape(&report.created_at),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let body = format!(
                r#"
                <section class="hero compact"><h1>Reports</h1><p>{} Readiness-Snapshots</p></section>
                <section class="panel wide">
                  <table>
                    <thead><tr><th>Titel</th><th>Applicability</th><th>ISO</th><th>NIS2</th><th>Erstellt</th></tr></thead>
                    <tbody>{}</tbody>
                  </table>
                </section>
                "#,
                reports.len(),
                if rows.is_empty() {
                    web_empty_row(5, "Keine Reports vorhanden.")
                } else {
                    rows
                },
            );
            web_page("Reports", "/reports/", Some(&context), &body)
        }
        Err(err) => web_error_page("Reports", "/reports/", &context, &err.to_string()),
    }
}
async fn web_roadmap(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
        return web_missing_context("Roadmap", "/roadmap/");
    };
    let Some(store) = state.roadmap_store else {
        return web_store_missing("Roadmap", "/roadmap/", &context, "Roadmap");
    };
    match store.list_plans(context.tenant_id, 50).await {
        Ok(plans) => {
            let rows = plans
                .iter()
                .map(|plan| {
                    format!(
                        r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                        html_escape(&plan.title),
                        html_escape(&plan.overall_priority),
                        plan.phase_count,
                        plan.task_count,
                        plan.open_task_count,
                        html_escape(plan.planned_start.as_deref().unwrap_or("-")),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let body = format!(
                r#"
                <section class="hero compact"><h1>Roadmap</h1><p>{} Plaene</p></section>
                <section class="panel wide">
                  <table>
                    <thead><tr><th>Titel</th><th>Prioritaet</th><th>Phasen</th><th>Tasks</th><th>Offen</th><th>Start</th></tr></thead>
                    <tbody>{}</tbody>
                  </table>
                </section>
                "#,
                plans.len(),
                if rows.is_empty() {
                    web_empty_row(6, "Keine Roadmaps vorhanden.")
                } else {
                    rows
                },
            );
            web_page("Roadmap", "/roadmap/", Some(&context), &body)
        }
        Err(err) => web_error_page("Roadmap", "/roadmap/", &context, &err.to_string()),
    }
}
async fn web_assets(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
        return web_missing_context("Assets", "/assets/");
    };
    let Some(store) = state.asset_store else {
        return web_store_missing("Assets", "/assets/", &context, "Asset");
    };
    match store.list_information_assets(context.tenant_id, 100).await {
        Ok(assets) => {
            let rows = assets
                .iter()
                .map(|asset| {
                    format!(
                        r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                        html_escape(&asset.name),
                        html_escape(&asset.asset_type_label),
                        html_escape(&asset.criticality_label),
                        html_escape(asset.owner_display.as_deref().unwrap_or("-")),
                        html_escape(asset.business_unit_name.as_deref().unwrap_or("-")),
                        yes_no(asset.is_in_scope),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let body = format!(
                r#"
                <section class="hero compact"><h1>Assets</h1><p>{} Informationswerte</p></section>
                <section class="panel wide">
                  <table>
                    <thead><tr><th>Name</th><th>Typ</th><th>Kritikalitaet</th><th>Owner</th><th>Business Unit</th><th>Scope</th></tr></thead>
                    <tbody>{}</tbody>
                  </table>
                </section>
                "#,
                assets.len(),
                if rows.is_empty() {
                    web_empty_row(6, "Keine Assets vorhanden.")
                } else {
                    rows
                },
            );
            web_page("Assets", "/assets/", Some(&context), &body)
        }
        Err(err) => web_error_page("Assets", "/assets/", &context, &err.to_string()),
    }
}
async fn web_imports(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let display_context = web_context_from_request(&query, &headers, &state).await;
    let auth_context = authenticated_tenant_context(&state, &headers).await.ok();
    let Some(context) = display_context.or_else(|| {
        auth_context.as_ref().map(|context| WebContext {
            tenant_id: context.tenant_id,
            user_id: context.user_id,
            user_email: context.user_email.clone(),
        })
    }) else {
        return web_missing_context("Imports", "/imports/");
    };
    let Some(_) = state.import_store else {
        return web_store_missing("Imports", "/imports/", &context, "Import");
    };

    web_imports_page(&context, None)
}

async fn web_imports_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<WebImportCsvForm>,
) -> Response {
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(_) => return web_missing_context("Imports", "/imports/").into_response(),
    };
    let context = WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    };
    if !auth_context.can_write() {
        return web_error_page(
            "Imports",
            "/imports/",
            &context,
            "Diese Rust-Webroute benoetigt eine schreibende ISCY-Rolle.",
        )
        .into_response();
    }
    let Some(store) = state.import_store else {
        return web_store_missing("Imports", "/imports/", &context, "Import").into_response();
    };
    let (headers, rows) = match parse_import_csv(&form.csv_data) {
        Ok(parsed) => parsed,
        Err(message) => {
            return web_error_page("Imports", "/imports/", &context, &message).into_response();
        }
    };
    let job = import_store::ImportJobRequest {
        import_type: form.import_type,
        replace_existing: form.replace_existing.is_some(),
        rows,
    };
    match store.apply_job(auth_context.tenant_id, job).await {
        Ok(result) => web_imports_page(&context, Some((&headers, &result))).into_response(),
        Err(err) => {
            web_error_page("Imports", "/imports/", &context, &err.to_string()).into_response()
        }
    }
}

async fn web_imports_preview_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(_) => return web_missing_context("Imports", "/imports/").into_response(),
    };
    let context = WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    };
    if !auth_context.can_write() {
        return web_error_page(
            "Imports",
            "/imports/",
            &context,
            "Diese Rust-Webroute benoetigt eine schreibende ISCY-Rolle.",
        )
        .into_response();
    }
    let Some(store) = state.import_store else {
        return web_store_missing("Imports", "/imports/", &context, "Import").into_response();
    };
    let form = match parse_import_upload_form(&headers, &body) {
        Ok(form) => form,
        Err(message) => {
            return web_error_page("Imports", "/imports/", &context, &message).into_response();
        }
    };
    let file = match import_upload_file_from_form(&form) {
        Ok(file) => file,
        Err(message) => {
            return web_error_page("Imports", "/imports/", &context, &message).into_response();
        }
    };
    let import_type = match required_import_type_field(&form.fields) {
        Ok(import_type) => import_type,
        Err(message) => {
            return web_error_page("Imports", "/imports/", &context, &message).into_response();
        }
    };
    let replace_existing = form_bool_field(&form.fields, "replace_existing");
    let selected_mapping =
        match import_preview::selected_mapping_from_fields(&import_type, &form.fields) {
            Ok(mapping) => mapping,
            Err(message) => {
                return web_error_page("Imports", "/imports/", &context, &message).into_response();
            }
        };
    let preview = match import_preview::build_import_preview(
        &file,
        &import_type,
        replace_existing,
        selected_mapping,
    ) {
        Ok(preview) => preview,
        Err(message) => {
            return web_error_page("Imports", "/imports/", &context, &message).into_response();
        }
    };
    let action = form
        .fields
        .get("action")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("preview");

    if action.eq_ignore_ascii_case("confirm") {
        if !import_preview::supports_required_name_mapping(&preview.preview.selected_mapping) {
            return web_imports_preview_page(
                &context,
                &preview.preview,
                &file,
                Some(
                    "Die Pflichtzuordnung fuer das Feld \"name\" fehlt. Bitte mindestens das Namensfeld zuordnen.",
                ),
            )
            .into_response();
        }
        let rows = match import_preview::apply_mapping(
            &preview.rows,
            &preview.preview.import_type,
            &preview.preview.selected_mapping,
        ) {
            Ok(rows) => rows,
            Err(message) => {
                return web_error_page("Imports", "/imports/", &context, &message).into_response();
            }
        };
        let job = import_store::ImportJobRequest {
            import_type: preview.preview.import_type.clone(),
            replace_existing: preview.preview.replace_existing,
            rows,
        };
        return match store.apply_job(auth_context.tenant_id, job).await {
            Ok(result) => web_imports_page(&context, Some((&preview.preview.headers, &result)))
                .into_response(),
            Err(err) => {
                web_error_page("Imports", "/imports/", &context, &err.to_string()).into_response()
            }
        };
    }

    web_imports_preview_page(&context, &preview.preview, &file, None).into_response()
}

async fn web_processes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
        return web_missing_context("Processes", "/processes/");
    };
    let Some(store) = state.process_store else {
        return web_store_missing("Processes", "/processes/", &context, "Process");
    };
    match store.list_processes(context.tenant_id, 100).await {
        Ok(processes) => {
            let rows = processes
                .iter()
                .map(|process| {
                    format!(
                        r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                        html_escape(&process.name),
                        html_escape(&process.status_label),
                        html_escape(process.business_unit_name.as_deref().unwrap_or("-")),
                        html_escape(process.owner_display.as_deref().unwrap_or("-")),
                        yes_no(process.documented),
                        yes_no(process.evidenced),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let body = format!(
                r#"
                <section class="hero compact"><h1>Processes</h1><p>{} Prozesse</p></section>
                <section class="panel wide">
                  <table>
                    <thead><tr><th>Name</th><th>Status</th><th>Business Unit</th><th>Owner</th><th>Dokumentiert</th><th>Evidenced</th></tr></thead>
                    <tbody>{}</tbody>
                  </table>
                </section>
                "#,
                processes.len(),
                if rows.is_empty() {
                    web_empty_row(6, "Keine Prozesse vorhanden.")
                } else {
                    rows
                },
            );
            web_page("Processes", "/processes/", Some(&context), &body)
        }
        Err(err) => web_error_page("Processes", "/processes/", &context, &err.to_string()),
    }
}
async fn web_requirements(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
        return web_missing_context("Requirements", "/requirements/");
    };
    let Some(store) = state.requirement_store else {
        return web_store_missing("Requirements", "/requirements/", &context, "Requirement");
    };
    match store.library(200).await {
        Ok(library) => {
            let active_count = library
                .requirements
                .iter()
                .filter(|requirement| requirement.is_active)
                .count() as i64;
            let version_rows = library
                .mapping_versions
                .iter()
                .map(|version| {
                    format!(
                        r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                        html_escape(&version.framework),
                        html_escape(&version.title),
                        html_escape(&version.version),
                        html_escape(&version.status_label),
                        version.requirement_count,
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let requirement_rows = library
                .requirements
                .iter()
                .map(|requirement| {
                    format!(
                        r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                        html_escape(&requirement.framework_label),
                        html_escape(&requirement.code),
                        html_escape(&requirement.title),
                        html_escape(&requirement.domain),
                        html_escape(&requirement.coverage_level_label),
                        html_escape(
                            requirement
                                .primary_source
                                .as_ref()
                                .map(|source| source.citation.as_str())
                                .unwrap_or("-"),
                        ),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let body = format!(
                r#"
                <section class="hero compact"><h1>Requirements</h1><p>{} Anforderungen · {} aktive</p></section>
                <section class="metrics">
                  {}
                  {}
                  {}
                </section>
                <section class="grid">
                  <article class="panel wide">
                    <h2>Mapping-Versionen</h2>
                    <table>
                      <thead><tr><th>Framework</th><th>Titel</th><th>Version</th><th>Status</th><th>Requirements</th></tr></thead>
                      <tbody>{}</tbody>
                    </table>
                  </article>
                  <article class="panel wide">
                    <h2>Requirement Library</h2>
                    <table>
                      <thead><tr><th>Framework</th><th>Code</th><th>Titel</th><th>Domain</th><th>Coverage</th><th>Quelle</th></tr></thead>
                      <tbody>{}</tbody>
                    </table>
                  </article>
                </section>
                "#,
                library.requirements.len(),
                active_count,
                metric_card("Requirements", library.requirements.len() as i64),
                metric_card("Aktiv", active_count),
                metric_card("Mappings", library.mapping_versions.len() as i64),
                if version_rows.is_empty() {
                    web_empty_row(5, "Keine Mapping-Versionen vorhanden.")
                } else {
                    version_rows
                },
                if requirement_rows.is_empty() {
                    web_empty_row(6, "Keine Requirements vorhanden.")
                } else {
                    requirement_rows
                },
            );
            web_page("Requirements", "/requirements/", Some(&context), &body)
        }
        Err(err) => web_error_page("Requirements", "/requirements/", &context, &err.to_string()),
    }
}
async fn web_assessments(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
        return web_missing_context("Assessments", "/assessments/");
    };
    let Some(store) = state.assessment_store else {
        return web_store_missing("Assessments", "/assessments/", &context, "Assessment");
    };
    let applicability = match store.list_applicability(context.tenant_id, 50).await {
        Ok(items) => items,
        Err(err) => {
            return web_error_page("Assessments", "/assessments/", &context, &err.to_string())
        }
    };
    let assessments = match store.list_assessments(context.tenant_id, 100).await {
        Ok(items) => items,
        Err(err) => {
            return web_error_page("Assessments", "/assessments/", &context, &err.to_string())
        }
    };
    let measures = match store.list_measures(context.tenant_id, 100).await {
        Ok(items) => items,
        Err(err) => {
            return web_error_page("Assessments", "/assessments/", &context, &err.to_string())
        }
    };

    let applicability_rows = applicability
        .iter()
        .map(|item| {
            format!(
                r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                html_escape(&item.sector),
                html_escape(&item.company_size),
                html_escape(&item.status_label),
                html_escape(&item.reasoning),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let assessment_rows = assessments
        .iter()
        .map(|item| {
            format!(
                r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                html_escape(&item.process_name),
                html_escape(&item.requirement_code),
                html_escape(&item.requirement_title),
                html_escape(&item.status_label),
                html_escape(item.owner_display.as_deref().unwrap_or("-")),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let measure_rows = measures
        .iter()
        .map(|item| {
            format!(
                r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                html_escape(&item.title),
                html_escape(&item.priority_label),
                html_escape(&item.status_label),
                html_escape(item.owner_display.as_deref().unwrap_or("-")),
                html_escape(item.due_date.as_deref().unwrap_or("-")),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let body = format!(
        r#"
        <section class="hero compact"><h1>Assessments</h1><p>Tenant {} · {} Assessments · {} Measures</p></section>
        <section class="metrics">
          {}
          {}
          {}
        </section>
        <section class="grid">
          <article class="panel wide">
            <h2>Applicability</h2>
            <table>
              <thead><tr><th>Sektor</th><th>Groesse</th><th>Status</th><th>Begruendung</th></tr></thead>
              <tbody>{}</tbody>
            </table>
          </article>
          <article class="panel wide">
            <h2>Assessments</h2>
            <table>
              <thead><tr><th>Prozess</th><th>Requirement</th><th>Titel</th><th>Status</th><th>Owner</th></tr></thead>
              <tbody>{}</tbody>
            </table>
          </article>
          <article class="panel wide">
            <h2>Measures</h2>
            <table>
              <thead><tr><th>Titel</th><th>Prioritaet</th><th>Status</th><th>Owner</th><th>Faellig</th></tr></thead>
              <tbody>{}</tbody>
            </table>
          </article>
        </section>
        "#,
        context.tenant_id,
        assessments.len(),
        measures.len(),
        metric_card("Applicability", applicability.len() as i64),
        metric_card("Assessments", assessments.len() as i64),
        metric_card("Measures", measures.len() as i64),
        if applicability_rows.is_empty() {
            web_empty_row(4, "Keine Betroffenheitsanalyse vorhanden.")
        } else {
            applicability_rows
        },
        if assessment_rows.is_empty() {
            web_empty_row(5, "Keine Assessments vorhanden.")
        } else {
            assessment_rows
        },
        if measure_rows.is_empty() {
            web_empty_row(5, "Keine Measures vorhanden.")
        } else {
            measure_rows
        },
    );
    web_page("Assessments", "/assessments/", Some(&context), &body)
}
async fn web_organizations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
        return web_missing_context("Organizations", "/organizations/");
    };
    let Some(store) = state.tenant_store else {
        return web_store_missing("Organizations", "/organizations/", &context, "Tenant");
    };
    match store.tenant_profile(context.tenant_id).await {
        Ok(Some(tenant)) => {
            let operation_countries = if tenant.operation_countries.is_empty() {
                "-".to_string()
            } else {
                html_escape(&tenant.operation_countries.join(", "))
            };
            let body = format!(
                r#"
                <section class="hero compact"><h1>Organizations</h1><p>{}</p></section>
                <section class="metrics">
                  {}
                  {}
                  {}
                </section>
                <section class="panel wide">
                  <table>
                    <tbody>
                      <tr><th>Slug</th><td>{}</td></tr>
                      <tr><th>Land</th><td>{}</td></tr>
                      <tr><th>Operationslaender</th><td>{}</td></tr>
                      <tr><th>Sektor</th><td>{}</td></tr>
                      <tr><th>Mitarbeitende</th><td>{}</td></tr>
                      <tr><th>Umsatz Mio.</th><td>{}</td></tr>
                      <tr><th>Bilanzsumme Mio.</th><td>{}</td></tr>
                      <tr><th>Kritische Services</th><td>{}</td></tr>
                      <tr><th>Supply Chain Rolle</th><td>{}</td></tr>
                      <tr><th>NIS2 relevant</th><td>{}</td></tr>
                      <tr><th>KRITIS relevant</th><td>{}</td></tr>
                      <tr><th>Digitale Produkte</th><td>{}</td></tr>
                      <tr><th>AI Systeme</th><td>{}</td></tr>
                      <tr><th>OT / IACS</th><td>{}</td></tr>
                      <tr><th>Automotive</th><td>{}</td></tr>
                      <tr><th>PSIRT definiert</th><td>{}</td></tr>
                      <tr><th>SBOM erforderlich</th><td>{}</td></tr>
                      <tr><th>Product Security Scope</th><td>{}</td></tr>
                      <tr><th>Beschreibung</th><td>{}</td></tr>
                    </tbody>
                  </table>
                </section>
                "#,
                html_escape(&tenant.name),
                metric_card("Mitarbeitende", tenant.employee_count),
                metric_card("Laender", tenant.operation_countries.len() as i64),
                metric_card("Tenant-ID", tenant.id),
                html_escape(&tenant.slug),
                html_escape(&tenant.country),
                operation_countries,
                html_escape(&tenant.sector),
                tenant.employee_count,
                html_escape(&tenant.annual_revenue_million),
                html_escape(&tenant.balance_sheet_million),
                html_escape(&tenant.critical_services),
                html_escape(&tenant.supply_chain_role),
                yes_no(tenant.nis2_relevant),
                yes_no(tenant.kritis_relevant),
                yes_no(tenant.develops_digital_products),
                yes_no(tenant.uses_ai_systems),
                yes_no(tenant.ot_iacs_scope),
                yes_no(tenant.automotive_scope),
                yes_no(tenant.psirt_defined),
                yes_no(tenant.sbom_required),
                html_escape(&tenant.product_security_scope),
                html_escape(&tenant.description),
            );
            web_page("Organizations", "/organizations/", Some(&context), &body)
        }
        Ok(None) => web_error_page(
            "Organizations",
            "/organizations/",
            &context,
            "Tenant wurde fuer diesen Kontext nicht gefunden.",
        ),
        Err(err) => web_error_page(
            "Organizations",
            "/organizations/",
            &context,
            &err.to_string(),
        ),
    }
}
async fn web_admin_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let display_context = web_context_from_request(&query, &headers, &state).await;
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(err) => {
            if let Some(context) = display_context.as_ref() {
                return web_error_page("Users", "/admin/users/", context, err.message());
            }
            return web_missing_context("Users", "/admin/users/");
        }
    };
    let context = display_context.unwrap_or_else(|| WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    });
    if admin_permission_error(&auth_context).is_some() {
        return web_error_page(
            "Users",
            "/admin/users/",
            &context,
            "Diese Rust-Webroute benoetigt eine Admin-Rolle.",
        );
    }
    let Some(store) = state.account_store else {
        return web_store_missing("Users", "/admin/users/", &context, "Account");
    };

    let users = match store.list_users(context.tenant_id).await {
        Ok(users) => users,
        Err(err) => return web_error_page("Users", "/admin/users/", &context, &err.to_string()),
    };
    let roles = match store.list_roles().await {
        Ok(roles) => roles,
        Err(err) => return web_error_page("Users", "/admin/users/", &context, &err.to_string()),
    };
    let groups = match store.list_groups().await {
        Ok(groups) => groups,
        Err(err) => return web_error_page("Users", "/admin/users/", &context, &err.to_string()),
    };
    let permissions = match store.list_permissions().await {
        Ok(permissions) => permissions,
        Err(err) => return web_error_page("Users", "/admin/users/", &context, &err.to_string()),
    };
    let create_role_options = role_options_for(&roles, "CONTRIBUTOR");
    let create_group_options = group_options_for(&groups, &[]);
    let create_permission_options = permission_options_for(&permissions, &[]);
    let rows = users
        .iter()
        .map(|user| {
            format!(
                r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                html_escape(&user.username),
                html_escape(&user.display_name),
                html_escape(&user.email),
                html_escape(&user.roles.join(", ")),
                html_escape(&user.groups.join(", ")),
                html_escape(&user.permissions.join(", ")),
                yes_no(user.is_active),
                yes_no(user.is_staff),
                yes_no(user.is_superuser),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let edit_forms = users
        .iter()
        .map(|user| {
            let selected_role = user
                .roles
                .first()
                .map(String::as_str)
                .unwrap_or(user.role.as_str());
            format!(
                r#"
                <form class="user-editor" method="post" action="/admin/users/{}">
                  <h3>{}</h3>
                  <input name="groups_present" type="hidden" value="1">
                  <input name="permissions_present" type="hidden" value="1">
                  <div class="form-grid">
                    <label>Benutzername<input name="username" type="text" autocomplete="username" required value="{}"></label>
                    <label>Neues Passwort<input name="password" type="password" autocomplete="new-password"></label>
                    <label>Vorname<input name="first_name" type="text" autocomplete="given-name" value="{}"></label>
                    <label>Nachname<input name="last_name" type="text" autocomplete="family-name" value="{}"></label>
                    <label>E-Mail<input name="email" type="email" autocomplete="email" value="{}"></label>
                    <label>Jobtitel<input name="job_title" type="text" value="{}"></label>
                    <label>Rolle<select name="role">{}</select></label>
                    <label>Gruppen<select name="groups" multiple size="3">{}</select></label>
                    <label>Direktrechte<select name="permissions" multiple size="5">{}</select></label>
                  </div>
                  <div class="toggle-row">
                    <label class="checkbox-row"><input name="is_active" type="checkbox" value="1"{}> Aktiv</label>
                    <label class="checkbox-row"><input name="is_staff" type="checkbox" value="1"{}> Staff</label>
                    <label class="checkbox-row"><input name="is_superuser" type="checkbox" value="1"{}> Superuser</label>
                  </div>
                  <button type="submit">Aenderungen speichern</button>
                </form>
                "#,
                user.id,
                html_escape(&user.display_name),
                html_escape(&user.username),
                html_escape(&user.first_name),
                html_escape(&user.last_name),
                html_escape(&user.email),
                html_escape(&user.job_title),
                role_options_for(&roles, selected_role),
                group_options_for(&groups, &user.groups),
                permission_options_for(&permissions, &user.permissions),
                checked_attr(user.is_active),
                checked_attr(user.is_staff),
                checked_attr(user.is_superuser),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let body = format!(
        r#"
        <section class="hero compact"><h1>Users</h1><p>{} Accounts fuer Tenant {}</p></section>
        <section class="grid">
          <article class="panel wide">
            <h2>Accounts</h2>
            <table>
              <thead><tr><th>User</th><th>Name</th><th>E-Mail</th><th>Rollen</th><th>Gruppen</th><th>Direktrechte</th><th>Aktiv</th><th>Staff</th><th>Superuser</th></tr></thead>
              <tbody>{}</tbody>
            </table>
          </article>
          <article class="panel wide">
            <h2>User anlegen</h2>
            <form method="post" action="/admin/users/">
              <label>Benutzername<input name="username" type="text" autocomplete="username" required></label>
              <label>Passwort<input name="password" type="password" autocomplete="new-password" required></label>
              <label>Vorname<input name="first_name" type="text" autocomplete="given-name"></label>
              <label>Nachname<input name="last_name" type="text" autocomplete="family-name"></label>
              <label>E-Mail<input name="email" type="email" autocomplete="email"></label>
              <label>Jobtitel<input name="job_title" type="text"></label>
              <label>Rolle<select name="role">{}</select></label>
              <label>Gruppen<select name="groups" multiple size="3">{}</select></label>
              <label>Direktrechte<select name="permissions" multiple size="5">{}</select></label>
              <label class="checkbox-row"><input name="is_staff" type="checkbox" value="1"> Staff</label>
              <label class="checkbox-row"><input name="is_superuser" type="checkbox" value="1"> Superuser</label>
              <button type="submit">User anlegen</button>
            </form>
          </article>
          <article class="panel wide">
            <h2>User bearbeiten</h2>
            <div class="editor-stack">{}</div>
          </article>
        </section>
        "#,
        users.len(),
        context.tenant_id,
        if rows.is_empty() {
            web_empty_row(9, "Keine Accounts vorhanden.")
        } else {
            rows
        },
        create_role_options,
        create_group_options,
        create_permission_options,
        if edit_forms.is_empty() {
            "<p>Keine Accounts vorhanden.</p>".to_string()
        } else {
            edit_forms
        },
    );
    web_page("Users", "/admin/users/", Some(&context), &body)
}

async fn web_admin_users_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<WebAccountUserCreateForm>,
) -> Response {
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(_) => return web_missing_context("Users", "/admin/users/").into_response(),
    };
    let context = WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    };
    if admin_permission_error(&auth_context).is_some() {
        return web_error_page(
            "Users",
            "/admin/users/",
            &context,
            "Diese Rust-Webroute benoetigt eine Admin-Rolle.",
        )
        .into_response();
    }
    let Some(store) = state.account_store else {
        return web_store_missing("Users", "/admin/users/", &context, "Account").into_response();
    };
    let role = form
        .role
        .as_ref()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let roles = role.as_ref().map(|role| vec![role.clone()]);
    let payload = account_store::AccountUserWriteRequest {
        username: Some(form.username),
        password: Some(form.password),
        first_name: form.first_name,
        last_name: form.last_name,
        email: form.email,
        role,
        roles,
        groups: form.groups,
        permissions: form.permissions,
        job_title: form.job_title,
        is_staff: Some(form.is_staff.is_some()),
        is_superuser: Some(form.is_superuser.is_some()),
        is_active: Some(true),
    };
    match store
        .create_user(auth_context.tenant_id, auth_context.user_id, payload)
        .await
    {
        Ok(_) => Redirect::to("/admin/users/").into_response(),
        Err(err) => {
            web_error_page("Users", "/admin/users/", &context, &err.to_string()).into_response()
        }
    }
}

async fn web_admin_user_update(
    Path(user_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<WebAccountUserUpdateForm>,
) -> Response {
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(_) => return web_missing_context("Users", "/admin/users/").into_response(),
    };
    let context = WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    };
    if admin_permission_error(&auth_context).is_some() {
        return web_error_page(
            "Users",
            "/admin/users/",
            &context,
            "Diese Rust-Webroute benoetigt eine Admin-Rolle.",
        )
        .into_response();
    }
    let Some(store) = state.account_store else {
        return web_store_missing("Users", "/admin/users/", &context, "Account").into_response();
    };
    let role = form
        .role
        .as_ref()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let roles = role.as_ref().map(|role| vec![role.clone()]);
    let groups = if form.groups_present.is_some() {
        Some(form.groups.unwrap_or_default())
    } else {
        form.groups
    };
    let permissions = if form.permissions_present.is_some() {
        Some(form.permissions.unwrap_or_default())
    } else {
        form.permissions
    };
    let payload = account_store::AccountUserWriteRequest {
        username: Some(form.username),
        password: form.password,
        first_name: form.first_name,
        last_name: form.last_name,
        email: form.email,
        role,
        roles,
        groups,
        permissions,
        job_title: form.job_title,
        is_staff: Some(form.is_staff.is_some()),
        is_superuser: Some(form.is_superuser.is_some()),
        is_active: Some(form.is_active.is_some()),
    };
    match store
        .update_user(
            auth_context.tenant_id,
            user_id,
            auth_context.user_id,
            payload,
        )
        .await
    {
        Ok(Some(_)) => Redirect::to("/admin/users/").into_response(),
        Ok(None) => web_error_page(
            "Users",
            "/admin/users/",
            &context,
            "Account-User wurde nicht gefunden.",
        )
        .into_response(),
        Err(err) => {
            web_error_page("Users", "/admin/users/", &context, &err.to_string()).into_response()
        }
    }
}
async fn web_product_security(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
        return web_missing_context("Product Security", "/product-security/");
    };
    let Some(store) = state.product_security_store else {
        return web_store_missing(
            "Product Security",
            "/product-security/",
            &context,
            "Product Security",
        );
    };
    match store.overview(context.tenant_id, 50, 20).await {
        Ok(Some(overview)) => {
            let matrix_rows = [
                ("CRA", &overview.matrix.cra),
                ("AI Act", &overview.matrix.ai_act),
                ("IEC 62443", &overview.matrix.iec62443),
                ("ISO/SAE 21434", &overview.matrix.iso_sae_21434),
            ]
            .iter()
            .map(|(framework, item)| {
                format!(
                    r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                    html_escape(framework),
                    yes_no(item.applicable),
                    html_escape(&item.label),
                    html_escape(&item.reason),
                )
            })
            .collect::<Vec<_>>()
            .join("");
            let product_rows = overview
                .products
                .iter()
                .map(|product| {
                    let scope_flags = [
                        (product.has_digital_elements, "Digital"),
                        (product.includes_ai, "AI"),
                        (product.ot_iacs_context, "OT/IACS"),
                        (product.automotive_context, "Automotive"),
                    ]
                    .iter()
                    .filter_map(|(enabled, label)| enabled.then_some(*label))
                    .collect::<Vec<_>>()
                    .join(", ");
                    format!(
                        r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                        html_escape(&product.name),
                        html_escape(product.family_name.as_deref().unwrap_or("-")),
                        html_escape(&product.code),
                        html_escape(&product.description),
                        html_escape(if scope_flags.is_empty() {
                            "-"
                        } else {
                            scope_flags.as_str()
                        }),
                        product.release_count,
                        product.vulnerability_count,
                        product.psirt_case_count,
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let snapshot_rows = overview
                .snapshots
                .iter()
                .map(|snapshot| {
                    format!(
                        r#"<tr><td>{}</td><td>{}%</td><td>{}%</td><td>{}%</td><td>{}</td><td>{}</td></tr>"#,
                        html_escape(&snapshot.product_name),
                        snapshot.cra_readiness_percent,
                        snapshot.ai_act_readiness_percent,
                        snapshot.threat_model_coverage_percent,
                        snapshot.open_vulnerability_count,
                        html_escape(&snapshot.summary),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let body = format!(
                r#"
                <section class="hero compact"><h1>Product Security</h1><p>Tenant {} · {}</p></section>
                <section class="metrics">
                  {}
                  {}
                  {}
                  {}
                </section>
                <section class="grid">
                  <article class="panel wide">
                    <h2>Regulatorische Matrix</h2>
                    <p>{}</p>
                    <table>
                      <thead><tr><th>Framework</th><th>Applicable</th><th>Status</th><th>Begruendung</th></tr></thead>
                      <tbody>{}</tbody>
                    </table>
                  </article>
                  <article class="panel wide">
                    <h2>Produkte</h2>
                    <table>
                      <thead><tr><th>Produkt</th><th>Familie</th><th>Code</th><th>Beschreibung</th><th>Scope</th><th>Releases</th><th>Schwachstellen</th><th>PSIRT</th></tr></thead>
                      <tbody>{}</tbody>
                    </table>
                  </article>
                  <article class="panel wide">
                    <h2>Letzte Snapshots</h2>
                    <table>
                      <thead><tr><th>Produkt</th><th>CRA</th><th>AI Act</th><th>Threat Coverage</th><th>Offen</th><th>Summary</th></tr></thead>
                      <tbody>{}</tbody>
                    </table>
                  </article>
                </section>
                "#,
                overview.tenant_id,
                html_escape(&overview.matrix.summary),
                metric_card("Produkte", overview.posture.products),
                metric_card("Offene Vulns", overview.posture.open_vulnerabilities),
                metric_card(
                    "Kritisch offen",
                    overview.posture.critical_open_vulnerabilities
                ),
                metric_card("PSIRT offen", overview.posture.psirt_cases_open),
                html_escape(&overview.matrix.summary),
                if matrix_rows.is_empty() {
                    web_empty_row(4, "Keine Matrixdaten vorhanden.")
                } else {
                    matrix_rows
                },
                if product_rows.is_empty() {
                    web_empty_row(8, "Keine Produkte vorhanden.")
                } else {
                    product_rows
                },
                if snapshot_rows.is_empty() {
                    web_empty_row(6, "Keine Snapshots vorhanden.")
                } else {
                    snapshot_rows
                },
            );
            web_page(
                "Product Security",
                "/product-security/",
                Some(&context),
                &body,
            )
        }
        Ok(None) => web_error_page(
            "Product Security",
            "/product-security/",
            &context,
            "Tenant wurde fuer diesen Kontext nicht gefunden.",
        ),
        Err(err) => web_error_page(
            "Product Security",
            "/product-security/",
            &context,
            &err.to_string(),
        ),
    }
}
async fn web_cves(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let context = web_context_from_request(&query, &headers, &state).await;
    web_static_section("Vulnerability Intelligence", "/cves/", context.as_ref())
}
async fn web_navigator(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
        return web_missing_context("Guidance Navigator", "/navigator/");
    };
    let Some(tenant_store) = state.tenant_store else {
        return web_store_missing("Guidance Navigator", "/navigator/", &context, "Tenant");
    };
    let Some(assessment_store) = state.assessment_store else {
        return web_store_missing("Guidance Navigator", "/navigator/", &context, "Assessment");
    };
    let Some(process_store) = state.process_store else {
        return web_store_missing("Guidance Navigator", "/navigator/", &context, "Process");
    };
    let Some(risk_store) = state.risk_store else {
        return web_store_missing("Guidance Navigator", "/navigator/", &context, "Risk");
    };
    let Some(requirement_store) = state.requirement_store else {
        return web_store_missing("Guidance Navigator", "/navigator/", &context, "Requirement");
    };

    let tenant = match tenant_store.tenant_profile(context.tenant_id).await {
        Ok(Some(tenant)) => tenant,
        Ok(None) => {
            return web_error_page(
                "Guidance Navigator",
                "/navigator/",
                &context,
                "Tenant wurde fuer diesen Kontext nicht gefunden.",
            )
        }
        Err(err) => {
            return web_error_page(
                "Guidance Navigator",
                "/navigator/",
                &context,
                &err.to_string(),
            )
        }
    };
    let applicability = match assessment_store
        .list_applicability(context.tenant_id, 50)
        .await
    {
        Ok(items) => items,
        Err(err) => {
            return web_error_page(
                "Guidance Navigator",
                "/navigator/",
                &context,
                &err.to_string(),
            )
        }
    };
    let assessments = match assessment_store
        .list_assessments(context.tenant_id, 100)
        .await
    {
        Ok(items) => items,
        Err(err) => {
            return web_error_page(
                "Guidance Navigator",
                "/navigator/",
                &context,
                &err.to_string(),
            )
        }
    };
    let measures = match assessment_store.list_measures(context.tenant_id, 100).await {
        Ok(items) => items,
        Err(err) => {
            return web_error_page(
                "Guidance Navigator",
                "/navigator/",
                &context,
                &err.to_string(),
            )
        }
    };
    let processes = match process_store.list_processes(context.tenant_id, 100).await {
        Ok(items) => items,
        Err(err) => {
            return web_error_page(
                "Guidance Navigator",
                "/navigator/",
                &context,
                &err.to_string(),
            )
        }
    };
    let risks = match risk_store.list_risks(context.tenant_id, 100).await {
        Ok(items) => items,
        Err(err) => {
            return web_error_page(
                "Guidance Navigator",
                "/navigator/",
                &context,
                &err.to_string(),
            )
        }
    };
    let requirement_library = match requirement_store.library(10_000).await {
        Ok(library) => library,
        Err(err) => {
            return web_error_page(
                "Guidance Navigator",
                "/navigator/",
                &context,
                &err.to_string(),
            )
        }
    };

    let active_requirement_count = requirement_library
        .requirements
        .iter()
        .filter(|requirement| requirement.is_active)
        .count() as u32;
    let measure_open_count = measures
        .iter()
        .filter(|measure| !measure.status.eq_ignore_ascii_case("DONE"))
        .count() as u32;
    let payload = GuidanceEvaluateRequest {
        description_present: !tenant.description.trim().is_empty(),
        sector_present: !tenant.sector.trim().is_empty(),
        applicability_count: applicability.len() as u32,
        process_count: processes.len() as u32,
        risk_count: risks.len() as u32,
        assessment_count: assessments.len() as u32,
        measure_count: measures.len() as u32,
        measure_open_count,
        requirement_count: active_requirement_count,
    };
    let evaluation = evaluate_guidance_response(&payload);
    let completed_steps = GUIDANCE_STEPS
        .iter()
        .filter(|step| guidance_step_done(step.code, &payload))
        .count();
    let progress_percent =
        ((completed_steps as f64 / GUIDANCE_STEPS.len() as f64) * 100.0).round() as i64;
    let next_step = evaluation
        .current_step_code
        .as_deref()
        .and_then(guidance_step_definition);
    let next_action_link = next_step
        .map(|step| {
            format!(
                r#"<p><a href="{}">{}</a></p>"#,
                web_path_with_context(step.path, Some(&context)),
                html_escape(step.cta_label),
            )
        })
        .unwrap_or_else(|| {
            format!(
                r#"<p><a href="{}">Zur Evidence-Uebersicht</a></p>"#,
                web_path_with_context("/evidence/", Some(&context)),
            )
        });
    let todo_items = if evaluation.todo_items.is_empty() {
        "<li>Aktuell keine offenen Guidance-Todos.</li>".to_string()
    } else {
        evaluation
            .todo_items
            .iter()
            .map(|item| format!(r#"<li>{}</li>"#, html_escape(item)))
            .collect::<Vec<_>>()
            .join("")
    };
    let step_rows = GUIDANCE_STEPS
        .iter()
        .enumerate()
        .map(|(index, step)| {
            let done = guidance_step_done(step.code, &payload);
            let status = if done {
                "Abgeschlossen"
            } else if evaluation.current_step_code.as_deref() == Some(step.code) {
                "Aktiv"
            } else {
                "Ausstehend"
            };
            format!(
                r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><a href="{}">{}</a></td></tr>"#,
                index + 1,
                html_escape(step.title),
                html_escape(step.description),
                status,
                web_path_with_context(step.path, Some(&context)),
                html_escape(step.cta_label),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let body = format!(
        r#"
        <section class="hero compact"><h1>Guidance Navigator</h1><p>{} · {} von {} Guided Steps abgeschlossen</p></section>
        <section class="metrics">
          {}
          {}
          {}
          {}
        </section>
        <section class="grid">
          <article class="panel wide">
            <h2>Naechster Schritt</h2>
            <p>{}</p>
            <p>{}</p>
            {}
          </article>
          <article class="panel wide">
            <h2>Journey Status</h2>
            <table>
              <tbody>
                <tr><th>Tenant</th><td>{}</td></tr>
                <tr><th>Scope vorhanden</th><td>{}</td></tr>
                <tr><th>Aktive Requirements</th><td>{}</td></tr>
                <tr><th>Applicability</th><td>{}</td></tr>
                <tr><th>Prozesse</th><td>{}</td></tr>
                <tr><th>Risiken</th><td>{}</td></tr>
                <tr><th>Assessments</th><td>{}</td></tr>
                <tr><th>Measures</th><td>{}</td></tr>
                <tr><th>Offene Measures</th><td>{}</td></tr>
              </tbody>
            </table>
          </article>
          <article class="panel wide">
            <h2>Guided Steps</h2>
            <table>
              <thead><tr><th>#</th><th>Schritt</th><th>Beschreibung</th><th>Status</th><th>Aktion</th></tr></thead>
              <tbody>{}</tbody>
            </table>
          </article>
          <article class="panel wide">
            <h2>Offene To-dos</h2>
            <ul>{}</ul>
          </article>
        </section>
        "#,
        html_escape(&tenant.name),
        completed_steps,
        GUIDANCE_STEPS.len(),
        metric_card("Fortschritt %", progress_percent),
        metric_card("Todos", evaluation.todo_items.len() as i64),
        metric_card("Offene Measures", measure_open_count as i64),
        metric_card("Risiken", risks.len() as i64),
        html_escape(&evaluation.summary),
        html_escape(&evaluation.next_action_text),
        next_action_link,
        html_escape(&tenant.name),
        yes_no(payload.description_present && payload.sector_present),
        active_requirement_count,
        applicability.len(),
        processes.len(),
        risks.len(),
        assessments.len(),
        measures.len(),
        measure_open_count,
        step_rows,
        todo_items,
    );
    web_page("Guidance Navigator", "/navigator/", Some(&context), &body)
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

fn web_imports_page(
    context: &WebContext,
    result: Option<(&[String], &import_store::ImportJobResult)>,
) -> Html<String> {
    let result_panel = result
        .map(|(headers, result)| {
            format!(
                r#"
                <article class="panel wide">
                  <h2>Import uebernommen</h2>
                  <table>
                    <tbody>
                      <tr><th>Typ</th><td>{}</td></tr>
                      <tr><th>CSV-Spalten</th><td>{}</td></tr>
                      <tr><th>Zeilen</th><td>{}</td></tr>
                      <tr><th>Angelegt</th><td>{}</td></tr>
                      <tr><th>Aktualisiert</th><td>{}</td></tr>
                      <tr><th>Uebersprungen</th><td>{}</td></tr>
                    </tbody>
                  </table>
                </article>
                "#,
                html_escape(&result.import_type),
                html_escape(&headers.join(", ")),
                result.row_count,
                result.created,
                result.updated,
                result.skipped,
            )
        })
        .unwrap_or_default();
    let body = format!(
        r#"
        <section class="hero compact"><h1>Imports</h1><p>Datei- und Direktimport fuer Tenant {}</p></section>
        <section class="grid">
          {}
          <article class="panel wide">
            <h2>Datei hochladen</h2>
            <form method="post" action="/imports/preview/" enctype="multipart/form-data">
              <div class="form-grid">
                <label>Importtyp<select name="import_type">{}</select></label>
                <label class="checkbox-row"><input name="replace_existing" type="checkbox" value="1"> Bestehende Tenant-Daten ersetzen</label>
              </div>
              <label>Datei<input name="file" type="file" accept=".csv,.xlsx,.xlsm" required></label>
              <button type="submit" name="action" value="preview">Vorschau erstellen</button>
            </form>
          </article>
          <article class="panel wide">
            <h2>CSV direkt einspielen</h2>
            <form method="post" action="/imports/">
              <div class="form-grid">
                <label>Importtyp<select name="import_type">{}</select></label>
                <label class="checkbox-row"><input name="replace_existing" type="checkbox" value="1"> Bestehende Tenant-Daten ersetzen</label>
              </div>
              <label>CSV-Inhalt<textarea name="csv_data" rows="12" spellcheck="false" required placeholder="name&#10;Security Operations&#10;Governance"></textarea></label>
              <button type="submit">Import starten</button>
            </form>
          </article>
          <article class="panel wide">
            <h2>Unterstuetzte Typen</h2>
            <table>
              <thead><tr><th>Typ</th><th>Schluesselspalten</th><th>Formate</th></tr></thead>
              <tbody>
                <tr><td>business_units</td><td>name</td><td>CSV, XLSX, XLSM</td></tr>
                <tr><td>processes</td><td>name, business_unit, status, scope, description</td><td>CSV, XLSX, XLSM</td></tr>
                <tr><td>suppliers</td><td>name, service_description, criticality</td><td>CSV, XLSX, XLSM</td></tr>
                <tr><td>assets</td><td>name, business_unit, asset_type, criticality, description</td><td>CSV, XLSX, XLSM</td></tr>
              </tbody>
            </table>
          </article>
        </section>
        "#,
        context.tenant_id,
        result_panel,
        import_type_options_for("business_units"),
        import_type_options_for("business_units"),
    );
    web_page("Imports", "/imports/", Some(context), &body)
}

fn web_imports_preview_page(
    context: &WebContext,
    preview: &ImportPreview,
    upload_file: &ImportUploadFile,
    error_message: Option<&str>,
) -> Html<String> {
    let file_data_base64 = BASE64_STANDARD.encode(&upload_file.data);
    let mapping_rows = preview
        .mapping_rows
        .iter()
        .map(|row| {
            format!(
                r#"<tr><td>{}{}</td><td><select name="map_{}">{}</select></td><td>{}</td><td>{}</td></tr>"#,
                html_escape(&row.expected),
                if row.required { " *" } else { "" },
                html_escape(&row.expected),
                import_mapping_options_for(&preview.headers, &row.matched),
                if row.status.eq_ignore_ascii_case("ok") {
                    "Erkannt"
                } else {
                    "Fehlt"
                },
                if row.synonyms.is_empty() {
                    "-".to_string()
                } else {
                    html_escape(&row.synonyms.join(", "))
                },
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let preview_table_headers = preview
        .headers
        .iter()
        .map(|header| format!(r#"<th>{}</th>"#, html_escape(header)))
        .collect::<Vec<_>>()
        .join("");
    let preview_rows = preview
        .preview_rows
        .iter()
        .take(10)
        .map(|row| {
            let values = preview
                .headers
                .iter()
                .map(|header| {
                    format!(
                        r#"<td>{}</td>"#,
                        html_escape(row.get(header).map(String::as_str).unwrap_or(""))
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            format!(r#"<tr>{values}</tr>"#)
        })
        .collect::<Vec<_>>()
        .join("");
    let summary = format!(
        "{} von {} Zielspalten erkannt · {} Zeilen in Datei{}",
        preview.matched,
        preview.mapping_rows.len(),
        preview.total_row_count,
        if preview.truncated {
            format!(
                " · Vorschau zeigt erste {} Zeilen",
                preview.preview_row_count
            )
        } else {
            String::new()
        }
    );
    let error_panel = error_message
        .map(|message| {
            format!(
                r#"<article class="panel wide error"><h2>Zuordnung unvollstaendig</h2><p>{}</p></article>"#,
                html_escape(message)
            )
        })
        .unwrap_or_default();
    let body = format!(
        r#"
        <section class="hero compact"><h1>Import-Vorschau</h1><p>{}</p></section>
        <section class="grid">
          {}
          <article class="panel wide">
            <h2>Datei</h2>
            <table>
              <tbody>
                <tr><th>Datei</th><td>{}</td></tr>
                <tr><th>Format</th><td>{}</td></tr>
                <tr><th>Importtyp</th><td>{}</td></tr>
                <tr><th>Ersetzen</th><td>{}</td></tr>
              </tbody>
            </table>
          </article>
          <article class="panel wide">
            <h2>Zuordnung pruefen</h2>
            <form method="post" action="/imports/preview/" enctype="multipart/form-data">
              <input name="import_type" type="hidden" value="{}">
              <input name="replace_existing" type="hidden" value="{}">
              <input name="file_name" type="hidden" value="{}">
              <input name="file_data_base64" type="hidden" value="{}">
              <table>
                <thead><tr><th>Zielspalte</th><th>Quellspalte</th><th>Status</th><th>Hinweise</th></tr></thead>
                <tbody>{}</tbody>
              </table>
              <div class="actions">
                <button type="submit" name="action" value="update">Zuordnung aktualisieren</button>
                <button type="submit" name="action" value="confirm">Import bestaetigen</button>
              </div>
            </form>
          </article>
          <article class="panel wide">
            <h2>Tabellenvorschau</h2>
            <p>Anzeige der ersten {} Zeilen.</p>
            <table>
              <thead><tr>{}</tr></thead>
              <tbody>{}</tbody>
            </table>
          </article>
          <article class="panel wide">
            <h2>Nicht zugeordnete Spalten</h2>
            <p>{}</p>
            <p><a href="{}">Zurueck zum Upload</a></p>
          </article>
        </section>
        "#,
        html_escape(&summary),
        error_panel,
        html_escape(&preview.file_name),
        html_escape(&preview.file_kind.to_ascii_uppercase()),
        html_escape(&preview.import_type),
        if preview.replace_existing {
            "Ja"
        } else {
            "Nein"
        },
        html_escape(&preview.import_type),
        if preview.replace_existing { "1" } else { "0" },
        html_escape(&preview.file_name),
        html_escape(&file_data_base64),
        if mapping_rows.is_empty() {
            web_empty_row(4, "Keine erwarteten Spalten konfiguriert.")
        } else {
            mapping_rows
        },
        preview.preview_row_count.min(10),
        if preview_table_headers.is_empty() {
            "<th>Keine Spalten</th>".to_string()
        } else {
            preview_table_headers
        },
        if preview_rows.is_empty() {
            web_empty_row(
                preview.headers.len().max(1),
                "Keine Zeilen in der Datei gefunden.",
            )
        } else {
            preview_rows
        },
        if preview.extra_headers.is_empty() {
            "Alle erkannten Spalten sind aktuell zugeordnet.".to_string()
        } else {
            html_escape(&preview.extra_headers.join(", "))
        },
        web_path_with_context("/imports/", Some(context)),
    );
    web_page("Imports", "/imports/", Some(context), &body)
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
        ("/navigator/", "Navigator"),
        ("/risks/", "Risks"),
        ("/evidence/", "Evidence"),
        ("/roadmap/", "Roadmap"),
        ("/reports/", "Reports"),
        ("/assets/", "Assets"),
        ("/imports/", "Imports"),
        ("/processes/", "Processes"),
        ("/product-security/", "Product Security"),
        ("/admin/users/", "Users"),
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
    h3 {{ margin:0; font-size:17px; }}
    p {{ margin:0 0 8px; color:var(--muted); }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(230px, 1fr)); gap:14px; }}
    .metrics {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(160px, 1fr)); gap:12px; margin-bottom:16px; }}
    .panel {{ background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:18px; box-shadow:0 1px 2px rgba(20, 30, 40, 0.04); }}
    .panel.wide {{ grid-column:1 / -1; overflow-x:auto; }}
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
    input, select, textarea {{ width:100%; padding:10px 12px; border:1px solid var(--line); border-radius:6px; font:inherit; background:#fff; }}
    textarea {{ min-height:220px; resize:vertical; font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; }}
    input[type="checkbox"] {{ width:auto; }}
    .checkbox-row {{ display:flex; align-items:center; gap:8px; }}
    .form-grid {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(190px, 1fr)); gap:12px; }}
    .editor-stack {{ display:grid; gap:16px; }}
    .user-editor {{ padding:14px 0; border-top:1px solid var(--line); }}
    .user-editor:first-child {{ padding-top:0; border-top:0; }}
    .toggle-row {{ display:flex; flex-wrap:wrap; gap:12px; }}
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

fn web_empty_row(colspan: usize, message: &str) -> String {
    format!(
        r#"<tr><td colspan="{}">{}</td></tr>"#,
        colspan,
        html_escape(message),
    )
}

pub(crate) fn parse_import_csv(raw: &str) -> Result<ParsedImportCsv, String> {
    let records = parse_csv_records(raw)?;
    if records.is_empty() {
        return Err("CSV braucht eine Kopfzeile.".to_string());
    }

    let mut headers = Vec::new();
    for header in &records[0] {
        let header = header.trim().trim_start_matches('\u{feff}').to_string();
        if header.is_empty() {
            continue;
        }
        if headers
            .iter()
            .any(|existing: &String| existing.eq_ignore_ascii_case(&header))
        {
            return Err(format!("CSV-Spalte kommt mehrfach vor: {header}"));
        }
        headers.push(header);
    }
    if headers.is_empty() {
        return Err("CSV braucht mindestens eine benannte Spalte.".to_string());
    }

    let rows = records
        .into_iter()
        .skip(1)
        .map(|record| {
            headers
                .iter()
                .enumerate()
                .map(|(index, header)| {
                    let value = record
                        .get(index)
                        .map(|value| value.trim().to_string())
                        .unwrap_or_default();
                    (header.clone(), Value::String(value))
                })
                .collect::<HashMap<_, _>>()
        })
        .collect::<Vec<_>>();

    Ok((headers, rows))
}

fn parse_csv_records(raw: &str) -> Result<Vec<Vec<String>>, String> {
    let normalized = raw.replace("\r\n", "\n").replace('\r', "\n");
    let delimiter = detect_csv_delimiter(&normalized);
    let mut records = Vec::new();
    let mut record = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut saw_field_content = false;
    let mut chars = normalized.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                if in_quotes && chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    in_quotes = !in_quotes;
                    saw_field_content = true;
                }
            }
            value if value == delimiter && !in_quotes => {
                record.push(std::mem::take(&mut field));
                saw_field_content = true;
            }
            '\n' if !in_quotes => {
                record.push(std::mem::take(&mut field));
                if saw_field_content || record.iter().any(|value| !value.is_empty()) {
                    records.push(std::mem::take(&mut record));
                } else {
                    record.clear();
                }
                saw_field_content = false;
            }
            value => {
                field.push(value);
                saw_field_content = true;
            }
        }
    }

    if in_quotes {
        return Err("CSV enthaelt ein nicht geschlossenes Anfuehrungszeichen.".to_string());
    }
    if saw_field_content || !field.is_empty() || !record.is_empty() {
        record.push(field);
        records.push(record);
    }

    Ok(records)
}

fn detect_csv_delimiter(raw: &str) -> char {
    let mut comma_count = 0;
    let mut semicolon_count = 0;
    let mut in_quotes = false;
    let mut chars = raw.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                if in_quotes && chars.peek() == Some(&'"') {
                    chars.next();
                } else {
                    in_quotes = !in_quotes;
                }
            }
            ',' if !in_quotes => comma_count += 1,
            ';' if !in_quotes => semicolon_count += 1,
            '\n' if !in_quotes && comma_count + semicolon_count > 0 => break,
            _ => {}
        }
    }

    if semicolon_count > comma_count {
        ';'
    } else {
        ','
    }
}

fn parse_evidence_upload_form(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<EvidenceUploadFormData, String> {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| "Content-Type fuer Upload fehlt.".to_string())?;
    let boundary = multipart_boundary(content_type)
        .ok_or_else(|| "Multipart-Boundary fuer Upload fehlt.".to_string())?;
    let parts = parse_multipart_parts(body, &boundary)?;
    let mut fields = HashMap::new();
    let mut file = None;

    for part in parts {
        if part.name == "file" {
            if let Some(filename) = part
                .filename
                .map(|filename| filename.trim().to_string())
                .filter(|filename| !filename.is_empty())
            {
                file = Some(EvidenceUploadFile {
                    filename,
                    content_type: part.content_type,
                    data: part.data,
                });
            }
        } else {
            fields.insert(
                part.name,
                String::from_utf8_lossy(&part.data)
                    .trim_end_matches(['\r', '\n'])
                    .to_string(),
            );
        }
    }

    Ok(EvidenceUploadFormData { fields, file })
}

fn parse_import_upload_form(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<ImportUploadFormData, String> {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| "Content-Type fuer Import fehlt.".to_string())?;
    let boundary = multipart_boundary(content_type)
        .ok_or_else(|| "Multipart-Boundary fuer Import fehlt.".to_string())?;
    let parts = parse_multipart_parts(body, &boundary)?;
    let mut fields = HashMap::new();
    let mut file = None;

    for part in parts {
        if part.name == "file" {
            if let Some(filename) = part
                .filename
                .map(|filename| filename.trim().to_string())
                .filter(|filename| !filename.is_empty())
            {
                file = Some(ImportUploadFile {
                    filename,
                    data: part.data,
                });
            }
        } else {
            fields.insert(
                part.name,
                String::from_utf8_lossy(&part.data)
                    .trim_end_matches(['\r', '\n'])
                    .to_string(),
            );
        }
    }

    Ok(ImportUploadFormData { fields, file })
}

fn multipart_boundary(content_type: &str) -> Option<String> {
    content_type.split(';').find_map(|part| {
        let part = part.trim();
        let (name, value) = part.split_once('=')?;
        if !name.trim().eq_ignore_ascii_case("boundary") {
            return None;
        }
        let value = value.trim().trim_matches('"');
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    })
}

fn parse_multipart_parts(body: &[u8], boundary: &str) -> Result<Vec<MultipartPart>, String> {
    if boundary.len() > 200 {
        return Err("Multipart-Boundary ist zu lang.".to_string());
    }
    let marker = format!("--{boundary}").into_bytes();
    let mut parts = Vec::new();
    let mut pos = find_subslice(body, &marker)
        .ok_or_else(|| "Multipart-Boundary wurde im Upload nicht gefunden.".to_string())?;

    loop {
        pos += marker.len();
        if body.get(pos..pos + 2) == Some(b"--") {
            break;
        }
        if body.get(pos..pos + 2) == Some(b"\r\n") {
            pos += 2;
        } else if body.get(pos..pos + 1) == Some(b"\n") {
            pos += 1;
        }

        let header_end = find_subslice(&body[pos..], b"\r\n\r\n")
            .or_else(|| find_subslice(&body[pos..], b"\n\n"))
            .ok_or_else(|| "Multipart-Header ist unvollstaendig.".to_string())?;
        let header_separator_len = if body[pos + header_end..].starts_with(b"\r\n\r\n") {
            4
        } else {
            2
        };
        let header_bytes = &body[pos..pos + header_end];
        let data_start = pos + header_end + header_separator_len;
        let next = find_subslice(&body[data_start..], &marker)
            .ok_or_else(|| "Multipart-Ende wurde nicht gefunden.".to_string())?;
        let mut data = body[data_start..data_start + next].to_vec();
        trim_multipart_data_end(&mut data);
        if let Some(part) = multipart_part_from_headers(header_bytes, data)? {
            parts.push(part);
        }
        pos = data_start + next;
    }

    Ok(parts)
}

fn multipart_part_from_headers(
    header_bytes: &[u8],
    data: Vec<u8>,
) -> Result<Option<MultipartPart>, String> {
    let headers = String::from_utf8_lossy(header_bytes);
    let mut name = None;
    let mut filename = None;
    let mut content_type = None;
    for line in headers.lines() {
        let Some((header_name, header_value)) = line.split_once(':') else {
            continue;
        };
        if header_name
            .trim()
            .eq_ignore_ascii_case("content-disposition")
        {
            for param in header_value.split(';').map(str::trim) {
                let Some((key, value)) = param.split_once('=') else {
                    continue;
                };
                let value = unquote_multipart_param(value.trim());
                if key.trim().eq_ignore_ascii_case("name") {
                    name = Some(value);
                } else if key.trim().eq_ignore_ascii_case("filename") {
                    filename = Some(value);
                }
            }
        } else if header_name.trim().eq_ignore_ascii_case("content-type") {
            content_type = Some(header_value.trim().to_ascii_lowercase());
        }
    }

    let Some(name) = name else {
        return Ok(None);
    };
    Ok(Some(MultipartPart {
        name,
        filename,
        content_type,
        data,
    }))
}

fn unquote_multipart_param(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        value[1..value.len() - 1].replace("\\\"", "\"")
    } else {
        value.to_string()
    }
}

fn trim_multipart_data_end(data: &mut Vec<u8>) {
    if data.ends_with(b"\r\n") {
        data.truncate(data.len() - 2);
    } else if data.ends_with(b"\n") {
        data.truncate(data.len() - 1);
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn optional_i64_form_field(fields: &HashMap<String, String>, name: &str) -> Option<i64> {
    fields
        .get(name)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
}

fn import_upload_file_from_form(form: &ImportUploadFormData) -> Result<ImportUploadFile, String> {
    if let Some(file) = form.file.as_ref() {
        return Ok(file.clone());
    }
    let file_name = form
        .fields
        .get("file_name")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Bitte CSV- oder XLSX-Datei fuer den Import auswaehlen.".to_string())?;
    let file_data = form
        .fields
        .get("file_data_base64")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Import-Datei fehlt fuer die Vorschau oder Bestaetigung.".to_string())?;
    let data = BASE64_STANDARD.decode(file_data).map_err(|_| {
        "Import-Datei konnte aus dem Formular nicht wiederhergestellt werden.".to_string()
    })?;
    Ok(ImportUploadFile {
        filename: file_name.to_string(),
        data,
    })
}

fn required_import_type_field(fields: &HashMap<String, String>) -> Result<String, String> {
    fields
        .get("import_type")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
        .ok_or_else(|| "Importtyp fehlt.".to_string())
}

fn form_bool_field(fields: &HashMap<String, String>, name: &str) -> bool {
    fields
        .get(name)
        .map(String::as_str)
        .map(str::trim)
        .is_some_and(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "ja" | "on"
            )
        })
}

fn evidence_media_root(state: &AppState) -> PathBuf {
    state
        .evidence_media_root
        .clone()
        .or_else(|| {
            std::env::var("ISCY_MEDIA_ROOT")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(PathBuf::from)
        })
        .or_else(|| {
            std::env::var("MEDIA_ROOT")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from("media"))
}

fn save_evidence_upload(
    media_root: &FsPath,
    file: &EvidenceUploadFile,
) -> Result<SavedEvidenceFile, String> {
    validate_evidence_upload_file(file)?;
    let now = chrono::Utc::now();
    let relative_dir = format!("evidence/{:04}/{:02}", now.year(), now.month());
    let directory = media_root.join(&relative_dir);
    fs::create_dir_all(&directory).map_err(|err| {
        format!("Evidence-Upload-Verzeichnis konnte nicht erstellt werden: {err}")
    })?;
    let file_name = evidence_storage_filename(&file.filename, &relative_dir)?;
    let relative_path = format!("{relative_dir}/{file_name}");
    let absolute_path = directory.join(file_name);
    fs::write(&absolute_path, &file.data)
        .map_err(|err| format!("Evidence-Datei konnte nicht gespeichert werden: {err}"))?;
    Ok(SavedEvidenceFile {
        relative_path,
        absolute_path,
    })
}

fn validate_evidence_upload_file(file: &EvidenceUploadFile) -> Result<(), String> {
    if file.data.len() > EVIDENCE_MAX_UPLOAD_BYTES {
        return Err(format!(
            "Datei ist zu gross ({:.1} MB). Maximum: 25 MB.",
            file.data.len() as f64 / 1024.0 / 1024.0
        ));
    }
    if let Some(content_type) = file.content_type.as_deref() {
        if EVIDENCE_BLOCKED_CONTENT_TYPES
            .iter()
            .any(|blocked| content_type.eq_ignore_ascii_case(blocked))
        {
            return Err(format!(
                "Dateityp \"{}\" ist aus Sicherheitsgruenden nicht erlaubt.",
                content_type
            ));
        }
    }
    let extension = file_extension(&file.filename).ok_or_else(|| {
        "Datei braucht eine erlaubte Endung: pdf, docx, xlsx, png, jpg, jpeg, csv oder txt."
            .to_string()
    })?;
    if !EVIDENCE_ALLOWED_EXTENSIONS
        .iter()
        .any(|allowed| extension.eq_ignore_ascii_case(allowed))
    {
        return Err(format!(
            "Dateityp \".{}\" ist nicht erlaubt. Erlaubt: .pdf, .docx, .xlsx, .png, .jpg, .jpeg, .csv, .txt",
            html_escape(&extension)
        ));
    }
    Ok(())
}

fn evidence_storage_filename(original_name: &str, relative_dir: &str) -> Result<String, String> {
    let safe_name = sanitize_filename(original_name);
    let extension = file_extension(&safe_name).ok_or_else(|| {
        "Datei braucht eine erlaubte Endung: pdf, docx, xlsx, png, jpg, jpeg, csv oder txt."
            .to_string()
    })?;
    let extension_with_dot = format!(".{extension}");
    let stem = safe_name
        .strip_suffix(&extension_with_dot)
        .unwrap_or(&safe_name)
        .trim_matches('.');
    let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S%3f").to_string();
    let reserved = relative_dir.len() + 1 + timestamp.len() + 1 + extension_with_dot.len();
    let stem_budget = 100usize.saturating_sub(reserved).max(12);
    let stem = truncate_ascii(stem, stem_budget);
    let file_name = format!("{timestamp}_{stem}{extension_with_dot}");
    if relative_dir.len() + 1 + file_name.len() > 100 {
        return Err("Evidence-Dateiname ist zu lang.".to_string());
    }
    Ok(file_name)
}

fn sanitize_filename(original_name: &str) -> String {
    let basename = FsPath::new(original_name)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("evidence");
    let sanitized = basename
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('.')
        .to_string();
    if sanitized.is_empty() {
        "evidence.txt".to_string()
    } else {
        sanitized
    }
}

pub(crate) fn file_extension(filename: &str) -> Option<String> {
    FsPath::new(filename)
        .extension()
        .and_then(|value| value.to_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
}

fn truncate_ascii(value: &str, max_len: usize) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii())
        .take(max_len)
        .collect::<String>()
        .trim_matches('.')
        .to_string()
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "Ja"
    } else {
        "Nein"
    }
}

fn checked_attr(value: bool) -> &'static str {
    if value {
        " checked"
    } else {
        ""
    }
}

fn import_type_options_for(selected_type: &str) -> String {
    [
        ("business_units", "Business Units"),
        ("processes", "Processes"),
        ("suppliers", "Suppliers"),
        ("assets", "Assets"),
    ]
    .iter()
    .map(|(code, label)| {
        let selected = if *code == selected_type {
            " selected"
        } else {
            ""
        };
        format!(
            r#"<option value="{}"{}>{}</option>"#,
            html_escape(code),
            selected,
            html_escape(label),
        )
    })
    .collect::<Vec<_>>()
    .join("")
}

fn import_mapping_options_for(headers: &[String], selected_header: &str) -> String {
    std::iter::once((
        "".to_string(),
        "-- nicht zuordnen --".to_string(),
        selected_header.trim().is_empty(),
    ))
    .chain(headers.iter().map(|header| {
        (
            header.clone(),
            header.clone(),
            header.eq_ignore_ascii_case(selected_header),
        )
    }))
    .map(|(value, label, selected)| {
        format!(
            r#"<option value="{}"{}>{}</option>"#,
            html_escape(&value),
            if selected { " selected" } else { "" },
            html_escape(&label),
        )
    })
    .collect::<Vec<_>>()
    .join("")
}

fn evidence_status_options_for(selected_status: &str) -> String {
    [
        ("DRAFT", "Entwurf"),
        ("SUBMITTED", "Zur Pruefung eingereicht"),
        ("APPROVED", "Freigegeben"),
        ("REJECTED", "Abgelehnt"),
    ]
    .iter()
    .map(|(code, label)| {
        let selected = if *code == selected_status {
            " selected"
        } else {
            ""
        };
        format!(
            r#"<option value="{}"{}>{}</option>"#,
            html_escape(code),
            selected,
            html_escape(label),
        )
    })
    .collect::<Vec<_>>()
    .join("")
}

fn role_options_for(roles: &[account_store::AccountRole], selected_code: &str) -> String {
    roles
        .iter()
        .map(|role| {
            let selected = if role.code.eq_ignore_ascii_case(selected_code) {
                " selected"
            } else {
                ""
            };
            format!(
                r#"<option value="{}"{}>{}</option>"#,
                html_escape(&role.code),
                selected,
                html_escape(&role.label),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn group_options_for(groups: &[account_store::AccountGroup], selected_names: &[String]) -> String {
    groups
        .iter()
        .map(|group| {
            let selected = if selected_names.iter().any(|name| name == &group.name) {
                " selected"
            } else {
                ""
            };
            format!(
                r#"<option value="{}"{}>{}</option>"#,
                html_escape(&group.name),
                selected,
                html_escape(&group.name),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn permission_options_for(
    permissions: &[account_store::AccountPermission],
    selected_codes: &[String],
) -> String {
    permissions
        .iter()
        .map(|permission| {
            let selected = if selected_codes
                .iter()
                .any(|code| code == &permission.codename)
            {
                " selected"
            } else {
                ""
            };
            let label = format!(
                "{}.{}: {}",
                permission.app_label, permission.model, permission.codename
            );
            format!(
                r#"<option value="{}"{}>{}</option>"#,
                html_escape(&permission.codename),
                selected,
                html_escape(&label),
            )
        })
        .collect::<Vec<_>>()
        .join("")
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
    Json(evaluate_guidance_response(&payload))
}

fn guidance_step_definition(code: &str) -> Option<GuidanceStepDefinition> {
    GUIDANCE_STEPS
        .iter()
        .find(|step| step.code == code)
        .copied()
}

fn guidance_step_done(code: &str, payload: &GuidanceEvaluateRequest) -> bool {
    match code {
        "applicability_checked" => payload.applicability_count >= 1,
        "company_scope_defined" => payload.description_present && payload.sector_present,
        "requirements_available" => payload.requirement_count >= 4,
        "initial_processes_captured" => payload.process_count >= 3,
        "initial_risks_captured" => payload.risk_count >= 1,
        "initial_assessment_done" => payload.assessment_count >= 1,
        "soc_phishing_playbook_applied" => payload.measure_count >= 1,
        _ => false,
    }
}

fn evaluate_guidance_response(payload: &GuidanceEvaluateRequest) -> GuidanceEvaluateResponse {
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

    let current_step_code = GUIDANCE_STEPS
        .iter()
        .find(|step| !guidance_step_done(step.code, payload))
        .map(|step| step.code.to_string());
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

    GuidanceEvaluateResponse {
        current_step_code,
        summary,
        next_action_text,
        todo_items,
    }
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
            "/api/v1/auth/sessions",
            post(auth_session_create).get(auth_session_current),
        )
        .route("/api/v1/auth/session", get(auth_session_current))
        .route("/api/v1/auth/logout", post(auth_logout))
        .route(
            "/api/v1/accounts/users",
            get(account_users).post(account_user_create),
        )
        .route(
            "/api/v1/accounts/users/{user_id}",
            patch(account_user_update),
        )
        .route("/api/v1/accounts/roles", get(account_roles))
        .route("/api/v1/accounts/groups", get(account_groups))
        .route("/api/v1/accounts/permissions", get(account_permissions))
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
        .route("/api/v1/evidence/uploads", post(evidence_upload))
        .route(
            "/api/v1/evidence/sessions/{session_id}/needs/sync",
            post(evidence_need_sync),
        )
        .route("/api/v1/import-center/jobs", post(import_center_job))
        .route("/api/v1/import-center/csv", post(import_center_csv_job))
        .route("/api/v1/import-center/preview", post(import_center_preview))
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
        .route("/login/", get(web_login).post(web_login_submit))
        .route("/navigator/", get(web_navigator))
        .route("/dashboard/", get(web_dashboard))
        .route("/catalog/", get(web_catalog))
        .route("/reports/", get(web_reports))
        .route("/roadmap/", get(web_roadmap))
        .route("/evidence/", get(web_evidence).post(web_evidence_upload))
        .route("/assets/", get(web_assets))
        .route("/imports/", get(web_imports).post(web_imports_submit))
        .route("/imports/preview/", post(web_imports_preview_submit))
        .route("/processes/", get(web_processes))
        .route("/requirements/", get(web_requirements))
        .route("/risks/", get(web_risks))
        .route("/assessments/", get(web_assessments))
        .route("/organizations/", get(web_organizations))
        .route(
            "/admin/users/",
            get(web_admin_users).post(web_admin_users_submit),
        )
        .route("/admin/users/{user_id}", post(web_admin_user_update))
        .route("/product-security/", get(web_product_security))
        .route("/cves/", get(web_cves))
        .route("/api/v1/nvd/normalize", post(nvd_normalize))
        .route("/api/v1/nvd/import", post(nvd_import))
        .route("/api/v1/nvd/upsert", post(nvd_upsert))
        .route("/api/v1/llm/generate", post(llm_generate))
        .route("/api/v1/risk/priority", post(risk_priority))
        .route("/api/v1/guidance/evaluate", post(guidance_evaluate))
        .route("/api/v1/reports/cve-summary", post(report_cve_summary))
        .layer(DefaultBodyLimit::max(MULTIPART_FORM_BODY_LIMIT_BYTES))
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
