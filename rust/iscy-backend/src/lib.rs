use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Json, Path, State},
    extract::{Form, Query},
    http::{
        header::{AUTHORIZATION, CONTENT_DISPOSITION, CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE},
        HeaderMap, HeaderValue, StatusCode,
    },
    middleware,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, patch, post},
    Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use chrono::{Datelike, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::{Path as FsPath, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub mod account_store;
pub mod agent_store;
pub mod ai_governance_store;
pub mod assessment_store;
pub mod asset_store;
pub mod auth_store;
pub mod catalog_store;
pub mod control_store;
pub mod cve_store;
pub mod dashboard_store;
pub mod db_admin;
pub mod evidence_store;
pub mod hardening;
pub mod import_preview;
pub mod import_store;
pub mod incident_store;
pub mod process_store;
pub mod product_security_store;
pub mod report_store;
pub mod request_context;
pub mod requirement_store;
pub mod risk_store;
pub mod roadmap_store;
pub mod security_store;
pub mod supplier_store;
pub mod tenant_store;
pub mod wizard_store;

use account_store::AccountStore;
use agent_store::AgentStore;
use ai_governance_store::AiGovernanceStore;
use assessment_store::AssessmentStore;
use asset_store::AssetStore;
use auth_store::AuthStore;
use catalog_store::CatalogStore;
use control_store::ControlStore;
use cve_store::{CveStore, NvdCveRecord};
use dashboard_store::DashboardStore;
use evidence_store::EvidenceStore;
use hardening::CommunitySecurityConfig;
use import_preview::{ImportPreview, ImportUploadFile};
use import_store::ImportStore;
use incident_store::{IncidentAlertmanagerMetrics, IncidentStore};
use process_store::ProcessStore;
use product_security_store::ProductSecurityStore;
use report_store::ReportStore;
use request_context::{AuthenticatedTenantContext, RequestContext, RequiredTenantContextError};
use requirement_store::RequirementStore;
use risk_store::RiskStore;
use roadmap_store::RoadmapStore;
use security_store::SecurityStore;
use supplier_store::SupplierStore;
use tenant_store::TenantStore;
use wizard_store::WizardStore;

#[derive(Clone, Default)]
pub struct AppState {
    pub account_store: Option<AccountStore>,
    pub ai_governance_store: Option<AiGovernanceStore>,
    pub agent_store: Option<AgentStore>,
    pub asset_store: Option<AssetStore>,
    pub assessment_store: Option<AssessmentStore>,
    pub auth_store: Option<AuthStore>,
    pub catalog_store: Option<CatalogStore>,
    pub control_store: Option<ControlStore>,
    pub cve_store: Option<CveStore>,
    pub dashboard_store: Option<DashboardStore>,
    pub evidence_store: Option<EvidenceStore>,
    pub incident_store: Option<IncidentStore>,
    pub import_store: Option<ImportStore>,
    pub process_store: Option<ProcessStore>,
    pub product_security_store: Option<ProductSecurityStore>,
    pub report_store: Option<ReportStore>,
    pub requirement_store: Option<RequirementStore>,
    pub risk_store: Option<RiskStore>,
    pub roadmap_store: Option<RoadmapStore>,
    pub security_store: Option<SecurityStore>,
    pub supplier_store: Option<SupplierStore>,
    pub tenant_store: Option<TenantStore>,
    pub wizard_store: Option<WizardStore>,
    pub evidence_media_root: Option<PathBuf>,
    pub nvd_api_base_url: Option<String>,
    pub database_url: Option<String>,
    pub security_config: CommunitySecurityConfig,
    login_rate_limits: Arc<Mutex<HashMap<String, LoginRateLimitEntry>>>,
}

#[derive(Debug, Clone)]
struct LoginRateLimitEntry {
    failures: u32,
    first_failure_at: Instant,
    blocked_until: Option<Instant>,
}

impl AppState {
    pub fn new(cve_store: Option<CveStore>) -> Self {
        Self {
            account_store: None,
            ai_governance_store: None,
            agent_store: None,
            asset_store: None,
            assessment_store: None,
            auth_store: None,
            catalog_store: None,
            control_store: None,
            cve_store,
            dashboard_store: None,
            evidence_store: None,
            incident_store: None,
            import_store: None,
            process_store: None,
            product_security_store: None,
            report_store: None,
            requirement_store: None,
            risk_store: None,
            roadmap_store: None,
            security_store: None,
            supplier_store: None,
            tenant_store: None,
            wizard_store: None,
            evidence_media_root: None,
            nvd_api_base_url: None,
            database_url: None,
            security_config: CommunitySecurityConfig::default(),
            login_rate_limits: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn with_stores(cve_store: Option<CveStore>, tenant_store: Option<TenantStore>) -> Self {
        Self {
            account_store: None,
            ai_governance_store: None,
            agent_store: None,
            asset_store: None,
            assessment_store: None,
            auth_store: None,
            catalog_store: None,
            control_store: None,
            cve_store,
            dashboard_store: None,
            evidence_store: None,
            incident_store: None,
            import_store: None,
            process_store: None,
            product_security_store: None,
            report_store: None,
            requirement_store: None,
            risk_store: None,
            roadmap_store: None,
            security_store: None,
            supplier_store: None,
            tenant_store,
            wizard_store: None,
            evidence_media_root: None,
            nvd_api_base_url: None,
            database_url: None,
            security_config: CommunitySecurityConfig::default(),
            login_rate_limits: Arc::new(Mutex::new(HashMap::new())),
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

    pub fn with_ai_governance_store(
        mut self,
        ai_governance_store: Option<AiGovernanceStore>,
    ) -> Self {
        self.ai_governance_store = ai_governance_store;
        self
    }

    pub fn with_agent_store(mut self, agent_store: Option<AgentStore>) -> Self {
        self.agent_store = agent_store;
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

    pub fn with_incident_store(mut self, incident_store: Option<IncidentStore>) -> Self {
        self.incident_store = incident_store;
        self
    }

    pub fn with_evidence_media_root(mut self, evidence_media_root: Option<PathBuf>) -> Self {
        self.evidence_media_root = evidence_media_root;
        self
    }

    pub fn with_nvd_api_base_url(mut self, nvd_api_base_url: Option<String>) -> Self {
        self.nvd_api_base_url = nvd_api_base_url;
        self
    }

    pub fn with_database_url(mut self, database_url: Option<String>) -> Self {
        self.database_url = database_url;
        self
    }

    pub fn with_security_config(mut self, security_config: CommunitySecurityConfig) -> Self {
        self.security_config = security_config;
        self
    }

    pub fn with_security_store(mut self, security_store: Option<SecurityStore>) -> Self {
        self.security_store = security_store;
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

    pub fn with_control_store(mut self, control_store: Option<ControlStore>) -> Self {
        self.control_store = control_store;
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

    pub fn with_supplier_store(mut self, supplier_store: Option<SupplierStore>) -> Self {
        self.supplier_store = supplier_store;
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

#[derive(Debug, Serialize)]
pub struct AgentEnrollResponse {
    pub accepted: bool,
    pub api_version: &'static str,
    pub auth_model: &'static str,
    pub agent_secret: Option<String>,
    pub device: agent_store::AgentDeviceSummary,
}

#[derive(Debug, Serialize)]
pub struct AgentEnrollmentTokenCreateResponse {
    pub accepted: bool,
    pub api_version: &'static str,
    pub token: String,
    pub enrollment: agent_store::AgentEnrollmentTokenSummary,
}

#[derive(Debug, Serialize)]
pub struct AgentHeartbeatResponse {
    pub accepted: bool,
    pub api_version: &'static str,
    pub heartbeat: agent_store::AgentHeartbeatSummary,
}

#[derive(Debug, Serialize)]
pub struct AgentFindingsResponse {
    pub accepted: bool,
    pub api_version: &'static str,
    pub created: usize,
    pub device: agent_store::AgentDeviceSummary,
    pub findings: Vec<agent_store::AgentFindingSummary>,
}

#[derive(Debug, Serialize)]
pub struct AgentDevicesResponse {
    pub api_version: &'static str,
    pub tenant_id: i64,
    pub devices: Vec<agent_store::AgentDeviceSummary>,
}

#[derive(Debug, Serialize)]
pub struct AgentFindingsListResponse {
    pub api_version: &'static str,
    pub tenant_id: i64,
    pub device_id: i64,
    pub findings: Vec<agent_store::AgentFindingSummary>,
}

#[derive(Debug, Serialize)]
pub struct AgentPostureResponse {
    pub api_version: &'static str,
    pub posture: agent_store::AgentPostureOverview,
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

#[derive(Debug, Deserialize)]
struct WebControlStatusForm {
    status: Option<String>,
    maturity_score: Option<i64>,
    evidence_status: Option<String>,
    notes: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebTenantRegulatoryProfileForm {
    country: Option<String>,
    operation_countries: Option<String>,
    description: Option<String>,
    sector: Option<String>,
    employee_count: Option<String>,
    annual_revenue_million: Option<String>,
    balance_sheet_million: Option<String>,
    critical_services: Option<String>,
    supply_chain_role: Option<String>,
    nis2_relevant: Option<String>,
    kritis_relevant: Option<String>,
    develops_digital_products: Option<String>,
    uses_ai_systems: Option<String>,
    ot_iacs_scope: Option<String>,
    automotive_scope: Option<String>,
    psirt_defined: Option<String>,
    sbom_required: Option<String>,
    product_security_scope: Option<String>,
    dora_relevant: Option<String>,
    dora_financial_entity: Option<String>,
    dora_ict_third_party_provider: Option<String>,
    processes_personal_data: Option<String>,
    gdpr_controller: Option<String>,
    gdpr_processor: Option<String>,
    gdpr_special_categories: Option<String>,
    cra_relevant: Option<String>,
    ai_act_profile: Option<String>,
    ai_act_high_risk: Option<String>,
    tisax_relevant: Option<String>,
    iso27001_target: Option<String>,
    regulatory_profile_notes: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebManagementReviewGenerateForm {
    title: Option<String>,
    period_start: Option<String>,
    period_end: Option<String>,
    executive_summary: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebManagementReviewStatusForm {
    status: String,
    decision_notes: Option<String>,
    next_actions: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebCveCorrelationDecisionForm {
    status: String,
    rationale: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebProductSecurityCveReviewBulkForm {
    action: String,
    #[serde(default, deserialize_with = "deserialize_form_i64_list")]
    correlation_id: Vec<i64>,
    review_filter: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebRiskReviewForm {
    action: String,
    review_notes: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebCveLlmTestForm {
    prompt: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebCveAssessmentForm {
    cve_id: String,
    product_id: Option<String>,
    release_id: Option<String>,
    component_id: Option<String>,
    exposure: Option<String>,
    asset_criticality: Option<String>,
    epss_score: Option<String>,
    in_kev_catalog: Option<String>,
    exploit_maturity: Option<String>,
    affects_critical_service: Option<String>,
    nis2_relevant: Option<String>,
    nis2_impact_summary: Option<String>,
    repository_name: Option<String>,
    repository_url: Option<String>,
    git_ref: Option<String>,
    source_package: Option<String>,
    source_package_version: Option<String>,
    regulatory_tags: Option<String>,
    business_context: Option<String>,
    existing_controls: Option<String>,
    auto_create_risk: Option<String>,
    run_llm: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebIncidentForm {
    title: String,
    summary: Option<String>,
    incident_type: Option<String>,
    runbook_template: Option<String>,
    severity: Option<String>,
    status: Option<String>,
    owner_id: Option<String>,
    reporter_id: Option<String>,
    related_risk_id: Option<String>,
    related_asset_id: Option<String>,
    related_process_id: Option<String>,
    detected_at: Option<String>,
    confirmed_at: Option<String>,
    contained_at: Option<String>,
    resolved_at: Option<String>,
    nis2_reportable: Option<String>,
    nis2_significance_status: Option<String>,
    nis2_significance_criteria: Option<String>,
    nis2_significance_justification: Option<String>,
    nis2_significance_reference: Option<String>,
    nis2_significance_assessed_at: Option<String>,
    early_warning_sent_at: Option<String>,
    notification_sent_at: Option<String>,
    final_report_sent_at: Option<String>,
    authority_reference: Option<String>,
    stakeholder_summary: Option<String>,
    lessons_learned: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebIncidentTimelineNoteForm {
    summary: Option<String>,
    detail: String,
}

#[derive(Debug, Deserialize)]
struct WebIncidentRunbookTemplateForm {
    action: Option<String>,
    slug: Option<String>,
    title: Option<String>,
    description: Option<String>,
    incident_type: Option<String>,
    severity: Option<String>,
    body: Option<String>,
    sort_order: Option<String>,
    is_active: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebIncidentRunbookStepForm {
    action: Option<String>,
    is_done: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebIncidentReviewForm {
    action: String,
    notes: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebIncidentTimelineEventMarkerForm {
    is_export_highlight: Option<String>,
    export_note: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebProductSecurityThresholdForm {
    scope: Option<String>,
    sbom_coverage_min: Option<String>,
    csaf_coverage_min: Option<String>,
    threat_tara_coverage_min: Option<String>,
    review_backlog_max: Option<String>,
    critical_open_vulnerabilities_max: Option<String>,
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

fn deserialize_form_i64_list<'de, D>(deserializer: D) -> Result<Vec<i64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }

    Option::<OneOrMany>::deserialize(deserializer)?
        .map(|value| match value {
            OneOrMany::One(value) => vec![value],
            OneOrMany::Many(values) => values,
        })
        .unwrap_or_default()
        .into_iter()
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            value.trim().parse::<i64>().map_err(|_| {
                serde::de::Error::custom(format!("ungueltige ID in Formularliste: {value}"))
            })
        })
        .collect()
}

#[derive(Debug, Serialize)]
pub struct TenantProfileResponse {
    pub api_version: &'static str,
    pub tenant: tenant_store::TenantProfile,
}

#[derive(Debug, Serialize)]
pub struct TenantProfileUpdateResponse {
    pub accepted: bool,
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
pub struct SupplierRiskOverviewResponse {
    pub api_version: &'static str,
    #[serde(flatten)]
    pub overview: supplier_store::SupplierRiskOverview,
}

#[derive(Debug, Serialize)]
pub struct SupplierRiskDetailResponse {
    pub api_version: &'static str,
    pub supplier: supplier_store::SupplierRiskSummaryRow,
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
pub struct AiGovernanceOverviewResponse {
    pub api_version: &'static str,
    #[serde(flatten)]
    pub overview: ai_governance_store::AiGovernanceOverview,
}

#[derive(Debug, Serialize)]
pub struct AiGovernanceDetailResponse {
    pub api_version: &'static str,
    #[serde(flatten)]
    pub detail: ai_governance_store::AiGovernanceSystemDetail,
}

#[derive(Debug, Serialize)]
pub struct AiGovernanceSystemWriteResponse {
    pub accepted: bool,
    pub api_version: &'static str,
    #[serde(flatten)]
    pub result: ai_governance_store::AiGovernanceSystemWriteResult,
}

#[derive(Debug, Serialize)]
pub struct ProductSecurityOverviewResponse {
    pub api_version: &'static str,
    #[serde(flatten)]
    pub overview: product_security_store::ProductSecurityOverview,
}

#[derive(Debug, Serialize)]
pub struct ProductSecurityTrendsResponse {
    pub api_version: &'static str,
    pub tenant_id: i64,
    pub trends: product_security_store::ProductSecurityTrendDashboard,
}

#[derive(Debug, Serialize)]
pub struct ProductSecurityDetailResponse {
    pub api_version: &'static str,
    #[serde(flatten)]
    pub detail: product_security_store::ProductSecurityDetail,
}

#[derive(Debug, Serialize)]
pub struct ProductSecurityCraReadinessResponse {
    pub api_version: &'static str,
    #[serde(flatten)]
    pub readiness: product_security_store::ProductSecurityCraReadiness,
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
pub struct ProductSecurityArtifactImportResponse {
    pub accepted: bool,
    pub api_version: &'static str,
    #[serde(flatten)]
    pub result: product_security_store::ProductSecurityArtifactImportResult,
}

#[derive(Debug, Serialize)]
pub struct ProductSecurityImportHistoryExportResponse {
    pub api_version: &'static str,
    pub tenant_id: i64,
    pub artifacts: Vec<product_security_store::ProductSecurityImportArtifactSummary>,
}

#[derive(Debug, Serialize)]
pub struct ProductSecurityImportDetailResponse {
    pub api_version: &'static str,
    #[serde(flatten)]
    pub detail: product_security_store::ProductSecurityImportArtifactDetail,
}

#[derive(Debug, Serialize)]
pub struct ProductSecuritySbomDiffResponse {
    pub api_version: &'static str,
    #[serde(flatten)]
    pub diff: product_security_store::ProductSecuritySbomDiff,
}

#[derive(Debug, Deserialize)]
pub struct ProductSecuritySbomDiffQuery {
    pub base_artifact_id: i64,
    pub target_artifact_id: i64,
}

#[derive(Debug, Deserialize)]
pub struct AlertmanagerWebhookPayload {
    pub receiver: Option<String>,
    pub status: Option<String>,
    #[serde(default)]
    pub alerts: Vec<AlertmanagerWebhookAlert>,
    #[serde(rename = "groupLabels", default)]
    pub group_labels: HashMap<String, String>,
    #[serde(rename = "commonLabels", default)]
    pub common_labels: HashMap<String, String>,
    #[serde(rename = "commonAnnotations", default)]
    pub common_annotations: HashMap<String, String>,
    #[serde(rename = "externalURL")]
    pub external_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AlertmanagerWebhookAlert {
    pub status: Option<String>,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub annotations: HashMap<String, String>,
    pub fingerprint: Option<String>,
    #[serde(rename = "startsAt")]
    pub starts_at: Option<String>,
    #[serde(rename = "endsAt")]
    pub ends_at: Option<String>,
    #[serde(rename = "generatorURL")]
    pub generator_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AlertmanagerWebhookResponse {
    pub accepted: bool,
    pub api_version: &'static str,
    pub receiver: String,
    pub status: String,
    pub alert_count: i64,
    pub firing_count: i64,
    pub resolved_count: i64,
    pub severity_counts: BTreeMap<String, i64>,
    pub tenant_hint: Option<String>,
    pub external_url: Option<String>,
    pub persistence: AlertmanagerPersistenceSummary,
    pub alerts: Vec<AlertmanagerAlertSummary>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct AlertmanagerPersistenceSummary {
    pub enabled: bool,
    pub created_incidents: i64,
    pub created_evidence: i64,
    pub deduplicated_incidents: i64,
    pub resolved_incidents: i64,
    pub ignored_resolved_alerts: i64,
    pub skipped_reason: Option<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct AlertmanagerAlertSummary {
    pub alertname: String,
    pub fingerprint: Option<String>,
    pub status: String,
    pub severity: String,
    pub service: String,
    pub summary: String,
    pub description: String,
    pub starts_at: Option<String>,
    pub ends_at: Option<String>,
    pub source_url: Option<String>,
    pub action_hint: String,
}

#[derive(Debug, Serialize)]
pub struct ProductSecurityCveCorrelationResponse {
    pub accepted: bool,
    pub api_version: &'static str,
    #[serde(flatten)]
    pub result: product_security_store::ProductSecurityCveCorrelationResult,
}

#[derive(Debug, Serialize)]
pub struct ProductSecurityCveCorrelationDecisionResponse {
    pub accepted: bool,
    pub api_version: &'static str,
    #[serde(flatten)]
    pub result: product_security_store::ProductSecurityCveCorrelationDecisionResult,
}

#[derive(Debug, Serialize)]
pub struct ProductSecurityAcceptedCorrelationWorkResponse {
    pub accepted: bool,
    pub api_version: &'static str,
    #[serde(flatten)]
    pub result: product_security_store::ProductSecurityAcceptedCorrelationWorkResult,
}

#[derive(Debug, Serialize)]
pub struct CveFeedResponse {
    pub api_version: &'static str,
    pub tenant_id: i64,
    pub summary: cve_store::CveDashboardSummary,
    pub cves: Vec<cve_store::CveRecordSummary>,
}

#[derive(Debug, Serialize)]
pub struct CveDetailResponse {
    pub api_version: &'static str,
    pub cve: cve_store::CveRecordDetail,
}

#[derive(Debug, Serialize)]
pub struct CveAssessmentRegisterResponse {
    pub api_version: &'static str,
    pub tenant_id: i64,
    pub summary: cve_store::CveAssessmentDashboardSummary,
    pub assessments: Vec<cve_store::CveAssessmentSummary>,
}

#[derive(Debug, Serialize)]
pub struct CveAssessmentDetailResponse {
    pub api_version: &'static str,
    pub assessment: cve_store::CveAssessmentDetail,
}

#[derive(Debug, Serialize)]
pub struct CveAssessmentWriteResponse {
    pub accepted: bool,
    pub api_version: &'static str,
    pub created: bool,
    pub assessment: cve_store::CveAssessmentDetail,
}

#[derive(Debug, Clone, Serialize)]
struct LlmRuntimeInfo {
    backend: &'static str,
    model_name: String,
    model_path: Option<String>,
    import_ok: bool,
    runtime_ok: bool,
    n_ctx: u32,
    n_threads: u32,
    n_gpu_layers: i32,
    note: String,
    error: Option<String>,
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

#[derive(Debug, Serialize)]
pub struct RiskReviewResponse {
    pub accepted: bool,
    pub api_version: &'static str,
    #[serde(flatten)]
    pub result: risk_store::RiskReviewResult,
}

#[derive(Debug, Serialize)]
pub struct IncidentRegisterResponse {
    pub api_version: &'static str,
    pub tenant_id: i64,
    pub incidents: Vec<incident_store::IncidentSummary>,
}

#[derive(Debug, Serialize)]
pub struct IncidentRunbookTemplateListResponse {
    pub api_version: &'static str,
    pub tenant_id: i64,
    pub templates: Vec<incident_store::IncidentRunbookTemplateSummary>,
}

#[derive(Debug, Deserialize)]
pub struct IncidentTimelineNoteRequest {
    pub summary: Option<String>,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct IncidentDetailResponse {
    pub api_version: &'static str,
    pub incident: incident_store::IncidentSummary,
    pub events: Vec<incident_store::IncidentEventSummary>,
}

#[derive(Debug, Serialize)]
pub struct IncidentEventWriteResponse {
    pub api_version: &'static str,
    pub event: incident_store::IncidentEventSummary,
}

#[derive(Debug, Serialize)]
pub struct IncidentWriteResponse {
    pub api_version: &'static str,
    #[serde(flatten)]
    pub result: incident_store::IncidentWriteResult,
}

#[derive(Debug, Deserialize)]
pub struct EvidenceOverviewQuery {
    pub session_id: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct EvidenceQualityResponse {
    pub api_version: &'static str,
    pub tenant_id: i64,
    pub session_id: Option<i64>,
    pub quality: evidence_store::EvidenceQualityOverview,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct WebContextQuery {
    pub tenant_id: Option<i64>,
    pub user_id: Option<i64>,
    pub user_email: Option<String>,
    pub session_id: Option<i64>,
    pub timeline: Option<String>,
    pub evidence_title: Option<String>,
    pub evidence_description: Option<String>,
    pub linked_requirement: Option<String>,
    pub evidence_status: Option<String>,
    pub return_to: Option<String>,
    pub review_filter: Option<String>,
    pub alert_filter: Option<String>,
    pub incident_filter: Option<String>,
    pub control_id: Option<i64>,
    pub incident_id: Option<i64>,
    pub requirement_id: Option<i64>,
    pub evidence_id: Option<i64>,
    pub need_id: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebAiGovernanceCreateForm {
    pub product_id: Option<i64>,
    pub name: String,
    pub purpose: String,
    pub model_provider: String,
    pub model_name: String,
    pub model_version: String,
    pub deployment_context: String,
    pub data_categories: String,
    pub decision_impact: String,
    pub human_oversight: String,
    pub ai_act_classification: String,
    pub criticality: String,
    pub monitoring_plan: String,
    pub evidence_key: String,
    pub risk_summary: String,
    pub next_review_due_at: String,
    pub notes: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebAiGovernanceUpdateForm {
    pub ai_act_classification: String,
    pub criticality: String,
    pub status: String,
    pub human_oversight: String,
    pub monitoring_plan: String,
    pub evidence_key: String,
    pub risk_summary: String,
    pub next_review_due_at: String,
    pub notes: String,
}

#[derive(Debug, Clone, Deserialize)]
struct WebProductSecuritySbomDiffQuery {
    tenant_id: Option<i64>,
    user_id: Option<i64>,
    user_email: Option<String>,
    base_artifact_id: i64,
    target_artifact_id: i64,
}

#[derive(Debug, Clone)]
struct WebContext {
    tenant_id: i64,
    user_id: i64,
    user_email: Option<String>,
}

#[derive(Debug, Clone)]
struct ProductSecurityScopeConfig {
    scope: String,
    thresholds: ProductSecurityThresholds,
}

#[derive(Debug, Clone, Copy)]
struct ProductSecurityThresholds {
    sbom_coverage_min: i64,
    csaf_coverage_min: i64,
    threat_tara_coverage_min: i64,
    review_backlog_max: i64,
    critical_open_vulnerabilities_max: i64,
}

#[derive(Debug, Clone)]
struct StatusOperationsOverview {
    issue_count: i64,
    severity: StatusOperationsSeverity,
    exit_code: i64,
    rows: String,
    signals: Vec<StatusSignal>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum StatusOperationsSeverity {
    Ok,
    Warn,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum StatusSignalLevel {
    Ok,
    Warn,
    Danger,
}

#[derive(Debug, Clone, Serialize)]
struct StatusSignal {
    area: String,
    signal: String,
    level: StatusSignalLevel,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    href: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct StatusStoreStatus {
    name: &'static str,
    configured: bool,
    scope: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct StatusOperationsJsonResponse {
    accepted: bool,
    api_version: &'static str,
    service: &'static str,
    tenant_id: Option<i64>,
    user_id: Option<i64>,
    issue_count: i64,
    severity: StatusOperationsSeverity,
    exit_code: i64,
    runtime: StatusRuntimeJson,
    security: StatusSecurityJson,
    migration: StatusMigrationJson,
    build: StatusBuildJson,
    modules: Vec<StatusStoreStatus>,
    signals: Vec<StatusSignal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alertmanager_incidents: Option<IncidentAlertmanagerMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alertmanager_incident_details: Option<Vec<StatusAlertmanagerIncidentDetail>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    product_security_trends: Option<product_security_store::ProductSecurityTrendDashboard>,
}

#[derive(Debug, Clone, Serialize)]
struct StatusAlertmanagerIncidentDetail {
    id: i64,
    title: String,
    severity: String,
    status: String,
    state: String,
    review_required: bool,
    href: String,
}

#[derive(Debug, Clone, Serialize)]
struct StatusRuntimeJson {
    rust_only: bool,
    strict_mode: bool,
    evidence_media_root: Option<String>,
    nvd_api_base_url: String,
}

#[derive(Debug, Clone, Serialize)]
struct StatusSecurityJson {
    app_mode: String,
    trust_identity_headers: bool,
    trusted_proxy_configured: bool,
    secure_cookies: bool,
    https_confirmed: bool,
    hsts_enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
struct StatusMigrationJson {
    level: StatusSignalLevel,
    readable: bool,
    database_kind: Option<String>,
    applied_count: i64,
    expected_count: usize,
    latest_applied_version: Option<String>,
    latest_applied_at: Option<String>,
    expected_latest_version: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct StatusBuildJson {
    version: &'static str,
    commit: String,
    profile: &'static str,
    target: &'static str,
}

impl Default for ProductSecurityThresholds {
    fn default() -> Self {
        Self {
            sbom_coverage_min: 80,
            csaf_coverage_min: 80,
            threat_tara_coverage_min: 80,
            review_backlog_max: 0,
            critical_open_vulnerabilities_max: 0,
        }
    }
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
    sha256: String,
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
pub struct ManagementReviewPackagesResponse {
    pub api_version: &'static str,
    pub tenant_id: i64,
    pub packages: Vec<report_store::ManagementReviewPackageSummary>,
}

#[derive(Debug, Serialize)]
pub struct ManagementReviewPackageResponse {
    pub api_version: &'static str,
    pub package: report_store::ManagementReviewPackageDetail,
}

#[derive(Debug, Serialize)]
pub struct ManagementReviewPackageWriteResponse {
    pub accepted: bool,
    pub api_version: &'static str,
    pub package: report_store::ManagementReviewPackageDetail,
}

#[derive(Debug, Serialize)]
pub struct RequirementLibraryResponse {
    pub api_version: &'static str,
    #[serde(flatten)]
    pub library: requirement_store::RequirementLibrary,
}

#[derive(Debug, Serialize)]
pub struct ControlLibraryResponse {
    pub api_version: &'static str,
    #[serde(flatten)]
    pub library: control_store::ControlLibrary,
}

#[derive(Debug, Serialize)]
pub struct ControlStatusUpdateResponse {
    pub accepted: bool,
    pub api_version: &'static str,
    #[serde(flatten)]
    pub result: control_store::ControlStatusUpdateResult,
}

#[derive(Debug, Serialize)]
pub struct ControlRoadmapGenerationResponse {
    pub accepted: bool,
    pub api_version: &'static str,
    #[serde(flatten)]
    pub result: control_store::ControlRoadmapGenerationResult,
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

const DEFAULT_NVD_API_BASE_URL: &str = "https://services.nvd.nist.gov";
const NVD_API_REQUEST_TIMEOUT_SECS: u64 = 30;
const NVD_API_MAX_RETRIES: usize = 2;
const NVD_API_RETRY_DELAY_MILLIS: u64 = 500;

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

fn api_error_response(
    status: StatusCode,
    error_code: &'static str,
    message: impl Into<String>,
) -> Response {
    (
        status,
        Json(ApiErrorResponse {
            accepted: false,
            api_version: "v1",
            error_code,
            message: message.into(),
        }),
    )
        .into_response()
}

struct ApiError {
    status: StatusCode,
    error_code: &'static str,
    message: String,
}

impl ApiError {
    fn into_response(self) -> Response {
        api_error_response(self.status, self.error_code, self.message)
    }
}

fn validated_cve_id(raw_cve_id: &str) -> Result<String, ApiError> {
    let normalized = normalize_cve_id(raw_cve_id);
    if normalized.is_empty() {
        return Err(ApiError {
            status: StatusCode::BAD_REQUEST,
            error_code: "empty_cve_id",
            message: "CVE-ID darf nicht leer sein.".to_string(),
        });
    }
    if !is_valid_cve_id(&normalized) {
        return Err(ApiError {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            error_code: "invalid_cve_id",
            message: format!(
                "CVE-ID '{}' entspricht nicht dem erwarteten Format CVE-YYYY-NNNN.",
                normalized
            ),
        });
    }
    Ok(normalized)
}

fn nvd_import_base_url(state: &AppState) -> String {
    state
        .nvd_api_base_url
        .clone()
        .or_else(|| std::env::var("NVD_API_BASE_URL").ok())
        .map(|value| value.trim().trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_NVD_API_BASE_URL.to_string())
}

fn nvd_api_key() -> Option<String> {
    std::env::var("NVD_API_KEY")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn nvd_retryable_status(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 429 | 500 | 502 | 503 | 504)
}

async fn fetch_nvd_payload(state: &AppState, cve_id: &str) -> Result<Value, Response> {
    let base_url = nvd_import_base_url(state);
    if let Some(path) = base_url.strip_prefix("file://") {
        let payload = fs::read_to_string(path).map_err(|err| {
            api_error_response(
                StatusCode::BAD_GATEWAY,
                "nvd_upstream_error",
                format!("NVD-Fixture konnte fuer {cve_id} nicht gelesen werden: {err}"),
            )
        })?;
        return serde_json::from_str::<Value>(&payload).map_err(|err| {
            api_error_response(
                StatusCode::BAD_GATEWAY,
                "nvd_invalid_payload",
                format!("NVD-Fixture konnte nicht als JSON gelesen werden: {err}"),
            )
        });
    }
    let api_key = nvd_api_key();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(NVD_API_REQUEST_TIMEOUT_SECS))
        .build()
        .map_err(|err| {
            api_error_response(
                StatusCode::BAD_GATEWAY,
                "nvd_upstream_error",
                format!("Rust-NVD-Client konnte nicht aufgebaut werden: {err}"),
            )
        })?;
    let url = format!("{base_url}/rest/json/cves/2.0");

    for attempt in 0..=NVD_API_MAX_RETRIES {
        let mut request = client
            .get(&url)
            .query(&[("cveId", cve_id)])
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(api_key) = api_key.as_deref() {
            request = request.header("apiKey", api_key);
        }

        match request.send().await {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    return response.json::<Value>().await.map_err(|err| {
                        api_error_response(
                            StatusCode::BAD_GATEWAY,
                            "nvd_invalid_payload",
                            format!("NVD-Antwort konnte nicht als JSON gelesen werden: {err}"),
                        )
                    });
                }

                let detail = response
                    .text()
                    .await
                    .ok()
                    .map(|body| body.trim().to_string())
                    .filter(|body| !body.is_empty())
                    .unwrap_or_else(|| format!("HTTP {}", status.as_u16()));
                if nvd_retryable_status(status) && attempt < NVD_API_MAX_RETRIES {
                    tokio::time::sleep(Duration::from_millis(
                        NVD_API_RETRY_DELAY_MILLIS * (attempt as u64 + 1),
                    ))
                    .await;
                    continue;
                }
                return Err(api_error_response(
                    StatusCode::BAD_GATEWAY,
                    "nvd_upstream_error",
                    format!("NVD lieferte fuer {cve_id} einen Fehler: {detail}"),
                ));
            }
            Err(err) => {
                let retryable = err.is_timeout() || err.is_connect() || err.is_request();
                if retryable && attempt < NVD_API_MAX_RETRIES {
                    tokio::time::sleep(Duration::from_millis(
                        NVD_API_RETRY_DELAY_MILLIS * (attempt as u64 + 1),
                    ))
                    .await;
                    continue;
                }
                return Err(api_error_response(
                    StatusCode::BAD_GATEWAY,
                    "nvd_upstream_error",
                    format!("NVD konnte fuer {cve_id} nicht erreicht werden: {err}"),
                ));
            }
        }
    }

    Err(api_error_response(
        StatusCode::BAD_GATEWAY,
        "nvd_upstream_error",
        format!("NVD konnte fuer {cve_id} nicht erreicht werden."),
    ))
}

fn first_nvd_cve(payload: &Value) -> Option<Value> {
    payload
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .and_then(|vulnerabilities| vulnerabilities.first())
        .and_then(|entry| entry.get("cve"))
        .cloned()
}

fn nvd_normalize_response(payload: NvdImportRequest) -> Response {
    let normalized = match validated_cve_id(&payload.cve_id) {
        Ok(normalized) => normalized,
        Err(err) => return err.into_response(),
    };
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

async fn operations_alertmanager_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !alertmanager_token_matches(&headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "invalid_alertmanager_token",
                message: "Alertmanager-Webhook-Token ist ungueltig oder fehlt.".to_string(),
            }),
        )
            .into_response();
    }
    if let Err(response) = alertmanager_hmac_valid(&state, &headers, &body).await {
        return response;
    }
    let payload = match serde_json::from_slice::<AlertmanagerWebhookPayload>(&body) {
        Ok(payload) => payload,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: "invalid_alertmanager_payload",
                    message: "Alertmanager-Webhook-Payload ist kein gueltiges JSON.".to_string(),
                }),
            )
                .into_response();
        }
    };
    let alert_count = payload.alerts.len() as i64;
    let firing_count = payload
        .alerts
        .iter()
        .filter(|alert| alert.status.as_deref().unwrap_or("firing") == "firing")
        .count() as i64;
    let resolved_count = payload
        .alerts
        .iter()
        .filter(|alert| alert.status.as_deref().unwrap_or_default() == "resolved")
        .count() as i64;
    let mut severity_counts = BTreeMap::new();
    let alerts = payload
        .alerts
        .iter()
        .map(|alert| {
            let severity = alert_label(alert, &payload, "severity", "unknown");
            *severity_counts.entry(severity.clone()).or_insert(0) += 1;
            AlertmanagerAlertSummary {
                alertname: alert_label(alert, &payload, "alertname", "unknown"),
                fingerprint: alert
                    .fingerprint
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string),
                status: alert.status.clone().unwrap_or_else(|| "firing".to_string()),
                severity: severity.clone(),
                service: alert_label(alert, &payload, "service", "iscy"),
                summary: alert_annotation(alert, &payload, "summary", "Alert ohne Summary"),
                description: alert_annotation(alert, &payload, "description", ""),
                starts_at: alert.starts_at.clone(),
                ends_at: alert.ends_at.clone(),
                source_url: alert.generator_url.clone(),
                action_hint: alertmanager_action_hint(
                    alert.status.as_deref().unwrap_or("firing"),
                    &severity,
                )
                .to_string(),
            }
        })
        .collect::<Vec<_>>();
    let persistence = persist_alertmanager_alerts(&state, &headers, &alerts).await;
    let tenant_hint = payload
        .common_labels
        .get("tenant_id")
        .or_else(|| payload.common_labels.get("tenant"))
        .or_else(|| payload.group_labels.get("tenant_id"))
        .or_else(|| payload.group_labels.get("tenant"))
        .cloned();
    (
        StatusCode::ACCEPTED,
        Json(AlertmanagerWebhookResponse {
            accepted: true,
            api_version: "v1",
            receiver: payload
                .receiver
                .clone()
                .unwrap_or_else(|| "iscy-alertmanager".to_string()),
            status: payload.status.clone().unwrap_or_else(|| {
                if firing_count > 0 {
                    "firing".to_string()
                } else {
                    "resolved".to_string()
                }
            }),
            alert_count,
            firing_count,
            resolved_count,
            severity_counts,
            tenant_hint,
            external_url: payload.external_url.clone(),
            persistence,
            alerts,
        }),
    )
        .into_response()
}

fn alertmanager_token_matches(headers: &HeaderMap) -> bool {
    let Ok(Some(expected)) = hardening::secret_value("ISCY_ALERTMANAGER_TOKEN") else {
        return true;
    };
    let expected = expected.trim();
    if expected.is_empty() {
        return true;
    }
    let header_token = headers
        .get("x-iscy-alert-token")
        .and_then(|value| value.to_str().ok())
        .map(str::trim);
    if header_token == Some(expected) {
        return true;
    }
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().strip_prefix("Bearer "))
        .is_some_and(|value| value.trim() == expected)
}

type AlertmanagerHmacSha256 = Hmac<Sha256>;

async fn alertmanager_hmac_valid(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), Response> {
    let Ok(current_secret) = hardening::secret_value("ISCY_ALERTMANAGER_HMAC_SECRET") else {
        return Err(alertmanager_auth_response(
            "invalid_alertmanager_hmac_config",
            "Alertmanager-HMAC-Secret konnte nicht gelesen werden.",
        ));
    };
    let Some(current_secret) = current_secret else {
        return Ok(());
    };
    let previous_secret =
        hardening::secret_value("ISCY_ALERTMANAGER_HMAC_PREVIOUS_SECRET").unwrap_or(None);
    let timestamp = header_string(headers, "x-iscy-alert-timestamp").ok_or_else(|| {
        alertmanager_auth_response(
            "missing_alertmanager_hmac_timestamp",
            "Alertmanager-HMAC benoetigt x-iscy-alert-timestamp.",
        )
    })?;
    let max_age = alertmanager_hmac_max_age();
    validate_alertmanager_timestamp(&timestamp, max_age)?;
    let signature = header_string(headers, "x-iscy-alert-signature").ok_or_else(|| {
        alertmanager_auth_response(
            "missing_alertmanager_hmac_signature",
            "Alertmanager-HMAC benoetigt x-iscy-alert-signature.",
        )
    })?;
    let signature = signature
        .strip_prefix("sha256=")
        .unwrap_or(signature.as_str())
        .trim();
    let signed_body = alertmanager_hmac_message(&timestamp, body);
    if alertmanager_hmac_secret_matches(&current_secret, &signed_body, signature)
        || previous_secret
            .as_deref()
            .is_some_and(|secret| alertmanager_hmac_secret_matches(secret, &signed_body, signature))
    {
        let nonce = header_string(headers, "x-iscy-alert-nonce")
            .unwrap_or_else(|| format!("{}:{}", timestamp.trim(), signature.trim()));
        consume_alertmanager_hmac_nonce(state, &nonce, max_age).await?;
        return Ok(());
    }
    Err(alertmanager_auth_response(
        "invalid_alertmanager_hmac_signature",
        "Alertmanager-HMAC-Signatur ist ungueltig.",
    ))
}

fn alertmanager_hmac_max_age() -> Duration {
    std::env::var("ISCY_ALERTMANAGER_HMAC_MAX_AGE_SECONDS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(300))
}

fn validate_alertmanager_timestamp(timestamp: &str, max_age: Duration) -> Result<(), Response> {
    let parsed = timestamp.trim().parse::<i64>().map_err(|_| {
        alertmanager_auth_response(
            "invalid_alertmanager_hmac_timestamp",
            "x-iscy-alert-timestamp muss Unix-Epoch-Sekunden enthalten.",
        )
    })?;
    let now = Utc::now().timestamp();
    if (now - parsed).unsigned_abs() > max_age.as_secs() {
        return Err(alertmanager_auth_response(
            "stale_alertmanager_hmac_timestamp",
            "Alertmanager-HMAC-Timestamp liegt ausserhalb des erlaubten Replay-Fensters.",
        ));
    }
    Ok(())
}

async fn consume_alertmanager_hmac_nonce(
    state: &AppState,
    nonce: &str,
    max_age: Duration,
) -> Result<(), Response> {
    let Some(store) = state.security_store.as_ref() else {
        return Ok(());
    };
    match store
        .consume_hmac_nonce("alertmanager", nonce, max_age)
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(alertmanager_auth_response(
            "replayed_alertmanager_hmac_nonce",
            "Alertmanager-HMAC-Nonce wurde im Replay-Fenster bereits verwendet.",
        )),
        Err(_) => Err(alertmanager_auth_response(
            "invalid_alertmanager_hmac_nonce_store",
            "Alertmanager-HMAC-Nonce konnte nicht persistiert werden.",
        )),
    }
}

fn alertmanager_hmac_message(timestamp: &str, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(timestamp.len() + 1 + body.len());
    message.extend_from_slice(timestamp.trim().as_bytes());
    message.push(b'.');
    message.extend_from_slice(body);
    message
}

fn alertmanager_hmac_secret_matches(secret: &str, message: &[u8], signature: &str) -> bool {
    let Ok(mut mac) = AlertmanagerHmacSha256::new_from_slice(secret.trim().as_bytes()) else {
        return false;
    };
    mac.update(message);
    let expected = hex_encode_bytes(&mac.finalize().into_bytes());
    constant_time_eq(expected.as_bytes(), signature.as_bytes())
}

fn alertmanager_auth_response(error_code: &'static str, message: &'static str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ApiErrorResponse {
            accepted: false,
            api_version: "v1",
            error_code,
            message: message.to_string(),
        }),
    )
        .into_response()
}

fn hex_encode_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (left_byte, right_byte) in left.iter().zip(right.iter()) {
        diff |= left_byte ^ right_byte;
    }
    diff == 0
}

fn alert_label(
    alert: &AlertmanagerWebhookAlert,
    payload: &AlertmanagerWebhookPayload,
    key: &str,
    fallback: &str,
) -> String {
    alert
        .labels
        .get(key)
        .or_else(|| payload.common_labels.get(key))
        .or_else(|| payload.group_labels.get(key))
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_string()
}

fn alert_annotation(
    alert: &AlertmanagerWebhookAlert,
    payload: &AlertmanagerWebhookPayload,
    key: &str,
    fallback: &str,
) -> String {
    alert
        .annotations
        .get(key)
        .or_else(|| payload.common_annotations.get(key))
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_string()
}

fn alertmanager_action_hint(status: &str, severity: &str) -> &'static str {
    if status.eq_ignore_ascii_case("resolved") {
        return "Runbook aktualisieren und Evidence zur Entstoerung verlinken.";
    }
    match severity.trim().to_ascii_lowercase().as_str() {
        "critical" => "Sofort Incident/Runbook pruefen und Verantwortliche eskalieren.",
        "warning" => "Backlog pruefen, Owner setzen und naechstes Review einplanen.",
        _ => "Signal triagieren und bei Bedarf als Evidence oder Roadmap-Arbeit aufnehmen.",
    }
}

async fn persist_alertmanager_alerts(
    state: &AppState,
    headers: &HeaderMap,
    alerts: &[AlertmanagerAlertSummary],
) -> AlertmanagerPersistenceSummary {
    let context = match alertmanager_persistence_context(state, headers).await {
        Ok(context) => context,
        Err(_) => {
            return AlertmanagerPersistenceSummary {
                skipped_reason: Some("missing_tenant_context".to_string()),
                ..Default::default()
            }
        }
    };
    if !context.can_write() {
        return AlertmanagerPersistenceSummary {
            skipped_reason: Some("read_only_context".to_string()),
            ..Default::default()
        };
    }
    let Some(incident_store) = state.incident_store.clone() else {
        return AlertmanagerPersistenceSummary {
            skipped_reason: Some("incident_store_not_configured".to_string()),
            ..Default::default()
        };
    };
    let evidence_store = state.evidence_store.clone();
    let mut summary = AlertmanagerPersistenceSummary {
        enabled: true,
        ..Default::default()
    };
    let require_resolution_review = alertmanager_resolution_review_required();
    for alert in alerts {
        let authority_reference = alertmanager_authority_reference(alert);
        let existing_incident = match incident_store
            .open_alertmanager_incident_by_reference(context.tenant_id, &authority_reference)
            .await
        {
            Ok(existing) => existing,
            Err(err) => {
                summary.errors.push(format!(
                    "Deduplizierungspruefung fuer {} konnte nicht ausgefuehrt werden: {err}",
                    alert.alertname
                ));
                continue;
            }
        };

        if alert.status.eq_ignore_ascii_case("resolved") {
            let Some(existing) = existing_incident else {
                summary.ignored_resolved_alerts += 1;
                continue;
            };
            match incident_store
                .update_incident(
                    context.tenant_id,
                    existing.id,
                    Some(context.user_id),
                    alertmanager_resolved_incident_payload(alert),
                )
                .await
            {
                Ok(Some(result)) => {
                    summary.resolved_incidents += 1;
                    if alertmanager_resolution_review_required_for_incident(
                        &result.incident,
                        require_resolution_review,
                    ) {
                        let review_note = "Root Cause und Lessons Learned fehlen nach automatischem Alertmanager-Resolved; bitte fachlichen Abschluss in der Fallakte dokumentieren.";
                        if let Err(err) = incident_store
                            .update_incident_review_state(
                                context.tenant_id,
                                existing.id,
                                context.user_id,
                                "request_changes",
                                Some(review_note),
                            )
                            .await
                        {
                            summary.errors.push(format!(
                                "Resolved-Reviewpflicht fuer {} konnte nicht gesetzt werden: {err}",
                                alert.alertname
                            ));
                        }
                    }
                    if let Err(err) = incident_store
                        .append_incident_event(
                            context.tenant_id,
                            existing.id,
                            Some(context.user_id),
                            incident_store::IncidentEventWriteRequest::timeline_note(
                                Some("Alertmanager-Alert resolved"),
                                &format!(
                                    "Alertmanager meldet '{}' als resolved. Fingerprint: {}. Quelle: {}.",
                                    alert.alertname,
                                    alert.fingerprint.as_deref().unwrap_or("-"),
                                    alert.source_url.as_deref().unwrap_or("-"),
                                ),
                            ),
                        )
                        .await
                    {
                        summary.errors.push(format!(
                            "Resolved-Notiz fuer {} konnte nicht erstellt werden: {err}",
                            alert.alertname
                        ));
                    }
                }
                Ok(None) => summary.ignored_resolved_alerts += 1,
                Err(err) => summary.errors.push(format!(
                    "Incident fuer resolved Alert {} konnte nicht geschlossen werden: {err}",
                    alert.alertname
                )),
            }
            continue;
        }

        if let Some(existing) = existing_incident {
            summary.deduplicated_incidents += 1;
            if let Err(err) = incident_store
                .append_incident_event(
                    context.tenant_id,
                    existing.id,
                    Some(context.user_id),
                    incident_store::IncidentEventWriteRequest::timeline_note(
                        Some("Alertmanager-Alert dedupliziert"),
                        &format!(
                            "Alertmanager-Alert '{}' wurde erneut empfangen und der bestehenden Fallakte #{} zugeordnet. Fingerprint: {}.",
                            alert.alertname,
                            existing.id,
                            alert.fingerprint.as_deref().unwrap_or("-"),
                        ),
                    ),
                )
                .await
            {
                summary.errors.push(format!(
                    "Deduplizierungsnotiz fuer {} konnte nicht erstellt werden: {err}",
                    alert.alertname
                ));
            }
            continue;
        }
        let payload = alertmanager_incident_payload(alert);
        match incident_store
            .create_incident(context.tenant_id, Some(context.user_id), payload)
            .await
        {
            Ok(result) => {
                summary.created_incidents += 1;
                if let Some(store) = evidence_store.clone() {
                    let evidence_payload = alertmanager_evidence_payload(alert, result.incident.id);
                    match store
                        .create_evidence_item(context.tenant_id, context.user_id, evidence_payload)
                        .await
                    {
                        Ok(item) => {
                            summary.created_evidence += 1;
                            record_incident_evidence_event(
                                state,
                                context.tenant_id,
                                context.user_id,
                                &item,
                            )
                            .await;
                        }
                        Err(err) => summary.errors.push(format!(
                            "Evidence fuer {} konnte nicht erstellt werden: {err}",
                            alert.alertname
                        )),
                    }
                }
            }
            Err(err) => summary.errors.push(format!(
                "Incident fuer {} konnte nicht erstellt werden: {err}",
                alert.alertname
            )),
        }
    }
    if summary.created_incidents == 0
        && summary.deduplicated_incidents == 0
        && summary.resolved_incidents == 0
        && summary.errors.is_empty()
    {
        summary.skipped_reason = Some(if summary.ignored_resolved_alerts > 0 {
            "no_matching_open_alertmanager_incident".to_string()
        } else {
            "no_firing_alerts".to_string()
        });
    }
    summary
}

async fn alertmanager_persistence_context(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedTenantContext, RequiredTenantContextError> {
    match RequestContext::authenticated_tenant_from_headers(headers) {
        Ok(context) => Ok(context),
        Err(_) => authenticated_tenant_context(state, headers).await,
    }
}

fn alertmanager_incident_payload(
    alert: &AlertmanagerAlertSummary,
) -> incident_store::IncidentWriteRequest {
    let severity = alertmanager_incident_severity(&alert.severity).to_string();
    let title = alertmanager_limit_text(
        &format!("Alertmanager: {} ({})", alert.alertname, alert.severity),
        240,
    );
    let summary = alertmanager_alert_detail(alert);
    incident_store::IncidentWriteRequest {
        reporter_id: None,
        owner_id: None,
        related_risk_id: None,
        related_asset_id: None,
        related_process_id: None,
        title: Some(title),
        summary: Some(summary),
        incident_type: Some("GENERAL".to_string()),
        runbook_template: Some(alertmanager_runbook_template(alert).to_string()),
        severity: Some(severity),
        status: Some("TRIAGE".to_string()),
        detected_at: Some(alert.starts_at.clone()),
        confirmed_at: None,
        contained_at: None,
        resolved_at: None,
        nis2_reportable: Some(false),
        nis2_significance_status: Some("NOT_ASSESSED".to_string()),
        nis2_significance_criteria: Some(String::new()),
        nis2_significance_justification: Some(
            "Automatisch aus Alertmanager erzeugt; noch keine NIS2-Erheblichkeitsentscheidung."
                .to_string(),
        ),
        nis2_significance_reference: Some(String::new()),
        nis2_significance_assessed_at: None,
        early_warning_sent_at: None,
        notification_sent_at: None,
        final_report_sent_at: None,
        authority_reference: Some(alertmanager_authority_reference(alert)),
        stakeholder_summary: Some(alert.summary.clone()),
        lessons_learned: None,
    }
}

fn alertmanager_resolved_incident_payload(
    alert: &AlertmanagerAlertSummary,
) -> incident_store::IncidentWriteRequest {
    let resolved_at = alert
        .ends_at
        .clone()
        .or_else(|| alert.starts_at.clone())
        .unwrap_or_else(|| Utc::now().to_rfc3339());
    incident_store::IncidentWriteRequest {
        reporter_id: None,
        owner_id: None,
        related_risk_id: None,
        related_asset_id: None,
        related_process_id: None,
        title: None,
        summary: None,
        incident_type: None,
        runbook_template: None,
        severity: None,
        status: Some("RESOLVED".to_string()),
        detected_at: None,
        confirmed_at: None,
        contained_at: None,
        resolved_at: Some(Some(resolved_at)),
        nis2_reportable: None,
        nis2_significance_status: None,
        nis2_significance_criteria: None,
        nis2_significance_justification: None,
        nis2_significance_reference: None,
        nis2_significance_assessed_at: None,
        early_warning_sent_at: None,
        notification_sent_at: None,
        final_report_sent_at: None,
        authority_reference: None,
        stakeholder_summary: None,
        lessons_learned: None,
    }
}

fn alertmanager_resolution_review_required() -> bool {
    env_flag_enabled("ISCY_ALERTMANAGER_REQUIRE_RESOLUTION_REVIEW")
        || env_flag_enabled("ISCY_REQUIRE_INCIDENT_ROOT_CAUSE_ON_RESOLVE")
}

fn alertmanager_resolution_review_required_for_incident(
    incident: &incident_store::IncidentSummary,
    required_enabled: bool,
) -> bool {
    required_enabled
        && incident.authority_reference.starts_with("Alertmanager:")
        && matches!(incident.status.as_str(), "RESOLVED" | "CLOSED")
        && incident.lessons_learned.trim().is_empty()
}

fn alertmanager_authority_reference(alert: &AlertmanagerAlertSummary) -> String {
    if let Some(fingerprint) = alert
        .fingerprint
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return format!(
            "Alertmanager:fp:{}",
            alertmanager_limit_text(fingerprint, 190)
        );
    }
    format!(
        "Alertmanager:{}",
        alertmanager_limit_text(&alert.alertname, 220)
    )
}

fn alertmanager_evidence_payload(
    alert: &AlertmanagerAlertSummary,
    incident_id: i64,
) -> evidence_store::EvidenceItemCreateRequest {
    evidence_store::EvidenceItemCreateRequest {
        session_id: None,
        domain_id: None,
        measure_id: None,
        requirement_id: None,
        control_id: None,
        incident_id: Some(incident_id),
        title: alertmanager_limit_text(&format!("Alertmanager Evidence: {}", alert.alertname), 240),
        description: alertmanager_alert_detail(alert),
        linked_requirement: format!("OPERATIONS:ALERTMANAGER:{}", alert.alertname),
        file_name: None,
        supersedes_id: None,
        file_sha256: String::new(),
        valid_until: None,
        retention_until: None,
        retention_reason: "Alertmanager-Fallakte; Aufbewahrung nach Incident-Policy.".to_string(),
        sensitivity: "INTERNAL".to_string(),
        status: Some("SUBMITTED".to_string()),
        review_notes: "Automatisch aus Alertmanager-Webhook erzeugt.".to_string(),
    }
}

fn alertmanager_alert_detail(alert: &AlertmanagerAlertSummary) -> String {
    [
        format!("Alert: {}", alert.alertname),
        format!(
            "Fingerprint: {}",
            alert.fingerprint.as_deref().unwrap_or("-")
        ),
        format!("Status: {}", alert.status),
        format!("Severity: {}", alert.severity),
        format!("Service: {}", alert.service),
        format!("Summary: {}", alert.summary),
        format!("Description: {}", alert.description),
        format!("Starts At: {}", alert.starts_at.as_deref().unwrap_or("-")),
        format!("Ends At: {}", alert.ends_at.as_deref().unwrap_or("-")),
        format!("Source: {}", alert.source_url.as_deref().unwrap_or("-")),
        format!("Action: {}", alert.action_hint),
    ]
    .join("\n")
}

fn alertmanager_runbook_template(alert: &AlertmanagerAlertSummary) -> &'static str {
    if alert.severity.eq_ignore_ascii_case("critical") {
        return "1. Statusseite /status/ und Prometheus-Quelle pruefen.\n2. Incident Owner und technische Verantwortliche informieren.\n3. Auswirkungen, Scope und Tenant-Kontext bestaetigen.\n4. Eindaemmung oder Workaround dokumentieren.\n5. Evidence, Root Cause und Lessons Learned nachziehen.";
    }
    "1. Signal pruefen und Quelle bestaetigen.\n2. Owner, Scope und betroffene Controls bewerten.\n3. Falls noetig Roadmap-/Evidence-Arbeit anlegen.\n4. Monitoring-Schwelle oder Runbook nachjustieren.\n5. Abschluss im Review dokumentieren."
}

fn alertmanager_incident_severity(severity: &str) -> &'static str {
    match severity.trim().to_ascii_lowercase().as_str() {
        "critical" => "CRITICAL",
        "warning" | "warn" => "MEDIUM",
        "info" => "INFO",
        _ => "LOW",
    }
}

fn alertmanager_limit_text(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect::<String>()
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

fn evidence_upload_payload_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        let message = cause.to_string();
        message.contains("nicht gefunden")
            || message.contains("darf nicht")
            || message.contains("muss ")
            || message.contains("ungueltig")
            || message.contains("bereits ersetzt")
    })
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

fn agent_store_error_response(err: anyhow::Error, action: &'static str) -> Response {
    let details = err
        .chain()
        .map(|cause| cause.to_string())
        .collect::<Vec<_>>()
        .join(": ");
    let payload_error = details.contains("Agent-");
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
                "invalid_agent_payload"
            } else {
                "database_error"
            },
            message: format!("{action}: {details}"),
        }),
    )
        .into_response()
}

fn header_string(headers: &HeaderMap, name: &'static str) -> Option<String> {
    headers
        .get(name)
        .and_then(|raw| raw.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn agent_enrollment_token_from_headers(headers: &HeaderMap) -> Option<String> {
    header_string(headers, "x-iscy-agent-enrollment-token")
}

fn agent_secret_from_headers(headers: &HeaderMap) -> Option<String> {
    header_string(headers, "x-iscy-agent-secret")
}

fn agent_mtls_fingerprint_from_headers(headers: &HeaderMap) -> Option<String> {
    header_string(headers, "x-iscy-agent-mtls-fingerprint")
        .or_else(|| header_string(headers, "x-ssl-client-fingerprint"))
        .or_else(|| header_string(headers, "ssl-client-fingerprint"))
}

#[derive(Debug, Clone, Copy)]
enum AgentTenantHeaderError {
    Missing,
    Invalid,
}

impl AgentTenantHeaderError {
    fn into_response(self) -> Response {
        match self {
            Self::Missing => agent_auth_error_response(
                StatusCode::UNAUTHORIZED,
                "missing_agent_tenant",
                "Agent-Requests benoetigen den Header x-iscy-tenant-id.",
            ),
            Self::Invalid => agent_auth_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_agent_tenant",
                "Header x-iscy-tenant-id muss eine positive Tenant-ID enthalten.",
            ),
        }
    }
}

fn agent_tenant_id_from_headers(headers: &HeaderMap) -> Result<i64, AgentTenantHeaderError> {
    let Some(raw_tenant_id) = header_string(headers, "x-iscy-tenant-id") else {
        return Err(AgentTenantHeaderError::Missing);
    };
    let tenant_id = raw_tenant_id.parse::<i64>().ok().filter(|value| *value > 0);
    tenant_id.ok_or(AgentTenantHeaderError::Invalid)
}

fn agent_auth_error_response(
    status: StatusCode,
    error_code: &'static str,
    message: &'static str,
) -> Response {
    (
        status,
        Json(ApiErrorResponse {
            accepted: false,
            api_version: "v1",
            error_code,
            message: message.to_string(),
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
    query
        .to_context()
        .or_else(|| web_context_from_headers(headers))
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

fn session_cookie_value(token: &str, security_config: &CommunitySecurityConfig) -> String {
    format!(
        "{ISCY_SESSION_COOKIE}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800{}",
        security_config.cookie_secure_suffix()
    )
}

fn expired_session_cookie_value(security_config: &CommunitySecurityConfig) -> String {
    format!(
        "iscy_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0{}",
        security_config.cookie_secure_suffix()
    )
}

fn web_context_from_headers(headers: &HeaderMap) -> Option<WebContext> {
    let tenant_id = header_string(headers, "x-iscy-tenant-id")?
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0)?;
    let user_id = header_string(headers, "x-iscy-user-id")?
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0)?;
    Some(WebContext {
        tenant_id,
        user_id,
        user_email: header_string(headers, "x-iscy-user-email"),
    })
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

const LOGIN_RATE_LIMIT_MAX_FAILURES: u32 = 5;
const LOGIN_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(15 * 60);
const LOGIN_RATE_LIMIT_BLOCK: Duration = Duration::from_secs(15 * 60);

fn login_rate_limit_key(tenant_id: Option<i64>, username: &str) -> String {
    format!(
        "{}:{}",
        tenant_id
            .map(|value| value.to_string())
            .unwrap_or_else(|| "global".to_string()),
        username.trim().to_ascii_lowercase()
    )
}

async fn login_rate_limit_remaining_block(state: &AppState, key: &str) -> Option<Duration> {
    if let Some(store) = state.security_store.as_ref() {
        if let Ok(remaining) = store
            .login_rate_limit_remaining_block(key, LOGIN_RATE_LIMIT_WINDOW)
            .await
        {
            return remaining;
        }
    }
    login_rate_limit_remaining_block_memory(state, key)
}

fn login_rate_limit_remaining_block_memory(state: &AppState, key: &str) -> Option<Duration> {
    let now = Instant::now();
    let mut guard = state.login_rate_limits.lock().ok()?;
    let entry = guard.get(key)?;
    if let Some(blocked_until) = entry.blocked_until {
        if blocked_until > now {
            return Some(blocked_until.duration_since(now));
        }
    }
    if now.duration_since(entry.first_failure_at) > LOGIN_RATE_LIMIT_WINDOW {
        guard.remove(key);
    }
    None
}

async fn login_rate_limit_record_failure(
    state: &AppState,
    key: &str,
    tenant_id: Option<i64>,
    username: &str,
) {
    if let Some(store) = state.security_store.as_ref() {
        if store
            .record_login_failure(
                key,
                tenant_id,
                username,
                LOGIN_RATE_LIMIT_MAX_FAILURES,
                LOGIN_RATE_LIMIT_WINDOW,
                LOGIN_RATE_LIMIT_BLOCK,
            )
            .await
            .is_ok()
        {
            return;
        }
    }
    login_rate_limit_record_failure_memory(state, key);
}

fn login_rate_limit_record_failure_memory(state: &AppState, key: &str) {
    let now = Instant::now();
    let Ok(mut guard) = state.login_rate_limits.lock() else {
        return;
    };
    let entry = guard
        .entry(key.to_string())
        .or_insert_with(|| LoginRateLimitEntry {
            failures: 0,
            first_failure_at: now,
            blocked_until: None,
        });
    if now.duration_since(entry.first_failure_at) > LOGIN_RATE_LIMIT_WINDOW {
        entry.failures = 0;
        entry.first_failure_at = now;
        entry.blocked_until = None;
    }
    entry.failures = entry.failures.saturating_add(1);
    if entry.failures >= LOGIN_RATE_LIMIT_MAX_FAILURES {
        entry.blocked_until = Some(now + LOGIN_RATE_LIMIT_BLOCK);
    }
}

async fn login_rate_limit_record_success(state: &AppState, key: &str) {
    if let Some(store) = state.security_store.as_ref() {
        if store.clear_login_limit(key).await.is_ok() {
            return;
        }
    }
    login_rate_limit_record_success_memory(state, key);
}

fn login_rate_limit_record_success_memory(state: &AppState, key: &str) {
    if let Ok(mut guard) = state.login_rate_limits.lock() {
        guard.remove(key);
    }
}

fn login_rate_limited_response(remaining: Duration) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(ApiErrorResponse {
            accepted: false,
            api_version: "v1",
            error_code: "login_rate_limited",
            message: format!(
                "Zu viele fehlgeschlagene Login-Versuche. Bitte in {} Sekunden erneut versuchen.",
                remaining.as_secs().max(1)
            ),
        }),
    )
        .into_response()
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
    let Some(store) = state.auth_store.clone() else {
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
    let mut login_context = None;
    let session_result = match (
        payload.username.as_deref(),
        payload.password.as_deref(),
        payload.tenant_id,
        payload.user_id,
    ) {
        (Some(username), Some(password), tenant_id, _) => {
            let key = login_rate_limit_key(tenant_id, username);
            if let Some(remaining) = login_rate_limit_remaining_block(&state, &key).await {
                return login_rate_limited_response(remaining);
            }
            login_context = Some((key, tenant_id, username.to_string()));
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
            if let Some((key, _, _)) = login_context.as_ref() {
                login_rate_limit_record_success(&state, key).await;
            }
            let cookie = session_cookie_value(&session.token, &state.security_config);
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
        Ok(None) => {
            if let Some((key, tenant_id, username)) = login_context.as_ref() {
                login_rate_limit_record_failure(&state, key, *tenant_id, username).await;
            }
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: "invalid_login_context",
                    message: "Login-Daten sind fuer Rust-Session nicht gueltig.".to_string(),
                }),
            )
                .into_response()
        }
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
        &expired_session_cookie_value(&state.security_config),
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

async fn agent_posture(State(state): State<AppState>, headers: HeaderMap) -> Response {
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
    let Some(store) = state.agent_store.clone() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Agent-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };
    match store.posture_overview(context.tenant_id).await {
        Ok(posture) => (
            StatusCode::OK,
            Json(AgentPostureResponse {
                api_version: "v1",
                posture,
            }),
        )
            .into_response(),
        Err(err) => {
            agent_store_error_response(err, "Zero-Trust-Posture konnte nicht gelesen werden")
        }
    }
}

async fn agent_devices(State(state): State<AppState>, headers: HeaderMap) -> Response {
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
    let Some(store) = state.agent_store.clone() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Agent-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };
    match store.list_devices(context.tenant_id, 200).await {
        Ok(devices) => (
            StatusCode::OK,
            Json(AgentDevicesResponse {
                api_version: "v1",
                tenant_id: context.tenant_id,
                devices,
            }),
        )
            .into_response(),
        Err(err) => agent_store_error_response(err, "Agent-Devices konnten nicht gelesen werden"),
    }
}

async fn agent_device_findings(
    Path(device_id): Path<i64>,
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
    let Some(store) = state.agent_store.clone() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Agent-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };
    match store
        .list_device_findings(context.tenant_id, device_id, 200)
        .await
    {
        Ok(findings) => (
            StatusCode::OK,
            Json(AgentFindingsListResponse {
                api_version: "v1",
                tenant_id: context.tenant_id,
                device_id,
                findings,
            }),
        )
            .into_response(),
        Err(err) => agent_store_error_response(err, "Agent-Findings konnten nicht gelesen werden"),
    }
}

async fn agent_enrollment_token_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<agent_store::AgentEnrollmentTokenCreateRequest>,
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
    let Some(store) = state.agent_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Agent-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store
        .create_enrollment_token(context.tenant_id, Some(context.user_id), payload)
        .await
    {
        Ok(result) => (
            StatusCode::CREATED,
            Json(AgentEnrollmentTokenCreateResponse {
                accepted: true,
                api_version: "v1",
                token: result.token,
                enrollment: result.enrollment,
            }),
        )
            .into_response(),
        Err(err) => {
            agent_store_error_response(err, "Agent-Enrollment-Token konnte nicht erstellt werden")
        }
    }
}

async fn agent_enroll(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<agent_store::AgentEnrollRequest>,
) -> Response {
    let Some(store) = state.agent_store.clone() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Agent-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    if let Some(enrollment_token) = agent_enrollment_token_from_headers(&headers) {
        let tenant_id = match agent_tenant_id_from_headers(&headers) {
            Ok(tenant_id) => tenant_id,
            Err(err) => return err.into_response(),
        };
        let mtls_fingerprint = agent_mtls_fingerprint_from_headers(&headers);
        return match store
            .enroll_device_with_token(
                tenant_id,
                payload,
                &enrollment_token,
                mtls_fingerprint.as_deref(),
            )
            .await
        {
            Ok(Some(result)) => (
                StatusCode::CREATED,
                Json(AgentEnrollResponse {
                    accepted: true,
                    api_version: "v1",
                    auth_model: "enrollment_token",
                    agent_secret: Some(result.agent_secret),
                    device: result.device,
                }),
            )
                .into_response(),
            Ok(None) => agent_auth_error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_agent_enrollment_token",
                "Agent-Enrollment-Token ist ungueltig, abgelaufen, verbraucht oder nicht fuer dieses Geraet zugelassen.",
            ),
            Err(err) => {
                agent_store_error_response(err, "Agent-Enrollment konnte nicht gespeichert werden")
            }
        };
    }

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
    match store.enroll_device(context.tenant_id, payload).await {
        Ok(device) => (
            StatusCode::CREATED,
            Json(AgentEnrollResponse {
                accepted: true,
                api_version: "v1",
                auth_model: "tenant_context",
                agent_secret: None,
                device,
            }),
        )
            .into_response(),
        Err(err) => {
            agent_store_error_response(err, "Agent-Enrollment konnte nicht gespeichert werden")
        }
    }
}

async fn agent_heartbeat(
    Path(device_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<agent_store::AgentHeartbeatRequest>,
) -> Response {
    let Some(store) = state.agent_store.clone() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Agent-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };
    let tenant_id = if let Some(agent_secret) = agent_secret_from_headers(&headers) {
        let tenant_id = match agent_tenant_id_from_headers(&headers) {
            Ok(tenant_id) => tenant_id,
            Err(err) => return err.into_response(),
        };
        let mtls_fingerprint = agent_mtls_fingerprint_from_headers(&headers);
        match store
            .verify_agent_secret(
                tenant_id,
                device_id,
                &agent_secret,
                mtls_fingerprint.as_deref(),
            )
            .await
        {
            Ok(true) => tenant_id,
            Ok(false) => {
                return agent_auth_error_response(
                    StatusCode::UNAUTHORIZED,
                    "invalid_agent_secret",
                    "Agent-Secret oder mTLS-Fingerprint ist ungueltig.",
                );
            }
            Err(err) => {
                return agent_store_error_response(
                    err,
                    "Agent-Secret konnte nicht geprueft werden",
                );
            }
        }
    } else {
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
        context.tenant_id
    };
    match store.record_heartbeat(tenant_id, device_id, payload).await {
        Ok(Some(heartbeat)) => (
            StatusCode::CREATED,
            Json(AgentHeartbeatResponse {
                accepted: true,
                api_version: "v1",
                heartbeat,
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "agent_device_not_found",
                message: format!("Agent-Device '{}' wurde nicht gefunden.", device_id),
            }),
        )
            .into_response(),
        Err(err) => {
            agent_store_error_response(err, "Agent-Heartbeat konnte nicht gespeichert werden")
        }
    }
}

async fn agent_findings(
    Path(device_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<agent_store::AgentFindingsRequest>,
) -> Response {
    let Some(store) = state.agent_store.clone() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Agent-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };
    let tenant_id = if let Some(agent_secret) = agent_secret_from_headers(&headers) {
        let tenant_id = match agent_tenant_id_from_headers(&headers) {
            Ok(tenant_id) => tenant_id,
            Err(err) => return err.into_response(),
        };
        let mtls_fingerprint = agent_mtls_fingerprint_from_headers(&headers);
        match store
            .verify_agent_secret(
                tenant_id,
                device_id,
                &agent_secret,
                mtls_fingerprint.as_deref(),
            )
            .await
        {
            Ok(true) => tenant_id,
            Ok(false) => {
                return agent_auth_error_response(
                    StatusCode::UNAUTHORIZED,
                    "invalid_agent_secret",
                    "Agent-Secret oder mTLS-Fingerprint ist ungueltig.",
                );
            }
            Err(err) => {
                return agent_store_error_response(
                    err,
                    "Agent-Secret konnte nicht geprueft werden",
                );
            }
        }
    } else {
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
        context.tenant_id
    };
    match store.record_findings(tenant_id, device_id, payload).await {
        Ok(Some((device, findings))) => (
            StatusCode::CREATED,
            Json(AgentFindingsResponse {
                accepted: true,
                api_version: "v1",
                created: findings.len(),
                device,
                findings,
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "agent_device_not_found",
                message: format!("Agent-Device '{}' wurde nicht gefunden.", device_id),
            }),
        )
            .into_response(),
        Err(err) => {
            agent_store_error_response(err, "Agent-Findings konnten nicht gespeichert werden")
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

async fn organization_tenant_profile_update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<tenant_store::TenantRegulatoryProfileUpdateRequest>,
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

    match store
        .update_regulatory_profile(context.tenant_id, payload)
        .await
    {
        Ok(Some(tenant)) => (
            StatusCode::OK,
            Json(TenantProfileUpdateResponse {
                accepted: true,
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
            StatusCode::BAD_REQUEST,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "tenant_profile_invalid",
                message: format!(
                    "Tenant-Regulierungsprofil konnte nicht gespeichert werden: {err}"
                ),
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

async fn supplier_risk_overview(State(state): State<AppState>, headers: HeaderMap) -> Response {
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

    let Some(store) = state.supplier_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Supplier-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.overview(context.tenant_id, 200).await {
        Ok(overview) => (
            StatusCode::OK,
            Json(SupplierRiskOverviewResponse {
                api_version: "v1",
                overview,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Supplier-Risk-Uebersicht konnte nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn supplier_risk_detail(
    Path(supplier_id): Path<i64>,
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

    let Some(store) = state.supplier_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Supplier-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.detail(context.tenant_id, supplier_id).await {
        Ok(Some(supplier)) => (
            StatusCode::OK,
            Json(SupplierRiskDetailResponse {
                api_version: "v1",
                supplier,
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "not_found",
                message: "Supplier wurde fuer diesen Tenant nicht gefunden.".to_string(),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Supplier-Detail konnte nicht gelesen werden: {err}"),
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

async fn ai_governance_overview(State(state): State<AppState>, headers: HeaderMap) -> Response {
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

    let Some(store) = state.ai_governance_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-AI-Governance-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.overview(context.tenant_id, 200).await {
        Ok(overview) => (
            StatusCode::OK,
            Json(AiGovernanceOverviewResponse {
                api_version: "v1",
                overview,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("AI-Governance-Uebersicht konnte nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn ai_governance_create_system(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ai_governance_store::AiGovernanceSystemCreateRequest>,
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
    let Some(store) = state.ai_governance_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-AI-Governance-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.create_system(context.tenant_id, payload).await {
        Ok(result) => (
            StatusCode::CREATED,
            Json(AiGovernanceSystemWriteResponse {
                accepted: true,
                api_version: "v1",
                result,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "invalid_ai_governance_payload",
                message: err.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn ai_governance_detail(
    Path(system_id): Path<i64>,
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
    let Some(store) = state.ai_governance_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-AI-Governance-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.detail(context.tenant_id, system_id).await {
        Ok(Some(detail)) => (
            StatusCode::OK,
            Json(AiGovernanceDetailResponse {
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
                error_code: "not_found",
                message: "AI-Governance-System wurde fuer diesen Tenant nicht gefunden."
                    .to_string(),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("AI-Governance-Detail konnte nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn ai_governance_update_system(
    Path(system_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ai_governance_store::AiGovernanceSystemUpdateRequest>,
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
    let Some(store) = state.ai_governance_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-AI-Governance-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store
        .update_system(context.tenant_id, system_id, payload)
        .await
    {
        Ok(Some(result)) => (
            StatusCode::OK,
            Json(AiGovernanceSystemWriteResponse {
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
                error_code: "not_found",
                message: "AI-Governance-System wurde fuer diesen Tenant nicht gefunden."
                    .to_string(),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "invalid_ai_governance_payload",
                message: err.to_string(),
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

async fn product_security_trends(State(state): State<AppState>, headers: HeaderMap) -> Response {
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
            Json(ProductSecurityTrendsResponse {
                api_version: "v1",
                tenant_id: context.tenant_id,
                trends: overview.trend_dashboard,
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "tenant_not_found",
                message: "Tenant wurde fuer Product-Security-Trends nicht gefunden.".to_string(),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Product-Security-Trends konnten nicht gelesen werden: {err}"),
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

async fn product_security_product_cra_readiness(
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

    match store.cra_readiness(context.tenant_id, product_id).await {
        Ok(Some(readiness)) => (
            StatusCode::OK,
            Json(ProductSecurityCraReadinessResponse {
                api_version: "v1",
                readiness,
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
                message: format!("CRA-Readiness konnte nicht gelesen werden: {err}"),
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

async fn product_security_csaf_import(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<product_security_store::ProductSecurityArtifactImportRequest>,
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
        .import_csaf(context.tenant_id, context.user_id, payload)
        .await
    {
        Ok(result) => (
            StatusCode::CREATED,
            Json(ProductSecurityArtifactImportResponse {
                accepted: true,
                api_version: "v1",
                result,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "invalid_product_security_import",
                message: format!("CSAF-Import konnte nicht verarbeitet werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn product_security_sbom_import(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<product_security_store::ProductSecurityArtifactImportRequest>,
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
        .import_sbom(context.tenant_id, context.user_id, payload)
        .await
    {
        Ok(result) => (
            StatusCode::CREATED,
            Json(ProductSecurityArtifactImportResponse {
                accepted: true,
                api_version: "v1",
                result,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "invalid_product_security_import",
                message: format!("SBOM-Import konnte nicht verarbeitet werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn product_security_import_history_export_csv(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    product_security_import_history_export(state, headers, ProductSecurityImportHistoryFormat::Csv)
        .await
}

async fn product_security_import_history_export_json(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    product_security_import_history_export(state, headers, ProductSecurityImportHistoryFormat::Json)
        .await
}

async fn product_security_import_history_export(
    state: AppState,
    headers: HeaderMap,
    export_format: ProductSecurityImportHistoryFormat,
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
    match store.import_history(context.tenant_id, 500).await {
        Ok(artifacts) => product_security_import_history_download_response(
            context.tenant_id,
            &artifacts,
            export_format,
        ),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!(
                    "Product-Security-Import-Historie konnte nicht exportiert werden: {err}"
                ),
            }),
        )
            .into_response(),
    }
}

async fn product_security_import_detail(
    Path(artifact_id): Path<i64>,
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
    match store.import_detail(context.tenant_id, artifact_id).await {
        Ok(Some(detail)) => (
            StatusCode::OK,
            Json(ProductSecurityImportDetailResponse {
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
                error_code: "product_security_import_not_found",
                message: "Product-Security-Import wurde nicht gefunden.".to_string(),
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
                    "Product-Security-Importdetail konnte nicht gelesen werden: {err}"
                ),
            }),
        )
            .into_response(),
    }
}

async fn product_security_sbom_diff(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ProductSecuritySbomDiffQuery>,
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
    match store
        .sbom_diff(
            context.tenant_id,
            query.base_artifact_id,
            query.target_artifact_id,
        )
        .await
    {
        Ok(Some(diff)) => (
            StatusCode::OK,
            Json(ProductSecuritySbomDiffResponse {
                api_version: "v1",
                diff,
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "product_security_import_not_found",
                message: "Mindestens ein SBOM-Import wurde nicht gefunden.".to_string(),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "invalid_product_security_sbom_diff",
                message: format!("SBOM-Diff konnte nicht erstellt werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn product_security_cve_correlations(
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
        .suggest_cve_asset_correlations(context.tenant_id)
        .await
    {
        Ok(result) => (
            StatusCode::CREATED,
            Json(ProductSecurityCveCorrelationResponse {
                accepted: true,
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
                message: format!("CVE-Asset-Korrelationen konnten nicht erzeugt werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn product_security_cve_correlation_generate_work(
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
        .generate_work_from_accepted_correlations(context.tenant_id)
        .await
    {
        Ok(result) => (
            StatusCode::CREATED,
            Json(ProductSecurityAcceptedCorrelationWorkResponse {
                accepted: true,
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
                message: format!(
                    "Risiko-/Roadmap-Vorschlaege aus akzeptierten CVE-Korrelationen konnten nicht erzeugt werden: {err}"
                ),
            }),
        )
            .into_response(),
    }
}

async fn product_security_cve_correlation_update(
    Path(correlation_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<product_security_store::ProductSecurityCveCorrelationDecisionRequest>,
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
        .update_cve_correlation(context.tenant_id, correlation_id, payload)
        .await
    {
        Ok(Some(result)) => (
            StatusCode::OK,
            Json(ProductSecurityCveCorrelationDecisionResponse {
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
                error_code: "product_security_cve_correlation_not_found",
                message: "CVE-Asset-Korrelation wurde nicht gefunden.".to_string(),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "invalid_product_security_cve_correlation",
                message: format!("CVE-Asset-Korrelation konnte nicht aktualisiert werden: {err}"),
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

async fn risk_review(
    Path(risk_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<risk_store::RiskReviewRequest>,
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

    match store
        .review_risk(context.tenant_id, risk_id, context.user_id, payload)
        .await
    {
        Ok(Some(result)) => (
            StatusCode::OK,
            Json(RiskReviewResponse {
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
                error_code: "risk_not_found",
                message: format!("Risiko {} wurde nicht gefunden.", risk_id),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "invalid_risk_review",
                message: format!("Risiko-Review konnte nicht verarbeitet werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn incident_register(State(state): State<AppState>, headers: HeaderMap) -> Response {
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

    let Some(store) = state.incident_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Incident-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.list_incidents(context.tenant_id, 200).await {
        Ok(incidents) => (
            StatusCode::OK,
            Json(IncidentRegisterResponse {
                api_version: "v1",
                tenant_id: context.tenant_id,
                incidents,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Incidentliste konnte nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn incident_runbook_templates(State(state): State<AppState>, headers: HeaderMap) -> Response {
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

    let Some(store) = state.incident_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Incident-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.list_runbook_templates(context.tenant_id, 100).await {
        Ok(templates) => (
            StatusCode::OK,
            Json(IncidentRunbookTemplateListResponse {
                api_version: "v1",
                tenant_id: context.tenant_id,
                templates,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Runbook-Templates konnten nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn incident_detail(
    Path(incident_id): Path<i64>,
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

    let Some(store) = state.incident_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Incident-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.incident_detail(context.tenant_id, incident_id).await {
        Ok(Some(incident)) => match store
            .list_incident_events(context.tenant_id, incident_id, 50)
            .await
        {
            Ok(events) => (
                StatusCode::OK,
                Json(IncidentDetailResponse {
                    api_version: "v1",
                    incident,
                    events,
                }),
            )
                .into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: "database_error",
                    message: format!("Incident-Timeline konnte nicht gelesen werden: {err}"),
                }),
            )
                .into_response(),
        },
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "incident_not_found",
                message: format!("Incident {} wurde nicht gefunden.", incident_id),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Incidentdetail konnte nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn incident_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<incident_store::IncidentWriteRequest>,
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

    let Some(store) = state.incident_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Incident-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store
        .create_incident(context.tenant_id, Some(context.user_id), payload)
        .await
    {
        Ok(result) => (
            StatusCode::CREATED,
            Json(IncidentWriteResponse {
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
                message: format!("Incident konnte nicht erstellt werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn incident_update(
    Path(incident_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<incident_store::IncidentWriteRequest>,
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

    let Some(store) = state.incident_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Incident-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store
        .update_incident(
            context.tenant_id,
            incident_id,
            Some(context.user_id),
            payload,
        )
        .await
    {
        Ok(Some(result)) => (
            StatusCode::OK,
            Json(IncidentWriteResponse {
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
                error_code: "incident_not_found",
                message: format!("Incident {} wurde nicht gefunden.", incident_id),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Incident konnte nicht aktualisiert werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn incident_timeline_note_create(
    Path(incident_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<IncidentTimelineNoteRequest>,
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
    let payload = match incident_timeline_note_payload(payload.summary, payload.detail) {
        Ok(payload) => payload,
        Err(message) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: "invalid_timeline_note",
                    message,
                }),
            )
                .into_response();
        }
    };

    let Some(store) = state.incident_store.clone() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Incident-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.incident_detail(context.tenant_id, incident_id).await {
        Ok(Some(_)) => match store
            .append_incident_event(
                context.tenant_id,
                incident_id,
                Some(context.user_id),
                payload,
            )
            .await
        {
            Ok(event) => (
                StatusCode::CREATED,
                Json(IncidentEventWriteResponse {
                    api_version: "v1",
                    event,
                }),
            )
                .into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: "database_error",
                    message: format!("Timeline-Notiz konnte nicht gespeichert werden: {err}"),
                }),
            )
                .into_response(),
        },
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "incident_not_found",
                message: format!("Incident {} wurde nicht gefunden.", incident_id),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Incidentdetail konnte nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn incident_nis2_export(
    Path(incident_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    incident_regulatory_export_format(
        incident_id,
        state,
        headers,
        IncidentPackageKind::Nis2,
        IncidentExportFormat::Markdown,
    )
    .await
}

async fn incident_nis2_export_html(
    Path(incident_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    incident_regulatory_export_format(
        incident_id,
        state,
        headers,
        IncidentPackageKind::Nis2,
        IncidentExportFormat::Html,
    )
    .await
}

async fn incident_nis2_export_pdf(
    Path(incident_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    incident_regulatory_export_format(
        incident_id,
        state,
        headers,
        IncidentPackageKind::Nis2,
        IncidentExportFormat::Pdf,
    )
    .await
}

async fn incident_dora_export(
    Path(incident_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    incident_regulatory_export_format(
        incident_id,
        state,
        headers,
        IncidentPackageKind::Dora,
        IncidentExportFormat::Markdown,
    )
    .await
}

async fn incident_dora_export_html(
    Path(incident_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    incident_regulatory_export_format(
        incident_id,
        state,
        headers,
        IncidentPackageKind::Dora,
        IncidentExportFormat::Html,
    )
    .await
}

async fn incident_dora_export_pdf(
    Path(incident_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    incident_regulatory_export_format(
        incident_id,
        state,
        headers,
        IncidentPackageKind::Dora,
        IncidentExportFormat::Pdf,
    )
    .await
}

async fn incident_dsgvo_export(
    Path(incident_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    incident_regulatory_export_format(
        incident_id,
        state,
        headers,
        IncidentPackageKind::Dsgvo,
        IncidentExportFormat::Markdown,
    )
    .await
}

async fn incident_dsgvo_export_html(
    Path(incident_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    incident_regulatory_export_format(
        incident_id,
        state,
        headers,
        IncidentPackageKind::Dsgvo,
        IncidentExportFormat::Html,
    )
    .await
}

async fn incident_dsgvo_export_pdf(
    Path(incident_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    incident_regulatory_export_format(
        incident_id,
        state,
        headers,
        IncidentPackageKind::Dsgvo,
        IncidentExportFormat::Pdf,
    )
    .await
}

async fn incident_timeline_export_csv(
    Path(incident_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    incident_timeline_export_format(
        incident_id,
        state,
        headers,
        IncidentTimelineExportFormat::Csv,
    )
    .await
}

async fn incident_timeline_export_json(
    Path(incident_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    incident_timeline_export_format(
        incident_id,
        state,
        headers,
        IncidentTimelineExportFormat::Json,
    )
    .await
}

async fn incident_timeline_export_format(
    incident_id: i64,
    state: AppState,
    headers: HeaderMap,
    export_format: IncidentTimelineExportFormat,
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

    let Some(store) = state.incident_store.clone() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Incident-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };
    match store.incident_detail(context.tenant_id, incident_id).await {
        Ok(Some(incident)) => match store
            .list_incident_events(context.tenant_id, incident.id, 500)
            .await
        {
            Ok(events) => {
                incident_timeline_export_download_response(&incident, &events, export_format)
            }
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: "database_error",
                    message: format!("Incident-Timeline konnte nicht exportiert werden: {err}"),
                }),
            )
                .into_response(),
        },
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "incident_not_found",
                message: format!("Incident {} wurde nicht gefunden.", incident_id),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Incidentdetail konnte nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn incident_regulatory_export_format(
    incident_id: i64,
    state: AppState,
    headers: HeaderMap,
    package_kind: IncidentPackageKind,
    export_format: IncidentExportFormat,
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

    let Some(store) = state.incident_store.clone() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Incident-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.incident_detail(context.tenant_id, incident_id).await {
        Ok(Some(incident)) => {
            let evidence_items =
                incident_linked_evidence(&state, context.tenant_id, incident.id).await;
            match store
                .list_incident_events(context.tenant_id, incident.id, 50)
                .await
            {
                Ok(events) => incident_export_download_response(
                    &incident,
                    &evidence_items,
                    &events,
                    package_kind,
                    export_format,
                ),
                Err(err) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiErrorResponse {
                        accepted: false,
                        api_version: "v1",
                        error_code: "database_error",
                        message: format!("Incident-Timeline konnte nicht exportiert werden: {err}"),
                    }),
                )
                    .into_response(),
            }
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "incident_not_found",
                message: format!("Incident {} wurde nicht gefunden.", incident_id),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Incident-Meldepaket konnte nicht erstellt werden: {err}"),
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

async fn evidence_quality(
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
        .evidence_quality(context.tenant_id, query.session_id, 500, 100)
        .await
    {
        Ok(quality) => (
            StatusCode::OK,
            Json(EvidenceQualityResponse {
                api_version: "v1",
                tenant_id: context.tenant_id,
                session_id: query.session_id,
                quality,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Evidence-Qualitaet konnte nicht gelesen werden: {err}"),
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
        control_id: optional_i64_form_field(&form.fields, "control_id"),
        incident_id: optional_i64_form_field(&form.fields, "incident_id"),
        title: form.fields.get("title").cloned().unwrap_or_default(),
        description: form.fields.get("description").cloned().unwrap_or_default(),
        linked_requirement: form
            .fields
            .get("linked_requirement")
            .cloned()
            .unwrap_or_default(),
        file_name: saved_file.as_ref().map(|file| file.relative_path.clone()),
        supersedes_id: optional_i64_form_field(&form.fields, "supersedes_id"),
        file_sha256: saved_file
            .as_ref()
            .map(|file| file.sha256.clone())
            .unwrap_or_default(),
        valid_until: form.fields.get("valid_until").cloned(),
        retention_until: form.fields.get("retention_until").cloned(),
        retention_reason: form
            .fields
            .get("retention_reason")
            .cloned()
            .unwrap_or_default(),
        sensitivity: form
            .fields
            .get("sensitivity")
            .cloned()
            .unwrap_or_else(|| "INTERNAL".to_string()),
        status: form.fields.get("status").cloned(),
        review_notes: form.fields.get("review_notes").cloned().unwrap_or_default(),
    };

    match store
        .create_evidence_item(context.tenant_id, context.user_id, payload)
        .await
    {
        Ok(item) => {
            record_incident_evidence_event(&state, context.tenant_id, context.user_id, &item).await;
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
            let payload_error = evidence_upload_payload_error(&err);
            let status = if payload_error {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            let message = if payload_error {
                "Evidence-Verknuepfung ist ungueltig oder fuer diesen Tenant nicht verfuegbar."
                    .to_string()
            } else {
                format!("Evidence konnte nicht erstellt werden: {err}")
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
                    message,
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

async fn management_review_packages(State(state): State<AppState>, headers: HeaderMap) -> Response {
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
    match store.list_management_reviews(context.tenant_id, 50).await {
        Ok(packages) => (
            StatusCode::OK,
            Json(ManagementReviewPackagesResponse {
                api_version: "v1",
                tenant_id: context.tenant_id,
                packages,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Management-Reviews konnten nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn management_review_generate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<report_store::ManagementReviewGenerateRequest>,
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
    match store
        .generate_management_review(context.tenant_id, context.user_id, payload)
        .await
    {
        Ok(package) => (
            StatusCode::CREATED,
            Json(ManagementReviewPackageWriteResponse {
                accepted: true,
                api_version: "v1",
                package,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Management-Review konnte nicht erzeugt werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn management_review_detail(
    Path(review_id): Path<i64>,
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
    match store
        .management_review_detail(context.tenant_id, review_id)
        .await
    {
        Ok(Some(package)) => (
            StatusCode::OK,
            Json(ManagementReviewPackageResponse {
                api_version: "v1",
                package,
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "management_review_not_found",
                message: format!("Management-Review {} wurde nicht gefunden.", review_id),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Management-Review konnte nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn management_review_status_update(
    Path(review_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<report_store::ManagementReviewStatusUpdateRequest>,
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
    match store
        .update_management_review_status(context.tenant_id, context.user_id, review_id, payload)
        .await
    {
        Ok(Some(package)) => (
            StatusCode::OK,
            Json(ManagementReviewPackageWriteResponse {
                accepted: true,
                api_version: "v1",
                package,
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "management_review_not_found",
                message: format!("Management-Review {} wurde nicht gefunden.", review_id),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "management_review_invalid",
                message: format!("Management-Review konnte nicht aktualisiert werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn management_review_export_markdown(
    Path(review_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    management_review_export_format(
        review_id,
        state,
        headers,
        ManagementReviewExportFormat::Markdown,
    )
    .await
}

async fn management_review_export_html(
    Path(review_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    management_review_export_format(
        review_id,
        state,
        headers,
        ManagementReviewExportFormat::Html,
    )
    .await
}

async fn management_review_export_pdf(
    Path(review_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    management_review_export_format(review_id, state, headers, ManagementReviewExportFormat::Pdf)
        .await
}

async fn management_review_export_json(
    Path(review_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    management_review_export_format(
        review_id,
        state,
        headers,
        ManagementReviewExportFormat::Json,
    )
    .await
}

async fn management_review_export_format(
    review_id: i64,
    state: AppState,
    headers: HeaderMap,
    export_format: ManagementReviewExportFormat,
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
    match store
        .management_review_detail(context.tenant_id, review_id)
        .await
    {
        Ok(Some(package)) => management_review_export_download_response(&package, export_format),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "management_review_not_found",
                message: format!("Management-Review {} wurde nicht gefunden.", review_id),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("Management-Review-Export konnte nicht erstellt werden: {err}"),
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

async fn control_library(State(state): State<AppState>, headers: HeaderMap) -> Response {
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

    let Some(store) = state.control_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Control-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };

    match store.library(context.tenant_id).await {
        Ok(library) => (
            StatusCode::OK,
            Json(ControlLibraryResponse {
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
                message: format!("Control Library konnte nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn control_status_update(
    Path(control_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<control_store::ControlStatusUpdateRequest>,
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
    let Some(store) = state.control_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Control-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };
    match store
        .update_status(context.tenant_id, context.user_id, control_id, payload)
        .await
    {
        Ok(Some(result)) => (
            StatusCode::OK,
            Json(ControlStatusUpdateResponse {
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
                error_code: "control_not_found",
                message: format!("ISCY-Control '{}' wurde nicht gefunden.", control_id),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "invalid_control_status",
                message: format!("Control-Status konnte nicht aktualisiert werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn control_roadmap_generate(State(state): State<AppState>, headers: HeaderMap) -> Response {
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
    let Some(store) = state.control_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_not_configured",
                message: "Rust-Control-Store ist nicht konfiguriert.".to_string(),
            }),
        )
            .into_response();
    };
    match store.generate_roadmap_from_gaps(context.tenant_id).await {
        Ok(result) => (
            StatusCode::CREATED,
            Json(ControlRoadmapGenerationResponse {
                accepted: true,
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
                message: format!("ISCY-27 Gap-Roadmap konnte nicht erzeugt werden: {err}"),
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
            "ISCY-27 Controls",
            &web_path_with_context("/controls/", context.as_ref()),
            "Steuerungskern und Crosswalk",
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
    let Some(store) = state.auth_store.clone() else {
        return web_page(
            "Login",
            "/login/",
            None,
            r#"<section class="panel form-panel error"><h1>Login</h1><p>Rust-Auth-Store ist nicht konfiguriert.</p></section>"#,
        )
        .into_response();
    };
    let login_key = login_rate_limit_key(form.tenant_id, &form.username);
    if let Some(remaining) = login_rate_limit_remaining_block(&state, &login_key).await {
        return web_page(
            "Login",
            "/login/",
            None,
            &format!(
                r#"<section class="panel form-panel error"><h1>Login</h1><p>Zu viele fehlgeschlagene Login-Versuche. Bitte in {} Sekunden erneut versuchen.</p></section>"#,
                remaining.as_secs().max(1)
            ),
        )
        .into_response();
    }
    match store
        .create_session_for_login(form.tenant_id, &form.username, &form.password)
        .await
    {
        Ok(Some(session)) => {
            login_rate_limit_record_success(&state, &login_key).await;
            redirect_with_cookie(
                "/dashboard/",
                &session_cookie_value(&session.token, &state.security_config),
            )
        }
        Ok(None) => {
            login_rate_limit_record_failure(&state, &login_key, form.tenant_id, &form.username)
                .await;
            web_page(
                "Login",
                "/login/",
                None,
                r#"<section class="panel form-panel error"><h1>Login</h1><p>Benutzername oder Passwort ist nicht gueltig.</p></section>"#,
            )
            .into_response()
        }
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
            let unassessed_incident_href =
                web_path_with_context("/incidents/?incident_filter=unassessed", Some(&context));
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
                metric_link_card(
                    "Erheblichkeit offen",
                    summary.unassessed_incident_count,
                    &unassessed_incident_href,
                ),
                latest_report,
            );
            web_page("Dashboard", "/dashboard/", Some(&context), &body)
        }
        Err(err) => web_error_page("Dashboard", "/dashboard/", &context, &err.to_string()),
    }
}

async fn web_zero_trust(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
        return web_missing_context("Zero Trust", "/zero-trust/");
    };
    let Some(store) = state.agent_store else {
        return web_store_missing("Zero Trust", "/zero-trust/", &context, "Agent");
    };
    match store.posture_overview(context.tenant_id).await {
        Ok(posture) => {
            let pillar_rows = posture
                .pillar_scores
                .iter()
                .map(|pillar| {
                    format!(
                        r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                        html_escape(&pillar.pillar),
                        score_badge(pillar.score),
                        pillar.open_finding_count,
                        pillar.critical_finding_count,
                        pillar.high_finding_count,
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let device_rows = posture
                .recent_devices
                .iter()
                .map(|device| {
                    format!(
                        r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                        html_escape(&device.hostname),
                        html_escape(&device.os_family),
                        html_escape(&device.agent_version),
                        score_badge(device.zero_trust_score),
                        device.open_finding_count,
                        html_escape(device.last_seen_at.as_deref().unwrap_or("-")),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let finding_rows = posture
                .open_findings
                .iter()
                .map(|finding| {
                    format!(
                        r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                        html_escape(finding.hostname.as_deref().unwrap_or("-")),
                        html_escape(&finding.pillar),
                        severity_badge(&finding.severity, &finding.severity_label),
                        html_escape(&finding.title),
                        html_escape(&finding.recommendation),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let catalog_rows = posture
                .check_catalog
                .iter()
                .map(|check| {
                    format!(
                        r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                        html_escape(&check.check_id),
                        html_escape(&check.pillar),
                        html_escape(&check.platform_scope),
                        severity_badge(&check.severity, &check.severity),
                        yes_no_badge(check.enabled),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let priority_title = zero_trust_priority_title(&posture);
            let priority_detail = zero_trust_priority_detail(&posture);
            let body = format!(
                r#"
                <section class="hero compact"><h1>Zero Trust</h1><p>Tenant {}</p></section>
                <section class="zt-focus">
                  <article class="panel zt-score">
                    <span class="eyebrow">Zero-Trust-Reife</span>
                    <strong class="{}">{}</strong>
                    {}
                  </article>
                  <article class="panel zt-priority">
                    <span class="eyebrow">Naechster Fokus</span>
                    <h2>{}</h2>
                    <p>{}</p>
                  </article>
                </section>
                <section class="metrics">
                  {}
                  {}
                  {}
                  {}
                  {}
                </section>
                <section class="grid">
                  <article class="panel wide">
                    <h2>Pillars</h2>
                    <table>
                      <thead><tr><th>Pillar</th><th>Score</th><th>Offen</th><th>Kritisch</th><th>Hoch</th></tr></thead>
                      <tbody>{}</tbody>
                    </table>
                  </article>
                  <article class="panel wide">
                    <h2>Devices</h2>
                    <table>
                      <thead><tr><th>Hostname</th><th>OS</th><th>Agent</th><th>Score</th><th>Offen</th><th>Last seen</th></tr></thead>
                      <tbody>{}</tbody>
                    </table>
                  </article>
                  <article class="panel wide">
                    <h2>Open Findings</h2>
                    <table>
                      <thead><tr><th>Device</th><th>Pillar</th><th>Severity</th><th>Titel</th><th>Empfehlung</th></tr></thead>
                      <tbody>{}</tbody>
                    </table>
                  </article>
                  <article class="panel wide">
                    <h2>Check Catalog</h2>
                    <table>
                      <thead><tr><th>Check</th><th>Pillar</th><th>Plattformen</th><th>Severity</th><th>Aktiv</th></tr></thead>
                      <tbody>{}</tbody>
                    </table>
                  </article>
                </section>
                "#,
                context.tenant_id,
                score_text_class(posture.average_zero_trust_score),
                posture.average_zero_trust_score,
                score_band_badge(posture.average_zero_trust_score),
                html_escape(&priority_title),
                html_escape(&priority_detail),
                metric_card("ZT Score", posture.average_zero_trust_score),
                metric_card("Devices", posture.device_count),
                metric_card("Aktiv", posture.active_device_count),
                metric_card("Offene Findings", posture.open_finding_count),
                metric_card(
                    "Kritisch/Hoch",
                    posture.critical_finding_count + posture.high_finding_count
                ),
                if pillar_rows.is_empty() {
                    web_empty_row(5, "Keine offenen Pillar-Findings.")
                } else {
                    pillar_rows
                },
                if device_rows.is_empty() {
                    web_empty_row(6, "Keine Agent-Devices vorhanden.")
                } else {
                    device_rows
                },
                if finding_rows.is_empty() {
                    web_empty_row(5, "Keine offenen Findings.")
                } else {
                    finding_rows
                },
                if catalog_rows.is_empty() {
                    web_empty_row(5, "Kein Check-Katalog vorhanden.")
                } else {
                    catalog_rows
                },
            );
            web_page("Zero Trust", "/zero-trust/", Some(&context), &body)
        }
        Err(err) => web_error_page("Zero Trust", "/zero-trust/", &context, &err.to_string()),
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
    let can_write = authenticated_tenant_context(&state, &headers)
        .await
        .is_ok_and(|auth_context| auth_context.can_write());
    let Some(store) = state.risk_store else {
        return web_store_missing("Risks", "/risks/", &context, "Risk");
    };
    match store.list_risks(context.tenant_id, 50).await {
        Ok(risks) => {
            let rows = risks
                .iter()
                .map(|risk| {
                    let linked_requirement =
                        evidence_key_from_text(&risk.treatment_plan)
                            .unwrap_or_else(|| format!("RISK:{}", risk.id));
                    let evidence_href = evidence_prefill_href(
                        &context,
                        &format!("Risk-Evidence: {}", risk.title),
                        &format!(
                            "Nachweis zum Risiko {}. Threat: {}. Vulnerability: {}. Treatment: {}.",
                            risk.title, risk.threat, risk.vulnerability, risk.treatment_plan
                        ),
                        &linked_requirement,
                        Some("SUBMITTED"),
                        Some(&web_path_with_context("/risks/", Some(&context))),
                    );
                    let review_actions = if can_write {
                        let action = web_path_with_context(
                            &format!("/risks/{}/review", risk.id),
                            Some(&context),
                        );
                        format!(
                            r#"<form method="post" action="{}" class="inline-form">
                                <input type="hidden" name="action" value="approve_treatment">
                                <input type="hidden" name="review_notes" value="Treatment im Risk-Review freigegeben.">
                                <button type="submit">Behandlung</button>
                              </form>
                              <form method="post" action="{}" class="inline-form">
                                <input type="hidden" name="action" value="accept_risk">
                                <input type="hidden" name="review_notes" value="Restrisiko fachlich akzeptiert.">
                                <button type="submit">Akzeptieren</button>
                              </form>
                              <form method="post" action="{}" class="inline-form">
                                <input type="hidden" name="action" value="mark_mitigated">
                                <input type="hidden" name="review_notes" value="Massnahme umgesetzt und Risiko mitigiert.">
                                <button type="submit">Mitigiert</button>
                              </form>"#,
                            action, action, action,
                        )
                    } else {
                        "-".to_string()
                    };
                    format!(
                        r#"<tr><td><a href="{}">{}</a></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><a href="{}">Evidence</a></td><td>{}</td></tr>"#,
                        web_path_with_context(&format!("/api/v1/risks/{}", risk.id), Some(&context)),
                        html_escape(&risk.title),
                        risk.score,
                        html_escape(&risk.risk_level_label),
                        html_escape(&risk.status_label),
                        html_escape(risk.owner_display.as_deref().unwrap_or("-")),
                        evidence_href,
                        review_actions,
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let body = format!(
                r#"
                <section class="hero compact"><h1>Risks</h1><p>{} Risiken</p></section>
                <section class="panel wide">
                  <table>
                    <thead><tr><th>Titel</th><th>Score</th><th>Level</th><th>Status</th><th>Owner</th><th>Evidence</th><th>Review</th></tr></thead>
                    <tbody>{}</tbody>
                  </table>
                </section>
                "#,
                risks.len(),
                if rows.is_empty() {
                    r#"<tr><td colspan="7">Keine Risiken vorhanden.</td></tr>"#.to_string()
                } else {
                    rows
                },
            );
            web_page("Risks", "/risks/", Some(&context), &body)
        }
        Err(err) => web_error_page("Risks", "/risks/", &context, &err.to_string()),
    }
}

async fn web_risk_review_submit(
    Path(risk_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<WebRiskReviewForm>,
) -> Response {
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(_) => return web_missing_context("Risks", "/risks/").into_response(),
    };
    let context = WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    };
    if !auth_context.can_write() {
        return web_error_page(
            "Risks",
            "/risks/",
            &context,
            "Diese Rust-Webroute benoetigt eine schreibende ISCY-Rolle.",
        )
        .into_response();
    }
    let Some(store) = state.risk_store else {
        return web_store_missing("Risks", "/risks/", &context, "Risk").into_response();
    };
    let payload = risk_store::RiskReviewRequest {
        action: form.action,
        review_notes: form.review_notes,
    };
    match store
        .review_risk(
            auth_context.tenant_id,
            risk_id,
            auth_context.user_id,
            payload,
        )
        .await
    {
        Ok(Some(_)) => {
            Redirect::to(&web_path_with_context("/risks/", Some(&context))).into_response()
        }
        Ok(None) => web_error_page(
            "Risks",
            "/risks/",
            &context,
            "Risiko wurde fuer diesen Tenant nicht gefunden.",
        )
        .into_response(),
        Err(err) => web_error_page("Risks", "/risks/", &context, &err.to_string()).into_response(),
    }
}

async fn web_incidents(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
        return web_missing_context("Incidents", "/incidents/");
    };
    let Some(store) = state.incident_store.clone() else {
        return web_store_missing("Incidents", "/incidents/", &context, "Incident");
    };
    let can_write = authenticated_tenant_context(&state, &headers)
        .await
        .is_ok_and(|auth_context| auth_context.can_write());
    match store.list_incidents(context.tenant_id, 50).await {
        Ok(all_incidents) => {
            let incident_filter =
                normalize_incident_register_filter(query.incident_filter.as_deref());
            let incidents = filter_incident_register_rows(&all_incidents, incident_filter.as_str());
            let runbook_templates = store
                .list_runbook_templates(context.tenant_id, 25)
                .await
                .unwrap_or_default();
            let reportable_count = all_incidents
                .iter()
                .filter(|incident| incident.nis2_reportable)
                .count() as i64;
            let open_count = all_incidents
                .iter()
                .filter(|incident| !matches!(incident.status.as_str(), "RESOLVED" | "CLOSED"))
                .count() as i64;
            let overdue_count = all_incidents
                .iter()
                .filter(|incident| {
                    matches!(incident.early_warning_state.as_str(), "OVERDUE")
                        || matches!(incident.notification_state.as_str(), "OVERDUE")
                        || matches!(incident.final_report_state.as_str(), "OVERDUE")
                })
                .count() as i64;
            let unassessed_count = all_incidents
                .iter()
                .filter(|incident| {
                    incident.nis2_significance_status == "NOT_ASSESSED"
                        && !matches!(incident.status.as_str(), "RESOLVED" | "CLOSED")
                })
                .count() as i64;
            let filter_links = incident_register_filter_links(&context, incident_filter.as_str());
            let rows = incidents
                .iter()
                .map(|incident| {
                    format!(
                        r#"<tr><td><a href="{}">{}</a><p>{}</p></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                        web_path_with_context(
                            &format!("/incidents/{}", incident.id),
                            Some(&context)
                        ),
                        html_escape(&incident.title),
                        html_escape(&incident.summary),
                        html_escape(&incident.incident_type_label),
                        html_escape(&incident.severity_label),
                        html_escape(&incident.status_label),
                        html_escape(&incident.nis2_significance_label),
                        html_escape(&incident.nis2_reportability_label),
                        html_escape(&incident.early_warning_state_label),
                        html_escape(&incident.notification_state_label),
                        html_escape(incident.owner_display.as_deref().unwrap_or("-")),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let form_panel = if can_write {
                format!(
                    r#"
                    <article class="panel wide">
                      <h2>Incident erfassen</h2>
                      <form method="post" action="{}">
                        <div class="form-grid">
                          <label>Titel<input name="title" type="text" required></label>
                          <label>Typ<select name="incident_type">{}</select></label>
                          <label>Severity<select name="severity">{}</select></label>
                          <label>Status<select name="status">{}</select></label>
                          <label>Runbook-Vorlage<select name="runbook_template">{}</select></label>
                          <label>Owner-ID<input name="owner_id" type="number" min="1"></label>
                          <label>Reporter-ID<input name="reporter_id" type="number" min="1"></label>
                          <label>Risk-ID<input name="related_risk_id" type="number" min="1"></label>
                          <label>Asset-ID<input name="related_asset_id" type="number" min="1"></label>
                          <label>Process-ID<input name="related_process_id" type="number" min="1"></label>
                          <label>Erkannt am<input name="detected_at" type="date"></label>
                        </div>
                        <label>NIS2-Erheblichkeitsstatus<select name="nis2_significance_status">{}</select></label>
                        <label>Kriterien nach NIS2 Art. 23 / EU 2024/2690<textarea name="nis2_significance_criteria" rows="4" placeholder="z.B. erhebliche Betriebsstoerung, finanzieller Schaden, betroffene Personen, malicious unauthorized access, wiederholte Incidents mit gleicher Root Cause"></textarea></label>
                        <label>Begruendung der Entscheidung<textarea name="nis2_significance_justification" rows="3" placeholder="Warum ist der Incident erheblich, wahrscheinlich erheblich oder nicht erheblich?"></textarea></label>
                        <label>Kurzbeschreibung<textarea name="summary" rows="4"></textarea></label>
                        <label>Stakeholder-Zusammenfassung<textarea name="stakeholder_summary" rows="3"></textarea></label>
                        <label>Behoerden-/Case-Referenz<input name="authority_reference" type="text"></label>
                        <button type="submit">Incident anlegen</button>
                      </form>
                    </article>
                    "#,
                    web_path_with_context("/incidents/", Some(&context)),
                    incident_type_options_for("GENERAL"),
                    incident_severity_options_for("HIGH"),
                    incident_status_options_for("TRIAGE"),
                    incident_runbook_template_options(&runbook_templates, None),
                    incident_nis2_significance_options_for("NOT_ASSESSED"),
                )
            } else {
                r#"<article class="panel wide"><h2>Incident erfassen</h2><p>Fuer neue Incidents ist eine schreibende ISCY-Rolle notwendig.</p></article>"#.to_string()
            };
            let runbook_template_href =
                web_path_with_context("/incidents/runbook-templates/", Some(&context));
            let body = format!(
                r#"
                <section class="hero compact"><h1>Incidents</h1><p>NIS2-Fallakte, Meldefristen und Nachverfolgung</p></section>
                <p><a href="{}">Runbook-Templates verwalten</a></p>
                <section class="metrics">
                  {}
                  {}
                  {}
                  {}
                </section>
                <section class="grid">
                  <article class="panel wide">
                    {}
                    <table>
                      <thead><tr><th>Incident</th><th>Typ</th><th>Severity</th><th>Status</th><th>Erheblichkeit</th><th>NIS2</th><th>24h</th><th>72h</th><th>Owner</th></tr></thead>
                      <tbody>{}</tbody>
                    </table>
                  </article>
                  {}
                </section>
                "#,
                html_escape(&runbook_template_href),
                metric_card("Offen", open_count),
                metric_card("NIS2", reportable_count),
                metric_card("Ueberfaellig", overdue_count),
                metric_card("Erheblichkeit offen", unassessed_count),
                filter_links,
                if rows.is_empty() {
                    web_empty_row(9, "Keine Incidents vorhanden.")
                } else {
                    rows
                },
                form_panel,
            );
            web_page("Incidents", "/incidents/", Some(&context), &body)
        }
        Err(err) => web_error_page("Incidents", "/incidents/", &context, &err.to_string()),
    }
}

async fn web_operations_incidents(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
        return web_missing_context("Alert Operations", "/operations/incidents/");
    };
    let Some(store) = state.incident_store.clone() else {
        return web_store_missing(
            "Alert Operations",
            "/operations/incidents/",
            &context,
            "Incident",
        );
    };
    match store.list_incidents(context.tenant_id, 200).await {
        Ok(incidents) => {
            let require_resolution_review = alertmanager_resolution_review_required();
            let active_filter = alert_operations_filter(query.alert_filter.as_deref());
            let alert_incidents = incidents
                .iter()
                .filter(|incident| incident.authority_reference.starts_with("Alertmanager:"))
                .collect::<Vec<_>>();
            let total_count = alert_incidents.len() as i64;
            let open_count = alert_incidents
                .iter()
                .filter(|incident| !matches!(incident.status.as_str(), "RESOLVED" | "CLOSED"))
                .count() as i64;
            let triage_count = alert_incidents
                .iter()
                .filter(|incident| incident.status == "TRIAGE")
                .count() as i64;
            let critical_open_count = alert_incidents
                .iter()
                .filter(|incident| {
                    incident.severity == "CRITICAL"
                        && !matches!(incident.status.as_str(), "RESOLVED" | "CLOSED")
                })
                .count() as i64;
            let resolved_count = alert_incidents
                .iter()
                .filter(|incident| matches!(incident.status.as_str(), "RESOLVED" | "CLOSED"))
                .count() as i64;
            let review_required_count = alert_incidents
                .iter()
                .filter(|incident| {
                    alertmanager_resolution_review_required_for_incident(
                        incident,
                        require_resolution_review,
                    )
                })
                .count() as i64;
            let filter_links = alert_operations_filter_links(
                &context,
                active_filter,
                total_count,
                open_count,
                critical_open_count,
                resolved_count,
            );
            let rows = alert_incidents
                .iter()
                .filter(|incident| alert_operations_filter_matches(incident, active_filter))
                .take(75)
                .map(|incident| {
                    let detail_href =
                        web_path_with_context(&format!("/incidents/{}", incident.id), Some(&context));
                    format!(
                        r#"<tr><td><a href="{}">{}</a><p>{}</p><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                        detail_href,
                        html_escape(&incident.title),
                        html_escape(&incident.summary),
                        html_escape(&incident.authority_reference),
                        incident_severity_badge(&incident.severity, &incident.severity_label),
                        incident_status_badge(&incident.status, &incident.status_label),
                        alertmanager_resolution_review_badge(incident, require_resolution_review),
                        html_escape(incident.detected_at.as_deref().unwrap_or("-")),
                        html_escape(incident.resolved_at.as_deref().unwrap_or("-")),
                        html_escape(incident.owner_display.as_deref().unwrap_or("-")),
                        html_escape(&incident.updated_at),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let body = format!(
                r#"
                <section class="hero compact"><h1>Alert Operations</h1><p>Alertmanager-Fallakten, Deduplizierung und resolved Cutover im Rust-only-Betrieb.</p></section>
                <section class="metrics">
                  {}
                  {}
                  {}
                  {}
                  {}
                  {}
                </section>
                <section class="grid">
                  {}
                  {}
                  <article class="panel wide">
                    <h2>Alertmanager-Fallakten</h2>
                    {}
                    <table>
                      <thead><tr><th>Fallakte</th><th>Severity</th><th>Status</th><th>Abschluss</th><th>Erkannt</th><th>Resolved</th><th>Owner</th><th>Aktualisiert</th></tr></thead>
                      <tbody>{}</tbody>
                    </table>
                  </article>
                </section>
                "#,
                metric_card("Alert-Faelle", total_count),
                metric_card("Offen", open_count),
                metric_card("Triage", triage_count),
                metric_card("Kritisch offen", critical_open_count),
                metric_card("Resolved", resolved_count),
                metric_card("Review Pflicht", review_required_count),
                web_link_card(
                    "Incident-Fallakten",
                    &web_path_with_context("/incidents/", Some(&context)),
                    "Vollstaendige Bearbeitung, Runbooks, Evidence und NIS2-Pakete",
                ),
                web_link_card(
                    "Operations JSON",
                    &web_path_with_context("/status/operations.json", Some(&context)),
                    "Maschinenlesbarer Drilldown fuer Monitoring und Agenten",
                ),
                filter_links,
                if rows.is_empty() {
                    web_empty_row(
                        8,
                        "Keine Alertmanager-Fallakten fuer diesen Filter vorhanden.",
                    )
                } else {
                    rows
                },
            );
            web_page(
                "Alert Operations",
                "/operations/incidents/",
                Some(&context),
                &body,
            )
        }
        Err(err) => web_error_page(
            "Alert Operations",
            "/operations/incidents/",
            &context,
            &err.to_string(),
        ),
    }
}

fn alert_operations_filter(value: Option<&str>) -> &'static str {
    match value.unwrap_or_default().trim() {
        "open" => "open",
        "critical" => "critical",
        "resolved" => "resolved",
        _ => "all",
    }
}

fn alert_operations_filter_matches(
    incident: &incident_store::IncidentSummary,
    filter: &str,
) -> bool {
    match alert_operations_filter(Some(filter)) {
        "open" => !matches!(incident.status.as_str(), "RESOLVED" | "CLOSED"),
        "critical" => {
            incident.severity == "CRITICAL"
                && !matches!(incident.status.as_str(), "RESOLVED" | "CLOSED")
        }
        "resolved" => matches!(incident.status.as_str(), "RESOLVED" | "CLOSED"),
        _ => true,
    }
}

fn alert_operations_filter_path(context: &WebContext, filter: &str) -> String {
    match alert_operations_filter(Some(filter)) {
        "all" => web_path_with_context("/operations/incidents/", Some(context)),
        normalized => web_path_with_context(
            &format!("/operations/incidents/?alert_filter={normalized}"),
            Some(context),
        ),
    }
}

fn alert_operations_filter_links(
    context: &WebContext,
    active_filter: &str,
    all_count: i64,
    open_count: i64,
    critical_count: i64,
    resolved_count: i64,
) -> String {
    let links = [
        ("all", "Alle", all_count),
        ("open", "Open", open_count),
        ("critical", "Critical", critical_count),
        ("resolved", "Resolved", resolved_count),
    ]
    .iter()
    .map(|(filter, label, count)| {
        let active = alert_operations_filter(Some(active_filter)) == *filter;
        format!(
            r#"<a href="{}"{}>{} ({})</a>"#,
            alert_operations_filter_path(context, filter),
            if active { r#" class="active""# } else { "" },
            html_escape(label),
            count,
        )
    })
    .collect::<Vec<_>>()
    .join(" ");
    format!(r#"<div class="filter-links">{links}</div>"#)
}

fn alertmanager_resolution_review_badge(
    incident: &incident_store::IncidentSummary,
    require_resolution_review: bool,
) -> String {
    if alertmanager_resolution_review_required_for_incident(incident, require_resolution_review) {
        return web_badge("Root Cause fehlt", "warn");
    }
    if matches!(incident.status.as_str(), "RESOLVED" | "CLOSED") {
        return web_badge("Abgeschlossen", "ok");
    }
    web_badge("In Arbeit", "info")
}

async fn web_incidents_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<WebIncidentForm>,
) -> Response {
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(_) => return web_missing_context("Incidents", "/incidents/").into_response(),
    };
    let context = WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    };
    if !auth_context.can_write() {
        return web_error_page(
            "Incidents",
            "/incidents/",
            &context,
            "Diese Rust-Webroute benoetigt eine schreibende ISCY-Rolle.",
        )
        .into_response();
    }
    let Some(store) = state.incident_store else {
        return web_store_missing("Incidents", "/incidents/", &context, "Incident").into_response();
    };
    let payload = match web_incident_form_request(form) {
        Ok(payload) => payload,
        Err(message) => {
            return web_error_page("Incidents", "/incidents/", &context, &message).into_response()
        }
    };
    match store
        .create_incident(auth_context.tenant_id, Some(auth_context.user_id), payload)
        .await
    {
        Ok(_) => {
            Redirect::to(&web_path_with_context("/incidents/", Some(&context))).into_response()
        }
        Err(err) => {
            web_error_page("Incidents", "/incidents/", &context, &err.to_string()).into_response()
        }
    }
}

async fn web_incident_runbook_templates(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
        return web_missing_context("Runbook-Templates", "/incidents/runbook-templates/");
    };
    let Some(store) = state.incident_store.clone() else {
        return web_store_missing(
            "Runbook-Templates",
            "/incidents/runbook-templates/",
            &context,
            "Incident",
        );
    };
    let can_write = authenticated_tenant_context(&state, &headers)
        .await
        .is_ok_and(|auth_context| auth_context.can_write());
    match store
        .list_runbook_templates_admin(context.tenant_id, 200)
        .await
    {
        Ok(templates) => {
            let rows = incident_runbook_template_admin_rows(&context, &templates, can_write);
            let create_panel = incident_runbook_template_create_panel(&context, can_write);
            let body = format!(
                r#"
                <section class="hero compact"><h1>Runbook-Templates</h1><p>Incident-Vorlagen fuer Fallakten und abhakbare Aufgaben</p></section>
                <section class="grid">
                  <article class="panel wide">
                    <h2>Template-Bibliothek</h2>
                    <table>
                      <thead><tr><th>Vorlage</th><th>Status</th><th>Typ</th><th>Severity</th><th>Reihenfolge</th><th>Aktion</th></tr></thead>
                      <tbody>{}</tbody>
                    </table>
                  </article>
                  {}
                </section>
                "#,
                rows, create_panel,
            );
            web_page("Runbook-Templates", "/incidents/", Some(&context), &body)
        }
        Err(err) => web_error_page(
            "Runbook-Templates",
            "/incidents/runbook-templates/",
            &context,
            &err.to_string(),
        ),
    }
}

async fn web_incident_runbook_templates_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<WebIncidentRunbookTemplateForm>,
) -> Response {
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(_) => {
            return web_missing_context("Runbook-Templates", "/incidents/runbook-templates/")
                .into_response()
        }
    };
    let context = WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    };
    if !auth_context.can_write() {
        return web_error_page(
            "Runbook-Templates",
            "/incidents/runbook-templates/",
            &context,
            "Diese Rust-Webroute benoetigt eine schreibende ISCY-Rolle.",
        )
        .into_response();
    }
    let Some(store) = state.incident_store else {
        return web_store_missing(
            "Runbook-Templates",
            "/incidents/runbook-templates/",
            &context,
            "Incident",
        )
        .into_response();
    };
    let payload = match web_runbook_template_form_request(form) {
        Ok(payload) => payload,
        Err(message) => {
            return web_error_page(
                "Runbook-Templates",
                "/incidents/runbook-templates/",
                &context,
                &message,
            )
            .into_response()
        }
    };
    match store
        .create_runbook_template(auth_context.tenant_id, payload)
        .await
    {
        Ok(_) => Redirect::to(&web_path_with_context(
            "/incidents/runbook-templates/",
            Some(&context),
        ))
        .into_response(),
        Err(err) => web_error_page(
            "Runbook-Templates",
            "/incidents/runbook-templates/",
            &context,
            &err.to_string(),
        )
        .into_response(),
    }
}

async fn web_incident_runbook_template_update(
    Path(template_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<WebIncidentRunbookTemplateForm>,
) -> Response {
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(_) => {
            return web_missing_context("Runbook-Templates", "/incidents/runbook-templates/")
                .into_response()
        }
    };
    let context = WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    };
    if !auth_context.can_write() {
        return web_error_page(
            "Runbook-Templates",
            "/incidents/runbook-templates/",
            &context,
            "Diese Rust-Webroute benoetigt eine schreibende ISCY-Rolle.",
        )
        .into_response();
    }
    let Some(store) = state.incident_store else {
        return web_store_missing(
            "Runbook-Templates",
            "/incidents/runbook-templates/",
            &context,
            "Incident",
        )
        .into_response();
    };
    let action = form
        .action
        .as_deref()
        .unwrap_or("update")
        .trim()
        .to_ascii_lowercase();
    let result = if action == "delete" || action == "deactivate" {
        store
            .deactivate_runbook_template(auth_context.tenant_id, template_id)
            .await
    } else {
        match web_runbook_template_form_request(form) {
            Ok(payload) => {
                store
                    .update_runbook_template(auth_context.tenant_id, template_id, payload)
                    .await
            }
            Err(message) => {
                return web_error_page(
                    "Runbook-Templates",
                    "/incidents/runbook-templates/",
                    &context,
                    &message,
                )
                .into_response()
            }
        }
    };
    match result {
        Ok(Some(_)) => Redirect::to(&web_path_with_context(
            "/incidents/runbook-templates/",
            Some(&context),
        ))
        .into_response(),
        Ok(None) => web_error_page(
            "Runbook-Templates",
            "/incidents/runbook-templates/",
            &context,
            &format!("Runbook-Template {} wurde nicht gefunden.", template_id),
        )
        .into_response(),
        Err(err) => web_error_page(
            "Runbook-Templates",
            "/incidents/runbook-templates/",
            &context,
            &err.to_string(),
        )
        .into_response(),
    }
}

async fn web_incident_detail(
    Path(incident_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
        return web_missing_context("Incidents", "/incidents/");
    };
    let Some(store) = state.incident_store.clone() else {
        return web_store_missing("Incidents", "/incidents/", &context, "Incident");
    };
    let can_write = authenticated_tenant_context(&state, &headers)
        .await
        .is_ok_and(|auth_context| auth_context.can_write());
    match store.incident_detail(context.tenant_id, incident_id).await {
        Ok(Some(incident)) => {
            let related_risk = incident.related_risk_title.as_deref().unwrap_or("-");
            let related_asset = incident.related_asset_name.as_deref().unwrap_or("-");
            let related_process = incident.related_process_name.as_deref().unwrap_or("-");
            let owner = incident.owner_display.as_deref().unwrap_or("-");
            let reporter = incident.reporter_display.as_deref().unwrap_or("-");
            let evidence_items =
                incident_linked_evidence(&state, context.tenant_id, incident.id).await;
            let evidence_rows = incident_evidence_rows(&evidence_items);
            let timeline_events = store
                .list_incident_events(context.tenant_id, incident.id, 30)
                .await
                .unwrap_or_default();
            let timeline_filter = normalize_incident_timeline_filter(query.timeline.as_deref());
            let filtered_timeline_events =
                filter_incident_events(&timeline_events, timeline_filter.as_str());
            let timeline_rows = incident_event_rows_for_web(
                &filtered_timeline_events,
                &context,
                incident.id,
                can_write,
            );
            let timeline_filter_links =
                incident_timeline_filter_links(&context, incident.id, timeline_filter.as_str());
            let timeline_note_panel =
                incident_timeline_note_panel(&context, incident.id, can_write);
            let runbook_templates = store
                .list_runbook_templates(context.tenant_id, 25)
                .await
                .unwrap_or_default();
            let runbook_template_rows = incident_runbook_template_rows(&runbook_templates);
            let runbook_steps = store
                .list_runbook_steps(context.tenant_id, incident.id)
                .await
                .unwrap_or_default();
            let runbook_step_rows =
                incident_runbook_step_rows(&context, incident.id, &runbook_steps, can_write);
            let runbook_step_count = if runbook_steps.is_empty() {
                incident_runbook_step_count(&incident.runbook_template)
            } else {
                runbook_steps.len()
            };
            let runbook_done_count = runbook_steps.iter().filter(|step| step.is_done).count();
            let evidence_upload_panel = incident_evidence_upload_panel(
                &context,
                incident.id,
                can_write,
                state.evidence_store.is_some(),
            );
            let markdown_export_href = web_path_with_context(
                &format!("/incidents/{}/nis2-export", incident.id),
                Some(&context),
            );
            let html_export_href = web_path_with_context(
                &format!("/incidents/{}/nis2-export.html", incident.id),
                Some(&context),
            );
            let pdf_export_href = web_path_with_context(
                &format!("/incidents/{}/nis2-export.pdf", incident.id),
                Some(&context),
            );
            let dora_markdown_export_href = web_path_with_context(
                &format!("/incidents/{}/dora-export", incident.id),
                Some(&context),
            );
            let dora_html_export_href = web_path_with_context(
                &format!("/incidents/{}/dora-export.html", incident.id),
                Some(&context),
            );
            let dora_pdf_export_href = web_path_with_context(
                &format!("/incidents/{}/dora-export.pdf", incident.id),
                Some(&context),
            );
            let dsgvo_markdown_export_href = web_path_with_context(
                &format!("/incidents/{}/dsgvo-export", incident.id),
                Some(&context),
            );
            let dsgvo_html_export_href = web_path_with_context(
                &format!("/incidents/{}/dsgvo-export.html", incident.id),
                Some(&context),
            );
            let dsgvo_pdf_export_href = web_path_with_context(
                &format!("/incidents/{}/dsgvo-export.pdf", incident.id),
                Some(&context),
            );
            let timeline_csv_href = web_path_with_context(
                &format!("/incidents/{}/timeline.csv", incident.id),
                Some(&context),
            );
            let timeline_json_href = web_path_with_context(
                &format!("/incidents/{}/timeline.json", incident.id),
                Some(&context),
            );
            let api_export_href = web_path_with_context(
                &format!("/api/v1/incidents/{}/nis2-export", incident.id),
                Some(&context),
            );
            let review_panel = incident_review_panel(&context, &incident, can_write);
            let edit_panel = if can_write {
                incident_edit_form_panel(&context, &incident, &runbook_templates)
            } else {
                r#"<article class="panel wide"><h2>Bearbeiten</h2><p>Fuer Aenderungen ist eine schreibende ISCY-Rolle notwendig.</p></article>"#.to_string()
            };
            let workflow_panel = incident_decision_flow_panel(
                &context,
                &incident,
                runbook_done_count,
                runbook_step_count,
                evidence_items.len(),
            );
            let case_panel = format!(
                r#"
                <article id="incident-case" class="panel wide">
                  <h2>Fallakte</h2>
                  <table>
                    <tbody>
                      <tr><th>Status</th><td>{}</td><th>Severity</th><td>{}</td></tr>
                      <tr><th>Typ</th><td>{}</td><th>Runbook</th><td>{} Schritte</td></tr>
                      <tr><th>Erheblichkeit</th><td>{}</td><th>NIS2</th><td>{}</td></tr>
                      <tr><th>Bewertet am</th><td>{}</td><th>Owner</th><td>{}</td></tr>
                      <tr><th>Reporter</th><td>{}</td><th>Behoerdenreferenz</th><td>{}</td></tr>
                      <tr><th>Risiko</th><td>{}</td><th>Asset</th><td>{}</td></tr>
                      <tr><th>Prozess</th><td>{}</td><th>Erkannt</th><td>{}</td></tr>
                      <tr><th>24h-Fruehwarnung</th><td>{} ({})</td><th>72h-Meldung</th><td>{} ({})</td></tr>
                      <tr><th>30-Tage-Bericht</th><td>{} ({})</td><th>Final gemeldet</th><td>{}</td></tr>
                      <tr><th>Meldepaket</th><td>{}</td><th>Version</th><td>{}</td></tr>
                    </tbody>
                  </table>
                </article>
                "#,
                html_escape(&incident.status_label),
                html_escape(&incident.severity_label),
                html_escape(&incident.incident_type_label),
                runbook_step_count,
                html_escape(&incident.nis2_significance_label),
                html_escape(&incident.nis2_reportability_label),
                html_escape(
                    incident
                        .nis2_significance_assessed_at
                        .as_deref()
                        .unwrap_or("-"),
                ),
                html_escape(owner),
                html_escape(reporter),
                html_escape(&incident.authority_reference),
                html_escape(related_risk),
                html_escape(related_asset),
                html_escape(related_process),
                html_escape(incident.detected_at.as_deref().unwrap_or("-")),
                html_escape(incident.early_warning_due_at.as_deref().unwrap_or("-")),
                html_escape(&incident.early_warning_state_label),
                html_escape(incident.notification_due_at.as_deref().unwrap_or("-")),
                html_escape(&incident.notification_state_label),
                html_escape(incident.final_report_due_at.as_deref().unwrap_or("-")),
                html_escape(&incident.final_report_state_label),
                html_escape(incident.final_report_sent_at.as_deref().unwrap_or("-")),
                html_escape(&incident.review_state_label),
                html_escape(&incident.report_package_version),
            );
            let significance_panel = format!(
                r#"
                <article id="incident-significance" class="panel wide">
                  <h2>NIS2-Erheblichkeitsentscheidung</h2>
                  <table>
                    <tbody>
                      <tr><th>Status</th><td>{}</td><th>NIS2</th><td>{}</td></tr>
                      <tr><th>Bewertet am</th><td>{}</td><th>Referenz</th><td>{}</td></tr>
                    </tbody>
                  </table>
                  <h3>Kriterien</h3>
                  <p>{}</p>
                  <h3>Begruendung</h3>
                  <p>{}</p>
                </article>
                "#,
                html_escape(&incident.nis2_significance_label),
                html_escape(&incident.nis2_reportability_label),
                html_escape(
                    incident
                        .nis2_significance_assessed_at
                        .as_deref()
                        .unwrap_or("-"),
                ),
                html_escape(&incident.nis2_significance_reference),
                html_escape(&incident.nis2_significance_criteria),
                html_escape(&incident.nis2_significance_justification),
            );
            let context_panel = format!(
                r#"
                <article id="incident-context" class="panel wide">
                  <h2>Beschreibung</h2>
                  <p>{}</p>
                  <h2>Stakeholder</h2>
                  <p>{}</p>
                  <h2>Lessons Learned</h2>
                  <p>{}</p>
                </article>
                "#,
                html_escape(&incident.summary),
                html_escape(&incident.stakeholder_summary),
                html_escape(&incident.lessons_learned),
            );
            let runbook_panel = format!(
                r#"
                <article id="incident-runbook" class="panel wide">
                  <h2>Runbook</h2>
                  <table>
                    <thead><tr><th>Schritt</th><th>Status</th><th>Erledigt von</th><th>Aktion</th></tr></thead>
                    <tbody>{}</tbody>
                  </table>
                  <details><summary>Vorlagentext</summary><pre>{}</pre></details>
                </article>
                "#,
                runbook_step_rows,
                html_escape(&incident.runbook_template),
            );
            let runbook_library_panel = format!(
                r#"
                <article class="panel wide">
                  <h2>Runbook-Bibliothek</h2>
                  <table>
                    <thead><tr><th>Vorlage</th><th>Typ</th><th>Severity</th><th>Beschreibung</th></tr></thead>
                    <tbody>{}</tbody>
                  </table>
                </article>
                "#,
                runbook_template_rows
            );
            let timeline_panel = format!(
                r#"
                <article id="incident-timeline" class="panel wide">
                  <h2>Timeline</h2>
                  {}
                  <table>
                    <thead><tr><th>Zeitpunkt</th><th>Ereignis</th><th>Zusammenfassung</th><th>Actor</th><th>Detail</th><th>Export</th></tr></thead>
                    <tbody>{}</tbody>
                  </table>
                  {}
                </article>
                "#,
                timeline_filter_links, timeline_rows, timeline_note_panel,
            );
            let evidence_panel = format!(
                r#"
                <article id="incident-evidence" class="panel wide">
                  <h2>Evidence</h2>
                  <table>
                    <thead><tr><th>Titel</th><th>Version</th><th>Klasse</th><th>Status</th><th>Requirement</th><th>Gueltig bis</th><th>SHA-256</th><th>Datei</th></tr></thead>
                    <tbody>{}</tbody>
                  </table>
                  {}
                </article>
                "#,
                evidence_rows, evidence_upload_panel,
            );
            let package_panel = format!(
                r#"
                <article id="incident-package" class="panel wide">
                  <h2>Meldepaket</h2>
                  <h3>NIS2</h3>
                  <p><a href="{}">NIS2 Markdown herunterladen</a></p>
                  <p><a href="{}">NIS2 HTML herunterladen</a></p>
                  <p><a href="{}">NIS2 PDF herunterladen</a></p>
                  <h3>DORA</h3>
                  <p><a href="{}">DORA Markdown herunterladen</a></p>
                  <p><a href="{}">DORA HTML herunterladen</a></p>
                  <p><a href="{}">DORA PDF herunterladen</a></p>
                  <h3>DSGVO</h3>
                  <p><a href="{}">DSGVO Markdown herunterladen</a></p>
                  <p><a href="{}">DSGVO HTML herunterladen</a></p>
                  <p><a href="{}">DSGVO PDF herunterladen</a></p>
                  <p><a href="{}">Timeline CSV herunterladen</a></p>
                  <p><a href="{}">Timeline JSON herunterladen</a></p>
                  <p><a href="{}">API-Export oeffnen</a></p>
                </article>
                "#,
                html_escape(&markdown_export_href),
                html_escape(&html_export_href),
                html_escape(&pdf_export_href),
                html_escape(&dora_markdown_export_href),
                html_escape(&dora_html_export_href),
                html_escape(&dora_pdf_export_href),
                html_escape(&dsgvo_markdown_export_href),
                html_escape(&dsgvo_html_export_href),
                html_escape(&dsgvo_pdf_export_href),
                html_escape(&timeline_csv_href),
                html_escape(&timeline_json_href),
                html_escape(&api_export_href),
            );
            let body = format!(
                r#"
                <section class="hero compact"><h1>{}</h1><p>NIS2-Fallakte und Meldepaket</p></section>
                {}
                <section class="grid">
                  {}
                  {}
                  {}
                  {}
                  {}
                  {}
                  {}
                  {}
                  {}
                  <div id="incident-edit" class="wide-anchor">{}</div>
                </section>
                "#,
                html_escape(&incident.title),
                workflow_panel,
                case_panel,
                significance_panel,
                context_panel,
                review_panel,
                runbook_panel,
                runbook_library_panel,
                timeline_panel,
                evidence_panel,
                package_panel,
                edit_panel,
            );
            web_page("Incidents", "/incidents/", Some(&context), &body)
        }
        Ok(None) => web_error_page(
            "Incidents",
            "/incidents/",
            &context,
            &format!("Incident {} wurde nicht gefunden.", incident_id),
        ),
        Err(err) => web_error_page("Incidents", "/incidents/", &context, &err.to_string()),
    }
}

async fn web_incident_detail_submit(
    Path(incident_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<WebIncidentForm>,
) -> Response {
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(_) => return web_missing_context("Incidents", "/incidents/").into_response(),
    };
    let context = WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    };
    if !auth_context.can_write() {
        return web_error_page(
            "Incidents",
            "/incidents/",
            &context,
            "Diese Rust-Webroute benoetigt eine schreibende ISCY-Rolle.",
        )
        .into_response();
    }
    let Some(store) = state.incident_store else {
        return web_store_missing("Incidents", "/incidents/", &context, "Incident").into_response();
    };
    let payload = match web_incident_form_request(form) {
        Ok(payload) => payload,
        Err(message) => {
            return web_error_page("Incidents", "/incidents/", &context, &message).into_response()
        }
    };
    match store
        .update_incident(
            auth_context.tenant_id,
            incident_id,
            Some(auth_context.user_id),
            payload,
        )
        .await
    {
        Ok(Some(_)) => Redirect::to(&web_path_with_context(
            &format!("/incidents/{}", incident_id),
            Some(&context),
        ))
        .into_response(),
        Ok(None) => web_error_page(
            "Incidents",
            "/incidents/",
            &context,
            &format!("Incident {} wurde nicht gefunden.", incident_id),
        )
        .into_response(),
        Err(err) => {
            web_error_page("Incidents", "/incidents/", &context, &err.to_string()).into_response()
        }
    }
}

async fn web_incident_review_submit(
    Path(incident_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<WebIncidentReviewForm>,
) -> Response {
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(_) => return web_missing_context("Incidents", "/incidents/").into_response(),
    };
    let context = WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    };
    if !auth_context.can_write() {
        return web_error_page(
            "Incidents",
            "/incidents/",
            &context,
            "Diese Rust-Webroute benoetigt eine schreibende ISCY-Rolle.",
        )
        .into_response();
    }
    let Some(store) = state.incident_store else {
        return web_store_missing("Incidents", "/incidents/", &context, "Incident").into_response();
    };
    match store
        .update_incident_review_state(
            auth_context.tenant_id,
            incident_id,
            auth_context.user_id,
            &form.action,
            form.notes.as_deref(),
        )
        .await
    {
        Ok(Some(_)) => Redirect::to(&web_path_with_context(
            &format!("/incidents/{}", incident_id),
            Some(&context),
        ))
        .into_response(),
        Ok(None) => web_error_page(
            "Incidents",
            "/incidents/",
            &context,
            &format!("Incident {} wurde nicht gefunden.", incident_id),
        )
        .into_response(),
        Err(err) => {
            web_error_page("Incidents", "/incidents/", &context, &err.to_string()).into_response()
        }
    }
}

async fn web_incident_timeline_note_submit(
    Path(incident_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<WebIncidentTimelineNoteForm>,
) -> Response {
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(_) => return web_missing_context("Incidents", "/incidents/").into_response(),
    };
    let context = WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    };
    if !auth_context.can_write() {
        return web_error_page(
            "Incidents",
            "/incidents/",
            &context,
            "Diese Rust-Webroute benoetigt eine schreibende ISCY-Rolle.",
        )
        .into_response();
    }
    let payload = match incident_timeline_note_payload(form.summary, form.detail) {
        Ok(payload) => payload,
        Err(message) => {
            return web_error_page("Incidents", "/incidents/", &context, &message).into_response()
        }
    };
    let Some(store) = state.incident_store else {
        return web_store_missing("Incidents", "/incidents/", &context, "Incident").into_response();
    };
    match store
        .append_incident_event(
            auth_context.tenant_id,
            incident_id,
            Some(auth_context.user_id),
            payload,
        )
        .await
    {
        Ok(_) => Redirect::to(&web_path_with_context(
            &format!("/incidents/{}", incident_id),
            Some(&context),
        ))
        .into_response(),
        Err(err) => {
            web_error_page("Incidents", "/incidents/", &context, &err.to_string()).into_response()
        }
    }
}

async fn web_incident_runbook_step_submit(
    Path((incident_id, step_id)): Path<(i64, i64)>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<WebIncidentRunbookStepForm>,
) -> Response {
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(_) => return web_missing_context("Incidents", "/incidents/").into_response(),
    };
    let context = WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    };
    if !auth_context.can_write() {
        return web_error_page(
            "Incidents",
            "/incidents/",
            &context,
            "Diese Rust-Webroute benoetigt eine schreibende ISCY-Rolle.",
        )
        .into_response();
    }
    let Some(store) = state.incident_store else {
        return web_store_missing("Incidents", "/incidents/", &context, "Incident").into_response();
    };
    let action = form
        .action
        .as_deref()
        .unwrap_or("toggle")
        .trim()
        .to_ascii_lowercase();
    if action == "move_up" || action == "move_down" {
        return match store
            .move_runbook_step(
                auth_context.tenant_id,
                incident_id,
                step_id,
                Some(auth_context.user_id),
                action.as_str(),
            )
            .await
        {
            Ok(_) => Redirect::to(&web_path_with_context(
                &format!("/incidents/{}", incident_id),
                Some(&context),
            ))
            .into_response(),
            Err(err) => web_error_page("Incidents", "/incidents/", &context, &err.to_string())
                .into_response(),
        };
    }
    let is_done = form_checkbox_value(form.is_done);
    match store
        .set_runbook_step_done(
            auth_context.tenant_id,
            incident_id,
            step_id,
            Some(auth_context.user_id),
            is_done,
        )
        .await
    {
        Ok(Some(_)) => Redirect::to(&web_path_with_context(
            &format!("/incidents/{}", incident_id),
            Some(&context),
        ))
        .into_response(),
        Ok(None) => web_error_page(
            "Incidents",
            "/incidents/",
            &context,
            &format!("Runbook-Schritt {} wurde nicht gefunden.", step_id),
        )
        .into_response(),
        Err(err) => {
            web_error_page("Incidents", "/incidents/", &context, &err.to_string()).into_response()
        }
    }
}

async fn web_incident_timeline_event_marker_submit(
    Path((incident_id, event_id)): Path<(i64, i64)>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<WebIncidentTimelineEventMarkerForm>,
) -> Response {
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(_) => return web_missing_context("Incidents", "/incidents/").into_response(),
    };
    let context = WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    };
    if !auth_context.can_write() {
        return web_error_page(
            "Incidents",
            "/incidents/",
            &context,
            "Diese Rust-Webroute benoetigt eine schreibende ISCY-Rolle.",
        )
        .into_response();
    }
    let Some(store) = state.incident_store else {
        return web_store_missing("Incidents", "/incidents/", &context, "Incident").into_response();
    };
    match store
        .update_incident_event_export_marker(
            auth_context.tenant_id,
            incident_id,
            event_id,
            form_checkbox_value(form.is_export_highlight),
            form.export_note.as_deref(),
        )
        .await
    {
        Ok(Some(_)) => Redirect::to(&web_path_with_context(
            &format!("/incidents/{}?timeline=highlighted", incident_id),
            Some(&context),
        ))
        .into_response(),
        Ok(None) => web_error_page(
            "Incidents",
            "/incidents/",
            &context,
            &format!("Timeline-Event {} wurde nicht gefunden.", event_id),
        )
        .into_response(),
        Err(err) => {
            web_error_page("Incidents", "/incidents/", &context, &err.to_string()).into_response()
        }
    }
}

async fn web_incident_nis2_export(
    Path(incident_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Response {
    web_incident_regulatory_export_format(
        incident_id,
        state,
        headers,
        query,
        IncidentPackageKind::Nis2,
        IncidentExportFormat::Markdown,
    )
    .await
}

async fn web_incident_nis2_export_html(
    Path(incident_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Response {
    web_incident_regulatory_export_format(
        incident_id,
        state,
        headers,
        query,
        IncidentPackageKind::Nis2,
        IncidentExportFormat::Html,
    )
    .await
}

async fn web_incident_nis2_export_pdf(
    Path(incident_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Response {
    web_incident_regulatory_export_format(
        incident_id,
        state,
        headers,
        query,
        IncidentPackageKind::Nis2,
        IncidentExportFormat::Pdf,
    )
    .await
}

async fn web_incident_dora_export(
    Path(incident_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Response {
    web_incident_regulatory_export_format(
        incident_id,
        state,
        headers,
        query,
        IncidentPackageKind::Dora,
        IncidentExportFormat::Markdown,
    )
    .await
}

async fn web_incident_dora_export_html(
    Path(incident_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Response {
    web_incident_regulatory_export_format(
        incident_id,
        state,
        headers,
        query,
        IncidentPackageKind::Dora,
        IncidentExportFormat::Html,
    )
    .await
}

async fn web_incident_dora_export_pdf(
    Path(incident_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Response {
    web_incident_regulatory_export_format(
        incident_id,
        state,
        headers,
        query,
        IncidentPackageKind::Dora,
        IncidentExportFormat::Pdf,
    )
    .await
}

async fn web_incident_dsgvo_export(
    Path(incident_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Response {
    web_incident_regulatory_export_format(
        incident_id,
        state,
        headers,
        query,
        IncidentPackageKind::Dsgvo,
        IncidentExportFormat::Markdown,
    )
    .await
}

async fn web_incident_dsgvo_export_html(
    Path(incident_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Response {
    web_incident_regulatory_export_format(
        incident_id,
        state,
        headers,
        query,
        IncidentPackageKind::Dsgvo,
        IncidentExportFormat::Html,
    )
    .await
}

async fn web_incident_dsgvo_export_pdf(
    Path(incident_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Response {
    web_incident_regulatory_export_format(
        incident_id,
        state,
        headers,
        query,
        IncidentPackageKind::Dsgvo,
        IncidentExportFormat::Pdf,
    )
    .await
}

async fn web_incident_timeline_export_csv(
    Path(incident_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Response {
    web_incident_timeline_export_format(
        incident_id,
        state,
        headers,
        query,
        IncidentTimelineExportFormat::Csv,
    )
    .await
}

async fn web_incident_timeline_export_json(
    Path(incident_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Response {
    web_incident_timeline_export_format(
        incident_id,
        state,
        headers,
        query,
        IncidentTimelineExportFormat::Json,
    )
    .await
}

async fn web_incident_timeline_export_format(
    incident_id: i64,
    state: AppState,
    headers: HeaderMap,
    query: WebContextQuery,
    export_format: IncidentTimelineExportFormat,
) -> Response {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
        return web_missing_context("Incidents", "/incidents/").into_response();
    };
    let Some(store) = state.incident_store.clone() else {
        return web_store_missing("Incidents", "/incidents/", &context, "Incident").into_response();
    };
    match store.incident_detail(context.tenant_id, incident_id).await {
        Ok(Some(incident)) => match store
            .list_incident_events(context.tenant_id, incident.id, 500)
            .await
        {
            Ok(events) => {
                incident_timeline_export_download_response(&incident, &events, export_format)
            }
            Err(err) => web_error_page("Incidents", "/incidents/", &context, &err.to_string())
                .into_response(),
        },
        Ok(None) => web_error_page(
            "Incidents",
            "/incidents/",
            &context,
            &format!("Incident {} wurde nicht gefunden.", incident_id),
        )
        .into_response(),
        Err(err) => {
            web_error_page("Incidents", "/incidents/", &context, &err.to_string()).into_response()
        }
    }
}

async fn web_incident_regulatory_export_format(
    incident_id: i64,
    state: AppState,
    headers: HeaderMap,
    query: WebContextQuery,
    package_kind: IncidentPackageKind,
    export_format: IncidentExportFormat,
) -> Response {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
        return web_missing_context("Incidents", "/incidents/").into_response();
    };
    let Some(store) = state.incident_store.clone() else {
        return web_store_missing("Incidents", "/incidents/", &context, "Incident").into_response();
    };
    match store.incident_detail(context.tenant_id, incident_id).await {
        Ok(Some(incident)) => {
            let evidence_items =
                incident_linked_evidence(&state, context.tenant_id, incident.id).await;
            match store
                .list_incident_events(context.tenant_id, incident.id, 50)
                .await
            {
                Ok(events) => incident_export_download_response(
                    &incident,
                    &evidence_items,
                    &events,
                    package_kind,
                    export_format,
                ),
                Err(err) => web_error_page("Incidents", "/incidents/", &context, &err.to_string())
                    .into_response(),
            }
        }
        Ok(None) => web_error_page(
            "Incidents",
            "/incidents/",
            &context,
            &format!("Incident {} wurde nicht gefunden.", incident_id),
        )
        .into_response(),
        Err(err) => {
            web_error_page("Incidents", "/incidents/", &context, &err.to_string()).into_response()
        }
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
            let prefill_title = query.evidence_title.as_deref().unwrap_or("");
            let prefill_description = query.evidence_description.as_deref().unwrap_or("");
            let prefill_linked_requirement = query.linked_requirement.as_deref().unwrap_or("");
            let prefill_status = query.evidence_status.as_deref().unwrap_or("SUBMITTED");
            let prefill_session_id = query
                .session_id
                .map(|value| value.to_string())
                .unwrap_or_default();
            let prefill_requirement_id = query
                .requirement_id
                .map(|value| value.to_string())
                .unwrap_or_default();
            let prefill_control_id = query
                .control_id
                .map(|value| value.to_string())
                .unwrap_or_default();
            let prefill_incident_id = query
                .incident_id
                .map(|value| value.to_string())
                .unwrap_or_default();
            let return_to_hidden = safe_web_return_path(query.return_to.as_ref())
                .map(|return_to| {
                    format!(
                        r#"<input type="hidden" name="return_to" value="{}">"#,
                        html_escape(&return_to)
                    )
                })
                .unwrap_or_default();
            let rows = overview
                .evidence_items
                .iter()
                .map(|item| {
                    let hash = if item.file_sha256.is_empty() {
                        "-"
                    } else {
                        item.file_sha256.get(..12).unwrap_or(&item.file_sha256)
                    };
                    format!(
                        r#"<tr><td>{}</td><td>v{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>"#,
                        html_escape(&item.title),
                        item.version_number,
                        html_escape(&item.sensitivity),
                        html_escape(&item.status_label),
                        html_escape(item.valid_until.as_deref().unwrap_or("-")),
                        html_escape(hash),
                        html_escape(item.owner_display.as_deref().unwrap_or("-")),
                        html_escape(
                            item.incident_title
                                .as_deref()
                                .or(item.requirement_code.as_deref())
                                .unwrap_or("-"),
                        ),
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
                  {}
                </section>
                <section class="panel wide">
                  <h2>Evidence-Qualitaet</h2>
                  <p><a href="{}">Nachweisreife und Review-Luecken oeffnen</a></p>
                </section>
                <section class="grid">
                  <article class="panel wide">
                    <table>
                      <thead><tr><th>Titel</th><th>Version</th><th>Schutzklasse</th><th>Status</th><th>Gueltig bis</th><th>SHA-256</th><th>Owner</th><th>Verknuepfung</th></tr></thead>
                      <tbody>{}</tbody>
                    </table>
                  </article>
                  <article class="panel wide">
                    <h2>Evidence hochladen</h2>
                    <form method="post" action="{}" enctype="multipart/form-data">
                      {}
                      <div class="form-grid">
                        <label>Titel<input name="title" type="text" value="{}" required></label>
                        <label>Status<select name="status">{}</select></label>
                        <label>Session-ID<input name="session_id" type="number" min="1" value="{}"></label>
                        <label>Requirement-ID<input name="requirement_id" type="number" min="1" value="{}"></label>
                        <label>Control-ID<input name="control_id" type="number" min="1" value="{}"></label>
                        <label>Incident-ID<input name="incident_id" type="number" min="1" value="{}"></label>
                        <label>Vorgaenger-ID<input name="supersedes_id" type="number" min="1"></label>
                        <label>Schutzklasse<select name="sensitivity">{}</select></label>
                        <label>Gueltig bis<input name="valid_until" type="date"></label>
                        <label>Aufbewahren bis<input name="retention_until" type="date"></label>
                      </div>
                      <label>Linked Requirement<input name="linked_requirement" type="text" value="{}"></label>
                      <label>Beschreibung<textarea name="description" rows="4">{}</textarea></label>
                      <label>Retention-Begruendung<textarea name="retention_reason" rows="2"></textarea></label>
                      <label>Review-Notiz<textarea name="review_notes" rows="2"></textarea></label>
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
                metric_card("Qualitaet", overview.evidence_items.len() as i64),
                web_path_with_context("/evidence/quality/", Some(&context)),
                if rows.is_empty() {
                    r#"<tr><td colspan="8">Keine Evidenzen vorhanden.</td></tr>"#.to_string()
                } else {
                    rows
                },
                web_path_with_context("/evidence/", Some(&context)),
                return_to_hidden,
                html_escape(prefill_title),
                evidence_status_options_for(prefill_status),
                html_escape(&prefill_session_id),
                html_escape(&prefill_requirement_id),
                html_escape(&prefill_control_id),
                html_escape(&prefill_incident_id),
                evidence_sensitivity_options_for("INTERNAL"),
                html_escape(prefill_linked_requirement),
                html_escape(prefill_description),
            );
            web_page("Evidence", "/evidence/", Some(&context), &body)
        }
        Err(err) => web_error_page("Evidence", "/evidence/", &context, &err.to_string()),
    }
}

async fn web_evidence_quality(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
        return web_missing_context("Evidence Quality", "/evidence/quality/");
    };
    let Some(store) = state.evidence_store else {
        return web_store_missing(
            "Evidence Quality",
            "/evidence/quality/",
            &context,
            "Evidence",
        );
    };
    match store
        .evidence_quality(context.tenant_id, query.session_id, 500, 100)
        .await
    {
        Ok(quality) => {
            let item_rows = quality
                .items
                .iter()
                .filter(|item| !item.issues.is_empty() || item.quality_score < 85)
                .map(|item| {
                    let href = web_path_with_context(&item.href, Some(&context));
                    format!(
                        r#"<tr><td><a href="{}">{}</a></td><td>v{} · {}</td><td>{}</td><td>{}</td><td>{}</td><td>{}%</td><td>{}</td></tr>"#,
                        html_escape(&href),
                        html_escape(&item.title),
                        item.version_number,
                        html_escape(&item.sensitivity),
                        html_escape(item.valid_until.as_deref().unwrap_or("-")),
                        html_escape(&item.status_label),
                        html_escape(&item.quality_level),
                        item.quality_score,
                        html_escape(&item.issues.join("; ")),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let need_rows = quality
                .needs
                .iter()
                .filter(|need| !need.issues.is_empty())
                .map(|need| {
                    let href = web_path_with_context(&need.href, Some(&context));
                    format!(
                        r#"<tr><td><a href="{}">{}</a></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                        html_escape(&href),
                        html_escape(&need.title),
                        html_escape(&need.requirement_code),
                        html_escape(&need.status_label),
                        need.covered_count,
                        html_escape(&need.issues.join("; ")),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let body = format!(
                r#"
                <section class="hero compact"><h1>Evidence Quality</h1><p>{} · Ø {}%</p></section>
                <section class="metrics">
                  {}
                  {}
                  {}
                  {}
                  {}
                  {}
                  {}
                  {}
                  {}
                </section>
                <section class="panel wide">
                  <h2>Nachweisreife</h2>
                  <table>
                    <thead><tr><th>Evidence</th><th>Version / Klasse</th><th>Gueltig bis</th><th>Status</th><th>Level</th><th>Score</th><th>Issues</th></tr></thead>
                    <tbody>{}</tbody>
                  </table>
                </section>
                <section class="panel wide">
                  <h2>Evidence Needs</h2>
                  <table>
                    <thead><tr><th>Need</th><th>Requirement</th><th>Status</th><th>Coverage</th><th>Issues</th></tr></thead>
                    <tbody>{}</tbody>
                  </table>
                </section>
                "#,
                html_escape(&quality.summary.maturity_label),
                quality.summary.average_score,
                metric_card("Nachweise", quality.summary.total_items),
                metric_card("Freigegeben", quality.summary.approved_items),
                metric_card("Reviewed", quality.summary.reviewed_items),
                metric_card("Offene Needs", quality.summary.open_needs),
                metric_card("Mit Hash", quality.summary.items_with_hash),
                metric_card("Abgelaufen", quality.summary.expired_items),
                metric_card("Laeuft bald ab", quality.summary.expiring_items),
                metric_card("Retention gesetzt", quality.summary.retention_defined_items),
                metric_card("Retention faellig", quality.summary.retention_due_items),
                if item_rows.is_empty() {
                    web_empty_row(7, "Keine Evidence-Qualitaetsluecken sichtbar.")
                } else {
                    item_rows
                },
                if need_rows.is_empty() {
                    web_empty_row(5, "Keine offenen Evidence-Needs sichtbar.")
                } else {
                    need_rows
                },
            );
            web_page(
                "Evidence Quality",
                "/evidence/quality/",
                Some(&context),
                &body,
            )
        }
        Err(err) => web_error_page(
            "Evidence Quality",
            "/evidence/quality/",
            &context,
            &err.to_string(),
        ),
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
        control_id: optional_i64_form_field(&form.fields, "control_id"),
        incident_id: optional_i64_form_field(&form.fields, "incident_id"),
        title: form.fields.get("title").cloned().unwrap_or_default(),
        description: form.fields.get("description").cloned().unwrap_or_default(),
        linked_requirement: form
            .fields
            .get("linked_requirement")
            .cloned()
            .unwrap_or_default(),
        file_name: saved_file.as_ref().map(|file| file.relative_path.clone()),
        supersedes_id: optional_i64_form_field(&form.fields, "supersedes_id"),
        file_sha256: saved_file
            .as_ref()
            .map(|file| file.sha256.clone())
            .unwrap_or_default(),
        valid_until: form.fields.get("valid_until").cloned(),
        retention_until: form.fields.get("retention_until").cloned(),
        retention_reason: form
            .fields
            .get("retention_reason")
            .cloned()
            .unwrap_or_default(),
        sensitivity: form
            .fields
            .get("sensitivity")
            .cloned()
            .unwrap_or_else(|| "INTERNAL".to_string()),
        status: form.fields.get("status").cloned(),
        review_notes: form.fields.get("review_notes").cloned().unwrap_or_default(),
    };
    match store
        .create_evidence_item(auth_context.tenant_id, auth_context.user_id, payload)
        .await
    {
        Ok(item) => {
            record_incident_evidence_event(
                &state,
                auth_context.tenant_id,
                auth_context.user_id,
                &item,
            )
            .await;
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
            if let Some(return_to) = safe_web_return_path(form.fields.get("return_to")) {
                return Redirect::to(&return_to).into_response();
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
                  <h2>Management Review</h2>
                  <p><a href="{}">Management-Review-/Audit-Pakete vorbereiten</a></p>
                </section>
                <section class="panel wide">
                  <table>
                    <thead><tr><th>Titel</th><th>Applicability</th><th>ISO</th><th>NIS2</th><th>Erstellt</th></tr></thead>
                    <tbody>{}</tbody>
                  </table>
                </section>
                "#,
                reports.len(),
                web_path_with_context("/management-reviews/", Some(&context)),
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

async fn web_management_reviews(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
        return web_missing_context("Management Reviews", "/management-reviews/");
    };
    let can_write = authenticated_tenant_context(&state, &headers)
        .await
        .is_ok_and(|auth_context| auth_context.can_write());
    let Some(store) = state.report_store.as_ref() else {
        return web_store_missing(
            "Management Reviews",
            "/management-reviews/",
            &context,
            "Report",
        );
    };
    match store.list_management_reviews(context.tenant_id, 50).await {
        Ok(packages) => {
            let rows = packages
                .iter()
                .map(|package| {
                    let detail_href = web_path_with_context(
                        &format!("/management-reviews/{}", package.id),
                        Some(&context),
                    );
                    format!(
                        r#"<tr><td><a href="{}">{}</a></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                        detail_href,
                        html_escape(&package.title),
                        html_escape(&package.status_label),
                        html_escape(package.period_start.as_deref().unwrap_or("-")),
                        html_escape(package.period_end.as_deref().unwrap_or("-")),
                        html_escape(&package.created_at),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let generate_panel = if can_write {
                format!(
                    r#"
                    <section class="panel wide">
                      <h2>Paket erzeugen</h2>
                      <form method="post" action="{}">
                        <div class="form-grid">
                          <label>Titel<input name="title" value="Management Review {}"></label>
                          <label>Zeitraum Start<input name="period_start" type="date"></label>
                          <label>Zeitraum Ende<input name="period_end" type="date"></label>
                        </div>
                        <label>Executive Summary<textarea name="executive_summary" rows="4"></textarea></label>
                        <button type="submit">Management-Review-Paket erzeugen</button>
                      </form>
                    </section>
                    "#,
                    web_path_with_context("/management-reviews/", Some(&context)),
                    Utc::now().format("%Y-%m-%d"),
                )
            } else {
                r#"<section class="panel wide"><h2>Paket erzeugen</h2><p>Zum Erzeugen oder Freigeben wird eine schreibende ISCY-Rolle benoetigt.</p></section>"#.to_string()
            };
            let body = format!(
                r#"
                <section class="hero compact"><h1>Management Reviews</h1><p>{} Audit-/Review-Pakete</p></section>
                {}
                <section class="panel wide">
                  <h2>Pakete</h2>
                  <table>
                    <thead><tr><th>Titel</th><th>Status</th><th>Start</th><th>Ende</th><th>Erstellt</th></tr></thead>
                    <tbody>{}</tbody>
                  </table>
                </section>
                "#,
                packages.len(),
                generate_panel,
                if rows.is_empty() {
                    web_empty_row(5, "Keine Management-Review-Pakete vorhanden.")
                } else {
                    rows
                },
            );
            web_page(
                "Management Reviews",
                "/management-reviews/",
                Some(&context),
                &body,
            )
        }
        Err(err) => web_error_page(
            "Management Reviews",
            "/management-reviews/",
            &context,
            &err.to_string(),
        ),
    }
}

async fn web_management_reviews_generate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
    Form(form): Form<WebManagementReviewGenerateForm>,
) -> Response {
    let display_context = web_context_from_request(&query, &headers, &state).await;
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(err) => {
            if let Some(context) = display_context.as_ref() {
                return web_error_page(
                    "Management Reviews",
                    "/management-reviews/",
                    context,
                    err.message(),
                )
                .into_response();
            }
            return web_missing_context("Management Reviews", "/management-reviews/")
                .into_response();
        }
    };
    let context = display_context.unwrap_or_else(|| WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    });
    if !auth_context.can_write() {
        return web_error_page(
            "Management Reviews",
            "/management-reviews/",
            &context,
            "Diese Rust-Webroute benoetigt eine schreibende ISCY-Rolle.",
        )
        .into_response();
    }
    let Some(store) = state.report_store else {
        return web_store_missing(
            "Management Reviews",
            "/management-reviews/",
            &context,
            "Report",
        )
        .into_response();
    };
    let payload = report_store::ManagementReviewGenerateRequest {
        title: normalized_optional_form_text(form.title),
        period_start: normalized_optional_form_text(form.period_start),
        period_end: normalized_optional_form_text(form.period_end),
        executive_summary: normalized_optional_form_text(form.executive_summary),
    };
    match store
        .generate_management_review(auth_context.tenant_id, auth_context.user_id, payload)
        .await
    {
        Ok(package) => Redirect::to(&web_path_with_context(
            &format!("/management-reviews/{}", package.id),
            Some(&context),
        ))
        .into_response(),
        Err(err) => web_error_page(
            "Management Reviews",
            "/management-reviews/",
            &context,
            &err.to_string(),
        )
        .into_response(),
    }
}

async fn web_management_review_detail(
    Path(review_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
        return web_missing_context("Management Review", "/management-reviews/");
    };
    let can_write = authenticated_tenant_context(&state, &headers)
        .await
        .is_ok_and(|auth_context| auth_context.can_write());
    let Some(store) = state.report_store.as_ref() else {
        return web_store_missing(
            "Management Review",
            "/management-reviews/",
            &context,
            "Report",
        );
    };
    match store
        .management_review_detail(context.tenant_id, review_id)
        .await
    {
        Ok(Some(package)) => {
            let status_panel = management_review_status_panel(&package, &context, can_write);
            let export_panel = management_review_export_panel(&package, &context);
            let body = format!(
                r#"
                <section class="hero compact"><h1>{}</h1><p>{}</p></section>
                <section class="metrics">{}</section>
                <section class="panel wide">
                  <h2>Executive Summary</h2>
                  <p>{}</p>
                </section>
                {}
                {}
                <section class="grid">
                  {}
                  {}
                  {}
                  {}
                  {}
                  {}
                  {}
                  {}
                </section>
                "#,
                html_escape(&package.title),
                html_escape(&package.status_label),
                management_review_metric_cards(&package.metrics_json),
                html_escape(&package.executive_summary),
                status_panel,
                export_panel,
                management_review_object_panel("Kennzahlen", &package.metrics_json),
                management_review_array_panel(
                    "Top-Risiken",
                    &package.top_risks_json,
                    &[
                        ("title", "Titel"),
                        ("status", "Status"),
                        ("score", "Score"),
                        ("treatment_plan", "Behandlung"),
                    ],
                    &context,
                ),
                management_review_array_panel(
                    "ISCY-27 Control-Gaps",
                    &package.control_gaps_json,
                    &[
                        ("code", "Control"),
                        ("title", "Titel"),
                        ("status", "Status"),
                        ("evidence_status", "Evidence"),
                    ],
                    &context,
                ),
                management_review_array_panel(
                    "Evidence-Luecken",
                    &package.evidence_gaps_json,
                    &[
                        ("requirement_code", "Requirement"),
                        ("title", "Evidence"),
                        ("status", "Status"),
                        ("covered_count", "Coverage"),
                    ],
                    &context,
                ),
                management_review_array_panel(
                    "Incident-Entscheidungen",
                    &package.incident_decisions_json,
                    &[
                        ("title", "Incident"),
                        ("severity", "Severity"),
                        ("nis2_significance_status", "Erheblichkeit"),
                        ("review_state", "Review"),
                    ],
                    &context,
                ),
                management_review_array_panel(
                    "Roadmap-Fokus",
                    &package.roadmap_json,
                    &[
                        ("title", "Task"),
                        ("priority", "Prioritaet"),
                        ("status", "Status"),
                        ("due_date", "Faellig"),
                    ],
                    &context,
                ),
                management_review_object_panel("Product Security", &package.product_security_json),
                management_review_object_panel("Agent Posture", &package.agent_posture_json),
            );
            web_page(
                "Management Review",
                "/management-reviews/",
                Some(&context),
                &body,
            )
        }
        Ok(None) => web_error_page(
            "Management Review",
            "/management-reviews/",
            &context,
            "Management-Review wurde nicht gefunden.",
        ),
        Err(err) => web_error_page(
            "Management Review",
            "/management-reviews/",
            &context,
            &err.to_string(),
        ),
    }
}

async fn web_management_review_status_submit(
    Path(review_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
    Form(form): Form<WebManagementReviewStatusForm>,
) -> Response {
    let display_context = web_context_from_request(&query, &headers, &state).await;
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(err) => {
            if let Some(context) = display_context.as_ref() {
                return web_error_page(
                    "Management Review",
                    "/management-reviews/",
                    context,
                    err.message(),
                )
                .into_response();
            }
            return web_missing_context("Management Review", "/management-reviews/")
                .into_response();
        }
    };
    let context = display_context.unwrap_or_else(|| WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    });
    if !auth_context.can_write() {
        return web_error_page(
            "Management Review",
            "/management-reviews/",
            &context,
            "Diese Rust-Webroute benoetigt eine schreibende ISCY-Rolle.",
        )
        .into_response();
    }
    let Some(store) = state.report_store else {
        return web_store_missing(
            "Management Review",
            "/management-reviews/",
            &context,
            "Report",
        )
        .into_response();
    };
    let payload = report_store::ManagementReviewStatusUpdateRequest {
        status: form.status,
        decision_notes: normalized_optional_form_text(form.decision_notes),
        next_actions: normalized_optional_form_text(form.next_actions),
    };
    match store
        .update_management_review_status(
            auth_context.tenant_id,
            auth_context.user_id,
            review_id,
            payload,
        )
        .await
    {
        Ok(Some(_)) => Redirect::to(&web_path_with_context(
            &format!("/management-reviews/{review_id}"),
            Some(&context),
        ))
        .into_response(),
        Ok(None) => web_error_page(
            "Management Review",
            "/management-reviews/",
            &context,
            "Management-Review wurde nicht gefunden.",
        )
        .into_response(),
        Err(err) => web_error_page(
            "Management Review",
            "/management-reviews/",
            &context,
            &err.to_string(),
        )
        .into_response(),
    }
}

async fn web_management_review_export_markdown(
    Path(review_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Response {
    web_management_review_export_format(
        review_id,
        state,
        headers,
        query,
        ManagementReviewExportFormat::Markdown,
    )
    .await
}

async fn web_management_review_export_html(
    Path(review_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Response {
    web_management_review_export_format(
        review_id,
        state,
        headers,
        query,
        ManagementReviewExportFormat::Html,
    )
    .await
}

async fn web_management_review_export_pdf(
    Path(review_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Response {
    web_management_review_export_format(
        review_id,
        state,
        headers,
        query,
        ManagementReviewExportFormat::Pdf,
    )
    .await
}

async fn web_management_review_export_json(
    Path(review_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Response {
    web_management_review_export_format(
        review_id,
        state,
        headers,
        query,
        ManagementReviewExportFormat::Json,
    )
    .await
}

async fn web_management_review_export_format(
    review_id: i64,
    state: AppState,
    headers: HeaderMap,
    query: WebContextQuery,
    export_format: ManagementReviewExportFormat,
) -> Response {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
        return web_missing_context("Management Review", "/management-reviews/").into_response();
    };
    let Some(store) = state.report_store else {
        return web_store_missing(
            "Management Review",
            "/management-reviews/",
            &context,
            "Report",
        )
        .into_response();
    };
    match store
        .management_review_detail(context.tenant_id, review_id)
        .await
    {
        Ok(Some(package)) => management_review_export_download_response(&package, export_format),
        Ok(None) => web_error_page(
            "Management Review",
            "/management-reviews/",
            &context,
            "Management-Review wurde nicht gefunden.",
        )
        .into_response(),
        Err(err) => web_error_page(
            "Management Review",
            "/management-reviews/",
            &context,
            &err.to_string(),
        )
        .into_response(),
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
            let mut task_rows = Vec::new();
            for plan in &plans {
                match store.plan_detail(context.tenant_id, plan.id).await {
                    Ok(Some(detail)) => {
                        for task in detail.tasks {
                            let linked_requirement = evidence_key_from_text(&task.description)
                                .unwrap_or_else(|| format!("ROADMAP:TASK:{}", task.id));
                            let evidence_href = evidence_prefill_href(
                                &context,
                                &format!("Roadmap-Evidence: {}", task.title),
                                &format!(
                                    "Nachweis zum Roadmap-Task '{}'. Plan: {}. Phase: {}. Beschreibung: {}.",
                                    task.title, plan.title, task.phase_name, task.description
                                ),
                                &linked_requirement,
                                Some("SUBMITTED"),
                                Some(&web_path_with_context("/roadmap/", Some(&context))),
                            );
                            task_rows.push(format!(
                                r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><a href="{}">Evidence</a></td></tr>"#,
                                html_escape(&plan.title),
                                html_escape(&task.phase_name),
                                html_escape(&task.title),
                                html_escape(&task.priority),
                                html_escape(&task.status_label),
                                html_escape(task.due_date.as_deref().unwrap_or("-")),
                                evidence_href,
                            ));
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        return web_error_page("Roadmap", "/roadmap/", &context, &err.to_string())
                    }
                }
            }
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
                <section class="panel wide">
                  <h2>Roadmap-Tasks</h2>
                  <table>
                    <thead><tr><th>Plan</th><th>Phase</th><th>Task</th><th>Prioritaet</th><th>Status</th><th>Faellig</th><th>Evidence</th></tr></thead>
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
                if task_rows.is_empty() {
                    web_empty_row(7, "Keine Roadmap-Tasks vorhanden.")
                } else {
                    task_rows.join("")
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
                        r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>"#,
                        html_escape(&asset.name),
                        html_escape(&asset.asset_type_label),
                        html_escape(&asset.criticality_label),
                        html_escape(asset.owner_display.as_deref().unwrap_or("-")),
                        html_escape(asset.business_unit_name.as_deref().unwrap_or("-")),
                        yes_no(asset.is_in_scope),
                        html_escape(&asset.cpe23_uri),
                        html_escape(&asset.package_url),
                        html_escape(&asset.sbom_document_url),
                        html_escape(&asset.software_inventory_ref),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let body = format!(
                r#"
                <section class="hero compact"><h1>Assets</h1><p>{} Informationswerte</p></section>
                <section class="panel wide">
                  <table>
                    <thead><tr><th>Name</th><th>Typ</th><th>Kritikalitaet</th><th>Owner</th><th>Business Unit</th><th>Scope</th><th>CPE 2.3</th><th>PURL</th><th>SBOM</th><th>Inventory Ref</th></tr></thead>
                    <tbody>{}</tbody>
                  </table>
                </section>
                "#,
                assets.len(),
                if rows.is_empty() {
                    web_empty_row(10, "Keine Assets vorhanden.")
                } else {
                    rows
                },
            );
            web_page("Assets", "/assets/", Some(&context), &body)
        }
        Err(err) => web_error_page("Assets", "/assets/", &context, &err.to_string()),
    }
}

async fn web_suppliers(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
        return web_missing_context("Suppliers", "/suppliers/");
    };
    let Some(store) = state.supplier_store else {
        return web_store_missing("Suppliers", "/suppliers/", &context, "Supplier");
    };
    match store.overview(context.tenant_id, 200).await {
        Ok(overview) => {
            let rows = overview
                .suppliers
                .iter()
                .map(|supplier| {
                    let evidence_href = evidence_prefill_href(
                        &context,
                        &format!("Supplier Evidence: {}", supplier.name),
                        "Supplier Review, Vertrag, Security Annex, Zertifikat, SLA, SBOM/CSAF oder Exit-Nachweis.",
                        &format!("SUPPLIER:{}", supplier.id),
                        Some("SUBMITTED"),
                        Some("/suppliers/"),
                    );
                    let api_href = web_path_with_context(
                        &format!("/api/v1/suppliers/{}", supplier.id),
                        Some(&context),
                    );
                    let evidence_count =
                        format!("{} / {}", supplier.approved_evidence_count, supplier.evidence_count);
                    let exposure = format!(
                        "{} CVE · {} Risiken",
                        supplier.open_vulnerability_count, supplier.open_risk_count
                    );
                    format!(
                        r#"<tr><td><a href="{}">{}</a><p>{}</p></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><a href="{}">Evidence</a></td></tr>"#,
                        html_escape(&api_href),
                        html_escape(&supplier.name),
                        html_escape(&supplier.service_description),
                        web_badge(
                            &supplier.criticality_label,
                            supplier_criticality_badge_class(&supplier.criticality),
                        ),
                        web_badge(&supplier.score_label, score_badge_class(supplier.score)),
                        supplier.score,
                        html_escape(supplier.owner_display.as_deref().unwrap_or("-")),
                        framework_badges(&supplier.regulatory_flags),
                        supplier.review_status_label,
                        evidence_count,
                        exposure,
                        supplier_issue_summary(&supplier.issues),
                        html_escape(&evidence_href),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let body = format!(
                r#"
                <section class="hero compact"><h1>Suppliers</h1><p>Third-Party Risk, DORA/NIS2/CRA/TISAX-Nachweise und Exit-Abhaengigkeiten</p></section>
                <section class="metrics">
                  {}
                  {}
                  {}
                  {}
                  {}
                  {}
                </section>
                <section class="panel wide">
                  <h2>Supplier-Risk Register</h2>
                  <table>
                    <thead><tr><th>Supplier</th><th>Kritikalitaet</th><th>Reife</th><th>Score</th><th>Owner</th><th>Scope</th><th>Review</th><th>Evidence</th><th>Exposure</th><th>Issues</th><th>Nachweis</th></tr></thead>
                    <tbody>{}</tbody>
                  </table>
                </section>
                "#,
                metric_card("Supplier", overview.summary.total_suppliers),
                metric_card("Kritisch", overview.summary.critical_suppliers),
                metric_card("High Risk", overview.summary.high_risk_suppliers),
                metric_card("Review ueberfaellig", overview.summary.overdue_reviews),
                metric_card("Evidence fehlt", overview.summary.missing_evidence),
                metric_card("Ø Score", overview.summary.average_score),
                if rows.is_empty() {
                    web_empty_row(11, "Keine Supplier vorhanden.")
                } else {
                    rows
                },
            );
            web_page("Suppliers", "/suppliers/", Some(&context), &body)
        }
        Err(err) => web_error_page("Suppliers", "/suppliers/", &context, &err.to_string()),
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

async fn web_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let context = web_context_from_request(&query, &headers, &state).await;
    let can_write = authenticated_tenant_context(&state, &headers)
        .await
        .is_ok_and(|auth_context| auth_context.can_write());
    let store_statuses = status_store_statuses(&state);
    let configured_stores = store_statuses
        .iter()
        .filter(|store| store.configured)
        .count() as i64;
    let store_rows = store_statuses
        .iter()
        .map(|store| {
            format!(
                r#"<tr><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                html_escape(store.name),
                if store.configured {
                    web_badge("bereit", "ok")
                } else {
                    web_badge("nicht verbunden", "warn")
                },
                html_escape(store.scope),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let rust_only = env_flag_enabled("RUST_ONLY_MODE");
    let strict_mode = env_flag_enabled("RUST_STRICT_MODE");
    let media_root = state
        .evidence_media_root
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "nicht gesetzt".to_string());
    let nvd_base = state
        .nvd_api_base_url
        .as_deref()
        .unwrap_or("NVD-Default")
        .to_string();
    let runtime_rows = [
        (
            "Rust-only",
            if rust_only {
                web_badge("aktiv", "ok")
            } else {
                web_badge("nicht gesetzt", "warn")
            },
            env_value_or("RUST_ONLY_MODE", "nicht gesetzt"),
        ),
        (
            "Strict Mode",
            if strict_mode {
                web_badge("aktiv", "ok")
            } else {
                web_badge("nicht gesetzt", "warn")
            },
            env_value_or("RUST_STRICT_MODE", "nicht gesetzt"),
        ),
        (
            "Evidence Media",
            signal_badge(state.evidence_media_root.is_some()),
            media_root,
        ),
        (
            "App Mode",
            web_badge(state.security_config.mode_label(), "info"),
            state.security_config.mode_label().to_string(),
        ),
        (
            "Identity Header",
            if state.security_config.trust_identity_headers {
                web_badge("trusted", "warn")
            } else {
                web_badge("deny by default", "ok")
            },
            if state.security_config.trust_identity_headers {
                "x-iscy-* Identity-Header werden akzeptiert.".to_string()
            } else {
                "x-iscy-* Identity-Header werden ohne Trusted-Proxy-Kontext blockiert.".to_string()
            },
        ),
        (
            "Session Cookies",
            if state.security_config.secure_cookies {
                web_badge("Secure", "ok")
            } else {
                web_badge("lokal", "warn")
            },
            if state.security_config.secure_cookies {
                "HttpOnly; Secure; SameSite=Lax".to_string()
            } else {
                "HttpOnly; SameSite=Lax fuer lokale HTTP-Entwicklung.".to_string()
            },
        ),
        (
            "HSTS",
            if state.security_config.hsts_enabled {
                web_badge("aktiv", "ok")
            } else {
                web_badge("aus", "muted-badge")
            },
            if state.security_config.hsts_enabled {
                "Strict-Transport-Security wird gesetzt.".to_string()
            } else {
                "HSTS wird erst nach bestaetigtem HTTPS aktiviert.".to_string()
            },
        ),
        ("NVD API", web_badge("konfiguriert", "info"), nvd_base),
    ]
    .iter()
    .map(|(name, status, detail)| {
        format!(
            r#"<tr><td>{}</td><td>{}</td><td>{}</td></tr>"#,
            html_escape(name),
            status,
            html_escape(detail),
        )
    })
    .collect::<Vec<_>>()
    .join("");
    let migration_status = match state.database_url.as_deref() {
        Some(database_url) => match db_admin::migration_status(database_url).await {
            Ok(status) => MigrationStatusView::Ready(status),
            Err(err) => MigrationStatusView::Error(err.to_string()),
        },
        None => MigrationStatusView::Missing,
    };
    let (migration_metric, migration_rows) = migration_status_view(&migration_status);
    let operations_overview = status_operations_overview(
        &state,
        context.as_ref(),
        &migration_status,
        rust_only,
        strict_mode,
        configured_stores,
        store_statuses.len() as i64,
    )
    .await;
    let build_rows = build_status_rows();
    let status_action_panel = if context.is_some() && can_write && state.control_store.is_some() {
        format!(
            r#"<article class="panel wide">
                <h2>Cutover-Aktionen</h2>
                <form method="post" action="{}">
                  <button type="submit">ISCY-27-Gaps in Roadmap ueberfuehren</button>
                </form>
              </article>"#,
            web_path_with_context("/status/control-gaps/generate", context.as_ref()),
        )
    } else {
        String::new()
    };
    let status_links = [
        web_link_card(
            "Live Health JSON",
            "/health/live",
            "Maschinenlesbarer Liveness-Check fuer CI und Betrieb",
        ),
        web_link_card(
            "Operations JSON",
            &web_path_with_context("/status/operations.json", context.as_ref()),
            "Betriebszentrale als maschinenlesbarer Drilldown",
        ),
        web_link_card(
            "Prometheus Metrics",
            &web_path_with_context("/metrics", context.as_ref()),
            "Betriebssignale fuer Prometheus-kompatibles Monitoring",
        ),
        web_link_card(
            "Product Security",
            &web_path_with_context("/product-security/", context.as_ref()),
            "SBOM, CSAF, CVE-Reviews und CRA/AI-Act-Signale",
        ),
        web_link_card(
            "Incidents",
            &web_path_with_context("/incidents/", context.as_ref()),
            "Alert-Fallakten, Runbooks, Evidence und Meldepakete",
        ),
        web_link_card(
            "Alert Operations",
            &web_path_with_context("/operations/incidents/", context.as_ref()),
            "Offene, deduplizierte und resolved Alertmanager-Fallakten",
        ),
        web_link_card(
            "ISCY-27",
            &web_path_with_context("/controls/", context.as_ref()),
            "27 Controls, Evidence und Roadmap-Gaps",
        ),
    ]
    .join("");
    let prometheus_scrape_config_panel = prometheus_scrape_config_panel();
    let grafana_query_cheatsheet_panel = grafana_query_cheatsheet_panel();
    let body = format!(
        r#"
        <section class="hero compact">
          <h1>Rust-only Status</h1>
          <p>Betriebsuebersicht fuer Backend, Runtime-Flags und fachliche Kernmodule.</p>
        </section>
        <section class="metrics">
          {}
          {}
          {}
          {}
          {}
        </section>
        <section class="grid">
          <article class="panel wide">
            <h2>Betriebszentrale</h2>
            <table>
              <thead><tr><th>Bereich</th><th>Signal</th><th>Status</th><th>Detail</th><th>Aktion</th></tr></thead>
              <tbody>{}</tbody>
            </table>
          </article>
          {}
          <article class="panel wide">
            <h2>Runtime</h2>
            <table>
              <thead><tr><th>Signal</th><th>Status</th><th>Detail</th></tr></thead>
              <tbody>{}</tbody>
            </table>
          </article>
          <article class="panel wide">
            <h2>Kernmodule</h2>
            <table>
              <thead><tr><th>Modul</th><th>Status</th><th>Scope</th></tr></thead>
              <tbody>{}</tbody>
            </table>
          </article>
          <article class="panel wide">
            <h2>Build</h2>
            <table>
              <thead><tr><th>Signal</th><th>Wert</th></tr></thead>
              <tbody>{}</tbody>
            </table>
          </article>
          <article class="panel wide">
            <h2>Datenbank-Migrationen</h2>
            <table>
              <thead><tr><th>Signal</th><th>Status</th><th>Detail</th></tr></thead>
              <tbody>{}</tbody>
            </table>
          </article>
          {}
          {}
          {}
        </section>
        "#,
        metric_card("Module bereit", configured_stores),
        metric_card("Rust-only", if rust_only { 1 } else { 0 }),
        metric_card("Strict Mode", if strict_mode { 1 } else { 0 }),
        metric_card("Migrationen", migration_metric),
        metric_card("Offene Signale", operations_overview.issue_count),
        operations_overview.rows,
        status_action_panel,
        runtime_rows,
        store_rows,
        build_rows,
        migration_rows,
        prometheus_scrape_config_panel,
        grafana_query_cheatsheet_panel,
        status_links,
    );
    web_page("Rust-only Status", "/status/", context.as_ref(), &body)
}

fn prometheus_scrape_config_panel() -> String {
    let scrape_config = format!(
        r#"scrape_configs:
  - job_name: "iscy-rust"
    metrics_path: "/metrics"
    static_configs:
      - targets: ["{}"]
"#,
        prometheus_scrape_target(),
    );
    format!(
        r#"<article class="panel wide">
            <h2>Prometheus Scrape Config</h2>
            <button type="button" onclick="navigator.clipboard && navigator.clipboard.writeText(document.getElementById('iscy-prometheus-scrape-config').innerText)">Kopieren</button>
            <pre id="iscy-prometheus-scrape-config">{}</pre>
          </article>"#,
        html_escape(&scrape_config),
    )
}

fn prometheus_scrape_target() -> String {
    let raw_bind = std::env::var("RUST_BACKEND_BIND")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "127.0.0.1:9000".to_string());
    if let Some(port) = raw_bind.strip_prefix("0.0.0.0:") {
        return format!("127.0.0.1:{port}");
    }
    if let Some(port) = raw_bind.strip_prefix("[::]:") {
        return format!("127.0.0.1:{port}");
    }
    raw_bind
}

fn grafana_query_cheatsheet_panel() -> String {
    let rows = [
        (
            "Betriebsstatus",
            "iscy_operations_exit_code",
            "0 OK, 1 Warnung, 2 kritisch",
        ),
        (
            "Offene Signale",
            "iscy_operations_issue_count",
            "Anzahl Warn-/Kritisch-Signale",
        ),
        (
            "Kritische Signale",
            r#"iscy_operations_signal{level="critical"}"#,
            "Tabelle oder Stat fuer kritische Einzelbefunde",
        ),
        (
            "Warnsignale",
            r#"iscy_operations_signal{level="warn"}"#,
            "Tabelle fuer offene Pruefpunkte",
        ),
        (
            "Modulstatus",
            "iscy_operations_module_configured",
            "Rust-Stores und fachliche Module",
        ),
        (
            "Migrationen",
            "iscy_operations_migration_applied / iscy_operations_migration_expected",
            "Schema-Fortschritt als Gauge",
        ),
        (
            "Runtime Flags",
            "iscy_operations_runtime_flag",
            "Rust-only und Strict-Mode sichtbar machen",
        ),
        (
            "Build Info",
            "iscy_operations_build_info",
            "Version, Commit, Profil und Target",
        ),
        (
            "Alert-Incidents",
            r#"iscy_operations_alertmanager_incidents_total{state!="all"}"#,
            "Persistierte Alertmanager-Fallakten nach open, critical_open und resolved",
        ),
        (
            "Alert-Drilldown",
            "iscy_operations_alertmanager_incident_info",
            "Konkrete Incident-Fallakten fuer Grafana-Links",
        ),
    ]
    .iter()
    .map(|(name, query, detail)| {
        format!(
            r#"<tr><td>{}</td><td><code>{}</code></td><td>{}</td></tr>"#,
            html_escape(name),
            html_escape(query),
            html_escape(detail),
        )
    })
    .collect::<Vec<_>>()
    .join("");
    format!(
        r#"<article class="panel wide">
            <h2>Grafana Queries</h2>
            <table>
              <thead><tr><th>Panel</th><th>PromQL</th><th>Hinweis</th></tr></thead>
              <tbody>{}</tbody>
            </table>
          </article>"#,
        rows,
    )
}

async fn status_operations_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Json<StatusOperationsJsonResponse> {
    Json(status_operations_payload(&state, &headers, &query).await)
}

async fn status_operations_metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Response {
    let payload = status_operations_payload(&state, &headers, &query).await;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    (
        StatusCode::OK,
        response_headers,
        status_operations_metrics_body(&payload),
    )
        .into_response()
}

async fn status_operations_payload(
    state: &AppState,
    headers: &HeaderMap,
    query: &WebContextQuery,
) -> StatusOperationsJsonResponse {
    let context = web_context_from_request(query, headers, state).await;
    let store_statuses = status_store_statuses(state);
    let configured_stores = store_statuses
        .iter()
        .filter(|store| store.configured)
        .count() as i64;
    let rust_only = env_flag_enabled("RUST_ONLY_MODE");
    let strict_mode = env_flag_enabled("RUST_STRICT_MODE");
    let migration_status = match state.database_url.as_deref() {
        Some(database_url) => match db_admin::migration_status(database_url).await {
            Ok(status) => MigrationStatusView::Ready(status),
            Err(err) => MigrationStatusView::Error(err.to_string()),
        },
        None => MigrationStatusView::Missing,
    };
    let operations_overview = status_operations_overview(
        state,
        context.as_ref(),
        &migration_status,
        rust_only,
        strict_mode,
        configured_stores,
        store_statuses.len() as i64,
    )
    .await;
    let product_security_trends = product_security_trends_for_status(state, context.as_ref()).await;
    let alertmanager_incidents =
        alertmanager_incident_metrics_for_status(state, context.as_ref()).await;
    let alertmanager_incident_details =
        alertmanager_incident_details_for_status(state, context.as_ref()).await;
    StatusOperationsJsonResponse {
        accepted: true,
        api_version: "v1",
        service: "iscy-rust-backend",
        tenant_id: context.as_ref().map(|context| context.tenant_id),
        user_id: context.as_ref().map(|context| context.user_id),
        issue_count: operations_overview.issue_count,
        severity: operations_overview.severity,
        exit_code: operations_overview.exit_code,
        runtime: StatusRuntimeJson {
            rust_only,
            strict_mode,
            evidence_media_root: state
                .evidence_media_root
                .as_ref()
                .map(|path| path.display().to_string()),
            nvd_api_base_url: state
                .nvd_api_base_url
                .as_deref()
                .unwrap_or("NVD-Default")
                .to_string(),
        },
        security: StatusSecurityJson {
            app_mode: state.security_config.mode_label().to_string(),
            trust_identity_headers: state.security_config.trust_identity_headers,
            trusted_proxy_configured: state.security_config.trusted_proxy_configured,
            secure_cookies: state.security_config.secure_cookies,
            https_confirmed: state.security_config.https_confirmed,
            hsts_enabled: state.security_config.hsts_enabled,
        },
        migration: status_migration_json(&migration_status),
        build: StatusBuildJson {
            version: env!("CARGO_PKG_VERSION"),
            commit: build_commit(),
            profile: option_env!("PROFILE").unwrap_or("unknown"),
            target: option_env!("TARGET").unwrap_or("unknown"),
        },
        modules: store_statuses,
        signals: operations_overview.signals,
        alertmanager_incidents,
        alertmanager_incident_details,
        product_security_trends,
    }
}

fn status_operations_metrics_body(payload: &StatusOperationsJsonResponse) -> String {
    let configured_modules = payload
        .modules
        .iter()
        .filter(|module| module.configured)
        .count();
    let tenant_id = payload
        .tenant_id
        .map(|tenant_id| tenant_id.to_string())
        .unwrap_or_else(|| "none".to_string());
    let user_id = payload
        .user_id
        .map(|user_id| user_id.to_string())
        .unwrap_or_else(|| "none".to_string());
    let mut body = String::new();
    body.push_str(
        "# HELP iscy_operations_context_info ISCY operations context metadata.\n\
         # TYPE iscy_operations_context_info gauge\n",
    );
    body.push_str(&format!(
        "iscy_operations_context_info{{service=\"{}\",tenant_id=\"{}\",user_id=\"{}\"}} 1\n",
        prometheus_label_value(payload.service),
        prometheus_label_value(&tenant_id),
        prometheus_label_value(&user_id),
    ));
    body.push_str(
        "# HELP iscy_operations_build_info ISCY Rust backend build metadata.\n\
         # TYPE iscy_operations_build_info gauge\n",
    );
    body.push_str(&format!(
        "iscy_operations_build_info{{version=\"{}\",commit=\"{}\",profile=\"{}\",target=\"{}\"}} 1\n",
        prometheus_label_value(payload.build.version),
        prometheus_label_value(&payload.build.commit),
        prometheus_label_value(payload.build.profile),
        prometheus_label_value(payload.build.target),
    ));
    body.push_str(
        "# HELP iscy_operations_exit_code Overall ISCY operations exit code: 0 ok, 1 warn, 2 critical.\n\
         # TYPE iscy_operations_exit_code gauge\n",
    );
    body.push_str(&format!(
        "iscy_operations_exit_code{{severity=\"{}\"}} {}\n",
        payload.severity.as_label(),
        payload.exit_code,
    ));
    body.push_str(
        "# HELP iscy_operations_issue_count Number of warning or critical operation signals.\n\
         # TYPE iscy_operations_issue_count gauge\n",
    );
    body.push_str(&format!(
        "iscy_operations_issue_count {}\n",
        payload.issue_count
    ));
    body.push_str(
        "# HELP iscy_operations_runtime_flag Runtime flag state, 1 enabled and 0 disabled.\n\
         # TYPE iscy_operations_runtime_flag gauge\n",
    );
    body.push_str(&format!(
        "iscy_operations_runtime_flag{{name=\"rust_only\"}} {}\n",
        bool_metric(payload.runtime.rust_only)
    ));
    body.push_str(&format!(
        "iscy_operations_runtime_flag{{name=\"strict_mode\"}} {}\n",
        bool_metric(payload.runtime.strict_mode)
    ));
    body.push_str(
        "# HELP iscy_operations_security_flag Security hardening flag state, 1 enabled and 0 disabled.\n\
         # TYPE iscy_operations_security_flag gauge\n",
    );
    body.push_str(&format!(
        "iscy_operations_security_flag{{name=\"trust_identity_headers\",app_mode=\"{}\"}} {}\n",
        prometheus_label_value(&payload.security.app_mode),
        bool_metric(payload.security.trust_identity_headers)
    ));
    body.push_str(&format!(
        "iscy_operations_security_flag{{name=\"trusted_proxy_configured\",app_mode=\"{}\"}} {}\n",
        prometheus_label_value(&payload.security.app_mode),
        bool_metric(payload.security.trusted_proxy_configured)
    ));
    body.push_str(&format!(
        "iscy_operations_security_flag{{name=\"secure_cookies\",app_mode=\"{}\"}} {}\n",
        prometheus_label_value(&payload.security.app_mode),
        bool_metric(payload.security.secure_cookies)
    ));
    body.push_str(&format!(
        "iscy_operations_security_flag{{name=\"https_confirmed\",app_mode=\"{}\"}} {}\n",
        prometheus_label_value(&payload.security.app_mode),
        bool_metric(payload.security.https_confirmed)
    ));
    body.push_str(&format!(
        "iscy_operations_security_flag{{name=\"hsts_enabled\",app_mode=\"{}\"}} {}\n",
        prometheus_label_value(&payload.security.app_mode),
        bool_metric(payload.security.hsts_enabled)
    ));
    body.push_str(
        "# HELP iscy_operations_migration_applied Applied Rust database migrations.\n\
         # TYPE iscy_operations_migration_applied gauge\n",
    );
    body.push_str(&format!(
        "iscy_operations_migration_applied{{level=\"{}\",readable=\"{}\"}} {}\n",
        payload.migration.level.as_label(),
        payload.migration.readable,
        payload.migration.applied_count,
    ));
    body.push_str(
        "# HELP iscy_operations_migration_expected Expected Rust database migrations.\n\
         # TYPE iscy_operations_migration_expected gauge\n",
    );
    body.push_str(&format!(
        "iscy_operations_migration_expected {}\n",
        payload.migration.expected_count
    ));
    body.push_str(
        "# HELP iscy_operations_modules_configured Number of configured Rust stores/modules.\n\
         # TYPE iscy_operations_modules_configured gauge\n",
    );
    body.push_str(&format!(
        "iscy_operations_modules_configured {}\n",
        configured_modules
    ));
    body.push_str(
        "# HELP iscy_operations_modules_total Total expected Rust stores/modules.\n\
         # TYPE iscy_operations_modules_total gauge\n",
    );
    body.push_str(&format!(
        "iscy_operations_modules_total {}\n",
        payload.modules.len()
    ));
    body.push_str(
        "# HELP iscy_operations_module_configured Rust store/module configured flag, 1 configured and 0 missing.\n\
         # TYPE iscy_operations_module_configured gauge\n",
    );
    for module in &payload.modules {
        body.push_str(&format!(
            "iscy_operations_module_configured{{name=\"{}\",scope=\"{}\"}} {}\n",
            prometheus_label_value(module.name),
            prometheus_label_value(module.scope),
            bool_metric(module.configured),
        ));
    }
    body.push_str(
        "# HELP iscy_operations_signal Operation signal state: 0 ok, 1 warn, 2 critical.\n\
         # TYPE iscy_operations_signal gauge\n",
    );
    for signal in &payload.signals {
        body.push_str(&format!(
            "iscy_operations_signal{{area=\"{}\",signal=\"{}\",level=\"{}\"}} {}\n",
            prometheus_label_value(&signal.area),
            prometheus_label_value(&signal.signal),
            signal.level.as_label(),
            signal.level.metric_value(),
        ));
    }
    if let Some(metrics) = payload.alertmanager_incidents.as_ref() {
        push_alertmanager_incident_metrics(&mut body, metrics);
    }
    if let Some(details) = payload.alertmanager_incident_details.as_ref() {
        push_alertmanager_incident_detail_metrics(&mut body, details);
    }
    if let Some(trends) = payload.product_security_trends.as_ref() {
        push_product_security_trend_metrics(&mut body, trends);
    }
    body
}

async fn alertmanager_incident_metrics_for_status(
    state: &AppState,
    context: Option<&WebContext>,
) -> Option<IncidentAlertmanagerMetrics> {
    let context = context?;
    let store = state.incident_store.as_ref()?;
    store.alertmanager_metrics(context.tenant_id).await.ok()
}

async fn alertmanager_incident_details_for_status(
    state: &AppState,
    context: Option<&WebContext>,
) -> Option<Vec<StatusAlertmanagerIncidentDetail>> {
    let context = context?;
    let store = state.incident_store.as_ref()?;
    let require_resolution_review = alertmanager_resolution_review_required();
    store
        .list_incidents(context.tenant_id, 75)
        .await
        .ok()
        .map(|incidents| {
            incidents
                .into_iter()
                .filter(|incident| incident.authority_reference.starts_with("Alertmanager:"))
                .map(|incident| {
                    let state = alertmanager_incident_state(&incident).to_string();
                    let review_required = alertmanager_resolution_review_required_for_incident(
                        &incident,
                        require_resolution_review,
                    );
                    StatusAlertmanagerIncidentDetail {
                        id: incident.id,
                        title: incident.title,
                        severity: incident.severity,
                        status: incident.status,
                        state,
                        review_required,
                        href: web_path_with_context(
                            &format!("/incidents/{}", incident.id),
                            Some(context),
                        ),
                    }
                })
                .collect::<Vec<_>>()
        })
}

fn alertmanager_incident_state(incident: &incident_store::IncidentSummary) -> &'static str {
    if matches!(incident.status.as_str(), "RESOLVED" | "CLOSED") {
        "resolved"
    } else if incident.severity == "CRITICAL" {
        "critical_open"
    } else {
        "open"
    }
}

fn push_alertmanager_incident_metrics(body: &mut String, metrics: &IncidentAlertmanagerMetrics) {
    body.push_str(
        "# HELP iscy_operations_alertmanager_incidents_total Alertmanager-origin incidents by state.\n\
         # TYPE iscy_operations_alertmanager_incidents_total gauge\n",
    );
    for (state, value) in [
        ("all", metrics.total),
        ("open", metrics.open),
        ("triage", metrics.triage),
        ("critical_open", metrics.critical_open),
        ("resolved", metrics.resolved),
    ] {
        body.push_str(&format!(
            "iscy_operations_alertmanager_incidents_total{{state=\"{}\"}} {}\n",
            state, value,
        ));
    }
}

fn push_alertmanager_incident_detail_metrics(
    body: &mut String,
    details: &[StatusAlertmanagerIncidentDetail],
) {
    body.push_str(
        "# HELP iscy_operations_alertmanager_incident_info Alertmanager-origin incident detail labels for Grafana drilldowns.\n\
         # TYPE iscy_operations_alertmanager_incident_info gauge\n",
    );
    for incident in details {
        body.push_str(&format!(
            "iscy_operations_alertmanager_incident_info{{incident_id=\"{}\",title=\"{}\",severity=\"{}\",status=\"{}\",state=\"{}\",review_required=\"{}\",href=\"{}\"}} 1\n",
            incident.id,
            prometheus_label_value(&incident.title),
            prometheus_label_value(&incident.severity),
            prometheus_label_value(&incident.status),
            prometheus_label_value(&incident.state),
            incident.review_required,
            prometheus_label_value(&incident.href),
        ));
    }
}

async fn product_security_trends_for_status(
    state: &AppState,
    context: Option<&WebContext>,
) -> Option<product_security_store::ProductSecurityTrendDashboard> {
    let context = context?;
    let store = state.product_security_store.as_ref()?;
    store
        .overview(context.tenant_id, 25, 10)
        .await
        .ok()
        .flatten()
        .map(|overview| overview.trend_dashboard)
}

fn push_product_security_trend_metrics(
    body: &mut String,
    trends: &product_security_store::ProductSecurityTrendDashboard,
) {
    body.push_str(
        "# HELP iscy_product_security_coverage_percent Product Security coverage by kind.\n\
         # TYPE iscy_product_security_coverage_percent gauge\n",
    );
    body.push_str(&format!(
        "iscy_product_security_coverage_percent{{kind=\"sbom\"}} {}\n",
        trends.coverage.sbom_coverage_percent,
    ));
    body.push_str(&format!(
        "iscy_product_security_coverage_percent{{kind=\"csaf\"}} {}\n",
        trends.coverage.csaf_coverage_percent,
    ));
    body.push_str(&format!(
        "iscy_product_security_coverage_percent{{kind=\"threat_tara\"}} {}\n",
        trends.coverage.threat_tara_coverage_percent,
    ));
    body.push_str(
        "# HELP iscy_product_security_coverage_total Product Security raw coverage counters.\n\
         # TYPE iscy_product_security_coverage_total gauge\n",
    );
    for (kind, value) in [
        ("products", trends.coverage.product_count),
        ("components", trends.coverage.component_count),
        ("components_with_sbom", trends.coverage.components_with_sbom),
        ("products_with_csaf", trends.coverage.products_with_csaf),
        (
            "products_with_threat_tara",
            trends.coverage.products_with_threat_tara,
        ),
    ] {
        body.push_str(&format!(
            "iscy_product_security_coverage_total{{kind=\"{}\"}} {}\n",
            kind, value,
        ));
    }
    body.push_str(
        "# HELP iscy_product_security_import_validation_total Product Security import validation counters.\n\
         # TYPE iscy_product_security_import_validation_total gauge\n",
    );
    for (status, value) in [
        ("total", trends.import_validation.total_imports),
        ("valid", trends.import_validation.valid_imports),
        ("warning", trends.import_validation.warning_imports),
        ("invalid", trends.import_validation.invalid_imports),
        ("errors", trends.import_validation.validation_error_count),
    ] {
        body.push_str(&format!(
            "iscy_product_security_import_validation_total{{status=\"{}\"}} {}\n",
            status, value,
        ));
    }
    body.push_str(
        "# HELP iscy_product_security_trend_signal Product Security trend signal current value.\n\
         # TYPE iscy_product_security_trend_signal gauge\n",
    );
    for signal in &trends.signals {
        body.push_str(&format!(
            "iscy_product_security_trend_signal{{key=\"{}\",label=\"{}\",status=\"{}\",direction=\"{}\"}} {}\n",
            prometheus_label_value(&signal.key),
            prometheus_label_value(&signal.label),
            prometheus_label_value(&signal.status),
            prometheus_label_value(&signal.direction),
            signal.current,
        ));
    }
    body.push_str(
        "# HELP iscy_product_security_snapshot_readiness_percent Product Security snapshot readiness by product and dimension.\n\
         # TYPE iscy_product_security_snapshot_readiness_percent gauge\n",
    );
    for snapshot in &trends.snapshot_points {
        for (dimension, value) in [
            ("cra", snapshot.cra_readiness_percent),
            ("ai_act", snapshot.ai_act_readiness_percent),
            ("threat_model", snapshot.threat_model_coverage_percent),
            ("psirt", snapshot.psirt_readiness_percent),
        ] {
            body.push_str(&format!(
                "iscy_product_security_snapshot_readiness_percent{{product_id=\"{}\",product_name=\"{}\",dimension=\"{}\"}} {}\n",
                snapshot.product_id,
                prometheus_label_value(&snapshot.product_name),
                dimension,
                value,
            ));
        }
    }
    body.push_str(
        "# HELP iscy_product_security_snapshot_open_vulnerabilities Product Security snapshot open vulnerabilities by product and severity bucket.\n\
         # TYPE iscy_product_security_snapshot_open_vulnerabilities gauge\n",
    );
    for snapshot in &trends.snapshot_points {
        body.push_str(&format!(
            "iscy_product_security_snapshot_open_vulnerabilities{{product_id=\"{}\",product_name=\"{}\",severity=\"all\"}} {}\n",
            snapshot.product_id,
            prometheus_label_value(&snapshot.product_name),
            snapshot.open_vulnerability_count,
        ));
        body.push_str(&format!(
            "iscy_product_security_snapshot_open_vulnerabilities{{product_id=\"{}\",product_name=\"{}\",severity=\"critical\"}} {}\n",
            snapshot.product_id,
            prometheus_label_value(&snapshot.product_name),
            snapshot.critical_vulnerability_count,
        ));
    }
}

fn prometheus_label_value(value: &str) -> String {
    value
        .replace('\\', r"\\")
        .replace('"', r#"\""#)
        .replace('\n', r"\n")
}

fn bool_metric(value: bool) -> i64 {
    if value {
        1
    } else {
        0
    }
}

async fn web_status_control_gaps_generate_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(_) => return web_missing_context("Rust-only Status", "/status/").into_response(),
    };
    let context = WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    };
    if !auth_context.can_write() {
        return web_error_page(
            "Rust-only Status",
            "/status/",
            &context,
            "Diese Rust-Webroute benoetigt eine schreibende ISCY-Rolle.",
        )
        .into_response();
    }
    let Some(store) = state.control_store else {
        return web_store_missing("Rust-only Status", "/status/", &context, "Control")
            .into_response();
    };
    match store
        .generate_roadmap_from_gaps(auth_context.tenant_id)
        .await
    {
        Ok(_) => Redirect::to(&web_path_with_context("/roadmap/", Some(&context))).into_response(),
        Err(err) => web_error_page("Rust-only Status", "/status/", &context, &err.to_string())
            .into_response(),
    }
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

async fn web_controls(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
        return web_missing_context("ISCY-27 Controls", "/controls/");
    };
    let can_write = authenticated_tenant_context(&state, &headers)
        .await
        .is_ok_and(|auth_context| auth_context.can_write());
    let Some(store) = state.control_store else {
        return web_store_missing("ISCY-27 Controls", "/controls/", &context, "Control");
    };
    match store.library(context.tenant_id).await {
        Ok(library) => {
            let evidence_gap_count = library
                .controls
                .iter()
                .filter(|control| control.evidence_status != "EVIDENCED")
                .count() as i64;
            let roadmap_open_count = library
                .controls
                .iter()
                .map(|control| control.roadmap_open_task_count)
                .sum::<i64>();
            let effective_count = library
                .controls
                .iter()
                .filter(|control| control.status == "EFFECTIVE")
                .count() as i64;
            let framework_mapping_count = library
                .controls
                .iter()
                .map(|control| control.mapping_count)
                .sum::<i64>();
            let control_signal_panel = format!(
                r#"<article class="panel wide">
                    <h2>Steuerungsindikatoren</h2>
                    <table>
                      <thead><tr><th>Signal</th><th>Status</th><th>Naechster Fokus</th></tr></thead>
                      <tbody>
                        <tr><td>Control-Gaps</td><td>{}</td><td>{}</td></tr>
                        <tr><td>Evidence-Luecken</td><td>{}</td><td>{}</td></tr>
                        <tr><td>Roadmap-Backlog</td><td>{}</td><td>{}</td></tr>
                        <tr><td>Regulatory Mapping</td><td>{}</td><td>{} Mappings ueber {} Frameworks gepflegt</td></tr>
                      </tbody>
                    </table>
                  </article>"#,
                signal_badge(library.gap_controls == 0),
                if library.gap_controls == 0 {
                    "Alle Controls mindestens teilweise abgedeckt"
                } else {
                    "Gap-Tasks erzeugen und Owner pruefen"
                },
                signal_badge(evidence_gap_count == 0),
                if evidence_gap_count == 0 {
                    "Evidence-Stand stabil halten"
                } else {
                    "Nachweise direkt an Controls verknuepfen"
                },
                signal_badge(roadmap_open_count == 0),
                if roadmap_open_count == 0 {
                    "Keine offenen Control-Tasks"
                } else {
                    "Offene Tasks priorisieren und Fristen setzen"
                },
                signal_badge(framework_mapping_count > 0 && effective_count > 0),
                framework_mapping_count,
                library.framework_count,
            );
            let group_rows = library
                .groups
                .iter()
                .map(|group| {
                    format!(
                        r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{:.2}</td></tr>"#,
                        html_escape(&group.code),
                        html_escape(&group.name),
                        group.control_count,
                        group.covered_count,
                        group.average_maturity,
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let control_rows = library
                .controls
                .iter()
                .map(|control| {
                    let status_cell = if can_write {
                        format!(
                            r#"<form class="inline-form" method="post" action="{}">
                                <select name="status">{}</select>
                                <input name="maturity_score" type="number" min="0" max="5" value="{}">
                                <select name="evidence_status">{}</select>
                                <input name="notes" type="text" value="{}">
                                <button type="submit">Speichern</button>
                              </form>"#,
                            web_path_with_context(
                                &format!("/controls/{}/status", control.id),
                                Some(&context),
                            ),
                            control_status_options_for(&control.status),
                            control.maturity_score,
                            control_evidence_status_options_for(&control.evidence_status),
                            html_escape(&control.tenant_notes),
                        )
                    } else {
                        format!(
                            "{}<br>{}/{}<br>{}",
                            web_badge(
                                &control.status_label,
                                control_status_badge_class(&control.status),
                            ),
                            control.maturity_score,
                            control.maturity_target,
                            web_badge(
                                &control.evidence_status_label,
                                evidence_status_badge_class(&control.evidence_status),
                            ),
                        )
                    };
                    format!(
                        r#"<tr><td>{}</td><td><strong>{}</strong><p>{}</p></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}/{}</td><td>{}</td></tr>"#,
                        html_escape(&control.code),
                        html_escape(&control.title),
                        html_escape(&control.objective),
                        html_escape(&control.group_name),
                        status_cell,
                        framework_badges(&control.frameworks),
                        control.evidence_count,
                        control.roadmap_open_task_count,
                        control.roadmap_task_count,
                        html_escape(control.owner_display.as_deref().unwrap_or("-")),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let control_options = library
                .controls
                .iter()
                .map(|control| {
                    format!(
                        r#"<option value="{}">{} · {}</option>"#,
                        control.id,
                        html_escape(&control.code),
                        html_escape(&control.title),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let action_panel = if can_write {
                format!(
                    r#"<article class="panel wide">
                        <h2>Control-Arbeit</h2>
                        <form method="post" action="{}">
                          <button type="submit">Gap-Tasks erzeugen</button>
                        </form>
                        <form method="post" action="{}" enctype="multipart/form-data">
                          <input type="hidden" name="return_to" value="{}">
                          <div class="form-grid">
                            <label>Control<select name="control_id">{}</select></label>
                            <label>Titel<input name="title" type="text" required></label>
                            <label>Status<select name="status">{}</select></label>
                            <label>Schutzklasse<select name="sensitivity">{}</select></label>
                            <label>Gueltig bis<input name="valid_until" type="date"></label>
                            <label>Aufbewahren bis<input name="retention_until" type="date"></label>
                          </div>
                          <label>Linked Requirement<input name="linked_requirement" type="text" value="ISCY-27"></label>
                          <label>Beschreibung<textarea name="description" rows="3"></textarea></label>
                          <label>Retention-Begruendung<textarea name="retention_reason" rows="2"></textarea></label>
                          <label>Datei<input name="file" type="file" accept=".pdf,.docx,.xlsx,.png,.jpg,.jpeg,.csv,.txt"></label>
                          <button type="submit">Evidence an Control haengen</button>
                        </form>
                      </article>"#,
                    web_path_with_context("/controls/roadmap/generate", Some(&context)),
                    web_path_with_context("/evidence/", Some(&context)),
                    html_escape(&web_path_with_context("/controls/", Some(&context))),
                    control_options,
                    evidence_status_options_for("SUBMITTED"),
                    evidence_sensitivity_options_for("INTERNAL"),
                )
            } else {
                String::new()
            };
            let mapping_rows = library
                .controls
                .iter()
                .flat_map(|control| {
                    control.mappings.iter().map(move |mapping| {
                        format!(
                            r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                            html_escape(&control.code),
                            html_escape(&mapping.framework_label),
                            html_escape(&mapping.source_code),
                            html_escape(&mapping.legal_reference),
                            html_escape(&mapping.coverage_level_label),
                            html_escape(&mapping.rationale),
                        )
                    })
                })
                .collect::<Vec<_>>()
                .join("");
            let body = format!(
                r#"
                <section class="hero compact">
                  <h1>ISCY-27 Controls</h1>
                  <p>Funktionaler Steuerungskern fuer NIS2, DORA, AI Act, CRA, DSGVO, TISAX und ISO 27001.</p>
                  <p class="muted">Frameworks: {}</p>
                </section>
                <section class="metrics">
                  {}
                  {}
                  {}
                  {}
                  {}
                </section>
                <section class="grid">
                  {}
                  <article class="panel wide">
                    <h2>Control-Gruppen</h2>
                    <table>
                      <thead><tr><th>Code</th><th>Gruppe</th><th>Controls</th><th>Abgedeckt</th><th>Maturity</th></tr></thead>
                      <tbody>{}</tbody>
                    </table>
                  </article>
                  <article class="panel wide">
                    <h2>27-Control Heatmap</h2>
                    <table>
                      <thead><tr><th>Control</th><th>Titel</th><th>Gruppe</th><th>Status / Reife / Nachweis</th><th>Frameworks</th><th>Evidence</th><th>Roadmap</th><th>Owner</th></tr></thead>
                      <tbody>{}</tbody>
                    </table>
                  </article>
                  {}
                  <article class="panel wide">
                    <h2>Regulatory Crosswalk</h2>
                    <table>
                      <thead><tr><th>Control</th><th>Framework</th><th>Quelle</th><th>Referenz</th><th>Coverage</th><th>Rationale</th></tr></thead>
                      <tbody>{}</tbody>
                    </table>
                  </article>
                </section>
                "#,
                html_escape(&library.frameworks.join(", ")),
                metric_card("Controls", library.total_controls),
                metric_card("Abgedeckt", library.covered_controls),
                metric_card("Gaps", library.gap_controls),
                metric_card("Maturity", library.average_maturity.round() as i64),
                metric_card("Frameworks", library.framework_count),
                control_signal_panel,
                if group_rows.is_empty() {
                    web_empty_row(5, "Keine Control-Gruppen vorhanden.")
                } else {
                    group_rows
                },
                if control_rows.is_empty() {
                    web_empty_row(8, "Keine Controls vorhanden.")
                } else {
                    control_rows
                },
                action_panel,
                if mapping_rows.is_empty() {
                    web_empty_row(6, "Keine Regulatory Mappings vorhanden.")
                } else {
                    mapping_rows
                },
            );
            web_page("ISCY-27 Controls", "/controls/", Some(&context), &body)
        }
        Err(err) => web_error_page("ISCY-27 Controls", "/controls/", &context, &err.to_string()),
    }
}

async fn web_control_status_submit(
    Path(control_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<WebControlStatusForm>,
) -> Response {
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(_) => return web_missing_context("ISCY-27 Controls", "/controls/").into_response(),
    };
    let context = WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    };
    if !auth_context.can_write() {
        return web_error_page(
            "ISCY-27 Controls",
            "/controls/",
            &context,
            "Diese Rust-Webroute benoetigt eine schreibende ISCY-Rolle.",
        )
        .into_response();
    }
    let Some(store) = state.control_store else {
        return web_store_missing("ISCY-27 Controls", "/controls/", &context, "Control")
            .into_response();
    };
    let payload = control_store::ControlStatusUpdateRequest {
        status: form.status,
        maturity_score: form.maturity_score,
        evidence_status: form.evidence_status,
        notes: form.notes,
        owner_id: Some(auth_context.user_id),
    };
    match store
        .update_status(
            auth_context.tenant_id,
            auth_context.user_id,
            control_id,
            payload,
        )
        .await
    {
        Ok(Some(_)) => {
            Redirect::to(&web_path_with_context("/controls/", Some(&context))).into_response()
        }
        Ok(None) => web_error_page(
            "ISCY-27 Controls",
            "/controls/",
            &context,
            "ISCY-Control wurde nicht gefunden.",
        )
        .into_response(),
        Err(err) => web_error_page("ISCY-27 Controls", "/controls/", &context, &err.to_string())
            .into_response(),
    }
}

async fn web_control_roadmap_generate_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(_) => return web_missing_context("ISCY-27 Controls", "/controls/").into_response(),
    };
    let context = WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    };
    if !auth_context.can_write() {
        return web_error_page(
            "ISCY-27 Controls",
            "/controls/",
            &context,
            "Diese Rust-Webroute benoetigt eine schreibende ISCY-Rolle.",
        )
        .into_response();
    }
    let Some(store) = state.control_store else {
        return web_store_missing("ISCY-27 Controls", "/controls/", &context, "Control")
            .into_response();
    };
    match store
        .generate_roadmap_from_gaps(auth_context.tenant_id)
        .await
    {
        Ok(_) => Redirect::to(&web_path_with_context("/roadmap/", Some(&context))).into_response(),
        Err(err) => web_error_page("ISCY-27 Controls", "/controls/", &context, &err.to_string())
            .into_response(),
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
    let Some(store) = state.tenant_store.as_ref() else {
        return web_store_missing("Organizations", "/organizations/", &context, "Tenant");
    };
    let can_write = authenticated_tenant_context(&state, &headers)
        .await
        .is_ok_and(|auth_context| auth_context.can_write());
    match store.tenant_profile(context.tenant_id).await {
        Ok(Some(tenant)) => {
            let operation_countries = if tenant.operation_countries.is_empty() {
                "-".to_string()
            } else {
                html_escape(&tenant.operation_countries.join(", "))
            };
            let regulatory_rows = tenant_regulatory_profile_rows(&tenant);
            let edit_panel = if can_write {
                tenant_regulatory_profile_form(&tenant, &context)
            } else {
                r#"<section class="panel wide"><h2>Regulatorisches Organisationsprofil</h2><p>Dieses Profil ist lesbar. Zum Speichern wird eine schreibende ISCY-Rolle benoetigt.</p></section>"#.to_string()
            };
            let body = format!(
                r#"
                <section class="hero compact"><h1>Organizations</h1><p>{}</p></section>
                <section class="metrics">
                  {}
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
                      <tr><th>DORA relevant</th><td>{}</td></tr>
                      <tr><th>DORA Finanzunternehmen</th><td>{}</td></tr>
                      <tr><th>DORA IKT-Drittdienstleister</th><td>{}</td></tr>
                      <tr><th>Personenbezogene Daten</th><td>{}</td></tr>
                      <tr><th>DSGVO Verantwortlicher</th><td>{}</td></tr>
                      <tr><th>DSGVO Auftragsverarbeiter</th><td>{}</td></tr>
                      <tr><th>Besondere Datenkategorien</th><td>{}</td></tr>
                      <tr><th>CRA relevant</th><td>{}</td></tr>
                      <tr><th>AI-Act-Profil</th><td>{}</td></tr>
                      <tr><th>AI Act Hochrisiko</th><td>{}</td></tr>
                      <tr><th>TISAX relevant</th><td>{}</td></tr>
                      <tr><th>ISO-27001 Zielbild</th><td>{}</td></tr>
                      <tr><th>Regulatorische Notizen</th><td>{}</td></tr>
                      <tr><th>Beschreibung</th><td>{}</td></tr>
                    </tbody>
                  </table>
                </section>
                <section class="panel wide">
                  <h2>Regulatorische Matrix</h2>
                  <table>
                    <thead><tr><th>Pfad</th><th>Status</th><th>Warum</th><th>Naechster Schritt</th></tr></thead>
                    <tbody>{}</tbody>
                  </table>
                </section>
                {}
                "#,
                html_escape(&tenant.name),
                metric_card("Mitarbeitende", tenant.employee_count),
                metric_card("Laender", tenant.operation_countries.len() as i64),
                metric_card("Tenant-ID", tenant.id),
                metric_card("Aktive Pfade", tenant_regulatory_active_count(&tenant)),
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
                yes_no(tenant.dora_relevant),
                yes_no(tenant.dora_financial_entity),
                yes_no(tenant.dora_ict_third_party_provider),
                yes_no(tenant.processes_personal_data),
                yes_no(tenant.gdpr_controller),
                yes_no(tenant.gdpr_processor),
                yes_no(tenant.gdpr_special_categories),
                yes_no(tenant.cra_relevant),
                html_escape(&tenant.ai_act_profile),
                yes_no(tenant.ai_act_high_risk),
                yes_no(tenant.tisax_relevant),
                html_escape(&tenant.iso27001_target),
                html_escape(&tenant.regulatory_profile_notes),
                html_escape(&tenant.description),
                regulatory_rows,
                edit_panel,
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

async fn web_organizations_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
    Form(form): Form<WebTenantRegulatoryProfileForm>,
) -> Response {
    let display_context = web_context_from_request(&query, &headers, &state).await;
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(err) => {
            if let Some(context) = display_context.as_ref() {
                return web_error_page("Organizations", "/organizations/", context, err.message())
                    .into_response();
            }
            return web_missing_context("Organizations", "/organizations/").into_response();
        }
    };
    let context = display_context.unwrap_or_else(|| WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    });
    if !auth_context.can_write() {
        return web_error_page(
            "Organizations",
            "/organizations/",
            &context,
            "Diese Rust-Webroute benoetigt eine schreibende ISCY-Rolle.",
        )
        .into_response();
    }
    let Some(store) = state.tenant_store else {
        return web_store_missing("Organizations", "/organizations/", &context, "Tenant")
            .into_response();
    };
    let payload = match tenant_regulatory_profile_form_request(form) {
        Ok(payload) => payload,
        Err(err) => {
            return web_error_page("Organizations", "/organizations/", &context, &err)
                .into_response();
        }
    };
    match store
        .update_regulatory_profile(context.tenant_id, payload)
        .await
    {
        Ok(Some(_)) => {
            Redirect::to(&web_path_with_context("/organizations/", Some(&context))).into_response()
        }
        Ok(None) => web_error_page(
            "Organizations",
            "/organizations/",
            &context,
            "Tenant wurde fuer diesen Kontext nicht gefunden.",
        )
        .into_response(),
        Err(err) => web_error_page(
            "Organizations",
            "/organizations/",
            &context,
            &err.to_string(),
        )
        .into_response(),
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

async fn web_ai_governance(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
        return web_missing_context("AI Governance", "/ai-governance/");
    };
    let can_write = authenticated_tenant_context(&state, &headers)
        .await
        .is_ok_and(|auth_context| auth_context.can_write());
    let Some(store) = state.ai_governance_store.as_ref() else {
        return web_store_missing(
            "AI Governance",
            "/ai-governance/",
            &context,
            "AI Governance",
        );
    };

    match store.overview(context.tenant_id, 200).await {
        Ok(overview) => {
            let product_options = ai_governance_product_options(&state, context.tenant_id).await;
            let system_rows = overview
                .systems
                .iter()
                .map(|system| {
                    let evidence_href = evidence_prefill_href(
                        &context,
                        &format!("AI-Governance Evidence: {}", system.name),
                        &format!(
                            "Nachweis fuer AI-Governance-System {}. Einstufung: {}. Status: {}.",
                            system.name,
                            system.ai_act_classification_label,
                            system.status_label,
                        ),
                        &system.evidence_key,
                        Some("SUBMITTED"),
                        Some(&web_path_with_context("/ai-governance/", Some(&context))),
                    );
                    format!(
                        r##"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><a href="{}">Evidence</a></td><td><a href="#ai-system-{}">Review</a></td></tr>"##,
                        html_escape(&system.name),
                        html_escape(system.product_name.as_deref().unwrap_or("-")),
                        html_escape(&system.model_provider),
                        web_badge(
                            &system.ai_act_classification_label,
                            ai_governance_classification_class(&system.ai_act_classification),
                        ),
                        web_badge(&system.status_label, ai_governance_status_class(&system.status)),
                        html_escape(system.next_review_due_at.as_deref().unwrap_or("-")),
                        system.open_requirement_count,
                        evidence_href,
                        system.id,
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let detail_panels = overview
                .systems
                .iter()
                .map(|system| ai_governance_system_panel(&context, system, can_write))
                .collect::<Vec<_>>()
                .join("");
            let create_panel = if can_write {
                format!(
                    r#"<article class="panel wide">
                    <h2>AI-System anlegen</h2>
                    <form method="post" action="{}">
                      <div class="form-grid">
                        <label>Name<input name="name" required></label>
                        <label>Produkt<select name="product_id"><option value="">Tenantweit</option>{}</select></label>
                        <label>Provider<input name="model_provider"></label>
                        <label>Modell<input name="model_name"></label>
                        <label>Version<input name="model_version"></label>
                        <label>AI-Act-Klasse<select name="ai_act_classification">{}</select></label>
                        <label>Kritikalitaet<select name="criticality">{}</select></label>
                        <label>Naechster Review<input name="next_review_due_at" type="date"></label>
                      </div>
                      <label>Zweck<textarea name="purpose" rows="2"></textarea></label>
                      <label>Deployment-Kontext<textarea name="deployment_context" rows="2"></textarea></label>
                      <label>Datenkategorien<textarea name="data_categories" rows="2"></textarea></label>
                      <label>Entscheidungswirkung<textarea name="decision_impact" rows="2"></textarea></label>
                      <label>Human Oversight<textarea name="human_oversight" rows="2"></textarea></label>
                      <label>Monitoringplan<textarea name="monitoring_plan" rows="2"></textarea></label>
                      <label>Evidence-Key<input name="evidence_key" placeholder="AI-GOV:SYSTEM:..."></label>
                      <label>Risikosummary<textarea name="risk_summary" rows="2"></textarea></label>
                      <label>Notizen<textarea name="notes" rows="2"></textarea></label>
                      <button type="submit">Anlegen</button>
                    </form>
                  </article>"#,
                    web_path_with_context("/ai-governance/systems", Some(&context)),
                    product_options,
                    ai_governance_classification_options("NOT_ASSESSED"),
                    ai_governance_criticality_options("MEDIUM"),
                )
            } else {
                String::new()
            };
            let body = format!(
                r#"
                <section class="hero compact"><h1>AI Governance</h1><p>Tenant {} · AI-Systemregister, Einstufung, Review und Evidence</p></section>
                <section class="metrics">
                  {}
                  {}
                  {}
                  {}
                  {}
                  {}
                </section>
                <section class="grid">
                  <article class="panel wide">
                    <h2>AI-Systemregister</h2>
                    <table>
                      <thead><tr><th>System</th><th>Produkt</th><th>Provider</th><th>Klasse</th><th>Status</th><th>Review</th><th>Gaps</th><th>Evidence</th><th>Details</th></tr></thead>
                      <tbody>{}</tbody>
                    </table>
                  </article>
                  {}
                  {}
                </section>
                "#,
                context.tenant_id,
                metric_card("AI-Systeme", overview.summary.total_systems),
                metric_card("High Risk", overview.summary.high_risk_systems),
                metric_card("Nicht bewertet", overview.summary.not_assessed_systems),
                metric_card("Review faellig", overview.summary.review_due_systems),
                metric_card("Evidence fehlt", overview.summary.evidence_missing),
                metric_card("Governance-Gaps", overview.summary.open_governance_gaps),
                if system_rows.is_empty() {
                    web_empty_row(9, "Noch keine AI-Systeme vorhanden.")
                } else {
                    system_rows
                },
                create_panel,
                detail_panels,
            );
            web_page("AI Governance", "/ai-governance/", Some(&context), &body)
        }
        Err(err) => web_error_page(
            "AI Governance",
            "/ai-governance/",
            &context,
            &err.to_string(),
        ),
    }
}

async fn web_ai_governance_create_system(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<WebAiGovernanceCreateForm>,
) -> Response {
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(_) => return web_missing_context("AI Governance", "/ai-governance/").into_response(),
    };
    let context = WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    };
    if !auth_context.can_write() {
        return web_error_page(
            "AI Governance",
            "/ai-governance/",
            &context,
            "Diese Rust-Webroute benoetigt eine schreibende ISCY-Rolle.",
        )
        .into_response();
    }
    let Some(store) = state.ai_governance_store else {
        return web_store_missing(
            "AI Governance",
            "/ai-governance/",
            &context,
            "AI Governance",
        )
        .into_response();
    };
    let payload = ai_governance_create_payload_from_form(form);
    match store.create_system(auth_context.tenant_id, payload).await {
        Ok(_) => {
            Redirect::to(&web_path_with_context("/ai-governance/", Some(&context))).into_response()
        }
        Err(err) => web_error_page(
            "AI Governance",
            "/ai-governance/",
            &context,
            &err.to_string(),
        )
        .into_response(),
    }
}

async fn web_ai_governance_update_system(
    Path(system_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<WebAiGovernanceUpdateForm>,
) -> Response {
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(_) => return web_missing_context("AI Governance", "/ai-governance/").into_response(),
    };
    let context = WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    };
    if !auth_context.can_write() {
        return web_error_page(
            "AI Governance",
            "/ai-governance/",
            &context,
            "Diese Rust-Webroute benoetigt eine schreibende ISCY-Rolle.",
        )
        .into_response();
    }
    let Some(store) = state.ai_governance_store else {
        return web_store_missing(
            "AI Governance",
            "/ai-governance/",
            &context,
            "AI Governance",
        )
        .into_response();
    };
    let payload = ai_governance_update_payload_from_form(form);
    match store
        .update_system(auth_context.tenant_id, system_id, payload)
        .await
    {
        Ok(Some(_)) => {
            Redirect::to(&web_path_with_context("/ai-governance/", Some(&context))).into_response()
        }
        Ok(None) => web_error_page(
            "AI Governance",
            "/ai-governance/",
            &context,
            "AI-Governance-System wurde fuer diesen Tenant nicht gefunden.",
        )
        .into_response(),
        Err(err) => web_error_page(
            "AI Governance",
            "/ai-governance/",
            &context,
            &err.to_string(),
        )
        .into_response(),
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
    let can_write = authenticated_tenant_context(&state, &headers)
        .await
        .is_ok_and(|auth_context| auth_context.can_write());
    let Some(store) = state.product_security_store.as_ref() else {
        return web_store_missing(
            "Product Security",
            "/product-security/",
            &context,
            "Product Security",
        );
    };
    match store.overview(context.tenant_id, 50, 20).await {
        Ok(Some(overview)) => {
            let product_security_config = match state.tenant_store.as_ref() {
                Some(tenant_store) => match tenant_store.tenant_profile(context.tenant_id).await {
                    Ok(Some(tenant)) => {
                        product_security_scope_config(&tenant.product_security_scope)
                    }
                    Ok(None) | Err(_) => ProductSecurityScopeConfig {
                        scope: String::new(),
                        thresholds: ProductSecurityThresholds::default(),
                    },
                },
                None => ProductSecurityScopeConfig {
                    scope: String::new(),
                    thresholds: ProductSecurityThresholds::default(),
                },
            };
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
            let mut cra_readiness_items = Vec::new();
            for product in &overview.products {
                if let Ok(Some(readiness)) =
                    store.cra_readiness(context.tenant_id, product.id).await
                {
                    cra_readiness_items.push(readiness);
                }
            }
            let cra_readiness_rows = cra_readiness_items
                .iter()
                .map(|readiness| {
                    let weakest = readiness
                        .dimensions
                        .iter()
                        .min_by_key(|dimension| dimension.score_percent)
                        .map(|dimension| {
                            format!("{} {}%", dimension.label, dimension.score_percent)
                        })
                        .unwrap_or_else(|| "-".to_string());
                    format!(
                        r#"<tr><td>{}</td><td>{}%</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                        html_escape(&readiness.product_name),
                        readiness.readiness_percent,
                        web_badge(
                            &readiness.status_label,
                            product_security_cra_status_class(&readiness.status)
                        ),
                        html_escape(&weakest),
                        html_escape(&readiness.summary),
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
                        r#"<tr><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}/{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
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
                        product.sbom_component_count,
                        product.component_count,
                        product.csaf_advisory_count,
                        product.cve_count,
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
            let import_rows = overview
                .import_artifacts
                .iter()
                .map(|artifact| {
                    let errors = if artifact.validation_errors.is_empty() {
                        "Keine".to_string()
                    } else {
                        artifact
                            .validation_errors
                            .iter()
                            .map(|error| html_escape(error))
                            .collect::<Vec<_>>()
                            .join("<br>")
                    };
                    format!(
                        r#"<tr><td>{}</td><td><a href="{}">{}</a></td><td>{}</td><td>{} {}</td><td>{}</td><td>{}</td><td>{}/{}</td><td>{}</td><td>{}</td></tr>"#,
                        html_escape(&artifact.artifact_type),
                        web_path_with_context(
                            &format!("/product-security/imports/{}", artifact.id),
                            Some(&context),
                        ),
                        html_escape(&artifact.file_name),
                        html_escape(artifact.product_name.as_deref().unwrap_or("Tenantweit")),
                        html_escape(&artifact.format_name),
                        html_escape(&artifact.format_version),
                        html_escape(&artifact.validation_status),
                        errors,
                        artifact.matched_component_count,
                        artifact.component_count,
                        artifact.cve_count,
                        html_escape(&artifact.created_at),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let correlation_rows = overview
                .cve_correlations
                .iter()
                .map(|correlation| {
                    let actions = if can_write && correlation.status == "SUGGESTED" {
                        format!(
                            r#"<form method="post" action="{}" class="inline-form">
                                <input type="hidden" name="status" value="ACCEPTED">
                                <input type="hidden" name="rationale" value="Fachlich akzeptiert im Product-Security-Review.">
                                <button type="submit">Akzeptieren</button>
                              </form>
                              <form method="post" action="{}" class="inline-form">
                                <input type="hidden" name="status" value="REJECTED">
                                <input type="hidden" name="rationale" value="Fachlich abgelehnt im Product-Security-Review.">
                                <button type="submit">Ablehnen</button>
                              </form>"#,
                            web_path_with_context(
                                &format!(
                                    "/product-security/cve-correlations/{}",
                                    correlation.id
                                ),
                                Some(&context),
                            ),
                            web_path_with_context(
                                &format!(
                                    "/product-security/cve-correlations/{}",
                                    correlation.id
                                ),
                                Some(&context),
                            ),
                        )
                    } else if can_write && correlation.status == "ACCEPTED" {
                        let evidence_href = evidence_prefill_href(
                            &context,
                            &format!("CVE-Evidence: {}", correlation.cve),
                            &format!(
                                "Nachweis zur akzeptierten CVE-Korrelation {}. Asset: {}. Produkt: {}. Komponente: {}. Match: {} {}.",
                                correlation.cve,
                                correlation.asset_name.as_deref().unwrap_or("-"),
                                correlation.product_name.as_deref().unwrap_or("-"),
                                correlation.component_name.as_deref().unwrap_or("-"),
                                correlation.match_type,
                                correlation.match_value,
                            ),
                            &format!("PRODUCT-SECURITY:CVE:{}", correlation.cve),
                            Some("SUBMITTED"),
                            Some(&web_path_with_context("/product-security/", Some(&context))),
                        );
                        format!(r#"<a href="{}">Evidence verknuepfen</a>"#, evidence_href)
                    } else {
                        "-".to_string()
                    };
                    format!(
                        r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code><br>{}</td><td>{}%</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                        html_escape(&correlation.cve),
                        html_escape(correlation.asset_name.as_deref().unwrap_or("-")),
                        html_escape(correlation.product_name.as_deref().unwrap_or("-")),
                        html_escape(correlation.component_name.as_deref().unwrap_or("-")),
                        html_escape(&correlation.match_type),
                        html_escape(&correlation.match_value),
                        correlation.confidence,
                        html_escape(&correlation.status),
                        html_escape(&correlation.rationale),
                        actions,
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let active_review_filter =
                product_security_review_filter(query.review_filter.as_deref());
            let product_security_return =
                product_security_review_filter_path(&context, active_review_filter);
            let risk_missing_count = overview
                .cve_risk_review_queue
                .iter()
                .filter(|item| item.risk_id.is_none())
                .count() as i64;
            let review_filter_links = product_security_review_filter_links(
                &context,
                active_review_filter,
                overview.cve_risk_review_queue.len() as i64,
                overview.review_metrics.open_risk_reviews,
                overview.review_metrics.evidence_missing,
                risk_missing_count,
            );
            let review_bulk_controls = if can_write {
                format!(
                    r#"<form id="product-security-review-bulk" method="post" action="{}" class="inline-form">
                        <input type="hidden" name="review_filter" value="{}">
                        <label>Bulk-Aktion
                          <select name="action">
                            <option value="generate_work">Risiko/Roadmap erzeugen</option>
                            <option value="approve_treatment">Behandlung freigeben</option>
                            <option value="accept_risk">Restrisiko akzeptieren</option>
                            <option value="mark_mitigated">Als mitigiert markieren</option>
                          </select>
                        </label>
                        <button type="submit">Auf Auswahl anwenden</button>
                      </form>"#,
                    web_path_with_context(
                        "/product-security/cve-risk-reviews/bulk",
                        Some(&context),
                    ),
                    html_escape(active_review_filter),
                )
            } else {
                String::new()
            };
            let review_queue_rows = overview
                .cve_risk_review_queue
                .iter()
                .filter(|item| product_security_review_filter_matches(item, active_review_filter))
                .map(|item| {
                    let target = [
                        item.asset_name.as_deref(),
                        item.product_name.as_deref(),
                        item.component_name.as_deref(),
                    ]
                    .into_iter()
                    .flatten()
                    .filter(|value| !value.trim().is_empty())
                    .collect::<Vec<_>>()
                    .join(" / ");
                    let evidence_href = evidence_prefill_href(
                        &context,
                        &format!("CVE-Evidence: {}", item.cve),
                        &format!(
                            "Nachweis zur CVE-Risiko-Review-Queue {}. Ziel: {}. Match: {} {}. Risiko: {}.",
                            item.cve,
                            if target.is_empty() { "-" } else { target.as_str() },
                            item.match_type,
                            item.match_value,
                            item.risk_title.as_deref().unwrap_or("noch nicht erzeugt"),
                        ),
                        &item.evidence_key,
                        Some("SUBMITTED"),
                        Some(&product_security_return),
                    );
                    let risk_display = match (item.risk_id, item.risk_title.as_deref()) {
                        (Some(id), Some(title)) => {
                            format!("#{} {}", id, html_escape(title))
                        }
                        (Some(id), None) => format!("#{}", id),
                        (None, _) => "Risiko fehlt".to_string(),
                    };
                    let roadmap_display =
                        item.roadmap_task_title.as_deref().unwrap_or("Task fehlt");
                    let evidence_display = if item.evidence_missing {
                        "Fehlt".to_string()
                    } else {
                        format!("{} Nachweis(e)", item.evidence_count)
                    };
                    let review_state = if item.needs_review {
                        "Review offen"
                    } else {
                        "Abgeschlossen"
                    };
                    let selection = if can_write {
                        format!(
                            r#"<input form="product-security-review-bulk" type="checkbox" name="correlation_id" value="{}" aria-label="{} auswaehlen">"#,
                            item.correlation_id,
                            html_escape(&item.cve),
                        )
                    } else {
                        "-".to_string()
                    };
                    let actions = if can_write {
                        if let Some(risk_id) = item.risk_id {
                            let action = web_path_with_context(
                                &format!("/risks/{}/review", risk_id),
                                Some(&context),
                            );
                            format!(
                                r#"<form method="post" action="{}" class="inline-form">
                                    <input type="hidden" name="action" value="approve_treatment">
                                    <input type="hidden" name="review_notes" value="CVE-Risiko im Product-Security-Review zur Behandlung freigegeben.">
                                    <button type="submit">Behandlung</button>
                                  </form>
                                  <form method="post" action="{}" class="inline-form">
                                    <input type="hidden" name="action" value="accept_risk">
                                    <input type="hidden" name="review_notes" value="CVE-Restrisiko nach Product-Security-Review akzeptiert.">
                                    <button type="submit">Akzeptieren</button>
                                  </form>
                                  <form method="post" action="{}" class="inline-form">
                                    <input type="hidden" name="action" value="mark_mitigated">
                                    <input type="hidden" name="review_notes" value="CVE-Massnahme umgesetzt und Evidence verknuepft.">
                                    <button type="submit">Mitigiert</button>
                                  </form>"#,
                                action, action, action,
                            )
                        } else {
                            format!(
                                r#"<form method="post" action="{}" class="inline-form">
                                    <button type="submit">Risiko erzeugen</button>
                                  </form>"#,
                                web_path_with_context(
                                    "/product-security/cve-correlations/generate-work",
                                    Some(&context),
                                ),
                            )
                        }
                    } else {
                        "-".to_string()
                    };
                    format!(
                        r#"<tr><td>{}</td><td>{}<br><small>{}% Confidence</small></td><td>{}</td><td>{}<br><small>{} · {}</small></td><td>{}<br><small>{}</small></td><td>{}</td><td><a href="{}">Evidence</a></td><td>{}</td></tr>"#,
                        selection,
                        html_escape(&item.cve),
                        item.confidence,
                        html_escape(if target.is_empty() { "-" } else { target.as_str() }),
                        risk_display,
                        html_escape(&item.risk_status_label),
                        review_state,
                        html_escape(roadmap_display),
                        html_escape(&item.roadmap_task_status_label),
                        evidence_display,
                        evidence_href,
                        actions,
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let product_options = overview
                .products
                .iter()
                .map(|product| {
                    format!(
                        r#"<option value="{}">{} · {}</option>"#,
                        product.id,
                        html_escape(&product.code),
                        html_escape(&product.name),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let import_export_actions = format!(
                r#"<div class="inline-actions">
                    <a href="{}">CSV Export</a>
                    <a href="{}">JSON Export</a>
                  </div>"#,
                web_path_with_context("/product-security/imports.csv", Some(&context)),
                web_path_with_context("/product-security/imports.json", Some(&context)),
            );
            let sbom_artifacts = overview
                .import_artifacts
                .iter()
                .filter(|artifact| artifact.artifact_type == "SBOM")
                .collect::<Vec<_>>();
            let sbom_diff_action = if sbom_artifacts.len() >= 2 {
                let target = sbom_artifacts[0];
                let base = sbom_artifacts[1];
                format!(
                    r#"<div class="inline-actions"><a href="{}">Letzte zwei SBOMs vergleichen</a></div>"#,
                    web_path_with_context(
                        &format!(
                            "/product-security/sbom-diff?base_artifact_id={}&target_artifact_id={}",
                            base.id, target.id
                        ),
                        Some(&context),
                    )
                )
            } else {
                String::new()
            };
            let import_panel = if can_write {
                format!(
                    r#"<article class="panel wide">
                    <h2>Security Advisories & SBOM</h2>
                    <div class="grid">
                      <form method="post" action="{}" enctype="multipart/form-data">
                        <h3>CSAF importieren</h3>
                        <label>Produkt<select name="product_id"><option value="">Tenantweit</option>{}</select></label>
                        <label>Datei<input name="file" type="file" accept=".json,.csaf" required></label>
                        <button type="submit">CSAF validieren</button>
                      </form>
                      <form method="post" action="{}" enctype="multipart/form-data">
                        <h3>SBOM importieren</h3>
                        <label>Produkt<select name="product_id"><option value="">Tenantweit</option>{}</select></label>
                        <label>Datei<input name="file" type="file" accept=".json,.spdx,.cdx" required></label>
                        <button type="submit">SBOM abgleichen</button>
                      </form>
                      <form method="post" action="{}">
                        <h3>CVE-Korrelation</h3>
                        <button type="submit">CVE-Asset-Vorschlaege erzeugen</button>
                      </form>
                      <form method="post" action="{}">
                        <h3>Risiko & Roadmap</h3>
                        <button type="submit">Akzeptierte CVEs uebernehmen</button>
                      </form>
                    </div>
                  </article>"#,
                    web_path_with_context("/product-security/import/csaf", Some(&context)),
                    product_options,
                    web_path_with_context("/product-security/import/sbom", Some(&context)),
                    overview
                        .products
                        .iter()
                        .map(|product| {
                            format!(
                                r#"<option value="{}">{} · {}</option>"#,
                                product.id,
                                html_escape(&product.code),
                                html_escape(&product.name),
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(""),
                    web_path_with_context("/product-security/cve-correlations", Some(&context)),
                    web_path_with_context(
                        "/product-security/cve-correlations/generate-work",
                        Some(&context),
                    ),
                )
            } else {
                String::new()
            };
            let total_components = overview
                .products
                .iter()
                .map(|product| product.component_count)
                .sum::<i64>();
            let sbom_components = overview
                .products
                .iter()
                .map(|product| product.sbom_component_count)
                .sum::<i64>();
            let products_with_csaf = overview
                .products
                .iter()
                .filter(|product| product.csaf_advisory_count > 0)
                .count() as i64;
            let products_with_threat_model = overview
                .products
                .iter()
                .filter(|product| product.threat_model_count > 0 && product.tara_count > 0)
                .count() as i64;
            let product_count = overview.products.len() as i64;
            let sbom_coverage = ratio_percent(sbom_components, total_components);
            let csaf_coverage = ratio_percent(products_with_csaf, product_count);
            let threat_coverage = ratio_percent(products_with_threat_model, product_count);
            let review_backlog = overview.review_metrics.open_cve_reviews
                + overview.review_metrics.open_risk_reviews
                + overview.review_metrics.evidence_missing;
            let thresholds = product_security_config.thresholds;
            let product_security_signal_panel = format!(
                r#"<article class="panel wide">
                    <h2>Product-Security-Steuerung</h2>
                    <table>
                      <thead><tr><th>Signal</th><th>Wert</th><th>Status</th><th>Naechster Fokus</th></tr></thead>
                      <tbody>
                        <tr><td>SBOM Coverage</td><td>{}%</td><td>{}</td><td>{}/{} Komponenten mit SBOM</td></tr>
                        <tr><td>CSAF Coverage</td><td>{}%</td><td>{}</td><td>{}/{} Produkte mit Advisory-Spur</td></tr>
                        <tr><td>Threat/TARA Coverage</td><td>{}%</td><td>{}</td><td>{}/{} Produkte mit Threat Model und TARA</td></tr>
                        <tr><td>Review-Backlog</td><td>{}</td><td>{}</td><td>CVE-, Risiko- und Evidence-Reviews buendeln</td></tr>
                        <tr><td>Kritische Schwachstellen</td><td>{}</td><td>{}</td><td>PSIRT, Roadmap und Evidence zusammenfuehren</td></tr>
                      </tbody>
                    </table>
                  </article>"#,
                sbom_coverage,
                signal_badge(
                    total_components == 0 || sbom_coverage >= thresholds.sbom_coverage_min
                ),
                sbom_components,
                total_components,
                csaf_coverage,
                signal_badge(product_count == 0 || csaf_coverage >= thresholds.csaf_coverage_min),
                products_with_csaf,
                product_count,
                threat_coverage,
                signal_badge(
                    product_count == 0 || threat_coverage >= thresholds.threat_tara_coverage_min
                ),
                products_with_threat_model,
                product_count,
                review_backlog,
                signal_badge(review_backlog <= thresholds.review_backlog_max),
                overview.posture.critical_open_vulnerabilities,
                signal_badge(
                    overview.posture.critical_open_vulnerabilities
                        <= thresholds.critical_open_vulnerabilities_max,
                ),
            );
            let trend_signal_rows = overview
                .trend_dashboard
                .signals
                .iter()
                .map(|signal| {
                    let previous = signal
                        .previous
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "-".to_string());
                    let delta = signal
                        .delta
                        .map(|value| format!("{value:+}"))
                        .unwrap_or_else(|| "-".to_string());
                    format!(
                        r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                        html_escape(&signal.label),
                        signal.current,
                        previous,
                        delta,
                        web_badge(
                            product_security_trend_status_label(&signal.status),
                            product_security_trend_status_class(&signal.status),
                        ),
                        html_escape(&signal.detail),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let snapshot_trend_rows = overview
                .trend_dashboard
                .snapshot_points
                .iter()
                .map(|point| {
                    format!(
                        r#"<tr><td>{}</td><td>{}</td><td>{}%</td><td>{}%</td><td>{}%</td><td>{}%</td><td>{}</td><td>{}</td></tr>"#,
                        html_escape(&point.created_at),
                        html_escape(&point.product_name),
                        point.cra_readiness_percent,
                        point.ai_act_readiness_percent,
                        point.threat_model_coverage_percent,
                        point.psirt_readiness_percent,
                        point.open_vulnerability_count,
                        point.critical_vulnerability_count,
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let trend_panel = format!(
                r#"<article class="panel wide">
                    <h2>Product-Security-Trends</h2>
                    <table>
                      <thead><tr><th>Signal</th><th>Aktuell</th><th>Vorher</th><th>Delta</th><th>Status</th><th>Detail</th></tr></thead>
                      <tbody>{}</tbody>
                    </table>
                    <h3>Snapshot-Verlauf</h3>
                    <table>
                      <thead><tr><th>Zeit</th><th>Produkt</th><th>CRA</th><th>AI Act</th><th>Threat</th><th>PSIRT</th><th>Offen</th><th>Kritisch</th></tr></thead>
                      <tbody>{}</tbody>
                    </table>
                    <p>Importvalidierung: {} valide, {} Warnung(en), {} fehlerhaft, {} Validierungsdetail(s).</p>
                  </article>"#,
                if trend_signal_rows.is_empty() {
                    web_empty_row(6, "Noch keine Trenddaten vorhanden.")
                } else {
                    trend_signal_rows
                },
                if snapshot_trend_rows.is_empty() {
                    web_empty_row(8, "Noch keine Snapshots fuer Trendverlauf vorhanden.")
                } else {
                    snapshot_trend_rows
                },
                overview.trend_dashboard.import_validation.valid_imports,
                overview.trend_dashboard.import_validation.warning_imports,
                overview.trend_dashboard.import_validation.invalid_imports,
                overview
                    .trend_dashboard
                    .import_validation
                    .validation_error_count,
            );
            let threshold_panel = product_security_threshold_panel(
                &context,
                &product_security_config,
                can_write && state.tenant_store.is_some(),
            );
            let body = format!(
                r#"
                <section class="hero compact"><h1>Product Security</h1><p>Tenant {} · {}</p></section>
                <section class="metrics">
                  {}
                  {}
                  {}
                  {}
                  {}
                  {}
                </section>
                <section class="grid">
                  {}
                  {}
                  {}
                  <article class="panel wide">
                    <h2>Regulatorische Matrix</h2>
                    <p>{}</p>
                    <table>
                      <thead><tr><th>Framework</th><th>Applicable</th><th>Status</th><th>Begruendung</th></tr></thead>
                      <tbody>{}</tbody>
                    </table>
                  </article>
                  <article class="panel wide">
                    <h2>CRA-Readiness</h2>
                    <table>
                      <thead><tr><th>Produkt</th><th>Readiness</th><th>Status</th><th>Schwaechstes Signal</th><th>Summary</th></tr></thead>
                      <tbody>{}</tbody>
                    </table>
                  </article>
                  <article class="panel wide">
                    <h2>Produkte</h2>
                    <table>
                      <thead><tr><th>Produkt</th><th>Familie</th><th>Code</th><th>Beschreibung</th><th>Scope</th><th>Releases</th><th>SBOM</th><th>CSAF</th><th>CVEs</th><th>Schwachstellen</th><th>PSIRT</th></tr></thead>
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
                  {}
                  <article class="panel wide">
                    <h2>Import-Historie</h2>
                    {}
                    {}
                    <table>
                      <thead><tr><th>Typ</th><th>Datei</th><th>Produkt</th><th>Format</th><th>Status</th><th>Validierung</th><th>SBOM</th><th>CVEs</th><th>Zeit</th></tr></thead>
                      <tbody>{}</tbody>
                    </table>
                  </article>
                  <article class="panel wide">
                    <h2>CVE-Risiko-Review-Queue</h2>
                    {}
                    {}
                    <table>
                      <thead><tr><th>Auswahl</th><th>CVE</th><th>Ziel</th><th>Risiko</th><th>Roadmap</th><th>Evidence</th><th>Verknuepfen</th><th>Review</th></tr></thead>
                      <tbody>{}</tbody>
                    </table>
                  </article>
                  <article class="panel wide">
                    <h2>CVE-Asset-Korrelationen</h2>
                    <table>
                      <thead><tr><th>CVE</th><th>Asset</th><th>Produkt</th><th>Komponente</th><th>Match</th><th>Confidence</th><th>Status</th><th>Rationale</th><th>Review</th></tr></thead>
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
                metric_card(
                    "CVE-Reviews offen",
                    overview.review_metrics.open_cve_reviews
                ),
                metric_card("Evidence fehlt", overview.review_metrics.evidence_missing),
                product_security_signal_panel,
                trend_panel,
                threshold_panel,
                html_escape(&overview.matrix.summary),
                if matrix_rows.is_empty() {
                    web_empty_row(4, "Keine Matrixdaten vorhanden.")
                } else {
                    matrix_rows
                },
                if cra_readiness_rows.is_empty() {
                    web_empty_row(5, "Noch keine CRA-Readiness-Daten vorhanden.")
                } else {
                    cra_readiness_rows
                },
                if product_rows.is_empty() {
                    web_empty_row(11, "Keine Produkte vorhanden.")
                } else {
                    product_rows
                },
                if snapshot_rows.is_empty() {
                    web_empty_row(6, "Keine Snapshots vorhanden.")
                } else {
                    snapshot_rows
                },
                import_panel,
                import_export_actions,
                sbom_diff_action,
                if import_rows.is_empty() {
                    web_empty_row(9, "Noch keine CSAF-/SBOM-Importe vorhanden.")
                } else {
                    import_rows
                },
                review_filter_links,
                review_bulk_controls,
                if review_queue_rows.is_empty() {
                    web_empty_row(
                        8,
                        &format!(
                            "Keine CVE-Risiken fuer Filter {}.",
                            product_security_review_filter_label(active_review_filter)
                        ),
                    )
                } else {
                    review_queue_rows
                },
                if correlation_rows.is_empty() {
                    web_empty_row(9, "Noch keine CVE-Asset-Korrelationen vorhanden.")
                } else {
                    correlation_rows
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

async fn web_product_security_thresholds_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<WebProductSecurityThresholdForm>,
) -> Response {
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(_) => {
            return web_missing_context("Product Security", "/product-security/").into_response()
        }
    };
    let context = WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    };
    if !auth_context.can_write() {
        return web_error_page(
            "Product Security",
            "/product-security/",
            &context,
            "Diese Rust-Webroute benoetigt eine schreibende ISCY-Rolle.",
        )
        .into_response();
    }
    let Some(tenant_store) = state.tenant_store else {
        return web_store_missing("Product Security", "/product-security/", &context, "Tenant")
            .into_response();
    };
    let thresholds = match product_security_thresholds_from_form(&form) {
        Ok(thresholds) => thresholds,
        Err(message) => {
            return web_error_page("Product Security", "/product-security/", &context, &message)
                .into_response()
        }
    };
    let scope = form.scope.unwrap_or_default();
    let scope_config = product_security_scope_config_json(&scope, thresholds);
    match tenant_store
        .update_product_security_scope(auth_context.tenant_id, &scope_config)
        .await
    {
        Ok(Some(_)) => Redirect::to(&web_path_with_context("/product-security/", Some(&context)))
            .into_response(),
        Ok(None) => web_error_page(
            "Product Security",
            "/product-security/",
            &context,
            "Tenant wurde nicht gefunden.",
        )
        .into_response(),
        Err(err) => web_error_page(
            "Product Security",
            "/product-security/",
            &context,
            &err.to_string(),
        )
        .into_response(),
    }
}

async fn web_product_security_import_detail(
    Path(artifact_id): Path<i64>,
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
    match store.import_detail(context.tenant_id, artifact_id).await {
        Ok(Some(detail)) => {
            let artifact = &detail.artifact;
            let validation_rows = if artifact.validation_errors.is_empty() {
                r#"<li>Keine Validierungsfehler.</li>"#.to_string()
            } else {
                artifact
                    .validation_errors
                    .iter()
                    .map(|error| format!("<li>{}</li>", html_escape(error)))
                    .collect::<Vec<_>>()
                    .join("")
            };
            let component_rows = detail
                .components
                .iter()
                .map(|component| {
                    let evidence_href = evidence_prefill_href(
                        &context,
                        &format!(
                            "Product-Security-Evidence: {} {}",
                            component.name, component.version
                        ),
                        &format!(
                            "Nachweis fuer Import {} / Komponente {} {}. Match: {}. CPE: {}. PURL: {}.",
                            artifact.file_name,
                            component.name,
                            component.version,
                            component.match_reason,
                            component.cpe23_uri,
                            component.package_url,
                        ),
                        &format!(
                            "PRODUCT-SECURITY:IMPORT:{}:COMPONENT:{}",
                            artifact.id, component.id
                        ),
                        None,
                        Some(&web_path_with_context(
                            &format!("/product-security/imports/{}", artifact.id),
                            Some(&context),
                        )),
                    );
                    format!(
                        r#"<tr><td>{}<br><small>{}</small></td><td>{}</td><td>{}</td><td><code>{}</code><br><code>{}</code></td><td>{}</td><td>{}<br><small>{}</small></td><td><a href="{}">Evidence verknuepfen</a></td></tr>"#,
                        html_escape(&component.name),
                        html_escape(&component.version),
                        html_escape(component.product_name.as_deref().unwrap_or("-")),
                        html_escape(component.component_name.as_deref().unwrap_or("-")),
                        html_escape(&component.cpe23_uri),
                        html_escape(&component.package_url),
                        html_escape(&component.supplier_name),
                        html_escape(&component.match_status_label),
                        html_escape(&component.match_reason),
                        evidence_href,
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let body = format!(
                r#"
                <section class="hero compact"><h1>Import {}</h1><p>{} · {} {} · {}</p></section>
                <section class="metrics">
                  {}
                  {}
                  {}
                </section>
                <section class="grid">
                  <article class="panel wide">
                    <h2>Validierung</h2>
                    <p>Status: {}</p>
                    <ul>{}</ul>
                  </article>
                  <article class="panel wide">
                    <h2>Komponenten-Matches</h2>
                    <table>
                      <thead><tr><th>Import-Komponente</th><th>Produkt</th><th>ISCY-Komponente</th><th>Identifier</th><th>Supplier</th><th>Match</th><th>Evidence</th></tr></thead>
                      <tbody>{}</tbody>
                    </table>
                  </article>
                </section>
                "#,
                artifact.id,
                html_escape(&artifact.artifact_type),
                html_escape(&artifact.format_name),
                html_escape(&artifact.format_version),
                html_escape(&artifact.file_name),
                metric_card("Komponenten", artifact.component_count),
                metric_card("Matches", artifact.matched_component_count),
                metric_card("CVEs", artifact.cve_count),
                html_escape(&artifact.validation_status),
                validation_rows,
                if component_rows.is_empty() {
                    web_empty_row(7, "Keine Komponenten-Matches fuer diesen Import vorhanden.")
                } else {
                    component_rows
                },
            );
            web_page(
                "Product Security Import",
                "/product-security/",
                Some(&context),
                &body,
            )
        }
        Ok(None) => web_error_page(
            "Product Security",
            "/product-security/",
            &context,
            "Product-Security-Import wurde fuer diesen Tenant nicht gefunden.",
        ),
        Err(err) => web_error_page(
            "Product Security",
            "/product-security/",
            &context,
            &err.to_string(),
        ),
    }
}

async fn web_product_security_sbom_diff(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebProductSecuritySbomDiffQuery>,
) -> Html<String> {
    let context_query = WebContextQuery {
        tenant_id: query.tenant_id,
        user_id: query.user_id,
        user_email: query.user_email.clone(),
        ..WebContextQuery::default()
    };
    let Some(context) = web_context_from_request(&context_query, &headers, &state).await else {
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
    match store
        .sbom_diff(
            context.tenant_id,
            query.base_artifact_id,
            query.target_artifact_id,
        )
        .await
    {
        Ok(Some(diff)) => {
            let component_rows = diff
                .components
                .iter()
                .map(|component| {
                    format!(
                        r#"<tr><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                        html_escape(&component.name),
                        web_badge(&component.status_label, product_security_sbom_diff_status_class(&component.status)),
                        html_escape(&component.identity_key),
                        html_escape(component.base_version.as_deref().unwrap_or("-")),
                        html_escape(component.target_version.as_deref().unwrap_or("-")),
                        html_escape(component.target_match_status.as_deref().unwrap_or("-")),
                        html_escape(&component.detail),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let body = format!(
                r#"
                <section class="hero compact"><h1>SBOM-Diff</h1><p>{} -> {}</p></section>
                <section class="metrics">
                  {}
                  {}
                  {}
                  {}
                  {}
                </section>
                <section class="grid">
                  <article class="panel wide">
                    <h2>Vergleich</h2>
                    <p>Basis: #{} {} · Ziel: #{} {}</p>
                    <table>
                      <thead><tr><th>Komponente</th><th>Status</th><th>Identitaet</th><th>Basis-Version</th><th>Ziel-Version</th><th>Match</th><th>Detail</th></tr></thead>
                      <tbody>{}</tbody>
                    </table>
                  </article>
                </section>
                "#,
                html_escape(&diff.base_artifact.file_name),
                html_escape(&diff.target_artifact.file_name),
                metric_card("Neu", diff.summary.added),
                metric_card("Entfernt", diff.summary.removed),
                metric_card("Geaendert", diff.summary.changed),
                metric_card("Unveraendert", diff.summary.unchanged),
                metric_card("Verglichen", diff.summary.total_compared),
                diff.base_artifact.id,
                html_escape(&diff.base_artifact.file_name),
                diff.target_artifact.id,
                html_escape(&diff.target_artifact.file_name),
                if component_rows.is_empty() {
                    web_empty_row(7, "Keine Komponenten im SBOM-Diff vorhanden.")
                } else {
                    component_rows
                },
            );
            web_page("SBOM-Diff", "/product-security/", Some(&context), &body)
        }
        Ok(None) => web_error_page(
            "Product Security",
            "/product-security/",
            &context,
            "Mindestens ein SBOM-Import wurde fuer diesen Tenant nicht gefunden.",
        ),
        Err(err) => web_error_page(
            "Product Security",
            "/product-security/",
            &context,
            &err.to_string(),
        ),
    }
}

async fn web_product_security_import_csaf(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    web_product_security_import(state, headers, body, "CSAF").await
}

async fn web_product_security_import_sbom(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    web_product_security_import(state, headers, body, "SBOM").await
}

async fn web_product_security_imports_csv(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Response {
    web_product_security_import_history_export(
        state,
        headers,
        query,
        ProductSecurityImportHistoryFormat::Csv,
    )
    .await
}

async fn web_product_security_imports_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Response {
    web_product_security_import_history_export(
        state,
        headers,
        query,
        ProductSecurityImportHistoryFormat::Json,
    )
    .await
}

async fn web_product_security_import_history_export(
    state: AppState,
    headers: HeaderMap,
    query: WebContextQuery,
    export_format: ProductSecurityImportHistoryFormat,
) -> Response {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
        return web_missing_context("Product Security", "/product-security/").into_response();
    };
    let Some(store) = state.product_security_store else {
        return web_store_missing(
            "Product Security",
            "/product-security/",
            &context,
            "Product Security",
        )
        .into_response();
    };
    match store.import_history(context.tenant_id, 500).await {
        Ok(artifacts) => product_security_import_history_download_response(
            context.tenant_id,
            &artifacts,
            export_format,
        ),
        Err(err) => web_error_page(
            "Product Security",
            "/product-security/",
            &context,
            &err.to_string(),
        )
        .into_response(),
    }
}

async fn web_product_security_import(
    state: AppState,
    headers: HeaderMap,
    body: Bytes,
    artifact_type: &str,
) -> Response {
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(_) => {
            return web_missing_context("Product Security", "/product-security/").into_response()
        }
    };
    let context = WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    };
    if !auth_context.can_write() {
        return web_error_page(
            "Product Security",
            "/product-security/",
            &context,
            "Diese Rust-Webroute benoetigt eine schreibende ISCY-Rolle.",
        )
        .into_response();
    }
    let Some(store) = state.product_security_store else {
        return web_store_missing(
            "Product Security",
            "/product-security/",
            &context,
            "Product Security",
        )
        .into_response();
    };
    let form = match parse_import_upload_form(&headers, &body) {
        Ok(form) => form,
        Err(message) => {
            return web_error_page("Product Security", "/product-security/", &context, &message)
                .into_response();
        }
    };
    let payload = match product_security_import_request_from_form(&form) {
        Ok(payload) => payload,
        Err(message) => {
            return web_error_page("Product Security", "/product-security/", &context, &message)
                .into_response();
        }
    };
    let result = if artifact_type == "CSAF" {
        store
            .import_csaf(auth_context.tenant_id, auth_context.user_id, payload)
            .await
    } else {
        store
            .import_sbom(auth_context.tenant_id, auth_context.user_id, payload)
            .await
    };
    match result {
        Ok(_) => Redirect::to(&web_path_with_context("/product-security/", Some(&context)))
            .into_response(),
        Err(err) => web_error_page(
            "Product Security",
            "/product-security/",
            &context,
            &err.to_string(),
        )
        .into_response(),
    }
}

async fn web_product_security_cve_correlation_generate_work(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(_) => {
            return web_missing_context("Product Security", "/product-security/").into_response()
        }
    };
    let context = WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    };
    if !auth_context.can_write() {
        return web_error_page(
            "Product Security",
            "/product-security/",
            &context,
            "Diese Rust-Webroute benoetigt eine schreibende ISCY-Rolle.",
        )
        .into_response();
    }
    let Some(store) = state.product_security_store else {
        return web_store_missing(
            "Product Security",
            "/product-security/",
            &context,
            "Product Security",
        )
        .into_response();
    };
    match store
        .generate_work_from_accepted_correlations(auth_context.tenant_id)
        .await
    {
        Ok(_) => Redirect::to(&web_path_with_context("/product-security/", Some(&context)))
            .into_response(),
        Err(err) => web_error_page(
            "Product Security",
            "/product-security/",
            &context,
            &err.to_string(),
        )
        .into_response(),
    }
}

async fn web_product_security_cve_reviews_bulk(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<WebProductSecurityCveReviewBulkForm>,
) -> Response {
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(_) => {
            return web_missing_context("Product Security", "/product-security/").into_response()
        }
    };
    let context = WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    };
    if !auth_context.can_write() {
        return web_error_page(
            "Product Security",
            "/product-security/",
            &context,
            "Diese Rust-Webroute benoetigt eine schreibende ISCY-Rolle.",
        )
        .into_response();
    }
    let redirect_path = product_security_review_filter_path(
        &context,
        product_security_review_filter(form.review_filter.as_deref()),
    );
    let selected_correlation_ids = form
        .correlation_id
        .iter()
        .copied()
        .filter(|value| *value > 0)
        .collect::<Vec<_>>();
    if selected_correlation_ids.is_empty() {
        return Redirect::to(&redirect_path).into_response();
    }
    let Some(store) = state.product_security_store.clone() else {
        return web_store_missing(
            "Product Security",
            "/product-security/",
            &context,
            "Product Security",
        )
        .into_response();
    };
    match form.action.trim() {
        "generate_work" => {
            for correlation_id in selected_correlation_ids {
                if let Err(err) = store
                    .generate_work_for_accepted_correlation(auth_context.tenant_id, correlation_id)
                    .await
                {
                    return web_error_page(
                        "Product Security",
                        "/product-security/",
                        &context,
                        &err.to_string(),
                    )
                    .into_response();
                }
            }
            Redirect::to(&redirect_path).into_response()
        }
        "approve_treatment" | "accept_risk" | "mark_mitigated" => {
            let Some(risk_store) = state.risk_store.clone() else {
                return web_store_missing(
                    "Product Security",
                    "/product-security/",
                    &context,
                    "Risk Review",
                )
                .into_response();
            };
            let overview = match store.overview(auth_context.tenant_id, 500, 20).await {
                Ok(Some(overview)) => overview,
                Ok(None) => {
                    return web_error_page(
                        "Product Security",
                        "/product-security/",
                        &context,
                        "Tenant wurde fuer diesen Kontext nicht gefunden.",
                    )
                    .into_response();
                }
                Err(err) => {
                    return web_error_page(
                        "Product Security",
                        "/product-security/",
                        &context,
                        &err.to_string(),
                    )
                    .into_response();
                }
            };
            for item in overview
                .cve_risk_review_queue
                .iter()
                .filter(|item| selected_correlation_ids.contains(&item.correlation_id))
            {
                let Some(risk_id) = item.risk_id else {
                    continue;
                };
                let payload = risk_store::RiskReviewRequest {
                    action: form.action.clone(),
                    review_notes: Some(
                        product_security_bulk_review_notes(&form.action).to_string(),
                    ),
                };
                if let Err(err) = risk_store
                    .review_risk(
                        auth_context.tenant_id,
                        risk_id,
                        auth_context.user_id,
                        payload,
                    )
                    .await
                {
                    return web_error_page(
                        "Product Security",
                        "/product-security/",
                        &context,
                        &err.to_string(),
                    )
                    .into_response();
                }
            }
            Redirect::to(&redirect_path).into_response()
        }
        _ => web_error_page(
            "Product Security",
            "/product-security/",
            &context,
            "Unbekannte Bulk-Aktion fuer CVE-Reviews.",
        )
        .into_response(),
    }
}

async fn web_product_security_cve_correlations_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(_) => {
            return web_missing_context("Product Security", "/product-security/").into_response()
        }
    };
    let context = WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    };
    if !auth_context.can_write() {
        return web_error_page(
            "Product Security",
            "/product-security/",
            &context,
            "Diese Rust-Webroute benoetigt eine schreibende ISCY-Rolle.",
        )
        .into_response();
    }
    let Some(store) = state.product_security_store else {
        return web_store_missing(
            "Product Security",
            "/product-security/",
            &context,
            "Product Security",
        )
        .into_response();
    };
    match store
        .suggest_cve_asset_correlations(auth_context.tenant_id)
        .await
    {
        Ok(_) => Redirect::to(&web_path_with_context("/product-security/", Some(&context)))
            .into_response(),
        Err(err) => web_error_page(
            "Product Security",
            "/product-security/",
            &context,
            &err.to_string(),
        )
        .into_response(),
    }
}

async fn web_product_security_cve_correlation_update(
    Path(correlation_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<WebCveCorrelationDecisionForm>,
) -> Response {
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(_) => {
            return web_missing_context("Product Security", "/product-security/").into_response()
        }
    };
    let context = WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    };
    if !auth_context.can_write() {
        return web_error_page(
            "Product Security",
            "/product-security/",
            &context,
            "Diese Rust-Webroute benoetigt eine schreibende ISCY-Rolle.",
        )
        .into_response();
    }
    let Some(store) = state.product_security_store else {
        return web_store_missing(
            "Product Security",
            "/product-security/",
            &context,
            "Product Security",
        )
        .into_response();
    };
    let payload = product_security_store::ProductSecurityCveCorrelationDecisionRequest {
        status: form.status,
        rationale: form.rationale,
    };
    match store
        .update_cve_correlation(auth_context.tenant_id, correlation_id, payload)
        .await
    {
        Ok(Some(_)) => Redirect::to(&web_path_with_context("/product-security/", Some(&context)))
            .into_response(),
        Ok(None) => web_error_page(
            "Product Security",
            "/product-security/",
            &context,
            "CVE-Asset-Korrelation wurde nicht gefunden.",
        )
        .into_response(),
        Err(err) => web_error_page(
            "Product Security",
            "/product-security/",
            &context,
            &err.to_string(),
        )
        .into_response(),
    }
}

fn product_security_review_filter(value: Option<&str>) -> &'static str {
    match value.unwrap_or_default().trim() {
        "review_open" => "review_open",
        "evidence_missing" => "evidence_missing",
        "risk_missing" => "risk_missing",
        _ => "all",
    }
}

fn product_security_review_filter_label(filter: &str) -> &'static str {
    match product_security_review_filter(Some(filter)) {
        "review_open" => "Review offen",
        "evidence_missing" => "Evidence fehlt",
        "risk_missing" => "Risiko fehlt",
        _ => "Alle",
    }
}

fn product_security_review_filter_matches(
    item: &product_security_store::ProductSecurityCveRiskReviewSummary,
    filter: &str,
) -> bool {
    match product_security_review_filter(Some(filter)) {
        "review_open" => item.needs_review,
        "evidence_missing" => item.evidence_missing,
        "risk_missing" => item.risk_id.is_none(),
        _ => true,
    }
}

fn product_security_review_filter_path(context: &WebContext, filter: &str) -> String {
    match product_security_review_filter(Some(filter)) {
        "all" => web_path_with_context("/product-security/", Some(context)),
        normalized => web_path_with_context(
            &format!(
                "/product-security/?review_filter={}",
                url_component(normalized)
            ),
            Some(context),
        ),
    }
}

fn product_security_review_filter_links(
    context: &WebContext,
    active_filter: &str,
    all_count: i64,
    review_open_count: i64,
    evidence_missing_count: i64,
    risk_missing_count: i64,
) -> String {
    [
        ("all", "Alle", all_count),
        ("review_open", "Review offen", review_open_count),
        ("evidence_missing", "Evidence fehlt", evidence_missing_count),
        ("risk_missing", "Risiko fehlt", risk_missing_count),
    ]
    .iter()
    .map(|(filter, label, count)| {
        let active = product_security_review_filter(Some(active_filter)) == *filter;
        format!(
            r#"<a href="{}"{}>{} ({})</a>"#,
            product_security_review_filter_path(context, filter),
            if active { r#" class="active""# } else { "" },
            html_escape(label),
            count,
        )
    })
    .collect::<Vec<_>>()
    .join(" ")
}

fn product_security_bulk_review_notes(action: &str) -> &'static str {
    match action.trim() {
        "approve_treatment" => {
            "CVE-Risiken wurden per Product-Security-Bulk-Review zur Behandlung freigegeben."
        }
        "accept_risk" => "CVE-Restrisiken wurden per Product-Security-Bulk-Review akzeptiert.",
        "mark_mitigated" => {
            "CVE-Massnahmen wurden per Product-Security-Bulk-Review als mitigiert markiert."
        }
        _ => "CVE-Risiken wurden per Product-Security-Bulk-Review geprueft.",
    }
}

fn product_security_trend_status_label(status: &str) -> &'static str {
    match status.trim().to_ascii_lowercase().as_str() {
        "ok" => "stabil",
        "critical" => "kritisch",
        "warn" | "warning" => "handeln",
        _ => "offen",
    }
}

fn product_security_trend_status_class(status: &str) -> &'static str {
    match status.trim().to_ascii_lowercase().as_str() {
        "ok" => "ok",
        "critical" => "danger",
        "warn" | "warning" => "warn",
        _ => "info",
    }
}

fn product_security_cra_status_class(status: &str) -> &'static str {
    match status {
        "READY" => "ok",
        "PARTIAL" => "warn",
        "GAP" => "danger",
        _ => "info",
    }
}

fn product_security_sbom_diff_status_class(status: &str) -> &'static str {
    match status {
        "ADDED" => "ok",
        "REMOVED" => "danger",
        "CHANGED" => "warn",
        "UNCHANGED" => "muted-badge",
        _ => "info",
    }
}

fn selected_attr(selected: bool) -> &'static str {
    if selected {
        " selected"
    } else {
        ""
    }
}

fn web_cve_assessment_form_request(
    form: WebCveAssessmentForm,
) -> Result<cve_store::CveAssessmentWriteRequest, String> {
    Ok(cve_store::CveAssessmentWriteRequest {
        cve_id: form.cve_id,
        product_id: optional_form_i64(form.product_id, "Produkt")?,
        release_id: optional_form_i64(form.release_id, "Release")?,
        component_id: optional_form_i64(form.component_id, "Komponente")?,
        exposure: form.exposure,
        asset_criticality: form.asset_criticality,
        epss_score: optional_form_f64(form.epss_score, "EPSS-Score")?,
        in_kev_catalog: Some(form.in_kev_catalog.is_some()),
        exploit_maturity: form.exploit_maturity,
        affects_critical_service: form.affects_critical_service.is_some(),
        nis2_relevant: Some(form.nis2_relevant.is_some()),
        nis2_impact_summary: form.nis2_impact_summary,
        repository_name: form.repository_name,
        repository_url: form.repository_url,
        git_ref: form.git_ref,
        source_package: form.source_package,
        source_package_version: form.source_package_version,
        regulatory_tags: comma_separated_form_list(form.regulatory_tags),
        business_context: form.business_context,
        existing_controls: form.existing_controls,
        auto_create_risk: form.auto_create_risk.is_some(),
        run_llm: form.run_llm.is_some(),
    })
}

fn tenant_regulatory_profile_form_request(
    form: WebTenantRegulatoryProfileForm,
) -> Result<tenant_store::TenantRegulatoryProfileUpdateRequest, String> {
    Ok(tenant_store::TenantRegulatoryProfileUpdateRequest {
        country: normalized_optional_form_text(form.country),
        operation_countries: Some(comma_separated_form_list(form.operation_countries)),
        description: normalized_optional_form_text(form.description),
        sector: normalized_optional_form_text(form.sector),
        employee_count: optional_form_i64_nonnegative(form.employee_count, "Mitarbeitende")?,
        annual_revenue_million: normalized_optional_form_text(form.annual_revenue_million),
        balance_sheet_million: normalized_optional_form_text(form.balance_sheet_million),
        critical_services: normalized_optional_form_text(form.critical_services),
        supply_chain_role: normalized_optional_form_text(form.supply_chain_role),
        nis2_relevant: Some(form_checkbox_value(form.nis2_relevant)),
        kritis_relevant: Some(form_checkbox_value(form.kritis_relevant)),
        develops_digital_products: Some(form_checkbox_value(form.develops_digital_products)),
        uses_ai_systems: Some(form_checkbox_value(form.uses_ai_systems)),
        ot_iacs_scope: Some(form_checkbox_value(form.ot_iacs_scope)),
        automotive_scope: Some(form_checkbox_value(form.automotive_scope)),
        psirt_defined: Some(form_checkbox_value(form.psirt_defined)),
        sbom_required: Some(form_checkbox_value(form.sbom_required)),
        product_security_scope: normalized_optional_form_text(form.product_security_scope),
        dora_relevant: Some(form_checkbox_value(form.dora_relevant)),
        dora_financial_entity: Some(form_checkbox_value(form.dora_financial_entity)),
        dora_ict_third_party_provider: Some(form_checkbox_value(
            form.dora_ict_third_party_provider,
        )),
        processes_personal_data: Some(form_checkbox_value(form.processes_personal_data)),
        gdpr_controller: Some(form_checkbox_value(form.gdpr_controller)),
        gdpr_processor: Some(form_checkbox_value(form.gdpr_processor)),
        gdpr_special_categories: Some(form_checkbox_value(form.gdpr_special_categories)),
        cra_relevant: Some(form_checkbox_value(form.cra_relevant)),
        ai_act_profile: normalized_optional_form_text(form.ai_act_profile),
        ai_act_high_risk: Some(form_checkbox_value(form.ai_act_high_risk)),
        tisax_relevant: Some(form_checkbox_value(form.tisax_relevant)),
        iso27001_target: normalized_optional_form_text(form.iso27001_target),
        regulatory_profile_notes: normalized_optional_form_text(form.regulatory_profile_notes),
    })
}

fn web_incident_form_request(
    form: WebIncidentForm,
) -> Result<incident_store::IncidentWriteRequest, String> {
    let nis2_significance_status = form.nis2_significance_status;
    let nis2_reportable = nis2_significance_status
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| value.eq_ignore_ascii_case("SIGNIFICANT"))
        || form.nis2_reportable.is_some();
    Ok(incident_store::IncidentWriteRequest {
        reporter_id: Some(optional_form_i64(form.reporter_id, "Reporter")?),
        owner_id: Some(optional_form_i64(form.owner_id, "Owner")?),
        related_risk_id: Some(optional_form_i64(form.related_risk_id, "Risiko")?),
        related_asset_id: Some(optional_form_i64(form.related_asset_id, "Asset")?),
        related_process_id: Some(optional_form_i64(form.related_process_id, "Prozess")?),
        title: Some(form.title),
        summary: form.summary,
        incident_type: form.incident_type,
        runbook_template: form.runbook_template,
        severity: form.severity,
        status: form.status,
        detected_at: optional_form_text_for_write(form.detected_at),
        confirmed_at: optional_form_text_for_write(form.confirmed_at),
        contained_at: optional_form_text_for_write(form.contained_at),
        resolved_at: optional_form_text_for_write(form.resolved_at),
        nis2_reportable: Some(nis2_reportable),
        nis2_significance_status,
        nis2_significance_criteria: form.nis2_significance_criteria,
        nis2_significance_justification: form.nis2_significance_justification,
        nis2_significance_reference: form.nis2_significance_reference,
        nis2_significance_assessed_at: optional_form_text_for_write(
            form.nis2_significance_assessed_at,
        ),
        early_warning_sent_at: optional_form_text_for_write(form.early_warning_sent_at),
        notification_sent_at: optional_form_text_for_write(form.notification_sent_at),
        final_report_sent_at: optional_form_text_for_write(form.final_report_sent_at),
        authority_reference: form.authority_reference,
        stakeholder_summary: form.stakeholder_summary,
        lessons_learned: form.lessons_learned,
    })
}

fn web_runbook_template_form_request(
    form: WebIncidentRunbookTemplateForm,
) -> Result<incident_store::IncidentRunbookTemplateWriteRequest, String> {
    Ok(incident_store::IncidentRunbookTemplateWriteRequest {
        slug: normalized_optional_form_text(form.slug),
        title: normalized_required_form_text(form.title, "Runbook-Titel")?,
        description: normalized_optional_form_text(form.description),
        incident_type: form.incident_type,
        severity: form.severity,
        body: normalized_required_form_text(form.body, "Runbook-Inhalt")?,
        is_active: Some(form_checkbox_value(form.is_active)),
        sort_order: optional_form_sort_order(form.sort_order)?,
    })
}

fn normalized_required_form_text(
    value: Option<String>,
    field_label: &str,
) -> Result<Option<String>, String> {
    let value = value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if value.is_none() {
        return Err(format!("{field_label} darf nicht leer sein."));
    }
    Ok(value)
}

fn normalized_optional_form_text(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn optional_form_sort_order(value: Option<String>) -> Result<Option<i64>, String> {
    let Some(value) = value.map(|value| value.trim().to_string()) else {
        return Ok(None);
    };
    if value.is_empty() {
        return Ok(None);
    }
    let parsed = value
        .parse::<i64>()
        .map_err(|_| "Reihenfolge muss eine ganze Zahl sein.".to_string())?;
    Ok(Some(parsed))
}

fn form_checkbox_value(value: Option<String>) -> bool {
    value
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| matches!(value, "1" | "true" | "yes" | "ja" | "on"))
}

fn incident_timeline_note_payload(
    summary: Option<String>,
    detail: String,
) -> Result<incident_store::IncidentEventWriteRequest, String> {
    let detail = detail.trim().to_string();
    if detail.is_empty() {
        return Err("Timeline-Notiz darf nicht leer sein.".to_string());
    }
    let summary = summary
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    Ok(incident_store::IncidentEventWriteRequest::timeline_note(
        summary.as_deref(),
        &detail,
    ))
}

fn incident_decision_flow_panel(
    context: &WebContext,
    incident: &incident_store::IncidentSummary,
    runbook_done_count: usize,
    runbook_total_count: usize,
    evidence_count: usize,
) -> String {
    let case_href = incident_detail_anchor_href(context, incident.id, "incident-case");
    let significance_href =
        incident_detail_anchor_href(context, incident.id, "incident-significance");
    let handling_href = incident_detail_anchor_href(context, incident.id, "incident-runbook");
    let package_href = incident_detail_anchor_href(context, incident.id, "incident-package");

    let case_detail = format!(
        "{} · {}",
        incident.incident_type_label, incident.severity_label
    );
    let significance_detail = incident
        .nis2_significance_assessed_at
        .as_deref()
        .map(|value| format!("Bewertet am {value}"))
        .unwrap_or_else(|| "Bewertung offen".to_string());
    let handling_detail = if runbook_total_count == 0 {
        format!("{evidence_count} Evidence · Runbook offen")
    } else {
        format!("{runbook_done_count}/{runbook_total_count} Runbook · {evidence_count} Evidence")
    };
    let (package_class, package_value, package_detail) = incident_package_flow_state(incident);

    format!(
        r##"
        <section class="incident-flow" aria-label="Incident-Entscheidungsfluss">
          {}
          {}
          {}
          {}
        </section>
        "##,
        incident_flow_step(
            "1",
            "Vorfall",
            &incident.status_label,
            &case_detail,
            incident_status_badge_class(&incident.status),
            &case_href,
        ),
        incident_flow_step(
            "2",
            "Erheblichkeit",
            &incident.nis2_significance_label,
            &significance_detail,
            incident_significance_badge_class(&incident.nis2_significance_status),
            &significance_href,
        ),
        incident_flow_step(
            "3",
            "Bearbeitung",
            "Runbook / Evidence",
            &handling_detail,
            incident_handling_flow_class(runbook_done_count, runbook_total_count, evidence_count),
            &handling_href,
        ),
        incident_flow_step(
            "4",
            "Meldepaket",
            package_value,
            package_detail,
            package_class,
            &package_href,
        ),
    )
}

fn incident_flow_step(
    index: &str,
    title: &str,
    value: &str,
    detail: &str,
    class_name: &str,
    href: &str,
) -> String {
    format!(
        r##"<a class="flow-step {}" href="{}"><span class="flow-index">{}</span><span class="eyebrow">{}</span><strong>{}</strong><small>{}</small></a>"##,
        html_escape(class_name),
        html_escape(href),
        html_escape(index),
        html_escape(title),
        html_escape(value),
        html_escape(detail),
    )
}

fn incident_detail_anchor_href(context: &WebContext, incident_id: i64, anchor: &str) -> String {
    format!(
        "{}#{}",
        web_path_with_context(&format!("/incidents/{incident_id}"), Some(context)),
        anchor
    )
}

fn incident_package_flow_state(
    incident: &incident_store::IncidentSummary,
) -> (&'static str, &'static str, &'static str) {
    if !incident.nis2_reportable {
        return ("muted-badge", "Nicht aktiv", "Fristen nicht gestartet");
    }
    if incident.final_report_state == "SENT" {
        return ("ok", "Vollstaendig", "Finalbericht gemeldet");
    }
    if incident.early_warning_state == "OVERDUE"
        || incident.notification_state == "OVERDUE"
        || incident.final_report_state == "OVERDUE"
    {
        return ("danger", "Ueberfaellig", "Meldepaket priorisieren");
    }
    if incident.early_warning_state == "DUE_SOON"
        || incident.notification_state == "DUE_SOON"
        || incident.final_report_state == "DUE_SOON"
    {
        return ("warn", "Faellig bald", "Meldeschritte vorbereiten");
    }
    ("info", "Aktiv", "Meldeschritte im Blick")
}

fn incident_handling_flow_class(
    runbook_done_count: usize,
    runbook_total_count: usize,
    evidence_count: usize,
) -> &'static str {
    if runbook_total_count == 0 || evidence_count == 0 {
        "warn"
    } else if runbook_done_count >= runbook_total_count {
        "ok"
    } else {
        "info"
    }
}

fn optional_form_text_for_write(value: Option<String>) -> Option<Option<String>> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(Some)
}

fn incident_edit_form_panel(
    context: &WebContext,
    incident: &incident_store::IncidentSummary,
    runbook_templates: &[incident_store::IncidentRunbookTemplateSummary],
) -> String {
    let action = web_path_with_context(&format!("/incidents/{}", incident.id), Some(context));
    let owner_id = incident
        .owner_id
        .map(|value| value.to_string())
        .unwrap_or_default();
    let reporter_id = incident
        .reporter_id
        .map(|value| value.to_string())
        .unwrap_or_default();
    let related_risk_id = incident
        .related_risk_id
        .map(|value| value.to_string())
        .unwrap_or_default();
    let related_asset_id = incident
        .related_asset_id
        .map(|value| value.to_string())
        .unwrap_or_default();
    let related_process_id = incident
        .related_process_id
        .map(|value| value.to_string())
        .unwrap_or_default();
    let template_rows = incident_runbook_template_rows(runbook_templates);
    format!(
        r#"
        <article class="panel wide">
          <h2>Fallakte bearbeiten</h2>
          <form method="post" action="{}">
            <div class="form-grid">
              <label>Titel<input name="title" type="text" required value="{}"></label>
              <label>Typ<select name="incident_type">{}</select></label>
              <label>Severity<select name="severity">{}</select></label>
              <label>Status<select name="status">{}</select></label>
              <label>Owner-ID<input name="owner_id" type="number" min="1" value="{}"></label>
              <label>Reporter-ID<input name="reporter_id" type="number" min="1" value="{}"></label>
              <label>Risk-ID<input name="related_risk_id" type="number" min="1" value="{}"></label>
              <label>Asset-ID<input name="related_asset_id" type="number" min="1" value="{}"></label>
              <label>Process-ID<input name="related_process_id" type="number" min="1" value="{}"></label>
              <label>Erkannt am<input name="detected_at" type="text" value="{}"></label>
              <label>Bestaetigt am<input name="confirmed_at" type="text" value="{}"></label>
              <label>Eingedaemmt am<input name="contained_at" type="text" value="{}"></label>
              <label>Behoben am<input name="resolved_at" type="text" value="{}"></label>
              <label>24h gesendet<input name="early_warning_sent_at" type="text" value="{}"></label>
              <label>72h gesendet<input name="notification_sent_at" type="text" value="{}"></label>
              <label>Final gesendet<input name="final_report_sent_at" type="text" value="{}"></label>
              <label>NIS2-Erheblichkeit<select name="nis2_significance_status">{}</select></label>
              <label>Erheblichkeit bewertet am<input name="nis2_significance_assessed_at" type="text" value="{}"></label>
              <label>Behoerden-/Case-Referenz<input name="authority_reference" type="text" value="{}"></label>
            </div>
            <p class="muted">24h-/72h-/30-Tage-Fristen werden erst aktiv, wenn die Erheblichkeitsentscheidung auf "Erheblich / NIS2 meldepflichtig" steht.</p>
            <label>Kriterien nach NIS2 Art. 23 / EU 2024/2690<textarea name="nis2_significance_criteria" rows="4">{}</textarea></label>
            <label>Begruendung der Entscheidung<textarea name="nis2_significance_justification" rows="4">{}</textarea></label>
            <label>Referenz / Rechtsgrundlage<input name="nis2_significance_reference" type="text" value="{}"></label>
            <label>Kurzbeschreibung<textarea name="summary" rows="4">{}</textarea></label>
            <label>Runbook<textarea name="runbook_template" rows="7">{}</textarea></label>
            <label>Stakeholder-Zusammenfassung<textarea name="stakeholder_summary" rows="3">{}</textarea></label>
            <label>Lessons Learned<textarea name="lessons_learned" rows="3">{}</textarea></label>
            <button type="submit">Fallakte speichern</button>
          </form>
          <h3>Verfuegbare Runbook-Vorlagen</h3>
          <table>
            <thead><tr><th>Vorlage</th><th>Typ</th><th>Severity</th><th>Beschreibung</th></tr></thead>
            <tbody>{}</tbody>
          </table>
        </article>
        "#,
        html_escape(&action),
        html_escape(&incident.title),
        incident_type_options_for(&incident.incident_type),
        incident_severity_options_for(&incident.severity),
        incident_status_options_for(&incident.status),
        html_escape(&owner_id),
        html_escape(&reporter_id),
        html_escape(&related_risk_id),
        html_escape(&related_asset_id),
        html_escape(&related_process_id),
        html_escape(incident.detected_at.as_deref().unwrap_or("")),
        html_escape(incident.confirmed_at.as_deref().unwrap_or("")),
        html_escape(incident.contained_at.as_deref().unwrap_or("")),
        html_escape(incident.resolved_at.as_deref().unwrap_or("")),
        html_escape(incident.early_warning_sent_at.as_deref().unwrap_or("")),
        html_escape(incident.notification_sent_at.as_deref().unwrap_or("")),
        html_escape(incident.final_report_sent_at.as_deref().unwrap_or("")),
        incident_nis2_significance_options_for(&incident.nis2_significance_status),
        html_escape(
            incident
                .nis2_significance_assessed_at
                .as_deref()
                .unwrap_or("")
        ),
        html_escape(&incident.authority_reference),
        html_escape(&incident.nis2_significance_criteria),
        html_escape(&incident.nis2_significance_justification),
        html_escape(&incident.nis2_significance_reference),
        html_escape(&incident.summary),
        html_escape(&incident.runbook_template),
        html_escape(&incident.stakeholder_summary),
        html_escape(&incident.lessons_learned),
        template_rows,
    )
}

fn incident_regulatory_decision_matrix_markdown(
    incident: &incident_store::IncidentSummary,
) -> String {
    let (nis2_status, nis2_next_step) = incident_nis2_matrix_status(incident);
    format!(
        r#"## Regulatorische Entscheidungsmatrix

| Regelwerk | Status in ISCY | Ausloeser / Prueffrage | Frist / naechster Schritt |
| --- | --- | --- | --- |
| NIS2 | {} | Erheblicher Sicherheitsvorfall nach NIS2 Art. 23 und EU 2024/2690 Art. 3? | {} |
| DORA | Fachlich pruefen | Schwerwiegender IKT-bezogener Vorfall im Finanz-/IKT-Dienstleister-Kontext? | Klassifizieren und ggf. DORA-Meldepaket ableiten. |
| DSGVO | Fachlich pruefen | Verletzung personenbezogener Daten mit Risiko fuer Betroffene? | Datenschutzreview, ggf. 72h-Meldung an Aufsicht. |"#,
        md_value(&nis2_status),
        md_value(&nis2_next_step),
    )
}

fn incident_regulatory_decision_matrix_html(incident: &incident_store::IncidentSummary) -> String {
    let (nis2_status, nis2_next_step) = incident_nis2_matrix_status(incident);
    format!(
        r#"
  <h2>Regulatorische Entscheidungsmatrix</h2>
  <table>
    <thead><tr><th>Regelwerk</th><th>Status in ISCY</th><th>Ausloeser / Prueffrage</th><th>Frist / naechster Schritt</th></tr></thead>
    <tbody>
      <tr><td>NIS2</td><td>{}</td><td>Erheblicher Sicherheitsvorfall nach NIS2 Art. 23 und EU 2024/2690 Art. 3?</td><td>{}</td></tr>
      <tr><td>DORA</td><td>Fachlich pruefen</td><td>Schwerwiegender IKT-bezogener Vorfall im Finanz-/IKT-Dienstleister-Kontext?</td><td>Klassifizieren und ggf. DORA-Meldepaket ableiten.</td></tr>
      <tr><td>DSGVO</td><td>Fachlich pruefen</td><td>Verletzung personenbezogener Daten mit Risiko fuer Betroffene?</td><td>Datenschutzreview, ggf. 72h-Meldung an Aufsicht.</td></tr>
    </tbody>
  </table>
"#,
        html_escape(&nis2_status),
        html_escape(&nis2_next_step),
    )
}

fn incident_regulatory_decision_matrix_pdf_lines(
    incident: &incident_store::IncidentSummary,
) -> Vec<String> {
    let (nis2_status, nis2_next_step) = incident_nis2_matrix_status(incident);
    let mut lines = vec!["Regulatorische Entscheidungsmatrix:".to_string()];
    lines.extend(wrap_pdf_text(
        &format!("NIS2: {} | {}", nis2_status, nis2_next_step),
        92,
    ));
    lines.extend(wrap_pdf_text(
        "DORA: Fachlich pruefen | Schwerwiegender IKT-bezogener Vorfall im Finanz-/IKT-Dienstleister-Kontext?",
        92,
    ));
    lines.extend(wrap_pdf_text(
        "DSGVO: Fachlich pruefen | Datenschutzreview, ggf. 72h-Meldung bei meldepflichtiger Verletzung personenbezogener Daten.",
        92,
    ));
    lines
}

fn incident_nis2_matrix_status(incident: &incident_store::IncidentSummary) -> (String, String) {
    if incident.nis2_reportable {
        return (
            "Meldepflichtig / Fristen aktiv".to_string(),
            "24h-Fruehwarnung, 72h-Meldung und 30-Tage-Abschlussbericht fuehren.".to_string(),
        );
    }
    match incident.nis2_significance_status.as_str() {
        "NOT_SIGNIFICANT" if incident.review_state == "APPROVED" => (
            "Nicht erheblich / freigegeben".to_string(),
            "Keine NIS2-Fristen aktiv; Freigabe und Begruendung im Meldepaket dokumentiert."
                .to_string(),
        ),
        "NOT_SIGNIFICANT" => (
            "Nicht erheblich / Review erforderlich".to_string(),
            "Fachliche Freigabe einholen; keine NIS2-Fristen aktiv.".to_string(),
        ),
        _ => (
            "Bewertung offen".to_string(),
            "Erheblichkeitsbewertung abschliessen, bevor Meldefristen aktiviert werden."
                .to_string(),
        ),
    }
}

fn incident_nis2_markdown(
    incident: &incident_store::IncidentSummary,
    evidence_items: &[evidence_store::EvidenceItemSummary],
    events: &[incident_store::IncidentEventSummary],
) -> String {
    let evidence_rows = incident_evidence_markdown_rows(evidence_items);
    let event_rows = incident_event_markdown_rows(events);
    let decision_matrix = incident_regulatory_decision_matrix_markdown(incident);
    format!(
        r#"# ISCY NIS2-Meldepaket: {}

## Fallakte

| Feld | Wert |
| --- | --- |
| Incident-ID | {} |
| Tenant-ID | {} |
| Titel | {} |
| Incident-Typ | {} |
| Severity | {} |
| Status | {} |
| Erheblichkeitsstatus | {} |
| Erheblich bewertet am | {} |
| NIS2-Einstufung | {} |
| Behoerden-/Case-Referenz | {} |
| Meldepaket-Review | {} |
| Meldepaket-Version | {} |
| Geprueft von/am | {} / {} |
| Freigegeben von/am | {} / {} |

## Betroffene Bezuege

| Bezug | Wert |
| --- | --- |
| Reporter | {} |
| Owner | {} |
| Risiko | {} |
| Asset | {} |
| Prozess | {} |

## NIS2-Erheblichkeitsentscheidung

| Feld | Wert |
| --- | --- |
| Kriterien | {} |
| Begruendung | {} |
| Referenz | {} |

{}

## Meldefristen

| Schritt | Faellig | Gesendet | Status |
| --- | --- | --- | --- |
| 24h-Fruehwarnung | {} | {} | {} |
| 72h-Meldung | {} | {} | {} |
| 30-Tage-Abschlussbericht | {} | {} | {} |

## Beschreibung

{}

## Stakeholder-Zusammenfassung

{}

## Lessons Learned

{}

## Runbook

{}

## Evidence

| Titel | Version | Klasse | Status | Requirement | Gueltig bis | SHA-256 | Datei |
| --- | --- | --- | --- | --- | --- | --- | --- |
{}

## Audit-Timeline

| Zeitpunkt | Ereignis | Zusammenfassung | Actor | Detail | Export |
| --- | --- | --- | --- | --- | --- |
{}

## Zeitlinie

| Ereignis | Zeitpunkt |
| --- | --- |
| Erkannt | {} |
| Bestaetigt | {} |
| Eingedaemmt | {} |
| Behoben | {} |
| Erstellt | {} |
| Aktualisiert | {} |
"#,
        md_value(&incident.title),
        incident.id,
        incident.tenant_id,
        md_value(&incident.title),
        md_value(&incident.incident_type_label),
        md_value(&incident.severity_label),
        md_value(&incident.status_label),
        md_value(&incident.nis2_significance_label),
        md_optional(incident.nis2_significance_assessed_at.as_deref()),
        md_value(&incident.nis2_reportability_label),
        md_value(&incident.authority_reference),
        md_value(&incident.review_state_label),
        md_value(&incident.report_package_version),
        md_optional(incident.reviewed_by_display.as_deref()),
        md_optional(incident.reviewed_at.as_deref()),
        md_optional(incident.approved_by_display.as_deref()),
        md_optional(incident.approved_at.as_deref()),
        md_optional(incident.reporter_display.as_deref()),
        md_optional(incident.owner_display.as_deref()),
        md_optional(incident.related_risk_title.as_deref()),
        md_optional(incident.related_asset_name.as_deref()),
        md_optional(incident.related_process_name.as_deref()),
        md_block(&incident.nis2_significance_criteria),
        md_block(&incident.nis2_significance_justification),
        md_block(&incident.nis2_significance_reference),
        decision_matrix,
        md_optional(incident.early_warning_due_at.as_deref()),
        md_optional(incident.early_warning_sent_at.as_deref()),
        md_value(&incident.early_warning_state_label),
        md_optional(incident.notification_due_at.as_deref()),
        md_optional(incident.notification_sent_at.as_deref()),
        md_value(&incident.notification_state_label),
        md_optional(incident.final_report_due_at.as_deref()),
        md_optional(incident.final_report_sent_at.as_deref()),
        md_value(&incident.final_report_state_label),
        md_block(&incident.summary),
        md_block(&incident.stakeholder_summary),
        md_block(&incident.lessons_learned),
        md_block(&incident.runbook_template),
        evidence_rows,
        event_rows,
        md_optional(incident.detected_at.as_deref()),
        md_optional(incident.confirmed_at.as_deref()),
        md_optional(incident.contained_at.as_deref()),
        md_optional(incident.resolved_at.as_deref()),
        md_value(&incident.created_at),
        md_value(&incident.updated_at),
    )
}

#[derive(Debug, Clone, Copy)]
enum IncidentPackageKind {
    Nis2,
    Dora,
    Dsgvo,
}

impl IncidentPackageKind {
    fn slug(self) -> &'static str {
        match self {
            Self::Nis2 => "nis2",
            Self::Dora => "dora",
            Self::Dsgvo => "dsgvo",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Nis2 => "NIS2",
            Self::Dora => "DORA",
            Self::Dsgvo => "DSGVO",
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::Nis2 => "NIS2-Meldepaket",
            Self::Dora => "DORA-IKT-Vorfallpaket",
            Self::Dsgvo => "DSGVO-Datenschutzvorfallpaket",
        }
    }

    fn trigger_question(self) -> &'static str {
        match self {
            Self::Nis2 => {
                "Erheblicher Sicherheitsvorfall nach NIS2 Art. 23 und EU 2024/2690 Art. 3?"
            }
            Self::Dora => {
                "Schwerwiegender IKT-bezogener Vorfall im Finanz-/IKT-Dienstleister-Kontext?"
            }
            Self::Dsgvo => "Verletzung personenbezogener Daten mit Risiko fuer Betroffene?",
        }
    }

    fn decision_note(self) -> &'static str {
        match self {
            Self::Nis2 => {
                "ISCY aktiviert NIS2-Fristen erst bei der Einstufung Erheblich / NIS2 meldepflichtig."
            }
            Self::Dora => {
                "ISCY bereitet die fachliche DORA-Klassifizierung vor; Meldepflicht und Fristen haengen vom Finanzsektor-/IKT-Dienstleister-Kontext und der Major-Incident-Bewertung ab."
            }
            Self::Dsgvo => {
                "ISCY bereitet die Datenschutzpruefung vor; eine 72h-Meldung ist erst bei meldepflichtiger Verletzung personenbezogener Daten relevant."
            }
        }
    }

    fn next_step(self) -> &'static str {
        match self {
            Self::Nis2 => {
                "Erheblichkeitsentscheidung mit Kriterien, Begruendung und Referenz abschliessen."
            }
            Self::Dora => {
                "Finanz-/IKT-Dienstleister-Bezug, Auswirkungen auf IKT-Services, Kunden und Kritikalitaet pruefen; bei Major Incident DORA-Meldeweg ableiten."
            }
            Self::Dsgvo => {
                "Personenbezug, Risiko fuer Betroffene, Schutzmassnahmen und Benachrichtigungspflichten mit Datenschutzrolle pruefen."
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum IncidentExportFormat {
    Markdown,
    Html,
    Pdf,
}

#[derive(Debug, Clone, Copy)]
enum ManagementReviewExportFormat {
    Markdown,
    Html,
    Pdf,
    Json,
}

#[derive(Debug, Clone, Copy)]
enum IncidentTimelineExportFormat {
    Csv,
    Json,
}

#[derive(Debug, Clone, Copy)]
enum ProductSecurityImportHistoryFormat {
    Csv,
    Json,
}

fn incident_export_download_response(
    incident: &incident_store::IncidentSummary,
    evidence_items: &[evidence_store::EvidenceItemSummary],
    events: &[incident_store::IncidentEventSummary],
    package_kind: IncidentPackageKind,
    export_format: IncidentExportFormat,
) -> Response {
    match export_format {
        IncidentExportFormat::Markdown => {
            let body = match package_kind {
                IncidentPackageKind::Nis2 => {
                    incident_nis2_markdown(incident, evidence_items, events)
                }
                IncidentPackageKind::Dora | IncidentPackageKind::Dsgvo => {
                    incident_regulatory_package_markdown(
                        incident,
                        evidence_items,
                        events,
                        package_kind,
                    )
                }
            };
            markdown_download_response(
                &format!("iscy-incident-{}-{}.md", incident.id, package_kind.slug()),
                body,
            )
        }
        IncidentExportFormat::Html => {
            let body = match package_kind {
                IncidentPackageKind::Nis2 => incident_nis2_html(incident, evidence_items, events),
                IncidentPackageKind::Dora | IncidentPackageKind::Dsgvo => {
                    incident_regulatory_package_html(incident, evidence_items, events, package_kind)
                }
            };
            html_download_response(
                &format!("iscy-incident-{}-{}.html", incident.id, package_kind.slug()),
                body,
            )
        }
        IncidentExportFormat::Pdf => {
            let body = match package_kind {
                IncidentPackageKind::Nis2 => incident_nis2_pdf(incident, evidence_items, events),
                IncidentPackageKind::Dora | IncidentPackageKind::Dsgvo => {
                    incident_regulatory_package_pdf(incident, evidence_items, events, package_kind)
                }
            };
            binary_download_response(
                &format!("iscy-incident-{}-{}.pdf", incident.id, package_kind.slug()),
                "application/pdf",
                body,
            )
        }
    }
}

fn incident_timeline_export_download_response(
    incident: &incident_store::IncidentSummary,
    events: &[incident_store::IncidentEventSummary],
    export_format: IncidentTimelineExportFormat,
) -> Response {
    match export_format {
        IncidentTimelineExportFormat::Csv => text_download_response(
            &format!("iscy-incident-{}-timeline.csv", incident.id),
            "text/csv; charset=utf-8",
            incident_timeline_csv(events),
        ),
        IncidentTimelineExportFormat::Json => text_download_response(
            &format!("iscy-incident-{}-timeline.json", incident.id),
            "application/json; charset=utf-8",
            incident_timeline_json(incident, events),
        ),
    }
}

fn product_security_import_history_download_response(
    tenant_id: i64,
    artifacts: &[product_security_store::ProductSecurityImportArtifactSummary],
    export_format: ProductSecurityImportHistoryFormat,
) -> Response {
    match export_format {
        ProductSecurityImportHistoryFormat::Csv => text_download_response(
            &format!("iscy-product-security-tenant-{tenant_id}-imports.csv"),
            "text/csv; charset=utf-8",
            product_security_import_history_csv(artifacts),
        ),
        ProductSecurityImportHistoryFormat::Json => text_download_response(
            &format!("iscy-product-security-tenant-{tenant_id}-imports.json"),
            "application/json; charset=utf-8",
            product_security_import_history_json(tenant_id, artifacts),
        ),
    }
}

fn management_review_export_download_response(
    package: &report_store::ManagementReviewPackageDetail,
    export_format: ManagementReviewExportFormat,
) -> Response {
    match export_format {
        ManagementReviewExportFormat::Markdown => markdown_download_response(
            &format!("iscy-management-review-{}.md", package.id),
            management_review_markdown(package),
        ),
        ManagementReviewExportFormat::Html => html_download_response(
            &format!("iscy-management-review-{}.html", package.id),
            management_review_html(package),
        ),
        ManagementReviewExportFormat::Pdf => binary_download_response(
            &format!("iscy-management-review-{}.pdf", package.id),
            "application/pdf",
            management_review_pdf(package),
        ),
        ManagementReviewExportFormat::Json => text_download_response(
            &format!("iscy-management-review-{}.json", package.id),
            "application/json; charset=utf-8",
            serde_json::to_string_pretty(&serde_json::json!({
                "api_version": "v1",
                "package": package
            }))
            .unwrap_or_else(|_| "{}".to_string()),
        ),
    }
}

fn management_review_markdown(package: &report_store::ManagementReviewPackageDetail) -> String {
    let mut markdown = format!(
        "# ISCY Management Review: {}\n\n| Feld | Wert |\n| --- | --- |\n| Review-ID | {} |\n| Tenant-ID | {} |\n| Zeitraum | {} bis {} |\n| Status | {} |\n| Erstellt | {} |\n| Aktualisiert | {} |\n| Freigegeben | {} |\n\n## Executive Summary\n\n{}\n\n## Entscheidung\n\n| Feld | Wert |\n| --- | --- |\n| Entscheidung | {} |\n| Naechste Massnahmen | {} |\n\n## Kennzahlen\n\n{}\n",
        md_value(&package.title),
        package.id,
        package.tenant_id,
        md_optional(package.period_start.as_deref()),
        md_optional(package.period_end.as_deref()),
        md_value(&package.status_label),
        md_value(&package.created_at),
        md_value(&package.updated_at),
        md_optional(package.approved_at.as_deref()),
        md_value(&package.executive_summary),
        md_value(&package.decision_notes),
        md_value(&package.next_actions),
        management_review_object_markdown(&package.metrics_json),
    );
    markdown.push_str(&management_review_array_markdown(
        "Top-Risiken",
        &package.top_risks_json,
        &[
            ("title", "Titel"),
            ("status", "Status"),
            ("score", "Score"),
            ("treatment_plan", "Behandlung"),
        ],
    ));
    markdown.push_str(&management_review_array_markdown(
        "ISCY-27 Control-Gaps",
        &package.control_gaps_json,
        &[
            ("code", "Control"),
            ("title", "Titel"),
            ("status", "Status"),
            ("evidence_status", "Evidence"),
        ],
    ));
    markdown.push_str(&management_review_array_markdown(
        "Evidence-Luecken",
        &package.evidence_gaps_json,
        &[
            ("requirement_code", "Requirement"),
            ("title", "Evidence"),
            ("status", "Status"),
            ("covered_count", "Coverage"),
        ],
    ));
    markdown.push_str(&management_review_array_markdown(
        "Incident-Entscheidungen",
        &package.incident_decisions_json,
        &[
            ("title", "Incident"),
            ("severity", "Severity"),
            ("nis2_significance_status", "Erheblichkeit"),
            ("review_state", "Review"),
        ],
    ));
    markdown.push_str(&management_review_array_markdown(
        "Roadmap-Fokus",
        &package.roadmap_json,
        &[
            ("title", "Task"),
            ("priority", "Prioritaet"),
            ("status", "Status"),
            ("due_date", "Faellig"),
        ],
    ));
    markdown.push_str("\n## Product Security\n\n");
    markdown.push_str(&management_review_object_markdown(
        &package.product_security_json,
    ));
    markdown.push_str("\n## Agent Posture\n\n");
    markdown.push_str(&management_review_object_markdown(
        &package.agent_posture_json,
    ));
    markdown
}

fn management_review_html(package: &report_store::ManagementReviewPackageDetail) -> String {
    format!(
        r#"<!doctype html>
<html lang="de">
<head><meta charset="utf-8"><title>ISCY Management Review {}</title></head>
<body>
<h1>{}</h1>
<p><strong>Status:</strong> {} · <strong>Zeitraum:</strong> {} bis {}</p>
<h2>Executive Summary</h2>
<p>{}</p>
<h2>Entscheidung</h2>
<table><tbody>
<tr><th>Entscheidung</th><td>{}</td></tr>
<tr><th>Naechste Massnahmen</th><td>{}</td></tr>
<tr><th>Freigabe</th><td>{}</td></tr>
</tbody></table>
<h2>Kennzahlen</h2>
{}
{}
{}
{}
{}
{}
<h2>Product Security</h2>
{}
<h2>Agent Posture</h2>
{}
</body>
</html>"#,
        package.id,
        html_escape(&package.title),
        html_escape(&package.status_label),
        html_escape(package.period_start.as_deref().unwrap_or("-")),
        html_escape(package.period_end.as_deref().unwrap_or("-")),
        html_escape(&package.executive_summary),
        html_escape(&package.decision_notes),
        html_escape(&package.next_actions),
        html_escape(package.approved_at.as_deref().unwrap_or("-")),
        management_review_object_html(&package.metrics_json),
        management_review_array_html(
            "Top-Risiken",
            &package.top_risks_json,
            &[
                ("title", "Titel"),
                ("status", "Status"),
                ("score", "Score"),
                ("treatment_plan", "Behandlung"),
            ],
        ),
        management_review_array_html(
            "ISCY-27 Control-Gaps",
            &package.control_gaps_json,
            &[
                ("code", "Control"),
                ("title", "Titel"),
                ("status", "Status"),
                ("evidence_status", "Evidence"),
            ],
        ),
        management_review_array_html(
            "Evidence-Luecken",
            &package.evidence_gaps_json,
            &[
                ("requirement_code", "Requirement"),
                ("title", "Evidence"),
                ("status", "Status"),
                ("covered_count", "Coverage"),
            ],
        ),
        management_review_array_html(
            "Incident-Entscheidungen",
            &package.incident_decisions_json,
            &[
                ("title", "Incident"),
                ("severity", "Severity"),
                ("nis2_significance_status", "Erheblichkeit"),
                ("review_state", "Review"),
            ],
        ),
        management_review_array_html(
            "Roadmap-Fokus",
            &package.roadmap_json,
            &[
                ("title", "Task"),
                ("priority", "Prioritaet"),
                ("status", "Status"),
                ("due_date", "Faellig"),
            ],
        ),
        management_review_object_html(&package.product_security_json),
        management_review_object_html(&package.agent_posture_json),
    )
}

fn management_review_pdf(package: &report_store::ManagementReviewPackageDetail) -> Vec<u8> {
    let mut lines = vec![
        format!("ISCY Management Review: {}", package.title),
        format!("Review-ID: {}", package.id),
        format!("Tenant-ID: {}", package.tenant_id),
        format!(
            "Zeitraum: {} bis {}",
            package.period_start.as_deref().unwrap_or("-"),
            package.period_end.as_deref().unwrap_or("-")
        ),
        format!("Status: {}", package.status_label),
        format!(
            "Freigabe: {}",
            package.approved_at.as_deref().unwrap_or("-")
        ),
        String::new(),
        "Executive Summary:".to_string(),
    ];
    lines.extend(wrap_pdf_text(&package.executive_summary, 92));
    lines.push(String::new());
    lines.push("Entscheidung:".to_string());
    lines.extend(wrap_pdf_text(&package.decision_notes, 92));
    lines.push("Naechste Massnahmen:".to_string());
    lines.extend(wrap_pdf_text(&package.next_actions, 92));
    lines.push(String::new());
    lines.push("Kennzahlen:".to_string());
    lines.extend(wrap_pdf_text(
        &management_review_object_plain(&package.metrics_json),
        92,
    ));
    lines.push(String::new());
    lines.push("Top-Risiken:".to_string());
    lines.extend(management_review_array_pdf_lines(
        &package.top_risks_json,
        &["title", "status", "score"],
    ));
    lines.push("Control-Gaps:".to_string());
    lines.extend(management_review_array_pdf_lines(
        &package.control_gaps_json,
        &["code", "title", "evidence_status"],
    ));
    lines.push("Evidence-Luecken:".to_string());
    lines.extend(management_review_array_pdf_lines(
        &package.evidence_gaps_json,
        &["requirement_code", "title", "status"],
    ));
    lines.push("Incidents:".to_string());
    lines.extend(management_review_array_pdf_lines(
        &package.incident_decisions_json,
        &["title", "severity", "nis2_significance_status"],
    ));
    simple_pdf_document(&lines)
}

fn management_review_object_markdown(value: &Value) -> String {
    let Some(object) = value.as_object() else {
        return "-\n".to_string();
    };
    let mut markdown = String::from("| Kennzahl | Wert |\n| --- | --- |\n");
    for (key, value) in object {
        markdown.push_str(&format!(
            "| {} | {} |\n",
            md_value(key),
            md_value(&management_review_json_display(value))
        ));
    }
    markdown
}

fn management_review_array_markdown(title: &str, value: &Value, fields: &[(&str, &str)]) -> String {
    let mut markdown = format!("\n## {title}\n\n");
    let header = fields
        .iter()
        .map(|(_, label)| md_value(label))
        .collect::<Vec<_>>()
        .join(" | ");
    markdown.push_str(&format!("| {header} | Link |\n"));
    markdown.push_str(&format!(
        "|{}|---|\n",
        fields.iter().map(|_| " --- ").collect::<Vec<_>>().join("|")
    ));
    let Some(items) = value.as_array() else {
        markdown.push_str("| - | - |\n");
        return markdown;
    };
    if items.is_empty() {
        markdown.push_str("| - | - |\n");
        return markdown;
    }
    for item in items {
        let cells = fields
            .iter()
            .map(|(key, _)| {
                md_value(&management_review_json_display(
                    item.get(*key).unwrap_or(&Value::Null),
                ))
            })
            .collect::<Vec<_>>()
            .join(" | ");
        let href = item.get("href").and_then(Value::as_str).unwrap_or("-");
        markdown.push_str(&format!("| {cells} | {} |\n", md_value(href)));
    }
    markdown
}

fn management_review_object_html(value: &Value) -> String {
    let rows = value
        .as_object()
        .map(|object| {
            object
                .iter()
                .map(|(key, value)| {
                    format!(
                        "<tr><th>{}</th><td>{}</td></tr>",
                        html_escape(key),
                        html_escape(&management_review_json_display(value))
                    )
                })
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default();
    format!("<table><tbody>{rows}</tbody></table>")
}

fn management_review_array_html(title: &str, value: &Value, fields: &[(&str, &str)]) -> String {
    let header = fields
        .iter()
        .map(|(_, label)| format!("<th>{}</th>", html_escape(label)))
        .collect::<Vec<_>>()
        .join("");
    let rows = value
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    let href = item.get("href").and_then(Value::as_str);
                    let cells = fields
                        .iter()
                        .enumerate()
                        .map(|(index, (key, _))| {
                            let display = html_escape(&management_review_json_display(
                                item.get(*key).unwrap_or(&Value::Null),
                            ));
                            if index == 0 {
                                if let Some(href) = href {
                                    return format!(
                                        r#"<td><a href="{}">{}</a></td>"#,
                                        html_escape(href),
                                        display
                                    );
                                }
                            }
                            format!("<td>{display}</td>")
                        })
                        .collect::<Vec<_>>()
                        .join("");
                    format!("<tr>{cells}</tr>")
                })
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default();
    format!(
        "<h2>{}</h2><table><thead><tr>{}</tr></thead><tbody>{}</tbody></table>",
        html_escape(title),
        header,
        rows
    )
}

fn management_review_object_plain(value: &Value) -> String {
    value
        .as_object()
        .map(|object| {
            object
                .iter()
                .map(|(key, value)| format!("{key}: {}", management_review_json_display(value)))
                .collect::<Vec<_>>()
                .join("; ")
        })
        .unwrap_or_else(|| "-".to_string())
}

fn management_review_array_pdf_lines(value: &Value, fields: &[&str]) -> Vec<String> {
    let Some(items) = value.as_array() else {
        return vec!["-".to_string()];
    };
    if items.is_empty() {
        return vec!["-".to_string()];
    }
    items
        .iter()
        .take(8)
        .flat_map(|item| {
            let line = fields
                .iter()
                .map(|key| management_review_json_display(item.get(*key).unwrap_or(&Value::Null)))
                .collect::<Vec<_>>()
                .join(" | ");
            wrap_pdf_text(&line, 92)
        })
        .collect()
}

fn incident_timeline_csv(events: &[incident_store::IncidentEventSummary]) -> String {
    let mut rows = vec![[
        "created_at",
        "event_type",
        "event_type_label",
        "summary",
        "actor",
        "detail",
        "from_status",
        "to_status",
        "evidence_item_id",
        "is_export_highlight",
        "export_note",
    ]
    .join(",")];
    for event in events {
        rows.push(
            [
                csv_value(&event.created_at),
                csv_value(&event.event_type),
                csv_value(&event.event_type_label),
                csv_value(&event.summary),
                csv_value(event.actor_display.as_deref().unwrap_or("")),
                csv_value(&event.detail),
                csv_value(event.from_status.as_deref().unwrap_or("")),
                csv_value(event.to_status.as_deref().unwrap_or("")),
                csv_value(
                    &event
                        .evidence_item_id
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                ),
                csv_value(if event.is_export_highlight {
                    "true"
                } else {
                    "false"
                }),
                csv_value(&event.export_note),
            ]
            .join(","),
        );
    }
    rows.join("\n")
}

fn product_security_import_history_csv(
    artifacts: &[product_security_store::ProductSecurityImportArtifactSummary],
) -> String {
    let mut rows = vec![[
        "id",
        "tenant_id",
        "product_id",
        "product_name",
        "artifact_type",
        "file_name",
        "document_id",
        "format_name",
        "format_version",
        "validation_status",
        "validation_errors",
        "component_count",
        "matched_component_count",
        "cve_count",
        "created_by_id",
        "created_at",
        "updated_at",
    ]
    .join(",")];
    for artifact in artifacts {
        rows.push(
            [
                csv_value(&artifact.id.to_string()),
                csv_value(&artifact.tenant_id.to_string()),
                csv_value(
                    &artifact
                        .product_id
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                ),
                csv_value(artifact.product_name.as_deref().unwrap_or("")),
                csv_value(&artifact.artifact_type),
                csv_value(&artifact.file_name),
                csv_value(&artifact.document_id),
                csv_value(&artifact.format_name),
                csv_value(&artifact.format_version),
                csv_value(&artifact.validation_status),
                csv_value(&artifact.validation_errors.join(" | ")),
                csv_value(&artifact.component_count.to_string()),
                csv_value(&artifact.matched_component_count.to_string()),
                csv_value(&artifact.cve_count.to_string()),
                csv_value(
                    &artifact
                        .created_by_id
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                ),
                csv_value(&artifact.created_at),
                csv_value(&artifact.updated_at),
            ]
            .join(","),
        );
    }
    rows.join("\n")
}

fn product_security_import_history_json(
    tenant_id: i64,
    artifacts: &[product_security_store::ProductSecurityImportArtifactSummary],
) -> String {
    serde_json::to_string_pretty(&ProductSecurityImportHistoryExportResponse {
        api_version: "v1",
        tenant_id,
        artifacts: artifacts.to_vec(),
    })
    .unwrap_or_else(|_| "{}".to_string())
}

fn incident_timeline_json(
    incident: &incident_store::IncidentSummary,
    events: &[incident_store::IncidentEventSummary],
) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "api_version": "v1",
        "tenant_id": incident.tenant_id,
        "incident_id": incident.id,
        "incident_title": incident.title,
        "review_state": incident.review_state,
        "review_state_label": incident.review_state_label,
        "events": events,
    }))
    .unwrap_or_else(|_| "{}".to_string())
}

fn incident_nis2_html(
    incident: &incident_store::IncidentSummary,
    evidence_items: &[evidence_store::EvidenceItemSummary],
    events: &[incident_store::IncidentEventSummary],
) -> String {
    let evidence_rows = incident_evidence_rows(evidence_items);
    let event_rows = incident_event_rows(events);
    let decision_matrix = incident_regulatory_decision_matrix_html(incident);
    format!(
        r#"<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <title>ISCY NIS2-Meldepaket {}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 32px; color: #172026; }}
    h1, h2 {{ color: #0f3d3e; }}
    table {{ border-collapse: collapse; width: 100%; margin: 12px 0 24px; }}
    th, td {{ border: 1px solid #ccd6d8; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #eef5f4; }}
    pre {{ white-space: pre-wrap; background: #f6f8f8; padding: 12px; border: 1px solid #d9e1e3; }}
  </style>
</head>
<body>
  <h1>ISCY NIS2-Meldepaket: {}</h1>
  <h2>Fallakte</h2>
  <table>
    <tbody>
      <tr><th>Incident-ID</th><td>{}</td><th>Tenant-ID</th><td>{}</td></tr>
      <tr><th>Titel</th><td>{}</td><th>Typ</th><td>{}</td></tr>
      <tr><th>Severity</th><td>{}</td><th>Status</th><td>{}</td></tr>
      <tr><th>Erheblichkeitsstatus</th><td>{}</td><th>Erheblich bewertet am</th><td>{}</td></tr>
      <tr><th>NIS2</th><td>{}</td><th>Behoerden-/Case-Referenz</th><td>{}</td></tr>
      <tr><th>Meldepaket-Review</th><td>{}</td><th>Version</th><td>{}</td></tr>
      <tr><th>Geprueft</th><td>{} ({})</td><th>Freigegeben</th><td>{} ({})</td></tr>
      <tr><th>24h-Fruehwarnung</th><td>{} ({})</td><th>72h-Meldung</th><td>{} ({})</td></tr>
      <tr><th>30-Tage-Bericht</th><td>{} ({})</td><th>Final gesendet</th><td>{}</td></tr>
    </tbody>
  </table>
  <h2>Beschreibung</h2>
  <p>{}</p>
  <h2>Stakeholder</h2>
  <p>{}</p>
  <h2>NIS2-Erheblichkeitsentscheidung</h2>
  <table>
    <tbody>
      <tr><th>Kriterien</th><td>{}</td></tr>
      <tr><th>Begruendung</th><td>{}</td></tr>
      <tr><th>Referenz</th><td>{}</td></tr>
    </tbody>
  </table>
  {}
  <h2>Runbook</h2>
  <pre>{}</pre>
  <h2>Evidence</h2>
  <table>
    <thead><tr><th>Titel</th><th>Version</th><th>Klasse</th><th>Status</th><th>Requirement</th><th>Gueltig bis</th><th>SHA-256</th><th>Datei</th></tr></thead>
    <tbody>{}</tbody>
  </table>
  <h2>Audit-Timeline</h2>
  <table>
    <thead><tr><th>Zeitpunkt</th><th>Ereignis</th><th>Zusammenfassung</th><th>Actor</th><th>Detail</th><th>Export</th></tr></thead>
    <tbody>{}</tbody>
  </table>
  <h2>Lessons Learned</h2>
  <p>{}</p>
</body>
</html>
"#,
        incident.id,
        html_escape(&incident.title),
        incident.id,
        incident.tenant_id,
        html_escape(&incident.title),
        html_escape(&incident.incident_type_label),
        html_escape(&incident.severity_label),
        html_escape(&incident.status_label),
        html_escape(&incident.nis2_significance_label),
        html_escape(
            incident
                .nis2_significance_assessed_at
                .as_deref()
                .unwrap_or("-")
        ),
        html_escape(&incident.nis2_reportability_label),
        html_escape(&incident.authority_reference),
        html_escape(&incident.review_state_label),
        html_escape(&incident.report_package_version),
        html_escape(incident.reviewed_by_display.as_deref().unwrap_or("-")),
        html_escape(incident.reviewed_at.as_deref().unwrap_or("-")),
        html_escape(incident.approved_by_display.as_deref().unwrap_or("-")),
        html_escape(incident.approved_at.as_deref().unwrap_or("-")),
        html_escape(incident.early_warning_due_at.as_deref().unwrap_or("-")),
        html_escape(&incident.early_warning_state_label),
        html_escape(incident.notification_due_at.as_deref().unwrap_or("-")),
        html_escape(&incident.notification_state_label),
        html_escape(incident.final_report_due_at.as_deref().unwrap_or("-")),
        html_escape(&incident.final_report_state_label),
        html_escape(incident.final_report_sent_at.as_deref().unwrap_or("-")),
        html_escape(&incident.summary),
        html_escape(&incident.stakeholder_summary),
        html_escape(&incident.nis2_significance_criteria),
        html_escape(&incident.nis2_significance_justification),
        html_escape(&incident.nis2_significance_reference),
        decision_matrix,
        html_escape(&incident.runbook_template),
        evidence_rows,
        event_rows,
        html_escape(&incident.lessons_learned),
    )
}

fn incident_nis2_pdf(
    incident: &incident_store::IncidentSummary,
    evidence_items: &[evidence_store::EvidenceItemSummary],
    events: &[incident_store::IncidentEventSummary],
) -> Vec<u8> {
    let mut lines = vec![
        format!("ISCY NIS2-Meldepaket: {}", incident.title),
        format!("Incident-ID: {}", incident.id),
        format!("Tenant-ID: {}", incident.tenant_id),
        format!("Typ: {}", incident.incident_type_label),
        format!("Severity: {}", incident.severity_label),
        format!("Status: {}", incident.status_label),
        format!("Erheblichkeitsstatus: {}", incident.nis2_significance_label),
        format!(
            "Erheblich bewertet am: {}",
            incident
                .nis2_significance_assessed_at
                .as_deref()
                .unwrap_or("-")
        ),
        format!("NIS2: {}", incident.nis2_reportability_label),
        format!("Behoerden-/Case-Referenz: {}", incident.authority_reference),
        format!(
            "Meldepaket-Review: {} (Version {})",
            incident.review_state_label, incident.report_package_version
        ),
        format!(
            "Geprueft: {} ({})",
            incident.reviewed_by_display.as_deref().unwrap_or("-"),
            incident.reviewed_at.as_deref().unwrap_or("-")
        ),
        format!(
            "Freigegeben: {} ({})",
            incident.approved_by_display.as_deref().unwrap_or("-"),
            incident.approved_at.as_deref().unwrap_or("-")
        ),
        format!(
            "24h-Fruehwarnung: {} ({})",
            incident.early_warning_due_at.as_deref().unwrap_or("-"),
            incident.early_warning_state_label
        ),
        format!(
            "72h-Meldung: {} ({})",
            incident.notification_due_at.as_deref().unwrap_or("-"),
            incident.notification_state_label
        ),
        format!(
            "30-Tage-Bericht: {} ({})",
            incident.final_report_due_at.as_deref().unwrap_or("-"),
            incident.final_report_state_label
        ),
        String::new(),
        "Beschreibung:".to_string(),
    ];
    lines.extend(wrap_pdf_text(&incident.summary, 92));
    lines.push(String::new());
    lines.push("NIS2-Erheblichkeitsentscheidung:".to_string());
    lines.push("Kriterien:".to_string());
    lines.extend(wrap_pdf_text(&incident.nis2_significance_criteria, 92));
    lines.push("Begruendung:".to_string());
    lines.extend(wrap_pdf_text(&incident.nis2_significance_justification, 92));
    lines.push("Referenz:".to_string());
    lines.extend(wrap_pdf_text(&incident.nis2_significance_reference, 92));
    lines.push(String::new());
    lines.extend(incident_regulatory_decision_matrix_pdf_lines(incident));
    lines.push(String::new());
    lines.push("Runbook:".to_string());
    for line in incident.runbook_template.lines() {
        lines.extend(wrap_pdf_text(line, 92));
    }
    lines.push(String::new());
    lines.push("Evidence:".to_string());
    if evidence_items.is_empty() {
        lines.push("-".to_string());
    } else {
        for item in evidence_items {
            lines.extend(wrap_pdf_text(
                &format!(
                    "{} | v{} | {} | {} | {} | {} | {} | SHA-256 {}",
                    item.title,
                    item.version_number,
                    item.sensitivity,
                    item.status_label,
                    item.requirement_code.as_deref().unwrap_or("-"),
                    item.valid_until.as_deref().unwrap_or("-"),
                    item.file_name.as_deref().unwrap_or("-"),
                    if item.file_sha256.is_empty() {
                        "-"
                    } else {
                        &item.file_sha256
                    }
                ),
                92,
            ));
        }
    }
    lines.push(String::new());
    lines.push("Audit-Timeline:".to_string());
    if events.is_empty() {
        lines.push("-".to_string());
    } else {
        for event in events {
            lines.extend(wrap_pdf_text(
                &format!(
                    "{} | {} | {} | {} | {}",
                    event.created_at,
                    event.event_type_label,
                    event.summary,
                    event.actor_display.as_deref().unwrap_or("-"),
                    if event.is_export_highlight {
                        "Export"
                    } else {
                        "-"
                    }
                ),
                92,
            ));
            if !event.detail.trim().is_empty() {
                lines.extend(wrap_pdf_text(&format!("Detail: {}", event.detail), 92));
            }
            if event.is_export_highlight && !event.export_note.trim().is_empty() {
                lines.extend(wrap_pdf_text(
                    &format!("Export-Notiz: {}", event.export_note),
                    92,
                ));
            }
        }
    }
    lines.push(String::new());
    lines.push("Lessons Learned:".to_string());
    lines.extend(wrap_pdf_text(&incident.lessons_learned, 92));
    simple_pdf_document(&lines)
}

fn incident_regulatory_package_markdown(
    incident: &incident_store::IncidentSummary,
    evidence_items: &[evidence_store::EvidenceItemSummary],
    events: &[incident_store::IncidentEventSummary],
    package_kind: IncidentPackageKind,
) -> String {
    let evidence_rows = incident_evidence_markdown_rows(evidence_items);
    let event_rows = incident_event_markdown_rows(events);
    format!(
        r#"# ISCY {}: {}

## Fallakte

| Feld | Wert |
| --- | --- |
| Incident-ID | {} |
| Tenant-ID | {} |
| Titel | {} |
| Incident-Typ | {} |
| Severity | {} |
| Status | {} |
| NIS2-Erheblichkeit | {} |
| Meldepaket-Review | {} |
| Behoerden-/Case-Referenz | {} |

## Entscheidung und Pruefpfad

| Feld | Wert |
| --- | --- |
| Regelwerk | {} |
| Prueffrage | {} |
| Status in ISCY | Fachlich pruefen |
| Einordnung | {} |
| Naechster Schritt | {} |

## Beschreibung

{}

## Stakeholder-Zusammenfassung

{}

## Evidence

| Titel | Version | Klasse | Status | Requirement | Gueltig bis | SHA-256 | Datei |
| --- | --- | --- | --- | --- | --- | --- | --- |
{}

## Audit-Timeline

| Zeitpunkt | Ereignis | Zusammenfassung | Actor | Detail | Export |
| --- | --- | --- | --- | --- | --- |
{}

## Zeitlinie

| Ereignis | Zeitpunkt |
| --- | --- |
| Erkannt | {} |
| Bestaetigt | {} |
| Eingedaemmt | {} |
| Behoben | {} |
| Erstellt | {} |
| Aktualisiert | {} |
"#,
        package_kind.title(),
        md_value(&incident.title),
        incident.id,
        incident.tenant_id,
        md_value(&incident.title),
        md_value(&incident.incident_type_label),
        md_value(&incident.severity_label),
        md_value(&incident.status_label),
        md_value(&incident.nis2_significance_label),
        md_value(&incident.review_state_label),
        md_value(&incident.authority_reference),
        package_kind.label(),
        md_value(package_kind.trigger_question()),
        md_value(package_kind.decision_note()),
        md_value(package_kind.next_step()),
        md_block(&incident.summary),
        md_block(&incident.stakeholder_summary),
        evidence_rows,
        event_rows,
        md_optional(incident.detected_at.as_deref()),
        md_optional(incident.confirmed_at.as_deref()),
        md_optional(incident.contained_at.as_deref()),
        md_optional(incident.resolved_at.as_deref()),
        md_value(&incident.created_at),
        md_value(&incident.updated_at),
    )
}

fn incident_regulatory_package_html(
    incident: &incident_store::IncidentSummary,
    evidence_items: &[evidence_store::EvidenceItemSummary],
    events: &[incident_store::IncidentEventSummary],
    package_kind: IncidentPackageKind,
) -> String {
    let evidence_rows = incident_evidence_rows(evidence_items);
    let event_rows = incident_event_rows(events);
    format!(
        r#"<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <title>ISCY {} {}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 32px; color: #172026; }}
    h1, h2 {{ color: #0f3d3e; }}
    table {{ border-collapse: collapse; width: 100%; margin: 12px 0 24px; }}
    th, td {{ border: 1px solid #ccd6d8; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #eef5f4; }}
  </style>
</head>
<body>
  <h1>ISCY {}: {}</h1>
  <h2>Fallakte</h2>
  <table>
    <tbody>
      <tr><th>Incident-ID</th><td>{}</td><th>Tenant-ID</th><td>{}</td></tr>
      <tr><th>Titel</th><td>{}</td><th>Typ</th><td>{}</td></tr>
      <tr><th>Severity</th><td>{}</td><th>Status</th><td>{}</td></tr>
      <tr><th>NIS2-Erheblichkeit</th><td>{}</td><th>Review</th><td>{}</td></tr>
      <tr><th>Behoerden-/Case-Referenz</th><td colspan="3">{}</td></tr>
    </tbody>
  </table>
  <h2>Entscheidung und Pruefpfad</h2>
  <table>
    <tbody>
      <tr><th>Regelwerk</th><td>{}</td></tr>
      <tr><th>Prueffrage</th><td>{}</td></tr>
      <tr><th>Status in ISCY</th><td>Fachlich pruefen</td></tr>
      <tr><th>Einordnung</th><td>{}</td></tr>
      <tr><th>Naechster Schritt</th><td>{}</td></tr>
    </tbody>
  </table>
  <h2>Beschreibung</h2>
  <p>{}</p>
  <h2>Stakeholder</h2>
  <p>{}</p>
  <h2>Evidence</h2>
  <table>
    <thead><tr><th>Titel</th><th>Version</th><th>Klasse</th><th>Status</th><th>Requirement</th><th>Gueltig bis</th><th>SHA-256</th><th>Datei</th></tr></thead>
    <tbody>{}</tbody>
  </table>
  <h2>Audit-Timeline</h2>
  <table>
    <thead><tr><th>Zeitpunkt</th><th>Ereignis</th><th>Zusammenfassung</th><th>Actor</th><th>Detail</th><th>Export</th></tr></thead>
    <tbody>{}</tbody>
  </table>
</body>
</html>
"#,
        package_kind.title(),
        incident.id,
        package_kind.title(),
        html_escape(&incident.title),
        incident.id,
        incident.tenant_id,
        html_escape(&incident.title),
        html_escape(&incident.incident_type_label),
        html_escape(&incident.severity_label),
        html_escape(&incident.status_label),
        html_escape(&incident.nis2_significance_label),
        html_escape(&incident.review_state_label),
        html_escape(&incident.authority_reference),
        package_kind.label(),
        html_escape(package_kind.trigger_question()),
        html_escape(package_kind.decision_note()),
        html_escape(package_kind.next_step()),
        html_escape(&incident.summary),
        html_escape(&incident.stakeholder_summary),
        evidence_rows,
        event_rows,
    )
}

fn incident_regulatory_package_pdf(
    incident: &incident_store::IncidentSummary,
    evidence_items: &[evidence_store::EvidenceItemSummary],
    events: &[incident_store::IncidentEventSummary],
    package_kind: IncidentPackageKind,
) -> Vec<u8> {
    let mut lines = vec![
        format!("ISCY {}: {}", package_kind.title(), incident.title),
        format!("Incident-ID: {}", incident.id),
        format!("Tenant-ID: {}", incident.tenant_id),
        format!("Typ: {}", incident.incident_type_label),
        format!("Severity: {}", incident.severity_label),
        format!("Status: {}", incident.status_label),
        format!("NIS2-Erheblichkeit: {}", incident.nis2_significance_label),
        format!("Review: {}", incident.review_state_label),
        format!("Behoerden-/Case-Referenz: {}", incident.authority_reference),
        String::new(),
        "Entscheidung und Pruefpfad:".to_string(),
    ];
    lines.extend(wrap_pdf_text(
        &format!("Regelwerk: {}", package_kind.label()),
        92,
    ));
    lines.extend(wrap_pdf_text(
        &format!("Prueffrage: {}", package_kind.trigger_question()),
        92,
    ));
    lines.extend(wrap_pdf_text("Status in ISCY: Fachlich pruefen", 92));
    lines.extend(wrap_pdf_text(
        &format!("Einordnung: {}", package_kind.decision_note()),
        92,
    ));
    lines.extend(wrap_pdf_text(
        &format!("Naechster Schritt: {}", package_kind.next_step()),
        92,
    ));
    lines.push(String::new());
    lines.push("Beschreibung:".to_string());
    lines.extend(wrap_pdf_text(&incident.summary, 92));
    lines.push(String::new());
    lines.push("Evidence:".to_string());
    if evidence_items.is_empty() {
        lines.push("-".to_string());
    } else {
        for item in evidence_items {
            lines.extend(wrap_pdf_text(
                &format!(
                    "{} | v{} | {} | {} | {} | {} | {} | SHA-256 {}",
                    item.title,
                    item.version_number,
                    item.sensitivity,
                    item.status_label,
                    item.requirement_code.as_deref().unwrap_or("-"),
                    item.valid_until.as_deref().unwrap_or("-"),
                    item.file_name.as_deref().unwrap_or("-"),
                    if item.file_sha256.is_empty() {
                        "-"
                    } else {
                        &item.file_sha256
                    }
                ),
                92,
            ));
        }
    }
    lines.push(String::new());
    lines.push("Audit-Timeline:".to_string());
    if events.is_empty() {
        lines.push("-".to_string());
    } else {
        for event in events {
            lines.extend(wrap_pdf_text(
                &format!(
                    "{} | {} | {} | {}",
                    event.created_at,
                    event.event_type_label,
                    event.summary,
                    event.actor_display.as_deref().unwrap_or("-")
                ),
                92,
            ));
        }
    }
    simple_pdf_document(&lines)
}

fn simple_pdf_document(lines: &[String]) -> Vec<u8> {
    let mut content = String::from("BT\n/F1 9 Tf\n50 800 Td\n10 TL\n");
    for line in lines.iter().take(76) {
        content.push_str(&format!("({}) Tj\nT*\n", pdf_escape(line)));
    }
    content.push_str("ET\n");

    let objects = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>".to_string(),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
        format!("<< /Length {} >>\nstream\n{}endstream", content.len(), content),
    ];
    let mut pdf = String::from("%PDF-1.4\n");
    let mut offsets = Vec::with_capacity(objects.len());
    for (index, object) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.push_str(&format!("{} 0 obj\n{}\nendobj\n", index + 1, object));
    }
    let xref_start = pdf.len();
    pdf.push_str(&format!("xref\n0 {}\n", objects.len() + 1));
    pdf.push_str("0000000000 65535 f\n");
    for offset in offsets {
        pdf.push_str(&format!("{offset:010} 00000 n\n"));
    }
    pdf.push_str(&format!(
        "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
        objects.len() + 1,
        xref_start
    ));
    pdf.into_bytes()
}

fn wrap_pdf_text(value: &str, max_len: usize) -> Vec<String> {
    let sanitized = pdf_plain_text(value);
    if sanitized.trim().is_empty() {
        return vec!["-".to_string()];
    }
    let mut lines = Vec::new();
    for raw_line in sanitized.lines() {
        let mut current = String::new();
        for word in raw_line.split_whitespace() {
            if current.len() + word.len() + 1 > max_len && !current.is_empty() {
                lines.push(current);
                current = String::new();
            }
            if !current.is_empty() {
                current.push(' ');
            }
            current.push_str(word);
        }
        if !current.is_empty() {
            lines.push(current);
        }
    }
    if lines.is_empty() {
        vec!["-".to_string()]
    } else {
        lines
    }
}

fn pdf_plain_text(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            '\n' | '\r' => '\n',
            ch if ch.is_ascii() && !ch.is_control() => ch,
            _ => '?',
        })
        .collect()
}

fn pdf_escape(value: &str) -> String {
    pdf_plain_text(value)
        .replace('\\', "\\\\")
        .replace('(', "\\(")
        .replace(')', "\\)")
}

fn html_download_response(file_name: &str, body: String) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    let disposition = format!("attachment; filename=\"{}\"", file_name);
    if let Ok(value) = HeaderValue::from_str(&disposition) {
        headers.insert(CONTENT_DISPOSITION, value);
    }
    (StatusCode::OK, headers, body).into_response()
}

fn text_download_response(file_name: &str, content_type: &'static str, body: String) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    let disposition = format!("attachment; filename=\"{}\"", file_name);
    if let Ok(value) = HeaderValue::from_str(&disposition) {
        headers.insert(CONTENT_DISPOSITION, value);
    }
    (StatusCode::OK, headers, body).into_response()
}

fn binary_download_response(
    file_name: &str,
    content_type: &'static str,
    body: Vec<u8>,
) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    let disposition = format!("attachment; filename=\"{}\"", file_name);
    if let Ok(value) = HeaderValue::from_str(&disposition) {
        headers.insert(CONTENT_DISPOSITION, value);
    }
    (StatusCode::OK, headers, body).into_response()
}

fn markdown_download_response(file_name: &str, body: String) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/markdown; charset=utf-8"),
    );
    let disposition = format!("attachment; filename=\"{}\"", file_name);
    if let Ok(value) = HeaderValue::from_str(&disposition) {
        headers.insert(CONTENT_DISPOSITION, value);
    }
    (StatusCode::OK, headers, body).into_response()
}

fn md_optional(value: Option<&str>) -> String {
    value.map(md_value).unwrap_or_else(|| "-".to_string())
}

fn md_value(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "-".to_string()
    } else {
        trimmed.replace('|', "\\|")
    }
}

fn csv_value(value: &str) -> String {
    let escaped = value.replace('"', "\"\"");
    format!("\"{}\"", escaped.replace(['\n', '\r'], " "))
}

fn md_block(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "-".to_string()
    } else {
        trimmed.to_string()
    }
}

async fn incident_linked_evidence(
    state: &AppState,
    tenant_id: i64,
    incident_id: i64,
) -> Vec<evidence_store::EvidenceItemSummary> {
    let Some(store) = state.evidence_store.clone() else {
        return Vec::new();
    };
    store
        .list_evidence_for_incident(tenant_id, incident_id, 50)
        .await
        .unwrap_or_default()
}

async fn record_incident_evidence_event(
    state: &AppState,
    tenant_id: i64,
    actor_id: i64,
    item: &evidence_store::EvidenceItemSummary,
) {
    let (Some(incident_id), Some(store)) = (item.incident_id, state.incident_store.clone()) else {
        return;
    };
    let _ = store
        .append_incident_event(
            tenant_id,
            incident_id,
            Some(actor_id),
            incident_store::IncidentEventWriteRequest::evidence_uploaded(item.id, &item.title),
        )
        .await;
}

fn incident_evidence_rows(evidence_items: &[evidence_store::EvidenceItemSummary]) -> String {
    if evidence_items.is_empty() {
        return web_empty_row(8, "Keine Evidence mit diesem Incident verknuepft.");
    }
    evidence_items
        .iter()
        .map(|item| {
            format!(
                r#"<tr><td>{}</td><td>v{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>"#,
                html_escape(&item.title),
                item.version_number,
                html_escape(&item.sensitivity),
                html_escape(&item.status_label),
                html_escape(item.requirement_code.as_deref().unwrap_or("-")),
                html_escape(item.valid_until.as_deref().unwrap_or("-")),
                html_escape(if item.file_sha256.is_empty() {
                    "-"
                } else {
                    &item.file_sha256
                }),
                html_escape(item.file_name.as_deref().unwrap_or("-")),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn incident_runbook_template_options(
    templates: &[incident_store::IncidentRunbookTemplateSummary],
    selected_slug: Option<&str>,
) -> String {
    if templates.is_empty() {
        return format!(
            r#"<option value="{}">Standard-Runbook</option>"#,
            html_escape(incident_store_default_runbook())
        );
    }
    templates
        .iter()
        .enumerate()
        .map(|(index, template)| {
            let selected = selected_slug
                .map(|slug| slug == template.slug)
                .unwrap_or(index == 0);
            format!(
                r#"<option value="{}"{}>{} · {} · {}</option>"#,
                html_escape(&template.body),
                selected_attr(selected),
                html_escape(&template.title),
                html_escape(&template.incident_type_label),
                html_escape(&template.severity_label),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn incident_runbook_template_rows(
    templates: &[incident_store::IncidentRunbookTemplateSummary],
) -> String {
    if templates.is_empty() {
        return web_empty_row(4, "Keine Runbook-Vorlagen fuer diesen Tenant vorhanden.");
    }
    templates
        .iter()
        .map(|template| {
            format!(
                r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                html_escape(&template.title),
                html_escape(&template.incident_type_label),
                html_escape(&template.severity_label),
                html_escape(&template.description),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn incident_runbook_template_admin_rows(
    context: &WebContext,
    templates: &[incident_store::IncidentRunbookTemplateSummary],
    can_write: bool,
) -> String {
    if templates.is_empty() {
        return web_empty_row(6, "Keine Runbook-Vorlagen fuer diesen Tenant vorhanden.");
    }
    templates
        .iter()
        .map(|template| {
            let status = if template.is_active {
                "Aktiv"
            } else {
                "Deaktiviert"
            };
            let action = if can_write {
                let update_action = web_path_with_context(
                    &format!("/incidents/runbook-templates/{}", template.id),
                    Some(context),
                );
                format!(
                    r#"
                    <details>
                      <summary>Bearbeiten</summary>
                      <form method="post" action="{}">
                        <input name="action" type="hidden" value="update">
                        <div class="form-grid">
                          <label>Slug<input name="slug" type="text" value="{}" maxlength="80"></label>
                          <label>Titel<input name="title" type="text" required value="{}"></label>
                          <label>Typ<select name="incident_type">{}</select></label>
                          <label>Severity<select name="severity">{}</select></label>
                          <label>Reihenfolge<input name="sort_order" type="number" value="{}"></label>
                        </div>
                        <label class="checkbox-row"><input name="is_active" type="checkbox" value="1"{}> Aktiv</label>
                        <label>Beschreibung<textarea name="description" rows="2">{}</textarea></label>
                        <label>Runbook<textarea name="body" rows="5" required>{}</textarea></label>
                        <button type="submit">Speichern</button>
                      </form>
                      <form method="post" action="{}">
                        <input name="action" type="hidden" value="deactivate">
                        <button type="submit">Deaktivieren</button>
                      </form>
                    </details>
                    "#,
                    html_escape(&update_action),
                    html_escape(&template.slug),
                    html_escape(&template.title),
                    incident_type_options_for(&template.incident_type),
                    incident_severity_options_for(&template.severity),
                    template.sort_order,
                    checked_attr(template.is_active),
                    html_escape(&template.description),
                    html_escape(&template.body),
                    html_escape(&update_action),
                )
            } else {
                "-".to_string()
            };
            format!(
                r#"<tr><td><strong>{}</strong><p>{}</p></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                html_escape(&template.title),
                html_escape(&template.description),
                html_escape(status),
                html_escape(&template.incident_type_label),
                html_escape(&template.severity_label),
                template.sort_order,
                action,
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn incident_runbook_template_create_panel(context: &WebContext, can_write: bool) -> String {
    if !can_write {
        return r#"<article class="panel wide"><h2>Neue Vorlage</h2><p>Fuer Runbook-Template-CRUD ist eine schreibende ISCY-Rolle notwendig.</p></article>"#.to_string();
    }
    let action = web_path_with_context("/incidents/runbook-templates/", Some(context));
    format!(
        r#"
        <article class="panel wide">
          <h2>Neue Vorlage</h2>
          <form method="post" action="{}">
            <div class="form-grid">
              <label>Slug<input name="slug" type="text" maxlength="80"></label>
              <label>Titel<input name="title" type="text" required></label>
              <label>Typ<select name="incident_type">{}</select></label>
              <label>Severity<select name="severity">{}</select></label>
              <label>Reihenfolge<input name="sort_order" type="number" value="100"></label>
            </div>
            <label class="checkbox-row"><input name="is_active" type="checkbox" value="1" checked> Aktiv</label>
            <label>Beschreibung<textarea name="description" rows="2"></textarea></label>
            <label>Runbook<textarea name="body" rows="7" required>{}</textarea></label>
            <button type="submit">Vorlage anlegen</button>
          </form>
        </article>
        "#,
        html_escape(&action),
        incident_type_options_for("GENERAL"),
        incident_severity_options_for("MEDIUM"),
        html_escape(incident_store_default_runbook()),
    )
}

fn incident_store_default_runbook() -> &'static str {
    "1. Scope: betroffene Systeme, Prozesse, Personen und Zeitraum erfassen.\n2. Eindaemmung: unmittelbare Schutzmassnahmen und Verantwortliche festlegen.\n3. Bewertung: Schweregrad, NIS2-Erheblichkeit, Datenbezug und Business Impact pruefen.\n4. Kommunikation: Owner, Management, Legal und externe Stellen abstimmen.\n5. Abschluss: Root Cause, Evidence, Lessons Learned und Massnahmen dokumentieren."
}

fn incident_runbook_step_rows(
    context: &WebContext,
    incident_id: i64,
    steps: &[incident_store::IncidentRunbookStepSummary],
    can_write: bool,
) -> String {
    if steps.is_empty() {
        return web_empty_row(4, "Keine Runbook-Schritte fuer diese Fallakte vorhanden.");
    }
    steps
        .iter()
        .map(|step| {
            let status = if step.is_done { "Erledigt" } else { "Offen" };
            let action = if can_write {
                let form_action = web_path_with_context(
                    &format!("/incidents/{incident_id}/runbook-steps/{}", step.id),
                    Some(context),
                );
                format!(
                    r#"
                    <form method="post" action="{}">
                      <input name="action" type="hidden" value="toggle">
                      <label class="checkbox-row"><input name="is_done" type="checkbox" value="1"{}> Erledigt</label>
                      <button type="submit">Speichern</button>
                    </form>
                    <form method="post" action="{}">
                      <input name="action" type="hidden" value="move_up">
                      <button type="submit">Hoch</button>
                    </form>
                    <form method="post" action="{}">
                      <input name="action" type="hidden" value="move_down">
                      <button type="submit">Runter</button>
                    </form>
                    "#,
                    html_escape(&form_action),
                    checked_attr(step.is_done),
                    html_escape(&form_action),
                    html_escape(&form_action),
                )
            } else {
                "-".to_string()
            };
            let detail = if step.detail.trim().is_empty() {
                String::new()
            } else {
                format!("<p>{}</p>", html_escape(&step.detail))
            };
            format!(
                r#"<tr><td><strong>{}. {}</strong>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                step.step_number,
                html_escape(&step.title),
                detail,
                html_escape(status),
                html_escape(step.done_by_display.as_deref().unwrap_or("-")),
                action,
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn incident_review_panel(
    context: &WebContext,
    incident: &incident_store::IncidentSummary,
    can_write: bool,
) -> String {
    let reviewed_by = incident.reviewed_by_display.as_deref().unwrap_or("-");
    let approved_by = incident.approved_by_display.as_deref().unwrap_or("-");
    let action =
        web_path_with_context(&format!("/incidents/{}/review", incident.id), Some(context));
    let form = if can_write {
        format!(
            r#"
            <form method="post" action="{}">
              <label>Review-/Freigabenotiz<textarea name="notes" rows="3"></textarea></label>
              <div class="toolbar">
                <button name="action" value="request_review" type="submit">Review anfordern</button>
                <button name="action" value="reviewed" type="submit">Als geprueft markieren</button>
                <button name="action" value="approve" type="submit">Freigeben</button>
                <button name="action" value="changes_requested" type="submit">Aenderungen anfordern</button>
                <button name="action" value="reopen" type="submit">Zurueck in Entwurf</button>
              </div>
            </form>
            "#,
            html_escape(&action),
        )
    } else {
        "<p>Fuer Review/Freigabe ist eine schreibende ISCY-Rolle notwendig.</p>".to_string()
    };
    format!(
        r#"
        <article class="panel wide">
          <h2>Review und Freigabe</h2>
          <table>
            <tbody>
              <tr><th>Status</th><td>{}</td><th>Version</th><td>{}</td></tr>
              <tr><th>Geprueft von</th><td>{}</td><th>Geprueft am</th><td>{}</td></tr>
              <tr><th>Freigegeben von</th><td>{}</td><th>Freigegeben am</th><td>{}</td></tr>
              <tr><th>Review-Notiz</th><td colspan="3">{}</td></tr>
              <tr><th>Freigabe-Notiz</th><td colspan="3">{}</td></tr>
            </tbody>
          </table>
          {}
        </article>
        "#,
        html_escape(&incident.review_state_label),
        html_escape(&incident.report_package_version),
        html_escape(reviewed_by),
        html_escape(incident.reviewed_at.as_deref().unwrap_or("-")),
        html_escape(approved_by),
        html_escape(incident.approved_at.as_deref().unwrap_or("-")),
        html_escape(&incident.review_notes),
        html_escape(&incident.approval_notes),
        form,
    )
}

fn incident_event_rows(events: &[incident_store::IncidentEventSummary]) -> String {
    if events.is_empty() {
        return web_empty_row(6, "Noch keine Timeline-Events vorhanden.");
    }
    events
        .iter()
        .map(|event| {
            let export = if event.is_export_highlight {
                if event.export_note.trim().is_empty() {
                    "Exportrelevant".to_string()
                } else {
                    format!("Exportrelevant: {}", event.export_note)
                }
            } else {
                "-".to_string()
            };
            format!(
                r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                html_escape(&event.created_at),
                html_escape(&event.event_type_label),
                html_escape(&event.summary),
                html_escape(event.actor_display.as_deref().unwrap_or("-")),
                html_escape(&event.detail),
                html_escape(&export),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn incident_event_rows_for_web(
    events: &[incident_store::IncidentEventSummary],
    context: &WebContext,
    incident_id: i64,
    can_write: bool,
) -> String {
    if events.is_empty() {
        return web_empty_row(6, "Keine Timeline-Events fuer diesen Filter vorhanden.");
    }
    events
        .iter()
        .map(|event| {
            let export_marker =
                incident_event_export_marker_form(event, context, incident_id, can_write);
            let detail = if event.export_note.trim().is_empty() {
                html_escape(&event.detail)
            } else {
                format!(
                    "{}<p><strong>Export-Notiz:</strong> {}</p>",
                    html_escape(&event.detail),
                    html_escape(&event.export_note)
                )
            };
            format!(
                r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                html_escape(&event.created_at),
                html_escape(&event.event_type_label),
                html_escape(&event.summary),
                html_escape(event.actor_display.as_deref().unwrap_or("-")),
                detail,
                export_marker,
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn incident_event_export_marker_form(
    event: &incident_store::IncidentEventSummary,
    context: &WebContext,
    incident_id: i64,
    can_write: bool,
) -> String {
    let label = if event.is_export_highlight {
        "Exportrelevant"
    } else {
        "-"
    };
    if !can_write {
        return html_escape(label);
    }
    let action = web_path_with_context(
        &format!("/incidents/{incident_id}/timeline-events/{}", event.id),
        Some(context),
    );
    format!(
        r#"
        <form method="post" action="{}">
          <label class="checkbox-row"><input name="is_export_highlight" type="checkbox" value="1"{}> Export</label>
          <input name="export_note" type="text" value="{}" maxlength="1000">
          <button type="submit">Merken</button>
        </form>
        "#,
        html_escape(&action),
        checked_attr(event.is_export_highlight),
        html_escape(&event.export_note),
    )
}

fn normalize_incident_timeline_filter(value: Option<&str>) -> String {
    match value.unwrap_or("all").trim().to_ascii_lowercase().as_str() {
        "highlighted" | "export" => "highlighted".to_string(),
        "notes" | "note" => "notes".to_string(),
        "evidence" => "evidence".to_string(),
        "status" => "status".to_string(),
        "runbook" => "runbook".to_string(),
        "review" => "review".to_string(),
        _ => "all".to_string(),
    }
}

fn normalize_incident_register_filter(value: Option<&str>) -> String {
    match value.unwrap_or("all").trim().to_ascii_lowercase().as_str() {
        "unassessed" | "erheblichkeit_offen" | "open_significance" => "unassessed".to_string(),
        _ => "all".to_string(),
    }
}

fn filter_incident_register_rows(
    incidents: &[incident_store::IncidentSummary],
    register_filter: &str,
) -> Vec<incident_store::IncidentSummary> {
    incidents
        .iter()
        .filter(|incident| match register_filter {
            "unassessed" => {
                incident.nis2_significance_status == "NOT_ASSESSED"
                    && !matches!(incident.status.as_str(), "RESOLVED" | "CLOSED")
            }
            _ => true,
        })
        .cloned()
        .collect()
}

fn incident_register_filter_links(context: &WebContext, selected_filter: &str) -> String {
    [("all", "Alle"), ("unassessed", "Erheblichkeit offen")]
        .iter()
        .map(|(value, label)| {
            let href = if *value == "all" {
                web_path_with_context("/incidents/", Some(context))
            } else {
                web_path_with_context(
                    &format!("/incidents/?incident_filter={value}"),
                    Some(context),
                )
            };
            let class_attr = if *value == selected_filter {
                r#" class="active""#
            } else {
                ""
            };
            format!(
                r#"<a{} href="{}">{}</a>"#,
                class_attr,
                html_escape(&href),
                html_escape(label)
            )
        })
        .collect::<Vec<_>>()
        .join(" · ")
}

fn filter_incident_events(
    events: &[incident_store::IncidentEventSummary],
    timeline_filter: &str,
) -> Vec<incident_store::IncidentEventSummary> {
    events
        .iter()
        .filter(|event| match timeline_filter {
            "highlighted" => event.is_export_highlight,
            "notes" => event.event_type == "TIMELINE_NOTE",
            "evidence" => event.event_type == "EVIDENCE_UPLOADED",
            "status" => event.event_type == "STATUS_CHANGED",
            "runbook" => event.event_type == "RUNBOOK_STEP_UPDATED",
            "review" => event.event_type == "INCIDENT_REVIEW_UPDATED",
            _ => true,
        })
        .cloned()
        .collect()
}

fn incident_timeline_filter_links(
    context: &WebContext,
    incident_id: i64,
    selected_filter: &str,
) -> String {
    [
        ("all", "Alle"),
        ("highlighted", "Export"),
        ("notes", "Notizen"),
        ("evidence", "Evidence"),
        ("status", "Status"),
        ("runbook", "Runbook"),
        ("review", "Review"),
    ]
    .iter()
    .map(|(value, label)| {
        let href = web_path_with_context(
            &format!("/incidents/{incident_id}?timeline={value}"),
            Some(context),
        );
        let class_attr = if *value == selected_filter {
            r#" class="active""#
        } else {
            ""
        };
        format!(
            r#"<a{} href="{}">{}</a>"#,
            class_attr,
            html_escape(&href),
            html_escape(label),
        )
    })
    .collect::<Vec<_>>()
    .join(" ")
}

fn incident_timeline_note_panel(context: &WebContext, incident_id: i64, can_write: bool) -> String {
    if !can_write {
        return "<p>Fuer Timeline-Notizen ist eine schreibende ISCY-Rolle notwendig.</p>"
            .to_string();
    }
    let action = web_path_with_context(
        &format!("/incidents/{incident_id}/timeline-notes"),
        Some(context),
    );
    format!(
        r#"
        <form method="post" action="{}">
          <h3>Timeline-Notiz</h3>
          <label>Kurzfassung<input name="summary" type="text" maxlength="255"></label>
          <label>Notiz<textarea name="detail" rows="4" required></textarea></label>
          <button type="submit">Notiz speichern</button>
        </form>
        "#,
        html_escape(&action),
    )
}

fn incident_event_markdown_rows(events: &[incident_store::IncidentEventSummary]) -> String {
    if events.is_empty() {
        return "| - | - | - | - | - | - |".to_string();
    }
    events
        .iter()
        .map(|event| {
            let export = if event.is_export_highlight {
                if event.export_note.trim().is_empty() {
                    "Exportrelevant".to_string()
                } else {
                    format!("Exportrelevant: {}", event.export_note)
                }
            } else {
                "-".to_string()
            };
            format!(
                "| {} | {} | {} | {} | {} | {} |",
                md_value(&event.created_at),
                md_value(&event.event_type_label),
                md_value(&event.summary),
                md_optional(event.actor_display.as_deref()),
                md_value(&event.detail),
                md_value(&export),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn incident_evidence_upload_panel(
    context: &WebContext,
    incident_id: i64,
    can_write: bool,
    evidence_store_available: bool,
) -> String {
    if !evidence_store_available {
        return "<p>Evidence Store ist fuer diese Fallakte nicht konfiguriert.</p>".to_string();
    }
    if !can_write {
        return "<p>Fuer Evidence-Uploads ist eine schreibende ISCY-Rolle notwendig.</p>"
            .to_string();
    }
    let return_to = web_path_with_context(&format!("/incidents/{}", incident_id), Some(context));
    format!(
        r#"
        <h2>Evidence zum Incident hochladen</h2>
        <form method="post" action="/evidence/" enctype="multipart/form-data">
          <input name="incident_id" type="hidden" value="{}">
          <input name="return_to" type="hidden" value="{}">
          <div class="form-grid">
            <label>Titel<input name="title" type="text" required></label>
            <label>Status<select name="status">{}</select></label>
            <label>Session-ID<input name="session_id" type="number" min="1"></label>
            <label>Requirement-ID<input name="requirement_id" type="number" min="1"></label>
            <label>Vorgaenger-ID<input name="supersedes_id" type="number" min="1"></label>
            <label>Schutzklasse<select name="sensitivity">{}</select></label>
            <label>Gueltig bis<input name="valid_until" type="date"></label>
            <label>Aufbewahren bis<input name="retention_until" type="date"></label>
          </div>
          <label>Linked Requirement<input name="linked_requirement" type="text"></label>
          <label>Beschreibung<textarea name="description" rows="3"></textarea></label>
          <label>Retention-Begruendung<textarea name="retention_reason" rows="2"></textarea></label>
          <label>Datei<input name="file" type="file" accept=".pdf,.docx,.xlsx,.png,.jpg,.jpeg,.csv,.txt"></label>
          <button type="submit">Evidence an Fallakte haengen</button>
        </form>
        "#,
        incident_id,
        html_escape(&return_to),
        evidence_status_options_for("SUBMITTED"),
        evidence_sensitivity_options_for("INTERNAL"),
    )
}

fn incident_evidence_markdown_rows(
    evidence_items: &[evidence_store::EvidenceItemSummary],
) -> String {
    if evidence_items.is_empty() {
        return "| - | - | - | - | - | - | - | - |".to_string();
    }
    evidence_items
        .iter()
        .map(|item| {
            format!(
                "| {} | v{} | {} | {} | {} | {} | {} | {} |",
                md_value(&item.title),
                item.version_number,
                md_value(&item.sensitivity),
                md_value(&item.status_label),
                md_optional(item.requirement_code.as_deref()),
                md_optional(item.valid_until.as_deref()),
                md_value(if item.file_sha256.is_empty() {
                    "-"
                } else {
                    &item.file_sha256
                }),
                md_optional(item.file_name.as_deref()),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn incident_runbook_step_count(runbook_template: &str) -> usize {
    runbook_template
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count()
}

fn incident_type_options_for(selected_type: &str) -> String {
    [
        ("GENERAL", "Allgemein"),
        ("PHISHING", "Phishing"),
        ("MALWARE", "Malware"),
        ("DATA_BREACH", "Datenabfluss"),
        ("OUTAGE", "Ausfall"),
        ("SUPPLIER", "Lieferant"),
        ("VULNERABILITY", "Schwachstelle"),
    ]
    .iter()
    .map(|(value, label)| {
        format!(
            r#"<option value="{}"{}>{}</option>"#,
            value,
            selected_attr(value == &selected_type),
            label
        )
    })
    .collect::<Vec<_>>()
    .join("")
}

fn incident_severity_options_for(selected_status: &str) -> String {
    [
        ("CRITICAL", "Kritisch"),
        ("HIGH", "Hoch"),
        ("MEDIUM", "Mittel"),
        ("LOW", "Niedrig"),
        ("INFO", "Info"),
    ]
    .iter()
    .map(|(value, label)| {
        format!(
            r#"<option value="{}"{}>{}</option>"#,
            value,
            selected_attr(value == &selected_status),
            label
        )
    })
    .collect::<Vec<_>>()
    .join("")
}

fn incident_status_options_for(selected_status: &str) -> String {
    [
        ("TRIAGE", "Triage"),
        ("CONFIRMED", "Bestaetigt"),
        ("CONTAINED", "Eingedaemmt"),
        ("RESOLVED", "Behoben"),
        ("CLOSED", "Geschlossen"),
    ]
    .iter()
    .map(|(value, label)| {
        format!(
            r#"<option value="{}"{}>{}</option>"#,
            value,
            selected_attr(value == &selected_status),
            label
        )
    })
    .collect::<Vec<_>>()
    .join("")
}

fn incident_nis2_significance_options_for(selected_status: &str) -> String {
    [
        ("NOT_ASSESSED", "Nicht bewertet"),
        ("NOT_SIGNIFICANT", "Nicht erheblich"),
        ("LIKELY_SIGNIFICANT", "Wahrscheinlich erheblich"),
        ("SIGNIFICANT", "Erheblich / NIS2 meldepflichtig"),
    ]
    .iter()
    .map(|(value, label)| {
        format!(
            r#"<option value="{}"{}>{}</option>"#,
            value,
            selected_attr(value == &selected_status),
            label
        )
    })
    .collect::<Vec<_>>()
    .join("")
}

fn incident_status_badge(status: &str, label: &str) -> String {
    web_badge(label, incident_status_badge_class(status))
}

fn incident_status_badge_class(status: &str) -> &'static str {
    match status {
        "RESOLVED" | "CLOSED" => "ok",
        "TRIAGE" => "warn",
        "CONFIRMED" | "CONTAINED" => "info",
        _ => "muted-badge",
    }
}

fn incident_significance_badge_class(status: &str) -> &'static str {
    match status {
        "NOT_SIGNIFICANT" => "ok",
        "LIKELY_SIGNIFICANT" => "warn",
        "SIGNIFICANT" => "danger",
        _ => "warn",
    }
}

fn incident_severity_badge(severity: &str, label: &str) -> String {
    let class_name = match severity {
        "CRITICAL" => "danger",
        "HIGH" => "high",
        "MEDIUM" => "warn",
        "LOW" => "info",
        _ => "muted-badge",
    };
    web_badge(label, class_name)
}

fn web_cve_assessment_form_panel(
    context: &WebContext,
    options: Option<&cve_store::CveAssessmentFormOptions>,
    can_write: bool,
) -> String {
    if !can_write {
        return r#"
        <article class="panel wide">
          <h2>Neue Analyse</h2>
          <p>Fuer neue CVE-Assessments ist eine schreibende ISCY-Rolle notwendig.</p>
        </article>
        "#
        .to_string();
    }
    let Some(options) = options else {
        return r#"
        <article class="panel wide">
          <h2>Neue Analyse</h2>
          <p>Produkt- und Releaseoptionen konnten noch nicht geladen werden.</p>
        </article>
        "#
        .to_string();
    };

    let product_options = options
        .products
        .iter()
        .map(|product| {
            format!(
                r#"<option value="{}">{}</option>"#,
                product.id,
                html_escape(&product.name),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let release_options = options
        .releases
        .iter()
        .map(|release| {
            format!(
                r#"<option value="{}">{}</option>"#,
                release.id,
                html_escape(&release.label),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let component_options = options
        .components
        .iter()
        .map(|component| {
            format!(
                r#"<option value="{}">{}</option>"#,
                component.id,
                html_escape(&component.label),
            )
        })
        .collect::<Vec<_>>()
        .join("");

    format!(
        r#"
        <article class="panel wide">
          <h2>Neue Analyse</h2>
          <form method="post" action="{}">
            <div class="grid two">
              <label>CVE-ID<input type="text" name="cve_id" placeholder="CVE-2026-1234" required></label>
              <label>Produkt
                <select name="product_id">
                  <option value="">Kein Produkt</option>
                  {}
                </select>
              </label>
              <label>Release
                <select name="release_id">
                  <option value="">Kein Release</option>
                  {}
                </select>
              </label>
              <label>Komponente
                <select name="component_id">
                  <option value="">Keine Komponente</option>
                  {}
                </select>
              </label>
              <label>Exponierung
                <select name="exposure">
                  <option value="UNKNOWN"{}>Unklar</option>
                  <option value="INTERNAL"{}>Nur intern</option>
                  <option value="CUSTOMER"{}>Beim Kunden</option>
                  <option value="INTERNET"{}>Internet-exponiert</option>
                </select>
              </label>
              <label>Kritikalitaet
                <select name="asset_criticality">
                  <option value="LOW"{}>Niedrig</option>
                  <option value="MEDIUM"{}>Mittel</option>
                  <option value="HIGH"{}>Hoch</option>
                  <option value="CRITICAL"{}>Kritisch</option>
                </select>
              </label>
              <label>EPSS-Score<input type="text" name="epss_score" placeholder="0.9130"></label>
              <label>Exploit-Reife
                <select name="exploit_maturity">
                  <option value="UNKNOWN"{}>Unbekannt</option>
                  <option value="UNPROVEN"{}>Kein Exploit bekannt</option>
                  <option value="POC"{}>Proof of Concept</option>
                  <option value="ACTIVE"{}>Aktive Ausnutzung</option>
                  <option value="AUTOMATED"{}>Automatisiert</option>
                </select>
              </label>
              <label>Repository<input type="text" name="repository_name" placeholder="sensor-gateway"></label>
              <label>Repository-URL<input type="text" name="repository_url" placeholder="https://git.example/iscy"></label>
              <label>Git-Ref<input type="text" name="git_ref" placeholder="main"></label>
              <label>Source Package<input type="text" name="source_package" placeholder="gateway-firmware"></label>
              <label>Package-Version<input type="text" name="source_package_version" placeholder="1.0.3"></label>
              <label>Regulatorische Tags<input type="text" name="regulatory_tags" placeholder="NIS2, CRA"></label>
            </div>
            <label>NIS2-Impact<textarea name="nis2_impact_summary" rows="3"></textarea></label>
            <label>Business Context<textarea name="business_context" rows="4"></textarea></label>
            <label>Bestehende Kontrollen<textarea name="existing_controls" rows="4"></textarea></label>
            <div class="toolbar">
              <label><input type="checkbox" name="in_kev_catalog"> KEV</label>
              <label><input type="checkbox" name="affects_critical_service"> Kritischer Service betroffen</label>
              <label><input type="checkbox" name="nis2_relevant"> NIS2-relevant</label>
              <label><input type="checkbox" name="auto_create_risk"{}> Risiko automatisch anlegen</label>
              <label><input type="checkbox" name="run_llm"{}> LLM-Stub anwenden</label>
              <button type="submit">Analyse speichern</button>
            </div>
          </form>
        </article>
        "#,
        web_path_with_context("/cves/", Some(context)),
        product_options,
        release_options,
        component_options,
        selected_attr(true),
        selected_attr(false),
        selected_attr(false),
        selected_attr(false),
        selected_attr(false),
        selected_attr(true),
        selected_attr(false),
        selected_attr(false),
        selected_attr(true),
        selected_attr(false),
        selected_attr(false),
        selected_attr(false),
        selected_attr(false),
        checked_attr(true),
        checked_attr(true),
    )
}

async fn web_cves(
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
        return web_missing_context("Vulnerability Intelligence", "/cves/");
    };
    let can_write = auth_context
        .as_ref()
        .is_some_and(|context| context.can_write());
    let Some(store) = state.cve_store else {
        return web_store_missing("Vulnerability Intelligence", "/cves/", &context, "CVE");
    };
    let summary = match store.dashboard_summary().await {
        Ok(summary) => summary,
        Err(err) => {
            return web_error_page(
                "Vulnerability Intelligence",
                "/cves/",
                &context,
                &err.to_string(),
            )
        }
    };
    let cves = match store.list_recent(50).await {
        Ok(cves) => cves,
        Err(err) => {
            return web_error_page(
                "Vulnerability Intelligence",
                "/cves/",
                &context,
                &err.to_string(),
            )
        }
    };
    let assessment_summary = match store.assessment_dashboard_summary(context.tenant_id).await {
        Ok(summary) => summary,
        Err(err) => {
            return web_error_page(
                "Vulnerability Intelligence",
                "/cves/",
                &context,
                &err.to_string(),
            )
        }
    };
    let assessments = match store.list_assessments(context.tenant_id, 20).await {
        Ok(items) => items,
        Err(err) => {
            return web_error_page(
                "Vulnerability Intelligence",
                "/cves/",
                &context,
                &err.to_string(),
            )
        }
    };
    let form_options = if can_write {
        match store.assessment_form_options(context.tenant_id).await {
            Ok(options) => Some(options),
            Err(err) => {
                return web_error_page(
                    "Vulnerability Intelligence",
                    "/cves/",
                    &context,
                    &err.to_string(),
                )
            }
        }
    } else {
        None
    };
    let rows = cves
        .iter()
        .map(|cve| {
            format!(
                r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                html_escape(&cve.cve_id),
                html_escape(&cve.severity_label),
                html_escape(cve.cvss_score.as_deref().unwrap_or("-")),
                html_escape(cve.epss_score.as_deref().unwrap_or("-")),
                yes_no(cve.in_kev_catalog),
                html_escape(cve.published_at.as_deref().unwrap_or("-")),
                html_escape(&cve.description),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let assessment_rows = assessments
        .iter()
        .map(|assessment| {
            let mut flags = Vec::new();
            if assessment.in_kev_catalog {
                flags.push("KEV");
            }
            if assessment.nis2_relevant {
                flags.push("NIS2");
            }
            let flags_display = if flags.is_empty() {
                "-".to_string()
            } else {
                flags.join(", ")
            };
            format!(
                r#"<tr><td><strong>{}</strong><div class="muted">{}</div></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><a href="{}">Oeffnen</a></td></tr>"#,
                html_escape(&assessment.cve_id),
                html_escape(&assessment.cve_description),
                html_escape(assessment.product_name.as_deref().unwrap_or("-")),
                html_escape(&assessment.deterministic_priority),
                html_escape(&assessment.llm_status_label),
                html_escape(&flags_display),
                html_escape(assessment.related_risk_title.as_deref().unwrap_or("-")),
                web_path_with_context(
                    &format!("/cves/assessments/{}", assessment.id),
                    Some(&context),
                ),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let body = format!(
        r#"
        <section class="hero compact"><h1>Vulnerability Intelligence</h1><p>Globaler CVE-Feed plus tenantgebundene Assessments direkt aus Rust. Tenant {} ist aktuell aktiv.</p></section>
        <section class="metrics">
          {}
          {}
          {}
          {}
          {}
          {}
          {}
          {}
        </section>
        <section class="grid">
          {}
          {}
          {}
          {}
          {}
          <article class="panel wide">
            <h2>Letzte Assessments</h2>
            <table>
              <thead><tr><th>CVE</th><th>Produkt</th><th>Prioritaet</th><th>LLM</th><th>Flags</th><th>Risiko</th><th>Detail</th></tr></thead>
              <tbody>{}</tbody>
            </table>
          </article>
          <article class="panel wide">
            <h2>Letzte CVEs</h2>
            <table>
              <thead><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Publiziert</th><th>Beschreibung</th></tr></thead>
              <tbody>{}</tbody>
            </table>
          </article>
        </section>
        "#,
        context.tenant_id,
        metric_card("Records", summary.total),
        metric_card("Kritisch", summary.critical),
        metric_card("KEV", summary.kev),
        metric_card("Mit EPSS", summary.with_epss),
        metric_card("Assessments", assessment_summary.total),
        metric_card("Mit Risiko", assessment_summary.with_risk),
        metric_card("LLM", assessment_summary.llm_generated),
        metric_card(
            "Hotspot",
            assessment_summary.risk_hotspot_score.round() as i64
        ),
        web_link_card(
            "JSON Feed",
            &web_path_with_context("/api/v1/cves", Some(&context)),
            "API fuer Summary und aktuelle CVEs",
        ),
        web_link_card(
            "Assessments API",
            &web_path_with_context("/api/v1/cve-assessments", Some(&context)),
            "Tenantgebundene CVE-Assessments als JSON",
        ),
        web_link_card(
            "LLM Runtime testen",
            &web_path_with_context("/cves/llm-test/", Some(&context)),
            "Lokalen Rust-LLM-Test direkt aus der Web-Shell starten",
        ),
        web_link_card(
            "Product Security",
            &web_path_with_context("/product-security/", Some(&context)),
            "Verknuepfte Produkt- und Vulnerability-Perspektive",
        ),
        web_cve_assessment_form_panel(&context, form_options.as_ref(), can_write),
        if assessment_rows.is_empty() {
            web_empty_row(7, "Noch keine tenantgebundenen CVE-Assessments vorhanden.")
        } else {
            assessment_rows
        },
        if rows.is_empty() {
            web_empty_row(7, "Keine CVE-Records vorhanden.")
        } else {
            rows
        },
    );
    web_page(
        "Vulnerability Intelligence",
        "/cves/",
        Some(&context),
        &body,
    )
}

async fn web_cves_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<WebCveAssessmentForm>,
) -> Response {
    let auth_context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(_) => {
            return web_missing_context("Vulnerability Intelligence", "/cves/").into_response()
        }
    };
    let context = WebContext {
        tenant_id: auth_context.tenant_id,
        user_id: auth_context.user_id,
        user_email: auth_context.user_email.clone(),
    };
    if !auth_context.can_write() {
        return web_error_page(
            "Vulnerability Intelligence",
            "/cves/",
            &context,
            "Diese Rust-Webroute benoetigt eine schreibende ISCY-Rolle.",
        )
        .into_response();
    }
    let Some(store) = state.cve_store else {
        return web_store_missing("Vulnerability Intelligence", "/cves/", &context, "CVE")
            .into_response();
    };
    let request = match web_cve_assessment_form_request(form) {
        Ok(request) => request,
        Err(message) => {
            return web_error_page("Vulnerability Intelligence", "/cves/", &context, &message)
                .into_response()
        }
    };
    match store
        .upsert_assessment(auth_context.tenant_id, request)
        .await
    {
        Ok(result) => Redirect::to(&web_path_with_context(
            &format!("/cves/{}/", result.assessment.summary.id),
            Some(&context),
        ))
        .into_response(),
        Err(err) => web_error_page(
            "Vulnerability Intelligence",
            "/cves/",
            &context,
            &err.to_string(),
        )
        .into_response(),
    }
}

fn web_cve_llm_test_page(
    context: &WebContext,
    runtime: &LlmRuntimeInfo,
    prompt: &str,
    output: Option<&str>,
) -> Html<String> {
    let output_panel = output
        .map(|output| {
            format!(
                r#"<article class="panel wide"><h2>Testausgabe</h2><pre>{}</pre></article>"#,
                html_escape(output),
            )
        })
        .unwrap_or_default();
    let body = format!(
        r#"
        <section class="hero compact"><h1>LLM-Runtime-Test</h1><p>Rust-only Runtimecheck fuer Tenant {}</p></section>
        <section class="grid">
          <article class="panel wide">
            <h2>Runtime</h2>
            <table>
              <tbody>
                <tr><th>Status</th><td>{}</td></tr>
                <tr><th>Backend</th><td>{}</td></tr>
                <tr><th>Modell</th><td>{}</td></tr>
                <tr><th>Pfad</th><td>{}</td></tr>
                <tr><th>Import</th><td>{}</td></tr>
                <tr><th>Kontext</th><td>{} · Threads {} · GPU-Layers {}</td></tr>
                <tr><th>Hinweis</th><td>{}</td></tr>
              </tbody>
            </table>
          </article>
          <article class="panel wide">
            <h2>Kleinen Prompt testen</h2>
            <form method="post" action="{}">
              <label>Test-Prompt<textarea name="prompt" rows="6" spellcheck="false">{}</textarea></label>
              <button type="submit">Runtime testen</button>
            </form>
          </article>
          {}
        </section>
        "#,
        context.tenant_id,
        if runtime.runtime_ok {
            "bereit"
        } else {
            "nicht bereit"
        },
        html_escape(runtime.backend),
        html_escape(&runtime.model_name),
        html_escape(runtime.model_path.as_deref().unwrap_or("nicht gesetzt")),
        yes_no(runtime.import_ok),
        runtime.n_ctx,
        runtime.n_threads,
        runtime.n_gpu_layers,
        html_escape(&runtime.note),
        web_path_with_context("/cves/llm-test/", Some(context)),
        html_escape(prompt),
        output_panel,
    );
    web_page("LLM-Runtime-Test", "/cves/llm-test/", Some(context), &body)
}

async fn web_cve_llm_test(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
        return web_missing_context("LLM-Runtime-Test", "/cves/llm-test/");
    };
    let runtime = llm_runtime_info();
    web_cve_llm_test_page(&context, &runtime, llm_test_default_prompt(), None)
}

async fn web_cve_llm_test_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
    Form(form): Form<WebCveLlmTestForm>,
) -> Html<String> {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
        return web_missing_context("LLM-Runtime-Test", "/cves/llm-test/");
    };
    let runtime = llm_runtime_info();
    let prompt = form
        .prompt
        .unwrap_or_else(|| llm_test_default_prompt().to_string());
    let output = serde_json::to_string_pretty(&llm_generate_result(&prompt, 256).result)
        .unwrap_or_else(|_| "{\"status\":\"error\"}".to_string());
    web_cve_llm_test_page(&context, &runtime, &prompt, Some(&output))
}

async fn web_cve_assessment_detail(
    Path(assessment_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebContextQuery>,
) -> Html<String> {
    let Some(context) = web_context_from_request(&query, &headers, &state).await else {
        return web_missing_context("CVE Assessment", "/cves/");
    };
    let Some(store) = state.cve_store else {
        return web_store_missing("CVE Assessment", "/cves/", &context, "CVE");
    };
    match store
        .assessment_detail(context.tenant_id, assessment_id)
        .await
    {
        Ok(Some(assessment)) => {
            let actions = if assessment.recommended_actions.is_empty() {
                "<li>Keine LLM-Massnahmen vorhanden.</li>".to_string()
            } else {
                assessment
                    .recommended_actions
                    .iter()
                    .map(|item| format!(r#"<li>{}</li>"#, html_escape(item)))
                    .collect::<Vec<_>>()
                    .join("")
            };
            let evidence = if assessment.evidence_needed.is_empty() {
                "<li>Keine spezifischen Evidenzen vorgeschlagen.</li>".to_string()
            } else {
                assessment
                    .evidence_needed
                    .iter()
                    .map(|item| format!(r#"<li>{}</li>"#, html_escape(item)))
                    .collect::<Vec<_>>()
                    .join("")
            };
            let repository_display = if assessment.repository_name.trim().is_empty() {
                "-".to_string()
            } else {
                assessment.repository_name.clone()
            };
            let git_ref_display = if assessment.git_ref.trim().is_empty() {
                "-".to_string()
            } else {
                assessment.git_ref.clone()
            };
            let package_display = if assessment.source_package.trim().is_empty() {
                "-".to_string()
            } else if assessment.source_package_version.trim().is_empty() {
                assessment.source_package.clone()
            } else {
                format!(
                    "{} {}",
                    assessment.source_package, assessment.source_package_version
                )
            };
            let body = format!(
                r#"
                <section class="hero compact"><h1>{}</h1><p>{}</p></section>
                <section class="grid">
                  <article class="panel wide">
                    <h2>Kontext & Deterministik</h2>
                    <table>
                      <tbody>
                        <tr><th>Produkt</th><td>{}</td></tr>
                        <tr><th>Release</th><td>{}</td></tr>
                        <tr><th>Komponente</th><td>{}</td></tr>
                        <tr><th>Exponierung</th><td>{}</td></tr>
                        <tr><th>Kritikalitaet</th><td>{}</td></tr>
                        <tr><th>EPSS</th><td>{}</td></tr>
                        <tr><th>KEV</th><td>{}</td></tr>
                        <tr><th>Exploit-Reife</th><td>{}</td></tr>
                        <tr><th>NIS2</th><td>{}</td></tr>
                        <tr><th>Prioritaet</th><td>{}</td></tr>
                        <tr><th>Frist</th><td>{} Tage</td></tr>
                        <tr><th>Risiko</th><td>{}</td></tr>
                        <tr><th>Schwachstelle</th><td>{}</td></tr>
                        <tr><th>Repository</th><td>{}</td></tr>
                        <tr><th>Git-Ref</th><td>{}</td></tr>
                        <tr><th>Paket</th><td>{}</td></tr>
                        <tr><th>Confidence</th><td>{}</td></tr>
                      </tbody>
                    </table>
                  </article>
                  <article class="panel wide">
                    <h2>Technische Zusammenfassung</h2>
                    <p>{}</p>
                    <h3>Business Impact</h3>
                    <p>{}</p>
                    <h3>Angriffsweg</h3>
                    <p>{}</p>
                    <h3>Management Summary</h3>
                    <p>{}</p>
                  </article>
                  <article class="panel wide">
                    <h2>Empfohlene Massnahmen</h2>
                    <ul>{}</ul>
                  </article>
                  <article class="panel wide">
                    <h2>Benoetigte Evidenzen</h2>
                    <ul>{}</ul>
                  </article>
                </section>
                "#,
                html_escape(&assessment.summary.cve_id),
                html_escape(&assessment.summary.cve_description),
                html_escape(assessment.summary.product_name.as_deref().unwrap_or("-")),
                html_escape(assessment.summary.release_version.as_deref().unwrap_or("-")),
                html_escape(assessment.summary.component_name.as_deref().unwrap_or("-")),
                html_escape(&assessment.summary.exposure_label),
                html_escape(&assessment.summary.asset_criticality_label),
                html_escape(assessment.summary.epss_score.as_deref().unwrap_or("-")),
                yes_no(assessment.summary.in_kev_catalog),
                html_escape(&assessment.summary.exploit_maturity_label),
                yes_no(assessment.summary.nis2_relevant),
                html_escape(&assessment.summary.deterministic_priority),
                assessment.summary.deterministic_due_days,
                html_escape(
                    assessment
                        .summary
                        .related_risk_title
                        .as_deref()
                        .unwrap_or("-")
                ),
                html_escape(
                    assessment
                        .summary
                        .linked_vulnerability_title
                        .as_deref()
                        .unwrap_or("-"),
                ),
                html_escape(&repository_display),
                html_escape(&git_ref_display),
                html_escape(&package_display),
                html_escape(&assessment.summary.confidence),
                html_escape(if assessment.technical_summary.trim().is_empty() {
                    "Noch keine LLM-Zusammenfassung vorhanden."
                } else {
                    assessment.technical_summary.as_str()
                }),
                html_escape(if assessment.business_impact.trim().is_empty() {
                    "-"
                } else {
                    assessment.business_impact.as_str()
                }),
                html_escape(if assessment.attack_path.trim().is_empty() {
                    "-"
                } else {
                    assessment.attack_path.as_str()
                }),
                html_escape(if assessment.management_summary.trim().is_empty() {
                    "-"
                } else {
                    assessment.management_summary.as_str()
                }),
                actions,
                evidence,
            );
            web_page("CVE Assessment", "/cves/", Some(&context), &body)
        }
        Ok(None) => web_error_page(
            "CVE Assessment",
            "/cves/",
            &context,
            "Assessment wurde nicht gefunden.",
        ),
        Err(err) => web_error_page("CVE Assessment", "/cves/", &context, &err.to_string()),
    }
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
                <tr><td>suppliers</td><td>name, service_description, criticality, contact_email, contract_reference, data_categories, regions, exit_dependency, regulatory_scope, review_status, next_review_due_at, evidence_required</td><td>CSV, XLSX, XLSM</td></tr>
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

async fn ai_governance_product_options(state: &AppState, tenant_id: i64) -> String {
    let Some(store) = state.product_security_store.as_ref() else {
        return String::new();
    };
    match store.overview(tenant_id, 200, 5).await {
        Ok(Some(overview)) => overview
            .products
            .iter()
            .map(|product| {
                format!(
                    r#"<option value="{}">{} · {}</option>"#,
                    product.id,
                    html_escape(&product.code),
                    html_escape(&product.name),
                )
            })
            .collect::<Vec<_>>()
            .join(""),
        Ok(None) | Err(_) => String::new(),
    }
}

fn ai_governance_system_panel(
    context: &WebContext,
    system: &ai_governance_store::AiGovernanceSystemSummary,
    can_write: bool,
) -> String {
    let requirement_rows = ai_governance_store::ai_governance_requirements(system)
        .iter()
        .map(|requirement| {
            format!(
                r#"<tr><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                html_escape(&requirement.label),
                web_badge(
                    &requirement.status_label,
                    ai_governance_requirement_class(&requirement.status),
                ),
                html_escape(&requirement.detail),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let evidence_href = evidence_prefill_href(
        context,
        &format!("AI-Governance Evidence: {}", system.name),
        &format!(
            "Nachweis fuer AI-Governance-System {}. Evidence-Key: {}.",
            system.name, system.evidence_key
        ),
        &system.evidence_key,
        Some("SUBMITTED"),
        Some(&web_path_with_context("/ai-governance/", Some(context))),
    );
    let form = if can_write {
        format!(
            r#"<form method="post" action="{}">
              <div class="form-grid">
                <label>AI-Act-Klasse<select name="ai_act_classification">{}</select></label>
                <label>Kritikalitaet<select name="criticality">{}</select></label>
                <label>Status<select name="status">{}</select></label>
                <label>Naechster Review<input name="next_review_due_at" type="date" value="{}"></label>
              </div>
              <label>Human Oversight<textarea name="human_oversight" rows="2">{}</textarea></label>
              <label>Monitoringplan<textarea name="monitoring_plan" rows="2">{}</textarea></label>
              <label>Evidence-Key<input name="evidence_key" value="{}"></label>
              <label>Risikosummary<textarea name="risk_summary" rows="2">{}</textarea></label>
              <label>Notizen<textarea name="notes" rows="2">{}</textarea></label>
              <button type="submit">Review speichern</button>
            </form>"#,
            web_path_with_context(
                &format!("/ai-governance/systems/{}", system.id),
                Some(context),
            ),
            ai_governance_classification_options(&system.ai_act_classification),
            ai_governance_criticality_options(&system.criticality),
            ai_governance_status_options(&system.status),
            html_escape(ai_governance_date_value(
                system.next_review_due_at.as_deref()
            )),
            html_escape(&system.human_oversight),
            html_escape(&system.monitoring_plan),
            html_escape(&system.evidence_key),
            html_escape(&system.risk_summary),
            html_escape(&system.notes),
        )
    } else {
        String::new()
    };
    format!(
        r#"<article id="ai-system-{}" class="panel wide">
          <h2>{}</h2>
          <table>
            <tbody>
              <tr><th>Produkt</th><td>{}</td><th>Owner</th><td>{}</td></tr>
              <tr><th>Modell</th><td>{} {}</td><th>Provider</th><td>{}</td></tr>
              <tr><th>Zweck</th><td colspan="3">{}</td></tr>
              <tr><th>Daten</th><td>{}</td><th>Impact</th><td>{}</td></tr>
              <tr><th>Evidence</th><td><a href="{}">{} Nachweis(e)</a></td><th>Freigegeben</th><td>{}</td></tr>
            </tbody>
          </table>
          <h3>Governance-Anforderungen</h3>
          <table>
            <thead><tr><th>Anforderung</th><th>Status</th><th>Detail</th></tr></thead>
            <tbody>{}</tbody>
          </table>
          {}
        </article>"#,
        system.id,
        html_escape(&system.name),
        html_escape(system.product_name.as_deref().unwrap_or("-")),
        html_escape(system.owner_display.as_deref().unwrap_or("-")),
        html_escape(&system.model_name),
        html_escape(&system.model_version),
        html_escape(&system.model_provider),
        html_escape(&system.purpose),
        html_escape(&system.data_categories),
        html_escape(&system.decision_impact),
        evidence_href,
        system.evidence_count,
        system.approved_evidence_count,
        if requirement_rows.is_empty() {
            web_empty_row(3, "Keine Governance-Anforderungen berechnet.")
        } else {
            requirement_rows
        },
        form,
    )
}

fn ai_governance_create_payload_from_form(
    form: WebAiGovernanceCreateForm,
) -> ai_governance_store::AiGovernanceSystemCreateRequest {
    ai_governance_store::AiGovernanceSystemCreateRequest {
        product_id: form.product_id.filter(|id| *id > 0),
        owner_id: None,
        name: form.name,
        purpose: form.purpose,
        model_provider: form.model_provider,
        model_name: form.model_name,
        model_version: form.model_version,
        deployment_context: form.deployment_context,
        data_categories: form.data_categories,
        decision_impact: form.decision_impact,
        human_oversight: form.human_oversight,
        ai_act_classification: Some(form.ai_act_classification),
        criticality: Some(form.criticality),
        status: Some("IN_REVIEW".to_string()),
        logging_required: Some(true),
        transparency_required: Some(true),
        cybersecurity_required: Some(true),
        monitoring_plan: form.monitoring_plan,
        evidence_key: Some(form.evidence_key),
        risk_summary: form.risk_summary,
        next_review_due_at: Some(form.next_review_due_at),
        notes: form.notes,
    }
}

fn ai_governance_update_payload_from_form(
    form: WebAiGovernanceUpdateForm,
) -> ai_governance_store::AiGovernanceSystemUpdateRequest {
    ai_governance_store::AiGovernanceSystemUpdateRequest {
        product_id: None,
        owner_id: None,
        name: None,
        purpose: None,
        model_provider: None,
        model_name: None,
        model_version: None,
        deployment_context: None,
        data_categories: None,
        decision_impact: None,
        human_oversight: Some(form.human_oversight),
        ai_act_classification: Some(form.ai_act_classification),
        criticality: Some(form.criticality),
        status: Some(form.status),
        logging_required: None,
        transparency_required: None,
        cybersecurity_required: None,
        monitoring_plan: Some(form.monitoring_plan),
        evidence_key: Some(form.evidence_key),
        risk_summary: Some(form.risk_summary),
        next_review_due_at: Some(form.next_review_due_at),
        notes: Some(form.notes),
    }
}

fn ai_governance_classification_options(selected: &str) -> String {
    [
        ("NOT_ASSESSED", "Nicht bewertet"),
        ("HIGH_RISK", "High Risk"),
        ("LIMITED_RISK", "Limited Risk"),
        ("MINIMAL_RISK", "Minimal Risk"),
        ("NOT_IN_SCOPE", "Nicht im Scope"),
        ("PROHIBITED", "Verboten / nicht freigegeben"),
    ]
    .iter()
    .map(|(value, label)| option_tag(value, label, selected))
    .collect::<Vec<_>>()
    .join("")
}

fn ai_governance_criticality_options(selected: &str) -> String {
    [
        ("CRITICAL", "Kritisch"),
        ("HIGH", "Hoch"),
        ("MEDIUM", "Mittel"),
        ("LOW", "Niedrig"),
    ]
    .iter()
    .map(|(value, label)| option_tag(value, label, selected))
    .collect::<Vec<_>>()
    .join("")
}

fn ai_governance_status_options(selected: &str) -> String {
    [
        ("DRAFT", "Entwurf"),
        ("IN_REVIEW", "In Review"),
        ("APPROVED", "Freigegeben"),
        ("RETIRED", "Stillgelegt"),
    ]
    .iter()
    .map(|(value, label)| option_tag(value, label, selected))
    .collect::<Vec<_>>()
    .join("")
}

fn option_tag(value: &str, label: &str, selected: &str) -> String {
    let selected_attr = if value.eq_ignore_ascii_case(selected) {
        " selected"
    } else {
        ""
    };
    format!(
        r#"<option value="{}"{}>{}</option>"#,
        html_escape(value),
        selected_attr,
        html_escape(label),
    )
}

fn ai_governance_classification_class(value: &str) -> &'static str {
    match value {
        "PROHIBITED" | "HIGH_RISK" => "danger-badge",
        "NOT_ASSESSED" => "warning-badge",
        "LIMITED_RISK" => "info-badge",
        "NOT_IN_SCOPE" => "muted-badge",
        _ => "ok-badge",
    }
}

fn ai_governance_status_class(value: &str) -> &'static str {
    match value {
        "APPROVED" => "ok-badge",
        "RETIRED" => "muted-badge",
        "DRAFT" => "warning-badge",
        _ => "info-badge",
    }
}

fn ai_governance_requirement_class(value: &str) -> &'static str {
    match value {
        "OK" => "ok-badge",
        "WATCH" => "warning-badge",
        _ => "danger-badge",
    }
}

fn ai_governance_date_value(value: Option<&str>) -> &str {
    value.and_then(|value| value.get(..10)).unwrap_or("")
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
        ("/status/", "Status"),
        ("/navigator/", "Navigator"),
        ("/controls/", "ISCY-27"),
        ("/zero-trust/", "Zero Trust"),
        ("/incidents/", "Incidents"),
        ("/cves/", "CVEs"),
        ("/risks/", "Risks"),
        ("/evidence/", "Evidence"),
        ("/roadmap/", "Roadmap"),
        ("/reports/", "Reports"),
        ("/management-reviews/", "Reviews"),
        ("/assets/", "Assets"),
        ("/suppliers/", "Suppliers"),
        ("/imports/", "Imports"),
        ("/processes/", "Processes"),
        ("/ai-governance/", "AI Governance"),
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
    :root {{ color-scheme: light; --ink:#17202a; --muted:#5b6776; --line:#d8dee6; --bg:#f6f8fb; --panel:#ffffff; --soft:#eef4f7; --accent:#0f766e; --accent-weak:#e6f4f1; --success:#047857; --warn:#b45309; --danger:#b42318; --info:#1d4ed8; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; font-family:Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color:var(--ink); background:var(--bg); }}
    header {{ display:grid; grid-template-columns:auto minmax(0,1fr) auto; align-items:center; gap:12px; padding:12px 20px; background:rgba(255,255,255,.96); border-bottom:1px solid var(--line); box-shadow:0 1px 2px rgba(20,30,40,.04); position:sticky; top:0; z-index:1; backdrop-filter:saturate(180%) blur(10px); }}
    .brand {{ font-weight:800; letter-spacing:0; color:var(--ink); text-decoration:none; }}
    nav {{ display:flex; flex-wrap:wrap; gap:4px; min-width:0; overflow:visible; font-size:14px; scrollbar-width:none; }}
    nav::-webkit-scrollbar {{ display:none; }}
    nav a, .context a {{ flex:0 0 auto; color:var(--ink); text-decoration:none; white-space:nowrap; padding:7px 8px; border-radius:6px; border:1px solid transparent; }}
    nav a.active, nav a:hover, .context a:hover {{ border-color:#b8d8d0; background:var(--accent-weak); }}
    .context {{ display:flex; flex-wrap:wrap; justify-content:flex-end; gap:6px; font-size:13px; color:var(--muted); }}
    .context span {{ padding:7px 9px; border:1px solid var(--line); border-radius:6px; background:#fff; }}
    main {{ width:min(1180px, 100%); margin:0 auto; padding:28px 20px 44px; }}
    .hero {{ padding:28px 0 20px; margin-bottom:18px; border-bottom:1px solid var(--line); }}
    .hero.compact {{ padding:12px 0 18px; }}
    h1 {{ margin:0 0 8px; font-size:40px; line-height:1.1; }}
    h2 {{ margin:0 0 10px; font-size:20px; }}
    h3 {{ margin:0; font-size:17px; }}
    p {{ margin:0 0 8px; color:var(--muted); overflow-wrap:anywhere; }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(230px, 1fr)); gap:14px; }}
    .metrics {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(160px, 1fr)); gap:12px; margin-bottom:16px; }}
    .incident-flow {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(190px, 1fr)); gap:12px; margin:0 0 16px; }}
    .flow-step {{ display:grid; grid-template-columns:auto minmax(0, 1fr); gap:4px 10px; align-items:start; min-height:116px; padding:14px; color:var(--ink); text-decoration:none; background:#fff; border:1px solid var(--line); border-radius:8px; box-shadow:0 1px 2px rgba(20,30,40,.04); }}
    .flow-step:hover {{ border-color:#b8d8d0; box-shadow:0 8px 22px rgba(20,30,40,.08); }}
    .flow-step strong, .flow-step small {{ grid-column:2; overflow-wrap:anywhere; }}
    .flow-step strong {{ font-size:18px; line-height:1.2; }}
    .flow-step small {{ color:var(--muted); }}
    .flow-step .eyebrow {{ grid-column:2; }}
    .flow-index {{ grid-row:1 / span 3; display:grid; place-items:center; width:32px; height:32px; border-radius:999px; background:var(--soft); color:var(--ink); font-weight:900; }}
    .flow-step.ok {{ border-color:#abefc6; background:#f6fef9; }}
    .flow-step.warn {{ border-color:#fedf89; background:#fffcf2; }}
    .flow-step.info {{ border-color:#bfdbfe; background:#f8fbff; }}
    .flow-step.danger {{ border-color:#fecdca; background:#fff8f7; }}
    .flow-step.muted-badge {{ background:#fff; }}
    .panel {{ background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:18px; box-shadow:0 1px 2px rgba(20, 30, 40, 0.04); }}
    .panel.wide {{ grid-column:1 / -1; overflow-x:auto; }}
    .panel.error {{ border-color:#fed7aa; background:#fff7ed; }}
    .wide-anchor {{ grid-column:1 / -1; }}
    .form-panel {{ max-width:520px; }}
    .card-link {{ display:block; min-height:120px; color:var(--ink); text-decoration:none; }}
    .card-link:hover {{ border-color:#b8d8d0; box-shadow:0 8px 22px rgba(20,30,40,.08); }}
    .metric {{ min-height:96px; }}
    .metric span, .eyebrow {{ display:block; color:var(--muted); font-size:12px; font-weight:700; text-transform:uppercase; }}
    .metric strong {{ display:block; font-size:30px; line-height:1.05; margin-top:8px; }}
    .filter-links {{ display:flex; flex-wrap:wrap; gap:8px; margin:0 0 12px; }}
    .filter-links a {{ color:var(--ink); text-decoration:none; white-space:nowrap; padding:7px 10px; border:1px solid var(--line); border-radius:999px; background:#fff; font-size:13px; font-weight:700; }}
    .filter-links a.active, .filter-links a:hover {{ color:var(--accent); border-color:#b8d8d0; background:var(--accent-weak); }}
    .zt-focus {{ display:grid; grid-template-columns:minmax(190px,260px) minmax(0,1fr); gap:14px; margin-bottom:16px; }}
    .zt-score {{ display:grid; align-content:start; gap:10px; min-height:138px; }}
    .zt-score strong {{ font-size:52px; line-height:1; }}
    .zt-priority h2 {{ font-size:22px; margin-bottom:8px; }}
    .score-ok {{ color:var(--success); }}
    .score-warn {{ color:var(--warn); }}
    .score-danger {{ color:var(--danger); }}
    .muted {{ color:var(--muted); }}
    table {{ width:100%; min-width:720px; border-collapse:collapse; }}
    th, td {{ padding:10px 8px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; overflow-wrap:anywhere; }}
    th {{ color:var(--muted); font-size:12px; text-transform:uppercase; }}
    td a {{ color:var(--accent); text-decoration:none; }}
    pre {{ white-space:pre-wrap; overflow-wrap:anywhere; }}
    .badge {{ display:inline-flex; align-items:center; min-height:24px; padding:3px 8px; border-radius:999px; border:1px solid transparent; background:var(--soft); color:var(--ink); font-size:12px; font-weight:800; line-height:1.2; white-space:nowrap; }}
    .badge.ok {{ color:var(--success); background:#ecfdf3; border-color:#abefc6; }}
    .badge.warn {{ color:var(--warn); background:#fffaeb; border-color:#fedf89; }}
    .badge.high {{ color:#c2410c; background:#fff7ed; border-color:#fed7aa; }}
    .badge.danger {{ color:var(--danger); background:#fef3f2; border-color:#fecdca; }}
    .badge.info {{ color:var(--info); background:#eff6ff; border-color:#bfdbfe; }}
    .badge.muted-badge {{ color:var(--muted); background:#f8fafc; border-color:var(--line); }}
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
    button:hover {{ background:#0b5f58; }}
    a:focus-visible, button:focus-visible, input:focus-visible, select:focus-visible, textarea:focus-visible {{ outline:3px solid #99f6e4; outline-offset:2px; }}
    @media (max-width: 720px) {{ header {{ grid-template-columns:1fr; align-items:start; padding:12px 16px; }} nav {{ width:100%; flex-wrap:nowrap; overflow-x:auto; padding-bottom:2px; }} h1 {{ font-size:32px; }} .context {{ justify-content:flex-start; }} .zt-focus {{ grid-template-columns:1fr; }} main {{ padding:22px 14px 36px; }} }}
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

fn metric_link_card(label: &str, value: i64, href: &str) -> String {
    format!(
        r#"<a class="panel metric" href="{}"><span>{}</span><strong>{}</strong></a>"#,
        html_escape(href),
        html_escape(label),
        value,
    )
}

fn ratio_percent(part: i64, total: i64) -> i64 {
    if total <= 0 {
        0
    } else {
        ((part as f64 / total as f64) * 100.0).round() as i64
    }
}

fn signal_badge(ok: bool) -> String {
    if ok {
        web_badge("stabil", "ok")
    } else {
        web_badge("handeln", "warn")
    }
}

fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn env_value_or(name: &str, fallback: &str) -> String {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

enum MigrationStatusView {
    Ready(db_admin::DbMigrationStatus),
    Missing,
    Error(String),
}

fn migration_status_view(status: &MigrationStatusView) -> (i64, String) {
    match status {
        MigrationStatusView::Ready(status) => {
            let complete = status.applied_count >= status.expected_count as i64;
            (
                status.applied_count,
                [
                    status_row("Datenbank", web_badge(status.database_kind, "info"), ""),
                    status_row(
                        "Migrationen",
                        signal_badge(complete),
                        &format!(
                            "{}/{} angewendet",
                            status.applied_count, status.expected_count
                        ),
                    ),
                    status_row(
                        "Letzte angewendet",
                        signal_badge(
                            status.latest_applied_version.as_deref()
                                == status.expected_latest_version,
                        ),
                        status
                            .latest_applied_version
                            .as_deref()
                            .unwrap_or("keine Migration registriert"),
                    ),
                    status_row(
                        "Soll-Version",
                        web_badge("erwartet", "info"),
                        status.expected_latest_version.unwrap_or("unbekannt"),
                    ),
                    status_row(
                        "Angewendet am",
                        web_badge("Info", "muted-badge"),
                        status.latest_applied_at.as_deref().unwrap_or("-"),
                    ),
                ]
                .join(""),
            )
        }
        MigrationStatusView::Missing => (
            0,
            status_row(
                "Datenbank",
                web_badge("nicht konfiguriert", "warn"),
                "DATABASE_URL ist im AppState nicht gesetzt.",
            ),
        ),
        MigrationStatusView::Error(message) => (
            0,
            status_row("Datenbank", web_badge("nicht lesbar", "danger"), message),
        ),
    }
}

fn build_status_rows() -> String {
    [
        status_pair_row("Version", env!("CARGO_PKG_VERSION")),
        status_pair_row("Commit", &build_commit()),
        status_pair_row("Profil", option_env!("PROFILE").unwrap_or("unknown")),
        status_pair_row("Ziel", option_env!("TARGET").unwrap_or("unknown")),
    ]
    .join("")
}

fn build_commit() -> String {
    std::env::var("ISCY_BUILD_COMMIT")
        .or_else(|_| std::env::var("GIT_COMMIT"))
        .or_else(|_| std::env::var("GITHUB_SHA"))
        .ok()
        .or_else(|| option_env!("ISCY_BUILD_COMMIT").map(ToString::to_string))
        .or_else(|| option_env!("GIT_COMMIT").map(ToString::to_string))
        .or_else(|| option_env!("GITHUB_SHA").map(ToString::to_string))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(12).collect::<String>())
        .unwrap_or_else(|| "unknown".to_string())
}

fn status_row(signal: &str, status: String, detail: &str) -> String {
    format!(
        r#"<tr><td>{}</td><td>{}</td><td>{}</td></tr>"#,
        html_escape(signal),
        status,
        html_escape(detail),
    )
}

fn status_pair_row(signal: &str, value: &str) -> String {
    format!(
        r#"<tr><td>{}</td><td>{}</td></tr>"#,
        html_escape(signal),
        html_escape(value),
    )
}

fn status_store_statuses(state: &AppState) -> Vec<StatusStoreStatus> {
    vec![
        StatusStoreStatus {
            name: "Auth & Sessions",
            configured: state.auth_store.is_some(),
            scope: "Login, RBAC, Rollen",
        },
        StatusStoreStatus {
            name: "Accounts",
            configured: state.account_store.is_some(),
            scope: "User- und Gruppenverwaltung",
        },
        StatusStoreStatus {
            name: "Dashboard",
            configured: state.dashboard_store.is_some(),
            scope: "Management-Uebersicht",
        },
        StatusStoreStatus {
            name: "ISCY-27",
            configured: state.control_store.is_some(),
            scope: "Control-Kern und Mappings",
        },
        StatusStoreStatus {
            name: "Product Security",
            configured: state.product_security_store.is_some(),
            scope: "CRA, SBOM, CSAF, CVE-Reviews",
        },
        StatusStoreStatus {
            name: "AI Governance",
            configured: state.ai_governance_store.is_some(),
            scope: "AI-Systemregister, AI-Act-Einstufung, Evidence",
        },
        StatusStoreStatus {
            name: "Risks",
            configured: state.risk_store.is_some(),
            scope: "Risiko-Register und Reviews",
        },
        StatusStoreStatus {
            name: "Evidence",
            configured: state.evidence_store.is_some(),
            scope: "Nachweise und Uploads",
        },
        StatusStoreStatus {
            name: "Incidents",
            configured: state.incident_store.is_some(),
            scope: "NIS2- und Runbook-Flows",
        },
        StatusStoreStatus {
            name: "Imports",
            configured: state.import_store.is_some(),
            scope: "CSV- und Datenimporte",
        },
        StatusStoreStatus {
            name: "Assets",
            configured: state.asset_store.is_some(),
            scope: "Asset- und CPE/PURL-Bezug",
        },
        StatusStoreStatus {
            name: "Suppliers",
            configured: state.supplier_store.is_some(),
            scope: "Third-Party Risk und Lieferkettennachweise",
        },
        StatusStoreStatus {
            name: "Roadmap",
            configured: state.roadmap_store.is_some(),
            scope: "Massnahmen und Tasks",
        },
        StatusStoreStatus {
            name: "Reports",
            configured: state.report_store.is_some(),
            scope: "Snapshots und Exporte",
        },
        StatusStoreStatus {
            name: "Agents",
            configured: state.agent_store.is_some(),
            scope: "Zero-Trust-Posture",
        },
    ]
}

async fn status_operations_overview(
    state: &AppState,
    context: Option<&WebContext>,
    migration_status: &MigrationStatusView,
    rust_only: bool,
    strict_mode: bool,
    configured_stores: i64,
    total_stores: i64,
) -> StatusOperationsOverview {
    let mut signals = vec![
        StatusSignal::new(
            "Health",
            "Live Health",
            StatusSignalLevel::Ok,
            "/health/live liefert Liveness fuer CI, Monitoring und lokalen Betrieb.",
            Some("/health/live".to_string()),
        ),
        StatusSignal::new(
            "Runtime",
            "Rust-only",
            if rust_only {
                StatusSignalLevel::Ok
            } else {
                StatusSignalLevel::Warn
            },
            if rust_only {
                "Rust-only-Modus ist aktiv."
            } else {
                "RUST_ONLY_MODE ist nicht gesetzt."
            },
            None,
        ),
        StatusSignal::new(
            "Runtime",
            "Strict Mode",
            if strict_mode {
                StatusSignalLevel::Ok
            } else {
                StatusSignalLevel::Warn
            },
            if strict_mode {
                "Strict Mode ist aktiv."
            } else {
                "RUST_STRICT_MODE ist nicht gesetzt."
            },
            None,
        ),
        StatusSignal::new(
            "Security",
            "App Mode",
            if state.security_config.app_mode.is_production() {
                StatusSignalLevel::Ok
            } else {
                StatusSignalLevel::Warn
            },
            format!(
                "ISCY_APP_MODE={} (development/demo sind nicht fuer oeffentlichen Produktivbetrieb gedacht).",
                state.security_config.mode_label()
            ),
            None,
        ),
        StatusSignal::new(
            "Security",
            "Identity-Header-Grenze",
            if state.security_config.trust_identity_headers {
                StatusSignalLevel::Warn
            } else {
                StatusSignalLevel::Ok
            },
            if state.security_config.trust_identity_headers {
                "x-iscy-* Identity-Header werden akzeptiert; nur hinter einem Header-saeubernden Reverse Proxy produktiv nutzen.".to_string()
            } else {
                "x-iscy-* Identity-Header sind deny-by-default blockiert.".to_string()
            },
            None,
        ),
        StatusSignal::new(
            "Security",
            "Session-Cookies",
            if state.security_config.secure_cookies {
                StatusSignalLevel::Ok
            } else {
                StatusSignalLevel::Warn
            },
            if state.security_config.secure_cookies {
                "Session-Cookies werden mit Secure, HttpOnly und SameSite=Lax gesetzt.".to_string()
            } else {
                "Session-Cookies sind fuer lokale HTTP-Entwicklung ohne Secure markiert.".to_string()
            },
            None,
        ),
        StatusSignal::new(
            "Migrationen",
            "Datenbank-Schema",
            migration_signal_level(migration_status),
            migration_signal_detail(migration_status),
            None,
        ),
        StatusSignal::new(
            "Module",
            "Kernmodule verbunden",
            if configured_stores >= total_stores {
                StatusSignalLevel::Ok
            } else {
                StatusSignalLevel::Warn
            },
            format!("{configured_stores}/{total_stores} Rust-Stores sind verbunden."),
            None,
        ),
    ];

    match context {
        Some(context) => {
            signals.extend(control_operation_signals(state, context).await);
            signals.extend(evidence_operation_signals(state, context).await);
            signals.extend(product_security_operation_signals(state, context).await);
            signals.extend(ai_governance_operation_signals(state, context).await);
        }
        None => {
            signals.push(StatusSignal::new(
                "ISCY-27",
                "Offene Control-Gaps",
                StatusSignalLevel::Warn,
                "Tenant-Kontext fehlt; Live-Gaps brauchen tenant_id und user_id.",
                Some("/controls/".to_string()),
            ));
            signals.push(StatusSignal::new(
                "Product Security",
                "Offene CVE-Reviews",
                StatusSignalLevel::Warn,
                "Tenant-Kontext fehlt; CVE-Reviews brauchen tenant_id und user_id.",
                Some("/product-security/".to_string()),
            ));
            signals.push(StatusSignal::new(
                "Evidence",
                "Evidence-Lifecycle",
                StatusSignalLevel::Warn,
                "Tenant-Kontext fehlt; Ablauf- und Retention-Signale brauchen tenant_id und user_id.",
                Some("/evidence/quality/".to_string()),
            ));
            signals.push(StatusSignal::new(
                "Product Security",
                "Evidence fehlt",
                StatusSignalLevel::Warn,
                "Tenant-Kontext fehlt; Evidence-Lage braucht tenant_id und user_id.",
                Some("/product-security/".to_string()),
            ));
            signals.push(StatusSignal::new(
                "AI Governance",
                "AI-Systeme nicht bewertet",
                StatusSignalLevel::Warn,
                "Tenant-Kontext fehlt; AI-Governance-Signale brauchen tenant_id und user_id.",
                Some("/ai-governance/".to_string()),
            ));
        }
    }

    let issue_count = signals
        .iter()
        .filter(|signal| signal.level.is_issue())
        .count() as i64;
    let severity = StatusOperationsSeverity::from_signals(&signals);
    StatusOperationsOverview {
        issue_count,
        severity,
        exit_code: severity.exit_code(),
        rows: status_signal_rows(&signals),
        signals,
    }
}

async fn evidence_operation_signals(state: &AppState, context: &WebContext) -> Vec<StatusSignal> {
    let href = Some(web_path_with_context("/evidence/quality/", Some(context)));
    let Some(store) = state.evidence_store.as_ref() else {
        return vec![StatusSignal::new(
            "Evidence",
            "Evidence-Lifecycle",
            StatusSignalLevel::Warn,
            "Evidence-Store ist nicht konfiguriert.",
            href,
        )];
    };
    match store
        .evidence_quality(context.tenant_id, None, 1000, 100)
        .await
    {
        Ok(quality) => vec![
            StatusSignal::new(
                "Evidence",
                "Evidence abgelaufen",
                if quality.summary.expired_items == 0 {
                    StatusSignalLevel::Ok
                } else {
                    StatusSignalLevel::Danger
                },
                format!(
                    "{} Nachweise sind abgelaufen.",
                    quality.summary.expired_items
                ),
                href.clone(),
            ),
            StatusSignal::new(
                "Evidence",
                "Evidence laeuft bald ab",
                if quality.summary.expiring_items == 0 {
                    StatusSignalLevel::Ok
                } else {
                    StatusSignalLevel::Warn
                },
                format!(
                    "{} Nachweise laufen innerhalb von 30 Tagen ab.",
                    quality.summary.expiring_items
                ),
                href.clone(),
            ),
            StatusSignal::new(
                "Evidence",
                "Retention dokumentiert",
                if quality.summary.retention_defined_items == quality.summary.total_items {
                    StatusSignalLevel::Ok
                } else {
                    StatusSignalLevel::Warn
                },
                format!(
                    "{}/{} Nachweise haben eine Aufbewahrungsfrist.",
                    quality.summary.retention_defined_items, quality.summary.total_items
                ),
                href,
            ),
            StatusSignal::new(
                "Evidence",
                "Retention-Pruefung faellig",
                if quality.summary.retention_due_items == 0 {
                    StatusSignalLevel::Ok
                } else {
                    StatusSignalLevel::Warn
                },
                format!(
                    "{} Nachweise haben das Aufbewahrungsdatum erreicht.",
                    quality.summary.retention_due_items
                ),
                Some(web_path_with_context("/evidence/quality/", Some(context))),
            ),
        ],
        Err(err) => vec![StatusSignal::new(
            "Evidence",
            "Evidence-Lifecycle",
            StatusSignalLevel::Warn,
            format!("Evidence-Lifecycle konnte nicht gelesen werden: {err}"),
            href,
        )],
    }
}

async fn control_operation_signals(state: &AppState, context: &WebContext) -> Vec<StatusSignal> {
    let Some(store) = state.control_store.as_ref() else {
        return vec![StatusSignal::new(
            "ISCY-27",
            "Offene Control-Gaps",
            StatusSignalLevel::Warn,
            "Control-Store ist nicht konfiguriert.",
            Some(web_path_with_context("/controls/", Some(context))),
        )];
    };
    match store.library(context.tenant_id).await {
        Ok(library) => {
            let partial_controls = library
                .controls
                .iter()
                .filter(|control| control.status.eq_ignore_ascii_case("PARTIAL"))
                .count() as i64;
            let evidence_missing = library
                .controls
                .iter()
                .filter(|control| control.evidence_status.eq_ignore_ascii_case("MISSING"))
                .count() as i64;
            let controls_needing_work = library.gap_controls + partial_controls;
            let open_gap_roadmap_tasks = library
                .controls
                .iter()
                .filter(|control| {
                    control.status.eq_ignore_ascii_case("GAP")
                        || control.status.eq_ignore_ascii_case("PARTIAL")
                })
                .map(|control| control.roadmap_open_task_count)
                .sum::<i64>();
            vec![
                StatusSignal::new(
                    "ISCY-27",
                    "Offene Control-Gaps",
                    if library.gap_controls == 0 {
                        StatusSignalLevel::Ok
                    } else {
                        StatusSignalLevel::Warn
                    },
                    format!(
                        "{} GAP, {} PARTIAL, Durchschnittsreife {:.1}/5.",
                        library.gap_controls, partial_controls, library.average_maturity
                    ),
                    Some(web_path_with_context("/controls/", Some(context))),
                ),
                StatusSignal::new(
                    "ISCY-27",
                    "Control-Evidence fehlt",
                    if evidence_missing == 0 {
                        StatusSignalLevel::Ok
                    } else {
                        StatusSignalLevel::Warn
                    },
                    format!(
                        "{evidence_missing}/{} Controls ohne ausreichende Evidence.",
                        library.total_controls
                    ),
                    Some(web_path_with_context("/evidence/", Some(context))),
                ),
                StatusSignal::new(
                    "Roadmap",
                    "Gap-Roadmap-Spur",
                    if controls_needing_work == 0 || open_gap_roadmap_tasks > 0 {
                        StatusSignalLevel::Ok
                    } else {
                        StatusSignalLevel::Warn
                    },
                    format!(
                        "{open_gap_roadmap_tasks} offene Roadmap-Tasks fuer {controls_needing_work} offene GAP/PARTIAL Controls."
                    ),
                    Some(web_path_with_context("/roadmap/", Some(context))),
                ),
            ]
        }
        Err(err) => vec![StatusSignal::new(
            "ISCY-27",
            "Offene Control-Gaps",
            StatusSignalLevel::Danger,
            format!("Control-Library konnte nicht gelesen werden: {err}"),
            Some(web_path_with_context("/controls/", Some(context))),
        )],
    }
}

async fn product_security_operation_signals(
    state: &AppState,
    context: &WebContext,
) -> Vec<StatusSignal> {
    let Some(store) = state.product_security_store.as_ref() else {
        return vec![
            StatusSignal::new(
                "Product Security",
                "Offene CVE-Reviews",
                StatusSignalLevel::Warn,
                "Product-Security-Store ist nicht konfiguriert.",
                Some(web_path_with_context("/product-security/", Some(context))),
            ),
            StatusSignal::new(
                "Product Security",
                "Evidence fehlt",
                StatusSignalLevel::Warn,
                "Product-Security-Store ist nicht konfiguriert.",
                Some(web_path_with_context("/product-security/", Some(context))),
            ),
        ];
    };
    match store.overview(context.tenant_id, 25, 10).await {
        Ok(Some(overview)) => {
            let risk_missing = overview
                .cve_risk_review_queue
                .iter()
                .filter(|item| item.risk_id.is_none())
                .count() as i64;
            let invalid_imports = overview
                .import_artifacts
                .iter()
                .filter(|artifact| artifact.validation_status.eq_ignore_ascii_case("INVALID"))
                .count() as i64;
            let total_components = overview
                .products
                .iter()
                .map(|product| product.component_count)
                .sum::<i64>();
            let sbom_components = overview
                .products
                .iter()
                .map(|product| product.sbom_component_count)
                .sum::<i64>();
            let sbom_coverage = ratio_percent(sbom_components, total_components);
            vec![
                StatusSignal::new(
                    "Product Security",
                    "Offene CVE-Reviews",
                    if overview.review_metrics.open_cve_reviews == 0 {
                        StatusSignalLevel::Ok
                    } else {
                        StatusSignalLevel::Warn
                    },
                    format!(
                        "{} offen, davon {} Korrelationen vorgeschlagen und {} ohne Risiko.",
                        overview.review_metrics.open_cve_reviews,
                        overview.review_metrics.suggested_correlation_reviews,
                        risk_missing
                    ),
                    Some(product_security_review_filter_path(context, "review_open")),
                ),
                StatusSignal::new(
                    "Product Security",
                    "Evidence fehlt",
                    if overview.review_metrics.evidence_missing == 0 {
                        StatusSignalLevel::Ok
                    } else {
                        StatusSignalLevel::Warn
                    },
                    format!(
                        "{} CVE-/Risiko-Reviews ohne verknuepfte Evidence.",
                        overview.review_metrics.evidence_missing
                    ),
                    Some(product_security_review_filter_path(
                        context,
                        "evidence_missing",
                    )),
                ),
                StatusSignal::new(
                    "Product Security",
                    "Kritische CVEs offen",
                    if overview.posture.critical_open_vulnerabilities == 0 {
                        StatusSignalLevel::Ok
                    } else {
                        StatusSignalLevel::Danger
                    },
                    format!(
                        "{} kritisch, {} Schwachstellen insgesamt offen.",
                        overview.posture.critical_open_vulnerabilities,
                        overview.posture.open_vulnerabilities
                    ),
                    Some(web_path_with_context("/product-security/", Some(context))),
                ),
                StatusSignal::new(
                    "Product Security",
                    "SBOM/CSAF Importlage",
                    if invalid_imports == 0 {
                        StatusSignalLevel::Ok
                    } else {
                        StatusSignalLevel::Warn
                    },
                    format!(
                        "{} Importe, {} ungueltig, SBOM Coverage {}%.",
                        overview.import_artifacts.len(),
                        invalid_imports,
                        sbom_coverage
                    ),
                    Some(web_path_with_context("/product-security/", Some(context))),
                ),
            ]
        }
        Ok(None) => vec![StatusSignal::new(
            "Product Security",
            "Offene CVE-Reviews",
            StatusSignalLevel::Warn,
            "Tenant wurde im Product-Security-Kontext nicht gefunden.",
            Some(web_path_with_context("/product-security/", Some(context))),
        )],
        Err(err) => vec![StatusSignal::new(
            "Product Security",
            "Offene CVE-Reviews",
            StatusSignalLevel::Danger,
            format!("Product-Security-Overview konnte nicht gelesen werden: {err}"),
            Some(web_path_with_context("/product-security/", Some(context))),
        )],
    }
}

async fn ai_governance_operation_signals(
    state: &AppState,
    context: &WebContext,
) -> Vec<StatusSignal> {
    let Some(store) = state.ai_governance_store.as_ref() else {
        return vec![StatusSignal::new(
            "AI Governance",
            "AI-Systeme nicht bewertet",
            StatusSignalLevel::Warn,
            "AI-Governance-Store ist nicht konfiguriert.",
            Some(web_path_with_context("/ai-governance/", Some(context))),
        )];
    };
    match store.overview(context.tenant_id, 200).await {
        Ok(overview) => vec![
            StatusSignal::new(
                "AI Governance",
                "AI-Systeme nicht bewertet",
                if overview.summary.not_assessed_systems == 0 {
                    StatusSignalLevel::Ok
                } else {
                    StatusSignalLevel::Warn
                },
                format!(
                    "{} von {} AI-Systemen sind noch nicht eingestuft.",
                    overview.summary.not_assessed_systems, overview.summary.total_systems
                ),
                Some(web_path_with_context("/ai-governance/", Some(context))),
            ),
            StatusSignal::new(
                "AI Governance",
                "AI-Reviews faellig",
                if overview.summary.review_due_systems == 0 {
                    StatusSignalLevel::Ok
                } else {
                    StatusSignalLevel::Warn
                },
                format!(
                    "{} AI-Governance-Reviews sind faellig.",
                    overview.summary.review_due_systems
                ),
                Some(web_path_with_context("/ai-governance/", Some(context))),
            ),
            StatusSignal::new(
                "AI Governance",
                "AI-Evidence fehlt",
                if overview.summary.evidence_missing == 0 {
                    StatusSignalLevel::Ok
                } else {
                    StatusSignalLevel::Warn
                },
                format!(
                    "{} AI-Systeme haben noch keine Evidence-Spur.",
                    overview.summary.evidence_missing
                ),
                Some(web_path_with_context("/ai-governance/", Some(context))),
            ),
            StatusSignal::new(
                "AI Governance",
                "AI-Governance-Gaps",
                if overview.summary.open_governance_gaps == 0 {
                    StatusSignalLevel::Ok
                } else {
                    StatusSignalLevel::Warn
                },
                format!(
                    "{} offene AI-Governance-Anforderungen.",
                    overview.summary.open_governance_gaps
                ),
                Some(web_path_with_context("/ai-governance/", Some(context))),
            ),
        ],
        Err(err) => vec![StatusSignal::new(
            "AI Governance",
            "AI-Systeme nicht bewertet",
            StatusSignalLevel::Danger,
            format!("AI-Governance-Uebersicht konnte nicht gelesen werden: {err}"),
            Some(web_path_with_context("/ai-governance/", Some(context))),
        )],
    }
}

fn migration_signal_level(status: &MigrationStatusView) -> StatusSignalLevel {
    match status {
        MigrationStatusView::Ready(status) => {
            if status.applied_count >= status.expected_count as i64
                && status.latest_applied_version.as_deref() == status.expected_latest_version
            {
                StatusSignalLevel::Ok
            } else {
                StatusSignalLevel::Warn
            }
        }
        MigrationStatusView::Missing => StatusSignalLevel::Warn,
        MigrationStatusView::Error(_) => StatusSignalLevel::Danger,
    }
}

fn migration_signal_detail(status: &MigrationStatusView) -> String {
    match status {
        MigrationStatusView::Ready(status) => format!(
            "{}/{} angewendet; letzte Version {}.",
            status.applied_count,
            status.expected_count,
            status
                .latest_applied_version
                .as_deref()
                .unwrap_or("nicht registriert")
        ),
        MigrationStatusView::Missing => "DATABASE_URL ist im AppState nicht gesetzt.".to_string(),
        MigrationStatusView::Error(message) => {
            format!("Migrationsstatus konnte nicht gelesen werden: {message}")
        }
    }
}

fn status_migration_json(status: &MigrationStatusView) -> StatusMigrationJson {
    match status {
        MigrationStatusView::Ready(status) => StatusMigrationJson {
            level: migration_signal_level(&MigrationStatusView::Ready(status.clone())),
            readable: true,
            database_kind: Some(status.database_kind.to_string()),
            applied_count: status.applied_count,
            expected_count: status.expected_count,
            latest_applied_version: status.latest_applied_version.clone(),
            latest_applied_at: status.latest_applied_at.clone(),
            expected_latest_version: status.expected_latest_version.map(ToString::to_string),
            message: None,
        },
        MigrationStatusView::Missing => StatusMigrationJson {
            level: StatusSignalLevel::Warn,
            readable: false,
            database_kind: None,
            applied_count: 0,
            expected_count: 0,
            latest_applied_version: None,
            latest_applied_at: None,
            expected_latest_version: None,
            message: Some("DATABASE_URL ist im AppState nicht gesetzt.".to_string()),
        },
        MigrationStatusView::Error(message) => StatusMigrationJson {
            level: StatusSignalLevel::Danger,
            readable: false,
            database_kind: None,
            applied_count: 0,
            expected_count: 0,
            latest_applied_version: None,
            latest_applied_at: None,
            expected_latest_version: None,
            message: Some(message.clone()),
        },
    }
}

fn status_signal_rows(signals: &[StatusSignal]) -> String {
    signals
        .iter()
        .map(|signal| {
            let action = signal
                .href
                .as_deref()
                .map(|href| format!(r#"<a href="{}">Oeffnen</a>"#, html_escape(href)))
                .unwrap_or_else(|| "-".to_string());
            format!(
                r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                html_escape(&signal.area),
                html_escape(&signal.signal),
                status_signal_badge(signal.level),
                html_escape(&signal.detail),
                action,
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn status_signal_badge(level: StatusSignalLevel) -> String {
    match level {
        StatusSignalLevel::Ok => web_badge("OK", "ok"),
        StatusSignalLevel::Warn => web_badge("Pruefen", "warn"),
        StatusSignalLevel::Danger => web_badge("Kritisch", "danger"),
    }
}

impl StatusSignal {
    fn new(
        area: impl Into<String>,
        signal: impl Into<String>,
        level: StatusSignalLevel,
        detail: impl Into<String>,
        href: Option<String>,
    ) -> Self {
        Self {
            area: area.into(),
            signal: signal.into(),
            level,
            detail: detail.into(),
            href,
        }
    }
}

impl StatusSignalLevel {
    fn is_issue(self) -> bool {
        matches!(self, Self::Warn | Self::Danger)
    }

    fn as_label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Danger => "critical",
        }
    }

    fn metric_value(self) -> i64 {
        match self {
            Self::Ok => 0,
            Self::Warn => 1,
            Self::Danger => 2,
        }
    }
}

impl StatusOperationsSeverity {
    fn from_signals(signals: &[StatusSignal]) -> Self {
        if signals
            .iter()
            .any(|signal| signal.level == StatusSignalLevel::Danger)
        {
            return Self::Critical;
        }
        if signals
            .iter()
            .any(|signal| signal.level == StatusSignalLevel::Warn)
        {
            return Self::Warn;
        }
        Self::Ok
    }

    fn exit_code(self) -> i64 {
        match self {
            Self::Ok => 0,
            Self::Warn => 1,
            Self::Critical => 2,
        }
    }

    fn as_label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Critical => "critical",
        }
    }
}

fn product_security_scope_config(raw: &str) -> ProductSecurityScopeConfig {
    let trimmed = raw.trim();
    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        let scope = value
            .get("scope")
            .or_else(|| value.get("description"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        let threshold_source = value.get("thresholds").unwrap_or(&value);
        return ProductSecurityScopeConfig {
            scope,
            thresholds: ProductSecurityThresholds {
                sbom_coverage_min: json_i64_threshold(
                    threshold_source,
                    &["sbom_coverage_min", "sbom_coverage"],
                    80,
                    0,
                    100,
                ),
                csaf_coverage_min: json_i64_threshold(
                    threshold_source,
                    &["csaf_coverage_min", "csaf_coverage"],
                    80,
                    0,
                    100,
                ),
                threat_tara_coverage_min: json_i64_threshold(
                    threshold_source,
                    &["threat_tara_coverage_min", "threat_tara_coverage"],
                    80,
                    0,
                    100,
                ),
                review_backlog_max: json_i64_threshold(
                    threshold_source,
                    &["review_backlog_max", "review_backlog"],
                    0,
                    0,
                    999,
                ),
                critical_open_vulnerabilities_max: json_i64_threshold(
                    threshold_source,
                    &[
                        "critical_open_vulnerabilities_max",
                        "critical_open_vulnerabilities",
                    ],
                    0,
                    0,
                    999,
                ),
            },
        };
    }
    ProductSecurityScopeConfig {
        scope: trimmed.to_string(),
        thresholds: ProductSecurityThresholds::default(),
    }
}

fn json_i64_threshold(value: &Value, names: &[&str], default: i64, min: i64, max: i64) -> i64 {
    names
        .iter()
        .find_map(|name| value.get(*name))
        .and_then(|value| {
            value
                .as_i64()
                .or_else(|| value.as_str()?.trim().parse::<i64>().ok())
        })
        .unwrap_or(default)
        .clamp(min, max)
}

fn product_security_scope_config_json(
    scope: &str,
    thresholds: ProductSecurityThresholds,
) -> String {
    serde_json::json!({
        "scope": scope.trim(),
        "thresholds": {
            "sbom_coverage_min": thresholds.sbom_coverage_min,
            "csaf_coverage_min": thresholds.csaf_coverage_min,
            "threat_tara_coverage_min": thresholds.threat_tara_coverage_min,
            "review_backlog_max": thresholds.review_backlog_max,
            "critical_open_vulnerabilities_max": thresholds.critical_open_vulnerabilities_max
        }
    })
    .to_string()
}

fn product_security_thresholds_from_form(
    form: &WebProductSecurityThresholdForm,
) -> Result<ProductSecurityThresholds, String> {
    Ok(ProductSecurityThresholds {
        sbom_coverage_min: threshold_form_i64(
            "SBOM Coverage",
            form.sbom_coverage_min.as_deref(),
            80,
            0,
            100,
        )?,
        csaf_coverage_min: threshold_form_i64(
            "CSAF Coverage",
            form.csaf_coverage_min.as_deref(),
            80,
            0,
            100,
        )?,
        threat_tara_coverage_min: threshold_form_i64(
            "Threat/TARA Coverage",
            form.threat_tara_coverage_min.as_deref(),
            80,
            0,
            100,
        )?,
        review_backlog_max: threshold_form_i64(
            "Review-Backlog",
            form.review_backlog_max.as_deref(),
            0,
            0,
            999,
        )?,
        critical_open_vulnerabilities_max: threshold_form_i64(
            "Kritische Schwachstellen",
            form.critical_open_vulnerabilities_max.as_deref(),
            0,
            0,
            999,
        )?,
    })
}

fn threshold_form_i64(
    label: &str,
    value: Option<&str>,
    default: i64,
    min: i64,
    max: i64,
) -> Result<i64, String> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(default);
    };
    let parsed = value
        .parse::<i64>()
        .map_err(|_| format!("{label} muss eine Zahl sein."))?;
    if parsed < min || parsed > max {
        return Err(format!("{label} muss zwischen {min} und {max} liegen."));
    }
    Ok(parsed)
}

fn product_security_threshold_panel(
    context: &WebContext,
    config: &ProductSecurityScopeConfig,
    can_write: bool,
) -> String {
    let thresholds = config.thresholds;
    if can_write {
        return format!(
            r#"<article class="panel wide">
                <h2>Ampel-Schwellen</h2>
                <form method="post" action="{}">
                  <label>Product-Security-Scope<textarea name="scope" rows="3">{}</textarea></label>
                  <div class="form-grid">
                    <label>SBOM Coverage Minimum (%)<input name="sbom_coverage_min" type="number" min="0" max="100" value="{}"></label>
                    <label>CSAF Coverage Minimum (%)<input name="csaf_coverage_min" type="number" min="0" max="100" value="{}"></label>
                    <label>Threat/TARA Coverage Minimum (%)<input name="threat_tara_coverage_min" type="number" min="0" max="100" value="{}"></label>
                    <label>Review-Backlog Maximum<input name="review_backlog_max" type="number" min="0" max="999" value="{}"></label>
                    <label>Kritische Schwachstellen Maximum<input name="critical_open_vulnerabilities_max" type="number" min="0" max="999" value="{}"></label>
                  </div>
                  <button type="submit">Schwellen speichern</button>
                </form>
              </article>"#,
            web_path_with_context("/product-security/thresholds", Some(context)),
            html_escape(&config.scope),
            thresholds.sbom_coverage_min,
            thresholds.csaf_coverage_min,
            thresholds.threat_tara_coverage_min,
            thresholds.review_backlog_max,
            thresholds.critical_open_vulnerabilities_max,
        );
    }
    format!(
        r#"<article class="panel wide">
            <h2>Ampel-Schwellen</h2>
            <table>
              <thead><tr><th>Signal</th><th>Schwelle</th></tr></thead>
              <tbody>
                <tr><td>SBOM Coverage Minimum</td><td>{}%</td></tr>
                <tr><td>CSAF Coverage Minimum</td><td>{}%</td></tr>
                <tr><td>Threat/TARA Coverage Minimum</td><td>{}%</td></tr>
                <tr><td>Review-Backlog Maximum</td><td>{}</td></tr>
                <tr><td>Kritische Schwachstellen Maximum</td><td>{}</td></tr>
              </tbody>
            </table>
          </article>"#,
        thresholds.sbom_coverage_min,
        thresholds.csaf_coverage_min,
        thresholds.threat_tara_coverage_min,
        thresholds.review_backlog_max,
        thresholds.critical_open_vulnerabilities_max,
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

fn product_security_import_request_from_form(
    form: &ImportUploadFormData,
) -> Result<product_security_store::ProductSecurityArtifactImportRequest, String> {
    let file = form
        .file
        .as_ref()
        .ok_or_else(|| "Bitte eine CSAF- oder SBOM-JSON-Datei auswaehlen.".to_string())?;
    let document: Value = serde_json::from_slice(&file.data)
        .map_err(|err| format!("JSON-Datei konnte nicht gelesen werden: {err}"))?;
    Ok(
        product_security_store::ProductSecurityArtifactImportRequest {
            product_id: optional_i64_form_field(&form.fields, "product_id"),
            file_name: file.filename.clone(),
            document,
        },
    )
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

fn optional_form_i64(value: Option<String>, field_label: &str) -> Result<Option<i64>, String> {
    let Some(value) = value.map(|item| item.trim().to_string()) else {
        return Ok(None);
    };
    if value.is_empty() {
        return Ok(None);
    }
    let parsed = value
        .parse::<i64>()
        .map_err(|_| format!("{field_label} muss eine ganze Zahl sein."))?;
    if parsed <= 0 {
        return Err(format!("{field_label} muss groesser als 0 sein."));
    }
    Ok(Some(parsed))
}

fn optional_form_i64_nonnegative(
    value: Option<String>,
    field_label: &str,
) -> Result<Option<i64>, String> {
    let Some(value) = value.map(|item| item.trim().to_string()) else {
        return Ok(None);
    };
    if value.is_empty() {
        return Ok(None);
    }
    let parsed = value
        .parse::<i64>()
        .map_err(|_| format!("{field_label} muss eine ganze Zahl sein."))?;
    if parsed < 0 {
        return Err(format!("{field_label} darf nicht negativ sein."));
    }
    Ok(Some(parsed))
}

fn optional_form_f64(value: Option<String>, field_label: &str) -> Result<Option<f64>, String> {
    let Some(value) = value.map(|item| item.trim().to_string()) else {
        return Ok(None);
    };
    if value.is_empty() {
        return Ok(None);
    }
    value
        .parse::<f64>()
        .map(Some)
        .map_err(|_| format!("{field_label} muss eine Zahl sein."))
}

fn comma_separated_form_list(value: Option<String>) -> Vec<String> {
    value
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToString::to_string)
        .collect()
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
        sha256: format!("{:x}", Sha256::digest(&file.data)),
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

fn tenant_regulatory_active_count(tenant: &tenant_store::TenantProfile) -> i64 {
    [
        tenant.nis2_relevant || tenant.kritis_relevant,
        tenant.dora_relevant
            || tenant.dora_financial_entity
            || tenant.dora_ict_third_party_provider,
        tenant.processes_personal_data || tenant.gdpr_controller || tenant.gdpr_processor,
        tenant.cra_relevant || tenant.develops_digital_products,
        tenant.uses_ai_systems
            || tenant.ai_act_high_risk
            || !matches!(
                tenant.ai_act_profile.as_str(),
                "" | "NOT_ASSESSED" | "NOT_RELEVANT"
            ),
        tenant.tisax_relevant || tenant.automotive_scope,
        !matches!(
            tenant.iso27001_target.as_str(),
            "" | "NOT_DEFINED" | "NOT_RELEVANT"
        ),
    ]
    .into_iter()
    .filter(|enabled| *enabled)
    .count() as i64
}

fn tenant_regulatory_profile_rows(tenant: &tenant_store::TenantProfile) -> String {
    let rows = [
        (
            "NIS2 / KRITIS",
            tenant.nis2_relevant || tenant.kritis_relevant,
            if tenant.kritis_relevant {
                "KRITIS- oder kritischer Service-Kontext ist gesetzt."
            } else if tenant.nis2_relevant {
                "NIS2-Betroffenheit ist im Organisationsprofil gesetzt."
            } else {
                "Keine NIS2-/KRITIS-Betroffenheit im Profil gesetzt."
            },
            if tenant.nis2_relevant || tenant.kritis_relevant {
                "Controls, Incidents und Evidence gegen NIS2-Scope fuehren."
            } else {
                "Betroffenheit fachlich pruefen und Entscheidung dokumentieren."
            },
        ),
        (
            "DORA",
            tenant.dora_relevant
                || tenant.dora_financial_entity
                || tenant.dora_ict_third_party_provider,
            if tenant.dora_financial_entity {
                "Finanzunternehmen-Kontext ist gesetzt."
            } else if tenant.dora_ict_third_party_provider {
                "IKT-Drittdienstleister-Kontext ist gesetzt."
            } else if tenant.dora_relevant {
                "DORA-Relevanz wurde fachlich markiert."
            } else {
                "Kein DORA-Kontext im Profil gesetzt."
            },
            if tenant.dora_relevant
                || tenant.dora_financial_entity
                || tenant.dora_ict_third_party_provider
            {
                "IKT-Risiko, IKT-Vorfallprozess und Drittparteienbezug pruefen."
            } else {
                "Finanzsektor- oder IKT-Drittparteienrolle pruefen."
            },
        ),
        (
            "DSGVO",
            tenant.processes_personal_data || tenant.gdpr_controller || tenant.gdpr_processor,
            if tenant.gdpr_controller && tenant.gdpr_processor {
                "Verantwortlicher- und Auftragsverarbeiterrolle sind gesetzt."
            } else if tenant.gdpr_controller {
                "Verantwortlichenrolle ist gesetzt."
            } else if tenant.gdpr_processor {
                "Auftragsverarbeiterrolle ist gesetzt."
            } else if tenant.processes_personal_data {
                "Personenbezogene Daten sind im Scope."
            } else {
                "Kein Personenbezug im Profil gesetzt."
            },
            if tenant.gdpr_special_categories {
                "Datenarten, TOMs, Meldepfad und Betroffenenrisiko priorisiert pruefen."
            } else if tenant.processes_personal_data
                || tenant.gdpr_controller
                || tenant.gdpr_processor
            {
                "Datenschutzrolle, TOMs und Incident-Meldepfad pruefen."
            } else {
                "Personenbezug und Datenschutzrolle fachlich bestaetigen."
            },
        ),
        (
            "CRA / Product Security",
            tenant.cra_relevant || tenant.develops_digital_products,
            if tenant.cra_relevant {
                "CRA-Relevanz wurde fachlich markiert."
            } else if tenant.develops_digital_products {
                "Produkte mit digitalen Elementen sind im Profil gesetzt."
            } else {
                "Kein CRA-/Digitalprodukt-Fokus im Profil gesetzt."
            },
            if tenant.cra_relevant || tenant.develops_digital_products {
                "SBOM, PSIRT, Vulnerability Handling und Supportfenster steuern."
            } else {
                "Produkt-/Herstellerrolle und digitale Elemente pruefen."
            },
        ),
        (
            "EU AI Act",
            tenant.uses_ai_systems
                || tenant.ai_act_high_risk
                || !matches!(
                    tenant.ai_act_profile.as_str(),
                    "" | "NOT_ASSESSED" | "NOT_RELEVANT"
                ),
            if tenant.ai_act_high_risk {
                "Hochrisiko-KI wurde markiert."
            } else if tenant.uses_ai_systems {
                "KI-Systeme sind im Profil gesetzt."
            } else {
                "Kein aktiver KI-Scope im Profil gesetzt."
            },
            if tenant.ai_act_high_risk {
                "KI-Risikomanagement, Logging, Human Oversight und Security priorisieren."
            } else if tenant.uses_ai_systems {
                "KI-Inventar und AI-Act-Klassifizierung ergaenzen."
            } else {
                "KI-Nutzung und Anbieter-/Betreiberrolle pruefen."
            },
        ),
        (
            "TISAX / Automotive",
            tenant.tisax_relevant || tenant.automotive_scope,
            if tenant.tisax_relevant {
                "TISAX-Scope ist gesetzt."
            } else if tenant.automotive_scope {
                "Automotive-Scope ist gesetzt."
            } else {
                "Kein TISAX-/Automotive-Scope im Profil gesetzt."
            },
            if tenant.tisax_relevant || tenant.automotive_scope {
                "Supplier-, Prototypen-, Informations- und Produktsecurity-Nachweise pruefen."
            } else {
                "Automotive-Kunden- oder TISAX-Anforderung pruefen."
            },
        ),
        (
            "ISO 27001",
            !matches!(
                tenant.iso27001_target.as_str(),
                "" | "NOT_DEFINED" | "NOT_RELEVANT"
            ),
            if tenant.iso27001_target.is_empty() || tenant.iso27001_target == "NOT_DEFINED" {
                "Kein ISO-27001-Zielbild gesetzt."
            } else {
                "ISO-27001-Zielbild ist gesetzt."
            },
            "Management Review, SoA, Risk Treatment und Evidence-Reife steuern.",
        ),
    ];
    rows.iter()
        .map(|(label, active, reason, next_step)| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(label),
                if *active {
                    web_badge("Aktiv", "ok")
                } else {
                    web_badge("Pruefen", "muted-badge")
                },
                html_escape(reason),
                html_escape(next_step),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn tenant_regulatory_profile_form(
    tenant: &tenant_store::TenantProfile,
    context: &WebContext,
) -> String {
    let action = web_path_with_context("/organizations/", Some(context));
    format!(
        r#"
        <section class="panel wide">
          <h2>Regulatorisches Organisationsprofil bearbeiten</h2>
          <form method="post" action="{}">
            <div class="form-grid">
              <label>Land<input name="country" value="{}"></label>
              <label>Operationslaender<input name="operation_countries" value="{}"></label>
              <label>Sektor<input name="sector" value="{}"></label>
              <label>Mitarbeitende<input name="employee_count" type="number" min="0" value="{}"></label>
              <label>Umsatz Mio.<input name="annual_revenue_million" value="{}"></label>
              <label>Bilanzsumme Mio.<input name="balance_sheet_million" value="{}"></label>
              <label>AI-Act-Profil<select name="ai_act_profile">{}</select></label>
              <label>ISO-27001 Zielbild<select name="iso27001_target">{}</select></label>
            </div>
            <div class="form-grid">
              <label>Kritische Services<textarea name="critical_services" rows="3">{}</textarea></label>
              <label>Supply Chain Rolle<textarea name="supply_chain_role" rows="3">{}</textarea></label>
              <label>Product Security Scope<textarea name="product_security_scope" rows="3">{}</textarea></label>
              <label>Beschreibung<textarea name="description" rows="3">{}</textarea></label>
            </div>
            <div class="form-grid">
              <label class="checkbox-row"><input name="nis2_relevant" type="checkbox" value="1"{}> NIS2 relevant</label>
              <label class="checkbox-row"><input name="kritis_relevant" type="checkbox" value="1"{}> KRITIS relevant</label>
              <label class="checkbox-row"><input name="dora_relevant" type="checkbox" value="1"{}> DORA relevant</label>
              <label class="checkbox-row"><input name="dora_financial_entity" type="checkbox" value="1"{}> DORA Finanzunternehmen</label>
              <label class="checkbox-row"><input name="dora_ict_third_party_provider" type="checkbox" value="1"{}> DORA IKT-Drittdienstleister</label>
              <label class="checkbox-row"><input name="processes_personal_data" type="checkbox" value="1"{}> Personenbezogene Daten</label>
              <label class="checkbox-row"><input name="gdpr_controller" type="checkbox" value="1"{}> DSGVO Verantwortlicher</label>
              <label class="checkbox-row"><input name="gdpr_processor" type="checkbox" value="1"{}> DSGVO Auftragsverarbeiter</label>
              <label class="checkbox-row"><input name="gdpr_special_categories" type="checkbox" value="1"{}> Besondere Datenkategorien</label>
              <label class="checkbox-row"><input name="develops_digital_products" type="checkbox" value="1"{}> Digitale Produkte</label>
              <label class="checkbox-row"><input name="cra_relevant" type="checkbox" value="1"{}> CRA relevant</label>
              <label class="checkbox-row"><input name="uses_ai_systems" type="checkbox" value="1"{}> KI-Systeme</label>
              <label class="checkbox-row"><input name="ai_act_high_risk" type="checkbox" value="1"{}> AI Act Hochrisiko</label>
              <label class="checkbox-row"><input name="ot_iacs_scope" type="checkbox" value="1"{}> OT / IACS</label>
              <label class="checkbox-row"><input name="automotive_scope" type="checkbox" value="1"{}> Automotive</label>
              <label class="checkbox-row"><input name="tisax_relevant" type="checkbox" value="1"{}> TISAX relevant</label>
              <label class="checkbox-row"><input name="psirt_defined" type="checkbox" value="1"{}> PSIRT definiert</label>
              <label class="checkbox-row"><input name="sbom_required" type="checkbox" value="1"{}> SBOM erforderlich</label>
            </div>
            <label>Regulatorische Notizen<textarea name="regulatory_profile_notes" rows="4">{}</textarea></label>
            <button type="submit">Regulierungsprofil speichern</button>
          </form>
        </section>
        "#,
        html_escape(&action),
        html_escape(&tenant.country),
        html_escape(&tenant.operation_countries.join(", ")),
        html_escape(&tenant.sector),
        tenant.employee_count,
        html_escape(&tenant.annual_revenue_million),
        html_escape(&tenant.balance_sheet_million),
        tenant_profile_ai_act_options(&tenant.ai_act_profile),
        tenant_profile_iso27001_options(&tenant.iso27001_target),
        html_escape(&tenant.critical_services),
        html_escape(&tenant.supply_chain_role),
        html_escape(&tenant.product_security_scope),
        html_escape(&tenant.description),
        checked_attr(tenant.nis2_relevant),
        checked_attr(tenant.kritis_relevant),
        checked_attr(tenant.dora_relevant),
        checked_attr(tenant.dora_financial_entity),
        checked_attr(tenant.dora_ict_third_party_provider),
        checked_attr(tenant.processes_personal_data),
        checked_attr(tenant.gdpr_controller),
        checked_attr(tenant.gdpr_processor),
        checked_attr(tenant.gdpr_special_categories),
        checked_attr(tenant.develops_digital_products),
        checked_attr(tenant.cra_relevant),
        checked_attr(tenant.uses_ai_systems),
        checked_attr(tenant.ai_act_high_risk),
        checked_attr(tenant.ot_iacs_scope),
        checked_attr(tenant.automotive_scope),
        checked_attr(tenant.tisax_relevant),
        checked_attr(tenant.psirt_defined),
        checked_attr(tenant.sbom_required),
        html_escape(&tenant.regulatory_profile_notes),
    )
}

fn tenant_profile_ai_act_options(selected: &str) -> String {
    tenant_profile_select_options(
        selected,
        &[
            ("NOT_ASSESSED", "Nicht bewertet"),
            ("NOT_RELEVANT", "Nicht relevant"),
            ("MINIMAL_RISK", "Minimales Risiko"),
            ("LIMITED_RISK", "Begrenztes Risiko"),
            ("HIGH_RISK", "Hochrisiko"),
        ],
    )
}

fn tenant_profile_iso27001_options(selected: &str) -> String {
    tenant_profile_select_options(
        selected,
        &[
            ("NOT_DEFINED", "Nicht definiert"),
            ("NOT_RELEVANT", "Nicht relevant"),
            ("ISMS_BUILDUP", "ISMS-Aufbau"),
            ("CERTIFICATION_READY", "Zertifizierungsreif"),
            ("CERTIFIED", "Zertifiziert"),
        ],
    )
}

fn tenant_profile_select_options(selected: &str, options: &[(&str, &str)]) -> String {
    options
        .iter()
        .map(|(value, label)| {
            format!(
                r#"<option value="{}"{}>{}</option>"#,
                html_escape(value),
                selected_attr(*value == selected),
                html_escape(label),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn management_review_status_panel(
    package: &report_store::ManagementReviewPackageDetail,
    context: &WebContext,
    can_write: bool,
) -> String {
    let decision_notes = if package.decision_notes.trim().is_empty() {
        "-"
    } else {
        package.decision_notes.as_str()
    };
    let next_actions = if package.next_actions.trim().is_empty() {
        "-"
    } else {
        package.next_actions.as_str()
    };
    let approval = package
        .approved_at
        .as_deref()
        .map(|approved_at| {
            format!(
                "Freigegeben am {} durch User {}",
                html_escape(approved_at),
                package
                    .approved_by_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "-".to_string())
            )
        })
        .unwrap_or_else(|| "Noch nicht freigegeben".to_string());
    let form = if can_write {
        format!(
            r#"
            <form method="post" action="{}">
              <div class="form-grid">
                <label>Status<select name="status">{}</select></label>
              </div>
              <label>Entscheidung / Freigabenotiz<textarea name="decision_notes" rows="3">{}</textarea></label>
              <label>Naechste Massnahmen<textarea name="next_actions" rows="3">{}</textarea></label>
              <button type="submit">Review-Status speichern</button>
            </form>
            "#,
            web_path_with_context(
                &format!("/management-reviews/{}/status", package.id),
                Some(context)
            ),
            management_review_status_options(&package.status),
            html_escape(&package.decision_notes),
            html_escape(&package.next_actions),
        )
    } else {
        "<p>Zum Bearbeiten oder Freigeben wird eine schreibende ISCY-Rolle benoetigt.</p>"
            .to_string()
    };
    format!(
        r#"
        <section class="panel wide">
          <h2>Review und Freigabe</h2>
          <table>
            <tbody>
              <tr><th>Status</th><td>{}</td><th>Freigabe</th><td>{}</td></tr>
              <tr><th>Entscheidung</th><td colspan="3">{}</td></tr>
              <tr><th>Naechste Massnahmen</th><td colspan="3">{}</td></tr>
            </tbody>
          </table>
          {}
        </section>
        "#,
        html_escape(&package.status_label),
        approval,
        html_escape(decision_notes),
        html_escape(next_actions),
        form,
    )
}

fn management_review_status_options(selected: &str) -> String {
    [
        ("DRAFT", "Entwurf"),
        ("IN_REVIEW", "In Review"),
        ("APPROVED", "Freigegeben"),
    ]
    .iter()
    .map(|(value, label)| {
        format!(
            r#"<option value="{}"{}>{}</option>"#,
            value,
            selected_attr(*value == selected),
            label,
        )
    })
    .collect::<Vec<_>>()
    .join("")
}

fn management_review_export_panel(
    package: &report_store::ManagementReviewPackageDetail,
    context: &WebContext,
) -> String {
    let markdown_href = web_path_with_context(
        &format!("/management-reviews/{}/export", package.id),
        Some(context),
    );
    let html_href = web_path_with_context(
        &format!("/management-reviews/{}/export.html", package.id),
        Some(context),
    );
    let pdf_href = web_path_with_context(
        &format!("/management-reviews/{}/export.pdf", package.id),
        Some(context),
    );
    let json_href = web_path_with_context(
        &format!("/management-reviews/{}/export.json", package.id),
        Some(context),
    );
    format!(
        r#"
        <section class="panel wide">
          <h2>Export</h2>
          <p><a href="{}">Markdown</a> · <a href="{}">HTML</a> · <a href="{}">PDF</a> · <a href="{}">JSON</a></p>
        </section>
        "#,
        html_escape(&markdown_href),
        html_escape(&html_href),
        html_escape(&pdf_href),
        html_escape(&json_href),
    )
}

fn management_review_metric_cards(metrics: &Value) -> String {
    [
        ("Risiken", "open_risks"),
        ("Control-Gaps", "open_control_gaps"),
        ("Evidence offen", "open_evidence_needs"),
        ("Roadmap offen", "open_roadmap_tasks"),
    ]
    .iter()
    .map(|(label, key)| {
        metric_card(
            label,
            metrics.get(*key).and_then(Value::as_i64).unwrap_or(0),
        )
    })
    .collect::<Vec<_>>()
    .join("")
}

fn management_review_object_panel(title: &str, value: &Value) -> String {
    let rows = value
        .as_object()
        .map(|object| {
            object
                .iter()
                .map(|(key, value)| {
                    format!(
                        r#"<tr><th>{}</th><td>{}</td></tr>"#,
                        html_escape(key),
                        html_escape(&management_review_json_display(value)),
                    )
                })
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default();
    format!(
        r#"<article class="panel wide"><h2>{}</h2><table><tbody>{}</tbody></table></article>"#,
        html_escape(title),
        if rows.is_empty() {
            web_empty_row(2, "Keine Daten vorhanden.")
        } else {
            rows
        },
    )
}

fn management_review_array_panel(
    title: &str,
    value: &Value,
    fields: &[(&str, &str)],
    context: &WebContext,
) -> String {
    let header = fields
        .iter()
        .map(|(_, label)| format!("<th>{}</th>", html_escape(label)))
        .collect::<Vec<_>>()
        .join("");
    let rows = value
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    let href = item
                        .get("href")
                        .and_then(Value::as_str)
                        .map(|href| web_path_with_context(href, Some(context)));
                    let cells = fields
                        .iter()
                        .enumerate()
                        .map(|(index, (key, _))| {
                            let display = html_escape(&management_review_json_display(
                                item.get(*key).unwrap_or(&Value::Null),
                            ));
                            if index == 0 {
                                if let Some(href) = href.as_ref() {
                                    return format!(
                                        r#"<td><a href="{}">{}</a></td>"#,
                                        html_escape(href),
                                        display
                                    );
                                }
                            }
                            format!("<td>{display}</td>")
                        })
                        .collect::<Vec<_>>()
                        .join("");
                    format!("<tr>{cells}</tr>")
                })
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default();
    format!(
        r#"
        <article class="panel wide">
          <h2>{}</h2>
          <table>
            <thead><tr>{}</tr></thead>
            <tbody>{}</tbody>
          </table>
        </article>
        "#,
        html_escape(title),
        header,
        if rows.is_empty() {
            web_empty_row(fields.len(), "Keine Daten vorhanden.")
        } else {
            rows
        },
    )
}

fn management_review_json_display(value: &Value) -> String {
    match value {
        Value::Null => "-".to_string(),
        Value::Bool(value) => {
            if *value {
                "Ja".to_string()
            } else {
                "Nein".to_string()
            }
        }
        Value::Number(value) => value.to_string(),
        Value::String(value) if value.trim().is_empty() => "-".to_string(),
        Value::String(value) => value.clone(),
        Value::Array(values) => values
            .iter()
            .map(management_review_json_display)
            .collect::<Vec<_>>()
            .join(", "),
        Value::Object(_) => value.to_string(),
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "Ja"
    } else {
        "Nein"
    }
}

fn yes_no_badge(value: bool) -> String {
    if value {
        web_badge("Ja", "ok")
    } else {
        web_badge("Nein", "muted-badge")
    }
}

fn score_badge(score: i64) -> String {
    web_badge(&score.to_string(), score_badge_class(score))
}

fn score_band_badge(score: i64) -> String {
    web_badge(score_band_label(score), score_badge_class(score))
}

fn web_badge(label: &str, class_name: &str) -> String {
    format!(
        r#"<span class="badge {}">{}</span>"#,
        class_name,
        html_escape(label),
    )
}

fn framework_badges(frameworks: &[String]) -> String {
    if frameworks.is_empty() {
        return "-".to_string();
    }
    frameworks
        .iter()
        .map(|framework| web_badge(framework, "info"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn control_status_badge_class(status: &str) -> &'static str {
    match status.trim().to_ascii_uppercase().as_str() {
        "EFFECTIVE" | "IMPLEMENTED" => "ok",
        "PARTIAL" => "warn",
        "GAP" => "danger",
        "NOT_APPLICABLE" => "muted-badge",
        _ => "muted-badge",
    }
}

fn evidence_status_badge_class(status: &str) -> &'static str {
    match status.trim().to_ascii_uppercase().as_str() {
        "EVIDENCED" => "ok",
        "PARTIAL" => "warn",
        "MISSING" => "danger",
        _ => "muted-badge",
    }
}

fn supplier_criticality_badge_class(criticality: &str) -> &'static str {
    match criticality.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" | "VERY_HIGH" => "danger",
        "HIGH" => "high",
        "MEDIUM" => "warn",
        "LOW" => "info",
        _ => "muted-badge",
    }
}

fn supplier_issue_summary(issues: &[String]) -> String {
    if issues.is_empty() {
        return web_badge("Keine offenen Issues", "ok");
    }
    issues
        .iter()
        .take(3)
        .map(|issue| format!("<p>{}</p>", html_escape(issue)))
        .collect::<Vec<_>>()
        .join("")
}

fn score_band_label(score: i64) -> &'static str {
    if score >= 80 {
        "Stabil"
    } else if score >= 60 {
        "Beobachten"
    } else {
        "Handeln"
    }
}

fn score_badge_class(score: i64) -> &'static str {
    if score >= 80 {
        "ok"
    } else if score >= 60 {
        "warn"
    } else {
        "danger"
    }
}

fn score_text_class(score: i64) -> &'static str {
    if score >= 80 {
        "score-ok"
    } else if score >= 60 {
        "score-warn"
    } else {
        "score-danger"
    }
}

fn severity_badge(severity: &str, label: &str) -> String {
    web_badge(label, severity_badge_class(severity))
}

fn severity_badge_class(severity: &str) -> &'static str {
    match severity.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" | "KRITISCH" => "danger",
        "HIGH" | "HOCH" => "high",
        "MEDIUM" | "MITTEL" => "warn",
        "LOW" | "NIEDRIG" => "info",
        "INFO" | "INFORMATIONAL" => "muted-badge",
        _ => "muted-badge",
    }
}

fn zero_trust_priority_title(posture: &agent_store::AgentPostureOverview) -> String {
    if posture.device_count == 0 {
        "Agent-Rollout starten".to_string()
    } else if posture.critical_finding_count > 0 {
        "Kritische Findings zuerst schliessen".to_string()
    } else if posture.high_finding_count > 0 {
        "Hohe Findings in die Roadmap ziehen".to_string()
    } else if posture.stale_device_count > 0 {
        "Agent-Freshness verbessern".to_string()
    } else if posture.open_finding_count > 0 {
        "Offene Findings nach Pillar abbauen".to_string()
    } else {
        "Posture stabil halten".to_string()
    }
}

fn zero_trust_priority_detail(posture: &agent_store::AgentPostureOverview) -> String {
    if posture.device_count == 0 {
        return "Noch keine Agent-Devices registriert. Naechster Schritt ist ein kontrollierter Rollout mit Enrollment-Token und mTLS-Bindung.".to_string();
    }
    if let Some(pillar) = most_exposed_pillar(posture) {
        return format!(
            "Fokus-Pillar {}: {} offene Findings, davon {} kritisch und {} hoch.",
            pillar.pillar,
            pillar.open_finding_count,
            pillar.critical_finding_count,
            pillar.high_finding_count,
        );
    }
    if posture.stale_device_count > 0 {
        return format!(
            "{} Agent-Devices sind nicht frisch gesehen worden. Heartbeat, Netzwerkweg und Agent-Service pruefen.",
            posture.stale_device_count,
        );
    }
    "Alle gemeldeten Agent-Findings sind aktuell geschlossen. Sinnvoll bleibt: Abdeckung je Plattform ausbauen und Ausnahmen befristet dokumentieren.".to_string()
}

fn most_exposed_pillar(
    posture: &agent_store::AgentPostureOverview,
) -> Option<&agent_store::AgentPillarScore> {
    posture
        .pillar_scores
        .iter()
        .filter(|pillar| pillar.open_finding_count > 0)
        .max_by_key(|pillar| {
            (
                pillar.critical_finding_count,
                pillar.high_finding_count,
                pillar.open_finding_count,
            )
        })
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

fn evidence_sensitivity_options_for(selected_sensitivity: &str) -> String {
    [
        ("PUBLIC", "Oeffentlich"),
        ("INTERNAL", "Intern"),
        ("CONFIDENTIAL", "Vertraulich"),
        ("RESTRICTED", "Streng vertraulich"),
    ]
    .iter()
    .map(|(code, label)| {
        let selected = if *code == selected_sensitivity {
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

fn control_status_options_for(selected_status: &str) -> String {
    [
        ("GAP", "Fehlt"),
        ("PARTIAL", "Teilweise"),
        ("IMPLEMENTED", "Umgesetzt"),
        ("EFFECTIVE", "Wirksam"),
        ("NOT_APPLICABLE", "Nicht anwendbar"),
    ]
    .iter()
    .map(|(code, label)| {
        format!(
            r#"<option value="{}"{}>{}</option>"#,
            html_escape(code),
            selected_attr(*code == selected_status),
            html_escape(label),
        )
    })
    .collect::<Vec<_>>()
    .join("")
}

fn control_evidence_status_options_for(selected_status: &str) -> String {
    [
        ("MISSING", "Fehlt"),
        ("PARTIAL", "Teilweise"),
        ("EVIDENCED", "Nachgewiesen"),
    ]
    .iter()
    .map(|(code, label)| {
        format!(
            r#"<option value="{}"{}>{}</option>"#,
            html_escape(code),
            selected_attr(*code == selected_status),
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

fn evidence_prefill_href(
    context: &WebContext,
    title: &str,
    description: &str,
    linked_requirement: &str,
    status: Option<&str>,
    return_to: Option<&str>,
) -> String {
    let mut path = format!(
        "/evidence/?evidence_title={}&evidence_description={}&linked_requirement={}",
        url_component(title),
        url_component(description),
        url_component(linked_requirement),
    );
    if let Some(status) = status.filter(|value| !value.trim().is_empty()) {
        path.push_str("&evidence_status=");
        path.push_str(&url_component(status));
    }
    if let Some(return_to) = return_to.filter(|value| !value.trim().is_empty()) {
        path.push_str("&return_to=");
        path.push_str(&url_component(return_to));
    }
    web_path_with_context(&path, Some(context))
}

fn evidence_key_from_text(value: &str) -> Option<String> {
    let (_, after_marker) = value.split_once("Evidence-Key:")?;
    let key = after_marker
        .trim_start()
        .split(|character: char| character.is_ascii_whitespace() || matches!(character, '.' | ','))
        .next()
        .unwrap_or_default()
        .trim();
    (!key.is_empty()).then(|| key.to_string())
}

fn safe_web_return_path(value: Option<&String>) -> Option<String> {
    let value = value?.trim();
    if value.starts_with('/')
        && !value.starts_with("//")
        && !value.contains('\r')
        && !value.contains('\n')
    {
        Some(value.to_string())
    } else {
        None
    }
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

async fn cve_feed(State(state): State<AppState>, headers: HeaderMap) -> Response {
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

    let summary = match store.dashboard_summary().await {
        Ok(summary) => summary,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: "database_error",
                    message: format!("CVE-Summary konnte nicht gelesen werden: {err}"),
                }),
            )
                .into_response();
        }
    };
    let cves = match store.list_recent(100).await {
        Ok(cves) => cves,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: "database_error",
                    message: format!("CVE-Liste konnte nicht gelesen werden: {err}"),
                }),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        Json(CveFeedResponse {
            api_version: "v1",
            tenant_id: context.tenant_id,
            summary,
            cves,
        }),
    )
        .into_response()
}

async fn cve_detail(
    Path(cve_id): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let _context = match authenticated_tenant_context(&state, &headers).await {
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
    let normalized = normalize_cve_id(&cve_id);
    if normalized.is_empty() || !is_valid_cve_id(&normalized) {
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

    match store.detail(&normalized).await {
        Ok(Some(cve)) => (
            StatusCode::OK,
            Json(CveDetailResponse {
                api_version: "v1",
                cve,
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "cve_not_found",
                message: format!("CVE '{}' wurde nicht gefunden.", normalized),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("CVE-Detail konnte nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn cve_assessment_register(State(state): State<AppState>, headers: HeaderMap) -> Response {
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

    let summary = match store.assessment_dashboard_summary(context.tenant_id).await {
        Ok(summary) => summary,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: "database_error",
                    message: format!("CVE-Assessment-Summary konnte nicht gelesen werden: {err}"),
                }),
            )
                .into_response();
        }
    };
    let assessments = match store.list_assessments(context.tenant_id, 100).await {
        Ok(assessments) => assessments,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiErrorResponse {
                    accepted: false,
                    api_version: "v1",
                    error_code: "database_error",
                    message: format!("CVE-Assessments konnten nicht gelesen werden: {err}"),
                }),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        Json(CveAssessmentRegisterResponse {
            api_version: "v1",
            tenant_id: context.tenant_id,
            summary,
            assessments,
        }),
    )
        .into_response()
}

fn cve_assessment_write_error_response(err: anyhow::Error) -> Response {
    let raw_message = err.to_string();
    let (status, error_code, message) =
        if let Some(message) = raw_message.strip_prefix("validation:") {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_assessment_input",
                message.trim().to_string(),
            )
        } else if let Some(message) = raw_message.strip_prefix("not_found:cve:") {
            (
                StatusCode::NOT_FOUND,
                "cve_not_found",
                message.trim().to_string(),
            )
        } else if let Some(message) = raw_message.strip_prefix("not_found:product:") {
            (
                StatusCode::NOT_FOUND,
                "product_not_found",
                message.trim().to_string(),
            )
        } else if let Some(message) = raw_message.strip_prefix("not_found:release:") {
            (
                StatusCode::NOT_FOUND,
                "release_not_found",
                message.trim().to_string(),
            )
        } else if let Some(message) = raw_message.strip_prefix("not_found:component:") {
            (
                StatusCode::NOT_FOUND,
                "component_not_found",
                message.trim().to_string(),
            )
        } else if let Some(message) = raw_message.strip_prefix("database_error:") {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                message.trim().to_string(),
            )
        } else {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                format!("CVE-Assessment konnte nicht gespeichert werden: {raw_message}"),
            )
        };

    (
        status,
        Json(ApiErrorResponse {
            accepted: false,
            api_version: "v1",
            error_code,
            message,
        }),
    )
        .into_response()
}

async fn cve_assessment_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<cve_store::CveAssessmentWriteRequest>,
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

    match store.upsert_assessment(context.tenant_id, payload).await {
        Ok(result) => (
            if result.created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            Json(CveAssessmentWriteResponse {
                accepted: true,
                api_version: "v1",
                created: result.created,
                assessment: result.assessment,
            }),
        )
            .into_response(),
        Err(err) => cve_assessment_write_error_response(err),
    }
}

async fn cve_assessment_detail(
    Path(assessment_id): Path<i64>,
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

    match store
        .assessment_detail(context.tenant_id, assessment_id)
        .await
    {
        Ok(Some(assessment)) => (
            StatusCode::OK,
            Json(CveAssessmentDetailResponse {
                api_version: "v1",
                assessment,
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "cve_assessment_not_found",
                message: format!("CVE-Assessment '{}' wurde nicht gefunden.", assessment_id),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                accepted: false,
                api_version: "v1",
                error_code: "database_error",
                message: format!("CVE-Assessment konnte nicht gelesen werden: {err}"),
            }),
        )
            .into_response(),
    }
}

async fn nvd_normalize(Json(payload): Json<NvdImportRequest>) -> Response {
    nvd_normalize_response(payload)
}

async fn nvd_import(
    State(state): State<AppState>,
    Json(payload): Json<NvdImportRequest>,
) -> Response {
    let normalized = match validated_cve_id(&payload.cve_id) {
        Ok(normalized) => normalized,
        Err(err) => return err.into_response(),
    };
    let Some(store) = state.cve_store.as_ref() else {
        return api_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_not_configured",
            "Rust-CVE-Store ist nicht konfiguriert.",
        );
    };
    let raw_payload = match fetch_nvd_payload(&state, &normalized).await {
        Ok(payload) => payload,
        Err(response) => return response,
    };
    let Some(cve) = first_nvd_cve(&raw_payload) else {
        return api_error_response(
            StatusCode::NOT_FOUND,
            "cve_not_found",
            format!("Keine CVE-Daten fuer {normalized} gefunden."),
        );
    };
    let record = NvdCveRecord::from_nvd_value(&cve, &raw_payload, &normalized)
        .with_cve_id(normalized.clone());
    if let Err(err) = store.upsert_nvd_cve(&record).await {
        return api_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            format!("CVE konnte nicht persistiert werden: {err}"),
        );
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

async fn nvd_upsert(
    State(state): State<AppState>,
    Json(payload): Json<NvdPersistRequest>,
) -> Response {
    let raw_payload = payload.raw_payload.unwrap_or_else(|| payload.cve.clone());
    let fallback_cve_id = payload.cve_id.as_deref().unwrap_or("");
    let record = NvdCveRecord::from_nvd_value(&payload.cve, &raw_payload, fallback_cve_id);
    let normalized = match validated_cve_id(&record.cve_id) {
        Ok(normalized) => normalized,
        Err(err) => return err.into_response(),
    };

    let Some(store) = state.cve_store.as_ref() else {
        return api_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_not_configured",
            "Rust-CVE-Store ist nicht konfiguriert.",
        );
    };

    let record = record.with_cve_id(normalized.clone());
    if let Err(err) = store.upsert_nvd_cve(&record).await {
        return api_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            format!("CVE konnte nicht persistiert werden: {err}"),
        );
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

fn llm_runtime_info() -> LlmRuntimeInfo {
    let model_name = std::env::var("LOCAL_LLM_MODEL_NAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "iscy-rust-llm-stub-v1".to_string());
    let model_path = std::env::var("LOCAL_LLM_MODEL_PATH")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let n_ctx = std::env::var("LOCAL_LLM_N_CTX")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(8192);
    let n_threads = std::env::var("LOCAL_LLM_N_THREADS")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(4);
    let n_gpu_layers = std::env::var("LOCAL_LLM_N_GPU_LAYERS")
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
        .unwrap_or(0);
    LlmRuntimeInfo {
        backend: "rust_service",
        model_name,
        model_path,
        import_ok: true,
        runtime_ok: true,
        n_ctx,
        n_threads,
        n_gpu_layers,
        note: "Rust-only Session nutzt aktuell den integrierten lokalen Stub fuer CVE-Enrichment und Runtime-Tests.".to_string(),
        error: None,
    }
}

fn llm_test_default_prompt() -> &'static str {
    "Return exactly this JSON: {\"status\":\"ok\",\"message\":\"local-llm-ready\"}"
}

fn llm_generate_result(prompt: &str, max_tokens: u32) -> LlmGenerateResponse {
    let excerpt: String = prompt.chars().take(240).collect();
    LlmGenerateResponse {
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
    }
}

async fn llm_generate(Json(payload): Json<LlmGenerateRequest>) -> Json<LlmGenerateResponse> {
    Json(llm_generate_result(
        &payload.prompt,
        payload.max_tokens.unwrap_or(900),
    ))
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
    let security_config = state.security_config.clone();
    Router::new()
        .route("/health", get(health_live))
        .route("/health/ready", get(health_live))
        .route("/health/live", get(health_live))
        .route("/metrics", get(status_operations_metrics))
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
            get(organization_tenant_profile).patch(organization_tenant_profile_update),
        )
        .route("/api/v1/catalog/domains", get(catalog_domains))
        .route("/api/v1/controls", get(control_library))
        .route(
            "/api/v1/controls/{control_id}/status",
            patch(control_status_update),
        )
        .route(
            "/api/v1/controls/roadmap/generate",
            post(control_roadmap_generate),
        )
        .route("/api/v1/dashboard/summary", get(dashboard_summary))
        .route("/api/v1/status/operations", get(status_operations_json))
        .route("/api/v1/status/metrics", get(status_operations_metrics))
        .route(
            "/api/v1/operations/alertmanager",
            post(operations_alertmanager_webhook),
        )
        .route("/api/v1/agents/posture", get(agent_posture))
        .route("/api/v1/agents/devices", get(agent_devices))
        .route(
            "/api/v1/agents/enrollment-tokens",
            post(agent_enrollment_token_create),
        )
        .route("/api/v1/agents/enroll", post(agent_enroll))
        .route(
            "/api/v1/agents/devices/{device_id}/heartbeat",
            post(agent_heartbeat),
        )
        .route(
            "/api/v1/agents/devices/{device_id}/findings",
            get(agent_device_findings).post(agent_findings),
        )
        .route("/api/v1/assets/information-assets", get(asset_inventory))
        .route("/api/v1/suppliers", get(supplier_risk_overview))
        .route("/api/v1/suppliers/{supplier_id}", get(supplier_risk_detail))
        .route("/api/v1/processes", get(process_register))
        .route("/api/v1/processes/{process_id}", get(process_detail))
        .route(
            "/api/v1/ai-governance/systems",
            get(ai_governance_overview).post(ai_governance_create_system),
        )
        .route(
            "/api/v1/ai-governance/systems/{system_id}",
            get(ai_governance_detail).patch(ai_governance_update_system),
        )
        .route(
            "/api/v1/product-security/overview",
            get(product_security_overview),
        )
        .route(
            "/api/v1/product-security/trends",
            get(product_security_trends),
        )
        .route(
            "/api/v1/product-security/products/{product_id}",
            get(product_security_product_detail),
        )
        .route(
            "/api/v1/product-security/products/{product_id}/cra-readiness",
            get(product_security_product_cra_readiness),
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
        .route(
            "/api/v1/product-security/import/csaf",
            post(product_security_csaf_import),
        )
        .route(
            "/api/v1/product-security/import/sbom",
            post(product_security_sbom_import),
        )
        .route(
            "/api/v1/product-security/imports/export.csv",
            get(product_security_import_history_export_csv),
        )
        .route(
            "/api/v1/product-security/imports/export.json",
            get(product_security_import_history_export_json),
        )
        .route(
            "/api/v1/product-security/imports/{artifact_id}",
            get(product_security_import_detail),
        )
        .route(
            "/api/v1/product-security/sbom-diff",
            get(product_security_sbom_diff),
        )
        .route(
            "/api/v1/product-security/cve-correlations",
            post(product_security_cve_correlations),
        )
        .route(
            "/api/v1/product-security/cve-correlations/generate-work",
            post(product_security_cve_correlation_generate_work),
        )
        .route(
            "/api/v1/product-security/cve-correlations/{correlation_id}",
            patch(product_security_cve_correlation_update),
        )
        .route("/api/v1/risks", get(risk_register).post(risk_create))
        .route("/api/v1/risks/{risk_id}/review", post(risk_review))
        .route(
            "/api/v1/risks/{risk_id}",
            get(risk_detail).patch(risk_update),
        )
        .route(
            "/api/v1/incidents",
            get(incident_register).post(incident_create),
        )
        .route(
            "/api/v1/incidents/runbook-templates",
            get(incident_runbook_templates),
        )
        .route(
            "/api/v1/incidents/{incident_id}",
            get(incident_detail).patch(incident_update),
        )
        .route(
            "/api/v1/incidents/{incident_id}/timeline-notes",
            post(incident_timeline_note_create),
        )
        .route(
            "/api/v1/incidents/{incident_id}/nis2-export",
            get(incident_nis2_export),
        )
        .route(
            "/api/v1/incidents/{incident_id}/nis2-export.html",
            get(incident_nis2_export_html),
        )
        .route(
            "/api/v1/incidents/{incident_id}/nis2-export.pdf",
            get(incident_nis2_export_pdf),
        )
        .route(
            "/api/v1/incidents/{incident_id}/dora-export",
            get(incident_dora_export),
        )
        .route(
            "/api/v1/incidents/{incident_id}/dora-export.html",
            get(incident_dora_export_html),
        )
        .route(
            "/api/v1/incidents/{incident_id}/dora-export.pdf",
            get(incident_dora_export_pdf),
        )
        .route(
            "/api/v1/incidents/{incident_id}/dsgvo-export",
            get(incident_dsgvo_export),
        )
        .route(
            "/api/v1/incidents/{incident_id}/dsgvo-export.html",
            get(incident_dsgvo_export_html),
        )
        .route(
            "/api/v1/incidents/{incident_id}/dsgvo-export.pdf",
            get(incident_dsgvo_export_pdf),
        )
        .route(
            "/api/v1/incidents/{incident_id}/timeline.csv",
            get(incident_timeline_export_csv),
        )
        .route(
            "/api/v1/incidents/{incident_id}/timeline.json",
            get(incident_timeline_export_json),
        )
        .route("/api/v1/evidence", get(evidence_overview))
        .route("/api/v1/evidence/quality", get(evidence_quality))
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
        .route(
            "/api/v1/reports/management-reviews",
            get(management_review_packages).post(management_review_generate),
        )
        .route(
            "/api/v1/reports/management-reviews/{review_id}",
            get(management_review_detail).patch(management_review_status_update),
        )
        .route(
            "/api/v1/reports/management-reviews/{review_id}/export",
            get(management_review_export_markdown),
        )
        .route(
            "/api/v1/reports/management-reviews/{review_id}/export.html",
            get(management_review_export_html),
        )
        .route(
            "/api/v1/reports/management-reviews/{review_id}/export.pdf",
            get(management_review_export_pdf),
        )
        .route(
            "/api/v1/reports/management-reviews/{review_id}/export.json",
            get(management_review_export_json),
        )
        .route("/api/v1/cves", get(cve_feed))
        .route("/api/v1/cves/{cve_id}", get(cve_detail))
        .route(
            "/api/v1/cve-assessments",
            get(cve_assessment_register).post(cve_assessment_create),
        )
        .route(
            "/api/v1/cve-assessments/{assessment_id}",
            get(cve_assessment_detail),
        )
        .route("/api/v1/requirements", get(requirement_library))
        .route("/", get(web_index))
        .route("/login/", get(web_login).post(web_login_submit))
        .route("/navigator/", get(web_navigator))
        .route("/dashboard/", get(web_dashboard))
        .route("/status/", get(web_status))
        .route("/status/operations.json", get(status_operations_json))
        .route(
            "/status/control-gaps/generate",
            post(web_status_control_gaps_generate_submit),
        )
        .route("/operations/incidents/", get(web_operations_incidents))
        .route("/zero-trust/", get(web_zero_trust))
        .route("/incidents/", get(web_incidents).post(web_incidents_submit))
        .route(
            "/incidents/runbook-templates/",
            get(web_incident_runbook_templates).post(web_incident_runbook_templates_submit),
        )
        .route(
            "/incidents/runbook-templates/{template_id}",
            post(web_incident_runbook_template_update),
        )
        .route(
            "/incidents/{incident_id}",
            get(web_incident_detail).post(web_incident_detail_submit),
        )
        .route(
            "/incidents/{incident_id}/runbook-steps/{step_id}",
            post(web_incident_runbook_step_submit),
        )
        .route(
            "/incidents/{incident_id}/review",
            post(web_incident_review_submit),
        )
        .route(
            "/incidents/{incident_id}/timeline-events/{event_id}",
            post(web_incident_timeline_event_marker_submit),
        )
        .route(
            "/incidents/{incident_id}/timeline-notes",
            post(web_incident_timeline_note_submit),
        )
        .route(
            "/incidents/{incident_id}/nis2-export",
            get(web_incident_nis2_export),
        )
        .route(
            "/incidents/{incident_id}/nis2-export.html",
            get(web_incident_nis2_export_html),
        )
        .route(
            "/incidents/{incident_id}/nis2-export.pdf",
            get(web_incident_nis2_export_pdf),
        )
        .route(
            "/incidents/{incident_id}/dora-export",
            get(web_incident_dora_export),
        )
        .route(
            "/incidents/{incident_id}/dora-export.html",
            get(web_incident_dora_export_html),
        )
        .route(
            "/incidents/{incident_id}/dora-export.pdf",
            get(web_incident_dora_export_pdf),
        )
        .route(
            "/incidents/{incident_id}/dsgvo-export",
            get(web_incident_dsgvo_export),
        )
        .route(
            "/incidents/{incident_id}/dsgvo-export.html",
            get(web_incident_dsgvo_export_html),
        )
        .route(
            "/incidents/{incident_id}/dsgvo-export.pdf",
            get(web_incident_dsgvo_export_pdf),
        )
        .route(
            "/incidents/{incident_id}/timeline.csv",
            get(web_incident_timeline_export_csv),
        )
        .route(
            "/incidents/{incident_id}/timeline.json",
            get(web_incident_timeline_export_json),
        )
        .route("/controls/", get(web_controls))
        .route(
            "/controls/{control_id}/status",
            post(web_control_status_submit),
        )
        .route(
            "/controls/roadmap/generate",
            post(web_control_roadmap_generate_submit),
        )
        .route("/catalog/", get(web_catalog))
        .route("/reports/", get(web_reports))
        .route(
            "/management-reviews/",
            get(web_management_reviews).post(web_management_reviews_generate),
        )
        .route(
            "/management-reviews/{review_id}",
            get(web_management_review_detail),
        )
        .route(
            "/management-reviews/{review_id}/status",
            post(web_management_review_status_submit),
        )
        .route(
            "/management-reviews/{review_id}/export",
            get(web_management_review_export_markdown),
        )
        .route(
            "/management-reviews/{review_id}/export.html",
            get(web_management_review_export_html),
        )
        .route(
            "/management-reviews/{review_id}/export.pdf",
            get(web_management_review_export_pdf),
        )
        .route(
            "/management-reviews/{review_id}/export.json",
            get(web_management_review_export_json),
        )
        .route("/roadmap/", get(web_roadmap))
        .route("/evidence/", get(web_evidence).post(web_evidence_upload))
        .route("/evidence/quality/", get(web_evidence_quality))
        .route("/assets/", get(web_assets))
        .route("/suppliers/", get(web_suppliers))
        .route("/imports/", get(web_imports).post(web_imports_submit))
        .route("/imports/preview/", post(web_imports_preview_submit))
        .route("/processes/", get(web_processes))
        .route("/requirements/", get(web_requirements))
        .route("/risks/", get(web_risks))
        .route("/risks/{risk_id}/review", post(web_risk_review_submit))
        .route("/assessments/", get(web_assessments))
        .route(
            "/organizations/",
            get(web_organizations).post(web_organizations_submit),
        )
        .route(
            "/admin/users/",
            get(web_admin_users).post(web_admin_users_submit),
        )
        .route("/admin/users/{user_id}", post(web_admin_user_update))
        .route(
            "/ai-governance/",
            get(web_ai_governance).post(web_ai_governance_create_system),
        )
        .route(
            "/ai-governance/systems",
            post(web_ai_governance_create_system),
        )
        .route(
            "/ai-governance/systems/{system_id}",
            post(web_ai_governance_update_system),
        )
        .route("/product-security/", get(web_product_security))
        .route(
            "/product-security/thresholds",
            post(web_product_security_thresholds_submit),
        )
        .route(
            "/product-security/import/csaf",
            post(web_product_security_import_csaf),
        )
        .route(
            "/product-security/import/sbom",
            post(web_product_security_import_sbom),
        )
        .route(
            "/product-security/imports.csv",
            get(web_product_security_imports_csv),
        )
        .route(
            "/product-security/imports.json",
            get(web_product_security_imports_json),
        )
        .route(
            "/product-security/imports/{artifact_id}",
            get(web_product_security_import_detail),
        )
        .route(
            "/product-security/sbom-diff",
            get(web_product_security_sbom_diff),
        )
        .route(
            "/product-security/cve-correlations",
            post(web_product_security_cve_correlations_submit),
        )
        .route(
            "/product-security/cve-correlations/generate-work",
            post(web_product_security_cve_correlation_generate_work),
        )
        .route(
            "/product-security/cve-risk-reviews/bulk",
            post(web_product_security_cve_reviews_bulk),
        )
        .route(
            "/product-security/cve-correlations/{correlation_id}",
            post(web_product_security_cve_correlation_update),
        )
        .route("/cves/", get(web_cves).post(web_cves_submit))
        .route(
            "/cves/llm-test/",
            get(web_cve_llm_test).post(web_cve_llm_test_submit),
        )
        .route(
            "/cves/assessments/{assessment_id}",
            get(web_cve_assessment_detail),
        )
        .route("/cves/{assessment_id}/", get(web_cve_assessment_detail))
        .route("/api/v1/nvd/normalize", post(nvd_normalize))
        .route("/api/v1/nvd/import", post(nvd_import))
        .route("/api/v1/nvd/upsert", post(nvd_upsert))
        .route("/api/v1/llm/generate", post(llm_generate))
        .route("/api/v1/risk/priority", post(risk_priority))
        .route("/api/v1/guidance/evaluate", post(guidance_evaluate))
        .route("/api/v1/reports/cve-summary", post(report_cve_summary))
        .layer(DefaultBodyLimit::max(MULTIPART_FORM_BODY_LIMIT_BYTES))
        .layer(middleware::from_fn_with_state(
            security_config,
            hardening::community_security_headers,
        ))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use hmac::Mac;

    use super::{
        alertmanager_hmac_message, alertmanager_hmac_secret_matches, hex_encode_bytes,
        normalize_cve_id, AlertmanagerHmacSha256,
    };

    #[test]
    fn normalize_cve_id_uppercases_and_trims() {
        assert_eq!(normalize_cve_id(" cve-2026-1234 "), "CVE-2026-1234");
    }

    #[test]
    fn alertmanager_hmac_matches_timestamp_and_body() {
        let message = alertmanager_hmac_message("1800000000", br#"{"status":"firing"}"#);
        let mut mac = AlertmanagerHmacSha256::new_from_slice(b"strong-alert-secret").unwrap();
        mac.update(&message);
        let signature = hex_encode_bytes(&mac.finalize().into_bytes());

        assert!(alertmanager_hmac_secret_matches(
            "strong-alert-secret",
            &message,
            &signature
        ));
        assert!(!alertmanager_hmac_secret_matches(
            "wrong-secret",
            &message,
            &signature
        ));
    }
}
