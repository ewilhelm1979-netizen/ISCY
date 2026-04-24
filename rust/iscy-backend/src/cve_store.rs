use std::str::FromStr;

use anyhow::{bail, Context};
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{
    postgres::{PgPool, PgPoolOptions},
    sqlite::{SqlitePool, SqlitePoolOptions},
    types::Json,
    Row,
};

#[derive(Clone)]
pub enum CveStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone)]
pub struct NvdCveRecord {
    pub cve_id: String,
    pub description: String,
    pub cvss_score: Option<Decimal>,
    pub cvss_vector: String,
    pub severity: String,
    pub weakness_ids_json: Value,
    pub references_json: Value,
    pub configurations_json: Value,
    pub raw_json: Value,
    pub published_at: Option<DateTime<Utc>>,
    pub modified_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CveDashboardSummary {
    pub total: i64,
    pub critical: i64,
    pub high: i64,
    pub kev: i64,
    pub known_ransomware: i64,
    pub with_epss: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CveRecordSummary {
    pub id: i64,
    pub cve_id: String,
    pub source: String,
    pub description: String,
    pub cvss_score: Option<String>,
    pub cvss_vector: String,
    pub severity: String,
    pub severity_label: String,
    pub epss_score: Option<String>,
    pub in_kev_catalog: bool,
    pub kev_known_ransomware: bool,
    pub published_at: Option<String>,
    pub modified_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CveRecordDetail {
    pub id: i64,
    pub cve_id: String,
    pub source: String,
    pub description: String,
    pub cvss_score: Option<String>,
    pub cvss_vector: String,
    pub severity: String,
    pub severity_label: String,
    pub weakness_ids: Vec<String>,
    pub references: Vec<String>,
    pub configurations_json: Value,
    pub epss_score: Option<String>,
    pub in_kev_catalog: bool,
    pub kev_date_added: Option<String>,
    pub kev_vendor_project: String,
    pub kev_product: String,
    pub kev_required_action: String,
    pub kev_known_ransomware: bool,
    pub raw_json: Value,
    pub published_at: Option<String>,
    pub modified_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CveAssessmentDashboardSummary {
    pub total: i64,
    pub critical: i64,
    pub with_risk: i64,
    pub llm_generated: i64,
    pub nis2: i64,
    pub kev: i64,
    pub risk_hotspot_score: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CveAssessmentSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub cve_id: String,
    pub cve_description: String,
    pub cve_severity: String,
    pub cve_severity_label: String,
    pub cve_cvss_score: Option<String>,
    pub product_id: Option<i64>,
    pub product_name: Option<String>,
    pub release_id: Option<i64>,
    pub release_version: Option<String>,
    pub component_id: Option<i64>,
    pub component_name: Option<String>,
    pub linked_vulnerability_id: Option<i64>,
    pub linked_vulnerability_title: Option<String>,
    pub related_risk_id: Option<i64>,
    pub related_risk_title: Option<String>,
    pub exposure: String,
    pub exposure_label: String,
    pub asset_criticality: String,
    pub asset_criticality_label: String,
    pub epss_score: Option<String>,
    pub in_kev_catalog: bool,
    pub exploit_maturity: String,
    pub exploit_maturity_label: String,
    pub affects_critical_service: bool,
    pub nis2_relevant: bool,
    pub deterministic_priority: String,
    pub llm_status: String,
    pub llm_status_label: String,
    pub deterministic_due_days: i64,
    pub confidence: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CveAssessmentDetail {
    #[serde(flatten)]
    pub summary: CveAssessmentSummary,
    pub cvss_vector: String,
    pub weakness_ids: Vec<String>,
    pub references: Vec<String>,
    pub kev_date_added: Option<String>,
    pub kev_vendor_project: String,
    pub kev_product: String,
    pub kev_required_action: String,
    pub kev_known_ransomware: bool,
    pub repository_name: String,
    pub repository_url: String,
    pub git_ref: String,
    pub source_package: String,
    pub source_package_version: String,
    pub regulatory_tags: Vec<String>,
    pub deterministic_factors_json: Value,
    pub nis2_impact_summary: String,
    pub business_context: String,
    pub existing_controls: String,
    pub llm_backend: String,
    pub llm_model_name: String,
    pub technical_summary: String,
    pub business_impact: String,
    pub attack_path: String,
    pub management_summary: String,
    pub recommended_actions: Vec<String>,
    pub evidence_needed: Vec<String>,
    pub raw_llm_json: Value,
    pub reviewed_by_display: Option<String>,
    pub reviewed_at: Option<String>,
    pub review_notes: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CveAssessmentWriteRequest {
    pub cve_id: String,
    pub product_id: Option<i64>,
    pub release_id: Option<i64>,
    pub component_id: Option<i64>,
    pub exposure: Option<String>,
    pub asset_criticality: Option<String>,
    pub epss_score: Option<f64>,
    pub in_kev_catalog: Option<bool>,
    pub exploit_maturity: Option<String>,
    #[serde(default)]
    pub affects_critical_service: bool,
    pub nis2_relevant: Option<bool>,
    pub nis2_impact_summary: Option<String>,
    pub repository_name: Option<String>,
    pub repository_url: Option<String>,
    pub git_ref: Option<String>,
    pub source_package: Option<String>,
    pub source_package_version: Option<String>,
    #[serde(default)]
    pub regulatory_tags: Vec<String>,
    pub business_context: Option<String>,
    pub existing_controls: Option<String>,
    #[serde(default = "bool_true")]
    pub auto_create_risk: bool,
    #[serde(default = "bool_true")]
    pub run_llm: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CveAssessmentWriteResult {
    pub created: bool,
    pub assessment: CveAssessmentDetail,
}

#[derive(Debug, Clone, Serialize)]
pub struct CveAssessmentFormOptions {
    pub products: Vec<CveAssessmentProductOption>,
    pub releases: Vec<CveAssessmentReleaseOption>,
    pub components: Vec<CveAssessmentComponentOption>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CveAssessmentProductOption {
    pub id: i64,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CveAssessmentReleaseOption {
    pub id: i64,
    pub product_id: i64,
    pub version: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CveAssessmentComponentOption {
    pub id: i64,
    pub product_id: i64,
    pub name: String,
    pub version: String,
    pub label: String,
}

impl CveStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer CVE-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer CVE-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-CVE-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn dashboard_summary(&self) -> anyhow::Result<CveDashboardSummary> {
        match self {
            Self::Postgres(pool) => dashboard_summary_postgres(pool).await,
            Self::Sqlite(pool) => dashboard_summary_sqlite(pool).await,
        }
    }

    pub async fn list_recent(&self, limit: i64) -> anyhow::Result<Vec<CveRecordSummary>> {
        match self {
            Self::Postgres(pool) => list_recent_postgres(pool, limit).await,
            Self::Sqlite(pool) => list_recent_sqlite(pool, limit).await,
        }
    }

    pub async fn detail(&self, cve_id: &str) -> anyhow::Result<Option<CveRecordDetail>> {
        match self {
            Self::Postgres(pool) => detail_postgres(pool, cve_id).await,
            Self::Sqlite(pool) => detail_sqlite(pool, cve_id).await,
        }
    }

    pub async fn assessment_dashboard_summary(
        &self,
        tenant_id: i64,
    ) -> anyhow::Result<CveAssessmentDashboardSummary> {
        match self {
            Self::Postgres(pool) => assessment_dashboard_summary_postgres(pool, tenant_id).await,
            Self::Sqlite(pool) => assessment_dashboard_summary_sqlite(pool, tenant_id).await,
        }
    }

    pub async fn list_assessments(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<CveAssessmentSummary>> {
        match self {
            Self::Postgres(pool) => list_assessments_postgres(pool, tenant_id, limit).await,
            Self::Sqlite(pool) => list_assessments_sqlite(pool, tenant_id, limit).await,
        }
    }

    pub async fn assessment_detail(
        &self,
        tenant_id: i64,
        assessment_id: i64,
    ) -> anyhow::Result<Option<CveAssessmentDetail>> {
        match self {
            Self::Postgres(pool) => {
                assessment_detail_postgres(pool, tenant_id, assessment_id).await
            }
            Self::Sqlite(pool) => assessment_detail_sqlite(pool, tenant_id, assessment_id).await,
        }
    }

    pub async fn upsert_assessment(
        &self,
        tenant_id: i64,
        payload: CveAssessmentWriteRequest,
    ) -> anyhow::Result<CveAssessmentWriteResult> {
        match self {
            Self::Postgres(pool) => upsert_assessment_postgres(pool, tenant_id, payload).await,
            Self::Sqlite(pool) => upsert_assessment_sqlite(pool, tenant_id, payload).await,
        }
    }

    pub async fn assessment_form_options(
        &self,
        tenant_id: i64,
    ) -> anyhow::Result<CveAssessmentFormOptions> {
        match self {
            Self::Postgres(pool) => assessment_form_options_postgres(pool, tenant_id).await,
            Self::Sqlite(pool) => assessment_form_options_sqlite(pool, tenant_id).await,
        }
    }

    pub async fn upsert_nvd_cve(&self, record: &NvdCveRecord) -> anyhow::Result<()> {
        match self {
            Self::Postgres(pool) => upsert_postgres(pool, record).await,
            Self::Sqlite(pool) => upsert_sqlite(pool, record).await,
        }
    }
}

impl NvdCveRecord {
    pub fn from_nvd_value(cve_payload: &Value, raw_payload: &Value, fallback_cve_id: &str) -> Self {
        let cve = cve_payload.get("cve").unwrap_or(cve_payload);
        let cve_id = cve
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or(fallback_cve_id)
            .trim()
            .to_string();
        let (cvss_score, cvss_vector, severity) =
            cvss_fields(cve.get("metrics").unwrap_or(&Value::Null));

        Self {
            cve_id,
            description: description(cve),
            cvss_score,
            cvss_vector,
            severity,
            weakness_ids_json: json!(weakness_ids(cve)),
            references_json: json!(references(cve)),
            configurations_json: cve
                .get("configurations")
                .cloned()
                .unwrap_or_else(|| json!([])),
            raw_json: raw_payload.clone(),
            published_at: parse_nvd_datetime(cve.get("published")),
            modified_at: parse_nvd_datetime(cve.get("lastModified")),
        }
    }

    pub fn with_cve_id(mut self, cve_id: String) -> Self {
        self.cve_id = cve_id;
        self
    }
}

pub fn normalize_database_url(database_url: &str) -> String {
    let trimmed = database_url.trim();
    if let Some(path) = trimmed.strip_prefix("sqlite:///") {
        if path.starts_with('/') {
            trimmed.to_string()
        } else {
            format!("sqlite://{path}")
        }
    } else {
        trimmed.to_string()
    }
}

#[derive(Debug, Clone)]
struct NormalizedAssessmentWriteRequest {
    cve_id: String,
    product_id: Option<i64>,
    release_id: Option<i64>,
    component_id: Option<i64>,
    exposure: String,
    asset_criticality: String,
    epss_score: Option<Decimal>,
    in_kev_catalog: Option<bool>,
    exploit_maturity: String,
    affects_critical_service: bool,
    nis2_relevant: Option<bool>,
    nis2_impact_summary: String,
    repository_name: String,
    repository_url: String,
    git_ref: String,
    source_package: String,
    source_package_version: String,
    regulatory_tags: Vec<String>,
    business_context: String,
    existing_controls: String,
    auto_create_risk: bool,
    run_llm: bool,
}

#[derive(Debug, Clone)]
struct CveRecordContext {
    id: i64,
    cve_id: String,
    description: String,
    severity: String,
    cvss_score: Option<Decimal>,
    epss_score: Option<Decimal>,
    in_kev_catalog: bool,
}

#[derive(Debug, Clone)]
struct ProductRecord {
    id: i64,
    name: String,
}

#[derive(Debug, Clone)]
struct ReleaseRecord {
    id: i64,
    product_id: i64,
}

#[derive(Debug, Clone)]
struct ComponentRecord {
    id: i64,
    product_id: i64,
}

#[derive(Debug, Clone)]
struct ExistingAssessmentState {
    id: i64,
    linked_vulnerability_id: Option<i64>,
    related_risk_id: Option<i64>,
    technical_summary: String,
    business_impact: String,
    attack_path: String,
    management_summary: String,
    recommended_actions: Vec<String>,
    evidence_needed: Vec<String>,
    raw_llm_json: Value,
    confidence: String,
    prompt_hash: String,
}

#[derive(Debug, Clone)]
struct DeterministicPriorityResult {
    priority: String,
    due_days: i64,
    factors_json: Value,
}

#[derive(Debug, Clone)]
struct DeterministicPriorityInput<'a> {
    cve: &'a CveRecordContext,
    exposure: &'a str,
    asset_criticality: &'a str,
    epss_score: Option<Decimal>,
    in_kev_catalog: bool,
    exploit_maturity: &'a str,
    affects_critical_service: bool,
    nis2_relevant: bool,
}

#[derive(Debug, Clone)]
struct LlmAssessmentResult {
    backend: String,
    model_name: String,
    status: String,
    technical_summary: String,
    business_impact: String,
    attack_path: String,
    management_summary: String,
    recommended_actions: Vec<String>,
    evidence_needed: Vec<String>,
    raw_json: Value,
    confidence: String,
    prompt_hash: String,
}

#[derive(Debug, Clone)]
struct AssessmentWriteFields {
    cve_record_id: i64,
    product_id: Option<i64>,
    release_id: Option<i64>,
    component_id: Option<i64>,
    linked_vulnerability_id: Option<i64>,
    related_risk_id: Option<i64>,
    exposure: String,
    asset_criticality: String,
    epss_score: Option<Decimal>,
    in_kev_catalog: bool,
    exploit_maturity: String,
    affects_critical_service: bool,
    nis2_relevant: bool,
    nis2_impact_summary: String,
    repository_name: String,
    repository_url: String,
    git_ref: String,
    source_package: String,
    source_package_version: String,
    regulatory_tags: Vec<String>,
    deterministic_factors_json: Value,
    business_context: String,
    existing_controls: String,
    deterministic_priority: String,
    deterministic_due_days: i64,
    llm_backend: String,
    llm_model_name: String,
    llm_status: String,
    technical_summary: String,
    business_impact: String,
    attack_path: String,
    management_summary: String,
    recommended_actions: Vec<String>,
    evidence_needed: Vec<String>,
    raw_llm_json: Value,
    confidence: String,
    prompt_hash: String,
}

fn bool_true() -> bool {
    true
}

fn normalize_assessment_write_request(
    payload: CveAssessmentWriteRequest,
) -> anyhow::Result<NormalizedAssessmentWriteRequest> {
    let cve_id = payload.cve_id.trim().to_uppercase();
    if cve_id.is_empty() {
        bail!("validation:CVE-ID darf nicht leer sein.");
    }
    if !crate::is_valid_cve_id(&cve_id) {
        bail!(
            "validation:CVE-ID '{}' entspricht nicht dem erwarteten Format CVE-YYYY-NNNN.",
            cve_id
        );
    }

    let epss_score = match payload.epss_score {
        Some(score) if !(0.0..=1.0).contains(&score) => {
            bail!("validation:EPSS-Score muss zwischen 0.0 und 1.0 liegen.");
        }
        Some(score) => Some(
            Decimal::from_str(&score.to_string())
                .context("validation:EPSS-Score konnte nicht verarbeitet werden.")?,
        ),
        None => None,
    };

    Ok(NormalizedAssessmentWriteRequest {
        cve_id,
        product_id: payload.product_id.filter(|value| *value > 0),
        release_id: payload.release_id.filter(|value| *value > 0),
        component_id: payload.component_id.filter(|value| *value > 0),
        exposure: normalize_exposure(payload.exposure.as_deref()),
        asset_criticality: normalize_asset_criticality(payload.asset_criticality.as_deref()),
        epss_score,
        in_kev_catalog: payload.in_kev_catalog,
        exploit_maturity: normalize_exploit_maturity(payload.exploit_maturity.as_deref()),
        affects_critical_service: payload.affects_critical_service,
        nis2_relevant: payload.nis2_relevant,
        nis2_impact_summary: normalize_text_input(payload.nis2_impact_summary, 4000),
        repository_name: normalize_text_input(payload.repository_name, 255),
        repository_url: normalize_text_input(payload.repository_url, 200),
        git_ref: normalize_text_input(payload.git_ref, 128),
        source_package: normalize_text_input(payload.source_package, 255),
        source_package_version: normalize_text_input(payload.source_package_version, 128),
        regulatory_tags: normalize_regulatory_tags(payload.regulatory_tags),
        business_context: normalize_text_input(payload.business_context, 8000),
        existing_controls: normalize_text_input(payload.existing_controls, 8000),
        auto_create_risk: payload.auto_create_risk,
        run_llm: payload.run_llm,
    })
}

fn normalize_text_input(value: Option<String>, max_chars: usize) -> String {
    let mut normalized = value.unwrap_or_default().trim().to_string();
    if normalized.chars().count() > max_chars {
        normalized = normalized.chars().take(max_chars).collect();
    }
    normalized
}

fn normalize_regulatory_tags(values: Vec<String>) -> Vec<String> {
    let mut tags = Vec::new();
    for value in values {
        let normalized = value.trim();
        if normalized.is_empty() {
            continue;
        }
        if tags.iter().any(|item| item == normalized) {
            continue;
        }
        tags.push(normalized.to_string());
    }
    tags
}

fn ensure_nis2_tag(mut values: Vec<String>, nis2_relevant: bool) -> Vec<String> {
    if nis2_relevant && !values.iter().any(|value| value == "NIS2") {
        values.push("NIS2".to_string());
    }
    values
}

fn normalize_exposure(value: Option<&str>) -> String {
    match value.unwrap_or("UNKNOWN").trim().to_uppercase().as_str() {
        "INTERNET" | "CUSTOMER" | "INTERNAL" => value.unwrap().trim().to_uppercase(),
        _ => "UNKNOWN".to_string(),
    }
}

fn normalize_asset_criticality(value: Option<&str>) -> String {
    match normalize_severity(value.unwrap_or("MEDIUM")).as_str() {
        "CRITICAL" | "HIGH" | "LOW" => normalize_severity(value.unwrap_or("MEDIUM")),
        "MEDIUM" => "MEDIUM".to_string(),
        _ => "MEDIUM".to_string(),
    }
}

fn normalize_exploit_maturity(value: Option<&str>) -> String {
    match value.unwrap_or("UNKNOWN").trim().to_uppercase().as_str() {
        "UNPROVEN" | "POC" | "ACTIVE" | "AUTOMATED" => value.unwrap().trim().to_uppercase(),
        _ => "UNKNOWN".to_string(),
    }
}

fn llm_backend_name() -> String {
    "RUST_SERVICE".to_string()
}

fn llm_model_name() -> String {
    std::env::var("LOCAL_LLM_MODEL_NAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "iscy-rust-llm-stub-v1".to_string())
}

fn decimal_to_f64(value: Option<Decimal>) -> f64 {
    value
        .and_then(|number| number.to_string().parse::<f64>().ok())
        .unwrap_or(0.0)
}

fn round_two(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn calculate_deterministic_priority(
    input: DeterministicPriorityInput<'_>,
) -> DeterministicPriorityResult {
    let base_score = decimal_to_f64(input.cve.cvss_score);
    let epss_f64 = decimal_to_f64(input.epss_score);
    let mut bump = 0.0_f64;
    let mut drivers = Vec::new();

    match input.exposure {
        "INTERNET" => {
            bump += 1.5;
            drivers.push("internet_exposure");
        }
        "CUSTOMER" => {
            bump += 1.0;
            drivers.push("customer_exposure");
        }
        _ => {}
    }
    match input.asset_criticality {
        "CRITICAL" => {
            bump += 1.5;
            drivers.push("critical_asset");
        }
        "HIGH" => {
            bump += 1.0;
            drivers.push("high_asset");
        }
        _ => {}
    }
    if epss_f64 >= 0.90 {
        bump += 2.0;
        drivers.push("epss_90");
    } else if epss_f64 >= 0.50 {
        bump += 1.0;
        drivers.push("epss_50");
    } else if epss_f64 >= 0.20 {
        bump += 0.5;
        drivers.push("epss_20");
    }
    if input.in_kev_catalog {
        bump += 2.5;
        drivers.push("kev");
    }
    match input.exploit_maturity {
        "AUTOMATED" => {
            bump += 2.0;
            drivers.push("automated_exploit");
        }
        "ACTIVE" => {
            bump += 1.5;
            drivers.push("active_exploit");
        }
        "POC" => {
            bump += 0.5;
            drivers.push("poc_exploit");
        }
        _ => {}
    }
    if input.affects_critical_service {
        bump += 1.5;
        drivers.push("critical_service");
    }
    if input.nis2_relevant {
        bump += 1.0;
        drivers.push("nis2");
    }

    let effective_score = base_score + bump;
    let (priority, due_days) = if effective_score >= 9.5 {
        ("CRITICAL".to_string(), 7)
    } else if effective_score >= 8.0 {
        ("HIGH".to_string(), 14)
    } else if effective_score >= 6.0 {
        ("MEDIUM".to_string(), 30)
    } else {
        ("LOW".to_string(), 60)
    };

    DeterministicPriorityResult {
        priority,
        due_days,
        factors_json: json!({
            "base_score": round_two(base_score),
            "effective_score": round_two(effective_score),
            "bump_total": round_two(bump),
            "drivers": drivers,
            "exposure": input.exposure,
            "asset_criticality": input.asset_criticality,
            "epss_score": input.epss_score.map(|value| value.to_string()),
            "in_kev_catalog": input.in_kev_catalog,
            "exploit_maturity": input.exploit_maturity,
            "affects_critical_service": input.affects_critical_service,
            "nis2_relevant": input.nis2_relevant,
        }),
    }
}

fn build_llm_prompt(
    cve: &CveRecordContext,
    product_name: Option<&str>,
    payload: &NormalizedAssessmentWriteRequest,
    priority: &str,
    due_days: i64,
) -> String {
    format!(
        "CVE={}; product={}; exposure={}; criticality={}; priority={}; due_days={}; business_context={}; controls={}",
        cve.cve_id,
        product_name.unwrap_or("CVE-Risiko"),
        payload.exposure,
        payload.asset_criticality,
        priority,
        due_days,
        payload.business_context,
        payload.existing_controls,
    )
}

fn llm_assessment_result(
    prompt: &str,
    cve: &CveRecordContext,
    product_name: Option<&str>,
) -> LlmAssessmentResult {
    let prompt_hash = format!("{:x}", Sha256::digest(prompt.as_bytes()));
    let product_display = product_name.unwrap_or("CVE-Risiko");
    let technical_summary = format!(
        "{} betrifft {} und sollte gegen reale Versionsstaende validiert werden.",
        cve.cve_id, product_display
    );
    let business_impact = format!(
        "{} kann Betriebs- und Compliance-Auswirkungen fuer {} ausloesen.",
        cve.cve_id, product_display
    );
    let attack_path = if cve.in_kev_catalog {
        "Bekannte Ausnutzung vorhanden; externe Angriffsvektoren priorisieren.".to_string()
    } else {
        "Angriffspfad haengt von Exponierung, erreichbaren Komponenten und wirksamen Kontrollen ab."
            .to_string()
    };
    let management_summary = format!(
        "Patch, Containment und Evidenzsammlung fuer {} zeitnah priorisieren.",
        cve.cve_id
    );
    let recommended_actions = vec![
        "Betroffene Produkte, Releases und Komponenten verifizieren".to_string(),
        "Patch oder kompensierende Massnahme planen und dokumentieren".to_string(),
        "Monitoring und Nachweis fuer Umsetzung sammeln".to_string(),
    ];
    let evidence_needed = vec![
        "Asset- oder Produktinventar mit Versionsstand".to_string(),
        "Patch- oder Change-Nachweis".to_string(),
        "Monitoring- oder Detection-Logs".to_string(),
    ];
    let raw_json = json!({
        "technical_summary": technical_summary,
        "business_impact": business_impact,
        "attack_path": attack_path,
        "management_summary": management_summary,
        "recommended_actions": recommended_actions,
        "evidence_needed": evidence_needed,
        "confidence": "medium",
        "backend": "rust_service",
        "prompt_excerpt": prompt.chars().take(240).collect::<String>(),
    });
    LlmAssessmentResult {
        backend: llm_backend_name(),
        model_name: llm_model_name(),
        status: "GENERATED".to_string(),
        technical_summary: raw_json["technical_summary"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        business_impact: raw_json["business_impact"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        attack_path: raw_json["attack_path"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        management_summary: raw_json["management_summary"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        recommended_actions,
        evidence_needed,
        raw_json,
        confidence: "medium".to_string(),
        prompt_hash,
    }
}

fn existing_or_blank_llm_result(existing: Option<&ExistingAssessmentState>) -> LlmAssessmentResult {
    LlmAssessmentResult {
        backend: llm_backend_name(),
        model_name: llm_model_name(),
        status: "DISABLED".to_string(),
        technical_summary: existing
            .map(|item| item.technical_summary.clone())
            .unwrap_or_default(),
        business_impact: existing
            .map(|item| item.business_impact.clone())
            .unwrap_or_default(),
        attack_path: existing
            .map(|item| item.attack_path.clone())
            .unwrap_or_default(),
        management_summary: existing
            .map(|item| item.management_summary.clone())
            .unwrap_or_default(),
        recommended_actions: existing
            .map(|item| item.recommended_actions.clone())
            .unwrap_or_default(),
        evidence_needed: existing
            .map(|item| item.evidence_needed.clone())
            .unwrap_or_default(),
        raw_json: existing
            .map(|item| item.raw_llm_json.clone())
            .unwrap_or_else(|| json!({})),
        confidence: existing
            .map(|item| item.confidence.clone())
            .unwrap_or_else(|| "medium".to_string()),
        prompt_hash: existing
            .map(|item| item.prompt_hash.clone())
            .unwrap_or_default(),
    }
}

fn risk_title_for(cve_id: &str, product_name: Option<&str>) -> String {
    format!(
        "{} \u{2013} {}",
        cve_id,
        product_name.unwrap_or("CVE-Risiko")
    )
}

fn risk_title_legacy_for(cve_id: &str, product_name: Option<&str>) -> String {
    format!("{} - {}", cve_id, product_name.unwrap_or("CVE-Risiko"))
}

fn risk_impact_for(priority: &str) -> i64 {
    match priority {
        "CRITICAL" => 5,
        "HIGH" => 4,
        "MEDIUM" => 3,
        "LOW" => 2,
        _ => 3,
    }
}

fn risk_likelihood_for(exposure: &str) -> i64 {
    match exposure {
        "INTERNET" => 5,
        "CUSTOMER" => 4,
        "INTERNAL" => 3,
        _ => 2,
    }
}

fn build_assessment_write_fields(
    payload: &NormalizedAssessmentWriteRequest,
    cve: &CveRecordContext,
    tenant_default_nis2: bool,
    product_name: Option<&str>,
    existing: Option<&ExistingAssessmentState>,
) -> AssessmentWriteFields {
    let epss_score = payload.epss_score.or(cve.epss_score);
    let in_kev_catalog = payload.in_kev_catalog.unwrap_or(cve.in_kev_catalog);
    let exploit_maturity = if in_kev_catalog && payload.exploit_maturity == "UNKNOWN" {
        "ACTIVE".to_string()
    } else {
        payload.exploit_maturity.clone()
    };
    let nis2_relevant = payload.nis2_relevant.unwrap_or(tenant_default_nis2);
    let regulatory_tags = ensure_nis2_tag(payload.regulatory_tags.clone(), nis2_relevant);
    let deterministic = calculate_deterministic_priority(DeterministicPriorityInput {
        cve,
        exposure: &payload.exposure,
        asset_criticality: &payload.asset_criticality,
        epss_score,
        in_kev_catalog,
        exploit_maturity: &exploit_maturity,
        affects_critical_service: payload.affects_critical_service,
        nis2_relevant,
    });
    let llm = if payload.run_llm {
        let prompt = build_llm_prompt(
            cve,
            product_name,
            payload,
            &deterministic.priority,
            deterministic.due_days,
        );
        llm_assessment_result(&prompt, cve, product_name)
    } else {
        existing_or_blank_llm_result(existing)
    };

    AssessmentWriteFields {
        cve_record_id: cve.id,
        product_id: payload.product_id,
        release_id: payload.release_id,
        component_id: payload.component_id,
        linked_vulnerability_id: existing.and_then(|item| item.linked_vulnerability_id),
        related_risk_id: existing.and_then(|item| item.related_risk_id),
        exposure: payload.exposure.clone(),
        asset_criticality: payload.asset_criticality.clone(),
        epss_score,
        in_kev_catalog,
        exploit_maturity,
        affects_critical_service: payload.affects_critical_service,
        nis2_relevant,
        nis2_impact_summary: payload.nis2_impact_summary.clone(),
        repository_name: payload.repository_name.clone(),
        repository_url: payload.repository_url.clone(),
        git_ref: payload.git_ref.clone(),
        source_package: payload.source_package.clone(),
        source_package_version: payload.source_package_version.clone(),
        regulatory_tags,
        deterministic_factors_json: deterministic.factors_json,
        business_context: payload.business_context.clone(),
        existing_controls: payload.existing_controls.clone(),
        deterministic_priority: deterministic.priority,
        deterministic_due_days: deterministic.due_days,
        llm_backend: llm.backend,
        llm_model_name: llm.model_name,
        llm_status: llm.status,
        technical_summary: llm.technical_summary,
        business_impact: llm.business_impact,
        attack_path: llm.attack_path,
        management_summary: llm.management_summary,
        recommended_actions: llm.recommended_actions,
        evidence_needed: llm.evidence_needed,
        raw_llm_json: llm.raw_json,
        confidence: llm.confidence,
        prompt_hash: llm.prompt_hash,
    }
}

async fn dashboard_summary_postgres(pool: &PgPool) -> anyhow::Result<CveDashboardSummary> {
    let row = sqlx::query(
        r#"
        SELECT
            COUNT(*)::bigint AS total,
            COALESCE(SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END), 0)::bigint AS critical,
            COALESCE(SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END), 0)::bigint AS high,
            COALESCE(SUM(CASE WHEN in_kev_catalog THEN 1 ELSE 0 END), 0)::bigint AS kev,
            COALESCE(SUM(CASE WHEN kev_known_ransomware THEN 1 ELSE 0 END), 0)::bigint AS known_ransomware,
            COALESCE(SUM(CASE WHEN epss_score IS NOT NULL THEN 1 ELSE 0 END), 0)::bigint AS with_epss
        FROM vulnerability_intelligence_cverecord
        "#,
    )
    .fetch_one(pool)
    .await
    .context("PostgreSQL-CVE-Summary konnte nicht gelesen werden")?;

    Ok(CveDashboardSummary {
        total: row.try_get("total")?,
        critical: row.try_get("critical")?,
        high: row.try_get("high")?,
        kev: row.try_get("kev")?,
        known_ransomware: row.try_get("known_ransomware")?,
        with_epss: row.try_get("with_epss")?,
    })
}

async fn dashboard_summary_sqlite(pool: &SqlitePool) -> anyhow::Result<CveDashboardSummary> {
    let row = sqlx::query(
        r#"
        SELECT
            COUNT(*) AS total,
            COALESCE(SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END), 0) AS critical,
            COALESCE(SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END), 0) AS high,
            COALESCE(SUM(CASE WHEN in_kev_catalog THEN 1 ELSE 0 END), 0) AS kev,
            COALESCE(SUM(CASE WHEN kev_known_ransomware THEN 1 ELSE 0 END), 0) AS known_ransomware,
            COALESCE(SUM(CASE WHEN epss_score IS NOT NULL THEN 1 ELSE 0 END), 0) AS with_epss
        FROM vulnerability_intelligence_cverecord
        "#,
    )
    .fetch_one(pool)
    .await
    .context("SQLite-CVE-Summary konnte nicht gelesen werden")?;

    Ok(CveDashboardSummary {
        total: row.try_get("total")?,
        critical: row.try_get("critical")?,
        high: row.try_get("high")?,
        kev: row.try_get("kev")?,
        known_ransomware: row.try_get("known_ransomware")?,
        with_epss: row.try_get("with_epss")?,
    })
}

async fn list_recent_postgres(pool: &PgPool, limit: i64) -> anyhow::Result<Vec<CveRecordSummary>> {
    let rows = sqlx::query(
        r#"
        SELECT
            id,
            cve_id,
            source,
            description,
            CAST(cvss_score AS TEXT) AS cvss_score_text,
            cvss_vector,
            severity,
            CAST(epss_score AS TEXT) AS epss_score_text,
            in_kev_catalog,
            kev_known_ransomware,
            published_at::text AS published_at,
            modified_at::text AS modified_at,
            created_at::text AS created_at,
            updated_at::text AS updated_at
        FROM vulnerability_intelligence_cverecord
        ORDER BY COALESCE(published_at, modified_at, created_at) DESC, cve_id DESC
        LIMIT $1
        "#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("PostgreSQL-CVE-Liste konnte nicht gelesen werden")?;

    rows.into_iter()
        .map(summary_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_recent_sqlite(
    pool: &SqlitePool,
    limit: i64,
) -> anyhow::Result<Vec<CveRecordSummary>> {
    let rows = sqlx::query(
        r#"
        SELECT
            id,
            cve_id,
            source,
            description,
            CAST(cvss_score AS TEXT) AS cvss_score_text,
            cvss_vector,
            severity,
            CAST(epss_score AS TEXT) AS epss_score_text,
            in_kev_catalog,
            kev_known_ransomware,
            CAST(published_at AS TEXT) AS published_at,
            CAST(modified_at AS TEXT) AS modified_at,
            CAST(created_at AS TEXT) AS created_at,
            CAST(updated_at AS TEXT) AS updated_at
        FROM vulnerability_intelligence_cverecord
        ORDER BY COALESCE(published_at, modified_at, created_at) DESC, cve_id DESC
        LIMIT ?
        "#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("SQLite-CVE-Liste konnte nicht gelesen werden")?;

    rows.into_iter()
        .map(summary_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn detail_postgres(pool: &PgPool, cve_id: &str) -> anyhow::Result<Option<CveRecordDetail>> {
    let row = sqlx::query(
        r#"
        SELECT
            id,
            cve_id,
            source,
            description,
            CAST(cvss_score AS TEXT) AS cvss_score_text,
            cvss_vector,
            severity,
            COALESCE(weakness_ids_json::text, '[]') AS weakness_ids_json_text,
            COALESCE(references_json::text, '[]') AS references_json_text,
            COALESCE(configurations_json::text, '[]') AS configurations_json_text,
            CAST(epss_score AS TEXT) AS epss_score_text,
            in_kev_catalog,
            kev_date_added::text AS kev_date_added,
            kev_vendor_project,
            kev_product,
            kev_required_action,
            kev_known_ransomware,
            COALESCE(raw_json::text, '{}') AS raw_json_text,
            published_at::text AS published_at,
            modified_at::text AS modified_at,
            created_at::text AS created_at,
            updated_at::text AS updated_at
        FROM vulnerability_intelligence_cverecord
        WHERE cve_id = $1
        "#,
    )
    .bind(cve_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-CVE-Detail konnte nicht gelesen werden")?;

    row.map(detail_from_pg_row).transpose().map_err(Into::into)
}

async fn detail_sqlite(pool: &SqlitePool, cve_id: &str) -> anyhow::Result<Option<CveRecordDetail>> {
    let row = sqlx::query(
        r#"
        SELECT
            id,
            cve_id,
            source,
            description,
            CAST(cvss_score AS TEXT) AS cvss_score_text,
            cvss_vector,
            severity,
            COALESCE(CAST(weakness_ids_json AS TEXT), '[]') AS weakness_ids_json_text,
            COALESCE(CAST(references_json AS TEXT), '[]') AS references_json_text,
            COALESCE(CAST(configurations_json AS TEXT), '[]') AS configurations_json_text,
            CAST(epss_score AS TEXT) AS epss_score_text,
            in_kev_catalog,
            CAST(kev_date_added AS TEXT) AS kev_date_added,
            kev_vendor_project,
            kev_product,
            kev_required_action,
            kev_known_ransomware,
            COALESCE(CAST(raw_json AS TEXT), '{}') AS raw_json_text,
            CAST(published_at AS TEXT) AS published_at,
            CAST(modified_at AS TEXT) AS modified_at,
            CAST(created_at AS TEXT) AS created_at,
            CAST(updated_at AS TEXT) AS updated_at
        FROM vulnerability_intelligence_cverecord
        WHERE cve_id = ?
        "#,
    )
    .bind(cve_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-CVE-Detail konnte nicht gelesen werden")?;

    row.map(detail_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

async fn assessment_dashboard_summary_postgres(
    pool: &PgPool,
    tenant_id: i64,
) -> anyhow::Result<CveAssessmentDashboardSummary> {
    let row = sqlx::query(
        r#"
        SELECT
            COUNT(*)::bigint AS total,
            COALESCE(SUM(CASE WHEN assessment.deterministic_priority = 'CRITICAL' THEN 1 ELSE 0 END), 0)::bigint AS critical,
            COALESCE(SUM(CASE WHEN assessment.related_risk_id IS NOT NULL THEN 1 ELSE 0 END), 0)::bigint AS with_risk,
            COALESCE(SUM(CASE WHEN assessment.llm_status = 'GENERATED' THEN 1 ELSE 0 END), 0)::bigint AS llm_generated,
            COALESCE(SUM(CASE WHEN assessment.nis2_relevant THEN 1 ELSE 0 END), 0)::bigint AS nis2,
            COALESCE(SUM(CASE WHEN assessment.in_kev_catalog THEN 1 ELSE 0 END), 0)::bigint AS kev
        FROM vulnerability_intelligence_cveassessment assessment
        WHERE assessment.tenant_id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .context("PostgreSQL-CVE-Assessment-Summary konnte nicht gelesen werden")?;

    let total: i64 = row.try_get("total")?;
    let critical: i64 = row.try_get("critical")?;
    let with_risk: i64 = row.try_get("with_risk")?;
    let llm_generated: i64 = row.try_get("llm_generated")?;
    let nis2: i64 = row.try_get("nis2")?;
    let kev: i64 = row.try_get("kev")?;
    Ok(CveAssessmentDashboardSummary {
        total,
        critical,
        with_risk,
        llm_generated,
        nis2,
        kev,
        risk_hotspot_score: assessment_hotspot_score(total, critical, kev, nis2),
    })
}

async fn assessment_dashboard_summary_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
) -> anyhow::Result<CveAssessmentDashboardSummary> {
    let row = sqlx::query(
        r#"
        SELECT
            COUNT(*) AS total,
            COALESCE(SUM(CASE WHEN assessment.deterministic_priority = 'CRITICAL' THEN 1 ELSE 0 END), 0) AS critical,
            COALESCE(SUM(CASE WHEN assessment.related_risk_id IS NOT NULL THEN 1 ELSE 0 END), 0) AS with_risk,
            COALESCE(SUM(CASE WHEN assessment.llm_status = 'GENERATED' THEN 1 ELSE 0 END), 0) AS llm_generated,
            COALESCE(SUM(CASE WHEN assessment.nis2_relevant THEN 1 ELSE 0 END), 0) AS nis2,
            COALESCE(SUM(CASE WHEN assessment.in_kev_catalog THEN 1 ELSE 0 END), 0) AS kev
        FROM vulnerability_intelligence_cveassessment assessment
        WHERE assessment.tenant_id = ?
        "#,
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .context("SQLite-CVE-Assessment-Summary konnte nicht gelesen werden")?;

    let total: i64 = row.try_get("total")?;
    let critical: i64 = row.try_get("critical")?;
    let with_risk: i64 = row.try_get("with_risk")?;
    let llm_generated: i64 = row.try_get("llm_generated")?;
    let nis2: i64 = row.try_get("nis2")?;
    let kev: i64 = row.try_get("kev")?;
    Ok(CveAssessmentDashboardSummary {
        total,
        critical,
        with_risk,
        llm_generated,
        nis2,
        kev,
        risk_hotspot_score: assessment_hotspot_score(total, critical, kev, nis2),
    })
}

async fn list_assessments_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<CveAssessmentSummary>> {
    let rows = sqlx::query(assessment_list_postgres_sql())
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-CVE-Assessment-Liste konnte nicht gelesen werden")?;

    rows.into_iter()
        .map(assessment_summary_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_assessments_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<CveAssessmentSummary>> {
    let rows = sqlx::query(assessment_list_sqlite_sql())
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("SQLite-CVE-Assessment-Liste konnte nicht gelesen werden")?;

    rows.into_iter()
        .map(assessment_summary_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn assessment_detail_postgres(
    pool: &PgPool,
    tenant_id: i64,
    assessment_id: i64,
) -> anyhow::Result<Option<CveAssessmentDetail>> {
    let row = sqlx::query(assessment_detail_postgres_sql())
        .bind(tenant_id)
        .bind(assessment_id)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-CVE-Assessment-Detail konnte nicht gelesen werden")?;

    row.map(assessment_detail_from_pg_row)
        .transpose()
        .map_err(Into::into)
}

async fn assessment_detail_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    assessment_id: i64,
) -> anyhow::Result<Option<CveAssessmentDetail>> {
    let row = sqlx::query(assessment_detail_sqlite_sql())
        .bind(tenant_id)
        .bind(assessment_id)
        .fetch_optional(pool)
        .await
        .context("SQLite-CVE-Assessment-Detail konnte nicht gelesen werden")?;

    row.map(assessment_detail_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

async fn assessment_form_options_postgres(
    pool: &PgPool,
    tenant_id: i64,
) -> anyhow::Result<CveAssessmentFormOptions> {
    let products = sqlx::query(
        r#"
        SELECT id, name
        FROM product_security_product
        WHERE tenant_id = $1
        ORDER BY name ASC, id ASC
        "#,
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .context("PostgreSQL-Produktoptionen konnten nicht gelesen werden")?
    .into_iter()
    .map(|row| {
        Ok(CveAssessmentProductOption {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
        })
    })
    .collect::<Result<Vec<_>, sqlx::Error>>()?;

    let releases = sqlx::query(
        r#"
        SELECT
            release.id,
            release.product_id,
            release.version,
            product.name || ' / ' || release.version AS label
        FROM product_security_productrelease release
        JOIN product_security_product product
            ON product.id = release.product_id AND product.tenant_id = release.tenant_id
        WHERE release.tenant_id = $1
        ORDER BY product.name ASC, release.version ASC, release.id ASC
        "#,
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .context("PostgreSQL-Releaseoptionen konnten nicht gelesen werden")?
    .into_iter()
    .map(|row| {
        Ok(CveAssessmentReleaseOption {
            id: row.try_get("id")?,
            product_id: row.try_get("product_id")?,
            version: row.try_get("version")?,
            label: row.try_get("label")?,
        })
    })
    .collect::<Result<Vec<_>, sqlx::Error>>()?;

    let components = sqlx::query(
        r#"
        SELECT
            component.id,
            component.product_id,
            component.name,
            component.version,
            product.name || ' / ' || component.name ||
                CASE
                    WHEN component.version <> '' THEN ' ' || component.version
                    ELSE ''
                END AS label
        FROM product_security_component component
        JOIN product_security_product product
            ON product.id = component.product_id AND product.tenant_id = component.tenant_id
        WHERE component.tenant_id = $1
        ORDER BY product.name ASC, component.name ASC, component.id ASC
        "#,
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .context("PostgreSQL-Komponentenoptionen konnten nicht gelesen werden")?
    .into_iter()
    .map(|row| {
        Ok(CveAssessmentComponentOption {
            id: row.try_get("id")?,
            product_id: row.try_get("product_id")?,
            name: row.try_get("name")?,
            version: row.try_get("version")?,
            label: row.try_get("label")?,
        })
    })
    .collect::<Result<Vec<_>, sqlx::Error>>()?;

    Ok(CveAssessmentFormOptions {
        products,
        releases,
        components,
    })
}

async fn assessment_form_options_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
) -> anyhow::Result<CveAssessmentFormOptions> {
    let products = sqlx::query(
        r#"
        SELECT id, name
        FROM product_security_product
        WHERE tenant_id = ?1
        ORDER BY name ASC, id ASC
        "#,
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .context("SQLite-Produktoptionen konnten nicht gelesen werden")?
    .into_iter()
    .map(|row| {
        Ok(CveAssessmentProductOption {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
        })
    })
    .collect::<Result<Vec<_>, sqlx::Error>>()?;

    let releases = sqlx::query(
        r#"
        SELECT
            release.id,
            release.product_id,
            release.version,
            product.name || ' / ' || release.version AS label
        FROM product_security_productrelease release
        JOIN product_security_product product
            ON product.id = release.product_id AND product.tenant_id = release.tenant_id
        WHERE release.tenant_id = ?1
        ORDER BY product.name ASC, release.version ASC, release.id ASC
        "#,
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .context("SQLite-Releaseoptionen konnten nicht gelesen werden")?
    .into_iter()
    .map(|row| {
        Ok(CveAssessmentReleaseOption {
            id: row.try_get("id")?,
            product_id: row.try_get("product_id")?,
            version: row.try_get("version")?,
            label: row.try_get("label")?,
        })
    })
    .collect::<Result<Vec<_>, sqlx::Error>>()?;

    let components = sqlx::query(
        r#"
        SELECT
            component.id,
            component.product_id,
            component.name,
            component.version,
            product.name || ' / ' || component.name ||
                CASE
                    WHEN component.version <> '' THEN ' ' || component.version
                    ELSE ''
                END AS label
        FROM product_security_component component
        JOIN product_security_product product
            ON product.id = component.product_id AND product.tenant_id = component.tenant_id
        WHERE component.tenant_id = ?1
        ORDER BY product.name ASC, component.name ASC, component.id ASC
        "#,
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .context("SQLite-Komponentenoptionen konnten nicht gelesen werden")?
    .into_iter()
    .map(|row| {
        Ok(CveAssessmentComponentOption {
            id: row.try_get("id")?,
            product_id: row.try_get("product_id")?,
            name: row.try_get("name")?,
            version: row.try_get("version")?,
            label: row.try_get("label")?,
        })
    })
    .collect::<Result<Vec<_>, sqlx::Error>>()?;

    Ok(CveAssessmentFormOptions {
        products,
        releases,
        components,
    })
}

async fn fetch_cve_record_postgres(
    pool: &PgPool,
    cve_id: &str,
) -> anyhow::Result<Option<CveRecordContext>> {
    let row = sqlx::query(
        r#"
        SELECT
            id,
            cve_id,
            description,
            severity,
            cvss_score,
            epss_score,
            in_kev_catalog
        FROM vulnerability_intelligence_cverecord
        WHERE cve_id = $1
        "#,
    )
    .bind(cve_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-CVE-Kontext konnte nicht gelesen werden")?;

    row.map(|row| {
        Ok::<_, sqlx::Error>(CveRecordContext {
            id: row.try_get("id")?,
            cve_id: row.try_get("cve_id")?,
            description: row.try_get("description")?,
            severity: row.try_get("severity")?,
            cvss_score: row.try_get("cvss_score")?,
            epss_score: row.try_get("epss_score")?,
            in_kev_catalog: row.try_get("in_kev_catalog")?,
        })
    })
    .transpose()
    .map_err(Into::into)
}

async fn fetch_cve_record_sqlite(
    pool: &SqlitePool,
    cve_id: &str,
) -> anyhow::Result<Option<CveRecordContext>> {
    let row = sqlx::query(
        r#"
        SELECT
            id,
            cve_id,
            description,
            severity,
            CAST(cvss_score AS TEXT) AS cvss_score_text,
            CAST(epss_score AS TEXT) AS epss_score_text,
            in_kev_catalog
        FROM vulnerability_intelligence_cverecord
        WHERE cve_id = ?1
        "#,
    )
    .bind(cve_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-CVE-Kontext konnte nicht gelesen werden")?;

    row.map(|row| {
        Ok::<_, sqlx::Error>(CveRecordContext {
            id: row.try_get("id")?,
            cve_id: row.try_get("cve_id")?,
            description: row.try_get("description")?,
            severity: row.try_get("severity")?,
            cvss_score: row
                .try_get::<Option<String>, _>("cvss_score_text")?
                .and_then(|value| Decimal::from_str(value.trim()).ok()),
            epss_score: row
                .try_get::<Option<String>, _>("epss_score_text")?
                .and_then(|value| Decimal::from_str(value.trim()).ok()),
            in_kev_catalog: row.try_get("in_kev_catalog")?,
        })
    })
    .transpose()
    .map_err(Into::into)
}

async fn tenant_default_nis2_postgres(pool: &PgPool, tenant_id: i64) -> anyhow::Result<bool> {
    sqlx::query_scalar::<_, bool>(
        "SELECT nis2_relevant FROM organizations_tenant WHERE id = $1 LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-Tenantdefault fuer NIS2 konnte nicht gelesen werden")
    .map(|value| value.unwrap_or(false))
}

async fn tenant_default_nis2_sqlite(pool: &SqlitePool, tenant_id: i64) -> anyhow::Result<bool> {
    let has_column: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('organizations_tenant') WHERE name = 'nis2_relevant')",
    )
    .fetch_one(pool)
    .await
    .context("SQLite-Schema fuer organizations_tenant konnte nicht gelesen werden")?;
    if !has_column {
        return Ok(false);
    }
    sqlx::query_scalar::<_, bool>(
        "SELECT nis2_relevant FROM organizations_tenant WHERE id = ?1 LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-Tenantdefault fuer NIS2 konnte nicht gelesen werden")
    .map(|value| value.unwrap_or(false))
}

async fn product_record_postgres(
    pool: &PgPool,
    tenant_id: i64,
    product_id: i64,
) -> anyhow::Result<Option<ProductRecord>> {
    sqlx::query("SELECT id, name FROM product_security_product WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(product_id)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-Produkt konnte nicht gelesen werden")?
        .map(|row| {
            Ok::<_, sqlx::Error>(ProductRecord {
                id: row.try_get("id")?,
                name: row.try_get("name")?,
            })
        })
        .transpose()
        .map_err(Into::into)
}

async fn product_record_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    product_id: i64,
) -> anyhow::Result<Option<ProductRecord>> {
    sqlx::query("SELECT id, name FROM product_security_product WHERE tenant_id = ?1 AND id = ?2")
        .bind(tenant_id)
        .bind(product_id)
        .fetch_optional(pool)
        .await
        .context("SQLite-Produkt konnte nicht gelesen werden")?
        .map(|row| {
            Ok::<_, sqlx::Error>(ProductRecord {
                id: row.try_get("id")?,
                name: row.try_get("name")?,
            })
        })
        .transpose()
        .map_err(Into::into)
}

async fn release_record_postgres(
    pool: &PgPool,
    tenant_id: i64,
    release_id: i64,
) -> anyhow::Result<Option<ReleaseRecord>> {
    sqlx::query(
        "SELECT id, product_id FROM product_security_productrelease WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(release_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-Release konnte nicht gelesen werden")?
    .map(|row| {
        Ok::<_, sqlx::Error>(ReleaseRecord {
            id: row.try_get("id")?,
            product_id: row.try_get("product_id")?,
        })
    })
    .transpose()
    .map_err(Into::into)
}

async fn release_record_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    release_id: i64,
) -> anyhow::Result<Option<ReleaseRecord>> {
    sqlx::query(
        "SELECT id, product_id FROM product_security_productrelease WHERE tenant_id = ?1 AND id = ?2",
    )
    .bind(tenant_id)
    .bind(release_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-Release konnte nicht gelesen werden")?
    .map(|row| {
        Ok::<_, sqlx::Error>(ReleaseRecord {
            id: row.try_get("id")?,
            product_id: row.try_get("product_id")?,
        })
    })
    .transpose()
    .map_err(Into::into)
}

async fn component_record_postgres(
    pool: &PgPool,
    tenant_id: i64,
    component_id: i64,
) -> anyhow::Result<Option<ComponentRecord>> {
    sqlx::query(
        "SELECT id, product_id FROM product_security_component WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(component_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-Komponente konnte nicht gelesen werden")?
    .map(|row| {
        Ok::<_, sqlx::Error>(ComponentRecord {
            id: row.try_get("id")?,
            product_id: row.try_get("product_id")?,
        })
    })
    .transpose()
    .map_err(Into::into)
}

async fn component_record_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    component_id: i64,
) -> anyhow::Result<Option<ComponentRecord>> {
    sqlx::query(
        "SELECT id, product_id FROM product_security_component WHERE tenant_id = ?1 AND id = ?2",
    )
    .bind(tenant_id)
    .bind(component_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-Komponente konnte nicht gelesen werden")?
    .map(|row| {
        Ok::<_, sqlx::Error>(ComponentRecord {
            id: row.try_get("id")?,
            product_id: row.try_get("product_id")?,
        })
    })
    .transpose()
    .map_err(Into::into)
}

async fn existing_assessment_postgres(
    pool: &PgPool,
    tenant_id: i64,
    cve_record_id: i64,
    product_id: Option<i64>,
    release_id: Option<i64>,
    component_id: Option<i64>,
) -> anyhow::Result<Option<ExistingAssessmentState>> {
    let row = sqlx::query(
        r#"
        SELECT
            id,
            linked_vulnerability_id,
            related_risk_id,
            technical_summary,
            business_impact,
            attack_path,
            management_summary,
            COALESCE(recommended_actions_json::text, '[]') AS recommended_actions_json_text,
            COALESCE(evidence_needed_json::text, '[]') AS evidence_needed_json_text,
            COALESCE(raw_llm_json::text, '{}') AS raw_llm_json_text,
            confidence,
            prompt_hash
        FROM vulnerability_intelligence_cveassessment
        WHERE tenant_id = $1
          AND cve_id = $2
          AND product_id IS NOT DISTINCT FROM $3
          AND release_id IS NOT DISTINCT FROM $4
          AND component_id IS NOT DISTINCT FROM $5
        ORDER BY id DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(cve_record_id)
    .bind(product_id)
    .bind(release_id)
    .bind(component_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-bestehendes CVE-Assessment konnte nicht gelesen werden")?;

    row.map(existing_assessment_from_pg_row)
        .transpose()
        .map_err(Into::into)
}

async fn existing_assessment_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    cve_record_id: i64,
    product_id: Option<i64>,
    release_id: Option<i64>,
    component_id: Option<i64>,
) -> anyhow::Result<Option<ExistingAssessmentState>> {
    let row = sqlx::query(
        r#"
        SELECT
            id,
            linked_vulnerability_id,
            related_risk_id,
            technical_summary,
            business_impact,
            attack_path,
            management_summary,
            COALESCE(CAST(recommended_actions_json AS TEXT), '[]') AS recommended_actions_json_text,
            COALESCE(CAST(evidence_needed_json AS TEXT), '[]') AS evidence_needed_json_text,
            COALESCE(CAST(raw_llm_json AS TEXT), '{}') AS raw_llm_json_text,
            confidence,
            prompt_hash
        FROM vulnerability_intelligence_cveassessment
        WHERE tenant_id = ?1
          AND cve_id = ?2
          AND ((product_id IS NULL AND ?3 IS NULL) OR product_id = ?3)
          AND ((release_id IS NULL AND ?4 IS NULL) OR release_id = ?4)
          AND ((component_id IS NULL AND ?5 IS NULL) OR component_id = ?5)
        ORDER BY id DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(cve_record_id)
    .bind(product_id)
    .bind(release_id)
    .bind(component_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-bestehendes CVE-Assessment konnte nicht gelesen werden")?;

    row.map(existing_assessment_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

fn existing_assessment_from_pg_row(
    row: sqlx::postgres::PgRow,
) -> Result<ExistingAssessmentState, sqlx::Error> {
    Ok(ExistingAssessmentState {
        id: row.try_get("id")?,
        linked_vulnerability_id: row.try_get("linked_vulnerability_id")?,
        related_risk_id: row.try_get("related_risk_id")?,
        technical_summary: row.try_get("technical_summary")?,
        business_impact: row.try_get("business_impact")?,
        attack_path: row.try_get("attack_path")?,
        management_summary: row.try_get("management_summary")?,
        recommended_actions: parse_json_string_array(row.try_get("recommended_actions_json_text")?),
        evidence_needed: parse_json_string_array(row.try_get("evidence_needed_json_text")?),
        raw_llm_json: parse_json_value(row.try_get("raw_llm_json_text")?, json!({})),
        confidence: row.try_get("confidence")?,
        prompt_hash: row.try_get("prompt_hash")?,
    })
}

fn existing_assessment_from_sqlite_row(
    row: sqlx::sqlite::SqliteRow,
) -> Result<ExistingAssessmentState, sqlx::Error> {
    Ok(ExistingAssessmentState {
        id: row.try_get("id")?,
        linked_vulnerability_id: row.try_get("linked_vulnerability_id")?,
        related_risk_id: row.try_get("related_risk_id")?,
        technical_summary: row.try_get("technical_summary")?,
        business_impact: row.try_get("business_impact")?,
        attack_path: row.try_get("attack_path")?,
        management_summary: row.try_get("management_summary")?,
        recommended_actions: parse_json_string_array(row.try_get("recommended_actions_json_text")?),
        evidence_needed: parse_json_string_array(row.try_get("evidence_needed_json_text")?),
        raw_llm_json: parse_json_value(row.try_get("raw_llm_json_text")?, json!({})),
        confidence: row.try_get("confidence")?,
        prompt_hash: row.try_get("prompt_hash")?,
    })
}

fn resolve_product_release_component(
    payload: &NormalizedAssessmentWriteRequest,
    product: Option<ProductRecord>,
    release: Option<ReleaseRecord>,
    component: Option<ComponentRecord>,
) -> anyhow::Result<(
    Option<ProductRecord>,
    Option<ReleaseRecord>,
    Option<ComponentRecord>,
)> {
    let mut product = product;
    if product.is_none() {
        product = release
            .as_ref()
            .map(|item| ProductRecord {
                id: item.product_id,
                name: String::new(),
            })
            .or_else(|| {
                component.as_ref().map(|item| ProductRecord {
                    id: item.product_id,
                    name: String::new(),
                })
            });
    }

    if let Some(release) = release.as_ref() {
        if let Some(product) = product.as_ref() {
            if product.id != release.product_id {
                bail!("validation:Release gehoert nicht zum ausgewaehlten Produkt.");
            }
        }
    }
    if let Some(component) = component.as_ref() {
        if let Some(product) = product.as_ref() {
            if product.id != component.product_id {
                bail!("validation:Komponente gehoert nicht zum ausgewaehlten Produkt.");
            }
        }
    }
    if let (Some(release), Some(component)) = (release.as_ref(), component.as_ref()) {
        if release.product_id != component.product_id {
            bail!("validation:Release und Komponente gehoeren nicht zum selben Produkt.");
        }
    }

    let product_id = product.as_ref().map(|item| item.id);
    if payload.product_id.is_none()
        && product_id.is_some()
        && product.as_ref().is_some_and(|item| item.name.is_empty())
    {
        bail!(
            "validation:Produkt muss explizit gesetzt werden, wenn nur Release oder Komponente uebergeben werden."
        );
    }

    Ok((product, release, component))
}

async fn upsert_linked_vulnerability_postgres(
    pool: &PgPool,
    tenant_id: i64,
    cve: &CveRecordContext,
    product: &ProductRecord,
    release: Option<&ReleaseRecord>,
    component: Option<&ComponentRecord>,
) -> anyhow::Result<i64> {
    let existing = sqlx::query(
        r#"
        SELECT id, title
        FROM product_security_vulnerability
        WHERE tenant_id = $1
          AND product_id = $2
          AND release_id IS NOT DISTINCT FROM $3
          AND component_id IS NOT DISTINCT FROM $4
          AND cve = $5
        ORDER BY id DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(product.id)
    .bind(release.map(|item| item.id))
    .bind(component.map(|item| item.id))
    .bind(&cve.cve_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-Produktvulnerability konnte nicht abgeglichen werden")?;

    let summary: String = cve.description.chars().take(2000).collect();
    if let Some(row) = existing {
        let vulnerability_id: i64 = row.try_get("id")?;
        let title: String = row.try_get("title")?;
        let summary = if title.trim() == cve.cve_id {
            summary
        } else {
            sqlx::query_scalar::<_, String>(
                "SELECT summary FROM product_security_vulnerability WHERE id = $1",
            )
            .bind(vulnerability_id)
            .fetch_one(pool)
            .await
            .unwrap_or(summary)
        };
        sqlx::query(
            r#"
            UPDATE product_security_vulnerability
            SET severity = $1,
                status = 'OPEN',
                summary = $2,
                updated_at = NOW()
            WHERE id = $3 AND tenant_id = $4
            "#,
        )
        .bind(&cve.severity)
        .bind(summary)
        .bind(vulnerability_id)
        .bind(tenant_id)
        .execute(pool)
        .await
        .context("PostgreSQL-Produktvulnerability konnte nicht aktualisiert werden")?;
        return Ok(vulnerability_id);
    }

    sqlx::query_scalar(
        r#"
        INSERT INTO product_security_vulnerability (
            tenant_id,
            product_id,
            release_id,
            component_id,
            title,
            cve,
            severity,
            status,
            remediation_due,
            summary,
            created_at,
            updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'OPEN', NULL, $8, NOW(), NOW())
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(product.id)
    .bind(release.map(|item| item.id))
    .bind(component.map(|item| item.id))
    .bind(&cve.cve_id)
    .bind(&cve.cve_id)
    .bind(&cve.severity)
    .bind(summary)
    .fetch_one(pool)
    .await
    .context("PostgreSQL-Produktvulnerability konnte nicht erstellt werden")
}

async fn upsert_linked_vulnerability_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    cve: &CveRecordContext,
    product: &ProductRecord,
    release: Option<&ReleaseRecord>,
    component: Option<&ComponentRecord>,
) -> anyhow::Result<i64> {
    let existing = sqlx::query(
        r#"
        SELECT id, title
        FROM product_security_vulnerability
        WHERE tenant_id = ?1
          AND product_id = ?2
          AND ((release_id IS NULL AND ?3 IS NULL) OR release_id = ?3)
          AND ((component_id IS NULL AND ?4 IS NULL) OR component_id = ?4)
          AND cve = ?5
        ORDER BY id DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(product.id)
    .bind(release.map(|item| item.id))
    .bind(component.map(|item| item.id))
    .bind(&cve.cve_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-Produktvulnerability konnte nicht abgeglichen werden")?;

    let summary: String = cve.description.chars().take(2000).collect();
    if let Some(row) = existing {
        let vulnerability_id: i64 = row.try_get("id")?;
        let title: String = row.try_get("title")?;
        let summary = if title.trim() == cve.cve_id {
            summary
        } else {
            sqlx::query_scalar::<_, String>(
                "SELECT summary FROM product_security_vulnerability WHERE id = ?1",
            )
            .bind(vulnerability_id)
            .fetch_one(pool)
            .await
            .unwrap_or(summary)
        };
        sqlx::query(
            r#"
            UPDATE product_security_vulnerability
            SET severity = ?1,
                status = 'OPEN',
                summary = ?2,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?3 AND tenant_id = ?4
            "#,
        )
        .bind(&cve.severity)
        .bind(summary)
        .bind(vulnerability_id)
        .bind(tenant_id)
        .execute(pool)
        .await
        .context("SQLite-Produktvulnerability konnte nicht aktualisiert werden")?;
        return Ok(vulnerability_id);
    }

    let result = sqlx::query(
        r#"
        INSERT INTO product_security_vulnerability (
            tenant_id,
            product_id,
            release_id,
            component_id,
            title,
            cve,
            severity,
            status,
            remediation_due,
            summary,
            created_at,
            updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'OPEN', NULL, ?8, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        "#,
    )
    .bind(tenant_id)
    .bind(product.id)
    .bind(release.map(|item| item.id))
    .bind(component.map(|item| item.id))
    .bind(&cve.cve_id)
    .bind(&cve.cve_id)
    .bind(&cve.severity)
    .bind(summary)
    .execute(pool)
    .await
    .context("SQLite-Produktvulnerability konnte nicht erstellt werden")?;
    Ok(result.last_insert_rowid())
}

async fn upsert_related_risk_postgres(
    pool: &PgPool,
    tenant_id: i64,
    cve: &CveRecordContext,
    product_name: Option<&str>,
    fields: &AssessmentWriteFields,
) -> anyhow::Result<i64> {
    let title = risk_title_for(&cve.cve_id, product_name);
    let legacy_title = risk_title_legacy_for(&cve.cve_id, product_name);
    let description = if fields.business_context.trim().is_empty() {
        cve.description.chars().take(3000).collect::<String>()
    } else {
        fields.business_context.clone()
    };
    let threat = if fields.attack_path.trim().is_empty() {
        cve.description.chars().take(1000).collect::<String>()
    } else {
        fields.attack_path.clone()
    };
    let treatment_plan = if fields.management_summary.trim().is_empty() {
        fields.business_impact.clone()
    } else {
        fields.management_summary.clone()
    };

    let existing_risk_id = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT id
        FROM risks_risk
        WHERE tenant_id = $1
          AND (title = $2 OR title = $3)
        ORDER BY id DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(&title)
    .bind(&legacy_title)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-Risiko konnte nicht abgeglichen werden")?;

    if let Some(risk_id) = existing_risk_id {
        sqlx::query(
            r#"
            UPDATE risks_risk
            SET title = $1,
                description = $2,
                threat = $3,
                vulnerability = $4,
                impact = $5,
                likelihood = $6,
                status = 'ANALYZING',
                treatment_strategy = 'MITIGATE',
                treatment_plan = $7,
                updated_at = NOW()
            WHERE id = $8 AND tenant_id = $9
            "#,
        )
        .bind(&title)
        .bind(description)
        .bind(threat)
        .bind(&cve.cve_id)
        .bind(risk_impact_for(&fields.deterministic_priority))
        .bind(risk_likelihood_for(&fields.exposure))
        .bind(treatment_plan)
        .bind(risk_id)
        .bind(tenant_id)
        .execute(pool)
        .await
        .context("PostgreSQL-Risiko konnte nicht aktualisiert werden")?;
        return Ok(risk_id);
    }

    sqlx::query_scalar(
        r#"
        INSERT INTO risks_risk (
            tenant_id,
            category_id,
            process_id,
            asset_id,
            owner_id,
            title,
            description,
            threat,
            vulnerability,
            impact,
            likelihood,
            residual_impact,
            residual_likelihood,
            status,
            treatment_strategy,
            treatment_plan,
            treatment_due_date,
            accepted_by_id,
            accepted_at,
            review_date,
            created_at,
            updated_at
        )
        VALUES (
            $1,
            NULL,
            NULL,
            NULL,
            NULL,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            NULL,
            NULL,
            'ANALYZING',
            'MITIGATE',
            $8,
            NULL,
            NULL,
            NULL,
            NULL,
            NOW(),
            NOW()
        )
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(title)
    .bind(description)
    .bind(threat)
    .bind(&cve.cve_id)
    .bind(risk_impact_for(&fields.deterministic_priority))
    .bind(risk_likelihood_for(&fields.exposure))
    .bind(treatment_plan)
    .fetch_one(pool)
    .await
    .context("PostgreSQL-Risiko konnte nicht erstellt werden")
}

async fn upsert_related_risk_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    cve: &CveRecordContext,
    product_name: Option<&str>,
    fields: &AssessmentWriteFields,
) -> anyhow::Result<i64> {
    let title = risk_title_for(&cve.cve_id, product_name);
    let legacy_title = risk_title_legacy_for(&cve.cve_id, product_name);
    let description = if fields.business_context.trim().is_empty() {
        cve.description.chars().take(3000).collect::<String>()
    } else {
        fields.business_context.clone()
    };
    let threat = if fields.attack_path.trim().is_empty() {
        cve.description.chars().take(1000).collect::<String>()
    } else {
        fields.attack_path.clone()
    };
    let treatment_plan = if fields.management_summary.trim().is_empty() {
        fields.business_impact.clone()
    } else {
        fields.management_summary.clone()
    };

    let existing_risk_id = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT id
        FROM risks_risk
        WHERE tenant_id = ?1
          AND (title = ?2 OR title = ?3)
        ORDER BY id DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(&title)
    .bind(&legacy_title)
    .fetch_optional(pool)
    .await
    .context("SQLite-Risiko konnte nicht abgeglichen werden")?;

    if let Some(risk_id) = existing_risk_id {
        sqlx::query(
            r#"
            UPDATE risks_risk
            SET title = ?1,
                description = ?2,
                threat = ?3,
                vulnerability = ?4,
                impact = ?5,
                likelihood = ?6,
                status = 'ANALYZING',
                treatment_strategy = 'MITIGATE',
                treatment_plan = ?7,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?8 AND tenant_id = ?9
            "#,
        )
        .bind(&title)
        .bind(description)
        .bind(threat)
        .bind(&cve.cve_id)
        .bind(risk_impact_for(&fields.deterministic_priority))
        .bind(risk_likelihood_for(&fields.exposure))
        .bind(treatment_plan)
        .bind(risk_id)
        .bind(tenant_id)
        .execute(pool)
        .await
        .context("SQLite-Risiko konnte nicht aktualisiert werden")?;
        return Ok(risk_id);
    }

    let result = sqlx::query(
        r#"
        INSERT INTO risks_risk (
            tenant_id,
            category_id,
            process_id,
            asset_id,
            owner_id,
            title,
            description,
            threat,
            vulnerability,
            impact,
            likelihood,
            residual_impact,
            residual_likelihood,
            status,
            treatment_strategy,
            treatment_plan,
            treatment_due_date,
            accepted_by_id,
            accepted_at,
            review_date,
            created_at,
            updated_at
        )
        VALUES (
            ?1,
            NULL,
            NULL,
            NULL,
            NULL,
            ?2,
            ?3,
            ?4,
            ?5,
            ?6,
            ?7,
            NULL,
            NULL,
            'ANALYZING',
            'MITIGATE',
            ?8,
            NULL,
            NULL,
            NULL,
            NULL,
            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP
        )
        "#,
    )
    .bind(tenant_id)
    .bind(title)
    .bind(description)
    .bind(threat)
    .bind(&cve.cve_id)
    .bind(risk_impact_for(&fields.deterministic_priority))
    .bind(risk_likelihood_for(&fields.exposure))
    .bind(treatment_plan)
    .execute(pool)
    .await
    .context("SQLite-Risiko konnte nicht erstellt werden")?;
    Ok(result.last_insert_rowid())
}

async fn upsert_assessment_postgres(
    pool: &PgPool,
    tenant_id: i64,
    payload: CveAssessmentWriteRequest,
) -> anyhow::Result<CveAssessmentWriteResult> {
    let payload = normalize_assessment_write_request(payload)?;
    let Some(cve) = fetch_cve_record_postgres(pool, &payload.cve_id).await? else {
        bail!(
            "not_found:cve:CVE '{}' wurde nicht gefunden. Bitte zuerst importieren oder synchronisieren.",
            payload.cve_id
        );
    };

    let explicit_product = if let Some(product_id) = payload.product_id {
        Some(
            product_record_postgres(pool, tenant_id, product_id)
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "not_found:product:Produkt {} wurde nicht gefunden.",
                        product_id
                    )
                })?,
        )
    } else {
        None
    };
    let release = if let Some(release_id) = payload.release_id {
        Some(
            release_record_postgres(pool, tenant_id, release_id)
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "not_found:release:Release {} wurde nicht gefunden.",
                        release_id
                    )
                })?,
        )
    } else {
        None
    };
    let component = if let Some(component_id) = payload.component_id {
        Some(
            component_record_postgres(pool, tenant_id, component_id)
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "not_found:component:Komponente {} wurde nicht gefunden.",
                        component_id
                    )
                })?,
        )
    } else {
        None
    };
    let (product, release, component) =
        resolve_product_release_component(&payload, explicit_product, release, component)?;
    let existing = existing_assessment_postgres(
        pool,
        tenant_id,
        cve.id,
        product.as_ref().map(|item| item.id),
        release.as_ref().map(|item| item.id),
        component.as_ref().map(|item| item.id),
    )
    .await?;
    let tenant_default_nis2 = tenant_default_nis2_postgres(pool, tenant_id).await?;
    let mut fields = build_assessment_write_fields(
        &payload,
        &cve,
        tenant_default_nis2,
        product.as_ref().map(|item| item.name.as_str()),
        existing.as_ref(),
    );

    if payload.auto_create_risk {
        fields.linked_vulnerability_id = if let Some(product) = product.as_ref() {
            Some(
                upsert_linked_vulnerability_postgres(
                    pool,
                    tenant_id,
                    &cve,
                    product,
                    release.as_ref(),
                    component.as_ref(),
                )
                .await?,
            )
        } else {
            existing
                .as_ref()
                .and_then(|item| item.linked_vulnerability_id)
        };
        fields.related_risk_id = Some(
            upsert_related_risk_postgres(
                pool,
                tenant_id,
                &cve,
                product.as_ref().map(|item| item.name.as_str()),
                &fields,
            )
            .await?,
        );
    }

    let regulatory_tags_json = Json(json!(fields.regulatory_tags));
    let deterministic_factors_json = Json(fields.deterministic_factors_json.clone());
    let recommended_actions_json = Json(json!(fields.recommended_actions));
    let evidence_needed_json = Json(json!(fields.evidence_needed));
    let raw_llm_json = Json(fields.raw_llm_json.clone());

    let (assessment_id, created) = if let Some(existing) = existing.as_ref() {
        sqlx::query(
            r#"
            UPDATE vulnerability_intelligence_cveassessment
            SET linked_vulnerability_id = $1,
                related_risk_id = $2,
                exposure = $3,
                asset_criticality = $4,
                epss_score = $5,
                in_kev_catalog = $6,
                exploit_maturity = $7,
                affects_critical_service = $8,
                nis2_relevant = $9,
                nis2_impact_summary = $10,
                repository_name = $11,
                repository_url = $12,
                git_ref = $13,
                source_package = $14,
                source_package_version = $15,
                regulatory_tags_json = $16,
                deterministic_factors_json = $17,
                business_context = $18,
                existing_controls = $19,
                deterministic_priority = $20,
                deterministic_due_days = $21,
                llm_backend = $22,
                llm_model_name = $23,
                llm_status = $24,
                technical_summary = $25,
                business_impact = $26,
                attack_path = $27,
                management_summary = $28,
                recommended_actions_json = $29,
                evidence_needed_json = $30,
                raw_llm_json = $31,
                confidence = $32,
                prompt_hash = $33,
                updated_at = NOW()
            WHERE id = $34 AND tenant_id = $35
            "#,
        )
        .bind(fields.linked_vulnerability_id)
        .bind(fields.related_risk_id)
        .bind(&fields.exposure)
        .bind(&fields.asset_criticality)
        .bind(fields.epss_score)
        .bind(fields.in_kev_catalog)
        .bind(&fields.exploit_maturity)
        .bind(fields.affects_critical_service)
        .bind(fields.nis2_relevant)
        .bind(&fields.nis2_impact_summary)
        .bind(&fields.repository_name)
        .bind(&fields.repository_url)
        .bind(&fields.git_ref)
        .bind(&fields.source_package)
        .bind(&fields.source_package_version)
        .bind(regulatory_tags_json)
        .bind(deterministic_factors_json)
        .bind(&fields.business_context)
        .bind(&fields.existing_controls)
        .bind(&fields.deterministic_priority)
        .bind(fields.deterministic_due_days)
        .bind(&fields.llm_backend)
        .bind(&fields.llm_model_name)
        .bind(&fields.llm_status)
        .bind(&fields.technical_summary)
        .bind(&fields.business_impact)
        .bind(&fields.attack_path)
        .bind(&fields.management_summary)
        .bind(recommended_actions_json)
        .bind(evidence_needed_json)
        .bind(raw_llm_json)
        .bind(&fields.confidence)
        .bind(&fields.prompt_hash)
        .bind(existing.id)
        .bind(tenant_id)
        .execute(pool)
        .await
        .context("PostgreSQL-CVE-Assessment konnte nicht aktualisiert werden")?;
        (existing.id, false)
    } else {
        let insert_regulatory_tags_json = Json(json!(fields.regulatory_tags.clone()));
        let insert_deterministic_factors_json = Json(fields.deterministic_factors_json.clone());
        let insert_recommended_actions_json = Json(json!(fields.recommended_actions.clone()));
        let insert_evidence_needed_json = Json(json!(fields.evidence_needed.clone()));
        let insert_raw_llm_json = Json(fields.raw_llm_json.clone());
        let assessment_id: i64 = sqlx::query_scalar(
            r#"
            INSERT INTO vulnerability_intelligence_cveassessment (
                tenant_id,
                cve_id,
                product_id,
                release_id,
                component_id,
                linked_vulnerability_id,
                related_risk_id,
                exposure,
                asset_criticality,
                epss_score,
                in_kev_catalog,
                exploit_maturity,
                affects_critical_service,
                nis2_relevant,
                nis2_impact_summary,
                repository_name,
                repository_url,
                git_ref,
                source_package,
                source_package_version,
                regulatory_tags_json,
                deterministic_factors_json,
                business_context,
                existing_controls,
                deterministic_priority,
                deterministic_due_days,
                llm_backend,
                llm_model_name,
                llm_status,
                technical_summary,
                business_impact,
                attack_path,
                management_summary,
                recommended_actions_json,
                evidence_needed_json,
                raw_llm_json,
                confidence,
                prompt_hash,
                reviewed_by_id,
                reviewed_at,
                review_notes,
                created_at,
                updated_at
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
                $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32,
                $33, $34, $35, $36, $37, $38, NULL, NULL, '', NOW(), NOW()
            )
            RETURNING id
            "#,
        )
        .bind(tenant_id)
        .bind(fields.cve_record_id)
        .bind(fields.product_id)
        .bind(fields.release_id)
        .bind(fields.component_id)
        .bind(fields.linked_vulnerability_id)
        .bind(fields.related_risk_id)
        .bind(&fields.exposure)
        .bind(&fields.asset_criticality)
        .bind(fields.epss_score)
        .bind(fields.in_kev_catalog)
        .bind(&fields.exploit_maturity)
        .bind(fields.affects_critical_service)
        .bind(fields.nis2_relevant)
        .bind(&fields.nis2_impact_summary)
        .bind(&fields.repository_name)
        .bind(&fields.repository_url)
        .bind(&fields.git_ref)
        .bind(&fields.source_package)
        .bind(&fields.source_package_version)
        .bind(insert_regulatory_tags_json)
        .bind(insert_deterministic_factors_json)
        .bind(&fields.business_context)
        .bind(&fields.existing_controls)
        .bind(&fields.deterministic_priority)
        .bind(fields.deterministic_due_days)
        .bind(&fields.llm_backend)
        .bind(&fields.llm_model_name)
        .bind(&fields.llm_status)
        .bind(&fields.technical_summary)
        .bind(&fields.business_impact)
        .bind(&fields.attack_path)
        .bind(&fields.management_summary)
        .bind(insert_recommended_actions_json)
        .bind(insert_evidence_needed_json)
        .bind(insert_raw_llm_json)
        .bind(&fields.confidence)
        .bind(&fields.prompt_hash)
        .fetch_one(pool)
        .await
        .context("PostgreSQL-CVE-Assessment konnte nicht erstellt werden")?;
        (assessment_id, true)
    };

    let assessment = assessment_detail_postgres(pool, tenant_id, assessment_id)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "database_error:Gespeichertes CVE-Assessment konnte nicht geladen werden."
            )
        })?;
    Ok(CveAssessmentWriteResult {
        created,
        assessment,
    })
}

async fn upsert_assessment_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    payload: CveAssessmentWriteRequest,
) -> anyhow::Result<CveAssessmentWriteResult> {
    let payload = normalize_assessment_write_request(payload)?;
    let Some(cve) = fetch_cve_record_sqlite(pool, &payload.cve_id).await? else {
        bail!(
            "not_found:cve:CVE '{}' wurde nicht gefunden. Bitte zuerst importieren oder synchronisieren.",
            payload.cve_id
        );
    };

    let explicit_product = if let Some(product_id) = payload.product_id {
        Some(
            product_record_sqlite(pool, tenant_id, product_id)
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "not_found:product:Produkt {} wurde nicht gefunden.",
                        product_id
                    )
                })?,
        )
    } else {
        None
    };
    let release = if let Some(release_id) = payload.release_id {
        Some(
            release_record_sqlite(pool, tenant_id, release_id)
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "not_found:release:Release {} wurde nicht gefunden.",
                        release_id
                    )
                })?,
        )
    } else {
        None
    };
    let component = if let Some(component_id) = payload.component_id {
        Some(
            component_record_sqlite(pool, tenant_id, component_id)
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "not_found:component:Komponente {} wurde nicht gefunden.",
                        component_id
                    )
                })?,
        )
    } else {
        None
    };
    let (product, release, component) =
        resolve_product_release_component(&payload, explicit_product, release, component)?;
    let existing = existing_assessment_sqlite(
        pool,
        tenant_id,
        cve.id,
        product.as_ref().map(|item| item.id),
        release.as_ref().map(|item| item.id),
        component.as_ref().map(|item| item.id),
    )
    .await?;
    let tenant_default_nis2 = tenant_default_nis2_sqlite(pool, tenant_id).await?;
    let mut fields = build_assessment_write_fields(
        &payload,
        &cve,
        tenant_default_nis2,
        product.as_ref().map(|item| item.name.as_str()),
        existing.as_ref(),
    );

    if payload.auto_create_risk {
        fields.linked_vulnerability_id = if let Some(product) = product.as_ref() {
            Some(
                upsert_linked_vulnerability_sqlite(
                    pool,
                    tenant_id,
                    &cve,
                    product,
                    release.as_ref(),
                    component.as_ref(),
                )
                .await?,
            )
        } else {
            existing
                .as_ref()
                .and_then(|item| item.linked_vulnerability_id)
        };
        fields.related_risk_id = Some(
            upsert_related_risk_sqlite(
                pool,
                tenant_id,
                &cve,
                product.as_ref().map(|item| item.name.as_str()),
                &fields,
            )
            .await?,
        );
    }

    let regulatory_tags_json = serde_json::to_string(&fields.regulatory_tags)?;
    let deterministic_factors_json = serde_json::to_string(&fields.deterministic_factors_json)?;
    let recommended_actions_json = serde_json::to_string(&fields.recommended_actions)?;
    let evidence_needed_json = serde_json::to_string(&fields.evidence_needed)?;
    let raw_llm_json = serde_json::to_string(&fields.raw_llm_json)?;

    let (assessment_id, created) = if let Some(existing) = existing.as_ref() {
        sqlx::query(
            r#"
            UPDATE vulnerability_intelligence_cveassessment
            SET linked_vulnerability_id = ?1,
                related_risk_id = ?2,
                exposure = ?3,
                asset_criticality = ?4,
                epss_score = ?5,
                in_kev_catalog = ?6,
                exploit_maturity = ?7,
                affects_critical_service = ?8,
                nis2_relevant = ?9,
                nis2_impact_summary = ?10,
                repository_name = ?11,
                repository_url = ?12,
                git_ref = ?13,
                source_package = ?14,
                source_package_version = ?15,
                regulatory_tags_json = ?16,
                deterministic_factors_json = ?17,
                business_context = ?18,
                existing_controls = ?19,
                deterministic_priority = ?20,
                deterministic_due_days = ?21,
                llm_backend = ?22,
                llm_model_name = ?23,
                llm_status = ?24,
                technical_summary = ?25,
                business_impact = ?26,
                attack_path = ?27,
                management_summary = ?28,
                recommended_actions_json = ?29,
                evidence_needed_json = ?30,
                raw_llm_json = ?31,
                confidence = ?32,
                prompt_hash = ?33,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?34 AND tenant_id = ?35
            "#,
        )
        .bind(fields.linked_vulnerability_id)
        .bind(fields.related_risk_id)
        .bind(&fields.exposure)
        .bind(&fields.asset_criticality)
        .bind(fields.epss_score.map(|value| value.to_string()))
        .bind(fields.in_kev_catalog)
        .bind(&fields.exploit_maturity)
        .bind(fields.affects_critical_service)
        .bind(fields.nis2_relevant)
        .bind(&fields.nis2_impact_summary)
        .bind(&fields.repository_name)
        .bind(&fields.repository_url)
        .bind(&fields.git_ref)
        .bind(&fields.source_package)
        .bind(&fields.source_package_version)
        .bind(regulatory_tags_json)
        .bind(deterministic_factors_json)
        .bind(&fields.business_context)
        .bind(&fields.existing_controls)
        .bind(&fields.deterministic_priority)
        .bind(fields.deterministic_due_days)
        .bind(&fields.llm_backend)
        .bind(&fields.llm_model_name)
        .bind(&fields.llm_status)
        .bind(&fields.technical_summary)
        .bind(&fields.business_impact)
        .bind(&fields.attack_path)
        .bind(&fields.management_summary)
        .bind(recommended_actions_json)
        .bind(evidence_needed_json)
        .bind(raw_llm_json)
        .bind(&fields.confidence)
        .bind(&fields.prompt_hash)
        .bind(existing.id)
        .bind(tenant_id)
        .execute(pool)
        .await
        .context("SQLite-CVE-Assessment konnte nicht aktualisiert werden")?;
        (existing.id, false)
    } else {
        let result = sqlx::query(
            r#"
            INSERT INTO vulnerability_intelligence_cveassessment (
                tenant_id,
                cve_id,
                product_id,
                release_id,
                component_id,
                linked_vulnerability_id,
                related_risk_id,
                exposure,
                asset_criticality,
                epss_score,
                in_kev_catalog,
                exploit_maturity,
                affects_critical_service,
                nis2_relevant,
                nis2_impact_summary,
                repository_name,
                repository_url,
                git_ref,
                source_package,
                source_package_version,
                regulatory_tags_json,
                deterministic_factors_json,
                business_context,
                existing_controls,
                deterministic_priority,
                deterministic_due_days,
                llm_backend,
                llm_model_name,
                llm_status,
                technical_summary,
                business_impact,
                attack_path,
                management_summary,
                recommended_actions_json,
                evidence_needed_json,
                raw_llm_json,
                confidence,
                prompt_hash,
                reviewed_by_id,
                reviewed_at,
                review_notes,
                created_at,
                updated_at
            )
            VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
                ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32,
                ?33, ?34, ?35, ?36, ?37, ?38, NULL, NULL, '', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            )
            "#,
        )
        .bind(tenant_id)
        .bind(fields.cve_record_id)
        .bind(fields.product_id)
        .bind(fields.release_id)
        .bind(fields.component_id)
        .bind(fields.linked_vulnerability_id)
        .bind(fields.related_risk_id)
        .bind(&fields.exposure)
        .bind(&fields.asset_criticality)
        .bind(fields.epss_score.map(|value| value.to_string()))
        .bind(fields.in_kev_catalog)
        .bind(&fields.exploit_maturity)
        .bind(fields.affects_critical_service)
        .bind(fields.nis2_relevant)
        .bind(&fields.nis2_impact_summary)
        .bind(&fields.repository_name)
        .bind(&fields.repository_url)
        .bind(&fields.git_ref)
        .bind(&fields.source_package)
        .bind(&fields.source_package_version)
        .bind(serde_json::to_string(&fields.regulatory_tags)?)
        .bind(serde_json::to_string(&fields.deterministic_factors_json)?)
        .bind(&fields.business_context)
        .bind(&fields.existing_controls)
        .bind(&fields.deterministic_priority)
        .bind(fields.deterministic_due_days)
        .bind(&fields.llm_backend)
        .bind(&fields.llm_model_name)
        .bind(&fields.llm_status)
        .bind(&fields.technical_summary)
        .bind(&fields.business_impact)
        .bind(&fields.attack_path)
        .bind(&fields.management_summary)
        .bind(serde_json::to_string(&fields.recommended_actions)?)
        .bind(serde_json::to_string(&fields.evidence_needed)?)
        .bind(serde_json::to_string(&fields.raw_llm_json)?)
        .bind(&fields.confidence)
        .bind(&fields.prompt_hash)
        .execute(pool)
        .await
        .context("SQLite-CVE-Assessment konnte nicht erstellt werden")?;
        (result.last_insert_rowid(), true)
    };

    let assessment = assessment_detail_sqlite(pool, tenant_id, assessment_id)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "database_error:Gespeichertes CVE-Assessment konnte nicht geladen werden."
            )
        })?;
    Ok(CveAssessmentWriteResult {
        created,
        assessment,
    })
}

fn assessment_list_postgres_sql() -> &'static str {
    r#"
    SELECT
        assessment.id,
        assessment.tenant_id,
        cve.cve_id,
        cve.description AS cve_description,
        cve.severity AS cve_severity,
        CAST(cve.cvss_score AS TEXT) AS cve_cvss_score_text,
        assessment.product_id,
        product.name AS product_name,
        assessment.release_id,
        release.version AS release_version,
        assessment.component_id,
        component.name AS component_name,
        assessment.linked_vulnerability_id,
        vulnerability.title AS linked_vulnerability_title,
        assessment.related_risk_id,
        risk.title AS related_risk_title,
        assessment.exposure,
        assessment.asset_criticality,
        CAST(assessment.epss_score AS TEXT) AS epss_score_text,
        assessment.in_kev_catalog,
        assessment.exploit_maturity,
        assessment.affects_critical_service,
        assessment.nis2_relevant,
        assessment.deterministic_priority,
        assessment.llm_status,
        assessment.deterministic_due_days::bigint AS deterministic_due_days,
        assessment.confidence,
        assessment.created_at::text AS created_at,
        assessment.updated_at::text AS updated_at
    FROM vulnerability_intelligence_cveassessment assessment
    JOIN vulnerability_intelligence_cverecord cve
        ON cve.id = assessment.cve_id
    LEFT JOIN product_security_product product
        ON product.id = assessment.product_id AND product.tenant_id = assessment.tenant_id
    LEFT JOIN product_security_productrelease release
        ON release.id = assessment.release_id AND release.tenant_id = assessment.tenant_id
    LEFT JOIN product_security_component component
        ON component.id = assessment.component_id AND component.tenant_id = assessment.tenant_id
    LEFT JOIN product_security_vulnerability vulnerability
        ON vulnerability.id = assessment.linked_vulnerability_id AND vulnerability.tenant_id = assessment.tenant_id
    LEFT JOIN risks_risk risk
        ON risk.id = assessment.related_risk_id AND risk.tenant_id = assessment.tenant_id
    WHERE assessment.tenant_id = $1
    ORDER BY COALESCE(assessment.updated_at, assessment.created_at) DESC, assessment.id DESC
    LIMIT $2
    "#
}

fn assessment_list_sqlite_sql() -> &'static str {
    r#"
    SELECT
        assessment.id,
        assessment.tenant_id,
        cve.cve_id,
        cve.description AS cve_description,
        cve.severity AS cve_severity,
        CAST(cve.cvss_score AS TEXT) AS cve_cvss_score_text,
        assessment.product_id,
        product.name AS product_name,
        assessment.release_id,
        release.version AS release_version,
        assessment.component_id,
        component.name AS component_name,
        assessment.linked_vulnerability_id,
        vulnerability.title AS linked_vulnerability_title,
        assessment.related_risk_id,
        risk.title AS related_risk_title,
        assessment.exposure,
        assessment.asset_criticality,
        CAST(assessment.epss_score AS TEXT) AS epss_score_text,
        assessment.in_kev_catalog,
        assessment.exploit_maturity,
        assessment.affects_critical_service,
        assessment.nis2_relevant,
        assessment.deterministic_priority,
        assessment.llm_status,
        assessment.deterministic_due_days,
        assessment.confidence,
        CAST(assessment.created_at AS TEXT) AS created_at,
        CAST(assessment.updated_at AS TEXT) AS updated_at
    FROM vulnerability_intelligence_cveassessment assessment
    JOIN vulnerability_intelligence_cverecord cve
        ON cve.id = assessment.cve_id
    LEFT JOIN product_security_product product
        ON product.id = assessment.product_id AND product.tenant_id = assessment.tenant_id
    LEFT JOIN product_security_productrelease release
        ON release.id = assessment.release_id AND release.tenant_id = assessment.tenant_id
    LEFT JOIN product_security_component component
        ON component.id = assessment.component_id AND component.tenant_id = assessment.tenant_id
    LEFT JOIN product_security_vulnerability vulnerability
        ON vulnerability.id = assessment.linked_vulnerability_id AND vulnerability.tenant_id = assessment.tenant_id
    LEFT JOIN risks_risk risk
        ON risk.id = assessment.related_risk_id AND risk.tenant_id = assessment.tenant_id
    WHERE assessment.tenant_id = ?
    ORDER BY COALESCE(assessment.updated_at, assessment.created_at) DESC, assessment.id DESC
    LIMIT ?
    "#
}

fn assessment_detail_postgres_sql() -> &'static str {
    r#"
    SELECT
        assessment.id,
        assessment.tenant_id,
        cve.cve_id,
        cve.description AS cve_description,
        cve.severity AS cve_severity,
        CAST(cve.cvss_score AS TEXT) AS cve_cvss_score_text,
        cve.cvss_vector,
        COALESCE(cve.weakness_ids_json::text, '[]') AS weakness_ids_json_text,
        COALESCE(cve.references_json::text, '[]') AS references_json_text,
        cve.kev_date_added::text AS kev_date_added,
        cve.kev_vendor_project,
        cve.kev_product,
        cve.kev_required_action,
        cve.kev_known_ransomware,
        assessment.product_id,
        product.name AS product_name,
        assessment.release_id,
        release.version AS release_version,
        assessment.component_id,
        component.name AS component_name,
        assessment.linked_vulnerability_id,
        vulnerability.title AS linked_vulnerability_title,
        assessment.related_risk_id,
        risk.title AS related_risk_title,
        assessment.exposure,
        assessment.asset_criticality,
        CAST(assessment.epss_score AS TEXT) AS epss_score_text,
        assessment.in_kev_catalog,
        assessment.exploit_maturity,
        assessment.affects_critical_service,
        assessment.nis2_relevant,
        assessment.deterministic_priority,
        assessment.llm_status,
        assessment.deterministic_due_days::bigint AS deterministic_due_days,
        assessment.confidence,
        assessment.repository_name,
        assessment.repository_url,
        assessment.git_ref,
        assessment.source_package,
        assessment.source_package_version,
        COALESCE(assessment.regulatory_tags_json::text, '[]') AS regulatory_tags_json_text,
        COALESCE(assessment.deterministic_factors_json::text, '{}') AS deterministic_factors_json_text,
        assessment.nis2_impact_summary,
        assessment.business_context,
        assessment.existing_controls,
        assessment.llm_backend,
        assessment.llm_model_name,
        assessment.technical_summary,
        assessment.business_impact,
        assessment.attack_path,
        assessment.management_summary,
        COALESCE(assessment.recommended_actions_json::text, '[]') AS recommended_actions_json_text,
        COALESCE(assessment.evidence_needed_json::text, '[]') AS evidence_needed_json_text,
        COALESCE(assessment.raw_llm_json::text, '{}') AS raw_llm_json_text,
        reviewer.username AS reviewed_by_username,
        reviewer.first_name AS reviewed_by_first_name,
        reviewer.last_name AS reviewed_by_last_name,
        assessment.reviewed_at::text AS reviewed_at,
        assessment.review_notes,
        assessment.created_at::text AS created_at,
        assessment.updated_at::text AS updated_at
    FROM vulnerability_intelligence_cveassessment assessment
    JOIN vulnerability_intelligence_cverecord cve
        ON cve.id = assessment.cve_id
    LEFT JOIN product_security_product product
        ON product.id = assessment.product_id AND product.tenant_id = assessment.tenant_id
    LEFT JOIN product_security_productrelease release
        ON release.id = assessment.release_id AND release.tenant_id = assessment.tenant_id
    LEFT JOIN product_security_component component
        ON component.id = assessment.component_id AND component.tenant_id = assessment.tenant_id
    LEFT JOIN product_security_vulnerability vulnerability
        ON vulnerability.id = assessment.linked_vulnerability_id AND vulnerability.tenant_id = assessment.tenant_id
    LEFT JOIN risks_risk risk
        ON risk.id = assessment.related_risk_id AND risk.tenant_id = assessment.tenant_id
    LEFT JOIN accounts_user reviewer
        ON reviewer.id = assessment.reviewed_by_id
    WHERE assessment.tenant_id = $1 AND assessment.id = $2
    "#
}

fn assessment_detail_sqlite_sql() -> &'static str {
    r#"
    SELECT
        assessment.id,
        assessment.tenant_id,
        cve.cve_id,
        cve.description AS cve_description,
        cve.severity AS cve_severity,
        CAST(cve.cvss_score AS TEXT) AS cve_cvss_score_text,
        cve.cvss_vector,
        COALESCE(CAST(cve.weakness_ids_json AS TEXT), '[]') AS weakness_ids_json_text,
        COALESCE(CAST(cve.references_json AS TEXT), '[]') AS references_json_text,
        CAST(cve.kev_date_added AS TEXT) AS kev_date_added,
        cve.kev_vendor_project,
        cve.kev_product,
        cve.kev_required_action,
        cve.kev_known_ransomware,
        assessment.product_id,
        product.name AS product_name,
        assessment.release_id,
        release.version AS release_version,
        assessment.component_id,
        component.name AS component_name,
        assessment.linked_vulnerability_id,
        vulnerability.title AS linked_vulnerability_title,
        assessment.related_risk_id,
        risk.title AS related_risk_title,
        assessment.exposure,
        assessment.asset_criticality,
        CAST(assessment.epss_score AS TEXT) AS epss_score_text,
        assessment.in_kev_catalog,
        assessment.exploit_maturity,
        assessment.affects_critical_service,
        assessment.nis2_relevant,
        assessment.deterministic_priority,
        assessment.llm_status,
        assessment.deterministic_due_days,
        assessment.confidence,
        assessment.repository_name,
        assessment.repository_url,
        assessment.git_ref,
        assessment.source_package,
        assessment.source_package_version,
        COALESCE(CAST(assessment.regulatory_tags_json AS TEXT), '[]') AS regulatory_tags_json_text,
        COALESCE(CAST(assessment.deterministic_factors_json AS TEXT), '{}') AS deterministic_factors_json_text,
        assessment.nis2_impact_summary,
        assessment.business_context,
        assessment.existing_controls,
        assessment.llm_backend,
        assessment.llm_model_name,
        assessment.technical_summary,
        assessment.business_impact,
        assessment.attack_path,
        assessment.management_summary,
        COALESCE(CAST(assessment.recommended_actions_json AS TEXT), '[]') AS recommended_actions_json_text,
        COALESCE(CAST(assessment.evidence_needed_json AS TEXT), '[]') AS evidence_needed_json_text,
        COALESCE(CAST(assessment.raw_llm_json AS TEXT), '{}') AS raw_llm_json_text,
        reviewer.username AS reviewed_by_username,
        reviewer.first_name AS reviewed_by_first_name,
        reviewer.last_name AS reviewed_by_last_name,
        CAST(assessment.reviewed_at AS TEXT) AS reviewed_at,
        assessment.review_notes,
        CAST(assessment.created_at AS TEXT) AS created_at,
        CAST(assessment.updated_at AS TEXT) AS updated_at
    FROM vulnerability_intelligence_cveassessment assessment
    JOIN vulnerability_intelligence_cverecord cve
        ON cve.id = assessment.cve_id
    LEFT JOIN product_security_product product
        ON product.id = assessment.product_id AND product.tenant_id = assessment.tenant_id
    LEFT JOIN product_security_productrelease release
        ON release.id = assessment.release_id AND release.tenant_id = assessment.tenant_id
    LEFT JOIN product_security_component component
        ON component.id = assessment.component_id AND component.tenant_id = assessment.tenant_id
    LEFT JOIN product_security_vulnerability vulnerability
        ON vulnerability.id = assessment.linked_vulnerability_id AND vulnerability.tenant_id = assessment.tenant_id
    LEFT JOIN risks_risk risk
        ON risk.id = assessment.related_risk_id AND risk.tenant_id = assessment.tenant_id
    LEFT JOIN accounts_user reviewer
        ON reviewer.id = assessment.reviewed_by_id
    WHERE assessment.tenant_id = ? AND assessment.id = ?
    "#
}

async fn upsert_postgres(pool: &PgPool, record: &NvdCveRecord) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO vulnerability_intelligence_cverecord (
            created_at,
            updated_at,
            cve_id,
            source,
            description,
            cvss_score,
            cvss_vector,
            severity,
            weakness_ids_json,
            references_json,
            configurations_json,
            epss_score,
            in_kev_catalog,
            kev_date_added,
            kev_vendor_project,
            kev_product,
            kev_required_action,
            kev_known_ransomware,
            raw_json,
            published_at,
            modified_at
        )
        VALUES (
            NOW(),
            NOW(),
            $1,
            'NVD',
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8,
            NULL,
            FALSE,
            NULL,
            '',
            '',
            '',
            FALSE,
            $9,
            $10,
            $11
        )
        ON CONFLICT (cve_id) DO UPDATE SET
            updated_at = NOW(),
            source = EXCLUDED.source,
            description = EXCLUDED.description,
            cvss_score = EXCLUDED.cvss_score,
            cvss_vector = EXCLUDED.cvss_vector,
            severity = EXCLUDED.severity,
            weakness_ids_json = EXCLUDED.weakness_ids_json,
            references_json = EXCLUDED.references_json,
            configurations_json = EXCLUDED.configurations_json,
            raw_json = EXCLUDED.raw_json,
            published_at = EXCLUDED.published_at,
            modified_at = EXCLUDED.modified_at
        "#,
    )
    .bind(&record.cve_id)
    .bind(&record.description)
    .bind(record.cvss_score)
    .bind(&record.cvss_vector)
    .bind(&record.severity)
    .bind(Json(record.weakness_ids_json.clone()))
    .bind(Json(record.references_json.clone()))
    .bind(Json(record.configurations_json.clone()))
    .bind(Json(record.raw_json.clone()))
    .bind(record.published_at)
    .bind(record.modified_at)
    .execute(pool)
    .await
    .context("PostgreSQL-Upsert fuer CVERecord fehlgeschlagen")?;
    Ok(())
}

async fn upsert_sqlite(pool: &SqlitePool, record: &NvdCveRecord) -> anyhow::Result<()> {
    let weakness_ids_json = serde_json::to_string(&record.weakness_ids_json)?;
    let references_json = serde_json::to_string(&record.references_json)?;
    let configurations_json = serde_json::to_string(&record.configurations_json)?;
    let raw_json = serde_json::to_string(&record.raw_json)?;
    let cvss_score = record.cvss_score.map(|score| score.to_string());
    let published_at = record.published_at.map(|dt| dt.to_rfc3339());
    let modified_at = record.modified_at.map(|dt| dt.to_rfc3339());

    sqlx::query(
        r#"
        INSERT INTO vulnerability_intelligence_cverecord (
            created_at,
            updated_at,
            cve_id,
            source,
            description,
            cvss_score,
            cvss_vector,
            severity,
            weakness_ids_json,
            references_json,
            configurations_json,
            epss_score,
            in_kev_catalog,
            kev_date_added,
            kev_vendor_project,
            kev_product,
            kev_required_action,
            kev_known_ransomware,
            raw_json,
            published_at,
            modified_at
        )
        VALUES (
            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP,
            ?,
            'NVD',
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            NULL,
            0,
            NULL,
            '',
            '',
            '',
            0,
            ?,
            ?,
            ?
        )
        ON CONFLICT (cve_id) DO UPDATE SET
            updated_at = CURRENT_TIMESTAMP,
            source = excluded.source,
            description = excluded.description,
            cvss_score = excluded.cvss_score,
            cvss_vector = excluded.cvss_vector,
            severity = excluded.severity,
            weakness_ids_json = excluded.weakness_ids_json,
            references_json = excluded.references_json,
            configurations_json = excluded.configurations_json,
            raw_json = excluded.raw_json,
            published_at = excluded.published_at,
            modified_at = excluded.modified_at
        "#,
    )
    .bind(&record.cve_id)
    .bind(&record.description)
    .bind(cvss_score)
    .bind(&record.cvss_vector)
    .bind(&record.severity)
    .bind(weakness_ids_json)
    .bind(references_json)
    .bind(configurations_json)
    .bind(raw_json)
    .bind(published_at)
    .bind(modified_at)
    .execute(pool)
    .await
    .context("SQLite-Upsert fuer CVERecord fehlgeschlagen")?;
    Ok(())
}

fn description(cve: &Value) -> String {
    let descriptions = cve
        .get("descriptions")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    descriptions
        .iter()
        .find(|item| item.get("lang").and_then(Value::as_str) == Some("en"))
        .or_else(|| descriptions.first())
        .and_then(|item| item.get("value"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn cvss_fields(metrics: &Value) -> (Option<Decimal>, String, String) {
    for key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30"] {
        let Some(metric) = metrics
            .get(key)
            .and_then(Value::as_array)
            .and_then(|items| items.first())
        else {
            continue;
        };
        let cvss = metric.get("cvssData").unwrap_or(&Value::Null);
        let score = cvss.get("baseScore").and_then(decimal_from_json);
        let vector = cvss
            .get("vectorString")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let severity = metric
            .get("baseSeverity")
            .or_else(|| cvss.get("baseSeverity"))
            .and_then(Value::as_str)
            .map(normalize_severity)
            .unwrap_or_else(|| "UNKNOWN".to_string());
        return (score, vector, severity);
    }
    (None, String::new(), "UNKNOWN".to_string())
}

fn decimal_from_json(value: &Value) -> Option<Decimal> {
    match value {
        Value::Number(number) => Decimal::from_str(&number.to_string()).ok(),
        Value::String(text) => Decimal::from_str(text.trim()).ok(),
        _ => None,
    }
}

fn normalize_severity(severity: &str) -> String {
    let normalized = severity.trim().to_uppercase();
    match normalized.as_str() {
        "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" => normalized,
        _ => "UNKNOWN".to_string(),
    }
}

fn weakness_ids(cve: &Value) -> Vec<String> {
    cve.get("weaknesses")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|weakness| {
            weakness
                .get("description")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter_map(|desc| desc.get("value").and_then(Value::as_str))
        .filter(|value| !value.trim().is_empty())
        .map(ToString::to_string)
        .collect()
}

fn references(cve: &Value) -> Vec<String> {
    cve.get("references")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|reference| reference.get("url").and_then(Value::as_str))
        .filter(|value| !value.trim().is_empty())
        .map(ToString::to_string)
        .collect()
}

fn parse_nvd_datetime(value: Option<&Value>) -> Option<DateTime<Utc>> {
    let text = value?.as_str()?.trim();
    if text.is_empty() {
        return None;
    }
    DateTime::parse_from_rfc3339(text)
        .map(|dt| dt.with_timezone(&Utc))
        .ok()
}

fn summary_from_pg_row(row: sqlx::postgres::PgRow) -> Result<CveRecordSummary, sqlx::Error> {
    let severity: String = row.try_get("severity")?;
    Ok(CveRecordSummary {
        id: row.try_get("id")?,
        cve_id: row.try_get("cve_id")?,
        source: row.try_get("source")?,
        description: row.try_get("description")?,
        cvss_score: row.try_get("cvss_score_text")?,
        cvss_vector: row.try_get("cvss_vector")?,
        severity_label: severity_label(&severity).to_string(),
        severity,
        epss_score: row.try_get("epss_score_text")?,
        in_kev_catalog: row.try_get("in_kev_catalog")?,
        kev_known_ransomware: row.try_get("kev_known_ransomware")?,
        published_at: row.try_get("published_at")?,
        modified_at: row.try_get("modified_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn summary_from_sqlite_row(row: sqlx::sqlite::SqliteRow) -> Result<CveRecordSummary, sqlx::Error> {
    let severity: String = row.try_get("severity")?;
    Ok(CveRecordSummary {
        id: row.try_get("id")?,
        cve_id: row.try_get("cve_id")?,
        source: row.try_get("source")?,
        description: row.try_get("description")?,
        cvss_score: row.try_get("cvss_score_text")?,
        cvss_vector: row.try_get("cvss_vector")?,
        severity_label: severity_label(&severity).to_string(),
        severity,
        epss_score: row.try_get("epss_score_text")?,
        in_kev_catalog: row.try_get("in_kev_catalog")?,
        kev_known_ransomware: row.try_get("kev_known_ransomware")?,
        published_at: row.try_get("published_at")?,
        modified_at: row.try_get("modified_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn detail_from_pg_row(row: sqlx::postgres::PgRow) -> Result<CveRecordDetail, sqlx::Error> {
    let severity: String = row.try_get("severity")?;
    Ok(CveRecordDetail {
        id: row.try_get("id")?,
        cve_id: row.try_get("cve_id")?,
        source: row.try_get("source")?,
        description: row.try_get("description")?,
        cvss_score: row.try_get("cvss_score_text")?,
        cvss_vector: row.try_get("cvss_vector")?,
        severity_label: severity_label(&severity).to_string(),
        severity,
        weakness_ids: parse_json_string_array(row.try_get("weakness_ids_json_text")?),
        references: parse_json_string_array(row.try_get("references_json_text")?),
        configurations_json: parse_json_value(row.try_get("configurations_json_text")?, json!([])),
        epss_score: row.try_get("epss_score_text")?,
        in_kev_catalog: row.try_get("in_kev_catalog")?,
        kev_date_added: row.try_get("kev_date_added")?,
        kev_vendor_project: row.try_get("kev_vendor_project")?,
        kev_product: row.try_get("kev_product")?,
        kev_required_action: row.try_get("kev_required_action")?,
        kev_known_ransomware: row.try_get("kev_known_ransomware")?,
        raw_json: parse_json_value(row.try_get("raw_json_text")?, json!({})),
        published_at: row.try_get("published_at")?,
        modified_at: row.try_get("modified_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn detail_from_sqlite_row(row: sqlx::sqlite::SqliteRow) -> Result<CveRecordDetail, sqlx::Error> {
    let severity: String = row.try_get("severity")?;
    Ok(CveRecordDetail {
        id: row.try_get("id")?,
        cve_id: row.try_get("cve_id")?,
        source: row.try_get("source")?,
        description: row.try_get("description")?,
        cvss_score: row.try_get("cvss_score_text")?,
        cvss_vector: row.try_get("cvss_vector")?,
        severity_label: severity_label(&severity).to_string(),
        severity,
        weakness_ids: parse_json_string_array(row.try_get("weakness_ids_json_text")?),
        references: parse_json_string_array(row.try_get("references_json_text")?),
        configurations_json: parse_json_value(row.try_get("configurations_json_text")?, json!([])),
        epss_score: row.try_get("epss_score_text")?,
        in_kev_catalog: row.try_get("in_kev_catalog")?,
        kev_date_added: row.try_get("kev_date_added")?,
        kev_vendor_project: row.try_get("kev_vendor_project")?,
        kev_product: row.try_get("kev_product")?,
        kev_required_action: row.try_get("kev_required_action")?,
        kev_known_ransomware: row.try_get("kev_known_ransomware")?,
        raw_json: parse_json_value(row.try_get("raw_json_text")?, json!({})),
        published_at: row.try_get("published_at")?,
        modified_at: row.try_get("modified_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn assessment_summary_from_pg_row(
    row: sqlx::postgres::PgRow,
) -> Result<CveAssessmentSummary, sqlx::Error> {
    let cve_severity: String = row.try_get("cve_severity")?;
    let exposure: String = row.try_get("exposure")?;
    let asset_criticality: String = row.try_get("asset_criticality")?;
    let exploit_maturity: String = row.try_get("exploit_maturity")?;
    let llm_status: String = row.try_get("llm_status")?;
    Ok(CveAssessmentSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        cve_id: row.try_get("cve_id")?,
        cve_description: row.try_get("cve_description")?,
        cve_severity_label: severity_label(&cve_severity).to_string(),
        cve_severity,
        cve_cvss_score: row.try_get("cve_cvss_score_text")?,
        product_id: row.try_get("product_id")?,
        product_name: row.try_get("product_name")?,
        release_id: row.try_get("release_id")?,
        release_version: row.try_get("release_version")?,
        component_id: row.try_get("component_id")?,
        component_name: row.try_get("component_name")?,
        linked_vulnerability_id: row.try_get("linked_vulnerability_id")?,
        linked_vulnerability_title: row.try_get("linked_vulnerability_title")?,
        related_risk_id: row.try_get("related_risk_id")?,
        related_risk_title: row.try_get("related_risk_title")?,
        exposure_label: exposure_label(&exposure).to_string(),
        exposure,
        asset_criticality_label: asset_criticality_label(&asset_criticality).to_string(),
        asset_criticality,
        epss_score: row.try_get("epss_score_text")?,
        in_kev_catalog: row.try_get("in_kev_catalog")?,
        exploit_maturity_label: exploit_maturity_label(&exploit_maturity).to_string(),
        exploit_maturity,
        affects_critical_service: row.try_get("affects_critical_service")?,
        nis2_relevant: row.try_get("nis2_relevant")?,
        deterministic_priority: row.try_get("deterministic_priority")?,
        llm_status_label: llm_status_label(&llm_status).to_string(),
        llm_status,
        deterministic_due_days: row.try_get("deterministic_due_days")?,
        confidence: row.try_get("confidence")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn assessment_summary_from_sqlite_row(
    row: sqlx::sqlite::SqliteRow,
) -> Result<CveAssessmentSummary, sqlx::Error> {
    let cve_severity: String = row.try_get("cve_severity")?;
    let exposure: String = row.try_get("exposure")?;
    let asset_criticality: String = row.try_get("asset_criticality")?;
    let exploit_maturity: String = row.try_get("exploit_maturity")?;
    let llm_status: String = row.try_get("llm_status")?;
    Ok(CveAssessmentSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        cve_id: row.try_get("cve_id")?,
        cve_description: row.try_get("cve_description")?,
        cve_severity_label: severity_label(&cve_severity).to_string(),
        cve_severity,
        cve_cvss_score: row.try_get("cve_cvss_score_text")?,
        product_id: row.try_get("product_id")?,
        product_name: row.try_get("product_name")?,
        release_id: row.try_get("release_id")?,
        release_version: row.try_get("release_version")?,
        component_id: row.try_get("component_id")?,
        component_name: row.try_get("component_name")?,
        linked_vulnerability_id: row.try_get("linked_vulnerability_id")?,
        linked_vulnerability_title: row.try_get("linked_vulnerability_title")?,
        related_risk_id: row.try_get("related_risk_id")?,
        related_risk_title: row.try_get("related_risk_title")?,
        exposure_label: exposure_label(&exposure).to_string(),
        exposure,
        asset_criticality_label: asset_criticality_label(&asset_criticality).to_string(),
        asset_criticality,
        epss_score: row.try_get("epss_score_text")?,
        in_kev_catalog: row.try_get("in_kev_catalog")?,
        exploit_maturity_label: exploit_maturity_label(&exploit_maturity).to_string(),
        exploit_maturity,
        affects_critical_service: row.try_get("affects_critical_service")?,
        nis2_relevant: row.try_get("nis2_relevant")?,
        deterministic_priority: row.try_get("deterministic_priority")?,
        llm_status_label: llm_status_label(&llm_status).to_string(),
        llm_status,
        deterministic_due_days: row.try_get("deterministic_due_days")?,
        confidence: row.try_get("confidence")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn assessment_detail_from_pg_row(
    row: sqlx::postgres::PgRow,
) -> Result<CveAssessmentDetail, sqlx::Error> {
    let cve_severity: String = row.try_get("cve_severity")?;
    let exposure: String = row.try_get("exposure")?;
    let asset_criticality: String = row.try_get("asset_criticality")?;
    let exploit_maturity: String = row.try_get("exploit_maturity")?;
    let llm_status: String = row.try_get("llm_status")?;
    Ok(CveAssessmentDetail {
        summary: CveAssessmentSummary {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            cve_id: row.try_get("cve_id")?,
            cve_description: row.try_get("cve_description")?,
            cve_severity_label: severity_label(&cve_severity).to_string(),
            cve_severity,
            cve_cvss_score: row.try_get("cve_cvss_score_text")?,
            product_id: row.try_get("product_id")?,
            product_name: row.try_get("product_name")?,
            release_id: row.try_get("release_id")?,
            release_version: row.try_get("release_version")?,
            component_id: row.try_get("component_id")?,
            component_name: row.try_get("component_name")?,
            linked_vulnerability_id: row.try_get("linked_vulnerability_id")?,
            linked_vulnerability_title: row.try_get("linked_vulnerability_title")?,
            related_risk_id: row.try_get("related_risk_id")?,
            related_risk_title: row.try_get("related_risk_title")?,
            exposure_label: exposure_label(&exposure).to_string(),
            exposure,
            asset_criticality_label: asset_criticality_label(&asset_criticality).to_string(),
            asset_criticality,
            epss_score: row.try_get("epss_score_text")?,
            in_kev_catalog: row.try_get("in_kev_catalog")?,
            exploit_maturity_label: exploit_maturity_label(&exploit_maturity).to_string(),
            exploit_maturity,
            affects_critical_service: row.try_get("affects_critical_service")?,
            nis2_relevant: row.try_get("nis2_relevant")?,
            deterministic_priority: row.try_get("deterministic_priority")?,
            llm_status_label: llm_status_label(&llm_status).to_string(),
            llm_status,
            deterministic_due_days: row.try_get("deterministic_due_days")?,
            confidence: row.try_get("confidence")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        },
        cvss_vector: row.try_get("cvss_vector")?,
        weakness_ids: parse_json_string_array(row.try_get("weakness_ids_json_text")?),
        references: parse_json_string_array(row.try_get("references_json_text")?),
        kev_date_added: row.try_get("kev_date_added")?,
        kev_vendor_project: row.try_get("kev_vendor_project")?,
        kev_product: row.try_get("kev_product")?,
        kev_required_action: row.try_get("kev_required_action")?,
        kev_known_ransomware: row.try_get("kev_known_ransomware")?,
        repository_name: row.try_get("repository_name")?,
        repository_url: row.try_get("repository_url")?,
        git_ref: row.try_get("git_ref")?,
        source_package: row.try_get("source_package")?,
        source_package_version: row.try_get("source_package_version")?,
        regulatory_tags: parse_json_string_array(row.try_get("regulatory_tags_json_text")?),
        deterministic_factors_json: parse_json_value(
            row.try_get("deterministic_factors_json_text")?,
            json!({}),
        ),
        nis2_impact_summary: row.try_get("nis2_impact_summary")?,
        business_context: row.try_get("business_context")?,
        existing_controls: row.try_get("existing_controls")?,
        llm_backend: row.try_get("llm_backend")?,
        llm_model_name: row.try_get("llm_model_name")?,
        technical_summary: row.try_get("technical_summary")?,
        business_impact: row.try_get("business_impact")?,
        attack_path: row.try_get("attack_path")?,
        management_summary: row.try_get("management_summary")?,
        recommended_actions: parse_json_string_array(row.try_get("recommended_actions_json_text")?),
        evidence_needed: parse_json_string_array(row.try_get("evidence_needed_json_text")?),
        raw_llm_json: parse_json_value(row.try_get("raw_llm_json_text")?, json!({})),
        reviewed_by_display: user_display(
            row.try_get("reviewed_by_username")?,
            row.try_get("reviewed_by_first_name")?,
            row.try_get("reviewed_by_last_name")?,
        ),
        reviewed_at: row.try_get("reviewed_at")?,
        review_notes: row.try_get("review_notes")?,
    })
}

fn assessment_detail_from_sqlite_row(
    row: sqlx::sqlite::SqliteRow,
) -> Result<CveAssessmentDetail, sqlx::Error> {
    let cve_severity: String = row.try_get("cve_severity")?;
    let exposure: String = row.try_get("exposure")?;
    let asset_criticality: String = row.try_get("asset_criticality")?;
    let exploit_maturity: String = row.try_get("exploit_maturity")?;
    let llm_status: String = row.try_get("llm_status")?;
    Ok(CveAssessmentDetail {
        summary: CveAssessmentSummary {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            cve_id: row.try_get("cve_id")?,
            cve_description: row.try_get("cve_description")?,
            cve_severity_label: severity_label(&cve_severity).to_string(),
            cve_severity,
            cve_cvss_score: row.try_get("cve_cvss_score_text")?,
            product_id: row.try_get("product_id")?,
            product_name: row.try_get("product_name")?,
            release_id: row.try_get("release_id")?,
            release_version: row.try_get("release_version")?,
            component_id: row.try_get("component_id")?,
            component_name: row.try_get("component_name")?,
            linked_vulnerability_id: row.try_get("linked_vulnerability_id")?,
            linked_vulnerability_title: row.try_get("linked_vulnerability_title")?,
            related_risk_id: row.try_get("related_risk_id")?,
            related_risk_title: row.try_get("related_risk_title")?,
            exposure_label: exposure_label(&exposure).to_string(),
            exposure,
            asset_criticality_label: asset_criticality_label(&asset_criticality).to_string(),
            asset_criticality,
            epss_score: row.try_get("epss_score_text")?,
            in_kev_catalog: row.try_get("in_kev_catalog")?,
            exploit_maturity_label: exploit_maturity_label(&exploit_maturity).to_string(),
            exploit_maturity,
            affects_critical_service: row.try_get("affects_critical_service")?,
            nis2_relevant: row.try_get("nis2_relevant")?,
            deterministic_priority: row.try_get("deterministic_priority")?,
            llm_status_label: llm_status_label(&llm_status).to_string(),
            llm_status,
            deterministic_due_days: row.try_get("deterministic_due_days")?,
            confidence: row.try_get("confidence")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        },
        cvss_vector: row.try_get("cvss_vector")?,
        weakness_ids: parse_json_string_array(row.try_get("weakness_ids_json_text")?),
        references: parse_json_string_array(row.try_get("references_json_text")?),
        kev_date_added: row.try_get("kev_date_added")?,
        kev_vendor_project: row.try_get("kev_vendor_project")?,
        kev_product: row.try_get("kev_product")?,
        kev_required_action: row.try_get("kev_required_action")?,
        kev_known_ransomware: row.try_get("kev_known_ransomware")?,
        repository_name: row.try_get("repository_name")?,
        repository_url: row.try_get("repository_url")?,
        git_ref: row.try_get("git_ref")?,
        source_package: row.try_get("source_package")?,
        source_package_version: row.try_get("source_package_version")?,
        regulatory_tags: parse_json_string_array(row.try_get("regulatory_tags_json_text")?),
        deterministic_factors_json: parse_json_value(
            row.try_get("deterministic_factors_json_text")?,
            json!({}),
        ),
        nis2_impact_summary: row.try_get("nis2_impact_summary")?,
        business_context: row.try_get("business_context")?,
        existing_controls: row.try_get("existing_controls")?,
        llm_backend: row.try_get("llm_backend")?,
        llm_model_name: row.try_get("llm_model_name")?,
        technical_summary: row.try_get("technical_summary")?,
        business_impact: row.try_get("business_impact")?,
        attack_path: row.try_get("attack_path")?,
        management_summary: row.try_get("management_summary")?,
        recommended_actions: parse_json_string_array(row.try_get("recommended_actions_json_text")?),
        evidence_needed: parse_json_string_array(row.try_get("evidence_needed_json_text")?),
        raw_llm_json: parse_json_value(row.try_get("raw_llm_json_text")?, json!({})),
        reviewed_by_display: user_display(
            row.try_get("reviewed_by_username")?,
            row.try_get("reviewed_by_first_name")?,
            row.try_get("reviewed_by_last_name")?,
        ),
        reviewed_at: row.try_get("reviewed_at")?,
        review_notes: row.try_get("review_notes")?,
    })
}

fn parse_json_string_array(raw: String) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(&raw).unwrap_or_default()
}

fn parse_json_value(raw: String, fallback: Value) -> Value {
    serde_json::from_str(&raw).unwrap_or(fallback)
}

fn severity_label(severity: &str) -> &'static str {
    match severity {
        "CRITICAL" => "Kritisch",
        "HIGH" => "Hoch",
        "MEDIUM" => "Mittel",
        "LOW" => "Niedrig",
        _ => "Unbekannt",
    }
}

fn exposure_label(value: &str) -> &'static str {
    match value {
        "INTERNET" => "Internet-exponiert",
        "INTERNAL" => "Nur intern",
        "CUSTOMER" => "Beim Kunden / ausgeliefert",
        _ => "Unklar",
    }
}

fn asset_criticality_label(value: &str) -> &'static str {
    severity_label(value)
}

fn exploit_maturity_label(value: &str) -> &'static str {
    match value {
        "UNPROVEN" => "Kein bekannter Exploit",
        "POC" => "Proof of Concept",
        "ACTIVE" => "Aktive Ausnutzung",
        "AUTOMATED" => "Automatisierbar / Massenangriff",
        _ => "Unbekannt",
    }
}

fn llm_status_label(value: &str) -> &'static str {
    match value {
        "DISABLED" => "Nicht aktiviert",
        "PENDING" => "Ausstehend",
        "GENERATED" => "Generiert",
        "REVIEWED" => "Reviewed",
        "FAILED" => "Fehlgeschlagen",
        _ => "Unbekannt",
    }
}

fn user_display(
    username: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
) -> Option<String> {
    let full_name = format!(
        "{} {}",
        first_name.unwrap_or_default().trim(),
        last_name.unwrap_or_default().trim()
    )
    .trim()
    .to_string();
    if !full_name.is_empty() {
        Some(full_name)
    } else {
        username.filter(|value| !value.trim().is_empty())
    }
}

fn assessment_hotspot_score(total: i64, critical: i64, kev: i64, nis2: i64) -> f64 {
    if total <= 0 {
        return 0.0;
    }
    let total = total as f64;
    let critical_ratio = critical as f64 / total;
    let kev_ratio = kev as f64 / total;
    let nis2_ratio = nis2 as f64 / total;
    let score = ((critical_ratio * 0.5) + (kev_ratio * 0.3) + (nis2_ratio * 0.2)) * 100.0;
    (score * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::{normalize_database_url, parse_json_string_array, severity_label};

    #[test]
    fn normalize_database_url_keeps_postgres_urls() {
        assert_eq!(
            normalize_database_url("postgresql://isms:isms@db:5432/isms"),
            "postgresql://isms:isms@db:5432/isms"
        );
    }

    #[test]
    fn normalize_database_url_converts_django_relative_sqlite_urls() {
        assert_eq!(
            normalize_database_url("sqlite:///db.sqlite3"),
            "sqlite://db.sqlite3"
        );
    }

    #[test]
    fn normalize_database_url_keeps_absolute_sqlite_urls() {
        assert_eq!(
            normalize_database_url("sqlite:////tmp/iscy.sqlite3"),
            "sqlite:////tmp/iscy.sqlite3"
        );
    }

    #[test]
    fn parse_json_string_array_tolerates_invalid_json() {
        assert!(parse_json_string_array("not-json".to_string()).is_empty());
    }

    #[test]
    fn severity_label_maps_known_values() {
        assert_eq!(severity_label("CRITICAL"), "Kritisch");
        assert_eq!(severity_label("UNKNOWN"), "Unbekannt");
    }
}
