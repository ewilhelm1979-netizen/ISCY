use anyhow::{bail, Context};
use chrono::{NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Postgres, QueryBuilder, Row, Sqlite,
};
use std::{collections::BTreeSet, error::Error, fmt};

use crate::cve_store::normalize_database_url;

#[derive(Clone)]
pub enum SupplierProductSecurityStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Default)]
pub struct SupplierProductSecurityFilters {
    pub supplier_id: Option<i64>,
    pub product: Option<String>,
    pub review_status: Option<String>,
    pub severity: Option<String>,
    pub dora_relevant: Option<bool>,
    pub nis2_relevant: Option<bool>,
    pub data_processing_relevant: Option<bool>,
    pub critical_services: Option<bool>,
    pub overdue: Option<bool>,
    pub limit: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SupplierProductSecurityOverview {
    pub tenant_id: i64,
    pub summary: SupplierProductSecuritySummary,
    pub filter_summary: Value,
    pub records: Vec<SupplierProductSecurityRecord>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SupplierProductSecuritySummary {
    pub total_records: i64,
    pub open_advisories: i64,
    pub critical_records: i64,
    pub overdue_reviews: i64,
    pub missing_evidence: i64,
    pub dora_relevant: i64,
    pub nis2_relevant: i64,
    pub data_processing_relevant: i64,
    pub critical_services: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SupplierProductSecurityDetail {
    pub record: SupplierProductSecurityRecord,
    pub evidence_links: Vec<SupplierProductSecurityEvidenceLink>,
    pub events: Vec<SupplierProductSecurityEvent>,
    pub contract_exit_history: Vec<SupplierContractExitHistoryEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SupplierProductSecurityRecord {
    pub id: i64,
    pub tenant_id: i64,
    pub supplier_id: i64,
    pub supplier_name: String,
    pub product_id: Option<i64>,
    pub product_name: Option<String>,
    pub product_or_service: String,
    pub criticality: String,
    pub criticality_label: String,
    pub internal_owner: String,
    pub supplier_security_contact: String,
    pub product_security_status: String,
    pub product_security_status_label: String,
    pub advisory_id: String,
    pub advisory_source_type: String,
    pub advisory_source_type_label: String,
    pub advisory_reference: String,
    pub cve_ids: Vec<String>,
    pub affected_versions: String,
    pub fixed_versions: String,
    pub severity: String,
    pub severity_label: String,
    pub cvss_score: Option<f64>,
    pub epss_score: Option<f64>,
    pub exploitation_status: String,
    pub exploitation_status_label: String,
    pub affected_assets_summary: String,
    pub impact_summary: String,
    pub remediation_summary: String,
    pub workaround_summary: String,
    pub review_status: String,
    pub review_status_label: String,
    pub owner: String,
    pub due_date: Option<String>,
    pub evidence_ids: Vec<i64>,
    pub sbom_vex_reference: String,
    pub open_actions: String,
    pub management_review_reference: String,
    pub contract_status: String,
    pub contract_status_label: String,
    pub contract_review_date: Option<String>,
    pub next_contract_review_due: Option<String>,
    pub exit_plan_status: String,
    pub exit_plan_status_label: String,
    pub exit_plan_version: String,
    pub exit_plan_review_date: Option<String>,
    pub exit_plan_owner: String,
    pub critical_service_dependency: bool,
    pub data_processing_relevance: bool,
    pub dora_ict_third_party_relevance: bool,
    pub nis2_supply_chain_relevance: bool,
    pub termination_risk_summary: String,
    pub alternative_supplier_summary: String,
    pub created_by_id: Option<i64>,
    pub updated_by_id: Option<i64>,
    pub reviewed_at: Option<String>,
    pub reviewed_by: Option<i64>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SupplierProductSecurityEvidenceLink {
    pub id: i64,
    pub record_id: i64,
    pub evidence_id: i64,
    pub title: String,
    pub status: String,
    pub link_type: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SupplierProductSecurityEvent {
    pub id: i64,
    pub record_id: i64,
    pub event_type: String,
    pub actor_id: Option<i64>,
    pub detail_json: Value,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SupplierContractExitHistoryEntry {
    pub id: i64,
    pub record_id: i64,
    pub supplier_id: i64,
    pub version_number: i64,
    pub changed_by: Option<i64>,
    pub changed_at: String,
    pub change_reason: String,
    pub previous_status: String,
    pub new_status: String,
    pub summary: String,
    pub evidence_ids: Vec<i64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SupplierProductSecurityWriteRequest {
    pub supplier_id: i64,
    #[serde(default)]
    pub product_id: Option<i64>,
    pub product_or_service: String,
    #[serde(default)]
    pub criticality: Option<String>,
    #[serde(default)]
    pub internal_owner: String,
    #[serde(default)]
    pub supplier_security_contact: String,
    #[serde(default)]
    pub product_security_status: Option<String>,
    #[serde(default)]
    pub advisory_id: String,
    #[serde(default)]
    pub advisory_source_type: Option<String>,
    #[serde(default)]
    pub advisory_reference: String,
    #[serde(default)]
    pub cve_ids: Vec<String>,
    #[serde(default)]
    pub affected_versions: String,
    #[serde(default)]
    pub fixed_versions: String,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub cvss_score: Option<f64>,
    #[serde(default)]
    pub epss_score: Option<f64>,
    #[serde(default)]
    pub exploitation_status: Option<String>,
    #[serde(default)]
    pub affected_assets_summary: String,
    #[serde(default)]
    pub impact_summary: String,
    #[serde(default)]
    pub remediation_summary: String,
    #[serde(default)]
    pub workaround_summary: String,
    #[serde(default)]
    pub review_status: Option<String>,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub due_date: Option<String>,
    #[serde(default)]
    pub evidence_ids: Vec<i64>,
    #[serde(default)]
    pub sbom_vex_reference: String,
    #[serde(default)]
    pub open_actions: String,
    #[serde(default)]
    pub management_review_reference: String,
    #[serde(default)]
    pub contract_status: Option<String>,
    #[serde(default)]
    pub contract_review_date: Option<String>,
    #[serde(default)]
    pub next_contract_review_due: Option<String>,
    #[serde(default)]
    pub exit_plan_status: Option<String>,
    #[serde(default)]
    pub exit_plan_version: String,
    #[serde(default)]
    pub exit_plan_review_date: Option<String>,
    #[serde(default)]
    pub exit_plan_owner: String,
    #[serde(default)]
    pub critical_service_dependency: Option<bool>,
    #[serde(default)]
    pub data_processing_relevance: Option<bool>,
    #[serde(default)]
    pub dora_ict_third_party_relevance: Option<bool>,
    #[serde(default)]
    pub nis2_supply_chain_relevance: Option<bool>,
    #[serde(default)]
    pub termination_risk_summary: String,
    #[serde(default)]
    pub alternative_supplier_summary: String,
    #[serde(default)]
    pub change_reason: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SupplierProductSecurityPatchRequest {
    #[serde(default)]
    pub product_id: Option<i64>,
    #[serde(default)]
    pub product_or_service: Option<String>,
    #[serde(default)]
    pub criticality: Option<String>,
    #[serde(default)]
    pub internal_owner: Option<String>,
    #[serde(default)]
    pub supplier_security_contact: Option<String>,
    #[serde(default)]
    pub product_security_status: Option<String>,
    #[serde(default)]
    pub advisory_id: Option<String>,
    #[serde(default)]
    pub advisory_source_type: Option<String>,
    #[serde(default)]
    pub advisory_reference: Option<String>,
    #[serde(default)]
    pub cve_ids: Option<Vec<String>>,
    #[serde(default)]
    pub affected_versions: Option<String>,
    #[serde(default)]
    pub fixed_versions: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub cvss_score: Option<f64>,
    #[serde(default)]
    pub epss_score: Option<f64>,
    #[serde(default)]
    pub exploitation_status: Option<String>,
    #[serde(default)]
    pub affected_assets_summary: Option<String>,
    #[serde(default)]
    pub impact_summary: Option<String>,
    #[serde(default)]
    pub remediation_summary: Option<String>,
    #[serde(default)]
    pub workaround_summary: Option<String>,
    #[serde(default)]
    pub review_status: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub due_date: Option<String>,
    #[serde(default)]
    pub evidence_ids: Option<Vec<i64>>,
    #[serde(default)]
    pub sbom_vex_reference: Option<String>,
    #[serde(default)]
    pub open_actions: Option<String>,
    #[serde(default)]
    pub management_review_reference: Option<String>,
    #[serde(default)]
    pub contract_status: Option<String>,
    #[serde(default)]
    pub contract_review_date: Option<String>,
    #[serde(default)]
    pub next_contract_review_due: Option<String>,
    #[serde(default)]
    pub exit_plan_status: Option<String>,
    #[serde(default)]
    pub exit_plan_version: Option<String>,
    #[serde(default)]
    pub exit_plan_review_date: Option<String>,
    #[serde(default)]
    pub exit_plan_owner: Option<String>,
    #[serde(default)]
    pub critical_service_dependency: Option<bool>,
    #[serde(default)]
    pub data_processing_relevance: Option<bool>,
    #[serde(default)]
    pub dora_ict_third_party_relevance: Option<bool>,
    #[serde(default)]
    pub nis2_supply_chain_relevance: Option<bool>,
    #[serde(default)]
    pub termination_risk_summary: Option<String>,
    #[serde(default)]
    pub alternative_supplier_summary: Option<String>,
    #[serde(default)]
    pub change_reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SupplierProductSecurityStatusRequest {
    pub new_status: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub review_notes: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SupplierProductSecurityEvidenceRequest {
    pub evidence_id: i64,
    #[serde(default)]
    pub link_type: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupplierProductSecurityErrorKind {
    NotFound,
    InvalidPayload,
    Database,
}

#[derive(Debug)]
pub struct SupplierProductSecurityError {
    kind: SupplierProductSecurityErrorKind,
    message: String,
}

pub type SupplierProductSecurityResult<T> = Result<T, SupplierProductSecurityError>;

impl SupplierProductSecurityError {
    pub fn kind(&self) -> SupplierProductSecurityErrorKind {
        self.kind
    }

    pub fn safe_message(&self) -> &str {
        &self.message
    }

    fn not_found() -> Self {
        Self {
            kind: SupplierProductSecurityErrorKind::NotFound,
            message: "Supplier/Product-Security-Datensatz wurde fuer diesen Tenant nicht gefunden."
                .to_string(),
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self {
            kind: SupplierProductSecurityErrorKind::InvalidPayload,
            message: message.into(),
        }
    }

    fn database() -> Self {
        Self {
            kind: SupplierProductSecurityErrorKind::Database,
            message: "Supplier/Product-Security-Daten konnten nicht verarbeitet werden."
                .to_string(),
        }
    }
}

impl fmt::Display for SupplierProductSecurityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for SupplierProductSecurityError {}

impl From<sqlx::Error> for SupplierProductSecurityError {
    fn from(_: sqlx::Error) -> Self {
        Self::database()
    }
}

impl From<serde_json::Error> for SupplierProductSecurityError {
    fn from(_: serde_json::Error) -> Self {
        Self::database()
    }
}

impl SupplierProductSecurityStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context(
                    "PostgreSQL-Verbindung fuer Supplier/Product-Security-Store fehlgeschlagen",
                )?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Supplier/Product-Security-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Supplier/Product-Security-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn overview(
        &self,
        tenant_id: i64,
        filters: SupplierProductSecurityFilters,
    ) -> anyhow::Result<SupplierProductSecurityOverview> {
        let records = match self {
            Self::Postgres(pool) => list_records_postgres(pool, tenant_id, &filters).await?,
            Self::Sqlite(pool) => list_records_sqlite(pool, tenant_id, &filters).await?,
        };
        Ok(SupplierProductSecurityOverview {
            tenant_id,
            summary: supplier_product_security_summary(&records),
            filter_summary: supplier_product_security_filter_summary(&filters),
            records,
        })
    }

    pub async fn detail(
        &self,
        tenant_id: i64,
        record_id: i64,
    ) -> SupplierProductSecurityResult<Option<SupplierProductSecurityDetail>> {
        match self {
            Self::Postgres(pool) => detail_postgres(pool, tenant_id, record_id).await,
            Self::Sqlite(pool) => detail_sqlite(pool, tenant_id, record_id).await,
        }
    }

    pub async fn create_record(
        &self,
        tenant_id: i64,
        actor_id: i64,
        payload: SupplierProductSecurityWriteRequest,
    ) -> SupplierProductSecurityResult<SupplierProductSecurityDetail> {
        let record = ValidatedSupplierProductSecurityRecord::from_create(payload)?;
        match self {
            Self::Postgres(pool) => create_record_postgres(pool, tenant_id, actor_id, record).await,
            Self::Sqlite(pool) => create_record_sqlite(pool, tenant_id, actor_id, record).await,
        }
    }

    pub async fn update_record(
        &self,
        tenant_id: i64,
        record_id: i64,
        actor_id: i64,
        payload: SupplierProductSecurityPatchRequest,
    ) -> SupplierProductSecurityResult<Option<SupplierProductSecurityDetail>> {
        match self {
            Self::Postgres(pool) => {
                update_record_postgres(pool, tenant_id, record_id, actor_id, payload).await
            }
            Self::Sqlite(pool) => {
                update_record_sqlite(pool, tenant_id, record_id, actor_id, payload).await
            }
        }
    }

    pub async fn update_status(
        &self,
        tenant_id: i64,
        record_id: i64,
        actor_id: i64,
        payload: SupplierProductSecurityStatusRequest,
    ) -> SupplierProductSecurityResult<Option<SupplierProductSecurityDetail>> {
        let status = normalize_review_status(&payload.new_status)?;
        let reason = normalized_text(&payload.reason, 1_000, "Statusgrund")?;
        let notes = normalized_text(&payload.review_notes, 2_000, "Review-Notiz")?;
        match self {
            Self::Postgres(pool) => {
                update_status_postgres(pool, tenant_id, record_id, actor_id, status, reason, notes)
                    .await
            }
            Self::Sqlite(pool) => {
                update_status_sqlite(pool, tenant_id, record_id, actor_id, status, reason, notes)
                    .await
            }
        }
    }

    pub async fn link_evidence(
        &self,
        tenant_id: i64,
        record_id: i64,
        actor_id: i64,
        payload: SupplierProductSecurityEvidenceRequest,
    ) -> SupplierProductSecurityResult<Option<SupplierProductSecurityDetail>> {
        let link_type = normalized_text(
            payload.link_type.as_deref().unwrap_or("review"),
            64,
            "Evidence-Linktyp",
        )?;
        match self {
            Self::Postgres(pool) => {
                link_evidence_postgres(
                    pool,
                    tenant_id,
                    record_id,
                    actor_id,
                    payload.evidence_id,
                    link_type,
                )
                .await
            }
            Self::Sqlite(pool) => {
                link_evidence_sqlite(
                    pool,
                    tenant_id,
                    record_id,
                    actor_id,
                    payload.evidence_id,
                    link_type,
                )
                .await
            }
        }
    }

    pub async fn events(
        &self,
        tenant_id: i64,
        record_id: i64,
    ) -> SupplierProductSecurityResult<Vec<SupplierProductSecurityEvent>> {
        match self {
            Self::Postgres(pool) => {
                ensure_record_postgres(pool, tenant_id, record_id).await?;
                list_events_postgres(pool, tenant_id, record_id).await
            }
            Self::Sqlite(pool) => {
                ensure_record_sqlite(pool, tenant_id, record_id).await?;
                list_events_sqlite(pool, tenant_id, record_id).await
            }
        }
    }

    pub async fn supplier_contract_exit_history(
        &self,
        tenant_id: i64,
        supplier_id: i64,
    ) -> SupplierProductSecurityResult<Vec<SupplierContractExitHistoryEntry>> {
        match self {
            Self::Postgres(pool) => {
                ensure_supplier_postgres(pool, tenant_id, supplier_id).await?;
                list_supplier_history_postgres(pool, tenant_id, supplier_id).await
            }
            Self::Sqlite(pool) => {
                ensure_supplier_sqlite(pool, tenant_id, supplier_id).await?;
                list_supplier_history_sqlite(pool, tenant_id, supplier_id).await
            }
        }
    }
}

#[derive(Debug, Clone)]
struct ValidatedSupplierProductSecurityRecord {
    supplier_id: i64,
    product_id: Option<i64>,
    product_or_service: String,
    criticality: String,
    internal_owner: String,
    supplier_security_contact: String,
    product_security_status: String,
    advisory_id: String,
    advisory_source_type: String,
    advisory_reference: String,
    cve_ids: Vec<String>,
    affected_versions: String,
    fixed_versions: String,
    severity: String,
    cvss_score: Option<f64>,
    epss_score: Option<f64>,
    exploitation_status: String,
    affected_assets_summary: String,
    impact_summary: String,
    remediation_summary: String,
    workaround_summary: String,
    review_status: String,
    owner: String,
    due_date: Option<String>,
    evidence_ids: Vec<i64>,
    sbom_vex_reference: String,
    open_actions: String,
    management_review_reference: String,
    contract_status: String,
    contract_review_date: Option<String>,
    next_contract_review_due: Option<String>,
    exit_plan_status: String,
    exit_plan_version: String,
    exit_plan_review_date: Option<String>,
    exit_plan_owner: String,
    critical_service_dependency: bool,
    data_processing_relevance: bool,
    dora_ict_third_party_relevance: bool,
    nis2_supply_chain_relevance: bool,
    termination_risk_summary: String,
    alternative_supplier_summary: String,
    change_reason: String,
}

impl ValidatedSupplierProductSecurityRecord {
    fn from_create(
        payload: SupplierProductSecurityWriteRequest,
    ) -> SupplierProductSecurityResult<Self> {
        if payload.supplier_id <= 0 {
            return Err(SupplierProductSecurityError::invalid(
                "Supplier-ID muss positiv sein.",
            ));
        }
        if payload.product_id.is_some_and(|value| value <= 0) {
            return Err(SupplierProductSecurityError::invalid(
                "Produkt-ID muss positiv sein.",
            ));
        }
        Ok(Self {
            supplier_id: payload.supplier_id,
            product_id: payload.product_id,
            product_or_service: normalized_required_text(
                &payload.product_or_service,
                255,
                "Produkt oder Service",
            )?,
            criticality: normalize_criticality(payload.criticality.as_deref().unwrap_or("medium"))?,
            internal_owner: normalized_text(&payload.internal_owner, 255, "Interner Owner")?,
            supplier_security_contact: normalized_text(
                &payload.supplier_security_contact,
                255,
                "Supplier Security Contact",
            )?,
            product_security_status: normalize_product_security_status(
                payload
                    .product_security_status
                    .as_deref()
                    .unwrap_or("not_assessed"),
            )?,
            advisory_id: normalized_text(&payload.advisory_id, 128, "Advisory-ID")?,
            advisory_source_type: normalize_advisory_source_type(
                payload.advisory_source_type.as_deref().unwrap_or("manual"),
            )?,
            advisory_reference: normalized_reference(&payload.advisory_reference)?,
            cve_ids: normalize_cve_ids(payload.cve_ids)?,
            affected_versions: normalized_text(
                &payload.affected_versions,
                1_000,
                "Betroffene Versionen",
            )?,
            fixed_versions: normalized_text(&payload.fixed_versions, 1_000, "Behobene Versionen")?,
            severity: normalize_severity(payload.severity.as_deref().unwrap_or("unknown"))?,
            cvss_score: normalize_score(payload.cvss_score, 0.0, 10.0, "CVSS")?,
            epss_score: normalize_score(payload.epss_score, 0.0, 1.0, "EPSS")?,
            exploitation_status: normalize_exploitation_status(
                payload.exploitation_status.as_deref().unwrap_or("unknown"),
            )?,
            affected_assets_summary: normalized_text(
                &payload.affected_assets_summary,
                2_000,
                "Asset-Zusammenfassung",
            )?,
            impact_summary: normalized_text(&payload.impact_summary, 4_000, "Impact")?,
            remediation_summary: normalized_text(
                &payload.remediation_summary,
                4_000,
                "Remediation",
            )?,
            workaround_summary: normalized_text(&payload.workaround_summary, 4_000, "Workaround")?,
            review_status: normalize_review_status(
                payload.review_status.as_deref().unwrap_or("draft"),
            )?,
            owner: normalized_text(&payload.owner, 255, "Owner")?,
            due_date: normalized_optional_date(payload.due_date.as_deref(), "Faelligkeit")?,
            evidence_ids: normalize_positive_ids(payload.evidence_ids, "Evidence-IDs")?,
            sbom_vex_reference: normalized_reference(&payload.sbom_vex_reference)?,
            open_actions: normalized_text(&payload.open_actions, 4_000, "Offene Massnahmen")?,
            management_review_reference: normalized_text(
                &payload.management_review_reference,
                512,
                "Management-Review-Bezug",
            )?,
            contract_status: normalize_contract_status(
                payload.contract_status.as_deref().unwrap_or("not_recorded"),
            )?,
            contract_review_date: normalized_optional_date(
                payload.contract_review_date.as_deref(),
                "Vertragspruefung",
            )?,
            next_contract_review_due: normalized_optional_date(
                payload.next_contract_review_due.as_deref(),
                "Naechste Vertragspruefung",
            )?,
            exit_plan_status: normalize_exit_plan_status(
                payload
                    .exit_plan_status
                    .as_deref()
                    .unwrap_or("not_recorded"),
            )?,
            exit_plan_version: normalized_text(
                &payload.exit_plan_version,
                64,
                "Exit-Plan-Version",
            )?,
            exit_plan_review_date: normalized_optional_date(
                payload.exit_plan_review_date.as_deref(),
                "Exit-Plan-Pruefung",
            )?,
            exit_plan_owner: normalized_text(&payload.exit_plan_owner, 255, "Exit-Plan-Owner")?,
            critical_service_dependency: payload.critical_service_dependency.unwrap_or(false),
            data_processing_relevance: payload.data_processing_relevance.unwrap_or(false),
            dora_ict_third_party_relevance: payload.dora_ict_third_party_relevance.unwrap_or(false),
            nis2_supply_chain_relevance: payload.nis2_supply_chain_relevance.unwrap_or(false),
            termination_risk_summary: normalized_text(
                &payload.termination_risk_summary,
                4_000,
                "Kuendigungsrisiko",
            )?,
            alternative_supplier_summary: normalized_text(
                &payload.alternative_supplier_summary,
                4_000,
                "Alternativlieferant",
            )?,
            change_reason: normalized_text(&payload.change_reason, 1_000, "Aenderungsgrund")?,
        })
    }

    fn apply_patch(
        current: &SupplierProductSecurityRecord,
        payload: SupplierProductSecurityPatchRequest,
    ) -> SupplierProductSecurityResult<Self> {
        Ok(Self {
            supplier_id: current.supplier_id,
            product_id: payload.product_id.or(current.product_id),
            product_or_service: match payload.product_or_service {
                Some(value) => normalized_required_text(&value, 255, "Produkt oder Service")?,
                None => current.product_or_service.clone(),
            },
            criticality: match payload.criticality {
                Some(value) => normalize_criticality(&value)?,
                None => current.criticality.clone(),
            },
            internal_owner: match payload.internal_owner {
                Some(value) => normalized_text(&value, 255, "Interner Owner")?,
                None => current.internal_owner.clone(),
            },
            supplier_security_contact: match payload.supplier_security_contact {
                Some(value) => normalized_text(&value, 255, "Supplier Security Contact")?,
                None => current.supplier_security_contact.clone(),
            },
            product_security_status: match payload.product_security_status {
                Some(value) => normalize_product_security_status(&value)?,
                None => current.product_security_status.clone(),
            },
            advisory_id: match payload.advisory_id {
                Some(value) => normalized_text(&value, 128, "Advisory-ID")?,
                None => current.advisory_id.clone(),
            },
            advisory_source_type: match payload.advisory_source_type {
                Some(value) => normalize_advisory_source_type(&value)?,
                None => current.advisory_source_type.clone(),
            },
            advisory_reference: match payload.advisory_reference {
                Some(value) => normalized_reference(&value)?,
                None => current.advisory_reference.clone(),
            },
            cve_ids: match payload.cve_ids {
                Some(value) => normalize_cve_ids(value)?,
                None => current.cve_ids.clone(),
            },
            affected_versions: match payload.affected_versions {
                Some(value) => normalized_text(&value, 1_000, "Betroffene Versionen")?,
                None => current.affected_versions.clone(),
            },
            fixed_versions: match payload.fixed_versions {
                Some(value) => normalized_text(&value, 1_000, "Behobene Versionen")?,
                None => current.fixed_versions.clone(),
            },
            severity: match payload.severity {
                Some(value) => normalize_severity(&value)?,
                None => current.severity.clone(),
            },
            cvss_score: normalize_score(
                payload.cvss_score.or(current.cvss_score),
                0.0,
                10.0,
                "CVSS",
            )?,
            epss_score: normalize_score(
                payload.epss_score.or(current.epss_score),
                0.0,
                1.0,
                "EPSS",
            )?,
            exploitation_status: match payload.exploitation_status {
                Some(value) => normalize_exploitation_status(&value)?,
                None => current.exploitation_status.clone(),
            },
            affected_assets_summary: match payload.affected_assets_summary {
                Some(value) => normalized_text(&value, 2_000, "Asset-Zusammenfassung")?,
                None => current.affected_assets_summary.clone(),
            },
            impact_summary: match payload.impact_summary {
                Some(value) => normalized_text(&value, 4_000, "Impact")?,
                None => current.impact_summary.clone(),
            },
            remediation_summary: match payload.remediation_summary {
                Some(value) => normalized_text(&value, 4_000, "Remediation")?,
                None => current.remediation_summary.clone(),
            },
            workaround_summary: match payload.workaround_summary {
                Some(value) => normalized_text(&value, 4_000, "Workaround")?,
                None => current.workaround_summary.clone(),
            },
            review_status: match payload.review_status {
                Some(value) => normalize_review_status(&value)?,
                None => current.review_status.clone(),
            },
            owner: match payload.owner {
                Some(value) => normalized_text(&value, 255, "Owner")?,
                None => current.owner.clone(),
            },
            due_date: match payload.due_date {
                Some(value) => normalized_optional_date(Some(&value), "Faelligkeit")?,
                None => current.due_date.clone(),
            },
            evidence_ids: match payload.evidence_ids {
                Some(value) => normalize_positive_ids(value, "Evidence-IDs")?,
                None => current.evidence_ids.clone(),
            },
            sbom_vex_reference: match payload.sbom_vex_reference {
                Some(value) => normalized_reference(&value)?,
                None => current.sbom_vex_reference.clone(),
            },
            open_actions: match payload.open_actions {
                Some(value) => normalized_text(&value, 4_000, "Offene Massnahmen")?,
                None => current.open_actions.clone(),
            },
            management_review_reference: match payload.management_review_reference {
                Some(value) => normalized_text(&value, 512, "Management-Review-Bezug")?,
                None => current.management_review_reference.clone(),
            },
            contract_status: match payload.contract_status {
                Some(value) => normalize_contract_status(&value)?,
                None => current.contract_status.clone(),
            },
            contract_review_date: match payload.contract_review_date {
                Some(value) => normalized_optional_date(Some(&value), "Vertragspruefung")?,
                None => current.contract_review_date.clone(),
            },
            next_contract_review_due: match payload.next_contract_review_due {
                Some(value) => normalized_optional_date(Some(&value), "Naechste Vertragspruefung")?,
                None => current.next_contract_review_due.clone(),
            },
            exit_plan_status: match payload.exit_plan_status {
                Some(value) => normalize_exit_plan_status(&value)?,
                None => current.exit_plan_status.clone(),
            },
            exit_plan_version: match payload.exit_plan_version {
                Some(value) => normalized_text(&value, 64, "Exit-Plan-Version")?,
                None => current.exit_plan_version.clone(),
            },
            exit_plan_review_date: match payload.exit_plan_review_date {
                Some(value) => normalized_optional_date(Some(&value), "Exit-Plan-Pruefung")?,
                None => current.exit_plan_review_date.clone(),
            },
            exit_plan_owner: match payload.exit_plan_owner {
                Some(value) => normalized_text(&value, 255, "Exit-Plan-Owner")?,
                None => current.exit_plan_owner.clone(),
            },
            critical_service_dependency: payload
                .critical_service_dependency
                .unwrap_or(current.critical_service_dependency),
            data_processing_relevance: payload
                .data_processing_relevance
                .unwrap_or(current.data_processing_relevance),
            dora_ict_third_party_relevance: payload
                .dora_ict_third_party_relevance
                .unwrap_or(current.dora_ict_third_party_relevance),
            nis2_supply_chain_relevance: payload
                .nis2_supply_chain_relevance
                .unwrap_or(current.nis2_supply_chain_relevance),
            termination_risk_summary: match payload.termination_risk_summary {
                Some(value) => normalized_text(&value, 4_000, "Kuendigungsrisiko")?,
                None => current.termination_risk_summary.clone(),
            },
            alternative_supplier_summary: match payload.alternative_supplier_summary {
                Some(value) => normalized_text(&value, 4_000, "Alternativlieferant")?,
                None => current.alternative_supplier_summary.clone(),
            },
            change_reason: normalized_text(
                payload
                    .change_reason
                    .as_deref()
                    .unwrap_or("Datensatz aktualisiert."),
                1_000,
                "Aenderungsgrund",
            )?,
        })
    }
}

const RECORD_SELECT: &str = r#"
SELECT
    record.id,
    record.tenant_id,
    record.supplier_id,
    supplier.name AS supplier_name,
    record.product_id,
    product.name AS product_name,
    record.product_or_service,
    record.criticality,
    record.internal_owner,
    record.supplier_security_contact,
    record.product_security_status,
    record.advisory_id,
    record.advisory_source_type,
    record.advisory_reference,
    record.cve_ids_json,
    record.affected_versions,
    record.fixed_versions,
    record.severity,
    record.cvss_score,
    record.epss_score,
    record.exploitation_status,
    record.affected_assets_summary,
    record.impact_summary,
    record.remediation_summary,
    record.workaround_summary,
    record.review_status,
    record.owner,
    record.due_date,
    record.evidence_ids_json,
    record.sbom_vex_reference,
    record.open_actions,
    record.management_review_reference,
    record.contract_status,
    record.contract_review_date,
    record.next_contract_review_due,
    record.exit_plan_status,
    record.exit_plan_version,
    record.exit_plan_review_date,
    record.exit_plan_owner,
    record.critical_service_dependency,
    record.data_processing_relevance,
    record.dora_ict_third_party_relevance,
    record.nis2_supply_chain_relevance,
    record.termination_risk_summary,
    record.alternative_supplier_summary,
    record.created_by_id,
    record.updated_by_id,
    record.reviewed_at,
    record.reviewed_by,
    record.created_at,
    record.updated_at
FROM supplier_product_security_record record
JOIN organizations_supplier supplier
    ON supplier.id = record.supplier_id
    AND supplier.tenant_id = record.tenant_id
LEFT JOIN product_security_product product
    ON product.id = record.product_id
    AND product.tenant_id = record.tenant_id
"#;

async fn list_records_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    filters: &SupplierProductSecurityFilters,
) -> anyhow::Result<Vec<SupplierProductSecurityRecord>> {
    let mut builder = QueryBuilder::<Sqlite>::new(RECORD_SELECT);
    push_filters_sqlite(&mut builder, tenant_id, filters);
    let rows = builder.build().fetch_all(pool).await?;
    rows.into_iter()
        .map(record_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_records_postgres(
    pool: &PgPool,
    tenant_id: i64,
    filters: &SupplierProductSecurityFilters,
) -> anyhow::Result<Vec<SupplierProductSecurityRecord>> {
    let mut builder = QueryBuilder::<Postgres>::new(RECORD_SELECT);
    push_filters_postgres(&mut builder, tenant_id, filters);
    let rows = builder.build().fetch_all(pool).await?;
    rows.into_iter()
        .map(record_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn push_filters_sqlite(
    builder: &mut QueryBuilder<'_, Sqlite>,
    tenant_id: i64,
    filters: &SupplierProductSecurityFilters,
) {
    builder.push(" WHERE record.tenant_id = ");
    builder.push_bind(tenant_id);
    push_common_filters(builder, filters);
}

fn push_filters_postgres(
    builder: &mut QueryBuilder<'_, Postgres>,
    tenant_id: i64,
    filters: &SupplierProductSecurityFilters,
) {
    builder.push(" WHERE record.tenant_id = ");
    builder.push_bind(tenant_id);
    push_common_filters(builder, filters);
}

fn push_common_filters<DB>(
    builder: &mut QueryBuilder<'_, DB>,
    filters: &SupplierProductSecurityFilters,
) where
    DB: sqlx::Database,
    for<'a> i64: sqlx::Encode<'a, DB> + sqlx::Type<DB>,
    for<'a> String: sqlx::Encode<'a, DB> + sqlx::Type<DB>,
    for<'a> bool: sqlx::Encode<'a, DB> + sqlx::Type<DB>,
{
    if let Some(supplier_id) = filters.supplier_id {
        builder.push(" AND record.supplier_id = ");
        builder.push_bind(supplier_id);
    }
    if let Some(product) = filters.product.as_ref() {
        builder.push(" AND LOWER(record.product_or_service) LIKE ");
        builder.push_bind(format!("%{}%", product.to_ascii_lowercase()));
    }
    if let Some(status) = filters.review_status.as_ref() {
        builder.push(" AND record.review_status = ");
        builder.push_bind(status.clone());
    }
    if let Some(severity) = filters.severity.as_ref() {
        builder.push(" AND record.severity = ");
        builder.push_bind(severity.clone());
    }
    if let Some(value) = filters.dora_relevant {
        builder.push(" AND record.dora_ict_third_party_relevance = ");
        builder.push_bind(value);
    }
    if let Some(value) = filters.nis2_relevant {
        builder.push(" AND record.nis2_supply_chain_relevance = ");
        builder.push_bind(value);
    }
    if let Some(value) = filters.data_processing_relevant {
        builder.push(" AND record.data_processing_relevance = ");
        builder.push_bind(value);
    }
    if let Some(value) = filters.critical_services {
        builder.push(" AND record.critical_service_dependency = ");
        builder.push_bind(value);
    }
    if filters.overdue == Some(true) {
        builder.push(" AND record.due_date IS NOT NULL AND record.due_date < ");
        builder.push_bind(Utc::now().date_naive().to_string());
        builder.push(" AND record.review_status NOT IN ('closed', 'mitigated', 'not_applicable')");
    }
    builder.push(
        " ORDER BY CASE record.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END DESC, record.updated_at DESC, record.id DESC LIMIT ",
    );
    builder.push_bind(filters.limit.clamp(1, 100));
}

async fn detail_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    record_id: i64,
) -> SupplierProductSecurityResult<Option<SupplierProductSecurityDetail>> {
    let Some(record) = fetch_record_sqlite(pool, tenant_id, record_id).await? else {
        return Ok(None);
    };
    Ok(Some(SupplierProductSecurityDetail {
        evidence_links: list_evidence_links_sqlite(pool, tenant_id, record_id).await?,
        events: list_events_sqlite(pool, tenant_id, record_id).await?,
        contract_exit_history: list_record_history_sqlite(pool, tenant_id, record_id).await?,
        record,
    }))
}

async fn detail_postgres(
    pool: &PgPool,
    tenant_id: i64,
    record_id: i64,
) -> SupplierProductSecurityResult<Option<SupplierProductSecurityDetail>> {
    let Some(record) = fetch_record_postgres(pool, tenant_id, record_id).await? else {
        return Ok(None);
    };
    Ok(Some(SupplierProductSecurityDetail {
        evidence_links: list_evidence_links_postgres(pool, tenant_id, record_id).await?,
        events: list_events_postgres(pool, tenant_id, record_id).await?,
        contract_exit_history: list_record_history_postgres(pool, tenant_id, record_id).await?,
        record,
    }))
}

async fn fetch_record_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    record_id: i64,
) -> Result<Option<SupplierProductSecurityRecord>, sqlx::Error> {
    let query = format!("{RECORD_SELECT} WHERE record.tenant_id = ? AND record.id = ?");
    sqlx::query(&query)
        .bind(tenant_id)
        .bind(record_id)
        .fetch_optional(pool)
        .await?
        .map(record_from_sqlite_row)
        .transpose()
}

async fn fetch_record_postgres(
    pool: &PgPool,
    tenant_id: i64,
    record_id: i64,
) -> Result<Option<SupplierProductSecurityRecord>, sqlx::Error> {
    let query = format!("{RECORD_SELECT} WHERE record.tenant_id = $1 AND record.id = $2");
    sqlx::query(&query)
        .bind(tenant_id)
        .bind(record_id)
        .fetch_optional(pool)
        .await?
        .map(record_from_pg_row)
        .transpose()
}

async fn create_record_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    actor_id: i64,
    record: ValidatedSupplierProductSecurityRecord,
) -> SupplierProductSecurityResult<SupplierProductSecurityDetail> {
    ensure_supplier_sqlite(pool, tenant_id, record.supplier_id).await?;
    ensure_product_sqlite(pool, tenant_id, record.product_id).await?;
    ensure_evidence_ids_sqlite(pool, tenant_id, &record.evidence_ids).await?;
    let record_id = insert_record_sqlite(pool, tenant_id, actor_id, &record).await?;
    for evidence_id in &record.evidence_ids {
        insert_evidence_link_sqlite(pool, tenant_id, record_id, actor_id, *evidence_id, "review")
            .await?;
    }
    let history = ContractHistoryInsert {
        tenant_id,
        record_id,
        supplier_id: record.supplier_id,
        actor_id,
        version_number: 1,
        previous_status: "",
        new_status: &record.contract_status,
        change_reason: &record.change_reason,
        evidence_ids: &record.evidence_ids,
    };
    insert_contract_history_sqlite(pool, &history).await?;
    insert_event_sqlite(
        pool,
        tenant_id,
        record_id,
        "supplier_product_security_record_created",
        Some(actor_id),
        json!({"supplier_id": record.supplier_id, "review_status": record.review_status}),
    )
    .await?;
    detail_sqlite(pool, tenant_id, record_id)
        .await?
        .ok_or_else(SupplierProductSecurityError::not_found)
}

async fn create_record_postgres(
    pool: &PgPool,
    tenant_id: i64,
    actor_id: i64,
    record: ValidatedSupplierProductSecurityRecord,
) -> SupplierProductSecurityResult<SupplierProductSecurityDetail> {
    ensure_supplier_postgres(pool, tenant_id, record.supplier_id).await?;
    ensure_product_postgres(pool, tenant_id, record.product_id).await?;
    ensure_evidence_ids_postgres(pool, tenant_id, &record.evidence_ids).await?;
    let record_id = insert_record_postgres(pool, tenant_id, actor_id, &record).await?;
    for evidence_id in &record.evidence_ids {
        insert_evidence_link_postgres(pool, tenant_id, record_id, actor_id, *evidence_id, "review")
            .await?;
    }
    let history = ContractHistoryInsert {
        tenant_id,
        record_id,
        supplier_id: record.supplier_id,
        actor_id,
        version_number: 1,
        previous_status: "",
        new_status: &record.contract_status,
        change_reason: &record.change_reason,
        evidence_ids: &record.evidence_ids,
    };
    insert_contract_history_postgres(pool, &history).await?;
    insert_event_postgres(
        pool,
        tenant_id,
        record_id,
        "supplier_product_security_record_created",
        Some(actor_id),
        json!({"supplier_id": record.supplier_id, "review_status": record.review_status}),
    )
    .await?;
    detail_postgres(pool, tenant_id, record_id)
        .await?
        .ok_or_else(SupplierProductSecurityError::not_found)
}

async fn insert_record_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    actor_id: i64,
    record: &ValidatedSupplierProductSecurityRecord,
) -> Result<i64, sqlx::Error> {
    let sql = insert_record_sql("?", "?");
    sqlx::query_scalar(&sql)
        .bind(tenant_id)
        .bind(record.supplier_id)
        .bind(record.product_id)
        .bind(&record.product_or_service)
        .bind(&record.criticality)
        .bind(&record.internal_owner)
        .bind(&record.supplier_security_contact)
        .bind(&record.product_security_status)
        .bind(&record.advisory_id)
        .bind(&record.advisory_source_type)
        .bind(&record.advisory_reference)
        .bind(json_ids(&record.cve_ids))
        .bind(&record.affected_versions)
        .bind(&record.fixed_versions)
        .bind(&record.severity)
        .bind(record.cvss_score)
        .bind(record.epss_score)
        .bind(&record.exploitation_status)
        .bind(&record.affected_assets_summary)
        .bind(&record.impact_summary)
        .bind(&record.remediation_summary)
        .bind(&record.workaround_summary)
        .bind(&record.review_status)
        .bind(&record.owner)
        .bind(&record.due_date)
        .bind(json_ids_i64(&record.evidence_ids))
        .bind(&record.sbom_vex_reference)
        .bind(&record.open_actions)
        .bind(&record.management_review_reference)
        .bind(&record.contract_status)
        .bind(&record.contract_review_date)
        .bind(&record.next_contract_review_due)
        .bind(&record.exit_plan_status)
        .bind(&record.exit_plan_version)
        .bind(&record.exit_plan_review_date)
        .bind(&record.exit_plan_owner)
        .bind(record.critical_service_dependency)
        .bind(record.data_processing_relevance)
        .bind(record.dora_ict_third_party_relevance)
        .bind(record.nis2_supply_chain_relevance)
        .bind(&record.termination_risk_summary)
        .bind(&record.alternative_supplier_summary)
        .bind(actor_id)
        .bind(actor_id)
        .fetch_one(pool)
        .await
}

async fn insert_record_postgres(
    pool: &PgPool,
    tenant_id: i64,
    actor_id: i64,
    record: &ValidatedSupplierProductSecurityRecord,
) -> Result<i64, sqlx::Error> {
    let sql = insert_record_sql("$", "$");
    sqlx::query_scalar(&sql)
        .bind(tenant_id)
        .bind(record.supplier_id)
        .bind(record.product_id)
        .bind(&record.product_or_service)
        .bind(&record.criticality)
        .bind(&record.internal_owner)
        .bind(&record.supplier_security_contact)
        .bind(&record.product_security_status)
        .bind(&record.advisory_id)
        .bind(&record.advisory_source_type)
        .bind(&record.advisory_reference)
        .bind(json_ids(&record.cve_ids))
        .bind(&record.affected_versions)
        .bind(&record.fixed_versions)
        .bind(&record.severity)
        .bind(record.cvss_score)
        .bind(record.epss_score)
        .bind(&record.exploitation_status)
        .bind(&record.affected_assets_summary)
        .bind(&record.impact_summary)
        .bind(&record.remediation_summary)
        .bind(&record.workaround_summary)
        .bind(&record.review_status)
        .bind(&record.owner)
        .bind(&record.due_date)
        .bind(json_ids_i64(&record.evidence_ids))
        .bind(&record.sbom_vex_reference)
        .bind(&record.open_actions)
        .bind(&record.management_review_reference)
        .bind(&record.contract_status)
        .bind(&record.contract_review_date)
        .bind(&record.next_contract_review_due)
        .bind(&record.exit_plan_status)
        .bind(&record.exit_plan_version)
        .bind(&record.exit_plan_review_date)
        .bind(&record.exit_plan_owner)
        .bind(record.critical_service_dependency)
        .bind(record.data_processing_relevance)
        .bind(record.dora_ict_third_party_relevance)
        .bind(record.nis2_supply_chain_relevance)
        .bind(&record.termination_risk_summary)
        .bind(&record.alternative_supplier_summary)
        .bind(actor_id)
        .bind(actor_id)
        .fetch_one(pool)
        .await
}

fn insert_record_sql(bind_prefix: &str, _placeholder: &str) -> String {
    let placeholders = if bind_prefix == "?" {
        (0..44).map(|_| "?".to_string()).collect::<Vec<_>>()
    } else {
        (1..=44)
            .map(|index| format!("${index}"))
            .collect::<Vec<_>>()
    };
    format!(
        r#"
        INSERT INTO supplier_product_security_record (
            tenant_id, supplier_id, product_id, product_or_service, criticality,
            internal_owner, supplier_security_contact, product_security_status,
            advisory_id, advisory_source_type, advisory_reference, cve_ids_json,
            affected_versions, fixed_versions, severity, cvss_score, epss_score,
            exploitation_status, affected_assets_summary, impact_summary,
            remediation_summary, workaround_summary, review_status, owner, due_date,
            evidence_ids_json, sbom_vex_reference, open_actions,
            management_review_reference, contract_status, contract_review_date,
            next_contract_review_due, exit_plan_status, exit_plan_version,
            exit_plan_review_date, exit_plan_owner, critical_service_dependency,
            data_processing_relevance, dora_ict_third_party_relevance,
            nis2_supply_chain_relevance, termination_risk_summary,
            alternative_supplier_summary, created_by_id, updated_by_id
        ) VALUES ({})
        RETURNING id
        "#,
        placeholders.join(", ")
    )
}

async fn update_record_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    record_id: i64,
    actor_id: i64,
    payload: SupplierProductSecurityPatchRequest,
) -> SupplierProductSecurityResult<Option<SupplierProductSecurityDetail>> {
    let Some(current) = fetch_record_sqlite(pool, tenant_id, record_id).await? else {
        return Ok(None);
    };
    let record = ValidatedSupplierProductSecurityRecord::apply_patch(&current, payload)?;
    ensure_product_sqlite(pool, tenant_id, record.product_id).await?;
    ensure_evidence_ids_sqlite(pool, tenant_id, &record.evidence_ids).await?;
    apply_update_sqlite(pool, tenant_id, record_id, actor_id, &record).await?;
    replace_evidence_links_sqlite(pool, tenant_id, record_id, actor_id, &record.evidence_ids)
        .await?;
    let version = next_history_version_sqlite(pool, tenant_id, record_id).await?;
    let history = ContractHistoryInsert {
        tenant_id,
        record_id,
        supplier_id: record.supplier_id,
        actor_id,
        version_number: version,
        previous_status: &current.contract_status,
        new_status: &record.contract_status,
        change_reason: &record.change_reason,
        evidence_ids: &record.evidence_ids,
    };
    insert_contract_history_sqlite(pool, &history).await?;
    insert_event_sqlite(
        pool,
        tenant_id,
        record_id,
        "supplier_product_security_record_updated",
        Some(actor_id),
        json!({"previous_status": current.review_status, "review_status": record.review_status}),
    )
    .await?;
    detail_sqlite(pool, tenant_id, record_id).await
}

async fn update_record_postgres(
    pool: &PgPool,
    tenant_id: i64,
    record_id: i64,
    actor_id: i64,
    payload: SupplierProductSecurityPatchRequest,
) -> SupplierProductSecurityResult<Option<SupplierProductSecurityDetail>> {
    let Some(current) = fetch_record_postgres(pool, tenant_id, record_id).await? else {
        return Ok(None);
    };
    let record = ValidatedSupplierProductSecurityRecord::apply_patch(&current, payload)?;
    ensure_product_postgres(pool, tenant_id, record.product_id).await?;
    ensure_evidence_ids_postgres(pool, tenant_id, &record.evidence_ids).await?;
    apply_update_postgres(pool, tenant_id, record_id, actor_id, &record).await?;
    replace_evidence_links_postgres(pool, tenant_id, record_id, actor_id, &record.evidence_ids)
        .await?;
    let version = next_history_version_postgres(pool, tenant_id, record_id).await?;
    let history = ContractHistoryInsert {
        tenant_id,
        record_id,
        supplier_id: record.supplier_id,
        actor_id,
        version_number: version,
        previous_status: &current.contract_status,
        new_status: &record.contract_status,
        change_reason: &record.change_reason,
        evidence_ids: &record.evidence_ids,
    };
    insert_contract_history_postgres(pool, &history).await?;
    insert_event_postgres(
        pool,
        tenant_id,
        record_id,
        "supplier_product_security_record_updated",
        Some(actor_id),
        json!({"previous_status": current.review_status, "review_status": record.review_status}),
    )
    .await?;
    detail_postgres(pool, tenant_id, record_id).await
}

async fn apply_update_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    record_id: i64,
    actor_id: i64,
    record: &ValidatedSupplierProductSecurityRecord,
) -> Result<(), sqlx::Error> {
    let sql = update_record_sql("?");
    bind_update(sqlx::query(&sql), tenant_id, record_id, actor_id, record)
        .execute(pool)
        .await?;
    Ok(())
}

async fn apply_update_postgres(
    pool: &PgPool,
    tenant_id: i64,
    record_id: i64,
    actor_id: i64,
    record: &ValidatedSupplierProductSecurityRecord,
) -> Result<(), sqlx::Error> {
    let sql = update_record_sql("$");
    bind_update(sqlx::query(&sql), tenant_id, record_id, actor_id, record)
        .execute(pool)
        .await?;
    Ok(())
}

fn update_record_sql(bind_prefix: &str) -> String {
    let placeholders = if bind_prefix == "?" {
        (0..41).map(|_| "?".to_string()).collect::<Vec<_>>()
    } else {
        (1..=41)
            .map(|index| format!("${index}"))
            .collect::<Vec<_>>()
    };
    format!(
        r#"
        UPDATE supplier_product_security_record SET
            product_id = {}, product_or_service = {}, criticality = {},
            internal_owner = {}, supplier_security_contact = {},
            product_security_status = {}, advisory_id = {}, advisory_source_type = {},
            advisory_reference = {}, cve_ids_json = {}, affected_versions = {},
            fixed_versions = {}, severity = {}, cvss_score = {}, epss_score = {},
            exploitation_status = {}, affected_assets_summary = {}, impact_summary = {},
            remediation_summary = {}, workaround_summary = {}, review_status = {},
            owner = {}, due_date = {}, evidence_ids_json = {}, sbom_vex_reference = {},
            open_actions = {}, management_review_reference = {}, contract_status = {},
            contract_review_date = {}, next_contract_review_due = {}, exit_plan_status = {},
            exit_plan_version = {}, exit_plan_review_date = {}, exit_plan_owner = {},
            critical_service_dependency = {}, data_processing_relevance = {},
            dora_ict_third_party_relevance = {}, nis2_supply_chain_relevance = {},
            termination_risk_summary = {}, alternative_supplier_summary = {},
            updated_by_id = {}, updated_at = CURRENT_TIMESTAMP
        WHERE tenant_id = {} AND id = {}
        "#,
        placeholders[0],
        placeholders[1],
        placeholders[2],
        placeholders[3],
        placeholders[4],
        placeholders[5],
        placeholders[6],
        placeholders[7],
        placeholders[8],
        placeholders[9],
        placeholders[10],
        placeholders[11],
        placeholders[12],
        placeholders[13],
        placeholders[14],
        placeholders[15],
        placeholders[16],
        placeholders[17],
        placeholders[18],
        placeholders[19],
        placeholders[20],
        placeholders[21],
        placeholders[22],
        placeholders[23],
        placeholders[24],
        placeholders[25],
        placeholders[26],
        placeholders[27],
        placeholders[28],
        placeholders[29],
        placeholders[30],
        placeholders[31],
        placeholders[32],
        placeholders[33],
        placeholders[34],
        placeholders[35],
        placeholders[36],
        placeholders[37],
        placeholders[38],
        placeholders[39],
        placeholders[40],
        if bind_prefix == "?" { "?" } else { "$42" },
        if bind_prefix == "?" { "?" } else { "$43" },
    )
}

fn bind_update<'q, DB>(
    query: sqlx::query::Query<'q, DB, <DB as sqlx::Database>::Arguments<'q>>,
    tenant_id: i64,
    record_id: i64,
    actor_id: i64,
    record: &ValidatedSupplierProductSecurityRecord,
) -> sqlx::query::Query<'q, DB, <DB as sqlx::Database>::Arguments<'q>>
where
    DB: sqlx::Database,
    for<'a> Option<i64>: sqlx::Encode<'a, DB> + sqlx::Type<DB>,
    for<'a> String: sqlx::Encode<'a, DB> + sqlx::Type<DB>,
    for<'a> Option<String>: sqlx::Encode<'a, DB> + sqlx::Type<DB>,
    for<'a> Option<f64>: sqlx::Encode<'a, DB> + sqlx::Type<DB>,
    for<'a> bool: sqlx::Encode<'a, DB> + sqlx::Type<DB>,
    for<'a> i64: sqlx::Encode<'a, DB> + sqlx::Type<DB>,
{
    query
        .bind(record.product_id)
        .bind(record.product_or_service.clone())
        .bind(record.criticality.clone())
        .bind(record.internal_owner.clone())
        .bind(record.supplier_security_contact.clone())
        .bind(record.product_security_status.clone())
        .bind(record.advisory_id.clone())
        .bind(record.advisory_source_type.clone())
        .bind(record.advisory_reference.clone())
        .bind(json_ids(&record.cve_ids))
        .bind(record.affected_versions.clone())
        .bind(record.fixed_versions.clone())
        .bind(record.severity.clone())
        .bind(record.cvss_score)
        .bind(record.epss_score)
        .bind(record.exploitation_status.clone())
        .bind(record.affected_assets_summary.clone())
        .bind(record.impact_summary.clone())
        .bind(record.remediation_summary.clone())
        .bind(record.workaround_summary.clone())
        .bind(record.review_status.clone())
        .bind(record.owner.clone())
        .bind(record.due_date.clone())
        .bind(json_ids_i64(&record.evidence_ids))
        .bind(record.sbom_vex_reference.clone())
        .bind(record.open_actions.clone())
        .bind(record.management_review_reference.clone())
        .bind(record.contract_status.clone())
        .bind(record.contract_review_date.clone())
        .bind(record.next_contract_review_due.clone())
        .bind(record.exit_plan_status.clone())
        .bind(record.exit_plan_version.clone())
        .bind(record.exit_plan_review_date.clone())
        .bind(record.exit_plan_owner.clone())
        .bind(record.critical_service_dependency)
        .bind(record.data_processing_relevance)
        .bind(record.dora_ict_third_party_relevance)
        .bind(record.nis2_supply_chain_relevance)
        .bind(record.termination_risk_summary.clone())
        .bind(record.alternative_supplier_summary.clone())
        .bind(actor_id)
        .bind(tenant_id)
        .bind(record_id)
}

async fn update_status_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    record_id: i64,
    actor_id: i64,
    status: String,
    reason: String,
    notes: String,
) -> SupplierProductSecurityResult<Option<SupplierProductSecurityDetail>> {
    let Some(current) = fetch_record_sqlite(pool, tenant_id, record_id).await? else {
        return Ok(None);
    };
    sqlx::query(
        "UPDATE supplier_product_security_record SET review_status = ?, reviewed_at = CURRENT_TIMESTAMP, reviewed_by = ?, updated_by_id = ?, updated_at = CURRENT_TIMESTAMP WHERE tenant_id = ? AND id = ?",
    )
    .bind(&status)
    .bind(actor_id)
    .bind(actor_id)
    .bind(tenant_id)
    .bind(record_id)
    .execute(pool)
    .await?;
    insert_event_sqlite(
        pool,
        tenant_id,
        record_id,
        "supplier_product_security_status_changed",
        Some(actor_id),
        json!({"previous_status": current.review_status, "new_status": status, "reason": reason, "review_notes": notes}),
    )
    .await?;
    detail_sqlite(pool, tenant_id, record_id).await
}

async fn update_status_postgres(
    pool: &PgPool,
    tenant_id: i64,
    record_id: i64,
    actor_id: i64,
    status: String,
    reason: String,
    notes: String,
) -> SupplierProductSecurityResult<Option<SupplierProductSecurityDetail>> {
    let Some(current) = fetch_record_postgres(pool, tenant_id, record_id).await? else {
        return Ok(None);
    };
    sqlx::query(
        "UPDATE supplier_product_security_record SET review_status = $1, reviewed_at = (CURRENT_TIMESTAMP)::text, reviewed_by = $2, updated_by_id = $3, updated_at = (CURRENT_TIMESTAMP)::text WHERE tenant_id = $4 AND id = $5",
    )
    .bind(&status)
    .bind(actor_id)
    .bind(actor_id)
    .bind(tenant_id)
    .bind(record_id)
    .execute(pool)
    .await?;
    insert_event_postgres(
        pool,
        tenant_id,
        record_id,
        "supplier_product_security_status_changed",
        Some(actor_id),
        json!({"previous_status": current.review_status, "new_status": status, "reason": reason, "review_notes": notes}),
    )
    .await?;
    detail_postgres(pool, tenant_id, record_id).await
}

async fn link_evidence_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    record_id: i64,
    actor_id: i64,
    evidence_id: i64,
    link_type: String,
) -> SupplierProductSecurityResult<Option<SupplierProductSecurityDetail>> {
    let Some(current) = fetch_record_sqlite(pool, tenant_id, record_id).await? else {
        return Ok(None);
    };
    ensure_evidence_ids_sqlite(pool, tenant_id, &[evidence_id]).await?;
    insert_evidence_link_sqlite(
        pool,
        tenant_id,
        record_id,
        actor_id,
        evidence_id,
        &link_type,
    )
    .await?;
    let mut ids = current.evidence_ids;
    ids.push(evidence_id);
    ids = normalize_positive_ids(ids, "Evidence-IDs")?;
    sqlx::query("UPDATE supplier_product_security_record SET evidence_ids_json = ?, updated_by_id = ?, updated_at = CURRENT_TIMESTAMP WHERE tenant_id = ? AND id = ?")
        .bind(json_ids_i64(&ids))
        .bind(actor_id)
        .bind(tenant_id)
        .bind(record_id)
        .execute(pool)
        .await?;
    insert_event_sqlite(
        pool,
        tenant_id,
        record_id,
        "supplier_product_security_evidence_linked",
        Some(actor_id),
        json!({"evidence_linked": true, "link_type": link_type}),
    )
    .await?;
    detail_sqlite(pool, tenant_id, record_id).await
}

async fn link_evidence_postgres(
    pool: &PgPool,
    tenant_id: i64,
    record_id: i64,
    actor_id: i64,
    evidence_id: i64,
    link_type: String,
) -> SupplierProductSecurityResult<Option<SupplierProductSecurityDetail>> {
    let Some(current) = fetch_record_postgres(pool, tenant_id, record_id).await? else {
        return Ok(None);
    };
    ensure_evidence_ids_postgres(pool, tenant_id, &[evidence_id]).await?;
    insert_evidence_link_postgres(
        pool,
        tenant_id,
        record_id,
        actor_id,
        evidence_id,
        &link_type,
    )
    .await?;
    let mut ids = current.evidence_ids;
    ids.push(evidence_id);
    ids = normalize_positive_ids(ids, "Evidence-IDs")?;
    sqlx::query("UPDATE supplier_product_security_record SET evidence_ids_json = $1, updated_by_id = $2, updated_at = (CURRENT_TIMESTAMP)::text WHERE tenant_id = $3 AND id = $4")
        .bind(json_ids_i64(&ids))
        .bind(actor_id)
        .bind(tenant_id)
        .bind(record_id)
        .execute(pool)
        .await?;
    insert_event_postgres(
        pool,
        tenant_id,
        record_id,
        "supplier_product_security_evidence_linked",
        Some(actor_id),
        json!({"evidence_linked": true, "link_type": link_type}),
    )
    .await?;
    detail_postgres(pool, tenant_id, record_id).await
}

async fn insert_evidence_link_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    record_id: i64,
    actor_id: i64,
    evidence_id: i64,
    link_type: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT OR IGNORE INTO supplier_product_security_evidence_link (tenant_id, record_id, evidence_id, link_type, created_by_id) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(tenant_id)
    .bind(record_id)
    .bind(evidence_id)
    .bind(link_type)
    .bind(actor_id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn insert_evidence_link_postgres(
    pool: &PgPool,
    tenant_id: i64,
    record_id: i64,
    actor_id: i64,
    evidence_id: i64,
    link_type: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO supplier_product_security_evidence_link (tenant_id, record_id, evidence_id, link_type, created_by_id) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tenant_id, record_id, evidence_id) DO NOTHING",
    )
    .bind(tenant_id)
    .bind(record_id)
    .bind(evidence_id)
    .bind(link_type)
    .bind(actor_id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn replace_evidence_links_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    record_id: i64,
    actor_id: i64,
    evidence_ids: &[i64],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM supplier_product_security_evidence_link WHERE tenant_id = ? AND record_id = ?",
    )
    .bind(tenant_id)
    .bind(record_id)
    .execute(pool)
    .await?;
    for evidence_id in evidence_ids {
        insert_evidence_link_sqlite(pool, tenant_id, record_id, actor_id, *evidence_id, "review")
            .await?;
    }
    Ok(())
}

async fn replace_evidence_links_postgres(
    pool: &PgPool,
    tenant_id: i64,
    record_id: i64,
    actor_id: i64,
    evidence_ids: &[i64],
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM supplier_product_security_evidence_link WHERE tenant_id = $1 AND record_id = $2")
        .bind(tenant_id)
        .bind(record_id)
        .execute(pool)
        .await?;
    for evidence_id in evidence_ids {
        insert_evidence_link_postgres(pool, tenant_id, record_id, actor_id, *evidence_id, "review")
            .await?;
    }
    Ok(())
}

async fn list_evidence_links_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    record_id: i64,
) -> SupplierProductSecurityResult<Vec<SupplierProductSecurityEvidenceLink>> {
    let rows = sqlx::query(
        r#"
        SELECT link.id, link.record_id, link.evidence_id, evidence.title, evidence.status,
               link.link_type, CAST(link.created_at AS TEXT) AS created_at
        FROM supplier_product_security_evidence_link link
        JOIN evidence_evidenceitem evidence
            ON evidence.id = link.evidence_id
            AND evidence.tenant_id = link.tenant_id
        WHERE link.tenant_id = ? AND link.record_id = ?
        ORDER BY link.created_at DESC, link.id DESC
        "#,
    )
    .bind(tenant_id)
    .bind(record_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(evidence_link_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_evidence_links_postgres(
    pool: &PgPool,
    tenant_id: i64,
    record_id: i64,
) -> SupplierProductSecurityResult<Vec<SupplierProductSecurityEvidenceLink>> {
    let rows = sqlx::query(
        r#"
        SELECT link.id, link.record_id, link.evidence_id, evidence.title, evidence.status,
               link.link_type, link.created_at AS created_at
        FROM supplier_product_security_evidence_link link
        JOIN evidence_evidenceitem evidence
            ON evidence.id = link.evidence_id
            AND evidence.tenant_id = link.tenant_id
        WHERE link.tenant_id = $1 AND link.record_id = $2
        ORDER BY link.created_at DESC, link.id DESC
        "#,
    )
    .bind(tenant_id)
    .bind(record_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(evidence_link_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn insert_event_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    record_id: i64,
    event_type: &str,
    actor_id: Option<i64>,
    detail_json: Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO supplier_product_security_event (tenant_id, record_id, event_type, actor_id, detail_json) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(tenant_id)
    .bind(record_id)
    .bind(event_type)
    .bind(actor_id)
    .bind(detail_json.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

async fn insert_event_postgres(
    pool: &PgPool,
    tenant_id: i64,
    record_id: i64,
    event_type: &str,
    actor_id: Option<i64>,
    detail_json: Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO supplier_product_security_event (tenant_id, record_id, event_type, actor_id, detail_json) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(tenant_id)
    .bind(record_id)
    .bind(event_type)
    .bind(actor_id)
    .bind(detail_json.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

async fn list_events_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    record_id: i64,
) -> SupplierProductSecurityResult<Vec<SupplierProductSecurityEvent>> {
    let rows = sqlx::query(
        "SELECT id, record_id, event_type, actor_id, detail_json, CAST(created_at AS TEXT) AS created_at FROM supplier_product_security_event WHERE tenant_id = ? AND record_id = ? ORDER BY created_at DESC, id DESC LIMIT 100",
    )
    .bind(tenant_id)
    .bind(record_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(event_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_events_postgres(
    pool: &PgPool,
    tenant_id: i64,
    record_id: i64,
) -> SupplierProductSecurityResult<Vec<SupplierProductSecurityEvent>> {
    let rows = sqlx::query(
        "SELECT id, record_id, event_type, actor_id, detail_json, created_at FROM supplier_product_security_event WHERE tenant_id = $1 AND record_id = $2 ORDER BY created_at DESC, id DESC LIMIT 100",
    )
    .bind(tenant_id)
    .bind(record_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(event_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

struct ContractHistoryInsert<'a> {
    tenant_id: i64,
    record_id: i64,
    supplier_id: i64,
    actor_id: i64,
    version_number: i64,
    previous_status: &'a str,
    new_status: &'a str,
    change_reason: &'a str,
    evidence_ids: &'a [i64],
}

async fn insert_contract_history_sqlite(
    pool: &SqlitePool,
    history: &ContractHistoryInsert<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO supplier_contract_exit_history (tenant_id, record_id, supplier_id, version_number, changed_by, change_reason, previous_status, new_status, summary, evidence_ids_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(history.tenant_id)
    .bind(history.record_id)
    .bind(history.supplier_id)
    .bind(history.version_number)
    .bind(history.actor_id)
    .bind(history.change_reason)
    .bind(history.previous_status)
    .bind(history.new_status)
    .bind(format!(
        "Contract-/Exit-Plan-Version {} erfasst.",
        history.version_number
    ))
    .bind(json_ids_i64(history.evidence_ids))
    .execute(pool)
    .await?;
    Ok(())
}

async fn insert_contract_history_postgres(
    pool: &PgPool,
    history: &ContractHistoryInsert<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO supplier_contract_exit_history (tenant_id, record_id, supplier_id, version_number, changed_by, change_reason, previous_status, new_status, summary, evidence_ids_json) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(history.tenant_id)
    .bind(history.record_id)
    .bind(history.supplier_id)
    .bind(history.version_number)
    .bind(history.actor_id)
    .bind(history.change_reason)
    .bind(history.previous_status)
    .bind(history.new_status)
    .bind(format!(
        "Contract-/Exit-Plan-Version {} erfasst.",
        history.version_number
    ))
    .bind(json_ids_i64(history.evidence_ids))
    .execute(pool)
    .await?;
    Ok(())
}

async fn next_history_version_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    record_id: i64,
) -> Result<i64, sqlx::Error> {
    let value = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(MAX(version_number), 0) + 1 FROM supplier_contract_exit_history WHERE tenant_id = ? AND record_id = ?",
    )
    .bind(tenant_id)
    .bind(record_id)
    .fetch_one(pool)
    .await?;
    Ok(value)
}

async fn next_history_version_postgres(
    pool: &PgPool,
    tenant_id: i64,
    record_id: i64,
) -> Result<i64, sqlx::Error> {
    let value = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(MAX(version_number), 0) + 1 FROM supplier_contract_exit_history WHERE tenant_id = $1 AND record_id = $2",
    )
    .bind(tenant_id)
    .bind(record_id)
    .fetch_one(pool)
    .await?;
    Ok(value)
}

async fn list_record_history_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    record_id: i64,
) -> SupplierProductSecurityResult<Vec<SupplierContractExitHistoryEntry>> {
    let rows = sqlx::query(
        "SELECT * FROM supplier_contract_exit_history WHERE tenant_id = ? AND record_id = ? ORDER BY version_number DESC, id DESC",
    )
    .bind(tenant_id)
    .bind(record_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(history_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_record_history_postgres(
    pool: &PgPool,
    tenant_id: i64,
    record_id: i64,
) -> SupplierProductSecurityResult<Vec<SupplierContractExitHistoryEntry>> {
    let rows = sqlx::query(
        "SELECT * FROM supplier_contract_exit_history WHERE tenant_id = $1 AND record_id = $2 ORDER BY version_number DESC, id DESC",
    )
    .bind(tenant_id)
    .bind(record_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(history_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_supplier_history_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    supplier_id: i64,
) -> SupplierProductSecurityResult<Vec<SupplierContractExitHistoryEntry>> {
    let rows = sqlx::query(
        "SELECT * FROM supplier_contract_exit_history WHERE tenant_id = ? AND supplier_id = ? ORDER BY changed_at DESC, id DESC LIMIT 100",
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(history_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_supplier_history_postgres(
    pool: &PgPool,
    tenant_id: i64,
    supplier_id: i64,
) -> SupplierProductSecurityResult<Vec<SupplierContractExitHistoryEntry>> {
    let rows = sqlx::query(
        "SELECT * FROM supplier_contract_exit_history WHERE tenant_id = $1 AND supplier_id = $2 ORDER BY changed_at DESC, id DESC LIMIT 100",
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(history_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn ensure_supplier_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    supplier_id: i64,
) -> SupplierProductSecurityResult<()> {
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM organizations_supplier WHERE tenant_id = ? AND id = ?",
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .fetch_one(pool)
    .await?;
    if exists == 0 {
        return Err(SupplierProductSecurityError::not_found());
    }
    Ok(())
}

async fn ensure_supplier_postgres(
    pool: &PgPool,
    tenant_id: i64,
    supplier_id: i64,
) -> SupplierProductSecurityResult<()> {
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint FROM organizations_supplier WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .fetch_one(pool)
    .await?;
    if exists == 0 {
        return Err(SupplierProductSecurityError::not_found());
    }
    Ok(())
}

async fn ensure_record_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    record_id: i64,
) -> SupplierProductSecurityResult<()> {
    if fetch_record_sqlite(pool, tenant_id, record_id)
        .await?
        .is_none()
    {
        return Err(SupplierProductSecurityError::not_found());
    }
    Ok(())
}

async fn ensure_record_postgres(
    pool: &PgPool,
    tenant_id: i64,
    record_id: i64,
) -> SupplierProductSecurityResult<()> {
    if fetch_record_postgres(pool, tenant_id, record_id)
        .await?
        .is_none()
    {
        return Err(SupplierProductSecurityError::not_found());
    }
    Ok(())
}

async fn ensure_product_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    product_id: Option<i64>,
) -> SupplierProductSecurityResult<()> {
    let Some(product_id) = product_id else {
        return Ok(());
    };
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM product_security_product WHERE tenant_id = ? AND id = ?",
    )
    .bind(tenant_id)
    .bind(product_id)
    .fetch_one(pool)
    .await?;
    if exists == 0 {
        return Err(SupplierProductSecurityError::invalid(
            "Produkt wurde fuer diesen Tenant nicht gefunden.",
        ));
    }
    Ok(())
}

async fn ensure_product_postgres(
    pool: &PgPool,
    tenant_id: i64,
    product_id: Option<i64>,
) -> SupplierProductSecurityResult<()> {
    let Some(product_id) = product_id else {
        return Ok(());
    };
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint FROM product_security_product WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(product_id)
    .fetch_one(pool)
    .await?;
    if exists == 0 {
        return Err(SupplierProductSecurityError::invalid(
            "Produkt wurde fuer diesen Tenant nicht gefunden.",
        ));
    }
    Ok(())
}

async fn ensure_evidence_ids_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    evidence_ids: &[i64],
) -> SupplierProductSecurityResult<()> {
    for evidence_id in evidence_ids {
        let exists = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM evidence_evidenceitem WHERE tenant_id = ? AND id = ?",
        )
        .bind(tenant_id)
        .bind(*evidence_id)
        .fetch_one(pool)
        .await?;
        if exists == 0 {
            return Err(SupplierProductSecurityError::invalid(
                "Evidence wurde fuer diesen Tenant nicht gefunden.",
            ));
        }
    }
    Ok(())
}

async fn ensure_evidence_ids_postgres(
    pool: &PgPool,
    tenant_id: i64,
    evidence_ids: &[i64],
) -> SupplierProductSecurityResult<()> {
    for evidence_id in evidence_ids {
        let exists = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)::bigint FROM evidence_evidenceitem WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(*evidence_id)
        .fetch_one(pool)
        .await?;
        if exists == 0 {
            return Err(SupplierProductSecurityError::invalid(
                "Evidence wurde fuer diesen Tenant nicht gefunden.",
            ));
        }
    }
    Ok(())
}

fn record_from_sqlite_row(row: SqliteRow) -> Result<SupplierProductSecurityRecord, sqlx::Error> {
    record_from_raw(RawRecord {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        supplier_id: row.try_get("supplier_id")?,
        supplier_name: row.try_get("supplier_name")?,
        product_id: row.try_get("product_id")?,
        product_name: row.try_get("product_name")?,
        product_or_service: row.try_get("product_or_service")?,
        criticality: row.try_get("criticality")?,
        internal_owner: row.try_get("internal_owner")?,
        supplier_security_contact: row.try_get("supplier_security_contact")?,
        product_security_status: row.try_get("product_security_status")?,
        advisory_id: row.try_get("advisory_id")?,
        advisory_source_type: row.try_get("advisory_source_type")?,
        advisory_reference: row.try_get("advisory_reference")?,
        cve_ids_json: row.try_get("cve_ids_json")?,
        affected_versions: row.try_get("affected_versions")?,
        fixed_versions: row.try_get("fixed_versions")?,
        severity: row.try_get("severity")?,
        cvss_score: row.try_get("cvss_score")?,
        epss_score: row.try_get("epss_score")?,
        exploitation_status: row.try_get("exploitation_status")?,
        affected_assets_summary: row.try_get("affected_assets_summary")?,
        impact_summary: row.try_get("impact_summary")?,
        remediation_summary: row.try_get("remediation_summary")?,
        workaround_summary: row.try_get("workaround_summary")?,
        review_status: row.try_get("review_status")?,
        owner: row.try_get("owner")?,
        due_date: row.try_get("due_date")?,
        evidence_ids_json: row.try_get("evidence_ids_json")?,
        sbom_vex_reference: row.try_get("sbom_vex_reference")?,
        open_actions: row.try_get("open_actions")?,
        management_review_reference: row.try_get("management_review_reference")?,
        contract_status: row.try_get("contract_status")?,
        contract_review_date: row.try_get("contract_review_date")?,
        next_contract_review_due: row.try_get("next_contract_review_due")?,
        exit_plan_status: row.try_get("exit_plan_status")?,
        exit_plan_version: row.try_get("exit_plan_version")?,
        exit_plan_review_date: row.try_get("exit_plan_review_date")?,
        exit_plan_owner: row.try_get("exit_plan_owner")?,
        critical_service_dependency: row.try_get("critical_service_dependency")?,
        data_processing_relevance: row.try_get("data_processing_relevance")?,
        dora_ict_third_party_relevance: row.try_get("dora_ict_third_party_relevance")?,
        nis2_supply_chain_relevance: row.try_get("nis2_supply_chain_relevance")?,
        termination_risk_summary: row.try_get("termination_risk_summary")?,
        alternative_supplier_summary: row.try_get("alternative_supplier_summary")?,
        created_by_id: row.try_get("created_by_id")?,
        updated_by_id: row.try_get("updated_by_id")?,
        reviewed_at: row.try_get("reviewed_at")?,
        reviewed_by: row.try_get("reviewed_by")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn record_from_pg_row(row: PgRow) -> Result<SupplierProductSecurityRecord, sqlx::Error> {
    record_from_raw(RawRecord {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        supplier_id: row.try_get("supplier_id")?,
        supplier_name: row.try_get("supplier_name")?,
        product_id: row.try_get("product_id")?,
        product_name: row.try_get("product_name")?,
        product_or_service: row.try_get("product_or_service")?,
        criticality: row.try_get("criticality")?,
        internal_owner: row.try_get("internal_owner")?,
        supplier_security_contact: row.try_get("supplier_security_contact")?,
        product_security_status: row.try_get("product_security_status")?,
        advisory_id: row.try_get("advisory_id")?,
        advisory_source_type: row.try_get("advisory_source_type")?,
        advisory_reference: row.try_get("advisory_reference")?,
        cve_ids_json: row.try_get("cve_ids_json")?,
        affected_versions: row.try_get("affected_versions")?,
        fixed_versions: row.try_get("fixed_versions")?,
        severity: row.try_get("severity")?,
        cvss_score: row.try_get("cvss_score")?,
        epss_score: row.try_get("epss_score")?,
        exploitation_status: row.try_get("exploitation_status")?,
        affected_assets_summary: row.try_get("affected_assets_summary")?,
        impact_summary: row.try_get("impact_summary")?,
        remediation_summary: row.try_get("remediation_summary")?,
        workaround_summary: row.try_get("workaround_summary")?,
        review_status: row.try_get("review_status")?,
        owner: row.try_get("owner")?,
        due_date: row.try_get("due_date")?,
        evidence_ids_json: row.try_get("evidence_ids_json")?,
        sbom_vex_reference: row.try_get("sbom_vex_reference")?,
        open_actions: row.try_get("open_actions")?,
        management_review_reference: row.try_get("management_review_reference")?,
        contract_status: row.try_get("contract_status")?,
        contract_review_date: row.try_get("contract_review_date")?,
        next_contract_review_due: row.try_get("next_contract_review_due")?,
        exit_plan_status: row.try_get("exit_plan_status")?,
        exit_plan_version: row.try_get("exit_plan_version")?,
        exit_plan_review_date: row.try_get("exit_plan_review_date")?,
        exit_plan_owner: row.try_get("exit_plan_owner")?,
        critical_service_dependency: row.try_get("critical_service_dependency")?,
        data_processing_relevance: row.try_get("data_processing_relevance")?,
        dora_ict_third_party_relevance: row.try_get("dora_ict_third_party_relevance")?,
        nis2_supply_chain_relevance: row.try_get("nis2_supply_chain_relevance")?,
        termination_risk_summary: row.try_get("termination_risk_summary")?,
        alternative_supplier_summary: row.try_get("alternative_supplier_summary")?,
        created_by_id: row.try_get("created_by_id")?,
        updated_by_id: row.try_get("updated_by_id")?,
        reviewed_at: row.try_get("reviewed_at")?,
        reviewed_by: row.try_get("reviewed_by")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

struct RawRecord {
    id: i64,
    tenant_id: i64,
    supplier_id: i64,
    supplier_name: String,
    product_id: Option<i64>,
    product_name: Option<String>,
    product_or_service: String,
    criticality: String,
    internal_owner: String,
    supplier_security_contact: String,
    product_security_status: String,
    advisory_id: String,
    advisory_source_type: String,
    advisory_reference: String,
    cve_ids_json: String,
    affected_versions: String,
    fixed_versions: String,
    severity: String,
    cvss_score: Option<f64>,
    epss_score: Option<f64>,
    exploitation_status: String,
    affected_assets_summary: String,
    impact_summary: String,
    remediation_summary: String,
    workaround_summary: String,
    review_status: String,
    owner: String,
    due_date: Option<String>,
    evidence_ids_json: String,
    sbom_vex_reference: String,
    open_actions: String,
    management_review_reference: String,
    contract_status: String,
    contract_review_date: Option<String>,
    next_contract_review_due: Option<String>,
    exit_plan_status: String,
    exit_plan_version: String,
    exit_plan_review_date: Option<String>,
    exit_plan_owner: String,
    critical_service_dependency: bool,
    data_processing_relevance: bool,
    dora_ict_third_party_relevance: bool,
    nis2_supply_chain_relevance: bool,
    termination_risk_summary: String,
    alternative_supplier_summary: String,
    created_by_id: Option<i64>,
    updated_by_id: Option<i64>,
    reviewed_at: Option<String>,
    reviewed_by: Option<i64>,
    created_at: String,
    updated_at: String,
}

fn record_from_raw(raw: RawRecord) -> Result<SupplierProductSecurityRecord, sqlx::Error> {
    let criticality = normalize_lossy(&raw.criticality);
    let product_security_status = normalize_lossy(&raw.product_security_status);
    let advisory_source_type = normalize_lossy(&raw.advisory_source_type);
    let severity = normalize_lossy(&raw.severity);
    let exploitation_status = normalize_lossy(&raw.exploitation_status);
    let review_status = normalize_lossy(&raw.review_status);
    let contract_status = normalize_lossy(&raw.contract_status);
    let exit_plan_status = normalize_lossy(&raw.exit_plan_status);
    Ok(SupplierProductSecurityRecord {
        id: raw.id,
        tenant_id: raw.tenant_id,
        supplier_id: raw.supplier_id,
        supplier_name: raw.supplier_name,
        product_id: raw.product_id,
        product_name: raw.product_name,
        product_or_service: raw.product_or_service,
        criticality_label: criticality_label(&criticality).to_string(),
        criticality,
        internal_owner: raw.internal_owner,
        supplier_security_contact: raw.supplier_security_contact,
        product_security_status_label: product_security_status_label(&product_security_status)
            .to_string(),
        product_security_status,
        advisory_id: raw.advisory_id,
        advisory_source_type_label: advisory_source_type_label(&advisory_source_type).to_string(),
        advisory_source_type,
        advisory_reference: raw.advisory_reference,
        cve_ids: parse_string_vec(&raw.cve_ids_json),
        affected_versions: raw.affected_versions,
        fixed_versions: raw.fixed_versions,
        severity_label: severity_label(&severity).to_string(),
        severity,
        cvss_score: raw.cvss_score,
        epss_score: raw.epss_score,
        exploitation_status_label: exploitation_status_label(&exploitation_status).to_string(),
        exploitation_status,
        affected_assets_summary: raw.affected_assets_summary,
        impact_summary: raw.impact_summary,
        remediation_summary: raw.remediation_summary,
        workaround_summary: raw.workaround_summary,
        review_status_label: review_status_label(&review_status).to_string(),
        review_status,
        owner: raw.owner,
        due_date: raw.due_date,
        evidence_ids: parse_i64_vec(&raw.evidence_ids_json),
        sbom_vex_reference: raw.sbom_vex_reference,
        open_actions: raw.open_actions,
        management_review_reference: raw.management_review_reference,
        contract_status_label: contract_status_label(&contract_status).to_string(),
        contract_status,
        contract_review_date: raw.contract_review_date,
        next_contract_review_due: raw.next_contract_review_due,
        exit_plan_status_label: exit_plan_status_label(&exit_plan_status).to_string(),
        exit_plan_status,
        exit_plan_version: raw.exit_plan_version,
        exit_plan_review_date: raw.exit_plan_review_date,
        exit_plan_owner: raw.exit_plan_owner,
        critical_service_dependency: raw.critical_service_dependency,
        data_processing_relevance: raw.data_processing_relevance,
        dora_ict_third_party_relevance: raw.dora_ict_third_party_relevance,
        nis2_supply_chain_relevance: raw.nis2_supply_chain_relevance,
        termination_risk_summary: raw.termination_risk_summary,
        alternative_supplier_summary: raw.alternative_supplier_summary,
        created_by_id: raw.created_by_id,
        updated_by_id: raw.updated_by_id,
        reviewed_at: raw.reviewed_at,
        reviewed_by: raw.reviewed_by,
        created_at: raw.created_at,
        updated_at: raw.updated_at,
    })
}

fn evidence_link_from_sqlite_row(
    row: SqliteRow,
) -> Result<SupplierProductSecurityEvidenceLink, sqlx::Error> {
    Ok(SupplierProductSecurityEvidenceLink {
        id: row.try_get("id")?,
        record_id: row.try_get("record_id")?,
        evidence_id: row.try_get("evidence_id")?,
        title: row.try_get("title")?,
        status: row.try_get("status")?,
        link_type: row.try_get("link_type")?,
        created_at: row.try_get("created_at")?,
    })
}

fn evidence_link_from_pg_row(
    row: PgRow,
) -> Result<SupplierProductSecurityEvidenceLink, sqlx::Error> {
    Ok(SupplierProductSecurityEvidenceLink {
        id: row.try_get("id")?,
        record_id: row.try_get("record_id")?,
        evidence_id: row.try_get("evidence_id")?,
        title: row.try_get("title")?,
        status: row.try_get("status")?,
        link_type: row.try_get("link_type")?,
        created_at: row.try_get("created_at")?,
    })
}

fn event_from_sqlite_row(row: SqliteRow) -> Result<SupplierProductSecurityEvent, sqlx::Error> {
    Ok(SupplierProductSecurityEvent {
        id: row.try_get("id")?,
        record_id: row.try_get("record_id")?,
        event_type: row.try_get("event_type")?,
        actor_id: row.try_get("actor_id")?,
        detail_json: parse_json_object(row.try_get("detail_json")?),
        created_at: row.try_get("created_at")?,
    })
}

fn event_from_pg_row(row: PgRow) -> Result<SupplierProductSecurityEvent, sqlx::Error> {
    Ok(SupplierProductSecurityEvent {
        id: row.try_get("id")?,
        record_id: row.try_get("record_id")?,
        event_type: row.try_get("event_type")?,
        actor_id: row.try_get("actor_id")?,
        detail_json: parse_json_object(row.try_get("detail_json")?),
        created_at: row.try_get("created_at")?,
    })
}

fn history_from_sqlite_row(
    row: SqliteRow,
) -> Result<SupplierContractExitHistoryEntry, sqlx::Error> {
    Ok(SupplierContractExitHistoryEntry {
        id: row.try_get("id")?,
        record_id: row.try_get("record_id")?,
        supplier_id: row.try_get("supplier_id")?,
        version_number: row.try_get("version_number")?,
        changed_by: row.try_get("changed_by")?,
        changed_at: row.try_get("changed_at")?,
        change_reason: row.try_get("change_reason")?,
        previous_status: row.try_get("previous_status")?,
        new_status: row.try_get("new_status")?,
        summary: row.try_get("summary")?,
        evidence_ids: parse_i64_vec(row.try_get("evidence_ids_json")?),
    })
}

fn history_from_pg_row(row: PgRow) -> Result<SupplierContractExitHistoryEntry, sqlx::Error> {
    Ok(SupplierContractExitHistoryEntry {
        id: row.try_get("id")?,
        record_id: row.try_get("record_id")?,
        supplier_id: row.try_get("supplier_id")?,
        version_number: row.try_get("version_number")?,
        changed_by: row.try_get("changed_by")?,
        changed_at: row.try_get("changed_at")?,
        change_reason: row.try_get("change_reason")?,
        previous_status: row.try_get("previous_status")?,
        new_status: row.try_get("new_status")?,
        summary: row.try_get("summary")?,
        evidence_ids: parse_i64_vec(row.try_get("evidence_ids_json")?),
    })
}

fn supplier_product_security_summary(
    records: &[SupplierProductSecurityRecord],
) -> SupplierProductSecuritySummary {
    let today = Utc::now().date_naive().to_string();
    SupplierProductSecuritySummary {
        total_records: records.len() as i64,
        open_advisories: records
            .iter()
            .filter(|record| {
                !matches!(
                    record.review_status.as_str(),
                    "closed" | "mitigated" | "not_applicable"
                )
            })
            .count() as i64,
        critical_records: records
            .iter()
            .filter(|record| record.severity == "critical" || record.criticality == "critical")
            .count() as i64,
        overdue_reviews: records
            .iter()
            .filter(|record| {
                record
                    .due_date
                    .as_deref()
                    .is_some_and(|due| due < today.as_str())
            })
            .count() as i64,
        missing_evidence: records
            .iter()
            .filter(|record| record.evidence_ids.is_empty())
            .count() as i64,
        dora_relevant: records
            .iter()
            .filter(|record| record.dora_ict_third_party_relevance)
            .count() as i64,
        nis2_relevant: records
            .iter()
            .filter(|record| record.nis2_supply_chain_relevance)
            .count() as i64,
        data_processing_relevant: records
            .iter()
            .filter(|record| record.data_processing_relevance)
            .count() as i64,
        critical_services: records
            .iter()
            .filter(|record| record.critical_service_dependency)
            .count() as i64,
    }
}

fn supplier_product_security_filter_summary(filters: &SupplierProductSecurityFilters) -> Value {
    json!({
        "supplier_id": filters.supplier_id,
        "product": filters.product,
        "review_status": filters.review_status,
        "severity": filters.severity,
        "dora_relevant": filters.dora_relevant,
        "nis2_relevant": filters.nis2_relevant,
        "data_processing_relevant": filters.data_processing_relevant,
        "critical_services": filters.critical_services,
        "overdue": filters.overdue,
        "limit": filters.limit
    })
}

fn normalized_required_text(
    value: &str,
    max_len: usize,
    field: &str,
) -> SupplierProductSecurityResult<String> {
    let value = normalized_text(value, max_len, field)?;
    if value.is_empty() {
        return Err(SupplierProductSecurityError::invalid(format!(
            "{field} darf nicht leer sein."
        )));
    }
    Ok(value)
}

fn normalized_text(
    value: &str,
    max_len: usize,
    field: &str,
) -> SupplierProductSecurityResult<String> {
    let value = value.trim();
    if value.chars().any(char::is_control) {
        return Err(SupplierProductSecurityError::invalid(format!(
            "{field} enthaelt nicht erlaubte Steuerzeichen."
        )));
    }
    if value.chars().count() > max_len {
        return Err(SupplierProductSecurityError::invalid(format!(
            "{field} ist zu lang."
        )));
    }
    Ok(value.to_string())
}

fn normalized_reference(value: &str) -> SupplierProductSecurityResult<String> {
    let value = normalized_text(value, 2_000, "Referenz")?;
    let lower = value.to_ascii_lowercase();
    if lower.contains("://") && !(lower.starts_with("https://") || lower.starts_with("http://")) {
        return Err(SupplierProductSecurityError::invalid(
            "Referenz-URLs duerfen nur http oder https verwenden.",
        ));
    }
    if lower.starts_with("javascript:")
        || lower.starts_with("data:")
        || lower.starts_with("file:")
        || lower.starts_with("ftp:")
    {
        return Err(SupplierProductSecurityError::invalid(
            "Referenz enthaelt ein nicht erlaubtes URL-Schema.",
        ));
    }
    Ok(value)
}

fn normalized_optional_date(
    value: Option<&str>,
    field: &str,
) -> SupplierProductSecurityResult<Option<String>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    NaiveDate::parse_from_str(value, "%Y-%m-%d").map_err(|_| {
        SupplierProductSecurityError::invalid(format!("{field} muss im Format YYYY-MM-DD sein."))
    })?;
    Ok(Some(value.to_string()))
}

fn normalize_score(
    score: Option<f64>,
    min: f64,
    max: f64,
    field: &str,
) -> SupplierProductSecurityResult<Option<f64>> {
    if let Some(score) = score {
        if !score.is_finite() || score < min || score > max {
            return Err(SupplierProductSecurityError::invalid(format!(
                "{field}-Score ist ausserhalb des erlaubten Bereichs."
            )));
        }
        return Ok(Some((score * 1000.0).round() / 1000.0));
    }
    Ok(None)
}

fn normalize_positive_ids(ids: Vec<i64>, field: &str) -> SupplierProductSecurityResult<Vec<i64>> {
    let mut seen = BTreeSet::new();
    for id in ids {
        if id <= 0 {
            return Err(SupplierProductSecurityError::invalid(format!(
                "{field} muessen positiv sein."
            )));
        }
        seen.insert(id);
    }
    Ok(seen.into_iter().collect())
}

fn normalize_cve_ids(ids: Vec<String>) -> SupplierProductSecurityResult<Vec<String>> {
    let mut seen = BTreeSet::new();
    for id in ids {
        let id = id.trim().to_ascii_uppercase();
        if id.is_empty() {
            continue;
        }
        let valid = id
            .strip_prefix("CVE-")
            .and_then(|rest| rest.split_once('-'))
            .is_some_and(|(year, number)| {
                year.len() == 4
                    && year.chars().all(|ch| ch.is_ascii_digit())
                    && number.len() >= 4
                    && number.chars().all(|ch| ch.is_ascii_digit())
            });
        if !valid {
            return Err(SupplierProductSecurityError::invalid(
                "CVE-IDs muessen dem Format CVE-YYYY-NNNN entsprechen.",
            ));
        }
        seen.insert(id);
    }
    Ok(seen.into_iter().collect())
}

fn normalize_criticality(value: &str) -> SupplierProductSecurityResult<String> {
    normalize_enum(
        value,
        &["critical", "high", "medium", "low", "unknown"],
        "Kritikalitaet",
    )
}

fn normalize_product_security_status(value: &str) -> SupplierProductSecurityResult<String> {
    normalize_enum(
        value,
        &[
            "not_assessed",
            "in_review",
            "affected",
            "not_affected",
            "remediation_required",
            "mitigated",
            "closed",
        ],
        "Product-Security-Status",
    )
}

fn normalize_advisory_source_type(value: &str) -> SupplierProductSecurityResult<String> {
    normalize_enum(
        value,
        &[
            "manual", "vendor", "psirt", "csaf", "sbom", "vex", "internal",
        ],
        "Advisory-Quelle",
    )
}

fn normalize_severity(value: &str) -> SupplierProductSecurityResult<String> {
    normalize_enum(
        value,
        &["critical", "high", "medium", "low", "info", "unknown"],
        "Schweregrad",
    )
}

fn normalize_exploitation_status(value: &str) -> SupplierProductSecurityResult<String> {
    normalize_enum(
        value,
        &[
            "unknown",
            "not_known",
            "proof_of_concept",
            "active",
            "exploited",
            "not_applicable",
        ],
        "Exploitation-Status",
    )
}

fn normalize_review_status(value: &str) -> SupplierProductSecurityResult<String> {
    normalize_enum(
        value,
        &[
            "draft",
            "needs_review",
            "in_review",
            "accepted_risk",
            "remediation_required",
            "mitigated",
            "closed",
            "not_applicable",
        ],
        "Review-Status",
    )
}

fn normalize_contract_status(value: &str) -> SupplierProductSecurityResult<String> {
    normalize_enum(
        value,
        &[
            "not_recorded",
            "draft",
            "active",
            "under_review",
            "renewal_due",
            "expired",
            "terminated",
            "exit_required",
            "not_applicable",
        ],
        "Vertragsstatus",
    )
}

fn normalize_exit_plan_status(value: &str) -> SupplierProductSecurityResult<String> {
    normalize_enum(
        value,
        &[
            "not_recorded",
            "missing",
            "draft",
            "planned",
            "tested",
            "needs_update",
            "accepted",
            "not_applicable",
        ],
        "Exit-Plan-Status",
    )
}

fn normalize_enum(
    value: &str,
    allowed: &[&str],
    field: &str,
) -> SupplierProductSecurityResult<String> {
    let normalized = normalize_lossy(value);
    if allowed.contains(&normalized.as_str()) {
        Ok(normalized)
    } else {
        Err(SupplierProductSecurityError::invalid(format!(
            "{field} ist nicht unterstuetzt."
        )))
    }
}

fn normalize_lossy(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}

fn parse_string_vec(value: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(value).unwrap_or_default()
}

fn parse_i64_vec(value: &str) -> Vec<i64> {
    serde_json::from_str::<Vec<i64>>(value).unwrap_or_default()
}

fn parse_json_object(value: String) -> Value {
    serde_json::from_str(&value).unwrap_or_else(|_| json!({}))
}

fn json_ids(ids: &[String]) -> String {
    serde_json::to_string(ids).unwrap_or_else(|_| "[]".to_string())
}

fn json_ids_i64(ids: &[i64]) -> String {
    serde_json::to_string(ids).unwrap_or_else(|_| "[]".to_string())
}

fn criticality_label(value: &str) -> &'static str {
    match value {
        "critical" => "Kritisch",
        "high" => "Hoch",
        "medium" => "Mittel",
        "low" => "Niedrig",
        _ => "Nicht bewertet",
    }
}

fn product_security_status_label(value: &str) -> &'static str {
    match value {
        "in_review" => "In Pruefung",
        "affected" => "Betroffen",
        "not_affected" => "Nicht betroffen",
        "remediation_required" => "Massnahme erforderlich",
        "mitigated" => "Mitigiert",
        "closed" => "Geschlossen",
        _ => "Nicht bewertet",
    }
}

fn advisory_source_type_label(value: &str) -> &'static str {
    match value {
        "vendor" => "Hersteller",
        "psirt" => "PSIRT",
        "csaf" => "CSAF",
        "sbom" => "SBOM",
        "vex" => "VEX",
        "internal" => "Intern",
        _ => "Manuell",
    }
}

fn severity_label(value: &str) -> &'static str {
    match value {
        "critical" => "Kritisch",
        "high" => "Hoch",
        "medium" => "Mittel",
        "low" => "Niedrig",
        "info" => "Info",
        _ => "Nicht bewertet",
    }
}

fn exploitation_status_label(value: &str) -> &'static str {
    match value {
        "not_known" => "Nicht bekannt",
        "proof_of_concept" => "Proof of Concept",
        "active" => "Aktiv",
        "exploited" => "Ausgenutzt",
        "not_applicable" => "Nicht anwendbar",
        _ => "Unbekannt",
    }
}

fn review_status_label(value: &str) -> &'static str {
    match value {
        "needs_review" => "Review offen",
        "in_review" => "In Review",
        "accepted_risk" => "Risiko akzeptiert",
        "remediation_required" => "Massnahme erforderlich",
        "mitigated" => "Mitigiert",
        "closed" => "Geschlossen",
        "not_applicable" => "Nicht anwendbar",
        _ => "Entwurf",
    }
}

fn contract_status_label(value: &str) -> &'static str {
    match value {
        "draft" => "Entwurf",
        "active" => "Aktiv",
        "under_review" => "In Vertragspruefung",
        "renewal_due" => "Verlaengerung faellig",
        "expired" => "Abgelaufen",
        "terminated" => "Beendet",
        "exit_required" => "Exit erforderlich",
        "not_applicable" => "Nicht anwendbar",
        _ => "Nicht erfasst",
    }
}

fn exit_plan_status_label(value: &str) -> &'static str {
    match value {
        "missing" => "Fehlt",
        "draft" => "Entwurf",
        "planned" => "Geplant",
        "tested" => "Getestet",
        "needs_update" => "Aktualisierung erforderlich",
        "accepted" => "Akzeptiert",
        "not_applicable" => "Nicht anwendbar",
        _ => "Nicht erfasst",
    }
}
