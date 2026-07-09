use anyhow::{bail, Context};
use chrono::{NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Postgres, Row, Sqlite, Transaction,
};
use std::{error::Error, fmt};

use crate::cve_store::normalize_database_url;

#[derive(Clone)]
pub enum SupplierStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Serialize)]
pub struct SupplierRiskOverview {
    pub tenant_id: i64,
    pub summary: SupplierRiskSummary,
    pub suppliers: Vec<SupplierRiskSummaryRow>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SupplierRiskSummary {
    pub total_suppliers: i64,
    pub critical_suppliers: i64,
    pub high_risk_suppliers: i64,
    pub overdue_reviews: i64,
    pub missing_evidence: i64,
    pub open_risks: i64,
    pub open_vulnerabilities: i64,
    pub average_score: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SupplierRiskDetail {
    pub supplier: SupplierRiskSummaryRow,
    pub reviews: Vec<SupplierReviewEvent>,
    pub subprocessors: Vec<SupplierSubprocessor>,
    pub evidence_links: Vec<SupplierEvidenceLink>,
    pub control_links: Vec<SupplierControlLink>,
    pub risk_links: Vec<SupplierRiskLink>,
    pub audit_events: Vec<SupplierAuditEvent>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SupplierRiskSummaryRow {
    pub id: i64,
    pub tenant_id: i64,
    pub name: String,
    pub service_description: String,
    pub criticality: String,
    pub criticality_label: String,
    pub owner_id: Option<i64>,
    pub owner_display: Option<String>,
    pub contact_email: String,
    pub contract_reference: String,
    pub data_categories: String,
    pub regions: String,
    pub exit_dependency: String,
    pub regulatory_scope: String,
    pub regulatory_flags: Vec<String>,
    pub review_status: String,
    pub review_status_label: String,
    pub approval_status: String,
    pub approval_status_label: String,
    pub risk_assessment: String,
    pub service_product_reference: String,
    pub data_access: bool,
    pub system_access: bool,
    pub ot_access: bool,
    pub exit_relevant: bool,
    pub responsible_role: String,
    pub responsible_user_id: Option<i64>,
    pub last_reviewed_at: Option<String>,
    pub next_review_due_at: Option<String>,
    pub evidence_required: bool,
    pub notes: String,
    pub contract_start_at: Option<String>,
    pub contract_end_at: Option<String>,
    pub contract_notice_period: String,
    pub contract_auto_renews: bool,
    pub next_contract_review_at: Option<String>,
    pub contract_evidence_id: Option<i64>,
    pub exit_test_required: bool,
    pub exit_test_status: String,
    pub exit_test_status_label: String,
    pub last_exit_test_at: Option<String>,
    pub next_exit_test_at: Option<String>,
    pub exit_test_result: String,
    pub exit_test_open_actions: String,
    pub exit_test_evidence_id: Option<i64>,
    pub component_count: i64,
    pub product_count: i64,
    pub open_vulnerability_count: i64,
    pub critical_vulnerability_count: i64,
    pub open_risk_count: i64,
    pub evidence_count: i64,
    pub approved_evidence_count: i64,
    pub linked_evidence_count: i64,
    pub linked_control_count: i64,
    pub linked_risk_count: i64,
    pub subprocessor_count: i64,
    pub score: i64,
    pub score_label: String,
    pub issues: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SupplierReviewEvent {
    pub id: i64,
    pub supplier_id: i64,
    pub old_status: String,
    pub old_status_label: String,
    pub new_status: String,
    pub new_status_label: String,
    pub actor_id: Option<i64>,
    pub reason: String,
    pub risk_level: String,
    pub evidence_refs: String,
    pub control_refs: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SupplierSubprocessor {
    pub id: i64,
    pub supplier_id: i64,
    pub name: String,
    pub purpose: String,
    pub country_region: String,
    pub data_relationship: String,
    pub criticality: String,
    pub criticality_label: String,
    pub approval_status: String,
    pub approval_status_label: String,
    pub review_due_at: Option<String>,
    pub created_by_id: Option<i64>,
    pub updated_by_id: Option<i64>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SupplierEvidenceLink {
    pub id: i64,
    pub evidence_id: i64,
    pub title: String,
    pub status: String,
    pub linked_requirement: String,
    pub link_type: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SupplierControlLink {
    pub id: i64,
    pub control_id: i64,
    pub code: String,
    pub title: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SupplierRiskLink {
    pub id: i64,
    pub risk_id: i64,
    pub title: String,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SupplierAuditEvent {
    pub id: i64,
    pub supplier_id: i64,
    pub event_type: String,
    pub actor_id: Option<i64>,
    pub detail: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SupplierCreateRequest {
    pub name: String,
    #[serde(default)]
    pub service_description: String,
    #[serde(default)]
    pub criticality: Option<String>,
    #[serde(default)]
    pub owner_id: Option<i64>,
    #[serde(default)]
    pub contact_email: String,
    #[serde(default)]
    pub contract_reference: String,
    #[serde(default)]
    pub data_categories: String,
    #[serde(default)]
    pub regions: String,
    #[serde(default)]
    pub exit_dependency: String,
    #[serde(default)]
    pub regulatory_scope: String,
    #[serde(default)]
    pub review_status: Option<String>,
    #[serde(default)]
    pub next_review_due_at: Option<String>,
    #[serde(default)]
    pub evidence_required: Option<bool>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub risk_assessment: Option<String>,
    #[serde(default)]
    pub service_product_reference: String,
    #[serde(default)]
    pub data_access: Option<bool>,
    #[serde(default)]
    pub system_access: Option<bool>,
    #[serde(default)]
    pub ot_access: Option<bool>,
    #[serde(default)]
    pub exit_relevant: Option<bool>,
    #[serde(default)]
    pub responsible_role: String,
    #[serde(default)]
    pub responsible_user_id: Option<i64>,
    #[serde(default)]
    pub contract_start_at: Option<String>,
    #[serde(default)]
    pub contract_end_at: Option<String>,
    #[serde(default)]
    pub contract_notice_period: String,
    #[serde(default)]
    pub contract_auto_renews: Option<bool>,
    #[serde(default)]
    pub next_contract_review_at: Option<String>,
    #[serde(default)]
    pub contract_evidence_id: Option<i64>,
    #[serde(default)]
    pub exit_test_required: Option<bool>,
    #[serde(default)]
    pub exit_test_status: Option<String>,
    #[serde(default)]
    pub last_exit_test_at: Option<String>,
    #[serde(default)]
    pub next_exit_test_at: Option<String>,
    #[serde(default)]
    pub exit_test_result: String,
    #[serde(default)]
    pub exit_test_open_actions: String,
    #[serde(default)]
    pub exit_test_evidence_id: Option<i64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SupplierUpdateRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub service_description: Option<String>,
    #[serde(default)]
    pub criticality: Option<String>,
    #[serde(default)]
    pub owner_id: Option<i64>,
    #[serde(default)]
    pub contact_email: Option<String>,
    #[serde(default)]
    pub contract_reference: Option<String>,
    #[serde(default)]
    pub data_categories: Option<String>,
    #[serde(default)]
    pub regions: Option<String>,
    #[serde(default)]
    pub exit_dependency: Option<String>,
    #[serde(default)]
    pub regulatory_scope: Option<String>,
    #[serde(default)]
    pub next_review_due_at: Option<String>,
    #[serde(default)]
    pub evidence_required: Option<bool>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub risk_assessment: Option<String>,
    #[serde(default)]
    pub service_product_reference: Option<String>,
    #[serde(default)]
    pub data_access: Option<bool>,
    #[serde(default)]
    pub system_access: Option<bool>,
    #[serde(default)]
    pub ot_access: Option<bool>,
    #[serde(default)]
    pub exit_relevant: Option<bool>,
    #[serde(default)]
    pub responsible_role: Option<String>,
    #[serde(default)]
    pub responsible_user_id: Option<i64>,
    #[serde(default)]
    pub contract_start_at: Option<String>,
    #[serde(default)]
    pub contract_end_at: Option<String>,
    #[serde(default)]
    pub contract_notice_period: Option<String>,
    #[serde(default)]
    pub contract_auto_renews: Option<bool>,
    #[serde(default)]
    pub next_contract_review_at: Option<String>,
    #[serde(default)]
    pub contract_evidence_id: Option<i64>,
    #[serde(default)]
    pub exit_test_required: Option<bool>,
    #[serde(default)]
    pub exit_test_status: Option<String>,
    #[serde(default)]
    pub last_exit_test_at: Option<String>,
    #[serde(default)]
    pub next_exit_test_at: Option<String>,
    #[serde(default)]
    pub exit_test_result: Option<String>,
    #[serde(default)]
    pub exit_test_open_actions: Option<String>,
    #[serde(default)]
    pub exit_test_evidence_id: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SupplierReviewRequest {
    pub new_status: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub risk_level: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<i64>,
    #[serde(default)]
    pub control_refs: Vec<i64>,
    #[serde(default)]
    pub next_review_due_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SupplierSubprocessorRequest {
    pub name: String,
    #[serde(default)]
    pub purpose: String,
    #[serde(default)]
    pub country_region: String,
    #[serde(default)]
    pub data_relationship: String,
    #[serde(default)]
    pub criticality: Option<String>,
    #[serde(default)]
    pub approval_status: Option<String>,
    #[serde(default)]
    pub review_due_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SupplierEvidenceLinkRequest {
    pub evidence_id: i64,
    #[serde(default)]
    pub link_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SupplierEntityLinkRequest {
    pub entity_id: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SupplierMutationResponse {
    pub status: SupplierMutationStatus,
    pub detail: Option<SupplierRiskDetail>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupplierMutationStatus {
    Created,
    Updated,
    AlreadyExists,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupplierStoreErrorKind {
    NotFound,
    InvalidPayload,
    Database,
}

#[derive(Debug)]
pub struct SupplierStoreError {
    kind: SupplierStoreErrorKind,
    message: String,
}

pub type SupplierStoreResult<T> = Result<T, SupplierStoreError>;

impl SupplierStoreError {
    pub fn kind(&self) -> SupplierStoreErrorKind {
        self.kind
    }

    pub fn safe_message(&self) -> &str {
        &self.message
    }

    fn not_found() -> Self {
        Self {
            kind: SupplierStoreErrorKind::NotFound,
            message: "Supplier-Objekt wurde fuer diesen Tenant nicht gefunden.".to_string(),
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self {
            kind: SupplierStoreErrorKind::InvalidPayload,
            message: message.into(),
        }
    }

    fn database() -> Self {
        Self {
            kind: SupplierStoreErrorKind::Database,
            message: "Supplier-Daten konnten nicht verarbeitet werden.".to_string(),
        }
    }
}

impl fmt::Display for SupplierStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for SupplierStoreError {}

impl From<sqlx::Error> for SupplierStoreError {
    fn from(_: sqlx::Error) -> Self {
        Self::database()
    }
}

impl From<serde_json::Error> for SupplierStoreError {
    fn from(_: serde_json::Error) -> Self {
        Self::database()
    }
}

impl SupplierStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Supplier-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Supplier-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-Supplier-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn overview(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<SupplierRiskOverview> {
        let suppliers = match self {
            Self::Postgres(pool) => list_suppliers_postgres(pool, tenant_id, limit).await?,
            Self::Sqlite(pool) => list_suppliers_sqlite(pool, tenant_id, limit).await?,
        };
        let summary = supplier_summary(&suppliers);
        Ok(SupplierRiskOverview {
            tenant_id,
            summary,
            suppliers,
        })
    }

    pub async fn detail(
        &self,
        tenant_id: i64,
        supplier_id: i64,
    ) -> anyhow::Result<Option<SupplierRiskDetail>> {
        match self {
            Self::Postgres(pool) => supplier_detail_postgres(pool, tenant_id, supplier_id).await,
            Self::Sqlite(pool) => supplier_detail_sqlite(pool, tenant_id, supplier_id).await,
        }
    }

    pub async fn create_supplier(
        &self,
        tenant_id: i64,
        actor_id: i64,
        payload: SupplierCreateRequest,
    ) -> SupplierStoreResult<SupplierRiskDetail> {
        match self {
            Self::Postgres(pool) => {
                create_supplier_postgres(pool, tenant_id, actor_id, payload).await
            }
            Self::Sqlite(pool) => create_supplier_sqlite(pool, tenant_id, actor_id, payload).await,
        }
    }

    pub async fn update_supplier(
        &self,
        tenant_id: i64,
        supplier_id: i64,
        actor_id: i64,
        payload: SupplierUpdateRequest,
    ) -> SupplierStoreResult<SupplierRiskDetail> {
        match self {
            Self::Postgres(pool) => {
                update_supplier_postgres(pool, tenant_id, supplier_id, actor_id, payload).await
            }
            Self::Sqlite(pool) => {
                update_supplier_sqlite(pool, tenant_id, supplier_id, actor_id, payload).await
            }
        }
    }

    pub async fn add_review(
        &self,
        tenant_id: i64,
        supplier_id: i64,
        actor_id: i64,
        payload: SupplierReviewRequest,
    ) -> SupplierStoreResult<SupplierRiskDetail> {
        match self {
            Self::Postgres(pool) => {
                add_review_postgres(pool, tenant_id, supplier_id, actor_id, payload).await
            }
            Self::Sqlite(pool) => {
                add_review_sqlite(pool, tenant_id, supplier_id, actor_id, payload).await
            }
        }
    }

    pub async fn list_reviews(
        &self,
        tenant_id: i64,
        supplier_id: i64,
    ) -> SupplierStoreResult<Vec<SupplierReviewEvent>> {
        match self {
            Self::Postgres(pool) => {
                ensure_supplier_postgres(pool, tenant_id, supplier_id).await?;
                list_reviews_postgres(pool, tenant_id, supplier_id).await
            }
            Self::Sqlite(pool) => {
                ensure_supplier_sqlite(pool, tenant_id, supplier_id).await?;
                list_reviews_sqlite(pool, tenant_id, supplier_id).await
            }
        }
    }

    pub async fn add_subprocessor(
        &self,
        tenant_id: i64,
        supplier_id: i64,
        actor_id: i64,
        payload: SupplierSubprocessorRequest,
    ) -> SupplierStoreResult<SupplierSubprocessor> {
        match self {
            Self::Postgres(pool) => {
                add_subprocessor_postgres(pool, tenant_id, supplier_id, actor_id, payload).await
            }
            Self::Sqlite(pool) => {
                add_subprocessor_sqlite(pool, tenant_id, supplier_id, actor_id, payload).await
            }
        }
    }

    pub async fn update_subprocessor(
        &self,
        tenant_id: i64,
        supplier_id: i64,
        subprocessor_id: i64,
        actor_id: i64,
        payload: SupplierSubprocessorRequest,
    ) -> SupplierStoreResult<SupplierSubprocessor> {
        match self {
            Self::Postgres(pool) => {
                update_subprocessor_postgres(
                    pool,
                    tenant_id,
                    supplier_id,
                    subprocessor_id,
                    actor_id,
                    payload,
                )
                .await
            }
            Self::Sqlite(pool) => {
                update_subprocessor_sqlite(
                    pool,
                    tenant_id,
                    supplier_id,
                    subprocessor_id,
                    actor_id,
                    payload,
                )
                .await
            }
        }
    }

    pub async fn list_subprocessors(
        &self,
        tenant_id: i64,
        supplier_id: i64,
    ) -> SupplierStoreResult<Vec<SupplierSubprocessor>> {
        match self {
            Self::Postgres(pool) => {
                ensure_supplier_postgres(pool, tenant_id, supplier_id).await?;
                list_subprocessors_postgres(pool, tenant_id, supplier_id).await
            }
            Self::Sqlite(pool) => {
                ensure_supplier_sqlite(pool, tenant_id, supplier_id).await?;
                list_subprocessors_sqlite(pool, tenant_id, supplier_id).await
            }
        }
    }

    pub async fn link_evidence(
        &self,
        tenant_id: i64,
        supplier_id: i64,
        actor_id: i64,
        payload: SupplierEvidenceLinkRequest,
    ) -> SupplierStoreResult<SupplierMutationStatus> {
        match self {
            Self::Postgres(pool) => {
                link_evidence_postgres(pool, tenant_id, supplier_id, actor_id, payload).await
            }
            Self::Sqlite(pool) => {
                link_evidence_sqlite(pool, tenant_id, supplier_id, actor_id, payload).await
            }
        }
    }

    pub async fn link_control(
        &self,
        tenant_id: i64,
        supplier_id: i64,
        actor_id: i64,
        payload: SupplierEntityLinkRequest,
    ) -> SupplierStoreResult<SupplierMutationStatus> {
        match self {
            Self::Postgres(pool) => {
                link_control_postgres(pool, tenant_id, supplier_id, actor_id, payload).await
            }
            Self::Sqlite(pool) => {
                link_control_sqlite(pool, tenant_id, supplier_id, actor_id, payload).await
            }
        }
    }

    pub async fn link_risk(
        &self,
        tenant_id: i64,
        supplier_id: i64,
        actor_id: i64,
        payload: SupplierEntityLinkRequest,
    ) -> SupplierStoreResult<SupplierMutationStatus> {
        match self {
            Self::Postgres(pool) => {
                link_risk_postgres(pool, tenant_id, supplier_id, actor_id, payload).await
            }
            Self::Sqlite(pool) => {
                link_risk_sqlite(pool, tenant_id, supplier_id, actor_id, payload).await
            }
        }
    }

    pub async fn list_evidence_links(
        &self,
        tenant_id: i64,
        supplier_id: i64,
    ) -> SupplierStoreResult<Vec<SupplierEvidenceLink>> {
        match self {
            Self::Postgres(pool) => {
                ensure_supplier_postgres(pool, tenant_id, supplier_id).await?;
                list_evidence_links_postgres(pool, tenant_id, supplier_id).await
            }
            Self::Sqlite(pool) => {
                ensure_supplier_sqlite(pool, tenant_id, supplier_id).await?;
                list_evidence_links_sqlite(pool, tenant_id, supplier_id).await
            }
        }
    }
}

async fn list_suppliers_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<SupplierRiskSummaryRow>> {
    let query = format!(
        "{POSTGRES_SUPPLIER_SELECT}
WHERE supplier.tenant_id = $1
ORDER BY
    CASE UPPER(supplier.criticality)
        WHEN 'CRITICAL' THEN 5
        WHEN 'VERY_HIGH' THEN 5
        WHEN 'HIGH' THEN 4
        WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 2
        ELSE 1
    END DESC,
    supplier.name ASC
LIMIT $2"
    );
    let rows = sqlx::query(&query)
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Supplier-Register konnte nicht gelesen werden")?;
    rows.into_iter()
        .map(supplier_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn supplier_detail_postgres(
    pool: &PgPool,
    tenant_id: i64,
    supplier_id: i64,
) -> anyhow::Result<Option<SupplierRiskDetail>> {
    let query =
        format!("{POSTGRES_SUPPLIER_SELECT}\nWHERE supplier.tenant_id = $1 AND supplier.id = $2");
    let row = sqlx::query(&query)
        .bind(tenant_id)
        .bind(supplier_id)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-Supplier-Detail konnte nicht gelesen werden")?;
    let Some(row) = row else {
        return Ok(None);
    };
    let supplier = supplier_from_pg_row(row)?;
    Ok(Some(SupplierRiskDetail {
        reviews: list_reviews_postgres(pool, tenant_id, supplier_id).await?,
        subprocessors: list_subprocessors_postgres(pool, tenant_id, supplier_id).await?,
        evidence_links: list_evidence_links_postgres(pool, tenant_id, supplier_id).await?,
        control_links: list_control_links_postgres(pool, tenant_id, supplier_id).await?,
        risk_links: list_risk_links_postgres(pool, tenant_id, supplier_id).await?,
        audit_events: list_audit_events_postgres(pool, tenant_id, supplier_id).await?,
        supplier,
    }))
}

async fn list_suppliers_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<SupplierRiskSummaryRow>> {
    let query = format!(
        "{SQLITE_SUPPLIER_SELECT}
WHERE supplier.tenant_id = ?
ORDER BY
    CASE UPPER(supplier.criticality)
        WHEN 'CRITICAL' THEN 5
        WHEN 'VERY_HIGH' THEN 5
        WHEN 'HIGH' THEN 4
        WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 2
        ELSE 1
    END DESC,
    supplier.name ASC
LIMIT ?"
    );
    let rows = sqlx::query(&query)
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("SQLite-Supplier-Register konnte nicht gelesen werden")?;
    rows.into_iter()
        .map(supplier_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn supplier_detail_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    supplier_id: i64,
) -> anyhow::Result<Option<SupplierRiskDetail>> {
    let query =
        format!("{SQLITE_SUPPLIER_SELECT}\nWHERE supplier.tenant_id = ? AND supplier.id = ?");
    let row = sqlx::query(&query)
        .bind(tenant_id)
        .bind(supplier_id)
        .fetch_optional(pool)
        .await
        .context("SQLite-Supplier-Detail konnte nicht gelesen werden")?;
    let Some(row) = row else {
        return Ok(None);
    };
    let supplier = supplier_from_sqlite_row(row)?;
    Ok(Some(SupplierRiskDetail {
        reviews: list_reviews_sqlite(pool, tenant_id, supplier_id).await?,
        subprocessors: list_subprocessors_sqlite(pool, tenant_id, supplier_id).await?,
        evidence_links: list_evidence_links_sqlite(pool, tenant_id, supplier_id).await?,
        control_links: list_control_links_sqlite(pool, tenant_id, supplier_id).await?,
        risk_links: list_risk_links_sqlite(pool, tenant_id, supplier_id).await?,
        audit_events: list_audit_events_sqlite(pool, tenant_id, supplier_id).await?,
        supplier,
    }))
}

const POSTGRES_SUPPLIER_SELECT: &str = r#"
SELECT
    supplier.id,
    supplier.tenant_id,
    supplier.name,
    supplier.service_description,
    supplier.criticality,
    supplier.owner_id,
    COALESCE(
        NULLIF(BTRIM(CONCAT(COALESCE(owner.first_name, ''), ' ', COALESCE(owner.last_name, ''))), ''),
        owner.username
    ) AS owner_display,
    supplier.contact_email,
    supplier.contract_reference,
    supplier.data_categories,
    supplier.regions,
    supplier.exit_dependency,
    supplier.regulatory_scope,
    supplier.review_status,
    supplier.approval_status,
    supplier.risk_assessment,
    supplier.service_product_reference,
    supplier.data_access,
    supplier.system_access,
    supplier.ot_access,
    supplier.exit_relevant,
    supplier.responsible_role,
    supplier.responsible_user_id,
    supplier.last_reviewed_at::text AS last_reviewed_at,
    supplier.next_review_due_at::text AS next_review_due_at,
    supplier.evidence_required,
    supplier.notes,
    supplier.contract_start_at,
    supplier.contract_end_at,
    supplier.contract_notice_period,
    supplier.contract_auto_renews,
    supplier.next_contract_review_at,
    supplier.contract_evidence_id,
    supplier.exit_test_required,
    supplier.exit_test_status,
    supplier.last_exit_test_at,
    supplier.next_exit_test_at,
    supplier.exit_test_result,
    supplier.exit_test_open_actions,
    supplier.exit_test_evidence_id,
    supplier.created_at::text AS created_at,
    supplier.updated_at::text AS updated_at,
    COALESCE(component_stats.component_count, 0) AS component_count,
    COALESCE(component_stats.product_count, 0) AS product_count,
    COALESCE(vulnerability_stats.open_vulnerability_count, 0) AS open_vulnerability_count,
    COALESCE(vulnerability_stats.critical_vulnerability_count, 0) AS critical_vulnerability_count,
    COALESCE(risk_stats.open_risk_count, 0) AS open_risk_count,
    COALESCE(evidence_stats.evidence_count, 0) AS evidence_count,
    COALESCE(evidence_stats.approved_evidence_count, 0) AS approved_evidence_count,
    COALESCE(linked_evidence_stats.linked_evidence_count, 0) AS linked_evidence_count,
    COALESCE(linked_control_stats.linked_control_count, 0) AS linked_control_count,
    COALESCE(linked_risk_stats.linked_risk_count, 0) AS linked_risk_count,
    COALESCE(subprocessor_stats.subprocessor_count, 0) AS subprocessor_count
FROM organizations_supplier supplier
LEFT JOIN accounts_user owner
    ON owner.id = supplier.owner_id
    AND (owner.tenant_id = supplier.tenant_id OR owner.tenant_id IS NULL)
LEFT JOIN (
    SELECT tenant_id, supplier_id, COUNT(*) AS component_count, COUNT(DISTINCT product_id) AS product_count
    FROM product_security_component
    WHERE supplier_id IS NOT NULL
    GROUP BY tenant_id, supplier_id
) component_stats
    ON component_stats.tenant_id = supplier.tenant_id AND component_stats.supplier_id = supplier.id
LEFT JOIN (
    SELECT component.tenant_id, component.supplier_id,
           COUNT(*) FILTER (WHERE UPPER(vulnerability.status) NOT IN ('FIXED', 'CLOSED', 'RESOLVED', 'ACCEPTED')) AS open_vulnerability_count,
           COUNT(*) FILTER (
               WHERE UPPER(vulnerability.status) NOT IN ('FIXED', 'CLOSED', 'RESOLVED', 'ACCEPTED')
                 AND UPPER(vulnerability.severity) = 'CRITICAL'
           ) AS critical_vulnerability_count
    FROM product_security_component component
    JOIN product_security_vulnerability vulnerability
        ON vulnerability.component_id = component.id
        AND vulnerability.tenant_id = component.tenant_id
    WHERE component.supplier_id IS NOT NULL
    GROUP BY component.tenant_id, component.supplier_id
) vulnerability_stats
    ON vulnerability_stats.tenant_id = supplier.tenant_id AND vulnerability_stats.supplier_id = supplier.id
LEFT JOIN (
    SELECT supplier_inner.id AS supplier_id,
           supplier_inner.tenant_id,
           COUNT(risk.id) AS open_risk_count
    FROM organizations_supplier supplier_inner
    LEFT JOIN risks_risk risk
        ON risk.tenant_id = supplier_inner.tenant_id
        AND UPPER(risk.status) NOT IN ('CLOSED', 'ACCEPTED')
        AND (
            LOWER(COALESCE(risk.title, '') || ' ' || COALESCE(risk.description, '') || ' ' || COALESCE(risk.treatment_plan, ''))
                LIKE '%' || LOWER(supplier_inner.name) || '%'
            OR (
                LOWER(COALESCE(risk.title, '') || ' ' || COALESCE(risk.description, '')) LIKE '%supplier%'
                AND UPPER(supplier_inner.criticality) IN ('CRITICAL', 'VERY_HIGH', 'HIGH')
            )
        )
    GROUP BY supplier_inner.id, supplier_inner.tenant_id
) risk_stats
    ON risk_stats.tenant_id = supplier.tenant_id AND risk_stats.supplier_id = supplier.id
LEFT JOIN (
    SELECT supplier_inner.id AS supplier_id,
           supplier_inner.tenant_id,
           COUNT(evidence.id) AS evidence_count,
           COUNT(evidence.id) FILTER (WHERE UPPER(evidence.status) = 'APPROVED') AS approved_evidence_count
    FROM organizations_supplier supplier_inner
    LEFT JOIN evidence_evidenceitem evidence
        ON evidence.tenant_id = supplier_inner.tenant_id
        AND (
            evidence.linked_requirement = 'SUPPLIER:' || supplier_inner.id::text
            OR LOWER(evidence.linked_requirement) = LOWER('SUPPLIER:' || supplier_inner.name)
            OR LOWER(evidence.title) LIKE '%' || LOWER(supplier_inner.name) || '%'
        )
    GROUP BY supplier_inner.id, supplier_inner.tenant_id
) evidence_stats
    ON evidence_stats.tenant_id = supplier.tenant_id AND evidence_stats.supplier_id = supplier.id
LEFT JOIN (
    SELECT tenant_id, supplier_id, COUNT(*) AS linked_evidence_count
    FROM supplier_evidence_link
    GROUP BY tenant_id, supplier_id
) linked_evidence_stats
    ON linked_evidence_stats.tenant_id = supplier.tenant_id AND linked_evidence_stats.supplier_id = supplier.id
LEFT JOIN (
    SELECT tenant_id, supplier_id, COUNT(*) AS linked_control_count
    FROM supplier_control_link
    GROUP BY tenant_id, supplier_id
) linked_control_stats
    ON linked_control_stats.tenant_id = supplier.tenant_id AND linked_control_stats.supplier_id = supplier.id
LEFT JOIN (
    SELECT tenant_id, supplier_id, COUNT(*) AS linked_risk_count
    FROM supplier_risk_link
    GROUP BY tenant_id, supplier_id
) linked_risk_stats
    ON linked_risk_stats.tenant_id = supplier.tenant_id AND linked_risk_stats.supplier_id = supplier.id
LEFT JOIN (
    SELECT tenant_id, supplier_id, COUNT(*) AS subprocessor_count
    FROM supplier_subprocessor
    GROUP BY tenant_id, supplier_id
) subprocessor_stats
    ON subprocessor_stats.tenant_id = supplier.tenant_id AND subprocessor_stats.supplier_id = supplier.id
"#;

const SQLITE_SUPPLIER_SELECT: &str = r#"
SELECT
    supplier.id,
    supplier.tenant_id,
    supplier.name,
    supplier.service_description,
    supplier.criticality,
    supplier.owner_id,
    COALESCE(
        NULLIF(TRIM(COALESCE(owner.first_name, '') || ' ' || COALESCE(owner.last_name, '')), ''),
        owner.username
    ) AS owner_display,
    supplier.contact_email,
    supplier.contract_reference,
    supplier.data_categories,
    supplier.regions,
    supplier.exit_dependency,
    supplier.regulatory_scope,
    supplier.review_status,
    supplier.approval_status,
    supplier.risk_assessment,
    supplier.service_product_reference,
    supplier.data_access,
    supplier.system_access,
    supplier.ot_access,
    supplier.exit_relevant,
    supplier.responsible_role,
    supplier.responsible_user_id,
    CAST(supplier.last_reviewed_at AS TEXT) AS last_reviewed_at,
    CAST(supplier.next_review_due_at AS TEXT) AS next_review_due_at,
    supplier.evidence_required,
    supplier.notes,
    supplier.contract_start_at,
    supplier.contract_end_at,
    supplier.contract_notice_period,
    supplier.contract_auto_renews,
    supplier.next_contract_review_at,
    supplier.contract_evidence_id,
    supplier.exit_test_required,
    supplier.exit_test_status,
    supplier.last_exit_test_at,
    supplier.next_exit_test_at,
    supplier.exit_test_result,
    supplier.exit_test_open_actions,
    supplier.exit_test_evidence_id,
    CAST(supplier.created_at AS TEXT) AS created_at,
    CAST(supplier.updated_at AS TEXT) AS updated_at,
    COALESCE(component_stats.component_count, 0) AS component_count,
    COALESCE(component_stats.product_count, 0) AS product_count,
    COALESCE(vulnerability_stats.open_vulnerability_count, 0) AS open_vulnerability_count,
    COALESCE(vulnerability_stats.critical_vulnerability_count, 0) AS critical_vulnerability_count,
    COALESCE(risk_stats.open_risk_count, 0) AS open_risk_count,
    COALESCE(evidence_stats.evidence_count, 0) AS evidence_count,
    COALESCE(evidence_stats.approved_evidence_count, 0) AS approved_evidence_count,
    COALESCE(linked_evidence_stats.linked_evidence_count, 0) AS linked_evidence_count,
    COALESCE(linked_control_stats.linked_control_count, 0) AS linked_control_count,
    COALESCE(linked_risk_stats.linked_risk_count, 0) AS linked_risk_count,
    COALESCE(subprocessor_stats.subprocessor_count, 0) AS subprocessor_count
FROM organizations_supplier supplier
LEFT JOIN accounts_user owner
    ON owner.id = supplier.owner_id
    AND (owner.tenant_id = supplier.tenant_id OR owner.tenant_id IS NULL)
LEFT JOIN (
    SELECT tenant_id, supplier_id, COUNT(*) AS component_count, COUNT(DISTINCT product_id) AS product_count
    FROM product_security_component
    WHERE supplier_id IS NOT NULL
    GROUP BY tenant_id, supplier_id
) component_stats
    ON component_stats.tenant_id = supplier.tenant_id AND component_stats.supplier_id = supplier.id
LEFT JOIN (
    SELECT component.tenant_id, component.supplier_id,
           SUM(CASE WHEN UPPER(vulnerability.status) NOT IN ('FIXED', 'CLOSED', 'RESOLVED', 'ACCEPTED') THEN 1 ELSE 0 END) AS open_vulnerability_count,
           SUM(CASE
               WHEN UPPER(vulnerability.status) NOT IN ('FIXED', 'CLOSED', 'RESOLVED', 'ACCEPTED')
                AND UPPER(vulnerability.severity) = 'CRITICAL'
               THEN 1 ELSE 0 END
           ) AS critical_vulnerability_count
    FROM product_security_component component
    JOIN product_security_vulnerability vulnerability
        ON vulnerability.component_id = component.id
        AND vulnerability.tenant_id = component.tenant_id
    WHERE component.supplier_id IS NOT NULL
    GROUP BY component.tenant_id, component.supplier_id
) vulnerability_stats
    ON vulnerability_stats.tenant_id = supplier.tenant_id AND vulnerability_stats.supplier_id = supplier.id
LEFT JOIN (
    SELECT supplier_inner.id AS supplier_id,
           supplier_inner.tenant_id,
           COUNT(risk.id) AS open_risk_count
    FROM organizations_supplier supplier_inner
    LEFT JOIN risks_risk risk
        ON risk.tenant_id = supplier_inner.tenant_id
        AND UPPER(risk.status) NOT IN ('CLOSED', 'ACCEPTED')
        AND (
            LOWER(COALESCE(risk.title, '') || ' ' || COALESCE(risk.description, '') || ' ' || COALESCE(risk.treatment_plan, ''))
                LIKE '%' || LOWER(supplier_inner.name) || '%'
            OR (
                LOWER(COALESCE(risk.title, '') || ' ' || COALESCE(risk.description, '')) LIKE '%supplier%'
                AND UPPER(supplier_inner.criticality) IN ('CRITICAL', 'VERY_HIGH', 'HIGH')
            )
        )
    GROUP BY supplier_inner.id, supplier_inner.tenant_id
) risk_stats
    ON risk_stats.tenant_id = supplier.tenant_id AND risk_stats.supplier_id = supplier.id
LEFT JOIN (
    SELECT supplier_inner.id AS supplier_id,
           supplier_inner.tenant_id,
           COUNT(evidence.id) AS evidence_count,
           SUM(CASE WHEN UPPER(evidence.status) = 'APPROVED' THEN 1 ELSE 0 END) AS approved_evidence_count
    FROM organizations_supplier supplier_inner
    LEFT JOIN evidence_evidenceitem evidence
        ON evidence.tenant_id = supplier_inner.tenant_id
        AND (
            evidence.linked_requirement = 'SUPPLIER:' || supplier_inner.id
            OR LOWER(evidence.linked_requirement) = LOWER('SUPPLIER:' || supplier_inner.name)
            OR LOWER(evidence.title) LIKE '%' || LOWER(supplier_inner.name) || '%'
        )
    GROUP BY supplier_inner.id, supplier_inner.tenant_id
) evidence_stats
    ON evidence_stats.tenant_id = supplier.tenant_id AND evidence_stats.supplier_id = supplier.id
LEFT JOIN (
    SELECT tenant_id, supplier_id, COUNT(*) AS linked_evidence_count
    FROM supplier_evidence_link
    GROUP BY tenant_id, supplier_id
) linked_evidence_stats
    ON linked_evidence_stats.tenant_id = supplier.tenant_id AND linked_evidence_stats.supplier_id = supplier.id
LEFT JOIN (
    SELECT tenant_id, supplier_id, COUNT(*) AS linked_control_count
    FROM supplier_control_link
    GROUP BY tenant_id, supplier_id
) linked_control_stats
    ON linked_control_stats.tenant_id = supplier.tenant_id AND linked_control_stats.supplier_id = supplier.id
LEFT JOIN (
    SELECT tenant_id, supplier_id, COUNT(*) AS linked_risk_count
    FROM supplier_risk_link
    GROUP BY tenant_id, supplier_id
) linked_risk_stats
    ON linked_risk_stats.tenant_id = supplier.tenant_id AND linked_risk_stats.supplier_id = supplier.id
LEFT JOIN (
    SELECT tenant_id, supplier_id, COUNT(*) AS subprocessor_count
    FROM supplier_subprocessor
    GROUP BY tenant_id, supplier_id
) subprocessor_stats
    ON subprocessor_stats.tenant_id = supplier.tenant_id AND subprocessor_stats.supplier_id = supplier.id
"#;

fn supplier_from_pg_row(row: PgRow) -> Result<SupplierRiskSummaryRow, sqlx::Error> {
    let raw = RawSupplierRow {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        name: row.try_get("name")?,
        service_description: row.try_get("service_description")?,
        criticality: row.try_get("criticality")?,
        owner_id: row.try_get("owner_id")?,
        owner_display: row.try_get("owner_display")?,
        contact_email: row.try_get("contact_email")?,
        contract_reference: row.try_get("contract_reference")?,
        data_categories: row.try_get("data_categories")?,
        regions: row.try_get("regions")?,
        exit_dependency: row.try_get("exit_dependency")?,
        regulatory_scope: row.try_get("regulatory_scope")?,
        review_status: row.try_get("review_status")?,
        approval_status: row.try_get("approval_status")?,
        risk_assessment: row.try_get("risk_assessment")?,
        service_product_reference: row.try_get("service_product_reference")?,
        data_access: row.try_get("data_access")?,
        system_access: row.try_get("system_access")?,
        ot_access: row.try_get("ot_access")?,
        exit_relevant: row.try_get("exit_relevant")?,
        responsible_role: row.try_get("responsible_role")?,
        responsible_user_id: row.try_get("responsible_user_id")?,
        last_reviewed_at: row.try_get("last_reviewed_at")?,
        next_review_due_at: row.try_get("next_review_due_at")?,
        evidence_required: row.try_get("evidence_required")?,
        notes: row.try_get("notes")?,
        contract_start_at: row.try_get("contract_start_at")?,
        contract_end_at: row.try_get("contract_end_at")?,
        contract_notice_period: row.try_get("contract_notice_period")?,
        contract_auto_renews: row.try_get("contract_auto_renews")?,
        next_contract_review_at: row.try_get("next_contract_review_at")?,
        contract_evidence_id: row.try_get("contract_evidence_id")?,
        exit_test_required: row.try_get("exit_test_required")?,
        exit_test_status: row.try_get("exit_test_status")?,
        last_exit_test_at: row.try_get("last_exit_test_at")?,
        next_exit_test_at: row.try_get("next_exit_test_at")?,
        exit_test_result: row.try_get("exit_test_result")?,
        exit_test_open_actions: row.try_get("exit_test_open_actions")?,
        exit_test_evidence_id: row.try_get("exit_test_evidence_id")?,
        component_count: row.try_get("component_count")?,
        product_count: row.try_get("product_count")?,
        open_vulnerability_count: row.try_get("open_vulnerability_count")?,
        critical_vulnerability_count: row.try_get("critical_vulnerability_count")?,
        open_risk_count: row.try_get("open_risk_count")?,
        evidence_count: row.try_get("evidence_count")?,
        approved_evidence_count: row.try_get("approved_evidence_count")?,
        linked_evidence_count: row.try_get("linked_evidence_count")?,
        linked_control_count: row.try_get("linked_control_count")?,
        linked_risk_count: row.try_get("linked_risk_count")?,
        subprocessor_count: row.try_get("subprocessor_count")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    };
    Ok(supplier_from_raw(raw))
}

fn supplier_from_sqlite_row(row: SqliteRow) -> Result<SupplierRiskSummaryRow, sqlx::Error> {
    let raw = RawSupplierRow {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        name: row.try_get("name")?,
        service_description: row.try_get("service_description")?,
        criticality: row.try_get("criticality")?,
        owner_id: row.try_get("owner_id")?,
        owner_display: row.try_get("owner_display")?,
        contact_email: row.try_get("contact_email")?,
        contract_reference: row.try_get("contract_reference")?,
        data_categories: row.try_get("data_categories")?,
        regions: row.try_get("regions")?,
        exit_dependency: row.try_get("exit_dependency")?,
        regulatory_scope: row.try_get("regulatory_scope")?,
        review_status: row.try_get("review_status")?,
        approval_status: row.try_get("approval_status")?,
        risk_assessment: row.try_get("risk_assessment")?,
        service_product_reference: row.try_get("service_product_reference")?,
        data_access: row.try_get("data_access")?,
        system_access: row.try_get("system_access")?,
        ot_access: row.try_get("ot_access")?,
        exit_relevant: row.try_get("exit_relevant")?,
        responsible_role: row.try_get("responsible_role")?,
        responsible_user_id: row.try_get("responsible_user_id")?,
        last_reviewed_at: row.try_get("last_reviewed_at")?,
        next_review_due_at: row.try_get("next_review_due_at")?,
        evidence_required: row.try_get("evidence_required")?,
        notes: row.try_get("notes")?,
        contract_start_at: row.try_get("contract_start_at")?,
        contract_end_at: row.try_get("contract_end_at")?,
        contract_notice_period: row.try_get("contract_notice_period")?,
        contract_auto_renews: row.try_get("contract_auto_renews")?,
        next_contract_review_at: row.try_get("next_contract_review_at")?,
        contract_evidence_id: row.try_get("contract_evidence_id")?,
        exit_test_required: row.try_get("exit_test_required")?,
        exit_test_status: row.try_get("exit_test_status")?,
        last_exit_test_at: row.try_get("last_exit_test_at")?,
        next_exit_test_at: row.try_get("next_exit_test_at")?,
        exit_test_result: row.try_get("exit_test_result")?,
        exit_test_open_actions: row.try_get("exit_test_open_actions")?,
        exit_test_evidence_id: row.try_get("exit_test_evidence_id")?,
        component_count: row.try_get("component_count")?,
        product_count: row.try_get("product_count")?,
        open_vulnerability_count: row.try_get("open_vulnerability_count")?,
        critical_vulnerability_count: row.try_get("critical_vulnerability_count")?,
        open_risk_count: row.try_get("open_risk_count")?,
        evidence_count: row.try_get("evidence_count")?,
        approved_evidence_count: row.try_get("approved_evidence_count")?,
        linked_evidence_count: row.try_get("linked_evidence_count")?,
        linked_control_count: row.try_get("linked_control_count")?,
        linked_risk_count: row.try_get("linked_risk_count")?,
        subprocessor_count: row.try_get("subprocessor_count")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    };
    Ok(supplier_from_raw(raw))
}

struct RawSupplierRow {
    id: i64,
    tenant_id: i64,
    name: String,
    service_description: String,
    criticality: String,
    owner_id: Option<i64>,
    owner_display: Option<String>,
    contact_email: String,
    contract_reference: String,
    data_categories: String,
    regions: String,
    exit_dependency: String,
    regulatory_scope: String,
    review_status: String,
    approval_status: String,
    risk_assessment: String,
    service_product_reference: String,
    data_access: bool,
    system_access: bool,
    ot_access: bool,
    exit_relevant: bool,
    responsible_role: String,
    responsible_user_id: Option<i64>,
    last_reviewed_at: Option<String>,
    next_review_due_at: Option<String>,
    evidence_required: bool,
    notes: String,
    contract_start_at: Option<String>,
    contract_end_at: Option<String>,
    contract_notice_period: String,
    contract_auto_renews: bool,
    next_contract_review_at: Option<String>,
    contract_evidence_id: Option<i64>,
    exit_test_required: bool,
    exit_test_status: String,
    last_exit_test_at: Option<String>,
    next_exit_test_at: Option<String>,
    exit_test_result: String,
    exit_test_open_actions: String,
    exit_test_evidence_id: Option<i64>,
    component_count: i64,
    product_count: i64,
    open_vulnerability_count: i64,
    critical_vulnerability_count: i64,
    open_risk_count: i64,
    evidence_count: i64,
    approved_evidence_count: i64,
    linked_evidence_count: i64,
    linked_control_count: i64,
    linked_risk_count: i64,
    subprocessor_count: i64,
    created_at: String,
    updated_at: String,
}

fn supplier_from_raw(raw: RawSupplierRow) -> SupplierRiskSummaryRow {
    let regulatory_flags = supplier_regulatory_flags(&raw);
    let issues = supplier_issues(&raw);
    let score = supplier_score(&raw, &issues);
    let review_status = normalize_workflow_status_lossy(&raw.review_status);
    let approval_status = normalize_workflow_status_lossy(&raw.approval_status);
    let exit_test_status = normalize_exit_status_lossy(&raw.exit_test_status);
    SupplierRiskSummaryRow {
        id: raw.id,
        tenant_id: raw.tenant_id,
        name: raw.name,
        service_description: raw.service_description,
        criticality_label: supplier_criticality_label(&raw.criticality).to_string(),
        criticality: normalize_upper(&raw.criticality),
        owner_id: raw.owner_id,
        owner_display: raw.owner_display,
        contact_email: raw.contact_email,
        contract_reference: raw.contract_reference,
        data_categories: raw.data_categories,
        regions: raw.regions,
        exit_dependency: raw.exit_dependency,
        regulatory_scope: raw.regulatory_scope,
        regulatory_flags,
        review_status_label: supplier_review_status_label(&review_status).to_string(),
        review_status,
        approval_status_label: supplier_review_status_label(&approval_status).to_string(),
        approval_status,
        risk_assessment: normalize_risk_level_lossy(&raw.risk_assessment),
        service_product_reference: raw.service_product_reference,
        data_access: raw.data_access,
        system_access: raw.system_access,
        ot_access: raw.ot_access,
        exit_relevant: raw.exit_relevant,
        responsible_role: raw.responsible_role,
        responsible_user_id: raw.responsible_user_id,
        last_reviewed_at: raw.last_reviewed_at,
        next_review_due_at: raw.next_review_due_at,
        evidence_required: raw.evidence_required,
        notes: raw.notes,
        contract_start_at: raw.contract_start_at,
        contract_end_at: raw.contract_end_at,
        contract_notice_period: raw.contract_notice_period,
        contract_auto_renews: raw.contract_auto_renews,
        next_contract_review_at: raw.next_contract_review_at,
        contract_evidence_id: raw.contract_evidence_id,
        exit_test_required: raw.exit_test_required,
        exit_test_status_label: supplier_exit_status_label(&exit_test_status).to_string(),
        exit_test_status,
        last_exit_test_at: raw.last_exit_test_at,
        next_exit_test_at: raw.next_exit_test_at,
        exit_test_result: raw.exit_test_result,
        exit_test_open_actions: raw.exit_test_open_actions,
        exit_test_evidence_id: raw.exit_test_evidence_id,
        component_count: raw.component_count,
        product_count: raw.product_count,
        open_vulnerability_count: raw.open_vulnerability_count,
        critical_vulnerability_count: raw.critical_vulnerability_count,
        open_risk_count: raw.open_risk_count,
        evidence_count: raw.evidence_count,
        approved_evidence_count: raw.approved_evidence_count,
        linked_evidence_count: raw.linked_evidence_count,
        linked_control_count: raw.linked_control_count,
        linked_risk_count: raw.linked_risk_count,
        subprocessor_count: raw.subprocessor_count,
        score,
        score_label: supplier_score_label(score).to_string(),
        issues,
        created_at: raw.created_at,
        updated_at: raw.updated_at,
    }
}

fn supplier_summary(suppliers: &[SupplierRiskSummaryRow]) -> SupplierRiskSummary {
    let total_suppliers = suppliers.len() as i64;
    let critical_suppliers = suppliers
        .iter()
        .filter(|supplier| is_high_criticality(&supplier.criticality))
        .count() as i64;
    let high_risk_suppliers = suppliers
        .iter()
        .filter(|supplier| supplier.score < 60 || supplier.critical_vulnerability_count > 0)
        .count() as i64;
    let overdue_reviews = suppliers
        .iter()
        .filter(|supplier| is_overdue(supplier.next_review_due_at.as_deref()))
        .count() as i64;
    let missing_evidence = suppliers
        .iter()
        .filter(|supplier| {
            supplier.evidence_required
                && supplier.approved_evidence_count == 0
                && supplier.linked_evidence_count == 0
        })
        .count() as i64;
    let open_risks = suppliers
        .iter()
        .map(|supplier| supplier.open_risk_count + supplier.linked_risk_count)
        .sum::<i64>();
    let open_vulnerabilities = suppliers
        .iter()
        .map(|supplier| supplier.open_vulnerability_count)
        .sum::<i64>();
    let average_score = if total_suppliers == 0 {
        0
    } else {
        suppliers.iter().map(|supplier| supplier.score).sum::<i64>() / total_suppliers
    };
    SupplierRiskSummary {
        total_suppliers,
        critical_suppliers,
        high_risk_suppliers,
        overdue_reviews,
        missing_evidence,
        open_risks,
        open_vulnerabilities,
        average_score,
    }
}

fn supplier_issues(raw: &RawSupplierRow) -> Vec<String> {
    let mut issues = Vec::new();
    let review_status = normalize_workflow_status_lossy(&raw.review_status);
    let exit_status = normalize_exit_status_lossy(&raw.exit_test_status);
    if raw.critical_vulnerability_count > 0 {
        issues.push("Kritische offene Produkt-/Komponenten-Schwachstellen vorhanden.".to_string());
    } else if raw.open_vulnerability_count > 0 {
        issues.push("Offene Produkt-/Komponenten-Schwachstellen vorhanden.".to_string());
    }
    if is_overdue(raw.next_review_due_at.as_deref()) || review_status == "expired" {
        issues.push("Supplier-Review ist ueberfaellig.".to_string());
    }
    if raw.evidence_required && raw.approved_evidence_count == 0 && raw.linked_evidence_count == 0 {
        issues.push("Freigegebene Supplier-Evidence fehlt.".to_string());
    }
    if is_high_criticality(&raw.criticality)
        && raw.open_risk_count == 0
        && raw.linked_risk_count == 0
    {
        issues.push("Supplier-Risiko ist fuer kritischen Supplier nicht dokumentiert.".to_string());
    }
    if !matches!(
        review_status.as_str(),
        "approved" | "approved_with_conditions"
    ) {
        issues.push("Supplier-Review ist nicht freigegeben.".to_string());
    }
    if raw.owner_id.is_none() && raw.responsible_user_id.is_none() {
        issues.push("Owner fehlt.".to_string());
    }
    if raw.contract_reference.trim().is_empty() && raw.contract_evidence_id.is_none() {
        issues.push("Vertrags-/Security-Annex-Referenz fehlt.".to_string());
    }
    if raw.contact_email.trim().is_empty() {
        issues.push("Security-Kontakt fehlt.".to_string());
    }
    if raw.regulatory_scope.trim().is_empty() {
        issues.push("Regulatorischer Scope fehlt.".to_string());
    }
    if is_high_criticality(&raw.criticality) && raw.data_categories.trim().is_empty() {
        issues.push("Datenarten fehlen fuer kritischen Supplier.".to_string());
    }
    if raw.evidence_required && raw.regions.trim().is_empty() {
        issues.push("Regionen/Leistungsorte fehlen.".to_string());
    }
    if (raw.exit_relevant || is_high_criticality(&raw.criticality))
        && raw.exit_dependency.trim().is_empty()
    {
        issues.push("Exit-Abhaengigkeit oder Exit-Strategie fehlt.".to_string());
    }
    if raw.exit_test_required && matches!(exit_status.as_str(), "required" | "failed" | "overdue") {
        issues.push("Exit-Test ist offen oder fehlgeschlagen.".to_string());
    }
    if raw.subprocessor_count > 0 && raw.linked_evidence_count == 0 {
        issues.push(
            "Unterauftragnehmer vorhanden, aber Supplier-Evidence ist nicht verknuepft."
                .to_string(),
        );
    }
    issues
}

fn supplier_score(raw: &RawSupplierRow, issues: &[String]) -> i64 {
    let mut score = 100;
    for issue in issues {
        score -= match issue.as_str() {
            "Kritische offene Produkt-/Komponenten-Schwachstellen vorhanden." => 22,
            "Supplier-Review ist ueberfaellig." => 20,
            "Freigegebene Supplier-Evidence fehlt." => 18,
            "Exit-Test ist offen oder fehlgeschlagen." => 15,
            "Supplier-Risiko ist fuer kritischen Supplier nicht dokumentiert." => 12,
            "Exit-Abhaengigkeit oder Exit-Strategie fehlt." => 10,
            "Vertrags-/Security-Annex-Referenz fehlt." => 10,
            "Supplier-Review ist nicht freigegeben." => 10,
            "Datenarten fehlen fuer kritischen Supplier." => 8,
            "Offene Produkt-/Komponenten-Schwachstellen vorhanden." => 8,
            "Unterauftragnehmer vorhanden, aber Supplier-Evidence ist nicht verknuepft." => 6,
            "Security-Kontakt fehlt." => 6,
            "Regionen/Leistungsorte fehlen." => 6,
            "Regulatorischer Scope fehlt." => 6,
            "Owner fehlt." => 6,
            _ => 4,
        };
    }
    if raw.component_count > 0 && (raw.approved_evidence_count > 0 || raw.linked_evidence_count > 0)
    {
        score += 5;
    }
    score.clamp(0, 100)
}

fn supplier_regulatory_flags(raw: &RawSupplierRow) -> Vec<String> {
    let mut flags = Vec::new();
    let scope = raw.regulatory_scope.to_ascii_uppercase();
    for flag in ["NIS2", "DORA", "CRA", "DSGVO", "TISAX", "AI_ACT"] {
        if scope.contains(flag) {
            flags.push(flag.replace('_', " "));
        }
    }
    if flags.iter().all(|flag| flag != "CRA") && raw.component_count > 0 {
        flags.push("CRA".to_string());
    }
    if flags.iter().all(|flag| flag != "DSGVO") && !raw.data_categories.trim().is_empty() {
        flags.push("DSGVO".to_string());
    }
    if flags.iter().all(|flag| flag != "NIS2") && is_high_criticality(&raw.criticality) {
        flags.push("NIS2".to_string());
    }
    if flags.iter().all(|flag| flag != "DORA")
        && (raw.system_access || raw.data_access)
        && raw.regulatory_scope.to_ascii_uppercase().contains("IKT")
    {
        flags.push("DORA".to_string());
    }
    flags.sort();
    flags.dedup();
    flags
}

async fn create_supplier_postgres(
    pool: &PgPool,
    tenant_id: i64,
    actor_id: i64,
    payload: SupplierCreateRequest,
) -> SupplierStoreResult<SupplierRiskDetail> {
    let normalized = validate_create_payload(payload)?;
    validate_user_ref_postgres(pool, tenant_id, normalized.owner_id).await?;
    validate_user_ref_postgres(pool, tenant_id, normalized.responsible_user_id).await?;
    validate_evidence_ref_postgres(pool, tenant_id, normalized.contract_evidence_id).await?;
    validate_evidence_ref_postgres(pool, tenant_id, normalized.exit_test_evidence_id).await?;
    let mut transaction = pool.begin().await?;
    let row = sqlx::query(
        r#"
        INSERT INTO organizations_supplier (
            tenant_id, name, service_description, criticality, owner_id,
            contact_email, contract_reference, data_categories, regions, exit_dependency,
            regulatory_scope, review_status, approval_status, next_review_due_at,
            evidence_required, notes, risk_assessment, service_product_reference,
            data_access, system_access, ot_access, exit_relevant, responsible_role,
            responsible_user_id, contract_start_at, contract_end_at, contract_notice_period,
            contract_auto_renews, next_contract_review_at, contract_evidence_id,
            exit_test_required, exit_test_status, last_exit_test_at, next_exit_test_at,
            exit_test_result, exit_test_open_actions, exit_test_evidence_id,
            created_at, updated_at
        )
        VALUES (
            $1, $2, $3, $4, $5,
            $6, $7, $8, $9, $10,
            $11, $12, $12, $13::date,
            $14, $15, $16, $17,
            $18, $19, $20, $21, $22,
            $23, $24, $25, $26,
            $27, $28, $29,
            $30, $31, $32, $33,
            $34, $35, $36,
            CURRENT_TIMESTAMP::text, CURRENT_TIMESTAMP::text
        )
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(&normalized.name)
    .bind(&normalized.service_description)
    .bind(&normalized.criticality)
    .bind(normalized.owner_id)
    .bind(&normalized.contact_email)
    .bind(&normalized.contract_reference)
    .bind(&normalized.data_categories)
    .bind(&normalized.regions)
    .bind(&normalized.exit_dependency)
    .bind(&normalized.regulatory_scope)
    .bind(&normalized.review_status)
    .bind(normalized.next_review_due_at.as_deref())
    .bind(normalized.evidence_required)
    .bind(&normalized.notes)
    .bind(&normalized.risk_assessment)
    .bind(&normalized.service_product_reference)
    .bind(normalized.data_access)
    .bind(normalized.system_access)
    .bind(normalized.ot_access)
    .bind(normalized.exit_relevant)
    .bind(&normalized.responsible_role)
    .bind(normalized.responsible_user_id)
    .bind(normalized.contract_start_at.as_deref())
    .bind(normalized.contract_end_at.as_deref())
    .bind(&normalized.contract_notice_period)
    .bind(normalized.contract_auto_renews)
    .bind(normalized.next_contract_review_at.as_deref())
    .bind(normalized.contract_evidence_id)
    .bind(normalized.exit_test_required)
    .bind(&normalized.exit_test_status)
    .bind(normalized.last_exit_test_at.as_deref())
    .bind(normalized.next_exit_test_at.as_deref())
    .bind(&normalized.exit_test_result)
    .bind(&normalized.exit_test_open_actions)
    .bind(normalized.exit_test_evidence_id)
    .fetch_one(&mut *transaction)
    .await?;
    let supplier_id: i64 = row.try_get("id")?;
    insert_audit_postgres_tx(
        &mut transaction,
        tenant_id,
        supplier_id,
        "supplier_created",
        Some(actor_id),
        "Supplier-Review-Datensatz erstellt.",
    )
    .await?;
    transaction.commit().await?;
    supplier_detail_postgres(pool, tenant_id, supplier_id)
        .await
        .map_err(|_| SupplierStoreError::database())?
        .ok_or_else(SupplierStoreError::not_found)
}

async fn create_supplier_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    actor_id: i64,
    payload: SupplierCreateRequest,
) -> SupplierStoreResult<SupplierRiskDetail> {
    let normalized = validate_create_payload(payload)?;
    validate_user_ref_sqlite(pool, tenant_id, normalized.owner_id).await?;
    validate_user_ref_sqlite(pool, tenant_id, normalized.responsible_user_id).await?;
    validate_evidence_ref_sqlite(pool, tenant_id, normalized.contract_evidence_id).await?;
    validate_evidence_ref_sqlite(pool, tenant_id, normalized.exit_test_evidence_id).await?;
    let mut transaction = pool.begin().await?;
    let row = sqlx::query(
        r#"
        INSERT INTO organizations_supplier (
            tenant_id, name, service_description, criticality, owner_id,
            contact_email, contract_reference, data_categories, regions, exit_dependency,
            regulatory_scope, review_status, approval_status, next_review_due_at,
            evidence_required, notes, risk_assessment, service_product_reference,
            data_access, system_access, ot_access, exit_relevant, responsible_role,
            responsible_user_id, contract_start_at, contract_end_at, contract_notice_period,
            contract_auto_renews, next_contract_review_at, contract_evidence_id,
            exit_test_required, exit_test_status, last_exit_test_at, next_exit_test_at,
            exit_test_result, exit_test_open_actions, exit_test_evidence_id,
            created_at, updated_at
        )
        VALUES (
            ?1, ?2, ?3, ?4, ?5,
            ?6, ?7, ?8, ?9, ?10,
            ?11, ?12, ?12, ?13,
            ?14, ?15, ?16, ?17,
            ?18, ?19, ?20, ?21, ?22,
            ?23, ?24, ?25, ?26,
            ?27, ?28, ?29,
            ?30, ?31, ?32, ?33,
            ?34, ?35, ?36,
            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
        )
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(&normalized.name)
    .bind(&normalized.service_description)
    .bind(&normalized.criticality)
    .bind(normalized.owner_id)
    .bind(&normalized.contact_email)
    .bind(&normalized.contract_reference)
    .bind(&normalized.data_categories)
    .bind(&normalized.regions)
    .bind(&normalized.exit_dependency)
    .bind(&normalized.regulatory_scope)
    .bind(&normalized.review_status)
    .bind(normalized.next_review_due_at.as_deref())
    .bind(normalized.evidence_required)
    .bind(&normalized.notes)
    .bind(&normalized.risk_assessment)
    .bind(&normalized.service_product_reference)
    .bind(normalized.data_access)
    .bind(normalized.system_access)
    .bind(normalized.ot_access)
    .bind(normalized.exit_relevant)
    .bind(&normalized.responsible_role)
    .bind(normalized.responsible_user_id)
    .bind(normalized.contract_start_at.as_deref())
    .bind(normalized.contract_end_at.as_deref())
    .bind(&normalized.contract_notice_period)
    .bind(normalized.contract_auto_renews)
    .bind(normalized.next_contract_review_at.as_deref())
    .bind(normalized.contract_evidence_id)
    .bind(normalized.exit_test_required)
    .bind(&normalized.exit_test_status)
    .bind(normalized.last_exit_test_at.as_deref())
    .bind(normalized.next_exit_test_at.as_deref())
    .bind(&normalized.exit_test_result)
    .bind(&normalized.exit_test_open_actions)
    .bind(normalized.exit_test_evidence_id)
    .fetch_one(&mut *transaction)
    .await?;
    let supplier_id: i64 = row.try_get("id")?;
    insert_audit_sqlite_tx(
        &mut transaction,
        tenant_id,
        supplier_id,
        "supplier_created",
        Some(actor_id),
        "Supplier-Review-Datensatz erstellt.",
    )
    .await?;
    transaction.commit().await?;
    supplier_detail_sqlite(pool, tenant_id, supplier_id)
        .await
        .map_err(|_| SupplierStoreError::database())?
        .ok_or_else(SupplierStoreError::not_found)
}

async fn update_supplier_postgres(
    pool: &PgPool,
    tenant_id: i64,
    supplier_id: i64,
    actor_id: i64,
    payload: SupplierUpdateRequest,
) -> SupplierStoreResult<SupplierRiskDetail> {
    ensure_supplier_postgres(pool, tenant_id, supplier_id).await?;
    let normalized = validate_update_payload(payload)?;
    validate_user_ref_postgres(pool, tenant_id, normalized.owner_id).await?;
    validate_user_ref_postgres(pool, tenant_id, normalized.responsible_user_id).await?;
    validate_evidence_ref_postgres(pool, tenant_id, normalized.contract_evidence_id).await?;
    validate_evidence_ref_postgres(pool, tenant_id, normalized.exit_test_evidence_id).await?;
    let mut transaction = pool.begin().await?;
    let result = sqlx::query(
        r#"
        UPDATE organizations_supplier
        SET name = COALESCE($3, name),
            service_description = COALESCE($4, service_description),
            criticality = COALESCE($5, criticality),
            owner_id = COALESCE($6, owner_id),
            contact_email = COALESCE($7, contact_email),
            contract_reference = COALESCE($8, contract_reference),
            data_categories = COALESCE($9, data_categories),
            regions = COALESCE($10, regions),
            exit_dependency = COALESCE($11, exit_dependency),
            regulatory_scope = COALESCE($12, regulatory_scope),
            next_review_due_at = COALESCE($13::date, next_review_due_at),
            evidence_required = COALESCE($14, evidence_required),
            notes = COALESCE($15, notes),
            risk_assessment = COALESCE($16, risk_assessment),
            service_product_reference = COALESCE($17, service_product_reference),
            data_access = COALESCE($18, data_access),
            system_access = COALESCE($19, system_access),
            ot_access = COALESCE($20, ot_access),
            exit_relevant = COALESCE($21, exit_relevant),
            responsible_role = COALESCE($22, responsible_role),
            responsible_user_id = COALESCE($23, responsible_user_id),
            contract_start_at = COALESCE($24, contract_start_at),
            contract_end_at = COALESCE($25, contract_end_at),
            contract_notice_period = COALESCE($26, contract_notice_period),
            contract_auto_renews = COALESCE($27, contract_auto_renews),
            next_contract_review_at = COALESCE($28, next_contract_review_at),
            contract_evidence_id = COALESCE($29, contract_evidence_id),
            exit_test_required = COALESCE($30, exit_test_required),
            exit_test_status = COALESCE($31, exit_test_status),
            last_exit_test_at = COALESCE($32, last_exit_test_at),
            next_exit_test_at = COALESCE($33, next_exit_test_at),
            exit_test_result = COALESCE($34, exit_test_result),
            exit_test_open_actions = COALESCE($35, exit_test_open_actions),
            exit_test_evidence_id = COALESCE($36, exit_test_evidence_id),
            updated_at = CURRENT_TIMESTAMP::text
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .bind(normalized.name.as_deref())
    .bind(normalized.service_description.as_deref())
    .bind(normalized.criticality.as_deref())
    .bind(normalized.owner_id)
    .bind(normalized.contact_email.as_deref())
    .bind(normalized.contract_reference.as_deref())
    .bind(normalized.data_categories.as_deref())
    .bind(normalized.regions.as_deref())
    .bind(normalized.exit_dependency.as_deref())
    .bind(normalized.regulatory_scope.as_deref())
    .bind(normalized.next_review_due_at.as_deref())
    .bind(normalized.evidence_required)
    .bind(normalized.notes.as_deref())
    .bind(normalized.risk_assessment.as_deref())
    .bind(normalized.service_product_reference.as_deref())
    .bind(normalized.data_access)
    .bind(normalized.system_access)
    .bind(normalized.ot_access)
    .bind(normalized.exit_relevant)
    .bind(normalized.responsible_role.as_deref())
    .bind(normalized.responsible_user_id)
    .bind(normalized.contract_start_at.as_deref())
    .bind(normalized.contract_end_at.as_deref())
    .bind(normalized.contract_notice_period.as_deref())
    .bind(normalized.contract_auto_renews)
    .bind(normalized.next_contract_review_at.as_deref())
    .bind(normalized.contract_evidence_id)
    .bind(normalized.exit_test_required)
    .bind(normalized.exit_test_status.as_deref())
    .bind(normalized.last_exit_test_at.as_deref())
    .bind(normalized.next_exit_test_at.as_deref())
    .bind(normalized.exit_test_result.as_deref())
    .bind(normalized.exit_test_open_actions.as_deref())
    .bind(normalized.exit_test_evidence_id)
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() != 1 {
        return Err(SupplierStoreError::not_found());
    }
    insert_audit_postgres_tx(
        &mut transaction,
        tenant_id,
        supplier_id,
        "supplier_updated",
        Some(actor_id),
        "Supplier-Review-Metadaten aktualisiert.",
    )
    .await?;
    transaction.commit().await?;
    supplier_detail_postgres(pool, tenant_id, supplier_id)
        .await
        .map_err(|_| SupplierStoreError::database())?
        .ok_or_else(SupplierStoreError::not_found)
}

async fn update_supplier_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    supplier_id: i64,
    actor_id: i64,
    payload: SupplierUpdateRequest,
) -> SupplierStoreResult<SupplierRiskDetail> {
    ensure_supplier_sqlite(pool, tenant_id, supplier_id).await?;
    let normalized = validate_update_payload(payload)?;
    validate_user_ref_sqlite(pool, tenant_id, normalized.owner_id).await?;
    validate_user_ref_sqlite(pool, tenant_id, normalized.responsible_user_id).await?;
    validate_evidence_ref_sqlite(pool, tenant_id, normalized.contract_evidence_id).await?;
    validate_evidence_ref_sqlite(pool, tenant_id, normalized.exit_test_evidence_id).await?;
    let mut transaction = pool.begin().await?;
    let result = sqlx::query(
        r#"
        UPDATE organizations_supplier
        SET name = COALESCE(?3, name),
            service_description = COALESCE(?4, service_description),
            criticality = COALESCE(?5, criticality),
            owner_id = COALESCE(?6, owner_id),
            contact_email = COALESCE(?7, contact_email),
            contract_reference = COALESCE(?8, contract_reference),
            data_categories = COALESCE(?9, data_categories),
            regions = COALESCE(?10, regions),
            exit_dependency = COALESCE(?11, exit_dependency),
            regulatory_scope = COALESCE(?12, regulatory_scope),
            next_review_due_at = COALESCE(?13, next_review_due_at),
            evidence_required = COALESCE(?14, evidence_required),
            notes = COALESCE(?15, notes),
            risk_assessment = COALESCE(?16, risk_assessment),
            service_product_reference = COALESCE(?17, service_product_reference),
            data_access = COALESCE(?18, data_access),
            system_access = COALESCE(?19, system_access),
            ot_access = COALESCE(?20, ot_access),
            exit_relevant = COALESCE(?21, exit_relevant),
            responsible_role = COALESCE(?22, responsible_role),
            responsible_user_id = COALESCE(?23, responsible_user_id),
            contract_start_at = COALESCE(?24, contract_start_at),
            contract_end_at = COALESCE(?25, contract_end_at),
            contract_notice_period = COALESCE(?26, contract_notice_period),
            contract_auto_renews = COALESCE(?27, contract_auto_renews),
            next_contract_review_at = COALESCE(?28, next_contract_review_at),
            contract_evidence_id = COALESCE(?29, contract_evidence_id),
            exit_test_required = COALESCE(?30, exit_test_required),
            exit_test_status = COALESCE(?31, exit_test_status),
            last_exit_test_at = COALESCE(?32, last_exit_test_at),
            next_exit_test_at = COALESCE(?33, next_exit_test_at),
            exit_test_result = COALESCE(?34, exit_test_result),
            exit_test_open_actions = COALESCE(?35, exit_test_open_actions),
            exit_test_evidence_id = COALESCE(?36, exit_test_evidence_id),
            updated_at = CURRENT_TIMESTAMP
        WHERE tenant_id = ?1 AND id = ?2
        "#,
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .bind(normalized.name.as_deref())
    .bind(normalized.service_description.as_deref())
    .bind(normalized.criticality.as_deref())
    .bind(normalized.owner_id)
    .bind(normalized.contact_email.as_deref())
    .bind(normalized.contract_reference.as_deref())
    .bind(normalized.data_categories.as_deref())
    .bind(normalized.regions.as_deref())
    .bind(normalized.exit_dependency.as_deref())
    .bind(normalized.regulatory_scope.as_deref())
    .bind(normalized.next_review_due_at.as_deref())
    .bind(normalized.evidence_required)
    .bind(normalized.notes.as_deref())
    .bind(normalized.risk_assessment.as_deref())
    .bind(normalized.service_product_reference.as_deref())
    .bind(normalized.data_access)
    .bind(normalized.system_access)
    .bind(normalized.ot_access)
    .bind(normalized.exit_relevant)
    .bind(normalized.responsible_role.as_deref())
    .bind(normalized.responsible_user_id)
    .bind(normalized.contract_start_at.as_deref())
    .bind(normalized.contract_end_at.as_deref())
    .bind(normalized.contract_notice_period.as_deref())
    .bind(normalized.contract_auto_renews)
    .bind(normalized.next_contract_review_at.as_deref())
    .bind(normalized.contract_evidence_id)
    .bind(normalized.exit_test_required)
    .bind(normalized.exit_test_status.as_deref())
    .bind(normalized.last_exit_test_at.as_deref())
    .bind(normalized.next_exit_test_at.as_deref())
    .bind(normalized.exit_test_result.as_deref())
    .bind(normalized.exit_test_open_actions.as_deref())
    .bind(normalized.exit_test_evidence_id)
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() != 1 {
        return Err(SupplierStoreError::not_found());
    }
    insert_audit_sqlite_tx(
        &mut transaction,
        tenant_id,
        supplier_id,
        "supplier_updated",
        Some(actor_id),
        "Supplier-Review-Metadaten aktualisiert.",
    )
    .await?;
    transaction.commit().await?;
    supplier_detail_sqlite(pool, tenant_id, supplier_id)
        .await
        .map_err(|_| SupplierStoreError::database())?
        .ok_or_else(SupplierStoreError::not_found)
}

async fn add_review_postgres(
    pool: &PgPool,
    tenant_id: i64,
    supplier_id: i64,
    actor_id: i64,
    payload: SupplierReviewRequest,
) -> SupplierStoreResult<SupplierRiskDetail> {
    let current_status = supplier_status_postgres(pool, tenant_id, supplier_id).await?;
    let normalized = validate_review_payload(payload)?;
    validate_id_refs_postgres(pool, tenant_id, "evidence", &normalized.evidence_refs).await?;
    validate_id_refs_postgres(pool, tenant_id, "control", &normalized.control_refs).await?;
    let evidence_refs_json = serde_json::to_string(&normalized.evidence_refs)?;
    let control_refs_json = serde_json::to_string(&normalized.control_refs)?;
    let mut transaction = pool.begin().await?;
    sqlx::query(
        r#"
        UPDATE organizations_supplier
        SET review_status = $3,
            approval_status = $3,
            risk_assessment = $4,
            last_reviewed_at = CURRENT_DATE,
            next_review_due_at = COALESCE($5::date, next_review_due_at),
            updated_at = CURRENT_TIMESTAMP::text
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .bind(&normalized.new_status)
    .bind(&normalized.risk_level)
    .bind(normalized.next_review_due_at.as_deref())
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r#"
        INSERT INTO supplier_review_event (
            tenant_id, supplier_id, old_status, new_status, actor_id, reason,
            risk_level, evidence_refs, control_refs, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_TIMESTAMP::text)
        "#,
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .bind(&current_status)
    .bind(&normalized.new_status)
    .bind(actor_id)
    .bind(&normalized.reason)
    .bind(&normalized.risk_level)
    .bind(&evidence_refs_json)
    .bind(&control_refs_json)
    .execute(&mut *transaction)
    .await?;
    insert_audit_postgres_tx(
        &mut transaction,
        tenant_id,
        supplier_id,
        "supplier_review_status_changed",
        Some(actor_id),
        &format!("Status {} -> {}.", current_status, normalized.new_status),
    )
    .await?;
    transaction.commit().await?;
    supplier_detail_postgres(pool, tenant_id, supplier_id)
        .await
        .map_err(|_| SupplierStoreError::database())?
        .ok_or_else(SupplierStoreError::not_found)
}

async fn add_review_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    supplier_id: i64,
    actor_id: i64,
    payload: SupplierReviewRequest,
) -> SupplierStoreResult<SupplierRiskDetail> {
    let current_status = supplier_status_sqlite(pool, tenant_id, supplier_id).await?;
    let normalized = validate_review_payload(payload)?;
    validate_id_refs_sqlite(pool, tenant_id, "evidence", &normalized.evidence_refs).await?;
    validate_id_refs_sqlite(pool, tenant_id, "control", &normalized.control_refs).await?;
    let evidence_refs_json = serde_json::to_string(&normalized.evidence_refs)?;
    let control_refs_json = serde_json::to_string(&normalized.control_refs)?;
    let mut transaction = pool.begin().await?;
    sqlx::query(
        r#"
        UPDATE organizations_supplier
        SET review_status = ?3,
            approval_status = ?3,
            risk_assessment = ?4,
            last_reviewed_at = date('now'),
            next_review_due_at = COALESCE(?5, next_review_due_at),
            updated_at = CURRENT_TIMESTAMP
        WHERE tenant_id = ?1 AND id = ?2
        "#,
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .bind(&normalized.new_status)
    .bind(&normalized.risk_level)
    .bind(normalized.next_review_due_at.as_deref())
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r#"
        INSERT INTO supplier_review_event (
            tenant_id, supplier_id, old_status, new_status, actor_id, reason,
            risk_level, evidence_refs, control_refs, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, CURRENT_TIMESTAMP)
        "#,
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .bind(&current_status)
    .bind(&normalized.new_status)
    .bind(actor_id)
    .bind(&normalized.reason)
    .bind(&normalized.risk_level)
    .bind(&evidence_refs_json)
    .bind(&control_refs_json)
    .execute(&mut *transaction)
    .await?;
    insert_audit_sqlite_tx(
        &mut transaction,
        tenant_id,
        supplier_id,
        "supplier_review_status_changed",
        Some(actor_id),
        &format!("Status {} -> {}.", current_status, normalized.new_status),
    )
    .await?;
    transaction.commit().await?;
    supplier_detail_sqlite(pool, tenant_id, supplier_id)
        .await
        .map_err(|_| SupplierStoreError::database())?
        .ok_or_else(SupplierStoreError::not_found)
}

async fn add_subprocessor_postgres(
    pool: &PgPool,
    tenant_id: i64,
    supplier_id: i64,
    actor_id: i64,
    payload: SupplierSubprocessorRequest,
) -> SupplierStoreResult<SupplierSubprocessor> {
    ensure_supplier_postgres(pool, tenant_id, supplier_id).await?;
    let normalized = validate_subprocessor_payload(payload)?;
    let mut transaction = pool.begin().await?;
    let row = sqlx::query(
        r#"
        INSERT INTO supplier_subprocessor (
            tenant_id, supplier_id, name, purpose, country_region, data_relationship,
            criticality, approval_status, review_due_at, created_by_id, updated_by_id,
            created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10, CURRENT_TIMESTAMP::text, CURRENT_TIMESTAMP::text)
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .bind(&normalized.name)
    .bind(&normalized.purpose)
    .bind(&normalized.country_region)
    .bind(&normalized.data_relationship)
    .bind(&normalized.criticality)
    .bind(&normalized.approval_status)
    .bind(normalized.review_due_at.as_deref())
    .bind(actor_id)
    .fetch_one(&mut *transaction)
    .await?;
    let subprocessor_id: i64 = row.try_get("id")?;
    insert_audit_postgres_tx(
        &mut transaction,
        tenant_id,
        supplier_id,
        "supplier_subprocessor_created",
        Some(actor_id),
        "Supplier-Unterauftragnehmer angelegt.",
    )
    .await?;
    transaction.commit().await?;
    get_subprocessor_postgres(pool, tenant_id, supplier_id, subprocessor_id).await
}

async fn add_subprocessor_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    supplier_id: i64,
    actor_id: i64,
    payload: SupplierSubprocessorRequest,
) -> SupplierStoreResult<SupplierSubprocessor> {
    ensure_supplier_sqlite(pool, tenant_id, supplier_id).await?;
    let normalized = validate_subprocessor_payload(payload)?;
    let mut transaction = pool.begin().await?;
    let row = sqlx::query(
        r#"
        INSERT INTO supplier_subprocessor (
            tenant_id, supplier_id, name, purpose, country_region, data_relationship,
            criticality, approval_status, review_due_at, created_by_id, updated_by_id,
            created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .bind(&normalized.name)
    .bind(&normalized.purpose)
    .bind(&normalized.country_region)
    .bind(&normalized.data_relationship)
    .bind(&normalized.criticality)
    .bind(&normalized.approval_status)
    .bind(normalized.review_due_at.as_deref())
    .bind(actor_id)
    .fetch_one(&mut *transaction)
    .await?;
    let subprocessor_id: i64 = row.try_get("id")?;
    insert_audit_sqlite_tx(
        &mut transaction,
        tenant_id,
        supplier_id,
        "supplier_subprocessor_created",
        Some(actor_id),
        "Supplier-Unterauftragnehmer angelegt.",
    )
    .await?;
    transaction.commit().await?;
    get_subprocessor_sqlite(pool, tenant_id, supplier_id, subprocessor_id).await
}

async fn update_subprocessor_postgres(
    pool: &PgPool,
    tenant_id: i64,
    supplier_id: i64,
    subprocessor_id: i64,
    actor_id: i64,
    payload: SupplierSubprocessorRequest,
) -> SupplierStoreResult<SupplierSubprocessor> {
    ensure_supplier_postgres(pool, tenant_id, supplier_id).await?;
    let normalized = validate_subprocessor_payload(payload)?;
    let mut transaction = pool.begin().await?;
    let result = sqlx::query(
        r#"
        UPDATE supplier_subprocessor
        SET name = $4,
            purpose = $5,
            country_region = $6,
            data_relationship = $7,
            criticality = $8,
            approval_status = $9,
            review_due_at = $10,
            updated_by_id = $11,
            updated_at = CURRENT_TIMESTAMP::text
        WHERE tenant_id = $1 AND supplier_id = $2 AND id = $3
        "#,
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .bind(subprocessor_id)
    .bind(&normalized.name)
    .bind(&normalized.purpose)
    .bind(&normalized.country_region)
    .bind(&normalized.data_relationship)
    .bind(&normalized.criticality)
    .bind(&normalized.approval_status)
    .bind(normalized.review_due_at.as_deref())
    .bind(actor_id)
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() != 1 {
        return Err(SupplierStoreError::not_found());
    }
    insert_audit_postgres_tx(
        &mut transaction,
        tenant_id,
        supplier_id,
        "supplier_subprocessor_updated",
        Some(actor_id),
        "Supplier-Unterauftragnehmer aktualisiert.",
    )
    .await?;
    transaction.commit().await?;
    get_subprocessor_postgres(pool, tenant_id, supplier_id, subprocessor_id).await
}

async fn update_subprocessor_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    supplier_id: i64,
    subprocessor_id: i64,
    actor_id: i64,
    payload: SupplierSubprocessorRequest,
) -> SupplierStoreResult<SupplierSubprocessor> {
    ensure_supplier_sqlite(pool, tenant_id, supplier_id).await?;
    let normalized = validate_subprocessor_payload(payload)?;
    let mut transaction = pool.begin().await?;
    let result = sqlx::query(
        r#"
        UPDATE supplier_subprocessor
        SET name = ?4,
            purpose = ?5,
            country_region = ?6,
            data_relationship = ?7,
            criticality = ?8,
            approval_status = ?9,
            review_due_at = ?10,
            updated_by_id = ?11,
            updated_at = CURRENT_TIMESTAMP
        WHERE tenant_id = ?1 AND supplier_id = ?2 AND id = ?3
        "#,
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .bind(subprocessor_id)
    .bind(&normalized.name)
    .bind(&normalized.purpose)
    .bind(&normalized.country_region)
    .bind(&normalized.data_relationship)
    .bind(&normalized.criticality)
    .bind(&normalized.approval_status)
    .bind(normalized.review_due_at.as_deref())
    .bind(actor_id)
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() != 1 {
        return Err(SupplierStoreError::not_found());
    }
    insert_audit_sqlite_tx(
        &mut transaction,
        tenant_id,
        supplier_id,
        "supplier_subprocessor_updated",
        Some(actor_id),
        "Supplier-Unterauftragnehmer aktualisiert.",
    )
    .await?;
    transaction.commit().await?;
    get_subprocessor_sqlite(pool, tenant_id, supplier_id, subprocessor_id).await
}

async fn link_evidence_postgres(
    pool: &PgPool,
    tenant_id: i64,
    supplier_id: i64,
    actor_id: i64,
    payload: SupplierEvidenceLinkRequest,
) -> SupplierStoreResult<SupplierMutationStatus> {
    ensure_supplier_postgres(pool, tenant_id, supplier_id).await?;
    validate_evidence_ref_postgres(pool, tenant_id, Some(payload.evidence_id)).await?;
    let link_type = clean_text(
        payload.link_type.unwrap_or_else(|| "review".to_string()),
        64,
    );
    let mut transaction = pool.begin().await?;
    let result = sqlx::query(
        r#"
        INSERT INTO supplier_evidence_link (
            tenant_id, supplier_id, evidence_id, link_type, created_by_id, created_at
        )
        VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP::text)
        ON CONFLICT DO NOTHING
        "#,
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .bind(payload.evidence_id)
    .bind(&link_type)
    .bind(actor_id)
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() == 0 {
        return Ok(SupplierMutationStatus::AlreadyExists);
    }
    insert_audit_postgres_tx(
        &mut transaction,
        tenant_id,
        supplier_id,
        "supplier_evidence_linked",
        Some(actor_id),
        "Evidence mit Supplier verknuepft.",
    )
    .await?;
    transaction.commit().await?;
    Ok(SupplierMutationStatus::Created)
}

async fn link_evidence_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    supplier_id: i64,
    actor_id: i64,
    payload: SupplierEvidenceLinkRequest,
) -> SupplierStoreResult<SupplierMutationStatus> {
    ensure_supplier_sqlite(pool, tenant_id, supplier_id).await?;
    validate_evidence_ref_sqlite(pool, tenant_id, Some(payload.evidence_id)).await?;
    let link_type = clean_text(
        payload.link_type.unwrap_or_else(|| "review".to_string()),
        64,
    );
    let mut transaction = pool.begin().await?;
    let result = sqlx::query(
        r#"
        INSERT INTO supplier_evidence_link (
            tenant_id, supplier_id, evidence_id, link_type, created_by_id, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP)
        ON CONFLICT DO NOTHING
        "#,
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .bind(payload.evidence_id)
    .bind(&link_type)
    .bind(actor_id)
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() == 0 {
        return Ok(SupplierMutationStatus::AlreadyExists);
    }
    insert_audit_sqlite_tx(
        &mut transaction,
        tenant_id,
        supplier_id,
        "supplier_evidence_linked",
        Some(actor_id),
        "Evidence mit Supplier verknuepft.",
    )
    .await?;
    transaction.commit().await?;
    Ok(SupplierMutationStatus::Created)
}

async fn link_control_postgres(
    pool: &PgPool,
    tenant_id: i64,
    supplier_id: i64,
    actor_id: i64,
    payload: SupplierEntityLinkRequest,
) -> SupplierStoreResult<SupplierMutationStatus> {
    ensure_supplier_postgres(pool, tenant_id, supplier_id).await?;
    validate_control_ref_postgres(pool, payload.entity_id).await?;
    let mut transaction = pool.begin().await?;
    let result = sqlx::query(
        "INSERT INTO supplier_control_link (tenant_id, supplier_id, control_id, created_by_id, created_at) VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP::text) ON CONFLICT DO NOTHING",
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .bind(payload.entity_id)
    .bind(actor_id)
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() == 0 {
        return Ok(SupplierMutationStatus::AlreadyExists);
    }
    insert_audit_postgres_tx(
        &mut transaction,
        tenant_id,
        supplier_id,
        "supplier_control_linked",
        Some(actor_id),
        "Control mit Supplier verknuepft.",
    )
    .await?;
    transaction.commit().await?;
    Ok(SupplierMutationStatus::Created)
}

async fn link_control_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    supplier_id: i64,
    actor_id: i64,
    payload: SupplierEntityLinkRequest,
) -> SupplierStoreResult<SupplierMutationStatus> {
    ensure_supplier_sqlite(pool, tenant_id, supplier_id).await?;
    validate_control_ref_sqlite(pool, payload.entity_id).await?;
    let mut transaction = pool.begin().await?;
    let result = sqlx::query(
        "INSERT INTO supplier_control_link (tenant_id, supplier_id, control_id, created_by_id, created_at) VALUES (?1, ?2, ?3, ?4, CURRENT_TIMESTAMP) ON CONFLICT DO NOTHING",
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .bind(payload.entity_id)
    .bind(actor_id)
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() == 0 {
        return Ok(SupplierMutationStatus::AlreadyExists);
    }
    insert_audit_sqlite_tx(
        &mut transaction,
        tenant_id,
        supplier_id,
        "supplier_control_linked",
        Some(actor_id),
        "Control mit Supplier verknuepft.",
    )
    .await?;
    transaction.commit().await?;
    Ok(SupplierMutationStatus::Created)
}

async fn link_risk_postgres(
    pool: &PgPool,
    tenant_id: i64,
    supplier_id: i64,
    actor_id: i64,
    payload: SupplierEntityLinkRequest,
) -> SupplierStoreResult<SupplierMutationStatus> {
    ensure_supplier_postgres(pool, tenant_id, supplier_id).await?;
    validate_risk_ref_postgres(pool, tenant_id, payload.entity_id).await?;
    let mut transaction = pool.begin().await?;
    let result = sqlx::query(
        "INSERT INTO supplier_risk_link (tenant_id, supplier_id, risk_id, created_by_id, created_at) VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP::text) ON CONFLICT DO NOTHING",
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .bind(payload.entity_id)
    .bind(actor_id)
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() == 0 {
        return Ok(SupplierMutationStatus::AlreadyExists);
    }
    insert_audit_postgres_tx(
        &mut transaction,
        tenant_id,
        supplier_id,
        "supplier_risk_linked",
        Some(actor_id),
        "Risiko mit Supplier verknuepft.",
    )
    .await?;
    transaction.commit().await?;
    Ok(SupplierMutationStatus::Created)
}

async fn link_risk_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    supplier_id: i64,
    actor_id: i64,
    payload: SupplierEntityLinkRequest,
) -> SupplierStoreResult<SupplierMutationStatus> {
    ensure_supplier_sqlite(pool, tenant_id, supplier_id).await?;
    validate_risk_ref_sqlite(pool, tenant_id, payload.entity_id).await?;
    let mut transaction = pool.begin().await?;
    let result = sqlx::query(
        "INSERT INTO supplier_risk_link (tenant_id, supplier_id, risk_id, created_by_id, created_at) VALUES (?1, ?2, ?3, ?4, CURRENT_TIMESTAMP) ON CONFLICT DO NOTHING",
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .bind(payload.entity_id)
    .bind(actor_id)
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() == 0 {
        return Ok(SupplierMutationStatus::AlreadyExists);
    }
    insert_audit_sqlite_tx(
        &mut transaction,
        tenant_id,
        supplier_id,
        "supplier_risk_linked",
        Some(actor_id),
        "Risiko mit Supplier verknuepft.",
    )
    .await?;
    transaction.commit().await?;
    Ok(SupplierMutationStatus::Created)
}

async fn supplier_status_postgres(
    pool: &PgPool,
    tenant_id: i64,
    supplier_id: i64,
) -> SupplierStoreResult<String> {
    let row = sqlx::query(
        "SELECT review_status FROM organizations_supplier WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .fetch_optional(pool)
    .await?;
    row.map(|row| normalize_workflow_status_lossy(row.get::<String, _>("review_status").as_str()))
        .ok_or_else(SupplierStoreError::not_found)
}

async fn supplier_status_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    supplier_id: i64,
) -> SupplierStoreResult<String> {
    let row = sqlx::query(
        "SELECT review_status FROM organizations_supplier WHERE tenant_id = ? AND id = ?",
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .fetch_optional(pool)
    .await?;
    row.map(|row| normalize_workflow_status_lossy(row.get::<String, _>("review_status").as_str()))
        .ok_or_else(SupplierStoreError::not_found)
}

async fn ensure_supplier_postgres(
    pool: &PgPool,
    tenant_id: i64,
    supplier_id: i64,
) -> SupplierStoreResult<()> {
    if supplier_id <= 0 {
        return Err(SupplierStoreError::not_found());
    }
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM organizations_supplier WHERE tenant_id = $1 AND id = $2)",
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .fetch_one(pool)
    .await?;
    if exists {
        Ok(())
    } else {
        Err(SupplierStoreError::not_found())
    }
}

async fn ensure_supplier_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    supplier_id: i64,
) -> SupplierStoreResult<()> {
    if supplier_id <= 0 {
        return Err(SupplierStoreError::not_found());
    }
    let exists: i64 = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM organizations_supplier WHERE tenant_id = ? AND id = ?)",
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .fetch_one(pool)
    .await?;
    if exists != 0 {
        Ok(())
    } else {
        Err(SupplierStoreError::not_found())
    }
}

async fn validate_user_ref_postgres(
    pool: &PgPool,
    tenant_id: i64,
    user_id: Option<i64>,
) -> SupplierStoreResult<()> {
    let Some(user_id) = user_id else {
        return Ok(());
    };
    if user_id <= 0 {
        return Err(SupplierStoreError::invalid("User-Referenz ist ungueltig."));
    }
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM accounts_user WHERE tenant_id = $1 AND id = $2)",
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    if exists {
        Ok(())
    } else {
        Err(SupplierStoreError::not_found())
    }
}

async fn validate_user_ref_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    user_id: Option<i64>,
) -> SupplierStoreResult<()> {
    let Some(user_id) = user_id else {
        return Ok(());
    };
    if user_id <= 0 {
        return Err(SupplierStoreError::invalid("User-Referenz ist ungueltig."));
    }
    let exists: i64 = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM accounts_user WHERE tenant_id = ? AND id = ?)",
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    if exists != 0 {
        Ok(())
    } else {
        Err(SupplierStoreError::not_found())
    }
}

async fn validate_evidence_ref_postgres(
    pool: &PgPool,
    tenant_id: i64,
    evidence_id: Option<i64>,
) -> SupplierStoreResult<()> {
    let Some(evidence_id) = evidence_id else {
        return Ok(());
    };
    if evidence_id <= 0 {
        return Err(SupplierStoreError::invalid(
            "Evidence-Referenz ist ungueltig.",
        ));
    }
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM evidence_evidenceitem WHERE tenant_id = $1 AND id = $2)",
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .fetch_one(pool)
    .await?;
    if exists {
        Ok(())
    } else {
        Err(SupplierStoreError::not_found())
    }
}

async fn validate_evidence_ref_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    evidence_id: Option<i64>,
) -> SupplierStoreResult<()> {
    let Some(evidence_id) = evidence_id else {
        return Ok(());
    };
    if evidence_id <= 0 {
        return Err(SupplierStoreError::invalid(
            "Evidence-Referenz ist ungueltig.",
        ));
    }
    let exists: i64 = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM evidence_evidenceitem WHERE tenant_id = ? AND id = ?)",
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .fetch_one(pool)
    .await?;
    if exists != 0 {
        Ok(())
    } else {
        Err(SupplierStoreError::not_found())
    }
}

async fn validate_control_ref_postgres(pool: &PgPool, control_id: i64) -> SupplierStoreResult<()> {
    if control_id <= 0 {
        return Err(SupplierStoreError::invalid(
            "Control-Referenz ist ungueltig.",
        ));
    }
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM iscy_control_control WHERE id = $1)")
            .bind(control_id)
            .fetch_one(pool)
            .await?;
    if exists {
        Ok(())
    } else {
        Err(SupplierStoreError::not_found())
    }
}

async fn validate_control_ref_sqlite(
    pool: &SqlitePool,
    control_id: i64,
) -> SupplierStoreResult<()> {
    if control_id <= 0 {
        return Err(SupplierStoreError::invalid(
            "Control-Referenz ist ungueltig.",
        ));
    }
    let exists: i64 =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM iscy_control_control WHERE id = ?)")
            .bind(control_id)
            .fetch_one(pool)
            .await?;
    if exists != 0 {
        Ok(())
    } else {
        Err(SupplierStoreError::not_found())
    }
}

async fn validate_risk_ref_postgres(
    pool: &PgPool,
    tenant_id: i64,
    risk_id: i64,
) -> SupplierStoreResult<()> {
    if risk_id <= 0 {
        return Err(SupplierStoreError::invalid(
            "Risiko-Referenz ist ungueltig.",
        ));
    }
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM risks_risk WHERE tenant_id = $1 AND id = $2)",
    )
    .bind(tenant_id)
    .bind(risk_id)
    .fetch_one(pool)
    .await?;
    if exists {
        Ok(())
    } else {
        Err(SupplierStoreError::not_found())
    }
}

async fn validate_risk_ref_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    risk_id: i64,
) -> SupplierStoreResult<()> {
    if risk_id <= 0 {
        return Err(SupplierStoreError::invalid(
            "Risiko-Referenz ist ungueltig.",
        ));
    }
    let exists: i64 = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM risks_risk WHERE tenant_id = ? AND id = ?)",
    )
    .bind(tenant_id)
    .bind(risk_id)
    .fetch_one(pool)
    .await?;
    if exists != 0 {
        Ok(())
    } else {
        Err(SupplierStoreError::not_found())
    }
}

async fn validate_id_refs_postgres(
    pool: &PgPool,
    tenant_id: i64,
    kind: &str,
    ids: &[i64],
) -> SupplierStoreResult<()> {
    for id in ids.iter().copied() {
        match kind {
            "evidence" => validate_evidence_ref_postgres(pool, tenant_id, Some(id)).await?,
            "control" => validate_control_ref_postgres(pool, id).await?,
            _ => return Err(SupplierStoreError::invalid("Referenztyp ist ungueltig.")),
        }
    }
    Ok(())
}

async fn validate_id_refs_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    kind: &str,
    ids: &[i64],
) -> SupplierStoreResult<()> {
    for id in ids.iter().copied() {
        match kind {
            "evidence" => validate_evidence_ref_sqlite(pool, tenant_id, Some(id)).await?,
            "control" => validate_control_ref_sqlite(pool, id).await?,
            _ => return Err(SupplierStoreError::invalid("Referenztyp ist ungueltig.")),
        }
    }
    Ok(())
}

async fn list_reviews_postgres(
    pool: &PgPool,
    tenant_id: i64,
    supplier_id: i64,
) -> SupplierStoreResult<Vec<SupplierReviewEvent>> {
    let rows = sqlx::query(review_select_postgres())
        .bind(tenant_id)
        .bind(supplier_id)
        .fetch_all(pool)
        .await?;
    rows.into_iter()
        .map(review_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_reviews_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    supplier_id: i64,
) -> SupplierStoreResult<Vec<SupplierReviewEvent>> {
    let rows = sqlx::query(review_select_sqlite())
        .bind(tenant_id)
        .bind(supplier_id)
        .fetch_all(pool)
        .await?;
    rows.into_iter()
        .map(review_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_subprocessors_postgres(
    pool: &PgPool,
    tenant_id: i64,
    supplier_id: i64,
) -> SupplierStoreResult<Vec<SupplierSubprocessor>> {
    let rows = sqlx::query(subprocessor_select_postgres())
        .bind(tenant_id)
        .bind(supplier_id)
        .fetch_all(pool)
        .await?;
    rows.into_iter()
        .map(subprocessor_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_subprocessors_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    supplier_id: i64,
) -> SupplierStoreResult<Vec<SupplierSubprocessor>> {
    let rows = sqlx::query(subprocessor_select_sqlite())
        .bind(tenant_id)
        .bind(supplier_id)
        .fetch_all(pool)
        .await?;
    rows.into_iter()
        .map(subprocessor_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn get_subprocessor_postgres(
    pool: &PgPool,
    tenant_id: i64,
    supplier_id: i64,
    subprocessor_id: i64,
) -> SupplierStoreResult<SupplierSubprocessor> {
    let query = format!("{} AND id = $3", subprocessor_select_postgres());
    let row = sqlx::query(&query)
        .bind(tenant_id)
        .bind(supplier_id)
        .bind(subprocessor_id)
        .fetch_optional(pool)
        .await?;
    row.map(subprocessor_from_pg_row)
        .transpose()?
        .ok_or_else(SupplierStoreError::not_found)
}

async fn get_subprocessor_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    supplier_id: i64,
    subprocessor_id: i64,
) -> SupplierStoreResult<SupplierSubprocessor> {
    let query = format!("{} AND id = ?", subprocessor_select_sqlite());
    let row = sqlx::query(&query)
        .bind(tenant_id)
        .bind(supplier_id)
        .bind(subprocessor_id)
        .fetch_optional(pool)
        .await?;
    row.map(subprocessor_from_sqlite_row)
        .transpose()?
        .ok_or_else(SupplierStoreError::not_found)
}

async fn list_evidence_links_postgres(
    pool: &PgPool,
    tenant_id: i64,
    supplier_id: i64,
) -> SupplierStoreResult<Vec<SupplierEvidenceLink>> {
    let rows = sqlx::query(
        r#"
        SELECT link.id, link.evidence_id, evidence.title, evidence.status, evidence.linked_requirement,
               link.link_type, link.created_at::text AS created_at
        FROM supplier_evidence_link link
        JOIN evidence_evidenceitem evidence
            ON evidence.tenant_id = link.tenant_id AND evidence.id = link.evidence_id
        WHERE link.tenant_id = $1 AND link.supplier_id = $2
        ORDER BY link.created_at DESC, link.id DESC
        "#,
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(evidence_link_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_evidence_links_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    supplier_id: i64,
) -> SupplierStoreResult<Vec<SupplierEvidenceLink>> {
    let rows = sqlx::query(
        r#"
        SELECT link.id, link.evidence_id, evidence.title, evidence.status, evidence.linked_requirement,
               link.link_type, CAST(link.created_at AS TEXT) AS created_at
        FROM supplier_evidence_link link
        JOIN evidence_evidenceitem evidence
            ON evidence.tenant_id = link.tenant_id AND evidence.id = link.evidence_id
        WHERE link.tenant_id = ? AND link.supplier_id = ?
        ORDER BY link.created_at DESC, link.id DESC
        "#,
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(evidence_link_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_control_links_postgres(
    pool: &PgPool,
    tenant_id: i64,
    supplier_id: i64,
) -> SupplierStoreResult<Vec<SupplierControlLink>> {
    let rows = sqlx::query(
        r#"
        SELECT link.id, link.control_id, control.code, control.title, link.created_at::text AS created_at
        FROM supplier_control_link link
        JOIN iscy_control_control control ON control.id = link.control_id
        WHERE link.tenant_id = $1 AND link.supplier_id = $2
        ORDER BY control.control_number ASC, link.id ASC
        "#,
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(control_link_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_control_links_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    supplier_id: i64,
) -> SupplierStoreResult<Vec<SupplierControlLink>> {
    let rows = sqlx::query(
        r#"
        SELECT link.id, link.control_id, control.code, control.title, CAST(link.created_at AS TEXT) AS created_at
        FROM supplier_control_link link
        JOIN iscy_control_control control ON control.id = link.control_id
        WHERE link.tenant_id = ? AND link.supplier_id = ?
        ORDER BY control.control_number ASC, link.id ASC
        "#,
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(control_link_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_risk_links_postgres(
    pool: &PgPool,
    tenant_id: i64,
    supplier_id: i64,
) -> SupplierStoreResult<Vec<SupplierRiskLink>> {
    let rows = sqlx::query(
        r#"
        SELECT link.id, link.risk_id, risk.title, risk.status, link.created_at::text AS created_at
        FROM supplier_risk_link link
        JOIN risks_risk risk ON risk.tenant_id = link.tenant_id AND risk.id = link.risk_id
        WHERE link.tenant_id = $1 AND link.supplier_id = $2
        ORDER BY link.created_at DESC, link.id DESC
        "#,
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(risk_link_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_risk_links_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    supplier_id: i64,
) -> SupplierStoreResult<Vec<SupplierRiskLink>> {
    let rows = sqlx::query(
        r#"
        SELECT link.id, link.risk_id, risk.title, risk.status, CAST(link.created_at AS TEXT) AS created_at
        FROM supplier_risk_link link
        JOIN risks_risk risk ON risk.tenant_id = link.tenant_id AND risk.id = link.risk_id
        WHERE link.tenant_id = ? AND link.supplier_id = ?
        ORDER BY link.created_at DESC, link.id DESC
        "#,
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(risk_link_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_audit_events_postgres(
    pool: &PgPool,
    tenant_id: i64,
    supplier_id: i64,
) -> SupplierStoreResult<Vec<SupplierAuditEvent>> {
    let rows = sqlx::query(
        r#"
        SELECT id, supplier_id, event_type, actor_id, detail, created_at::text AS created_at
        FROM supplier_audit_event
        WHERE tenant_id = $1 AND supplier_id = $2
        ORDER BY created_at DESC, id DESC
        LIMIT 100
        "#,
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(audit_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_audit_events_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    supplier_id: i64,
) -> SupplierStoreResult<Vec<SupplierAuditEvent>> {
    let rows = sqlx::query(
        r#"
        SELECT id, supplier_id, event_type, actor_id, detail, CAST(created_at AS TEXT) AS created_at
        FROM supplier_audit_event
        WHERE tenant_id = ? AND supplier_id = ?
        ORDER BY created_at DESC, id DESC
        LIMIT 100
        "#,
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(audit_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn insert_audit_postgres_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    supplier_id: i64,
    event_type: &str,
    actor_id: Option<i64>,
    detail: &str,
) -> SupplierStoreResult<()> {
    let result = sqlx::query(
        r#"
        INSERT INTO supplier_audit_event (
            tenant_id, supplier_id, event_type, actor_id, detail, created_at
        )
        SELECT $1, supplier.id, $3, $4, $5, CURRENT_TIMESTAMP::text
        FROM organizations_supplier supplier
        WHERE supplier.tenant_id = $1 AND supplier.id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(supplier_id)
    .bind(event_type)
    .bind(actor_id)
    .bind(clean_text(detail.to_string(), 1000))
    .execute(&mut **tx)
    .await?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(SupplierStoreError::not_found())
    }
}

async fn insert_audit_sqlite_tx(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    supplier_id: i64,
    event_type: &str,
    actor_id: Option<i64>,
    detail: &str,
) -> SupplierStoreResult<()> {
    let result = sqlx::query(
        r#"
        INSERT INTO supplier_audit_event (
            tenant_id, supplier_id, event_type, actor_id, detail, created_at
        )
        SELECT ?, supplier.id, ?, ?, ?, CURRENT_TIMESTAMP
        FROM organizations_supplier supplier
        WHERE supplier.tenant_id = ? AND supplier.id = ?
        "#,
    )
    .bind(tenant_id)
    .bind(event_type)
    .bind(actor_id)
    .bind(clean_text(detail.to_string(), 1000))
    .bind(tenant_id)
    .bind(supplier_id)
    .execute(&mut **tx)
    .await?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(SupplierStoreError::not_found())
    }
}

fn review_select_postgres() -> &'static str {
    r#"
    SELECT id, supplier_id, old_status, new_status, actor_id, reason, risk_level,
           evidence_refs, control_refs, created_at::text AS created_at
    FROM supplier_review_event
    WHERE tenant_id = $1 AND supplier_id = $2
    ORDER BY created_at DESC, id DESC
    "#
}

fn review_select_sqlite() -> &'static str {
    r#"
    SELECT id, supplier_id, old_status, new_status, actor_id, reason, risk_level,
           evidence_refs, control_refs, CAST(created_at AS TEXT) AS created_at
    FROM supplier_review_event
    WHERE tenant_id = ? AND supplier_id = ?
    ORDER BY created_at DESC, id DESC
    "#
}

fn subprocessor_select_postgres() -> &'static str {
    r#"
    SELECT id, supplier_id, name, purpose, country_region, data_relationship,
           criticality, approval_status, review_due_at, created_by_id, updated_by_id,
           created_at::text AS created_at, updated_at::text AS updated_at
    FROM supplier_subprocessor
    WHERE tenant_id = $1 AND supplier_id = $2
    "#
}

fn subprocessor_select_sqlite() -> &'static str {
    r#"
    SELECT id, supplier_id, name, purpose, country_region, data_relationship,
           criticality, approval_status, review_due_at, created_by_id, updated_by_id,
           CAST(created_at AS TEXT) AS created_at, CAST(updated_at AS TEXT) AS updated_at
    FROM supplier_subprocessor
    WHERE tenant_id = ? AND supplier_id = ?
    "#
}

fn review_from_pg_row(row: PgRow) -> Result<SupplierReviewEvent, sqlx::Error> {
    review_from_row(SupplierReviewRowValues {
        id: row.try_get("id")?,
        supplier_id: row.try_get("supplier_id")?,
        old_status_raw: row.try_get("old_status")?,
        new_status_raw: row.try_get("new_status")?,
        actor_id: row.try_get("actor_id")?,
        reason: row.try_get("reason")?,
        risk_level: row.try_get("risk_level")?,
        evidence_refs: row.try_get("evidence_refs")?,
        control_refs: row.try_get("control_refs")?,
        created_at: row.try_get("created_at")?,
    })
}

fn review_from_sqlite_row(row: SqliteRow) -> Result<SupplierReviewEvent, sqlx::Error> {
    review_from_row(SupplierReviewRowValues {
        id: row.try_get("id")?,
        supplier_id: row.try_get("supplier_id")?,
        old_status_raw: row.try_get("old_status")?,
        new_status_raw: row.try_get("new_status")?,
        actor_id: row.try_get("actor_id")?,
        reason: row.try_get("reason")?,
        risk_level: row.try_get("risk_level")?,
        evidence_refs: row.try_get("evidence_refs")?,
        control_refs: row.try_get("control_refs")?,
        created_at: row.try_get("created_at")?,
    })
}

struct SupplierReviewRowValues {
    id: i64,
    supplier_id: i64,
    old_status_raw: String,
    new_status_raw: String,
    actor_id: Option<i64>,
    reason: String,
    risk_level: String,
    evidence_refs: String,
    control_refs: String,
    created_at: String,
}

fn review_from_row(row: SupplierReviewRowValues) -> Result<SupplierReviewEvent, sqlx::Error> {
    let old_status = normalize_workflow_status_lossy(&row.old_status_raw);
    let new_status = normalize_workflow_status_lossy(&row.new_status_raw);
    Ok(SupplierReviewEvent {
        id: row.id,
        supplier_id: row.supplier_id,
        old_status_label: supplier_review_status_label(&old_status).to_string(),
        old_status,
        new_status_label: supplier_review_status_label(&new_status).to_string(),
        new_status,
        actor_id: row.actor_id,
        reason: row.reason,
        risk_level: normalize_risk_level_lossy(&row.risk_level),
        evidence_refs: row.evidence_refs,
        control_refs: row.control_refs,
        created_at: row.created_at,
    })
}

fn subprocessor_from_pg_row(row: PgRow) -> Result<SupplierSubprocessor, sqlx::Error> {
    subprocessor_from_values(SupplierSubprocessorRowValues {
        id: row.try_get("id")?,
        supplier_id: row.try_get("supplier_id")?,
        name: row.try_get("name")?,
        purpose: row.try_get("purpose")?,
        country_region: row.try_get("country_region")?,
        data_relationship: row.try_get("data_relationship")?,
        criticality_raw: row.try_get("criticality")?,
        approval_status_raw: row.try_get("approval_status")?,
        review_due_at: row.try_get("review_due_at")?,
        created_by_id: row.try_get("created_by_id")?,
        updated_by_id: row.try_get("updated_by_id")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn subprocessor_from_sqlite_row(row: SqliteRow) -> Result<SupplierSubprocessor, sqlx::Error> {
    subprocessor_from_values(SupplierSubprocessorRowValues {
        id: row.try_get("id")?,
        supplier_id: row.try_get("supplier_id")?,
        name: row.try_get("name")?,
        purpose: row.try_get("purpose")?,
        country_region: row.try_get("country_region")?,
        data_relationship: row.try_get("data_relationship")?,
        criticality_raw: row.try_get("criticality")?,
        approval_status_raw: row.try_get("approval_status")?,
        review_due_at: row.try_get("review_due_at")?,
        created_by_id: row.try_get("created_by_id")?,
        updated_by_id: row.try_get("updated_by_id")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

struct SupplierSubprocessorRowValues {
    id: i64,
    supplier_id: i64,
    name: String,
    purpose: String,
    country_region: String,
    data_relationship: String,
    criticality_raw: String,
    approval_status_raw: String,
    review_due_at: Option<String>,
    created_by_id: Option<i64>,
    updated_by_id: Option<i64>,
    created_at: String,
    updated_at: String,
}

fn subprocessor_from_values(
    row: SupplierSubprocessorRowValues,
) -> Result<SupplierSubprocessor, sqlx::Error> {
    let criticality = normalize_upper(&row.criticality_raw);
    let approval_status = normalize_workflow_status_lossy(&row.approval_status_raw);
    Ok(SupplierSubprocessor {
        id: row.id,
        supplier_id: row.supplier_id,
        name: row.name,
        purpose: row.purpose,
        country_region: row.country_region,
        data_relationship: row.data_relationship,
        criticality_label: supplier_criticality_label(&criticality).to_string(),
        criticality,
        approval_status_label: supplier_review_status_label(&approval_status).to_string(),
        approval_status,
        review_due_at: row.review_due_at,
        created_by_id: row.created_by_id,
        updated_by_id: row.updated_by_id,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

fn evidence_link_from_pg_row(row: PgRow) -> Result<SupplierEvidenceLink, sqlx::Error> {
    Ok(SupplierEvidenceLink {
        id: row.try_get("id")?,
        evidence_id: row.try_get("evidence_id")?,
        title: row.try_get("title")?,
        status: row.try_get("status")?,
        linked_requirement: row.try_get("linked_requirement")?,
        link_type: row.try_get("link_type")?,
        created_at: row.try_get("created_at")?,
    })
}

fn evidence_link_from_sqlite_row(row: SqliteRow) -> Result<SupplierEvidenceLink, sqlx::Error> {
    Ok(SupplierEvidenceLink {
        id: row.try_get("id")?,
        evidence_id: row.try_get("evidence_id")?,
        title: row.try_get("title")?,
        status: row.try_get("status")?,
        linked_requirement: row.try_get("linked_requirement")?,
        link_type: row.try_get("link_type")?,
        created_at: row.try_get("created_at")?,
    })
}

fn control_link_from_pg_row(row: PgRow) -> Result<SupplierControlLink, sqlx::Error> {
    Ok(SupplierControlLink {
        id: row.try_get("id")?,
        control_id: row.try_get("control_id")?,
        code: row.try_get("code")?,
        title: row.try_get("title")?,
        created_at: row.try_get("created_at")?,
    })
}

fn control_link_from_sqlite_row(row: SqliteRow) -> Result<SupplierControlLink, sqlx::Error> {
    Ok(SupplierControlLink {
        id: row.try_get("id")?,
        control_id: row.try_get("control_id")?,
        code: row.try_get("code")?,
        title: row.try_get("title")?,
        created_at: row.try_get("created_at")?,
    })
}

fn risk_link_from_pg_row(row: PgRow) -> Result<SupplierRiskLink, sqlx::Error> {
    Ok(SupplierRiskLink {
        id: row.try_get("id")?,
        risk_id: row.try_get("risk_id")?,
        title: row.try_get("title")?,
        status: row.try_get("status")?,
        created_at: row.try_get("created_at")?,
    })
}

fn risk_link_from_sqlite_row(row: SqliteRow) -> Result<SupplierRiskLink, sqlx::Error> {
    Ok(SupplierRiskLink {
        id: row.try_get("id")?,
        risk_id: row.try_get("risk_id")?,
        title: row.try_get("title")?,
        status: row.try_get("status")?,
        created_at: row.try_get("created_at")?,
    })
}

fn audit_from_pg_row(row: PgRow) -> Result<SupplierAuditEvent, sqlx::Error> {
    Ok(SupplierAuditEvent {
        id: row.try_get("id")?,
        supplier_id: row.try_get("supplier_id")?,
        event_type: row.try_get("event_type")?,
        actor_id: row.try_get("actor_id")?,
        detail: row.try_get("detail")?,
        created_at: row.try_get("created_at")?,
    })
}

fn audit_from_sqlite_row(row: SqliteRow) -> Result<SupplierAuditEvent, sqlx::Error> {
    Ok(SupplierAuditEvent {
        id: row.try_get("id")?,
        supplier_id: row.try_get("supplier_id")?,
        event_type: row.try_get("event_type")?,
        actor_id: row.try_get("actor_id")?,
        detail: row.try_get("detail")?,
        created_at: row.try_get("created_at")?,
    })
}

#[derive(Debug, Clone)]
struct ValidatedSupplierPayload {
    name: String,
    service_description: String,
    criticality: String,
    owner_id: Option<i64>,
    contact_email: String,
    contract_reference: String,
    data_categories: String,
    regions: String,
    exit_dependency: String,
    regulatory_scope: String,
    review_status: String,
    next_review_due_at: Option<String>,
    evidence_required: bool,
    notes: String,
    risk_assessment: String,
    service_product_reference: String,
    data_access: bool,
    system_access: bool,
    ot_access: bool,
    exit_relevant: bool,
    responsible_role: String,
    responsible_user_id: Option<i64>,
    contract_start_at: Option<String>,
    contract_end_at: Option<String>,
    contract_notice_period: String,
    contract_auto_renews: bool,
    next_contract_review_at: Option<String>,
    contract_evidence_id: Option<i64>,
    exit_test_required: bool,
    exit_test_status: String,
    last_exit_test_at: Option<String>,
    next_exit_test_at: Option<String>,
    exit_test_result: String,
    exit_test_open_actions: String,
    exit_test_evidence_id: Option<i64>,
}

#[derive(Debug, Clone)]
struct ValidatedSupplierUpdate {
    name: Option<String>,
    service_description: Option<String>,
    criticality: Option<String>,
    owner_id: Option<i64>,
    contact_email: Option<String>,
    contract_reference: Option<String>,
    data_categories: Option<String>,
    regions: Option<String>,
    exit_dependency: Option<String>,
    regulatory_scope: Option<String>,
    next_review_due_at: Option<String>,
    evidence_required: Option<bool>,
    notes: Option<String>,
    risk_assessment: Option<String>,
    service_product_reference: Option<String>,
    data_access: Option<bool>,
    system_access: Option<bool>,
    ot_access: Option<bool>,
    exit_relevant: Option<bool>,
    responsible_role: Option<String>,
    responsible_user_id: Option<i64>,
    contract_start_at: Option<String>,
    contract_end_at: Option<String>,
    contract_notice_period: Option<String>,
    contract_auto_renews: Option<bool>,
    next_contract_review_at: Option<String>,
    contract_evidence_id: Option<i64>,
    exit_test_required: Option<bool>,
    exit_test_status: Option<String>,
    last_exit_test_at: Option<String>,
    next_exit_test_at: Option<String>,
    exit_test_result: Option<String>,
    exit_test_open_actions: Option<String>,
    exit_test_evidence_id: Option<i64>,
}

#[derive(Debug, Clone)]
struct ValidatedReviewPayload {
    new_status: String,
    reason: String,
    risk_level: String,
    evidence_refs: Vec<i64>,
    control_refs: Vec<i64>,
    next_review_due_at: Option<String>,
}

#[derive(Debug, Clone)]
struct ValidatedSubprocessorPayload {
    name: String,
    purpose: String,
    country_region: String,
    data_relationship: String,
    criticality: String,
    approval_status: String,
    review_due_at: Option<String>,
}

fn validate_create_payload(
    payload: SupplierCreateRequest,
) -> SupplierStoreResult<ValidatedSupplierPayload> {
    let name = clean_required_text(payload.name, 255, "Supplier-Name")?;
    let review_status =
        normalize_workflow_status(payload.review_status.as_deref().unwrap_or("draft"))?;
    let risk_assessment = normalize_risk_level(
        payload
            .risk_assessment
            .as_deref()
            .unwrap_or_else(|| payload.criticality.as_deref().unwrap_or("medium")),
    )?;
    let exit_test_status = normalize_exit_status(
        payload
            .exit_test_status
            .as_deref()
            .unwrap_or("not_required"),
    )?;
    Ok(ValidatedSupplierPayload {
        name,
        service_description: clean_text(payload.service_description, 4000),
        criticality: normalize_criticality(payload.criticality.as_deref().unwrap_or("medium")),
        owner_id: positive_id_option(payload.owner_id, "Owner")?,
        contact_email: clean_text(payload.contact_email, 254),
        contract_reference: clean_text(payload.contract_reference, 255),
        data_categories: clean_text(payload.data_categories, 4000),
        regions: clean_text(payload.regions, 4000),
        exit_dependency: clean_text(payload.exit_dependency, 4000),
        regulatory_scope: clean_text(payload.regulatory_scope, 4000),
        review_status,
        next_review_due_at: normalize_optional_date(payload.next_review_due_at)?,
        evidence_required: payload.evidence_required.unwrap_or(true),
        notes: clean_text(payload.notes, 4000),
        risk_assessment,
        service_product_reference: clean_text(payload.service_product_reference, 4000),
        data_access: payload.data_access.unwrap_or(false),
        system_access: payload.system_access.unwrap_or(false),
        ot_access: payload.ot_access.unwrap_or(false),
        exit_relevant: payload.exit_relevant.unwrap_or(false),
        responsible_role: clean_text(payload.responsible_role, 64),
        responsible_user_id: positive_id_option(payload.responsible_user_id, "Responsible User")?,
        contract_start_at: normalize_optional_date(payload.contract_start_at)?,
        contract_end_at: normalize_optional_date(payload.contract_end_at)?,
        contract_notice_period: clean_text(payload.contract_notice_period, 128),
        contract_auto_renews: payload.contract_auto_renews.unwrap_or(false),
        next_contract_review_at: normalize_optional_date(payload.next_contract_review_at)?,
        contract_evidence_id: positive_id_option(
            payload.contract_evidence_id,
            "Contract Evidence",
        )?,
        exit_test_required: payload.exit_test_required.unwrap_or(false),
        exit_test_status,
        last_exit_test_at: normalize_optional_date(payload.last_exit_test_at)?,
        next_exit_test_at: normalize_optional_date(payload.next_exit_test_at)?,
        exit_test_result: clean_text(payload.exit_test_result, 4000),
        exit_test_open_actions: clean_text(payload.exit_test_open_actions, 4000),
        exit_test_evidence_id: positive_id_option(payload.exit_test_evidence_id, "Exit Evidence")?,
    })
}

fn validate_update_payload(
    payload: SupplierUpdateRequest,
) -> SupplierStoreResult<ValidatedSupplierUpdate> {
    Ok(ValidatedSupplierUpdate {
        name: payload
            .name
            .map(|value| clean_required_text(value, 255, "Supplier-Name"))
            .transpose()?,
        service_description: payload
            .service_description
            .map(|value| clean_text(value, 4000)),
        criticality: payload
            .criticality
            .map(|value| normalize_criticality(&value)),
        owner_id: positive_id_option(payload.owner_id, "Owner")?,
        contact_email: payload.contact_email.map(|value| clean_text(value, 254)),
        contract_reference: payload
            .contract_reference
            .map(|value| clean_text(value, 255)),
        data_categories: payload.data_categories.map(|value| clean_text(value, 4000)),
        regions: payload.regions.map(|value| clean_text(value, 4000)),
        exit_dependency: payload.exit_dependency.map(|value| clean_text(value, 4000)),
        regulatory_scope: payload
            .regulatory_scope
            .map(|value| clean_text(value, 4000)),
        next_review_due_at: normalize_optional_date(payload.next_review_due_at)?,
        evidence_required: payload.evidence_required,
        notes: payload.notes.map(|value| clean_text(value, 4000)),
        risk_assessment: payload
            .risk_assessment
            .map(|value| normalize_risk_level(&value))
            .transpose()?,
        service_product_reference: payload
            .service_product_reference
            .map(|value| clean_text(value, 4000)),
        data_access: payload.data_access,
        system_access: payload.system_access,
        ot_access: payload.ot_access,
        exit_relevant: payload.exit_relevant,
        responsible_role: payload.responsible_role.map(|value| clean_text(value, 64)),
        responsible_user_id: positive_id_option(payload.responsible_user_id, "Responsible User")?,
        contract_start_at: normalize_optional_date(payload.contract_start_at)?,
        contract_end_at: normalize_optional_date(payload.contract_end_at)?,
        contract_notice_period: payload
            .contract_notice_period
            .map(|value| clean_text(value, 128)),
        contract_auto_renews: payload.contract_auto_renews,
        next_contract_review_at: normalize_optional_date(payload.next_contract_review_at)?,
        contract_evidence_id: positive_id_option(
            payload.contract_evidence_id,
            "Contract Evidence",
        )?,
        exit_test_required: payload.exit_test_required,
        exit_test_status: payload
            .exit_test_status
            .map(|value| normalize_exit_status(&value))
            .transpose()?,
        last_exit_test_at: normalize_optional_date(payload.last_exit_test_at)?,
        next_exit_test_at: normalize_optional_date(payload.next_exit_test_at)?,
        exit_test_result: payload
            .exit_test_result
            .map(|value| clean_text(value, 4000)),
        exit_test_open_actions: payload
            .exit_test_open_actions
            .map(|value| clean_text(value, 4000)),
        exit_test_evidence_id: positive_id_option(payload.exit_test_evidence_id, "Exit Evidence")?,
    })
}

fn validate_review_payload(
    payload: SupplierReviewRequest,
) -> SupplierStoreResult<ValidatedReviewPayload> {
    let new_status = normalize_workflow_status(&payload.new_status)?;
    let reason = clean_text(payload.reason.unwrap_or_default(), 4000);
    if matches!(new_status.as_str(), "approved_with_conditions" | "rejected") && reason.is_empty() {
        return Err(SupplierStoreError::invalid(
            "Fuer approved_with_conditions und rejected ist eine Begruendung erforderlich.",
        ));
    }
    let risk_level = normalize_risk_level(payload.risk_level.as_deref().unwrap_or("medium"))?;
    let evidence_refs = sanitize_id_list(payload.evidence_refs, "Evidence")?;
    let control_refs = sanitize_id_list(payload.control_refs, "Control")?;
    Ok(ValidatedReviewPayload {
        new_status,
        reason,
        risk_level,
        evidence_refs,
        control_refs,
        next_review_due_at: normalize_optional_date(payload.next_review_due_at)?,
    })
}

fn validate_subprocessor_payload(
    payload: SupplierSubprocessorRequest,
) -> SupplierStoreResult<ValidatedSubprocessorPayload> {
    Ok(ValidatedSubprocessorPayload {
        name: clean_required_text(payload.name, 255, "Subprocessor-Name")?,
        purpose: clean_text(payload.purpose, 4000),
        country_region: clean_text(payload.country_region, 128),
        data_relationship: clean_text(payload.data_relationship, 128),
        criticality: normalize_criticality(payload.criticality.as_deref().unwrap_or("medium")),
        approval_status: normalize_workflow_status(
            payload.approval_status.as_deref().unwrap_or("draft"),
        )?,
        review_due_at: normalize_optional_date(payload.review_due_at)?,
    })
}

fn clean_required_text(
    value: String,
    max_len: usize,
    field_name: &str,
) -> SupplierStoreResult<String> {
    let cleaned = clean_text(value, max_len);
    if cleaned.is_empty() {
        Err(SupplierStoreError::invalid(format!(
            "{field_name} ist erforderlich."
        )))
    } else {
        Ok(cleaned)
    }
}

fn clean_text(value: String, max_len: usize) -> String {
    value
        .trim()
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
        .take(max_len)
        .collect()
}

fn positive_id_option(value: Option<i64>, field_name: &str) -> SupplierStoreResult<Option<i64>> {
    match value {
        Some(value) if value <= 0 => Err(SupplierStoreError::invalid(format!(
            "{field_name}-Referenz ist ungueltig."
        ))),
        value => Ok(value),
    }
}

fn sanitize_id_list(values: Vec<i64>, field_name: &str) -> SupplierStoreResult<Vec<i64>> {
    let mut ids = Vec::new();
    for value in values {
        if value <= 0 {
            return Err(SupplierStoreError::invalid(format!(
                "{field_name}-Referenz ist ungueltig."
            )));
        }
        if !ids.contains(&value) {
            ids.push(value);
        }
    }
    Ok(ids)
}

fn normalize_optional_date(value: Option<String>) -> SupplierStoreResult<Option<String>> {
    let Some(value) = value.map(|value| clean_text(value, 32)) else {
        return Ok(None);
    };
    if value.is_empty() {
        return Ok(None);
    }
    let date = NaiveDate::parse_from_str(&value, "%Y-%m-%d")
        .map_err(|_| SupplierStoreError::invalid("Datum muss im Format YYYY-MM-DD vorliegen."))?;
    Ok(Some(date.format("%Y-%m-%d").to_string()))
}

fn normalize_workflow_status(status: &str) -> SupplierStoreResult<String> {
    let normalized = normalize_token(status);
    if supplier_workflow_statuses().contains(&normalized.as_str()) {
        Ok(normalized)
    } else {
        Err(SupplierStoreError::invalid(
            "Supplier-Review-Status ist nicht unterstuetzt.",
        ))
    }
}

fn normalize_workflow_status_lossy(status: &str) -> String {
    match normalize_token(status).as_str() {
        "approved" | "reviewed" => "approved".to_string(),
        "approved_with_conditions" => "approved_with_conditions".to_string(),
        "in_review" => "in_review".to_string(),
        "rejected" => "rejected".to_string(),
        "expired" => "expired".to_string(),
        "archived" => "archived".to_string(),
        "not_reviewed" | "notreviewed" | "" => "draft".to_string(),
        _ => "draft".to_string(),
    }
}

fn supplier_workflow_statuses() -> &'static [&'static str] {
    &[
        "draft",
        "in_review",
        "approved",
        "approved_with_conditions",
        "rejected",
        "expired",
        "archived",
    ]
}

fn normalize_exit_status(status: &str) -> SupplierStoreResult<String> {
    let normalized = normalize_token(status);
    if supplier_exit_statuses().contains(&normalized.as_str()) {
        Ok(normalized)
    } else {
        Err(SupplierStoreError::invalid(
            "Exit-Test-Status ist nicht unterstuetzt.",
        ))
    }
}

fn normalize_exit_status_lossy(status: &str) -> String {
    let normalized = normalize_token(status);
    if supplier_exit_statuses().contains(&normalized.as_str()) {
        normalized
    } else {
        "not_required".to_string()
    }
}

fn supplier_exit_statuses() -> &'static [&'static str] {
    &[
        "not_required",
        "required",
        "planned",
        "passed",
        "failed",
        "overdue",
    ]
}

fn normalize_risk_level(value: &str) -> SupplierStoreResult<String> {
    let normalized = normalize_token(value);
    match normalized.as_str() {
        "low" | "medium" | "high" | "critical" => Ok(normalized),
        _ => Err(SupplierStoreError::invalid(
            "Risiko-Level ist nicht unterstuetzt.",
        )),
    }
}

fn normalize_risk_level_lossy(value: &str) -> String {
    match normalize_token(value).as_str() {
        "low" => "low".to_string(),
        "high" => "high".to_string(),
        "critical" | "very_high" => "critical".to_string(),
        _ => "medium".to_string(),
    }
}

fn normalize_criticality(value: &str) -> String {
    match normalize_token(value).as_str() {
        "critical" => "CRITICAL".to_string(),
        "very_high" => "VERY_HIGH".to_string(),
        "high" => "HIGH".to_string(),
        "low" => "LOW".to_string(),
        _ => "MEDIUM".to_string(),
    }
}

fn normalize_token(value: &str) -> String {
    value.trim().replace('-', "_").to_ascii_lowercase()
}

fn supplier_criticality_label(criticality: &str) -> &'static str {
    match normalize_upper(criticality).as_str() {
        "CRITICAL" | "VERY_HIGH" => "Kritisch",
        "HIGH" => "Hoch",
        "MEDIUM" => "Mittel",
        "LOW" => "Niedrig",
        _ => "Nicht bewertet",
    }
}

fn supplier_review_status_label(status: &str) -> &'static str {
    match normalize_workflow_status_lossy(status).as_str() {
        "approved" => "Freigegeben",
        "approved_with_conditions" => "Mit Auflagen",
        "in_review" => "In Review",
        "rejected" => "Abgelehnt",
        "expired" => "Abgelaufen",
        "archived" => "Archiviert",
        _ => "Entwurf",
    }
}

fn supplier_exit_status_label(status: &str) -> &'static str {
    match normalize_exit_status_lossy(status).as_str() {
        "required" => "Erforderlich",
        "planned" => "Geplant",
        "passed" => "Bestanden",
        "failed" => "Fehlgeschlagen",
        "overdue" => "Ueberfaellig",
        _ => "Nicht erforderlich",
    }
}

fn supplier_score_label(score: i64) -> &'static str {
    if score >= 80 {
        "Belastbar"
    } else if score >= 60 {
        "Beobachten"
    } else if score >= 40 {
        "Handlungsbedarf"
    } else {
        "Kritisch"
    }
}

fn normalize_upper(value: &str) -> String {
    value.trim().to_ascii_uppercase()
}

fn is_high_criticality(criticality: &str) -> bool {
    matches!(
        normalize_upper(criticality).as_str(),
        "CRITICAL" | "VERY_HIGH" | "HIGH"
    )
}

fn is_overdue(date_value: Option<&str>) -> bool {
    let Some(date_value) = date_value.map(str::trim).filter(|value| !value.is_empty()) else {
        return false;
    };
    let Ok(date) = NaiveDate::parse_from_str(date_value, "%Y-%m-%d") else {
        return false;
    };
    date < Utc::now().date_naive()
}
