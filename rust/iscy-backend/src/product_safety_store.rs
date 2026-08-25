use std::{fmt, sync::Arc};

use anyhow::{bail, Context};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Postgres, Row, Sqlite, Transaction,
};
use tokio::sync::{Mutex, MutexGuard};

use crate::cve_store::normalize_database_url;

pub const PERMISSION_VIEW_PRODUCT_SAFETY: &str = "view_product_safety";
pub const PERMISSION_MANAGE_PRODUCT_APPLICABILITY: &str = "manage_product_applicability";
pub const PERMISSION_MANAGE_PRODUCT_SAFETY: &str = "manage_product_safety";
pub const PERMISSION_REVIEW_PRODUCT_SAFETY: &str = "review_product_safety";
pub const PERMISSION_MANAGE_SAFETY_SECURITY_INTERACTION: &str =
    "manage_safety_security_interaction";
pub const PERMISSION_LINK_PRODUCT_SAFETY_EVIDENCE: &str = "link_product_safety_evidence";

const LEGAL_ACTS: [&str; 2] = ["CRA", "MACHINERY_REGULATION"];
const APPLICABILITY_STATUSES: [&str; 4] = [
    "NOT_ASSESSED",
    "REVIEW_REQUIRED",
    "IN_SCOPE",
    "OUT_OF_SCOPE",
];
const PRODUCT_ROLES: [&str; 6] = [
    "MACHINERY",
    "RELATED_PRODUCT",
    "SAFETY_COMPONENT",
    "SAFETY_RELATED_SOFTWARE",
    "OTHER",
    "REVIEW_REQUIRED",
];
const SAFETY_CRITICALITIES: [&str; 5] = ["LOW", "MEDIUM", "HIGH", "CRITICAL", "REVIEW_REQUIRED"];
const SAFETY_FUNCTION_STATUSES: [&str; 2] = ["ACTIVE", "ARCHIVED"];
const WORKFLOW_STATUSES: [&str; 5] = [
    "OPEN",
    "UNDER_REVIEW",
    "MITIGATION_REQUIRED",
    "ACCEPTED_FOR_REVIEW",
    "CLOSED",
];
const INTERACTION_TYPES: [&str; 6] = [
    "CYBER_CAN_TRIGGER_HAZARD",
    "CYBER_CAN_DEGRADE_SAFETY_FUNCTION",
    "SAFETY_CONTROL_DEPENDS_ON_CYBER_CONTROL",
    "SECURITY_CONTROL_CAN_AFFECT_SAFETY",
    "SHARED_COMPONENT",
    "REVIEW_REQUIRED",
];

#[derive(Clone)]
pub enum ProductSafetyStore {
    Postgres(PgPool),
    Sqlite {
        pool: SqlitePool,
        write_lock: Arc<Mutex<()>>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductSafetyErrorKind {
    InvalidInput,
    NotFound,
    Conflict,
    Database,
}

#[derive(Debug)]
pub struct ProductSafetyError {
    kind: ProductSafetyErrorKind,
    code: &'static str,
    message: &'static str,
}

impl ProductSafetyError {
    pub fn kind(&self) -> ProductSafetyErrorKind {
        self.kind
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &'static str {
        self.message
    }

    fn invalid(code: &'static str, message: &'static str) -> Self {
        Self {
            kind: ProductSafetyErrorKind::InvalidInput,
            code,
            message,
        }
    }

    fn not_found() -> Self {
        Self {
            kind: ProductSafetyErrorKind::NotFound,
            code: "product_safety_object_not_found",
            message: "Das angeforderte Product-Safety-Objekt wurde nicht gefunden.",
        }
    }

    fn conflict(code: &'static str, message: &'static str) -> Self {
        Self {
            kind: ProductSafetyErrorKind::Conflict,
            code,
            message,
        }
    }

    fn database() -> Self {
        Self {
            kind: ProductSafetyErrorKind::Database,
            code: "product_safety_database_error",
            message: "Die Product-Safety-Daten konnten intern nicht verarbeitet werden.",
        }
    }
}

impl fmt::Display for ProductSafetyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for ProductSafetyError {}

#[derive(Debug, Clone, Serialize)]
pub struct ProductIdentity {
    pub id: i64,
    pub tenant_id: i64,
    pub name: String,
    pub code: String,
    pub description: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicabilityWriteRequest {
    pub legal_act: String,
    pub applicability_status: String,
    pub product_role: String,
    pub reasoning: String,
    pub expected_revision: Option<i64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RegulatoryApplicability {
    pub id: i64,
    pub tenant_id: i64,
    pub product_id: i64,
    pub legal_act: String,
    pub applicability_status: String,
    pub product_role: String,
    pub reasoning: String,
    pub assessed_by_id: i64,
    pub assessed_at: String,
    pub reviewed_at: Option<String>,
    pub revision: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineryProfileWriteRequest {
    pub product_role: String,
    pub intended_purpose: String,
    pub reasonably_foreseeable_use: Option<String>,
    pub reasonably_foreseeable_misuse: Option<String>,
    pub operational_environment: Option<String>,
    pub lifecycle_phase: String,
    pub human_interaction: Option<String>,
    pub network_connectivity_context: Option<String>,
    pub remote_access_context: Option<String>,
    pub safety_related_software_present: bool,
    pub programmable_control_system_present: bool,
    pub external_communication_interfaces_present: bool,
    pub expected_revision: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MachineryProductProfile {
    pub id: i64,
    pub tenant_id: i64,
    pub product_id: i64,
    pub product_role: String,
    pub intended_purpose: String,
    pub reasonably_foreseeable_use: String,
    pub reasonably_foreseeable_misuse: String,
    pub operational_environment: String,
    pub lifecycle_phase: String,
    pub human_interaction: String,
    pub network_connectivity_context: String,
    pub remote_access_context: String,
    pub safety_related_software_present: bool,
    pub programmable_control_system_present: bool,
    pub external_communication_interfaces_present: bool,
    pub revision: i64,
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyFunctionWriteRequest {
    pub name: String,
    pub description: Option<String>,
    pub function_identifier: String,
    pub criticality: String,
    pub status: Option<String>,
    pub owner_id: Option<i64>,
    pub expected_revision: Option<i64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SafetyFunction {
    pub id: i64,
    pub tenant_id: i64,
    pub product_id: i64,
    pub name: String,
    pub description: String,
    pub function_identifier: String,
    pub criticality: String,
    pub status: String,
    pub owner_id: Option<i64>,
    pub revision: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafetyFunctionWriteResult {
    pub created: bool,
    pub safety_function: SafetyFunction,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HazardWriteRequest {
    pub title: String,
    pub description: Option<String>,
    pub hazard_category: String,
    pub affected_safety_function_id: Option<i64>,
    pub operational_phase: String,
    pub potential_consequence: String,
    pub risk_estimation_method: String,
    pub initial_risk: String,
    pub residual_risk: Option<String>,
    pub status: Option<String>,
    pub owner_id: Option<i64>,
    pub expected_revision: Option<i64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SafetyHazard {
    pub id: i64,
    pub tenant_id: i64,
    pub product_id: i64,
    pub title: String,
    pub description: String,
    pub hazard_category: String,
    pub affected_safety_function_id: Option<i64>,
    pub operational_phase: String,
    pub potential_consequence: String,
    pub risk_estimation_method: String,
    pub initial_risk: String,
    pub residual_risk: String,
    pub status: String,
    pub owner_id: Option<i64>,
    pub revision: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyAssessmentCreateRequest {
    pub expected_hazard_revision: i64,
    pub lifecycle_operating_state: String,
    pub existing_safeguards: Option<String>,
    pub risk_estimation_method: String,
    pub initial_assessment: String,
    pub additional_measures: Option<String>,
    pub residual_assessment: String,
    pub review_date: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SafetyAssessment {
    pub id: i64,
    pub tenant_id: i64,
    pub hazard_id: i64,
    pub assessment_revision: i64,
    pub lifecycle_operating_state: String,
    pub existing_safeguards: String,
    pub risk_estimation_method: String,
    pub initial_assessment: String,
    pub additional_measures: String,
    pub residual_assessment: String,
    pub reviewer_id: i64,
    pub review_date: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CyberSourceRef {
    pub source_type: String,
    pub source_id: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetySecurityInteractionCreateRequest {
    pub hazard_id: i64,
    pub safety_function_id: i64,
    pub cyber_source: CyberSourceRef,
    pub interaction_type: String,
    pub status: Option<String>,
    pub security_consequence: String,
    pub measures: Option<String>,
    pub rationale: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetySecurityInteractionUpdateRequest {
    pub expected_revision: i64,
    pub status: String,
    pub security_consequence: String,
    pub measures: Option<String>,
    pub rationale: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SafetySecurityInteraction {
    pub id: i64,
    pub tenant_id: i64,
    pub product_id: i64,
    pub hazard_id: i64,
    pub safety_function_id: i64,
    pub cyber_source: CyberSourceRef,
    pub interaction_type: String,
    pub status: String,
    pub security_consequence: String,
    pub measures: String,
    pub rationale: String,
    pub revision: i64,
    pub closed_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafetySecurityInteractionWriteResult {
    pub created: bool,
    pub interaction: SafetySecurityInteraction,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegulatoryRequirementReference {
    pub id: Option<i64>,
    pub requirement_code: String,
    pub legal_act: String,
    pub citation: String,
    pub title: String,
    pub source_classification: String,
    pub source_reference: String,
    pub implementation_status: String,
    pub reasoning: String,
    pub revision: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyEvidenceLinkRequest {
    pub evidence_id: i64,
    pub target_type: String,
    pub target_id: i64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SafetyEvidenceLink {
    pub id: i64,
    pub evidence_id: i64,
    pub target_type: String,
    pub target_id: i64,
    pub created: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSafetyReadiness {
    pub cra_applicability: String,
    pub machinery_regulation_applicability: String,
    pub documented_safety_functions: i64,
    pub open_hazards: i64,
    pub hazards_under_review: i64,
    pub identified_interactions: i64,
    pub interactions_mitigation_required: i64,
    pub evidence_gaps: i64,
    pub missing_items: Vec<String>,
    pub open_reviews: Vec<String>,
    pub human_assessment: &'static str,
    pub technical_documentation_status: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductConformityDetail {
    pub product: ProductIdentity,
    pub applicability: Vec<RegulatoryApplicability>,
    pub machinery_profile: Option<MachineryProductProfile>,
    pub safety_functions: Vec<SafetyFunction>,
    pub hazards: Vec<SafetyHazard>,
    pub security_interactions: Vec<SafetySecurityInteraction>,
    pub requirements: Vec<RegulatoryRequirementReference>,
    pub readiness: ProductSafetyReadiness,
    pub legal_boundary: &'static str,
}

#[derive(Debug)]
struct NormalizedApplicability {
    legal_act: String,
    status: String,
    product_role: String,
    reasoning: String,
    expected_revision: Option<i64>,
}

#[derive(Debug)]
struct NormalizedFunction {
    name: String,
    description: String,
    identifier: String,
    criticality: String,
    status: String,
    owner_id: Option<i64>,
    expected_revision: Option<i64>,
}

#[derive(Debug)]
struct NormalizedHazard {
    title: String,
    description: String,
    category: String,
    function_id: Option<i64>,
    operational_phase: String,
    consequence: String,
    method: String,
    initial_risk: String,
    residual_risk: String,
    status: String,
    owner_id: Option<i64>,
    expected_revision: Option<i64>,
}

#[derive(Debug)]
struct NormalizedAssessment {
    expected_hazard_revision: i64,
    lifecycle_operating_state: String,
    existing_safeguards: String,
    risk_estimation_method: String,
    initial_assessment: String,
    additional_measures: String,
    residual_assessment: String,
    review_date: String,
}

#[derive(Debug)]
struct NormalizedInteraction {
    hazard_id: i64,
    safety_function_id: i64,
    cyber_source: CyberSourceRef,
    interaction_type: String,
    status: String,
    security_consequence: String,
    measures: String,
    rationale: String,
    deduplication_key: String,
}

impl ProductSafetyStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Product-Safety-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Product-Safety-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite {
                pool,
                write_lock: Arc::new(Mutex::new(())),
            });
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Product-Safety-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite {
            pool,
            write_lock: Arc::new(Mutex::new(())),
        }
    }

    async fn sqlite_write_guard(&self) -> Option<MutexGuard<'_, ()>> {
        match self {
            Self::Sqlite { write_lock, .. } => Some(write_lock.lock().await),
            Self::Postgres(_) => None,
        }
    }

    pub async fn product_detail(
        &self,
        tenant_id: i64,
        product_id: i64,
    ) -> Result<ProductConformityDetail, ProductSafetyError> {
        let product = self.product_identity(tenant_id, product_id).await?;
        let applicability = self.list_applicability(tenant_id, product_id).await?;
        let machinery_profile = self.machinery_profile(tenant_id, product_id).await?;
        let safety_functions = self.list_safety_functions(tenant_id, product_id).await?;
        let hazards = self.list_hazards(tenant_id, product_id).await?;
        let security_interactions = self.list_interactions(tenant_id, product_id).await?;
        let requirements = self.list_requirements(tenant_id, product_id).await?;
        let readiness = readiness_from(
            &applicability,
            machinery_profile.as_ref(),
            &safety_functions,
            &hazards,
            &security_interactions,
            &requirements,
            self.evidence_link_count(tenant_id, product_id).await?,
        );
        Ok(ProductConformityDetail {
            product,
            applicability,
            machinery_profile,
            safety_functions,
            hazards,
            security_interactions,
            requirements,
            readiness,
            legal_boundary: "Bewertungs- und Nachweisunterstuetzung; keine automatische Rechts-, CE- oder Konformitaetsentscheidung.",
        })
    }

    pub async fn readiness(
        &self,
        tenant_id: i64,
        product_id: i64,
    ) -> Result<ProductSafetyReadiness, ProductSafetyError> {
        Ok(self.product_detail(tenant_id, product_id).await?.readiness)
    }

    pub async fn list_applicability(
        &self,
        tenant_id: i64,
        product_id: i64,
    ) -> Result<Vec<RegulatoryApplicability>, ProductSafetyError> {
        self.product_identity(tenant_id, product_id).await?;
        let sql_pg = "SELECT * FROM product_regulatory_applicability WHERE tenant_id=$1 AND product_id=$2 ORDER BY legal_act LIMIT 2";
        let sql_sq = "SELECT * FROM product_regulatory_applicability WHERE tenant_id=? AND product_id=? ORDER BY legal_act LIMIT 2";
        match self {
            Self::Postgres(pool) => sqlx::query(sql_pg)
                .bind(tenant_id)
                .bind(product_id)
                .fetch_all(pool)
                .await
                .map_err(|_| ProductSafetyError::database())?
                .into_iter()
                .map(applicability_from_pg_row)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProductSafetyError::database()),
            Self::Sqlite { pool, .. } => sqlx::query(sql_sq)
                .bind(tenant_id)
                .bind(product_id)
                .fetch_all(pool)
                .await
                .map_err(|_| ProductSafetyError::database())?
                .into_iter()
                .map(applicability_from_sqlite_row)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProductSafetyError::database()),
        }
    }

    pub async fn upsert_applicability(
        &self,
        tenant_id: i64,
        product_id: i64,
        actor_id: i64,
        request: ApplicabilityWriteRequest,
    ) -> Result<RegulatoryApplicability, ProductSafetyError> {
        let normalized = normalize_applicability(request)?;
        let _guard = self.sqlite_write_guard().await;
        match self {
            Self::Postgres(pool) => {
                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|_| ProductSafetyError::database())?;
                validate_actor_pg(&mut tx, tenant_id, actor_id).await?;
                validate_product_pg(&mut tx, tenant_id, product_id).await?;
                let current = applicability_by_act_pg(
                    &mut tx,
                    tenant_id,
                    product_id,
                    &normalized.legal_act,
                    true,
                )
                .await?;
                let record = if let Some(current) = current {
                    let expected = normalized.expected_revision.ok_or_else(stale_revision)?;
                    if current.revision != expected {
                        return Err(stale_revision());
                    }
                    update_applicability_pg(
                        &mut tx,
                        tenant_id,
                        product_id,
                        actor_id,
                        &normalized,
                        expected,
                    )
                    .await?
                } else {
                    if normalized.expected_revision.is_some() {
                        return Err(stale_revision());
                    }
                    insert_applicability_pg(&mut tx, tenant_id, product_id, actor_id, &normalized)
                        .await?
                };
                insert_audit_pg(
                    &mut tx,
                    tenant_id,
                    actor_id,
                    "APPLICABILITY",
                    record.id,
                    "applicability_changed",
                    record.revision,
                    &record.applicability_status,
                    &json!({"legal_act": record.legal_act}),
                )
                .await?;
                tx.commit()
                    .await
                    .map_err(|_| ProductSafetyError::database())?;
                Ok(record)
            }
            Self::Sqlite { pool, .. } => {
                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|_| ProductSafetyError::database())?;
                validate_actor_sqlite(&mut tx, tenant_id, actor_id).await?;
                validate_product_sqlite(&mut tx, tenant_id, product_id).await?;
                let current = applicability_by_act_sqlite(
                    &mut tx,
                    tenant_id,
                    product_id,
                    &normalized.legal_act,
                )
                .await?;
                let record = if let Some(current) = current {
                    let expected = normalized.expected_revision.ok_or_else(stale_revision)?;
                    if current.revision != expected {
                        return Err(stale_revision());
                    }
                    update_applicability_sqlite(
                        &mut tx,
                        tenant_id,
                        product_id,
                        actor_id,
                        &normalized,
                        expected,
                    )
                    .await?
                } else {
                    if normalized.expected_revision.is_some() {
                        return Err(stale_revision());
                    }
                    insert_applicability_sqlite(
                        &mut tx,
                        tenant_id,
                        product_id,
                        actor_id,
                        &normalized,
                    )
                    .await?
                };
                insert_audit_sqlite(
                    &mut tx,
                    tenant_id,
                    actor_id,
                    "APPLICABILITY",
                    record.id,
                    "applicability_changed",
                    record.revision,
                    &record.applicability_status,
                    &json!({"legal_act": record.legal_act}),
                )
                .await?;
                tx.commit()
                    .await
                    .map_err(|_| ProductSafetyError::database())?;
                Ok(record)
            }
        }
    }

    pub async fn machinery_profile(
        &self,
        tenant_id: i64,
        product_id: i64,
    ) -> Result<Option<MachineryProductProfile>, ProductSafetyError> {
        self.product_identity(tenant_id, product_id).await?;
        match self {
            Self::Postgres(pool) => sqlx::query(
                "SELECT * FROM machinery_product_profile WHERE tenant_id=$1 AND product_id=$2",
            )
            .bind(tenant_id)
            .bind(product_id)
            .fetch_optional(pool)
            .await
            .map_err(|_| ProductSafetyError::database())?
            .map(profile_from_pg_row)
            .transpose()
            .map_err(|_| ProductSafetyError::database()),
            Self::Sqlite { pool, .. } => sqlx::query(
                "SELECT * FROM machinery_product_profile WHERE tenant_id=? AND product_id=?",
            )
            .bind(tenant_id)
            .bind(product_id)
            .fetch_optional(pool)
            .await
            .map_err(|_| ProductSafetyError::database())?
            .map(profile_from_sqlite_row)
            .transpose()
            .map_err(|_| ProductSafetyError::database()),
        }
    }

    pub async fn upsert_machinery_profile(
        &self,
        tenant_id: i64,
        product_id: i64,
        actor_id: i64,
        request: MachineryProfileWriteRequest,
    ) -> Result<MachineryProductProfile, ProductSafetyError> {
        let request = normalize_profile(request)?;
        let _guard = self.sqlite_write_guard().await;
        match self {
            Self::Postgres(pool) => {
                upsert_profile_pg(pool, tenant_id, product_id, actor_id, &request).await
            }
            Self::Sqlite { pool, .. } => {
                upsert_profile_sqlite(pool, tenant_id, product_id, actor_id, &request).await
            }
        }
    }

    pub async fn list_safety_functions(
        &self,
        tenant_id: i64,
        product_id: i64,
    ) -> Result<Vec<SafetyFunction>, ProductSafetyError> {
        self.product_identity(tenant_id, product_id).await?;
        match self {
            Self::Postgres(pool) => sqlx::query("SELECT * FROM product_safety_function WHERE tenant_id=$1 AND product_id=$2 ORDER BY id LIMIT 500")
                .bind(tenant_id).bind(product_id).fetch_all(pool).await.map_err(|_| ProductSafetyError::database())?
                .into_iter().map(function_from_pg_row).collect::<Result<Vec<_>, _>>().map_err(|_| ProductSafetyError::database()),
            Self::Sqlite { pool, .. } => sqlx::query("SELECT * FROM product_safety_function WHERE tenant_id=? AND product_id=? ORDER BY id LIMIT 500")
                .bind(tenant_id).bind(product_id).fetch_all(pool).await.map_err(|_| ProductSafetyError::database())?
                .into_iter().map(function_from_sqlite_row).collect::<Result<Vec<_>, _>>().map_err(|_| ProductSafetyError::database()),
        }
    }

    pub async fn create_safety_function(
        &self,
        tenant_id: i64,
        product_id: i64,
        actor_id: i64,
        request: SafetyFunctionWriteRequest,
    ) -> Result<SafetyFunctionWriteResult, ProductSafetyError> {
        let normalized = normalize_function(request, false)?;
        let _guard = self.sqlite_write_guard().await;
        match self {
            Self::Postgres(pool) => {
                create_function_pg(pool, tenant_id, product_id, actor_id, &normalized).await
            }
            Self::Sqlite { pool, .. } => {
                create_function_sqlite(pool, tenant_id, product_id, actor_id, &normalized).await
            }
        }
    }

    pub async fn update_safety_function(
        &self,
        tenant_id: i64,
        function_id: i64,
        actor_id: i64,
        request: SafetyFunctionWriteRequest,
    ) -> Result<SafetyFunction, ProductSafetyError> {
        let normalized = normalize_function(request, true)?;
        let _guard = self.sqlite_write_guard().await;
        match self {
            Self::Postgres(pool) => {
                update_function_pg(pool, tenant_id, function_id, actor_id, &normalized).await
            }
            Self::Sqlite { pool, .. } => {
                update_function_sqlite(pool, tenant_id, function_id, actor_id, &normalized).await
            }
        }
    }

    pub async fn list_hazards(
        &self,
        tenant_id: i64,
        product_id: i64,
    ) -> Result<Vec<SafetyHazard>, ProductSafetyError> {
        self.product_identity(tenant_id, product_id).await?;
        match self {
            Self::Postgres(pool) => sqlx::query("SELECT * FROM product_safety_hazard WHERE tenant_id=$1 AND product_id=$2 ORDER BY id LIMIT 500")
                .bind(tenant_id).bind(product_id).fetch_all(pool).await.map_err(|_| ProductSafetyError::database())?
                .into_iter().map(hazard_from_pg_row).collect::<Result<Vec<_>, _>>().map_err(|_| ProductSafetyError::database()),
            Self::Sqlite { pool, .. } => sqlx::query("SELECT * FROM product_safety_hazard WHERE tenant_id=? AND product_id=? ORDER BY id LIMIT 500")
                .bind(tenant_id).bind(product_id).fetch_all(pool).await.map_err(|_| ProductSafetyError::database())?
                .into_iter().map(hazard_from_sqlite_row).collect::<Result<Vec<_>, _>>().map_err(|_| ProductSafetyError::database()),
        }
    }

    pub async fn get_hazard(
        &self,
        tenant_id: i64,
        hazard_id: i64,
    ) -> Result<SafetyHazard, ProductSafetyError> {
        match self {
            Self::Postgres(pool) => {
                sqlx::query("SELECT * FROM product_safety_hazard WHERE tenant_id=$1 AND id=$2")
                    .bind(tenant_id)
                    .bind(hazard_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(|_| ProductSafetyError::database())?
                    .map(hazard_from_pg_row)
                    .transpose()
                    .map_err(|_| ProductSafetyError::database())?
                    .ok_or_else(ProductSafetyError::not_found)
            }
            Self::Sqlite { pool, .. } => {
                sqlx::query("SELECT * FROM product_safety_hazard WHERE tenant_id=? AND id=?")
                    .bind(tenant_id)
                    .bind(hazard_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(|_| ProductSafetyError::database())?
                    .map(hazard_from_sqlite_row)
                    .transpose()
                    .map_err(|_| ProductSafetyError::database())?
                    .ok_or_else(ProductSafetyError::not_found)
            }
        }
    }

    pub async fn create_hazard(
        &self,
        tenant_id: i64,
        product_id: i64,
        actor_id: i64,
        request: HazardWriteRequest,
    ) -> Result<SafetyHazard, ProductSafetyError> {
        let normalized = normalize_hazard(request, false)?;
        let _guard = self.sqlite_write_guard().await;
        match self {
            Self::Postgres(pool) => {
                create_hazard_pg(pool, tenant_id, product_id, actor_id, &normalized).await
            }
            Self::Sqlite { pool, .. } => {
                create_hazard_sqlite(pool, tenant_id, product_id, actor_id, &normalized).await
            }
        }
    }

    pub async fn update_hazard(
        &self,
        tenant_id: i64,
        hazard_id: i64,
        actor_id: i64,
        request: HazardWriteRequest,
    ) -> Result<SafetyHazard, ProductSafetyError> {
        let normalized = normalize_hazard(request, true)?;
        let _guard = self.sqlite_write_guard().await;
        match self {
            Self::Postgres(pool) => {
                update_hazard_pg(pool, tenant_id, hazard_id, actor_id, &normalized).await
            }
            Self::Sqlite { pool, .. } => {
                update_hazard_sqlite(pool, tenant_id, hazard_id, actor_id, &normalized).await
            }
        }
    }

    pub async fn list_assessments(
        &self,
        tenant_id: i64,
        hazard_id: i64,
    ) -> Result<Vec<SafetyAssessment>, ProductSafetyError> {
        self.get_hazard(tenant_id, hazard_id).await?;
        match self {
            Self::Postgres(pool) => sqlx::query("SELECT * FROM product_safety_assessment WHERE tenant_id=$1 AND hazard_id=$2 ORDER BY assessment_revision LIMIT 500")
                .bind(tenant_id).bind(hazard_id).fetch_all(pool).await.map_err(|_| ProductSafetyError::database())?
                .into_iter().map(assessment_from_pg_row).collect::<Result<Vec<_>, _>>().map_err(|_| ProductSafetyError::database()),
            Self::Sqlite { pool, .. } => sqlx::query("SELECT * FROM product_safety_assessment WHERE tenant_id=? AND hazard_id=? ORDER BY assessment_revision LIMIT 500")
                .bind(tenant_id).bind(hazard_id).fetch_all(pool).await.map_err(|_| ProductSafetyError::database())?
                .into_iter().map(assessment_from_sqlite_row).collect::<Result<Vec<_>, _>>().map_err(|_| ProductSafetyError::database()),
        }
    }

    pub async fn create_assessment(
        &self,
        tenant_id: i64,
        hazard_id: i64,
        actor_id: i64,
        request: SafetyAssessmentCreateRequest,
    ) -> Result<SafetyAssessment, ProductSafetyError> {
        let normalized = normalize_assessment(request)?;
        let _guard = self.sqlite_write_guard().await;
        match self {
            Self::Postgres(pool) => {
                create_assessment_pg(pool, tenant_id, hazard_id, actor_id, &normalized).await
            }
            Self::Sqlite { pool, .. } => {
                create_assessment_sqlite(pool, tenant_id, hazard_id, actor_id, &normalized).await
            }
        }
    }

    pub async fn list_interactions(
        &self,
        tenant_id: i64,
        product_id: i64,
    ) -> Result<Vec<SafetySecurityInteraction>, ProductSafetyError> {
        self.product_identity(tenant_id, product_id).await?;
        match self {
            Self::Postgres(pool) => sqlx::query("SELECT * FROM safety_security_interaction WHERE tenant_id=$1 AND product_id=$2 ORDER BY id LIMIT 500")
                .bind(tenant_id).bind(product_id).fetch_all(pool).await.map_err(|_| ProductSafetyError::database())?
                .into_iter().map(interaction_from_pg_row).collect::<Result<Vec<_>, _>>().map_err(|_| ProductSafetyError::database()),
            Self::Sqlite { pool, .. } => sqlx::query("SELECT * FROM safety_security_interaction WHERE tenant_id=? AND product_id=? ORDER BY id LIMIT 500")
                .bind(tenant_id).bind(product_id).fetch_all(pool).await.map_err(|_| ProductSafetyError::database())?
                .into_iter().map(interaction_from_sqlite_row).collect::<Result<Vec<_>, _>>().map_err(|_| ProductSafetyError::database()),
        }
    }

    pub async fn create_interaction(
        &self,
        tenant_id: i64,
        product_id: i64,
        actor_id: i64,
        request: SafetySecurityInteractionCreateRequest,
    ) -> Result<SafetySecurityInteractionWriteResult, ProductSafetyError> {
        let normalized = normalize_interaction(tenant_id, product_id, request)?;
        let _guard = self.sqlite_write_guard().await;
        match self {
            Self::Postgres(pool) => {
                create_interaction_pg(pool, tenant_id, product_id, actor_id, &normalized).await
            }
            Self::Sqlite { pool, .. } => {
                create_interaction_sqlite(pool, tenant_id, product_id, actor_id, &normalized).await
            }
        }
    }

    pub async fn update_interaction(
        &self,
        tenant_id: i64,
        interaction_id: i64,
        actor_id: i64,
        request: SafetySecurityInteractionUpdateRequest,
    ) -> Result<SafetySecurityInteraction, ProductSafetyError> {
        let status = choice(
            request.status,
            &WORKFLOW_STATUSES,
            "invalid_interaction_status",
        )?;
        let consequence = required_text(
            request.security_consequence,
            4000,
            "interaction_consequence_required",
        )?;
        let measures = optional_text(request.measures, 4000, "interaction_measures_too_long")?;
        let rationale = optional_text(request.rationale, 4000, "interaction_rationale_too_long")?;
        if request.expected_revision < 1 {
            return Err(stale_revision());
        }
        let _guard = self.sqlite_write_guard().await;
        match self {
            Self::Postgres(pool) => {
                update_interaction_pg(
                    pool,
                    tenant_id,
                    interaction_id,
                    actor_id,
                    request.expected_revision,
                    &status,
                    &consequence,
                    &measures,
                    &rationale,
                )
                .await
            }
            Self::Sqlite { pool, .. } => {
                update_interaction_sqlite(
                    pool,
                    tenant_id,
                    interaction_id,
                    actor_id,
                    request.expected_revision,
                    &status,
                    &consequence,
                    &measures,
                    &rationale,
                )
                .await
            }
        }
    }

    pub async fn list_requirements(
        &self,
        tenant_id: i64,
        product_id: i64,
    ) -> Result<Vec<RegulatoryRequirementReference>, ProductSafetyError> {
        self.product_identity(tenant_id, product_id).await?;
        let mut stored = match self {
            Self::Postgres(pool) => sqlx::query("SELECT * FROM product_regulatory_requirement WHERE tenant_id=$1 AND product_id=$2 ORDER BY requirement_code LIMIT 500")
                .bind(tenant_id).bind(product_id).fetch_all(pool).await.map_err(|_| ProductSafetyError::database())?
                .into_iter().map(requirement_from_pg_row).collect::<Result<Vec<_>, _>>().map_err(|_| ProductSafetyError::database())?,
            Self::Sqlite { pool, .. } => sqlx::query("SELECT * FROM product_regulatory_requirement WHERE tenant_id=? AND product_id=? ORDER BY requirement_code LIMIT 500")
                .bind(tenant_id).bind(product_id).fetch_all(pool).await.map_err(|_| ProductSafetyError::database())?
                .into_iter().map(requirement_from_sqlite_row).collect::<Result<Vec<_>, _>>().map_err(|_| ProductSafetyError::database())?,
        };
        for reference in default_requirement_references() {
            if !stored
                .iter()
                .any(|item| item.requirement_code == reference.requirement_code)
            {
                stored.push(reference);
            }
        }
        stored.sort_by(|left, right| left.requirement_code.cmp(&right.requirement_code));
        Ok(stored)
    }

    pub async fn link_evidence(
        &self,
        tenant_id: i64,
        product_id: i64,
        actor_id: i64,
        request: SafetyEvidenceLinkRequest,
    ) -> Result<SafetyEvidenceLink, ProductSafetyError> {
        let target_type = normalize_evidence_target_type(&request.target_type)?;
        if request.evidence_id < 1 || request.target_id < 1 {
            return Err(ProductSafetyError::invalid(
                "invalid_evidence_link_reference",
                "Evidence- und Zielreferenz muessen positive IDs sein.",
            ));
        }
        let _guard = self.sqlite_write_guard().await;
        match self {
            Self::Postgres(pool) => {
                link_evidence_pg(pool, tenant_id, product_id, actor_id, request, target_type).await
            }
            Self::Sqlite { pool, .. } => {
                link_evidence_sqlite(pool, tenant_id, product_id, actor_id, request, target_type)
                    .await
            }
        }
    }

    pub async fn unlink_evidence(
        &self,
        tenant_id: i64,
        product_id: i64,
        actor_id: i64,
        request: SafetyEvidenceLinkRequest,
    ) -> Result<(), ProductSafetyError> {
        let target_type = normalize_evidence_target_type(&request.target_type)?;
        if request.evidence_id < 1 || request.target_id < 1 {
            return Err(ProductSafetyError::invalid(
                "invalid_evidence_link_reference",
                "Evidence- und Zielreferenz muessen positive IDs sein.",
            ));
        }
        let _guard = self.sqlite_write_guard().await;
        match self {
            Self::Postgres(pool) => {
                unlink_evidence_pg(pool, tenant_id, product_id, actor_id, request, target_type)
                    .await
            }
            Self::Sqlite { pool, .. } => {
                unlink_evidence_sqlite(pool, tenant_id, product_id, actor_id, request, target_type)
                    .await
            }
        }
    }

    async fn product_identity(
        &self,
        tenant_id: i64,
        product_id: i64,
    ) -> Result<ProductIdentity, ProductSafetyError> {
        match self {
            Self::Postgres(pool) => sqlx::query("SELECT id,tenant_id,name,code,description FROM product_security_product WHERE tenant_id=$1 AND id=$2")
                .bind(tenant_id).bind(product_id).fetch_optional(pool).await.map_err(|_| ProductSafetyError::database())?
                .map(product_from_pg_row).transpose().map_err(|_| ProductSafetyError::database())?.ok_or_else(ProductSafetyError::not_found),
            Self::Sqlite { pool, .. } => sqlx::query("SELECT id,tenant_id,name,code,description FROM product_security_product WHERE tenant_id=? AND id=?")
                .bind(tenant_id).bind(product_id).fetch_optional(pool).await.map_err(|_| ProductSafetyError::database())?
                .map(product_from_sqlite_row).transpose().map_err(|_| ProductSafetyError::database())?.ok_or_else(ProductSafetyError::not_found),
        }
    }

    async fn evidence_link_count(
        &self,
        tenant_id: i64,
        product_id: i64,
    ) -> Result<i64, ProductSafetyError> {
        let sql_pg = "SELECT COUNT(*) AS count FROM product_safety_evidence_link el WHERE el.tenant_id=$1 AND (el.safety_function_id IN (SELECT id FROM product_safety_function WHERE tenant_id=$1 AND product_id=$2) OR el.hazard_id IN (SELECT id FROM product_safety_hazard WHERE tenant_id=$1 AND product_id=$2) OR el.assessment_id IN (SELECT a.id FROM product_safety_assessment a JOIN product_safety_hazard h ON h.tenant_id=a.tenant_id AND h.id=a.hazard_id WHERE h.tenant_id=$1 AND h.product_id=$2) OR el.interaction_id IN (SELECT id FROM safety_security_interaction WHERE tenant_id=$1 AND product_id=$2) OR el.requirement_link_id IN (SELECT id FROM product_regulatory_requirement WHERE tenant_id=$1 AND product_id=$2))";
        let sql_sq = "SELECT COUNT(*) AS count FROM product_safety_evidence_link el WHERE el.tenant_id=? AND (el.safety_function_id IN (SELECT id FROM product_safety_function WHERE tenant_id=? AND product_id=?) OR el.hazard_id IN (SELECT id FROM product_safety_hazard WHERE tenant_id=? AND product_id=?) OR el.assessment_id IN (SELECT a.id FROM product_safety_assessment a JOIN product_safety_hazard h ON h.tenant_id=a.tenant_id AND h.id=a.hazard_id WHERE h.tenant_id=? AND h.product_id=?) OR el.interaction_id IN (SELECT id FROM safety_security_interaction WHERE tenant_id=? AND product_id=?) OR el.requirement_link_id IN (SELECT id FROM product_regulatory_requirement WHERE tenant_id=? AND product_id=?))";
        match self {
            Self::Postgres(pool) => sqlx::query(sql_pg)
                .bind(tenant_id)
                .bind(product_id)
                .fetch_one(pool)
                .await
                .map_err(|_| ProductSafetyError::database())?
                .try_get("count")
                .map_err(|_| ProductSafetyError::database()),
            Self::Sqlite { pool, .. } => sqlx::query(sql_sq)
                .bind(tenant_id)
                .bind(tenant_id)
                .bind(product_id)
                .bind(tenant_id)
                .bind(product_id)
                .bind(tenant_id)
                .bind(product_id)
                .bind(tenant_id)
                .bind(product_id)
                .bind(tenant_id)
                .bind(product_id)
                .fetch_one(pool)
                .await
                .map_err(|_| ProductSafetyError::database())?
                .try_get("count")
                .map_err(|_| ProductSafetyError::database()),
        }
    }
}

fn normalize_evidence_target_type(value: &str) -> Result<&'static str, ProductSafetyError> {
    match value.trim().to_ascii_uppercase().as_str() {
        "SAFETY_FUNCTION" => Ok("SAFETY_FUNCTION"),
        "HAZARD" => Ok("HAZARD"),
        "ASSESSMENT" => Ok("ASSESSMENT"),
        "INTERACTION" => Ok("INTERACTION"),
        "REGULATORY_REQUIREMENT" => Ok("REGULATORY_REQUIREMENT"),
        _ => Err(ProductSafetyError::invalid(
            "invalid_evidence_target_type",
            "Der Evidence-Zieltyp ist nicht unterstuetzt.",
        )),
    }
}

fn evidence_target_column(target_type: &str) -> &'static str {
    match target_type {
        "SAFETY_FUNCTION" => "safety_function_id",
        "HAZARD" => "hazard_id",
        "ASSESSMENT" => "assessment_id",
        "INTERACTION" => "interaction_id",
        "REGULATORY_REQUIREMENT" => "requirement_link_id",
        _ => unreachable!("evidence target was normalized"),
    }
}

fn normalize_applicability(
    request: ApplicabilityWriteRequest,
) -> Result<NormalizedApplicability, ProductSafetyError> {
    Ok(NormalizedApplicability {
        legal_act: choice(request.legal_act, &LEGAL_ACTS, "invalid_legal_act")?,
        status: choice(
            request.applicability_status,
            &APPLICABILITY_STATUSES,
            "invalid_applicability_status",
        )?,
        product_role: choice(request.product_role, &PRODUCT_ROLES, "invalid_product_role")?,
        reasoning: required_text(request.reasoning, 4000, "applicability_reasoning_required")?,
        expected_revision: request.expected_revision,
    })
}

fn normalize_profile(
    mut request: MachineryProfileWriteRequest,
) -> Result<MachineryProfileWriteRequest, ProductSafetyError> {
    request.product_role = choice(request.product_role, &PRODUCT_ROLES, "invalid_product_role")?;
    request.intended_purpose =
        required_text(request.intended_purpose, 4000, "intended_purpose_required")?;
    request.reasonably_foreseeable_use = Some(optional_text(
        request.reasonably_foreseeable_use,
        4000,
        "foreseeable_use_too_long",
    )?);
    request.reasonably_foreseeable_misuse = Some(optional_text(
        request.reasonably_foreseeable_misuse,
        4000,
        "foreseeable_misuse_too_long",
    )?);
    request.operational_environment = Some(optional_text(
        request.operational_environment,
        4000,
        "operational_environment_too_long",
    )?);
    request.lifecycle_phase =
        required_text(request.lifecycle_phase, 32, "lifecycle_phase_required")?;
    request.human_interaction = Some(optional_text(
        request.human_interaction,
        4000,
        "human_interaction_too_long",
    )?);
    request.network_connectivity_context = Some(optional_text(
        request.network_connectivity_context,
        4000,
        "network_context_too_long",
    )?);
    request.remote_access_context = Some(optional_text(
        request.remote_access_context,
        4000,
        "remote_access_context_too_long",
    )?);
    Ok(request)
}

fn normalize_function(
    request: SafetyFunctionWriteRequest,
    update: bool,
) -> Result<NormalizedFunction, ProductSafetyError> {
    if update && request.expected_revision.unwrap_or(0) < 1 {
        return Err(stale_revision());
    }
    if !update && request.expected_revision.is_some() {
        return Err(stale_revision());
    }
    Ok(NormalizedFunction {
        name: required_text(request.name, 255, "safety_function_name_required")?,
        description: optional_text(
            request.description,
            4000,
            "safety_function_description_too_long",
        )?,
        identifier: required_text(
            request.function_identifier,
            100,
            "safety_function_identifier_required",
        )?,
        criticality: choice(
            request.criticality,
            &SAFETY_CRITICALITIES,
            "invalid_safety_function_criticality",
        )?,
        status: choice(
            request.status.unwrap_or_else(|| "ACTIVE".to_string()),
            &SAFETY_FUNCTION_STATUSES,
            "invalid_safety_function_status",
        )?,
        owner_id: request.owner_id,
        expected_revision: request.expected_revision,
    })
}

fn normalize_hazard(
    request: HazardWriteRequest,
    update: bool,
) -> Result<NormalizedHazard, ProductSafetyError> {
    if update && request.expected_revision.unwrap_or(0) < 1 {
        return Err(stale_revision());
    }
    if !update && request.expected_revision.is_some() {
        return Err(stale_revision());
    }
    Ok(NormalizedHazard {
        title: required_text(request.title, 255, "hazard_title_required")?,
        description: optional_text(request.description, 4000, "hazard_description_too_long")?,
        category: required_text(request.hazard_category, 64, "hazard_category_required")?,
        function_id: request.affected_safety_function_id,
        operational_phase: required_text(
            request.operational_phase,
            64,
            "hazard_operational_phase_required",
        )?,
        consequence: required_text(
            request.potential_consequence,
            4000,
            "hazard_consequence_required",
        )?,
        method: required_text(
            request.risk_estimation_method,
            2000,
            "risk_estimation_method_required",
        )?,
        initial_risk: required_text(request.initial_risk, 64, "initial_risk_required")?,
        residual_risk: required_text(
            request
                .residual_risk
                .unwrap_or_else(|| "NOT_ASSESSED".to_string()),
            64,
            "residual_risk_required",
        )?,
        status: choice(
            request.status.unwrap_or_else(|| "OPEN".to_string()),
            &WORKFLOW_STATUSES,
            "invalid_hazard_status",
        )?,
        owner_id: request.owner_id,
        expected_revision: request.expected_revision,
    })
}

fn normalize_assessment(
    request: SafetyAssessmentCreateRequest,
) -> Result<NormalizedAssessment, ProductSafetyError> {
    if request.expected_hazard_revision < 1 {
        return Err(stale_revision());
    }
    Ok(NormalizedAssessment {
        expected_hazard_revision: request.expected_hazard_revision,
        lifecycle_operating_state: required_text(
            request.lifecycle_operating_state,
            255,
            "assessment_operating_state_required",
        )?,
        existing_safeguards: optional_text(
            request.existing_safeguards,
            4000,
            "assessment_safeguards_too_long",
        )?,
        risk_estimation_method: required_text(
            request.risk_estimation_method,
            2000,
            "assessment_method_required",
        )?,
        initial_assessment: required_text(
            request.initial_assessment,
            2000,
            "initial_assessment_required",
        )?,
        additional_measures: optional_text(
            request.additional_measures,
            4000,
            "assessment_measures_too_long",
        )?,
        residual_assessment: required_text(
            request.residual_assessment,
            2000,
            "residual_assessment_required",
        )?,
        review_date: required_text(request.review_date, 64, "assessment_review_date_required")?,
    })
}

fn normalize_interaction(
    tenant_id: i64,
    product_id: i64,
    request: SafetySecurityInteractionCreateRequest,
) -> Result<NormalizedInteraction, ProductSafetyError> {
    if request.hazard_id < 1 || request.safety_function_id < 1 || request.cyber_source.source_id < 1
    {
        return Err(ProductSafetyError::invalid(
            "invalid_interaction_reference",
            "Interaction-Referenzen muessen positive IDs sein.",
        ));
    }
    let source_type = choice(
        request.cyber_source.source_type,
        &[
            "VULNERABILITY",
            "SECURITY_OBSERVATION",
            "RISK",
            "SBOM_COMPONENT",
            "CVE_CORRELATION",
            "THREAT_SCENARIO",
            "TARA",
        ],
        "invalid_cyber_source_type",
    )?;
    let interaction_type = choice(
        request.interaction_type,
        &INTERACTION_TYPES,
        "invalid_interaction_type",
    )?;
    let status = choice(
        request.status.unwrap_or_else(|| "OPEN".to_string()),
        &WORKFLOW_STATUSES,
        "invalid_interaction_status",
    )?;
    if status == "CLOSED" {
        return Err(ProductSafetyError::invalid(
            "invalid_interaction_initial_status",
            "Eine neue Safety-Security-Interaction darf nicht als CLOSED angelegt werden.",
        ));
    }
    let cyber_source = CyberSourceRef {
        source_type,
        source_id: request.cyber_source.source_id,
    };
    let mut digest = Sha256::new();
    digest.update(format!(
        "{tenant_id}:{product_id}:{}:{}:{}:{}:{}",
        request.hazard_id,
        request.safety_function_id,
        cyber_source.source_type,
        cyber_source.source_id,
        interaction_type
    ));
    Ok(NormalizedInteraction {
        hazard_id: request.hazard_id,
        safety_function_id: request.safety_function_id,
        cyber_source,
        interaction_type,
        status,
        security_consequence: required_text(
            request.security_consequence,
            4000,
            "interaction_consequence_required",
        )?,
        measures: optional_text(request.measures, 4000, "interaction_measures_too_long")?,
        rationale: optional_text(request.rationale, 4000, "interaction_rationale_too_long")?,
        deduplication_key: format!("{:x}", digest.finalize()),
    })
}

fn required_text(
    value: String,
    max: usize,
    code: &'static str,
) -> Result<String, ProductSafetyError> {
    let value = value.trim().to_string();
    if value.is_empty() || value.chars().count() > max {
        return Err(ProductSafetyError::invalid(
            code,
            "Ein Pflichtfeld fehlt oder ueberschreitet die erlaubte Laenge.",
        ));
    }
    Ok(value)
}

fn optional_text(
    value: Option<String>,
    max: usize,
    code: &'static str,
) -> Result<String, ProductSafetyError> {
    let value = value.unwrap_or_default().trim().to_string();
    if value.chars().count() > max {
        return Err(ProductSafetyError::invalid(
            code,
            "Ein Textfeld ueberschreitet die erlaubte Laenge.",
        ));
    }
    Ok(value)
}

fn choice(
    value: String,
    allowed: &[&str],
    code: &'static str,
) -> Result<String, ProductSafetyError> {
    let value = value.trim().to_ascii_uppercase();
    if !allowed.contains(&value.as_str()) {
        return Err(ProductSafetyError::invalid(
            code,
            "Der angegebene Zustands- oder Typwert ist nicht erlaubt.",
        ));
    }
    Ok(value)
}

fn stale_revision() -> ProductSafetyError {
    ProductSafetyError::conflict(
        "stale_product_safety_revision",
        "Die erwartete Revision ist veraltet; die Mutation wurde nicht gespeichert.",
    )
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn readiness_from(
    applicability: &[RegulatoryApplicability],
    profile: Option<&MachineryProductProfile>,
    functions: &[SafetyFunction],
    hazards: &[SafetyHazard],
    interactions: &[SafetySecurityInteraction],
    requirements: &[RegulatoryRequirementReference],
    evidence_links: i64,
) -> ProductSafetyReadiness {
    let status = |act: &str| {
        applicability
            .iter()
            .find(|item| item.legal_act == act)
            .map(|item| item.applicability_status.clone())
            .unwrap_or_else(|| "NOT_ASSESSED".to_string())
    };
    let mut missing_items = Vec::new();
    if profile.is_none() {
        missing_items.push("Machinery product profile".to_string());
    }
    if functions.is_empty() {
        missing_items.push("Safety functions".to_string());
    }
    if hazards.is_empty() {
        missing_items.push("Hazards".to_string());
    }
    if evidence_links == 0 {
        missing_items.push("Evidence links".to_string());
    }
    let mut open_reviews = applicability
        .iter()
        .filter(|item| {
            matches!(
                item.applicability_status.as_str(),
                "NOT_ASSESSED" | "REVIEW_REQUIRED"
            )
        })
        .map(|item| format!("{} applicability", item.legal_act))
        .collect::<Vec<_>>();
    open_reviews.extend(
        requirements
            .iter()
            .filter(|item| item.implementation_status != "READY_FOR_HUMAN_REVIEW")
            .map(|item| item.requirement_code.clone()),
    );
    ProductSafetyReadiness {
        cra_applicability: status("CRA"),
        machinery_regulation_applicability: status("MACHINERY_REGULATION"),
        documented_safety_functions: functions
            .iter()
            .filter(|item| item.status == "ACTIVE")
            .count() as i64,
        open_hazards: hazards.iter().filter(|item| item.status == "OPEN").count() as i64,
        hazards_under_review: hazards
            .iter()
            .filter(|item| item.status == "UNDER_REVIEW")
            .count() as i64,
        identified_interactions: interactions.len() as i64,
        interactions_mitigation_required: interactions
            .iter()
            .filter(|item| item.status == "MITIGATION_REQUIRED")
            .count() as i64,
        evidence_gaps: if evidence_links == 0 { 1 } else { 0 },
        missing_items,
        open_reviews,
        human_assessment: "REQUIRED",
        technical_documentation_status: "READY_FOR_HUMAN_REVIEW",
    }
}

fn default_requirement_references() -> Vec<RegulatoryRequirementReference> {
    vec![
        RegulatoryRequirementReference {
            id: None,
            requirement_code: "EU-2023-1230-ANNEX-III-1.1.9".to_string(),
            legal_act: "MACHINERY_REGULATION".to_string(),
            citation: "Anhang III, 1.1.9".to_string(),
            title: "Schutz vor Korrumpierung".to_string(),
            source_classification: "OFFICIAL_PRIMARY".to_string(),
            source_reference: "https://eur-lex.europa.eu/eli/reg/2023/1230/oj/eng".to_string(),
            implementation_status: "NOT_ASSESSED".to_string(),
            reasoning: String::new(),
            revision: 0,
        },
        RegulatoryRequirementReference {
            id: None,
            requirement_code: "EU-2023-1230-ANNEX-III-1.2.1".to_string(),
            legal_act: "MACHINERY_REGULATION".to_string(),
            citation: "Anhang III, 1.2.1".to_string(),
            title: "Sicherheit und Zuverlaessigkeit von Steuerungen".to_string(),
            source_classification: "OFFICIAL_PRIMARY".to_string(),
            source_reference: "https://eur-lex.europa.eu/eli/reg/2023/1230/oj/eng".to_string(),
            implementation_status: "NOT_ASSESSED".to_string(),
            reasoning: String::new(),
            revision: 0,
        },
    ]
}

macro_rules! define_row_readers {
    ($product_fn:ident, $app_fn:ident, $profile_fn:ident, $function_fn:ident, $hazard_fn:ident, $assessment_fn:ident, $interaction_fn:ident, $requirement_fn:ident, $row:ty) => {
        fn $product_fn(row: $row) -> Result<ProductIdentity, sqlx::Error> {
            Ok(ProductIdentity {
                id: row.try_get("id")?,
                tenant_id: row.try_get("tenant_id")?,
                name: row.try_get("name")?,
                code: row.try_get("code")?,
                description: row.try_get("description")?,
            })
        }

        fn $app_fn(row: $row) -> Result<RegulatoryApplicability, sqlx::Error> {
            Ok(RegulatoryApplicability {
                id: row.try_get("id")?,
                tenant_id: row.try_get("tenant_id")?,
                product_id: row.try_get("product_id")?,
                legal_act: row.try_get("legal_act")?,
                applicability_status: row.try_get("applicability_status")?,
                product_role: row.try_get("product_role")?,
                reasoning: row.try_get("reasoning")?,
                assessed_by_id: row.try_get("assessed_by_id")?,
                assessed_at: row.try_get("assessed_at")?,
                reviewed_at: row.try_get("reviewed_at")?,
                revision: row.try_get("revision")?,
                created_at: row.try_get("created_at")?,
                updated_at: row.try_get("updated_at")?,
            })
        }

        fn $profile_fn(row: $row) -> Result<MachineryProductProfile, sqlx::Error> {
            Ok(MachineryProductProfile {
                id: row.try_get("id")?,
                tenant_id: row.try_get("tenant_id")?,
                product_id: row.try_get("product_id")?,
                product_role: row.try_get("product_role")?,
                intended_purpose: row.try_get("intended_purpose")?,
                reasonably_foreseeable_use: row.try_get("reasonably_foreseeable_use")?,
                reasonably_foreseeable_misuse: row.try_get("reasonably_foreseeable_misuse")?,
                operational_environment: row.try_get("operational_environment")?,
                lifecycle_phase: row.try_get("lifecycle_phase")?,
                human_interaction: row.try_get("human_interaction")?,
                network_connectivity_context: row.try_get("network_connectivity_context")?,
                remote_access_context: row.try_get("remote_access_context")?,
                safety_related_software_present: row.try_get("safety_related_software_present")?,
                programmable_control_system_present: row
                    .try_get("programmable_control_system_present")?,
                external_communication_interfaces_present: row
                    .try_get("external_communication_interfaces_present")?,
                revision: row.try_get("revision")?,
                updated_at: row.try_get("updated_at")?,
            })
        }

        fn $function_fn(row: $row) -> Result<SafetyFunction, sqlx::Error> {
            Ok(SafetyFunction {
                id: row.try_get("id")?,
                tenant_id: row.try_get("tenant_id")?,
                product_id: row.try_get("product_id")?,
                name: row.try_get("name")?,
                description: row.try_get("description")?,
                function_identifier: row.try_get("function_identifier")?,
                criticality: row.try_get("criticality")?,
                status: row.try_get("status")?,
                owner_id: row.try_get("owner_id")?,
                revision: row.try_get("revision")?,
                created_at: row.try_get("created_at")?,
                updated_at: row.try_get("updated_at")?,
            })
        }

        fn $hazard_fn(row: $row) -> Result<SafetyHazard, sqlx::Error> {
            Ok(SafetyHazard {
                id: row.try_get("id")?,
                tenant_id: row.try_get("tenant_id")?,
                product_id: row.try_get("product_id")?,
                title: row.try_get("title")?,
                description: row.try_get("description")?,
                hazard_category: row.try_get("hazard_category")?,
                affected_safety_function_id: row.try_get("affected_safety_function_id")?,
                operational_phase: row.try_get("operational_phase")?,
                potential_consequence: row.try_get("potential_consequence")?,
                risk_estimation_method: row.try_get("risk_estimation_method")?,
                initial_risk: row.try_get("initial_risk")?,
                residual_risk: row.try_get("residual_risk")?,
                status: row.try_get("status")?,
                owner_id: row.try_get("owner_id")?,
                revision: row.try_get("revision")?,
                created_at: row.try_get("created_at")?,
                updated_at: row.try_get("updated_at")?,
            })
        }

        fn $assessment_fn(row: $row) -> Result<SafetyAssessment, sqlx::Error> {
            Ok(SafetyAssessment {
                id: row.try_get("id")?,
                tenant_id: row.try_get("tenant_id")?,
                hazard_id: row.try_get("hazard_id")?,
                assessment_revision: row.try_get("assessment_revision")?,
                lifecycle_operating_state: row.try_get("lifecycle_operating_state")?,
                existing_safeguards: row.try_get("existing_safeguards")?,
                risk_estimation_method: row.try_get("risk_estimation_method")?,
                initial_assessment: row.try_get("initial_assessment")?,
                additional_measures: row.try_get("additional_measures")?,
                residual_assessment: row.try_get("residual_assessment")?,
                reviewer_id: row.try_get("reviewer_id")?,
                review_date: row.try_get("review_date")?,
                created_at: row.try_get("created_at")?,
            })
        }

        fn $interaction_fn(row: $row) -> Result<SafetySecurityInteraction, sqlx::Error> {
            let source_candidates = [
                (
                    "VULNERABILITY",
                    row.try_get::<Option<i64>, _>("vulnerability_id")?,
                ),
                (
                    "SECURITY_OBSERVATION",
                    row.try_get::<Option<i64>, _>("security_observation_id")?,
                ),
                ("RISK", row.try_get::<Option<i64>, _>("cyber_risk_id")?),
                (
                    "SBOM_COMPONENT",
                    row.try_get::<Option<i64>, _>("sbom_component_id")?,
                ),
                (
                    "CVE_CORRELATION",
                    row.try_get::<Option<i64>, _>("cve_correlation_id")?,
                ),
                (
                    "THREAT_SCENARIO",
                    row.try_get::<Option<i64>, _>("threat_scenario_id")?,
                ),
                ("TARA", row.try_get::<Option<i64>, _>("tara_id")?),
            ];
            let (source_type, source_id) = source_candidates
                .into_iter()
                .find_map(|(kind, id)| id.map(|id| (kind, id)))
                .ok_or(sqlx::Error::RowNotFound)?;
            Ok(SafetySecurityInteraction {
                id: row.try_get("id")?,
                tenant_id: row.try_get("tenant_id")?,
                product_id: row.try_get("product_id")?,
                hazard_id: row.try_get("hazard_id")?,
                safety_function_id: row.try_get("safety_function_id")?,
                cyber_source: CyberSourceRef {
                    source_type: source_type.to_string(),
                    source_id,
                },
                interaction_type: row.try_get("interaction_type")?,
                status: row.try_get("status")?,
                security_consequence: row.try_get("security_consequence")?,
                measures: row.try_get("measures")?,
                rationale: row.try_get("rationale")?,
                revision: row.try_get("revision")?,
                closed_at: row.try_get("closed_at")?,
                created_at: row.try_get("created_at")?,
                updated_at: row.try_get("updated_at")?,
            })
        }

        fn $requirement_fn(row: $row) -> Result<RegulatoryRequirementReference, sqlx::Error> {
            Ok(RegulatoryRequirementReference {
                id: Some(row.try_get("id")?),
                requirement_code: row.try_get("requirement_code")?,
                legal_act: row.try_get("legal_act")?,
                citation: row.try_get("citation")?,
                title: row.try_get("title")?,
                source_classification: row.try_get("source_classification")?,
                source_reference: row.try_get("source_reference")?,
                implementation_status: row.try_get("implementation_status")?,
                reasoning: row.try_get("reasoning")?,
                revision: row.try_get("revision")?,
            })
        }
    };
}

define_row_readers!(
    product_from_pg_row,
    applicability_from_pg_row,
    profile_from_pg_row,
    function_from_pg_row,
    hazard_from_pg_row,
    assessment_from_pg_row,
    interaction_from_pg_row,
    requirement_from_pg_row,
    PgRow
);
define_row_readers!(
    product_from_sqlite_row,
    applicability_from_sqlite_row,
    profile_from_sqlite_row,
    function_from_sqlite_row,
    hazard_from_sqlite_row,
    assessment_from_sqlite_row,
    interaction_from_sqlite_row,
    requirement_from_sqlite_row,
    SqliteRow
);

async fn validate_actor_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    actor_id: i64,
) -> Result<(), ProductSafetyError> {
    let count: i64 = sqlx::query("SELECT COUNT(*) AS count FROM accounts_user WHERE tenant_id=$1 AND id=$2 AND is_active=TRUE")
        .bind(tenant_id).bind(actor_id).fetch_one(&mut **tx).await.map_err(|_| ProductSafetyError::database())?.try_get("count").map_err(|_| ProductSafetyError::database())?;
    if count != 1 {
        return Err(ProductSafetyError::not_found());
    }
    Ok(())
}

async fn validate_actor_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    actor_id: i64,
) -> Result<(), ProductSafetyError> {
    let count: i64 = sqlx::query(
        "SELECT COUNT(*) AS count FROM accounts_user WHERE tenant_id=? AND id=? AND is_active=1",
    )
    .bind(tenant_id)
    .bind(actor_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ProductSafetyError::database())?
    .try_get("count")
    .map_err(|_| ProductSafetyError::database())?;
    if count != 1 {
        return Err(ProductSafetyError::not_found());
    }
    Ok(())
}

async fn validate_product_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    product_id: i64,
) -> Result<(), ProductSafetyError> {
    validate_relation_pg(tx, "product_security_product", tenant_id, product_id).await
}

async fn validate_product_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    product_id: i64,
) -> Result<(), ProductSafetyError> {
    validate_relation_sqlite(tx, "product_security_product", tenant_id, product_id).await
}

async fn validate_evidence_target_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    product_id: i64,
    target_type: &str,
    target_id: i64,
) -> Result<(), ProductSafetyError> {
    let statement = match target_type {
        "SAFETY_FUNCTION" => "SELECT COUNT(*) AS count FROM product_safety_function WHERE tenant_id=$1 AND product_id=$2 AND id=$3",
        "HAZARD" => "SELECT COUNT(*) AS count FROM product_safety_hazard WHERE tenant_id=$1 AND product_id=$2 AND id=$3",
        "ASSESSMENT" => "SELECT COUNT(*) AS count FROM product_safety_assessment a JOIN product_safety_hazard h ON h.tenant_id=a.tenant_id AND h.id=a.hazard_id WHERE a.tenant_id=$1 AND h.product_id=$2 AND a.id=$3",
        "INTERACTION" => "SELECT COUNT(*) AS count FROM safety_security_interaction WHERE tenant_id=$1 AND product_id=$2 AND id=$3",
        "REGULATORY_REQUIREMENT" => "SELECT COUNT(*) AS count FROM product_regulatory_requirement WHERE tenant_id=$1 AND product_id=$2 AND id=$3",
        _ => unreachable!("evidence target was normalized"),
    };
    let count: i64 = sqlx::query(statement)
        .bind(tenant_id)
        .bind(product_id)
        .bind(target_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| ProductSafetyError::database())?
        .try_get("count")
        .map_err(|_| ProductSafetyError::database())?;
    if count != 1 {
        return Err(ProductSafetyError::not_found());
    }
    Ok(())
}

async fn validate_evidence_target_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    product_id: i64,
    target_type: &str,
    target_id: i64,
) -> Result<(), ProductSafetyError> {
    let statement = match target_type {
        "SAFETY_FUNCTION" => "SELECT COUNT(*) AS count FROM product_safety_function WHERE tenant_id=? AND product_id=? AND id=?",
        "HAZARD" => "SELECT COUNT(*) AS count FROM product_safety_hazard WHERE tenant_id=? AND product_id=? AND id=?",
        "ASSESSMENT" => "SELECT COUNT(*) AS count FROM product_safety_assessment a JOIN product_safety_hazard h ON h.tenant_id=a.tenant_id AND h.id=a.hazard_id WHERE a.tenant_id=? AND h.product_id=? AND a.id=?",
        "INTERACTION" => "SELECT COUNT(*) AS count FROM safety_security_interaction WHERE tenant_id=? AND product_id=? AND id=?",
        "REGULATORY_REQUIREMENT" => "SELECT COUNT(*) AS count FROM product_regulatory_requirement WHERE tenant_id=? AND product_id=? AND id=?",
        _ => unreachable!("evidence target was normalized"),
    };
    let count: i64 = sqlx::query(statement)
        .bind(tenant_id)
        .bind(product_id)
        .bind(target_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| ProductSafetyError::database())?
        .try_get("count")
        .map_err(|_| ProductSafetyError::database())?;
    if count != 1 {
        return Err(ProductSafetyError::not_found());
    }
    Ok(())
}

async fn validate_relation_pg(
    tx: &mut Transaction<'_, Postgres>,
    table: &'static str,
    tenant_id: i64,
    object_id: i64,
) -> Result<(), ProductSafetyError> {
    let statement = format!("SELECT COUNT(*) AS count FROM {table} WHERE tenant_id=$1 AND id=$2");
    let count: i64 = sqlx::query(&statement)
        .bind(tenant_id)
        .bind(object_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| ProductSafetyError::database())?
        .try_get("count")
        .map_err(|_| ProductSafetyError::database())?;
    if count != 1 {
        return Err(ProductSafetyError::not_found());
    }
    Ok(())
}

async fn validate_relation_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    table: &'static str,
    tenant_id: i64,
    object_id: i64,
) -> Result<(), ProductSafetyError> {
    let statement = format!("SELECT COUNT(*) AS count FROM {table} WHERE tenant_id=? AND id=?");
    let count: i64 = sqlx::query(&statement)
        .bind(tenant_id)
        .bind(object_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| ProductSafetyError::database())?
        .try_get("count")
        .map_err(|_| ProductSafetyError::database())?;
    if count != 1 {
        return Err(ProductSafetyError::not_found());
    }
    Ok(())
}

async fn validate_owner_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    owner_id: Option<i64>,
) -> Result<(), ProductSafetyError> {
    if let Some(owner_id) = owner_id {
        validate_relation_pg(tx, "accounts_user", tenant_id, owner_id).await?;
    }
    Ok(())
}

async fn validate_owner_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    owner_id: Option<i64>,
) -> Result<(), ProductSafetyError> {
    if let Some(owner_id) = owner_id {
        validate_relation_sqlite(tx, "accounts_user", tenant_id, owner_id).await?;
    }
    Ok(())
}

async fn validate_function_for_product_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    product_id: i64,
    function_id: Option<i64>,
) -> Result<(), ProductSafetyError> {
    let Some(function_id) = function_id else {
        return Ok(());
    };
    let count: i64 = sqlx::query("SELECT COUNT(*) AS count FROM product_safety_function WHERE tenant_id=$1 AND product_id=$2 AND id=$3")
        .bind(tenant_id).bind(product_id).bind(function_id).fetch_one(&mut **tx).await.map_err(|_| ProductSafetyError::database())?.try_get("count").map_err(|_| ProductSafetyError::database())?;
    if count != 1 {
        return Err(ProductSafetyError::not_found());
    }
    Ok(())
}

async fn validate_function_for_product_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    product_id: i64,
    function_id: Option<i64>,
) -> Result<(), ProductSafetyError> {
    let Some(function_id) = function_id else {
        return Ok(());
    };
    let count: i64 = sqlx::query("SELECT COUNT(*) AS count FROM product_safety_function WHERE tenant_id=? AND product_id=? AND id=?")
        .bind(tenant_id).bind(product_id).bind(function_id).fetch_one(&mut **tx).await.map_err(|_| ProductSafetyError::database())?.try_get("count").map_err(|_| ProductSafetyError::database())?;
    if count != 1 {
        return Err(ProductSafetyError::not_found());
    }
    Ok(())
}

async fn validate_interaction_refs_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    product_id: i64,
    normalized: &NormalizedInteraction,
) -> Result<(), ProductSafetyError> {
    validate_function_for_product_pg(
        tx,
        tenant_id,
        product_id,
        Some(normalized.safety_function_id),
    )
    .await?;
    let hazard_count: i64 = sqlx::query("SELECT COUNT(*) AS count FROM product_safety_hazard WHERE tenant_id=$1 AND product_id=$2 AND id=$3")
        .bind(tenant_id).bind(product_id).bind(normalized.hazard_id).fetch_one(&mut **tx).await.map_err(|_| ProductSafetyError::database())?.try_get("count").map_err(|_| ProductSafetyError::database())?;
    if hazard_count != 1 {
        return Err(ProductSafetyError::not_found());
    }
    validate_cyber_source_pg(tx, tenant_id, product_id, &normalized.cyber_source).await
}

async fn validate_interaction_refs_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    product_id: i64,
    normalized: &NormalizedInteraction,
) -> Result<(), ProductSafetyError> {
    validate_function_for_product_sqlite(
        tx,
        tenant_id,
        product_id,
        Some(normalized.safety_function_id),
    )
    .await?;
    let hazard_count: i64 = sqlx::query("SELECT COUNT(*) AS count FROM product_safety_hazard WHERE tenant_id=? AND product_id=? AND id=?")
        .bind(tenant_id).bind(product_id).bind(normalized.hazard_id).fetch_one(&mut **tx).await.map_err(|_| ProductSafetyError::database())?.try_get("count").map_err(|_| ProductSafetyError::database())?;
    if hazard_count != 1 {
        return Err(ProductSafetyError::not_found());
    }
    validate_cyber_source_sqlite(tx, tenant_id, product_id, &normalized.cyber_source).await
}

async fn validate_cyber_source_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    product_id: i64,
    source: &CyberSourceRef,
) -> Result<(), ProductSafetyError> {
    let (table, product_clause) = match source.source_type.as_str() {
        "VULNERABILITY" => ("product_security_vulnerability", " AND product_id=$3"),
        "SECURITY_OBSERVATION" => ("security_observation", ""),
        "RISK" => ("risks_risk", ""),
        "SBOM_COMPONENT" => ("product_security_importcomponent", " AND product_id=$3"),
        "CVE_CORRELATION" => ("product_security_cvecorrelation", " AND product_id=$3"),
        "THREAT_SCENARIO" => ("product_security_threatscenario", ""),
        "TARA" => ("product_security_tara", " AND product_id=$3"),
        _ => {
            return Err(ProductSafetyError::invalid(
                "invalid_cyber_source_type",
                "Unbekannter Cyber-Quelltyp.",
            ))
        }
    };
    let statement = format!(
        "SELECT COUNT(*) AS count FROM {table} WHERE tenant_id=$1 AND id=$2{product_clause}"
    );
    let mut query = sqlx::query(&statement)
        .bind(tenant_id)
        .bind(source.source_id);
    if !product_clause.is_empty() {
        query = query.bind(product_id);
    }
    let count: i64 = query
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| ProductSafetyError::database())?
        .try_get("count")
        .map_err(|_| ProductSafetyError::database())?;
    if count != 1 {
        return Err(ProductSafetyError::not_found());
    }
    if source.source_type == "THREAT_SCENARIO" {
        let count: i64 = sqlx::query("SELECT COUNT(*) AS count FROM product_security_threatscenario s JOIN product_security_threatmodel m ON m.tenant_id=s.tenant_id AND m.id=s.threat_model_id WHERE s.tenant_id=$1 AND s.id=$2 AND m.product_id=$3")
            .bind(tenant_id).bind(source.source_id).bind(product_id).fetch_one(&mut **tx).await.map_err(|_| ProductSafetyError::database())?.try_get("count").map_err(|_| ProductSafetyError::database())?;
        if count != 1 {
            return Err(ProductSafetyError::not_found());
        }
    }
    Ok(())
}

async fn validate_cyber_source_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    product_id: i64,
    source: &CyberSourceRef,
) -> Result<(), ProductSafetyError> {
    let (table, product_bound) = match source.source_type.as_str() {
        "VULNERABILITY" => ("product_security_vulnerability", true),
        "SECURITY_OBSERVATION" => ("security_observation", false),
        "RISK" => ("risks_risk", false),
        "SBOM_COMPONENT" => ("product_security_importcomponent", true),
        "CVE_CORRELATION" => ("product_security_cvecorrelation", true),
        "THREAT_SCENARIO" => ("product_security_threatscenario", false),
        "TARA" => ("product_security_tara", true),
        _ => {
            return Err(ProductSafetyError::invalid(
                "invalid_cyber_source_type",
                "Unbekannter Cyber-Quelltyp.",
            ))
        }
    };
    let statement = if product_bound {
        format!("SELECT COUNT(*) AS count FROM {table} WHERE tenant_id=? AND id=? AND product_id=?")
    } else {
        format!("SELECT COUNT(*) AS count FROM {table} WHERE tenant_id=? AND id=?")
    };
    let mut query = sqlx::query(&statement)
        .bind(tenant_id)
        .bind(source.source_id);
    if product_bound {
        query = query.bind(product_id);
    }
    let count: i64 = query
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| ProductSafetyError::database())?
        .try_get("count")
        .map_err(|_| ProductSafetyError::database())?;
    if count != 1 {
        return Err(ProductSafetyError::not_found());
    }
    if source.source_type == "THREAT_SCENARIO" {
        let count: i64 = sqlx::query("SELECT COUNT(*) AS count FROM product_security_threatscenario s JOIN product_security_threatmodel m ON m.tenant_id=s.tenant_id AND m.id=s.threat_model_id WHERE s.tenant_id=? AND s.id=? AND m.product_id=?")
            .bind(tenant_id).bind(source.source_id).bind(product_id).fetch_one(&mut **tx).await.map_err(|_| ProductSafetyError::database())?.try_get("count").map_err(|_| ProductSafetyError::database())?;
        if count != 1 {
            return Err(ProductSafetyError::not_found());
        }
    }
    Ok(())
}

async fn link_evidence_pg(
    pool: &PgPool,
    tenant_id: i64,
    product_id: i64,
    actor_id: i64,
    request: SafetyEvidenceLinkRequest,
    target_type: &'static str,
) -> Result<SafetyEvidenceLink, ProductSafetyError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    validate_actor_pg(&mut tx, tenant_id, actor_id).await?;
    validate_product_pg(&mut tx, tenant_id, product_id).await?;
    validate_relation_pg(
        &mut tx,
        "evidence_evidenceitem",
        tenant_id,
        request.evidence_id,
    )
    .await?;
    validate_evidence_target_pg(
        &mut tx,
        tenant_id,
        product_id,
        target_type,
        request.target_id,
    )
    .await?;
    let column = evidence_target_column(target_type);
    let target_key = format!("{target_type}:{}", request.target_id);
    let insert = format!(
        "INSERT INTO product_safety_evidence_link (tenant_id,evidence_id,{column},target_key,linked_by_id) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (tenant_id,evidence_id,target_key) DO NOTHING RETURNING id"
    );
    let inserted: Option<i64> = sqlx::query(&insert)
        .bind(tenant_id)
        .bind(request.evidence_id)
        .bind(request.target_id)
        .bind(&target_key)
        .bind(actor_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ProductSafetyError::database())?
        .map(|row| row.try_get("id"))
        .transpose()
        .map_err(|_| ProductSafetyError::database())?;
    let created = inserted.is_some();
    let link_id = match inserted {
        Some(id) => id,
        None => sqlx::query("SELECT id FROM product_safety_evidence_link WHERE tenant_id=$1 AND evidence_id=$2 AND target_key=$3")
            .bind(tenant_id).bind(request.evidence_id).bind(&target_key).fetch_one(&mut *tx).await
            .map_err(|_| ProductSafetyError::database())?.try_get("id").map_err(|_| ProductSafetyError::database())?,
    };
    if created {
        insert_audit_pg(
            &mut tx,
            tenant_id,
            actor_id,
            "EVIDENCE_LINK",
            link_id,
            "evidence_linked",
            1,
            "LINKED",
            &json!({"evidence_id": request.evidence_id, "target_type": target_type, "target_id": request.target_id}),
        )
        .await?;
    }
    tx.commit()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    Ok(SafetyEvidenceLink {
        id: link_id,
        evidence_id: request.evidence_id,
        target_type: target_type.to_string(),
        target_id: request.target_id,
        created,
    })
}

async fn link_evidence_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    product_id: i64,
    actor_id: i64,
    request: SafetyEvidenceLinkRequest,
    target_type: &'static str,
) -> Result<SafetyEvidenceLink, ProductSafetyError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    validate_actor_sqlite(&mut tx, tenant_id, actor_id).await?;
    validate_product_sqlite(&mut tx, tenant_id, product_id).await?;
    validate_relation_sqlite(
        &mut tx,
        "evidence_evidenceitem",
        tenant_id,
        request.evidence_id,
    )
    .await?;
    validate_evidence_target_sqlite(
        &mut tx,
        tenant_id,
        product_id,
        target_type,
        request.target_id,
    )
    .await?;
    let column = evidence_target_column(target_type);
    let target_key = format!("{target_type}:{}", request.target_id);
    let insert = format!(
        "INSERT OR IGNORE INTO product_safety_evidence_link (tenant_id,evidence_id,{column},target_key,linked_by_id) VALUES (?,?,?,?,?)"
    );
    let created = sqlx::query(&insert)
        .bind(tenant_id)
        .bind(request.evidence_id)
        .bind(request.target_id)
        .bind(&target_key)
        .bind(actor_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| ProductSafetyError::database())?
        .rows_affected()
        == 1;
    let link_id: i64 = sqlx::query("SELECT id FROM product_safety_evidence_link WHERE tenant_id=? AND evidence_id=? AND target_key=?")
        .bind(tenant_id).bind(request.evidence_id).bind(&target_key).fetch_one(&mut *tx).await
        .map_err(|_| ProductSafetyError::database())?.try_get("id").map_err(|_| ProductSafetyError::database())?;
    if created {
        insert_audit_sqlite(
            &mut tx,
            tenant_id,
            actor_id,
            "EVIDENCE_LINK",
            link_id,
            "evidence_linked",
            1,
            "LINKED",
            &json!({"evidence_id": request.evidence_id, "target_type": target_type, "target_id": request.target_id}),
        )
        .await?;
    }
    tx.commit()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    Ok(SafetyEvidenceLink {
        id: link_id,
        evidence_id: request.evidence_id,
        target_type: target_type.to_string(),
        target_id: request.target_id,
        created,
    })
}

async fn unlink_evidence_pg(
    pool: &PgPool,
    tenant_id: i64,
    product_id: i64,
    actor_id: i64,
    request: SafetyEvidenceLinkRequest,
    target_type: &'static str,
) -> Result<(), ProductSafetyError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    validate_actor_pg(&mut tx, tenant_id, actor_id).await?;
    validate_product_pg(&mut tx, tenant_id, product_id).await?;
    validate_evidence_target_pg(
        &mut tx,
        tenant_id,
        product_id,
        target_type,
        request.target_id,
    )
    .await?;
    let target_key = format!("{target_type}:{}", request.target_id);
    let link_id: Option<i64> = sqlx::query("SELECT id FROM product_safety_evidence_link WHERE tenant_id=$1 AND evidence_id=$2 AND target_key=$3 FOR UPDATE")
        .bind(tenant_id).bind(request.evidence_id).bind(&target_key).fetch_optional(&mut *tx).await
        .map_err(|_| ProductSafetyError::database())?.map(|row| row.try_get("id")).transpose().map_err(|_| ProductSafetyError::database())?;
    let Some(link_id) = link_id else {
        return Err(ProductSafetyError::not_found());
    };
    sqlx::query("DELETE FROM product_safety_evidence_link WHERE tenant_id=$1 AND id=$2")
        .bind(tenant_id)
        .bind(link_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| ProductSafetyError::database())?;
    insert_audit_pg(&mut tx, tenant_id, actor_id, "EVIDENCE_LINK", link_id, "evidence_unlinked", 1, "UNLINKED", &json!({"evidence_id": request.evidence_id, "target_type": target_type, "target_id": request.target_id})).await?;
    tx.commit()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    Ok(())
}

async fn unlink_evidence_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    product_id: i64,
    actor_id: i64,
    request: SafetyEvidenceLinkRequest,
    target_type: &'static str,
) -> Result<(), ProductSafetyError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    validate_actor_sqlite(&mut tx, tenant_id, actor_id).await?;
    validate_product_sqlite(&mut tx, tenant_id, product_id).await?;
    validate_evidence_target_sqlite(
        &mut tx,
        tenant_id,
        product_id,
        target_type,
        request.target_id,
    )
    .await?;
    let target_key = format!("{target_type}:{}", request.target_id);
    let link_id: Option<i64> = sqlx::query("SELECT id FROM product_safety_evidence_link WHERE tenant_id=? AND evidence_id=? AND target_key=?")
        .bind(tenant_id).bind(request.evidence_id).bind(&target_key).fetch_optional(&mut *tx).await
        .map_err(|_| ProductSafetyError::database())?.map(|row| row.try_get("id")).transpose().map_err(|_| ProductSafetyError::database())?;
    let Some(link_id) = link_id else {
        return Err(ProductSafetyError::not_found());
    };
    sqlx::query("DELETE FROM product_safety_evidence_link WHERE tenant_id=? AND id=?")
        .bind(tenant_id)
        .bind(link_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| ProductSafetyError::database())?;
    insert_audit_sqlite(&mut tx, tenant_id, actor_id, "EVIDENCE_LINK", link_id, "evidence_unlinked", 1, "UNLINKED", &json!({"evidence_id": request.evidence_id, "target_type": target_type, "target_id": request.target_id})).await?;
    tx.commit()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "the explicit audit tuple keeps every security-relevant field visible at each transactional call site"
)]
async fn insert_audit_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    actor_id: i64,
    object_type: &str,
    object_id: i64,
    event_type: &str,
    revision: i64,
    new_state: &str,
    detail: &serde_json::Value,
) -> Result<(), ProductSafetyError> {
    let detail = serde_json::to_string(detail).map_err(|_| ProductSafetyError::database())?;
    sqlx::query("INSERT INTO product_safety_audit_event (tenant_id,object_type,object_id,event_type,actor_id,new_state,revision,detail_json) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(tenant_id).bind(object_type).bind(object_id).bind(event_type).bind(actor_id).bind(new_state).bind(revision).bind(detail)
        .execute(&mut **tx).await.map_err(|_| ProductSafetyError::database())?;
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "the explicit audit tuple keeps every security-relevant field visible at each transactional call site"
)]
async fn insert_audit_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    actor_id: i64,
    object_type: &str,
    object_id: i64,
    event_type: &str,
    revision: i64,
    new_state: &str,
    detail: &serde_json::Value,
) -> Result<(), ProductSafetyError> {
    let detail = serde_json::to_string(detail).map_err(|_| ProductSafetyError::database())?;
    sqlx::query("INSERT INTO product_safety_audit_event (tenant_id,object_type,object_id,event_type,actor_id,new_state,revision,detail_json) VALUES (?,?,?,?,?,?,?,?)")
        .bind(tenant_id).bind(object_type).bind(object_id).bind(event_type).bind(actor_id).bind(new_state).bind(revision).bind(detail)
        .execute(&mut **tx).await.map_err(|_| ProductSafetyError::database())?;
    Ok(())
}

async fn applicability_by_act_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    product_id: i64,
    legal_act: &str,
    for_update: bool,
) -> Result<Option<RegulatoryApplicability>, ProductSafetyError> {
    let suffix = if for_update { " FOR UPDATE" } else { "" };
    let statement = format!("SELECT * FROM product_regulatory_applicability WHERE tenant_id=$1 AND product_id=$2 AND legal_act=$3{suffix}");
    sqlx::query(&statement)
        .bind(tenant_id)
        .bind(product_id)
        .bind(legal_act)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| ProductSafetyError::database())?
        .map(applicability_from_pg_row)
        .transpose()
        .map_err(|_| ProductSafetyError::database())
}

async fn applicability_by_act_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    product_id: i64,
    legal_act: &str,
) -> Result<Option<RegulatoryApplicability>, ProductSafetyError> {
    sqlx::query("SELECT * FROM product_regulatory_applicability WHERE tenant_id=? AND product_id=? AND legal_act=?").bind(tenant_id).bind(product_id).bind(legal_act).fetch_optional(&mut **tx).await.map_err(|_| ProductSafetyError::database())?.map(applicability_from_sqlite_row).transpose().map_err(|_| ProductSafetyError::database())
}

async fn insert_applicability_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    product_id: i64,
    actor_id: i64,
    normalized: &NormalizedApplicability,
) -> Result<RegulatoryApplicability, ProductSafetyError> {
    let timestamp = now();
    sqlx::query("INSERT INTO product_regulatory_applicability (tenant_id,product_id,legal_act,applicability_status,product_role,reasoning,assessed_by_id,assessed_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8) RETURNING *")
        .bind(tenant_id).bind(product_id).bind(&normalized.legal_act).bind(&normalized.status).bind(&normalized.product_role).bind(&normalized.reasoning).bind(actor_id).bind(timestamp)
        .fetch_one(&mut **tx).await.map_err(|_| ProductSafetyError::database()).and_then(|row| applicability_from_pg_row(row).map_err(|_| ProductSafetyError::database()))
}

async fn insert_applicability_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    product_id: i64,
    actor_id: i64,
    normalized: &NormalizedApplicability,
) -> Result<RegulatoryApplicability, ProductSafetyError> {
    let timestamp = now();
    sqlx::query("INSERT INTO product_regulatory_applicability (tenant_id,product_id,legal_act,applicability_status,product_role,reasoning,assessed_by_id,assessed_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?) RETURNING *")
        .bind(tenant_id).bind(product_id).bind(&normalized.legal_act).bind(&normalized.status).bind(&normalized.product_role).bind(&normalized.reasoning).bind(actor_id).bind(&timestamp).bind(&timestamp)
        .fetch_one(&mut **tx).await.map_err(|_| ProductSafetyError::database()).and_then(|row| applicability_from_sqlite_row(row).map_err(|_| ProductSafetyError::database()))
}

async fn update_applicability_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    product_id: i64,
    actor_id: i64,
    normalized: &NormalizedApplicability,
    expected: i64,
) -> Result<RegulatoryApplicability, ProductSafetyError> {
    let timestamp = now();
    sqlx::query("UPDATE product_regulatory_applicability SET applicability_status=$1,product_role=$2,reasoning=$3,assessed_by_id=$4,assessed_at=$5,reviewed_at=$5,revision=revision+1,updated_at=$5 WHERE tenant_id=$6 AND product_id=$7 AND legal_act=$8 AND revision=$9 RETURNING *")
        .bind(&normalized.status).bind(&normalized.product_role).bind(&normalized.reasoning).bind(actor_id).bind(timestamp).bind(tenant_id).bind(product_id).bind(&normalized.legal_act).bind(expected)
        .fetch_optional(&mut **tx).await.map_err(|_| ProductSafetyError::database())?.map(applicability_from_pg_row).transpose().map_err(|_| ProductSafetyError::database())?.ok_or_else(stale_revision)
}

async fn update_applicability_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    product_id: i64,
    actor_id: i64,
    normalized: &NormalizedApplicability,
    expected: i64,
) -> Result<RegulatoryApplicability, ProductSafetyError> {
    let timestamp = now();
    sqlx::query("UPDATE product_regulatory_applicability SET applicability_status=?,product_role=?,reasoning=?,assessed_by_id=?,assessed_at=?,reviewed_at=?,revision=revision+1,updated_at=? WHERE tenant_id=? AND product_id=? AND legal_act=? AND revision=? RETURNING *")
        .bind(&normalized.status).bind(&normalized.product_role).bind(&normalized.reasoning).bind(actor_id).bind(&timestamp).bind(&timestamp).bind(&timestamp).bind(tenant_id).bind(product_id).bind(&normalized.legal_act).bind(expected)
        .fetch_optional(&mut **tx).await.map_err(|_| ProductSafetyError::database())?.map(applicability_from_sqlite_row).transpose().map_err(|_| ProductSafetyError::database())?.ok_or_else(stale_revision)
}

async fn upsert_profile_pg(
    pool: &PgPool,
    tenant_id: i64,
    product_id: i64,
    actor_id: i64,
    request: &MachineryProfileWriteRequest,
) -> Result<MachineryProductProfile, ProductSafetyError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    validate_actor_pg(&mut tx, tenant_id, actor_id).await?;
    validate_product_pg(&mut tx, tenant_id, product_id).await?;
    let current = sqlx::query(
        "SELECT * FROM machinery_product_profile WHERE tenant_id=$1 AND product_id=$2 FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(product_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| ProductSafetyError::database())?
    .map(profile_from_pg_row)
    .transpose()
    .map_err(|_| ProductSafetyError::database())?;
    let timestamp = now();
    let profile = if let Some(current) = current {
        let expected = request.expected_revision.ok_or_else(stale_revision)?;
        if current.revision != expected {
            return Err(stale_revision());
        }
        sqlx::query("UPDATE machinery_product_profile SET product_role=$1,intended_purpose=$2,reasonably_foreseeable_use=$3,reasonably_foreseeable_misuse=$4,operational_environment=$5,lifecycle_phase=$6,human_interaction=$7,network_connectivity_context=$8,remote_access_context=$9,safety_related_software_present=$10,programmable_control_system_present=$11,external_communication_interfaces_present=$12,updated_by_id=$13,revision=revision+1,updated_at=$14 WHERE tenant_id=$15 AND product_id=$16 AND revision=$17 RETURNING *")
            .bind(&request.product_role).bind(&request.intended_purpose).bind(request.reasonably_foreseeable_use.as_deref().unwrap_or_default()).bind(request.reasonably_foreseeable_misuse.as_deref().unwrap_or_default()).bind(request.operational_environment.as_deref().unwrap_or_default()).bind(&request.lifecycle_phase).bind(request.human_interaction.as_deref().unwrap_or_default()).bind(request.network_connectivity_context.as_deref().unwrap_or_default()).bind(request.remote_access_context.as_deref().unwrap_or_default()).bind(request.safety_related_software_present).bind(request.programmable_control_system_present).bind(request.external_communication_interfaces_present).bind(actor_id).bind(timestamp).bind(tenant_id).bind(product_id).bind(expected)
            .fetch_optional(&mut *tx).await.map_err(|_| ProductSafetyError::database())?.map(profile_from_pg_row).transpose().map_err(|_| ProductSafetyError::database())?.ok_or_else(stale_revision)?
    } else {
        if request.expected_revision.is_some() {
            return Err(stale_revision());
        }
        sqlx::query("INSERT INTO machinery_product_profile (tenant_id,product_id,product_role,intended_purpose,reasonably_foreseeable_use,reasonably_foreseeable_misuse,operational_environment,lifecycle_phase,human_interaction,network_connectivity_context,remote_access_context,safety_related_software_present,programmable_control_system_present,external_communication_interfaces_present,updated_by_id,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING *")
            .bind(tenant_id).bind(product_id).bind(&request.product_role).bind(&request.intended_purpose).bind(request.reasonably_foreseeable_use.as_deref().unwrap_or_default()).bind(request.reasonably_foreseeable_misuse.as_deref().unwrap_or_default()).bind(request.operational_environment.as_deref().unwrap_or_default()).bind(&request.lifecycle_phase).bind(request.human_interaction.as_deref().unwrap_or_default()).bind(request.network_connectivity_context.as_deref().unwrap_or_default()).bind(request.remote_access_context.as_deref().unwrap_or_default()).bind(request.safety_related_software_present).bind(request.programmable_control_system_present).bind(request.external_communication_interfaces_present).bind(actor_id).bind(timestamp)
            .fetch_one(&mut *tx).await.map_err(|_| ProductSafetyError::database()).and_then(|row| profile_from_pg_row(row).map_err(|_| ProductSafetyError::database()))?
    };
    insert_audit_pg(
        &mut tx,
        tenant_id,
        actor_id,
        "PROFILE",
        profile.id,
        "machinery_profile_changed",
        profile.revision,
        &profile.product_role,
        &json!({"product_id": product_id}),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    Ok(profile)
}

async fn upsert_profile_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    product_id: i64,
    actor_id: i64,
    request: &MachineryProfileWriteRequest,
) -> Result<MachineryProductProfile, ProductSafetyError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    validate_actor_sqlite(&mut tx, tenant_id, actor_id).await?;
    validate_product_sqlite(&mut tx, tenant_id, product_id).await?;
    let current =
        sqlx::query("SELECT * FROM machinery_product_profile WHERE tenant_id=? AND product_id=?")
            .bind(tenant_id)
            .bind(product_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| ProductSafetyError::database())?
            .map(profile_from_sqlite_row)
            .transpose()
            .map_err(|_| ProductSafetyError::database())?;
    let timestamp = now();
    let profile = if let Some(current) = current {
        let expected = request.expected_revision.ok_or_else(stale_revision)?;
        if current.revision != expected {
            return Err(stale_revision());
        }
        sqlx::query("UPDATE machinery_product_profile SET product_role=?,intended_purpose=?,reasonably_foreseeable_use=?,reasonably_foreseeable_misuse=?,operational_environment=?,lifecycle_phase=?,human_interaction=?,network_connectivity_context=?,remote_access_context=?,safety_related_software_present=?,programmable_control_system_present=?,external_communication_interfaces_present=?,updated_by_id=?,revision=revision+1,updated_at=? WHERE tenant_id=? AND product_id=? AND revision=? RETURNING *")
            .bind(&request.product_role).bind(&request.intended_purpose).bind(request.reasonably_foreseeable_use.as_deref().unwrap_or_default()).bind(request.reasonably_foreseeable_misuse.as_deref().unwrap_or_default()).bind(request.operational_environment.as_deref().unwrap_or_default()).bind(&request.lifecycle_phase).bind(request.human_interaction.as_deref().unwrap_or_default()).bind(request.network_connectivity_context.as_deref().unwrap_or_default()).bind(request.remote_access_context.as_deref().unwrap_or_default()).bind(request.safety_related_software_present).bind(request.programmable_control_system_present).bind(request.external_communication_interfaces_present).bind(actor_id).bind(timestamp).bind(tenant_id).bind(product_id).bind(expected)
            .fetch_optional(&mut *tx).await.map_err(|_| ProductSafetyError::database())?.map(profile_from_sqlite_row).transpose().map_err(|_| ProductSafetyError::database())?.ok_or_else(stale_revision)?
    } else {
        if request.expected_revision.is_some() {
            return Err(stale_revision());
        }
        sqlx::query("INSERT INTO machinery_product_profile (tenant_id,product_id,product_role,intended_purpose,reasonably_foreseeable_use,reasonably_foreseeable_misuse,operational_environment,lifecycle_phase,human_interaction,network_connectivity_context,remote_access_context,safety_related_software_present,programmable_control_system_present,external_communication_interfaces_present,updated_by_id,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING *")
            .bind(tenant_id).bind(product_id).bind(&request.product_role).bind(&request.intended_purpose).bind(request.reasonably_foreseeable_use.as_deref().unwrap_or_default()).bind(request.reasonably_foreseeable_misuse.as_deref().unwrap_or_default()).bind(request.operational_environment.as_deref().unwrap_or_default()).bind(&request.lifecycle_phase).bind(request.human_interaction.as_deref().unwrap_or_default()).bind(request.network_connectivity_context.as_deref().unwrap_or_default()).bind(request.remote_access_context.as_deref().unwrap_or_default()).bind(request.safety_related_software_present).bind(request.programmable_control_system_present).bind(request.external_communication_interfaces_present).bind(actor_id).bind(timestamp)
            .fetch_one(&mut *tx).await.map_err(|_| ProductSafetyError::database()).and_then(|row| profile_from_sqlite_row(row).map_err(|_| ProductSafetyError::database()))?
    };
    insert_audit_sqlite(
        &mut tx,
        tenant_id,
        actor_id,
        "PROFILE",
        profile.id,
        "machinery_profile_changed",
        profile.revision,
        &profile.product_role,
        &json!({"product_id": product_id}),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    Ok(profile)
}

fn same_function(existing: &SafetyFunction, normalized: &NormalizedFunction) -> bool {
    existing.name == normalized.name
        && existing.description == normalized.description
        && existing.function_identifier == normalized.identifier
        && existing.criticality == normalized.criticality
        && existing.status == normalized.status
        && existing.owner_id == normalized.owner_id
}

async fn create_function_pg(
    pool: &PgPool,
    tenant_id: i64,
    product_id: i64,
    actor_id: i64,
    normalized: &NormalizedFunction,
) -> Result<SafetyFunctionWriteResult, ProductSafetyError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    validate_actor_pg(&mut tx, tenant_id, actor_id).await?;
    validate_product_pg(&mut tx, tenant_id, product_id).await?;
    validate_owner_pg(&mut tx, tenant_id, normalized.owner_id).await?;
    if let Some(existing) = sqlx::query("SELECT * FROM product_safety_function WHERE tenant_id=$1 AND product_id=$2 AND function_identifier=$3 FOR UPDATE")
        .bind(tenant_id).bind(product_id).bind(&normalized.identifier).fetch_optional(&mut *tx).await.map_err(|_| ProductSafetyError::database())?.map(function_from_pg_row).transpose().map_err(|_| ProductSafetyError::database())? {
        if !same_function(&existing, normalized) { return Err(ProductSafetyError::conflict("duplicate_safety_function", "Die Function-ID ist bereits mit abweichenden Daten vergeben.")); }
        tx.commit().await.map_err(|_| ProductSafetyError::database())?;
        return Ok(SafetyFunctionWriteResult { created: false, safety_function: existing });
    }
    let timestamp = now();
    let function = sqlx::query("INSERT INTO product_safety_function (tenant_id,product_id,name,description,function_identifier,criticality,status,owner_id,created_by_id,updated_by_id,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$10) RETURNING *")
        .bind(tenant_id).bind(product_id).bind(&normalized.name).bind(&normalized.description).bind(&normalized.identifier).bind(&normalized.criticality).bind(&normalized.status).bind(normalized.owner_id).bind(actor_id).bind(timestamp)
        .fetch_one(&mut *tx).await.map_err(|_| ProductSafetyError::database()).and_then(|row| function_from_pg_row(row).map_err(|_| ProductSafetyError::database()))?;
    insert_audit_pg(
        &mut tx,
        tenant_id,
        actor_id,
        "SAFETY_FUNCTION",
        function.id,
        "safety_function_created",
        function.revision,
        &function.status,
        &json!({"product_id": product_id, "function_identifier": function.function_identifier}),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    Ok(SafetyFunctionWriteResult {
        created: true,
        safety_function: function,
    })
}

async fn create_function_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    product_id: i64,
    actor_id: i64,
    normalized: &NormalizedFunction,
) -> Result<SafetyFunctionWriteResult, ProductSafetyError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    validate_actor_sqlite(&mut tx, tenant_id, actor_id).await?;
    validate_product_sqlite(&mut tx, tenant_id, product_id).await?;
    validate_owner_sqlite(&mut tx, tenant_id, normalized.owner_id).await?;
    if let Some(existing) = sqlx::query("SELECT * FROM product_safety_function WHERE tenant_id=? AND product_id=? AND function_identifier=?")
        .bind(tenant_id).bind(product_id).bind(&normalized.identifier).fetch_optional(&mut *tx).await.map_err(|_| ProductSafetyError::database())?.map(function_from_sqlite_row).transpose().map_err(|_| ProductSafetyError::database())? {
        if !same_function(&existing, normalized) { return Err(ProductSafetyError::conflict("duplicate_safety_function", "Die Function-ID ist bereits mit abweichenden Daten vergeben.")); }
        tx.commit().await.map_err(|_| ProductSafetyError::database())?;
        return Ok(SafetyFunctionWriteResult { created: false, safety_function: existing });
    }
    let timestamp = now();
    let function = sqlx::query("INSERT INTO product_safety_function (tenant_id,product_id,name,description,function_identifier,criticality,status,owner_id,created_by_id,updated_by_id,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?) RETURNING *")
        .bind(tenant_id).bind(product_id).bind(&normalized.name).bind(&normalized.description).bind(&normalized.identifier).bind(&normalized.criticality).bind(&normalized.status).bind(normalized.owner_id).bind(actor_id).bind(actor_id).bind(timestamp)
        .fetch_one(&mut *tx).await.map_err(|_| ProductSafetyError::database()).and_then(|row| function_from_sqlite_row(row).map_err(|_| ProductSafetyError::database()))?;
    insert_audit_sqlite(
        &mut tx,
        tenant_id,
        actor_id,
        "SAFETY_FUNCTION",
        function.id,
        "safety_function_created",
        function.revision,
        &function.status,
        &json!({"product_id": product_id, "function_identifier": function.function_identifier}),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    Ok(SafetyFunctionWriteResult {
        created: true,
        safety_function: function,
    })
}

async fn update_function_pg(
    pool: &PgPool,
    tenant_id: i64,
    function_id: i64,
    actor_id: i64,
    normalized: &NormalizedFunction,
) -> Result<SafetyFunction, ProductSafetyError> {
    let expected = normalized.expected_revision.ok_or_else(stale_revision)?;
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    validate_actor_pg(&mut tx, tenant_id, actor_id).await?;
    validate_owner_pg(&mut tx, tenant_id, normalized.owner_id).await?;
    let current = sqlx::query(
        "SELECT * FROM product_safety_function WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(function_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| ProductSafetyError::database())?
    .map(function_from_pg_row)
    .transpose()
    .map_err(|_| ProductSafetyError::database())?
    .ok_or_else(ProductSafetyError::not_found)?;
    if current.revision != expected {
        return Err(stale_revision());
    }
    let updated = sqlx::query("UPDATE product_safety_function SET name=$1,description=$2,function_identifier=$3,criticality=$4,status=$5,owner_id=$6,updated_by_id=$7,revision=revision+1,updated_at=$8 WHERE tenant_id=$9 AND id=$10 AND revision=$11 RETURNING *")
        .bind(&normalized.name).bind(&normalized.description).bind(&normalized.identifier).bind(&normalized.criticality).bind(&normalized.status).bind(normalized.owner_id).bind(actor_id).bind(now()).bind(tenant_id).bind(function_id).bind(expected)
        .fetch_optional(&mut *tx).await.map_err(|_| ProductSafetyError::database())?.map(function_from_pg_row).transpose().map_err(|_| ProductSafetyError::database())?.ok_or_else(stale_revision)?;
    insert_audit_pg(
        &mut tx,
        tenant_id,
        actor_id,
        "SAFETY_FUNCTION",
        function_id,
        if updated.status == "ARCHIVED" {
            "safety_function_archived"
        } else {
            "safety_function_changed"
        },
        updated.revision,
        &updated.status,
        &json!({"product_id": updated.product_id}),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    Ok(updated)
}

async fn update_function_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    function_id: i64,
    actor_id: i64,
    normalized: &NormalizedFunction,
) -> Result<SafetyFunction, ProductSafetyError> {
    let expected = normalized.expected_revision.ok_or_else(stale_revision)?;
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    validate_actor_sqlite(&mut tx, tenant_id, actor_id).await?;
    validate_owner_sqlite(&mut tx, tenant_id, normalized.owner_id).await?;
    let current = sqlx::query("SELECT * FROM product_safety_function WHERE tenant_id=? AND id=?")
        .bind(tenant_id)
        .bind(function_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ProductSafetyError::database())?
        .map(function_from_sqlite_row)
        .transpose()
        .map_err(|_| ProductSafetyError::database())?
        .ok_or_else(ProductSafetyError::not_found)?;
    if current.revision != expected {
        return Err(stale_revision());
    }
    let updated = sqlx::query("UPDATE product_safety_function SET name=?,description=?,function_identifier=?,criticality=?,status=?,owner_id=?,updated_by_id=?,revision=revision+1,updated_at=? WHERE tenant_id=? AND id=? AND revision=? RETURNING *")
        .bind(&normalized.name).bind(&normalized.description).bind(&normalized.identifier).bind(&normalized.criticality).bind(&normalized.status).bind(normalized.owner_id).bind(actor_id).bind(now()).bind(tenant_id).bind(function_id).bind(expected)
        .fetch_optional(&mut *tx).await.map_err(|_| ProductSafetyError::database())?.map(function_from_sqlite_row).transpose().map_err(|_| ProductSafetyError::database())?.ok_or_else(stale_revision)?;
    insert_audit_sqlite(
        &mut tx,
        tenant_id,
        actor_id,
        "SAFETY_FUNCTION",
        function_id,
        if updated.status == "ARCHIVED" {
            "safety_function_archived"
        } else {
            "safety_function_changed"
        },
        updated.revision,
        &updated.status,
        &json!({"product_id": updated.product_id}),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    Ok(updated)
}

async fn create_hazard_pg(
    pool: &PgPool,
    tenant_id: i64,
    product_id: i64,
    actor_id: i64,
    normalized: &NormalizedHazard,
) -> Result<SafetyHazard, ProductSafetyError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    validate_actor_pg(&mut tx, tenant_id, actor_id).await?;
    validate_product_pg(&mut tx, tenant_id, product_id).await?;
    validate_owner_pg(&mut tx, tenant_id, normalized.owner_id).await?;
    validate_function_for_product_pg(&mut tx, tenant_id, product_id, normalized.function_id)
        .await?;
    let hazard = sqlx::query("INSERT INTO product_safety_hazard (tenant_id,product_id,title,description,hazard_category,affected_safety_function_id,operational_phase,potential_consequence,risk_estimation_method,initial_risk,residual_risk,status,owner_id,created_by_id,updated_by_id,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14,$15) RETURNING *")
        .bind(tenant_id).bind(product_id).bind(&normalized.title).bind(&normalized.description).bind(&normalized.category).bind(normalized.function_id).bind(&normalized.operational_phase).bind(&normalized.consequence).bind(&normalized.method).bind(&normalized.initial_risk).bind(&normalized.residual_risk).bind(&normalized.status).bind(normalized.owner_id).bind(actor_id).bind(now())
        .fetch_one(&mut *tx).await.map_err(|_| ProductSafetyError::database()).and_then(|row| hazard_from_pg_row(row).map_err(|_| ProductSafetyError::database()))?;
    insert_audit_pg(&mut tx, tenant_id, actor_id, "HAZARD", hazard.id, "hazard_created", hazard.revision, &hazard.status, &json!({"product_id": product_id, "safety_function_id": hazard.affected_safety_function_id})).await?;
    tx.commit()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    Ok(hazard)
}

async fn create_hazard_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    product_id: i64,
    actor_id: i64,
    normalized: &NormalizedHazard,
) -> Result<SafetyHazard, ProductSafetyError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    validate_actor_sqlite(&mut tx, tenant_id, actor_id).await?;
    validate_product_sqlite(&mut tx, tenant_id, product_id).await?;
    validate_owner_sqlite(&mut tx, tenant_id, normalized.owner_id).await?;
    validate_function_for_product_sqlite(&mut tx, tenant_id, product_id, normalized.function_id)
        .await?;
    let hazard = sqlx::query("INSERT INTO product_safety_hazard (tenant_id,product_id,title,description,hazard_category,affected_safety_function_id,operational_phase,potential_consequence,risk_estimation_method,initial_risk,residual_risk,status,owner_id,created_by_id,updated_by_id,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING *")
        .bind(tenant_id).bind(product_id).bind(&normalized.title).bind(&normalized.description).bind(&normalized.category).bind(normalized.function_id).bind(&normalized.operational_phase).bind(&normalized.consequence).bind(&normalized.method).bind(&normalized.initial_risk).bind(&normalized.residual_risk).bind(&normalized.status).bind(normalized.owner_id).bind(actor_id).bind(actor_id).bind(now())
        .fetch_one(&mut *tx).await.map_err(|_| ProductSafetyError::database()).and_then(|row| hazard_from_sqlite_row(row).map_err(|_| ProductSafetyError::database()))?;
    insert_audit_sqlite(&mut tx, tenant_id, actor_id, "HAZARD", hazard.id, "hazard_created", hazard.revision, &hazard.status, &json!({"product_id": product_id, "safety_function_id": hazard.affected_safety_function_id})).await?;
    tx.commit()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    Ok(hazard)
}

async fn update_hazard_pg(
    pool: &PgPool,
    tenant_id: i64,
    hazard_id: i64,
    actor_id: i64,
    normalized: &NormalizedHazard,
) -> Result<SafetyHazard, ProductSafetyError> {
    let expected = normalized.expected_revision.ok_or_else(stale_revision)?;
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    validate_actor_pg(&mut tx, tenant_id, actor_id).await?;
    validate_owner_pg(&mut tx, tenant_id, normalized.owner_id).await?;
    let current =
        sqlx::query("SELECT * FROM product_safety_hazard WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
            .bind(tenant_id)
            .bind(hazard_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| ProductSafetyError::database())?
            .map(hazard_from_pg_row)
            .transpose()
            .map_err(|_| ProductSafetyError::database())?
            .ok_or_else(ProductSafetyError::not_found)?;
    if current.revision != expected {
        return Err(stale_revision());
    }
    validate_function_for_product_pg(
        &mut tx,
        tenant_id,
        current.product_id,
        normalized.function_id,
    )
    .await?;
    let updated = sqlx::query("UPDATE product_safety_hazard SET title=$1,description=$2,hazard_category=$3,affected_safety_function_id=$4,operational_phase=$5,potential_consequence=$6,risk_estimation_method=$7,initial_risk=$8,residual_risk=$9,status=$10,owner_id=$11,updated_by_id=$12,revision=revision+1,updated_at=$13 WHERE tenant_id=$14 AND id=$15 AND revision=$16 RETURNING *")
        .bind(&normalized.title).bind(&normalized.description).bind(&normalized.category).bind(normalized.function_id).bind(&normalized.operational_phase).bind(&normalized.consequence).bind(&normalized.method).bind(&normalized.initial_risk).bind(&normalized.residual_risk).bind(&normalized.status).bind(normalized.owner_id).bind(actor_id).bind(now()).bind(tenant_id).bind(hazard_id).bind(expected)
        .fetch_optional(&mut *tx).await.map_err(|_| ProductSafetyError::database())?.map(hazard_from_pg_row).transpose().map_err(|_| ProductSafetyError::database())?.ok_or_else(stale_revision)?;
    insert_audit_pg(
        &mut tx,
        tenant_id,
        actor_id,
        "HAZARD",
        hazard_id,
        "hazard_changed",
        updated.revision,
        &updated.status,
        &json!({"product_id": updated.product_id}),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    Ok(updated)
}

async fn update_hazard_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    hazard_id: i64,
    actor_id: i64,
    normalized: &NormalizedHazard,
) -> Result<SafetyHazard, ProductSafetyError> {
    let expected = normalized.expected_revision.ok_or_else(stale_revision)?;
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    validate_actor_sqlite(&mut tx, tenant_id, actor_id).await?;
    validate_owner_sqlite(&mut tx, tenant_id, normalized.owner_id).await?;
    let current = sqlx::query("SELECT * FROM product_safety_hazard WHERE tenant_id=? AND id=?")
        .bind(tenant_id)
        .bind(hazard_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ProductSafetyError::database())?
        .map(hazard_from_sqlite_row)
        .transpose()
        .map_err(|_| ProductSafetyError::database())?
        .ok_or_else(ProductSafetyError::not_found)?;
    if current.revision != expected {
        return Err(stale_revision());
    }
    validate_function_for_product_sqlite(
        &mut tx,
        tenant_id,
        current.product_id,
        normalized.function_id,
    )
    .await?;
    let updated = sqlx::query("UPDATE product_safety_hazard SET title=?,description=?,hazard_category=?,affected_safety_function_id=?,operational_phase=?,potential_consequence=?,risk_estimation_method=?,initial_risk=?,residual_risk=?,status=?,owner_id=?,updated_by_id=?,revision=revision+1,updated_at=? WHERE tenant_id=? AND id=? AND revision=? RETURNING *")
        .bind(&normalized.title).bind(&normalized.description).bind(&normalized.category).bind(normalized.function_id).bind(&normalized.operational_phase).bind(&normalized.consequence).bind(&normalized.method).bind(&normalized.initial_risk).bind(&normalized.residual_risk).bind(&normalized.status).bind(normalized.owner_id).bind(actor_id).bind(now()).bind(tenant_id).bind(hazard_id).bind(expected)
        .fetch_optional(&mut *tx).await.map_err(|_| ProductSafetyError::database())?.map(hazard_from_sqlite_row).transpose().map_err(|_| ProductSafetyError::database())?.ok_or_else(stale_revision)?;
    insert_audit_sqlite(
        &mut tx,
        tenant_id,
        actor_id,
        "HAZARD",
        hazard_id,
        "hazard_changed",
        updated.revision,
        &updated.status,
        &json!({"product_id": updated.product_id}),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    Ok(updated)
}

async fn create_assessment_pg(
    pool: &PgPool,
    tenant_id: i64,
    hazard_id: i64,
    actor_id: i64,
    normalized: &NormalizedAssessment,
) -> Result<SafetyAssessment, ProductSafetyError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    validate_actor_pg(&mut tx, tenant_id, actor_id).await?;
    let hazard =
        sqlx::query("SELECT * FROM product_safety_hazard WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
            .bind(tenant_id)
            .bind(hazard_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| ProductSafetyError::database())?
            .map(hazard_from_pg_row)
            .transpose()
            .map_err(|_| ProductSafetyError::database())?
            .ok_or_else(ProductSafetyError::not_found)?;
    if hazard.revision != normalized.expected_hazard_revision {
        return Err(stale_revision());
    }
    let assessment_revision: i64 = sqlx::query("SELECT COALESCE(MAX(assessment_revision),0)+1 AS next_revision FROM product_safety_assessment WHERE tenant_id=$1 AND hazard_id=$2").bind(tenant_id).bind(hazard_id).fetch_one(&mut *tx).await.map_err(|_| ProductSafetyError::database())?.try_get("next_revision").map_err(|_| ProductSafetyError::database())?;
    let assessment = sqlx::query("INSERT INTO product_safety_assessment (tenant_id,hazard_id,assessment_revision,lifecycle_operating_state,existing_safeguards,risk_estimation_method,initial_assessment,additional_measures,residual_assessment,reviewer_id,review_date,created_by_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$10) RETURNING *")
        .bind(tenant_id).bind(hazard_id).bind(assessment_revision).bind(&normalized.lifecycle_operating_state).bind(&normalized.existing_safeguards).bind(&normalized.risk_estimation_method).bind(&normalized.initial_assessment).bind(&normalized.additional_measures).bind(&normalized.residual_assessment).bind(actor_id).bind(&normalized.review_date)
        .fetch_one(&mut *tx).await.map_err(|_| ProductSafetyError::database()).and_then(|row| assessment_from_pg_row(row).map_err(|_| ProductSafetyError::database()))?;
    let changed = sqlx::query("UPDATE product_safety_hazard SET revision=revision+1,updated_by_id=$1,updated_at=$2 WHERE tenant_id=$3 AND id=$4 AND revision=$5").bind(actor_id).bind(now()).bind(tenant_id).bind(hazard_id).bind(normalized.expected_hazard_revision).execute(&mut *tx).await.map_err(|_| ProductSafetyError::database())?.rows_affected();
    if changed != 1 {
        return Err(stale_revision());
    }
    insert_audit_pg(
        &mut tx,
        tenant_id,
        actor_id,
        "ASSESSMENT",
        assessment.id,
        "safety_assessment_created",
        assessment.assessment_revision,
        "READY_FOR_HUMAN_REVIEW",
        &json!({"hazard_id": hazard_id}),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    Ok(assessment)
}

async fn create_assessment_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    hazard_id: i64,
    actor_id: i64,
    normalized: &NormalizedAssessment,
) -> Result<SafetyAssessment, ProductSafetyError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    validate_actor_sqlite(&mut tx, tenant_id, actor_id).await?;
    let hazard = sqlx::query("SELECT * FROM product_safety_hazard WHERE tenant_id=? AND id=?")
        .bind(tenant_id)
        .bind(hazard_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ProductSafetyError::database())?
        .map(hazard_from_sqlite_row)
        .transpose()
        .map_err(|_| ProductSafetyError::database())?
        .ok_or_else(ProductSafetyError::not_found)?;
    if hazard.revision != normalized.expected_hazard_revision {
        return Err(stale_revision());
    }
    let assessment_revision: i64 = sqlx::query("SELECT COALESCE(MAX(assessment_revision),0)+1 AS next_revision FROM product_safety_assessment WHERE tenant_id=? AND hazard_id=?").bind(tenant_id).bind(hazard_id).fetch_one(&mut *tx).await.map_err(|_| ProductSafetyError::database())?.try_get("next_revision").map_err(|_| ProductSafetyError::database())?;
    let assessment = sqlx::query("INSERT INTO product_safety_assessment (tenant_id,hazard_id,assessment_revision,lifecycle_operating_state,existing_safeguards,risk_estimation_method,initial_assessment,additional_measures,residual_assessment,reviewer_id,review_date,created_by_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?) RETURNING *")
        .bind(tenant_id).bind(hazard_id).bind(assessment_revision).bind(&normalized.lifecycle_operating_state).bind(&normalized.existing_safeguards).bind(&normalized.risk_estimation_method).bind(&normalized.initial_assessment).bind(&normalized.additional_measures).bind(&normalized.residual_assessment).bind(actor_id).bind(&normalized.review_date).bind(actor_id)
        .fetch_one(&mut *tx).await.map_err(|_| ProductSafetyError::database()).and_then(|row| assessment_from_sqlite_row(row).map_err(|_| ProductSafetyError::database()))?;
    let changed = sqlx::query("UPDATE product_safety_hazard SET revision=revision+1,updated_by_id=?,updated_at=? WHERE tenant_id=? AND id=? AND revision=?").bind(actor_id).bind(now()).bind(tenant_id).bind(hazard_id).bind(normalized.expected_hazard_revision).execute(&mut *tx).await.map_err(|_| ProductSafetyError::database())?.rows_affected();
    if changed != 1 {
        return Err(stale_revision());
    }
    insert_audit_sqlite(
        &mut tx,
        tenant_id,
        actor_id,
        "ASSESSMENT",
        assessment.id,
        "safety_assessment_created",
        assessment.assessment_revision,
        "READY_FOR_HUMAN_REVIEW",
        &json!({"hazard_id": hazard_id}),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    Ok(assessment)
}

type CyberSourceColumns = (
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
);

fn cyber_columns(source: &CyberSourceRef) -> CyberSourceColumns {
    match source.source_type.as_str() {
        "VULNERABILITY" => (Some(source.source_id), None, None, None, None, None, None),
        "SECURITY_OBSERVATION" => (None, Some(source.source_id), None, None, None, None, None),
        "RISK" => (None, None, Some(source.source_id), None, None, None, None),
        "SBOM_COMPONENT" => (None, None, None, Some(source.source_id), None, None, None),
        "CVE_CORRELATION" => (None, None, None, None, Some(source.source_id), None, None),
        "THREAT_SCENARIO" => (None, None, None, None, None, Some(source.source_id), None),
        "TARA" => (None, None, None, None, None, None, Some(source.source_id)),
        _ => (None, None, None, None, None, None, None),
    }
}

fn same_interaction(
    existing: &SafetySecurityInteraction,
    normalized: &NormalizedInteraction,
) -> bool {
    existing.hazard_id == normalized.hazard_id
        && existing.safety_function_id == normalized.safety_function_id
        && existing.cyber_source == normalized.cyber_source
        && existing.interaction_type == normalized.interaction_type
        && existing.status == normalized.status
        && existing.security_consequence == normalized.security_consequence
        && existing.measures == normalized.measures
        && existing.rationale == normalized.rationale
}

fn valid_interaction_transition(current: &str, next: &str) -> bool {
    current == next
        || matches!(
            (current, next),
            ("OPEN", "UNDER_REVIEW" | "MITIGATION_REQUIRED")
                | (
                    "UNDER_REVIEW",
                    "MITIGATION_REQUIRED" | "ACCEPTED_FOR_REVIEW"
                )
                | (
                    "MITIGATION_REQUIRED",
                    "UNDER_REVIEW" | "ACCEPTED_FOR_REVIEW"
                )
                | ("ACCEPTED_FOR_REVIEW", "MITIGATION_REQUIRED" | "CLOSED")
        )
}

async fn create_interaction_pg(
    pool: &PgPool,
    tenant_id: i64,
    product_id: i64,
    actor_id: i64,
    normalized: &NormalizedInteraction,
) -> Result<SafetySecurityInteractionWriteResult, ProductSafetyError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    validate_actor_pg(&mut tx, tenant_id, actor_id).await?;
    validate_product_pg(&mut tx, tenant_id, product_id).await?;
    validate_interaction_refs_pg(&mut tx, tenant_id, product_id, normalized).await?;
    if let Some(existing) = sqlx::query("SELECT * FROM safety_security_interaction WHERE tenant_id=$1 AND deduplication_key=$2 FOR UPDATE").bind(tenant_id).bind(&normalized.deduplication_key).fetch_optional(&mut *tx).await.map_err(|_| ProductSafetyError::database())?.map(interaction_from_pg_row).transpose().map_err(|_| ProductSafetyError::database())? {
        if !same_interaction(&existing, normalized) { return Err(ProductSafetyError::conflict("duplicate_safety_security_interaction", "Die Interaction existiert bereits mit abweichenden Daten.")); }
        tx.commit().await.map_err(|_| ProductSafetyError::database())?;
        return Ok(SafetySecurityInteractionWriteResult { created: false, interaction: existing });
    }
    let (vulnerability, observation, risk, sbom, correlation, scenario, tara) =
        cyber_columns(&normalized.cyber_source);
    let interaction = sqlx::query("INSERT INTO safety_security_interaction (tenant_id,product_id,hazard_id,safety_function_id,vulnerability_id,security_observation_id,cyber_risk_id,sbom_component_id,cve_correlation_id,threat_scenario_id,tara_id,interaction_type,status,security_consequence,measures,rationale,deduplication_key,created_by_id,updated_by_id,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$18,$19) RETURNING *")
        .bind(tenant_id).bind(product_id).bind(normalized.hazard_id).bind(normalized.safety_function_id).bind(vulnerability).bind(observation).bind(risk).bind(sbom).bind(correlation).bind(scenario).bind(tara).bind(&normalized.interaction_type).bind(&normalized.status).bind(&normalized.security_consequence).bind(&normalized.measures).bind(&normalized.rationale).bind(&normalized.deduplication_key).bind(actor_id).bind(now())
        .fetch_one(&mut *tx).await.map_err(|_| ProductSafetyError::database()).and_then(|row| interaction_from_pg_row(row).map_err(|_| ProductSafetyError::database()))?;
    insert_audit_pg(
        &mut tx,
        tenant_id,
        actor_id,
        "INTERACTION",
        interaction.id,
        "safety_security_interaction_created",
        interaction.revision,
        &interaction.status,
        &json!({"product_id": product_id, "cyber_source": interaction.cyber_source}),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    Ok(SafetySecurityInteractionWriteResult {
        created: true,
        interaction,
    })
}

async fn create_interaction_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    product_id: i64,
    actor_id: i64,
    normalized: &NormalizedInteraction,
) -> Result<SafetySecurityInteractionWriteResult, ProductSafetyError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    validate_actor_sqlite(&mut tx, tenant_id, actor_id).await?;
    validate_product_sqlite(&mut tx, tenant_id, product_id).await?;
    validate_interaction_refs_sqlite(&mut tx, tenant_id, product_id, normalized).await?;
    if let Some(existing) = sqlx::query(
        "SELECT * FROM safety_security_interaction WHERE tenant_id=? AND deduplication_key=?",
    )
    .bind(tenant_id)
    .bind(&normalized.deduplication_key)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| ProductSafetyError::database())?
    .map(interaction_from_sqlite_row)
    .transpose()
    .map_err(|_| ProductSafetyError::database())?
    {
        if !same_interaction(&existing, normalized) {
            return Err(ProductSafetyError::conflict(
                "duplicate_safety_security_interaction",
                "Die Interaction existiert bereits mit abweichenden Daten.",
            ));
        }
        tx.commit()
            .await
            .map_err(|_| ProductSafetyError::database())?;
        return Ok(SafetySecurityInteractionWriteResult {
            created: false,
            interaction: existing,
        });
    }
    let (vulnerability, observation, risk, sbom, correlation, scenario, tara) =
        cyber_columns(&normalized.cyber_source);
    let interaction = sqlx::query("INSERT INTO safety_security_interaction (tenant_id,product_id,hazard_id,safety_function_id,vulnerability_id,security_observation_id,cyber_risk_id,sbom_component_id,cve_correlation_id,threat_scenario_id,tara_id,interaction_type,status,security_consequence,measures,rationale,deduplication_key,created_by_id,updated_by_id,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING *")
        .bind(tenant_id).bind(product_id).bind(normalized.hazard_id).bind(normalized.safety_function_id).bind(vulnerability).bind(observation).bind(risk).bind(sbom).bind(correlation).bind(scenario).bind(tara).bind(&normalized.interaction_type).bind(&normalized.status).bind(&normalized.security_consequence).bind(&normalized.measures).bind(&normalized.rationale).bind(&normalized.deduplication_key).bind(actor_id).bind(actor_id).bind(now())
        .fetch_one(&mut *tx).await.map_err(|_| ProductSafetyError::database()).and_then(|row| interaction_from_sqlite_row(row).map_err(|_| ProductSafetyError::database()))?;
    insert_audit_sqlite(
        &mut tx,
        tenant_id,
        actor_id,
        "INTERACTION",
        interaction.id,
        "safety_security_interaction_created",
        interaction.revision,
        &interaction.status,
        &json!({"product_id": product_id, "cyber_source": interaction.cyber_source}),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    Ok(SafetySecurityInteractionWriteResult {
        created: true,
        interaction,
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit optimistic-lock and workflow fields mirror the guarded SQL update"
)]
async fn update_interaction_pg(
    pool: &PgPool,
    tenant_id: i64,
    interaction_id: i64,
    actor_id: i64,
    expected_revision: i64,
    status: &str,
    consequence: &str,
    measures: &str,
    rationale: &str,
) -> Result<SafetySecurityInteraction, ProductSafetyError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    validate_actor_pg(&mut tx, tenant_id, actor_id).await?;
    let current = sqlx::query(
        "SELECT * FROM safety_security_interaction WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(interaction_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| ProductSafetyError::database())?
    .map(interaction_from_pg_row)
    .transpose()
    .map_err(|_| ProductSafetyError::database())?
    .ok_or_else(ProductSafetyError::not_found)?;
    if current.revision != expected_revision {
        return Err(stale_revision());
    }
    if !valid_interaction_transition(&current.status, status) {
        return Err(ProductSafetyError::conflict(
            "invalid_safety_security_interaction_transition",
            "Der Safety-Security-Interaction-Statuswechsel ist nicht zulaessig.",
        ));
    }
    let timestamp = now();
    let closed_at = (status == "CLOSED").then_some(timestamp.clone());
    let updated = sqlx::query("UPDATE safety_security_interaction SET status=$1,security_consequence=$2,measures=$3,rationale=$4,closed_at=$5,updated_by_id=$6,revision=revision+1,updated_at=$7 WHERE tenant_id=$8 AND id=$9 AND revision=$10 RETURNING *")
        .bind(status).bind(consequence).bind(measures).bind(rationale).bind(closed_at).bind(actor_id).bind(timestamp).bind(tenant_id).bind(interaction_id).bind(expected_revision)
        .fetch_optional(&mut *tx).await.map_err(|_| ProductSafetyError::database())?.map(interaction_from_pg_row).transpose().map_err(|_| ProductSafetyError::database())?.ok_or_else(stale_revision)?;
    insert_audit_pg(
        &mut tx,
        tenant_id,
        actor_id,
        "INTERACTION",
        interaction_id,
        if status == "CLOSED" {
            "safety_security_interaction_closed"
        } else {
            "safety_security_interaction_changed"
        },
        updated.revision,
        status,
        &json!({"workflow_complete_only": status == "CLOSED", "conformity_statement": false}),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    Ok(updated)
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit optimistic-lock and workflow fields mirror the guarded SQL update"
)]
async fn update_interaction_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    interaction_id: i64,
    actor_id: i64,
    expected_revision: i64,
    status: &str,
    consequence: &str,
    measures: &str,
    rationale: &str,
) -> Result<SafetySecurityInteraction, ProductSafetyError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    validate_actor_sqlite(&mut tx, tenant_id, actor_id).await?;
    let current =
        sqlx::query("SELECT * FROM safety_security_interaction WHERE tenant_id=? AND id=?")
            .bind(tenant_id)
            .bind(interaction_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| ProductSafetyError::database())?
            .map(interaction_from_sqlite_row)
            .transpose()
            .map_err(|_| ProductSafetyError::database())?
            .ok_or_else(ProductSafetyError::not_found)?;
    if current.revision != expected_revision {
        return Err(stale_revision());
    }
    if !valid_interaction_transition(&current.status, status) {
        return Err(ProductSafetyError::conflict(
            "invalid_safety_security_interaction_transition",
            "Der Safety-Security-Interaction-Statuswechsel ist nicht zulaessig.",
        ));
    }
    let timestamp = now();
    let closed_at = (status == "CLOSED").then_some(timestamp.clone());
    let updated = sqlx::query("UPDATE safety_security_interaction SET status=?,security_consequence=?,measures=?,rationale=?,closed_at=?,updated_by_id=?,revision=revision+1,updated_at=? WHERE tenant_id=? AND id=? AND revision=? RETURNING *")
        .bind(status).bind(consequence).bind(measures).bind(rationale).bind(closed_at).bind(actor_id).bind(timestamp).bind(tenant_id).bind(interaction_id).bind(expected_revision)
        .fetch_optional(&mut *tx).await.map_err(|_| ProductSafetyError::database())?.map(interaction_from_sqlite_row).transpose().map_err(|_| ProductSafetyError::database())?.ok_or_else(stale_revision)?;
    insert_audit_sqlite(
        &mut tx,
        tenant_id,
        actor_id,
        "INTERACTION",
        interaction_id,
        if status == "CLOSED" {
            "safety_security_interaction_closed"
        } else {
            "safety_security_interaction_changed"
        },
        updated.revision,
        status,
        &json!({"workflow_complete_only": status == "CLOSED", "conformity_statement": false}),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| ProductSafetyError::database())?;
    Ok(updated)
}

#[cfg(test)]
mod tests {
    use sqlx::{sqlite::SqlitePoolOptions, Row};

    use super::{
        ApplicabilityWriteRequest, CyberSourceRef, HazardWriteRequest, ProductSafetyErrorKind,
        ProductSafetyStore, SafetyAssessmentCreateRequest, SafetyEvidenceLinkRequest,
        SafetyFunctionWriteRequest, SafetySecurityInteractionCreateRequest,
        SafetySecurityInteractionUpdateRequest,
    };
    use crate::db_admin::run_sqlite_migrations;

    async fn fixture() -> (sqlx::SqlitePool, ProductSafetyStore) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        run_sqlite_migrations(&pool).await.unwrap();
        sqlx::query("PRAGMA foreign_keys=ON")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO organizations_tenant (id,name,slug) VALUES
             (501,'Safety Fixture','safety-fixture'),
             (502,'Foreign Safety Fixture','foreign-safety-fixture')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO evidence_evidenceitem (id,tenant_id,title,status) VALUES
             (5011,501,'Configuration baseline','APPROVED'),
             (5021,502,'Foreign evidence','APPROVED')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO accounts_user (id,username,tenant_id,role,is_active) VALUES
             (5011,'safety-admin',501,'COMPLIANCE_MANAGER',1),
             (5012,'safety-owner',501,'CONTRIBUTOR',1),
             (5021,'foreign-owner',502,'COMPLIANCE_MANAGER',1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO product_security_product (id,tenant_id,name,code,description) VALUES
             (5011,501,'Industrial Controller','CTRL-501','Synthetic controller'),
             (5021,502,'Foreign Controller','CTRL-502','Foreign synthetic controller')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO product_security_vulnerability (
                id,tenant_id,product_id,title,cve,status,vex_status,origin_key,summary
             ) VALUES
             (5011,501,5011,'Unauthorized manipulation of control logic','CVE-2026-0501','OPEN','AFFECTED','safety-fixture-vulnerability','Control logic modified'),
             (5021,502,5021,'Foreign finding','CVE-2026-0502','OPEN','AFFECTED','foreign-safety-fixture-vulnerability','Foreign')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let store = ProductSafetyStore::from_sqlite_pool(pool.clone());
        (pool, store)
    }

    fn function_request(identifier: &str) -> SafetyFunctionWriteRequest {
        SafetyFunctionWriteRequest {
            name: "Safe speed limitation".to_string(),
            description: Some(
                "Limits movement speed in the hazardous operating state.".to_string(),
            ),
            function_identifier: identifier.to_string(),
            criticality: "HIGH".to_string(),
            status: Some("ACTIVE".to_string()),
            owner_id: Some(5012),
            expected_revision: None,
        }
    }

    fn hazard_request(function_id: i64) -> HazardWriteRequest {
        HazardWriteRequest {
            title: "Unexpected high-speed movement".to_string(),
            description: Some("Synthetic machinery hazard".to_string()),
            hazard_category: "MECHANICAL".to_string(),
            affected_safety_function_id: Some(function_id),
            operational_phase: "OPERATION".to_string(),
            potential_consequence: "Unexpected hazardous movement".to_string(),
            risk_estimation_method: "Documented qualitative expert assessment".to_string(),
            initial_risk: "HIGH".to_string(),
            residual_risk: Some("REVIEW_REQUIRED".to_string()),
            status: Some("MITIGATION_REQUIRED".to_string()),
            owner_id: Some(5012),
            expected_revision: None,
        }
    }

    #[tokio::test]
    async fn applicability_is_product_bound_reasoned_and_revision_protected() {
        let (_pool, store) = fixture().await;
        for (legal_act, status) in [("CRA", "IN_SCOPE"), ("MACHINERY_REGULATION", "IN_SCOPE")] {
            let record = store
                .upsert_applicability(
                    501,
                    5011,
                    5011,
                    ApplicabilityWriteRequest {
                        legal_act: legal_act.to_string(),
                        applicability_status: status.to_string(),
                        product_role: "MACHINERY".to_string(),
                        reasoning: "Human scope assessment based on the synthetic product profile."
                            .to_string(),
                        expected_revision: None,
                    },
                )
                .await
                .unwrap();
            assert_eq!(record.revision, 1);
        }
        assert_eq!(store.list_applicability(501, 5011).await.unwrap().len(), 2);
        assert_eq!(
            store
                .upsert_applicability(
                    501,
                    5011,
                    5011,
                    ApplicabilityWriteRequest {
                        legal_act: "CRA".to_string(),
                        applicability_status: "REVIEW_REQUIRED".to_string(),
                        product_role: "MACHINERY".to_string(),
                        reasoning: "Re-review required.".to_string(),
                        expected_revision: Some(99),
                    },
                )
                .await
                .unwrap_err()
                .kind(),
            ProductSafetyErrorKind::Conflict
        );
        assert_eq!(
            store
                .upsert_applicability(
                    501,
                    5021,
                    5011,
                    ApplicabilityWriteRequest {
                        legal_act: "CRA".to_string(),
                        applicability_status: "IN_SCOPE".to_string(),
                        product_role: "MACHINERY".to_string(),
                        reasoning: "Foreign product must be hidden.".to_string(),
                        expected_revision: None,
                    },
                )
                .await
                .unwrap_err()
                .kind(),
            ProductSafetyErrorKind::NotFound
        );
        assert_eq!(
            store
                .upsert_applicability(
                    501,
                    5011,
                    5021,
                    ApplicabilityWriteRequest {
                        legal_act: "CRA".to_string(),
                        applicability_status: "IN_SCOPE".to_string(),
                        product_role: "MACHINERY".to_string(),
                        reasoning: "Foreign actor must be hidden.".to_string(),
                        expected_revision: Some(1),
                    },
                )
                .await
                .unwrap_err()
                .kind(),
            ProductSafetyErrorKind::NotFound
        );
        assert_eq!(
            store
                .upsert_applicability(
                    501,
                    5011,
                    5011,
                    ApplicabilityWriteRequest {
                        legal_act: "CRA".to_string(),
                        applicability_status: "IN_SCOPE".to_string(),
                        product_role: "MACHINERY".to_string(),
                        reasoning: " ".to_string(),
                        expected_revision: Some(1),
                    },
                )
                .await
                .unwrap_err()
                .kind(),
            ProductSafetyErrorKind::InvalidInput
        );
    }

    #[tokio::test]
    async fn synthetic_cyber_to_safety_chain_is_typed_idempotent_and_history_preserving() {
        let (_pool, store) = fixture().await;
        let function = store
            .create_safety_function(501, 5011, 5011, function_request("SAFE-SPEED-1"))
            .await
            .unwrap();
        assert!(function.created);
        let duplicate = store
            .create_safety_function(501, 5011, 5011, function_request("SAFE-SPEED-1"))
            .await
            .unwrap();
        assert!(!duplicate.created);
        let hazard = store
            .create_hazard(501, 5011, 5011, hazard_request(function.safety_function.id))
            .await
            .unwrap();
        let first_assessment = store
            .create_assessment(
                501,
                hazard.id,
                5011,
                SafetyAssessmentCreateRequest {
                    expected_hazard_revision: 1,
                    lifecycle_operating_state: "Production operation".to_string(),
                    existing_safeguards: Some(
                        "Authenticated update process; integrity validation".to_string(),
                    ),
                    risk_estimation_method: "Qualitative expert review".to_string(),
                    initial_assessment: "High, human review required".to_string(),
                    additional_measures: Some("Safety-independent protective measure".to_string()),
                    residual_assessment: "Review required after validation test".to_string(),
                    review_date: "2026-08-25".to_string(),
                },
            )
            .await
            .unwrap();
        let second_assessment = store
            .create_assessment(
                501,
                hazard.id,
                5011,
                SafetyAssessmentCreateRequest {
                    expected_hazard_revision: 2,
                    lifecycle_operating_state: "Production operation after measures".to_string(),
                    existing_safeguards: Some(
                        "Authenticated update process; integrity validation".to_string(),
                    ),
                    risk_estimation_method: "Qualitative expert review".to_string(),
                    initial_assessment: "High".to_string(),
                    additional_measures: Some(
                        "Independent protective measure and validation test".to_string(),
                    ),
                    residual_assessment: "Lower qualitative band; still human review".to_string(),
                    review_date: "2026-08-26".to_string(),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            (
                first_assessment.assessment_revision,
                second_assessment.assessment_revision
            ),
            (1, 2)
        );
        assert_eq!(
            store.list_assessments(501, hazard.id).await.unwrap().len(),
            2
        );

        let request = SafetySecurityInteractionCreateRequest {
            hazard_id: hazard.id,
            safety_function_id: function.safety_function.id,
            cyber_source: CyberSourceRef {
                source_type: "VULNERABILITY".to_string(),
                source_id: 5011,
            },
            interaction_type: "CYBER_CAN_DEGRADE_SAFETY_FUNCTION".to_string(),
            status: Some("MITIGATION_REQUIRED".to_string()),
            security_consequence: "Control logic modified".to_string(),
            measures: Some("Authenticated update process; integrity validation; safety-independent protective measure".to_string()),
            rationale: Some("Unauthorized manipulation can degrade safe speed limitation.".to_string()),
        };
        let interaction = store
            .create_interaction(501, 5011, 5011, request.clone())
            .await
            .unwrap();
        assert!(interaction.created);
        assert!(
            !store
                .create_interaction(501, 5011, 5011, request)
                .await
                .unwrap()
                .created
        );
        let accepted = store
            .update_interaction(
                501,
                interaction.interaction.id,
                5011,
                SafetySecurityInteractionUpdateRequest {
                    expected_revision: 1,
                    status: "ACCEPTED_FOR_REVIEW".to_string(),
                    security_consequence: "Control logic modified".to_string(),
                    measures: Some("Validated measures documented".to_string()),
                    rationale: Some("Ready for a human closure decision.".to_string()),
                },
            )
            .await
            .unwrap();
        let closed = store
            .update_interaction(
                501,
                interaction.interaction.id,
                5011,
                SafetySecurityInteractionUpdateRequest {
                    expected_revision: accepted.revision,
                    status: "CLOSED".to_string(),
                    security_consequence: "Control logic modified".to_string(),
                    measures: Some("Validated measures documented".to_string()),
                    rationale: Some(
                        "Workflow complete; no safety or conformity claim.".to_string(),
                    ),
                },
            )
            .await
            .unwrap();
        assert_eq!(closed.status, "CLOSED");
        let encoded = serde_json::to_string(&closed).unwrap();
        assert!(!encoded.contains("CONFORMITY_CONFIRMED"));
        assert!(!encoded.contains("compliant"));
    }

    #[tokio::test]
    async fn foreign_links_stale_updates_bounded_input_and_audit_rollback_fail_closed() {
        let (pool, store) = fixture().await;
        let function = store
            .create_safety_function(501, 5011, 5011, function_request("SAFE-SPEED-2"))
            .await
            .unwrap()
            .safety_function;
        let mut foreign_owner = function_request("FOREIGN-OWNER");
        foreign_owner.owner_id = Some(5021);
        assert_eq!(
            store
                .create_safety_function(501, 5011, 5011, foreign_owner)
                .await
                .unwrap_err()
                .kind(),
            ProductSafetyErrorKind::NotFound
        );
        let hazard = store
            .create_hazard(501, 5011, 5011, hazard_request(function.id))
            .await
            .unwrap();
        let mut stale = hazard_request(function.id);
        stale.expected_revision = Some(99);
        assert_eq!(
            store
                .update_hazard(501, hazard.id, 5011, stale)
                .await
                .unwrap_err()
                .kind(),
            ProductSafetyErrorKind::Conflict
        );
        let mut too_long = function_request("TOO-LONG");
        too_long.description = Some("x".repeat(4001));
        assert_eq!(
            store
                .create_safety_function(501, 5011, 5011, too_long)
                .await
                .unwrap_err()
                .kind(),
            ProductSafetyErrorKind::InvalidInput
        );
        assert_eq!(
            store
                .create_interaction(
                    501,
                    5011,
                    5011,
                    SafetySecurityInteractionCreateRequest {
                        hazard_id: hazard.id,
                        safety_function_id: function.id,
                        cyber_source: CyberSourceRef {
                            source_type: "VULNERABILITY".to_string(),
                            source_id: 5021,
                        },
                        interaction_type: "CYBER_CAN_TRIGGER_HAZARD".to_string(),
                        status: None,
                        security_consequence: "Foreign reference".to_string(),
                        measures: None,
                        rationale: None,
                    },
                )
                .await
                .unwrap_err()
                .kind(),
            ProductSafetyErrorKind::NotFound
        );

        sqlx::query(
            "CREATE TRIGGER fail_product_safety_audit BEFORE INSERT ON product_safety_audit_event
             BEGIN SELECT RAISE(ABORT, 'synthetic audit failure'); END",
        )
        .execute(&pool)
        .await
        .unwrap();
        let result = store
            .create_safety_function(501, 5011, 5011, function_request("ROLLBACK-ON-AUDIT"))
            .await;
        assert_eq!(result.unwrap_err().kind(), ProductSafetyErrorKind::Database);
        let count: i64 = sqlx::query("SELECT COUNT(*) AS count FROM product_safety_function WHERE tenant_id=501 AND function_identifier='ROLLBACK-ON-AUDIT'")
            .fetch_one(&pool).await.unwrap().try_get("count").unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn concurrent_hazard_updates_allow_exactly_one_revision() {
        let (_pool, store) = fixture().await;
        let function = store
            .create_safety_function(501, 5011, 5011, function_request("SAFE-SPEED-3"))
            .await
            .unwrap()
            .safety_function;
        let hazard = store
            .create_hazard(501, 5011, 5011, hazard_request(function.id))
            .await
            .unwrap();
        let mut left = hazard_request(function.id);
        left.title = "Concurrent left".to_string();
        left.expected_revision = Some(hazard.revision);
        let mut right = hazard_request(function.id);
        right.title = "Concurrent right".to_string();
        right.expected_revision = Some(hazard.revision);
        let left_store = store.clone();
        let right_store = store.clone();
        let (left_result, right_result) = tokio::join!(
            left_store.update_hazard(501, hazard.id, 5011, left),
            right_store.update_hazard(501, hazard.id, 5011, right)
        );
        assert_eq!(
            usize::from(left_result.is_ok()) + usize::from(right_result.is_ok()),
            1
        );
        let rejected = left_result.err().or_else(|| right_result.err()).unwrap();
        assert_eq!(rejected.kind(), ProductSafetyErrorKind::Conflict);
        assert_eq!(store.get_hazard(501, hazard.id).await.unwrap().revision, 2);
    }

    #[tokio::test]
    async fn evidence_links_are_tenant_bound_idempotent_audited_and_rollback_on_audit_failure() {
        let (pool, store) = fixture().await;
        let function = store
            .create_safety_function(501, 5011, 5011, function_request("SAFE-SPEED-EVIDENCE"))
            .await
            .unwrap()
            .safety_function;
        let request = SafetyEvidenceLinkRequest {
            evidence_id: 5011,
            target_type: "SAFETY_FUNCTION".to_string(),
            target_id: function.id,
        };
        let left = store.clone();
        let right = store.clone();
        let (first, second) = tokio::join!(
            left.link_evidence(501, 5011, 5011, request.clone()),
            right.link_evidence(501, 5011, 5011, request.clone())
        );
        assert_eq!(
            usize::from(first.unwrap().created) + usize::from(second.unwrap().created),
            1
        );
        let count: i64 = sqlx::query(
            "SELECT COUNT(*) AS count FROM product_safety_evidence_link WHERE tenant_id=501",
        )
        .fetch_one(&pool)
        .await
        .unwrap()
        .try_get("count")
        .unwrap();
        assert_eq!(count, 1);

        let foreign = store
            .link_evidence(
                501,
                5011,
                5011,
                SafetyEvidenceLinkRequest {
                    evidence_id: 5021,
                    ..request.clone()
                },
            )
            .await
            .unwrap_err();
        assert_eq!(foreign.kind(), ProductSafetyErrorKind::NotFound);

        store
            .unlink_evidence(501, 5011, 5011, request.clone())
            .await
            .unwrap();
        let unlink_audit: i64 = sqlx::query("SELECT COUNT(*) AS count FROM product_safety_audit_event WHERE tenant_id=501 AND event_type='evidence_unlinked'")
            .fetch_one(&pool).await.unwrap().try_get("count").unwrap();
        assert_eq!(unlink_audit, 1);

        sqlx::query(
            "CREATE TRIGGER fail_evidence_link_audit BEFORE INSERT ON product_safety_audit_event
             WHEN NEW.event_type='evidence_linked'
             BEGIN SELECT RAISE(ABORT, 'synthetic evidence audit failure'); END",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            store
                .link_evidence(501, 5011, 5011, request)
                .await
                .unwrap_err()
                .kind(),
            ProductSafetyErrorKind::Database
        );
        let count: i64 = sqlx::query(
            "SELECT COUNT(*) AS count FROM product_safety_evidence_link WHERE tenant_id=501",
        )
        .fetch_one(&pool)
        .await
        .unwrap()
        .try_get("count")
        .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn concurrent_assessment_and_interaction_revisions_reject_lost_updates() {
        let (_pool, store) = fixture().await;
        let function = store
            .create_safety_function(501, 5011, 5011, function_request("SAFE-SPEED-CONCURRENT"))
            .await
            .unwrap()
            .safety_function;
        let hazard = store
            .create_hazard(501, 5011, 5011, hazard_request(function.id))
            .await
            .unwrap();
        let interaction = store
            .create_interaction(
                501,
                5011,
                5011,
                SafetySecurityInteractionCreateRequest {
                    hazard_id: hazard.id,
                    safety_function_id: function.id,
                    cyber_source: CyberSourceRef {
                        source_type: "VULNERABILITY".to_string(),
                        source_id: 5011,
                    },
                    interaction_type: "CYBER_CAN_TRIGGER_HAZARD".to_string(),
                    status: Some("OPEN".to_string()),
                    security_consequence: "Control logic modified".to_string(),
                    measures: None,
                    rationale: None,
                },
            )
            .await
            .unwrap()
            .interaction;

        let assessment = SafetyAssessmentCreateRequest {
            expected_hazard_revision: hazard.revision,
            lifecycle_operating_state: "Concurrent operating state".to_string(),
            existing_safeguards: None,
            risk_estimation_method: "Qualitative human review".to_string(),
            initial_assessment: "Review required".to_string(),
            additional_measures: None,
            residual_assessment: "Review required".to_string(),
            review_date: "2026-08-25".to_string(),
        };
        let left = store.clone();
        let right = store.clone();
        let (left_result, right_result) = tokio::join!(
            left.create_assessment(501, hazard.id, 5011, assessment.clone()),
            right.create_assessment(501, hazard.id, 5011, assessment)
        );
        assert_eq!(
            usize::from(left_result.is_ok()) + usize::from(right_result.is_ok()),
            1
        );
        assert_eq!(
            left_result
                .err()
                .or_else(|| right_result.err())
                .unwrap()
                .kind(),
            ProductSafetyErrorKind::Conflict
        );

        let update = SafetySecurityInteractionUpdateRequest {
            expected_revision: interaction.revision,
            status: "UNDER_REVIEW".to_string(),
            security_consequence: "Control logic modified".to_string(),
            measures: None,
            rationale: None,
        };
        let left = store.clone();
        let right = store.clone();
        let (left_result, right_result) = tokio::join!(
            left.update_interaction(501, interaction.id, 5011, update.clone()),
            right.update_interaction(501, interaction.id, 5011, update)
        );
        assert_eq!(
            usize::from(left_result.is_ok()) + usize::from(right_result.is_ok()),
            1
        );
        assert_eq!(
            left_result
                .err()
                .or_else(|| right_result.err())
                .unwrap()
                .kind(),
            ProductSafetyErrorKind::Conflict
        );
        let current = store.list_interactions(501, 5011).await.unwrap().remove(0);
        let invalid = store
            .update_interaction(
                501,
                current.id,
                5011,
                SafetySecurityInteractionUpdateRequest {
                    expected_revision: current.revision,
                    status: "CLOSED".to_string(),
                    security_consequence: current.security_consequence,
                    measures: Some(current.measures),
                    rationale: Some(current.rationale),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(
            invalid.code(),
            "invalid_safety_security_interaction_transition"
        );
    }
}
