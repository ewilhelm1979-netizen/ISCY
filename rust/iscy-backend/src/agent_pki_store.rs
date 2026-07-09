use anyhow::{bail, Context};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Row,
};

use crate::cve_store::normalize_database_url;

const PROVIDER_TYPES: &[&str] = &[
    "internal_placeholder",
    "external_ca_placeholder",
    "step_ca_future",
    "vault_pki_future",
    "microsoft_ca_future",
    "acme_future",
    "manual_import",
    "not_configured",
];
const PROVIDER_STATUSES: &[&str] = &[
    "not_configured",
    "configured_metadata_only",
    "validation_required",
    "ready_for_test",
    "disabled",
    "error",
];
const CSR_STATUSES: &[&str] = &[
    "draft",
    "pending_review",
    "approved_for_issue",
    "rejected",
    "issued_metadata_only",
    "expired",
    "cancelled",
    "failed",
    "not_configured",
];
const CERTIFICATE_STATUSES: &[&str] = &[
    "not_present",
    "requested",
    "issued_metadata_only",
    "active",
    "expiring_soon",
    "expired",
    "revoked",
    "rotation_required",
    "validation_failed",
    "not_configured",
];
const MTLS_BINDING_STATUSES: &[&str] = &[
    "not_configured",
    "pending",
    "bound",
    "mismatch",
    "stale",
    "failed",
];
const REVOCATION_STATUSES: &[&str] = &[
    "not_applicable",
    "not_revoked",
    "revocation_requested",
    "revoked_metadata_only",
    "failed",
    "unknown",
];
const ROTATION_STATUSES: &[&str] = &[
    "not_configured",
    "not_required",
    "pending",
    "rotation_required",
    "scheduled",
    "completed_metadata_only",
    "failed",
];

#[derive(Clone)]
pub enum AgentPkiStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentPkiProviderWriteRequest {
    pub ca_provider_id: Option<String>,
    pub provider_name: Option<String>,
    pub provider_type: Option<String>,
    pub provider_status: Option<String>,
    pub trust_domain: Option<String>,
    pub issuing_policy: Option<String>,
    pub allowed_agent_profiles: Option<Vec<String>>,
    pub certificate_lifetime_days: Option<i64>,
    pub renewal_window_days: Option<i64>,
    pub revocation_mode: Option<String>,
    pub crl_or_ocsp_reference: Option<String>,
    pub key_storage_policy: Option<String>,
    pub secret_reference_status: Option<String>,
    pub known_limitations: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentPkiProvider {
    pub id: i64,
    pub tenant_id: i64,
    pub ca_provider_id: String,
    pub provider_name: String,
    pub provider_type: String,
    pub provider_status: String,
    pub trust_domain: String,
    pub issuing_policy: String,
    pub allowed_agent_profiles: Vec<String>,
    pub certificate_lifetime_days: i64,
    pub renewal_window_days: i64,
    pub revocation_mode: String,
    pub crl_or_ocsp_reference: String,
    pub key_storage_policy: String,
    pub secret_reference_status: String,
    pub known_limitations: String,
    pub created_by_id: Option<i64>,
    pub created_at: String,
    pub updated_at: String,
    pub last_validation_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentCertificateRequestCreateRequest {
    pub csr_id: Option<String>,
    pub agent_id: Option<i64>,
    pub agent_ref: Option<String>,
    pub asset_id: Option<i64>,
    pub asset_ref: Option<String>,
    pub subject_common_name: String,
    pub subject_alt_names: Option<Vec<String>>,
    pub key_algorithm: Option<String>,
    pub key_size_or_curve: Option<String>,
    pub requested_usages: Option<Vec<String>>,
    pub requested_lifetime_days: Option<i64>,
    pub csr_fingerprint: Option<String>,
    pub csr_pem_redacted_or_hash: Option<String>,
    pub public_key_fingerprint: Option<String>,
    pub ca_provider_id: Option<String>,
    pub audit_summary: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentCertificateRequestDecisionRequest {
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentCertificateRequest {
    pub id: i64,
    pub tenant_id: i64,
    pub csr_id: String,
    pub agent_id: Option<i64>,
    pub agent_ref: String,
    pub asset_id: Option<i64>,
    pub asset_ref: String,
    pub subject_common_name: String,
    pub subject_alt_names: Vec<String>,
    pub key_algorithm: String,
    pub key_size_or_curve: String,
    pub requested_usages: Vec<String>,
    pub requested_lifetime_days: i64,
    pub csr_status: String,
    pub csr_fingerprint: String,
    pub csr_pem_redacted_or_hash: String,
    pub public_key_fingerprint: String,
    pub requested_by: Option<i64>,
    pub requested_at: String,
    pub approved_by: Option<i64>,
    pub approved_at: Option<String>,
    pub rejected_by: Option<i64>,
    pub rejected_at: Option<String>,
    pub rejection_reason: String,
    pub ca_provider_id: String,
    pub certificate_id: String,
    pub audit_summary: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentCertificateStatusUpdateRequest {
    pub agent_id: Option<i64>,
    pub ca_provider_id: Option<String>,
    pub serial_number_hash: Option<String>,
    pub serial_reference: Option<String>,
    pub subject_summary: Option<String>,
    pub san_summary: Option<String>,
    pub issuer_summary: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub fingerprint_sha256: Option<String>,
    pub certificate_status: Option<String>,
    pub mtls_binding_status: Option<String>,
    pub rotation_status: Option<String>,
    pub revocation_status: Option<String>,
    pub evidence_ids: Option<Vec<i64>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentCertificateStatus {
    pub id: i64,
    pub tenant_id: i64,
    pub certificate_id: String,
    pub agent_id: Option<i64>,
    pub ca_provider_id: String,
    pub serial_number_hash: String,
    pub serial_reference: String,
    pub subject_summary: String,
    pub san_summary: String,
    pub issuer_summary: String,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub fingerprint_sha256: String,
    pub certificate_status: String,
    pub mtls_binding_status: String,
    pub rotation_status: String,
    pub revocation_status: String,
    pub last_seen_at: Option<String>,
    pub last_validation_at: Option<String>,
    pub evidence_ids: Vec<i64>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentPkiEvent {
    pub id: i64,
    pub tenant_id: i64,
    pub object_type: String,
    pub object_id: String,
    pub event_type: String,
    pub actor_id: Option<i64>,
    pub status: String,
    pub summary: String,
    pub error_class: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentPkiOverview {
    pub tenant_id: i64,
    pub provider_count: i64,
    pub configured_provider_count: i64,
    pub csr_count: i64,
    pub pending_csr_count: i64,
    pub certificate_count: i64,
    pub agents_without_certificate_status: i64,
    pub expiring_certificate_count: i64,
    pub expired_certificate_count: i64,
    pub mtls_gap_count: i64,
    pub rotation_required_count: i64,
    pub revocation_requested_count: i64,
    pub providers: Vec<AgentPkiProvider>,
    pub csrs: Vec<AgentCertificateRequest>,
    pub certificates: Vec<AgentCertificateStatus>,
}

impl AgentPkiStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Agent-PKI-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Agent-PKI-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Agent-PKI-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn overview(&self, tenant_id: i64, limit: i64) -> anyhow::Result<AgentPkiOverview> {
        let limit = clamp_limit(limit);
        match self {
            Self::Postgres(pool) => overview_postgres(pool, tenant_id, limit).await,
            Self::Sqlite(pool) => overview_sqlite(pool, tenant_id, limit).await,
        }
    }

    pub async fn agent_overview(
        &self,
        tenant_id: i64,
        agent_id: i64,
    ) -> anyhow::Result<AgentPkiOverview> {
        match self {
            Self::Postgres(pool) => agent_overview_postgres(pool, tenant_id, agent_id).await,
            Self::Sqlite(pool) => agent_overview_sqlite(pool, tenant_id, agent_id).await,
        }
    }

    pub async fn list_providers(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<AgentPkiProvider>> {
        let limit = clamp_limit(limit);
        match self {
            Self::Postgres(pool) => list_providers_postgres(pool, tenant_id, limit).await,
            Self::Sqlite(pool) => list_providers_sqlite(pool, tenant_id, limit).await,
        }
    }

    pub async fn provider_detail(
        &self,
        tenant_id: i64,
        ca_provider_id: &str,
    ) -> anyhow::Result<Option<AgentPkiProvider>> {
        match self {
            Self::Postgres(pool) => get_provider_postgres(pool, tenant_id, ca_provider_id).await,
            Self::Sqlite(pool) => get_provider_sqlite(pool, tenant_id, ca_provider_id).await,
        }
    }

    pub async fn create_provider(
        &self,
        tenant_id: i64,
        actor_id: i64,
        payload: AgentPkiProviderWriteRequest,
    ) -> anyhow::Result<AgentPkiProvider> {
        match self {
            Self::Postgres(pool) => {
                create_provider_postgres(pool, tenant_id, actor_id, payload).await
            }
            Self::Sqlite(pool) => create_provider_sqlite(pool, tenant_id, actor_id, payload).await,
        }
    }

    pub async fn update_provider(
        &self,
        tenant_id: i64,
        actor_id: i64,
        ca_provider_id: &str,
        payload: AgentPkiProviderWriteRequest,
    ) -> anyhow::Result<Option<AgentPkiProvider>> {
        match self {
            Self::Postgres(pool) => {
                update_provider_postgres(pool, tenant_id, actor_id, ca_provider_id, payload).await
            }
            Self::Sqlite(pool) => {
                update_provider_sqlite(pool, tenant_id, actor_id, ca_provider_id, payload).await
            }
        }
    }

    pub async fn list_csrs(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<AgentCertificateRequest>> {
        let limit = clamp_limit(limit);
        match self {
            Self::Postgres(pool) => list_csrs_postgres(pool, tenant_id, limit).await,
            Self::Sqlite(pool) => list_csrs_sqlite(pool, tenant_id, limit).await,
        }
    }

    pub async fn csr_detail(
        &self,
        tenant_id: i64,
        csr_id: &str,
    ) -> anyhow::Result<Option<AgentCertificateRequest>> {
        match self {
            Self::Postgres(pool) => get_csr_postgres(pool, tenant_id, csr_id).await,
            Self::Sqlite(pool) => get_csr_sqlite(pool, tenant_id, csr_id).await,
        }
    }

    pub async fn create_csr(
        &self,
        tenant_id: i64,
        actor_id: i64,
        payload: AgentCertificateRequestCreateRequest,
    ) -> anyhow::Result<AgentCertificateRequest> {
        match self {
            Self::Postgres(pool) => create_csr_postgres(pool, tenant_id, actor_id, payload).await,
            Self::Sqlite(pool) => create_csr_sqlite(pool, tenant_id, actor_id, payload).await,
        }
    }

    pub async fn approve_csr(
        &self,
        tenant_id: i64,
        actor_id: i64,
        csr_id: &str,
    ) -> anyhow::Result<Option<AgentCertificateRequest>> {
        self.transition_csr(
            tenant_id,
            actor_id,
            csr_id,
            "approved_for_issue",
            "",
            "csr_approved",
        )
        .await
    }

    pub async fn reject_csr(
        &self,
        tenant_id: i64,
        actor_id: i64,
        csr_id: &str,
        reason: &str,
    ) -> anyhow::Result<Option<AgentCertificateRequest>> {
        let reason = clean_text(reason, 512);
        if reason.is_empty() {
            bail!("Ablehnungsgrund ist erforderlich");
        }
        self.transition_csr(
            tenant_id,
            actor_id,
            csr_id,
            "rejected",
            &reason,
            "csr_rejected",
        )
        .await
    }

    pub async fn cancel_csr(
        &self,
        tenant_id: i64,
        actor_id: i64,
        csr_id: &str,
    ) -> anyhow::Result<Option<AgentCertificateRequest>> {
        self.transition_csr(
            tenant_id,
            actor_id,
            csr_id,
            "cancelled",
            "",
            "csr_cancelled",
        )
        .await
    }

    async fn transition_csr(
        &self,
        tenant_id: i64,
        actor_id: i64,
        csr_id: &str,
        status: &str,
        reason: &str,
        event_type: &str,
    ) -> anyhow::Result<Option<AgentCertificateRequest>> {
        let status = require_allowed(status, CSR_STATUSES, "csr_status")?;
        match self {
            Self::Postgres(pool) => {
                transition_csr_postgres(
                    pool, tenant_id, actor_id, csr_id, &status, reason, event_type,
                )
                .await
            }
            Self::Sqlite(pool) => {
                transition_csr_sqlite(
                    pool, tenant_id, actor_id, csr_id, &status, reason, event_type,
                )
                .await
            }
        }
    }

    pub async fn list_certificates(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<AgentCertificateStatus>> {
        let limit = clamp_limit(limit);
        match self {
            Self::Postgres(pool) => list_certificates_postgres(pool, tenant_id, limit).await,
            Self::Sqlite(pool) => list_certificates_sqlite(pool, tenant_id, limit).await,
        }
    }

    pub async fn certificate_detail(
        &self,
        tenant_id: i64,
        certificate_id: &str,
    ) -> anyhow::Result<Option<AgentCertificateStatus>> {
        match self {
            Self::Postgres(pool) => get_certificate_postgres(pool, tenant_id, certificate_id).await,
            Self::Sqlite(pool) => get_certificate_sqlite(pool, tenant_id, certificate_id).await,
        }
    }

    pub async fn update_certificate_status(
        &self,
        tenant_id: i64,
        actor_id: i64,
        certificate_id: &str,
        payload: AgentCertificateStatusUpdateRequest,
    ) -> anyhow::Result<AgentCertificateStatus> {
        match self {
            Self::Postgres(pool) => {
                update_certificate_status_postgres(
                    pool,
                    tenant_id,
                    actor_id,
                    certificate_id,
                    payload,
                )
                .await
            }
            Self::Sqlite(pool) => {
                update_certificate_status_sqlite(pool, tenant_id, actor_id, certificate_id, payload)
                    .await
            }
        }
    }

    pub async fn mark_rotation_required(
        &self,
        tenant_id: i64,
        actor_id: i64,
        certificate_id: &str,
    ) -> anyhow::Result<Option<AgentCertificateStatus>> {
        match self {
            Self::Postgres(pool) => {
                mark_certificate_flag_postgres(
                    pool,
                    tenant_id,
                    actor_id,
                    certificate_id,
                    "rotation_required",
                    "not_applicable",
                    "rotation_required",
                )
                .await
            }
            Self::Sqlite(pool) => {
                mark_certificate_flag_sqlite(
                    pool,
                    tenant_id,
                    actor_id,
                    certificate_id,
                    "rotation_required",
                    "not_applicable",
                    "rotation_required",
                )
                .await
            }
        }
    }

    pub async fn request_revocation(
        &self,
        tenant_id: i64,
        actor_id: i64,
        certificate_id: &str,
    ) -> anyhow::Result<Option<AgentCertificateStatus>> {
        match self {
            Self::Postgres(pool) => {
                mark_certificate_flag_postgres(
                    pool,
                    tenant_id,
                    actor_id,
                    certificate_id,
                    "not_applicable",
                    "revocation_requested",
                    "revocation_requested",
                )
                .await
            }
            Self::Sqlite(pool) => {
                mark_certificate_flag_sqlite(
                    pool,
                    tenant_id,
                    actor_id,
                    certificate_id,
                    "not_applicable",
                    "revocation_requested",
                    "revocation_requested",
                )
                .await
            }
        }
    }
}

fn clamp_limit(limit: i64) -> i64 {
    limit.clamp(1, 100)
}

fn clean_text(value: &str, max_len: usize) -> String {
    value.trim().chars().take(max_len).collect()
}

fn validate_safe_metadata(value: &str, field: &str) -> anyhow::Result<()> {
    let upper = value.to_ascii_uppercase();
    if upper.contains("PRIVATE KEY")
        || upper.contains("BEGIN RSA")
        || upper.contains("BEGIN EC")
        || upper.contains("BEGIN OPENSSH")
        || upper.contains("PASSWORD=")
        || upper.contains("SECRET=")
        || upper.contains("TOKEN=")
    {
        bail!("{field} enthaelt nicht erlaubtes Secret- oder Private-Key-Material");
    }
    if value.contains("/home/") || value.contains("\\Users\\") {
        bail!("{field} enthaelt einen lokalen absoluten Pfad");
    }
    Ok(())
}

fn require_allowed(value: &str, allowed: &[&str], field: &str) -> anyhow::Result<String> {
    let value = value.trim().to_ascii_lowercase();
    if allowed.contains(&value.as_str()) {
        Ok(value)
    } else {
        bail!("Nicht unterstuetzter Wert fuer {field}");
    }
}

fn normalize_identifier(value: Option<&str>, prefix: &str, seed: &str) -> String {
    let raw = value
        .map(clean_identifier)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            let mut hasher = Sha256::new();
            hasher.update(seed.as_bytes());
            hasher.update(Utc::now().to_rfc3339().as_bytes());
            format!("{prefix}-{:x}", hasher.finalize())
                .chars()
                .take(32)
                .collect()
        });
    raw.chars().take(128).collect()
}

fn clean_identifier(value: &str) -> String {
    value
        .trim()
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
        .take(128)
        .collect()
}

fn json_string_array(values: Option<Vec<String>>, max_items: usize) -> anyhow::Result<String> {
    let mut cleaned = Vec::new();
    for value in values.unwrap_or_default().into_iter().take(max_items) {
        let value = clean_text(&value, 255);
        validate_safe_metadata(&value, "Array-Metadaten")?;
        if !value.is_empty() && !cleaned.contains(&value) {
            cleaned.push(value);
        }
    }
    Ok(serde_json::to_string(&cleaned)?)
}

fn json_i64_array(values: Option<Vec<i64>>, max_items: usize) -> anyhow::Result<String> {
    let mut cleaned = Vec::new();
    for value in values.unwrap_or_default().into_iter().take(max_items) {
        if value > 0 && !cleaned.contains(&value) {
            cleaned.push(value);
        }
    }
    Ok(serde_json::to_string(&cleaned)?)
}

fn parse_string_array(raw: String) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(&raw).unwrap_or_default()
}

fn parse_i64_array(raw: String) -> Vec<i64> {
    serde_json::from_str::<Vec<i64>>(&raw).unwrap_or_default()
}

fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn normalize_provider_payload(
    tenant_id: i64,
    actor_id: i64,
    payload: AgentPkiProviderWriteRequest,
) -> anyhow::Result<ProviderValues> {
    let provider_name = clean_text(
        payload
            .provider_name
            .as_deref()
            .unwrap_or("Agent PKI Governance"),
        255,
    );
    validate_safe_metadata(&provider_name, "provider_name")?;
    let provider_type = require_allowed(
        payload.provider_type.as_deref().unwrap_or("not_configured"),
        PROVIDER_TYPES,
        "provider_type",
    )?;
    let provider_status = require_allowed(
        payload
            .provider_status
            .as_deref()
            .unwrap_or("configured_metadata_only"),
        PROVIDER_STATUSES,
        "provider_status",
    )?;
    let ca_provider_id = normalize_identifier(
        payload.ca_provider_id.as_deref(),
        "pki-provider",
        &provider_name,
    );
    let trust_domain = clean_text(
        payload.trust_domain.as_deref().unwrap_or("agent.local"),
        255,
    );
    let issuing_policy = clean_text(
        payload
            .issuing_policy
            .as_deref()
            .unwrap_or("metadata-only; keine produktive CA-Ausstellung"),
        1000,
    );
    let revocation_mode = clean_text(
        payload
            .revocation_mode
            .as_deref()
            .unwrap_or("metadata_only"),
        64,
    );
    let crl_or_ocsp_reference =
        clean_text(payload.crl_or_ocsp_reference.as_deref().unwrap_or(""), 512);
    let key_storage_policy = clean_text(
        payload
            .key_storage_policy
            .as_deref()
            .unwrap_or("private Schlüssel bleiben auf dem Agent; keine Speicherung in ISCY"),
        512,
    );
    let secret_reference_status = clean_text(
        payload
            .secret_reference_status
            .as_deref()
            .unwrap_or("no_secret_configured"),
        64,
    );
    let known_limitations = clean_text(payload.known_limitations.as_deref().unwrap_or("Vorbereitendes Governance-Modell ohne produktive CA, Secrets oder externe Ausstellung."), 1000);
    for (field, value) in [
        ("trust_domain", &trust_domain),
        ("issuing_policy", &issuing_policy),
        ("revocation_mode", &revocation_mode),
        ("crl_or_ocsp_reference", &crl_or_ocsp_reference),
        ("key_storage_policy", &key_storage_policy),
        ("secret_reference_status", &secret_reference_status),
        ("known_limitations", &known_limitations),
    ] {
        validate_safe_metadata(value, field)?;
    }
    let certificate_lifetime_days = payload
        .certificate_lifetime_days
        .unwrap_or(90)
        .clamp(1, 825);
    let renewal_window_days = payload
        .renewal_window_days
        .unwrap_or(30)
        .clamp(1, certificate_lifetime_days);
    Ok(ProviderValues {
        tenant_id,
        ca_provider_id,
        provider_name,
        provider_type,
        provider_status,
        trust_domain,
        issuing_policy,
        allowed_agent_profiles_json: json_string_array(payload.allowed_agent_profiles, 50)?,
        certificate_lifetime_days,
        renewal_window_days,
        revocation_mode,
        crl_or_ocsp_reference,
        key_storage_policy,
        secret_reference_status,
        known_limitations,
        actor_id,
    })
}

struct ProviderValues {
    tenant_id: i64,
    ca_provider_id: String,
    provider_name: String,
    provider_type: String,
    provider_status: String,
    trust_domain: String,
    issuing_policy: String,
    allowed_agent_profiles_json: String,
    certificate_lifetime_days: i64,
    renewal_window_days: i64,
    revocation_mode: String,
    crl_or_ocsp_reference: String,
    key_storage_policy: String,
    secret_reference_status: String,
    known_limitations: String,
    actor_id: i64,
}

fn normalize_csr_payload(
    tenant_id: i64,
    actor_id: i64,
    payload: AgentCertificateRequestCreateRequest,
) -> anyhow::Result<CsrValues> {
    let subject_common_name = clean_text(&payload.subject_common_name, 255);
    if subject_common_name.is_empty() {
        bail!("Subject Common Name ist erforderlich");
    }
    validate_safe_metadata(&subject_common_name, "subject_common_name")?;
    let csr_id = normalize_identifier(payload.csr_id.as_deref(), "csr", &subject_common_name);
    let agent_ref = clean_text(payload.agent_ref.as_deref().unwrap_or(""), 255);
    let asset_ref = clean_text(payload.asset_ref.as_deref().unwrap_or(""), 255);
    let key_algorithm = clean_text(payload.key_algorithm.as_deref().unwrap_or("ECDSA"), 64);
    let key_size_or_curve = clean_text(payload.key_size_or_curve.as_deref().unwrap_or("P-256"), 64);
    let ca_provider_id = payload
        .ca_provider_id
        .as_deref()
        .map(clean_identifier)
        .unwrap_or_default();
    let csr_pem_redacted_or_hash = clean_text(
        payload.csr_pem_redacted_or_hash.as_deref().unwrap_or(""),
        255,
    );
    if csr_pem_redacted_or_hash.contains("BEGIN CERTIFICATE REQUEST") {
        bail!("CSR-PEM wird in diesem Governance-Modell nicht roh gespeichert; bitte Fingerprint oder Hash verwenden");
    }
    for (field, value) in [
        ("agent_ref", &agent_ref),
        ("asset_ref", &asset_ref),
        ("key_algorithm", &key_algorithm),
        ("key_size_or_curve", &key_size_or_curve),
        ("csr_pem_redacted_or_hash", &csr_pem_redacted_or_hash),
        ("ca_provider_id", &ca_provider_id),
    ] {
        validate_safe_metadata(value, field)?;
    }
    let subject_alt_names_json = json_string_array(payload.subject_alt_names, 50)?;
    let requested_usages_json = json_string_array(payload.requested_usages, 20)?;
    let requested_lifetime_days = payload.requested_lifetime_days.unwrap_or(90).clamp(1, 825);
    let csr_fingerprint = payload
        .csr_fingerprint
        .map(|value| clean_text(&value, 128))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            sha256_hex(&format!(
                "{tenant_id}:{subject_common_name}:{subject_alt_names_json}"
            ))
        });
    let public_key_fingerprint = payload
        .public_key_fingerprint
        .map(|value| clean_text(&value, 128))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| sha256_hex(&format!("{csr_id}:{key_algorithm}:{key_size_or_curve}")));
    validate_safe_metadata(&csr_fingerprint, "csr_fingerprint")?;
    validate_safe_metadata(&public_key_fingerprint, "public_key_fingerprint")?;
    let audit_summary = clean_text(
        payload
            .audit_summary
            .as_deref()
            .unwrap_or("CSR metadata-only erfasst; keine CA-Ausstellung ausgeloest."),
        1000,
    );
    validate_safe_metadata(&audit_summary, "audit_summary")?;
    Ok(CsrValues {
        tenant_id,
        csr_id,
        agent_id: payload.agent_id,
        agent_ref,
        asset_id: payload.asset_id,
        asset_ref,
        subject_common_name,
        subject_alt_names_json,
        key_algorithm,
        key_size_or_curve,
        requested_usages_json,
        requested_lifetime_days,
        csr_fingerprint,
        csr_pem_redacted_or_hash,
        public_key_fingerprint,
        requested_by: actor_id,
        ca_provider_id,
        audit_summary,
    })
}

struct CsrValues {
    tenant_id: i64,
    csr_id: String,
    agent_id: Option<i64>,
    agent_ref: String,
    asset_id: Option<i64>,
    asset_ref: String,
    subject_common_name: String,
    subject_alt_names_json: String,
    key_algorithm: String,
    key_size_or_curve: String,
    requested_usages_json: String,
    requested_lifetime_days: i64,
    csr_fingerprint: String,
    csr_pem_redacted_or_hash: String,
    public_key_fingerprint: String,
    requested_by: i64,
    ca_provider_id: String,
    audit_summary: String,
}

fn normalize_certificate_payload(
    tenant_id: i64,
    certificate_id: &str,
    payload: AgentCertificateStatusUpdateRequest,
) -> anyhow::Result<CertificateValues> {
    let certificate_id = clean_identifier(certificate_id);
    if certificate_id.is_empty() {
        bail!("certificate_id ist erforderlich");
    }
    let ca_provider_id = payload
        .ca_provider_id
        .as_deref()
        .map(clean_identifier)
        .unwrap_or_default();
    let serial_number_hash = clean_text(payload.serial_number_hash.as_deref().unwrap_or(""), 128);
    let serial_reference = clean_text(
        payload
            .serial_reference
            .as_deref()
            .unwrap_or("metadata-only"),
        255,
    );
    let subject_summary = clean_text(
        payload
            .subject_summary
            .as_deref()
            .unwrap_or("Agent certificate metadata"),
        255,
    );
    let san_summary = clean_text(payload.san_summary.as_deref().unwrap_or(""), 1000);
    let issuer_summary = clean_text(
        payload
            .issuer_summary
            .as_deref()
            .unwrap_or("not_configured"),
        255,
    );
    let fingerprint_sha256 = payload
        .fingerprint_sha256
        .map(|value| clean_text(&value, 128))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| sha256_hex(&format!("{tenant_id}:{certificate_id}:{subject_summary}")));
    let certificate_status = require_allowed(
        payload
            .certificate_status
            .as_deref()
            .unwrap_or("issued_metadata_only"),
        CERTIFICATE_STATUSES,
        "certificate_status",
    )?;
    let mtls_binding_status = require_allowed(
        payload
            .mtls_binding_status
            .as_deref()
            .unwrap_or("not_configured"),
        MTLS_BINDING_STATUSES,
        "mtls_binding_status",
    )?;
    let rotation_status = require_allowed(
        payload
            .rotation_status
            .as_deref()
            .unwrap_or("not_configured"),
        ROTATION_STATUSES,
        "rotation_status",
    )?;
    let revocation_status = require_allowed(
        payload
            .revocation_status
            .as_deref()
            .unwrap_or("not_applicable"),
        REVOCATION_STATUSES,
        "revocation_status",
    )?;
    for (field, value) in [
        ("ca_provider_id", &ca_provider_id),
        ("serial_number_hash", &serial_number_hash),
        ("serial_reference", &serial_reference),
        ("subject_summary", &subject_summary),
        ("san_summary", &san_summary),
        ("issuer_summary", &issuer_summary),
        ("fingerprint_sha256", &fingerprint_sha256),
    ] {
        validate_safe_metadata(value, field)?;
    }
    Ok(CertificateValues {
        tenant_id,
        certificate_id,
        agent_id: payload.agent_id,
        ca_provider_id,
        serial_number_hash,
        serial_reference,
        subject_summary,
        san_summary,
        issuer_summary,
        not_before: payload.not_before.map(|value| clean_text(&value, 64)),
        not_after: payload.not_after.map(|value| clean_text(&value, 64)),
        fingerprint_sha256,
        certificate_status,
        mtls_binding_status,
        rotation_status,
        revocation_status,
        evidence_ids_json: json_i64_array(payload.evidence_ids, 50)?,
    })
}

struct CertificateValues {
    tenant_id: i64,
    certificate_id: String,
    agent_id: Option<i64>,
    ca_provider_id: String,
    serial_number_hash: String,
    serial_reference: String,
    subject_summary: String,
    san_summary: String,
    issuer_summary: String,
    not_before: Option<String>,
    not_after: Option<String>,
    fingerprint_sha256: String,
    certificate_status: String,
    mtls_binding_status: String,
    rotation_status: String,
    revocation_status: String,
    evidence_ids_json: String,
}

struct AgentPkiEventWrite<'a> {
    object_type: &'a str,
    object_id: &'a str,
    event_type: &'a str,
    actor_id: Option<i64>,
    status: &'a str,
    summary: &'a str,
    error_class: &'a str,
}

async fn create_provider_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    actor_id: i64,
    payload: AgentPkiProviderWriteRequest,
) -> anyhow::Result<AgentPkiProvider> {
    let provider = normalize_provider_payload(tenant_id, actor_id, payload)?;
    let row = sqlx::query(provider_insert_sqlite())
        .bind(provider.tenant_id)
        .bind(&provider.ca_provider_id)
        .bind(&provider.provider_name)
        .bind(&provider.provider_type)
        .bind(&provider.provider_status)
        .bind(&provider.trust_domain)
        .bind(&provider.issuing_policy)
        .bind(&provider.allowed_agent_profiles_json)
        .bind(provider.certificate_lifetime_days)
        .bind(provider.renewal_window_days)
        .bind(&provider.revocation_mode)
        .bind(&provider.crl_or_ocsp_reference)
        .bind(&provider.key_storage_policy)
        .bind(&provider.secret_reference_status)
        .bind(&provider.known_limitations)
        .bind(provider.actor_id)
        .fetch_one(pool)
        .await
        .context("SQLite-Agent-PKI-Provider konnte nicht gespeichert werden")?;
    insert_event_sqlite(
        pool,
        tenant_id,
        AgentPkiEventWrite {
            object_type: "provider",
            object_id: &provider.ca_provider_id,
            event_type: "provider_saved",
            actor_id: Some(actor_id),
            status: &provider.provider_status,
            summary: "PKI-Provider-Metadaten gespeichert.",
            error_class: "",
        },
    )
    .await?;
    provider_from_sqlite_row(row)
}

async fn create_provider_postgres(
    pool: &PgPool,
    tenant_id: i64,
    actor_id: i64,
    payload: AgentPkiProviderWriteRequest,
) -> anyhow::Result<AgentPkiProvider> {
    let provider = normalize_provider_payload(tenant_id, actor_id, payload)?;
    let row = sqlx::query(provider_insert_postgres())
        .bind(provider.tenant_id)
        .bind(&provider.ca_provider_id)
        .bind(&provider.provider_name)
        .bind(&provider.provider_type)
        .bind(&provider.provider_status)
        .bind(&provider.trust_domain)
        .bind(&provider.issuing_policy)
        .bind(&provider.allowed_agent_profiles_json)
        .bind(provider.certificate_lifetime_days)
        .bind(provider.renewal_window_days)
        .bind(&provider.revocation_mode)
        .bind(&provider.crl_or_ocsp_reference)
        .bind(&provider.key_storage_policy)
        .bind(&provider.secret_reference_status)
        .bind(&provider.known_limitations)
        .bind(provider.actor_id)
        .fetch_one(pool)
        .await
        .context("PostgreSQL-Agent-PKI-Provider konnte nicht gespeichert werden")?;
    insert_event_postgres(
        pool,
        tenant_id,
        AgentPkiEventWrite {
            object_type: "provider",
            object_id: &provider.ca_provider_id,
            event_type: "provider_saved",
            actor_id: Some(actor_id),
            status: &provider.provider_status,
            summary: "PKI-Provider-Metadaten gespeichert.",
            error_class: "",
        },
    )
    .await?;
    provider_from_pg_row(row)
}

fn provider_insert_sqlite() -> &'static str {
    r#"
    INSERT INTO agent_pki_provider (
        tenant_id, ca_provider_id, provider_name, provider_type, provider_status,
        trust_domain, issuing_policy, allowed_agent_profiles_json,
        certificate_lifetime_days, renewal_window_days, revocation_mode,
        crl_or_ocsp_reference, key_storage_policy, secret_reference_status,
        known_limitations, created_by_id, created_at, updated_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    ON CONFLICT (tenant_id, ca_provider_id) DO UPDATE SET
        provider_name = excluded.provider_name,
        provider_type = excluded.provider_type,
        provider_status = excluded.provider_status,
        trust_domain = excluded.trust_domain,
        issuing_policy = excluded.issuing_policy,
        allowed_agent_profiles_json = excluded.allowed_agent_profiles_json,
        certificate_lifetime_days = excluded.certificate_lifetime_days,
        renewal_window_days = excluded.renewal_window_days,
        revocation_mode = excluded.revocation_mode,
        crl_or_ocsp_reference = excluded.crl_or_ocsp_reference,
        key_storage_policy = excluded.key_storage_policy,
        secret_reference_status = excluded.secret_reference_status,
        known_limitations = excluded.known_limitations,
        updated_at = CURRENT_TIMESTAMP
    RETURNING id, tenant_id, ca_provider_id, provider_name, provider_type, provider_status,
        trust_domain, issuing_policy, allowed_agent_profiles_json, certificate_lifetime_days,
        renewal_window_days, revocation_mode, crl_or_ocsp_reference, key_storage_policy,
        secret_reference_status, known_limitations, created_by_id, created_at, updated_at,
        last_validation_at
    "#
}

fn provider_insert_postgres() -> &'static str {
    r#"
    INSERT INTO agent_pki_provider (
        tenant_id, ca_provider_id, provider_name, provider_type, provider_status,
        trust_domain, issuing_policy, allowed_agent_profiles_json,
        certificate_lifetime_days, renewal_window_days, revocation_mode,
        crl_or_ocsp_reference, key_storage_policy, secret_reference_status,
        known_limitations, created_by_id, created_at, updated_at
    )
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, (CURRENT_TIMESTAMP)::text, (CURRENT_TIMESTAMP)::text)
    ON CONFLICT (tenant_id, ca_provider_id) DO UPDATE SET
        provider_name = excluded.provider_name,
        provider_type = excluded.provider_type,
        provider_status = excluded.provider_status,
        trust_domain = excluded.trust_domain,
        issuing_policy = excluded.issuing_policy,
        allowed_agent_profiles_json = excluded.allowed_agent_profiles_json,
        certificate_lifetime_days = excluded.certificate_lifetime_days,
        renewal_window_days = excluded.renewal_window_days,
        revocation_mode = excluded.revocation_mode,
        crl_or_ocsp_reference = excluded.crl_or_ocsp_reference,
        key_storage_policy = excluded.key_storage_policy,
        secret_reference_status = excluded.secret_reference_status,
        known_limitations = excluded.known_limitations,
        updated_at = (CURRENT_TIMESTAMP)::text
    RETURNING id, tenant_id, ca_provider_id, provider_name, provider_type, provider_status,
        trust_domain, issuing_policy, allowed_agent_profiles_json, certificate_lifetime_days,
        renewal_window_days, revocation_mode, crl_or_ocsp_reference, key_storage_policy,
        secret_reference_status, known_limitations, created_by_id, created_at, updated_at,
        last_validation_at
    "#
}

async fn update_provider_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    actor_id: i64,
    ca_provider_id: &str,
    mut payload: AgentPkiProviderWriteRequest,
) -> anyhow::Result<Option<AgentPkiProvider>> {
    if get_provider_sqlite(pool, tenant_id, ca_provider_id)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    payload.ca_provider_id = Some(ca_provider_id.to_string());
    create_provider_sqlite(pool, tenant_id, actor_id, payload)
        .await
        .map(Some)
}

async fn update_provider_postgres(
    pool: &PgPool,
    tenant_id: i64,
    actor_id: i64,
    ca_provider_id: &str,
    mut payload: AgentPkiProviderWriteRequest,
) -> anyhow::Result<Option<AgentPkiProvider>> {
    if get_provider_postgres(pool, tenant_id, ca_provider_id)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    payload.ca_provider_id = Some(ca_provider_id.to_string());
    create_provider_postgres(pool, tenant_id, actor_id, payload)
        .await
        .map(Some)
}

async fn create_csr_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    actor_id: i64,
    payload: AgentCertificateRequestCreateRequest,
) -> anyhow::Result<AgentCertificateRequest> {
    let csr = normalize_csr_payload(tenant_id, actor_id, payload)?;
    validate_agent_and_provider_sqlite(pool, tenant_id, csr.agent_id, &csr.ca_provider_id).await?;
    let row = sqlx::query(csr_insert_sqlite())
        .bind(csr.tenant_id)
        .bind(&csr.csr_id)
        .bind(csr.agent_id)
        .bind(&csr.agent_ref)
        .bind(csr.asset_id)
        .bind(&csr.asset_ref)
        .bind(&csr.subject_common_name)
        .bind(&csr.subject_alt_names_json)
        .bind(&csr.key_algorithm)
        .bind(&csr.key_size_or_curve)
        .bind(&csr.requested_usages_json)
        .bind(csr.requested_lifetime_days)
        .bind(&csr.csr_fingerprint)
        .bind(&csr.csr_pem_redacted_or_hash)
        .bind(&csr.public_key_fingerprint)
        .bind(csr.requested_by)
        .bind(&csr.ca_provider_id)
        .bind(&csr.audit_summary)
        .fetch_one(pool)
        .await
        .context("SQLite-Agent-CSR konnte nicht gespeichert werden")?;
    insert_event_sqlite(
        pool,
        tenant_id,
        AgentPkiEventWrite {
            object_type: "csr",
            object_id: &csr.csr_id,
            event_type: "csr_created",
            actor_id: Some(actor_id),
            status: "pending_review",
            summary: "CSR metadata-only erfasst.",
            error_class: "",
        },
    )
    .await?;
    csr_from_sqlite_row(row)
}

async fn create_csr_postgres(
    pool: &PgPool,
    tenant_id: i64,
    actor_id: i64,
    payload: AgentCertificateRequestCreateRequest,
) -> anyhow::Result<AgentCertificateRequest> {
    let csr = normalize_csr_payload(tenant_id, actor_id, payload)?;
    validate_agent_and_provider_postgres(pool, tenant_id, csr.agent_id, &csr.ca_provider_id)
        .await?;
    let row = sqlx::query(csr_insert_postgres())
        .bind(csr.tenant_id)
        .bind(&csr.csr_id)
        .bind(csr.agent_id)
        .bind(&csr.agent_ref)
        .bind(csr.asset_id)
        .bind(&csr.asset_ref)
        .bind(&csr.subject_common_name)
        .bind(&csr.subject_alt_names_json)
        .bind(&csr.key_algorithm)
        .bind(&csr.key_size_or_curve)
        .bind(&csr.requested_usages_json)
        .bind(csr.requested_lifetime_days)
        .bind(&csr.csr_fingerprint)
        .bind(&csr.csr_pem_redacted_or_hash)
        .bind(&csr.public_key_fingerprint)
        .bind(csr.requested_by)
        .bind(&csr.ca_provider_id)
        .bind(&csr.audit_summary)
        .fetch_one(pool)
        .await
        .context("PostgreSQL-Agent-CSR konnte nicht gespeichert werden")?;
    insert_event_postgres(
        pool,
        tenant_id,
        AgentPkiEventWrite {
            object_type: "csr",
            object_id: &csr.csr_id,
            event_type: "csr_created",
            actor_id: Some(actor_id),
            status: "pending_review",
            summary: "CSR metadata-only erfasst.",
            error_class: "",
        },
    )
    .await?;
    csr_from_pg_row(row)
}

fn csr_insert_sqlite() -> &'static str {
    r#"
    INSERT INTO agent_certificate_request (
        tenant_id, csr_id, agent_id, agent_ref, asset_id, asset_ref,
        subject_common_name, subject_alt_names_json, key_algorithm,
        key_size_or_curve, requested_usages_json, requested_lifetime_days,
        csr_status, csr_fingerprint, csr_pem_redacted_or_hash,
        public_key_fingerprint, requested_by, requested_at, ca_provider_id,
        audit_summary, created_at, updated_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_review', ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    RETURNING id, tenant_id, csr_id, agent_id, agent_ref, asset_id, asset_ref,
        subject_common_name, subject_alt_names_json, key_algorithm, key_size_or_curve,
        requested_usages_json, requested_lifetime_days, csr_status, csr_fingerprint,
        csr_pem_redacted_or_hash, public_key_fingerprint, requested_by, requested_at,
        approved_by, approved_at, rejected_by, rejected_at, rejection_reason,
        ca_provider_id, certificate_id, audit_summary, created_at, updated_at
    "#
}

fn csr_insert_postgres() -> &'static str {
    r#"
    INSERT INTO agent_certificate_request (
        tenant_id, csr_id, agent_id, agent_ref, asset_id, asset_ref,
        subject_common_name, subject_alt_names_json, key_algorithm,
        key_size_or_curve, requested_usages_json, requested_lifetime_days,
        csr_status, csr_fingerprint, csr_pem_redacted_or_hash,
        public_key_fingerprint, requested_by, requested_at, ca_provider_id,
        audit_summary, created_at, updated_at
    )
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'pending_review', $13, $14, $15, $16, (CURRENT_TIMESTAMP)::text, $17, $18, (CURRENT_TIMESTAMP)::text, (CURRENT_TIMESTAMP)::text)
    RETURNING id, tenant_id, csr_id, agent_id, agent_ref, asset_id, asset_ref,
        subject_common_name, subject_alt_names_json, key_algorithm, key_size_or_curve,
        requested_usages_json, requested_lifetime_days, csr_status, csr_fingerprint,
        csr_pem_redacted_or_hash, public_key_fingerprint, requested_by, requested_at,
        approved_by, approved_at, rejected_by, rejected_at, rejection_reason,
        ca_provider_id, certificate_id, audit_summary, created_at, updated_at
    "#
}

async fn transition_csr_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    actor_id: i64,
    csr_id: &str,
    status: &str,
    reason: &str,
    event_type: &str,
) -> anyhow::Result<Option<AgentCertificateRequest>> {
    let csr_id = clean_identifier(csr_id);
    let row = sqlx::query(&csr_transition_sqlite(status))
        .bind(actor_id)
        .bind(reason)
        .bind(tenant_id)
        .bind(&csr_id)
        .fetch_optional(pool)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    insert_event_sqlite(
        pool,
        tenant_id,
        AgentPkiEventWrite {
            object_type: "csr",
            object_id: &csr_id,
            event_type,
            actor_id: Some(actor_id),
            status,
            summary: "CSR-Status metadata-only aktualisiert.",
            error_class: "",
        },
    )
    .await?;
    csr_from_sqlite_row(row).map(Some)
}

async fn transition_csr_postgres(
    pool: &PgPool,
    tenant_id: i64,
    actor_id: i64,
    csr_id: &str,
    status: &str,
    reason: &str,
    event_type: &str,
) -> anyhow::Result<Option<AgentCertificateRequest>> {
    let csr_id = clean_identifier(csr_id);
    let row = sqlx::query(&csr_transition_postgres(status))
        .bind(actor_id)
        .bind(reason)
        .bind(tenant_id)
        .bind(&csr_id)
        .fetch_optional(pool)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    insert_event_postgres(
        pool,
        tenant_id,
        AgentPkiEventWrite {
            object_type: "csr",
            object_id: &csr_id,
            event_type,
            actor_id: Some(actor_id),
            status,
            summary: "CSR-Status metadata-only aktualisiert.",
            error_class: "",
        },
    )
    .await?;
    csr_from_pg_row(row).map(Some)
}

fn csr_transition_sqlite(status: &str) -> String {
    let assignment = match status {
        "approved_for_issue" => "csr_status = 'approved_for_issue', approved_by = ?1, approved_at = CURRENT_TIMESTAMP, rejected_by = NULL, rejected_at = NULL, rejection_reason = ''",
        "rejected" => "csr_status = 'rejected', rejected_by = ?1, rejected_at = CURRENT_TIMESTAMP, rejection_reason = ?2",
        "cancelled" => "csr_status = 'cancelled', rejected_by = rejected_by, rejection_reason = CASE WHEN ?2 = '' THEN rejection_reason ELSE ?2 END, approved_by = approved_by + (?1 - ?1)",
        _ => "csr_status = 'failed', rejected_by = rejected_by, rejection_reason = CASE WHEN ?2 = '' THEN rejection_reason ELSE ?2 END, approved_by = approved_by + (?1 - ?1)",
    };
    format!("UPDATE agent_certificate_request SET {assignment}, updated_at = CURRENT_TIMESTAMP WHERE tenant_id = ?3 AND csr_id = ?4 RETURNING {CSR_COLUMNS}")
}

fn csr_transition_postgres(status: &str) -> String {
    let assignment = match status {
        "approved_for_issue" => "csr_status = 'approved_for_issue', approved_by = $1, approved_at = (CURRENT_TIMESTAMP)::text, rejected_by = NULL, rejected_at = NULL, rejection_reason = ''",
        "rejected" => "csr_status = 'rejected', rejected_by = $1, rejected_at = (CURRENT_TIMESTAMP)::text, rejection_reason = $2",
        "cancelled" => "csr_status = 'cancelled', rejected_by = rejected_by, rejection_reason = CASE WHEN $2 = '' THEN rejection_reason ELSE $2 END, approved_by = approved_by + ($1 - $1)",
        _ => "csr_status = 'failed', rejected_by = rejected_by, rejection_reason = CASE WHEN $2 = '' THEN rejection_reason ELSE $2 END, approved_by = approved_by + ($1 - $1)",
    };
    format!("UPDATE agent_certificate_request SET {assignment}, updated_at = (CURRENT_TIMESTAMP)::text WHERE tenant_id = $3 AND csr_id = $4 RETURNING {CSR_COLUMNS}")
}

async fn update_certificate_status_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    actor_id: i64,
    certificate_id: &str,
    payload: AgentCertificateStatusUpdateRequest,
) -> anyhow::Result<AgentCertificateStatus> {
    let cert = normalize_certificate_payload(tenant_id, certificate_id, payload)?;
    validate_agent_and_provider_sqlite(pool, tenant_id, cert.agent_id, &cert.ca_provider_id)
        .await?;
    let row = sqlx::query(certificate_upsert_sqlite())
        .bind(cert.tenant_id)
        .bind(&cert.certificate_id)
        .bind(cert.agent_id)
        .bind(&cert.ca_provider_id)
        .bind(&cert.serial_number_hash)
        .bind(&cert.serial_reference)
        .bind(&cert.subject_summary)
        .bind(&cert.san_summary)
        .bind(&cert.issuer_summary)
        .bind(&cert.not_before)
        .bind(&cert.not_after)
        .bind(&cert.fingerprint_sha256)
        .bind(&cert.certificate_status)
        .bind(&cert.mtls_binding_status)
        .bind(&cert.rotation_status)
        .bind(&cert.revocation_status)
        .bind(&cert.evidence_ids_json)
        .fetch_one(pool)
        .await
        .context("SQLite-Agent-Zertifikatsstatus konnte nicht gespeichert werden")?;
    insert_event_sqlite(
        pool,
        tenant_id,
        AgentPkiEventWrite {
            object_type: "certificate",
            object_id: &cert.certificate_id,
            event_type: "certificate_status_updated",
            actor_id: Some(actor_id),
            status: &cert.certificate_status,
            summary: "Zertifikatsstatus metadata-only aktualisiert.",
            error_class: "",
        },
    )
    .await?;
    certificate_from_sqlite_row(row)
}

async fn update_certificate_status_postgres(
    pool: &PgPool,
    tenant_id: i64,
    actor_id: i64,
    certificate_id: &str,
    payload: AgentCertificateStatusUpdateRequest,
) -> anyhow::Result<AgentCertificateStatus> {
    let cert = normalize_certificate_payload(tenant_id, certificate_id, payload)?;
    validate_agent_and_provider_postgres(pool, tenant_id, cert.agent_id, &cert.ca_provider_id)
        .await?;
    let row = sqlx::query(certificate_upsert_postgres())
        .bind(cert.tenant_id)
        .bind(&cert.certificate_id)
        .bind(cert.agent_id)
        .bind(&cert.ca_provider_id)
        .bind(&cert.serial_number_hash)
        .bind(&cert.serial_reference)
        .bind(&cert.subject_summary)
        .bind(&cert.san_summary)
        .bind(&cert.issuer_summary)
        .bind(&cert.not_before)
        .bind(&cert.not_after)
        .bind(&cert.fingerprint_sha256)
        .bind(&cert.certificate_status)
        .bind(&cert.mtls_binding_status)
        .bind(&cert.rotation_status)
        .bind(&cert.revocation_status)
        .bind(&cert.evidence_ids_json)
        .fetch_one(pool)
        .await
        .context("PostgreSQL-Agent-Zertifikatsstatus konnte nicht gespeichert werden")?;
    insert_event_postgres(
        pool,
        tenant_id,
        AgentPkiEventWrite {
            object_type: "certificate",
            object_id: &cert.certificate_id,
            event_type: "certificate_status_updated",
            actor_id: Some(actor_id),
            status: &cert.certificate_status,
            summary: "Zertifikatsstatus metadata-only aktualisiert.",
            error_class: "",
        },
    )
    .await?;
    certificate_from_pg_row(row)
}

fn certificate_upsert_sqlite() -> &'static str {
    r#"
    INSERT INTO agent_certificate_status (
        tenant_id, certificate_id, agent_id, ca_provider_id, serial_number_hash,
        serial_reference, subject_summary, san_summary, issuer_summary, not_before,
        not_after, fingerprint_sha256, certificate_status, mtls_binding_status,
        rotation_status, revocation_status, last_validation_at, evidence_ids_json,
        created_at, updated_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    ON CONFLICT (tenant_id, certificate_id) DO UPDATE SET
        agent_id = excluded.agent_id,
        ca_provider_id = excluded.ca_provider_id,
        serial_number_hash = excluded.serial_number_hash,
        serial_reference = excluded.serial_reference,
        subject_summary = excluded.subject_summary,
        san_summary = excluded.san_summary,
        issuer_summary = excluded.issuer_summary,
        not_before = excluded.not_before,
        not_after = excluded.not_after,
        fingerprint_sha256 = excluded.fingerprint_sha256,
        certificate_status = excluded.certificate_status,
        mtls_binding_status = excluded.mtls_binding_status,
        rotation_status = excluded.rotation_status,
        revocation_status = excluded.revocation_status,
        last_validation_at = CURRENT_TIMESTAMP,
        evidence_ids_json = excluded.evidence_ids_json,
        updated_at = CURRENT_TIMESTAMP
    RETURNING id, tenant_id, certificate_id, agent_id, ca_provider_id,
        serial_number_hash, serial_reference, subject_summary, san_summary,
        issuer_summary, not_before, not_after, fingerprint_sha256,
        certificate_status, mtls_binding_status, rotation_status, revocation_status,
        last_seen_at, last_validation_at, evidence_ids_json, created_at, updated_at
    "#
}

fn certificate_upsert_postgres() -> &'static str {
    r#"
    INSERT INTO agent_certificate_status (
        tenant_id, certificate_id, agent_id, ca_provider_id, serial_number_hash,
        serial_reference, subject_summary, san_summary, issuer_summary, not_before,
        not_after, fingerprint_sha256, certificate_status, mtls_binding_status,
        rotation_status, revocation_status, last_validation_at, evidence_ids_json,
        created_at, updated_at
    )
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, (CURRENT_TIMESTAMP)::text, $17, (CURRENT_TIMESTAMP)::text, (CURRENT_TIMESTAMP)::text)
    ON CONFLICT (tenant_id, certificate_id) DO UPDATE SET
        agent_id = excluded.agent_id,
        ca_provider_id = excluded.ca_provider_id,
        serial_number_hash = excluded.serial_number_hash,
        serial_reference = excluded.serial_reference,
        subject_summary = excluded.subject_summary,
        san_summary = excluded.san_summary,
        issuer_summary = excluded.issuer_summary,
        not_before = excluded.not_before,
        not_after = excluded.not_after,
        fingerprint_sha256 = excluded.fingerprint_sha256,
        certificate_status = excluded.certificate_status,
        mtls_binding_status = excluded.mtls_binding_status,
        rotation_status = excluded.rotation_status,
        revocation_status = excluded.revocation_status,
        last_validation_at = (CURRENT_TIMESTAMP)::text,
        evidence_ids_json = excluded.evidence_ids_json,
        updated_at = (CURRENT_TIMESTAMP)::text
    RETURNING id, tenant_id, certificate_id, agent_id, ca_provider_id,
        serial_number_hash, serial_reference, subject_summary, san_summary,
        issuer_summary, not_before, not_after, fingerprint_sha256,
        certificate_status, mtls_binding_status, rotation_status, revocation_status,
        last_seen_at, last_validation_at, evidence_ids_json, created_at, updated_at
    "#
}

async fn mark_certificate_flag_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    actor_id: i64,
    certificate_id: &str,
    rotation_status: &str,
    revocation_status: &str,
    event_type: &str,
) -> anyhow::Result<Option<AgentCertificateStatus>> {
    let Some(current) = get_certificate_sqlite(pool, tenant_id, certificate_id).await? else {
        return Ok(None);
    };
    let row = sqlx::query(
        r#"
        UPDATE agent_certificate_status
        SET rotation_status = CASE WHEN ?1 <> 'not_applicable' THEN ?1 ELSE rotation_status END,
            revocation_status = CASE WHEN ?2 <> 'not_applicable' THEN ?2 ELSE revocation_status END,
            certificate_status = CASE WHEN ?1 = 'rotation_required' THEN 'rotation_required' ELSE certificate_status END,
            updated_at = CURRENT_TIMESTAMP
        WHERE tenant_id = ?3 AND certificate_id = ?4
        RETURNING id, tenant_id, certificate_id, agent_id, ca_provider_id,
            serial_number_hash, serial_reference, subject_summary, san_summary,
            issuer_summary, not_before, not_after, fingerprint_sha256,
            certificate_status, mtls_binding_status, rotation_status, revocation_status,
            last_seen_at, last_validation_at, evidence_ids_json, created_at, updated_at
        "#,
    )
    .bind(rotation_status)
    .bind(revocation_status)
    .bind(tenant_id)
    .bind(&current.certificate_id)
    .fetch_one(pool)
    .await?;
    insert_event_sqlite(
        pool,
        tenant_id,
        AgentPkiEventWrite {
            object_type: "certificate",
            object_id: &current.certificate_id,
            event_type,
            actor_id: Some(actor_id),
            status: event_type,
            summary: "Zertifikats-Governance-Status markiert.",
            error_class: "",
        },
    )
    .await?;
    certificate_from_sqlite_row(row).map(Some)
}

async fn mark_certificate_flag_postgres(
    pool: &PgPool,
    tenant_id: i64,
    actor_id: i64,
    certificate_id: &str,
    rotation_status: &str,
    revocation_status: &str,
    event_type: &str,
) -> anyhow::Result<Option<AgentCertificateStatus>> {
    let Some(current) = get_certificate_postgres(pool, tenant_id, certificate_id).await? else {
        return Ok(None);
    };
    let row = sqlx::query(
        r#"
        UPDATE agent_certificate_status
        SET rotation_status = CASE WHEN $1 <> 'not_applicable' THEN $1 ELSE rotation_status END,
            revocation_status = CASE WHEN $2 <> 'not_applicable' THEN $2 ELSE revocation_status END,
            certificate_status = CASE WHEN $1 = 'rotation_required' THEN 'rotation_required' ELSE certificate_status END,
            updated_at = (CURRENT_TIMESTAMP)::text
        WHERE tenant_id = $3 AND certificate_id = $4
        RETURNING id, tenant_id, certificate_id, agent_id, ca_provider_id,
            serial_number_hash, serial_reference, subject_summary, san_summary,
            issuer_summary, not_before, not_after, fingerprint_sha256,
            certificate_status, mtls_binding_status, rotation_status, revocation_status,
            last_seen_at, last_validation_at, evidence_ids_json, created_at, updated_at
        "#,
    )
    .bind(rotation_status)
    .bind(revocation_status)
    .bind(tenant_id)
    .bind(&current.certificate_id)
    .fetch_one(pool)
    .await?;
    insert_event_postgres(
        pool,
        tenant_id,
        AgentPkiEventWrite {
            object_type: "certificate",
            object_id: &current.certificate_id,
            event_type,
            actor_id: Some(actor_id),
            status: event_type,
            summary: "Zertifikats-Governance-Status markiert.",
            error_class: "",
        },
    )
    .await?;
    certificate_from_pg_row(row).map(Some)
}

async fn validate_agent_and_provider_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    agent_id: Option<i64>,
    ca_provider_id: &str,
) -> anyhow::Result<()> {
    if let Some(agent_id) = agent_id {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM zero_trust_agent_device WHERE tenant_id = ? AND id = ?",
        )
        .bind(tenant_id)
        .bind(agent_id)
        .fetch_one(pool)
        .await?;
        if count == 0 {
            bail!("Agent gehoert nicht zum Tenant oder existiert nicht");
        }
    }
    if !ca_provider_id.is_empty() {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_pki_provider WHERE tenant_id = ? AND ca_provider_id = ?",
        )
        .bind(tenant_id)
        .bind(ca_provider_id)
        .fetch_one(pool)
        .await?;
        if count == 0 {
            bail!("PKI-Provider gehoert nicht zum Tenant oder existiert nicht");
        }
    }
    Ok(())
}

async fn validate_agent_and_provider_postgres(
    pool: &PgPool,
    tenant_id: i64,
    agent_id: Option<i64>,
    ca_provider_id: &str,
) -> anyhow::Result<()> {
    if let Some(agent_id) = agent_id {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM zero_trust_agent_device WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(agent_id)
        .fetch_one(pool)
        .await?;
        if count == 0 {
            bail!("Agent gehoert nicht zum Tenant oder existiert nicht");
        }
    }
    if !ca_provider_id.is_empty() {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*)::bigint FROM agent_pki_provider WHERE tenant_id = $1 AND ca_provider_id = $2")
                .bind(tenant_id)
                .bind(ca_provider_id)
                .fetch_one(pool)
                .await?;
        if count == 0 {
            bail!("PKI-Provider gehoert nicht zum Tenant oder existiert nicht");
        }
    }
    Ok(())
}

async fn overview_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<AgentPkiOverview> {
    build_overview_sqlite(pool, tenant_id, None, limit).await
}

async fn overview_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<AgentPkiOverview> {
    build_overview_postgres(pool, tenant_id, None, limit).await
}

async fn agent_overview_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    agent_id: i64,
) -> anyhow::Result<AgentPkiOverview> {
    build_overview_sqlite(pool, tenant_id, Some(agent_id), 50).await
}

async fn agent_overview_postgres(
    pool: &PgPool,
    tenant_id: i64,
    agent_id: i64,
) -> anyhow::Result<AgentPkiOverview> {
    build_overview_postgres(pool, tenant_id, Some(agent_id), 50).await
}

async fn build_overview_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    agent_id: Option<i64>,
    limit: i64,
) -> anyhow::Result<AgentPkiOverview> {
    let providers = list_providers_sqlite(pool, tenant_id, limit).await?;
    let csrs = if let Some(agent_id) = agent_id {
        list_csrs_for_agent_sqlite(pool, tenant_id, agent_id, limit).await?
    } else {
        list_csrs_sqlite(pool, tenant_id, limit).await?
    };
    let certificates = if let Some(agent_id) = agent_id {
        list_certificates_for_agent_sqlite(pool, tenant_id, agent_id, limit).await?
    } else {
        list_certificates_sqlite(pool, tenant_id, limit).await?
    };
    Ok(AgentPkiOverview {
        tenant_id,
        provider_count: count_sqlite(pool, "SELECT COUNT(*) FROM agent_pki_provider WHERE tenant_id = ?", tenant_id).await?,
        configured_provider_count: count_sqlite(pool, "SELECT COUNT(*) FROM agent_pki_provider WHERE tenant_id = ? AND provider_status <> 'not_configured'", tenant_id).await?,
        csr_count: count_sqlite(pool, "SELECT COUNT(*) FROM agent_certificate_request WHERE tenant_id = ?", tenant_id).await?,
        pending_csr_count: count_sqlite(pool, "SELECT COUNT(*) FROM agent_certificate_request WHERE tenant_id = ? AND csr_status = 'pending_review'", tenant_id).await?,
        certificate_count: count_sqlite(pool, "SELECT COUNT(*) FROM agent_certificate_status WHERE tenant_id = ?", tenant_id).await?,
        agents_without_certificate_status: count_sqlite(pool, "SELECT COUNT(*) FROM zero_trust_agent_device device WHERE device.tenant_id = ? AND NOT EXISTS (SELECT 1 FROM agent_certificate_status cert WHERE cert.tenant_id = device.tenant_id AND cert.agent_id = device.id)", tenant_id).await?,
        expiring_certificate_count: count_sqlite(pool, "SELECT COUNT(*) FROM agent_certificate_status WHERE tenant_id = ? AND certificate_status = 'expiring_soon'", tenant_id).await?,
        expired_certificate_count: count_sqlite(pool, "SELECT COUNT(*) FROM agent_certificate_status WHERE tenant_id = ? AND certificate_status = 'expired'", tenant_id).await?,
        mtls_gap_count: count_sqlite(pool, "SELECT COUNT(*) FROM agent_certificate_status WHERE tenant_id = ? AND mtls_binding_status IN ('not_configured','pending','mismatch','stale','failed')", tenant_id).await?,
        rotation_required_count: count_sqlite(pool, "SELECT COUNT(*) FROM agent_certificate_status WHERE tenant_id = ? AND rotation_status = 'rotation_required'", tenant_id).await?,
        revocation_requested_count: count_sqlite(pool, "SELECT COUNT(*) FROM agent_certificate_status WHERE tenant_id = ? AND revocation_status = 'revocation_requested'", tenant_id).await?,
        providers,
        csrs,
        certificates,
    })
}

async fn build_overview_postgres(
    pool: &PgPool,
    tenant_id: i64,
    agent_id: Option<i64>,
    limit: i64,
) -> anyhow::Result<AgentPkiOverview> {
    let providers = list_providers_postgres(pool, tenant_id, limit).await?;
    let csrs = if let Some(agent_id) = agent_id {
        list_csrs_for_agent_postgres(pool, tenant_id, agent_id, limit).await?
    } else {
        list_csrs_postgres(pool, tenant_id, limit).await?
    };
    let certificates = if let Some(agent_id) = agent_id {
        list_certificates_for_agent_postgres(pool, tenant_id, agent_id, limit).await?
    } else {
        list_certificates_postgres(pool, tenant_id, limit).await?
    };
    Ok(AgentPkiOverview {
        tenant_id,
        provider_count: count_postgres(pool, "SELECT COUNT(*)::bigint FROM agent_pki_provider WHERE tenant_id = $1", tenant_id).await?,
        configured_provider_count: count_postgres(pool, "SELECT COUNT(*)::bigint FROM agent_pki_provider WHERE tenant_id = $1 AND provider_status <> 'not_configured'", tenant_id).await?,
        csr_count: count_postgres(pool, "SELECT COUNT(*)::bigint FROM agent_certificate_request WHERE tenant_id = $1", tenant_id).await?,
        pending_csr_count: count_postgres(pool, "SELECT COUNT(*)::bigint FROM agent_certificate_request WHERE tenant_id = $1 AND csr_status = 'pending_review'", tenant_id).await?,
        certificate_count: count_postgres(pool, "SELECT COUNT(*)::bigint FROM agent_certificate_status WHERE tenant_id = $1", tenant_id).await?,
        agents_without_certificate_status: count_postgres(pool, "SELECT COUNT(*)::bigint FROM zero_trust_agent_device device WHERE device.tenant_id = $1 AND NOT EXISTS (SELECT 1 FROM agent_certificate_status cert WHERE cert.tenant_id = device.tenant_id AND cert.agent_id = device.id)", tenant_id).await?,
        expiring_certificate_count: count_postgres(pool, "SELECT COUNT(*)::bigint FROM agent_certificate_status WHERE tenant_id = $1 AND certificate_status = 'expiring_soon'", tenant_id).await?,
        expired_certificate_count: count_postgres(pool, "SELECT COUNT(*)::bigint FROM agent_certificate_status WHERE tenant_id = $1 AND certificate_status = 'expired'", tenant_id).await?,
        mtls_gap_count: count_postgres(pool, "SELECT COUNT(*)::bigint FROM agent_certificate_status WHERE tenant_id = $1 AND mtls_binding_status IN ('not_configured','pending','mismatch','stale','failed')", tenant_id).await?,
        rotation_required_count: count_postgres(pool, "SELECT COUNT(*)::bigint FROM agent_certificate_status WHERE tenant_id = $1 AND rotation_status = 'rotation_required'", tenant_id).await?,
        revocation_requested_count: count_postgres(pool, "SELECT COUNT(*)::bigint FROM agent_certificate_status WHERE tenant_id = $1 AND revocation_status = 'revocation_requested'", tenant_id).await?,
        providers,
        csrs,
        certificates,
    })
}

async fn count_sqlite(pool: &SqlitePool, sql: &str, tenant_id: i64) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar(sql)
        .bind(tenant_id)
        .fetch_one(pool)
        .await?)
}

async fn count_postgres(pool: &PgPool, sql: &str, tenant_id: i64) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar(sql)
        .bind(tenant_id)
        .fetch_one(pool)
        .await?)
}

async fn list_providers_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AgentPkiProvider>> {
    let rows = sqlx::query(&format!(
        "SELECT {PROVIDER_COLUMNS} FROM agent_pki_provider WHERE tenant_id = ? ORDER BY provider_name LIMIT ?"
    ))
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(provider_from_sqlite_row).collect()
}

async fn list_providers_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AgentPkiProvider>> {
    let rows = sqlx::query(&format!(
        "SELECT {PROVIDER_COLUMNS} FROM agent_pki_provider WHERE tenant_id = $1 ORDER BY provider_name LIMIT $2"
    ))
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(provider_from_pg_row).collect()
}

async fn get_provider_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    ca_provider_id: &str,
) -> anyhow::Result<Option<AgentPkiProvider>> {
    let row = sqlx::query(&format!(
        "SELECT {PROVIDER_COLUMNS} FROM agent_pki_provider WHERE tenant_id = ? AND ca_provider_id = ?"
    ))
    .bind(tenant_id)
    .bind(ca_provider_id)
    .fetch_optional(pool)
    .await?;
    row.map(provider_from_sqlite_row).transpose()
}

async fn get_provider_postgres(
    pool: &PgPool,
    tenant_id: i64,
    ca_provider_id: &str,
) -> anyhow::Result<Option<AgentPkiProvider>> {
    let row = sqlx::query(&format!(
        "SELECT {PROVIDER_COLUMNS} FROM agent_pki_provider WHERE tenant_id = $1 AND ca_provider_id = $2"
    ))
    .bind(tenant_id)
    .bind(ca_provider_id)
    .fetch_optional(pool)
    .await?;
    row.map(provider_from_pg_row).transpose()
}

async fn list_csrs_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AgentCertificateRequest>> {
    let rows = sqlx::query(&format!(
        "SELECT {CSR_COLUMNS} FROM agent_certificate_request WHERE tenant_id = ? ORDER BY requested_at DESC, id DESC LIMIT ?"
    ))
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(csr_from_sqlite_row).collect()
}

async fn list_csrs_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AgentCertificateRequest>> {
    let rows = sqlx::query(&format!(
        "SELECT {CSR_COLUMNS} FROM agent_certificate_request WHERE tenant_id = $1 ORDER BY requested_at DESC, id DESC LIMIT $2"
    ))
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(csr_from_pg_row).collect()
}

async fn list_csrs_for_agent_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    agent_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AgentCertificateRequest>> {
    let rows = sqlx::query(&format!(
        "SELECT {CSR_COLUMNS} FROM agent_certificate_request WHERE tenant_id = ? AND agent_id = ? ORDER BY requested_at DESC, id DESC LIMIT ?"
    ))
    .bind(tenant_id)
    .bind(agent_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(csr_from_sqlite_row).collect()
}

async fn list_csrs_for_agent_postgres(
    pool: &PgPool,
    tenant_id: i64,
    agent_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AgentCertificateRequest>> {
    let rows = sqlx::query(&format!(
        "SELECT {CSR_COLUMNS} FROM agent_certificate_request WHERE tenant_id = $1 AND agent_id = $2 ORDER BY requested_at DESC, id DESC LIMIT $3"
    ))
    .bind(tenant_id)
    .bind(agent_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(csr_from_pg_row).collect()
}

async fn get_csr_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    csr_id: &str,
) -> anyhow::Result<Option<AgentCertificateRequest>> {
    let row = sqlx::query(&format!(
        "SELECT {CSR_COLUMNS} FROM agent_certificate_request WHERE tenant_id = ? AND csr_id = ?"
    ))
    .bind(tenant_id)
    .bind(csr_id)
    .fetch_optional(pool)
    .await?;
    row.map(csr_from_sqlite_row).transpose()
}

async fn get_csr_postgres(
    pool: &PgPool,
    tenant_id: i64,
    csr_id: &str,
) -> anyhow::Result<Option<AgentCertificateRequest>> {
    let row = sqlx::query(&format!(
        "SELECT {CSR_COLUMNS} FROM agent_certificate_request WHERE tenant_id = $1 AND csr_id = $2"
    ))
    .bind(tenant_id)
    .bind(csr_id)
    .fetch_optional(pool)
    .await?;
    row.map(csr_from_pg_row).transpose()
}

async fn list_certificates_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AgentCertificateStatus>> {
    let rows = sqlx::query(&format!(
        "SELECT {CERT_COLUMNS} FROM agent_certificate_status WHERE tenant_id = ? ORDER BY updated_at DESC, id DESC LIMIT ?"
    ))
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(certificate_from_sqlite_row).collect()
}

async fn list_certificates_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AgentCertificateStatus>> {
    let rows = sqlx::query(&format!(
        "SELECT {CERT_COLUMNS} FROM agent_certificate_status WHERE tenant_id = $1 ORDER BY updated_at DESC, id DESC LIMIT $2"
    ))
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(certificate_from_pg_row).collect()
}

async fn list_certificates_for_agent_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    agent_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AgentCertificateStatus>> {
    let rows = sqlx::query(&format!(
        "SELECT {CERT_COLUMNS} FROM agent_certificate_status WHERE tenant_id = ? AND agent_id = ? ORDER BY updated_at DESC, id DESC LIMIT ?"
    ))
    .bind(tenant_id)
    .bind(agent_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(certificate_from_sqlite_row).collect()
}

async fn list_certificates_for_agent_postgres(
    pool: &PgPool,
    tenant_id: i64,
    agent_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AgentCertificateStatus>> {
    let rows = sqlx::query(&format!(
        "SELECT {CERT_COLUMNS} FROM agent_certificate_status WHERE tenant_id = $1 AND agent_id = $2 ORDER BY updated_at DESC, id DESC LIMIT $3"
    ))
    .bind(tenant_id)
    .bind(agent_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(certificate_from_pg_row).collect()
}

async fn get_certificate_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    certificate_id: &str,
) -> anyhow::Result<Option<AgentCertificateStatus>> {
    let row = sqlx::query(&format!(
        "SELECT {CERT_COLUMNS} FROM agent_certificate_status WHERE tenant_id = ? AND certificate_id = ?"
    ))
    .bind(tenant_id)
    .bind(certificate_id)
    .fetch_optional(pool)
    .await?;
    row.map(certificate_from_sqlite_row).transpose()
}

async fn get_certificate_postgres(
    pool: &PgPool,
    tenant_id: i64,
    certificate_id: &str,
) -> anyhow::Result<Option<AgentCertificateStatus>> {
    let row = sqlx::query(&format!(
        "SELECT {CERT_COLUMNS} FROM agent_certificate_status WHERE tenant_id = $1 AND certificate_id = $2"
    ))
    .bind(tenant_id)
    .bind(certificate_id)
    .fetch_optional(pool)
    .await?;
    row.map(certificate_from_pg_row).transpose()
}

async fn insert_event_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    event: AgentPkiEventWrite<'_>,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO agent_pki_event (tenant_id, object_type, object_id, event_type, actor_id, status, summary, error_class, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
    )
    .bind(tenant_id)
    .bind(event.object_type)
    .bind(event.object_id)
    .bind(event.event_type)
    .bind(event.actor_id)
    .bind(event.status)
    .bind(event.summary)
    .bind(event.error_class)
    .execute(pool)
    .await
    .context("SQLite-Agent-PKI-Audit konnte nicht geschrieben werden")?;
    Ok(())
}

async fn insert_event_postgres(
    pool: &PgPool,
    tenant_id: i64,
    event: AgentPkiEventWrite<'_>,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO agent_pki_event (tenant_id, object_type, object_id, event_type, actor_id, status, summary, error_class, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, (CURRENT_TIMESTAMP)::text)",
    )
    .bind(tenant_id)
    .bind(event.object_type)
    .bind(event.object_id)
    .bind(event.event_type)
    .bind(event.actor_id)
    .bind(event.status)
    .bind(event.summary)
    .bind(event.error_class)
    .execute(pool)
    .await
    .context("PostgreSQL-Agent-PKI-Audit konnte nicht geschrieben werden")?;
    Ok(())
}

const PROVIDER_COLUMNS: &str = "id, tenant_id, ca_provider_id, provider_name, provider_type, provider_status, trust_domain, issuing_policy, allowed_agent_profiles_json, certificate_lifetime_days, renewal_window_days, revocation_mode, crl_or_ocsp_reference, key_storage_policy, secret_reference_status, known_limitations, created_by_id, created_at, updated_at, last_validation_at";
const CSR_COLUMNS: &str = "id, tenant_id, csr_id, agent_id, agent_ref, asset_id, asset_ref, subject_common_name, subject_alt_names_json, key_algorithm, key_size_or_curve, requested_usages_json, requested_lifetime_days, csr_status, csr_fingerprint, csr_pem_redacted_or_hash, public_key_fingerprint, requested_by, requested_at, approved_by, approved_at, rejected_by, rejected_at, rejection_reason, ca_provider_id, certificate_id, audit_summary, created_at, updated_at";
const CERT_COLUMNS: &str = "id, tenant_id, certificate_id, agent_id, ca_provider_id, serial_number_hash, serial_reference, subject_summary, san_summary, issuer_summary, not_before, not_after, fingerprint_sha256, certificate_status, mtls_binding_status, rotation_status, revocation_status, last_seen_at, last_validation_at, evidence_ids_json, created_at, updated_at";

fn provider_from_sqlite_row(row: SqliteRow) -> anyhow::Result<AgentPkiProvider> {
    Ok(AgentPkiProvider {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        ca_provider_id: row.try_get("ca_provider_id")?,
        provider_name: row.try_get("provider_name")?,
        provider_type: row.try_get("provider_type")?,
        provider_status: row.try_get("provider_status")?,
        trust_domain: row.try_get("trust_domain")?,
        issuing_policy: row.try_get("issuing_policy")?,
        allowed_agent_profiles: parse_string_array(row.try_get("allowed_agent_profiles_json")?),
        certificate_lifetime_days: row.try_get("certificate_lifetime_days")?,
        renewal_window_days: row.try_get("renewal_window_days")?,
        revocation_mode: row.try_get("revocation_mode")?,
        crl_or_ocsp_reference: row.try_get("crl_or_ocsp_reference")?,
        key_storage_policy: row.try_get("key_storage_policy")?,
        secret_reference_status: row.try_get("secret_reference_status")?,
        known_limitations: row.try_get("known_limitations")?,
        created_by_id: row.try_get("created_by_id")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        last_validation_at: row.try_get("last_validation_at")?,
    })
}

fn provider_from_pg_row(row: PgRow) -> anyhow::Result<AgentPkiProvider> {
    Ok(AgentPkiProvider {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        ca_provider_id: row.try_get("ca_provider_id")?,
        provider_name: row.try_get("provider_name")?,
        provider_type: row.try_get("provider_type")?,
        provider_status: row.try_get("provider_status")?,
        trust_domain: row.try_get("trust_domain")?,
        issuing_policy: row.try_get("issuing_policy")?,
        allowed_agent_profiles: parse_string_array(row.try_get("allowed_agent_profiles_json")?),
        certificate_lifetime_days: row.try_get("certificate_lifetime_days")?,
        renewal_window_days: row.try_get("renewal_window_days")?,
        revocation_mode: row.try_get("revocation_mode")?,
        crl_or_ocsp_reference: row.try_get("crl_or_ocsp_reference")?,
        key_storage_policy: row.try_get("key_storage_policy")?,
        secret_reference_status: row.try_get("secret_reference_status")?,
        known_limitations: row.try_get("known_limitations")?,
        created_by_id: row.try_get("created_by_id")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        last_validation_at: row.try_get("last_validation_at")?,
    })
}

fn csr_from_sqlite_row(row: SqliteRow) -> anyhow::Result<AgentCertificateRequest> {
    Ok(AgentCertificateRequest {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        csr_id: row.try_get("csr_id")?,
        agent_id: row.try_get("agent_id")?,
        agent_ref: row.try_get("agent_ref")?,
        asset_id: row.try_get("asset_id")?,
        asset_ref: row.try_get("asset_ref")?,
        subject_common_name: row.try_get("subject_common_name")?,
        subject_alt_names: parse_string_array(row.try_get("subject_alt_names_json")?),
        key_algorithm: row.try_get("key_algorithm")?,
        key_size_or_curve: row.try_get("key_size_or_curve")?,
        requested_usages: parse_string_array(row.try_get("requested_usages_json")?),
        requested_lifetime_days: row.try_get("requested_lifetime_days")?,
        csr_status: row.try_get("csr_status")?,
        csr_fingerprint: row.try_get("csr_fingerprint")?,
        csr_pem_redacted_or_hash: row.try_get("csr_pem_redacted_or_hash")?,
        public_key_fingerprint: row.try_get("public_key_fingerprint")?,
        requested_by: row.try_get("requested_by")?,
        requested_at: row.try_get("requested_at")?,
        approved_by: row.try_get("approved_by")?,
        approved_at: row.try_get("approved_at")?,
        rejected_by: row.try_get("rejected_by")?,
        rejected_at: row.try_get("rejected_at")?,
        rejection_reason: row.try_get("rejection_reason")?,
        ca_provider_id: row.try_get("ca_provider_id")?,
        certificate_id: row.try_get("certificate_id")?,
        audit_summary: row.try_get("audit_summary")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn csr_from_pg_row(row: PgRow) -> anyhow::Result<AgentCertificateRequest> {
    Ok(AgentCertificateRequest {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        csr_id: row.try_get("csr_id")?,
        agent_id: row.try_get("agent_id")?,
        agent_ref: row.try_get("agent_ref")?,
        asset_id: row.try_get("asset_id")?,
        asset_ref: row.try_get("asset_ref")?,
        subject_common_name: row.try_get("subject_common_name")?,
        subject_alt_names: parse_string_array(row.try_get("subject_alt_names_json")?),
        key_algorithm: row.try_get("key_algorithm")?,
        key_size_or_curve: row.try_get("key_size_or_curve")?,
        requested_usages: parse_string_array(row.try_get("requested_usages_json")?),
        requested_lifetime_days: row.try_get("requested_lifetime_days")?,
        csr_status: row.try_get("csr_status")?,
        csr_fingerprint: row.try_get("csr_fingerprint")?,
        csr_pem_redacted_or_hash: row.try_get("csr_pem_redacted_or_hash")?,
        public_key_fingerprint: row.try_get("public_key_fingerprint")?,
        requested_by: row.try_get("requested_by")?,
        requested_at: row.try_get("requested_at")?,
        approved_by: row.try_get("approved_by")?,
        approved_at: row.try_get("approved_at")?,
        rejected_by: row.try_get("rejected_by")?,
        rejected_at: row.try_get("rejected_at")?,
        rejection_reason: row.try_get("rejection_reason")?,
        ca_provider_id: row.try_get("ca_provider_id")?,
        certificate_id: row.try_get("certificate_id")?,
        audit_summary: row.try_get("audit_summary")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn certificate_from_sqlite_row(row: SqliteRow) -> anyhow::Result<AgentCertificateStatus> {
    Ok(AgentCertificateStatus {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        certificate_id: row.try_get("certificate_id")?,
        agent_id: row.try_get("agent_id")?,
        ca_provider_id: row.try_get("ca_provider_id")?,
        serial_number_hash: row.try_get("serial_number_hash")?,
        serial_reference: row.try_get("serial_reference")?,
        subject_summary: row.try_get("subject_summary")?,
        san_summary: row.try_get("san_summary")?,
        issuer_summary: row.try_get("issuer_summary")?,
        not_before: row.try_get("not_before")?,
        not_after: row.try_get("not_after")?,
        fingerprint_sha256: row.try_get("fingerprint_sha256")?,
        certificate_status: row.try_get("certificate_status")?,
        mtls_binding_status: row.try_get("mtls_binding_status")?,
        rotation_status: row.try_get("rotation_status")?,
        revocation_status: row.try_get("revocation_status")?,
        last_seen_at: row.try_get("last_seen_at")?,
        last_validation_at: row.try_get("last_validation_at")?,
        evidence_ids: parse_i64_array(row.try_get("evidence_ids_json")?),
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn certificate_from_pg_row(row: PgRow) -> anyhow::Result<AgentCertificateStatus> {
    Ok(AgentCertificateStatus {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        certificate_id: row.try_get("certificate_id")?,
        agent_id: row.try_get("agent_id")?,
        ca_provider_id: row.try_get("ca_provider_id")?,
        serial_number_hash: row.try_get("serial_number_hash")?,
        serial_reference: row.try_get("serial_reference")?,
        subject_summary: row.try_get("subject_summary")?,
        san_summary: row.try_get("san_summary")?,
        issuer_summary: row.try_get("issuer_summary")?,
        not_before: row.try_get("not_before")?,
        not_after: row.try_get("not_after")?,
        fingerprint_sha256: row.try_get("fingerprint_sha256")?,
        certificate_status: row.try_get("certificate_status")?,
        mtls_binding_status: row.try_get("mtls_binding_status")?,
        rotation_status: row.try_get("rotation_status")?,
        revocation_status: row.try_get("revocation_status")?,
        last_seen_at: row.try_get("last_seen_at")?,
        last_validation_at: row.try_get("last_validation_at")?,
        evidence_ids: parse_i64_array(row.try_get("evidence_ids_json")?),
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}
