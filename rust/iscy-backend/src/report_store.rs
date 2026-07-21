use anyhow::{bail, Context};
use chrono::{NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Postgres, QueryBuilder, Row, Sqlite,
};

use crate::cve_store::normalize_database_url;

#[derive(Clone)]
pub enum ReportStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportSnapshotSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub session_id: i64,
    pub title: String,
    pub applicability_result: String,
    pub iso_readiness_percent: i64,
    pub nis2_readiness_percent: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportSnapshotDetail {
    pub id: i64,
    pub tenant_id: i64,
    pub session_id: i64,
    pub title: String,
    pub executive_summary: String,
    pub applicability_result: String,
    pub iso_readiness_percent: i64,
    pub nis2_readiness_percent: i64,
    pub kritis_readiness_percent: i64,
    pub cra_readiness_percent: i64,
    pub ai_act_readiness_percent: i64,
    pub iec62443_readiness_percent: i64,
    pub iso_sae_21434_readiness_percent: i64,
    pub regulatory_matrix_json: Value,
    pub compliance_versions_json: Value,
    pub product_security_json: Value,
    pub top_gaps_json: Value,
    pub top_measures_json: Value,
    pub roadmap_summary: Value,
    pub domain_scores_json: Value,
    pub next_steps_json: Value,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagementReviewPackageSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub title: String,
    pub template_type: String,
    pub template_name: String,
    pub template_version: String,
    pub period_start: Option<String>,
    pub period_end: Option<String>,
    pub status: String,
    pub status_label: String,
    pub generated_by_id: Option<i64>,
    pub approved_by_id: Option<i64>,
    pub approved_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagementReviewPackageDetail {
    pub id: i64,
    pub tenant_id: i64,
    pub title: String,
    pub template_type: String,
    pub template_name: String,
    pub template_version: String,
    pub period_start: Option<String>,
    pub period_end: Option<String>,
    pub status: String,
    pub status_label: String,
    pub generated_by_id: Option<i64>,
    pub approved_by_id: Option<i64>,
    pub approved_at: Option<String>,
    pub executive_summary: String,
    pub decision_notes: String,
    pub next_actions: String,
    pub metrics_json: Value,
    pub top_risks_json: Value,
    pub control_gaps_json: Value,
    pub evidence_gaps_json: Value,
    pub incident_decisions_json: Value,
    pub roadmap_json: Value,
    pub product_security_json: Value,
    pub agent_posture_json: Value,
    pub ai_governance_json: Value,
    pub supplier_json: Value,
    pub regulatory_context_json: Value,
    pub source_counts_json: Value,
    pub gap_summary_json: Value,
    pub decision_summary_json: Value,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManagementReviewGenerateRequest {
    pub template_type: Option<String>,
    pub title: Option<String>,
    pub period_start: Option<String>,
    pub period_end: Option<String>,
    pub executive_summary: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManagementTemplatePreviewRequest {
    pub period_start: Option<String>,
    pub period_end: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegulatoryReviewSnapshotFilters {
    pub template_type: Option<String>,
    pub status: Option<String>,
    pub period_start: Option<String>,
    pub period_end: Option<String>,
    pub has_open_gaps: Option<bool>,
    pub has_critical_gaps: Option<bool>,
    pub limit: i64,
}

impl Default for RegulatoryReviewSnapshotFilters {
    fn default() -> Self {
        Self {
            template_type: None,
            status: None,
            period_start: None,
            period_end: None,
            has_open_gaps: None,
            has_critical_gaps: None,
            limit: 50,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagementReviewTemplateSummary {
    pub template_type: String,
    pub template_version: String,
    pub name: String,
    pub purpose: String,
    pub regulatory_context: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagementReviewTemplateDetail {
    pub template_type: String,
    pub template_version: String,
    pub name: String,
    pub purpose: String,
    pub regulatory_context: Vec<String>,
    pub data_sources: Vec<String>,
    pub sections: Vec<String>,
    pub snapshot_structure: Vec<String>,
    pub gap_focus: Vec<String>,
    pub review_hints: Vec<String>,
    pub management_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagementReviewTemplatePreview {
    pub tenant_id: i64,
    pub template: ManagementReviewTemplateDetail,
    pub period_start: Option<String>,
    pub period_end: Option<String>,
    pub generated_at: String,
    pub title: String,
    pub executive_summary: String,
    pub metrics_json: Value,
    pub top_risks_json: Value,
    pub control_gaps_json: Value,
    pub evidence_gaps_json: Value,
    pub incident_decisions_json: Value,
    pub roadmap_json: Value,
    pub product_security_json: Value,
    pub agent_posture_json: Value,
    pub ai_governance_json: Value,
    pub supplier_json: Value,
    pub source_counts_json: Value,
    pub gap_summary_json: Value,
    pub decision_summary_json: Value,
    pub regulatory_context_json: Value,
    pub owner_hints_json: Value,
    pub gap_groups_json: Value,
    pub filter_summary_json: Value,
    pub data_completeness_summary_json: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManagementReviewStatusUpdateRequest {
    pub status: String,
    pub decision_notes: Option<String>,
    pub next_actions: Option<String>,
}

impl ReportStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Report-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Report-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-Report-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn list_snapshots(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<ReportSnapshotSummary>> {
        match self {
            Self::Postgres(pool) => list_snapshots_postgres(pool, tenant_id, limit).await,
            Self::Sqlite(pool) => list_snapshots_sqlite(pool, tenant_id, limit).await,
        }
    }

    pub async fn snapshot_detail(
        &self,
        tenant_id: i64,
        report_id: i64,
    ) -> anyhow::Result<Option<ReportSnapshotDetail>> {
        match self {
            Self::Postgres(pool) => snapshot_detail_postgres(pool, tenant_id, report_id).await,
            Self::Sqlite(pool) => snapshot_detail_sqlite(pool, tenant_id, report_id).await,
        }
    }

    pub async fn list_management_reviews(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<ManagementReviewPackageSummary>> {
        match self {
            Self::Postgres(pool) => list_management_reviews_postgres(pool, tenant_id, limit).await,
            Self::Sqlite(pool) => list_management_reviews_sqlite(pool, tenant_id, limit).await,
        }
    }

    pub async fn management_review_detail(
        &self,
        tenant_id: i64,
        review_id: i64,
    ) -> anyhow::Result<Option<ManagementReviewPackageDetail>> {
        match self {
            Self::Postgres(pool) => {
                management_review_detail_postgres(pool, tenant_id, review_id).await
            }
            Self::Sqlite(pool) => management_review_detail_sqlite(pool, tenant_id, review_id).await,
        }
    }

    pub fn management_review_templates() -> Vec<ManagementReviewTemplateSummary> {
        management_review_template_catalog()
            .iter()
            .map(|template| template.summary())
            .collect()
    }

    pub fn regulatory_review_packs() -> Vec<ManagementReviewTemplateSummary> {
        management_review_template_catalog()
            .iter()
            .copied()
            .filter(|template| is_regulatory_review_pack_template_type(template.template_type))
            .map(|template| template.summary())
            .collect()
    }

    pub fn management_review_template(
        template_type: &str,
    ) -> anyhow::Result<ManagementReviewTemplateDetail> {
        Ok(resolve_management_review_template(template_type)?.detail())
    }

    pub fn regulatory_review_pack(
        pack_type: &str,
    ) -> anyhow::Result<ManagementReviewTemplateDetail> {
        Ok(resolve_regulatory_review_pack(pack_type)?.detail())
    }

    pub fn canonical_regulatory_review_pack_type(pack_type: &str) -> anyhow::Result<String> {
        Ok(resolve_regulatory_review_pack(pack_type)?
            .template_type
            .to_string())
    }

    pub fn normalize_regulatory_review_status_filter(status: &str) -> anyhow::Result<String> {
        normalize_management_review_status(status)
    }

    pub fn regulatory_review_snapshot_filter_summary(
        filters: &RegulatoryReviewSnapshotFilters,
    ) -> Value {
        regulatory_review_filter_summary_json(filters)
    }

    pub async fn list_regulatory_review_pack_snapshots(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<ManagementReviewPackageSummary>> {
        match self {
            Self::Postgres(pool) => {
                list_regulatory_review_pack_snapshots_postgres(pool, tenant_id, limit).await
            }
            Self::Sqlite(pool) => {
                list_regulatory_review_pack_snapshots_sqlite(pool, tenant_id, limit).await
            }
        }
    }

    pub async fn list_regulatory_review_pack_snapshots_filtered(
        &self,
        tenant_id: i64,
        filters: RegulatoryReviewSnapshotFilters,
    ) -> anyhow::Result<Vec<ManagementReviewPackageSummary>> {
        match self {
            Self::Postgres(pool) => {
                list_regulatory_review_pack_snapshots_filtered_postgres(pool, tenant_id, &filters)
                    .await
            }
            Self::Sqlite(pool) => {
                list_regulatory_review_pack_snapshots_filtered_sqlite(pool, tenant_id, &filters)
                    .await
            }
        }
    }

    pub async fn regulatory_review_pack_snapshot_detail(
        &self,
        tenant_id: i64,
        review_id: i64,
    ) -> anyhow::Result<Option<ManagementReviewPackageDetail>> {
        let Some(package) = self.management_review_detail(tenant_id, review_id).await? else {
            return Ok(None);
        };
        if is_regulatory_review_pack_template_type(&package.template_type) {
            Ok(Some(package))
        } else {
            Ok(None)
        }
    }

    pub async fn preview_management_review_template(
        &self,
        tenant_id: i64,
        user_id: i64,
        template_type: &str,
        request: ManagementTemplatePreviewRequest,
    ) -> anyhow::Result<ManagementReviewTemplatePreview> {
        match self {
            Self::Postgres(pool) => {
                preview_management_review_template_postgres(
                    pool,
                    tenant_id,
                    user_id,
                    template_type,
                    request,
                )
                .await
            }
            Self::Sqlite(pool) => {
                preview_management_review_template_sqlite(
                    pool,
                    tenant_id,
                    user_id,
                    template_type,
                    request,
                )
                .await
            }
        }
    }

    pub async fn preview_regulatory_review_pack(
        &self,
        tenant_id: i64,
        user_id: i64,
        pack_type: &str,
        request: ManagementTemplatePreviewRequest,
    ) -> anyhow::Result<ManagementReviewTemplatePreview> {
        let template = resolve_regulatory_review_pack(pack_type)?;
        self.preview_management_review_template(tenant_id, user_id, template.template_type, request)
            .await
    }

    pub async fn generate_management_review(
        &self,
        tenant_id: i64,
        user_id: i64,
        request: ManagementReviewGenerateRequest,
    ) -> anyhow::Result<ManagementReviewPackageDetail> {
        match self {
            Self::Postgres(pool) => {
                generate_management_review_postgres(pool, tenant_id, user_id, request).await
            }
            Self::Sqlite(pool) => {
                generate_management_review_sqlite(pool, tenant_id, user_id, request).await
            }
        }
    }

    pub async fn generate_regulatory_review_pack(
        &self,
        tenant_id: i64,
        user_id: i64,
        pack_type: &str,
        mut request: ManagementReviewGenerateRequest,
    ) -> anyhow::Result<ManagementReviewPackageDetail> {
        let template = resolve_regulatory_review_pack(pack_type)?;
        request.template_type = Some(template.template_type.to_string());
        self.generate_management_review(tenant_id, user_id, request)
            .await
    }

    pub async fn update_management_review_status(
        &self,
        tenant_id: i64,
        user_id: i64,
        review_id: i64,
        request: ManagementReviewStatusUpdateRequest,
    ) -> anyhow::Result<Option<ManagementReviewPackageDetail>> {
        match self {
            Self::Postgres(pool) => {
                update_management_review_status_postgres(
                    pool, tenant_id, user_id, review_id, request,
                )
                .await
            }
            Self::Sqlite(pool) => {
                update_management_review_status_sqlite(pool, tenant_id, user_id, review_id, request)
                    .await
            }
        }
    }

    pub async fn audit_management_review_export(
        &self,
        tenant_id: i64,
        user_id: i64,
        review_id: i64,
        template_type: &str,
        export_format: &str,
    ) -> anyhow::Result<()> {
        let action = if is_regulatory_review_pack_template_type(template_type) {
            "regulatory_review_pack_export_generated"
        } else {
            "management_review_export_generated"
        };
        match self {
            Self::Postgres(pool) => {
                audit_management_review_event_postgres(
                    pool,
                    tenant_id,
                    Some(review_id),
                    template_type,
                    action,
                    Some(user_id),
                    &serde_json::json!({ "format": export_format }),
                )
                .await
            }
            Self::Sqlite(pool) => {
                audit_management_review_event_sqlite(
                    pool,
                    tenant_id,
                    Some(review_id),
                    template_type,
                    action,
                    Some(user_id),
                    &serde_json::json!({ "format": export_format }),
                )
                .await
            }
        }
    }
}

#[derive(Clone, Copy)]
struct ManagementReviewTemplateDefinition {
    template_type: &'static str,
    aliases: &'static [&'static str],
    template_version: &'static str,
    name: &'static str,
    purpose: &'static str,
    regulatory_context: &'static [&'static str],
    data_sources: &'static [&'static str],
    sections: &'static [&'static str],
    snapshot_structure: &'static [&'static str],
    gap_focus: &'static [&'static str],
    review_hints: &'static [&'static str],
    management_actions: &'static [&'static str],
}

impl ManagementReviewTemplateDefinition {
    fn summary(self) -> ManagementReviewTemplateSummary {
        ManagementReviewTemplateSummary {
            template_type: self.template_type.to_string(),
            template_version: self.template_version.to_string(),
            name: self.name.to_string(),
            purpose: self.purpose.to_string(),
            regulatory_context: strings(self.regulatory_context),
        }
    }

    fn detail(self) -> ManagementReviewTemplateDetail {
        ManagementReviewTemplateDetail {
            template_type: self.template_type.to_string(),
            template_version: self.template_version.to_string(),
            name: self.name.to_string(),
            purpose: self.purpose.to_string(),
            regulatory_context: strings(self.regulatory_context),
            data_sources: strings(self.data_sources),
            sections: strings(self.sections),
            snapshot_structure: strings(self.snapshot_structure),
            gap_focus: strings(self.gap_focus),
            review_hints: strings(self.review_hints),
            management_actions: strings(self.management_actions),
        }
    }
}

const MANAGEMENT_REVIEW_TEMPLATE_VERSION: &str = "2026.1";

const MANAGEMENT_REVIEW_TEMPLATES: &[ManagementReviewTemplateDefinition] = &[
    ManagementReviewTemplateDefinition {
        template_type: "generic_security_governance",
        aliases: &["generic", "security_governance", "governance"],
        template_version: MANAGEMENT_REVIEW_TEMPLATE_VERSION,
        name: "Generisches Security-Governance-Review",
        purpose: "Fachuebergreifendes Governance-Paket fuer regelmaessige Management-Steuerung.",
        regulatory_context: &["ISO 27001", "NIS2", "DORA", "CRA", "EU AI Act", "GDPR", "KRITIS"],
        data_sources: &[
            "risks",
            "ISCY-27 controls",
            "evidence",
            "incidents",
            "roadmap",
            "product security",
            "supplier reviews",
            "AI governance",
            "agent posture",
            "agent PKI/mTLS governance",
        ],
        sections: &[
            "Management-Zusammenfassung",
            "Risiko- und Control-Lage",
            "Evidence-Reife",
            "Incident- und Regulierungsentscheidungen",
            "Supplier und Product Security",
            "AI Governance",
            "Roadmap-Massnahmen",
            "Management-Entscheidungen",
        ],
        snapshot_structure: &[
            "metrics_json",
            "top_risks_json",
            "control_gaps_json",
            "evidence_gaps_json",
            "incident_decisions_json",
            "roadmap_json",
            "product_security_json",
            "supplier_json",
            "agent_posture_json",
            "ai_governance_json",
        ],
        gap_focus: &[
            "Kritische offene Risiken",
            "Offene ISCY-27-Control-Gaps",
            "Fehlende oder teilweise Evidence",
            "Nicht bewertete Incidents",
            "Offene Roadmap-Arbeit",
        ],
        review_hints: &[
            "Pruefen, ob der Snapshot genug Evidence fuer den Review-Zeitraum enthaelt.",
            "Regulatorische Unterstuetzung von Rechtsberatung oder Zertifizierung trennen.",
            "Entscheidungen und naechste Massnahmen vor der Freigabe dokumentieren.",
        ],
        management_actions: &[
            "Paket freigeben oder zur Nacharbeit zurueckgeben.",
            "Owner fuer kritische Luecken festlegen.",
            "Naechsten Review-Zeitraum und Eskalationspfad bestaetigen.",
        ],
    },
    ManagementReviewTemplateDefinition {
        template_type: "iso27001_management_review",
        aliases: &["iso27001", "iso_27001", "iso-27001"],
        template_version: MANAGEMENT_REVIEW_TEMPLATE_VERSION,
        name: "ISO 27001 Management Review",
        purpose: "Management review package for ISMS steering and continuous improvement.",
        regulatory_context: &["ISO 27001", "ISO 27001:2022 Clause 9.3"],
        data_sources: &[
            "risks",
            "ISCY-27 controls",
            "evidence",
            "incidents",
            "roadmap",
            "supplier reviews",
        ],
        sections: &[
            "ISMS context and scope hints",
            "Risk treatment status",
            "Control and evidence maturity",
            "Incident and nonconformity signals",
            "Supplier assurance",
            "Improvement actions",
            "Management decisions",
        ],
        snapshot_structure: &[
            "metrics_json",
            "top_risks_json",
            "control_gaps_json",
            "evidence_gaps_json",
            "incident_decisions_json",
            "supplier_json",
            "roadmap_json",
        ],
        gap_focus: &[
            "Missing evidence",
            "Open risk treatment",
            "Controls with partial maturity",
            "Overdue supplier reviews",
        ],
        review_hints: &[
            "Use the package as review support, not as certification evidence by itself.",
            "Check whether open gaps need corrective actions or risk acceptance.",
            "Confirm that previous management actions were followed up.",
        ],
        management_actions: &[
            "Approve ISMS improvement priorities.",
            "Decide risk acceptance or additional treatment.",
            "Schedule follow-up evidence collection.",
        ],
    },
    ManagementReviewTemplateDefinition {
        template_type: "nis2_management_summary",
        aliases: &["nis2", "nis-2"],
        template_version: MANAGEMENT_REVIEW_TEMPLATE_VERSION,
        name: "NIS2-Management-Zusammenfassung",
        purpose:
            "Management-Zusammenfassung fuer NIS2-Governance, Incident Readiness und Resilienz-Follow-up.",
        regulatory_context: &[
            "NIS2",
            "Commission Implementing Regulation (EU) 2024/2690 Article 3 best-practice",
        ],
        data_sources: &[
            "incidents",
            "ISCY-27 controls",
            "evidence",
            "roadmap",
            "supplier reviews",
            "agent posture",
            "agent PKI/mTLS governance",
        ],
        sections: &[
            "NIS2-Scope-Hinweise",
            "Incident-Erheblichkeit und Meldebereitschaft",
            "Control- und Evidence-Luecken",
            "Supplier-Abhaengigkeiten",
            "Operative Lage",
            "Management-Entscheidungen",
        ],
        snapshot_structure: &[
            "regulatory_context_json",
            "incident_decisions_json",
            "control_gaps_json",
            "evidence_gaps_json",
            "supplier_json",
            "agent_posture_json",
            "roadmap_json",
        ],
        gap_focus: &[
            "Nicht bewertete Incident-Erheblichkeit",
            "Fehlende Incident-Response-Evidence",
            "Kritische Supplier-Exponierung",
            "Veraltete Agent- oder Monitoring-Lage",
        ],
        review_hints: &[
            "Security Incidents vor Meldeentscheidungen von erheblichen Sicherheitsvorfaellen trennen.",
            "Article-3-Kriterien als strukturierte Best Practice nutzen, wo anwendbar.",
            "Rufbereitschaft, Wochenend- und Eskalationsverantwortung bestaetigen.",
        ],
        management_actions: &[
            "Incident-Klassifizierungsentscheidungen bestaetigen.",
            "Remediation fuer wesentliche Control- und Supplier-Luecken zuweisen.",
            "Massnahmen zur Meldebereitschaft freigeben.",
        ],
    },
    ManagementReviewTemplateDefinition {
        template_type: "dora_ict_risk_supplier_incident_summary",
        aliases: &["dora", "dora_ict", "dora_summary"],
        template_version: MANAGEMENT_REVIEW_TEMPLATE_VERSION,
        name: "DORA-ICT-Risk-, Supplier- und Incident-Zusammenfassung",
        purpose: "Steuerungspaket fuer ICT-Risk, Third-Party-Abhaengigkeiten und Incidents.",
        regulatory_context: &["DORA", "ICT risk management", "ICT third-party risk", "incident reporting"],
        data_sources: &[
            "risks",
            "incidents",
            "supplier reviews",
            "evidence",
            "product security",
            "roadmap",
        ],
        sections: &[
            "ICT-Risk-Profil",
            "Major-Incident- und Review-Signale",
            "Supplier- und Subprocessor-Exponierung",
            "Evidence- und Resilienz-Luecken",
            "Product-Security-Abhaengigkeiten",
            "Management-Entscheidungen",
        ],
        snapshot_structure: &[
            "metrics_json",
            "top_risks_json",
            "incident_decisions_json",
            "supplier_json",
            "product_security_json",
            "evidence_gaps_json",
            "roadmap_json",
        ],
        gap_focus: &[
            "Kritische ICT-Risiken",
            "Ueberfaellige Supplier-Reviews",
            "Offene Incident-Review-Entscheidungen",
            "Product-Security-CVE-Review-Backlog",
        ],
        review_hints: &[
            "Pruefen, ob Financial-Entity- oder ICT-Third-Party-Provider-Flags korrekt gesetzt sind.",
            "Supplier-Konzentration und Exit-Test-Lage pruefen.",
            "Dieses Paket nicht als formale regulatorische Einreichung behandeln.",
        ],
        management_actions: &[
            "ICT-Risk-Remediation-Prioritaeten freigeben.",
            "Kritische Supplier oder fehlende Exit-Tests eskalieren.",
            "Incident-Follow-up-Verantwortung bestaetigen.",
        ],
    },
    ManagementReviewTemplateDefinition {
        template_type: "dsgvo_data_protection_review",
        aliases: &["dsgvo", "gdpr", "data_protection", "privacy_review"],
        template_version: MANAGEMENT_REVIEW_TEMPLATE_VERSION,
        name: "DSGVO-Datenschutz-Review-Paket",
        purpose:
            "Kontextuelles Datenschutz-Paket fuer Evidence-, Incident-, Supplier- und AI-Governance-Reviews.",
        regulatory_context: &["DSGVO", "GDPR", "personal data governance", "data breach review"],
        data_sources: &[
            "tenant regulatory profile",
            "risks",
            "ISCY-27 controls",
            "evidence",
            "evidence integrity and disposition",
            "incidents",
            "supplier reviews",
            "AI governance",
            "roadmap",
        ],
        sections: &[
            "Datenschutz-Scope-Hinweise",
            "Personenbezogene Daten und AI-Governance-Signale",
            "Incident- und Data-Breach-Review-Bereitschaft",
            "Evidence-Integritaet, Legal Hold / Aufbewahrungssperre und Disposition",
            "Supplier- und Subprocessor-Follow-up",
            "Management-Entscheidungen",
        ],
        snapshot_structure: &[
            "regulatory_context_json",
            "metrics_json",
            "evidence_gaps_json",
            "incident_decisions_json",
            "supplier_json",
            "ai_governance_json",
            "roadmap_json",
            "gap_summary_json",
            "decision_summary_json",
        ],
        gap_focus: &[
            "Fehlende oder veraltete Datenschutz-Evidence",
            "Nicht bewertete Incident- und Breach-Review-Entscheidungen",
            "Evidence unter Legal Hold / Aufbewahrungssperre oder Disposition-Review",
            "Supplier-Reviews ohne Evidence-Links",
            "AI-Systeme ohne Risiko-, Evidence- oder Roadmap-Verknuepfung",
        ],
        review_hints: &[
            "Bestaetigen, ob das Tenant-Profil die Verarbeitung personenbezogener Daten noch korrekt abbildet.",
            "Das Paket als Governance-Unterstuetzung nutzen, nicht als Rechtsberatung oder Behoerdeneinreichung.",
            "Evidence-Aufbewahrungsentscheidungen von physischer Dateiloeschung trennen.",
        ],
        management_actions: &[
            "Owner fuer fehlende Datenschutz-Evidence festlegen.",
            "Incident-/Breach-Review-Verantwortung bestaetigen.",
            "Remediation fuer Supplier-, AI- und Evidence-Integritaetsluecken freigeben.",
        ],
    },
    ManagementReviewTemplateDefinition {
        template_type: "kritis_operational_resilience_summary",
        aliases: &["kritis", "critical_infrastructure"],
        template_version: MANAGEMENT_REVIEW_TEMPLATE_VERSION,
        name: "KRITIS Operational Resilience Summary",
        purpose: "Operational resilience review for critical services, incidents and continuity-related gaps.",
        regulatory_context: &["KRITIS", "NIS2", "operational resilience", "BCM"],
        data_sources: &[
            "incidents",
            "risks",
            "ISCY-27 controls",
            "evidence",
            "roadmap",
            "agent posture",
            "agent PKI/mTLS governance",
            "supplier reviews",
        ],
        sections: &[
            "Critical-service scope hints",
            "Incident and continuity posture",
            "Control and evidence gaps",
            "Supplier resilience",
            "Operational monitoring posture",
            "Management actions",
        ],
        snapshot_structure: &[
            "regulatory_context_json",
            "incident_decisions_json",
            "top_risks_json",
            "control_gaps_json",
            "evidence_gaps_json",
            "supplier_json",
            "agent_posture_json",
            "roadmap_json",
        ],
        gap_focus: &[
            "Critical incidents",
            "BCM and monitoring evidence gaps",
            "Critical supplier dependencies",
            "Open operational roadmap items",
        ],
        review_hints: &[
            "Focus on service continuity, escalation and recovery evidence.",
            "Confirm whether KRITIS relevance in the tenant profile is current.",
            "Review supplier dependencies for critical services.",
        ],
        management_actions: &[
            "Approve resilience remediation.",
            "Confirm escalation and continuity test ownership.",
            "Schedule follow-up for missing evidence.",
        ],
    },
];

fn management_review_template_catalog() -> &'static [ManagementReviewTemplateDefinition] {
    MANAGEMENT_REVIEW_TEMPLATES
}

fn is_regulatory_review_pack_template_type(template_type: &str) -> bool {
    matches!(
        template_type,
        "generic_security_governance"
            | "nis2_management_summary"
            | "dora_ict_risk_supplier_incident_summary"
            | "dsgvo_data_protection_review"
    )
}

fn resolve_management_review_template(
    template_type: &str,
) -> anyhow::Result<ManagementReviewTemplateDefinition> {
    let normalized = normalize_template_type(template_type);
    management_review_template_catalog()
        .iter()
        .copied()
        .find(|template| {
            template.template_type == normalized
                || template
                    .aliases
                    .iter()
                    .any(|alias| normalize_template_type(alias) == normalized)
        })
        .with_context(|| format!("Unbekannter Management-Review-Template-Typ: {template_type}"))
}

fn resolve_regulatory_review_pack(
    pack_type: &str,
) -> anyhow::Result<ManagementReviewTemplateDefinition> {
    let template = resolve_management_review_template(pack_type)?;
    if is_regulatory_review_pack_template_type(template.template_type) {
        return Ok(template);
    }
    bail!("Unbekannter Regulatory-Review-Pack-Typ: {pack_type}")
}

fn selected_management_review_template(
    template_type: Option<String>,
) -> anyhow::Result<ManagementReviewTemplateDefinition> {
    let template_type = clean_text(template_type, 64)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "generic_security_governance".to_string());
    resolve_management_review_template(&template_type)
}

fn normalize_template_type(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace(['-', ' '], "_")
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

async fn list_snapshots_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<ReportSnapshotSummary>> {
    let rows = sqlx::query(
        r#"
        SELECT
            id,
            tenant_id,
            session_id,
            title,
            applicability_result,
            iso_readiness_percent::bigint AS iso_readiness_percent,
            nis2_readiness_percent::bigint AS nis2_readiness_percent,
            created_at::text AS created_at,
            updated_at::text AS updated_at
        FROM reports_reportsnapshot
        WHERE tenant_id = $1
        ORDER BY created_at DESC, id DESC
        LIMIT $2
        "#,
    )
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("PostgreSQL-Reportliste konnte nicht gelesen werden")?;

    rows.into_iter()
        .map(summary_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_snapshots_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<ReportSnapshotSummary>> {
    let rows = sqlx::query(
        r#"
        SELECT
            id,
            tenant_id,
            session_id,
            title,
            applicability_result,
            iso_readiness_percent,
            nis2_readiness_percent,
            CAST(created_at AS TEXT) AS created_at,
            CAST(updated_at AS TEXT) AS updated_at
        FROM reports_reportsnapshot
        WHERE tenant_id = ?
        ORDER BY created_at DESC, id DESC
        LIMIT ?
        "#,
    )
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("SQLite-Reportliste konnte nicht gelesen werden")?;

    rows.into_iter()
        .map(summary_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn snapshot_detail_postgres(
    pool: &PgPool,
    tenant_id: i64,
    report_id: i64,
) -> anyhow::Result<Option<ReportSnapshotDetail>> {
    let row = sqlx::query(detail_postgres_sql())
        .bind(tenant_id)
        .bind(report_id)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-Reportdetail konnte nicht gelesen werden")?;

    row.map(detail_from_pg_row).transpose().map_err(Into::into)
}

async fn snapshot_detail_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    report_id: i64,
) -> anyhow::Result<Option<ReportSnapshotDetail>> {
    let row = sqlx::query(detail_sqlite_sql())
        .bind(tenant_id)
        .bind(report_id)
        .fetch_optional(pool)
        .await
        .context("SQLite-Reportdetail konnte nicht gelesen werden")?;

    row.map(detail_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

fn summary_from_pg_row(row: PgRow) -> Result<ReportSnapshotSummary, sqlx::Error> {
    Ok(ReportSnapshotSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        session_id: row.try_get("session_id")?,
        title: row.try_get("title")?,
        applicability_result: row.try_get("applicability_result")?,
        iso_readiness_percent: row.try_get("iso_readiness_percent")?,
        nis2_readiness_percent: row.try_get("nis2_readiness_percent")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn summary_from_sqlite_row(row: SqliteRow) -> Result<ReportSnapshotSummary, sqlx::Error> {
    Ok(ReportSnapshotSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        session_id: row.try_get("session_id")?,
        title: row.try_get("title")?,
        applicability_result: row.try_get("applicability_result")?,
        iso_readiness_percent: row.try_get("iso_readiness_percent")?,
        nis2_readiness_percent: row.try_get("nis2_readiness_percent")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn detail_from_pg_row(row: PgRow) -> Result<ReportSnapshotDetail, sqlx::Error> {
    Ok(ReportSnapshotDetail {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        session_id: row.try_get("session_id")?,
        title: row.try_get("title")?,
        executive_summary: row.try_get("executive_summary")?,
        applicability_result: row.try_get("applicability_result")?,
        iso_readiness_percent: row.try_get("iso_readiness_percent")?,
        nis2_readiness_percent: row.try_get("nis2_readiness_percent")?,
        kritis_readiness_percent: row.try_get("kritis_readiness_percent")?,
        cra_readiness_percent: row.try_get("cra_readiness_percent")?,
        ai_act_readiness_percent: row.try_get("ai_act_readiness_percent")?,
        iec62443_readiness_percent: row.try_get("iec62443_readiness_percent")?,
        iso_sae_21434_readiness_percent: row.try_get("iso_sae_21434_readiness_percent")?,
        regulatory_matrix_json: parse_json_object(row.try_get("regulatory_matrix_json_text")?),
        compliance_versions_json: parse_json_object(row.try_get("compliance_versions_json_text")?),
        product_security_json: parse_json_object(row.try_get("product_security_json_text")?),
        top_gaps_json: parse_json_array(row.try_get("top_gaps_json_text")?),
        top_measures_json: parse_json_array(row.try_get("top_measures_json_text")?),
        roadmap_summary: parse_json_array(row.try_get("roadmap_summary_text")?),
        domain_scores_json: parse_json_array(row.try_get("domain_scores_json_text")?),
        next_steps_json: parse_json_object(row.try_get("next_steps_json_text")?),
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn detail_from_sqlite_row(row: SqliteRow) -> Result<ReportSnapshotDetail, sqlx::Error> {
    Ok(ReportSnapshotDetail {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        session_id: row.try_get("session_id")?,
        title: row.try_get("title")?,
        executive_summary: row.try_get("executive_summary")?,
        applicability_result: row.try_get("applicability_result")?,
        iso_readiness_percent: row.try_get("iso_readiness_percent")?,
        nis2_readiness_percent: row.try_get("nis2_readiness_percent")?,
        kritis_readiness_percent: row.try_get("kritis_readiness_percent")?,
        cra_readiness_percent: row.try_get("cra_readiness_percent")?,
        ai_act_readiness_percent: row.try_get("ai_act_readiness_percent")?,
        iec62443_readiness_percent: row.try_get("iec62443_readiness_percent")?,
        iso_sae_21434_readiness_percent: row.try_get("iso_sae_21434_readiness_percent")?,
        regulatory_matrix_json: parse_json_object(row.try_get("regulatory_matrix_json_text")?),
        compliance_versions_json: parse_json_object(row.try_get("compliance_versions_json_text")?),
        product_security_json: parse_json_object(row.try_get("product_security_json_text")?),
        top_gaps_json: parse_json_array(row.try_get("top_gaps_json_text")?),
        top_measures_json: parse_json_array(row.try_get("top_measures_json_text")?),
        roadmap_summary: parse_json_array(row.try_get("roadmap_summary_text")?),
        domain_scores_json: parse_json_array(row.try_get("domain_scores_json_text")?),
        next_steps_json: parse_json_object(row.try_get("next_steps_json_text")?),
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn detail_postgres_sql() -> &'static str {
    r#"
    SELECT
        id,
        tenant_id,
        session_id,
        title,
        executive_summary,
        applicability_result,
        iso_readiness_percent::bigint AS iso_readiness_percent,
        nis2_readiness_percent::bigint AS nis2_readiness_percent,
        kritis_readiness_percent::bigint AS kritis_readiness_percent,
        cra_readiness_percent::bigint AS cra_readiness_percent,
        ai_act_readiness_percent::bigint AS ai_act_readiness_percent,
        iec62443_readiness_percent::bigint AS iec62443_readiness_percent,
        iso_sae_21434_readiness_percent::bigint AS iso_sae_21434_readiness_percent,
        COALESCE(regulatory_matrix_json::text, '{}') AS regulatory_matrix_json_text,
        COALESCE(compliance_versions_json::text, '{}') AS compliance_versions_json_text,
        COALESCE(product_security_json::text, '{}') AS product_security_json_text,
        COALESCE(top_gaps_json::text, '[]') AS top_gaps_json_text,
        COALESCE(top_measures_json::text, '[]') AS top_measures_json_text,
        COALESCE(roadmap_summary::text, '[]') AS roadmap_summary_text,
        COALESCE(domain_scores_json::text, '[]') AS domain_scores_json_text,
        COALESCE(next_steps_json::text, '{}') AS next_steps_json_text,
        created_at::text AS created_at,
        updated_at::text AS updated_at
    FROM reports_reportsnapshot
    WHERE tenant_id = $1 AND id = $2
    "#
}

fn detail_sqlite_sql() -> &'static str {
    r#"
    SELECT
        id,
        tenant_id,
        session_id,
        title,
        executive_summary,
        applicability_result,
        iso_readiness_percent,
        nis2_readiness_percent,
        kritis_readiness_percent,
        cra_readiness_percent,
        ai_act_readiness_percent,
        iec62443_readiness_percent,
        iso_sae_21434_readiness_percent,
        COALESCE(CAST(regulatory_matrix_json AS TEXT), '{}') AS regulatory_matrix_json_text,
        COALESCE(CAST(compliance_versions_json AS TEXT), '{}') AS compliance_versions_json_text,
        COALESCE(CAST(product_security_json AS TEXT), '{}') AS product_security_json_text,
        COALESCE(CAST(top_gaps_json AS TEXT), '[]') AS top_gaps_json_text,
        COALESCE(CAST(top_measures_json AS TEXT), '[]') AS top_measures_json_text,
        COALESCE(CAST(roadmap_summary AS TEXT), '[]') AS roadmap_summary_text,
        COALESCE(CAST(domain_scores_json AS TEXT), '[]') AS domain_scores_json_text,
        COALESCE(CAST(next_steps_json AS TEXT), '{}') AS next_steps_json_text,
        CAST(created_at AS TEXT) AS created_at,
        CAST(updated_at AS TEXT) AS updated_at
    FROM reports_reportsnapshot
    WHERE tenant_id = ? AND id = ?
    "#
}

async fn list_management_reviews_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<ManagementReviewPackageSummary>> {
    let rows = sqlx::query(management_review_list_postgres_sql())
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Management-Reviews konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(management_review_summary_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_management_reviews_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<ManagementReviewPackageSummary>> {
    let rows = sqlx::query(management_review_list_sqlite_sql())
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("SQLite-Management-Reviews konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(management_review_summary_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_regulatory_review_pack_snapshots_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<ManagementReviewPackageSummary>> {
    let rows = sqlx::query(regulatory_review_pack_snapshot_list_postgres_sql())
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Regulatory-Review-Packs konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(management_review_summary_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_regulatory_review_pack_snapshots_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<ManagementReviewPackageSummary>> {
    let rows = sqlx::query(regulatory_review_pack_snapshot_list_sqlite_sql())
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("SQLite-Regulatory-Review-Packs konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(management_review_summary_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_regulatory_review_pack_snapshots_filtered_postgres(
    pool: &PgPool,
    tenant_id: i64,
    filters: &RegulatoryReviewSnapshotFilters,
) -> anyhow::Result<Vec<ManagementReviewPackageSummary>> {
    let mut builder = QueryBuilder::<Postgres>::new(
        r#"
        SELECT
            id, tenant_id, title, period_start::text AS period_start, period_end::text AS period_end,
            template_type, template_version,
            status, generated_by_id, approved_by_id, approved_at::text AS approved_at,
            created_at::text AS created_at, updated_at::text AS updated_at
        FROM reports_managementreviewpackage
        WHERE tenant_id = "#,
    );
    builder.push_bind(tenant_id);
    push_regulatory_review_pack_filters(&mut builder, filters, true);
    builder.push(" ORDER BY created_at DESC, id DESC LIMIT ");
    builder.push_bind(filters.limit);
    let rows = builder
        .build()
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Regulatory-Review-Pack-Snapshots konnten nicht gelesen werden")?;
    let summaries = rows
        .into_iter()
        .map(management_review_summary_from_pg_row)
        .collect::<Result<Vec<_>, _>>()?;
    apply_regulatory_review_gap_filters_postgres(pool, tenant_id, summaries, filters).await
}

async fn list_regulatory_review_pack_snapshots_filtered_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    filters: &RegulatoryReviewSnapshotFilters,
) -> anyhow::Result<Vec<ManagementReviewPackageSummary>> {
    let mut builder = QueryBuilder::<Sqlite>::new(
        r#"
        SELECT
            id, tenant_id, title, CAST(period_start AS TEXT) AS period_start,
            template_type, template_version,
            CAST(period_end AS TEXT) AS period_end, status, generated_by_id, approved_by_id,
            CAST(approved_at AS TEXT) AS approved_at, CAST(created_at AS TEXT) AS created_at,
            CAST(updated_at AS TEXT) AS updated_at
        FROM reports_managementreviewpackage
        WHERE tenant_id = "#,
    );
    builder.push_bind(tenant_id);
    push_regulatory_review_pack_filters(&mut builder, filters, false);
    builder.push(" ORDER BY created_at DESC, id DESC LIMIT ");
    builder.push_bind(filters.limit);
    let rows = builder
        .build()
        .fetch_all(pool)
        .await
        .context("SQLite-Regulatory-Review-Pack-Snapshots konnten nicht gelesen werden")?;
    let summaries = rows
        .into_iter()
        .map(management_review_summary_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()?;
    apply_regulatory_review_gap_filters_sqlite(pool, tenant_id, summaries, filters).await
}

fn push_regulatory_review_pack_filters<'a, DB>(
    builder: &mut QueryBuilder<'a, DB>,
    filters: &'a RegulatoryReviewSnapshotFilters,
    postgres: bool,
) where
    DB: sqlx::Database,
    String: sqlx::Encode<'a, DB> + sqlx::Type<DB>,
{
    builder.push(
        r#"
          AND template_type IN (
            'generic_security_governance',
            'nis2_management_summary',
            'dora_ict_risk_supplier_incident_summary',
            'dsgvo_data_protection_review'
          )
        "#,
    );
    if let Some(template_type) = filters.template_type.as_ref() {
        builder.push(" AND template_type = ");
        builder.push_bind(template_type.clone());
    }
    if let Some(status) = filters.status.as_ref() {
        builder.push(" AND status = ");
        builder.push_bind(status.clone());
    }
    if let Some(period_start) = filters.period_start.as_ref() {
        if postgres {
            builder.push(" AND (period_end IS NULL OR period_end::text >= ");
        } else {
            builder.push(" AND (period_end IS NULL OR CAST(period_end AS TEXT) >= ");
        }
        builder.push_bind(period_start.clone());
        builder.push(")");
    }
    if let Some(period_end) = filters.period_end.as_ref() {
        if postgres {
            builder.push(" AND (period_start IS NULL OR period_start::text <= ");
        } else {
            builder.push(" AND (period_start IS NULL OR CAST(period_start AS TEXT) <= ");
        }
        builder.push_bind(period_end.clone());
        builder.push(")");
    }
}

async fn apply_regulatory_review_gap_filters_postgres(
    pool: &PgPool,
    tenant_id: i64,
    summaries: Vec<ManagementReviewPackageSummary>,
    filters: &RegulatoryReviewSnapshotFilters,
) -> anyhow::Result<Vec<ManagementReviewPackageSummary>> {
    if filters.has_open_gaps.is_none() && filters.has_critical_gaps.is_none() {
        return Ok(summaries);
    }
    let mut filtered = Vec::new();
    for summary in summaries {
        if let Some(detail) = management_review_detail_postgres(pool, tenant_id, summary.id).await?
        {
            if regulatory_review_snapshot_matches_gap_filters(&detail, filters) {
                filtered.push(summary);
            }
        }
    }
    Ok(filtered)
}

async fn apply_regulatory_review_gap_filters_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    summaries: Vec<ManagementReviewPackageSummary>,
    filters: &RegulatoryReviewSnapshotFilters,
) -> anyhow::Result<Vec<ManagementReviewPackageSummary>> {
    if filters.has_open_gaps.is_none() && filters.has_critical_gaps.is_none() {
        return Ok(summaries);
    }
    let mut filtered = Vec::new();
    for summary in summaries {
        if let Some(detail) = management_review_detail_sqlite(pool, tenant_id, summary.id).await? {
            if regulatory_review_snapshot_matches_gap_filters(&detail, filters) {
                filtered.push(summary);
            }
        }
    }
    Ok(filtered)
}

fn regulatory_review_snapshot_matches_gap_filters(
    detail: &ManagementReviewPackageDetail,
    filters: &RegulatoryReviewSnapshotFilters,
) -> bool {
    let has_open = regulatory_review_has_open_gaps(&detail.gap_summary_json);
    let has_critical = regulatory_review_has_critical_gaps(&detail.gap_summary_json);
    filters
        .has_open_gaps
        .is_none_or(|expected| expected == has_open)
        && filters
            .has_critical_gaps
            .is_none_or(|expected| expected == has_critical)
}

async fn management_review_detail_postgres(
    pool: &PgPool,
    tenant_id: i64,
    review_id: i64,
) -> anyhow::Result<Option<ManagementReviewPackageDetail>> {
    let row = sqlx::query(management_review_detail_postgres_sql())
        .bind(tenant_id)
        .bind(review_id)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-Management-Review konnte nicht gelesen werden")?;
    row.map(management_review_detail_from_pg_row)
        .transpose()
        .map_err(Into::into)
}

async fn management_review_detail_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    review_id: i64,
) -> anyhow::Result<Option<ManagementReviewPackageDetail>> {
    let row = sqlx::query(management_review_detail_sqlite_sql())
        .bind(tenant_id)
        .bind(review_id)
        .fetch_optional(pool)
        .await
        .context("SQLite-Management-Review konnte nicht gelesen werden")?;
    row.map(management_review_detail_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

async fn preview_management_review_template_postgres(
    pool: &PgPool,
    tenant_id: i64,
    user_id: i64,
    template_type: &str,
    request: ManagementTemplatePreviewRequest,
) -> anyhow::Result<ManagementReviewTemplatePreview> {
    let template = resolve_management_review_template(template_type)?;
    let snapshot = build_management_review_snapshot_postgres(pool, tenant_id, template).await?;
    let period_start = management_review_date(request.period_start, "Zeitraum-Start")?;
    let period_end = management_review_date(request.period_end, "Zeitraum-Ende")?;
    audit_management_review_event_postgres(
        pool,
        tenant_id,
        None,
        template.template_type,
        if is_regulatory_review_pack_template_type(template.template_type) {
            "regulatory_review_pack_previewed"
        } else {
            "management_review_template_previewed"
        },
        Some(user_id),
        &serde_json::json!({
            "template_version": template.template_version,
            "period_start": period_start.map(|date| date.to_string()),
            "period_end": period_end.map(|date| date.to_string())
        }),
    )
    .await?;
    Ok(management_review_preview_from_snapshot(
        tenant_id,
        template,
        period_start.map(|date| date.to_string()),
        period_end.map(|date| date.to_string()),
        snapshot,
    ))
}

async fn preview_management_review_template_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    user_id: i64,
    template_type: &str,
    request: ManagementTemplatePreviewRequest,
) -> anyhow::Result<ManagementReviewTemplatePreview> {
    let template = resolve_management_review_template(template_type)?;
    let snapshot = build_management_review_snapshot_sqlite(pool, tenant_id, template).await?;
    let period_start = clean_optional_text(request.period_start);
    let period_end = clean_optional_text(request.period_end);
    audit_management_review_event_sqlite(
        pool,
        tenant_id,
        None,
        template.template_type,
        if is_regulatory_review_pack_template_type(template.template_type) {
            "regulatory_review_pack_previewed"
        } else {
            "management_review_template_previewed"
        },
        Some(user_id),
        &serde_json::json!({
            "template_version": template.template_version,
            "period_start": period_start.clone(),
            "period_end": period_end.clone()
        }),
    )
    .await?;
    Ok(management_review_preview_from_snapshot(
        tenant_id,
        template,
        period_start,
        period_end,
        snapshot,
    ))
}

async fn generate_management_review_postgres(
    pool: &PgPool,
    tenant_id: i64,
    user_id: i64,
    request: ManagementReviewGenerateRequest,
) -> anyhow::Result<ManagementReviewPackageDetail> {
    let template = selected_management_review_template(request.template_type)?;
    let snapshot = build_management_review_snapshot_postgres(pool, tenant_id, template).await?;
    let title = review_title(request.title, template);
    let executive_summary = review_executive_summary(request.executive_summary, &snapshot);
    let period_start = management_review_date(request.period_start, "Zeitraum-Start")?;
    let period_end = management_review_date(request.period_end, "Zeitraum-Ende")?;
    let id: i64 = sqlx::query_scalar(
        r#"
        INSERT INTO reports_managementreviewpackage (
            tenant_id, title, template_type, template_version, period_start, period_end,
            status, generated_by_id,
            executive_summary, decision_notes, next_actions, metrics_json, top_risks_json,
            control_gaps_json, evidence_gaps_json, incident_decisions_json, roadmap_json,
            product_security_json, agent_posture_json, ai_governance_json, supplier_json,
            regulatory_context_json, source_counts_json, gap_summary_json, decision_summary_json,
            created_at, updated_at
        )
        VALUES (
            $1, $2, $3, $4, $5, $6,
            'DRAFT', $7,
            $8, '', '', $9, $10,
            $11, $12, $13, $14,
            $15, $16, $17, $18,
            $19, $20, $21, $22,
            NOW()::text, NOW()::text
        )
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(&title)
    .bind(template.template_type)
    .bind(template.template_version)
    .bind(period_start)
    .bind(period_end)
    .bind(user_id)
    .bind(&executive_summary)
    .bind(snapshot.metrics_json.to_string())
    .bind(snapshot.top_risks_json.to_string())
    .bind(snapshot.control_gaps_json.to_string())
    .bind(snapshot.evidence_gaps_json.to_string())
    .bind(snapshot.incident_decisions_json.to_string())
    .bind(snapshot.roadmap_json.to_string())
    .bind(snapshot.product_security_json.to_string())
    .bind(snapshot.agent_posture_json.to_string())
    .bind(sqlx::types::Json(snapshot.ai_governance_json.clone()))
    .bind(sqlx::types::Json(snapshot.supplier_json.clone()))
    .bind(sqlx::types::Json(snapshot.regulatory_context_json.clone()))
    .bind(sqlx::types::Json(snapshot.source_counts_json.clone()))
    .bind(sqlx::types::Json(snapshot.gap_summary_json.clone()))
    .bind(sqlx::types::Json(snapshot.decision_summary_json.clone()))
    .fetch_one(pool)
    .await
    .context("PostgreSQL-Management-Review konnte nicht erzeugt werden")?;
    audit_management_review_event_postgres(
        pool,
        tenant_id,
        Some(id),
        template.template_type,
        if is_regulatory_review_pack_template_type(template.template_type) {
            "regulatory_review_pack_snapshot_created"
        } else {
            "management_review_snapshot_created"
        },
        Some(user_id),
        &serde_json::json!({
            "template_version": template.template_version,
            "period_start": period_start.map(|date| date.to_string()),
            "period_end": period_end.map(|date| date.to_string())
        }),
    )
    .await?;
    management_review_detail_postgres(pool, tenant_id, id)
        .await?
        .context("Neu erzeugtes Management-Review wurde nicht gefunden")
}

async fn generate_management_review_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    user_id: i64,
    request: ManagementReviewGenerateRequest,
) -> anyhow::Result<ManagementReviewPackageDetail> {
    let template = selected_management_review_template(request.template_type)?;
    let snapshot = build_management_review_snapshot_sqlite(pool, tenant_id, template).await?;
    let title = review_title(request.title, template);
    let period_start = clean_optional_text(request.period_start);
    let period_end = clean_optional_text(request.period_end);
    let executive_summary = review_executive_summary(request.executive_summary, &snapshot);
    let id: i64 = sqlx::query_scalar(
        r#"
        INSERT INTO reports_managementreviewpackage (
            tenant_id, title, template_type, template_version, period_start, period_end,
            status, generated_by_id,
            executive_summary, decision_notes, next_actions, metrics_json, top_risks_json,
            control_gaps_json, evidence_gaps_json, incident_decisions_json, roadmap_json,
            product_security_json, agent_posture_json, ai_governance_json, supplier_json,
            regulatory_context_json, source_counts_json, gap_summary_json, decision_summary_json,
            created_at, updated_at
        )
        VALUES (
            ?, ?, ?, ?, ?, ?,
            'DRAFT', ?,
            ?, '', '', ?, ?,
            ?, ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?, ?, ?,
            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
        )
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(&title)
    .bind(template.template_type)
    .bind(template.template_version)
    .bind(period_start.as_deref())
    .bind(period_end.as_deref())
    .bind(user_id)
    .bind(&executive_summary)
    .bind(snapshot.metrics_json.to_string())
    .bind(snapshot.top_risks_json.to_string())
    .bind(snapshot.control_gaps_json.to_string())
    .bind(snapshot.evidence_gaps_json.to_string())
    .bind(snapshot.incident_decisions_json.to_string())
    .bind(snapshot.roadmap_json.to_string())
    .bind(snapshot.product_security_json.to_string())
    .bind(snapshot.agent_posture_json.to_string())
    .bind(snapshot.ai_governance_json.to_string())
    .bind(snapshot.supplier_json.to_string())
    .bind(snapshot.regulatory_context_json.to_string())
    .bind(snapshot.source_counts_json.to_string())
    .bind(snapshot.gap_summary_json.to_string())
    .bind(snapshot.decision_summary_json.to_string())
    .fetch_one(pool)
    .await
    .context("SQLite-Management-Review konnte nicht erzeugt werden")?;
    audit_management_review_event_sqlite(
        pool,
        tenant_id,
        Some(id),
        template.template_type,
        if is_regulatory_review_pack_template_type(template.template_type) {
            "regulatory_review_pack_snapshot_created"
        } else {
            "management_review_snapshot_created"
        },
        Some(user_id),
        &serde_json::json!({
            "template_version": template.template_version,
            "period_start": period_start.clone(),
            "period_end": period_end.clone()
        }),
    )
    .await?;
    management_review_detail_sqlite(pool, tenant_id, id)
        .await?
        .context("Neu erzeugtes Management-Review wurde nicht gefunden")
}

async fn update_management_review_status_postgres(
    pool: &PgPool,
    tenant_id: i64,
    user_id: i64,
    review_id: i64,
    request: ManagementReviewStatusUpdateRequest,
) -> anyhow::Result<Option<ManagementReviewPackageDetail>> {
    let status = normalize_management_review_status(&request.status)?;
    let decision_notes = clean_text(request.decision_notes, 4000);
    let next_actions = clean_text(request.next_actions, 4000);
    let result = sqlx::query(
        r#"
        UPDATE reports_managementreviewpackage
        SET
            status = $3,
            decision_notes = COALESCE($4, decision_notes),
            next_actions = COALESCE($5, next_actions),
            approved_by_id = CASE WHEN $3 = 'APPROVED' THEN $6 ELSE NULL END,
            approved_at = CASE WHEN $3 = 'APPROVED' THEN NOW()::text ELSE NULL END,
            updated_at = NOW()::text
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(review_id)
    .bind(&status)
    .bind(decision_notes)
    .bind(next_actions)
    .bind(user_id)
    .execute(pool)
    .await
    .context("PostgreSQL-Management-Review-Status konnte nicht aktualisiert werden")?;
    if result.rows_affected() == 0 {
        return Ok(None);
    }
    audit_management_review_event_postgres(
        pool,
        tenant_id,
        Some(review_id),
        "",
        "management_review_status_changed",
        Some(user_id),
        &serde_json::json!({
            "status": status
        }),
    )
    .await?;
    management_review_detail_postgres(pool, tenant_id, review_id).await
}

async fn update_management_review_status_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    user_id: i64,
    review_id: i64,
    request: ManagementReviewStatusUpdateRequest,
) -> anyhow::Result<Option<ManagementReviewPackageDetail>> {
    let status = normalize_management_review_status(&request.status)?;
    let decision_notes = clean_text(request.decision_notes, 4000);
    let next_actions = clean_text(request.next_actions, 4000);
    let result = sqlx::query(
        r#"
        UPDATE reports_managementreviewpackage
        SET
            status = ?,
            decision_notes = COALESCE(?, decision_notes),
            next_actions = COALESCE(?, next_actions),
            approved_by_id = CASE WHEN ? = 'APPROVED' THEN ? ELSE NULL END,
            approved_at = CASE WHEN ? = 'APPROVED' THEN CURRENT_TIMESTAMP ELSE NULL END,
            updated_at = CURRENT_TIMESTAMP
        WHERE tenant_id = ? AND id = ?
        "#,
    )
    .bind(&status)
    .bind(decision_notes)
    .bind(next_actions)
    .bind(&status)
    .bind(user_id)
    .bind(&status)
    .bind(tenant_id)
    .bind(review_id)
    .execute(pool)
    .await
    .context("SQLite-Management-Review-Status konnte nicht aktualisiert werden")?;
    if result.rows_affected() == 0 {
        return Ok(None);
    }
    audit_management_review_event_sqlite(
        pool,
        tenant_id,
        Some(review_id),
        "",
        "management_review_status_changed",
        Some(user_id),
        &serde_json::json!({
            "status": status
        }),
    )
    .await?;
    management_review_detail_sqlite(pool, tenant_id, review_id).await
}

struct ManagementReviewSnapshot {
    metrics_json: Value,
    top_risks_json: Value,
    control_gaps_json: Value,
    evidence_gaps_json: Value,
    incident_decisions_json: Value,
    roadmap_json: Value,
    product_security_json: Value,
    agent_posture_json: Value,
    ai_governance_json: Value,
    supplier_json: Value,
    regulatory_context_json: Value,
    source_counts_json: Value,
    gap_summary_json: Value,
    decision_summary_json: Value,
}

#[derive(Clone, Copy)]
struct ManagementReviewItemCounts {
    top_risks: i64,
    control_gaps: i64,
    evidence_gaps: i64,
    incidents: i64,
    roadmap: i64,
    ai_governance: i64,
    suppliers: i64,
}

type ReviewGapItemDefinition = (&'static str, &'static str, bool);
type ReviewGapGroupDefinition = (&'static str, &'static [ReviewGapItemDefinition]);

struct ManagementReviewDecisionSources<'a> {
    metrics: &'a Value,
    product_security: &'a Value,
    supplier: &'a Value,
    agent_posture: &'a Value,
    ai_governance: &'a Value,
    source_counts: &'a Value,
    incident_decisions: &'a Value,
    roadmap: &'a Value,
}

async fn build_management_review_snapshot_postgres(
    pool: &PgPool,
    tenant_id: i64,
    template: ManagementReviewTemplateDefinition,
) -> anyhow::Result<ManagementReviewSnapshot> {
    let top_risks_json = top_risks_postgres(pool, tenant_id).await?;
    let control_gaps_json = control_gaps_postgres(pool, tenant_id).await?;
    let evidence_gaps_json = evidence_gaps_postgres(pool, tenant_id).await?;
    let incident_decisions_json = incident_decisions_postgres(pool, tenant_id).await?;
    let roadmap_json = roadmap_items_postgres(pool, tenant_id).await?;
    let product_security_json = product_security_postgres(pool, tenant_id).await?;
    let supplier_json = supplier_review_postgres(pool, tenant_id).await?;
    let agent_posture_json = agent_posture_postgres(pool, tenant_id).await?;
    let ai_governance_json = ai_governance_postgres(pool, tenant_id).await?;
    let regulatory_context_json = regulatory_context_postgres(pool, tenant_id, template).await?;
    let counts = ManagementReviewItemCounts {
        top_risks: top_risks_json.as_array().map_or(0, Vec::len) as i64,
        control_gaps: control_gaps_json.as_array().map_or(0, Vec::len) as i64,
        evidence_gaps: evidence_gaps_json.as_array().map_or(0, Vec::len) as i64,
        incidents: incident_decisions_json.as_array().map_or(0, Vec::len) as i64,
        roadmap: roadmap_json.as_array().map_or(0, Vec::len) as i64,
        ai_governance: ai_governance_json["systems"].as_array().map_or(0, Vec::len) as i64,
        suppliers: supplier_json["suppliers"].as_array().map_or(0, Vec::len) as i64,
    };
    let metrics_json = management_review_metrics_postgres(pool, tenant_id, counts).await?;
    let source_counts_json = management_review_source_counts(
        &counts,
        &metrics_json,
        &product_security_json,
        &agent_posture_json,
    );
    let gap_summary_json = management_review_gap_summary(
        &metrics_json,
        &product_security_json,
        &supplier_json,
        &agent_posture_json,
        &ai_governance_json,
    );
    let decision_summary_json = management_review_decision_summary(
        template,
        ManagementReviewDecisionSources {
            metrics: &metrics_json,
            product_security: &product_security_json,
            supplier: &supplier_json,
            agent_posture: &agent_posture_json,
            ai_governance: &ai_governance_json,
            source_counts: &source_counts_json,
            incident_decisions: &incident_decisions_json,
            roadmap: &roadmap_json,
        },
    );
    Ok(ManagementReviewSnapshot {
        metrics_json,
        top_risks_json,
        control_gaps_json,
        evidence_gaps_json,
        incident_decisions_json,
        roadmap_json,
        product_security_json,
        agent_posture_json,
        ai_governance_json,
        supplier_json,
        regulatory_context_json,
        source_counts_json,
        gap_summary_json,
        decision_summary_json,
    })
}

async fn build_management_review_snapshot_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    template: ManagementReviewTemplateDefinition,
) -> anyhow::Result<ManagementReviewSnapshot> {
    let top_risks_json = top_risks_sqlite(pool, tenant_id).await?;
    let control_gaps_json = control_gaps_sqlite(pool, tenant_id).await?;
    let evidence_gaps_json = evidence_gaps_sqlite(pool, tenant_id).await?;
    let incident_decisions_json = incident_decisions_sqlite(pool, tenant_id).await?;
    let roadmap_json = roadmap_items_sqlite(pool, tenant_id).await?;
    let product_security_json = product_security_sqlite(pool, tenant_id).await?;
    let supplier_json = supplier_review_sqlite(pool, tenant_id).await?;
    let agent_posture_json = agent_posture_sqlite(pool, tenant_id).await?;
    let ai_governance_json = ai_governance_sqlite(pool, tenant_id).await?;
    let regulatory_context_json = regulatory_context_sqlite(pool, tenant_id, template).await?;
    let counts = ManagementReviewItemCounts {
        top_risks: top_risks_json.as_array().map_or(0, Vec::len) as i64,
        control_gaps: control_gaps_json.as_array().map_or(0, Vec::len) as i64,
        evidence_gaps: evidence_gaps_json.as_array().map_or(0, Vec::len) as i64,
        incidents: incident_decisions_json.as_array().map_or(0, Vec::len) as i64,
        roadmap: roadmap_json.as_array().map_or(0, Vec::len) as i64,
        ai_governance: ai_governance_json["systems"].as_array().map_or(0, Vec::len) as i64,
        suppliers: supplier_json["suppliers"].as_array().map_or(0, Vec::len) as i64,
    };
    let metrics_json = management_review_metrics_sqlite(pool, tenant_id, counts).await?;
    let source_counts_json = management_review_source_counts(
        &counts,
        &metrics_json,
        &product_security_json,
        &agent_posture_json,
    );
    let gap_summary_json = management_review_gap_summary(
        &metrics_json,
        &product_security_json,
        &supplier_json,
        &agent_posture_json,
        &ai_governance_json,
    );
    let decision_summary_json = management_review_decision_summary(
        template,
        ManagementReviewDecisionSources {
            metrics: &metrics_json,
            product_security: &product_security_json,
            supplier: &supplier_json,
            agent_posture: &agent_posture_json,
            ai_governance: &ai_governance_json,
            source_counts: &source_counts_json,
            incident_decisions: &incident_decisions_json,
            roadmap: &roadmap_json,
        },
    );
    Ok(ManagementReviewSnapshot {
        metrics_json,
        top_risks_json,
        control_gaps_json,
        evidence_gaps_json,
        incident_decisions_json,
        roadmap_json,
        product_security_json,
        agent_posture_json,
        ai_governance_json,
        supplier_json,
        regulatory_context_json,
        source_counts_json,
        gap_summary_json,
        decision_summary_json,
    })
}

async fn management_review_metrics_postgres(
    pool: &PgPool,
    tenant_id: i64,
    counts: ManagementReviewItemCounts,
) -> anyhow::Result<Value> {
    let evidence_integrity_storage = evidence_integrity_storage_postgres(pool, tenant_id).await?;
    Ok(serde_json::json!({
        "open_risks": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM risks_risk WHERE tenant_id = $1 AND status <> 'CLOSED'", tenant_id).await?,
        "critical_open_risks": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM risks_risk WHERE tenant_id = $1 AND status <> 'CLOSED' AND impact * likelihood >= 16", tenant_id).await?,
        "open_control_gaps": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM iscy_control_control c LEFT JOIN iscy_control_tenantstatus ts ON ts.control_id = c.id AND ts.tenant_id = $1 WHERE c.is_active = TRUE AND COALESCE(ts.status, 'GAP') IN ('GAP', 'PARTIAL')", tenant_id).await?,
        "missing_control_evidence": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM iscy_control_control c LEFT JOIN iscy_control_tenantstatus ts ON ts.control_id = c.id AND ts.tenant_id = $1 WHERE c.is_active = TRUE AND COALESCE(ts.evidence_status, 'MISSING') IN ('MISSING', 'PARTIAL')", tenant_id).await?,
        "open_evidence_needs": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_requirementevidenceneed WHERE tenant_id = $1 AND status <> 'COVERED'", tenant_id).await?,
        "approved_evidence_items": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_evidenceitem WHERE tenant_id = $1 AND status = 'APPROVED'", tenant_id).await?,
        "open_incidents": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM incidents_incident WHERE tenant_id = $1 AND status NOT IN ('RESOLVED', 'CLOSED')", tenant_id).await?,
        "unassessed_incidents": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM incidents_incident WHERE tenant_id = $1 AND nis2_significance_status = 'NOT_ASSESSED' AND status NOT IN ('RESOLVED', 'CLOSED')", tenant_id).await?,
        "open_roadmap_tasks": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM roadmap_roadmaptask task JOIN roadmap_roadmapphase phase ON task.phase_id = phase.id JOIN roadmap_roadmapplan plan ON phase.plan_id = plan.id WHERE plan.tenant_id = $1 AND task.status <> 'DONE'", tenant_id).await?,
        "critical_suppliers": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM organizations_supplier WHERE tenant_id = $1 AND UPPER(criticality) IN ('CRITICAL', 'VERY_HIGH', 'HIGH')", tenant_id).await?,
        "overdue_supplier_reviews": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM organizations_supplier WHERE tenant_id = $1 AND evidence_required = TRUE AND (next_review_due_at IS NULL OR next_review_due_at::text < CURRENT_DATE::text)", tenant_id).await?,
        "ai_governance_systems": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM ai_governance_system WHERE tenant_id = $1", tenant_id).await?,
        "ai_systems_without_risk_links": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM ai_governance_system system WHERE system.tenant_id = $1 AND NOT EXISTS (SELECT 1 FROM ai_governance_system_risk link WHERE link.tenant_id = system.tenant_id AND link.system_id = system.id)", tenant_id).await?,
        "ai_systems_without_roadmap_links": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM ai_governance_system system WHERE system.tenant_id = $1 AND NOT EXISTS (SELECT 1 FROM ai_governance_system_roadmap_task link WHERE link.tenant_id = system.tenant_id AND link.system_id = system.id)", tenant_id).await?,
        "evidence_integrity_not_checked": json_i64(&evidence_integrity_storage, "not_checked"),
        "evidence_integrity_valid": json_i64(&evidence_integrity_storage, "valid"),
        "evidence_integrity_mismatch": json_i64(&evidence_integrity_storage, "mismatch"),
        "evidence_storage_artifact_references": json_i64(&evidence_integrity_storage, "artifact_references"),
        "evidence_storage_drills_recorded": json_i64(&evidence_integrity_storage, "storage_drills_recorded"),
        "evidence_object_storage_backends": json_i64(&evidence_integrity_storage, "object_storage_backends"),
        "evidence_object_storage_ready_backends": json_i64(&evidence_integrity_storage, "object_storage_ready_backends"),
        "evidence_object_storage_config_errors": json_i64(&evidence_integrity_storage, "object_storage_config_errors"),
        "evidence_object_storage_refs": json_i64(&evidence_integrity_storage, "object_storage_refs"),
        "evidence_object_storage_drills_recorded": json_i64(&evidence_integrity_storage, "object_storage_drills_recorded"),
        "evidence_object_storage_drill_gaps": json_i64(&evidence_integrity_storage, "object_storage_drill_gaps"),
        "evidence_object_storage_object_gaps": json_i64(&evidence_integrity_storage, "object_storage_object_gaps"),
        "evidence_s3_runtime_objects": json_i64(&evidence_integrity_storage, "s3_runtime_objects"),
        "evidence_s3_upload_failures": json_i64(&evidence_integrity_storage, "s3_upload_failures"),
        "evidence_s3_restore_gaps": json_i64(&evidence_integrity_storage, "s3_restore_gaps"),
        "evidence_s3_runtime_errors": json_i64(&evidence_integrity_storage, "s3_runtime_errors"),
        "evidence_s3_orphan_reviews": json_i64(&evidence_integrity_storage, "s3_orphan_reviews"),
        "evidence_worker_runs_recorded": json_i64(&evidence_integrity_storage, "worker_runs_recorded"),
        "evidence_worker_missing_runs": if json_i64(&evidence_integrity_storage, "total_items") > 0 && json_i64(&evidence_integrity_storage, "worker_runs_recorded") == 0 { 1 } else { 0 },
        "evidence_storage_drill_gaps": (json_i64(&evidence_integrity_storage, "total_items") - json_i64(&evidence_integrity_storage, "storage_drills_recorded")).max(0),
        "evidence_legal_hold_active": json_i64(&evidence_integrity_storage, "legal_hold_active"),
        "evidence_disposition_due": json_i64(&evidence_integrity_storage, "disposition_due"),
        "evidence_disposition_executed": json_i64(&evidence_integrity_storage, "disposition_executed"),
        "evidence_disposition_failed": json_i64(&evidence_integrity_storage, "disposition_failed"),
        "evidence_integrity_storage": evidence_integrity_storage,
        "snapshot_items": {
            "top_risks": counts.top_risks,
            "control_gaps": counts.control_gaps,
            "evidence_gaps": counts.evidence_gaps,
            "incidents": counts.incidents,
            "roadmap": counts.roadmap,
            "ai_governance": counts.ai_governance,
            "suppliers": counts.suppliers
        }
    }))
}

async fn management_review_metrics_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    counts: ManagementReviewItemCounts,
) -> anyhow::Result<Value> {
    let evidence_integrity_storage = evidence_integrity_storage_sqlite(pool, tenant_id).await?;
    Ok(serde_json::json!({
        "open_risks": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM risks_risk WHERE tenant_id = ? AND status <> 'CLOSED'", tenant_id).await?,
        "critical_open_risks": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM risks_risk WHERE tenant_id = ? AND status <> 'CLOSED' AND impact * likelihood >= 16", tenant_id).await?,
        "open_control_gaps": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM iscy_control_control c LEFT JOIN iscy_control_tenantstatus ts ON ts.control_id = c.id AND ts.tenant_id = ? WHERE c.is_active = 1 AND COALESCE(ts.status, 'GAP') IN ('GAP', 'PARTIAL')", tenant_id).await?,
        "missing_control_evidence": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM iscy_control_control c LEFT JOIN iscy_control_tenantstatus ts ON ts.control_id = c.id AND ts.tenant_id = ? WHERE c.is_active = 1 AND COALESCE(ts.evidence_status, 'MISSING') IN ('MISSING', 'PARTIAL')", tenant_id).await?,
        "open_evidence_needs": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_requirementevidenceneed WHERE tenant_id = ? AND status <> 'COVERED'", tenant_id).await?,
        "approved_evidence_items": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_evidenceitem WHERE tenant_id = ? AND status = 'APPROVED'", tenant_id).await?,
        "open_incidents": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM incidents_incident WHERE tenant_id = ? AND status NOT IN ('RESOLVED', 'CLOSED')", tenant_id).await?,
        "unassessed_incidents": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM incidents_incident WHERE tenant_id = ? AND nis2_significance_status = 'NOT_ASSESSED' AND status NOT IN ('RESOLVED', 'CLOSED')", tenant_id).await?,
        "open_roadmap_tasks": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM roadmap_roadmaptask task JOIN roadmap_roadmapphase phase ON task.phase_id = phase.id JOIN roadmap_roadmapplan plan ON phase.plan_id = plan.id WHERE plan.tenant_id = ? AND task.status <> 'DONE'", tenant_id).await?,
        "critical_suppliers": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM organizations_supplier WHERE tenant_id = ? AND UPPER(criticality) IN ('CRITICAL', 'VERY_HIGH', 'HIGH')", tenant_id).await?,
        "overdue_supplier_reviews": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM organizations_supplier WHERE tenant_id = ? AND evidence_required = 1 AND (next_review_due_at IS NULL OR CAST(next_review_due_at AS TEXT) < date('now'))", tenant_id).await?,
        "ai_governance_systems": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM ai_governance_system WHERE tenant_id = ?", tenant_id).await?,
        "ai_systems_without_risk_links": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM ai_governance_system system WHERE system.tenant_id = ? AND NOT EXISTS (SELECT 1 FROM ai_governance_system_risk link WHERE link.tenant_id = system.tenant_id AND link.system_id = system.id)", tenant_id).await?,
        "ai_systems_without_roadmap_links": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM ai_governance_system system WHERE system.tenant_id = ? AND NOT EXISTS (SELECT 1 FROM ai_governance_system_roadmap_task link WHERE link.tenant_id = system.tenant_id AND link.system_id = system.id)", tenant_id).await?,
        "evidence_integrity_not_checked": json_i64(&evidence_integrity_storage, "not_checked"),
        "evidence_integrity_valid": json_i64(&evidence_integrity_storage, "valid"),
        "evidence_integrity_mismatch": json_i64(&evidence_integrity_storage, "mismatch"),
        "evidence_storage_artifact_references": json_i64(&evidence_integrity_storage, "artifact_references"),
        "evidence_storage_drills_recorded": json_i64(&evidence_integrity_storage, "storage_drills_recorded"),
        "evidence_object_storage_backends": json_i64(&evidence_integrity_storage, "object_storage_backends"),
        "evidence_object_storage_ready_backends": json_i64(&evidence_integrity_storage, "object_storage_ready_backends"),
        "evidence_object_storage_config_errors": json_i64(&evidence_integrity_storage, "object_storage_config_errors"),
        "evidence_object_storage_refs": json_i64(&evidence_integrity_storage, "object_storage_refs"),
        "evidence_object_storage_drills_recorded": json_i64(&evidence_integrity_storage, "object_storage_drills_recorded"),
        "evidence_object_storage_drill_gaps": json_i64(&evidence_integrity_storage, "object_storage_drill_gaps"),
        "evidence_object_storage_object_gaps": json_i64(&evidence_integrity_storage, "object_storage_object_gaps"),
        "evidence_s3_runtime_objects": json_i64(&evidence_integrity_storage, "s3_runtime_objects"),
        "evidence_s3_upload_failures": json_i64(&evidence_integrity_storage, "s3_upload_failures"),
        "evidence_s3_restore_gaps": json_i64(&evidence_integrity_storage, "s3_restore_gaps"),
        "evidence_s3_runtime_errors": json_i64(&evidence_integrity_storage, "s3_runtime_errors"),
        "evidence_s3_orphan_reviews": json_i64(&evidence_integrity_storage, "s3_orphan_reviews"),
        "evidence_worker_runs_recorded": json_i64(&evidence_integrity_storage, "worker_runs_recorded"),
        "evidence_worker_missing_runs": if json_i64(&evidence_integrity_storage, "total_items") > 0 && json_i64(&evidence_integrity_storage, "worker_runs_recorded") == 0 { 1 } else { 0 },
        "evidence_storage_drill_gaps": (json_i64(&evidence_integrity_storage, "total_items") - json_i64(&evidence_integrity_storage, "storage_drills_recorded")).max(0),
        "evidence_legal_hold_active": json_i64(&evidence_integrity_storage, "legal_hold_active"),
        "evidence_disposition_due": json_i64(&evidence_integrity_storage, "disposition_due"),
        "evidence_disposition_executed": json_i64(&evidence_integrity_storage, "disposition_executed"),
        "evidence_disposition_failed": json_i64(&evidence_integrity_storage, "disposition_failed"),
        "evidence_integrity_storage": evidence_integrity_storage,
        "snapshot_items": {
            "top_risks": counts.top_risks,
            "control_gaps": counts.control_gaps,
            "evidence_gaps": counts.evidence_gaps,
            "incidents": counts.incidents,
            "roadmap": counts.roadmap,
            "ai_governance": counts.ai_governance,
            "suppliers": counts.suppliers
        }
    }))
}

async fn evidence_integrity_storage_postgres(
    pool: &PgPool,
    tenant_id: i64,
) -> anyhow::Result<Value> {
    Ok(serde_json::json!({
        "total_items": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_evidenceitem WHERE tenant_id = $1", tenant_id).await?,
        "not_checked": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_evidenceitem WHERE tenant_id = $1 AND integrity_status = 'not_checked'", tenant_id).await?,
        "valid": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_evidenceitem WHERE tenant_id = $1 AND integrity_status = 'valid'", tenant_id).await?,
        "mismatch": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_evidenceitem WHERE tenant_id = $1 AND integrity_status = 'mismatch'", tenant_id).await?,
        "missing_artifact": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_evidenceitem WHERE tenant_id = $1 AND integrity_status = 'missing_artifact'", tenant_id).await?,
        "check_failed": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_evidenceitem WHERE tenant_id = $1 AND integrity_status = 'check_failed'", tenant_id).await?,
        "quarantined": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_evidenceitem WHERE tenant_id = $1 AND quarantine_status <> 'none'", tenant_id).await?,
        "artifact_references": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_evidenceitem WHERE tenant_id = $1 AND file IS NOT NULL AND BTRIM(file) <> ''", tenant_id).await?,
        "expected_hash_present": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_evidenceitem WHERE tenant_id = $1 AND (BTRIM(file_sha256) <> '' OR BTRIM(last_calculated_sha256) <> '')", tenant_id).await?,
        "storage_drills_recorded": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_evidenceitem WHERE tenant_id = $1 AND last_integrity_checked_at IS NOT NULL AND BTRIM(last_integrity_checked_at::text) <> ''", tenant_id).await?,
        "object_storage_backends": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_storage_backend_config WHERE tenant_id = $1 AND backend_type = 's3_compatible'", tenant_id).await?,
        "object_storage_ready_backends": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_storage_backend_config WHERE tenant_id = $1 AND backend_type = 's3_compatible' AND status IN ('ready_for_test','ready')", tenant_id).await?,
        "object_storage_config_errors": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_storage_backend_config WHERE tenant_id = $1 AND backend_type = 's3_compatible' AND (status = 'error' OR BTRIM(last_validation_error_class) <> '')", tenant_id).await?,
        "object_storage_refs": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_object_reference WHERE tenant_id = $1", tenant_id).await?,
        "object_storage_drills_recorded": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_object_reference WHERE tenant_id = $1 AND last_drill_at IS NOT NULL AND BTRIM(last_drill_at::text) <> ''", tenant_id).await?,
        "object_storage_drill_gaps": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_object_reference WHERE tenant_id = $1 AND (last_drill_at IS NULL OR BTRIM(last_drill_at::text) = '')", tenant_id).await?,
        "object_storage_object_gaps": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_object_reference WHERE tenant_id = $1 AND last_drill_error_class IN ('object_missing','object_unreadable','hash_mismatch','timeout','access_denied','backend_error','validation_required')", tenant_id).await?,
        "s3_runtime_objects": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_s3_runtime_object WHERE tenant_id = $1", tenant_id).await?,
        "s3_upload_failures": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_s3_runtime_object WHERE tenant_id = $1 AND upload_status = 'upload_failed'", tenant_id).await?,
        "s3_restore_gaps": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_s3_runtime_object WHERE tenant_id = $1 AND runtime_verification_status NOT IN ('verified','object_missing')", tenant_id).await?,
        "s3_runtime_errors": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_s3_runtime_object WHERE tenant_id = $1 AND BTRIM(last_runtime_error_class) <> ''", tenant_id).await?,
        "s3_orphan_reviews": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_s3_runtime_object WHERE tenant_id = $1 AND orphan_review_required = TRUE", tenant_id).await?,
        "worker_runs_recorded": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_integrity_worker_run WHERE tenant_id = $1", tenant_id).await?,
        "legal_hold_active": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_evidenceitem WHERE tenant_id = $1 AND legal_hold_status = 'active'", tenant_id).await?,
        "disposition_due": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_evidenceitem WHERE tenant_id = $1 AND (disposition_status IN ('due', 'approved_for_disposition', 'blocked_by_legal_hold') OR (disposition_due_at IS NOT NULL AND disposition_due_at::text <= CURRENT_DATE::text))", tenant_id).await?,
        "disposition_blocked": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_evidenceitem WHERE tenant_id = $1 AND legal_hold_blocks_disposition = TRUE", tenant_id).await?,
        "disposition_executed": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_evidenceitem WHERE tenant_id = $1 AND disposition_status = 'disposition_executed'", tenant_id).await?,
        "disposition_failed": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_evidenceitem WHERE tenant_id = $1 AND disposition_status = 'disposition_failed'", tenant_id).await?,
        "disposal_candidates": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM evidence_evidenceitem WHERE tenant_id = $1 AND disposal_candidate = TRUE", tenant_id).await?,
        "notes": [
            "Nur aggregierte Statuswerte; Evidence-Dateinamen, Pfade und Rohinhalte sind ausgeschlossen.",
            "Object-Storage-Metriken verwenden nur Backend-Metadaten, redaktionelle Object-Referenzen, Hashes und sichere Fehlerklassen; Secret-Werte und Objektinhalte sind ausgeschlossen.",
            "Physische Disposition erfolgt nur kontrolliert nach Freigabe ueber die Storage-Abstraktion; Tombstone-Metadaten bleiben erhalten."
        ]
    }))
}

async fn evidence_integrity_storage_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
) -> anyhow::Result<Value> {
    Ok(serde_json::json!({
        "total_items": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_evidenceitem WHERE tenant_id = ?", tenant_id).await?,
        "not_checked": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_evidenceitem WHERE tenant_id = ? AND integrity_status = 'not_checked'", tenant_id).await?,
        "valid": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_evidenceitem WHERE tenant_id = ? AND integrity_status = 'valid'", tenant_id).await?,
        "mismatch": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_evidenceitem WHERE tenant_id = ? AND integrity_status = 'mismatch'", tenant_id).await?,
        "missing_artifact": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_evidenceitem WHERE tenant_id = ? AND integrity_status = 'missing_artifact'", tenant_id).await?,
        "check_failed": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_evidenceitem WHERE tenant_id = ? AND integrity_status = 'check_failed'", tenant_id).await?,
        "quarantined": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_evidenceitem WHERE tenant_id = ? AND quarantine_status <> 'none'", tenant_id).await?,
        "artifact_references": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_evidenceitem WHERE tenant_id = ? AND file IS NOT NULL AND TRIM(file) <> ''", tenant_id).await?,
        "expected_hash_present": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_evidenceitem WHERE tenant_id = ? AND (TRIM(file_sha256) <> '' OR TRIM(last_calculated_sha256) <> '')", tenant_id).await?,
        "storage_drills_recorded": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_evidenceitem WHERE tenant_id = ? AND last_integrity_checked_at IS NOT NULL AND TRIM(CAST(last_integrity_checked_at AS TEXT)) <> ''", tenant_id).await?,
        "object_storage_backends": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_storage_backend_config WHERE tenant_id = ? AND backend_type = 's3_compatible'", tenant_id).await?,
        "object_storage_ready_backends": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_storage_backend_config WHERE tenant_id = ? AND backend_type = 's3_compatible' AND status IN ('ready_for_test','ready')", tenant_id).await?,
        "object_storage_config_errors": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_storage_backend_config WHERE tenant_id = ? AND backend_type = 's3_compatible' AND (status = 'error' OR TRIM(last_validation_error_class) <> '')", tenant_id).await?,
        "object_storage_refs": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_object_reference WHERE tenant_id = ?", tenant_id).await?,
        "object_storage_drills_recorded": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_object_reference WHERE tenant_id = ? AND last_drill_at IS NOT NULL AND TRIM(CAST(last_drill_at AS TEXT)) <> ''", tenant_id).await?,
        "object_storage_drill_gaps": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_object_reference WHERE tenant_id = ? AND (last_drill_at IS NULL OR TRIM(CAST(last_drill_at AS TEXT)) = '')", tenant_id).await?,
        "object_storage_object_gaps": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_object_reference WHERE tenant_id = ? AND last_drill_error_class IN ('object_missing','object_unreadable','hash_mismatch','timeout','access_denied','backend_error','validation_required')", tenant_id).await?,
        "s3_runtime_objects": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_s3_runtime_object WHERE tenant_id = ?", tenant_id).await?,
        "s3_upload_failures": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_s3_runtime_object WHERE tenant_id = ? AND upload_status = 'upload_failed'", tenant_id).await?,
        "s3_restore_gaps": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_s3_runtime_object WHERE tenant_id = ? AND runtime_verification_status NOT IN ('verified','object_missing')", tenant_id).await?,
        "s3_runtime_errors": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_s3_runtime_object WHERE tenant_id = ? AND TRIM(last_runtime_error_class) <> ''", tenant_id).await?,
        "s3_orphan_reviews": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_s3_runtime_object WHERE tenant_id = ? AND orphan_review_required = 1", tenant_id).await?,
        "worker_runs_recorded": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_integrity_worker_run WHERE tenant_id = ?", tenant_id).await?,
        "legal_hold_active": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_evidenceitem WHERE tenant_id = ? AND legal_hold_status = 'active'", tenant_id).await?,
        "disposition_due": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_evidenceitem WHERE tenant_id = ? AND (disposition_status IN ('due', 'approved_for_disposition', 'blocked_by_legal_hold') OR (disposition_due_at IS NOT NULL AND CAST(disposition_due_at AS TEXT) <= date('now')))", tenant_id).await?,
        "disposition_blocked": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_evidenceitem WHERE tenant_id = ? AND legal_hold_blocks_disposition = 1", tenant_id).await?,
        "disposition_executed": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_evidenceitem WHERE tenant_id = ? AND disposition_status = 'disposition_executed'", tenant_id).await?,
        "disposition_failed": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_evidenceitem WHERE tenant_id = ? AND disposition_status = 'disposition_failed'", tenant_id).await?,
        "disposal_candidates": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM evidence_evidenceitem WHERE tenant_id = ? AND disposal_candidate = 1", tenant_id).await?,
        "notes": [
            "Nur aggregierte Statuswerte; Evidence-Dateinamen, Pfade und Rohinhalte sind ausgeschlossen.",
            "Object-Storage-Metriken verwenden nur Backend-Metadaten, redaktionelle Object-Referenzen, Hashes und sichere Fehlerklassen; Secret-Werte und Objektinhalte sind ausgeschlossen.",
            "Physische Disposition erfolgt nur kontrolliert nach Freigabe ueber die Storage-Abstraktion; Tombstone-Metadaten bleiben erhalten."
        ]
    }))
}

async fn top_risks_postgres(pool: &PgPool, tenant_id: i64) -> anyhow::Result<Value> {
    let rows = sqlx::query(
        r#"
        SELECT id, title, status, impact::bigint AS impact, likelihood::bigint AS likelihood,
               (impact * likelihood)::bigint AS score, treatment_strategy, treatment_plan,
               COALESCE(review_date::text, '') AS review_date
        FROM risks_risk
        WHERE tenant_id = $1 AND status <> 'CLOSED'
        ORDER BY impact * likelihood DESC, updated_at DESC, id DESC
        LIMIT 10
        "#,
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;
    risk_pg_rows_to_json(rows)
}

async fn top_risks_sqlite(pool: &SqlitePool, tenant_id: i64) -> anyhow::Result<Value> {
    let rows = sqlx::query(
        r#"
        SELECT id, title, status, impact, likelihood, impact * likelihood AS score,
               treatment_strategy, treatment_plan, COALESCE(CAST(review_date AS TEXT), '') AS review_date
        FROM risks_risk
        WHERE tenant_id = ? AND status <> 'CLOSED'
        ORDER BY impact * likelihood DESC, updated_at DESC, id DESC
        LIMIT 10
        "#,
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;
    risk_sqlite_rows_to_json(rows)
}

async fn control_gaps_postgres(pool: &PgPool, tenant_id: i64) -> anyhow::Result<Value> {
    let rows = sqlx::query(control_gaps_postgres_sql())
        .bind(tenant_id)
        .fetch_all(pool)
        .await?;
    control_pg_rows_to_json(rows)
}

async fn control_gaps_sqlite(pool: &SqlitePool, tenant_id: i64) -> anyhow::Result<Value> {
    let rows = sqlx::query(control_gaps_sqlite_sql())
        .bind(tenant_id)
        .fetch_all(pool)
        .await?;
    control_sqlite_rows_to_json(rows)
}

async fn evidence_gaps_postgres(pool: &PgPool, tenant_id: i64) -> anyhow::Result<Value> {
    let rows = sqlx::query(evidence_gaps_postgres_sql())
        .bind(tenant_id)
        .fetch_all(pool)
        .await?;
    evidence_gap_pg_rows_to_json(rows)
}

async fn evidence_gaps_sqlite(pool: &SqlitePool, tenant_id: i64) -> anyhow::Result<Value> {
    let rows = sqlx::query(evidence_gaps_sqlite_sql())
        .bind(tenant_id)
        .fetch_all(pool)
        .await?;
    evidence_gap_sqlite_rows_to_json(rows)
}

async fn incident_decisions_postgres(pool: &PgPool, tenant_id: i64) -> anyhow::Result<Value> {
    let rows = sqlx::query(incident_decisions_postgres_sql())
        .bind(tenant_id)
        .fetch_all(pool)
        .await?;
    incident_pg_rows_to_json(rows)
}

async fn incident_decisions_sqlite(pool: &SqlitePool, tenant_id: i64) -> anyhow::Result<Value> {
    let rows = sqlx::query(incident_decisions_sqlite_sql())
        .bind(tenant_id)
        .fetch_all(pool)
        .await?;
    incident_sqlite_rows_to_json(rows)
}

async fn roadmap_items_postgres(pool: &PgPool, tenant_id: i64) -> anyhow::Result<Value> {
    let rows = sqlx::query(roadmap_items_postgres_sql())
        .bind(tenant_id)
        .fetch_all(pool)
        .await?;
    roadmap_pg_rows_to_json(rows)
}

async fn roadmap_items_sqlite(pool: &SqlitePool, tenant_id: i64) -> anyhow::Result<Value> {
    let rows = sqlx::query(roadmap_items_sqlite_sql())
        .bind(tenant_id)
        .fetch_all(pool)
        .await?;
    roadmap_sqlite_rows_to_json(rows)
}

async fn product_security_postgres(pool: &PgPool, tenant_id: i64) -> anyhow::Result<Value> {
    Ok(serde_json::json!({
        "products": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM product_security_product WHERE tenant_id = $1", tenant_id).await?,
        "open_vulnerabilities": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM product_security_vulnerability WHERE tenant_id = $1 AND status NOT IN ('FIXED', 'CLOSED', 'RESOLVED')", tenant_id).await?,
        "critical_open_vulnerabilities": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM product_security_vulnerability WHERE tenant_id = $1 AND severity = 'CRITICAL' AND status NOT IN ('FIXED', 'CLOSED', 'RESOLVED')", tenant_id).await?,
        "open_cve_correlation_reviews": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM product_security_cvecorrelation WHERE tenant_id = $1 AND status = 'SUGGESTED'", tenant_id).await?,
        "invalid_imports": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM product_security_importartifact WHERE tenant_id = $1 AND validation_status NOT IN ('VALID', 'VALIDATED')", tenant_id).await?,
        "supplier_product_security_records": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM supplier_product_security_record WHERE tenant_id = $1", tenant_id).await?,
        "open_supplier_product_security_advisories": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM supplier_product_security_record WHERE tenant_id = $1 AND review_status NOT IN ('closed', 'mitigated', 'not_applicable')", tenant_id).await?,
        "critical_supplier_product_security_advisories": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM supplier_product_security_record WHERE tenant_id = $1 AND (severity = 'critical' OR criticality = 'critical') AND review_status NOT IN ('closed', 'mitigated', 'not_applicable')", tenant_id).await?,
        "supplier_product_security_missing_evidence": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM supplier_product_security_record WHERE tenant_id = $1 AND review_status NOT IN ('closed', 'mitigated', 'not_applicable') AND (BTRIM(evidence_ids_json) = '[]' OR evidence_ids_json IS NULL)", tenant_id).await?,
        "supplier_product_security_missing_owner": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM supplier_product_security_record WHERE tenant_id = $1 AND BTRIM(owner) = '' AND BTRIM(internal_owner) = ''", tenant_id).await?,
        "supplier_product_security_open_actions": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM supplier_product_security_record WHERE tenant_id = $1 AND review_status NOT IN ('closed', 'mitigated', 'not_applicable') AND BTRIM(open_actions) <> ''", tenant_id).await?,
        "supplier_product_security_overdue_reviews": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM supplier_product_security_record WHERE tenant_id = $1 AND due_date IS NOT NULL AND due_date::text < CURRENT_DATE::text AND review_status NOT IN ('closed', 'mitigated', 'not_applicable')", tenant_id).await?,
        "supplier_product_security_dora_relevant": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM supplier_product_security_record WHERE tenant_id = $1 AND dora_ict_third_party_relevance = TRUE", tenant_id).await?,
        "supplier_product_security_nis2_relevant": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM supplier_product_security_record WHERE tenant_id = $1 AND nis2_supply_chain_relevance = TRUE", tenant_id).await?,
        "supplier_product_security_data_processing_relevant": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM supplier_product_security_record WHERE tenant_id = $1 AND data_processing_relevance = TRUE", tenant_id).await?,
        "supplier_product_security_critical_services": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM supplier_product_security_record WHERE tenant_id = $1 AND critical_service_dependency = TRUE", tenant_id).await?
    }))
}

async fn product_security_sqlite(pool: &SqlitePool, tenant_id: i64) -> anyhow::Result<Value> {
    Ok(serde_json::json!({
        "products": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM product_security_product WHERE tenant_id = ?", tenant_id).await?,
        "open_vulnerabilities": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM product_security_vulnerability WHERE tenant_id = ? AND status NOT IN ('FIXED', 'CLOSED', 'RESOLVED')", tenant_id).await?,
        "critical_open_vulnerabilities": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM product_security_vulnerability WHERE tenant_id = ? AND severity = 'CRITICAL' AND status NOT IN ('FIXED', 'CLOSED', 'RESOLVED')", tenant_id).await?,
        "open_cve_correlation_reviews": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM product_security_cvecorrelation WHERE tenant_id = ? AND status = 'SUGGESTED'", tenant_id).await?,
        "invalid_imports": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM product_security_importartifact WHERE tenant_id = ? AND validation_status NOT IN ('VALID', 'VALIDATED')", tenant_id).await?,
        "supplier_product_security_records": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM supplier_product_security_record WHERE tenant_id = ?", tenant_id).await?,
        "open_supplier_product_security_advisories": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM supplier_product_security_record WHERE tenant_id = ? AND review_status NOT IN ('closed', 'mitigated', 'not_applicable')", tenant_id).await?,
        "critical_supplier_product_security_advisories": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM supplier_product_security_record WHERE tenant_id = ? AND (severity = 'critical' OR criticality = 'critical') AND review_status NOT IN ('closed', 'mitigated', 'not_applicable')", tenant_id).await?,
        "supplier_product_security_missing_evidence": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM supplier_product_security_record WHERE tenant_id = ? AND review_status NOT IN ('closed', 'mitigated', 'not_applicable') AND (TRIM(evidence_ids_json) = '[]' OR evidence_ids_json IS NULL)", tenant_id).await?,
        "supplier_product_security_missing_owner": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM supplier_product_security_record WHERE tenant_id = ? AND TRIM(owner) = '' AND TRIM(internal_owner) = ''", tenant_id).await?,
        "supplier_product_security_open_actions": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM supplier_product_security_record WHERE tenant_id = ? AND review_status NOT IN ('closed', 'mitigated', 'not_applicable') AND TRIM(open_actions) <> ''", tenant_id).await?,
        "supplier_product_security_overdue_reviews": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM supplier_product_security_record WHERE tenant_id = ? AND due_date IS NOT NULL AND CAST(due_date AS TEXT) < date('now') AND review_status NOT IN ('closed', 'mitigated', 'not_applicable')", tenant_id).await?,
        "supplier_product_security_dora_relevant": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM supplier_product_security_record WHERE tenant_id = ? AND dora_ict_third_party_relevance = 1", tenant_id).await?,
        "supplier_product_security_nis2_relevant": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM supplier_product_security_record WHERE tenant_id = ? AND nis2_supply_chain_relevance = 1", tenant_id).await?,
        "supplier_product_security_data_processing_relevant": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM supplier_product_security_record WHERE tenant_id = ? AND data_processing_relevance = 1", tenant_id).await?,
        "supplier_product_security_critical_services": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM supplier_product_security_record WHERE tenant_id = ? AND critical_service_dependency = 1", tenant_id).await?
    }))
}

async fn supplier_review_postgres(pool: &PgPool, tenant_id: i64) -> anyhow::Result<Value> {
    let rows = sqlx::query(supplier_review_postgres_sql())
        .bind(tenant_id)
        .fetch_all(pool)
        .await?;
    let suppliers = rows
        .into_iter()
        .map(|row| {
            let id = row.try_get::<i64, _>("id")?;
            Ok(serde_json::json!({
                "id": id,
                "entity_type": "supplier",
                "href": format!("/suppliers/{id}/"),
                "name": row.try_get::<String, _>("name")?,
                "criticality": row.try_get::<String, _>("criticality")?,
                "review_status": row.try_get::<String, _>("review_status")?,
                "approval_status": row.try_get::<String, _>("approval_status")?,
                "next_review_due_at": row.try_get::<String, _>("next_review_due_at")?,
                "evidence_required": row.try_get::<bool, _>("evidence_required")?,
                "regulatory_scope": row.try_get::<String, _>("regulatory_scope")?,
                "evidence_links": row.try_get::<i64, _>("evidence_links")?,
                "subprocessors": row.try_get::<i64, _>("subprocessors")?,
                "open_risk_links": row.try_get::<i64, _>("open_risk_links")?
            }))
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()?;
    Ok(supplier_review_snapshot_json(suppliers))
}

async fn supplier_review_sqlite(pool: &SqlitePool, tenant_id: i64) -> anyhow::Result<Value> {
    let rows = sqlx::query(supplier_review_sqlite_sql())
        .bind(tenant_id)
        .fetch_all(pool)
        .await?;
    let suppliers = rows
        .into_iter()
        .map(|row| {
            let id = row.try_get::<i64, _>("id")?;
            Ok(serde_json::json!({
                "id": id,
                "entity_type": "supplier",
                "href": format!("/suppliers/{id}/"),
                "name": row.try_get::<String, _>("name")?,
                "criticality": row.try_get::<String, _>("criticality")?,
                "review_status": row.try_get::<String, _>("review_status")?,
                "approval_status": row.try_get::<String, _>("approval_status")?,
                "next_review_due_at": row.try_get::<String, _>("next_review_due_at")?,
                "evidence_required": row.try_get::<bool, _>("evidence_required")?,
                "regulatory_scope": row.try_get::<String, _>("regulatory_scope")?,
                "evidence_links": row.try_get::<i64, _>("evidence_links")?,
                "subprocessors": row.try_get::<i64, _>("subprocessors")?,
                "open_risk_links": row.try_get::<i64, _>("open_risk_links")?
            }))
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()?;
    Ok(supplier_review_snapshot_json(suppliers))
}

fn supplier_review_snapshot_json(suppliers: Vec<Value>) -> Value {
    let critical = suppliers
        .iter()
        .filter(|supplier| {
            supplier["criticality"]
                .as_str()
                .map(|value| {
                    matches!(
                        value.to_ascii_uppercase().as_str(),
                        "CRITICAL" | "VERY_HIGH" | "HIGH"
                    )
                })
                .unwrap_or(false)
        })
        .count() as i64;
    let missing_evidence = suppliers
        .iter()
        .filter(|supplier| {
            supplier["evidence_required"].as_bool().unwrap_or(false)
                && supplier["evidence_links"].as_i64().unwrap_or(0) == 0
        })
        .count() as i64;
    let overdue_or_unreviewed = suppliers
        .iter()
        .filter(|supplier| {
            let status = supplier["review_status"]
                .as_str()
                .unwrap_or_default()
                .to_ascii_lowercase();
            status == "not_reviewed" || status == "expired" || status == "draft"
        })
        .count() as i64;
    serde_json::json!({
        "supplier_count": suppliers.len(),
        "critical_suppliers": critical,
        "missing_supplier_evidence": missing_evidence,
        "overdue_or_unreviewed": overdue_or_unreviewed,
        "suppliers": suppliers
    })
}

async fn regulatory_context_postgres(
    pool: &PgPool,
    tenant_id: i64,
    template: ManagementReviewTemplateDefinition,
) -> anyhow::Result<Value> {
    let row = sqlx::query(regulatory_context_postgres_sql())
        .bind(tenant_id)
        .fetch_optional(pool)
        .await?;
    Ok(regulatory_context_json(
        template,
        row.map(regulatory_context_pg_row_to_json).transpose()?,
    ))
}

async fn regulatory_context_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    template: ManagementReviewTemplateDefinition,
) -> anyhow::Result<Value> {
    let row = sqlx::query(regulatory_context_sqlite_sql())
        .bind(tenant_id)
        .fetch_optional(pool)
        .await?;
    Ok(regulatory_context_json(
        template,
        row.map(regulatory_context_sqlite_row_to_json).transpose()?,
    ))
}

fn regulatory_context_json(
    template: ManagementReviewTemplateDefinition,
    tenant_profile: Option<Value>,
) -> Value {
    serde_json::json!({
        "template_type": template.template_type,
        "template_version": template.template_version,
        "regulatory_context": template.regulatory_context,
        "purpose": template.purpose,
        "tenant_profile": tenant_profile.unwrap_or_else(|| serde_json::json!({
            "status": "Kein regulatorisches Tenant-Profil erfasst"
        })),
        "disclaimer": "ISCY unterstuetzt Governance- und Evidence-Vorbereitung; dieser Snapshot ist keine Rechtsberatung, keine Zertifizierung und keine formale regulatorische Einreichung."
    })
}

fn regulatory_context_pg_row_to_json(row: PgRow) -> Result<Value, sqlx::Error> {
    Ok(serde_json::json!({
        "name": row.try_get::<String, _>("name")?,
        "country": row.try_get::<String, _>("country")?,
        "sector": row.try_get::<String, _>("sector")?,
        "nis2_relevant": row.try_get::<bool, _>("nis2_relevant")?,
        "kritis_relevant": row.try_get::<bool, _>("kritis_relevant")?,
        "dora_relevant": row.try_get::<bool, _>("dora_relevant")?,
        "dora_financial_entity": row.try_get::<bool, _>("dora_financial_entity")?,
        "dora_ict_third_party_provider": row.try_get::<bool, _>("dora_ict_third_party_provider")?,
        "develops_digital_products": row.try_get::<bool, _>("develops_digital_products")?,
        "processes_personal_data": row.try_get::<bool, _>("processes_personal_data")?,
        "uses_ai_systems": row.try_get::<bool, _>("uses_ai_systems")?,
        "ai_act_profile": row.try_get::<String, _>("ai_act_profile")?,
        "ai_act_high_risk": row.try_get::<bool, _>("ai_act_high_risk")?,
        "tisax_relevant": row.try_get::<bool, _>("tisax_relevant")?,
        "iso27001_target": row.try_get::<String, _>("iso27001_target")?,
        "product_security_scope": row.try_get::<String, _>("product_security_scope")?
    }))
}

fn regulatory_context_sqlite_row_to_json(row: SqliteRow) -> Result<Value, sqlx::Error> {
    Ok(serde_json::json!({
        "name": row.try_get::<String, _>("name")?,
        "country": row.try_get::<String, _>("country")?,
        "sector": row.try_get::<String, _>("sector")?,
        "nis2_relevant": row.try_get::<bool, _>("nis2_relevant")?,
        "kritis_relevant": row.try_get::<bool, _>("kritis_relevant")?,
        "dora_relevant": row.try_get::<bool, _>("dora_relevant")?,
        "dora_financial_entity": row.try_get::<bool, _>("dora_financial_entity")?,
        "dora_ict_third_party_provider": row.try_get::<bool, _>("dora_ict_third_party_provider")?,
        "develops_digital_products": row.try_get::<bool, _>("develops_digital_products")?,
        "processes_personal_data": row.try_get::<bool, _>("processes_personal_data")?,
        "uses_ai_systems": row.try_get::<bool, _>("uses_ai_systems")?,
        "ai_act_profile": row.try_get::<String, _>("ai_act_profile")?,
        "ai_act_high_risk": row.try_get::<bool, _>("ai_act_high_risk")?,
        "tisax_relevant": row.try_get::<bool, _>("tisax_relevant")?,
        "iso27001_target": row.try_get::<String, _>("iso27001_target")?,
        "product_security_scope": row.try_get::<String, _>("product_security_scope")?
    }))
}

async fn ai_governance_postgres(pool: &PgPool, tenant_id: i64) -> anyhow::Result<Value> {
    let rows = sqlx::query(
        r#"
        SELECT
            system.id,
            system.name,
            system.ai_act_classification,
            system.criticality,
            system.status,
            COALESCE(system.next_review_due_at, '') AS next_review_due_at,
            CASE WHEN BTRIM(system.risk_summary) = '' THEN TRUE ELSE FALSE END AS risk_summary_missing,
            (SELECT COUNT(*)::bigint FROM ai_governance_system_risk link
             WHERE link.tenant_id = system.tenant_id AND link.system_id = system.id) AS risk_links,
            (SELECT COUNT(*)::bigint FROM ai_governance_system_roadmap_task link
             WHERE link.tenant_id = system.tenant_id AND link.system_id = system.id) AS roadmap_task_links,
            (SELECT COUNT(*)::bigint FROM ai_governance_system_incident link
             WHERE link.tenant_id = system.tenant_id AND link.system_id = system.id) AS incident_links,
            (SELECT COUNT(*)::bigint FROM ai_governance_system_change link
             WHERE link.tenant_id = system.tenant_id AND link.system_id = system.id) AS change_links,
            (SELECT COUNT(*)::bigint FROM evidence_evidenceitem evidence
             WHERE evidence.tenant_id = system.tenant_id
               AND evidence.linked_requirement = system.evidence_key) AS evidence_count
        FROM ai_governance_system system
        WHERE system.tenant_id = $1
        ORDER BY system.criticality DESC, system.updated_at DESC, system.id DESC
        LIMIT 50
        "#,
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;
    let systems = rows
        .into_iter()
        .map(|row| {
            let id = row.try_get::<i64, _>("id")?;
            Ok(serde_json::json!({
                "id": id,
                "entity_type": "ai_governance_system",
                "href": format!("/ai-governance/#ai-system-{id}"),
                "name": row.try_get::<String, _>("name")?,
                "ai_act_classification": row.try_get::<String, _>("ai_act_classification")?,
                "criticality": row.try_get::<String, _>("criticality")?,
                "status": row.try_get::<String, _>("status")?,
                "next_review_due_at": row.try_get::<String, _>("next_review_due_at")?,
                "risk_summary_missing": row.try_get::<bool, _>("risk_summary_missing")?,
                "risk_links": row.try_get::<i64, _>("risk_links")?,
                "roadmap_task_links": row.try_get::<i64, _>("roadmap_task_links")?,
                "incident_links": row.try_get::<i64, _>("incident_links")?,
                "change_links": row.try_get::<i64, _>("change_links")?,
                "evidence_count": row.try_get::<i64, _>("evidence_count")?
            }))
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()?;
    Ok(ai_governance_snapshot_json(systems))
}

async fn ai_governance_sqlite(pool: &SqlitePool, tenant_id: i64) -> anyhow::Result<Value> {
    let rows = sqlx::query(
        r#"
        SELECT
            system.id,
            system.name,
            system.ai_act_classification,
            system.criticality,
            system.status,
            COALESCE(CAST(system.next_review_due_at AS TEXT), '') AS next_review_due_at,
            CASE WHEN TRIM(system.risk_summary) = '' THEN 1 ELSE 0 END AS risk_summary_missing,
            (SELECT COUNT(*) FROM ai_governance_system_risk link
             WHERE link.tenant_id = system.tenant_id AND link.system_id = system.id) AS risk_links,
            (SELECT COUNT(*) FROM ai_governance_system_roadmap_task link
             WHERE link.tenant_id = system.tenant_id AND link.system_id = system.id) AS roadmap_task_links,
            (SELECT COUNT(*) FROM ai_governance_system_incident link
             WHERE link.tenant_id = system.tenant_id AND link.system_id = system.id) AS incident_links,
            (SELECT COUNT(*) FROM ai_governance_system_change link
             WHERE link.tenant_id = system.tenant_id AND link.system_id = system.id) AS change_links,
            (SELECT COUNT(*) FROM evidence_evidenceitem evidence
             WHERE evidence.tenant_id = system.tenant_id
               AND evidence.linked_requirement = system.evidence_key) AS evidence_count
        FROM ai_governance_system system
        WHERE system.tenant_id = ?
        ORDER BY system.criticality DESC, system.updated_at DESC, system.id DESC
        LIMIT 50
        "#,
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;
    let systems = rows
        .into_iter()
        .map(|row| {
            let id = row.try_get::<i64, _>("id")?;
            Ok(serde_json::json!({
                "id": id,
                "entity_type": "ai_governance_system",
                "href": format!("/ai-governance/#ai-system-{id}"),
                "name": row.try_get::<String, _>("name")?,
                "ai_act_classification": row.try_get::<String, _>("ai_act_classification")?,
                "criticality": row.try_get::<String, _>("criticality")?,
                "status": row.try_get::<String, _>("status")?,
                "next_review_due_at": row.try_get::<String, _>("next_review_due_at")?,
                "risk_summary_missing": row.try_get::<bool, _>("risk_summary_missing")?,
                "risk_links": row.try_get::<i64, _>("risk_links")?,
                "roadmap_task_links": row.try_get::<i64, _>("roadmap_task_links")?,
                "incident_links": row.try_get::<i64, _>("incident_links")?,
                "change_links": row.try_get::<i64, _>("change_links")?,
                "evidence_count": row.try_get::<i64, _>("evidence_count")?
            }))
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()?;
    Ok(ai_governance_snapshot_json(systems))
}

fn ai_governance_snapshot_json(systems: Vec<Value>) -> Value {
    let linked_risks = systems
        .iter()
        .filter_map(|system| system["risk_links"].as_i64())
        .sum::<i64>();
    let linked_tasks = systems
        .iter()
        .filter_map(|system| system["roadmap_task_links"].as_i64())
        .sum::<i64>();
    let linked_incidents = systems
        .iter()
        .filter_map(|system| system["incident_links"].as_i64())
        .sum::<i64>();
    let linked_changes = systems
        .iter()
        .filter_map(|system| system["change_links"].as_i64())
        .sum::<i64>();
    serde_json::json!({
        "system_count": systems.len(),
        "linked_risks": linked_risks,
        "linked_roadmap_tasks": linked_tasks,
        "linked_incidents": linked_incidents,
        "linked_changes": linked_changes,
        "systems": systems
    })
}

async fn agent_posture_postgres(pool: &PgPool, tenant_id: i64) -> anyhow::Result<Value> {
    let release_artifacts = count_postgres(
        pool,
        "SELECT COUNT(*)::bigint AS count_value FROM agent_release_artifact WHERE tenant_id = $1",
        tenant_id,
    )
    .await?;
    let release_artifacts_without_checksum = count_postgres(
        pool,
        "SELECT COUNT(*)::bigint AS count_value FROM agent_release_artifact WHERE tenant_id = $1 AND (sha256 = '' OR verification_status IN ('not_available', 'failed', 'mismatch'))",
        tenant_id,
    )
    .await?;
    let unsigned_release_artifacts = count_postgres(
        pool,
        "SELECT COUNT(*)::bigint AS count_value FROM agent_release_artifact WHERE tenant_id = $1 AND signature_status IN ('unsigned', 'not_configured', 'failed', 'expired', 'untrusted', 'key_missing')",
        tenant_id,
    )
    .await?;
    let release_artifacts_missing_provenance = count_postgres(
        pool,
        "SELECT COUNT(*)::bigint AS count_value FROM agent_release_artifact WHERE tenant_id = $1 AND provenance_status IN ('missing', 'incomplete', 'failed')",
        tenant_id,
    )
    .await?;
    let release_artifacts_unverified = count_postgres(
        pool,
        "SELECT COUNT(*)::bigint AS count_value FROM agent_release_artifact WHERE tenant_id = $1 AND verification_status <> 'verified'",
        tenant_id,
    )
    .await?;
    let pki_providers = count_postgres(
        pool,
        "SELECT COUNT(*)::bigint AS count_value FROM agent_pki_provider WHERE tenant_id = $1",
        tenant_id,
    )
    .await?;
    let pki_provider_not_configured = count_postgres(
        pool,
        "SELECT COUNT(*)::bigint AS count_value FROM agent_pki_provider WHERE tenant_id = $1 AND provider_status = 'not_configured'",
        tenant_id,
    )
    .await?;
    let pending_csrs = count_postgres(
        pool,
        "SELECT COUNT(*)::bigint AS count_value FROM agent_certificate_request WHERE tenant_id = $1 AND csr_status = 'pending_review'",
        tenant_id,
    )
    .await?;
    let certificates = count_postgres(
        pool,
        "SELECT COUNT(*)::bigint AS count_value FROM agent_certificate_status WHERE tenant_id = $1",
        tenant_id,
    )
    .await?;
    let agents_without_certificate_status = count_postgres(
        pool,
        "SELECT COUNT(*)::bigint AS count_value FROM zero_trust_agent_device device WHERE device.tenant_id = $1 AND NOT EXISTS (SELECT 1 FROM agent_certificate_status cert WHERE cert.tenant_id = device.tenant_id AND cert.agent_id = device.id)",
        tenant_id,
    )
    .await?;
    let expiring_agent_certificates = count_postgres(
        pool,
        "SELECT COUNT(*)::bigint AS count_value FROM agent_certificate_status WHERE tenant_id = $1 AND certificate_status = 'expiring_soon'",
        tenant_id,
    )
    .await?;
    let expired_agent_certificates = count_postgres(
        pool,
        "SELECT COUNT(*)::bigint AS count_value FROM agent_certificate_status WHERE tenant_id = $1 AND certificate_status = 'expired'",
        tenant_id,
    )
    .await?;
    let mtls_binding_gaps = count_postgres(
        pool,
        "SELECT COUNT(*)::bigint AS count_value FROM agent_certificate_status WHERE tenant_id = $1 AND mtls_binding_status IN ('not_configured','pending','mismatch','stale','failed')",
        tenant_id,
    )
    .await?;
    let rotation_required_certificates = count_postgres(
        pool,
        "SELECT COUNT(*)::bigint AS count_value FROM agent_certificate_status WHERE tenant_id = $1 AND rotation_status = 'rotation_required'",
        tenant_id,
    )
    .await?;
    let revocation_requested_certificates = count_postgres(
        pool,
        "SELECT COUNT(*)::bigint AS count_value FROM agent_certificate_status WHERE tenant_id = $1 AND revocation_status = 'revocation_requested'",
        tenant_id,
    )
    .await?;
    let agent_pki_governance_gaps = (if pki_providers == 0 { 1 } else { 0 })
        + pki_provider_not_configured
        + pending_csrs
        + agents_without_certificate_status
        + expiring_agent_certificates
        + expired_agent_certificates
        + mtls_binding_gaps
        + rotation_required_certificates
        + revocation_requested_certificates;
    let mut posture = serde_json::json!({
        "devices": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM zero_trust_agent_device WHERE tenant_id = $1", tenant_id).await?,
        "active_devices": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM zero_trust_agent_device WHERE tenant_id = $1 AND enrollment_status = 'ACTIVE'", tenant_id).await?,
        "open_findings": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM zero_trust_agent_finding WHERE tenant_id = $1 AND status = 'OPEN'", tenant_id).await?,
        "critical_findings": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM zero_trust_agent_finding WHERE tenant_id = $1 AND status = 'OPEN' AND severity = 'CRITICAL'", tenant_id).await?,
        "release_artifacts": release_artifacts,
        "release_artifact_manifest_missing": if release_artifacts == 0 { 1 } else { 0 },
        "release_artifacts_without_checksum": release_artifacts_without_checksum,
        "unsigned_release_artifacts": unsigned_release_artifacts,
        "release_artifacts_missing_provenance": release_artifacts_missing_provenance,
        "release_artifacts_unverified": release_artifacts_unverified,
        "release_artifact_supply_chain_gaps": (if release_artifacts == 0 { 1 } else { 0 })
            + release_artifacts_without_checksum
            + unsigned_release_artifacts
            + release_artifacts_missing_provenance
            + release_artifacts_unverified,
        "agent_pki_providers": pki_providers,
        "agent_pki_provider_not_configured": pki_provider_not_configured,
        "agent_certificates": certificates,
        "agents_without_certificate_status": agents_without_certificate_status,
        "pending_agent_csrs": pending_csrs,
        "expiring_agent_certificates": expiring_agent_certificates,
        "expired_agent_certificates": expired_agent_certificates,
        "mtls_binding_gaps": mtls_binding_gaps,
        "rotation_required_certificates": rotation_required_certificates,
        "revocation_requested_certificates": revocation_requested_certificates,
        "agent_pki_governance_gaps": agent_pki_governance_gaps
    });
    merge_json_object(
        &mut posture,
        agent_rollout_review_postgres(pool, tenant_id).await?,
    );
    Ok(posture)
}

async fn agent_posture_sqlite(pool: &SqlitePool, tenant_id: i64) -> anyhow::Result<Value> {
    let release_artifacts = count_sqlite(
        pool,
        "SELECT COUNT(*) AS count_value FROM agent_release_artifact WHERE tenant_id = ?",
        tenant_id,
    )
    .await?;
    let release_artifacts_without_checksum = count_sqlite(
        pool,
        "SELECT COUNT(*) AS count_value FROM agent_release_artifact WHERE tenant_id = ? AND (sha256 = '' OR verification_status IN ('not_available', 'failed', 'mismatch'))",
        tenant_id,
    )
    .await?;
    let unsigned_release_artifacts = count_sqlite(
        pool,
        "SELECT COUNT(*) AS count_value FROM agent_release_artifact WHERE tenant_id = ? AND signature_status IN ('unsigned', 'not_configured', 'failed', 'expired', 'untrusted', 'key_missing')",
        tenant_id,
    )
    .await?;
    let release_artifacts_missing_provenance = count_sqlite(
        pool,
        "SELECT COUNT(*) AS count_value FROM agent_release_artifact WHERE tenant_id = ? AND provenance_status IN ('missing', 'incomplete', 'failed')",
        tenant_id,
    )
    .await?;
    let release_artifacts_unverified = count_sqlite(
        pool,
        "SELECT COUNT(*) AS count_value FROM agent_release_artifact WHERE tenant_id = ? AND verification_status <> 'verified'",
        tenant_id,
    )
    .await?;
    let pki_providers = count_sqlite(
        pool,
        "SELECT COUNT(*) AS count_value FROM agent_pki_provider WHERE tenant_id = ?",
        tenant_id,
    )
    .await?;
    let pki_provider_not_configured = count_sqlite(
        pool,
        "SELECT COUNT(*) AS count_value FROM agent_pki_provider WHERE tenant_id = ? AND provider_status = 'not_configured'",
        tenant_id,
    )
    .await?;
    let pending_csrs = count_sqlite(
        pool,
        "SELECT COUNT(*) AS count_value FROM agent_certificate_request WHERE tenant_id = ? AND csr_status = 'pending_review'",
        tenant_id,
    )
    .await?;
    let certificates = count_sqlite(
        pool,
        "SELECT COUNT(*) AS count_value FROM agent_certificate_status WHERE tenant_id = ?",
        tenant_id,
    )
    .await?;
    let agents_without_certificate_status = count_sqlite(
        pool,
        "SELECT COUNT(*) AS count_value FROM zero_trust_agent_device device WHERE device.tenant_id = ? AND NOT EXISTS (SELECT 1 FROM agent_certificate_status cert WHERE cert.tenant_id = device.tenant_id AND cert.agent_id = device.id)",
        tenant_id,
    )
    .await?;
    let expiring_agent_certificates = count_sqlite(
        pool,
        "SELECT COUNT(*) AS count_value FROM agent_certificate_status WHERE tenant_id = ? AND certificate_status = 'expiring_soon'",
        tenant_id,
    )
    .await?;
    let expired_agent_certificates = count_sqlite(
        pool,
        "SELECT COUNT(*) AS count_value FROM agent_certificate_status WHERE tenant_id = ? AND certificate_status = 'expired'",
        tenant_id,
    )
    .await?;
    let mtls_binding_gaps = count_sqlite(
        pool,
        "SELECT COUNT(*) AS count_value FROM agent_certificate_status WHERE tenant_id = ? AND mtls_binding_status IN ('not_configured','pending','mismatch','stale','failed')",
        tenant_id,
    )
    .await?;
    let rotation_required_certificates = count_sqlite(
        pool,
        "SELECT COUNT(*) AS count_value FROM agent_certificate_status WHERE tenant_id = ? AND rotation_status = 'rotation_required'",
        tenant_id,
    )
    .await?;
    let revocation_requested_certificates = count_sqlite(
        pool,
        "SELECT COUNT(*) AS count_value FROM agent_certificate_status WHERE tenant_id = ? AND revocation_status = 'revocation_requested'",
        tenant_id,
    )
    .await?;
    let agent_pki_governance_gaps = (if pki_providers == 0 { 1 } else { 0 })
        + pki_provider_not_configured
        + pending_csrs
        + agents_without_certificate_status
        + expiring_agent_certificates
        + expired_agent_certificates
        + mtls_binding_gaps
        + rotation_required_certificates
        + revocation_requested_certificates;
    let mut posture = serde_json::json!({
        "devices": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM zero_trust_agent_device WHERE tenant_id = ?", tenant_id).await?,
        "active_devices": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM zero_trust_agent_device WHERE tenant_id = ? AND enrollment_status = 'ACTIVE'", tenant_id).await?,
        "open_findings": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM zero_trust_agent_finding WHERE tenant_id = ? AND status = 'OPEN'", tenant_id).await?,
        "critical_findings": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM zero_trust_agent_finding WHERE tenant_id = ? AND status = 'OPEN' AND severity = 'CRITICAL'", tenant_id).await?,
        "release_artifacts": release_artifacts,
        "release_artifact_manifest_missing": if release_artifacts == 0 { 1 } else { 0 },
        "release_artifacts_without_checksum": release_artifacts_without_checksum,
        "unsigned_release_artifacts": unsigned_release_artifacts,
        "release_artifacts_missing_provenance": release_artifacts_missing_provenance,
        "release_artifacts_unverified": release_artifacts_unverified,
        "release_artifact_supply_chain_gaps": (if release_artifacts == 0 { 1 } else { 0 })
            + release_artifacts_without_checksum
            + unsigned_release_artifacts
            + release_artifacts_missing_provenance
            + release_artifacts_unverified,
        "agent_pki_providers": pki_providers,
        "agent_pki_provider_not_configured": pki_provider_not_configured,
        "agent_certificates": certificates,
        "agents_without_certificate_status": agents_without_certificate_status,
        "pending_agent_csrs": pending_csrs,
        "expiring_agent_certificates": expiring_agent_certificates,
        "expired_agent_certificates": expired_agent_certificates,
        "mtls_binding_gaps": mtls_binding_gaps,
        "rotation_required_certificates": rotation_required_certificates,
        "revocation_requested_certificates": revocation_requested_certificates,
        "agent_pki_governance_gaps": agent_pki_governance_gaps
    });
    merge_json_object(
        &mut posture,
        agent_rollout_review_sqlite(pool, tenant_id).await?,
    );
    Ok(posture)
}

async fn agent_rollout_review_postgres(pool: &PgPool, tenant_id: i64) -> anyhow::Result<Value> {
    let row = sqlx::query(
        r#"
        SELECT
            (SELECT COUNT(*)::bigint FROM zero_trust_agent_rollout WHERE tenant_id = $1) AS agent_rollout_count,
            (SELECT COUNT(*)::bigint FROM zero_trust_agent_rollout WHERE tenant_id = $1 AND status = 'active') AS agent_rollouts_active,
            (SELECT COUNT(*)::bigint FROM zero_trust_agent_rollout WHERE tenant_id = $1 AND status = 'paused') AS agent_rollouts_paused,
            (SELECT COUNT(*)::bigint FROM zero_trust_agent_rollout rollout WHERE tenant_id = $1 AND EXISTS (
                SELECT 1 FROM zero_trust_agent_rollout_target target
                WHERE target.tenant_id = rollout.tenant_id AND target.rollout_id = rollout.id AND target.status = 'failed'
            )) AS agent_rollouts_with_failures,
            (SELECT COUNT(*)::bigint FROM zero_trust_agent_rollout WHERE tenant_id = $1 AND status = 'rollback_required') AS agent_rollouts_rollback_required,
            (SELECT COUNT(*)::bigint FROM zero_trust_agent_rollout_ring WHERE tenant_id = $1 AND status IN ('failed', 'rollback_required')) AS agent_rollout_blocked_rings,
            (SELECT COUNT(*)::bigint FROM zero_trust_agent_rollout_target WHERE tenant_id = $1 AND status = 'failed') AS agent_rollout_failed_targets,
            (SELECT COUNT(*)::bigint FROM zero_trust_agent_rollout_target WHERE tenant_id = $1 AND status = 'blocked' AND preflight_status = 'failed') AS agent_rollout_open_preflight_blockers,
            (SELECT COUNT(*)::bigint FROM zero_trust_agent_rollout WHERE tenant_id = $1 AND owner_id IS NULL) AS agent_rollouts_without_owner,
            (SELECT COUNT(*)::bigint FROM zero_trust_agent_rollout WHERE tenant_id = $1 AND BTRIM(rollback_plan) = '') AS agent_rollouts_without_rollback_plan,
            (SELECT COUNT(*)::bigint FROM zero_trust_agent_rollout_manifest WHERE tenant_id = $1 AND status = 'active') AS agent_rollout_active_manifests,
            (SELECT COUNT(*)::bigint FROM zero_trust_agent_rollout_ring ring WHERE tenant_id = $1 AND status = 'ready' AND NOT EXISTS (
                SELECT 1 FROM zero_trust_agent_rollout_manifest manifest WHERE manifest.tenant_id=ring.tenant_id AND manifest.rollout_id=ring.rollout_id AND manifest.ring_id=ring.id AND manifest.status='active'
            )) AS agent_rollout_rings_without_manifest,
            (SELECT COUNT(*)::bigint FROM zero_trust_agent_rollout_handoff WHERE tenant_id = $1 AND status NOT IN ('completed','failed','expired','invalidated')) AS agent_rollout_active_handoffs,
            (SELECT COUNT(*)::bigint FROM zero_trust_agent_rollout_handoff WHERE tenant_id = $1 AND status IN ('exported','awaiting_results','partially_reported')) AS agent_rollout_handoffs_awaiting_results,
            (SELECT COALESCE(SUM(expected_result_count-reported_result_count),0)::bigint FROM zero_trust_agent_rollout_handoff WHERE tenant_id = $1 AND status IN ('exported','awaiting_results','partially_reported')) AS agent_rollout_missing_handoff_results,
            (SELECT COALESCE(SUM(failed_count+timed_out_count+unknown_count),0)::bigint FROM zero_trust_agent_rollout_handoff WHERE tenant_id = $1) AS agent_rollout_failed_import_results,
            (SELECT COALESCE(SUM(version_mismatch_count),0)::bigint FROM zero_trust_agent_rollout_handoff WHERE tenant_id = $1) AS agent_rollout_version_mismatches,
            COALESCE((
                SELECT ring_name FROM zero_trust_agent_rollout_ring
                WHERE tenant_id = $1 AND status IN ('active', 'observing', 'passed', 'failed', 'rollback_required', 'rolled_back')
                ORDER BY sequence_number DESC LIMIT 1
            ), 'none') AS agent_rollout_highest_ring
        "#,
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await?;
    agent_rollout_review_from_postgres_row(&row)
}

async fn agent_rollout_review_sqlite(pool: &SqlitePool, tenant_id: i64) -> anyhow::Result<Value> {
    let row = sqlx::query(
        r#"
        SELECT
            (SELECT COUNT(*) FROM zero_trust_agent_rollout WHERE tenant_id = ?1) AS agent_rollout_count,
            (SELECT COUNT(*) FROM zero_trust_agent_rollout WHERE tenant_id = ?1 AND status = 'active') AS agent_rollouts_active,
            (SELECT COUNT(*) FROM zero_trust_agent_rollout WHERE tenant_id = ?1 AND status = 'paused') AS agent_rollouts_paused,
            (SELECT COUNT(*) FROM zero_trust_agent_rollout rollout WHERE tenant_id = ?1 AND EXISTS (
                SELECT 1 FROM zero_trust_agent_rollout_target target
                WHERE target.tenant_id = rollout.tenant_id AND target.rollout_id = rollout.id AND target.status = 'failed'
            )) AS agent_rollouts_with_failures,
            (SELECT COUNT(*) FROM zero_trust_agent_rollout WHERE tenant_id = ?1 AND status = 'rollback_required') AS agent_rollouts_rollback_required,
            (SELECT COUNT(*) FROM zero_trust_agent_rollout_ring WHERE tenant_id = ?1 AND status IN ('failed', 'rollback_required')) AS agent_rollout_blocked_rings,
            (SELECT COUNT(*) FROM zero_trust_agent_rollout_target WHERE tenant_id = ?1 AND status = 'failed') AS agent_rollout_failed_targets,
            (SELECT COUNT(*) FROM zero_trust_agent_rollout_target WHERE tenant_id = ?1 AND status = 'blocked' AND preflight_status = 'failed') AS agent_rollout_open_preflight_blockers,
            (SELECT COUNT(*) FROM zero_trust_agent_rollout WHERE tenant_id = ?1 AND owner_id IS NULL) AS agent_rollouts_without_owner,
            (SELECT COUNT(*) FROM zero_trust_agent_rollout WHERE tenant_id = ?1 AND TRIM(rollback_plan) = '') AS agent_rollouts_without_rollback_plan,
            (SELECT COUNT(*) FROM zero_trust_agent_rollout_manifest WHERE tenant_id = ?1 AND status = 'active') AS agent_rollout_active_manifests,
            (SELECT COUNT(*) FROM zero_trust_agent_rollout_ring ring WHERE tenant_id = ?1 AND status = 'ready' AND NOT EXISTS (
                SELECT 1 FROM zero_trust_agent_rollout_manifest manifest WHERE manifest.tenant_id=ring.tenant_id AND manifest.rollout_id=ring.rollout_id AND manifest.ring_id=ring.id AND manifest.status='active'
            )) AS agent_rollout_rings_without_manifest,
            (SELECT COUNT(*) FROM zero_trust_agent_rollout_handoff WHERE tenant_id = ?1 AND status NOT IN ('completed','failed','expired','invalidated')) AS agent_rollout_active_handoffs,
            (SELECT COUNT(*) FROM zero_trust_agent_rollout_handoff WHERE tenant_id = ?1 AND status IN ('exported','awaiting_results','partially_reported')) AS agent_rollout_handoffs_awaiting_results,
            (SELECT COALESCE(SUM(expected_result_count-reported_result_count),0) FROM zero_trust_agent_rollout_handoff WHERE tenant_id = ?1 AND status IN ('exported','awaiting_results','partially_reported')) AS agent_rollout_missing_handoff_results,
            (SELECT COALESCE(SUM(failed_count+timed_out_count+unknown_count),0) FROM zero_trust_agent_rollout_handoff WHERE tenant_id = ?1) AS agent_rollout_failed_import_results,
            (SELECT COALESCE(SUM(version_mismatch_count),0) FROM zero_trust_agent_rollout_handoff WHERE tenant_id = ?1) AS agent_rollout_version_mismatches,
            COALESCE((
                SELECT ring_name FROM zero_trust_agent_rollout_ring
                WHERE tenant_id = ?1 AND status IN ('active', 'observing', 'passed', 'failed', 'rollback_required', 'rolled_back')
                ORDER BY sequence_number DESC LIMIT 1
            ), 'none') AS agent_rollout_highest_ring
        "#,
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await?;
    agent_rollout_review_from_sqlite_row(&row)
}

fn agent_rollout_review_from_postgres_row(row: &PgRow) -> anyhow::Result<Value> {
    Ok(serde_json::json!({
        "agent_rollout_count": row.try_get::<i64, _>("agent_rollout_count")?,
        "agent_rollouts_active": row.try_get::<i64, _>("agent_rollouts_active")?,
        "agent_rollouts_paused": row.try_get::<i64, _>("agent_rollouts_paused")?,
        "agent_rollouts_with_failures": row.try_get::<i64, _>("agent_rollouts_with_failures")?,
        "agent_rollouts_rollback_required": row.try_get::<i64, _>("agent_rollouts_rollback_required")?,
        "agent_rollout_blocked_rings": row.try_get::<i64, _>("agent_rollout_blocked_rings")?,
        "agent_rollout_failed_targets": row.try_get::<i64, _>("agent_rollout_failed_targets")?,
        "agent_rollout_open_preflight_blockers": row.try_get::<i64, _>("agent_rollout_open_preflight_blockers")?,
        "agent_rollouts_without_owner": row.try_get::<i64, _>("agent_rollouts_without_owner")?,
        "agent_rollouts_without_rollback_plan": row.try_get::<i64, _>("agent_rollouts_without_rollback_plan")?,
        "agent_rollout_active_manifests": row.try_get::<i64, _>("agent_rollout_active_manifests")?,
        "agent_rollout_rings_without_manifest": row.try_get::<i64, _>("agent_rollout_rings_without_manifest")?,
        "agent_rollout_active_handoffs": row.try_get::<i64, _>("agent_rollout_active_handoffs")?,
        "agent_rollout_handoffs_awaiting_results": row.try_get::<i64, _>("agent_rollout_handoffs_awaiting_results")?,
        "agent_rollout_missing_handoff_results": row.try_get::<i64, _>("agent_rollout_missing_handoff_results")?,
        "agent_rollout_failed_import_results": row.try_get::<i64, _>("agent_rollout_failed_import_results")?,
        "agent_rollout_version_mismatches": row.try_get::<i64, _>("agent_rollout_version_mismatches")?,
        "agent_rollout_highest_ring": row.try_get::<String, _>("agent_rollout_highest_ring")?
    }))
}

fn agent_rollout_review_from_sqlite_row(row: &SqliteRow) -> anyhow::Result<Value> {
    Ok(serde_json::json!({
        "agent_rollout_count": row.try_get::<i64, _>("agent_rollout_count")?,
        "agent_rollouts_active": row.try_get::<i64, _>("agent_rollouts_active")?,
        "agent_rollouts_paused": row.try_get::<i64, _>("agent_rollouts_paused")?,
        "agent_rollouts_with_failures": row.try_get::<i64, _>("agent_rollouts_with_failures")?,
        "agent_rollouts_rollback_required": row.try_get::<i64, _>("agent_rollouts_rollback_required")?,
        "agent_rollout_blocked_rings": row.try_get::<i64, _>("agent_rollout_blocked_rings")?,
        "agent_rollout_failed_targets": row.try_get::<i64, _>("agent_rollout_failed_targets")?,
        "agent_rollout_open_preflight_blockers": row.try_get::<i64, _>("agent_rollout_open_preflight_blockers")?,
        "agent_rollouts_without_owner": row.try_get::<i64, _>("agent_rollouts_without_owner")?,
        "agent_rollouts_without_rollback_plan": row.try_get::<i64, _>("agent_rollouts_without_rollback_plan")?,
        "agent_rollout_active_manifests": row.try_get::<i64, _>("agent_rollout_active_manifests")?,
        "agent_rollout_rings_without_manifest": row.try_get::<i64, _>("agent_rollout_rings_without_manifest")?,
        "agent_rollout_active_handoffs": row.try_get::<i64, _>("agent_rollout_active_handoffs")?,
        "agent_rollout_handoffs_awaiting_results": row.try_get::<i64, _>("agent_rollout_handoffs_awaiting_results")?,
        "agent_rollout_missing_handoff_results": row.try_get::<i64, _>("agent_rollout_missing_handoff_results")?,
        "agent_rollout_failed_import_results": row.try_get::<i64, _>("agent_rollout_failed_import_results")?,
        "agent_rollout_version_mismatches": row.try_get::<i64, _>("agent_rollout_version_mismatches")?,
        "agent_rollout_highest_ring": row.try_get::<String, _>("agent_rollout_highest_ring")?
    }))
}

fn merge_json_object(target: &mut Value, additional: Value) {
    let (Some(target), Some(additional)) = (target.as_object_mut(), additional.as_object()) else {
        return;
    };
    target.extend(additional.clone());
}

async fn count_postgres(pool: &PgPool, sql: &str, tenant_id: i64) -> anyhow::Result<i64> {
    let row = sqlx::query(sql).bind(tenant_id).fetch_one(pool).await?;
    Ok(row.try_get("count_value")?)
}

async fn count_sqlite(pool: &SqlitePool, sql: &str, tenant_id: i64) -> anyhow::Result<i64> {
    let row = sqlx::query(sql).bind(tenant_id).fetch_one(pool).await?;
    Ok(row.try_get("count_value")?)
}

async fn audit_management_review_event_postgres(
    pool: &PgPool,
    tenant_id: i64,
    review_id: Option<i64>,
    template_type: &str,
    action: &str,
    actor_id: Option<i64>,
    detail: &Value,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO management_review_audit_event (
            tenant_id, review_id, template_type, action, actor_id, detail, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, NOW()::text)
        "#,
    )
    .bind(tenant_id)
    .bind(review_id)
    .bind(template_type)
    .bind(action)
    .bind(actor_id)
    .bind(detail.to_string())
    .execute(pool)
    .await
    .context("PostgreSQL-Management-Review-Audit konnte nicht geschrieben werden")?;
    Ok(())
}

async fn audit_management_review_event_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    review_id: Option<i64>,
    template_type: &str,
    action: &str,
    actor_id: Option<i64>,
    detail: &Value,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO management_review_audit_event (
            tenant_id, review_id, template_type, action, actor_id, detail, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        "#,
    )
    .bind(tenant_id)
    .bind(review_id)
    .bind(template_type)
    .bind(action)
    .bind(actor_id)
    .bind(detail.to_string())
    .execute(pool)
    .await
    .context("SQLite-Management-Review-Audit konnte nicht geschrieben werden")?;
    Ok(())
}

fn management_review_source_counts(
    counts: &ManagementReviewItemCounts,
    metrics: &Value,
    product_security: &Value,
    agent_posture: &Value,
) -> Value {
    serde_json::json!({
        "risks": counts.top_risks,
        "controls": counts.control_gaps,
        "evidence": counts.evidence_gaps,
        "evidence_integrity_items": json_i64(&metrics["evidence_integrity_storage"], "total_items"),
        "evidence_storage_drills": json_i64(&metrics["evidence_integrity_storage"], "storage_drills_recorded"),
        "evidence_worker_runs": json_i64(&metrics["evidence_integrity_storage"], "worker_runs_recorded"),
        "incidents": counts.incidents,
        "roadmap_tasks": counts.roadmap,
        "product_security_products": json_i64(product_security, "products"),
        "product_security_open_vulnerabilities": json_i64(product_security, "open_vulnerabilities"),
        "supplier_product_security_records": json_i64(product_security, "supplier_product_security_records"),
        "suppliers": counts.suppliers,
        "agent_devices": json_i64(agent_posture, "devices"),
        "agent_release_artifacts": json_i64(agent_posture, "release_artifacts"),
        "agent_pki_providers": json_i64(agent_posture, "agent_pki_providers"),
        "agent_certificates": json_i64(agent_posture, "agent_certificates"),
        "ai_governance_systems": counts.ai_governance,
        "no_data_recorded": {
            "risks": counts.top_risks == 0,
            "controls": counts.control_gaps == 0,
            "evidence": counts.evidence_gaps == 0,
            "evidence_integrity": json_i64(&metrics["evidence_integrity_storage"], "total_items") == 0,
            "incidents": counts.incidents == 0,
            "roadmap_tasks": counts.roadmap == 0,
            "suppliers": counts.suppliers == 0,
            "supplier_product_security": json_i64(product_security, "supplier_product_security_records") == 0,
            "agent_release_artifacts": json_i64(agent_posture, "release_artifacts") == 0,
            "agent_pki": json_i64(agent_posture, "agent_pki_providers") == 0
                && json_i64(agent_posture, "agent_certificates") == 0,
            "ai_governance": counts.ai_governance == 0
        }
    })
}

fn management_review_gap_summary(
    metrics: &Value,
    product_security: &Value,
    supplier: &Value,
    agent_posture: &Value,
    ai_governance: &Value,
) -> Value {
    let mut summary = serde_json::json!({
        "critical_open_risks": json_i64(metrics, "critical_open_risks"),
        "open_control_gaps": json_i64(metrics, "open_control_gaps"),
        "missing_control_evidence": json_i64(metrics, "missing_control_evidence"),
        "open_evidence_needs": json_i64(metrics, "open_evidence_needs"),
        "unassessed_incidents": json_i64(metrics, "unassessed_incidents"),
        "open_roadmap_tasks": json_i64(metrics, "open_roadmap_tasks"),
        "critical_open_vulnerabilities": json_i64(product_security, "critical_open_vulnerabilities"),
        "open_cve_correlation_reviews": json_i64(product_security, "open_cve_correlation_reviews"),
        "invalid_product_security_imports": json_i64(product_security, "invalid_imports"),
        "open_supplier_product_security_advisories": json_i64(product_security, "open_supplier_product_security_advisories"),
        "critical_supplier_product_security_advisories": json_i64(product_security, "critical_supplier_product_security_advisories"),
        "supplier_product_security_missing_evidence": json_i64(product_security, "supplier_product_security_missing_evidence"),
        "supplier_product_security_missing_owner": json_i64(product_security, "supplier_product_security_missing_owner"),
        "supplier_product_security_open_actions": json_i64(product_security, "supplier_product_security_open_actions"),
        "supplier_product_security_overdue_reviews": json_i64(product_security, "supplier_product_security_overdue_reviews"),
        "supplier_product_security_dora_relevant": json_i64(product_security, "supplier_product_security_dora_relevant"),
        "supplier_product_security_nis2_relevant": json_i64(product_security, "supplier_product_security_nis2_relevant"),
        "supplier_product_security_data_processing_relevant": json_i64(product_security, "supplier_product_security_data_processing_relevant"),
        "supplier_product_security_critical_services": json_i64(product_security, "supplier_product_security_critical_services"),
        "evidence_integrity_not_checked": json_i64(metrics, "evidence_integrity_not_checked"),
        "evidence_integrity_mismatch": json_i64(metrics, "evidence_integrity_mismatch"),
        "evidence_storage_artifact_references": json_i64(metrics, "evidence_storage_artifact_references"),
        "evidence_storage_drills_recorded": json_i64(metrics, "evidence_storage_drills_recorded"),
        "evidence_object_storage_backends": json_i64(metrics, "evidence_object_storage_backends"),
        "evidence_object_storage_ready_backends": json_i64(metrics, "evidence_object_storage_ready_backends"),
        "evidence_object_storage_config_errors": json_i64(metrics, "evidence_object_storage_config_errors"),
        "evidence_object_storage_refs": json_i64(metrics, "evidence_object_storage_refs"),
        "evidence_object_storage_drills_recorded": json_i64(metrics, "evidence_object_storage_drills_recorded"),
        "evidence_object_storage_drill_gaps": json_i64(metrics, "evidence_object_storage_drill_gaps"),
        "evidence_object_storage_object_gaps": json_i64(metrics, "evidence_object_storage_object_gaps"),
        "evidence_s3_runtime_objects": json_i64(metrics, "evidence_s3_runtime_objects"),
        "evidence_s3_upload_failures": json_i64(metrics, "evidence_s3_upload_failures"),
        "evidence_s3_restore_gaps": json_i64(metrics, "evidence_s3_restore_gaps"),
        "evidence_s3_runtime_errors": json_i64(metrics, "evidence_s3_runtime_errors"),
        "evidence_s3_orphan_reviews": json_i64(metrics, "evidence_s3_orphan_reviews"),
        "evidence_worker_runs_recorded": json_i64(metrics, "evidence_worker_runs_recorded"),
        "evidence_worker_missing_runs": json_i64(metrics, "evidence_worker_missing_runs"),
        "evidence_storage_drill_gaps": json_i64(metrics, "evidence_storage_drill_gaps"),
        "evidence_legal_hold_active": json_i64(metrics, "evidence_legal_hold_active"),
        "evidence_disposition_due": json_i64(metrics, "evidence_disposition_due"),
        "evidence_disposition_executed": json_i64(metrics, "evidence_disposition_executed"),
        "evidence_disposition_failed": json_i64(metrics, "evidence_disposition_failed"),
        "critical_suppliers": json_i64(supplier, "critical_suppliers"),
        "missing_supplier_evidence": json_i64(supplier, "missing_supplier_evidence"),
        "overdue_or_unreviewed_suppliers": json_i64(supplier, "overdue_or_unreviewed"),
        "critical_agent_findings": json_i64(agent_posture, "critical_findings"),
        "stale_or_open_agent_findings": json_i64(agent_posture, "open_findings"),
        "ai_systems_without_risk_links": json_i64(metrics, "ai_systems_without_risk_links"),
        "ai_systems_without_roadmap_links": json_i64(metrics, "ai_systems_without_roadmap_links"),
        "ai_systems_without_evidence": ai_governance["systems"]
            .as_array()
            .map(|systems| {
                systems
                    .iter()
                    .filter(|system| system["evidence_count"].as_i64().unwrap_or(0) == 0)
                    .count() as i64
            })
            .unwrap_or(0)
    });
    if let Some(object) = summary.as_object_mut() {
        for (key, value) in [
            (
                "agent_release_artifact_manifest_missing",
                json_i64(agent_posture, "release_artifact_manifest_missing"),
            ),
            (
                "agent_release_artifacts_without_checksum",
                json_i64(agent_posture, "release_artifacts_without_checksum"),
            ),
            (
                "unsigned_agent_release_artifacts",
                json_i64(agent_posture, "unsigned_release_artifacts"),
            ),
            (
                "agent_release_artifacts_missing_provenance",
                json_i64(agent_posture, "release_artifacts_missing_provenance"),
            ),
            (
                "agent_release_artifacts_unverified",
                json_i64(agent_posture, "release_artifacts_unverified"),
            ),
            (
                "agent_release_artifact_supply_chain_gaps",
                json_i64(agent_posture, "release_artifact_supply_chain_gaps"),
            ),
            (
                "agent_pki_provider_missing",
                if json_i64(agent_posture, "agent_pki_providers") == 0 {
                    1
                } else {
                    0
                },
            ),
            (
                "agent_pki_provider_not_configured",
                json_i64(agent_posture, "agent_pki_provider_not_configured"),
            ),
            (
                "pending_agent_csrs",
                json_i64(agent_posture, "pending_agent_csrs"),
            ),
            (
                "agents_without_certificate_status",
                json_i64(agent_posture, "agents_without_certificate_status"),
            ),
            (
                "expiring_agent_certificates",
                json_i64(agent_posture, "expiring_agent_certificates"),
            ),
            (
                "expired_agent_certificates",
                json_i64(agent_posture, "expired_agent_certificates"),
            ),
            (
                "mtls_binding_gaps",
                json_i64(agent_posture, "mtls_binding_gaps"),
            ),
            (
                "rotation_required_certificates",
                json_i64(agent_posture, "rotation_required_certificates"),
            ),
            (
                "revocation_requested_certificates",
                json_i64(agent_posture, "revocation_requested_certificates"),
            ),
            (
                "agent_pki_governance_gaps",
                json_i64(agent_posture, "agent_pki_governance_gaps"),
            ),
        ] {
            object.insert(key.to_string(), serde_json::json!(value));
        }
    }
    summary
}

fn review_gap_groups(template_type: &str, gap_summary: &Value) -> Value {
    let groups: &[ReviewGapGroupDefinition] = match template_type {
        "nis2_management_summary" => &[
            (
                "Incident- und Meldeentscheidungs-Gaps",
                &[
                    ("Nicht bewertete Incidents", "unassessed_incidents", true),
                    ("Offene Roadmap-Tasks", "open_roadmap_tasks", false),
                ],
            ),
            (
                "Technische und organisatorische Massnahmen",
                &[
                    ("Offene Control-Gaps", "open_control_gaps", true),
                    (
                        "Fehlende Control-Evidence",
                        "missing_control_evidence",
                        false,
                    ),
                    ("Kritische Agent-Findings", "critical_agent_findings", true),
                    (
                        "Agenten ohne Zertifikatsstatus",
                        "agents_without_certificate_status",
                        false,
                    ),
                    ("mTLS-Bindungs-Gaps", "mtls_binding_gaps", true),
                    (
                        "Ablaufende oder abgelaufene Agent-Zertifikate",
                        "expired_agent_certificates",
                        true,
                    ),
                    ("Offene CSR-Pruefungen", "pending_agent_csrs", false),
                    (
                        "Rotation oder Widerruf offen",
                        "agent_pki_governance_gaps",
                        false,
                    ),
                ],
            ),
            (
                "Evidence- und Nachweis-Gaps",
                &[
                    ("Offene Evidence Needs", "open_evidence_needs", false),
                    (
                        "Nicht gepruefte Evidence",
                        "evidence_integrity_not_checked",
                        false,
                    ),
                    (
                        "Evidence-Integritaetsabweichungen",
                        "evidence_integrity_mismatch",
                        true,
                    ),
                    (
                        "Fehlgeschlagene Dispositionen",
                        "evidence_disposition_failed",
                        true,
                    ),
                    (
                        "Keine Worker-Laeufe dokumentiert",
                        "evidence_worker_missing_runs",
                        false,
                    ),
                    (
                        "Agent-Artefaktmanifest fehlt",
                        "agent_release_artifact_manifest_missing",
                        false,
                    ),
                    (
                        "Unsignierte Agent-Artefakte",
                        "unsigned_agent_release_artifacts",
                        true,
                    ),
                    (
                        "Agent-Artefakte ohne Provenance",
                        "agent_release_artifacts_missing_provenance",
                        false,
                    ),
                ],
            ),
            (
                "Supplier- und Supply-Chain-Gaps",
                &[
                    ("Kritische Supplier", "critical_suppliers", true),
                    (
                        "Offene Supplier/Product-Security-Advisorys",
                        "open_supplier_product_security_advisories",
                        true,
                    ),
                    (
                        "Kritische Lieferantenabhaengigkeiten",
                        "supplier_product_security_critical_services",
                        true,
                    ),
                    (
                        "Offene Supplier/Product-Security-Massnahmen",
                        "supplier_product_security_open_actions",
                        false,
                    ),
                    (
                        "Fehlende Supplier-Evidence",
                        "missing_supplier_evidence",
                        false,
                    ),
                    (
                        "Fehlende Supplier/Product-Security-Evidence",
                        "supplier_product_security_missing_evidence",
                        false,
                    ),
                    (
                        "Fehlende Supplier/Product-Security-Owner",
                        "supplier_product_security_missing_owner",
                        false,
                    ),
                    (
                        "Agent-Release-Supply-Chain-Gaps",
                        "agent_release_artifact_supply_chain_gaps",
                        false,
                    ),
                    (
                        "Ueberfaellige oder nicht bewertete Supplier",
                        "overdue_or_unreviewed_suppliers",
                        false,
                    ),
                ],
            ),
        ],
        "dora_ict_risk_supplier_incident_summary" => &[
            (
                "ICT-Risk-Gaps",
                &[
                    ("Kritische offene Risiken", "critical_open_risks", true),
                    ("Offene Control-Gaps", "open_control_gaps", false),
                ],
            ),
            (
                "Incident-Gaps",
                &[
                    ("Nicht bewertete Incidents", "unassessed_incidents", true),
                    ("Offene Roadmap-Tasks", "open_roadmap_tasks", false),
                ],
            ),
            (
                "ICT-Third-Party-Gaps",
                &[
                    ("Kritische Supplier", "critical_suppliers", true),
                    (
                        "DORA-relevante Supplier/Product-Security-Datensaetze",
                        "supplier_product_security_dora_relevant",
                        false,
                    ),
                    (
                        "Kritische ICT-Dienstleister / Services",
                        "supplier_product_security_critical_services",
                        true,
                    ),
                    (
                        "Offene Supplier/Product-Security-Advisorys",
                        "open_supplier_product_security_advisories",
                        true,
                    ),
                    (
                        "Ueberfaellige oder nicht bewertete Supplier",
                        "overdue_or_unreviewed_suppliers",
                        false,
                    ),
                    (
                        "Fehlende Supplier-Evidence",
                        "missing_supplier_evidence",
                        false,
                    ),
                ],
            ),
            (
                "Exit-, Contract- und Review-Gaps",
                &[
                    (
                        "Ueberfaellige Supplier/Product-Security-Reviews",
                        "supplier_product_security_overdue_reviews",
                        false,
                    ),
                    (
                        "Ueberfaellige oder nicht bewertete Supplier",
                        "overdue_or_unreviewed_suppliers",
                        false,
                    ),
                    ("Offene Roadmap-Tasks", "open_roadmap_tasks", false),
                ],
            ),
            (
                "Evidence-, Integritaets- und Storage-Gaps",
                &[
                    ("Offene Evidence Needs", "open_evidence_needs", false),
                    (
                        "Evidence-Integritaetsabweichungen",
                        "evidence_integrity_mismatch",
                        true,
                    ),
                    (
                        "Offene Storage-/Restore-Pruefungen",
                        "evidence_storage_drill_gaps",
                        false,
                    ),
                    (
                        "Object-Storage-Konfigurationsfehler",
                        "evidence_object_storage_config_errors",
                        true,
                    ),
                    (
                        "Offene Object-Storage-Drills",
                        "evidence_object_storage_drill_gaps",
                        false,
                    ),
                    (
                        "Object-Storage-Objekt-/Hash-Gaps",
                        "evidence_object_storage_object_gaps",
                        true,
                    ),
                    (
                        "S3-Runtime-Upload-Fehler",
                        "evidence_s3_upload_failures",
                        true,
                    ),
                    (
                        "Offene S3-Restore-Pruefungen",
                        "evidence_s3_restore_gaps",
                        false,
                    ),
                    (
                        "S3-Runtime-/Endpoint-/Secret-Fehler",
                        "evidence_s3_runtime_errors",
                        true,
                    ),
                    ("S3-Orphan-Reviews", "evidence_s3_orphan_reviews", true),
                    (
                        "Fehlgeschlagene Dispositionen",
                        "evidence_disposition_failed",
                        true,
                    ),
                    ("Faellige Disposition", "evidence_disposition_due", false),
                    (
                        "Agent-Artefakte ohne verifizierte Provenance",
                        "agent_release_artifacts_missing_provenance",
                        false,
                    ),
                    ("mTLS-Bindungs-Gaps", "mtls_binding_gaps", true),
                    (
                        "Agent-Zertifikatsrotation offen",
                        "rotation_required_certificates",
                        false,
                    ),
                    (
                        "Agent-Zertifikatswiderruf angefordert",
                        "revocation_requested_certificates",
                        true,
                    ),
                ],
            ),
        ],
        "dsgvo_data_protection_review" => &[
            (
                "Datenschutz- und Rollen-Gaps",
                &[
                    ("Offene Control-Gaps", "open_control_gaps", false),
                    (
                        "AI-Systeme ohne Risikolink",
                        "ai_systems_without_risk_links",
                        true,
                    ),
                    (
                        "AI-Systeme ohne Evidence",
                        "ai_systems_without_evidence",
                        false,
                    ),
                ],
            ),
            (
                "Incident- und Data-Breach-Gaps",
                &[
                    ("Nicht bewertete Incidents", "unassessed_incidents", true),
                    ("Offene Roadmap-Tasks", "open_roadmap_tasks", false),
                ],
            ),
            (
                "Retention-, Legal-Hold- und Disposition-Gaps",
                &[
                    ("Aktiver Legal Hold", "evidence_legal_hold_active", false),
                    ("Faellige Disposition", "evidence_disposition_due", false),
                    (
                        "Fehlgeschlagene Dispositionen",
                        "evidence_disposition_failed",
                        true,
                    ),
                    (
                        "Evidence-Integritaetsabweichungen",
                        "evidence_integrity_mismatch",
                        true,
                    ),
                ],
            ),
            (
                "Supplier mit Datenbezug",
                &[
                    ("Kritische Supplier", "critical_suppliers", true),
                    (
                        "Supplier/Product Security mit Datenbezug",
                        "supplier_product_security_data_processing_relevant",
                        false,
                    ),
                    (
                        "Offene Supplier-Advisorys mit moeglichem Datenbezug",
                        "open_supplier_product_security_advisories",
                        true,
                    ),
                    (
                        "Fehlende Supplier-Evidence",
                        "missing_supplier_evidence",
                        false,
                    ),
                    (
                        "Fehlende Supplier/Product-Security-Evidence",
                        "supplier_product_security_missing_evidence",
                        false,
                    ),
                    (
                        "Unverifizierte Agent-Deployment-Artefakte",
                        "agent_release_artifacts_unverified",
                        false,
                    ),
                    (
                        "Unklare Agent-Zertifikatsbindung",
                        "agents_without_certificate_status",
                        false,
                    ),
                    ("mTLS-Bindungs-Gaps", "mtls_binding_gaps", false),
                    (
                        "Fehlende Owner oder Reviews",
                        "supplier_product_security_missing_owner",
                        false,
                    ),
                    (
                        "Ueberfaellige oder nicht bewertete Supplier",
                        "overdue_or_unreviewed_suppliers",
                        false,
                    ),
                ],
            ),
            (
                "Evidence- und Schutzklassen-Gaps",
                &[
                    ("Offene Evidence Needs", "open_evidence_needs", false),
                    (
                        "Fehlende Control-Evidence",
                        "missing_control_evidence",
                        false,
                    ),
                ],
            ),
        ],
        _ => &[
            (
                "Risk",
                &[("Kritische offene Risiken", "critical_open_risks", true)],
            ),
            (
                "Control",
                &[
                    ("Offene Control-Gaps", "open_control_gaps", true),
                    (
                        "Fehlende Control-Evidence",
                        "missing_control_evidence",
                        false,
                    ),
                ],
            ),
            (
                "Evidence",
                &[
                    ("Offene Evidence Needs", "open_evidence_needs", false),
                    (
                        "Evidence-Integritaetsabweichungen",
                        "evidence_integrity_mismatch",
                        true,
                    ),
                    (
                        "Keine Worker-Laeufe dokumentiert",
                        "evidence_worker_missing_runs",
                        false,
                    ),
                    (
                        "Agent-Artefaktmanifest fehlt",
                        "agent_release_artifact_manifest_missing",
                        false,
                    ),
                    ("Faellige Disposition", "evidence_disposition_due", false),
                    (
                        "Fehlgeschlagene Dispositionen",
                        "evidence_disposition_failed",
                        true,
                    ),
                ],
            ),
            (
                "Incident",
                &[("Nicht bewertete Incidents", "unassessed_incidents", true)],
            ),
            (
                "Supplier",
                &[
                    ("Kritische Supplier", "critical_suppliers", true),
                    (
                        "Fehlende Supplier-Evidence",
                        "missing_supplier_evidence",
                        false,
                    ),
                ],
            ),
            (
                "Supplier/Product Security",
                &[
                    (
                        "Offene Advisorys",
                        "open_supplier_product_security_advisories",
                        true,
                    ),
                    (
                        "Offene Massnahmen",
                        "supplier_product_security_open_actions",
                        false,
                    ),
                    (
                        "Fehlende Evidence",
                        "supplier_product_security_missing_evidence",
                        false,
                    ),
                    (
                        "Ueberfaellige Reviews",
                        "supplier_product_security_overdue_reviews",
                        false,
                    ),
                ],
            ),
            (
                "Product Security",
                &[
                    (
                        "Kritische offene Schwachstellen",
                        "critical_open_vulnerabilities",
                        true,
                    ),
                    (
                        "Offene CVE-Korrelationen",
                        "open_cve_correlation_reviews",
                        false,
                    ),
                ],
            ),
            (
                "AI Governance",
                &[
                    (
                        "AI-Systeme ohne Risikolink",
                        "ai_systems_without_risk_links",
                        true,
                    ),
                    (
                        "AI-Systeme ohne Roadmap-Link",
                        "ai_systems_without_roadmap_links",
                        false,
                    ),
                ],
            ),
            (
                "Roadmap",
                &[("Offene Roadmap-Tasks", "open_roadmap_tasks", false)],
            ),
            (
                "Agent / Zero Trust",
                &[
                    ("Kritische Agent-Findings", "critical_agent_findings", true),
                    (
                        "Offene Agent-Findings",
                        "stale_or_open_agent_findings",
                        false,
                    ),
                    (
                        "Agent-Artefakte ohne Pruefsumme",
                        "agent_release_artifacts_without_checksum",
                        true,
                    ),
                    (
                        "Unsignierte Agent-Artefakte",
                        "unsigned_agent_release_artifacts",
                        true,
                    ),
                    (
                        "Agent-Artefakte ohne Provenance",
                        "agent_release_artifacts_missing_provenance",
                        false,
                    ),
                    (
                        "Unverifizierte Agent-Artefakte",
                        "agent_release_artifacts_unverified",
                        false,
                    ),
                    (
                        "Agent-PKI-Provider fehlt",
                        "agent_pki_provider_missing",
                        false,
                    ),
                    (
                        "Agent-PKI-Provider nicht konfiguriert",
                        "agent_pki_provider_not_configured",
                        false,
                    ),
                    ("Offene Agent-CSR", "pending_agent_csrs", false),
                    (
                        "Agenten ohne Zertifikatsstatus",
                        "agents_without_certificate_status",
                        false,
                    ),
                    ("mTLS-Bindungs-Gaps", "mtls_binding_gaps", true),
                    (
                        "Rotation erforderlich",
                        "rotation_required_certificates",
                        false,
                    ),
                    (
                        "Widerruf angefordert",
                        "revocation_requested_certificates",
                        true,
                    ),
                ],
            ),
        ],
    };

    let groups = groups
        .iter()
        .map(|(name, items)| {
            let items_json = items
                .iter()
                .map(|(label, key, critical)| {
                    let count = json_i64(gap_summary, key);
                    serde_json::json!({
                        "label": label,
                        "key": key,
                        "count": count,
                        "critical": *critical,
                        "status": if count > 0 { "Offen" } else { "Keine offenen Luecken" }
                    })
                })
                .collect::<Vec<_>>();
            let open_count = items_json
                .iter()
                .filter_map(|item| item["count"].as_i64())
                .sum::<i64>();
            let critical_count = items_json
                .iter()
                .filter(|item| item["critical"].as_bool().unwrap_or(false))
                .filter_map(|item| item["count"].as_i64())
                .sum::<i64>();
            serde_json::json!({
                "name": name,
                "open_count": open_count,
                "critical_count": critical_count,
                "status": if open_count > 0 { "Offen" } else { "Keine offenen Luecken" },
                "items": items_json
            })
        })
        .collect::<Vec<_>>();
    Value::Array(groups)
}

fn review_owner_hints(
    metrics: &Value,
    incident_decisions: &Value,
    roadmap: &Value,
    product_security: &Value,
    supplier: &Value,
    ai_governance: &Value,
) -> Value {
    let roadmap_owners = unique_owner_values(roadmap, "owner_role");
    let areas = vec![
        owner_hint(
            "Risk / Control",
            if json_i64(metrics, "open_control_gaps") > 0
                || json_i64(metrics, "critical_open_risks") > 0
            {
                "Owner fuer Risiko-/Control-Luecken pruefen"
            } else {
                "Keine offenen kritischen Hinweise aus dem Snapshot"
            },
            Vec::new(),
        ),
        owner_hint(
            "Incident Response",
            if incident_decisions
                .as_array()
                .is_some_and(|items| !items.is_empty())
            {
                "Incident-Verantwortung im Incident-Modul pruefen"
            } else {
                "Keine offenen Incident-Entscheidungen im Snapshot"
            },
            Vec::new(),
        ),
        owner_hint(
            "Roadmap",
            "Vorhandene Roadmap-Owner-Rollen aus offenen Tasks",
            roadmap_owners,
        ),
        owner_hint(
            "Supplier",
            if json_i64(supplier, "supplier_count") > 0 {
                "Supplier Owner / Security Contact im Supplier-Review pruefen"
            } else {
                "Keine Supplier-Daten erfasst"
            },
            Vec::new(),
        ),
        owner_hint(
            "Product Security / PSIRT",
            if json_i64(product_security, "products") > 0
                || json_i64(product_security, "supplier_product_security_records") > 0
            {
                "PSIRT-, Supplier/Product-Security- und Remediation-Verantwortung pruefen"
            } else {
                "Keine Product-Security-Daten erfasst"
            },
            Vec::new(),
        ),
        owner_hint(
            "AI Governance",
            if json_i64(ai_governance, "system_count") > 0 {
                "AI-System-Owner im AI-Governance-Register pruefen"
            } else {
                "Keine AI-Governance-Systeme erfasst"
            },
            Vec::new(),
        ),
    ];
    serde_json::json!({
        "hinweis": "Es werden nur vorhandene Rollen-/Owner-Hinweise angezeigt; fehlende Verantwortliche werden nicht geraten.",
        "areas": areas
    })
}

fn owner_hint(area: &str, hint: &str, owners: Vec<String>) -> Value {
    serde_json::json!({
        "area": area,
        "hint": hint,
        "owners": if owners.is_empty() {
            serde_json::json!(["Nicht erfasst"])
        } else {
            serde_json::json!(owners)
        }
    })
}

fn unique_owner_values(value: &Value, key: &str) -> Vec<String> {
    let mut owners = Vec::new();
    if let Some(items) = value.as_array() {
        for item in items {
            let Some(owner) = item
                .get(key)
                .and_then(Value::as_str)
                .and_then(safe_owner_label)
            else {
                continue;
            };
            if !owners.iter().any(|existing| existing == &owner) {
                owners.push(owner);
            }
            if owners.len() >= 8 {
                break;
            }
        }
    }
    owners
}

fn safe_owner_label(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value == "-" {
        return None;
    }
    if value.contains('@') {
        return Some("Kontakt erfasst (nicht angezeigt)".to_string());
    }
    Some(value.chars().take(80).collect())
}

fn review_data_completeness_summary(source_counts: &Value) -> Value {
    let areas = [
        ("Risiken", "risks"),
        ("Controls", "controls"),
        ("Evidence", "evidence"),
        ("Evidence-Integritaet", "evidence_integrity"),
        ("Incidents", "incidents"),
        ("Roadmap-Tasks", "roadmap_tasks"),
        ("Supplier", "suppliers"),
        ("Supplier/Product Security", "supplier_product_security"),
        ("Agent-Artefakte", "agent_release_artifacts"),
        ("Agent-PKI", "agent_pki"),
        ("AI Governance", "ai_governance"),
    ]
    .iter()
    .map(|(label, no_data_key)| {
        let count_key = match *no_data_key {
            "evidence_integrity" => "evidence_integrity_items",
            "roadmap_tasks" => "roadmap_tasks",
            "ai_governance" => "ai_governance_systems",
            "controls" => "controls",
            "suppliers" => "suppliers",
            "supplier_product_security" => "supplier_product_security_records",
            "agent_pki" => "agent_pki_providers",
            key => key,
        };
        let count = json_i64(source_counts, count_key);
        let missing = source_counts["no_data_recorded"]
            .get(*no_data_key)
            .and_then(Value::as_bool)
            .unwrap_or(count == 0);
        serde_json::json!({
            "area": label,
            "count": count,
            "status": if missing { "Nicht erfasst" } else { "Erfasst" }
        })
    })
    .collect::<Vec<_>>();
    serde_json::json!({
        "summary": "Datenvollstaendigkeit wird aus vorhandenen Snapshot-Quellen abgeleitet.",
        "areas": areas
    })
}

fn regulatory_review_has_open_gaps(gap_summary: &Value) -> bool {
    [
        "critical_open_risks",
        "open_control_gaps",
        "missing_control_evidence",
        "open_evidence_needs",
        "unassessed_incidents",
        "open_roadmap_tasks",
        "critical_open_vulnerabilities",
        "open_cve_correlation_reviews",
        "invalid_product_security_imports",
        "open_supplier_product_security_advisories",
        "critical_supplier_product_security_advisories",
        "supplier_product_security_missing_evidence",
        "supplier_product_security_missing_owner",
        "supplier_product_security_open_actions",
        "supplier_product_security_overdue_reviews",
        "evidence_integrity_not_checked",
        "evidence_integrity_mismatch",
        "evidence_worker_missing_runs",
        "evidence_storage_drill_gaps",
        "evidence_object_storage_config_errors",
        "evidence_object_storage_drill_gaps",
        "evidence_object_storage_object_gaps",
        "evidence_s3_upload_failures",
        "evidence_s3_restore_gaps",
        "evidence_s3_runtime_errors",
        "evidence_s3_orphan_reviews",
        "evidence_legal_hold_active",
        "evidence_disposition_due",
        "evidence_disposition_failed",
        "critical_suppliers",
        "missing_supplier_evidence",
        "overdue_or_unreviewed_suppliers",
        "critical_agent_findings",
        "stale_or_open_agent_findings",
        "agent_pki_provider_missing",
        "agent_pki_provider_not_configured",
        "pending_agent_csrs",
        "agents_without_certificate_status",
        "expiring_agent_certificates",
        "expired_agent_certificates",
        "mtls_binding_gaps",
        "rotation_required_certificates",
        "revocation_requested_certificates",
        "agent_pki_governance_gaps",
        "ai_systems_without_risk_links",
        "ai_systems_without_roadmap_links",
        "ai_systems_without_evidence",
    ]
    .iter()
    .any(|key| json_i64(gap_summary, key) > 0)
}

fn regulatory_review_has_critical_gaps(gap_summary: &Value) -> bool {
    [
        "critical_open_risks",
        "critical_open_vulnerabilities",
        "critical_supplier_product_security_advisories",
        "supplier_product_security_critical_services",
        "evidence_integrity_mismatch",
        "evidence_disposition_failed",
        "critical_suppliers",
        "critical_agent_findings",
        "expired_agent_certificates",
        "mtls_binding_gaps",
        "revocation_requested_certificates",
        "ai_systems_without_risk_links",
    ]
    .iter()
    .any(|key| json_i64(gap_summary, key) > 0)
}

fn regulatory_review_filter_summary_json(filters: &RegulatoryReviewSnapshotFilters) -> Value {
    serde_json::json!({
        "pack_type": filters.template_type.as_deref().unwrap_or("alle Review-Pakete"),
        "status": filters.status.as_deref().unwrap_or("alle Status"),
        "period_start": filters.period_start.as_deref().unwrap_or("nicht begrenzt"),
        "period_end": filters.period_end.as_deref().unwrap_or("nicht begrenzt"),
        "has_open_gaps": filters.has_open_gaps,
        "has_critical_gaps": filters.has_critical_gaps,
        "limit": filters.limit
    })
}

fn management_review_decision_summary(
    template: ManagementReviewTemplateDefinition,
    sources: ManagementReviewDecisionSources<'_>,
) -> Value {
    let mut required_decisions = Vec::new();
    if json_i64(sources.metrics, "critical_open_risks") > 0 {
        required_decisions.push("Risk Treatment oder Akzeptanz fuer kritische offene Risiken");
    }
    if json_i64(sources.metrics, "open_control_gaps") > 0
        || json_i64(sources.metrics, "missing_control_evidence") > 0
    {
        required_decisions.push("Owner und Zieltermin fuer Control- und Evidence-Luecken");
    }
    if json_i64(sources.metrics, "unassessed_incidents") > 0 {
        required_decisions.push("Incident-Erheblichkeit und Meldebereitschaft bewerten");
    }
    if json_i64(sources.product_security, "open_cve_correlation_reviews") > 0
        || json_i64(sources.product_security, "critical_open_vulnerabilities") > 0
    {
        required_decisions.push("Product-Security-CVE-Review und Remediation-Prioritaet");
    }
    if json_i64(
        sources.product_security,
        "open_supplier_product_security_advisories",
    ) > 0
        || json_i64(
            sources.product_security,
            "supplier_product_security_open_actions",
        ) > 0
        || json_i64(
            sources.product_security,
            "supplier_product_security_overdue_reviews",
        ) > 0
    {
        required_decisions.push(
            "Supplier/Product-Security-Advisorys, Vertrags-/Exit-Plan-Status und offene Massnahmen pruefen",
        );
    }
    if json_i64(
        sources.product_security,
        "supplier_product_security_missing_evidence",
    ) > 0
        || json_i64(
            sources.product_security,
            "supplier_product_security_missing_owner",
        ) > 0
    {
        required_decisions
            .push("Supplier/Product-Security-Evidence und Owner / Verantwortliche nachziehen");
    }
    if json_i64(sources.metrics, "evidence_integrity_mismatch") > 0
        || json_i64(sources.metrics, "evidence_integrity_not_checked") > 0
        || json_i64(sources.metrics, "evidence_worker_missing_runs") > 0
        || json_i64(sources.metrics, "evidence_storage_drill_gaps") > 0
        || json_i64(sources.metrics, "evidence_object_storage_config_errors") > 0
        || json_i64(sources.metrics, "evidence_object_storage_drill_gaps") > 0
        || json_i64(sources.metrics, "evidence_object_storage_object_gaps") > 0
        || json_i64(sources.metrics, "evidence_s3_upload_failures") > 0
        || json_i64(sources.metrics, "evidence_s3_restore_gaps") > 0
        || json_i64(sources.metrics, "evidence_s3_runtime_errors") > 0
        || json_i64(sources.metrics, "evidence_s3_orphan_reviews") > 0
        || json_i64(sources.metrics, "evidence_disposition_due") > 0
        || json_i64(sources.metrics, "evidence_disposition_failed") > 0
    {
        required_decisions.push(
            "Evidence-Integritaet, Object-Storage-/Restore-Pruefung, Legal Hold oder kontrollierte Disposition nachziehen",
        );
    }
    if json_i64(sources.supplier, "missing_supplier_evidence") > 0
        || json_i64(sources.supplier, "overdue_or_unreviewed") > 0
    {
        required_decisions.push("Supplier-Review-Follow-up und Evidence-Ownership klaeren");
    }
    if json_i64(sources.agent_posture, "critical_findings") > 0 {
        required_decisions.push("Agent-Posture-Remediation und operative Eskalation");
    }
    if json_i64(sources.agent_posture, "agent_pki_governance_gaps") > 0 {
        required_decisions
            .push("Agent-PKI-/mTLS-Governance, CSR-Review, Rotation oder Widerruf nachziehen");
    }
    if json_i64(sources.metrics, "ai_systems_without_risk_links") > 0
        || sources.ai_governance["system_count"].as_i64().unwrap_or(0) > 0
            && json_i64(sources.metrics, "ai_systems_without_roadmap_links") > 0
    {
        required_decisions.push("AI-Governance-Risiko-, Evidence- und Roadmap-Verknuepfung");
    }
    let gap_summary = management_review_gap_summary(
        sources.metrics,
        sources.product_security,
        sources.supplier,
        sources.agent_posture,
        sources.ai_governance,
    );
    serde_json::json!({
        "template_actions": template.management_actions,
        "required_management_decisions": required_decisions,
        "review_hints": template.review_hints,
        "owner_hints": review_owner_hints(
            sources.metrics,
            sources.incident_decisions,
            sources.roadmap,
            sources.product_security,
            sources.supplier,
            sources.ai_governance,
        ),
        "gap_groups": review_gap_groups(template.template_type, &gap_summary),
        "data_completeness_summary": review_data_completeness_summary(sources.source_counts),
        "generated_note": "Hinweise werden aus vorhandenen tenantgebundenen ISCY-Daten abgeleitet und muessen von verantwortlichen Ownern bestaetigt werden."
    })
}

fn management_review_preview_from_snapshot(
    tenant_id: i64,
    template: ManagementReviewTemplateDefinition,
    period_start: Option<String>,
    period_end: Option<String>,
    snapshot: ManagementReviewSnapshot,
) -> ManagementReviewTemplatePreview {
    let owner_hints_json = snapshot
        .decision_summary_json
        .get("owner_hints")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let gap_groups_json = snapshot
        .decision_summary_json
        .get("gap_groups")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    let data_completeness_summary_json = snapshot
        .decision_summary_json
        .get("data_completeness_summary")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let filter_summary_json =
        regulatory_review_filter_summary_json(&RegulatoryReviewSnapshotFilters {
            template_type: Some(template.template_type.to_string()),
            period_start: period_start.clone(),
            period_end: period_end.clone(),
            ..RegulatoryReviewSnapshotFilters::default()
        });
    ManagementReviewTemplatePreview {
        tenant_id,
        template: template.detail(),
        period_start,
        period_end,
        generated_at: Utc::now().to_rfc3339(),
        title: review_title(None, template),
        executive_summary: review_executive_summary(None, &snapshot),
        metrics_json: snapshot.metrics_json,
        top_risks_json: snapshot.top_risks_json,
        control_gaps_json: snapshot.control_gaps_json,
        evidence_gaps_json: snapshot.evidence_gaps_json,
        incident_decisions_json: snapshot.incident_decisions_json,
        roadmap_json: snapshot.roadmap_json,
        product_security_json: snapshot.product_security_json,
        agent_posture_json: snapshot.agent_posture_json,
        ai_governance_json: snapshot.ai_governance_json,
        supplier_json: snapshot.supplier_json,
        source_counts_json: snapshot.source_counts_json,
        gap_summary_json: snapshot.gap_summary_json,
        decision_summary_json: snapshot.decision_summary_json,
        regulatory_context_json: snapshot.regulatory_context_json,
        owner_hints_json,
        gap_groups_json,
        filter_summary_json,
        data_completeness_summary_json,
    }
}

fn json_i64(value: &Value, key: &str) -> i64 {
    value.get(key).and_then(Value::as_i64).unwrap_or(0)
}

fn management_review_list_postgres_sql() -> &'static str {
    r#"
    SELECT
        id, tenant_id, title, period_start::text AS period_start, period_end::text AS period_end,
        template_type, template_version,
        status, generated_by_id, approved_by_id, approved_at::text AS approved_at,
        created_at::text AS created_at, updated_at::text AS updated_at
    FROM reports_managementreviewpackage
    WHERE tenant_id = $1
    ORDER BY created_at DESC, id DESC
    LIMIT $2
    "#
}

fn management_review_list_sqlite_sql() -> &'static str {
    r#"
    SELECT
        id, tenant_id, title, CAST(period_start AS TEXT) AS period_start,
        template_type, template_version,
        CAST(period_end AS TEXT) AS period_end, status, generated_by_id, approved_by_id,
        CAST(approved_at AS TEXT) AS approved_at, CAST(created_at AS TEXT) AS created_at,
        CAST(updated_at AS TEXT) AS updated_at
    FROM reports_managementreviewpackage
    WHERE tenant_id = ?
    ORDER BY created_at DESC, id DESC
    LIMIT ?
    "#
}

fn regulatory_review_pack_snapshot_list_postgres_sql() -> &'static str {
    r#"
    SELECT
        id, tenant_id, title, period_start::text AS period_start, period_end::text AS period_end,
        template_type, template_version,
        status, generated_by_id, approved_by_id, approved_at::text AS approved_at,
        created_at::text AS created_at, updated_at::text AS updated_at
    FROM reports_managementreviewpackage
    WHERE tenant_id = $1
      AND template_type IN (
        'generic_security_governance',
        'nis2_management_summary',
        'dora_ict_risk_supplier_incident_summary',
        'dsgvo_data_protection_review'
      )
    ORDER BY created_at DESC, id DESC
    LIMIT $2
    "#
}

fn regulatory_review_pack_snapshot_list_sqlite_sql() -> &'static str {
    r#"
    SELECT
        id, tenant_id, title, CAST(period_start AS TEXT) AS period_start,
        template_type, template_version,
        CAST(period_end AS TEXT) AS period_end, status, generated_by_id, approved_by_id,
        CAST(approved_at AS TEXT) AS approved_at, CAST(created_at AS TEXT) AS created_at,
        CAST(updated_at AS TEXT) AS updated_at
    FROM reports_managementreviewpackage
    WHERE tenant_id = ?
      AND template_type IN (
        'generic_security_governance',
        'nis2_management_summary',
        'dora_ict_risk_supplier_incident_summary',
        'dsgvo_data_protection_review'
      )
    ORDER BY created_at DESC, id DESC
    LIMIT ?
    "#
}

fn management_review_detail_postgres_sql() -> &'static str {
    r#"
    SELECT
        id, tenant_id, title, period_start::text AS period_start, period_end::text AS period_end,
        template_type, template_version,
        status, generated_by_id, approved_by_id, approved_at::text AS approved_at,
        executive_summary, decision_notes, next_actions,
        COALESCE(metrics_json::text, '{}') AS metrics_json_text,
        COALESCE(top_risks_json::text, '[]') AS top_risks_json_text,
        COALESCE(control_gaps_json::text, '[]') AS control_gaps_json_text,
        COALESCE(evidence_gaps_json::text, '[]') AS evidence_gaps_json_text,
        COALESCE(incident_decisions_json::text, '[]') AS incident_decisions_json_text,
        COALESCE(roadmap_json::text, '[]') AS roadmap_json_text,
        COALESCE(product_security_json::text, '{}') AS product_security_json_text,
        COALESCE(agent_posture_json::text, '{}') AS agent_posture_json_text,
        COALESCE(ai_governance_json::text, '{}') AS ai_governance_json_text,
        COALESCE(supplier_json::text, '{}') AS supplier_json_text,
        COALESCE(regulatory_context_json::text, '{}') AS regulatory_context_json_text,
        COALESCE(source_counts_json::text, '{}') AS source_counts_json_text,
        COALESCE(gap_summary_json::text, '{}') AS gap_summary_json_text,
        COALESCE(decision_summary_json::text, '{}') AS decision_summary_json_text,
        created_at::text AS created_at,
        updated_at::text AS updated_at
    FROM reports_managementreviewpackage
    WHERE tenant_id = $1 AND id = $2
    "#
}

fn management_review_detail_sqlite_sql() -> &'static str {
    r#"
    SELECT
        id, tenant_id, title, CAST(period_start AS TEXT) AS period_start,
        template_type, template_version,
        CAST(period_end AS TEXT) AS period_end, status, generated_by_id, approved_by_id,
        CAST(approved_at AS TEXT) AS approved_at, executive_summary, decision_notes, next_actions,
        COALESCE(CAST(metrics_json AS TEXT), '{}') AS metrics_json_text,
        COALESCE(CAST(top_risks_json AS TEXT), '[]') AS top_risks_json_text,
        COALESCE(CAST(control_gaps_json AS TEXT), '[]') AS control_gaps_json_text,
        COALESCE(CAST(evidence_gaps_json AS TEXT), '[]') AS evidence_gaps_json_text,
        COALESCE(CAST(incident_decisions_json AS TEXT), '[]') AS incident_decisions_json_text,
        COALESCE(CAST(roadmap_json AS TEXT), '[]') AS roadmap_json_text,
        COALESCE(CAST(product_security_json AS TEXT), '{}') AS product_security_json_text,
        COALESCE(CAST(agent_posture_json AS TEXT), '{}') AS agent_posture_json_text,
        COALESCE(CAST(ai_governance_json AS TEXT), '{}') AS ai_governance_json_text,
        COALESCE(CAST(supplier_json AS TEXT), '{}') AS supplier_json_text,
        COALESCE(CAST(regulatory_context_json AS TEXT), '{}') AS regulatory_context_json_text,
        COALESCE(CAST(source_counts_json AS TEXT), '{}') AS source_counts_json_text,
        COALESCE(CAST(gap_summary_json AS TEXT), '{}') AS gap_summary_json_text,
        COALESCE(CAST(decision_summary_json AS TEXT), '{}') AS decision_summary_json_text,
        CAST(created_at AS TEXT) AS created_at,
        CAST(updated_at AS TEXT) AS updated_at
    FROM reports_managementreviewpackage
    WHERE tenant_id = ? AND id = ?
    "#
}

fn control_gaps_postgres_sql() -> &'static str {
    r#"
    SELECT c.id, c.control_number::bigint AS control_number, c.code, c.group_name, c.title,
           COALESCE(ts.status, 'GAP') AS status,
           COALESCE(ts.evidence_status, 'MISSING') AS evidence_status,
           COALESCE(ts.maturity_score, 0)::bigint AS maturity_score
    FROM iscy_control_control c
    LEFT JOIN iscy_control_tenantstatus ts ON ts.control_id = c.id AND ts.tenant_id = $1
    WHERE c.is_active = TRUE
      AND (COALESCE(ts.status, 'GAP') IN ('GAP', 'PARTIAL')
           OR COALESCE(ts.evidence_status, 'MISSING') IN ('MISSING', 'PARTIAL'))
    ORDER BY c.control_number ASC
    LIMIT 10
    "#
}

fn control_gaps_sqlite_sql() -> &'static str {
    r#"
    SELECT c.id, c.control_number, c.code, c.group_name, c.title,
           COALESCE(ts.status, 'GAP') AS status,
           COALESCE(ts.evidence_status, 'MISSING') AS evidence_status,
           COALESCE(ts.maturity_score, 0) AS maturity_score
    FROM iscy_control_control c
    LEFT JOIN iscy_control_tenantstatus ts ON ts.control_id = c.id AND ts.tenant_id = ?
    WHERE c.is_active = 1
      AND (COALESCE(ts.status, 'GAP') IN ('GAP', 'PARTIAL')
           OR COALESCE(ts.evidence_status, 'MISSING') IN ('MISSING', 'PARTIAL'))
    ORDER BY c.control_number ASC
    LIMIT 10
    "#
}

fn evidence_gaps_postgres_sql() -> &'static str {
    r#"
    SELECT need.id, need.title, need.status, need.rationale,
           req.framework, req.code, req.title AS requirement_title,
           need.covered_count::bigint AS covered_count
    FROM evidence_requirementevidenceneed need
    JOIN requirements_app_requirement req ON req.id = need.requirement_id
    WHERE need.tenant_id = $1 AND need.status <> 'COVERED'
    ORDER BY need.updated_at DESC, need.id DESC
    LIMIT 10
    "#
}

fn evidence_gaps_sqlite_sql() -> &'static str {
    r#"
    SELECT need.id, need.title, need.status, need.rationale,
           req.framework, req.code, req.title AS requirement_title, need.covered_count
    FROM evidence_requirementevidenceneed need
    JOIN requirements_app_requirement req ON req.id = need.requirement_id
    WHERE need.tenant_id = ? AND need.status <> 'COVERED'
    ORDER BY need.updated_at DESC, need.id DESC
    LIMIT 10
    "#
}

fn incident_decisions_postgres_sql() -> &'static str {
    r#"
    SELECT id, title, severity, status, nis2_significance_status, nis2_reportable,
           COALESCE(nis2_significance_criteria, '') AS criteria,
           COALESCE(nis2_significance_justification, '') AS justification,
           COALESCE(review_state, '') AS review_state,
           updated_at::text AS updated_at
    FROM incidents_incident
    WHERE tenant_id = $1
      AND (status NOT IN ('RESOLVED', 'CLOSED') OR nis2_significance_status <> 'NOT_SIGNIFICANT')
    ORDER BY updated_at DESC, id DESC
    LIMIT 10
    "#
}

fn incident_decisions_sqlite_sql() -> &'static str {
    r#"
    SELECT id, title, severity, status, nis2_significance_status, nis2_reportable,
           COALESCE(nis2_significance_criteria, '') AS criteria,
           COALESCE(nis2_significance_justification, '') AS justification,
           COALESCE(review_state, '') AS review_state,
           CAST(updated_at AS TEXT) AS updated_at
    FROM incidents_incident
    WHERE tenant_id = ?
      AND (status NOT IN ('RESOLVED', 'CLOSED') OR nis2_significance_status <> 'NOT_SIGNIFICANT')
    ORDER BY updated_at DESC, id DESC
    LIMIT 10
    "#
}

fn roadmap_items_postgres_sql() -> &'static str {
    r#"
    SELECT task.id, task.title, task.priority, task.status, task.owner_role,
           COALESCE(task.due_date::text, '') AS due_date, phase.name AS phase_name, plan.title AS plan_title
    FROM roadmap_roadmaptask task
    JOIN roadmap_roadmapphase phase ON task.phase_id = phase.id
    JOIN roadmap_roadmapplan plan ON phase.plan_id = plan.id
    WHERE plan.tenant_id = $1 AND task.status <> 'DONE'
    ORDER BY CASE task.priority WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END,
             task.due_date ASC NULLS LAST, task.id DESC
    LIMIT 10
    "#
}

fn roadmap_items_sqlite_sql() -> &'static str {
    r#"
    SELECT task.id, task.title, task.priority, task.status, task.owner_role,
           COALESCE(CAST(task.due_date AS TEXT), '') AS due_date, phase.name AS phase_name,
           plan.title AS plan_title
    FROM roadmap_roadmaptask task
    JOIN roadmap_roadmapphase phase ON task.phase_id = phase.id
    JOIN roadmap_roadmapplan plan ON phase.plan_id = plan.id
    WHERE plan.tenant_id = ? AND task.status <> 'DONE'
    ORDER BY CASE task.priority WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END,
             task.due_date ASC, task.id DESC
    LIMIT 10
    "#
}

fn supplier_review_postgres_sql() -> &'static str {
    r#"
    SELECT
        supplier.id,
        supplier.name,
        supplier.criticality,
        supplier.review_status,
        supplier.approval_status,
        COALESCE(supplier.next_review_due_at::text, '') AS next_review_due_at,
        supplier.evidence_required,
        COALESCE(supplier.regulatory_scope, '') AS regulatory_scope,
        (SELECT COUNT(*)::bigint FROM supplier_evidence_link link
         WHERE link.tenant_id = supplier.tenant_id AND link.supplier_id = supplier.id) AS evidence_links,
        (SELECT COUNT(*)::bigint FROM supplier_subprocessor subprocessor
         WHERE subprocessor.tenant_id = supplier.tenant_id AND subprocessor.supplier_id = supplier.id) AS subprocessors,
        (SELECT COUNT(*)::bigint FROM supplier_risk_link link
         JOIN risks_risk risk ON risk.tenant_id = link.tenant_id AND risk.id = link.risk_id
         WHERE link.tenant_id = supplier.tenant_id
           AND link.supplier_id = supplier.id
           AND risk.status <> 'CLOSED') AS open_risk_links
    FROM organizations_supplier supplier
    WHERE supplier.tenant_id = $1
    ORDER BY CASE UPPER(supplier.criticality)
             WHEN 'CRITICAL' THEN 1 WHEN 'VERY_HIGH' THEN 2 WHEN 'HIGH' THEN 3
             WHEN 'MEDIUM' THEN 4 ELSE 5 END,
             supplier.next_review_due_at ASC NULLS FIRST,
             supplier.id DESC
    LIMIT 10
    "#
}

fn supplier_review_sqlite_sql() -> &'static str {
    r#"
    SELECT
        supplier.id,
        supplier.name,
        supplier.criticality,
        supplier.review_status,
        supplier.approval_status,
        COALESCE(CAST(supplier.next_review_due_at AS TEXT), '') AS next_review_due_at,
        supplier.evidence_required,
        COALESCE(supplier.regulatory_scope, '') AS regulatory_scope,
        (SELECT COUNT(*) FROM supplier_evidence_link link
         WHERE link.tenant_id = supplier.tenant_id AND link.supplier_id = supplier.id) AS evidence_links,
        (SELECT COUNT(*) FROM supplier_subprocessor subprocessor
         WHERE subprocessor.tenant_id = supplier.tenant_id AND subprocessor.supplier_id = supplier.id) AS subprocessors,
        (SELECT COUNT(*) FROM supplier_risk_link link
         JOIN risks_risk risk ON risk.tenant_id = link.tenant_id AND risk.id = link.risk_id
         WHERE link.tenant_id = supplier.tenant_id
           AND link.supplier_id = supplier.id
           AND risk.status <> 'CLOSED') AS open_risk_links
    FROM organizations_supplier supplier
    WHERE supplier.tenant_id = ?
    ORDER BY CASE UPPER(supplier.criticality)
             WHEN 'CRITICAL' THEN 1 WHEN 'VERY_HIGH' THEN 2 WHEN 'HIGH' THEN 3
             WHEN 'MEDIUM' THEN 4 ELSE 5 END,
             supplier.next_review_due_at ASC,
             supplier.id DESC
    LIMIT 10
    "#
}

fn regulatory_context_postgres_sql() -> &'static str {
    r#"
    SELECT
        name,
        country,
        sector,
        nis2_relevant,
        kritis_relevant,
        dora_relevant,
        dora_financial_entity,
        dora_ict_third_party_provider,
        develops_digital_products,
        processes_personal_data,
        uses_ai_systems,
        ai_act_profile,
        ai_act_high_risk,
        tisax_relevant,
        iso27001_target,
        product_security_scope
    FROM organizations_tenant
    WHERE id = $1
    "#
}

fn regulatory_context_sqlite_sql() -> &'static str {
    r#"
    SELECT
        name,
        country,
        sector,
        nis2_relevant,
        kritis_relevant,
        dora_relevant,
        dora_financial_entity,
        dora_ict_third_party_provider,
        develops_digital_products,
        processes_personal_data,
        uses_ai_systems,
        ai_act_profile,
        ai_act_high_risk,
        tisax_relevant,
        iso27001_target,
        product_security_scope
    FROM organizations_tenant
    WHERE id = ?
    "#
}

fn risk_pg_rows_to_json(rows: Vec<PgRow>) -> anyhow::Result<Value> {
    rows.into_iter()
        .map(|row| {
            let id = row.try_get::<i64, _>("id")?;
            Ok(serde_json::json!({
                "id": id,
                "entity_type": "risk",
                "href": format!("/api/v1/risks/{id}"),
                "title": row.try_get::<String, _>("title")?,
                "status": row.try_get::<String, _>("status")?,
                "impact": row.try_get::<i64, _>("impact")?,
                "likelihood": row.try_get::<i64, _>("likelihood")?,
                "score": row.try_get::<i64, _>("score")?,
                "treatment_strategy": row.try_get::<String, _>("treatment_strategy")?,
                "treatment_plan": row.try_get::<String, _>("treatment_plan")?,
                "review_date": row.try_get::<String, _>("review_date")?
            }))
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map(Value::Array)
        .map_err(Into::into)
}

fn risk_sqlite_rows_to_json(rows: Vec<SqliteRow>) -> anyhow::Result<Value> {
    rows.into_iter()
        .map(|row| {
            let id = row.try_get::<i64, _>("id")?;
            Ok(serde_json::json!({
                "id": id,
                "entity_type": "risk",
                "href": format!("/api/v1/risks/{id}"),
                "title": row.try_get::<String, _>("title")?,
                "status": row.try_get::<String, _>("status")?,
                "impact": row.try_get::<i64, _>("impact")?,
                "likelihood": row.try_get::<i64, _>("likelihood")?,
                "score": row.try_get::<i64, _>("score")?,
                "treatment_strategy": row.try_get::<String, _>("treatment_strategy")?,
                "treatment_plan": row.try_get::<String, _>("treatment_plan")?,
                "review_date": row.try_get::<String, _>("review_date")?
            }))
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map(Value::Array)
        .map_err(Into::into)
}

fn control_pg_rows_to_json(rows: Vec<PgRow>) -> anyhow::Result<Value> {
    rows.into_iter()
        .map(|row| {
            let id = row.try_get::<i64, _>("id")?;
            Ok(serde_json::json!({
                "id": id,
                "entity_type": "control",
                "href": "/controls/",
                "control_number": row.try_get::<i64, _>("control_number")?,
                "code": row.try_get::<String, _>("code")?,
                "group_name": row.try_get::<String, _>("group_name")?,
                "title": row.try_get::<String, _>("title")?,
                "status": row.try_get::<String, _>("status")?,
                "evidence_status": row.try_get::<String, _>("evidence_status")?,
                "maturity_score": row.try_get::<i64, _>("maturity_score")?
            }))
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map(Value::Array)
        .map_err(Into::into)
}

fn control_sqlite_rows_to_json(rows: Vec<SqliteRow>) -> anyhow::Result<Value> {
    rows.into_iter()
        .map(|row| {
            let id = row.try_get::<i64, _>("id")?;
            Ok(serde_json::json!({
                "id": id,
                "entity_type": "control",
                "href": "/controls/",
                "control_number": row.try_get::<i64, _>("control_number")?,
                "code": row.try_get::<String, _>("code")?,
                "group_name": row.try_get::<String, _>("group_name")?,
                "title": row.try_get::<String, _>("title")?,
                "status": row.try_get::<String, _>("status")?,
                "evidence_status": row.try_get::<String, _>("evidence_status")?,
                "maturity_score": row.try_get::<i64, _>("maturity_score")?
            }))
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map(Value::Array)
        .map_err(Into::into)
}

fn evidence_gap_pg_rows_to_json(rows: Vec<PgRow>) -> anyhow::Result<Value> {
    rows.into_iter()
        .map(|row| {
            let id = row.try_get::<i64, _>("id")?;
            Ok(serde_json::json!({
                "id": id,
                "entity_type": "evidence_need",
                "href": "/evidence/",
                "title": row.try_get::<String, _>("title")?,
                "status": row.try_get::<String, _>("status")?,
                "framework": row.try_get::<String, _>("framework")?,
                "requirement_code": row.try_get::<String, _>("code")?,
                "requirement_title": row.try_get::<String, _>("requirement_title")?,
                "covered_count": row.try_get::<i64, _>("covered_count")?,
                "rationale": row.try_get::<String, _>("rationale")?
            }))
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map(Value::Array)
        .map_err(Into::into)
}

fn evidence_gap_sqlite_rows_to_json(rows: Vec<SqliteRow>) -> anyhow::Result<Value> {
    rows.into_iter()
        .map(|row| {
            let id = row.try_get::<i64, _>("id")?;
            Ok(serde_json::json!({
                "id": id,
                "entity_type": "evidence_need",
                "href": "/evidence/",
                "title": row.try_get::<String, _>("title")?,
                "status": row.try_get::<String, _>("status")?,
                "framework": row.try_get::<String, _>("framework")?,
                "requirement_code": row.try_get::<String, _>("code")?,
                "requirement_title": row.try_get::<String, _>("requirement_title")?,
                "covered_count": row.try_get::<i64, _>("covered_count")?,
                "rationale": row.try_get::<String, _>("rationale")?
            }))
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map(Value::Array)
        .map_err(Into::into)
}

fn incident_pg_rows_to_json(rows: Vec<PgRow>) -> anyhow::Result<Value> {
    rows.into_iter()
        .map(|row| {
            let id = row.try_get::<i64, _>("id")?;
            Ok(serde_json::json!({
                "id": id,
                "entity_type": "incident",
                "href": format!("/incidents/{id}"),
                "title": row.try_get::<String, _>("title")?,
                "severity": row.try_get::<String, _>("severity")?,
                "status": row.try_get::<String, _>("status")?,
                "nis2_significance_status": row.try_get::<String, _>("nis2_significance_status")?,
                "nis2_reportable": row.try_get::<bool, _>("nis2_reportable")?,
                "criteria": row.try_get::<String, _>("criteria")?,
                "justification": row.try_get::<String, _>("justification")?,
                "review_state": row.try_get::<String, _>("review_state")?,
                "updated_at": row.try_get::<String, _>("updated_at")?
            }))
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map(Value::Array)
        .map_err(Into::into)
}

fn incident_sqlite_rows_to_json(rows: Vec<SqliteRow>) -> anyhow::Result<Value> {
    rows.into_iter()
        .map(|row| {
            let id = row.try_get::<i64, _>("id")?;
            Ok(serde_json::json!({
                "id": id,
                "entity_type": "incident",
                "href": format!("/incidents/{id}"),
                "title": row.try_get::<String, _>("title")?,
                "severity": row.try_get::<String, _>("severity")?,
                "status": row.try_get::<String, _>("status")?,
                "nis2_significance_status": row.try_get::<String, _>("nis2_significance_status")?,
                "nis2_reportable": row.try_get::<bool, _>("nis2_reportable")?,
                "criteria": row.try_get::<String, _>("criteria")?,
                "justification": row.try_get::<String, _>("justification")?,
                "review_state": row.try_get::<String, _>("review_state")?,
                "updated_at": row.try_get::<String, _>("updated_at")?
            }))
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map(Value::Array)
        .map_err(Into::into)
}

fn roadmap_pg_rows_to_json(rows: Vec<PgRow>) -> anyhow::Result<Value> {
    rows.into_iter()
        .map(|row| {
            let id = row.try_get::<i64, _>("id")?;
            Ok(serde_json::json!({
                "id": id,
                "entity_type": "roadmap_task",
                "href": "/roadmap/",
                "title": row.try_get::<String, _>("title")?,
                "priority": row.try_get::<String, _>("priority")?,
                "status": row.try_get::<String, _>("status")?,
                "owner_role": row.try_get::<String, _>("owner_role")?,
                "due_date": row.try_get::<String, _>("due_date")?,
                "phase_name": row.try_get::<String, _>("phase_name")?,
                "plan_title": row.try_get::<String, _>("plan_title")?
            }))
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map(Value::Array)
        .map_err(Into::into)
}

fn roadmap_sqlite_rows_to_json(rows: Vec<SqliteRow>) -> anyhow::Result<Value> {
    rows.into_iter()
        .map(|row| {
            let id = row.try_get::<i64, _>("id")?;
            Ok(serde_json::json!({
                "id": id,
                "entity_type": "roadmap_task",
                "href": "/roadmap/",
                "title": row.try_get::<String, _>("title")?,
                "priority": row.try_get::<String, _>("priority")?,
                "status": row.try_get::<String, _>("status")?,
                "owner_role": row.try_get::<String, _>("owner_role")?,
                "due_date": row.try_get::<String, _>("due_date")?,
                "phase_name": row.try_get::<String, _>("phase_name")?,
                "plan_title": row.try_get::<String, _>("plan_title")?
            }))
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map(Value::Array)
        .map_err(Into::into)
}

fn management_review_summary_from_pg_row(
    row: PgRow,
) -> Result<ManagementReviewPackageSummary, sqlx::Error> {
    let status: String = row.try_get("status")?;
    let template_type: String = row.try_get("template_type")?;
    Ok(ManagementReviewPackageSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        title: row.try_get("title")?,
        template_name: management_review_template_name(&template_type),
        template_version: row.try_get("template_version")?,
        template_type,
        period_start: row.try_get("period_start")?,
        period_end: row.try_get("period_end")?,
        status_label: management_review_status_label(&status).to_string(),
        status,
        generated_by_id: row.try_get("generated_by_id")?,
        approved_by_id: row.try_get("approved_by_id")?,
        approved_at: row.try_get("approved_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn management_review_summary_from_sqlite_row(
    row: SqliteRow,
) -> Result<ManagementReviewPackageSummary, sqlx::Error> {
    let status: String = row.try_get("status")?;
    let template_type: String = row.try_get("template_type")?;
    Ok(ManagementReviewPackageSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        title: row.try_get("title")?,
        template_name: management_review_template_name(&template_type),
        template_version: row.try_get("template_version")?,
        template_type,
        period_start: row.try_get("period_start")?,
        period_end: row.try_get("period_end")?,
        status_label: management_review_status_label(&status).to_string(),
        status,
        generated_by_id: row.try_get("generated_by_id")?,
        approved_by_id: row.try_get("approved_by_id")?,
        approved_at: row.try_get("approved_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn management_review_detail_from_pg_row(
    row: PgRow,
) -> Result<ManagementReviewPackageDetail, sqlx::Error> {
    let status: String = row.try_get("status")?;
    let template_type: String = row.try_get("template_type")?;
    Ok(ManagementReviewPackageDetail {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        title: row.try_get("title")?,
        template_name: management_review_template_name(&template_type),
        template_version: row.try_get("template_version")?,
        template_type,
        period_start: row.try_get("period_start")?,
        period_end: row.try_get("period_end")?,
        status_label: management_review_status_label(&status).to_string(),
        status,
        generated_by_id: row.try_get("generated_by_id")?,
        approved_by_id: row.try_get("approved_by_id")?,
        approved_at: row.try_get("approved_at")?,
        executive_summary: row.try_get("executive_summary")?,
        decision_notes: row.try_get("decision_notes")?,
        next_actions: row.try_get("next_actions")?,
        metrics_json: parse_json_object(row.try_get("metrics_json_text")?),
        top_risks_json: parse_json_array(row.try_get("top_risks_json_text")?),
        control_gaps_json: parse_json_array(row.try_get("control_gaps_json_text")?),
        evidence_gaps_json: parse_json_array(row.try_get("evidence_gaps_json_text")?),
        incident_decisions_json: parse_json_array(row.try_get("incident_decisions_json_text")?),
        roadmap_json: parse_json_array(row.try_get("roadmap_json_text")?),
        product_security_json: parse_json_object(row.try_get("product_security_json_text")?),
        agent_posture_json: parse_json_object(row.try_get("agent_posture_json_text")?),
        ai_governance_json: parse_json_object(row.try_get("ai_governance_json_text")?),
        supplier_json: parse_json_object(row.try_get("supplier_json_text")?),
        regulatory_context_json: parse_json_object(row.try_get("regulatory_context_json_text")?),
        source_counts_json: parse_json_object(row.try_get("source_counts_json_text")?),
        gap_summary_json: parse_json_object(row.try_get("gap_summary_json_text")?),
        decision_summary_json: parse_json_object(row.try_get("decision_summary_json_text")?),
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn management_review_detail_from_sqlite_row(
    row: SqliteRow,
) -> Result<ManagementReviewPackageDetail, sqlx::Error> {
    let status: String = row.try_get("status")?;
    let template_type: String = row.try_get("template_type")?;
    Ok(ManagementReviewPackageDetail {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        title: row.try_get("title")?,
        template_name: management_review_template_name(&template_type),
        template_version: row.try_get("template_version")?,
        template_type,
        period_start: row.try_get("period_start")?,
        period_end: row.try_get("period_end")?,
        status_label: management_review_status_label(&status).to_string(),
        status,
        generated_by_id: row.try_get("generated_by_id")?,
        approved_by_id: row.try_get("approved_by_id")?,
        approved_at: row.try_get("approved_at")?,
        executive_summary: row.try_get("executive_summary")?,
        decision_notes: row.try_get("decision_notes")?,
        next_actions: row.try_get("next_actions")?,
        metrics_json: parse_json_object(row.try_get("metrics_json_text")?),
        top_risks_json: parse_json_array(row.try_get("top_risks_json_text")?),
        control_gaps_json: parse_json_array(row.try_get("control_gaps_json_text")?),
        evidence_gaps_json: parse_json_array(row.try_get("evidence_gaps_json_text")?),
        incident_decisions_json: parse_json_array(row.try_get("incident_decisions_json_text")?),
        roadmap_json: parse_json_array(row.try_get("roadmap_json_text")?),
        product_security_json: parse_json_object(row.try_get("product_security_json_text")?),
        agent_posture_json: parse_json_object(row.try_get("agent_posture_json_text")?),
        ai_governance_json: parse_json_object(row.try_get("ai_governance_json_text")?),
        supplier_json: parse_json_object(row.try_get("supplier_json_text")?),
        regulatory_context_json: parse_json_object(row.try_get("regulatory_context_json_text")?),
        source_counts_json: parse_json_object(row.try_get("source_counts_json_text")?),
        gap_summary_json: parse_json_object(row.try_get("gap_summary_json_text")?),
        decision_summary_json: parse_json_object(row.try_get("decision_summary_json_text")?),
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn management_review_template_name(template_type: &str) -> String {
    resolve_management_review_template(template_type)
        .map(|template| template.name.to_string())
        .unwrap_or_else(|_| template_type.to_string())
}

fn review_title(title: Option<String>, template: ManagementReviewTemplateDefinition) -> String {
    clean_text(title, 255)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("{} {}", template.name, Utc::now().format("%Y-%m-%d")))
}

fn review_executive_summary(
    summary: Option<String>,
    snapshot: &ManagementReviewSnapshot,
) -> String {
    if let Some(summary) = clean_text(summary, 4000).filter(|value| !value.is_empty()) {
        return summary;
    }
    let open_risks = snapshot.metrics_json["open_risks"].as_i64().unwrap_or(0);
    let open_tasks = snapshot.metrics_json["open_roadmap_tasks"]
        .as_i64()
        .unwrap_or(0);
    let control_gaps = snapshot.metrics_json["open_control_gaps"]
        .as_i64()
        .unwrap_or(0);
    let evidence_gaps = snapshot.metrics_json["open_evidence_needs"]
        .as_i64()
        .unwrap_or(0);
    let supplier_gaps = snapshot.supplier_json["missing_supplier_evidence"]
        .as_i64()
        .unwrap_or(0);
    let cve_reviews = snapshot.product_security_json["open_cve_correlation_reviews"]
        .as_i64()
        .unwrap_or(0);
    let ai_systems = snapshot.ai_governance_json["system_count"]
        .as_i64()
        .unwrap_or(0);
    format!(
        "Automatisch erzeugtes Management-Review-Paket: {open_risks} offene Risiken, {control_gaps} offene ISCY-27-Control-Gaps, {evidence_gaps} offene Evidence-Luecken, {supplier_gaps} Supplier-Nachweisluecken, {cve_reviews} offene CVE-Reviews, {ai_systems} AI-Governance-Systeme und {open_tasks} offene Roadmap-Tasks sind fuer die Review-Entscheidung zusammengefasst. Diese Zusammenfassung unterstuetzt Governance-Reviews und ersetzt keine Rechtsberatung, Zertifizierung oder formale Meldung."
    )
}

fn clean_optional_text(value: Option<String>) -> Option<String> {
    clean_text(value, 255).filter(|value| !value.is_empty())
}

fn management_review_date(value: Option<String>, label: &str) -> anyhow::Result<Option<NaiveDate>> {
    let Some(value) = clean_optional_text(value) else {
        return Ok(None);
    };
    NaiveDate::parse_from_str(&value, "%Y-%m-%d")
        .map(Some)
        .with_context(|| format!("{label} muss YYYY-MM-DD entsprechen"))
}

fn clean_text(value: Option<String>, max_len: usize) -> Option<String> {
    value.map(|value| value.trim().chars().take(max_len).collect::<String>())
}

fn normalize_management_review_status(value: &str) -> anyhow::Result<String> {
    let normalized = value.trim().to_ascii_uppercase().replace('-', "_");
    match normalized.as_str() {
        "DRAFT" | "IN_REVIEW" | "APPROVED" => Ok(normalized),
        _ => bail!("Nicht unterstuetzter Management-Review-Status: {value}"),
    }
}

fn management_review_status_label(status: &str) -> &'static str {
    match status {
        "APPROVED" => "Freigegeben",
        "IN_REVIEW" => "In Review",
        _ => "Entwurf",
    }
}

fn parse_json_object(raw: String) -> Value {
    serde_json::from_str(&raw).unwrap_or_else(|_| serde_json::json!({}))
}

fn parse_json_array(raw: String) -> Value {
    serde_json::from_str(&raw).unwrap_or_else(|_| serde_json::json!([]))
}
