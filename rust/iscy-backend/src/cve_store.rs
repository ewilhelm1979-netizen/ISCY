use std::str::FromStr;

use anyhow::{bail, Context};
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::Serialize;
use serde_json::{json, Value};
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
