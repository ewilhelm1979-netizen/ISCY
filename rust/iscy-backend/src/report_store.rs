use anyhow::{bail, Context};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Row,
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
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManagementReviewGenerateRequest {
    pub title: Option<String>,
    pub period_start: Option<String>,
    pub period_end: Option<String>,
    pub executive_summary: Option<String>,
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

async fn generate_management_review_postgres(
    pool: &PgPool,
    tenant_id: i64,
    user_id: i64,
    request: ManagementReviewGenerateRequest,
) -> anyhow::Result<ManagementReviewPackageDetail> {
    let snapshot = build_management_review_snapshot_postgres(pool, tenant_id).await?;
    let title = review_title(request.title);
    let executive_summary = review_executive_summary(request.executive_summary, &snapshot);
    let id: i64 = sqlx::query_scalar(
        r#"
        INSERT INTO reports_managementreviewpackage (
            tenant_id, title, period_start, period_end, status, generated_by_id,
            executive_summary, decision_notes, next_actions, metrics_json, top_risks_json,
            control_gaps_json, evidence_gaps_json, incident_decisions_json, roadmap_json,
            product_security_json, agent_posture_json, created_at, updated_at
        )
        VALUES (
            $1, $2, $3, $4, 'DRAFT', $5,
            $6, '', '', $7, $8,
            $9, $10, $11, $12,
            $13, $14, NOW()::text, NOW()::text
        )
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(&title)
    .bind(clean_optional_text(request.period_start))
    .bind(clean_optional_text(request.period_end))
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
    .fetch_one(pool)
    .await
    .context("PostgreSQL-Management-Review konnte nicht erzeugt werden")?;
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
    let snapshot = build_management_review_snapshot_sqlite(pool, tenant_id).await?;
    let title = review_title(request.title);
    let executive_summary = review_executive_summary(request.executive_summary, &snapshot);
    sqlx::query(
        r#"
        INSERT INTO reports_managementreviewpackage (
            tenant_id, title, period_start, period_end, status, generated_by_id,
            executive_summary, decision_notes, next_actions, metrics_json, top_risks_json,
            control_gaps_json, evidence_gaps_json, incident_decisions_json, roadmap_json,
            product_security_json, agent_posture_json, created_at, updated_at
        )
        VALUES (
            ?, ?, ?, ?, 'DRAFT', ?,
            ?, '', '', ?, ?,
            ?, ?, ?, ?,
            ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
        )
        "#,
    )
    .bind(tenant_id)
    .bind(&title)
    .bind(clean_optional_text(request.period_start))
    .bind(clean_optional_text(request.period_end))
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
    .execute(pool)
    .await
    .context("SQLite-Management-Review konnte nicht erzeugt werden")?;
    let id: i64 = sqlx::query_scalar("SELECT last_insert_rowid()")
        .fetch_one(pool)
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
}

async fn build_management_review_snapshot_postgres(
    pool: &PgPool,
    tenant_id: i64,
) -> anyhow::Result<ManagementReviewSnapshot> {
    let top_risks_json = top_risks_postgres(pool, tenant_id).await?;
    let control_gaps_json = control_gaps_postgres(pool, tenant_id).await?;
    let evidence_gaps_json = evidence_gaps_postgres(pool, tenant_id).await?;
    let incident_decisions_json = incident_decisions_postgres(pool, tenant_id).await?;
    let roadmap_json = roadmap_items_postgres(pool, tenant_id).await?;
    let product_security_json = product_security_postgres(pool, tenant_id).await?;
    let agent_posture_json = agent_posture_postgres(pool, tenant_id).await?;
    let metrics_json = management_review_metrics_postgres(
        pool,
        tenant_id,
        top_risks_json.as_array().map_or(0, Vec::len) as i64,
        control_gaps_json.as_array().map_or(0, Vec::len) as i64,
        evidence_gaps_json.as_array().map_or(0, Vec::len) as i64,
        incident_decisions_json.as_array().map_or(0, Vec::len) as i64,
        roadmap_json.as_array().map_or(0, Vec::len) as i64,
    )
    .await?;
    Ok(ManagementReviewSnapshot {
        metrics_json,
        top_risks_json,
        control_gaps_json,
        evidence_gaps_json,
        incident_decisions_json,
        roadmap_json,
        product_security_json,
        agent_posture_json,
    })
}

async fn build_management_review_snapshot_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
) -> anyhow::Result<ManagementReviewSnapshot> {
    let top_risks_json = top_risks_sqlite(pool, tenant_id).await?;
    let control_gaps_json = control_gaps_sqlite(pool, tenant_id).await?;
    let evidence_gaps_json = evidence_gaps_sqlite(pool, tenant_id).await?;
    let incident_decisions_json = incident_decisions_sqlite(pool, tenant_id).await?;
    let roadmap_json = roadmap_items_sqlite(pool, tenant_id).await?;
    let product_security_json = product_security_sqlite(pool, tenant_id).await?;
    let agent_posture_json = agent_posture_sqlite(pool, tenant_id).await?;
    let metrics_json = management_review_metrics_sqlite(
        pool,
        tenant_id,
        top_risks_json.as_array().map_or(0, Vec::len) as i64,
        control_gaps_json.as_array().map_or(0, Vec::len) as i64,
        evidence_gaps_json.as_array().map_or(0, Vec::len) as i64,
        incident_decisions_json.as_array().map_or(0, Vec::len) as i64,
        roadmap_json.as_array().map_or(0, Vec::len) as i64,
    )
    .await?;
    Ok(ManagementReviewSnapshot {
        metrics_json,
        top_risks_json,
        control_gaps_json,
        evidence_gaps_json,
        incident_decisions_json,
        roadmap_json,
        product_security_json,
        agent_posture_json,
    })
}

async fn management_review_metrics_postgres(
    pool: &PgPool,
    tenant_id: i64,
    top_risk_items: i64,
    control_gap_items: i64,
    evidence_gap_items: i64,
    incident_items: i64,
    roadmap_items: i64,
) -> anyhow::Result<Value> {
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
        "snapshot_items": {
            "top_risks": top_risk_items,
            "control_gaps": control_gap_items,
            "evidence_gaps": evidence_gap_items,
            "incidents": incident_items,
            "roadmap": roadmap_items
        }
    }))
}

async fn management_review_metrics_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    top_risk_items: i64,
    control_gap_items: i64,
    evidence_gap_items: i64,
    incident_items: i64,
    roadmap_items: i64,
) -> anyhow::Result<Value> {
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
        "snapshot_items": {
            "top_risks": top_risk_items,
            "control_gaps": control_gap_items,
            "evidence_gaps": evidence_gap_items,
            "incidents": incident_items,
            "roadmap": roadmap_items
        }
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
        "invalid_imports": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM product_security_importartifact WHERE tenant_id = $1 AND validation_status NOT IN ('VALID', 'VALIDATED')", tenant_id).await?
    }))
}

async fn product_security_sqlite(pool: &SqlitePool, tenant_id: i64) -> anyhow::Result<Value> {
    Ok(serde_json::json!({
        "products": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM product_security_product WHERE tenant_id = ?", tenant_id).await?,
        "open_vulnerabilities": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM product_security_vulnerability WHERE tenant_id = ? AND status NOT IN ('FIXED', 'CLOSED', 'RESOLVED')", tenant_id).await?,
        "critical_open_vulnerabilities": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM product_security_vulnerability WHERE tenant_id = ? AND severity = 'CRITICAL' AND status NOT IN ('FIXED', 'CLOSED', 'RESOLVED')", tenant_id).await?,
        "open_cve_correlation_reviews": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM product_security_cvecorrelation WHERE tenant_id = ? AND status = 'SUGGESTED'", tenant_id).await?,
        "invalid_imports": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM product_security_importartifact WHERE tenant_id = ? AND validation_status NOT IN ('VALID', 'VALIDATED')", tenant_id).await?
    }))
}

async fn agent_posture_postgres(pool: &PgPool, tenant_id: i64) -> anyhow::Result<Value> {
    Ok(serde_json::json!({
        "devices": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM zero_trust_agent_device WHERE tenant_id = $1", tenant_id).await?,
        "active_devices": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM zero_trust_agent_device WHERE tenant_id = $1 AND enrollment_status = 'ACTIVE'", tenant_id).await?,
        "open_findings": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM zero_trust_agent_finding WHERE tenant_id = $1 AND status = 'OPEN'", tenant_id).await?,
        "critical_findings": count_postgres(pool, "SELECT COUNT(*)::bigint AS count_value FROM zero_trust_agent_finding WHERE tenant_id = $1 AND status = 'OPEN' AND severity = 'CRITICAL'", tenant_id).await?
    }))
}

async fn agent_posture_sqlite(pool: &SqlitePool, tenant_id: i64) -> anyhow::Result<Value> {
    Ok(serde_json::json!({
        "devices": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM zero_trust_agent_device WHERE tenant_id = ?", tenant_id).await?,
        "active_devices": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM zero_trust_agent_device WHERE tenant_id = ? AND enrollment_status = 'ACTIVE'", tenant_id).await?,
        "open_findings": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM zero_trust_agent_finding WHERE tenant_id = ? AND status = 'OPEN'", tenant_id).await?,
        "critical_findings": count_sqlite(pool, "SELECT COUNT(*) AS count_value FROM zero_trust_agent_finding WHERE tenant_id = ? AND status = 'OPEN' AND severity = 'CRITICAL'", tenant_id).await?
    }))
}

async fn count_postgres(pool: &PgPool, sql: &str, tenant_id: i64) -> anyhow::Result<i64> {
    let row = sqlx::query(sql).bind(tenant_id).fetch_one(pool).await?;
    Ok(row.try_get("count_value")?)
}

async fn count_sqlite(pool: &SqlitePool, sql: &str, tenant_id: i64) -> anyhow::Result<i64> {
    let row = sqlx::query(sql).bind(tenant_id).fetch_one(pool).await?;
    Ok(row.try_get("count_value")?)
}

fn management_review_list_postgres_sql() -> &'static str {
    r#"
    SELECT
        id, tenant_id, title, period_start::text AS period_start, period_end::text AS period_end,
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
        CAST(period_end AS TEXT) AS period_end, status, generated_by_id, approved_by_id,
        CAST(approved_at AS TEXT) AS approved_at, CAST(created_at AS TEXT) AS created_at,
        CAST(updated_at AS TEXT) AS updated_at
    FROM reports_managementreviewpackage
    WHERE tenant_id = ?
    ORDER BY created_at DESC, id DESC
    LIMIT ?
    "#
}

fn management_review_detail_postgres_sql() -> &'static str {
    r#"
    SELECT
        id, tenant_id, title, period_start::text AS period_start, period_end::text AS period_end,
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
    Ok(ManagementReviewPackageSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        title: row.try_get("title")?,
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
    Ok(ManagementReviewPackageSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        title: row.try_get("title")?,
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
    Ok(ManagementReviewPackageDetail {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        title: row.try_get("title")?,
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
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn management_review_detail_from_sqlite_row(
    row: SqliteRow,
) -> Result<ManagementReviewPackageDetail, sqlx::Error> {
    let status: String = row.try_get("status")?;
    Ok(ManagementReviewPackageDetail {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        title: row.try_get("title")?,
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
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn review_title(title: Option<String>) -> String {
    clean_text(title, 255)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("Management Review {}", Utc::now().format("%Y-%m-%d")))
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
    format!(
        "Automatisch erzeugtes Management-Review-Paket: {open_risks} offene Risiken, {control_gaps} offene ISCY-27-Control-Gaps, {evidence_gaps} offene Evidence-Luecken und {open_tasks} offene Roadmap-Tasks sind fuer die Review-Entscheidung zusammengefasst."
    )
}

fn clean_optional_text(value: Option<String>) -> Option<String> {
    clean_text(value, 255).filter(|value| !value.is_empty())
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
