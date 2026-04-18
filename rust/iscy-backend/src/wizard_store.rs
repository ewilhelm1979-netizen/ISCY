use anyhow::{bail, Context};
use serde::Serialize;
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Row,
};

use crate::{
    cve_store::normalize_database_url,
    report_store::{ReportSnapshotDetail, ReportStore},
    roadmap_store::{RoadmapPlanDetail, RoadmapStore},
};

#[derive(Clone)]
pub enum WizardStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Serialize)]
pub struct WizardSessionSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub tenant_name: String,
    pub assessment_type: String,
    pub assessment_type_label: String,
    pub status: String,
    pub status_label: String,
    pub current_step: String,
    pub current_step_label: String,
    pub started_by_id: Option<i64>,
    pub started_by_display: Option<String>,
    pub applicability_result: String,
    pub applicability_reasoning: String,
    pub executive_summary: String,
    pub progress_percent: i64,
    pub completed_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WizardDomainScoreSummary {
    pub id: i64,
    pub session_id: i64,
    pub domain_id: i64,
    pub domain_code: String,
    pub domain_name: String,
    pub domain_sort_order: i64,
    pub score_raw: i64,
    pub score_percent: i64,
    pub maturity_level: String,
    pub gap_level: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WizardGapSummary {
    pub id: i64,
    pub session_id: i64,
    pub domain_id: i64,
    pub domain_code: String,
    pub domain_name: String,
    pub question_id: Option<i64>,
    pub severity: String,
    pub severity_label: String,
    pub title: String,
    pub description: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WizardMeasureSummary {
    pub id: i64,
    pub session_id: i64,
    pub domain_id: Option<i64>,
    pub domain_code: Option<String>,
    pub domain_name: Option<String>,
    pub question_id: Option<i64>,
    pub title: String,
    pub description: String,
    pub priority: String,
    pub priority_label: String,
    pub effort: String,
    pub effort_label: String,
    pub measure_type: String,
    pub measure_type_label: String,
    pub target_phase: String,
    pub owner_role: String,
    pub reason: String,
    pub status: String,
    pub status_label: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WizardResultsSummary {
    pub session: WizardSessionSummary,
    pub report: Option<ReportSnapshotDetail>,
    pub roadmap: Option<RoadmapPlanDetail>,
    pub domain_scores: Vec<WizardDomainScoreSummary>,
    pub gaps: Vec<WizardGapSummary>,
    pub measures: Vec<WizardMeasureSummary>,
    pub evidence_count: i64,
}

impl WizardStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Wizard-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Wizard-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-Wizard-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn list_sessions(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<WizardSessionSummary>> {
        match self {
            Self::Postgres(pool) => list_sessions_postgres(pool, tenant_id, limit).await,
            Self::Sqlite(pool) => list_sessions_sqlite(pool, tenant_id, limit).await,
        }
    }

    pub async fn results(
        &self,
        tenant_id: i64,
        session_id: i64,
    ) -> anyhow::Result<Option<WizardResultsSummary>> {
        match self {
            Self::Postgres(pool) => results_postgres(pool, tenant_id, session_id).await,
            Self::Sqlite(pool) => results_sqlite(pool, tenant_id, session_id).await,
        }
    }
}

async fn list_sessions_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<WizardSessionSummary>> {
    let rows = sqlx::query(session_list_postgres_sql())
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Wizard-Sessions konnten nicht gelesen werden")?;

    rows.into_iter()
        .map(session_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_sessions_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<WizardSessionSummary>> {
    let rows = sqlx::query(session_list_sqlite_sql())
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("SQLite-Wizard-Sessions konnten nicht gelesen werden")?;

    rows.into_iter()
        .map(session_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn results_postgres(
    pool: &PgPool,
    tenant_id: i64,
    session_id: i64,
) -> anyhow::Result<Option<WizardResultsSummary>> {
    let session = sqlx::query(session_detail_postgres_sql())
        .bind(tenant_id)
        .bind(session_id)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-Wizard-Session konnte nicht gelesen werden")?
        .map(session_from_pg_row)
        .transpose()?;

    let Some(session) = session else {
        return Ok(None);
    };

    let domain_scores = sqlx::query(domain_scores_postgres_sql())
        .bind(session_id)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Domain-Scores konnten nicht gelesen werden")?
        .into_iter()
        .map(domain_score_from_pg_row)
        .collect::<Result<Vec<_>, _>>()?;

    let gaps = sqlx::query(gaps_postgres_sql())
        .bind(session_id)
        .bind(20_i64)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Wizard-Gaps konnten nicht gelesen werden")?
        .into_iter()
        .map(gap_from_pg_row)
        .collect::<Result<Vec<_>, _>>()?;

    let measures = sqlx::query(measures_postgres_sql())
        .bind(session_id)
        .bind(20_i64)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Wizard-Massnahmen konnten nicht gelesen werden")?
        .into_iter()
        .map(measure_from_pg_row)
        .collect::<Result<Vec<_>, _>>()?;

    let evidence_count = evidence_count_postgres(pool, tenant_id, session_id).await?;
    let report = latest_report_id_postgres(pool, tenant_id, session_id)
        .await?
        .map(|report_id| async move {
            ReportStore::Postgres(pool.clone())
                .snapshot_detail(tenant_id, report_id)
                .await
        });
    let report = match report {
        Some(fut) => fut.await?,
        None => None,
    };
    let roadmap = latest_roadmap_id_postgres(pool, tenant_id, session_id)
        .await?
        .map(|plan_id| async move {
            RoadmapStore::Postgres(pool.clone())
                .plan_detail(tenant_id, plan_id)
                .await
        });
    let roadmap = match roadmap {
        Some(fut) => fut.await?,
        None => None,
    };

    Ok(Some(WizardResultsSummary {
        session,
        report,
        roadmap,
        domain_scores,
        gaps,
        measures,
        evidence_count,
    }))
}

async fn results_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    session_id: i64,
) -> anyhow::Result<Option<WizardResultsSummary>> {
    let session = sqlx::query(session_detail_sqlite_sql())
        .bind(tenant_id)
        .bind(session_id)
        .fetch_optional(pool)
        .await
        .context("SQLite-Wizard-Session konnte nicht gelesen werden")?
        .map(session_from_sqlite_row)
        .transpose()?;

    let Some(session) = session else {
        return Ok(None);
    };

    let domain_scores = sqlx::query(domain_scores_sqlite_sql())
        .bind(session_id)
        .fetch_all(pool)
        .await
        .context("SQLite-Domain-Scores konnten nicht gelesen werden")?
        .into_iter()
        .map(domain_score_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()?;

    let gaps = sqlx::query(gaps_sqlite_sql())
        .bind(session_id)
        .bind(20_i64)
        .fetch_all(pool)
        .await
        .context("SQLite-Wizard-Gaps konnten nicht gelesen werden")?
        .into_iter()
        .map(gap_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()?;

    let measures = sqlx::query(measures_sqlite_sql())
        .bind(session_id)
        .bind(20_i64)
        .fetch_all(pool)
        .await
        .context("SQLite-Wizard-Massnahmen konnten nicht gelesen werden")?
        .into_iter()
        .map(measure_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()?;

    let evidence_count = evidence_count_sqlite(pool, tenant_id, session_id).await?;
    let report = latest_report_id_sqlite(pool, tenant_id, session_id)
        .await?
        .map(|report_id| async move {
            ReportStore::Sqlite(pool.clone())
                .snapshot_detail(tenant_id, report_id)
                .await
        });
    let report = match report {
        Some(fut) => fut.await?,
        None => None,
    };
    let roadmap = latest_roadmap_id_sqlite(pool, tenant_id, session_id)
        .await?
        .map(|plan_id| async move {
            RoadmapStore::Sqlite(pool.clone())
                .plan_detail(tenant_id, plan_id)
                .await
        });
    let roadmap = match roadmap {
        Some(fut) => fut.await?,
        None => None,
    };

    Ok(Some(WizardResultsSummary {
        session,
        report,
        roadmap,
        domain_scores,
        gaps,
        measures,
        evidence_count,
    }))
}

async fn evidence_count_postgres(
    pool: &PgPool,
    tenant_id: i64,
    session_id: i64,
) -> anyhow::Result<i64> {
    let row = sqlx::query(
        r#"
        SELECT COUNT(*)::bigint AS evidence_count
        FROM evidence_evidenceitem
        WHERE tenant_id = $1 AND session_id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(session_id)
    .fetch_one(pool)
    .await
    .context("PostgreSQL-Evidenzzaehler konnte nicht gelesen werden")?;

    row.try_get("evidence_count").map_err(Into::into)
}

async fn evidence_count_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    session_id: i64,
) -> anyhow::Result<i64> {
    let row = sqlx::query(
        r#"
        SELECT COUNT(*) AS evidence_count
        FROM evidence_evidenceitem
        WHERE tenant_id = ? AND session_id = ?
        "#,
    )
    .bind(tenant_id)
    .bind(session_id)
    .fetch_one(pool)
    .await
    .context("SQLite-Evidenzzaehler konnte nicht gelesen werden")?;

    row.try_get("evidence_count").map_err(Into::into)
}

async fn latest_report_id_postgres(
    pool: &PgPool,
    tenant_id: i64,
    session_id: i64,
) -> anyhow::Result<Option<i64>> {
    let row = sqlx::query(
        r#"
        SELECT id
        FROM reports_reportsnapshot
        WHERE tenant_id = $1 AND session_id = $2
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(session_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-Wizard-Report-ID konnte nicht gelesen werden")?;

    row.map(|row| row.try_get("id"))
        .transpose()
        .map_err(Into::into)
}

async fn latest_report_id_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    session_id: i64,
) -> anyhow::Result<Option<i64>> {
    let row = sqlx::query(
        r#"
        SELECT id
        FROM reports_reportsnapshot
        WHERE tenant_id = ? AND session_id = ?
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(session_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-Wizard-Report-ID konnte nicht gelesen werden")?;

    row.map(|row| row.try_get("id"))
        .transpose()
        .map_err(Into::into)
}

async fn latest_roadmap_id_postgres(
    pool: &PgPool,
    tenant_id: i64,
    session_id: i64,
) -> anyhow::Result<Option<i64>> {
    let row = sqlx::query(
        r#"
        SELECT id
        FROM roadmap_roadmapplan
        WHERE tenant_id = $1 AND session_id = $2
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(session_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-Wizard-Roadmap-ID konnte nicht gelesen werden")?;

    row.map(|row| row.try_get("id"))
        .transpose()
        .map_err(Into::into)
}

async fn latest_roadmap_id_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    session_id: i64,
) -> anyhow::Result<Option<i64>> {
    let row = sqlx::query(
        r#"
        SELECT id
        FROM roadmap_roadmapplan
        WHERE tenant_id = ? AND session_id = ?
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(session_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-Wizard-Roadmap-ID konnte nicht gelesen werden")?;

    row.map(|row| row.try_get("id"))
        .transpose()
        .map_err(Into::into)
}

fn session_from_pg_row(row: PgRow) -> Result<WizardSessionSummary, sqlx::Error> {
    let assessment_type: String = row.try_get("assessment_type")?;
    let status: String = row.try_get("status")?;
    let current_step: String = row.try_get("current_step")?;
    Ok(WizardSessionSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        tenant_name: row.try_get("tenant_name")?,
        assessment_type_label: assessment_type_label(&assessment_type).to_string(),
        assessment_type,
        status_label: status_label(&status).to_string(),
        status,
        current_step_label: current_step_label(&current_step).to_string(),
        current_step,
        started_by_id: row.try_get("started_by_id")?,
        started_by_display: row.try_get("started_by_display")?,
        applicability_result: row.try_get("applicability_result")?,
        applicability_reasoning: row.try_get("applicability_reasoning")?,
        executive_summary: row.try_get("executive_summary")?,
        progress_percent: row.try_get("progress_percent")?,
        completed_at: row.try_get("completed_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn session_from_sqlite_row(row: SqliteRow) -> Result<WizardSessionSummary, sqlx::Error> {
    let assessment_type: String = row.try_get("assessment_type")?;
    let status: String = row.try_get("status")?;
    let current_step: String = row.try_get("current_step")?;
    Ok(WizardSessionSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        tenant_name: row.try_get("tenant_name")?,
        assessment_type_label: assessment_type_label(&assessment_type).to_string(),
        assessment_type,
        status_label: status_label(&status).to_string(),
        status,
        current_step_label: current_step_label(&current_step).to_string(),
        current_step,
        started_by_id: row.try_get("started_by_id")?,
        started_by_display: row.try_get("started_by_display")?,
        applicability_result: row.try_get("applicability_result")?,
        applicability_reasoning: row.try_get("applicability_reasoning")?,
        executive_summary: row.try_get("executive_summary")?,
        progress_percent: row.try_get("progress_percent")?,
        completed_at: row.try_get("completed_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn domain_score_from_pg_row(row: PgRow) -> Result<WizardDomainScoreSummary, sqlx::Error> {
    Ok(WizardDomainScoreSummary {
        id: row.try_get("id")?,
        session_id: row.try_get("session_id")?,
        domain_id: row.try_get("domain_id")?,
        domain_code: row.try_get("domain_code")?,
        domain_name: row.try_get("domain_name")?,
        domain_sort_order: row.try_get("domain_sort_order")?,
        score_raw: row.try_get("score_raw")?,
        score_percent: row.try_get("score_percent")?,
        maturity_level: row.try_get("maturity_level")?,
        gap_level: row.try_get("gap_level")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn domain_score_from_sqlite_row(row: SqliteRow) -> Result<WizardDomainScoreSummary, sqlx::Error> {
    Ok(WizardDomainScoreSummary {
        id: row.try_get("id")?,
        session_id: row.try_get("session_id")?,
        domain_id: row.try_get("domain_id")?,
        domain_code: row.try_get("domain_code")?,
        domain_name: row.try_get("domain_name")?,
        domain_sort_order: row.try_get("domain_sort_order")?,
        score_raw: row.try_get("score_raw")?,
        score_percent: row.try_get("score_percent")?,
        maturity_level: row.try_get("maturity_level")?,
        gap_level: row.try_get("gap_level")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn gap_from_pg_row(row: PgRow) -> Result<WizardGapSummary, sqlx::Error> {
    let severity: String = row.try_get("severity")?;
    Ok(WizardGapSummary {
        id: row.try_get("id")?,
        session_id: row.try_get("session_id")?,
        domain_id: row.try_get("domain_id")?,
        domain_code: row.try_get("domain_code")?,
        domain_name: row.try_get("domain_name")?,
        question_id: row.try_get("question_id")?,
        severity_label: severity_label(&severity).to_string(),
        severity,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn gap_from_sqlite_row(row: SqliteRow) -> Result<WizardGapSummary, sqlx::Error> {
    let severity: String = row.try_get("severity")?;
    Ok(WizardGapSummary {
        id: row.try_get("id")?,
        session_id: row.try_get("session_id")?,
        domain_id: row.try_get("domain_id")?,
        domain_code: row.try_get("domain_code")?,
        domain_name: row.try_get("domain_name")?,
        question_id: row.try_get("question_id")?,
        severity_label: severity_label(&severity).to_string(),
        severity,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn measure_from_pg_row(row: PgRow) -> Result<WizardMeasureSummary, sqlx::Error> {
    let priority: String = row.try_get("priority")?;
    let effort: String = row.try_get("effort")?;
    let measure_type: String = row.try_get("measure_type")?;
    let status: String = row.try_get("status")?;
    Ok(WizardMeasureSummary {
        id: row.try_get("id")?,
        session_id: row.try_get("session_id")?,
        domain_id: row.try_get("domain_id")?,
        domain_code: row.try_get("domain_code")?,
        domain_name: row.try_get("domain_name")?,
        question_id: row.try_get("question_id")?,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        priority_label: priority_label(&priority).to_string(),
        priority,
        effort_label: effort_label(&effort).to_string(),
        effort,
        measure_type_label: measure_type_label(&measure_type).to_string(),
        measure_type,
        target_phase: row.try_get("target_phase")?,
        owner_role: row.try_get("owner_role")?,
        reason: row.try_get("reason")?,
        status_label: measure_status_label(&status).to_string(),
        status,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn measure_from_sqlite_row(row: SqliteRow) -> Result<WizardMeasureSummary, sqlx::Error> {
    let priority: String = row.try_get("priority")?;
    let effort: String = row.try_get("effort")?;
    let measure_type: String = row.try_get("measure_type")?;
    let status: String = row.try_get("status")?;
    Ok(WizardMeasureSummary {
        id: row.try_get("id")?,
        session_id: row.try_get("session_id")?,
        domain_id: row.try_get("domain_id")?,
        domain_code: row.try_get("domain_code")?,
        domain_name: row.try_get("domain_name")?,
        question_id: row.try_get("question_id")?,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        priority_label: priority_label(&priority).to_string(),
        priority,
        effort_label: effort_label(&effort).to_string(),
        effort,
        measure_type_label: measure_type_label(&measure_type).to_string(),
        measure_type,
        target_phase: row.try_get("target_phase")?,
        owner_role: row.try_get("owner_role")?,
        reason: row.try_get("reason")?,
        status_label: measure_status_label(&status).to_string(),
        status,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn session_list_postgres_sql() -> &'static str {
    r#"
    SELECT
        session.id,
        session.tenant_id,
        tenant.name AS tenant_name,
        session.assessment_type,
        session.status,
        session.current_step,
        session.started_by_id,
        COALESCE(
            NULLIF(BTRIM(CONCAT(COALESCE(started_by.first_name, ''), ' ', COALESCE(started_by.last_name, ''))), ''),
            started_by.username
        ) AS started_by_display,
        session.applicability_result,
        session.applicability_reasoning,
        session.executive_summary,
        session.progress_percent::bigint AS progress_percent,
        session.completed_at::text AS completed_at,
        session.created_at::text AS created_at,
        session.updated_at::text AS updated_at
    FROM wizard_assessmentsession session
    JOIN organizations_tenant tenant ON tenant.id = session.tenant_id
    LEFT JOIN accounts_user started_by ON started_by.id = session.started_by_id
    WHERE session.tenant_id = $1
    ORDER BY session.updated_at DESC, session.id DESC
    LIMIT $2
    "#
}

fn session_list_sqlite_sql() -> &'static str {
    r#"
    SELECT
        session.id,
        session.tenant_id,
        tenant.name AS tenant_name,
        session.assessment_type,
        session.status,
        session.current_step,
        session.started_by_id,
        COALESCE(
            NULLIF(TRIM(COALESCE(started_by.first_name, '') || ' ' || COALESCE(started_by.last_name, '')), ''),
            started_by.username
        ) AS started_by_display,
        session.applicability_result,
        session.applicability_reasoning,
        session.executive_summary,
        session.progress_percent,
        CAST(session.completed_at AS TEXT) AS completed_at,
        CAST(session.created_at AS TEXT) AS created_at,
        CAST(session.updated_at AS TEXT) AS updated_at
    FROM wizard_assessmentsession session
    JOIN organizations_tenant tenant ON tenant.id = session.tenant_id
    LEFT JOIN accounts_user started_by ON started_by.id = session.started_by_id
    WHERE session.tenant_id = ?
    ORDER BY session.updated_at DESC, session.id DESC
    LIMIT ?
    "#
}

fn session_detail_postgres_sql() -> &'static str {
    r#"
    SELECT
        session.id,
        session.tenant_id,
        tenant.name AS tenant_name,
        session.assessment_type,
        session.status,
        session.current_step,
        session.started_by_id,
        COALESCE(
            NULLIF(BTRIM(CONCAT(COALESCE(started_by.first_name, ''), ' ', COALESCE(started_by.last_name, ''))), ''),
            started_by.username
        ) AS started_by_display,
        session.applicability_result,
        session.applicability_reasoning,
        session.executive_summary,
        session.progress_percent::bigint AS progress_percent,
        session.completed_at::text AS completed_at,
        session.created_at::text AS created_at,
        session.updated_at::text AS updated_at
    FROM wizard_assessmentsession session
    JOIN organizations_tenant tenant ON tenant.id = session.tenant_id
    LEFT JOIN accounts_user started_by ON started_by.id = session.started_by_id
    WHERE session.tenant_id = $1 AND session.id = $2
    "#
}

fn session_detail_sqlite_sql() -> &'static str {
    r#"
    SELECT
        session.id,
        session.tenant_id,
        tenant.name AS tenant_name,
        session.assessment_type,
        session.status,
        session.current_step,
        session.started_by_id,
        COALESCE(
            NULLIF(TRIM(COALESCE(started_by.first_name, '') || ' ' || COALESCE(started_by.last_name, '')), ''),
            started_by.username
        ) AS started_by_display,
        session.applicability_result,
        session.applicability_reasoning,
        session.executive_summary,
        session.progress_percent,
        CAST(session.completed_at AS TEXT) AS completed_at,
        CAST(session.created_at AS TEXT) AS created_at,
        CAST(session.updated_at AS TEXT) AS updated_at
    FROM wizard_assessmentsession session
    JOIN organizations_tenant tenant ON tenant.id = session.tenant_id
    LEFT JOIN accounts_user started_by ON started_by.id = session.started_by_id
    WHERE session.tenant_id = ? AND session.id = ?
    "#
}

fn domain_scores_postgres_sql() -> &'static str {
    r#"
    SELECT
        score.id,
        score.session_id,
        score.domain_id,
        domain.code AS domain_code,
        domain.name AS domain_name,
        domain.sort_order::bigint AS domain_sort_order,
        score.score_raw::bigint AS score_raw,
        score.score_percent::bigint AS score_percent,
        score.maturity_level,
        score.gap_level,
        score.created_at::text AS created_at,
        score.updated_at::text AS updated_at
    FROM wizard_domainscore score
    JOIN catalog_assessmentdomain domain ON domain.id = score.domain_id
    WHERE score.session_id = $1
    ORDER BY domain.sort_order ASC, domain.name ASC
    "#
}

fn domain_scores_sqlite_sql() -> &'static str {
    r#"
    SELECT
        score.id,
        score.session_id,
        score.domain_id,
        domain.code AS domain_code,
        domain.name AS domain_name,
        domain.sort_order AS domain_sort_order,
        score.score_raw,
        score.score_percent,
        score.maturity_level,
        score.gap_level,
        CAST(score.created_at AS TEXT) AS created_at,
        CAST(score.updated_at AS TEXT) AS updated_at
    FROM wizard_domainscore score
    JOIN catalog_assessmentdomain domain ON domain.id = score.domain_id
    WHERE score.session_id = ?
    ORDER BY domain.sort_order ASC, domain.name ASC
    "#
}

fn gaps_postgres_sql() -> &'static str {
    r#"
    SELECT
        gap.id,
        gap.session_id,
        gap.domain_id,
        domain.code AS domain_code,
        domain.name AS domain_name,
        gap.question_id,
        gap.severity,
        gap.title,
        gap.description,
        gap.created_at::text AS created_at,
        gap.updated_at::text AS updated_at
    FROM wizard_generatedgap gap
    JOIN catalog_assessmentdomain domain ON domain.id = gap.domain_id
    WHERE gap.session_id = $1
    ORDER BY gap.severity ASC, domain.sort_order ASC, gap.title ASC
    LIMIT $2
    "#
}

fn gaps_sqlite_sql() -> &'static str {
    r#"
    SELECT
        gap.id,
        gap.session_id,
        gap.domain_id,
        domain.code AS domain_code,
        domain.name AS domain_name,
        gap.question_id,
        gap.severity,
        gap.title,
        gap.description,
        CAST(gap.created_at AS TEXT) AS created_at,
        CAST(gap.updated_at AS TEXT) AS updated_at
    FROM wizard_generatedgap gap
    JOIN catalog_assessmentdomain domain ON domain.id = gap.domain_id
    WHERE gap.session_id = ?
    ORDER BY gap.severity ASC, domain.sort_order ASC, gap.title ASC
    LIMIT ?
    "#
}

fn measures_postgres_sql() -> &'static str {
    r#"
    SELECT
        measure.id,
        measure.session_id,
        measure.domain_id,
        domain.code AS domain_code,
        domain.name AS domain_name,
        measure.question_id,
        measure.title,
        measure.description,
        measure.priority,
        measure.effort,
        measure.measure_type,
        measure.target_phase,
        measure.owner_role,
        measure.reason,
        measure.status,
        measure.created_at::text AS created_at,
        measure.updated_at::text AS updated_at
    FROM wizard_generatedmeasure measure
    LEFT JOIN catalog_assessmentdomain domain ON domain.id = measure.domain_id
    WHERE measure.session_id = $1
    ORDER BY measure.priority ASC, domain.sort_order ASC NULLS LAST, measure.title ASC
    LIMIT $2
    "#
}

fn measures_sqlite_sql() -> &'static str {
    r#"
    SELECT
        measure.id,
        measure.session_id,
        measure.domain_id,
        domain.code AS domain_code,
        domain.name AS domain_name,
        measure.question_id,
        measure.title,
        measure.description,
        measure.priority,
        measure.effort,
        measure.measure_type,
        measure.target_phase,
        measure.owner_role,
        measure.reason,
        measure.status,
        CAST(measure.created_at AS TEXT) AS created_at,
        CAST(measure.updated_at AS TEXT) AS updated_at
    FROM wizard_generatedmeasure measure
    LEFT JOIN catalog_assessmentdomain domain ON domain.id = measure.domain_id
    WHERE measure.session_id = ?
    ORDER BY measure.priority ASC, domain.sort_order ASC, measure.title ASC
    LIMIT ?
    "#
}

fn assessment_type_label(value: &str) -> &'static str {
    match value {
        "APPLICABILITY" => "NIS2-/KRITIS-Relevanz pruefen",
        "ISO_READINESS" => "ISO-27001-Readiness bewerten",
        "FULL" => "Vollstaendige ISMS-/NIS2-Gap-Analyse",
        _ => "Unbekannt",
    }
}

fn status_label(value: &str) -> &'static str {
    match value {
        "DRAFT" => "Entwurf",
        "IN_PROGRESS" => "In Bearbeitung",
        "COMPLETED" => "Abgeschlossen",
        _ => "Unbekannt",
    }
}

fn current_step_label(value: &str) -> &'static str {
    match value {
        "profile" => "Unternehmensprofil",
        "applicability" => "Betroffenheit",
        "scope" => "Scope & Struktur",
        "maturity" => "Reifegradanalyse",
        "results" => "Ergebnis",
        _ => "Unbekannt",
    }
}

fn severity_label(value: &str) -> &'static str {
    match value {
        "CRITICAL" => "Kritisch",
        "HIGH" => "Hoch",
        "MEDIUM" => "Mittel",
        "LOW" => "Niedrig",
        _ => "Unbekannt",
    }
}

fn priority_label(value: &str) -> &'static str {
    severity_label(value)
}

fn effort_label(value: &str) -> &'static str {
    match value {
        "SMALL" => "Klein",
        "MEDIUM" => "Mittel",
        "LARGE" => "Gross",
        _ => "Unbekannt",
    }
}

fn measure_type_label(value: &str) -> &'static str {
    match value {
        "ORGANIZATIONAL" => "Organisatorisch",
        "TECHNICAL" => "Technisch",
        "DOCUMENTARY" => "Dokumentarisch",
        _ => "Unbekannt",
    }
}

fn measure_status_label(value: &str) -> &'static str {
    match value {
        "OPEN" => "Offen",
        "PLANNED" => "Geplant",
        "IN_PROGRESS" => "In Umsetzung",
        "DONE" => "Erledigt",
        _ => "Unbekannt",
    }
}
