use anyhow::{bail, Context};
use serde::Serialize;
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Row,
};

use crate::cve_store::normalize_database_url;

#[derive(Clone)]
pub enum AssessmentStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Serialize)]
pub struct ApplicabilityAssessmentSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub tenant_name: String,
    pub sector: String,
    pub company_size: String,
    pub critical_services: String,
    pub supply_chain_role: String,
    pub status: String,
    pub status_label: String,
    pub reasoning: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AssessmentSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub process_id: i64,
    pub process_name: String,
    pub requirement_id: i64,
    pub requirement_framework: String,
    pub requirement_code: String,
    pub requirement_title: String,
    pub owner_id: Option<i64>,
    pub owner_display: Option<String>,
    pub status: String,
    pub status_label: String,
    pub score: i64,
    pub notes: String,
    pub evidence_summary: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MeasureSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub assessment_id: Option<i64>,
    pub assessment_display: Option<String>,
    pub owner_id: Option<i64>,
    pub owner_display: Option<String>,
    pub title: String,
    pub description: String,
    pub priority: String,
    pub priority_label: String,
    pub status: String,
    pub status_label: String,
    pub due_date: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl AssessmentStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Assessment-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Assessment-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-Assessment-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn list_applicability(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<ApplicabilityAssessmentSummary>> {
        match self {
            Self::Postgres(pool) => list_applicability_postgres(pool, tenant_id, limit).await,
            Self::Sqlite(pool) => list_applicability_sqlite(pool, tenant_id, limit).await,
        }
    }

    pub async fn list_assessments(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<AssessmentSummary>> {
        match self {
            Self::Postgres(pool) => list_assessments_postgres(pool, tenant_id, limit).await,
            Self::Sqlite(pool) => list_assessments_sqlite(pool, tenant_id, limit).await,
        }
    }

    pub async fn list_measures(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<MeasureSummary>> {
        match self {
            Self::Postgres(pool) => list_measures_postgres(pool, tenant_id, limit).await,
            Self::Sqlite(pool) => list_measures_sqlite(pool, tenant_id, limit).await,
        }
    }
}

async fn list_applicability_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<ApplicabilityAssessmentSummary>> {
    let rows = sqlx::query(
        r#"
        SELECT
            item.id,
            item.tenant_id,
            tenant.name AS tenant_name,
            item.sector,
            item.company_size,
            item.critical_services,
            item.supply_chain_role,
            item.status,
            item.reasoning,
            item.created_at::text AS created_at,
            item.updated_at::text AS updated_at
        FROM assessments_applicabilityassessment item
        JOIN organizations_tenant tenant
            ON tenant.id = item.tenant_id
        WHERE item.tenant_id = $1
        ORDER BY item.created_at DESC, item.id DESC
        LIMIT $2
        "#,
    )
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("PostgreSQL-Betroffenheitsanalysen konnten nicht gelesen werden")?;

    rows.into_iter()
        .map(applicability_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_applicability_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<ApplicabilityAssessmentSummary>> {
    let rows = sqlx::query(
        r#"
        SELECT
            item.id,
            item.tenant_id,
            tenant.name AS tenant_name,
            item.sector,
            item.company_size,
            item.critical_services,
            item.supply_chain_role,
            item.status,
            item.reasoning,
            CAST(item.created_at AS TEXT) AS created_at,
            CAST(item.updated_at AS TEXT) AS updated_at
        FROM assessments_applicabilityassessment item
        JOIN organizations_tenant tenant
            ON tenant.id = item.tenant_id
        WHERE item.tenant_id = ?
        ORDER BY item.created_at DESC, item.id DESC
        LIMIT ?
        "#,
    )
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("SQLite-Betroffenheitsanalysen konnten nicht gelesen werden")?;

    rows.into_iter()
        .map(applicability_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_assessments_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AssessmentSummary>> {
    let rows = sqlx::query(
        r#"
        SELECT
            assessment.id,
            assessment.tenant_id,
            assessment.process_id,
            process.name AS process_name,
            assessment.requirement_id,
            req.framework AS requirement_framework,
            req.code AS requirement_code,
            req.title AS requirement_title,
            assessment.owner_id,
            COALESCE(
                NULLIF(BTRIM(CONCAT(COALESCE(owner.first_name, ''), ' ', COALESCE(owner.last_name, ''))), ''),
                owner.username
            ) AS owner_display,
            assessment.status,
            assessment.score,
            assessment.notes,
            assessment.evidence_summary,
            assessment.created_at::text AS created_at,
            assessment.updated_at::text AS updated_at
        FROM assessments_assessment assessment
        JOIN processes_process process
            ON process.id = assessment.process_id AND process.tenant_id = assessment.tenant_id
        JOIN requirements_app_requirement req
            ON req.id = assessment.requirement_id
        LEFT JOIN accounts_user owner
            ON owner.id = assessment.owner_id AND owner.tenant_id = assessment.tenant_id
        WHERE assessment.tenant_id = $1
        ORDER BY req.framework ASC, req.code ASC, assessment.id ASC
        LIMIT $2
        "#,
    )
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("PostgreSQL-Assessments konnten nicht gelesen werden")?;

    rows.into_iter()
        .map(assessment_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_assessments_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AssessmentSummary>> {
    let rows = sqlx::query(
        r#"
        SELECT
            assessment.id,
            assessment.tenant_id,
            assessment.process_id,
            process.name AS process_name,
            assessment.requirement_id,
            req.framework AS requirement_framework,
            req.code AS requirement_code,
            req.title AS requirement_title,
            assessment.owner_id,
            COALESCE(
                NULLIF(TRIM(COALESCE(owner.first_name, '') || ' ' || COALESCE(owner.last_name, '')), ''),
                owner.username
            ) AS owner_display,
            assessment.status,
            assessment.score,
            assessment.notes,
            assessment.evidence_summary,
            CAST(assessment.created_at AS TEXT) AS created_at,
            CAST(assessment.updated_at AS TEXT) AS updated_at
        FROM assessments_assessment assessment
        JOIN processes_process process
            ON process.id = assessment.process_id AND process.tenant_id = assessment.tenant_id
        JOIN requirements_app_requirement req
            ON req.id = assessment.requirement_id
        LEFT JOIN accounts_user owner
            ON owner.id = assessment.owner_id AND owner.tenant_id = assessment.tenant_id
        WHERE assessment.tenant_id = ?
        ORDER BY req.framework ASC, req.code ASC, assessment.id ASC
        LIMIT ?
        "#,
    )
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("SQLite-Assessments konnten nicht gelesen werden")?;

    rows.into_iter()
        .map(assessment_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_measures_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<MeasureSummary>> {
    let rows = sqlx::query(
        r#"
        SELECT
            measure.id,
            measure.tenant_id,
            measure.assessment_id,
            CASE
                WHEN assessment.id IS NULL THEN NULL
                ELSE CONCAT(process.name, ' -> ', req.framework, ' - ', req.code)
            END AS assessment_display,
            measure.owner_id,
            COALESCE(
                NULLIF(BTRIM(CONCAT(COALESCE(owner.first_name, ''), ' ', COALESCE(owner.last_name, ''))), ''),
                owner.username
            ) AS owner_display,
            measure.title,
            measure.description,
            measure.priority,
            measure.status,
            measure.due_date::text AS due_date,
            measure.created_at::text AS created_at,
            measure.updated_at::text AS updated_at
        FROM assessments_measure measure
        LEFT JOIN assessments_assessment assessment
            ON assessment.id = measure.assessment_id AND assessment.tenant_id = measure.tenant_id
        LEFT JOIN processes_process process
            ON process.id = assessment.process_id AND process.tenant_id = assessment.tenant_id
        LEFT JOIN requirements_app_requirement req
            ON req.id = assessment.requirement_id
        LEFT JOIN accounts_user owner
            ON owner.id = measure.owner_id AND owner.tenant_id = measure.tenant_id
        WHERE measure.tenant_id = $1
        ORDER BY measure.status ASC, measure.due_date ASC NULLS LAST, measure.id ASC
        LIMIT $2
        "#,
    )
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("PostgreSQL-Massnahmen konnten nicht gelesen werden")?;

    rows.into_iter()
        .map(measure_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_measures_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<MeasureSummary>> {
    let rows = sqlx::query(
        r#"
        SELECT
            measure.id,
            measure.tenant_id,
            measure.assessment_id,
            CASE
                WHEN assessment.id IS NULL THEN NULL
                ELSE process.name || ' -> ' || req.framework || ' - ' || req.code
            END AS assessment_display,
            measure.owner_id,
            COALESCE(
                NULLIF(TRIM(COALESCE(owner.first_name, '') || ' ' || COALESCE(owner.last_name, '')), ''),
                owner.username
            ) AS owner_display,
            measure.title,
            measure.description,
            measure.priority,
            measure.status,
            CAST(measure.due_date AS TEXT) AS due_date,
            CAST(measure.created_at AS TEXT) AS created_at,
            CAST(measure.updated_at AS TEXT) AS updated_at
        FROM assessments_measure measure
        LEFT JOIN assessments_assessment assessment
            ON assessment.id = measure.assessment_id AND assessment.tenant_id = measure.tenant_id
        LEFT JOIN processes_process process
            ON process.id = assessment.process_id AND process.tenant_id = assessment.tenant_id
        LEFT JOIN requirements_app_requirement req
            ON req.id = assessment.requirement_id
        LEFT JOIN accounts_user owner
            ON owner.id = measure.owner_id AND owner.tenant_id = measure.tenant_id
        WHERE measure.tenant_id = ?
        ORDER BY measure.status ASC, measure.due_date ASC, measure.id ASC
        LIMIT ?
        "#,
    )
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("SQLite-Massnahmen konnten nicht gelesen werden")?;

    rows.into_iter()
        .map(measure_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn applicability_from_pg_row(row: PgRow) -> Result<ApplicabilityAssessmentSummary, sqlx::Error> {
    let status: String = row.try_get("status")?;
    Ok(ApplicabilityAssessmentSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        tenant_name: row.try_get("tenant_name")?,
        sector: row.try_get("sector")?,
        company_size: row.try_get("company_size")?,
        critical_services: row.try_get("critical_services")?,
        supply_chain_role: row.try_get("supply_chain_role")?,
        status_label: applicability_status_label(&status).to_string(),
        status,
        reasoning: row.try_get("reasoning")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn applicability_from_sqlite_row(
    row: SqliteRow,
) -> Result<ApplicabilityAssessmentSummary, sqlx::Error> {
    let status: String = row.try_get("status")?;
    Ok(ApplicabilityAssessmentSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        tenant_name: row.try_get("tenant_name")?,
        sector: row.try_get("sector")?,
        company_size: row.try_get("company_size")?,
        critical_services: row.try_get("critical_services")?,
        supply_chain_role: row.try_get("supply_chain_role")?,
        status_label: applicability_status_label(&status).to_string(),
        status,
        reasoning: row.try_get("reasoning")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn assessment_from_pg_row(row: PgRow) -> Result<AssessmentSummary, sqlx::Error> {
    let status: String = row.try_get("status")?;
    Ok(AssessmentSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        process_id: row.try_get("process_id")?,
        process_name: row.try_get("process_name")?,
        requirement_id: row.try_get("requirement_id")?,
        requirement_framework: row.try_get("requirement_framework")?,
        requirement_code: row.try_get("requirement_code")?,
        requirement_title: row.try_get("requirement_title")?,
        owner_id: row.try_get("owner_id")?,
        owner_display: row.try_get("owner_display")?,
        status_label: assessment_status_label(&status).to_string(),
        status,
        score: row.try_get("score")?,
        notes: row.try_get("notes")?,
        evidence_summary: row.try_get("evidence_summary")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn assessment_from_sqlite_row(row: SqliteRow) -> Result<AssessmentSummary, sqlx::Error> {
    let status: String = row.try_get("status")?;
    Ok(AssessmentSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        process_id: row.try_get("process_id")?,
        process_name: row.try_get("process_name")?,
        requirement_id: row.try_get("requirement_id")?,
        requirement_framework: row.try_get("requirement_framework")?,
        requirement_code: row.try_get("requirement_code")?,
        requirement_title: row.try_get("requirement_title")?,
        owner_id: row.try_get("owner_id")?,
        owner_display: row.try_get("owner_display")?,
        status_label: assessment_status_label(&status).to_string(),
        status,
        score: row.try_get("score")?,
        notes: row.try_get("notes")?,
        evidence_summary: row.try_get("evidence_summary")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn measure_from_pg_row(row: PgRow) -> Result<MeasureSummary, sqlx::Error> {
    let priority: String = row.try_get("priority")?;
    let status: String = row.try_get("status")?;
    Ok(MeasureSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        assessment_id: row.try_get("assessment_id")?,
        assessment_display: row.try_get("assessment_display")?,
        owner_id: row.try_get("owner_id")?,
        owner_display: row.try_get("owner_display")?,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        priority_label: measure_priority_label(&priority).to_string(),
        priority,
        status_label: measure_status_label(&status).to_string(),
        status,
        due_date: row.try_get("due_date")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn measure_from_sqlite_row(row: SqliteRow) -> Result<MeasureSummary, sqlx::Error> {
    let priority: String = row.try_get("priority")?;
    let status: String = row.try_get("status")?;
    Ok(MeasureSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        assessment_id: row.try_get("assessment_id")?,
        assessment_display: row.try_get("assessment_display")?,
        owner_id: row.try_get("owner_id")?,
        owner_display: row.try_get("owner_display")?,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        priority_label: measure_priority_label(&priority).to_string(),
        priority,
        status_label: measure_status_label(&status).to_string(),
        status,
        due_date: row.try_get("due_date")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn applicability_status_label(value: &str) -> &'static str {
    match value {
        "RELEVANT" => "Voraussichtlich relevant",
        "POSSIBLY_RELEVANT" => "Möglicherweise relevant",
        "NOT_DIRECTLY_RELEVANT" => "Derzeit nicht direkt relevant",
        _ => "Möglicherweise relevant",
    }
}

fn assessment_status_label(value: &str) -> &'static str {
    match value {
        "FULFILLED" => "Ausreichend erfüllt",
        "PARTIAL" => "Teilweise erfüllt",
        "INFORMAL" => "Informal vorhanden",
        "DOCUMENTED_NOT_IMPLEMENTED" => "Dokumentiert, aber nicht umgesetzt",
        "IMPLEMENTED_NO_EVIDENCE" => "Umgesetzt, aber nicht nachweisbar",
        "MISSING" => "Fehlt vollständig",
        _ => "Fehlt vollständig",
    }
}

fn measure_priority_label(value: &str) -> &'static str {
    match value {
        "LOW" => "Low",
        "MEDIUM" => "Medium",
        "HIGH" => "High",
        _ => "Medium",
    }
}

fn measure_status_label(value: &str) -> &'static str {
    match value {
        "OPEN" => "Open",
        "IN_PROGRESS" => "In Progress",
        "BLOCKED" => "Blocked",
        "DONE" => "Done",
        _ => "Open",
    }
}
