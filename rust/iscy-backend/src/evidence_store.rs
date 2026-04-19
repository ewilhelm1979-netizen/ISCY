use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Row,
};

use crate::cve_store::normalize_database_url;

#[derive(Clone)]
pub enum EvidenceStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceOverview {
    pub evidence_items: Vec<EvidenceItemSummary>,
    pub evidence_needs: Vec<RequirementEvidenceNeedSummary>,
    pub need_summary: EvidenceNeedSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceNeedSummary {
    pub open: i64,
    pub partial: i64,
    pub covered: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceItemSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub session_id: Option<i64>,
    pub domain_id: Option<i64>,
    pub measure_id: Option<i64>,
    pub measure_title: Option<String>,
    pub requirement_id: Option<i64>,
    pub requirement_framework: Option<String>,
    pub requirement_code: Option<String>,
    pub requirement_title: Option<String>,
    pub mapping_program_name: Option<String>,
    pub mapping_version: Option<String>,
    pub source_authority: Option<String>,
    pub source_citation: Option<String>,
    pub source_title: Option<String>,
    pub title: String,
    pub description: String,
    pub linked_requirement: String,
    pub file_name: Option<String>,
    pub status: String,
    pub status_label: String,
    pub owner_id: Option<i64>,
    pub owner_display: Option<String>,
    pub review_notes: String,
    pub reviewed_by_id: Option<i64>,
    pub reviewed_by_display: Option<String>,
    pub reviewed_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequirementEvidenceNeedSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub session_id: Option<i64>,
    pub requirement_id: i64,
    pub requirement_framework: String,
    pub requirement_code: String,
    pub requirement_title: String,
    pub mapping_program_name: Option<String>,
    pub mapping_version: Option<String>,
    pub source_authority: Option<String>,
    pub source_citation: Option<String>,
    pub source_title: Option<String>,
    pub title: String,
    pub description: String,
    pub is_mandatory: bool,
    pub status: String,
    pub status_label: String,
    pub rationale: String,
    pub covered_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EvidenceNeedSyncRequest {
    pub covered_threshold: Option<i64>,
    pub partial_threshold: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceNeedSyncResult {
    pub session_id: i64,
    pub created: i64,
    pub updated: i64,
    pub need_summary: EvidenceNeedSummary,
}

#[derive(Debug, Clone)]
struct TenantEvidenceContext {
    sector: String,
    kritis_relevant: bool,
}

#[derive(Debug, Clone)]
struct RequirementSyncSource {
    id: i64,
    framework: String,
    code: String,
    description: String,
    evidence_required: bool,
    evidence_guidance: String,
    evidence_examples: String,
    sector_package: String,
    legal_reference: String,
    mapping_program_name: Option<String>,
    mapping_version: Option<String>,
    source_authority: Option<String>,
    source_citation: Option<String>,
    source_title: Option<String>,
    source_url: Option<String>,
}

impl EvidenceStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Evidence-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Evidence-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-Evidence-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn evidence_overview(
        &self,
        tenant_id: i64,
        session_id: Option<i64>,
        item_limit: i64,
        need_limit: i64,
    ) -> anyhow::Result<EvidenceOverview> {
        match self {
            Self::Postgres(pool) => {
                evidence_overview_postgres(pool, tenant_id, session_id, item_limit, need_limit)
                    .await
            }
            Self::Sqlite(pool) => {
                evidence_overview_sqlite(pool, tenant_id, session_id, item_limit, need_limit).await
            }
        }
    }

    pub async fn sync_evidence_needs(
        &self,
        tenant_id: i64,
        session_id: i64,
        payload: EvidenceNeedSyncRequest,
    ) -> anyhow::Result<Option<EvidenceNeedSyncResult>> {
        match self {
            Self::Postgres(pool) => {
                sync_evidence_needs_postgres(pool, tenant_id, session_id, payload).await
            }
            Self::Sqlite(pool) => {
                sync_evidence_needs_sqlite(pool, tenant_id, session_id, payload).await
            }
        }
    }
}

async fn evidence_overview_postgres(
    pool: &PgPool,
    tenant_id: i64,
    session_id: Option<i64>,
    item_limit: i64,
    need_limit: i64,
) -> anyhow::Result<EvidenceOverview> {
    Ok(EvidenceOverview {
        evidence_items: list_evidence_items_postgres(pool, tenant_id, session_id, item_limit)
            .await?,
        evidence_needs: list_evidence_needs_postgres(pool, tenant_id, session_id, need_limit)
            .await?,
        need_summary: evidence_need_summary_postgres(pool, tenant_id, session_id).await?,
    })
}

async fn evidence_overview_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    session_id: Option<i64>,
    item_limit: i64,
    need_limit: i64,
) -> anyhow::Result<EvidenceOverview> {
    Ok(EvidenceOverview {
        evidence_items: list_evidence_items_sqlite(pool, tenant_id, session_id, item_limit).await?,
        evidence_needs: list_evidence_needs_sqlite(pool, tenant_id, session_id, need_limit).await?,
        need_summary: evidence_need_summary_sqlite(pool, tenant_id, session_id).await?,
    })
}

async fn sync_evidence_needs_postgres(
    pool: &PgPool,
    tenant_id: i64,
    session_id: i64,
    payload: EvidenceNeedSyncRequest,
) -> anyhow::Result<Option<EvidenceNeedSyncResult>> {
    if !session_exists_postgres(pool, tenant_id, session_id).await? {
        return Ok(None);
    }
    let tenant_context = tenant_context_postgres(pool, tenant_id).await?;
    let requirements = sync_requirements_postgres(pool).await?;
    let covered_threshold = normalize_threshold(payload.covered_threshold, 2);
    let partial_threshold = normalize_threshold(payload.partial_threshold, 1);
    let mut created = 0;
    let mut updated = 0;

    for requirement in requirements
        .iter()
        .filter(|requirement| requirement_relevant(requirement, &tenant_context))
    {
        let covered_count =
            evidence_count_for_requirement_postgres(pool, tenant_id, requirement.id).await?;
        let status = need_status_for_count(covered_count, covered_threshold, partial_threshold);
        let title = format!(
            "Nachweis für {} {}",
            requirement.framework, requirement.code
        );
        let description = requirement_description(requirement);
        let rationale = requirement_rationale(requirement);
        let existing_id =
            existing_need_id_postgres(pool, tenant_id, session_id, requirement.id).await?;

        if let Some(need_id) = existing_id {
            sqlx::query(
                r#"
                UPDATE evidence_requirementevidenceneed
                SET title = $2,
                    description = $3,
                    is_mandatory = $4,
                    status = $5,
                    rationale = $6,
                    covered_count = $7,
                    updated_at = NOW()
                WHERE id = $1
                "#,
            )
            .bind(need_id)
            .bind(&title)
            .bind(&description)
            .bind(requirement.evidence_required)
            .bind(status)
            .bind(&rationale)
            .bind(covered_count)
            .execute(pool)
            .await
            .context("PostgreSQL-Evidenzpflicht konnte nicht aktualisiert werden")?;
            updated += 1;
        } else {
            sqlx::query(
                r#"
                INSERT INTO evidence_requirementevidenceneed (
                    tenant_id,
                    session_id,
                    requirement_id,
                    title,
                    description,
                    is_mandatory,
                    status,
                    rationale,
                    covered_count,
                    created_at,
                    updated_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
                "#,
            )
            .bind(tenant_id)
            .bind(session_id)
            .bind(requirement.id)
            .bind(&title)
            .bind(&description)
            .bind(requirement.evidence_required)
            .bind(status)
            .bind(&rationale)
            .bind(covered_count)
            .execute(pool)
            .await
            .context("PostgreSQL-Evidenzpflicht konnte nicht erstellt werden")?;
            created += 1;
        }
    }

    Ok(Some(EvidenceNeedSyncResult {
        session_id,
        created,
        updated,
        need_summary: evidence_need_summary_postgres(pool, tenant_id, Some(session_id)).await?,
    }))
}

async fn sync_evidence_needs_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    session_id: i64,
    payload: EvidenceNeedSyncRequest,
) -> anyhow::Result<Option<EvidenceNeedSyncResult>> {
    if !session_exists_sqlite(pool, tenant_id, session_id).await? {
        return Ok(None);
    }
    let tenant_context = tenant_context_sqlite(pool, tenant_id).await?;
    let requirements = sync_requirements_sqlite(pool).await?;
    let covered_threshold = normalize_threshold(payload.covered_threshold, 2);
    let partial_threshold = normalize_threshold(payload.partial_threshold, 1);
    let mut created = 0;
    let mut updated = 0;

    for requirement in requirements
        .iter()
        .filter(|requirement| requirement_relevant(requirement, &tenant_context))
    {
        let covered_count =
            evidence_count_for_requirement_sqlite(pool, tenant_id, requirement.id).await?;
        let status = need_status_for_count(covered_count, covered_threshold, partial_threshold);
        let title = format!(
            "Nachweis für {} {}",
            requirement.framework, requirement.code
        );
        let description = requirement_description(requirement);
        let rationale = requirement_rationale(requirement);
        let existing_id =
            existing_need_id_sqlite(pool, tenant_id, session_id, requirement.id).await?;

        if let Some(need_id) = existing_id {
            sqlx::query(
                r#"
                UPDATE evidence_requirementevidenceneed
                SET title = ?2,
                    description = ?3,
                    is_mandatory = ?4,
                    status = ?5,
                    rationale = ?6,
                    covered_count = ?7,
                    updated_at = datetime('now')
                WHERE id = ?1
                "#,
            )
            .bind(need_id)
            .bind(&title)
            .bind(&description)
            .bind(requirement.evidence_required)
            .bind(status)
            .bind(&rationale)
            .bind(covered_count)
            .execute(pool)
            .await
            .context("SQLite-Evidenzpflicht konnte nicht aktualisiert werden")?;
            updated += 1;
        } else {
            sqlx::query(
                r#"
                INSERT INTO evidence_requirementevidenceneed (
                    tenant_id,
                    session_id,
                    requirement_id,
                    title,
                    description,
                    is_mandatory,
                    status,
                    rationale,
                    covered_count,
                    created_at,
                    updated_at
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, datetime('now'), datetime('now'))
                "#,
            )
            .bind(tenant_id)
            .bind(session_id)
            .bind(requirement.id)
            .bind(&title)
            .bind(&description)
            .bind(requirement.evidence_required)
            .bind(status)
            .bind(&rationale)
            .bind(covered_count)
            .execute(pool)
            .await
            .context("SQLite-Evidenzpflicht konnte nicht erstellt werden")?;
            created += 1;
        }
    }

    Ok(Some(EvidenceNeedSyncResult {
        session_id,
        created,
        updated,
        need_summary: evidence_need_summary_sqlite(pool, tenant_id, Some(session_id)).await?,
    }))
}

async fn list_evidence_items_postgres(
    pool: &PgPool,
    tenant_id: i64,
    session_id: Option<i64>,
    limit: i64,
) -> anyhow::Result<Vec<EvidenceItemSummary>> {
    let rows = sqlx::query(
        r#"
        SELECT
            item.id,
            item.tenant_id,
            item.session_id,
            item.domain_id,
            item.measure_id,
            measure.title AS measure_title,
            item.requirement_id,
            req.framework AS requirement_framework,
            req.code AS requirement_code,
            req.title AS requirement_title,
            mv.program_name AS mapping_program_name,
            mv.version AS mapping_version,
            src.authority AS source_authority,
            src.citation AS source_citation,
            src.title AS source_title,
            item.title,
            item.description,
            item.linked_requirement,
            item.file AS file_name,
            item.status,
            item.owner_id,
            COALESCE(
                NULLIF(BTRIM(CONCAT(COALESCE(owner.first_name, ''), ' ', COALESCE(owner.last_name, ''))), ''),
                owner.username
            ) AS owner_display,
            item.review_notes,
            item.reviewed_by_id,
            COALESCE(
                NULLIF(BTRIM(CONCAT(COALESCE(reviewer.first_name, ''), ' ', COALESCE(reviewer.last_name, ''))), ''),
                reviewer.username
            ) AS reviewed_by_display,
            item.reviewed_at::text AS reviewed_at,
            item.created_at::text AS created_at,
            item.updated_at::text AS updated_at
        FROM evidence_evidenceitem item
        LEFT JOIN wizard_generatedmeasure measure
            ON measure.id = item.measure_id
        LEFT JOIN requirements_app_requirement req
            ON req.id = item.requirement_id
        LEFT JOIN requirements_app_mappingversion mv
            ON mv.id = req.mapping_version_id
        LEFT JOIN requirements_app_regulatorysource src
            ON src.id = req.primary_source_id
        LEFT JOIN accounts_user owner
            ON owner.id = item.owner_id AND owner.tenant_id = item.tenant_id
        LEFT JOIN accounts_user reviewer
            ON reviewer.id = item.reviewed_by_id AND reviewer.tenant_id = item.tenant_id
        WHERE item.tenant_id = $1
          AND ($2::bigint IS NULL OR item.session_id = $2)
        ORDER BY item.updated_at DESC, item.title ASC, item.id ASC
        LIMIT $3
        "#,
    )
    .bind(tenant_id)
    .bind(session_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("PostgreSQL-Evidenzliste konnte nicht gelesen werden")?;

    rows.into_iter()
        .map(evidence_item_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_evidence_items_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    session_id: Option<i64>,
    limit: i64,
) -> anyhow::Result<Vec<EvidenceItemSummary>> {
    let rows = sqlx::query(
        r#"
        SELECT
            item.id,
            item.tenant_id,
            item.session_id,
            item.domain_id,
            item.measure_id,
            measure.title AS measure_title,
            item.requirement_id,
            req.framework AS requirement_framework,
            req.code AS requirement_code,
            req.title AS requirement_title,
            mv.program_name AS mapping_program_name,
            mv.version AS mapping_version,
            src.authority AS source_authority,
            src.citation AS source_citation,
            src.title AS source_title,
            item.title,
            item.description,
            item.linked_requirement,
            item.file AS file_name,
            item.status,
            item.owner_id,
            COALESCE(
                NULLIF(TRIM(COALESCE(owner.first_name, '') || ' ' || COALESCE(owner.last_name, '')), ''),
                owner.username
            ) AS owner_display,
            item.review_notes,
            item.reviewed_by_id,
            COALESCE(
                NULLIF(TRIM(COALESCE(reviewer.first_name, '') || ' ' || COALESCE(reviewer.last_name, '')), ''),
                reviewer.username
            ) AS reviewed_by_display,
            CAST(item.reviewed_at AS TEXT) AS reviewed_at,
            CAST(item.created_at AS TEXT) AS created_at,
            CAST(item.updated_at AS TEXT) AS updated_at
        FROM evidence_evidenceitem item
        LEFT JOIN wizard_generatedmeasure measure
            ON measure.id = item.measure_id
        LEFT JOIN requirements_app_requirement req
            ON req.id = item.requirement_id
        LEFT JOIN requirements_app_mappingversion mv
            ON mv.id = req.mapping_version_id
        LEFT JOIN requirements_app_regulatorysource src
            ON src.id = req.primary_source_id
        LEFT JOIN accounts_user owner
            ON owner.id = item.owner_id AND owner.tenant_id = item.tenant_id
        LEFT JOIN accounts_user reviewer
            ON reviewer.id = item.reviewed_by_id AND reviewer.tenant_id = item.tenant_id
        WHERE item.tenant_id = ?
          AND (? IS NULL OR item.session_id = ?)
        ORDER BY item.updated_at DESC, item.title ASC, item.id ASC
        LIMIT ?
        "#,
    )
    .bind(tenant_id)
    .bind(session_id)
    .bind(session_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("SQLite-Evidenzliste konnte nicht gelesen werden")?;

    rows.into_iter()
        .map(evidence_item_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_evidence_needs_postgres(
    pool: &PgPool,
    tenant_id: i64,
    session_id: Option<i64>,
    limit: i64,
) -> anyhow::Result<Vec<RequirementEvidenceNeedSummary>> {
    let rows = sqlx::query(
        r#"
        SELECT
            need.id,
            need.tenant_id,
            need.session_id,
            need.requirement_id,
            req.framework AS requirement_framework,
            req.code AS requirement_code,
            req.title AS requirement_title,
            mv.program_name AS mapping_program_name,
            mv.version AS mapping_version,
            src.authority AS source_authority,
            src.citation AS source_citation,
            src.title AS source_title,
            need.title,
            need.description,
            need.is_mandatory,
            need.status,
            need.rationale,
            need.covered_count,
            need.created_at::text AS created_at,
            need.updated_at::text AS updated_at
        FROM evidence_requirementevidenceneed need
        JOIN requirements_app_requirement req
            ON req.id = need.requirement_id
        LEFT JOIN requirements_app_mappingversion mv
            ON mv.id = req.mapping_version_id
        LEFT JOIN requirements_app_regulatorysource src
            ON src.id = req.primary_source_id
        WHERE need.tenant_id = $1
          AND ($2::bigint IS NULL OR need.session_id = $2)
        ORDER BY need.status ASC, req.framework ASC, req.code ASC, need.id ASC
        LIMIT $3
        "#,
    )
    .bind(tenant_id)
    .bind(session_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("PostgreSQL-Evidenzpflichten konnten nicht gelesen werden")?;

    rows.into_iter()
        .map(evidence_need_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_evidence_needs_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    session_id: Option<i64>,
    limit: i64,
) -> anyhow::Result<Vec<RequirementEvidenceNeedSummary>> {
    let rows = sqlx::query(
        r#"
        SELECT
            need.id,
            need.tenant_id,
            need.session_id,
            need.requirement_id,
            req.framework AS requirement_framework,
            req.code AS requirement_code,
            req.title AS requirement_title,
            mv.program_name AS mapping_program_name,
            mv.version AS mapping_version,
            src.authority AS source_authority,
            src.citation AS source_citation,
            src.title AS source_title,
            need.title,
            need.description,
            need.is_mandatory,
            need.status,
            need.rationale,
            need.covered_count,
            CAST(need.created_at AS TEXT) AS created_at,
            CAST(need.updated_at AS TEXT) AS updated_at
        FROM evidence_requirementevidenceneed need
        JOIN requirements_app_requirement req
            ON req.id = need.requirement_id
        LEFT JOIN requirements_app_mappingversion mv
            ON mv.id = req.mapping_version_id
        LEFT JOIN requirements_app_regulatorysource src
            ON src.id = req.primary_source_id
        WHERE need.tenant_id = ?
          AND (? IS NULL OR need.session_id = ?)
        ORDER BY need.status ASC, req.framework ASC, req.code ASC, need.id ASC
        LIMIT ?
        "#,
    )
    .bind(tenant_id)
    .bind(session_id)
    .bind(session_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("SQLite-Evidenzpflichten konnten nicht gelesen werden")?;

    rows.into_iter()
        .map(evidence_need_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn evidence_need_summary_postgres(
    pool: &PgPool,
    tenant_id: i64,
    session_id: Option<i64>,
) -> anyhow::Result<EvidenceNeedSummary> {
    let row = sqlx::query(
        r#"
        SELECT
            COALESCE(SUM(CASE WHEN status = 'OPEN' THEN 1 ELSE 0 END), 0) AS open_count,
            COALESCE(SUM(CASE WHEN status = 'PARTIAL' THEN 1 ELSE 0 END), 0) AS partial_count,
            COALESCE(SUM(CASE WHEN status = 'COVERED' THEN 1 ELSE 0 END), 0) AS covered_count
        FROM evidence_requirementevidenceneed
        WHERE tenant_id = $1
          AND ($2::bigint IS NULL OR session_id = $2)
        "#,
    )
    .bind(tenant_id)
    .bind(session_id)
    .fetch_one(pool)
    .await
    .context("PostgreSQL-Evidenzpflichten-Summary konnte nicht gelesen werden")?;

    Ok(EvidenceNeedSummary {
        open: row.try_get("open_count")?,
        partial: row.try_get("partial_count")?,
        covered: row.try_get("covered_count")?,
    })
}

async fn evidence_need_summary_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    session_id: Option<i64>,
) -> anyhow::Result<EvidenceNeedSummary> {
    let row = sqlx::query(
        r#"
        SELECT
            COALESCE(SUM(CASE WHEN status = 'OPEN' THEN 1 ELSE 0 END), 0) AS open_count,
            COALESCE(SUM(CASE WHEN status = 'PARTIAL' THEN 1 ELSE 0 END), 0) AS partial_count,
            COALESCE(SUM(CASE WHEN status = 'COVERED' THEN 1 ELSE 0 END), 0) AS covered_count
        FROM evidence_requirementevidenceneed
        WHERE tenant_id = ?
          AND (? IS NULL OR session_id = ?)
        "#,
    )
    .bind(tenant_id)
    .bind(session_id)
    .bind(session_id)
    .fetch_one(pool)
    .await
    .context("SQLite-Evidenzpflichten-Summary konnte nicht gelesen werden")?;

    Ok(EvidenceNeedSummary {
        open: row.try_get("open_count")?,
        partial: row.try_get("partial_count")?,
        covered: row.try_get("covered_count")?,
    })
}

fn evidence_item_from_pg_row(row: PgRow) -> Result<EvidenceItemSummary, sqlx::Error> {
    let status: String = row.try_get("status")?;
    Ok(EvidenceItemSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        session_id: row.try_get("session_id")?,
        domain_id: row.try_get("domain_id")?,
        measure_id: row.try_get("measure_id")?,
        measure_title: row.try_get("measure_title")?,
        requirement_id: row.try_get("requirement_id")?,
        requirement_framework: row.try_get("requirement_framework")?,
        requirement_code: row.try_get("requirement_code")?,
        requirement_title: row.try_get("requirement_title")?,
        mapping_program_name: row.try_get("mapping_program_name")?,
        mapping_version: row.try_get("mapping_version")?,
        source_authority: row.try_get("source_authority")?,
        source_citation: row.try_get("source_citation")?,
        source_title: row.try_get("source_title")?,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        linked_requirement: row.try_get("linked_requirement")?,
        file_name: row.try_get("file_name")?,
        status_label: evidence_status_label(&status).to_string(),
        status,
        owner_id: row.try_get("owner_id")?,
        owner_display: row.try_get("owner_display")?,
        review_notes: row.try_get("review_notes")?,
        reviewed_by_id: row.try_get("reviewed_by_id")?,
        reviewed_by_display: row.try_get("reviewed_by_display")?,
        reviewed_at: row.try_get("reviewed_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn evidence_item_from_sqlite_row(row: SqliteRow) -> Result<EvidenceItemSummary, sqlx::Error> {
    let status: String = row.try_get("status")?;
    Ok(EvidenceItemSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        session_id: row.try_get("session_id")?,
        domain_id: row.try_get("domain_id")?,
        measure_id: row.try_get("measure_id")?,
        measure_title: row.try_get("measure_title")?,
        requirement_id: row.try_get("requirement_id")?,
        requirement_framework: row.try_get("requirement_framework")?,
        requirement_code: row.try_get("requirement_code")?,
        requirement_title: row.try_get("requirement_title")?,
        mapping_program_name: row.try_get("mapping_program_name")?,
        mapping_version: row.try_get("mapping_version")?,
        source_authority: row.try_get("source_authority")?,
        source_citation: row.try_get("source_citation")?,
        source_title: row.try_get("source_title")?,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        linked_requirement: row.try_get("linked_requirement")?,
        file_name: row.try_get("file_name")?,
        status_label: evidence_status_label(&status).to_string(),
        status,
        owner_id: row.try_get("owner_id")?,
        owner_display: row.try_get("owner_display")?,
        review_notes: row.try_get("review_notes")?,
        reviewed_by_id: row.try_get("reviewed_by_id")?,
        reviewed_by_display: row.try_get("reviewed_by_display")?,
        reviewed_at: row.try_get("reviewed_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn evidence_need_from_pg_row(row: PgRow) -> Result<RequirementEvidenceNeedSummary, sqlx::Error> {
    let status: String = row.try_get("status")?;
    Ok(RequirementEvidenceNeedSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        session_id: row.try_get("session_id")?,
        requirement_id: row.try_get("requirement_id")?,
        requirement_framework: row.try_get("requirement_framework")?,
        requirement_code: row.try_get("requirement_code")?,
        requirement_title: row.try_get("requirement_title")?,
        mapping_program_name: row.try_get("mapping_program_name")?,
        mapping_version: row.try_get("mapping_version")?,
        source_authority: row.try_get("source_authority")?,
        source_citation: row.try_get("source_citation")?,
        source_title: row.try_get("source_title")?,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        is_mandatory: row.try_get("is_mandatory")?,
        status_label: evidence_need_status_label(&status).to_string(),
        status,
        rationale: row.try_get("rationale")?,
        covered_count: row.try_get("covered_count")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn evidence_need_from_sqlite_row(
    row: SqliteRow,
) -> Result<RequirementEvidenceNeedSummary, sqlx::Error> {
    let status: String = row.try_get("status")?;
    Ok(RequirementEvidenceNeedSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        session_id: row.try_get("session_id")?,
        requirement_id: row.try_get("requirement_id")?,
        requirement_framework: row.try_get("requirement_framework")?,
        requirement_code: row.try_get("requirement_code")?,
        requirement_title: row.try_get("requirement_title")?,
        mapping_program_name: row.try_get("mapping_program_name")?,
        mapping_version: row.try_get("mapping_version")?,
        source_authority: row.try_get("source_authority")?,
        source_citation: row.try_get("source_citation")?,
        source_title: row.try_get("source_title")?,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        is_mandatory: row.try_get("is_mandatory")?,
        status_label: evidence_need_status_label(&status).to_string(),
        status,
        rationale: row.try_get("rationale")?,
        covered_count: row.try_get("covered_count")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

async fn session_exists_postgres(
    pool: &PgPool,
    tenant_id: i64,
    session_id: i64,
) -> anyhow::Result<bool> {
    let exists: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM wizard_assessmentsession WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(session_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-Assessment-Session konnte nicht validiert werden")?;
    Ok(exists.is_some())
}

async fn session_exists_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    session_id: i64,
) -> anyhow::Result<bool> {
    let exists: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM wizard_assessmentsession WHERE tenant_id = ?1 AND id = ?2",
    )
    .bind(tenant_id)
    .bind(session_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-Assessment-Session konnte nicht validiert werden")?;
    Ok(exists.is_some())
}

async fn tenant_context_postgres(
    pool: &PgPool,
    tenant_id: i64,
) -> anyhow::Result<TenantEvidenceContext> {
    let row = sqlx::query(
        r#"
        SELECT sector, kritis_relevant
        FROM organizations_tenant
        WHERE id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .context("PostgreSQL-Tenant-Kontext fuer Evidence-Sync konnte nicht gelesen werden")?;
    Ok(TenantEvidenceContext {
        sector: row.try_get("sector")?,
        kritis_relevant: row.try_get("kritis_relevant")?,
    })
}

async fn tenant_context_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
) -> anyhow::Result<TenantEvidenceContext> {
    let row = sqlx::query(
        r#"
        SELECT sector, kritis_relevant
        FROM organizations_tenant
        WHERE id = ?1
        "#,
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .context("SQLite-Tenant-Kontext fuer Evidence-Sync konnte nicht gelesen werden")?;
    Ok(TenantEvidenceContext {
        sector: row.try_get("sector")?,
        kritis_relevant: row.try_get("kritis_relevant")?,
    })
}

async fn sync_requirements_postgres(pool: &PgPool) -> anyhow::Result<Vec<RequirementSyncSource>> {
    let rows = sqlx::query(sync_requirements_postgres_sql())
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Requirements fuer Evidence-Sync konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(sync_requirement_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn sync_requirements_sqlite(pool: &SqlitePool) -> anyhow::Result<Vec<RequirementSyncSource>> {
    let rows = sqlx::query(sync_requirements_sqlite_sql())
        .fetch_all(pool)
        .await
        .context("SQLite-Requirements fuer Evidence-Sync konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(sync_requirement_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn evidence_count_for_requirement_postgres(
    pool: &PgPool,
    tenant_id: i64,
    requirement_id: i64,
) -> anyhow::Result<i64> {
    sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM evidence_evidenceitem WHERE tenant_id = $1 AND requirement_id = $2",
    )
    .bind(tenant_id)
    .bind(requirement_id)
    .fetch_one(pool)
    .await
    .context("PostgreSQL-Evidence-Coverage konnte nicht gezaehlt werden")
}

async fn evidence_count_for_requirement_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    requirement_id: i64,
) -> anyhow::Result<i64> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM evidence_evidenceitem WHERE tenant_id = ?1 AND requirement_id = ?2",
    )
    .bind(tenant_id)
    .bind(requirement_id)
    .fetch_one(pool)
    .await
    .context("SQLite-Evidence-Coverage konnte nicht gezaehlt werden")
}

async fn existing_need_id_postgres(
    pool: &PgPool,
    tenant_id: i64,
    session_id: i64,
    requirement_id: i64,
) -> anyhow::Result<Option<i64>> {
    sqlx::query_scalar(
        r#"
        SELECT id
        FROM evidence_requirementevidenceneed
        WHERE tenant_id = $1 AND session_id = $2 AND requirement_id = $3
        "#,
    )
    .bind(tenant_id)
    .bind(session_id)
    .bind(requirement_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-Evidenzpflicht konnte nicht gesucht werden")
}

async fn existing_need_id_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    session_id: i64,
    requirement_id: i64,
) -> anyhow::Result<Option<i64>> {
    sqlx::query_scalar(
        r#"
        SELECT id
        FROM evidence_requirementevidenceneed
        WHERE tenant_id = ?1 AND session_id = ?2 AND requirement_id = ?3
        "#,
    )
    .bind(tenant_id)
    .bind(session_id)
    .bind(requirement_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-Evidenzpflicht konnte nicht gesucht werden")
}

fn sync_requirement_from_pg_row(row: PgRow) -> Result<RequirementSyncSource, sqlx::Error> {
    Ok(RequirementSyncSource {
        id: row.try_get("id")?,
        framework: row.try_get("framework")?,
        code: row.try_get("code")?,
        description: row.try_get("description")?,
        evidence_required: row.try_get("evidence_required")?,
        evidence_guidance: row.try_get("evidence_guidance")?,
        evidence_examples: row.try_get("evidence_examples")?,
        sector_package: row.try_get("sector_package")?,
        legal_reference: row.try_get("legal_reference")?,
        mapping_program_name: row.try_get("mapping_program_name")?,
        mapping_version: row.try_get("mapping_version")?,
        source_authority: row.try_get("source_authority")?,
        source_citation: row.try_get("source_citation")?,
        source_title: row.try_get("source_title")?,
        source_url: row.try_get("source_url")?,
    })
}

fn sync_requirement_from_sqlite_row(row: SqliteRow) -> Result<RequirementSyncSource, sqlx::Error> {
    Ok(RequirementSyncSource {
        id: row.try_get("id")?,
        framework: row.try_get("framework")?,
        code: row.try_get("code")?,
        description: row.try_get("description")?,
        evidence_required: row.try_get("evidence_required")?,
        evidence_guidance: row.try_get("evidence_guidance")?,
        evidence_examples: row.try_get("evidence_examples")?,
        sector_package: row.try_get("sector_package")?,
        legal_reference: row.try_get("legal_reference")?,
        mapping_program_name: row.try_get("mapping_program_name")?,
        mapping_version: row.try_get("mapping_version")?,
        source_authority: row.try_get("source_authority")?,
        source_citation: row.try_get("source_citation")?,
        source_title: row.try_get("source_title")?,
        source_url: row.try_get("source_url")?,
    })
}

fn sync_requirements_postgres_sql() -> &'static str {
    r#"
    SELECT
        req.id,
        req.framework,
        req.code,
        req.description,
        req.evidence_required,
        req.evidence_guidance,
        req.evidence_examples,
        req.sector_package,
        req.legal_reference,
        mv.program_name AS mapping_program_name,
        mv.version AS mapping_version,
        src.authority AS source_authority,
        src.citation AS source_citation,
        src.title AS source_title,
        src.url AS source_url
    FROM requirements_app_requirement req
    LEFT JOIN requirements_app_mappingversion mv
        ON mv.id = req.mapping_version_id
    LEFT JOIN requirements_app_regulatorysource src
        ON src.id = req.primary_source_id
    WHERE req.is_active = TRUE
    ORDER BY req.framework ASC, req.code ASC
    "#
}

fn sync_requirements_sqlite_sql() -> &'static str {
    r#"
    SELECT
        req.id,
        req.framework,
        req.code,
        req.description,
        req.evidence_required,
        req.evidence_guidance,
        req.evidence_examples,
        req.sector_package,
        req.legal_reference,
        mv.program_name AS mapping_program_name,
        mv.version AS mapping_version,
        src.authority AS source_authority,
        src.citation AS source_citation,
        src.title AS source_title,
        src.url AS source_url
    FROM requirements_app_requirement req
    LEFT JOIN requirements_app_mappingversion mv
        ON mv.id = req.mapping_version_id
    LEFT JOIN requirements_app_regulatorysource src
        ON src.id = req.primary_source_id
    WHERE req.is_active = 1
    ORDER BY req.framework ASC, req.code ASC
    "#
}

fn requirement_relevant(
    requirement: &RequirementSyncSource,
    tenant_context: &TenantEvidenceContext,
) -> bool {
    let package = requirement.sector_package.trim().to_ascii_uppercase();
    if package.is_empty() || package == "ALL" {
        return true;
    }

    sector_packages(&tenant_context.sector, tenant_context.kritis_relevant).contains(&package)
}

fn sector_packages(sector: &str, kritis_relevant: bool) -> Vec<String> {
    let sector = sector.trim().to_ascii_uppercase();
    let mut packages = vec!["ALL".to_string()];
    if matches!(
        sector.as_str(),
        "DIGITAL_PROVIDERS" | "DIGITAL_INFRASTRUCTURE" | "ICT_SERVICE_MANAGEMENT" | "MSSP"
    ) {
        packages.push("DIGITAL".to_string());
    }
    if matches!(
        sector.as_str(),
        "BANKING" | "FINANCIAL_MARKET_INFRASTRUCTURE"
    ) {
        packages.push("FINANCE".to_string());
    }
    if kritis_relevant
        || matches!(
            sector.as_str(),
            "ENERGY"
                | "HYDROGEN"
                | "TRANSPORT"
                | "HEALTH"
                | "DRINKING_WATER"
                | "WASTEWATER"
                | "PUBLIC_ADMINISTRATION"
        )
    {
        packages.push("CRITICAL_INFRA".to_string());
    }
    packages
}

fn normalize_threshold(value: Option<i64>, default: i64) -> i64 {
    value.filter(|item| *item > 0).unwrap_or(default)
}

fn need_status_for_count(
    count: i64,
    covered_threshold: i64,
    partial_threshold: i64,
) -> &'static str {
    if count >= covered_threshold {
        "COVERED"
    } else if count >= partial_threshold {
        "PARTIAL"
    } else {
        "OPEN"
    }
}

fn requirement_description(requirement: &RequirementSyncSource) -> String {
    let mut parts = Vec::new();
    let primary = if requirement.evidence_guidance.trim().is_empty() {
        requirement.description.trim()
    } else {
        requirement.evidence_guidance.trim()
    };
    if !primary.is_empty() {
        parts.push(primary.to_string());
    }
    if let (Some(program_name), Some(version)) = (
        non_empty_option(requirement.mapping_program_name.as_deref()),
        non_empty_option(requirement.mapping_version.as_deref()),
    ) {
        parts.push(format!(
            "Mapping-Version: {} {} v{}",
            program_name, requirement.framework, version
        ));
    }
    if let Some(authority) = non_empty_option(requirement.source_authority.as_deref()) {
        let citation = non_empty_option(requirement.source_citation.as_deref())
            .or_else(|| non_empty_option(requirement.source_title.as_deref()));
        if let Some(citation) = citation {
            parts.push(format!("Quelle: {} - {}", authority, citation));
        }
    }
    parts.join(" | ")
}

fn requirement_rationale(requirement: &RequirementSyncSource) -> String {
    let mut parts = Vec::new();
    if requirement.evidence_examples.trim().is_empty() {
        parts.push(
            "Evidenzen, Richtlinien, Screenshots, Freigaben oder Prüfprotokolle hinterlegen."
                .to_string(),
        );
    } else {
        parts.push(requirement.evidence_examples.trim().to_string());
    }
    if !requirement.legal_reference.trim().is_empty() {
        parts.push(format!("Referenz: {}", requirement.legal_reference.trim()));
    }
    if let Some(url) = non_empty_option(requirement.source_url.as_deref()) {
        parts.push(format!("Quelle: {}", url));
    }
    parts.join(" | ")
}

fn non_empty_option(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn evidence_status_label(value: &str) -> &'static str {
    match value {
        "DRAFT" => "Entwurf",
        "SUBMITTED" => "Zur Prüfung eingereicht",
        "APPROVED" => "Freigegeben",
        "REJECTED" => "Abgelehnt",
        _ => "Entwurf",
    }
}

fn evidence_need_status_label(value: &str) -> &'static str {
    match value {
        "OPEN" => "Offen",
        "PARTIAL" => "Teilweise abgedeckt",
        "COVERED" => "Abgedeckt",
        _ => "Offen",
    }
}
