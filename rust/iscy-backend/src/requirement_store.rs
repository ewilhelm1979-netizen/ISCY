use anyhow::{bail, Context};
use serde::Serialize;
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Row,
};

use crate::cve_store::normalize_database_url;

#[derive(Clone)]
pub enum RequirementStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Serialize)]
pub struct MappingVersionSummary {
    pub id: i64,
    pub framework: String,
    pub slug: String,
    pub title: String,
    pub version: String,
    pub program_name: String,
    pub status: String,
    pub status_label: String,
    pub effective_on: Option<String>,
    pub notes: String,
    pub source_count: i64,
    pub requirement_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegulatorySourceRef {
    pub id: i64,
    pub framework: String,
    pub code: String,
    pub title: String,
    pub authority: String,
    pub citation: String,
    pub url: String,
    pub source_type: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequirementSummary {
    pub id: i64,
    pub framework: String,
    pub framework_label: String,
    pub code: String,
    pub title: String,
    pub domain: String,
    pub description: String,
    pub guidance: String,
    pub is_active: bool,
    pub evidence_required: bool,
    pub evidence_guidance: String,
    pub evidence_examples: String,
    pub sector_package: String,
    pub legal_reference: String,
    pub coverage_level: String,
    pub coverage_level_label: String,
    pub mapping_version: Option<MappingVersionSummary>,
    pub primary_source: Option<RegulatorySourceRef>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequirementLibrary {
    pub requirements: Vec<RequirementSummary>,
    pub mapping_versions: Vec<MappingVersionSummary>,
}

impl RequirementStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Requirement-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Requirement-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-Requirement-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn library(&self, limit: i64) -> anyhow::Result<RequirementLibrary> {
        match self {
            Self::Postgres(pool) => library_postgres(pool, limit).await,
            Self::Sqlite(pool) => library_sqlite(pool, limit).await,
        }
    }
}

async fn library_postgres(pool: &PgPool, limit: i64) -> anyhow::Result<RequirementLibrary> {
    let requirements = sqlx::query(requirements_postgres_sql())
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Requirements konnten nicht gelesen werden")?
        .into_iter()
        .map(requirement_from_pg_row)
        .collect::<Result<Vec<_>, _>>()?;
    let mapping_versions = sqlx::query(mapping_versions_postgres_sql())
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Mapping-Versionen konnten nicht gelesen werden")?
        .into_iter()
        .map(mapping_version_from_pg_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RequirementLibrary {
        requirements,
        mapping_versions,
    })
}

async fn library_sqlite(pool: &SqlitePool, limit: i64) -> anyhow::Result<RequirementLibrary> {
    let requirements = sqlx::query(requirements_sqlite_sql())
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("SQLite-Requirements konnten nicht gelesen werden")?
        .into_iter()
        .map(requirement_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()?;
    let mapping_versions = sqlx::query(mapping_versions_sqlite_sql())
        .fetch_all(pool)
        .await
        .context("SQLite-Mapping-Versionen konnten nicht gelesen werden")?
        .into_iter()
        .map(mapping_version_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RequirementLibrary {
        requirements,
        mapping_versions,
    })
}

fn requirement_from_pg_row(row: PgRow) -> Result<RequirementSummary, sqlx::Error> {
    let framework: String = row.try_get("framework")?;
    let coverage_level: String = row.try_get("coverage_level")?;
    Ok(RequirementSummary {
        id: row.try_get("id")?,
        framework_label: framework_label(&framework).to_string(),
        framework,
        code: row.try_get("code")?,
        title: row.try_get("title")?,
        domain: row.try_get("domain")?,
        description: row.try_get("description")?,
        guidance: row.try_get("guidance")?,
        is_active: row.try_get("is_active")?,
        evidence_required: row.try_get("evidence_required")?,
        evidence_guidance: row.try_get("evidence_guidance")?,
        evidence_examples: row.try_get("evidence_examples")?,
        sector_package: row.try_get("sector_package")?,
        legal_reference: row.try_get("legal_reference")?,
        coverage_level_label: coverage_level_label(&coverage_level).to_string(),
        coverage_level,
        mapping_version: mapping_version_from_prefixed_pg_row(&row)?,
        primary_source: regulatory_source_from_pg_row(&row)?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn requirement_from_sqlite_row(row: SqliteRow) -> Result<RequirementSummary, sqlx::Error> {
    let framework: String = row.try_get("framework")?;
    let coverage_level: String = row.try_get("coverage_level")?;
    Ok(RequirementSummary {
        id: row.try_get("id")?,
        framework_label: framework_label(&framework).to_string(),
        framework,
        code: row.try_get("code")?,
        title: row.try_get("title")?,
        domain: row.try_get("domain")?,
        description: row.try_get("description")?,
        guidance: row.try_get("guidance")?,
        is_active: row.try_get("is_active")?,
        evidence_required: row.try_get("evidence_required")?,
        evidence_guidance: row.try_get("evidence_guidance")?,
        evidence_examples: row.try_get("evidence_examples")?,
        sector_package: row.try_get("sector_package")?,
        legal_reference: row.try_get("legal_reference")?,
        coverage_level_label: coverage_level_label(&coverage_level).to_string(),
        coverage_level,
        mapping_version: mapping_version_from_prefixed_sqlite_row(&row)?,
        primary_source: regulatory_source_from_sqlite_row(&row)?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn mapping_version_from_prefixed_pg_row(
    row: &PgRow,
) -> Result<Option<MappingVersionSummary>, sqlx::Error> {
    let id: Option<i64> = row.try_get("mapping_version_id")?;
    Ok(id.map(|id| {
        let status: String = row.try_get("mapping_version_status").unwrap_or_default();
        MappingVersionSummary {
            id,
            framework: row.try_get("mapping_version_framework").unwrap_or_default(),
            slug: row.try_get("mapping_version_slug").unwrap_or_default(),
            title: row.try_get("mapping_version_title").unwrap_or_default(),
            version: row.try_get("mapping_version_version").unwrap_or_default(),
            program_name: row
                .try_get("mapping_version_program_name")
                .unwrap_or_default(),
            status_label: mapping_status_label(&status).to_string(),
            status,
            effective_on: row.try_get("mapping_version_effective_on").unwrap_or(None),
            notes: row.try_get("mapping_version_notes").unwrap_or_default(),
            source_count: row.try_get("mapping_version_source_count").unwrap_or(0),
            requirement_count: row
                .try_get("mapping_version_requirement_count")
                .unwrap_or(0),
            created_at: row
                .try_get("mapping_version_created_at")
                .unwrap_or_default(),
            updated_at: row
                .try_get("mapping_version_updated_at")
                .unwrap_or_default(),
        }
    }))
}

fn mapping_version_from_prefixed_sqlite_row(
    row: &SqliteRow,
) -> Result<Option<MappingVersionSummary>, sqlx::Error> {
    let id: Option<i64> = row.try_get("mapping_version_id")?;
    Ok(id.map(|id| {
        let status: String = row.try_get("mapping_version_status").unwrap_or_default();
        MappingVersionSummary {
            id,
            framework: row.try_get("mapping_version_framework").unwrap_or_default(),
            slug: row.try_get("mapping_version_slug").unwrap_or_default(),
            title: row.try_get("mapping_version_title").unwrap_or_default(),
            version: row.try_get("mapping_version_version").unwrap_or_default(),
            program_name: row
                .try_get("mapping_version_program_name")
                .unwrap_or_default(),
            status_label: mapping_status_label(&status).to_string(),
            status,
            effective_on: row.try_get("mapping_version_effective_on").unwrap_or(None),
            notes: row.try_get("mapping_version_notes").unwrap_or_default(),
            source_count: row.try_get("mapping_version_source_count").unwrap_or(0),
            requirement_count: row
                .try_get("mapping_version_requirement_count")
                .unwrap_or(0),
            created_at: row
                .try_get("mapping_version_created_at")
                .unwrap_or_default(),
            updated_at: row
                .try_get("mapping_version_updated_at")
                .unwrap_or_default(),
        }
    }))
}

fn regulatory_source_from_pg_row(row: &PgRow) -> Result<Option<RegulatorySourceRef>, sqlx::Error> {
    let id: Option<i64> = row.try_get("source_id")?;
    Ok(id.map(|id| RegulatorySourceRef {
        id,
        framework: row.try_get("source_framework").unwrap_or_default(),
        code: row.try_get("source_code").unwrap_or_default(),
        title: row.try_get("source_title").unwrap_or_default(),
        authority: row.try_get("source_authority").unwrap_or_default(),
        citation: row.try_get("source_citation").unwrap_or_default(),
        url: row.try_get("source_url").unwrap_or_default(),
        source_type: row.try_get("source_type").unwrap_or_default(),
    }))
}

fn regulatory_source_from_sqlite_row(
    row: &SqliteRow,
) -> Result<Option<RegulatorySourceRef>, sqlx::Error> {
    let id: Option<i64> = row.try_get("source_id")?;
    Ok(id.map(|id| RegulatorySourceRef {
        id,
        framework: row.try_get("source_framework").unwrap_or_default(),
        code: row.try_get("source_code").unwrap_or_default(),
        title: row.try_get("source_title").unwrap_or_default(),
        authority: row.try_get("source_authority").unwrap_or_default(),
        citation: row.try_get("source_citation").unwrap_or_default(),
        url: row.try_get("source_url").unwrap_or_default(),
        source_type: row.try_get("source_type").unwrap_or_default(),
    }))
}

fn mapping_version_from_pg_row(row: PgRow) -> Result<MappingVersionSummary, sqlx::Error> {
    let status: String = row.try_get("status")?;
    Ok(MappingVersionSummary {
        id: row.try_get("id")?,
        framework: row.try_get("framework")?,
        slug: row.try_get("slug")?,
        title: row.try_get("title")?,
        version: row.try_get("version")?,
        program_name: row.try_get("program_name")?,
        status_label: mapping_status_label(&status).to_string(),
        status,
        effective_on: row.try_get("effective_on")?,
        notes: row.try_get("notes")?,
        source_count: row.try_get("source_count")?,
        requirement_count: row.try_get("requirement_count")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn mapping_version_from_sqlite_row(row: SqliteRow) -> Result<MappingVersionSummary, sqlx::Error> {
    let status: String = row.try_get("status")?;
    Ok(MappingVersionSummary {
        id: row.try_get("id")?,
        framework: row.try_get("framework")?,
        slug: row.try_get("slug")?,
        title: row.try_get("title")?,
        version: row.try_get("version")?,
        program_name: row.try_get("program_name")?,
        status_label: mapping_status_label(&status).to_string(),
        status,
        effective_on: row.try_get("effective_on")?,
        notes: row.try_get("notes")?,
        source_count: row.try_get("source_count")?,
        requirement_count: row.try_get("requirement_count")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn requirements_postgres_sql() -> &'static str {
    r#"
    SELECT
        req.id,
        req.framework,
        req.code,
        req.title,
        req.domain,
        req.description,
        req.guidance,
        req.is_active,
        req.evidence_required,
        req.evidence_guidance,
        req.evidence_examples,
        req.sector_package,
        req.legal_reference,
        req.coverage_level,
        req.created_at::text AS created_at,
        req.updated_at::text AS updated_at,
        version.id AS mapping_version_id,
        version.framework AS mapping_version_framework,
        version.slug AS mapping_version_slug,
        version.title AS mapping_version_title,
        version.version AS mapping_version_version,
        version.program_name AS mapping_version_program_name,
        version.status AS mapping_version_status,
        version.effective_on::text AS mapping_version_effective_on,
        version.notes AS mapping_version_notes,
        version.created_at::text AS mapping_version_created_at,
        version.updated_at::text AS mapping_version_updated_at,
        (
            SELECT COUNT(*)::bigint
            FROM requirements_app_regulatorysource source_count
            WHERE source_count.mapping_version_id = version.id
        ) AS mapping_version_source_count,
        (
            SELECT COUNT(*)::bigint
            FROM requirements_app_requirement req_count
            WHERE req_count.mapping_version_id = version.id
        ) AS mapping_version_requirement_count,
        source.id AS source_id,
        source.framework AS source_framework,
        source.code AS source_code,
        source.title AS source_title,
        source.authority AS source_authority,
        source.citation AS source_citation,
        source.url AS source_url,
        source.source_type AS source_type
    FROM requirements_app_requirement req
    LEFT JOIN requirements_app_mappingversion version ON version.id = req.mapping_version_id
    LEFT JOIN requirements_app_regulatorysource source ON source.id = req.primary_source_id
    ORDER BY req.framework ASC, req.code ASC
    LIMIT $1
    "#
}

fn requirements_sqlite_sql() -> &'static str {
    r#"
    SELECT
        req.id,
        req.framework,
        req.code,
        req.title,
        req.domain,
        req.description,
        req.guidance,
        req.is_active,
        req.evidence_required,
        req.evidence_guidance,
        req.evidence_examples,
        req.sector_package,
        req.legal_reference,
        req.coverage_level,
        CAST(req.created_at AS TEXT) AS created_at,
        CAST(req.updated_at AS TEXT) AS updated_at,
        version.id AS mapping_version_id,
        version.framework AS mapping_version_framework,
        version.slug AS mapping_version_slug,
        version.title AS mapping_version_title,
        version.version AS mapping_version_version,
        version.program_name AS mapping_version_program_name,
        version.status AS mapping_version_status,
        CAST(version.effective_on AS TEXT) AS mapping_version_effective_on,
        version.notes AS mapping_version_notes,
        CAST(version.created_at AS TEXT) AS mapping_version_created_at,
        CAST(version.updated_at AS TEXT) AS mapping_version_updated_at,
        (
            SELECT COUNT(*)
            FROM requirements_app_regulatorysource source_count
            WHERE source_count.mapping_version_id = version.id
        ) AS mapping_version_source_count,
        (
            SELECT COUNT(*)
            FROM requirements_app_requirement req_count
            WHERE req_count.mapping_version_id = version.id
        ) AS mapping_version_requirement_count,
        source.id AS source_id,
        source.framework AS source_framework,
        source.code AS source_code,
        source.title AS source_title,
        source.authority AS source_authority,
        source.citation AS source_citation,
        source.url AS source_url,
        source.source_type AS source_type
    FROM requirements_app_requirement req
    LEFT JOIN requirements_app_mappingversion version ON version.id = req.mapping_version_id
    LEFT JOIN requirements_app_regulatorysource source ON source.id = req.primary_source_id
    ORDER BY req.framework ASC, req.code ASC
    LIMIT ?
    "#
}

fn mapping_versions_postgres_sql() -> &'static str {
    r#"
    SELECT
        version.id,
        version.framework,
        version.slug,
        version.title,
        version.version,
        version.program_name,
        version.status,
        version.effective_on::text AS effective_on,
        version.notes,
        COUNT(DISTINCT source.id)::bigint AS source_count,
        COUNT(DISTINCT req.id)::bigint AS requirement_count,
        version.created_at::text AS created_at,
        version.updated_at::text AS updated_at
    FROM requirements_app_mappingversion version
    LEFT JOIN requirements_app_regulatorysource source ON source.mapping_version_id = version.id
    LEFT JOIN requirements_app_requirement req ON req.mapping_version_id = version.id
    WHERE version.status = 'ACTIVE'
    GROUP BY
        version.id,
        version.framework,
        version.slug,
        version.title,
        version.version,
        version.program_name,
        version.status,
        version.effective_on,
        version.notes,
        version.created_at,
        version.updated_at
    ORDER BY version.framework ASC, version.effective_on DESC NULLS LAST, version.created_at DESC
    "#
}

fn mapping_versions_sqlite_sql() -> &'static str {
    r#"
    SELECT
        version.id,
        version.framework,
        version.slug,
        version.title,
        version.version,
        version.program_name,
        version.status,
        CAST(version.effective_on AS TEXT) AS effective_on,
        version.notes,
        COUNT(DISTINCT source.id) AS source_count,
        COUNT(DISTINCT req.id) AS requirement_count,
        CAST(version.created_at AS TEXT) AS created_at,
        CAST(version.updated_at AS TEXT) AS updated_at
    FROM requirements_app_mappingversion version
    LEFT JOIN requirements_app_regulatorysource source ON source.mapping_version_id = version.id
    LEFT JOIN requirements_app_requirement req ON req.mapping_version_id = version.id
    WHERE version.status = 'ACTIVE'
    GROUP BY
        version.id,
        version.framework,
        version.slug,
        version.title,
        version.version,
        version.program_name,
        version.status,
        version.effective_on,
        version.notes,
        version.created_at,
        version.updated_at
    ORDER BY version.framework ASC, version.effective_on DESC, version.created_at DESC
    "#
}

fn framework_label(value: &str) -> &'static str {
    match value {
        "ISO27001" => "ISO 27001",
        "NIS2" => "NIS2",
        "KRITIS" => "KRITIS",
        "CRA" => "Cyber Resilience Act",
        "AI_ACT" => "EU AI Act",
        "IEC62443" => "IEC 62443",
        "ISO_SAE_21434" => "ISO/SAE 21434",
        _ => "Unbekannt",
    }
}

fn coverage_level_label(value: &str) -> &'static str {
    match value {
        "PRIMARY" => "Primaer",
        "SUPPORTING" => "Unterstuetzend",
        "DERIVED" => "Abgeleitet",
        _ => "Unbekannt",
    }
}

fn mapping_status_label(value: &str) -> &'static str {
    match value {
        "DRAFT" => "Entwurf",
        "ACTIVE" => "Aktiv",
        "SUPERSEDED" => "Ersetzt",
        _ => "Unbekannt",
    }
}
