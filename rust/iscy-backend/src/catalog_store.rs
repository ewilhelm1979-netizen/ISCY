use anyhow::{bail, Context};
use serde::Serialize;
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Row,
};

use crate::cve_store::normalize_database_url;

#[derive(Clone)]
pub enum CatalogStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Serialize)]
pub struct AssessmentDomainDetail {
    pub id: i64,
    pub code: String,
    pub name: String,
    pub description: String,
    pub weight: i64,
    pub sort_order: i64,
    pub question_count: i64,
    pub questions: Vec<AssessmentQuestionSummary>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AssessmentQuestionSummary {
    pub id: i64,
    pub domain_id: Option<i64>,
    pub code: String,
    pub text: String,
    pub help_text: String,
    pub why_it_matters: String,
    pub question_kind: String,
    pub question_kind_label: String,
    pub wizard_step: String,
    pub wizard_step_label: String,
    pub weight: i64,
    pub is_required: bool,
    pub applies_to_iso27001: bool,
    pub applies_to_nis2: bool,
    pub applies_to_cra: bool,
    pub applies_to_ai_act: bool,
    pub applies_to_iec62443: bool,
    pub applies_to_iso_sae_21434: bool,
    pub applies_to_product_security: bool,
    pub sort_order: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CatalogDomainLibrary {
    pub question_count: i64,
    pub domains: Vec<AssessmentDomainDetail>,
}

impl CatalogStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Catalog-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Catalog-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-Catalog-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn domain_library(&self) -> anyhow::Result<CatalogDomainLibrary> {
        match self {
            Self::Postgres(pool) => domain_library_postgres(pool).await,
            Self::Sqlite(pool) => domain_library_sqlite(pool).await,
        }
    }
}

async fn domain_library_postgres(pool: &PgPool) -> anyhow::Result<CatalogDomainLibrary> {
    let mut domains = sqlx::query(domains_postgres_sql())
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Domainliste konnte nicht gelesen werden")?
        .into_iter()
        .map(domain_from_pg_row)
        .collect::<Result<Vec<_>, _>>()?;

    let questions = sqlx::query(questions_postgres_sql())
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Fragenliste konnte nicht gelesen werden")?
        .into_iter()
        .map(question_from_pg_row)
        .collect::<Result<Vec<_>, _>>()?;
    attach_questions(&mut domains, questions);

    let question_count =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::bigint FROM catalog_assessmentquestion")
            .fetch_one(pool)
            .await
            .context("PostgreSQL-Fragenzaehler konnte nicht gelesen werden")?;

    Ok(CatalogDomainLibrary {
        question_count,
        domains,
    })
}

async fn domain_library_sqlite(pool: &SqlitePool) -> anyhow::Result<CatalogDomainLibrary> {
    let mut domains = sqlx::query(domains_sqlite_sql())
        .fetch_all(pool)
        .await
        .context("SQLite-Domainliste konnte nicht gelesen werden")?
        .into_iter()
        .map(domain_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()?;

    let questions = sqlx::query(questions_sqlite_sql())
        .fetch_all(pool)
        .await
        .context("SQLite-Fragenliste konnte nicht gelesen werden")?
        .into_iter()
        .map(question_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()?;
    attach_questions(&mut domains, questions);

    let question_count =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM catalog_assessmentquestion")
            .fetch_one(pool)
            .await
            .context("SQLite-Fragenzaehler konnte nicht gelesen werden")?;

    Ok(CatalogDomainLibrary {
        question_count,
        domains,
    })
}

fn attach_questions(
    domains: &mut [AssessmentDomainDetail],
    questions: Vec<AssessmentQuestionSummary>,
) {
    for question in questions {
        if let Some(domain_id) = question.domain_id {
            if let Some(domain) = domains.iter_mut().find(|domain| domain.id == domain_id) {
                domain.questions.push(question);
            }
        }
    }
}

fn domain_from_pg_row(row: PgRow) -> Result<AssessmentDomainDetail, sqlx::Error> {
    Ok(AssessmentDomainDetail {
        id: row.try_get("id")?,
        code: row.try_get("code")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        weight: row.try_get("weight")?,
        sort_order: row.try_get("sort_order")?,
        question_count: row.try_get("question_count")?,
        questions: Vec::new(),
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn domain_from_sqlite_row(row: SqliteRow) -> Result<AssessmentDomainDetail, sqlx::Error> {
    Ok(AssessmentDomainDetail {
        id: row.try_get("id")?,
        code: row.try_get("code")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        weight: row.try_get("weight")?,
        sort_order: row.try_get("sort_order")?,
        question_count: row.try_get("question_count")?,
        questions: Vec::new(),
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn question_from_pg_row(row: PgRow) -> Result<AssessmentQuestionSummary, sqlx::Error> {
    let question_kind: String = row.try_get("question_kind")?;
    let wizard_step: String = row.try_get("wizard_step")?;
    Ok(AssessmentQuestionSummary {
        id: row.try_get("id")?,
        domain_id: row.try_get("domain_id")?,
        code: row.try_get("code")?,
        text: row.try_get("text")?,
        help_text: row.try_get("help_text")?,
        why_it_matters: row.try_get("why_it_matters")?,
        question_kind_label: question_kind_label(&question_kind).to_string(),
        question_kind,
        wizard_step_label: wizard_step_label(&wizard_step).to_string(),
        wizard_step,
        weight: row.try_get("weight")?,
        is_required: row.try_get("is_required")?,
        applies_to_iso27001: row.try_get("applies_to_iso27001")?,
        applies_to_nis2: row.try_get("applies_to_nis2")?,
        applies_to_cra: row.try_get("applies_to_cra")?,
        applies_to_ai_act: row.try_get("applies_to_ai_act")?,
        applies_to_iec62443: row.try_get("applies_to_iec62443")?,
        applies_to_iso_sae_21434: row.try_get("applies_to_iso_sae_21434")?,
        applies_to_product_security: row.try_get("applies_to_product_security")?,
        sort_order: row.try_get("sort_order")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn question_from_sqlite_row(row: SqliteRow) -> Result<AssessmentQuestionSummary, sqlx::Error> {
    let question_kind: String = row.try_get("question_kind")?;
    let wizard_step: String = row.try_get("wizard_step")?;
    Ok(AssessmentQuestionSummary {
        id: row.try_get("id")?,
        domain_id: row.try_get("domain_id")?,
        code: row.try_get("code")?,
        text: row.try_get("text")?,
        help_text: row.try_get("help_text")?,
        why_it_matters: row.try_get("why_it_matters")?,
        question_kind_label: question_kind_label(&question_kind).to_string(),
        question_kind,
        wizard_step_label: wizard_step_label(&wizard_step).to_string(),
        wizard_step,
        weight: row.try_get("weight")?,
        is_required: row.try_get("is_required")?,
        applies_to_iso27001: row.try_get("applies_to_iso27001")?,
        applies_to_nis2: row.try_get("applies_to_nis2")?,
        applies_to_cra: row.try_get("applies_to_cra")?,
        applies_to_ai_act: row.try_get("applies_to_ai_act")?,
        applies_to_iec62443: row.try_get("applies_to_iec62443")?,
        applies_to_iso_sae_21434: row.try_get("applies_to_iso_sae_21434")?,
        applies_to_product_security: row.try_get("applies_to_product_security")?,
        sort_order: row.try_get("sort_order")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn domains_postgres_sql() -> &'static str {
    r#"
    SELECT
        domain.id,
        domain.code,
        domain.name,
        domain.description,
        domain.weight::bigint AS weight,
        domain.sort_order::bigint AS sort_order,
        COUNT(question.id)::bigint AS question_count,
        domain.created_at::text AS created_at,
        domain.updated_at::text AS updated_at
    FROM catalog_assessmentdomain domain
    LEFT JOIN catalog_assessmentquestion question ON question.domain_id = domain.id
    GROUP BY
        domain.id,
        domain.code,
        domain.name,
        domain.description,
        domain.weight,
        domain.sort_order,
        domain.created_at,
        domain.updated_at
    ORDER BY domain.sort_order ASC, domain.name ASC
    "#
}

fn domains_sqlite_sql() -> &'static str {
    r#"
    SELECT
        domain.id,
        domain.code,
        domain.name,
        domain.description,
        domain.weight,
        domain.sort_order,
        COUNT(question.id) AS question_count,
        CAST(domain.created_at AS TEXT) AS created_at,
        CAST(domain.updated_at AS TEXT) AS updated_at
    FROM catalog_assessmentdomain domain
    LEFT JOIN catalog_assessmentquestion question ON question.domain_id = domain.id
    GROUP BY
        domain.id,
        domain.code,
        domain.name,
        domain.description,
        domain.weight,
        domain.sort_order,
        domain.created_at,
        domain.updated_at
    ORDER BY domain.sort_order ASC, domain.name ASC
    "#
}

fn questions_postgres_sql() -> &'static str {
    r#"
    SELECT
        question.id,
        question.domain_id,
        question.code,
        question.text,
        question.help_text,
        question.why_it_matters,
        question.question_kind,
        question.wizard_step,
        question.weight::bigint AS weight,
        question.is_required,
        question.applies_to_iso27001,
        question.applies_to_nis2,
        question.applies_to_cra,
        question.applies_to_ai_act,
        question.applies_to_iec62443,
        question.applies_to_iso_sae_21434,
        question.applies_to_product_security,
        question.sort_order::bigint AS sort_order,
        question.created_at::text AS created_at,
        question.updated_at::text AS updated_at
    FROM catalog_assessmentquestion question
    ORDER BY question.wizard_step ASC, question.sort_order ASC, question.code ASC
    "#
}

fn questions_sqlite_sql() -> &'static str {
    r#"
    SELECT
        question.id,
        question.domain_id,
        question.code,
        question.text,
        question.help_text,
        question.why_it_matters,
        question.question_kind,
        question.wizard_step,
        question.weight,
        question.is_required,
        question.applies_to_iso27001,
        question.applies_to_nis2,
        question.applies_to_cra,
        question.applies_to_ai_act,
        question.applies_to_iec62443,
        question.applies_to_iso_sae_21434,
        question.applies_to_product_security,
        question.sort_order,
        CAST(question.created_at AS TEXT) AS created_at,
        CAST(question.updated_at AS TEXT) AS updated_at
    FROM catalog_assessmentquestion question
    ORDER BY question.wizard_step ASC, question.sort_order ASC, question.code ASC
    "#
}

fn question_kind_label(value: &str) -> &'static str {
    match value {
        "APPLICABILITY" => "Betroffenheit",
        "MATURITY" => "Reifegrad",
        _ => "Unbekannt",
    }
}

fn wizard_step_label(value: &str) -> &'static str {
    match value {
        "applicability" => "Betroffenheit",
        "maturity" => "Reifegrad",
        _ => "Unbekannt",
    }
}
