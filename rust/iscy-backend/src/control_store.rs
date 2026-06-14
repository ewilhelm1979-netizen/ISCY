use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context};
use serde::Serialize;
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Row,
};

use crate::cve_store::normalize_database_url;

#[derive(Clone)]
pub enum ControlStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Serialize)]
pub struct ControlLibrary {
    pub total_controls: i64,
    pub covered_controls: i64,
    pub gap_controls: i64,
    pub average_maturity: f64,
    pub framework_count: i64,
    pub frameworks: Vec<String>,
    pub groups: Vec<ControlGroupSummary>,
    pub controls: Vec<ControlSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ControlGroupSummary {
    pub code: String,
    pub name: String,
    pub control_count: i64,
    pub covered_count: i64,
    pub average_maturity: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ControlSummary {
    pub id: i64,
    pub control_number: i64,
    pub code: String,
    pub group_code: String,
    pub group_name: String,
    pub title: String,
    pub objective: String,
    pub evidence_guidance: String,
    pub owner_role: String,
    pub maturity_target: i64,
    pub status: String,
    pub status_label: String,
    pub maturity_score: i64,
    pub evidence_status: String,
    pub evidence_status_label: String,
    pub tenant_notes: String,
    pub owner_display: Option<String>,
    pub reviewed_at: Option<String>,
    pub framework_count: i64,
    pub mapping_count: i64,
    pub frameworks: Vec<String>,
    pub mappings: Vec<ControlMappingSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ControlMappingSummary {
    pub id: i64,
    pub control_id: i64,
    pub framework: String,
    pub framework_label: String,
    pub source_code: String,
    pub source_title: String,
    pub legal_reference: String,
    pub coverage_level: String,
    pub coverage_level_label: String,
    pub rationale: String,
}

impl ControlStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Control-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Control-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-Control-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn library(&self, tenant_id: i64) -> anyhow::Result<ControlLibrary> {
        match self {
            Self::Postgres(pool) => library_postgres(pool, tenant_id).await,
            Self::Sqlite(pool) => library_sqlite(pool, tenant_id).await,
        }
    }
}

async fn library_postgres(pool: &PgPool, tenant_id: i64) -> anyhow::Result<ControlLibrary> {
    let mut controls = sqlx::query(controls_postgres_sql())
        .bind(tenant_id)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Control-Library konnte nicht gelesen werden")?
        .into_iter()
        .map(control_from_pg_row)
        .collect::<Result<Vec<_>, _>>()?;
    let mappings = sqlx::query(mappings_postgres_sql())
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Control-Mappings konnten nicht gelesen werden")?
        .into_iter()
        .map(mapping_from_pg_row)
        .collect::<Result<Vec<_>, _>>()?;
    attach_mappings(&mut controls, mappings);
    Ok(build_library(controls))
}

async fn library_sqlite(pool: &SqlitePool, tenant_id: i64) -> anyhow::Result<ControlLibrary> {
    let mut controls = sqlx::query(controls_sqlite_sql())
        .bind(tenant_id)
        .fetch_all(pool)
        .await
        .context("SQLite-Control-Library konnte nicht gelesen werden")?
        .into_iter()
        .map(control_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()?;
    let mappings = sqlx::query(mappings_sqlite_sql())
        .fetch_all(pool)
        .await
        .context("SQLite-Control-Mappings konnten nicht gelesen werden")?
        .into_iter()
        .map(mapping_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()?;
    attach_mappings(&mut controls, mappings);
    Ok(build_library(controls))
}

fn attach_mappings(controls: &mut [ControlSummary], mappings: Vec<ControlMappingSummary>) {
    let mut mapping_by_control = BTreeMap::<i64, Vec<ControlMappingSummary>>::new();
    for mapping in mappings {
        mapping_by_control
            .entry(mapping.control_id)
            .or_default()
            .push(mapping);
    }

    for control in controls {
        control.mappings = mapping_by_control.remove(&control.id).unwrap_or_default();
        let frameworks = control
            .mappings
            .iter()
            .map(|mapping| mapping.framework_label.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        control.framework_count = frameworks.len() as i64;
        control.mapping_count = control.mappings.len() as i64;
        control.frameworks = frameworks;
    }
}

fn build_library(controls: Vec<ControlSummary>) -> ControlLibrary {
    let total_controls = controls.len() as i64;
    let covered_controls = controls
        .iter()
        .filter(|control| is_control_covered(&control.status))
        .count() as i64;
    let gap_controls = controls
        .iter()
        .filter(|control| control.status.eq_ignore_ascii_case("GAP"))
        .count() as i64;
    let maturity_sum = controls
        .iter()
        .map(|control| control.maturity_score)
        .sum::<i64>();
    let average_maturity = average_score(maturity_sum, total_controls);

    let frameworks = controls
        .iter()
        .flat_map(|control| control.frameworks.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let mut group_map = BTreeMap::<String, GroupAccumulator>::new();
    for control in &controls {
        let entry = group_map
            .entry(control.group_code.clone())
            .or_insert_with(|| GroupAccumulator {
                name: control.group_name.clone(),
                control_count: 0,
                covered_count: 0,
                maturity_sum: 0,
            });
        entry.control_count += 1;
        entry.maturity_sum += control.maturity_score;
        if is_control_covered(&control.status) {
            entry.covered_count += 1;
        }
    }

    let groups = group_map
        .into_iter()
        .map(|(code, group)| ControlGroupSummary {
            code,
            name: group.name,
            control_count: group.control_count,
            covered_count: group.covered_count,
            average_maturity: average_score(group.maturity_sum, group.control_count),
        })
        .collect::<Vec<_>>();

    ControlLibrary {
        total_controls,
        covered_controls,
        gap_controls,
        average_maturity,
        framework_count: frameworks.len() as i64,
        frameworks,
        groups,
        controls,
    }
}

#[derive(Debug, Clone)]
struct GroupAccumulator {
    name: String,
    control_count: i64,
    covered_count: i64,
    maturity_sum: i64,
}

fn control_from_pg_row(row: PgRow) -> Result<ControlSummary, sqlx::Error> {
    let status: String = row.try_get("status")?;
    let evidence_status: String = row.try_get("evidence_status")?;
    Ok(ControlSummary {
        id: row.try_get("id")?,
        control_number: row.try_get("control_number")?,
        code: row.try_get("code")?,
        group_code: row.try_get("group_code")?,
        group_name: row.try_get("group_name")?,
        title: row.try_get("title")?,
        objective: row.try_get("objective")?,
        evidence_guidance: row.try_get("evidence_guidance")?,
        owner_role: row.try_get("owner_role")?,
        maturity_target: row.try_get("maturity_target")?,
        status_label: status_label(&status).to_string(),
        status,
        maturity_score: row.try_get("maturity_score")?,
        evidence_status_label: evidence_status_label(&evidence_status).to_string(),
        evidence_status,
        tenant_notes: row.try_get("tenant_notes")?,
        owner_display: row.try_get("owner_display")?,
        reviewed_at: row.try_get("reviewed_at")?,
        framework_count: 0,
        mapping_count: 0,
        frameworks: Vec::new(),
        mappings: Vec::new(),
    })
}

fn control_from_sqlite_row(row: SqliteRow) -> Result<ControlSummary, sqlx::Error> {
    let status: String = row.try_get("status")?;
    let evidence_status: String = row.try_get("evidence_status")?;
    Ok(ControlSummary {
        id: row.try_get("id")?,
        control_number: row.try_get("control_number")?,
        code: row.try_get("code")?,
        group_code: row.try_get("group_code")?,
        group_name: row.try_get("group_name")?,
        title: row.try_get("title")?,
        objective: row.try_get("objective")?,
        evidence_guidance: row.try_get("evidence_guidance")?,
        owner_role: row.try_get("owner_role")?,
        maturity_target: row.try_get("maturity_target")?,
        status_label: status_label(&status).to_string(),
        status,
        maturity_score: row.try_get("maturity_score")?,
        evidence_status_label: evidence_status_label(&evidence_status).to_string(),
        evidence_status,
        tenant_notes: row.try_get("tenant_notes")?,
        owner_display: row.try_get("owner_display")?,
        reviewed_at: row.try_get("reviewed_at")?,
        framework_count: 0,
        mapping_count: 0,
        frameworks: Vec::new(),
        mappings: Vec::new(),
    })
}

fn mapping_from_pg_row(row: PgRow) -> Result<ControlMappingSummary, sqlx::Error> {
    let framework: String = row.try_get("framework")?;
    let coverage_level: String = row.try_get("coverage_level")?;
    Ok(ControlMappingSummary {
        id: row.try_get("id")?,
        control_id: row.try_get("control_id")?,
        framework_label: framework_label(&framework).to_string(),
        framework,
        source_code: row.try_get("source_code")?,
        source_title: row.try_get("source_title")?,
        legal_reference: row.try_get("legal_reference")?,
        coverage_level_label: coverage_level_label(&coverage_level).to_string(),
        coverage_level,
        rationale: row.try_get("rationale")?,
    })
}

fn mapping_from_sqlite_row(row: SqliteRow) -> Result<ControlMappingSummary, sqlx::Error> {
    let framework: String = row.try_get("framework")?;
    let coverage_level: String = row.try_get("coverage_level")?;
    Ok(ControlMappingSummary {
        id: row.try_get("id")?,
        control_id: row.try_get("control_id")?,
        framework_label: framework_label(&framework).to_string(),
        framework,
        source_code: row.try_get("source_code")?,
        source_title: row.try_get("source_title")?,
        legal_reference: row.try_get("legal_reference")?,
        coverage_level_label: coverage_level_label(&coverage_level).to_string(),
        coverage_level,
        rationale: row.try_get("rationale")?,
    })
}

fn controls_sqlite_sql() -> &'static str {
    r#"
    SELECT
        control.id,
        control.control_number,
        control.code,
        control.group_code,
        control.group_name,
        control.title,
        control.objective,
        control.evidence_guidance,
        control.owner_role,
        control.maturity_target,
        COALESCE(status.status, 'GAP') AS status,
        COALESCE(status.maturity_score, 0) AS maturity_score,
        COALESCE(status.evidence_status, 'MISSING') AS evidence_status,
        COALESCE(status.notes, '') AS tenant_notes,
        status.reviewed_at AS reviewed_at,
        COALESCE(NULLIF(TRIM(COALESCE(owner.first_name, '') || ' ' || COALESCE(owner.last_name, '')), ''), owner.username) AS owner_display
    FROM iscy_control_control control
    LEFT JOIN iscy_control_tenantstatus status
        ON status.control_id = control.id
        AND status.tenant_id = ?
    LEFT JOIN accounts_user owner
        ON owner.id = status.owner_id
        AND owner.tenant_id = status.tenant_id
    WHERE control.is_active = 1
    ORDER BY control.sort_order ASC, control.control_number ASC
    "#
}

fn controls_postgres_sql() -> &'static str {
    r#"
    SELECT
        control.id,
        control.control_number::bigint AS control_number,
        control.code,
        control.group_code,
        control.group_name,
        control.title,
        control.objective,
        control.evidence_guidance,
        control.owner_role,
        control.maturity_target::bigint AS maturity_target,
        COALESCE(status.status, 'GAP') AS status,
        COALESCE(status.maturity_score, 0)::bigint AS maturity_score,
        COALESCE(status.evidence_status, 'MISSING') AS evidence_status,
        COALESCE(status.notes, '') AS tenant_notes,
        status.reviewed_at AS reviewed_at,
        COALESCE(NULLIF(TRIM(CONCAT(COALESCE(owner.first_name, ''), ' ', COALESCE(owner.last_name, ''))), ''), owner.username) AS owner_display
    FROM iscy_control_control control
    LEFT JOIN iscy_control_tenantstatus status
        ON status.control_id = control.id
        AND status.tenant_id = $1
    LEFT JOIN accounts_user owner
        ON owner.id = status.owner_id
        AND owner.tenant_id = status.tenant_id
    WHERE control.is_active = TRUE
    ORDER BY control.sort_order ASC, control.control_number ASC
    "#
}

fn mappings_sqlite_sql() -> &'static str {
    r#"
    SELECT
        mapping.id,
        mapping.control_id,
        mapping.framework,
        mapping.source_code,
        mapping.source_title,
        mapping.legal_reference,
        mapping.coverage_level,
        mapping.rationale
    FROM iscy_control_regulatorymapping mapping
    JOIN iscy_control_control control ON control.id = mapping.control_id
    WHERE control.is_active = 1
    ORDER BY control.sort_order ASC, mapping.framework ASC, mapping.source_code ASC
    "#
}

fn mappings_postgres_sql() -> &'static str {
    r#"
    SELECT
        mapping.id,
        mapping.control_id,
        mapping.framework,
        mapping.source_code,
        mapping.source_title,
        mapping.legal_reference,
        mapping.coverage_level,
        mapping.rationale
    FROM iscy_control_regulatorymapping mapping
    JOIN iscy_control_control control ON control.id = mapping.control_id
    WHERE control.is_active = TRUE
    ORDER BY control.sort_order ASC, mapping.framework ASC, mapping.source_code ASC
    "#
}

fn is_control_covered(status: &str) -> bool {
    matches!(
        status.trim().to_ascii_uppercase().as_str(),
        "IMPLEMENTED" | "EFFECTIVE"
    )
}

fn average_score(sum: i64, count: i64) -> f64 {
    if count == 0 {
        return 0.0;
    }
    ((sum as f64 / count as f64) * 100.0).round() / 100.0
}

fn framework_label(framework: &str) -> &'static str {
    match framework.trim().to_ascii_uppercase().as_str() {
        "AI_ACT" | "AIACT" | "AI-ACT" => "AI Act",
        "CRA" => "CRA",
        "DORA" => "DORA",
        "GDPR" | "DSGVO" => "DSGVO",
        "ISO27001" | "ISO_27001" => "ISO 27001",
        "NIS2" => "NIS2",
        "TISAX" => "TISAX",
        _ => "Sonstige",
    }
}

fn coverage_level_label(coverage_level: &str) -> &'static str {
    match coverage_level.trim().to_ascii_uppercase().as_str() {
        "PRIMARY" => "Primaer",
        "SUPPORTING" => "Unterstuetzend",
        _ => "Referenz",
    }
}

fn status_label(status: &str) -> &'static str {
    match status.trim().to_ascii_uppercase().as_str() {
        "EFFECTIVE" => "Wirksam",
        "IMPLEMENTED" => "Umgesetzt",
        "PARTIAL" => "Teilweise",
        "NOT_APPLICABLE" => "Nicht anwendbar",
        "GAP" => "Fehlt",
        _ => "Unklar",
    }
}

fn evidence_status_label(status: &str) -> &'static str {
    match status.trim().to_ascii_uppercase().as_str() {
        "EVIDENCED" => "Nachgewiesen",
        "PARTIAL" => "Teilweise",
        "MISSING" => "Fehlt",
        _ => "Unklar",
    }
}
