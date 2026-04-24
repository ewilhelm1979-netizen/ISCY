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
