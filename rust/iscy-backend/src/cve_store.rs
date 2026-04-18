use std::str::FromStr;

use anyhow::{bail, Context};
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde_json::{json, Value};
use sqlx::{
    postgres::{PgPool, PgPoolOptions},
    sqlite::{SqlitePool, SqlitePoolOptions},
    types::Json,
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

#[cfg(test)]
mod tests {
    use super::normalize_database_url;

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
}
