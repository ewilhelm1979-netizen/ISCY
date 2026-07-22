use std::{fmt, net::IpAddr, sync::Arc};

use anyhow::{bail, Context};
use chrono::{DateTime, SecondsFormat, Utc};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Postgres, Row, Sqlite, Transaction,
};
use tokio::sync::{Mutex, MutexGuard};

use crate::cve_store::normalize_database_url;

const MAX_INDICATOR_VALUE_BYTES: usize = 2048;
const MAX_OBSERVATION_ATTRIBUTES_BYTES: usize = 16 * 1024;
const MAX_ATTRIBUTE_DEPTH: usize = 4;
const MAX_ATTRIBUTE_COLLECTION_ITEMS: usize = 64;
const MAX_ATTRIBUTE_STRING_BYTES: usize = 1024;

#[derive(Clone)]
pub enum ThreatIntelligenceStore {
    Postgres(PgPool),
    Sqlite {
        pool: SqlitePool,
        write_lock: Arc<Mutex<()>>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatIntelligenceErrorKind {
    InvalidInput,
    NotFound,
    Conflict,
    Database,
}

#[derive(Debug)]
pub struct ThreatIntelligenceError {
    kind: ThreatIntelligenceErrorKind,
    message: &'static str,
}

impl ThreatIntelligenceError {
    pub fn kind(&self) -> ThreatIntelligenceErrorKind {
        self.kind
    }

    pub fn message(&self) -> &'static str {
        self.message
    }

    fn invalid(message: &'static str) -> Self {
        Self {
            kind: ThreatIntelligenceErrorKind::InvalidInput,
            message,
        }
    }

    fn not_found(message: &'static str) -> Self {
        Self {
            kind: ThreatIntelligenceErrorKind::NotFound,
            message,
        }
    }

    fn conflict(message: &'static str) -> Self {
        Self {
            kind: ThreatIntelligenceErrorKind::Conflict,
            message,
        }
    }

    fn database() -> Self {
        Self {
            kind: ThreatIntelligenceErrorKind::Database,
            message: "Threat-Intelligence-Daten konnten intern nicht verarbeitet werden.",
        }
    }
}

impl fmt::Display for ThreatIntelligenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for ThreatIntelligenceError {}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreatIndicatorWriteRequest {
    pub indicator_type: String,
    pub value: String,
    pub source_type: String,
    pub source_name: String,
    pub provenance_reference: String,
    pub confidence: i64,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub classification: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreatIndicatorUpdateRequest {
    pub confidence: Option<i64>,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub lifecycle_status: Option<String>,
    pub classification: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreatIndicatorSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub indicator_type: String,
    pub normalized_value: String,
    pub original_value: String,
    pub source_type: String,
    pub source_name: String,
    pub provenance_reference: String,
    pub confidence: i64,
    pub valid_from: String,
    pub valid_until: Option<String>,
    pub lifecycle_status: String,
    pub classification: String,
    pub created_by_id: i64,
    pub updated_by_id: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreatIndicatorWriteResult {
    pub created: bool,
    pub indicator: ThreatIndicatorSummary,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityObservationWriteRequest {
    pub source_type: String,
    pub source_reference: String,
    pub asset_id: Option<i64>,
    pub deduplication_key: String,
    pub observed_at: Option<String>,
    pub category: Option<String>,
    pub severity: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub attributes: Option<Value>,
    pub provenance_type: Option<String>,
    pub provenance_reference: Option<String>,
    pub owner_id: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityObservationTriageRequest {
    pub triage_status: String,
    pub owner_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityObservationSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub source_type: String,
    pub source_reference: String,
    pub agent_finding_id: Option<i64>,
    pub vulnerability_finding_id: Option<i64>,
    pub asset_id: Option<i64>,
    pub asset_name: Option<String>,
    pub deduplication_key: String,
    pub observed_at: String,
    pub recorded_at: String,
    pub category: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub attributes: Value,
    pub provenance_type: String,
    pub provenance_reference: String,
    pub triage_status: String,
    pub owner_id: Option<i64>,
    pub created_by_id: i64,
    pub updated_by_id: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityObservationWriteResult {
    pub created: bool,
    pub observation: SecurityObservationSummary,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationIndicatorLinkWriteRequest {
    pub indicator_id: i64,
    pub match_type: String,
    pub rationale: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationIndicatorLinkTriageRequest {
    pub triage_status: String,
    pub rationale: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObservationIndicatorLinkSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub observation_id: i64,
    pub observation_title: String,
    pub indicator_id: i64,
    pub indicator_type: String,
    pub indicator_value: String,
    pub match_origin: String,
    pub match_type: String,
    pub matched_at: String,
    pub evaluator_id: i64,
    pub triage_status: String,
    pub rationale: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObservationIndicatorLinkWriteResult {
    pub created: bool,
    pub link: ObservationIndicatorLinkSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityObservationAuditEvent {
    pub id: i64,
    pub tenant_id: i64,
    pub object_type: String,
    pub object_id: i64,
    pub event_type: String,
    pub actor_id: i64,
    pub summary: String,
    pub detail: Value,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreatIntelligenceOverview {
    pub tenant_id: i64,
    pub indicators: Vec<ThreatIndicatorSummary>,
    pub observations: Vec<SecurityObservationSummary>,
    pub links: Vec<ObservationIndicatorLinkSummary>,
    pub audit_events: Vec<SecurityObservationAuditEvent>,
}

#[derive(Debug)]
struct NormalizedIndicator {
    indicator_type: String,
    normalized_value: String,
    original_value: String,
    source_type: String,
    source_name: String,
    provenance_reference: String,
    confidence: i64,
    valid_from: String,
    valid_until: Option<String>,
    classification: String,
}

#[derive(Debug)]
struct NormalizedObservation {
    source_type: String,
    source_reference: String,
    agent_finding_id: Option<i64>,
    vulnerability_finding_id: Option<i64>,
    asset_id: Option<i64>,
    deduplication_key: String,
    observed_at: String,
    category: String,
    severity: String,
    title: String,
    description: String,
    attributes_json: String,
    provenance_type: String,
    provenance_reference: String,
    owner_id: Option<i64>,
}

#[derive(Debug)]
struct ReferencedFinding {
    source_reference: String,
    finding_id: i64,
    asset_id: Option<i64>,
    observed_at: String,
    category: &'static str,
    severity: String,
    title: String,
    description: String,
    provenance_type: &'static str,
    provenance_reference: String,
}

impl ThreatIntelligenceStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Threat-Intelligence-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Threat-Intelligence-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite {
                pool,
                write_lock: Arc::new(Mutex::new(())),
            });
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Threat-Intelligence-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite {
            pool,
            write_lock: Arc::new(Mutex::new(())),
        }
    }

    async fn sqlite_write_guard(&self) -> Option<MutexGuard<'_, ()>> {
        match self {
            Self::Sqlite { write_lock, .. } => Some(write_lock.lock().await),
            Self::Postgres(_) => None,
        }
    }

    pub async fn overview(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> Result<ThreatIntelligenceOverview, ThreatIntelligenceError> {
        let limit = limit.clamp(1, 200);
        Ok(ThreatIntelligenceOverview {
            tenant_id,
            indicators: self.list_indicators(tenant_id, limit).await?,
            observations: self.list_observations(tenant_id, limit).await?,
            links: self.list_links(tenant_id, limit).await?,
            audit_events: self.list_audit_events(tenant_id, limit).await?,
        })
    }

    pub async fn list_indicators(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> Result<Vec<ThreatIndicatorSummary>, ThreatIntelligenceError> {
        let limit = limit.clamp(1, 200);
        match self {
            Self::Postgres(pool) => sqlx::query(indicator_select_postgres())
                .bind(tenant_id)
                .bind(limit)
                .fetch_all(pool)
                .await
                .map_err(|_| ThreatIntelligenceError::database())?
                .into_iter()
                .map(indicator_from_pg_row)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ThreatIntelligenceError::database()),
            Self::Sqlite { pool, .. } => sqlx::query(indicator_select_sqlite())
                .bind(tenant_id)
                .bind(limit)
                .fetch_all(pool)
                .await
                .map_err(|_| ThreatIntelligenceError::database())?
                .into_iter()
                .map(indicator_from_sqlite_row)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ThreatIntelligenceError::database()),
        }
    }

    pub async fn create_indicator(
        &self,
        tenant_id: i64,
        actor_id: i64,
        request: ThreatIndicatorWriteRequest,
    ) -> Result<ThreatIndicatorWriteResult, ThreatIntelligenceError> {
        let indicator = normalize_indicator_request(request)?;
        let _sqlite_write_guard = self.sqlite_write_guard().await;
        match self {
            Self::Postgres(pool) => {
                let mut transaction = pool
                    .begin()
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                let existing = load_indicator_postgres(
                    &mut transaction,
                    tenant_id,
                    &indicator.indicator_type,
                    &indicator.normalized_value,
                )
                .await?;
                if let Some(existing) = existing {
                    ensure_same_indicator_provenance(&existing, &indicator)?;
                    transaction
                        .commit()
                        .await
                        .map_err(|_| ThreatIntelligenceError::database())?;
                    return Ok(ThreatIndicatorWriteResult {
                        created: false,
                        indicator: existing,
                    });
                }
                let row = sqlx::query(indicator_insert_postgres())
                    .bind(tenant_id)
                    .bind(&indicator.indicator_type)
                    .bind(&indicator.normalized_value)
                    .bind(&indicator.original_value)
                    .bind(&indicator.source_type)
                    .bind(&indicator.source_name)
                    .bind(&indicator.provenance_reference)
                    .bind(indicator.confidence)
                    .bind(&indicator.valid_from)
                    .bind(&indicator.valid_until)
                    .bind(&indicator.classification)
                    .bind(actor_id)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                let Some(row) = row else {
                    let existing = load_indicator_postgres(
                        &mut transaction,
                        tenant_id,
                        &indicator.indicator_type,
                        &indicator.normalized_value,
                    )
                    .await?
                    .ok_or_else(ThreatIntelligenceError::database)?;
                    ensure_same_indicator_provenance(&existing, &indicator)?;
                    transaction
                        .commit()
                        .await
                        .map_err(|_| ThreatIntelligenceError::database())?;
                    return Ok(ThreatIndicatorWriteResult {
                        created: false,
                        indicator: existing,
                    });
                };
                let created =
                    indicator_from_pg_row(row).map_err(|_| ThreatIntelligenceError::database())?;
                insert_audit_postgres(
                    &mut transaction,
                    tenant_id,
                    ("INDICATOR", created.id),
                    "indicator_created",
                    actor_id,
                    "Threat-Intelligence-Indikator erfasst",
                    &json!({
                        "indicator_type": created.indicator_type,
                        "value_sha256": sha256_hex(created.normalized_value.as_bytes()),
                        "source_type": created.source_type,
                        "classification": created.classification
                    }),
                )
                .await?;
                transaction
                    .commit()
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                Ok(ThreatIndicatorWriteResult {
                    created: true,
                    indicator: created,
                })
            }
            Self::Sqlite { pool, .. } => {
                let mut transaction = pool
                    .begin()
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                let existing = load_indicator_sqlite(
                    &mut transaction,
                    tenant_id,
                    &indicator.indicator_type,
                    &indicator.normalized_value,
                )
                .await?;
                if let Some(existing) = existing {
                    ensure_same_indicator_provenance(&existing, &indicator)?;
                    transaction
                        .commit()
                        .await
                        .map_err(|_| ThreatIntelligenceError::database())?;
                    return Ok(ThreatIndicatorWriteResult {
                        created: false,
                        indicator: existing,
                    });
                }
                let row = sqlx::query(indicator_insert_sqlite())
                    .bind(tenant_id)
                    .bind(&indicator.indicator_type)
                    .bind(&indicator.normalized_value)
                    .bind(&indicator.original_value)
                    .bind(&indicator.source_type)
                    .bind(&indicator.source_name)
                    .bind(&indicator.provenance_reference)
                    .bind(indicator.confidence)
                    .bind(&indicator.valid_from)
                    .bind(&indicator.valid_until)
                    .bind(&indicator.classification)
                    .bind(actor_id)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                let Some(row) = row else {
                    let existing = load_indicator_sqlite(
                        &mut transaction,
                        tenant_id,
                        &indicator.indicator_type,
                        &indicator.normalized_value,
                    )
                    .await?
                    .ok_or_else(ThreatIntelligenceError::database)?;
                    ensure_same_indicator_provenance(&existing, &indicator)?;
                    transaction
                        .commit()
                        .await
                        .map_err(|_| ThreatIntelligenceError::database())?;
                    return Ok(ThreatIndicatorWriteResult {
                        created: false,
                        indicator: existing,
                    });
                };
                let created = indicator_from_sqlite_row(row)
                    .map_err(|_| ThreatIntelligenceError::database())?;
                insert_audit_sqlite(
                    &mut transaction,
                    tenant_id,
                    ("INDICATOR", created.id),
                    "indicator_created",
                    actor_id,
                    "Threat-Intelligence-Indikator erfasst",
                    &json!({
                        "indicator_type": created.indicator_type,
                        "value_sha256": sha256_hex(created.normalized_value.as_bytes()),
                        "source_type": created.source_type,
                        "classification": created.classification
                    }),
                )
                .await?;
                transaction
                    .commit()
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                Ok(ThreatIndicatorWriteResult {
                    created: true,
                    indicator: created,
                })
            }
        }
    }

    pub async fn update_indicator(
        &self,
        tenant_id: i64,
        actor_id: i64,
        indicator_id: i64,
        request: ThreatIndicatorUpdateRequest,
    ) -> Result<ThreatIndicatorSummary, ThreatIntelligenceError> {
        let confidence = request.confidence.map(validate_confidence).transpose()?;
        let valid_until_was_provided = request.valid_until.is_some();
        let valid_from = request
            .valid_from
            .map(|value| validate_timestamp(&value))
            .transpose()?;
        let valid_until = request
            .valid_until
            .map(|value| validate_optional_timestamp(&value))
            .transpose()?
            .flatten();
        let lifecycle_status = request
            .lifecycle_status
            .map(|value| {
                normalize_enum(&value, &INDICATOR_STATUSES, "Ungueltiger Indicator-Status.")
            })
            .transpose()?;
        let classification = request
            .classification
            .map(|value| {
                normalize_enum(
                    &value,
                    &CLASSIFICATIONS,
                    "Ungueltige Indicator-Klassifizierung.",
                )
            })
            .transpose()?;
        let _sqlite_write_guard = self.sqlite_write_guard().await;
        match self {
            Self::Postgres(pool) => {
                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                let current = load_indicator_by_id_postgres(&mut tx, tenant_id, indicator_id)
                    .await?
                    .ok_or_else(|| {
                        ThreatIntelligenceError::not_found("Indikator wurde nicht gefunden.")
                    })?;
                let next_from = valid_from.as_deref().unwrap_or(&current.valid_from);
                let next_until = if valid_until_was_provided {
                    valid_until.as_deref()
                } else {
                    current.valid_until.as_deref()
                };
                validate_time_window(next_from, next_until)?;
                let row = sqlx::query(indicator_update_postgres())
                    .bind(tenant_id)
                    .bind(indicator_id)
                    .bind(confidence.unwrap_or(current.confidence))
                    .bind(next_from)
                    .bind(next_until)
                    .bind(
                        lifecycle_status
                            .as_deref()
                            .unwrap_or(&current.lifecycle_status),
                    )
                    .bind(classification.as_deref().unwrap_or(&current.classification))
                    .bind(actor_id)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                let updated =
                    indicator_from_pg_row(row).map_err(|_| ThreatIntelligenceError::database())?;
                insert_audit_postgres(&mut tx, tenant_id, ("INDICATOR", indicator_id), "indicator_updated", actor_id, "Threat-Intelligence-Indikator aktualisiert", &json!({"lifecycle_status":updated.lifecycle_status,"confidence":updated.confidence,"classification":updated.classification})).await?;
                tx.commit()
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                Ok(updated)
            }
            Self::Sqlite { pool, .. } => {
                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                let current = load_indicator_by_id_sqlite(&mut tx, tenant_id, indicator_id)
                    .await?
                    .ok_or_else(|| {
                        ThreatIntelligenceError::not_found("Indikator wurde nicht gefunden.")
                    })?;
                let next_from = valid_from.as_deref().unwrap_or(&current.valid_from);
                let next_until = if valid_until_was_provided {
                    valid_until.as_deref()
                } else {
                    current.valid_until.as_deref()
                };
                validate_time_window(next_from, next_until)?;
                let row = sqlx::query(indicator_update_sqlite())
                    .bind(tenant_id)
                    .bind(indicator_id)
                    .bind(confidence.unwrap_or(current.confidence))
                    .bind(next_from)
                    .bind(next_until)
                    .bind(
                        lifecycle_status
                            .as_deref()
                            .unwrap_or(&current.lifecycle_status),
                    )
                    .bind(classification.as_deref().unwrap_or(&current.classification))
                    .bind(actor_id)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                let updated = indicator_from_sqlite_row(row)
                    .map_err(|_| ThreatIntelligenceError::database())?;
                insert_audit_sqlite(&mut tx, tenant_id, ("INDICATOR", indicator_id), "indicator_updated", actor_id, "Threat-Intelligence-Indikator aktualisiert", &json!({"lifecycle_status":updated.lifecycle_status,"confidence":updated.confidence,"classification":updated.classification})).await?;
                tx.commit()
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                Ok(updated)
            }
        }
    }

    pub async fn list_observations(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> Result<Vec<SecurityObservationSummary>, ThreatIntelligenceError> {
        let limit = limit.clamp(1, 200);
        match self {
            Self::Postgres(pool) => sqlx::query(observation_select_postgres())
                .bind(tenant_id)
                .bind(limit)
                .fetch_all(pool)
                .await
                .map_err(|_| ThreatIntelligenceError::database())?
                .into_iter()
                .map(observation_from_pg_row)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ThreatIntelligenceError::database()),
            Self::Sqlite { pool, .. } => sqlx::query(observation_select_sqlite())
                .bind(tenant_id)
                .bind(limit)
                .fetch_all(pool)
                .await
                .map_err(|_| ThreatIntelligenceError::database())?
                .into_iter()
                .map(observation_from_sqlite_row)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ThreatIntelligenceError::database()),
        }
    }

    pub async fn create_observation(
        &self,
        tenant_id: i64,
        actor_id: i64,
        request: SecurityObservationWriteRequest,
    ) -> Result<SecurityObservationWriteResult, ThreatIntelligenceError> {
        let source_type = normalize_enum(
            &request.source_type,
            &OBSERVATION_SOURCE_TYPES,
            "Ungueltiger Observation-Herkunftstyp.",
        )?;
        let _sqlite_write_guard = self.sqlite_write_guard().await;
        match self {
            Self::Postgres(pool) => {
                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                let normalized =
                    normalize_observation_postgres(&mut tx, tenant_id, source_type, request)
                        .await?;
                if let Some(existing) = load_observation_by_origin_postgres(
                    &mut tx,
                    tenant_id,
                    &normalized.source_type,
                    &normalized.source_reference,
                    &normalized.deduplication_key,
                )
                .await?
                {
                    ensure_same_observation_origin(&existing, &normalized)?;
                    tx.commit()
                        .await
                        .map_err(|_| ThreatIntelligenceError::database())?;
                    return Ok(SecurityObservationWriteResult {
                        created: false,
                        observation: existing,
                    });
                }
                let Some(created) =
                    insert_observation_postgres(&mut tx, tenant_id, actor_id, &normalized).await?
                else {
                    let existing = load_observation_by_origin_postgres(
                        &mut tx,
                        tenant_id,
                        &normalized.source_type,
                        &normalized.source_reference,
                        &normalized.deduplication_key,
                    )
                    .await?
                    .ok_or_else(ThreatIntelligenceError::database)?;
                    ensure_same_observation_origin(&existing, &normalized)?;
                    tx.commit()
                        .await
                        .map_err(|_| ThreatIntelligenceError::database())?;
                    return Ok(SecurityObservationWriteResult {
                        created: false,
                        observation: existing,
                    });
                };
                insert_audit_postgres(&mut tx, tenant_id, ("OBSERVATION", created.id), "observation_created", actor_id, "Security Observation erfasst", &json!({"source_type":created.source_type,"source_reference_sha256":sha256_hex(created.source_reference.as_bytes()),"category":created.category,"severity":created.severity})).await?;
                tx.commit()
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                Ok(SecurityObservationWriteResult {
                    created: true,
                    observation: created,
                })
            }
            Self::Sqlite { pool, .. } => {
                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                let normalized =
                    normalize_observation_sqlite(&mut tx, tenant_id, source_type, request).await?;
                if let Some(existing) = load_observation_by_origin_sqlite(
                    &mut tx,
                    tenant_id,
                    &normalized.source_type,
                    &normalized.source_reference,
                    &normalized.deduplication_key,
                )
                .await?
                {
                    ensure_same_observation_origin(&existing, &normalized)?;
                    tx.commit()
                        .await
                        .map_err(|_| ThreatIntelligenceError::database())?;
                    return Ok(SecurityObservationWriteResult {
                        created: false,
                        observation: existing,
                    });
                }
                let Some(created) =
                    insert_observation_sqlite(&mut tx, tenant_id, actor_id, &normalized).await?
                else {
                    let existing = load_observation_by_origin_sqlite(
                        &mut tx,
                        tenant_id,
                        &normalized.source_type,
                        &normalized.source_reference,
                        &normalized.deduplication_key,
                    )
                    .await?
                    .ok_or_else(ThreatIntelligenceError::database)?;
                    ensure_same_observation_origin(&existing, &normalized)?;
                    tx.commit()
                        .await
                        .map_err(|_| ThreatIntelligenceError::database())?;
                    return Ok(SecurityObservationWriteResult {
                        created: false,
                        observation: existing,
                    });
                };
                insert_audit_sqlite(&mut tx, tenant_id, ("OBSERVATION", created.id), "observation_created", actor_id, "Security Observation erfasst", &json!({"source_type":created.source_type,"source_reference_sha256":sha256_hex(created.source_reference.as_bytes()),"category":created.category,"severity":created.severity})).await?;
                tx.commit()
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                Ok(SecurityObservationWriteResult {
                    created: true,
                    observation: created,
                })
            }
        }
    }

    pub async fn triage_observation(
        &self,
        tenant_id: i64,
        actor_id: i64,
        observation_id: i64,
        request: SecurityObservationTriageRequest,
    ) -> Result<SecurityObservationSummary, ThreatIntelligenceError> {
        let triage_status = normalize_enum(
            &request.triage_status,
            &OBSERVATION_STATUSES,
            "Ungueltiger Observation-Triage-Status.",
        )?;
        let _sqlite_write_guard = self.sqlite_write_guard().await;
        match self {
            Self::Postgres(pool) => {
                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                ensure_owner_postgres(&mut tx, tenant_id, request.owner_id).await?;
                let row = sqlx::query(observation_triage_postgres())
                    .bind(tenant_id)
                    .bind(observation_id)
                    .bind(&triage_status)
                    .bind(request.owner_id)
                    .bind(actor_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?
                    .ok_or_else(|| {
                        ThreatIntelligenceError::not_found(
                            "Security Observation wurde nicht gefunden.",
                        )
                    })?;
                let updated = observation_from_pg_row(row)
                    .map_err(|_| ThreatIntelligenceError::database())?;
                insert_audit_postgres(
                    &mut tx,
                    tenant_id,
                    ("OBSERVATION", observation_id),
                    "observation_triaged",
                    actor_id,
                    "Security Observation triagiert",
                    &json!({"triage_status":updated.triage_status,"owner_id":updated.owner_id}),
                )
                .await?;
                tx.commit()
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                Ok(updated)
            }
            Self::Sqlite { pool, .. } => {
                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                ensure_owner_sqlite(&mut tx, tenant_id, request.owner_id).await?;
                let row = sqlx::query(observation_triage_sqlite())
                    .bind(tenant_id)
                    .bind(observation_id)
                    .bind(&triage_status)
                    .bind(request.owner_id)
                    .bind(actor_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?
                    .ok_or_else(|| {
                        ThreatIntelligenceError::not_found(
                            "Security Observation wurde nicht gefunden.",
                        )
                    })?;
                let updated = observation_from_sqlite_row(row)
                    .map_err(|_| ThreatIntelligenceError::database())?;
                insert_audit_sqlite(
                    &mut tx,
                    tenant_id,
                    ("OBSERVATION", observation_id),
                    "observation_triaged",
                    actor_id,
                    "Security Observation triagiert",
                    &json!({"triage_status":updated.triage_status,"owner_id":updated.owner_id}),
                )
                .await?;
                tx.commit()
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                Ok(updated)
            }
        }
    }

    pub async fn list_links(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> Result<Vec<ObservationIndicatorLinkSummary>, ThreatIntelligenceError> {
        let limit = limit.clamp(1, 200);
        match self {
            Self::Postgres(pool) => sqlx::query(link_select_postgres())
                .bind(tenant_id)
                .bind(limit)
                .fetch_all(pool)
                .await
                .map_err(|_| ThreatIntelligenceError::database())?
                .into_iter()
                .map(link_from_pg_row)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ThreatIntelligenceError::database()),
            Self::Sqlite { pool, .. } => sqlx::query(link_select_sqlite())
                .bind(tenant_id)
                .bind(limit)
                .fetch_all(pool)
                .await
                .map_err(|_| ThreatIntelligenceError::database())?
                .into_iter()
                .map(link_from_sqlite_row)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ThreatIntelligenceError::database()),
        }
    }

    pub async fn list_links_for_observation(
        &self,
        tenant_id: i64,
        observation_id: i64,
        limit: i64,
    ) -> Result<Vec<ObservationIndicatorLinkSummary>, ThreatIntelligenceError> {
        let limit = limit.clamp(1, 200);
        match self {
            Self::Postgres(pool) => sqlx::query(link_select_for_observation_postgres())
                .bind(tenant_id)
                .bind(observation_id)
                .bind(limit)
                .fetch_all(pool)
                .await
                .map_err(|_| ThreatIntelligenceError::database())?
                .into_iter()
                .map(link_from_pg_row)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ThreatIntelligenceError::database()),
            Self::Sqlite { pool, .. } => sqlx::query(link_select_for_observation_sqlite())
                .bind(tenant_id)
                .bind(observation_id)
                .bind(limit)
                .fetch_all(pool)
                .await
                .map_err(|_| ThreatIntelligenceError::database())?
                .into_iter()
                .map(link_from_sqlite_row)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ThreatIntelligenceError::database()),
        }
    }

    pub async fn create_link(
        &self,
        tenant_id: i64,
        actor_id: i64,
        observation_id: i64,
        request: ObservationIndicatorLinkWriteRequest,
    ) -> Result<ObservationIndicatorLinkWriteResult, ThreatIntelligenceError> {
        let match_type =
            normalize_enum(&request.match_type, &MATCH_TYPES, "Ungueltiger Match-Typ.")?;
        let rationale = bounded_optional_text(
            request.rationale.as_deref(),
            1000,
            "Match-Begruendung ist zu lang.",
        )?;
        let _sqlite_write_guard = self.sqlite_write_guard().await;
        match self {
            Self::Postgres(pool) => {
                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                ensure_observation_and_indicator_postgres(
                    &mut tx,
                    tenant_id,
                    observation_id,
                    request.indicator_id,
                )
                .await?;
                if let Some(existing) =
                    load_link_postgres(&mut tx, tenant_id, observation_id, request.indicator_id)
                        .await?
                {
                    tx.commit()
                        .await
                        .map_err(|_| ThreatIntelligenceError::database())?;
                    return Ok(ObservationIndicatorLinkWriteResult {
                        created: false,
                        link: existing,
                    });
                }
                let inserted_id: Option<i64> = sqlx::query_scalar(link_insert_postgres())
                    .bind(tenant_id)
                    .bind(observation_id)
                    .bind(request.indicator_id)
                    .bind(&match_type)
                    .bind(actor_id)
                    .bind(&rationale)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                let Some(inserted_id) = inserted_id else {
                    let existing = load_link_postgres(
                        &mut tx,
                        tenant_id,
                        observation_id,
                        request.indicator_id,
                    )
                    .await?
                    .ok_or_else(ThreatIntelligenceError::database)?;
                    tx.commit()
                        .await
                        .map_err(|_| ThreatIntelligenceError::database())?;
                    return Ok(ObservationIndicatorLinkWriteResult {
                        created: false,
                        link: existing,
                    });
                };
                let created = load_link_by_id_postgres(&mut tx, tenant_id, inserted_id)
                    .await?
                    .ok_or_else(ThreatIntelligenceError::database)?;
                insert_audit_postgres(&mut tx, tenant_id, ("LINK", created.id), "indicator_observation_link_created", actor_id, "Indicator und Observation manuell verknuepft", &json!({"observation_id":observation_id,"indicator_id":request.indicator_id,"match_origin":"MANUAL","match_type":match_type})).await?;
                tx.commit()
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                Ok(ObservationIndicatorLinkWriteResult {
                    created: true,
                    link: created,
                })
            }
            Self::Sqlite { pool, .. } => {
                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                ensure_observation_and_indicator_sqlite(
                    &mut tx,
                    tenant_id,
                    observation_id,
                    request.indicator_id,
                )
                .await?;
                if let Some(existing) =
                    load_link_sqlite(&mut tx, tenant_id, observation_id, request.indicator_id)
                        .await?
                {
                    tx.commit()
                        .await
                        .map_err(|_| ThreatIntelligenceError::database())?;
                    return Ok(ObservationIndicatorLinkWriteResult {
                        created: false,
                        link: existing,
                    });
                }
                let inserted_id: Option<i64> = sqlx::query_scalar(link_insert_sqlite())
                    .bind(tenant_id)
                    .bind(observation_id)
                    .bind(request.indicator_id)
                    .bind(&match_type)
                    .bind(actor_id)
                    .bind(&rationale)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                let Some(inserted_id) = inserted_id else {
                    let existing =
                        load_link_sqlite(&mut tx, tenant_id, observation_id, request.indicator_id)
                            .await?
                            .ok_or_else(ThreatIntelligenceError::database)?;
                    tx.commit()
                        .await
                        .map_err(|_| ThreatIntelligenceError::database())?;
                    return Ok(ObservationIndicatorLinkWriteResult {
                        created: false,
                        link: existing,
                    });
                };
                let created = load_link_by_id_sqlite(&mut tx, tenant_id, inserted_id)
                    .await?
                    .ok_or_else(ThreatIntelligenceError::database)?;
                insert_audit_sqlite(&mut tx, tenant_id, ("LINK", created.id), "indicator_observation_link_created", actor_id, "Indicator und Observation manuell verknuepft", &json!({"observation_id":observation_id,"indicator_id":request.indicator_id,"match_origin":"MANUAL","match_type":match_type})).await?;
                tx.commit()
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                Ok(ObservationIndicatorLinkWriteResult {
                    created: true,
                    link: created,
                })
            }
        }
    }

    pub async fn triage_link(
        &self,
        tenant_id: i64,
        actor_id: i64,
        observation_id: i64,
        link_id: i64,
        request: ObservationIndicatorLinkTriageRequest,
    ) -> Result<ObservationIndicatorLinkSummary, ThreatIntelligenceError> {
        let status = normalize_enum(
            &request.triage_status,
            &LINK_STATUSES,
            "Ungueltiger Match-Triage-Status.",
        )?;
        let rationale = bounded_optional_text(
            request.rationale.as_deref(),
            1000,
            "Match-Begruendung ist zu lang.",
        )?;
        let _sqlite_write_guard = self.sqlite_write_guard().await;
        match self {
            Self::Postgres(pool) => {
                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                let updated_id: i64 = sqlx::query_scalar(link_triage_postgres())
                    .bind(tenant_id)
                    .bind(observation_id)
                    .bind(link_id)
                    .bind(&status)
                    .bind(&rationale)
                    .bind(actor_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?
                    .ok_or_else(|| {
                        ThreatIntelligenceError::not_found("Observation-Link wurde nicht gefunden.")
                    })?;
                let updated = load_link_by_id_postgres(&mut tx, tenant_id, updated_id)
                    .await?
                    .ok_or_else(ThreatIntelligenceError::database)?;
                insert_audit_postgres(
                    &mut tx,
                    tenant_id,
                    ("LINK", link_id),
                    "indicator_observation_link_triaged",
                    actor_id,
                    "Indicator-Observation-Link triagiert",
                    &json!({"triage_status":status,"observation_id":observation_id}),
                )
                .await?;
                tx.commit()
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                Ok(updated)
            }
            Self::Sqlite { pool, .. } => {
                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                let updated_id: i64 = sqlx::query_scalar(link_triage_sqlite())
                    .bind(tenant_id)
                    .bind(observation_id)
                    .bind(link_id)
                    .bind(&status)
                    .bind(&rationale)
                    .bind(actor_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?
                    .ok_or_else(|| {
                        ThreatIntelligenceError::not_found("Observation-Link wurde nicht gefunden.")
                    })?;
                let updated = load_link_by_id_sqlite(&mut tx, tenant_id, updated_id)
                    .await?
                    .ok_or_else(ThreatIntelligenceError::database)?;
                insert_audit_sqlite(
                    &mut tx,
                    tenant_id,
                    ("LINK", link_id),
                    "indicator_observation_link_triaged",
                    actor_id,
                    "Indicator-Observation-Link triagiert",
                    &json!({"triage_status":status,"observation_id":observation_id}),
                )
                .await?;
                tx.commit()
                    .await
                    .map_err(|_| ThreatIntelligenceError::database())?;
                Ok(updated)
            }
        }
    }

    pub async fn list_audit_events(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> Result<Vec<SecurityObservationAuditEvent>, ThreatIntelligenceError> {
        let limit = limit.clamp(1, 200);
        match self {
            Self::Postgres(pool) => sqlx::query(audit_select_postgres())
                .bind(tenant_id)
                .bind(limit)
                .fetch_all(pool)
                .await
                .map_err(|_| ThreatIntelligenceError::database())?
                .into_iter()
                .map(audit_from_pg_row)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ThreatIntelligenceError::database()),
            Self::Sqlite { pool, .. } => sqlx::query(audit_select_sqlite())
                .bind(tenant_id)
                .bind(limit)
                .fetch_all(pool)
                .await
                .map_err(|_| ThreatIntelligenceError::database())?
                .into_iter()
                .map(audit_from_sqlite_row)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ThreatIntelligenceError::database()),
        }
    }
}

const INDICATOR_TYPES: [&str; 5] = ["IPV4", "IPV6", "DOMAIN", "URL", "SHA256"];
const INDICATOR_STATUSES: [&str; 3] = ["ACTIVE", "INACTIVE", "ARCHIVED"];
const CLASSIFICATIONS: [&str; 7] = [
    "PUBLIC",
    "INTERNAL",
    "RESTRICTED",
    "TLP_CLEAR",
    "TLP_GREEN",
    "TLP_AMBER",
    "TLP_RED",
];
const OBSERVATION_SOURCE_TYPES: [&str; 3] = ["MANUAL", "AGENT_FINDING", "VULNERABILITY_FINDING"];
const OBSERVATION_CATEGORIES: [&str; 5] = [
    "POSTURE",
    "VULNERABILITY",
    "THREAT_ACTIVITY",
    "POLICY",
    "OTHER",
];
const SEVERITIES: [&str; 5] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const OBSERVATION_STATUSES: [&str; 5] = ["NEW", "IN_REVIEW", "CONFIRMED", "DISMISSED", "ARCHIVED"];
const MATCH_TYPES: [&str; 3] = ["EXACT", "CONTEXTUAL", "SOURCE_ASSERTED"];
const LINK_STATUSES: [&str; 4] = ["PENDING", "RELEVANT", "NOT_RELEVANT", "NEEDS_REVIEW"];

fn normalize_indicator_request(
    request: ThreatIndicatorWriteRequest,
) -> Result<NormalizedIndicator, ThreatIntelligenceError> {
    let indicator_type = normalize_enum(
        &request.indicator_type,
        &INDICATOR_TYPES,
        "Ungueltiger Indicator-Typ.",
    )?;
    let raw_value = bounded_required_text(
        &request.value,
        MAX_INDICATOR_VALUE_BYTES,
        "Indicator-Wert fehlt oder ist zu lang.",
    )?;
    let normalized_value = normalize_indicator_value(&indicator_type, &raw_value)?;
    let original_value = if normalized_value == raw_value {
        String::new()
    } else {
        raw_value
    };
    let source_type = bounded_upper_text(
        &request.source_type,
        32,
        "Indicator-Quellentyp fehlt oder ist zu lang.",
    )?;
    let source_name = bounded_required_text(
        &request.source_name,
        128,
        "Indicator-Quelle fehlt oder ist zu lang.",
    )?;
    let provenance_reference = bounded_required_text(
        &request.provenance_reference,
        255,
        "Indicator-Provenance fehlt oder ist zu lang.",
    )?;
    let confidence = validate_confidence(request.confidence)?;
    let valid_from = request
        .valid_from
        .as_deref()
        .map(validate_timestamp)
        .transpose()?
        .unwrap_or_else(now_timestamp);
    let valid_until = request
        .valid_until
        .as_deref()
        .map(validate_optional_timestamp)
        .transpose()?
        .flatten();
    validate_time_window(&valid_from, valid_until.as_deref())?;
    let classification = normalize_enum(
        &request.classification,
        &CLASSIFICATIONS,
        "Ungueltige Indicator-Klassifizierung.",
    )?;
    Ok(NormalizedIndicator {
        indicator_type,
        normalized_value,
        original_value,
        source_type,
        source_name,
        provenance_reference,
        confidence,
        valid_from,
        valid_until,
        classification,
    })
}

fn normalize_indicator_value(
    indicator_type: &str,
    raw: &str,
) -> Result<String, ThreatIntelligenceError> {
    match indicator_type {
        "IPV4" => match raw.parse::<IpAddr>() {
            Ok(IpAddr::V4(value)) => Ok(value.to_string()),
            _ => Err(ThreatIntelligenceError::invalid("Ungueltige IPv4-Adresse.")),
        },
        "IPV6" => match raw.parse::<IpAddr>() {
            Ok(IpAddr::V6(value)) => Ok(value.to_string()),
            _ => Err(ThreatIntelligenceError::invalid("Ungueltige IPv6-Adresse.")),
        },
        "DOMAIN" => normalize_domain(raw),
        "URL" => normalize_url(raw),
        "SHA256" => {
            let normalized = raw.to_ascii_lowercase();
            if normalized.len() == 64 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                Ok(normalized)
            } else {
                Err(ThreatIntelligenceError::invalid(
                    "Ungueltiger SHA-256-Wert.",
                ))
            }
        }
        _ => Err(ThreatIntelligenceError::invalid(
            "Ungueltiger Indicator-Typ.",
        )),
    }
}

fn normalize_domain(raw: &str) -> Result<String, ThreatIntelligenceError> {
    let normalized = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > 253
        || !normalized.is_ascii()
        || normalized.parse::<IpAddr>().is_ok()
    {
        return Err(ThreatIntelligenceError::invalid("Ungueltiger Domain-Wert."));
    }
    let labels = normalized.split('.').collect::<Vec<_>>();
    if labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(ThreatIntelligenceError::invalid("Ungueltiger Domain-Wert."));
    }
    Ok(normalized)
}

fn normalize_url(raw: &str) -> Result<String, ThreatIntelligenceError> {
    let mut url = Url::parse(raw)
        .map_err(|_| ThreatIntelligenceError::invalid("Ungueltiger URL-Indikator."))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(ThreatIntelligenceError::invalid(
            "URL-Indikator muss eine HTTP(S)-URL ohne Credentials sein.",
        ));
    }
    url.set_fragment(None);
    let normalized = url.to_string();
    if normalized.len() > MAX_INDICATOR_VALUE_BYTES {
        return Err(ThreatIntelligenceError::invalid(
            "URL-Indikator ist zu lang.",
        ));
    }
    Ok(normalized)
}

async fn normalize_observation_postgres(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    source_type: String,
    request: SecurityObservationWriteRequest,
) -> Result<NormalizedObservation, ThreatIntelligenceError> {
    let reference = if source_type == "AGENT_FINDING" {
        Some(load_agent_finding_postgres(tx, tenant_id, &request.source_reference).await?)
    } else if source_type == "VULNERABILITY_FINDING" {
        Some(load_vulnerability_finding_postgres(tx, tenant_id, &request.source_reference).await?)
    } else {
        None
    };
    ensure_asset_postgres(tx, tenant_id, request.asset_id).await?;
    ensure_owner_postgres(tx, tenant_id, request.owner_id).await?;
    normalize_observation_values(source_type, request, reference, tenant_id, None, None).await
}

async fn normalize_observation_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    source_type: String,
    request: SecurityObservationWriteRequest,
) -> Result<NormalizedObservation, ThreatIntelligenceError> {
    let reference = if source_type == "AGENT_FINDING" {
        Some(load_agent_finding_sqlite(tx, tenant_id, &request.source_reference).await?)
    } else if source_type == "VULNERABILITY_FINDING" {
        Some(load_vulnerability_finding_sqlite(tx, tenant_id, &request.source_reference).await?)
    } else {
        None
    };
    normalize_observation_values(source_type, request, reference, tenant_id, Some(tx), None).await
}

async fn normalize_observation_values(
    source_type: String,
    request: SecurityObservationWriteRequest,
    reference: Option<ReferencedFinding>,
    tenant_id: i64,
    sqlite_tx: Option<&mut Transaction<'_, Sqlite>>,
    _unused: Option<()>,
) -> Result<NormalizedObservation, ThreatIntelligenceError> {
    if let Some(tx) = sqlite_tx {
        ensure_asset_sqlite(tx, tenant_id, request.asset_id).await?;
        ensure_owner_sqlite(tx, tenant_id, request.owner_id).await?;
    }
    if let Some(finding) = reference {
        if request.asset_id.is_some()
            && finding.asset_id.is_some()
            && request.asset_id != finding.asset_id
        {
            return Err(ThreatIntelligenceError::invalid(
                "Asset-Referenz widerspricht dem referenzierten Finding.",
            ));
        }
        let deduplication_key = format!(
            "{}:{}",
            source_type.to_ascii_lowercase(),
            finding.finding_id
        );
        return Ok(NormalizedObservation {
            source_type: source_type.clone(),
            source_reference: finding.source_reference,
            agent_finding_id: (source_type == "AGENT_FINDING").then_some(finding.finding_id),
            vulnerability_finding_id: (source_type == "VULNERABILITY_FINDING")
                .then_some(finding.finding_id),
            asset_id: finding.asset_id.or(request.asset_id),
            deduplication_key,
            observed_at: finding.observed_at,
            category: finding.category.to_string(),
            severity: normalize_enum(
                &finding.severity,
                &SEVERITIES,
                "Referenziertes Finding besitzt keine unterstuetzte Severity.",
            )?,
            title: bounded_required_text(
                &finding.title,
                255,
                "Referenziertes Finding besitzt keinen gueltigen Titel.",
            )?,
            description: bounded_optional_text(
                Some(&finding.description),
                4000,
                "Referenzierte Finding-Beschreibung ist zu lang.",
            )?,
            attributes_json: "{}".to_string(),
            provenance_type: finding.provenance_type.to_string(),
            provenance_reference: finding.provenance_reference,
            owner_id: request.owner_id,
        });
    }
    let source_reference = bounded_required_text(
        &request.source_reference,
        255,
        "Observation-Herkunftsreferenz fehlt oder ist zu lang.",
    )?;
    let deduplication_key = bounded_required_text(
        &request.deduplication_key,
        128,
        "Observation-Deduplizierungsschluessel fehlt oder ist zu lang.",
    )?;
    let observed_at = request
        .observed_at
        .as_deref()
        .map(validate_timestamp)
        .transpose()?
        .unwrap_or_else(now_timestamp);
    let category = normalize_enum(
        request.category.as_deref().unwrap_or("OTHER"),
        &OBSERVATION_CATEGORIES,
        "Ungueltige Observation-Kategorie.",
    )?;
    let severity = normalize_enum(
        request.severity.as_deref().unwrap_or("MEDIUM"),
        &SEVERITIES,
        "Ungueltige Observation-Severity.",
    )?;
    let title = bounded_required_text(
        request.title.as_deref().unwrap_or(""),
        255,
        "Observation-Titel fehlt oder ist zu lang.",
    )?;
    let description = bounded_optional_text(
        request.description.as_deref(),
        4000,
        "Observation-Beschreibung ist zu lang.",
    )?;
    let attributes_json = validate_attributes(request.attributes.unwrap_or_else(|| json!({})))?;
    let provenance_type = bounded_upper_text(
        request.provenance_type.as_deref().unwrap_or("MANUAL"),
        32,
        "Observation-Provenance-Typ fehlt oder ist zu lang.",
    )?;
    let provenance_reference = bounded_required_text(
        request.provenance_reference.as_deref().unwrap_or(""),
        255,
        "Observation-Provenance fehlt oder ist zu lang.",
    )?;
    Ok(NormalizedObservation {
        source_type,
        source_reference,
        agent_finding_id: None,
        vulnerability_finding_id: None,
        asset_id: request.asset_id,
        deduplication_key,
        observed_at,
        category,
        severity,
        title,
        description,
        attributes_json,
        provenance_type,
        provenance_reference,
        owner_id: request.owner_id,
    })
}

fn validate_attributes(value: Value) -> Result<String, ThreatIntelligenceError> {
    if !value.is_object() {
        return Err(ThreatIntelligenceError::invalid(
            "Observation-Attribute muessen ein JSON-Objekt sein.",
        ));
    }
    validate_attribute_value(&value, 0)?;
    let serialized = serde_json::to_string(&value)
        .map_err(|_| ThreatIntelligenceError::invalid("Observation-Attribute sind ungueltig."))?;
    if serialized.len() > MAX_OBSERVATION_ATTRIBUTES_BYTES {
        return Err(ThreatIntelligenceError::invalid(
            "Observation-Attribute sind zu gross.",
        ));
    }
    Ok(serialized)
}

fn validate_attribute_value(value: &Value, depth: usize) -> Result<(), ThreatIntelligenceError> {
    if depth > MAX_ATTRIBUTE_DEPTH {
        return Err(ThreatIntelligenceError::invalid(
            "Observation-Attribute sind zu tief verschachtelt.",
        ));
    }
    match value {
        Value::Object(map) => {
            if map.len() > MAX_ATTRIBUTE_COLLECTION_ITEMS {
                return Err(ThreatIntelligenceError::invalid(
                    "Observation-Attribute enthalten zu viele Felder.",
                ));
            }
            for (key, child) in map {
                if key.len() > 64 || is_sensitive_attribute_key(key) {
                    return Err(ThreatIntelligenceError::invalid(
                        "Observation-Attribute enthalten ein unzulaessiges Feld.",
                    ));
                }
                validate_attribute_value(child, depth + 1)?;
            }
        }
        Value::Array(values) => {
            if values.len() > MAX_ATTRIBUTE_COLLECTION_ITEMS {
                return Err(ThreatIntelligenceError::invalid(
                    "Observation-Attribute enthalten zu viele Listeneintraege.",
                ));
            }
            for child in values {
                validate_attribute_value(child, depth + 1)?;
            }
        }
        Value::String(value) if value.len() > MAX_ATTRIBUTE_STRING_BYTES => {
            return Err(ThreatIntelligenceError::invalid(
                "Observation-Attributwert ist zu lang.",
            ))
        }
        _ => {}
    }
    Ok(())
}

fn is_sensitive_attribute_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase().replace('-', "_");
    [
        "password",
        "passwd",
        "secret",
        "token",
        "authorization",
        "cookie",
        "private_key",
        "credential",
    ]
    .iter()
    .any(|blocked| normalized.contains(blocked))
}

fn bounded_required_text(
    value: &str,
    max: usize,
    message: &'static str,
) -> Result<String, ThreatIntelligenceError> {
    let value = value.trim();
    if value.is_empty() || value.len() > max {
        Err(ThreatIntelligenceError::invalid(message))
    } else {
        Ok(value.to_string())
    }
}

fn bounded_optional_text(
    value: Option<&str>,
    max: usize,
    message: &'static str,
) -> Result<String, ThreatIntelligenceError> {
    let value = value.unwrap_or("").trim();
    if value.len() > max {
        Err(ThreatIntelligenceError::invalid(message))
    } else {
        Ok(value.to_string())
    }
}

fn bounded_upper_text(
    value: &str,
    max: usize,
    message: &'static str,
) -> Result<String, ThreatIntelligenceError> {
    let value = bounded_required_text(value, max, message)?.to_ascii_uppercase();
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        Ok(value)
    } else {
        Err(ThreatIntelligenceError::invalid(message))
    }
}

fn normalize_enum(
    value: &str,
    allowed: &[&str],
    message: &'static str,
) -> Result<String, ThreatIntelligenceError> {
    let value = value.trim().to_ascii_uppercase().replace([' ', '-'], "_");
    if allowed.iter().any(|candidate| *candidate == value) {
        Ok(value)
    } else {
        Err(ThreatIntelligenceError::invalid(message))
    }
}

fn validate_confidence(value: i64) -> Result<i64, ThreatIntelligenceError> {
    (0..=100).contains(&value).then_some(value).ok_or_else(|| {
        ThreatIntelligenceError::invalid("Indicator-Confidence muss zwischen 0 und 100 liegen.")
    })
}

fn validate_timestamp(value: &str) -> Result<String, ThreatIntelligenceError> {
    DateTime::parse_from_rfc3339(value.trim())
        .map(|value| {
            value
                .with_timezone(&Utc)
                .to_rfc3339_opts(SecondsFormat::Secs, true)
        })
        .map_err(|_| ThreatIntelligenceError::invalid("Zeitstempel muss RFC 3339 entsprechen."))
}

fn validate_optional_timestamp(value: &str) -> Result<Option<String>, ThreatIntelligenceError> {
    let value = value.trim();
    if value.is_empty() {
        Ok(None)
    } else {
        validate_timestamp(value).map(Some)
    }
}

fn validate_time_window(
    valid_from: &str,
    valid_until: Option<&str>,
) -> Result<(), ThreatIntelligenceError> {
    if let Some(valid_until) = valid_until {
        let start = DateTime::parse_from_rfc3339(valid_from)
            .map_err(|_| ThreatIntelligenceError::invalid("Ungueltiger Gueltigkeitsbeginn."))?;
        let end = DateTime::parse_from_rfc3339(valid_until)
            .map_err(|_| ThreatIntelligenceError::invalid("Ungueltiges Gueltigkeitsende."))?;
        if end <= start {
            return Err(ThreatIntelligenceError::invalid(
                "Gueltigkeitsende muss nach dem Gueltigkeitsbeginn liegen.",
            ));
        }
    }
    Ok(())
}

fn now_timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}
fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn ensure_same_indicator_provenance(
    existing: &ThreatIndicatorSummary,
    requested: &NormalizedIndicator,
) -> Result<(), ThreatIntelligenceError> {
    if existing.source_type == requested.source_type
        && existing.source_name == requested.source_name
        && existing.provenance_reference == requested.provenance_reference
    {
        Ok(())
    } else {
        Err(ThreatIntelligenceError::conflict(
            "Indikator existiert bereits mit abweichender Provenance.",
        ))
    }
}

fn ensure_same_observation_origin(
    existing: &SecurityObservationSummary,
    requested: &NormalizedObservation,
) -> Result<(), ThreatIntelligenceError> {
    if existing.source_type == requested.source_type
        && existing.source_reference == requested.source_reference
        && existing.deduplication_key == requested.deduplication_key
    {
        Ok(())
    } else {
        Err(ThreatIntelligenceError::conflict(
            "Observation-Herkunft oder Deduplizierungsschluessel ist bereits anderweitig belegt.",
        ))
    }
}

fn indicator_select_postgres() -> &'static str {
    "SELECT id,tenant_id,indicator_type,normalized_value,original_value,source_type,source_name,provenance_reference,confidence::bigint AS confidence,valid_from,valid_until,lifecycle_status,classification,created_by_id,updated_by_id,created_at::text AS created_at,updated_at::text AS updated_at FROM threat_intelligence_indicator WHERE tenant_id=$1 ORDER BY updated_at DESC,id DESC LIMIT $2"
}
fn indicator_select_sqlite() -> &'static str {
    "SELECT id,tenant_id,indicator_type,normalized_value,original_value,source_type,source_name,provenance_reference,confidence,valid_from,valid_until,lifecycle_status,classification,created_by_id,updated_by_id,CAST(created_at AS TEXT) AS created_at,CAST(updated_at AS TEXT) AS updated_at FROM threat_intelligence_indicator WHERE tenant_id=?1 ORDER BY updated_at DESC,id DESC LIMIT ?2"
}
fn indicator_insert_postgres() -> &'static str {
    "INSERT INTO threat_intelligence_indicator (tenant_id,indicator_type,normalized_value,original_value,source_type,source_name,provenance_reference,confidence,valid_from,valid_until,lifecycle_status,classification,created_by_id,updated_by_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'ACTIVE',$11,$12,$12) ON CONFLICT (tenant_id,indicator_type,normalized_value) DO NOTHING RETURNING id,tenant_id,indicator_type,normalized_value,original_value,source_type,source_name,provenance_reference,confidence::bigint AS confidence,valid_from,valid_until,lifecycle_status,classification,created_by_id,updated_by_id,created_at::text AS created_at,updated_at::text AS updated_at"
}
fn indicator_insert_sqlite() -> &'static str {
    "INSERT INTO threat_intelligence_indicator (tenant_id,indicator_type,normalized_value,original_value,source_type,source_name,provenance_reference,confidence,valid_from,valid_until,lifecycle_status,classification,created_by_id,updated_by_id) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'ACTIVE',?11,?12,?12) ON CONFLICT (tenant_id,indicator_type,normalized_value) DO NOTHING RETURNING id,tenant_id,indicator_type,normalized_value,original_value,source_type,source_name,provenance_reference,confidence,valid_from,valid_until,lifecycle_status,classification,created_by_id,updated_by_id,CAST(created_at AS TEXT) AS created_at,CAST(updated_at AS TEXT) AS updated_at"
}
fn indicator_update_postgres() -> &'static str {
    "UPDATE threat_intelligence_indicator SET confidence=$3,valid_from=$4,valid_until=$5,lifecycle_status=$6,classification=$7,updated_by_id=$8,updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$1 AND id=$2 RETURNING id,tenant_id,indicator_type,normalized_value,original_value,source_type,source_name,provenance_reference,confidence::bigint AS confidence,valid_from,valid_until,lifecycle_status,classification,created_by_id,updated_by_id,created_at::text AS created_at,updated_at::text AS updated_at"
}
fn indicator_update_sqlite() -> &'static str {
    "UPDATE threat_intelligence_indicator SET confidence=?3,valid_from=?4,valid_until=?5,lifecycle_status=?6,classification=?7,updated_by_id=?8,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?1 AND id=?2 RETURNING id,tenant_id,indicator_type,normalized_value,original_value,source_type,source_name,provenance_reference,confidence,valid_from,valid_until,lifecycle_status,classification,created_by_id,updated_by_id,CAST(created_at AS TEXT) AS created_at,CAST(updated_at AS TEXT) AS updated_at"
}

async fn load_indicator_postgres(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    indicator_type: &str,
    value: &str,
) -> Result<Option<ThreatIndicatorSummary>, ThreatIntelligenceError> {
    let row=sqlx::query("SELECT id,tenant_id,indicator_type,normalized_value,original_value,source_type,source_name,provenance_reference,confidence::bigint AS confidence,valid_from,valid_until,lifecycle_status,classification,created_by_id,updated_by_id,created_at::text AS created_at,updated_at::text AS updated_at FROM threat_intelligence_indicator WHERE tenant_id=$1 AND indicator_type=$2 AND normalized_value=$3").bind(tenant_id).bind(indicator_type).bind(value).fetch_optional(&mut **tx).await.map_err(|_|ThreatIntelligenceError::database())?;
    row.map(indicator_from_pg_row)
        .transpose()
        .map_err(|_| ThreatIntelligenceError::database())
}
async fn load_indicator_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    indicator_type: &str,
    value: &str,
) -> Result<Option<ThreatIndicatorSummary>, ThreatIntelligenceError> {
    let row=sqlx::query("SELECT id,tenant_id,indicator_type,normalized_value,original_value,source_type,source_name,provenance_reference,confidence,valid_from,valid_until,lifecycle_status,classification,created_by_id,updated_by_id,CAST(created_at AS TEXT) AS created_at,CAST(updated_at AS TEXT) AS updated_at FROM threat_intelligence_indicator WHERE tenant_id=?1 AND indicator_type=?2 AND normalized_value=?3").bind(tenant_id).bind(indicator_type).bind(value).fetch_optional(&mut **tx).await.map_err(|_|ThreatIntelligenceError::database())?;
    row.map(indicator_from_sqlite_row)
        .transpose()
        .map_err(|_| ThreatIntelligenceError::database())
}
async fn load_indicator_by_id_postgres(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    id: i64,
) -> Result<Option<ThreatIndicatorSummary>, ThreatIntelligenceError> {
    let row=sqlx::query("SELECT id,tenant_id,indicator_type,normalized_value,original_value,source_type,source_name,provenance_reference,confidence::bigint AS confidence,valid_from,valid_until,lifecycle_status,classification,created_by_id,updated_by_id,created_at::text AS created_at,updated_at::text AS updated_at FROM threat_intelligence_indicator WHERE tenant_id=$1 AND id=$2").bind(tenant_id).bind(id).fetch_optional(&mut **tx).await.map_err(|_|ThreatIntelligenceError::database())?;
    row.map(indicator_from_pg_row)
        .transpose()
        .map_err(|_| ThreatIntelligenceError::database())
}
async fn load_indicator_by_id_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    id: i64,
) -> Result<Option<ThreatIndicatorSummary>, ThreatIntelligenceError> {
    let row=sqlx::query("SELECT id,tenant_id,indicator_type,normalized_value,original_value,source_type,source_name,provenance_reference,confidence,valid_from,valid_until,lifecycle_status,classification,created_by_id,updated_by_id,CAST(created_at AS TEXT) AS created_at,CAST(updated_at AS TEXT) AS updated_at FROM threat_intelligence_indicator WHERE tenant_id=?1 AND id=?2").bind(tenant_id).bind(id).fetch_optional(&mut **tx).await.map_err(|_|ThreatIntelligenceError::database())?;
    row.map(indicator_from_sqlite_row)
        .transpose()
        .map_err(|_| ThreatIntelligenceError::database())
}

fn observation_select_postgres() -> &'static str {
    "SELECT o.id,o.tenant_id,o.source_type,o.source_reference,o.agent_finding_id,o.vulnerability_finding_id,o.asset_id,a.name AS asset_name,o.deduplication_key,o.observed_at,o.recorded_at,o.category,o.severity,o.title,o.description,o.attributes_json,o.provenance_type,o.provenance_reference,o.triage_status,o.owner_id,o.created_by_id,o.updated_by_id,o.created_at::text AS created_at,o.updated_at::text AS updated_at FROM security_observation o LEFT JOIN assets_app_informationasset a ON a.tenant_id=o.tenant_id AND a.id=o.asset_id WHERE o.tenant_id=$1 ORDER BY o.observed_at DESC,o.id DESC LIMIT $2"
}
fn observation_select_sqlite() -> &'static str {
    "SELECT o.id,o.tenant_id,o.source_type,o.source_reference,o.agent_finding_id,o.vulnerability_finding_id,o.asset_id,a.name AS asset_name,o.deduplication_key,o.observed_at,o.recorded_at,o.category,o.severity,o.title,o.description,o.attributes_json,o.provenance_type,o.provenance_reference,o.triage_status,o.owner_id,o.created_by_id,o.updated_by_id,CAST(o.created_at AS TEXT) AS created_at,CAST(o.updated_at AS TEXT) AS updated_at FROM security_observation o LEFT JOIN assets_app_informationasset a ON a.tenant_id=o.tenant_id AND a.id=o.asset_id WHERE o.tenant_id=?1 ORDER BY o.observed_at DESC,o.id DESC LIMIT ?2"
}
fn observation_insert_postgres() -> &'static str {
    "INSERT INTO security_observation (tenant_id,source_type,source_reference,agent_finding_id,vulnerability_finding_id,asset_id,deduplication_key,observed_at,category,severity,title,description,attributes_json,provenance_type,provenance_reference,triage_status,owner_id,created_by_id,updated_by_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'NEW',$16,$17,$17) ON CONFLICT DO NOTHING RETURNING id"
}
fn observation_insert_sqlite() -> &'static str {
    "INSERT INTO security_observation (tenant_id,source_type,source_reference,agent_finding_id,vulnerability_finding_id,asset_id,deduplication_key,observed_at,category,severity,title,description,attributes_json,provenance_type,provenance_reference,triage_status,owner_id,created_by_id,updated_by_id) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,'NEW',?16,?17,?17) ON CONFLICT DO NOTHING RETURNING id"
}
fn observation_triage_postgres() -> &'static str {
    "UPDATE security_observation SET triage_status=$3,owner_id=$4,updated_by_id=$5,updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$1 AND id=$2 RETURNING id,tenant_id,source_type,source_reference,agent_finding_id,vulnerability_finding_id,asset_id,NULL::text AS asset_name,deduplication_key,observed_at,recorded_at,category,severity,title,description,attributes_json,provenance_type,provenance_reference,triage_status,owner_id,created_by_id,updated_by_id,created_at::text AS created_at,updated_at::text AS updated_at"
}
fn observation_triage_sqlite() -> &'static str {
    "UPDATE security_observation SET triage_status=?3,owner_id=?4,updated_by_id=?5,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?1 AND id=?2 RETURNING id,tenant_id,source_type,source_reference,agent_finding_id,vulnerability_finding_id,asset_id,NULL AS asset_name,deduplication_key,observed_at,recorded_at,category,severity,title,description,attributes_json,provenance_type,provenance_reference,triage_status,owner_id,created_by_id,updated_by_id,CAST(created_at AS TEXT) AS created_at,CAST(updated_at AS TEXT) AS updated_at"
}

async fn insert_observation_postgres(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    actor_id: i64,
    o: &NormalizedObservation,
) -> Result<Option<SecurityObservationSummary>, ThreatIntelligenceError> {
    let id: Option<i64> = sqlx::query_scalar(observation_insert_postgres())
        .bind(tenant_id)
        .bind(&o.source_type)
        .bind(&o.source_reference)
        .bind(o.agent_finding_id)
        .bind(o.vulnerability_finding_id)
        .bind(o.asset_id)
        .bind(&o.deduplication_key)
        .bind(&o.observed_at)
        .bind(&o.category)
        .bind(&o.severity)
        .bind(&o.title)
        .bind(&o.description)
        .bind(&o.attributes_json)
        .bind(&o.provenance_type)
        .bind(&o.provenance_reference)
        .bind(o.owner_id)
        .bind(actor_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| ThreatIntelligenceError::database())?;
    match id {
        Some(id) => load_observation_by_id_postgres(tx, tenant_id, id).await,
        None => Ok(None),
    }
}
async fn insert_observation_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    actor_id: i64,
    o: &NormalizedObservation,
) -> Result<Option<SecurityObservationSummary>, ThreatIntelligenceError> {
    let id: Option<i64> = sqlx::query_scalar(observation_insert_sqlite())
        .bind(tenant_id)
        .bind(&o.source_type)
        .bind(&o.source_reference)
        .bind(o.agent_finding_id)
        .bind(o.vulnerability_finding_id)
        .bind(o.asset_id)
        .bind(&o.deduplication_key)
        .bind(&o.observed_at)
        .bind(&o.category)
        .bind(&o.severity)
        .bind(&o.title)
        .bind(&o.description)
        .bind(&o.attributes_json)
        .bind(&o.provenance_type)
        .bind(&o.provenance_reference)
        .bind(o.owner_id)
        .bind(actor_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| ThreatIntelligenceError::database())?;
    match id {
        Some(id) => load_observation_by_id_sqlite(tx, tenant_id, id).await,
        None => Ok(None),
    }
}
async fn load_observation_by_id_postgres(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    id: i64,
) -> Result<Option<SecurityObservationSummary>, ThreatIntelligenceError> {
    let sql = observation_select_postgres().replace(
        "WHERE o.tenant_id=$1 ORDER BY o.observed_at DESC,o.id DESC LIMIT $2",
        "WHERE o.tenant_id=$1 AND o.id=$2",
    );
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| ThreatIntelligenceError::database())?;
    row.map(observation_from_pg_row)
        .transpose()
        .map_err(|_| ThreatIntelligenceError::database())
}
async fn load_observation_by_id_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    id: i64,
) -> Result<Option<SecurityObservationSummary>, ThreatIntelligenceError> {
    let sql = observation_select_sqlite().replace(
        "WHERE o.tenant_id=?1 ORDER BY o.observed_at DESC,o.id DESC LIMIT ?2",
        "WHERE o.tenant_id=?1 AND o.id=?2",
    );
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| ThreatIntelligenceError::database())?;
    row.map(observation_from_sqlite_row)
        .transpose()
        .map_err(|_| ThreatIntelligenceError::database())
}
async fn load_observation_by_origin_postgres(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    source_type: &str,
    source_ref: &str,
    dedupe: &str,
) -> Result<Option<SecurityObservationSummary>, ThreatIntelligenceError> {
    let sql=observation_select_postgres().replace("WHERE o.tenant_id=$1 ORDER BY o.observed_at DESC,o.id DESC LIMIT $2","WHERE o.tenant_id=$1 AND ((o.source_type=$2 AND o.source_reference=$3) OR o.deduplication_key=$4) ORDER BY o.id LIMIT 1");
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(source_type)
        .bind(source_ref)
        .bind(dedupe)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| ThreatIntelligenceError::database())?;
    row.map(observation_from_pg_row)
        .transpose()
        .map_err(|_| ThreatIntelligenceError::database())
}
async fn load_observation_by_origin_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    source_type: &str,
    source_ref: &str,
    dedupe: &str,
) -> Result<Option<SecurityObservationSummary>, ThreatIntelligenceError> {
    let sql=observation_select_sqlite().replace("WHERE o.tenant_id=?1 ORDER BY o.observed_at DESC,o.id DESC LIMIT ?2","WHERE o.tenant_id=?1 AND ((o.source_type=?2 AND o.source_reference=?3) OR o.deduplication_key=?4) ORDER BY o.id LIMIT 1");
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(source_type)
        .bind(source_ref)
        .bind(dedupe)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| ThreatIntelligenceError::database())?;
    row.map(observation_from_sqlite_row)
        .transpose()
        .map_err(|_| ThreatIntelligenceError::database())
}

async fn load_agent_finding_postgres(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    source_ref: &str,
) -> Result<ReferencedFinding, ThreatIntelligenceError> {
    let id = parse_reference_id(source_ref)?;
    let row=sqlx::query("SELECT f.id,f.title,f.description,f.severity,f.observed_at,d.asset_id FROM zero_trust_agent_finding f JOIN zero_trust_agent_device d ON d.tenant_id=f.tenant_id AND d.id=f.device_id WHERE f.tenant_id=$1 AND f.id=$2").bind(tenant_id).bind(id).fetch_optional(&mut **tx).await.map_err(|_|ThreatIntelligenceError::database())?.ok_or_else(||ThreatIntelligenceError::not_found("Referenziertes Finding wurde nicht gefunden."))?;
    Ok(ReferencedFinding {
        source_reference: id.to_string(),
        finding_id: id,
        asset_id: row
            .try_get("asset_id")
            .map_err(|_| ThreatIntelligenceError::database())?,
        observed_at: row
            .try_get("observed_at")
            .map_err(|_| ThreatIntelligenceError::database())?,
        category: "POSTURE",
        severity: row
            .try_get("severity")
            .map_err(|_| ThreatIntelligenceError::database())?,
        title: row
            .try_get("title")
            .map_err(|_| ThreatIntelligenceError::database())?,
        description: row
            .try_get("description")
            .map_err(|_| ThreatIntelligenceError::database())?,
        provenance_type: "ISCY_AGENT_FINDING",
        provenance_reference: format!("zero_trust_agent_finding:{id}"),
    })
}
async fn load_agent_finding_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    source_ref: &str,
) -> Result<ReferencedFinding, ThreatIntelligenceError> {
    let id = parse_reference_id(source_ref)?;
    let row=sqlx::query("SELECT f.id,f.title,f.description,f.severity,f.observed_at,d.asset_id FROM zero_trust_agent_finding f JOIN zero_trust_agent_device d ON d.tenant_id=f.tenant_id AND d.id=f.device_id WHERE f.tenant_id=?1 AND f.id=?2").bind(tenant_id).bind(id).fetch_optional(&mut **tx).await.map_err(|_|ThreatIntelligenceError::database())?.ok_or_else(||ThreatIntelligenceError::not_found("Referenziertes Finding wurde nicht gefunden."))?;
    Ok(ReferencedFinding {
        source_reference: id.to_string(),
        finding_id: id,
        asset_id: row
            .try_get("asset_id")
            .map_err(|_| ThreatIntelligenceError::database())?,
        observed_at: row
            .try_get("observed_at")
            .map_err(|_| ThreatIntelligenceError::database())?,
        category: "POSTURE",
        severity: row
            .try_get("severity")
            .map_err(|_| ThreatIntelligenceError::database())?,
        title: row
            .try_get("title")
            .map_err(|_| ThreatIntelligenceError::database())?,
        description: row
            .try_get("description")
            .map_err(|_| ThreatIntelligenceError::database())?,
        provenance_type: "ISCY_AGENT_FINDING",
        provenance_reference: format!("zero_trust_agent_finding:{id}"),
    })
}
async fn load_vulnerability_finding_postgres(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    source_ref: &str,
) -> Result<ReferencedFinding, ThreatIntelligenceError> {
    let id = parse_reference_id(source_ref)?;
    let row=sqlx::query("SELECT id,title,summary,severity,created_at::text AS observed_at FROM product_security_vulnerability WHERE tenant_id=$1 AND id=$2").bind(tenant_id).bind(id).fetch_optional(&mut **tx).await.map_err(|_|ThreatIntelligenceError::database())?.ok_or_else(||ThreatIntelligenceError::not_found("Referenziertes Finding wurde nicht gefunden."))?;
    Ok(ReferencedFinding {
        source_reference: id.to_string(),
        finding_id: id,
        asset_id: None,
        observed_at: row
            .try_get("observed_at")
            .map_err(|_| ThreatIntelligenceError::database())?,
        category: "VULNERABILITY",
        severity: row
            .try_get("severity")
            .map_err(|_| ThreatIntelligenceError::database())?,
        title: row
            .try_get("title")
            .map_err(|_| ThreatIntelligenceError::database())?,
        description: row
            .try_get("summary")
            .map_err(|_| ThreatIntelligenceError::database())?,
        provenance_type: "ISCY_VULNERABILITY_FINDING",
        provenance_reference: format!("product_security_vulnerability:{id}"),
    })
}
async fn load_vulnerability_finding_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    source_ref: &str,
) -> Result<ReferencedFinding, ThreatIntelligenceError> {
    let id = parse_reference_id(source_ref)?;
    let row=sqlx::query("SELECT id,title,summary,severity,CAST(created_at AS TEXT) AS observed_at FROM product_security_vulnerability WHERE tenant_id=?1 AND id=?2").bind(tenant_id).bind(id).fetch_optional(&mut **tx).await.map_err(|_|ThreatIntelligenceError::database())?.ok_or_else(||ThreatIntelligenceError::not_found("Referenziertes Finding wurde nicht gefunden."))?;
    Ok(ReferencedFinding {
        source_reference: id.to_string(),
        finding_id: id,
        asset_id: None,
        observed_at: row
            .try_get("observed_at")
            .map_err(|_| ThreatIntelligenceError::database())?,
        category: "VULNERABILITY",
        severity: row
            .try_get("severity")
            .map_err(|_| ThreatIntelligenceError::database())?,
        title: row
            .try_get("title")
            .map_err(|_| ThreatIntelligenceError::database())?,
        description: row
            .try_get("summary")
            .map_err(|_| ThreatIntelligenceError::database())?,
        provenance_type: "ISCY_VULNERABILITY_FINDING",
        provenance_reference: format!("product_security_vulnerability:{id}"),
    })
}
fn parse_reference_id(value: &str) -> Result<i64, ThreatIntelligenceError> {
    value
        .trim()
        .parse::<i64>()
        .ok()
        .filter(|id| *id > 0)
        .ok_or_else(|| {
            ThreatIntelligenceError::invalid("Finding-Referenz muss eine positive ID sein.")
        })
}

async fn ensure_asset_postgres(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    asset_id: Option<i64>,
) -> Result<(), ThreatIntelligenceError> {
    if let Some(id) = asset_id {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM assets_app_informationasset WHERE tenant_id=$1 AND id=$2)",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| ThreatIntelligenceError::database())?;
        if !exists {
            return Err(ThreatIntelligenceError::not_found(
                "Referenziertes Objekt wurde nicht gefunden.",
            ));
        }
    }
    Ok(())
}
async fn ensure_asset_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    asset_id: Option<i64>,
) -> Result<(), ThreatIntelligenceError> {
    if let Some(id) = asset_id {
        let exists: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM assets_app_informationasset WHERE tenant_id=?1 AND id=?2)",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| ThreatIntelligenceError::database())?;
        if exists == 0 {
            return Err(ThreatIntelligenceError::not_found(
                "Referenziertes Objekt wurde nicht gefunden.",
            ));
        }
    }
    Ok(())
}
async fn ensure_owner_postgres(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    owner_id: Option<i64>,
) -> Result<(), ThreatIntelligenceError> {
    if let Some(id) = owner_id {
        let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM accounts_user WHERE tenant_id=$1 AND id=$2 AND is_active=TRUE)").bind(tenant_id).bind(id).fetch_one(&mut **tx).await.map_err(|_|ThreatIntelligenceError::database())?;
        if !exists {
            return Err(ThreatIntelligenceError::not_found(
                "Owner wurde nicht gefunden.",
            ));
        }
    }
    Ok(())
}
async fn ensure_owner_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    owner_id: Option<i64>,
) -> Result<(), ThreatIntelligenceError> {
    if let Some(id) = owner_id {
        let exists:i64=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM accounts_user WHERE tenant_id=?1 AND id=?2 AND is_active=1)").bind(tenant_id).bind(id).fetch_one(&mut **tx).await.map_err(|_|ThreatIntelligenceError::database())?;
        if exists == 0 {
            return Err(ThreatIntelligenceError::not_found(
                "Owner wurde nicht gefunden.",
            ));
        }
    }
    Ok(())
}

fn link_select_postgres() -> &'static str {
    "SELECT l.id,l.tenant_id,l.observation_id,o.title AS observation_title,l.indicator_id,i.indicator_type,i.normalized_value AS indicator_value,l.match_origin,l.match_type,l.matched_at,l.evaluator_id,l.triage_status,l.rationale,l.created_at::text AS created_at,l.updated_at::text AS updated_at FROM security_observation_indicator_link l JOIN security_observation o ON o.tenant_id=l.tenant_id AND o.id=l.observation_id JOIN threat_intelligence_indicator i ON i.tenant_id=l.tenant_id AND i.id=l.indicator_id WHERE l.tenant_id=$1 ORDER BY l.matched_at DESC,l.id DESC LIMIT $2"
}
fn link_select_sqlite() -> &'static str {
    "SELECT l.id,l.tenant_id,l.observation_id,o.title AS observation_title,l.indicator_id,i.indicator_type,i.normalized_value AS indicator_value,l.match_origin,l.match_type,l.matched_at,l.evaluator_id,l.triage_status,l.rationale,CAST(l.created_at AS TEXT) AS created_at,CAST(l.updated_at AS TEXT) AS updated_at FROM security_observation_indicator_link l JOIN security_observation o ON o.tenant_id=l.tenant_id AND o.id=l.observation_id JOIN threat_intelligence_indicator i ON i.tenant_id=l.tenant_id AND i.id=l.indicator_id WHERE l.tenant_id=?1 ORDER BY l.matched_at DESC,l.id DESC LIMIT ?2"
}
fn link_select_for_observation_postgres() -> &'static str {
    "SELECT l.id,l.tenant_id,l.observation_id,o.title AS observation_title,l.indicator_id,i.indicator_type,i.normalized_value AS indicator_value,l.match_origin,l.match_type,l.matched_at,l.evaluator_id,l.triage_status,l.rationale,l.created_at::text AS created_at,l.updated_at::text AS updated_at FROM security_observation_indicator_link l JOIN security_observation o ON o.tenant_id=l.tenant_id AND o.id=l.observation_id JOIN threat_intelligence_indicator i ON i.tenant_id=l.tenant_id AND i.id=l.indicator_id WHERE l.tenant_id=$1 AND l.observation_id=$2 ORDER BY l.matched_at DESC,l.id DESC LIMIT $3"
}
fn link_select_for_observation_sqlite() -> &'static str {
    "SELECT l.id,l.tenant_id,l.observation_id,o.title AS observation_title,l.indicator_id,i.indicator_type,i.normalized_value AS indicator_value,l.match_origin,l.match_type,l.matched_at,l.evaluator_id,l.triage_status,l.rationale,CAST(l.created_at AS TEXT) AS created_at,CAST(l.updated_at AS TEXT) AS updated_at FROM security_observation_indicator_link l JOIN security_observation o ON o.tenant_id=l.tenant_id AND o.id=l.observation_id JOIN threat_intelligence_indicator i ON i.tenant_id=l.tenant_id AND i.id=l.indicator_id WHERE l.tenant_id=?1 AND l.observation_id=?2 ORDER BY l.matched_at DESC,l.id DESC LIMIT ?3"
}
fn link_insert_postgres() -> &'static str {
    "INSERT INTO security_observation_indicator_link (tenant_id,observation_id,indicator_id,match_origin,match_type,matched_at,evaluator_id,triage_status,rationale) VALUES ($1,$2,$3,'MANUAL',$4,(CURRENT_TIMESTAMP)::text,$5,'PENDING',$6) ON CONFLICT (tenant_id,observation_id,indicator_id) DO NOTHING RETURNING id"
}
fn link_insert_sqlite() -> &'static str {
    "INSERT INTO security_observation_indicator_link (tenant_id,observation_id,indicator_id,match_origin,match_type,matched_at,evaluator_id,triage_status,rationale) VALUES (?1,?2,?3,'MANUAL',?4,CURRENT_TIMESTAMP,?5,'PENDING',?6) ON CONFLICT (tenant_id,observation_id,indicator_id) DO NOTHING RETURNING id"
}
fn link_triage_postgres() -> &'static str {
    "UPDATE security_observation_indicator_link SET triage_status=$4,rationale=$5,evaluator_id=$6,updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$1 AND observation_id=$2 AND id=$3 RETURNING id"
}
fn link_triage_sqlite() -> &'static str {
    "UPDATE security_observation_indicator_link SET triage_status=?4,rationale=?5,evaluator_id=?6,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?1 AND observation_id=?2 AND id=?3 RETURNING id"
}

async fn ensure_observation_and_indicator_postgres(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    observation_id: i64,
    indicator_id: i64,
) -> Result<(), ThreatIntelligenceError> {
    let count:i64=sqlx::query_scalar("SELECT (CASE WHEN EXISTS(SELECT 1 FROM security_observation WHERE tenant_id=$1 AND id=$2) THEN 1 ELSE 0 END + CASE WHEN EXISTS(SELECT 1 FROM threat_intelligence_indicator WHERE tenant_id=$1 AND id=$3) THEN 1 ELSE 0 END)::bigint").bind(tenant_id).bind(observation_id).bind(indicator_id).fetch_one(&mut **tx).await.map_err(|_|ThreatIntelligenceError::database())?;
    if count == 2 {
        Ok(())
    } else {
        Err(ThreatIntelligenceError::not_found(
            "Referenziertes Objekt wurde nicht gefunden.",
        ))
    }
}
async fn ensure_observation_and_indicator_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    observation_id: i64,
    indicator_id: i64,
) -> Result<(), ThreatIntelligenceError> {
    let count:i64=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM security_observation WHERE tenant_id=?1 AND id=?2) + EXISTS(SELECT 1 FROM threat_intelligence_indicator WHERE tenant_id=?1 AND id=?3)").bind(tenant_id).bind(observation_id).bind(indicator_id).fetch_one(&mut **tx).await.map_err(|_|ThreatIntelligenceError::database())?;
    if count == 2 {
        Ok(())
    } else {
        Err(ThreatIntelligenceError::not_found(
            "Referenziertes Objekt wurde nicht gefunden.",
        ))
    }
}
async fn load_link_postgres(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    observation_id: i64,
    indicator_id: i64,
) -> Result<Option<ObservationIndicatorLinkSummary>, ThreatIntelligenceError> {
    let sql = link_select_postgres().replace(
        "WHERE l.tenant_id=$1 ORDER BY l.matched_at DESC,l.id DESC LIMIT $2",
        "WHERE l.tenant_id=$1 AND l.observation_id=$2 AND l.indicator_id=$3",
    );
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(observation_id)
        .bind(indicator_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| ThreatIntelligenceError::database())?;
    row.map(link_from_pg_row)
        .transpose()
        .map_err(|_| ThreatIntelligenceError::database())
}
async fn load_link_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    observation_id: i64,
    indicator_id: i64,
) -> Result<Option<ObservationIndicatorLinkSummary>, ThreatIntelligenceError> {
    let sql = link_select_sqlite().replace(
        "WHERE l.tenant_id=?1 ORDER BY l.matched_at DESC,l.id DESC LIMIT ?2",
        "WHERE l.tenant_id=?1 AND l.observation_id=?2 AND l.indicator_id=?3",
    );
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(observation_id)
        .bind(indicator_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| ThreatIntelligenceError::database())?;
    row.map(link_from_sqlite_row)
        .transpose()
        .map_err(|_| ThreatIntelligenceError::database())
}

async fn load_link_by_id_postgres(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    link_id: i64,
) -> Result<Option<ObservationIndicatorLinkSummary>, ThreatIntelligenceError> {
    let sql = link_select_postgres().replace(
        "WHERE l.tenant_id=$1 ORDER BY l.matched_at DESC,l.id DESC LIMIT $2",
        "WHERE l.tenant_id=$1 AND l.id=$2",
    );
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(link_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| ThreatIntelligenceError::database())?;
    row.map(link_from_pg_row)
        .transpose()
        .map_err(|_| ThreatIntelligenceError::database())
}

async fn load_link_by_id_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    link_id: i64,
) -> Result<Option<ObservationIndicatorLinkSummary>, ThreatIntelligenceError> {
    let sql = link_select_sqlite().replace(
        "WHERE l.tenant_id=?1 ORDER BY l.matched_at DESC,l.id DESC LIMIT ?2",
        "WHERE l.tenant_id=?1 AND l.id=?2",
    );
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(link_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| ThreatIntelligenceError::database())?;
    row.map(link_from_sqlite_row)
        .transpose()
        .map_err(|_| ThreatIntelligenceError::database())
}

fn audit_select_postgres() -> &'static str {
    "SELECT id,tenant_id,object_type,object_id,event_type,actor_id,summary,detail_json,created_at::text AS created_at FROM security_observation_audit_event WHERE tenant_id=$1 ORDER BY created_at DESC,id DESC LIMIT $2"
}
fn audit_select_sqlite() -> &'static str {
    "SELECT id,tenant_id,object_type,object_id,event_type,actor_id,summary,detail_json,CAST(created_at AS TEXT) AS created_at FROM security_observation_audit_event WHERE tenant_id=?1 ORDER BY created_at DESC,id DESC LIMIT ?2"
}
async fn insert_audit_postgres(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    object: (&str, i64),
    event_type: &str,
    actor_id: i64,
    summary: &str,
    detail: &Value,
) -> Result<(), ThreatIntelligenceError> {
    let detail = serde_json::to_string(detail).map_err(|_| ThreatIntelligenceError::database())?;
    if detail.len() > 2048 {
        return Err(ThreatIntelligenceError::invalid(
            "Audit-Metadaten sind zu gross.",
        ));
    }
    sqlx::query("INSERT INTO security_observation_audit_event (tenant_id,object_type,object_id,event_type,actor_id,summary,detail_json) VALUES ($1,$2,$3,$4,$5,$6,$7)").bind(tenant_id).bind(object.0).bind(object.1).bind(event_type).bind(actor_id).bind(summary).bind(detail).execute(&mut **tx).await.map_err(|_|ThreatIntelligenceError::database())?;
    Ok(())
}
async fn insert_audit_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    object: (&str, i64),
    event_type: &str,
    actor_id: i64,
    summary: &str,
    detail: &Value,
) -> Result<(), ThreatIntelligenceError> {
    let detail = serde_json::to_string(detail).map_err(|_| ThreatIntelligenceError::database())?;
    if detail.len() > 2048 {
        return Err(ThreatIntelligenceError::invalid(
            "Audit-Metadaten sind zu gross.",
        ));
    }
    sqlx::query("INSERT INTO security_observation_audit_event (tenant_id,object_type,object_id,event_type,actor_id,summary,detail_json) VALUES (?1,?2,?3,?4,?5,?6,?7)").bind(tenant_id).bind(object.0).bind(object.1).bind(event_type).bind(actor_id).bind(summary).bind(detail).execute(&mut **tx).await.map_err(|_|ThreatIntelligenceError::database())?;
    Ok(())
}

fn indicator_from_pg_row(row: PgRow) -> Result<ThreatIndicatorSummary, sqlx::Error> {
    Ok(ThreatIndicatorSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        indicator_type: row.try_get("indicator_type")?,
        normalized_value: row.try_get("normalized_value")?,
        original_value: row.try_get("original_value")?,
        source_type: row.try_get("source_type")?,
        source_name: row.try_get("source_name")?,
        provenance_reference: row.try_get("provenance_reference")?,
        confidence: row.try_get("confidence")?,
        valid_from: row.try_get("valid_from")?,
        valid_until: row.try_get("valid_until")?,
        lifecycle_status: row.try_get("lifecycle_status")?,
        classification: row.try_get("classification")?,
        created_by_id: row.try_get("created_by_id")?,
        updated_by_id: row.try_get("updated_by_id")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}
fn indicator_from_sqlite_row(row: SqliteRow) -> Result<ThreatIndicatorSummary, sqlx::Error> {
    Ok(ThreatIndicatorSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        indicator_type: row.try_get("indicator_type")?,
        normalized_value: row.try_get("normalized_value")?,
        original_value: row.try_get("original_value")?,
        source_type: row.try_get("source_type")?,
        source_name: row.try_get("source_name")?,
        provenance_reference: row.try_get("provenance_reference")?,
        confidence: row.try_get("confidence")?,
        valid_from: row.try_get("valid_from")?,
        valid_until: row.try_get("valid_until")?,
        lifecycle_status: row.try_get("lifecycle_status")?,
        classification: row.try_get("classification")?,
        created_by_id: row.try_get("created_by_id")?,
        updated_by_id: row.try_get("updated_by_id")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}
fn observation_from_pg_row(row: PgRow) -> Result<SecurityObservationSummary, sqlx::Error> {
    let attributes_json: String = row.try_get("attributes_json")?;
    Ok(SecurityObservationSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        source_type: row.try_get("source_type")?,
        source_reference: row.try_get("source_reference")?,
        agent_finding_id: row.try_get("agent_finding_id")?,
        vulnerability_finding_id: row.try_get("vulnerability_finding_id")?,
        asset_id: row.try_get("asset_id")?,
        asset_name: row.try_get("asset_name")?,
        deduplication_key: row.try_get("deduplication_key")?,
        observed_at: row.try_get("observed_at")?,
        recorded_at: row.try_get("recorded_at")?,
        category: row.try_get("category")?,
        severity: row.try_get("severity")?,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        attributes: serde_json::from_str(&attributes_json).unwrap_or_else(|_| json!({})),
        provenance_type: row.try_get("provenance_type")?,
        provenance_reference: row.try_get("provenance_reference")?,
        triage_status: row.try_get("triage_status")?,
        owner_id: row.try_get("owner_id")?,
        created_by_id: row.try_get("created_by_id")?,
        updated_by_id: row.try_get("updated_by_id")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}
fn observation_from_sqlite_row(row: SqliteRow) -> Result<SecurityObservationSummary, sqlx::Error> {
    let attributes_json: String = row.try_get("attributes_json")?;
    Ok(SecurityObservationSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        source_type: row.try_get("source_type")?,
        source_reference: row.try_get("source_reference")?,
        agent_finding_id: row.try_get("agent_finding_id")?,
        vulnerability_finding_id: row.try_get("vulnerability_finding_id")?,
        asset_id: row.try_get("asset_id")?,
        asset_name: row.try_get("asset_name")?,
        deduplication_key: row.try_get("deduplication_key")?,
        observed_at: row.try_get("observed_at")?,
        recorded_at: row.try_get("recorded_at")?,
        category: row.try_get("category")?,
        severity: row.try_get("severity")?,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        attributes: serde_json::from_str(&attributes_json).unwrap_or_else(|_| json!({})),
        provenance_type: row.try_get("provenance_type")?,
        provenance_reference: row.try_get("provenance_reference")?,
        triage_status: row.try_get("triage_status")?,
        owner_id: row.try_get("owner_id")?,
        created_by_id: row.try_get("created_by_id")?,
        updated_by_id: row.try_get("updated_by_id")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}
fn link_from_pg_row(row: PgRow) -> Result<ObservationIndicatorLinkSummary, sqlx::Error> {
    Ok(ObservationIndicatorLinkSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        observation_id: row.try_get("observation_id")?,
        observation_title: row.try_get("observation_title")?,
        indicator_id: row.try_get("indicator_id")?,
        indicator_type: row.try_get("indicator_type")?,
        indicator_value: row.try_get("indicator_value")?,
        match_origin: row.try_get("match_origin")?,
        match_type: row.try_get("match_type")?,
        matched_at: row.try_get("matched_at")?,
        evaluator_id: row.try_get("evaluator_id")?,
        triage_status: row.try_get("triage_status")?,
        rationale: row.try_get("rationale")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}
fn link_from_sqlite_row(row: SqliteRow) -> Result<ObservationIndicatorLinkSummary, sqlx::Error> {
    Ok(ObservationIndicatorLinkSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        observation_id: row.try_get("observation_id")?,
        observation_title: row.try_get("observation_title")?,
        indicator_id: row.try_get("indicator_id")?,
        indicator_type: row.try_get("indicator_type")?,
        indicator_value: row.try_get("indicator_value")?,
        match_origin: row.try_get("match_origin")?,
        match_type: row.try_get("match_type")?,
        matched_at: row.try_get("matched_at")?,
        evaluator_id: row.try_get("evaluator_id")?,
        triage_status: row.try_get("triage_status")?,
        rationale: row.try_get("rationale")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}
fn audit_from_pg_row(row: PgRow) -> Result<SecurityObservationAuditEvent, sqlx::Error> {
    let raw: String = row.try_get("detail_json")?;
    Ok(SecurityObservationAuditEvent {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        object_type: row.try_get("object_type")?,
        object_id: row.try_get("object_id")?,
        event_type: row.try_get("event_type")?,
        actor_id: row.try_get("actor_id")?,
        summary: row.try_get("summary")?,
        detail: serde_json::from_str(&raw).unwrap_or_else(|_| json!({})),
        created_at: row.try_get("created_at")?,
    })
}
fn audit_from_sqlite_row(row: SqliteRow) -> Result<SecurityObservationAuditEvent, sqlx::Error> {
    let raw: String = row.try_get("detail_json")?;
    Ok(SecurityObservationAuditEvent {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        object_type: row.try_get("object_type")?,
        object_id: row.try_get("object_id")?,
        event_type: row.try_get("event_type")?,
        actor_id: row.try_get("actor_id")?,
        summary: row.try_get("summary")?,
        detail: serde_json::from_str(&raw).unwrap_or_else(|_| json!({})),
        created_at: row.try_get("created_at")?,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{normalize_indicator_value, validate_attributes};

    #[test]
    fn indicator_normalization_is_local_and_deterministic() {
        assert_eq!(
            normalize_indicator_value("IPV4", "192.0.2.10").unwrap(),
            "192.0.2.10"
        );
        assert_eq!(
            normalize_indicator_value("IPV6", "2001:0db8::1").unwrap(),
            "2001:db8::1"
        );
        assert_eq!(
            normalize_indicator_value("DOMAIN", "Example.COM.").unwrap(),
            "example.com"
        );
        assert_eq!(
            normalize_indicator_value("URL", "HTTPS://Example.COM/a#fragment").unwrap(),
            "https://example.com/a"
        );
        assert!(normalize_indicator_value("DOMAIN", "https://example.com").is_err());
        assert!(normalize_indicator_value("SHA256", "not-a-hash").is_err());
    }

    #[test]
    fn observation_attributes_are_bounded_and_reject_secret_fields() {
        assert!(validate_attributes(json!({"process":"browser","count":2})).is_ok());
        assert!(validate_attributes(json!({"access_token":"do-not-store"})).is_err());
        assert!(validate_attributes(json!(["raw", "log"])).is_err());
        assert!(validate_attributes(json!({"message":"x".repeat(1100)})).is_err());
    }
}
