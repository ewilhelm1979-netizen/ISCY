use anyhow::{bail, Context};
use chrono::{Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Postgres, Row, Sqlite, Transaction,
};

use crate::cve_store::normalize_database_url;
use crate::evidence_object_storage::{
    normalize_backend_status, normalize_backend_type, normalize_endpoint_policy,
    normalize_key_prefix, redacted_secret_display, secret_presence_status, validate_bucket_name,
    validate_endpoint_reference, validate_object_key, validate_secret_reference,
    EvidenceObjectDrillResult, EvidenceObjectReference, EvidenceObjectReferenceAttachRequest,
    EvidenceStorageBackendConfig, EvidenceStorageBackendConfigRequest, EvidenceStorageBackendEvent,
    EvidenceStorageSecretReferenceStatus, ObjectStorageValidationError, BACKEND_DISABLED,
    BACKEND_LOCAL_FILESYSTEM, BACKEND_S3_COMPATIBLE, STATUS_CONFIGURED_METADATA_ONLY,
    STATUS_DISABLED, STATUS_ERROR, STATUS_NOT_CONFIGURED, STATUS_READY, STATUS_READY_FOR_TEST,
    STATUS_VALIDATION_REQUIRED,
};

#[derive(Clone)]
pub enum EvidenceStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone)]
struct EvidenceIntegrityEventWrite {
    event_type: String,
    actor_id: Option<i64>,
    integrity_status: String,
    legal_hold_status: String,
    disposition_status: String,
    mismatch: bool,
    error_class: String,
    detail: Value,
    note: String,
}

async fn evidence_integrity_overview_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<EvidenceIntegrityOverview> {
    let sql = evidence_integrity_item_postgres_sql(
        "WHERE item.tenant_id = $1 ORDER BY item.updated_at DESC, item.id ASC LIMIT $2",
    );
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(limit.clamp(1, 500))
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Evidence-Integrity-Uebersicht konnte nicht gelesen werden")?;
    let items = rows
        .into_iter()
        .map(evidence_integrity_item_from_pg_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(EvidenceIntegrityOverview {
        summary: evidence_integrity_summary(&items),
        items,
    })
}

async fn evidence_integrity_overview_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<EvidenceIntegrityOverview> {
    let sql = evidence_integrity_item_sqlite_sql(
        "WHERE item.tenant_id = ?1 ORDER BY item.updated_at DESC, item.id ASC LIMIT ?2",
    );
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(limit.clamp(1, 500))
        .fetch_all(pool)
        .await
        .context("SQLite-Evidence-Integrity-Uebersicht konnte nicht gelesen werden")?;
    let items = rows
        .into_iter()
        .map(evidence_integrity_item_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(EvidenceIntegrityOverview {
        summary: evidence_integrity_summary(&items),
        items,
    })
}

fn evidence_integrity_summary(items: &[EvidenceIntegrityItem]) -> EvidenceIntegritySummary {
    EvidenceIntegritySummary {
        total_items: items.len() as i64,
        not_checked: count_integrity_status(items, "not_checked"),
        valid: count_integrity_status(items, "valid"),
        mismatch: count_integrity_status(items, "mismatch"),
        missing_artifact: count_integrity_status(items, "missing_artifact"),
        check_failed: count_integrity_status(items, "check_failed"),
        quarantined: count_integrity_status(items, "quarantined"),
        accepted_with_exception: count_integrity_status(items, "accepted_with_exception"),
        legal_hold_active: items
            .iter()
            .filter(|item| item.legal_hold_status == "active")
            .count() as i64,
        disposition_due: items
            .iter()
            .filter(|item| matches!(item.disposition_status.as_str(), "due" | "review_required"))
            .count() as i64,
        disposition_blocked: items
            .iter()
            .filter(|item| item.disposition_status == "blocked_by_legal_hold")
            .count() as i64,
        disposal_candidates: items.iter().filter(|item| item.disposal_candidate).count() as i64,
    }
}

fn count_integrity_status(items: &[EvidenceIntegrityItem], status: &str) -> i64 {
    items
        .iter()
        .filter(|item| item.integrity_status == status)
        .count() as i64
}

async fn evidence_integrity_target_postgres(
    pool: &PgPool,
    tenant_id: i64,
    evidence_id: i64,
) -> anyhow::Result<Option<EvidenceIntegrityTarget>> {
    let row = sqlx::query(
        r#"
        SELECT id, title, file AS file_name, file_sha256 AS expected_sha256
        FROM evidence_evidenceitem
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-Evidence-Integrity-Target konnte nicht gelesen werden")?;
    row.map(evidence_integrity_target_from_pg_row)
        .transpose()
        .map_err(Into::into)
}

async fn evidence_integrity_target_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    evidence_id: i64,
) -> anyhow::Result<Option<EvidenceIntegrityTarget>> {
    let row = sqlx::query(
        r#"
        SELECT id, title, file AS file_name, file_sha256 AS expected_sha256
        FROM evidence_evidenceitem
        WHERE tenant_id = ?1 AND id = ?2
        "#,
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-Evidence-Integrity-Target konnte nicht gelesen werden")?;
    row.map(evidence_integrity_target_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

async fn evidence_integrity_targets_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<EvidenceIntegrityTarget>> {
    let rows = sqlx::query(
        r#"
        SELECT id, title, file AS file_name, file_sha256 AS expected_sha256
        FROM evidence_evidenceitem
        WHERE tenant_id = $1
        ORDER BY COALESCE(last_integrity_checked_at, ''), updated_at DESC, id ASC
        LIMIT $2
        "#,
    )
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("PostgreSQL-Evidence-Integrity-Targets konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(evidence_integrity_target_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn evidence_integrity_targets_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<EvidenceIntegrityTarget>> {
    let rows = sqlx::query(
        r#"
        SELECT id, title, file AS file_name, file_sha256 AS expected_sha256
        FROM evidence_evidenceitem
        WHERE tenant_id = ?1
        ORDER BY COALESCE(last_integrity_checked_at, ''), updated_at DESC, id ASC
        LIMIT ?2
        "#,
    )
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("SQLite-Evidence-Integrity-Targets konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(evidence_integrity_target_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn evidence_integrity_target_from_pg_row(
    row: PgRow,
) -> Result<EvidenceIntegrityTarget, sqlx::Error> {
    Ok(EvidenceIntegrityTarget {
        id: row.try_get("id")?,
        title: row.try_get("title")?,
        file_name: row.try_get("file_name")?,
        expected_sha256: row.try_get("expected_sha256")?,
    })
}

fn evidence_integrity_target_from_sqlite_row(
    row: SqliteRow,
) -> Result<EvidenceIntegrityTarget, sqlx::Error> {
    Ok(EvidenceIntegrityTarget {
        id: row.try_get("id")?,
        title: row.try_get("title")?,
        file_name: row.try_get("file_name")?,
        expected_sha256: row.try_get("expected_sha256")?,
    })
}

async fn apply_integrity_check_result_postgres(
    pool: &PgPool,
    tenant_id: i64,
    evidence_id: i64,
    actor_id: i64,
    update: EvidenceIntegrityCheckUpdate,
) -> anyhow::Result<Option<EvidenceIntegrityItem>> {
    validate_integrity_update(&update)?;
    let mut tx = pool.begin().await?;
    let result = sqlx::query(
        r#"
        UPDATE evidence_evidenceitem
        SET last_integrity_checked_at = (CURRENT_TIMESTAMP)::text,
            last_calculated_sha256 = $3,
            integrity_status = $4,
            integrity_mismatch = $5,
            quarantine_status = $6,
            integrity_checked_by_id = $7,
            integrity_result = $8,
            integrity_error_class = $9,
            integrity_review_note = $10,
            updated_at = (CURRENT_TIMESTAMP)::text
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .bind(&update.calculated_sha256)
    .bind(&update.integrity_status)
    .bind(update.mismatch)
    .bind(&update.quarantine_status)
    .bind(actor_id)
    .bind(&update.result)
    .bind(&update.error_class)
    .bind(&update.review_note)
    .execute(&mut *tx)
    .await
    .context("PostgreSQL-Evidence-Integritaetsstatus konnte nicht aktualisiert werden")?;
    if result.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(None);
    }
    let event_type = match update.integrity_status.as_str() {
        "valid" => "integrity_hash_valid",
        "mismatch" => "integrity_hash_mismatch",
        "missing_artifact" => "integrity_artifact_missing",
        "check_failed" => "integrity_check_failed",
        "quarantined" => "integrity_quarantined",
        "accepted_with_exception" => "integrity_exception_accepted",
        _ => "integrity_check_completed",
    };
    insert_evidence_integrity_event_postgres_tx(
        &mut tx,
        tenant_id,
        evidence_id,
        EvidenceIntegrityEventWrite {
            event_type: event_type.to_string(),
            actor_id: Some(actor_id),
            integrity_status: update.integrity_status.clone(),
            legal_hold_status: String::new(),
            disposition_status: String::new(),
            mismatch: update.mismatch,
            error_class: update.error_class.clone(),
            detail: json!({
                "calculated_hash_present": !update.calculated_sha256.is_empty(),
                "mismatch": update.mismatch,
                "quarantine_status": update.quarantine_status,
            }),
            note: update.review_note,
        },
    )
    .await?;
    tx.commit().await?;
    evidence_integrity_item_by_id_postgres(pool, tenant_id, evidence_id).await
}

async fn apply_integrity_check_result_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    evidence_id: i64,
    actor_id: i64,
    update: EvidenceIntegrityCheckUpdate,
) -> anyhow::Result<Option<EvidenceIntegrityItem>> {
    validate_integrity_update(&update)?;
    let mut tx = pool.begin().await?;
    let result = sqlx::query(
        r#"
        UPDATE evidence_evidenceitem
        SET last_integrity_checked_at = datetime('now'),
            last_calculated_sha256 = ?3,
            integrity_status = ?4,
            integrity_mismatch = ?5,
            quarantine_status = ?6,
            integrity_checked_by_id = ?7,
            integrity_result = ?8,
            integrity_error_class = ?9,
            integrity_review_note = ?10,
            updated_at = datetime('now')
        WHERE tenant_id = ?1 AND id = ?2
        "#,
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .bind(&update.calculated_sha256)
    .bind(&update.integrity_status)
    .bind(update.mismatch)
    .bind(&update.quarantine_status)
    .bind(actor_id)
    .bind(&update.result)
    .bind(&update.error_class)
    .bind(&update.review_note)
    .execute(&mut *tx)
    .await
    .context("SQLite-Evidence-Integritaetsstatus konnte nicht aktualisiert werden")?;
    if result.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(None);
    }
    let event_type = match update.integrity_status.as_str() {
        "valid" => "integrity_hash_valid",
        "mismatch" => "integrity_hash_mismatch",
        "missing_artifact" => "integrity_artifact_missing",
        "check_failed" => "integrity_check_failed",
        "quarantined" => "integrity_quarantined",
        "accepted_with_exception" => "integrity_exception_accepted",
        _ => "integrity_check_completed",
    };
    insert_evidence_integrity_event_sqlite_tx(
        &mut tx,
        tenant_id,
        evidence_id,
        EvidenceIntegrityEventWrite {
            event_type: event_type.to_string(),
            actor_id: Some(actor_id),
            integrity_status: update.integrity_status.clone(),
            legal_hold_status: String::new(),
            disposition_status: String::new(),
            mismatch: update.mismatch,
            error_class: update.error_class.clone(),
            detail: json!({
                "calculated_hash_present": !update.calculated_sha256.is_empty(),
                "mismatch": update.mismatch,
                "quarantine_status": update.quarantine_status,
            }),
            note: update.review_note,
        },
    )
    .await?;
    tx.commit().await?;
    evidence_integrity_item_by_id_sqlite(pool, tenant_id, evidence_id).await
}

fn validate_integrity_update(update: &EvidenceIntegrityCheckUpdate) -> anyhow::Result<()> {
    normalize_integrity_status(&update.integrity_status)?;
    if !update.calculated_sha256.is_empty() {
        normalize_file_sha256(&update.calculated_sha256)?;
    }
    if !matches!(
        update.quarantine_status.as_str(),
        "none" | "review_required" | "quarantined" | "released"
    ) {
        bail!("Quarantaene-Status ist ungueltig.");
    }
    Ok(())
}

async fn evidence_integrity_item_by_id_postgres(
    pool: &PgPool,
    tenant_id: i64,
    evidence_id: i64,
) -> anyhow::Result<Option<EvidenceIntegrityItem>> {
    let sql = evidence_integrity_item_postgres_sql("WHERE item.tenant_id = $1 AND item.id = $2");
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(evidence_id)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-Evidence-Integrity-Detail konnte nicht gelesen werden")?;
    row.map(evidence_integrity_item_from_pg_row)
        .transpose()
        .map_err(Into::into)
}

async fn evidence_integrity_item_by_id_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    evidence_id: i64,
) -> anyhow::Result<Option<EvidenceIntegrityItem>> {
    let sql = evidence_integrity_item_sqlite_sql("WHERE item.tenant_id = ?1 AND item.id = ?2");
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(evidence_id)
        .fetch_optional(pool)
        .await
        .context("SQLite-Evidence-Integrity-Detail konnte nicht gelesen werden")?;
    row.map(evidence_integrity_item_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

async fn evidence_integrity_events_postgres(
    pool: &PgPool,
    tenant_id: i64,
    evidence_id: i64,
    limit: i64,
) -> anyhow::Result<Option<Vec<EvidenceIntegrityEvent>>> {
    if evidence_integrity_target_postgres(pool, tenant_id, evidence_id)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    let rows = sqlx::query(evidence_integrity_event_postgres_sql())
        .bind(tenant_id)
        .bind(evidence_id)
        .bind(limit.clamp(1, 200))
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Evidence-Integritaetsereignisse konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(evidence_integrity_event_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
        .map_err(Into::into)
}

async fn evidence_integrity_events_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    evidence_id: i64,
    limit: i64,
) -> anyhow::Result<Option<Vec<EvidenceIntegrityEvent>>> {
    if evidence_integrity_target_sqlite(pool, tenant_id, evidence_id)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    let rows = sqlx::query(evidence_integrity_event_sqlite_sql())
        .bind(tenant_id)
        .bind(evidence_id)
        .bind(limit.clamp(1, 200))
        .fetch_all(pool)
        .await
        .context("SQLite-Evidence-Integritaetsereignisse konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(evidence_integrity_event_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
        .map_err(Into::into)
}

async fn insert_evidence_integrity_event_postgres(
    pool: &PgPool,
    tenant_id: i64,
    evidence_id: i64,
    event: EvidenceIntegrityEventWrite,
) -> anyhow::Result<Option<EvidenceIntegrityEvent>> {
    if evidence_integrity_target_postgres(pool, tenant_id, evidence_id)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    let mut tx = pool.begin().await?;
    let id =
        insert_evidence_integrity_event_postgres_tx(&mut tx, tenant_id, evidence_id, event).await?;
    tx.commit().await?;
    evidence_integrity_event_by_id_postgres(pool, tenant_id, id).await
}

async fn insert_evidence_integrity_event_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    evidence_id: i64,
    event: EvidenceIntegrityEventWrite,
) -> anyhow::Result<Option<EvidenceIntegrityEvent>> {
    if evidence_integrity_target_sqlite(pool, tenant_id, evidence_id)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    let mut tx = pool.begin().await?;
    let id =
        insert_evidence_integrity_event_sqlite_tx(&mut tx, tenant_id, evidence_id, event).await?;
    tx.commit().await?;
    evidence_integrity_event_by_id_sqlite(pool, tenant_id, id).await
}

async fn insert_evidence_integrity_event_postgres_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    evidence_id: i64,
    event: EvidenceIntegrityEventWrite,
) -> anyhow::Result<i64> {
    let id: i64 = sqlx::query_scalar(
        r#"
        INSERT INTO evidence_integrity_event (
            tenant_id, evidence_id, event_type, actor_id, integrity_status,
            legal_hold_status, disposition_status, mismatch, error_class,
            detail_json, note, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, (CURRENT_TIMESTAMP)::text)
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .bind(event.event_type)
    .bind(event.actor_id)
    .bind(event.integrity_status)
    .bind(event.legal_hold_status)
    .bind(event.disposition_status)
    .bind(event.mismatch)
    .bind(event.error_class)
    .bind(event.detail.to_string())
    .bind(event.note)
    .fetch_one(&mut **tx)
    .await
    .context("PostgreSQL-Evidence-Integritaetsereignis konnte nicht geschrieben werden")?;
    Ok(id)
}

async fn insert_evidence_integrity_event_sqlite_tx(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    evidence_id: i64,
    event: EvidenceIntegrityEventWrite,
) -> anyhow::Result<i64> {
    let result = sqlx::query(
        r#"
        INSERT INTO evidence_integrity_event (
            tenant_id, evidence_id, event_type, actor_id, integrity_status,
            legal_hold_status, disposition_status, mismatch, error_class,
            detail_json, note, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, datetime('now'))
        "#,
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .bind(event.event_type)
    .bind(event.actor_id)
    .bind(event.integrity_status)
    .bind(event.legal_hold_status)
    .bind(event.disposition_status)
    .bind(event.mismatch)
    .bind(event.error_class)
    .bind(event.detail.to_string())
    .bind(event.note)
    .execute(&mut **tx)
    .await
    .context("SQLite-Evidence-Integritaetsereignis konnte nicht geschrieben werden")?;
    Ok(result.last_insert_rowid())
}

async fn evidence_integrity_event_by_id_postgres(
    pool: &PgPool,
    tenant_id: i64,
    event_id: i64,
) -> anyhow::Result<Option<EvidenceIntegrityEvent>> {
    let row = sqlx::query(
        r#"
        SELECT event.id, event.tenant_id, event.evidence_id, event.event_type,
               event.actor_id,
               COALESCE(NULLIF(BTRIM(CONCAT(COALESCE(actor.first_name, ''), ' ', COALESCE(actor.last_name, ''))), ''), actor.username) AS actor_display,
               event.integrity_status, event.legal_hold_status, event.disposition_status,
               event.mismatch, event.error_class, event.detail_json::text AS detail_json_text,
               event.note, event.created_at::text AS created_at
        FROM evidence_integrity_event event
        LEFT JOIN accounts_user actor
            ON actor.id = event.actor_id AND actor.tenant_id = event.tenant_id
        WHERE event.tenant_id = $1 AND event.id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(event_id)
    .fetch_optional(pool)
    .await?;
    row.map(evidence_integrity_event_from_pg_row)
        .transpose()
        .map_err(Into::into)
}

async fn evidence_integrity_event_by_id_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    event_id: i64,
) -> anyhow::Result<Option<EvidenceIntegrityEvent>> {
    let row = sqlx::query(
        r#"
        SELECT event.id, event.tenant_id, event.evidence_id, event.event_type,
               event.actor_id,
               COALESCE(NULLIF(TRIM(COALESCE(actor.first_name, '') || ' ' || COALESCE(actor.last_name, '')), ''), actor.username) AS actor_display,
               event.integrity_status, event.legal_hold_status, event.disposition_status,
               event.mismatch, event.error_class, CAST(event.detail_json AS TEXT) AS detail_json_text,
               event.note, CAST(event.created_at AS TEXT) AS created_at
        FROM evidence_integrity_event event
        LEFT JOIN accounts_user actor
            ON actor.id = event.actor_id AND actor.tenant_id = event.tenant_id
        WHERE event.tenant_id = ?1 AND event.id = ?2
        "#,
    )
    .bind(tenant_id)
    .bind(event_id)
    .fetch_optional(pool)
    .await?;
    row.map(evidence_integrity_event_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

#[derive(Debug, Clone)]
struct NormalizedStorageBackendConfig {
    backend_id: String,
    backend_type: String,
    display_name: String,
    status: String,
    endpoint_reference: String,
    region: String,
    bucket_name: String,
    key_prefix: String,
    access_key_secret_ref: String,
    secret_key_secret_ref: String,
    session_token_secret_ref: String,
    tls_required: bool,
    allow_path_style: bool,
    allowed_endpoint_policy: String,
    known_limitations: String,
}

fn normalize_storage_backend_payload(
    payload: EvidenceStorageBackendConfigRequest,
) -> anyhow::Result<NormalizedStorageBackendConfig> {
    let Some(backend_type) = normalize_backend_type(&payload.backend_type) else {
        return validation_bail(ObjectStorageValidationError::InvalidBackendType);
    };
    let backend_id = normalize_backend_id(payload.backend_id.as_deref(), backend_type)?;
    let Some(status) = normalize_backend_status(payload.status.as_deref(), backend_type) else {
        return validation_bail(ObjectStorageValidationError::InvalidBackendStatus);
    };
    let display_name = normalize_limited_text(
        &payload.display_name,
        160,
        if backend_type == BACKEND_S3_COMPATIBLE {
            "S3-kompatibler Evidence-Storage"
        } else if backend_type == BACKEND_LOCAL_FILESYSTEM {
            "Lokales Evidence-Dateisystem"
        } else {
            "Evidence-Storage deaktiviert"
        },
    );
    let endpoint_reference = payload
        .endpoint_reference
        .unwrap_or_default()
        .trim()
        .to_string();
    let region = normalize_limited_text(payload.region.as_deref().unwrap_or(""), 64, "");
    let bucket_name = if payload
        .bucket_name
        .as_deref()
        .unwrap_or("")
        .trim()
        .is_empty()
    {
        String::new()
    } else {
        validate_bucket_name(payload.bucket_name.as_deref().unwrap_or(""))?
    };
    let key_prefix = normalize_key_prefix(payload.key_prefix.as_deref())?;
    let access_key_secret_ref =
        validate_secret_reference(payload.access_key_secret_ref.as_deref().unwrap_or(""))?;
    let secret_key_secret_ref =
        validate_secret_reference(payload.secret_key_secret_ref.as_deref().unwrap_or(""))?;
    let session_token_secret_ref =
        validate_secret_reference(payload.session_token_secret_ref.as_deref().unwrap_or(""))?;
    let tls_required = payload.tls_required.unwrap_or(true);
    let allow_path_style = payload.allow_path_style.unwrap_or(false);
    let allowed_endpoint_policy =
        normalize_endpoint_policy(payload.allowed_endpoint_policy.as_deref());
    if backend_type == BACKEND_S3_COMPATIBLE && !endpoint_reference.is_empty() {
        validate_endpoint_reference(&endpoint_reference, tls_required, &allowed_endpoint_policy)?;
    }
    if backend_type == BACKEND_DISABLED
        && status != STATUS_DISABLED
        && status != STATUS_NOT_CONFIGURED
    {
        return validation_bail(ObjectStorageValidationError::InvalidBackendStatus);
    }
    Ok(NormalizedStorageBackendConfig {
        backend_id,
        backend_type: backend_type.to_string(),
        display_name,
        status: status.to_string(),
        endpoint_reference,
        region,
        bucket_name,
        key_prefix,
        access_key_secret_ref,
        secret_key_secret_ref,
        session_token_secret_ref,
        tls_required,
        allow_path_style,
        allowed_endpoint_policy,
        known_limitations: normalize_limited_text(
            payload.known_limitations.as_deref().unwrap_or(""),
            4000,
            "",
        ),
    })
}

fn normalize_backend_id(value: Option<&str>, backend_type: &str) -> anyhow::Result<String> {
    let fallback = match backend_type {
        BACKEND_LOCAL_FILESYSTEM => "local-filesystem",
        BACKEND_DISABLED => "disabled",
        _ => "s3-primary",
    };
    let value = value.unwrap_or(fallback).trim().to_ascii_lowercase();
    let valid = (3..=96).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
        && !value.starts_with('-')
        && !value.ends_with('-');
    if valid {
        Ok(value)
    } else {
        validation_bail(ObjectStorageValidationError::InvalidBackendType)
    }
}

fn normalize_limited_text(value: &str, max_chars: usize, fallback: &str) -> String {
    let value = value.trim();
    let value = if value.is_empty() { fallback } else { value };
    value.chars().take(max_chars).collect()
}

fn validation_bail<T>(err: ObjectStorageValidationError) -> anyhow::Result<T> {
    bail!("object_storage_validation:{}", err.safe_error_class())
}

fn validate_contract_status(value: Option<&str>) -> anyhow::Result<String> {
    let status = value.unwrap_or("").trim().to_ascii_lowercase();
    let status = if status.is_empty() {
        "metadata_only"
    } else {
        status.as_str()
    };
    match status {
        "metadata_only" | "present" | "missing" | "unreadable" | "timeout" | "access_denied"
        | "backend_error" => Ok(status.to_string()),
        _ => bail!("object_storage_validation:invalid_object_reference_status"),
    }
}

fn normalize_optional_sha256(value: Option<&str>) -> anyhow::Result<String> {
    let value = value.unwrap_or("").trim().to_ascii_lowercase();
    if value.is_empty() {
        return Ok(String::new());
    }
    let valid = value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit());
    if valid {
        Ok(value)
    } else {
        bail!("object_storage_validation:invalid_sha256")
    }
}

fn normalize_contract_size(value: Option<i64>) -> anyhow::Result<Option<i64>> {
    match value {
        Some(size) if size < 0 => bail!("object_storage_validation:invalid_object_size"),
        Some(size) => Ok(Some(size)),
        None => Ok(None),
    }
}

async fn evidence_storage_backend_configs_postgres(
    pool: &PgPool,
    tenant_id: i64,
) -> anyhow::Result<Vec<EvidenceStorageBackendConfig>> {
    let sql = evidence_storage_backend_config_postgres_select(
        "WHERE tenant_id = $1 ORDER BY backend_type, backend_id",
    );
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
        .context(
            "PostgreSQL-Evidence-Storage-Backend-Konfigurationen konnten nicht gelesen werden",
        )?;
    rows.into_iter()
        .map(evidence_storage_backend_config_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn evidence_storage_backend_configs_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
) -> anyhow::Result<Vec<EvidenceStorageBackendConfig>> {
    let sql = evidence_storage_backend_config_sqlite_select(
        "WHERE tenant_id = ?1 ORDER BY backend_type, backend_id",
    );
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
        .context("SQLite-Evidence-Storage-Backend-Konfigurationen konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(evidence_storage_backend_config_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn upsert_evidence_storage_backend_config_postgres(
    pool: &PgPool,
    tenant_id: i64,
    actor_id: i64,
    payload: EvidenceStorageBackendConfigRequest,
) -> anyhow::Result<EvidenceStorageBackendConfig> {
    let normalized = normalize_storage_backend_payload(payload)?;
    let mut tx = pool.begin().await?;
    let row = sqlx::query(evidence_storage_backend_config_postgres_upsert_sql())
        .bind(tenant_id)
        .bind(&normalized.backend_id)
        .bind(&normalized.backend_type)
        .bind(&normalized.display_name)
        .bind(&normalized.status)
        .bind(&normalized.endpoint_reference)
        .bind(&normalized.region)
        .bind(&normalized.bucket_name)
        .bind(&normalized.key_prefix)
        .bind(&normalized.access_key_secret_ref)
        .bind(&normalized.secret_key_secret_ref)
        .bind(&normalized.session_token_secret_ref)
        .bind(normalized.tls_required)
        .bind(normalized.allow_path_style)
        .bind(&normalized.allowed_endpoint_policy)
        .bind(actor_id)
        .bind(&normalized.known_limitations)
        .fetch_one(&mut *tx)
        .await
        .context(
            "PostgreSQL-Evidence-Storage-Backend-Konfiguration konnte nicht gespeichert werden",
        )?;
    let config = evidence_storage_backend_config_from_pg_row(row)?;
    refresh_secret_reference_statuses_postgres_tx(&mut tx, tenant_id, &config).await?;
    insert_storage_backend_event_postgres_tx(
        &mut tx,
        tenant_id,
        StorageBackendEventWrite {
            backend_id: config.backend_id.clone(),
            evidence_id: None,
            event_type: "storage_backend_config_saved",
            actor_id: Some(actor_id),
            status: config.status.clone(),
            error_class: String::new(),
            summary: "Evidence-Storage-Backend-Metadaten gespeichert.",
            detail: json!({"backend_type": config.backend_type, "secrets_exposed": false, "endpoint_credentials_allowed": false}),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(config)
}

async fn upsert_evidence_storage_backend_config_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    actor_id: i64,
    payload: EvidenceStorageBackendConfigRequest,
) -> anyhow::Result<EvidenceStorageBackendConfig> {
    let normalized = normalize_storage_backend_payload(payload)?;
    let mut tx = pool.begin().await?;
    let row = sqlx::query(evidence_storage_backend_config_sqlite_upsert_sql())
        .bind(tenant_id)
        .bind(&normalized.backend_id)
        .bind(&normalized.backend_type)
        .bind(&normalized.display_name)
        .bind(&normalized.status)
        .bind(&normalized.endpoint_reference)
        .bind(&normalized.region)
        .bind(&normalized.bucket_name)
        .bind(&normalized.key_prefix)
        .bind(&normalized.access_key_secret_ref)
        .bind(&normalized.secret_key_secret_ref)
        .bind(&normalized.session_token_secret_ref)
        .bind(normalized.tls_required)
        .bind(normalized.allow_path_style)
        .bind(&normalized.allowed_endpoint_policy)
        .bind(actor_id)
        .bind(&normalized.known_limitations)
        .fetch_one(&mut *tx)
        .await
        .context("SQLite-Evidence-Storage-Backend-Konfiguration konnte nicht gespeichert werden")?;
    let config = evidence_storage_backend_config_from_sqlite_row(row)?;
    refresh_secret_reference_statuses_sqlite_tx(&mut tx, tenant_id, &config).await?;
    insert_storage_backend_event_sqlite_tx(
        &mut tx,
        tenant_id,
        StorageBackendEventWrite {
            backend_id: config.backend_id.clone(),
            evidence_id: None,
            event_type: "storage_backend_config_saved",
            actor_id: Some(actor_id),
            status: config.status.clone(),
            error_class: String::new(),
            summary: "Evidence-Storage-Backend-Metadaten gespeichert.",
            detail: json!({"backend_type": config.backend_type, "secrets_exposed": false, "endpoint_credentials_allowed": false}),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(config)
}

async fn validate_evidence_storage_backend_config_postgres(
    pool: &PgPool,
    tenant_id: i64,
    backend_id: &str,
    actor_id: i64,
) -> anyhow::Result<
    Option<(
        EvidenceStorageBackendConfig,
        Vec<EvidenceStorageSecretReferenceStatus>,
    )>,
> {
    let Some(config) =
        evidence_storage_backend_config_by_id_postgres(pool, tenant_id, backend_id).await?
    else {
        return Ok(None);
    };
    let (status, error_class) = storage_backend_validation_status(&config);
    let mut tx = pool.begin().await?;
    sqlx::query(
        r#"
        UPDATE evidence_storage_backend_config
        SET last_validation_at = (CURRENT_TIMESTAMP)::text,
            last_validation_status = $3,
            last_validation_error_class = $4,
            status = $5,
            updated_at = (CURRENT_TIMESTAMP)::text
        WHERE tenant_id = $1 AND backend_id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(&config.backend_id)
    .bind(&status)
    .bind(&error_class)
    .bind(if error_class.is_empty() {
        STATUS_READY_FOR_TEST
    } else {
        STATUS_ERROR
    })
    .execute(&mut *tx)
    .await
    .context("PostgreSQL-Evidence-Storage-Backend-Validierung konnte nicht gespeichert werden")?;
    insert_storage_backend_event_postgres_tx(
        &mut tx,
        tenant_id,
        StorageBackendEventWrite {
            backend_id: config.backend_id.clone(),
            evidence_id: None,
            event_type: "storage_backend_validated",
            actor_id: Some(actor_id),
            status: status.clone(),
            error_class: error_class.clone(),
            summary: "Evidence-Storage-Backend ohne Secret-Werte validiert.",
            detail: json!({"network_checked": false, "secrets_exposed": false, "safe_error_class": error_class}),
        },
    )
    .await?;
    tx.commit().await?;
    let config =
        evidence_storage_backend_config_by_id_postgres(pool, tenant_id, backend_id).await?;
    let statuses =
        evidence_storage_secret_reference_statuses_postgres(pool, tenant_id, backend_id).await?;
    Ok(config.map(|config| (config, statuses)))
}

async fn validate_evidence_storage_backend_config_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    backend_id: &str,
    actor_id: i64,
) -> anyhow::Result<
    Option<(
        EvidenceStorageBackendConfig,
        Vec<EvidenceStorageSecretReferenceStatus>,
    )>,
> {
    let Some(config) =
        evidence_storage_backend_config_by_id_sqlite(pool, tenant_id, backend_id).await?
    else {
        return Ok(None);
    };
    let (status, error_class) = storage_backend_validation_status(&config);
    let mut tx = pool.begin().await?;
    sqlx::query(
        r#"
        UPDATE evidence_storage_backend_config
        SET last_validation_at = datetime('now'),
            last_validation_status = ?3,
            last_validation_error_class = ?4,
            status = ?5,
            updated_at = datetime('now')
        WHERE tenant_id = ?1 AND backend_id = ?2
        "#,
    )
    .bind(tenant_id)
    .bind(&config.backend_id)
    .bind(&status)
    .bind(&error_class)
    .bind(if error_class.is_empty() {
        STATUS_READY_FOR_TEST
    } else {
        STATUS_ERROR
    })
    .execute(&mut *tx)
    .await
    .context("SQLite-Evidence-Storage-Backend-Validierung konnte nicht gespeichert werden")?;
    insert_storage_backend_event_sqlite_tx(
        &mut tx,
        tenant_id,
        StorageBackendEventWrite {
            backend_id: config.backend_id.clone(),
            evidence_id: None,
            event_type: "storage_backend_validated",
            actor_id: Some(actor_id),
            status: status.clone(),
            error_class: error_class.clone(),
            summary: "Evidence-Storage-Backend ohne Secret-Werte validiert.",
            detail: json!({"network_checked": false, "secrets_exposed": false, "safe_error_class": error_class}),
        },
    )
    .await?;
    tx.commit().await?;
    let config = evidence_storage_backend_config_by_id_sqlite(pool, tenant_id, backend_id).await?;
    let statuses =
        evidence_storage_secret_reference_statuses_sqlite(pool, tenant_id, backend_id).await?;
    Ok(config.map(|config| (config, statuses)))
}

async fn attach_evidence_object_reference_postgres(
    pool: &PgPool,
    tenant_id: i64,
    evidence_id: i64,
    actor_id: i64,
    payload: EvidenceObjectReferenceAttachRequest,
) -> anyhow::Result<Option<EvidenceObjectReference>> {
    if evidence_integrity_target_postgres(pool, tenant_id, evidence_id)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    let Some(config) =
        evidence_storage_backend_config_by_id_postgres(pool, tenant_id, payload.backend_id.trim())
            .await?
    else {
        return Ok(None);
    };
    let normalized = normalize_object_reference_payload(tenant_id, evidence_id, &config, payload)?;
    let mut tx = pool.begin().await?;
    let row = sqlx::query(evidence_object_reference_postgres_upsert_sql())
        .bind(tenant_id)
        .bind(evidence_id)
        .bind(&config.backend_id)
        .bind(&config.backend_type)
        .bind(&normalized.object_key_redacted)
        .bind(&normalized.object_key_sha256)
        .bind(&normalized.object_reference_status)
        .bind(&normalized.expected_sha256)
        .bind(&normalized.contract_status)
        .bind(&normalized.contract_sha256)
        .bind(normalized.contract_size_bytes)
        .bind(actor_id)
        .fetch_one(&mut *tx)
        .await
        .context("PostgreSQL-Evidence-Object-Referenz konnte nicht gespeichert werden")?;
    let reference = evidence_object_reference_from_pg_row(row)?;
    insert_storage_backend_event_postgres_tx(
        &mut tx,
        tenant_id,
        StorageBackendEventWrite {
            backend_id: config.backend_id.clone(),
            evidence_id: Some(evidence_id),
            event_type: "storage_object_reference_linked",
            actor_id: Some(actor_id),
            status: reference.object_reference_status.clone(),
            error_class: String::new(),
            summary: "Evidence wurde mit einer redaktionellen Object-Storage-Referenz verknuepft.",
            detail: json!({"object_key_sha256": reference.object_key_sha256, "object_key_redacted": reference.object_key_redacted, "secrets_exposed": false}),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(Some(reference))
}

async fn attach_evidence_object_reference_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    evidence_id: i64,
    actor_id: i64,
    payload: EvidenceObjectReferenceAttachRequest,
) -> anyhow::Result<Option<EvidenceObjectReference>> {
    if evidence_integrity_target_sqlite(pool, tenant_id, evidence_id)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    let Some(config) =
        evidence_storage_backend_config_by_id_sqlite(pool, tenant_id, payload.backend_id.trim())
            .await?
    else {
        return Ok(None);
    };
    let normalized = normalize_object_reference_payload(tenant_id, evidence_id, &config, payload)?;
    let mut tx = pool.begin().await?;
    let row = sqlx::query(evidence_object_reference_sqlite_upsert_sql())
        .bind(tenant_id)
        .bind(evidence_id)
        .bind(&config.backend_id)
        .bind(&config.backend_type)
        .bind(&normalized.object_key_redacted)
        .bind(&normalized.object_key_sha256)
        .bind(&normalized.object_reference_status)
        .bind(&normalized.expected_sha256)
        .bind(&normalized.contract_status)
        .bind(&normalized.contract_sha256)
        .bind(normalized.contract_size_bytes)
        .bind(actor_id)
        .fetch_one(&mut *tx)
        .await
        .context("SQLite-Evidence-Object-Referenz konnte nicht gespeichert werden")?;
    let reference = evidence_object_reference_from_sqlite_row(row)?;
    insert_storage_backend_event_sqlite_tx(
        &mut tx,
        tenant_id,
        StorageBackendEventWrite {
            backend_id: config.backend_id.clone(),
            evidence_id: Some(evidence_id),
            event_type: "storage_object_reference_linked",
            actor_id: Some(actor_id),
            status: reference.object_reference_status.clone(),
            error_class: String::new(),
            summary: "Evidence wurde mit einer redaktionellen Object-Storage-Referenz verknuepft.",
            detail: json!({"object_key_sha256": reference.object_key_sha256, "object_key_redacted": reference.object_key_redacted, "secrets_exposed": false}),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(Some(reference))
}

#[derive(Debug, Clone)]
struct NormalizedObjectReferencePayload {
    object_key_redacted: String,
    object_key_sha256: String,
    object_reference_status: String,
    expected_sha256: String,
    contract_status: String,
    contract_sha256: String,
    contract_size_bytes: Option<i64>,
}

#[derive(Debug)]
struct StorageBackendEventWrite {
    backend_id: String,
    evidence_id: Option<i64>,
    event_type: &'static str,
    actor_id: Option<i64>,
    status: String,
    error_class: String,
    summary: &'static str,
    detail: Value,
}

fn normalize_object_reference_payload(
    tenant_id: i64,
    evidence_id: i64,
    config: &EvidenceStorageBackendConfig,
    payload: EvidenceObjectReferenceAttachRequest,
) -> anyhow::Result<NormalizedObjectReferencePayload> {
    if config.backend_type != BACKEND_S3_COMPATIBLE {
        return validation_bail(ObjectStorageValidationError::InvalidBackendType);
    }
    let object_key = validate_object_key(
        tenant_id,
        evidence_id,
        &config.key_prefix,
        &payload.object_key,
    )?;
    let contract_status = validate_contract_status(payload.contract_status.as_deref())?;
    let expected_sha256 = normalize_optional_sha256(payload.expected_sha256.as_deref())?;
    let contract_sha256 = normalize_optional_sha256(payload.contract_sha256.as_deref())?;
    let contract_size_bytes = normalize_contract_size(payload.contract_size_bytes)?;
    Ok(NormalizedObjectReferencePayload {
        object_key_redacted: object_key.redacted,
        object_key_sha256: object_key.sha256,
        object_reference_status: if contract_status == "metadata_only" {
            "metadata_only".to_string()
        } else {
            "ready_for_test".to_string()
        },
        expected_sha256,
        contract_status,
        contract_sha256,
        contract_size_bytes,
    })
}

async fn evidence_object_reference_postgres(
    pool: &PgPool,
    tenant_id: i64,
    evidence_id: i64,
) -> anyhow::Result<Option<EvidenceObjectReference>> {
    let sql = evidence_object_reference_postgres_select(
        "WHERE tenant_id = $1 AND evidence_id = $2 ORDER BY updated_at DESC LIMIT 1",
    );
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(evidence_id)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-Evidence-Object-Referenz konnte nicht gelesen werden")?;
    row.map(evidence_object_reference_from_pg_row)
        .transpose()
        .map_err(Into::into)
}

async fn evidence_object_reference_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    evidence_id: i64,
) -> anyhow::Result<Option<EvidenceObjectReference>> {
    let sql = evidence_object_reference_sqlite_select(
        "WHERE tenant_id = ?1 AND evidence_id = ?2 ORDER BY updated_at DESC LIMIT 1",
    );
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(evidence_id)
        .fetch_optional(pool)
        .await
        .context("SQLite-Evidence-Object-Referenz konnte nicht gelesen werden")?;
    row.map(evidence_object_reference_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

async fn verify_evidence_object_reference_postgres(
    pool: &PgPool,
    tenant_id: i64,
    evidence_id: i64,
    actor_id: i64,
) -> anyhow::Result<Option<EvidenceObjectDrillResult>> {
    let Some(reference) = evidence_object_reference_postgres(pool, tenant_id, evidence_id).await?
    else {
        return Ok(None);
    };
    let Some(config) =
        evidence_storage_backend_config_by_id_postgres(pool, tenant_id, &reference.backend_id)
            .await?
    else {
        return Ok(Some(object_drill_result_from_error(
            &reference,
            "check_failed",
            "backend_error",
        )));
    };
    let result = object_drill_result_from_contract(&config, &reference);
    persist_object_drill_result_postgres(pool, tenant_id, evidence_id, actor_id, &result).await?;
    Ok(Some(result))
}

async fn verify_evidence_object_reference_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    evidence_id: i64,
    actor_id: i64,
) -> anyhow::Result<Option<EvidenceObjectDrillResult>> {
    let Some(reference) = evidence_object_reference_sqlite(pool, tenant_id, evidence_id).await?
    else {
        return Ok(None);
    };
    let Some(config) =
        evidence_storage_backend_config_by_id_sqlite(pool, tenant_id, &reference.backend_id)
            .await?
    else {
        return Ok(Some(object_drill_result_from_error(
            &reference,
            "check_failed",
            "backend_error",
        )));
    };
    let result = object_drill_result_from_contract(&config, &reference);
    persist_object_drill_result_sqlite(pool, tenant_id, evidence_id, actor_id, &result).await?;
    Ok(Some(result))
}

async fn evidence_storage_backend_config_by_id_postgres(
    pool: &PgPool,
    tenant_id: i64,
    backend_id: &str,
) -> anyhow::Result<Option<EvidenceStorageBackendConfig>> {
    let sql =
        evidence_storage_backend_config_postgres_select("WHERE tenant_id = $1 AND backend_id = $2");
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(backend_id.trim())
        .fetch_optional(pool)
        .await?;
    row.map(evidence_storage_backend_config_from_pg_row)
        .transpose()
        .map_err(Into::into)
}

async fn evidence_storage_backend_config_by_id_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    backend_id: &str,
) -> anyhow::Result<Option<EvidenceStorageBackendConfig>> {
    let sql =
        evidence_storage_backend_config_sqlite_select("WHERE tenant_id = ?1 AND backend_id = ?2");
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(backend_id.trim())
        .fetch_optional(pool)
        .await?;
    row.map(evidence_storage_backend_config_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

fn storage_backend_validation_status(config: &EvidenceStorageBackendConfig) -> (String, String) {
    if config.backend_type == BACKEND_DISABLED {
        return (STATUS_NOT_CONFIGURED.to_string(), String::new());
    }
    if config.backend_type == BACKEND_LOCAL_FILESYSTEM {
        return (STATUS_READY.to_string(), String::new());
    }
    if config.backend_type != BACKEND_S3_COMPATIBLE {
        return (STATUS_ERROR.to_string(), "invalid_backend_type".to_string());
    }
    if config.endpoint_reference.trim().is_empty() {
        return (
            STATUS_VALIDATION_REQUIRED.to_string(),
            "invalid_endpoint".to_string(),
        );
    }
    if let Err(err) = validate_endpoint_reference(
        &config.endpoint_reference,
        config.tls_required,
        &config.allowed_endpoint_policy,
    ) {
        return (STATUS_ERROR.to_string(), err.safe_error_class().to_string());
    }
    if validate_bucket_name(&config.bucket_name).is_err() {
        return (
            STATUS_VALIDATION_REQUIRED.to_string(),
            "invalid_bucket_name".to_string(),
        );
    }
    if config.region.trim().is_empty() {
        return (
            STATUS_VALIDATION_REQUIRED.to_string(),
            "storage_not_configured".to_string(),
        );
    }
    if config.access_key_secret_ref.trim().is_empty()
        || config.secret_key_secret_ref.trim().is_empty()
    {
        return (
            STATUS_CONFIGURED_METADATA_ONLY.to_string(),
            "credentials_missing".to_string(),
        );
    }
    (STATUS_READY_FOR_TEST.to_string(), String::new())
}

fn object_drill_result_from_contract(
    config: &EvidenceStorageBackendConfig,
    reference: &EvidenceObjectReference,
) -> EvidenceObjectDrillResult {
    let (status, safe_error_class, object_present, readable, calculated_sha256) =
        match reference.contract_status.as_str() {
            "present" => {
                let hash_matches = !reference.expected_sha256.trim().is_empty()
                    && reference
                        .expected_sha256
                        .eq_ignore_ascii_case(&reference.contract_sha256);
                let status = if reference.expected_sha256.trim().is_empty() || hash_matches {
                    "valid"
                } else {
                    "mismatch"
                };
                let safe_error_class = if status == "mismatch" {
                    "hash_mismatch"
                } else {
                    ""
                };
                (
                    status.to_string(),
                    safe_error_class.to_string(),
                    true,
                    true,
                    reference.contract_sha256.clone(),
                )
            }
            "missing" => (
                "missing_artifact".to_string(),
                "object_missing".to_string(),
                false,
                false,
                String::new(),
            ),
            "unreadable" => (
                "check_failed".to_string(),
                "object_unreadable".to_string(),
                true,
                false,
                String::new(),
            ),
            "timeout" => (
                "check_failed".to_string(),
                "timeout".to_string(),
                true,
                false,
                String::new(),
            ),
            "access_denied" => (
                "check_failed".to_string(),
                "access_denied".to_string(),
                true,
                false,
                String::new(),
            ),
            "backend_error" => (
                "check_failed".to_string(),
                "backend_error".to_string(),
                false,
                false,
                String::new(),
            ),
            _ => (
                "check_failed".to_string(),
                "validation_required".to_string(),
                false,
                false,
                String::new(),
            ),
        };
    EvidenceObjectDrillResult {
        backend_id: config.backend_id.clone(),
        backend_type: config.backend_type.clone(),
        evidence_id: reference.evidence_id,
        object_reference_present: true,
        object_present,
        readable,
        expected_sha256_present: !reference.expected_sha256.trim().is_empty(),
        calculated_sha256,
        hash_matches: status == "valid",
        status,
        safe_error_class,
        size_bytes: reference.contract_size_bytes,
    }
}

fn object_drill_result_from_error(
    reference: &EvidenceObjectReference,
    status: &str,
    safe_error_class: &str,
) -> EvidenceObjectDrillResult {
    EvidenceObjectDrillResult {
        backend_id: reference.backend_id.clone(),
        backend_type: reference.backend_type.clone(),
        evidence_id: reference.evidence_id,
        object_reference_present: true,
        object_present: false,
        readable: false,
        expected_sha256_present: !reference.expected_sha256.trim().is_empty(),
        calculated_sha256: String::new(),
        hash_matches: false,
        status: status.to_string(),
        safe_error_class: safe_error_class.to_string(),
        size_bytes: None,
    }
}

async fn persist_object_drill_result_postgres(
    pool: &PgPool,
    tenant_id: i64,
    evidence_id: i64,
    actor_id: i64,
    result: &EvidenceObjectDrillResult,
) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        r#"
        UPDATE evidence_object_reference
        SET last_drill_at = (CURRENT_TIMESTAMP)::text,
            last_drill_status = $3,
            last_drill_error_class = $4,
            updated_at = (CURRENT_TIMESTAMP)::text
        WHERE tenant_id = $1 AND evidence_id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .bind(&result.status)
    .bind(&result.safe_error_class)
    .execute(&mut *tx)
    .await?;
    insert_storage_backend_event_postgres_tx(
        &mut tx,
        tenant_id,
        StorageBackendEventWrite {
            backend_id: result.backend_id.clone(),
            evidence_id: Some(evidence_id),
            event_type: "storage_object_drill_completed",
            actor_id: Some(actor_id),
            status: result.status.clone(),
            error_class: result.safe_error_class.clone(),
            summary: "Object-Storage-Contract-Drill abgeschlossen.",
            detail: json!({
                "object_present": result.object_present,
                "readable": result.readable,
                "hash_matches": result.hash_matches,
                "size_bytes": result.size_bytes,
                "object_contents_logged": false,
                "secrets_exposed": false
            }),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn persist_object_drill_result_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    evidence_id: i64,
    actor_id: i64,
    result: &EvidenceObjectDrillResult,
) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        r#"
        UPDATE evidence_object_reference
        SET last_drill_at = datetime('now'),
            last_drill_status = ?3,
            last_drill_error_class = ?4,
            updated_at = datetime('now')
        WHERE tenant_id = ?1 AND evidence_id = ?2
        "#,
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .bind(&result.status)
    .bind(&result.safe_error_class)
    .execute(&mut *tx)
    .await?;
    insert_storage_backend_event_sqlite_tx(
        &mut tx,
        tenant_id,
        StorageBackendEventWrite {
            backend_id: result.backend_id.clone(),
            evidence_id: Some(evidence_id),
            event_type: "storage_object_drill_completed",
            actor_id: Some(actor_id),
            status: result.status.clone(),
            error_class: result.safe_error_class.clone(),
            summary: "Object-Storage-Contract-Drill abgeschlossen.",
            detail: json!({
                "object_present": result.object_present,
                "readable": result.readable,
                "hash_matches": result.hash_matches,
                "size_bytes": result.size_bytes,
                "object_contents_logged": false,
                "secrets_exposed": false
            }),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn evidence_storage_secret_reference_statuses_postgres(
    pool: &PgPool,
    tenant_id: i64,
    backend_id: &str,
) -> anyhow::Result<Vec<EvidenceStorageSecretReferenceStatus>> {
    let sql = evidence_storage_secret_reference_status_postgres_select(
        "WHERE tenant_id = $1 AND backend_id = $2 ORDER BY secret_ref_type",
    );
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(backend_id)
        .fetch_all(pool)
        .await?;
    rows.into_iter()
        .map(evidence_storage_secret_reference_status_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn evidence_storage_secret_reference_statuses_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    backend_id: &str,
) -> anyhow::Result<Vec<EvidenceStorageSecretReferenceStatus>> {
    let sql = evidence_storage_secret_reference_status_sqlite_select(
        "WHERE tenant_id = ?1 AND backend_id = ?2 ORDER BY secret_ref_type",
    );
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(backend_id)
        .fetch_all(pool)
        .await?;
    rows.into_iter()
        .map(evidence_storage_secret_reference_status_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn refresh_secret_reference_statuses_postgres_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    config: &EvidenceStorageBackendConfig,
) -> anyhow::Result<()> {
    for (secret_ref_type, reference) in storage_secret_references(config) {
        sqlx::query(evidence_storage_secret_reference_status_postgres_upsert_sql())
            .bind(tenant_id)
            .bind(&config.backend_id)
            .bind(reference)
            .bind(secret_ref_type)
            .bind(secret_presence_status(reference))
            .bind(redacted_secret_display(reference))
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

async fn refresh_secret_reference_statuses_sqlite_tx(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    config: &EvidenceStorageBackendConfig,
) -> anyhow::Result<()> {
    for (secret_ref_type, reference) in storage_secret_references(config) {
        sqlx::query(evidence_storage_secret_reference_status_sqlite_upsert_sql())
            .bind(tenant_id)
            .bind(&config.backend_id)
            .bind(reference)
            .bind(secret_ref_type)
            .bind(secret_presence_status(reference))
            .bind(redacted_secret_display(reference))
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

fn storage_secret_references(config: &EvidenceStorageBackendConfig) -> [(&'static str, &str); 3] {
    [
        ("access_key", config.access_key_secret_ref.as_str()),
        ("secret_key", config.secret_key_secret_ref.as_str()),
        ("session_token", config.session_token_secret_ref.as_str()),
    ]
}

async fn evidence_storage_backend_events_postgres(
    pool: &PgPool,
    tenant_id: i64,
    backend_id: &str,
    limit: i64,
) -> anyhow::Result<Vec<EvidenceStorageBackendEvent>> {
    let sql = evidence_storage_backend_event_postgres_select(
        "WHERE tenant_id = $1 AND backend_id = $2 ORDER BY created_at DESC, id DESC LIMIT $3",
    );
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(backend_id.trim())
        .bind(limit.clamp(1, 200))
        .fetch_all(pool)
        .await?;
    rows.into_iter()
        .map(evidence_storage_backend_event_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn evidence_storage_backend_events_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    backend_id: &str,
    limit: i64,
) -> anyhow::Result<Vec<EvidenceStorageBackendEvent>> {
    let sql = evidence_storage_backend_event_sqlite_select(
        "WHERE tenant_id = ?1 AND backend_id = ?2 ORDER BY created_at DESC, id DESC LIMIT ?3",
    );
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(backend_id.trim())
        .bind(limit.clamp(1, 200))
        .fetch_all(pool)
        .await?;
    rows.into_iter()
        .map(evidence_storage_backend_event_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn insert_storage_backend_event_postgres_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    event: StorageBackendEventWrite,
) -> anyhow::Result<i64> {
    let id: i64 = sqlx::query_scalar(
        r#"
        INSERT INTO evidence_storage_backend_event (
            tenant_id, backend_id, evidence_id, event_type, actor_id,
            status, error_class, summary, detail_json, created_at
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,(CURRENT_TIMESTAMP)::text)
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(event.backend_id)
    .bind(event.evidence_id)
    .bind(event.event_type)
    .bind(event.actor_id)
    .bind(event.status)
    .bind(event.error_class)
    .bind(event.summary)
    .bind(event.detail.to_string())
    .fetch_one(&mut **tx)
    .await?;
    Ok(id)
}

async fn insert_storage_backend_event_sqlite_tx(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    event: StorageBackendEventWrite,
) -> anyhow::Result<i64> {
    let result = sqlx::query(
        r#"
        INSERT INTO evidence_storage_backend_event (
            tenant_id, backend_id, evidence_id, event_type, actor_id,
            status, error_class, summary, detail_json, created_at
        )
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,datetime('now'))
        "#,
    )
    .bind(tenant_id)
    .bind(event.backend_id)
    .bind(event.evidence_id)
    .bind(event.event_type)
    .bind(event.actor_id)
    .bind(event.status)
    .bind(event.error_class)
    .bind(event.summary)
    .bind(event.detail.to_string())
    .execute(&mut **tx)
    .await?;
    Ok(result.last_insert_rowid())
}

async fn set_legal_hold_postgres(
    pool: &PgPool,
    tenant_id: i64,
    evidence_id: i64,
    actor_id: i64,
    payload: EvidenceLegalHoldRequest,
) -> anyhow::Result<Option<EvidenceIntegrityItem>> {
    let reason = normalize_required_text(&payload.reason, "Legal-Hold-Begruendung")?;
    let note = payload.review_note.unwrap_or_default();
    let mut tx = pool.begin().await?;
    let result = sqlx::query(
        r#"
        UPDATE evidence_evidenceitem
        SET legal_hold_status = 'active',
            legal_hold_reason = $3,
            legal_hold_set_by = $4,
            legal_hold_set_at = (CURRENT_TIMESTAMP)::text,
            legal_hold_released_by = NULL,
            legal_hold_released_at = NULL,
            legal_hold_release_reason = '',
            legal_hold_blocks_disposition = TRUE,
            disposition_status = CASE
                WHEN disposition_status IN ('due','review_required','approved_for_disposition','disposition_completed_metadata_only')
                THEN 'blocked_by_legal_hold'
                ELSE disposition_status
            END,
            disposition_blocked_reason = CASE
                WHEN disposition_status IN ('due','review_required','approved_for_disposition','disposition_completed_metadata_only')
                THEN 'Legal Hold aktiv'
                ELSE disposition_blocked_reason
            END,
            integrity_review_note = $5,
            updated_at = (CURRENT_TIMESTAMP)::text
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .bind(reason)
    .bind(actor_id)
    .bind(note.trim())
    .execute(&mut *tx)
    .await
    .context("PostgreSQL-Legal-Hold konnte nicht gesetzt werden")?;
    if result.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(None);
    }
    insert_evidence_integrity_event_postgres_tx(
        &mut tx,
        tenant_id,
        evidence_id,
        EvidenceIntegrityEventWrite {
            event_type: "legal_hold_set".to_string(),
            actor_id: Some(actor_id),
            integrity_status: String::new(),
            legal_hold_status: "active".to_string(),
            disposition_status: String::new(),
            mismatch: false,
            error_class: String::new(),
            detail: json!({"reason_present": true, "blocks_disposition": true}),
            note,
        },
    )
    .await?;
    tx.commit().await?;
    evidence_integrity_item_by_id_postgres(pool, tenant_id, evidence_id).await
}

async fn set_legal_hold_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    evidence_id: i64,
    actor_id: i64,
    payload: EvidenceLegalHoldRequest,
) -> anyhow::Result<Option<EvidenceIntegrityItem>> {
    let reason = normalize_required_text(&payload.reason, "Legal-Hold-Begruendung")?;
    let note = payload.review_note.unwrap_or_default();
    let mut tx = pool.begin().await?;
    let result = sqlx::query(
        r#"
        UPDATE evidence_evidenceitem
        SET legal_hold_status = 'active',
            legal_hold_reason = ?3,
            legal_hold_set_by = ?4,
            legal_hold_set_at = datetime('now'),
            legal_hold_released_by = NULL,
            legal_hold_released_at = NULL,
            legal_hold_release_reason = '',
            legal_hold_blocks_disposition = 1,
            disposition_status = CASE
                WHEN disposition_status IN ('due','review_required','approved_for_disposition','disposition_completed_metadata_only')
                THEN 'blocked_by_legal_hold'
                ELSE disposition_status
            END,
            disposition_blocked_reason = CASE
                WHEN disposition_status IN ('due','review_required','approved_for_disposition','disposition_completed_metadata_only')
                THEN 'Legal Hold aktiv'
                ELSE disposition_blocked_reason
            END,
            integrity_review_note = ?5,
            updated_at = datetime('now')
        WHERE tenant_id = ?1 AND id = ?2
        "#,
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .bind(reason)
    .bind(actor_id)
    .bind(note.trim())
    .execute(&mut *tx)
    .await
    .context("SQLite-Legal-Hold konnte nicht gesetzt werden")?;
    if result.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(None);
    }
    insert_evidence_integrity_event_sqlite_tx(
        &mut tx,
        tenant_id,
        evidence_id,
        EvidenceIntegrityEventWrite {
            event_type: "legal_hold_set".to_string(),
            actor_id: Some(actor_id),
            integrity_status: String::new(),
            legal_hold_status: "active".to_string(),
            disposition_status: String::new(),
            mismatch: false,
            error_class: String::new(),
            detail: json!({"reason_present": true, "blocks_disposition": true}),
            note,
        },
    )
    .await?;
    tx.commit().await?;
    evidence_integrity_item_by_id_sqlite(pool, tenant_id, evidence_id).await
}

async fn release_legal_hold_postgres(
    pool: &PgPool,
    tenant_id: i64,
    evidence_id: i64,
    actor_id: i64,
    payload: EvidenceLegalHoldReleaseRequest,
) -> anyhow::Result<Option<EvidenceIntegrityItem>> {
    let reason =
        normalize_required_text(&payload.release_reason, "Legal-Hold-Freigabebegruendung")?;
    let note = payload.review_note.unwrap_or_default();
    let mut tx = pool.begin().await?;
    let result = sqlx::query(
        r#"
        UPDATE evidence_evidenceitem
        SET legal_hold_status = 'released',
            legal_hold_released_by = $3,
            legal_hold_released_at = (CURRENT_TIMESTAMP)::text,
            legal_hold_release_reason = $4,
            legal_hold_blocks_disposition = FALSE,
            disposition_status = CASE
                WHEN disposition_status = 'blocked_by_legal_hold' THEN 'review_required'
                ELSE disposition_status
            END,
            disposition_blocked_reason = CASE
                WHEN disposition_status = 'blocked_by_legal_hold' THEN ''
                ELSE disposition_blocked_reason
            END,
            integrity_review_note = $5,
            updated_at = (CURRENT_TIMESTAMP)::text
        WHERE tenant_id = $1 AND id = $2 AND legal_hold_status = 'active'
        "#,
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .bind(actor_id)
    .bind(reason)
    .bind(note.trim())
    .execute(&mut *tx)
    .await
    .context("PostgreSQL-Legal-Hold konnte nicht freigegeben werden")?;
    if result.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(None);
    }
    insert_evidence_integrity_event_postgres_tx(
        &mut tx,
        tenant_id,
        evidence_id,
        EvidenceIntegrityEventWrite {
            event_type: "legal_hold_released".to_string(),
            actor_id: Some(actor_id),
            integrity_status: String::new(),
            legal_hold_status: "released".to_string(),
            disposition_status: String::new(),
            mismatch: false,
            error_class: String::new(),
            detail: json!({"release_reason_present": true, "blocks_disposition": false}),
            note,
        },
    )
    .await?;
    tx.commit().await?;
    evidence_integrity_item_by_id_postgres(pool, tenant_id, evidence_id).await
}

async fn release_legal_hold_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    evidence_id: i64,
    actor_id: i64,
    payload: EvidenceLegalHoldReleaseRequest,
) -> anyhow::Result<Option<EvidenceIntegrityItem>> {
    let reason =
        normalize_required_text(&payload.release_reason, "Legal-Hold-Freigabebegruendung")?;
    let note = payload.review_note.unwrap_or_default();
    let mut tx = pool.begin().await?;
    let result = sqlx::query(
        r#"
        UPDATE evidence_evidenceitem
        SET legal_hold_status = 'released',
            legal_hold_released_by = ?3,
            legal_hold_released_at = datetime('now'),
            legal_hold_release_reason = ?4,
            legal_hold_blocks_disposition = 0,
            disposition_status = CASE
                WHEN disposition_status = 'blocked_by_legal_hold' THEN 'review_required'
                ELSE disposition_status
            END,
            disposition_blocked_reason = CASE
                WHEN disposition_status = 'blocked_by_legal_hold' THEN ''
                ELSE disposition_blocked_reason
            END,
            integrity_review_note = ?5,
            updated_at = datetime('now')
        WHERE tenant_id = ?1 AND id = ?2 AND legal_hold_status = 'active'
        "#,
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .bind(actor_id)
    .bind(reason)
    .bind(note.trim())
    .execute(&mut *tx)
    .await
    .context("SQLite-Legal-Hold konnte nicht freigegeben werden")?;
    if result.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(None);
    }
    insert_evidence_integrity_event_sqlite_tx(
        &mut tx,
        tenant_id,
        evidence_id,
        EvidenceIntegrityEventWrite {
            event_type: "legal_hold_released".to_string(),
            actor_id: Some(actor_id),
            integrity_status: String::new(),
            legal_hold_status: "released".to_string(),
            disposition_status: String::new(),
            mismatch: false,
            error_class: String::new(),
            detail: json!({"release_reason_present": true, "blocks_disposition": false}),
            note,
        },
    )
    .await?;
    tx.commit().await?;
    evidence_integrity_item_by_id_sqlite(pool, tenant_id, evidence_id).await
}

async fn decide_disposition_postgres(
    pool: &PgPool,
    tenant_id: i64,
    evidence_id: i64,
    actor_id: i64,
    payload: EvidenceDispositionRequest,
) -> anyhow::Result<Option<EvidenceIntegrityItem>> {
    let current = evidence_integrity_item_by_id_postgres(pool, tenant_id, evidence_id).await?;
    let Some(current) = current else {
        return Ok(None);
    };
    let mut status = normalize_disposition_status(&payload.disposition_status)?;
    let reason = normalize_required_text(&payload.reason, "Disposition-Begruendung")?;
    let decision = payload.decision.unwrap_or_default().trim().to_string();
    let retention_due_at =
        normalize_evidence_date(payload.retention_due_at.as_deref(), "Retention faellig am")?;
    let disposition_due_at = normalize_evidence_date(
        payload.disposition_due_at.as_deref(),
        "Disposition faellig am",
    )?;
    let mut blocked_reason = payload
        .blocked_reason
        .unwrap_or_default()
        .trim()
        .to_string();
    let legal_hold_blocks = current.legal_hold_status == "active";
    if legal_hold_blocks {
        status = "blocked_by_legal_hold".to_string();
        if blocked_reason.is_empty() {
            blocked_reason = "Legal Hold aktiv".to_string();
        }
    }
    let disposal_candidate = matches!(
        status.as_str(),
        "due"
            | "review_required"
            | "approved_for_disposition"
            | "disposition_completed_metadata_only"
    );
    let note = payload.review_note.unwrap_or_default();
    let mut tx = pool.begin().await?;
    let result = sqlx::query(
        r#"
        UPDATE evidence_evidenceitem
        SET disposition_status = $3,
            retention_due_at = $4,
            disposition_due_at = $5,
            disposition_decision = $6,
            disposition_reason = $7,
            disposition_decided_by = $8,
            disposition_decided_at = (CURRENT_TIMESTAMP)::text,
            disposition_blocked_reason = $9,
            disposal_candidate = $10,
            legal_hold_blocks_disposition = $11,
            integrity_review_note = $12,
            updated_at = (CURRENT_TIMESTAMP)::text
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .bind(&status)
    .bind(retention_due_at)
    .bind(disposition_due_at)
    .bind(&decision)
    .bind(reason)
    .bind(actor_id)
    .bind(&blocked_reason)
    .bind(disposal_candidate)
    .bind(legal_hold_blocks)
    .bind(note.trim())
    .execute(&mut *tx)
    .await
    .context("PostgreSQL-Disposition-Entscheidung konnte nicht gespeichert werden")?;
    if result.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(None);
    }
    let event_type = if status == "blocked_by_legal_hold" {
        "disposition_blocked"
    } else if status == "review_required" {
        "disposition_review_started"
    } else {
        "disposition_decision_recorded"
    };
    insert_evidence_integrity_event_postgres_tx(
        &mut tx,
        tenant_id,
        evidence_id,
        EvidenceIntegrityEventWrite {
            event_type: event_type.to_string(),
            actor_id: Some(actor_id),
            integrity_status: String::new(),
            legal_hold_status: current.legal_hold_status,
            disposition_status: status.clone(),
            mismatch: false,
            error_class: String::new(),
            detail: json!({
                "decision_present": !decision.is_empty(),
                "reason_present": true,
                "metadata_only": status == "disposition_completed_metadata_only",
                "legal_hold_blocks_disposition": legal_hold_blocks,
            }),
            note,
        },
    )
    .await?;
    tx.commit().await?;
    evidence_integrity_item_by_id_postgres(pool, tenant_id, evidence_id).await
}

async fn decide_disposition_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    evidence_id: i64,
    actor_id: i64,
    payload: EvidenceDispositionRequest,
) -> anyhow::Result<Option<EvidenceIntegrityItem>> {
    let current = evidence_integrity_item_by_id_sqlite(pool, tenant_id, evidence_id).await?;
    let Some(current) = current else {
        return Ok(None);
    };
    let mut status = normalize_disposition_status(&payload.disposition_status)?;
    let reason = normalize_required_text(&payload.reason, "Disposition-Begruendung")?;
    let decision = payload.decision.unwrap_or_default().trim().to_string();
    let retention_due_at =
        normalize_evidence_date(payload.retention_due_at.as_deref(), "Retention faellig am")?;
    let disposition_due_at = normalize_evidence_date(
        payload.disposition_due_at.as_deref(),
        "Disposition faellig am",
    )?;
    let mut blocked_reason = payload
        .blocked_reason
        .unwrap_or_default()
        .trim()
        .to_string();
    let legal_hold_blocks = current.legal_hold_status == "active";
    if legal_hold_blocks {
        status = "blocked_by_legal_hold".to_string();
        if blocked_reason.is_empty() {
            blocked_reason = "Legal Hold aktiv".to_string();
        }
    }
    let disposal_candidate = matches!(
        status.as_str(),
        "due"
            | "review_required"
            | "approved_for_disposition"
            | "disposition_completed_metadata_only"
    );
    let note = payload.review_note.unwrap_or_default();
    let mut tx = pool.begin().await?;
    let result = sqlx::query(
        r#"
        UPDATE evidence_evidenceitem
        SET disposition_status = ?3,
            retention_due_at = ?4,
            disposition_due_at = ?5,
            disposition_decision = ?6,
            disposition_reason = ?7,
            disposition_decided_by = ?8,
            disposition_decided_at = datetime('now'),
            disposition_blocked_reason = ?9,
            disposal_candidate = ?10,
            legal_hold_blocks_disposition = ?11,
            integrity_review_note = ?12,
            updated_at = datetime('now')
        WHERE tenant_id = ?1 AND id = ?2
        "#,
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .bind(&status)
    .bind(retention_due_at)
    .bind(disposition_due_at)
    .bind(&decision)
    .bind(reason)
    .bind(actor_id)
    .bind(&blocked_reason)
    .bind(disposal_candidate)
    .bind(legal_hold_blocks)
    .bind(note.trim())
    .execute(&mut *tx)
    .await
    .context("SQLite-Disposition-Entscheidung konnte nicht gespeichert werden")?;
    if result.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(None);
    }
    let event_type = if status == "blocked_by_legal_hold" {
        "disposition_blocked"
    } else if status == "review_required" {
        "disposition_review_started"
    } else {
        "disposition_decision_recorded"
    };
    insert_evidence_integrity_event_sqlite_tx(
        &mut tx,
        tenant_id,
        evidence_id,
        EvidenceIntegrityEventWrite {
            event_type: event_type.to_string(),
            actor_id: Some(actor_id),
            integrity_status: String::new(),
            legal_hold_status: current.legal_hold_status,
            disposition_status: status.clone(),
            mismatch: false,
            error_class: String::new(),
            detail: json!({
                "decision_present": !decision.is_empty(),
                "reason_present": true,
                "metadata_only": status == "disposition_completed_metadata_only",
                "legal_hold_blocks_disposition": legal_hold_blocks,
            }),
            note,
        },
    )
    .await?;
    tx.commit().await?;
    evidence_integrity_item_by_id_sqlite(pool, tenant_id, evidence_id).await
}

fn normalize_batch_limit(value: i64) -> i64 {
    value.clamp(1, 25)
}

fn normalize_integrity_status(value: &str) -> anyhow::Result<String> {
    let value = value.trim().to_ascii_lowercase();
    if matches!(
        value.as_str(),
        "not_checked"
            | "valid"
            | "mismatch"
            | "missing_artifact"
            | "check_failed"
            | "quarantined"
            | "accepted_with_exception"
    ) {
        Ok(value)
    } else {
        bail!("Integritaetsstatus ist ungueltig.");
    }
}

fn normalize_disposition_status(value: &str) -> anyhow::Result<String> {
    let value = value.trim().to_ascii_lowercase();
    if matches!(
        value.as_str(),
        "not_due"
            | "due"
            | "review_required"
            | "blocked_by_legal_hold"
            | "approved_for_disposition"
            | "disposition_deferred"
            | "disposition_completed_metadata_only"
            | "disposition_executed"
            | "disposition_failed"
            | "disposition_cancelled"
    ) {
        Ok(value)
    } else {
        bail!("Disposition-Status ist ungueltig.");
    }
}

fn integrity_status_label(status: &str) -> &'static str {
    match status {
        "valid" => "valid",
        "mismatch" => "Hash mismatch",
        "missing_artifact" => "Artefakt fehlt",
        "check_failed" => "Check fehlgeschlagen",
        "quarantined" => "Quarantaene",
        "accepted_with_exception" => "Ausnahme akzeptiert",
        _ => "nicht geprueft",
    }
}

fn legal_hold_status_label(status: &str) -> &'static str {
    match status {
        "active" => "Legal Hold aktiv",
        "released" => "Legal Hold freigegeben",
        _ => "kein Legal Hold",
    }
}

fn disposition_status_label(status: &str) -> &'static str {
    match status {
        "due" => "faellig",
        "review_required" => "Review erforderlich",
        "blocked_by_legal_hold" => "durch Legal Hold blockiert",
        "approved_for_disposition" => "Disposition freigegeben",
        "disposition_deferred" => "Disposition verschoben",
        "disposition_completed_metadata_only" => "metadata-only abgeschlossen",
        "disposition_executed" => "physisch ausgesondert",
        "disposition_failed" => "Aussonderung fehlgeschlagen",
        "disposition_cancelled" => "Disposition abgebrochen",
        _ => "nicht faellig",
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceOverview {
    pub evidence_items: Vec<EvidenceItemSummary>,
    pub evidence_needs: Vec<RequirementEvidenceNeedSummary>,
    pub need_summary: EvidenceNeedSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceQualityOverview {
    pub summary: EvidenceQualitySummary,
    pub items: Vec<EvidenceQualityItem>,
    pub needs: Vec<EvidenceQualityNeed>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceIntegrityOverview {
    pub summary: EvidenceIntegritySummary,
    pub items: Vec<EvidenceIntegrityItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceIntegritySummary {
    pub total_items: i64,
    pub not_checked: i64,
    pub valid: i64,
    pub mismatch: i64,
    pub missing_artifact: i64,
    pub check_failed: i64,
    pub quarantined: i64,
    pub accepted_with_exception: i64,
    pub legal_hold_active: i64,
    pub disposition_due: i64,
    pub disposition_blocked: i64,
    pub disposal_candidates: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceIntegrityItem {
    pub id: i64,
    pub tenant_id: i64,
    pub title: String,
    pub evidence_status: String,
    pub quality_status_label: String,
    pub sensitivity: String,
    pub owner_id: Option<i64>,
    pub owner_display: Option<String>,
    pub file_name: Option<String>,
    pub artifact_reference_present: bool,
    pub expected_sha256_present: bool,
    pub expected_sha256: String,
    pub last_calculated_sha256: String,
    pub last_integrity_checked_at: Option<String>,
    pub integrity_status: String,
    pub integrity_status_label: String,
    pub integrity_mismatch: bool,
    pub quarantine_status: String,
    pub integrity_checked_by_id: Option<i64>,
    pub integrity_checked_by_display: Option<String>,
    pub integrity_result: String,
    pub integrity_error_class: String,
    pub integrity_review_note: String,
    pub valid_until: Option<String>,
    pub retention_until: Option<String>,
    pub retention_due_at: Option<String>,
    pub legal_hold_status: String,
    pub legal_hold_status_label: String,
    pub legal_hold_reason: String,
    pub legal_hold_set_by: Option<i64>,
    pub legal_hold_set_by_display: Option<String>,
    pub legal_hold_set_at: Option<String>,
    pub legal_hold_released_by: Option<i64>,
    pub legal_hold_released_by_display: Option<String>,
    pub legal_hold_released_at: Option<String>,
    pub legal_hold_release_reason: String,
    pub disposition_status: String,
    pub disposition_status_label: String,
    pub disposition_due_at: Option<String>,
    pub disposition_decision: String,
    pub disposition_reason: String,
    pub disposition_decided_by: Option<i64>,
    pub disposition_decided_by_display: Option<String>,
    pub disposition_decided_at: Option<String>,
    pub disposition_blocked_reason: String,
    pub disposal_candidate: bool,
    pub legal_hold_blocks_disposition: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceIntegrityEvent {
    pub id: i64,
    pub tenant_id: i64,
    pub evidence_id: i64,
    pub event_type: String,
    pub actor_id: Option<i64>,
    pub actor_display: Option<String>,
    pub integrity_status: String,
    pub legal_hold_status: String,
    pub disposition_status: String,
    pub mismatch: bool,
    pub error_class: String,
    pub detail: Value,
    pub note: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceIntegrityTarget {
    pub id: i64,
    pub title: String,
    pub file_name: Option<String>,
    pub expected_sha256: String,
}

#[derive(Debug, Clone)]
pub struct EvidenceIntegrityCheckUpdate {
    pub calculated_sha256: String,
    pub integrity_status: String,
    pub mismatch: bool,
    pub quarantine_status: String,
    pub result: String,
    pub error_class: String,
    pub review_note: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EvidenceIntegrityBatchRequest {
    pub evidence_ids: Option<Vec<i64>>,
    pub limit: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EvidenceLegalHoldRequest {
    pub reason: String,
    pub review_note: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EvidenceLegalHoldReleaseRequest {
    pub release_reason: String,
    pub review_note: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EvidenceDispositionRequest {
    pub disposition_status: String,
    pub retention_due_at: Option<String>,
    pub disposition_due_at: Option<String>,
    pub decision: Option<String>,
    pub reason: String,
    pub blocked_reason: Option<String>,
    pub review_note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceIntegrityWorkerRun {
    pub id: i64,
    pub tenant_id: i64,
    pub started_by: Option<i64>,
    pub status: String,
    pub trigger_mode: String,
    pub batch_size: i64,
    pub max_runtime_seconds: i64,
    pub cooldown_seconds: i64,
    pub dry_run: bool,
    pub checked_count: i64,
    pub valid_count: i64,
    pub mismatch_count: i64,
    pub missing_count: i64,
    pub failed_count: i64,
    pub skipped_count: i64,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub detail: Value,
}

#[derive(Debug, Clone)]
pub struct EvidenceIntegrityWorkerRunCreate {
    pub trigger_mode: String,
    pub batch_size: i64,
    pub max_runtime_seconds: i64,
    pub cooldown_seconds: i64,
    pub dry_run: bool,
    pub detail: Value,
}

#[derive(Debug, Clone)]
pub struct EvidenceIntegrityWorkerRunFinish {
    pub status: String,
    pub checked_count: i64,
    pub valid_count: i64,
    pub mismatch_count: i64,
    pub missing_count: i64,
    pub failed_count: i64,
    pub skipped_count: i64,
    pub detail: Value,
}

#[derive(Debug, Clone)]
pub struct EvidenceDispositionExecution {
    pub deleted: bool,
    pub storage_backend: String,
    pub safe_error_class: String,
    pub tombstone_sha256: String,
    pub tombstone: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceQualitySummary {
    pub total_items: i64,
    pub approved_items: i64,
    pub reviewed_items: i64,
    pub items_with_file: i64,
    pub linked_items: i64,
    pub owner_assigned_items: i64,
    pub items_with_hash: i64,
    pub expired_items: i64,
    pub expiring_items: i64,
    pub retention_defined_items: i64,
    pub retention_due_items: i64,
    pub open_needs: i64,
    pub partial_needs: i64,
    pub covered_needs: i64,
    pub average_score: i64,
    pub maturity_label: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceQualityItem {
    pub id: i64,
    pub title: String,
    pub status: String,
    pub status_label: String,
    pub quality_score: i64,
    pub quality_level: String,
    pub issues: Vec<String>,
    pub href: String,
    pub owner_display: Option<String>,
    pub reviewed_at: Option<String>,
    pub file_name: Option<String>,
    pub linked_requirement: String,
    pub version_number: i64,
    pub sensitivity: String,
    pub valid_until: Option<String>,
    pub retention_until: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceQualityNeed {
    pub id: i64,
    pub title: String,
    pub requirement_code: String,
    pub status: String,
    pub status_label: String,
    pub covered_count: i64,
    pub quality_level: String,
    pub issues: Vec<String>,
    pub href: String,
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
    pub control_id: Option<i64>,
    pub incident_id: Option<i64>,
    pub incident_title: Option<String>,
    pub mapping_program_name: Option<String>,
    pub mapping_version: Option<String>,
    pub source_authority: Option<String>,
    pub source_citation: Option<String>,
    pub source_title: Option<String>,
    pub title: String,
    pub description: String,
    pub linked_requirement: String,
    pub file_name: Option<String>,
    pub version_number: i64,
    pub supersedes_id: Option<i64>,
    pub file_sha256: String,
    pub valid_until: Option<String>,
    pub retention_until: Option<String>,
    pub retention_reason: String,
    pub sensitivity: String,
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
pub struct EvidenceItemCreateRequest {
    pub session_id: Option<i64>,
    pub domain_id: Option<i64>,
    pub measure_id: Option<i64>,
    pub requirement_id: Option<i64>,
    pub control_id: Option<i64>,
    pub incident_id: Option<i64>,
    pub title: String,
    pub description: String,
    pub linked_requirement: String,
    pub file_name: Option<String>,
    pub supersedes_id: Option<i64>,
    pub file_sha256: String,
    pub valid_until: Option<String>,
    pub retention_until: Option<String>,
    pub retention_reason: String,
    pub sensitivity: String,
    pub status: Option<String>,
    pub review_notes: String,
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

    pub async fn evidence_quality(
        &self,
        tenant_id: i64,
        session_id: Option<i64>,
        item_limit: i64,
        need_limit: i64,
    ) -> anyhow::Result<EvidenceQualityOverview> {
        let overview = self
            .evidence_overview(tenant_id, session_id, item_limit, need_limit)
            .await?;
        Ok(evidence_quality_from_overview(overview))
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

    pub async fn create_evidence_item(
        &self,
        tenant_id: i64,
        owner_id: i64,
        payload: EvidenceItemCreateRequest,
    ) -> anyhow::Result<EvidenceItemSummary> {
        match self {
            Self::Postgres(pool) => {
                create_evidence_item_postgres(pool, tenant_id, owner_id, payload).await
            }
            Self::Sqlite(pool) => {
                create_evidence_item_sqlite(pool, tenant_id, owner_id, payload).await
            }
        }
    }

    pub async fn list_evidence_for_incident(
        &self,
        tenant_id: i64,
        incident_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<EvidenceItemSummary>> {
        match self {
            Self::Postgres(pool) => {
                list_evidence_items_for_incident_postgres(pool, tenant_id, incident_id, limit).await
            }
            Self::Sqlite(pool) => {
                list_evidence_items_for_incident_sqlite(pool, tenant_id, incident_id, limit).await
            }
        }
    }

    pub async fn evidence_integrity_overview(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<EvidenceIntegrityOverview> {
        match self {
            Self::Postgres(pool) => {
                evidence_integrity_overview_postgres(pool, tenant_id, limit).await
            }
            Self::Sqlite(pool) => evidence_integrity_overview_sqlite(pool, tenant_id, limit).await,
        }
    }

    pub async fn evidence_integrity_target(
        &self,
        tenant_id: i64,
        evidence_id: i64,
    ) -> anyhow::Result<Option<EvidenceIntegrityTarget>> {
        match self {
            Self::Postgres(pool) => {
                evidence_integrity_target_postgres(pool, tenant_id, evidence_id).await
            }
            Self::Sqlite(pool) => {
                evidence_integrity_target_sqlite(pool, tenant_id, evidence_id).await
            }
        }
    }

    pub async fn evidence_integrity_item(
        &self,
        tenant_id: i64,
        evidence_id: i64,
    ) -> anyhow::Result<Option<EvidenceIntegrityItem>> {
        match self {
            Self::Postgres(pool) => {
                evidence_integrity_item_by_id_postgres(pool, tenant_id, evidence_id).await
            }
            Self::Sqlite(pool) => {
                evidence_integrity_item_by_id_sqlite(pool, tenant_id, evidence_id).await
            }
        }
    }

    pub async fn evidence_integrity_targets(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<EvidenceIntegrityTarget>> {
        let limit = normalize_batch_limit(limit);
        match self {
            Self::Postgres(pool) => {
                evidence_integrity_targets_postgres(pool, tenant_id, limit).await
            }
            Self::Sqlite(pool) => evidence_integrity_targets_sqlite(pool, tenant_id, limit).await,
        }
    }

    pub async fn record_evidence_integrity_event(
        &self,
        tenant_id: i64,
        evidence_id: i64,
        actor_id: Option<i64>,
        event_type: &str,
        detail: Value,
        note: &str,
    ) -> anyhow::Result<Option<EvidenceIntegrityEvent>> {
        let event = EvidenceIntegrityEventWrite {
            event_type: event_type.to_string(),
            actor_id,
            integrity_status: String::new(),
            legal_hold_status: String::new(),
            disposition_status: String::new(),
            mismatch: false,
            error_class: String::new(),
            detail,
            note: note.trim().to_string(),
        };
        match self {
            Self::Postgres(pool) => {
                insert_evidence_integrity_event_postgres(pool, tenant_id, evidence_id, event).await
            }
            Self::Sqlite(pool) => {
                insert_evidence_integrity_event_sqlite(pool, tenant_id, evidence_id, event).await
            }
        }
    }

    pub async fn apply_integrity_check_result(
        &self,
        tenant_id: i64,
        evidence_id: i64,
        actor_id: i64,
        update: EvidenceIntegrityCheckUpdate,
    ) -> anyhow::Result<Option<EvidenceIntegrityItem>> {
        match self {
            Self::Postgres(pool) => {
                apply_integrity_check_result_postgres(
                    pool,
                    tenant_id,
                    evidence_id,
                    actor_id,
                    update,
                )
                .await
            }
            Self::Sqlite(pool) => {
                apply_integrity_check_result_sqlite(pool, tenant_id, evidence_id, actor_id, update)
                    .await
            }
        }
    }

    pub async fn evidence_integrity_events(
        &self,
        tenant_id: i64,
        evidence_id: i64,
        limit: i64,
    ) -> anyhow::Result<Option<Vec<EvidenceIntegrityEvent>>> {
        match self {
            Self::Postgres(pool) => {
                evidence_integrity_events_postgres(pool, tenant_id, evidence_id, limit).await
            }
            Self::Sqlite(pool) => {
                evidence_integrity_events_sqlite(pool, tenant_id, evidence_id, limit).await
            }
        }
    }

    pub async fn evidence_storage_backend_configs(
        &self,
        tenant_id: i64,
    ) -> anyhow::Result<Vec<EvidenceStorageBackendConfig>> {
        match self {
            Self::Postgres(pool) => {
                evidence_storage_backend_configs_postgres(pool, tenant_id).await
            }
            Self::Sqlite(pool) => evidence_storage_backend_configs_sqlite(pool, tenant_id).await,
        }
    }

    pub async fn evidence_storage_backend_config(
        &self,
        tenant_id: i64,
        backend_id: &str,
    ) -> anyhow::Result<Option<EvidenceStorageBackendConfig>> {
        match self {
            Self::Postgres(pool) => {
                evidence_storage_backend_config_by_id_postgres(pool, tenant_id, backend_id).await
            }
            Self::Sqlite(pool) => {
                evidence_storage_backend_config_by_id_sqlite(pool, tenant_id, backend_id).await
            }
        }
    }

    pub async fn upsert_evidence_storage_backend_config(
        &self,
        tenant_id: i64,
        actor_id: i64,
        payload: EvidenceStorageBackendConfigRequest,
    ) -> anyhow::Result<EvidenceStorageBackendConfig> {
        match self {
            Self::Postgres(pool) => {
                upsert_evidence_storage_backend_config_postgres(pool, tenant_id, actor_id, payload)
                    .await
            }
            Self::Sqlite(pool) => {
                upsert_evidence_storage_backend_config_sqlite(pool, tenant_id, actor_id, payload)
                    .await
            }
        }
    }

    pub async fn validate_evidence_storage_backend_config(
        &self,
        tenant_id: i64,
        backend_id: &str,
        actor_id: i64,
    ) -> anyhow::Result<
        Option<(
            EvidenceStorageBackendConfig,
            Vec<EvidenceStorageSecretReferenceStatus>,
        )>,
    > {
        match self {
            Self::Postgres(pool) => {
                validate_evidence_storage_backend_config_postgres(
                    pool, tenant_id, backend_id, actor_id,
                )
                .await
            }
            Self::Sqlite(pool) => {
                validate_evidence_storage_backend_config_sqlite(
                    pool, tenant_id, backend_id, actor_id,
                )
                .await
            }
        }
    }

    pub async fn evidence_storage_backend_events(
        &self,
        tenant_id: i64,
        backend_id: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<EvidenceStorageBackendEvent>> {
        match self {
            Self::Postgres(pool) => {
                evidence_storage_backend_events_postgres(pool, tenant_id, backend_id, limit).await
            }
            Self::Sqlite(pool) => {
                evidence_storage_backend_events_sqlite(pool, tenant_id, backend_id, limit).await
            }
        }
    }

    pub async fn attach_evidence_object_reference(
        &self,
        tenant_id: i64,
        evidence_id: i64,
        actor_id: i64,
        payload: EvidenceObjectReferenceAttachRequest,
    ) -> anyhow::Result<Option<EvidenceObjectReference>> {
        match self {
            Self::Postgres(pool) => {
                attach_evidence_object_reference_postgres(
                    pool,
                    tenant_id,
                    evidence_id,
                    actor_id,
                    payload,
                )
                .await
            }
            Self::Sqlite(pool) => {
                attach_evidence_object_reference_sqlite(
                    pool,
                    tenant_id,
                    evidence_id,
                    actor_id,
                    payload,
                )
                .await
            }
        }
    }

    pub async fn evidence_object_reference(
        &self,
        tenant_id: i64,
        evidence_id: i64,
    ) -> anyhow::Result<Option<EvidenceObjectReference>> {
        match self {
            Self::Postgres(pool) => {
                evidence_object_reference_postgres(pool, tenant_id, evidence_id).await
            }
            Self::Sqlite(pool) => {
                evidence_object_reference_sqlite(pool, tenant_id, evidence_id).await
            }
        }
    }

    pub async fn verify_evidence_object_reference(
        &self,
        tenant_id: i64,
        evidence_id: i64,
        actor_id: i64,
    ) -> anyhow::Result<Option<EvidenceObjectDrillResult>> {
        match self {
            Self::Postgres(pool) => {
                verify_evidence_object_reference_postgres(pool, tenant_id, evidence_id, actor_id)
                    .await
            }
            Self::Sqlite(pool) => {
                verify_evidence_object_reference_sqlite(pool, tenant_id, evidence_id, actor_id)
                    .await
            }
        }
    }

    pub async fn set_legal_hold(
        &self,
        tenant_id: i64,
        evidence_id: i64,
        actor_id: i64,
        payload: EvidenceLegalHoldRequest,
    ) -> anyhow::Result<Option<EvidenceIntegrityItem>> {
        match self {
            Self::Postgres(pool) => {
                set_legal_hold_postgres(pool, tenant_id, evidence_id, actor_id, payload).await
            }
            Self::Sqlite(pool) => {
                set_legal_hold_sqlite(pool, tenant_id, evidence_id, actor_id, payload).await
            }
        }
    }

    pub async fn release_legal_hold(
        &self,
        tenant_id: i64,
        evidence_id: i64,
        actor_id: i64,
        payload: EvidenceLegalHoldReleaseRequest,
    ) -> anyhow::Result<Option<EvidenceIntegrityItem>> {
        match self {
            Self::Postgres(pool) => {
                release_legal_hold_postgres(pool, tenant_id, evidence_id, actor_id, payload).await
            }
            Self::Sqlite(pool) => {
                release_legal_hold_sqlite(pool, tenant_id, evidence_id, actor_id, payload).await
            }
        }
    }

    pub async fn decide_disposition(
        &self,
        tenant_id: i64,
        evidence_id: i64,
        actor_id: i64,
        payload: EvidenceDispositionRequest,
    ) -> anyhow::Result<Option<EvidenceIntegrityItem>> {
        match self {
            Self::Postgres(pool) => {
                decide_disposition_postgres(pool, tenant_id, evidence_id, actor_id, payload).await
            }
            Self::Sqlite(pool) => {
                decide_disposition_sqlite(pool, tenant_id, evidence_id, actor_id, payload).await
            }
        }
    }

    pub async fn evidence_worker_runs(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<EvidenceIntegrityWorkerRun>> {
        match self {
            Self::Postgres(pool) => evidence_worker_runs_postgres(pool, tenant_id, limit).await,
            Self::Sqlite(pool) => evidence_worker_runs_sqlite(pool, tenant_id, limit).await,
        }
    }

    pub async fn create_evidence_worker_run(
        &self,
        tenant_id: i64,
        actor_id: i64,
        payload: EvidenceIntegrityWorkerRunCreate,
    ) -> anyhow::Result<EvidenceIntegrityWorkerRun> {
        match self {
            Self::Postgres(pool) => {
                create_evidence_worker_run_postgres(pool, tenant_id, actor_id, payload).await
            }
            Self::Sqlite(pool) => {
                create_evidence_worker_run_sqlite(pool, tenant_id, actor_id, payload).await
            }
        }
    }

    pub async fn claim_evidence_worker_run(
        &self,
        tenant_id: i64,
        actor_id: i64,
        payload: EvidenceIntegrityWorkerRunCreate,
    ) -> anyhow::Result<Option<EvidenceIntegrityWorkerRun>> {
        match self {
            Self::Postgres(pool) => {
                claim_evidence_worker_run_postgres(pool, tenant_id, actor_id, payload).await
            }
            Self::Sqlite(pool) => {
                claim_evidence_worker_run_sqlite(pool, tenant_id, actor_id, payload).await
            }
        }
    }

    pub async fn finish_evidence_worker_run(
        &self,
        tenant_id: i64,
        run_id: i64,
        payload: EvidenceIntegrityWorkerRunFinish,
    ) -> anyhow::Result<Option<EvidenceIntegrityWorkerRun>> {
        match self {
            Self::Postgres(pool) => {
                finish_evidence_worker_run_postgres(pool, tenant_id, run_id, payload).await
            }
            Self::Sqlite(pool) => {
                finish_evidence_worker_run_sqlite(pool, tenant_id, run_id, payload).await
            }
        }
    }

    pub async fn execute_disposition(
        &self,
        tenant_id: i64,
        evidence_id: i64,
        actor_id: i64,
        execution: EvidenceDispositionExecution,
    ) -> anyhow::Result<Option<EvidenceIntegrityItem>> {
        match self {
            Self::Postgres(pool) => {
                execute_disposition_postgres(pool, tenant_id, evidence_id, actor_id, execution)
                    .await
            }
            Self::Sqlite(pool) => {
                execute_disposition_sqlite(pool, tenant_id, evidence_id, actor_id, execution).await
            }
        }
    }
}

async fn evidence_worker_runs_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<EvidenceIntegrityWorkerRun>> {
    let rows = sqlx::query(evidence_worker_run_postgres_sql())
        .bind(tenant_id)
        .bind(limit.clamp(1, 25))
        .fetch_all(pool)
        .await?;
    rows.into_iter()
        .map(evidence_worker_run_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn evidence_worker_runs_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<EvidenceIntegrityWorkerRun>> {
    let rows = sqlx::query(evidence_worker_run_sqlite_sql())
        .bind(tenant_id)
        .bind(limit.clamp(1, 25))
        .fetch_all(pool)
        .await?;
    rows.into_iter()
        .map(evidence_worker_run_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn create_evidence_worker_run_postgres(
    pool: &PgPool,
    tenant_id: i64,
    actor_id: i64,
    payload: EvidenceIntegrityWorkerRunCreate,
) -> anyhow::Result<EvidenceIntegrityWorkerRun> {
    let row = sqlx::query(
        r#"
        INSERT INTO evidence_integrity_worker_run (
            tenant_id, started_by, status, trigger_mode, batch_size,
            max_runtime_seconds, cooldown_seconds, dry_run, detail_json
        )
        VALUES ($1, $2, 'running', $3, $4, $5, $6, $7, $8)
        RETURNING id, tenant_id, started_by, status, trigger_mode, batch_size,
                  max_runtime_seconds, cooldown_seconds, dry_run, checked_count,
                  valid_count, mismatch_count, missing_count, failed_count, skipped_count,
                  started_at, completed_at, detail_json::text AS detail_json_text
        "#,
    )
    .bind(tenant_id)
    .bind(actor_id)
    .bind(payload.trigger_mode)
    .bind(payload.batch_size)
    .bind(payload.max_runtime_seconds)
    .bind(payload.cooldown_seconds)
    .bind(payload.dry_run)
    .bind(sqlx::types::Json(payload.detail))
    .fetch_one(pool)
    .await?;
    evidence_worker_run_from_pg_row(row).map_err(Into::into)
}

async fn create_evidence_worker_run_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    actor_id: i64,
    payload: EvidenceIntegrityWorkerRunCreate,
) -> anyhow::Result<EvidenceIntegrityWorkerRun> {
    let result = sqlx::query(
        r#"
        INSERT INTO evidence_integrity_worker_run (
            tenant_id, started_by, status, trigger_mode, batch_size,
            max_runtime_seconds, cooldown_seconds, dry_run, detail_json
        )
        VALUES (?1, ?2, 'running', ?3, ?4, ?5, ?6, ?7, ?8)
        "#,
    )
    .bind(tenant_id)
    .bind(actor_id)
    .bind(payload.trigger_mode)
    .bind(payload.batch_size)
    .bind(payload.max_runtime_seconds)
    .bind(payload.cooldown_seconds)
    .bind(payload.dry_run)
    .bind(payload.detail.to_string())
    .execute(pool)
    .await?;
    evidence_worker_run_by_id_sqlite(pool, tenant_id, result.last_insert_rowid()).await
}

async fn claim_evidence_worker_run_postgres(
    pool: &PgPool,
    tenant_id: i64,
    actor_id: i64,
    payload: EvidenceIntegrityWorkerRunCreate,
) -> anyhow::Result<Option<EvidenceIntegrityWorkerRun>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(5_322_000_000_000_i64.saturating_add(tenant_id))
        .execute(&mut *tx)
        .await?;
    let active = sqlx::query(
        r#"
        SELECT id, tenant_id, started_by, status, trigger_mode, batch_size,
               max_runtime_seconds, cooldown_seconds, dry_run, checked_count,
               valid_count, mismatch_count, missing_count, failed_count, skipped_count,
               started_at, completed_at, detail_json::text AS detail_json_text
        FROM evidence_integrity_worker_run
        WHERE tenant_id = $1 AND status = 'running'
          AND started_at::timestamptz >= CURRENT_TIMESTAMP - INTERVAL '10 minutes'
        ORDER BY id DESC
        LIMIT 1
        FOR UPDATE
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await?;
    if active.is_some() {
        tx.rollback().await?;
        return Ok(None);
    }
    let row = sqlx::query(
        r#"
        INSERT INTO evidence_integrity_worker_run (
            tenant_id, started_by, status, trigger_mode, batch_size,
            max_runtime_seconds, cooldown_seconds, dry_run, detail_json
        )
        VALUES ($1, $2, 'running', $3, $4, $5, $6, $7, $8)
        RETURNING id, tenant_id, started_by, status, trigger_mode, batch_size,
                  max_runtime_seconds, cooldown_seconds, dry_run, checked_count,
                  valid_count, mismatch_count, missing_count, failed_count, skipped_count,
                  started_at, completed_at, detail_json::text AS detail_json_text
        "#,
    )
    .bind(tenant_id)
    .bind(actor_id)
    .bind(payload.trigger_mode)
    .bind(payload.batch_size)
    .bind(payload.max_runtime_seconds)
    .bind(payload.cooldown_seconds)
    .bind(payload.dry_run)
    .bind(sqlx::types::Json(payload.detail))
    .fetch_one(&mut *tx)
    .await?;
    let run = evidence_worker_run_from_pg_row(row)?;
    tx.commit().await?;
    Ok(Some(run))
}

async fn claim_evidence_worker_run_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    actor_id: i64,
    payload: EvidenceIntegrityWorkerRunCreate,
) -> anyhow::Result<Option<EvidenceIntegrityWorkerRun>> {
    let mut connection = pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *connection)
        .await?;
    let result = async {
        let active: Option<i64> = sqlx::query_scalar(
            r#"
            SELECT id
            FROM evidence_integrity_worker_run
            WHERE tenant_id = ?1 AND status = 'running'
              AND datetime(started_at) >= datetime('now', '-10 minutes')
            ORDER BY id DESC
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .fetch_optional(&mut *connection)
        .await?;
        if active.is_some() {
            return Ok(None);
        }
        let result = sqlx::query(
            r#"
            INSERT INTO evidence_integrity_worker_run (
                tenant_id, started_by, status, trigger_mode, batch_size,
                max_runtime_seconds, cooldown_seconds, dry_run, detail_json
            )
            VALUES (?1, ?2, 'running', ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
        )
        .bind(tenant_id)
        .bind(actor_id)
        .bind(payload.trigger_mode)
        .bind(payload.batch_size)
        .bind(payload.max_runtime_seconds)
        .bind(payload.cooldown_seconds)
        .bind(payload.dry_run)
        .bind(payload.detail.to_string())
        .execute(&mut *connection)
        .await?;
        let row = sqlx::query(evidence_worker_run_sqlite_sql())
            .bind(tenant_id)
            .bind(1_i64)
            .fetch_one(&mut *connection)
            .await?;
        let run = evidence_worker_run_from_sqlite_row(row)?;
        if run.id != result.last_insert_rowid() {
            return Err(sqlx::Error::RowNotFound);
        }
        Ok(Some(run))
    }
    .await;
    match result {
        Ok(run) => {
            sqlx::query("COMMIT").execute(&mut *connection).await?;
            Ok(run)
        }
        Err(error) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *connection).await;
            Err(error.into())
        }
    }
}

async fn finish_evidence_worker_run_postgres(
    pool: &PgPool,
    tenant_id: i64,
    run_id: i64,
    payload: EvidenceIntegrityWorkerRunFinish,
) -> anyhow::Result<Option<EvidenceIntegrityWorkerRun>> {
    let row = sqlx::query(
        r#"
        UPDATE evidence_integrity_worker_run
        SET status = $3,
            checked_count = $4,
            valid_count = $5,
            mismatch_count = $6,
            missing_count = $7,
            failed_count = $8,
            skipped_count = $9,
            completed_at = (CURRENT_TIMESTAMP)::text,
            detail_json = $10
        WHERE tenant_id = $1 AND id = $2
        RETURNING id, tenant_id, started_by, status, trigger_mode, batch_size,
                  max_runtime_seconds, cooldown_seconds, dry_run, checked_count,
                  valid_count, mismatch_count, missing_count, failed_count, skipped_count,
                  started_at, completed_at, detail_json::text AS detail_json_text
        "#,
    )
    .bind(tenant_id)
    .bind(run_id)
    .bind(payload.status)
    .bind(payload.checked_count)
    .bind(payload.valid_count)
    .bind(payload.mismatch_count)
    .bind(payload.missing_count)
    .bind(payload.failed_count)
    .bind(payload.skipped_count)
    .bind(sqlx::types::Json(payload.detail))
    .fetch_optional(pool)
    .await?;
    row.map(evidence_worker_run_from_pg_row)
        .transpose()
        .map_err(Into::into)
}

async fn finish_evidence_worker_run_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    run_id: i64,
    payload: EvidenceIntegrityWorkerRunFinish,
) -> anyhow::Result<Option<EvidenceIntegrityWorkerRun>> {
    let result = sqlx::query(
        r#"
        UPDATE evidence_integrity_worker_run
        SET status = ?3,
            checked_count = ?4,
            valid_count = ?5,
            mismatch_count = ?6,
            missing_count = ?7,
            failed_count = ?8,
            skipped_count = ?9,
            completed_at = datetime('now'),
            detail_json = ?10
        WHERE tenant_id = ?1 AND id = ?2
        "#,
    )
    .bind(tenant_id)
    .bind(run_id)
    .bind(payload.status)
    .bind(payload.checked_count)
    .bind(payload.valid_count)
    .bind(payload.mismatch_count)
    .bind(payload.missing_count)
    .bind(payload.failed_count)
    .bind(payload.skipped_count)
    .bind(payload.detail.to_string())
    .execute(pool)
    .await?;
    if result.rows_affected() == 0 {
        return Ok(None);
    }
    evidence_worker_run_by_id_sqlite(pool, tenant_id, run_id)
        .await
        .map(Some)
}

async fn evidence_worker_run_by_id_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    run_id: i64,
) -> anyhow::Result<EvidenceIntegrityWorkerRun> {
    let row = sqlx::query(
        r#"
        SELECT id, tenant_id, started_by, status, trigger_mode, batch_size,
               max_runtime_seconds, cooldown_seconds, dry_run, checked_count,
               valid_count, mismatch_count, missing_count, failed_count, skipped_count,
               CAST(started_at AS TEXT) AS started_at,
               CAST(completed_at AS TEXT) AS completed_at,
               detail_json AS detail_json_text
        FROM evidence_integrity_worker_run
        WHERE tenant_id = ?1 AND id = ?2
        "#,
    )
    .bind(tenant_id)
    .bind(run_id)
    .fetch_one(pool)
    .await?;
    evidence_worker_run_from_sqlite_row(row).map_err(Into::into)
}

async fn execute_disposition_postgres(
    pool: &PgPool,
    tenant_id: i64,
    evidence_id: i64,
    actor_id: i64,
    execution: EvidenceDispositionExecution,
) -> anyhow::Result<Option<EvidenceIntegrityItem>> {
    let current = evidence_integrity_item_by_id_postgres(pool, tenant_id, evidence_id).await?;
    let Some(current) = current else {
        return Ok(None);
    };
    validate_disposition_execution_state(&current)?;
    let final_status = if execution.deleted {
        "disposition_executed"
    } else {
        "disposition_failed"
    };
    let mut tx = pool.begin().await?;
    sqlx::query(
        r#"
        UPDATE evidence_evidenceitem
        SET file = CASE WHEN $4 THEN NULL ELSE file END,
            disposition_status = $5,
            disposition_executed_by = CASE WHEN $4 THEN $3 ELSE disposition_executed_by END,
            disposition_executed_at = CASE WHEN $4 THEN (CURRENT_TIMESTAMP)::text ELSE disposition_executed_at END,
            disposition_execution_error_class = $6,
            disposition_storage_backend = $7,
            disposition_tombstone_sha256 = $8,
            disposition_tombstone_json = $9,
            disposal_candidate = FALSE,
            updated_at = (CURRENT_TIMESTAMP)::text
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .bind(actor_id)
    .bind(execution.deleted)
    .bind(final_status)
    .bind(&execution.safe_error_class)
    .bind(&execution.storage_backend)
    .bind(&execution.tombstone_sha256)
    .bind(sqlx::types::Json(execution.tombstone.clone()))
    .execute(&mut *tx)
    .await?;
    insert_evidence_integrity_event_postgres_tx(
        &mut tx,
        tenant_id,
        evidence_id,
        EvidenceIntegrityEventWrite {
            event_type: if execution.deleted {
                "disposition_executed".to_string()
            } else {
                "disposition_execution_failed".to_string()
            },
            actor_id: Some(actor_id),
            integrity_status: String::new(),
            legal_hold_status: current.legal_hold_status,
            disposition_status: final_status.to_string(),
            mismatch: false,
            error_class: execution.safe_error_class,
            detail: execution.tombstone,
            note: String::new(),
        },
    )
    .await?;
    tx.commit().await?;
    evidence_integrity_item_by_id_postgres(pool, tenant_id, evidence_id).await
}

async fn execute_disposition_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    evidence_id: i64,
    actor_id: i64,
    execution: EvidenceDispositionExecution,
) -> anyhow::Result<Option<EvidenceIntegrityItem>> {
    let current = evidence_integrity_item_by_id_sqlite(pool, tenant_id, evidence_id).await?;
    let Some(current) = current else {
        return Ok(None);
    };
    validate_disposition_execution_state(&current)?;
    let final_status = if execution.deleted {
        "disposition_executed"
    } else {
        "disposition_failed"
    };
    let mut tx = pool.begin().await?;
    sqlx::query(
        r#"
        UPDATE evidence_evidenceitem
        SET file = CASE WHEN ?4 THEN NULL ELSE file END,
            disposition_status = ?5,
            disposition_executed_by = CASE WHEN ?4 THEN ?3 ELSE disposition_executed_by END,
            disposition_executed_at = CASE WHEN ?4 THEN datetime('now') ELSE disposition_executed_at END,
            disposition_execution_error_class = ?6,
            disposition_storage_backend = ?7,
            disposition_tombstone_sha256 = ?8,
            disposition_tombstone_json = ?9,
            disposal_candidate = 0,
            updated_at = datetime('now')
        WHERE tenant_id = ?1 AND id = ?2
        "#,
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .bind(actor_id)
    .bind(execution.deleted)
    .bind(final_status)
    .bind(&execution.safe_error_class)
    .bind(&execution.storage_backend)
    .bind(&execution.tombstone_sha256)
    .bind(execution.tombstone.to_string())
    .execute(&mut *tx)
    .await?;
    insert_evidence_integrity_event_sqlite_tx(
        &mut tx,
        tenant_id,
        evidence_id,
        EvidenceIntegrityEventWrite {
            event_type: if execution.deleted {
                "disposition_executed".to_string()
            } else {
                "disposition_execution_failed".to_string()
            },
            actor_id: Some(actor_id),
            integrity_status: String::new(),
            legal_hold_status: current.legal_hold_status,
            disposition_status: final_status.to_string(),
            mismatch: false,
            error_class: execution.safe_error_class,
            detail: execution.tombstone,
            note: String::new(),
        },
    )
    .await?;
    tx.commit().await?;
    evidence_integrity_item_by_id_sqlite(pool, tenant_id, evidence_id).await
}

fn validate_disposition_execution_state(item: &EvidenceIntegrityItem) -> anyhow::Result<()> {
    if item.legal_hold_status == "active" || item.legal_hold_blocks_disposition {
        bail!("Disposition ist durch Legal Hold blockiert.");
    }
    if item.disposition_status != "approved_for_disposition" {
        bail!("Disposition muss vor der Ausfuehrung freigegeben sein.");
    }
    if item.disposition_reason.trim().is_empty() {
        bail!("Disposition benoetigt eine dokumentierte Begruendung.");
    }
    Ok(())
}

fn evidence_worker_run_postgres_sql() -> &'static str {
    r#"
    SELECT id, tenant_id, started_by, status, trigger_mode, batch_size,
           max_runtime_seconds, cooldown_seconds, dry_run, checked_count,
           valid_count, mismatch_count, missing_count, failed_count, skipped_count,
           started_at, completed_at, detail_json::text AS detail_json_text
    FROM evidence_integrity_worker_run
    WHERE tenant_id = $1
    ORDER BY started_at DESC, id DESC
    LIMIT $2
    "#
}

fn evidence_worker_run_sqlite_sql() -> &'static str {
    r#"
    SELECT id, tenant_id, started_by, status, trigger_mode, batch_size,
           max_runtime_seconds, cooldown_seconds, dry_run, checked_count,
           valid_count, mismatch_count, missing_count, failed_count, skipped_count,
           CAST(started_at AS TEXT) AS started_at,
           CAST(completed_at AS TEXT) AS completed_at,
           detail_json AS detail_json_text
    FROM evidence_integrity_worker_run
    WHERE tenant_id = ?1
    ORDER BY started_at DESC, id DESC
    LIMIT ?2
    "#
}

fn evidence_worker_run_from_pg_row(row: PgRow) -> Result<EvidenceIntegrityWorkerRun, sqlx::Error> {
    evidence_worker_run_from_values(EvidenceWorkerRunValues {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        started_by: row.try_get("started_by")?,
        status: row.try_get("status")?,
        trigger_mode: row.try_get("trigger_mode")?,
        batch_size: row.try_get("batch_size")?,
        max_runtime_seconds: row.try_get("max_runtime_seconds")?,
        cooldown_seconds: row.try_get("cooldown_seconds")?,
        dry_run: row.try_get("dry_run")?,
        checked_count: row.try_get("checked_count")?,
        valid_count: row.try_get("valid_count")?,
        mismatch_count: row.try_get("mismatch_count")?,
        missing_count: row.try_get("missing_count")?,
        failed_count: row.try_get("failed_count")?,
        skipped_count: row.try_get("skipped_count")?,
        started_at: row.try_get("started_at")?,
        completed_at: row.try_get("completed_at")?,
        detail_json_text: row.try_get("detail_json_text")?,
    })
}

fn evidence_worker_run_from_sqlite_row(
    row: SqliteRow,
) -> Result<EvidenceIntegrityWorkerRun, sqlx::Error> {
    evidence_worker_run_from_values(EvidenceWorkerRunValues {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        started_by: row.try_get("started_by")?,
        status: row.try_get("status")?,
        trigger_mode: row.try_get("trigger_mode")?,
        batch_size: row.try_get("batch_size")?,
        max_runtime_seconds: row.try_get("max_runtime_seconds")?,
        cooldown_seconds: row.try_get("cooldown_seconds")?,
        dry_run: row.try_get("dry_run")?,
        checked_count: row.try_get("checked_count")?,
        valid_count: row.try_get("valid_count")?,
        mismatch_count: row.try_get("mismatch_count")?,
        missing_count: row.try_get("missing_count")?,
        failed_count: row.try_get("failed_count")?,
        skipped_count: row.try_get("skipped_count")?,
        started_at: row.try_get("started_at")?,
        completed_at: row.try_get("completed_at")?,
        detail_json_text: row.try_get("detail_json_text")?,
    })
}

struct EvidenceWorkerRunValues {
    id: i64,
    tenant_id: i64,
    started_by: Option<i64>,
    status: String,
    trigger_mode: String,
    batch_size: i64,
    max_runtime_seconds: i64,
    cooldown_seconds: i64,
    dry_run: bool,
    checked_count: i64,
    valid_count: i64,
    mismatch_count: i64,
    missing_count: i64,
    failed_count: i64,
    skipped_count: i64,
    started_at: String,
    completed_at: Option<String>,
    detail_json_text: String,
}

fn evidence_worker_run_from_values(
    values: EvidenceWorkerRunValues,
) -> Result<EvidenceIntegrityWorkerRun, sqlx::Error> {
    let detail = serde_json::from_str(&values.detail_json_text).unwrap_or_else(|_| json!({}));
    Ok(EvidenceIntegrityWorkerRun {
        id: values.id,
        tenant_id: values.tenant_id,
        started_by: values.started_by,
        status: values.status,
        trigger_mode: values.trigger_mode,
        batch_size: values.batch_size,
        max_runtime_seconds: values.max_runtime_seconds,
        cooldown_seconds: values.cooldown_seconds,
        dry_run: values.dry_run,
        checked_count: values.checked_count,
        valid_count: values.valid_count,
        mismatch_count: values.mismatch_count,
        missing_count: values.missing_count,
        failed_count: values.failed_count,
        skipped_count: values.skipped_count,
        started_at: values.started_at,
        completed_at: values.completed_at,
        detail,
    })
}

fn evidence_integrity_item_postgres_sql(where_clause: &str) -> String {
    format!(
        r#"
        SELECT
            item.id,
            item.tenant_id,
            item.title,
            item.status AS evidence_status,
            item.sensitivity,
            item.owner_id,
            COALESCE(NULLIF(BTRIM(CONCAT(COALESCE(owner.first_name, ''), ' ', COALESCE(owner.last_name, ''))), ''), owner.username) AS owner_display,
            item.file AS file_name,
            item.file_sha256 AS expected_sha256,
            item.last_calculated_sha256,
            item.last_integrity_checked_at,
            item.integrity_status,
            item.integrity_mismatch,
            item.quarantine_status,
            item.integrity_checked_by_id,
            COALESCE(NULLIF(BTRIM(CONCAT(COALESCE(checker.first_name, ''), ' ', COALESCE(checker.last_name, ''))), ''), checker.username) AS integrity_checked_by_display,
            item.integrity_result,
            item.integrity_error_class,
            item.integrity_review_note,
            item.valid_until,
            item.retention_until,
            item.retention_due_at,
            item.legal_hold_status,
            item.legal_hold_reason,
            item.legal_hold_set_by,
            COALESCE(NULLIF(BTRIM(CONCAT(COALESCE(hold_setter.first_name, ''), ' ', COALESCE(hold_setter.last_name, ''))), ''), hold_setter.username) AS legal_hold_set_by_display,
            item.legal_hold_set_at,
            item.legal_hold_released_by,
            COALESCE(NULLIF(BTRIM(CONCAT(COALESCE(hold_releaser.first_name, ''), ' ', COALESCE(hold_releaser.last_name, ''))), ''), hold_releaser.username) AS legal_hold_released_by_display,
            item.legal_hold_released_at,
            item.legal_hold_release_reason,
            item.disposition_status,
            item.disposition_due_at,
            item.disposition_decision,
            item.disposition_reason,
            item.disposition_decided_by,
            COALESCE(NULLIF(BTRIM(CONCAT(COALESCE(disposition_actor.first_name, ''), ' ', COALESCE(disposition_actor.last_name, ''))), ''), disposition_actor.username) AS disposition_decided_by_display,
            item.disposition_decided_at,
            item.disposition_blocked_reason,
            item.disposal_candidate,
            item.legal_hold_blocks_disposition,
            item.created_at::text AS created_at,
            item.updated_at::text AS updated_at
        FROM evidence_evidenceitem item
        LEFT JOIN accounts_user owner
            ON owner.id = item.owner_id AND owner.tenant_id = item.tenant_id
        LEFT JOIN accounts_user checker
            ON checker.id = item.integrity_checked_by_id AND checker.tenant_id = item.tenant_id
        LEFT JOIN accounts_user hold_setter
            ON hold_setter.id = item.legal_hold_set_by AND hold_setter.tenant_id = item.tenant_id
        LEFT JOIN accounts_user hold_releaser
            ON hold_releaser.id = item.legal_hold_released_by AND hold_releaser.tenant_id = item.tenant_id
        LEFT JOIN accounts_user disposition_actor
            ON disposition_actor.id = item.disposition_decided_by AND disposition_actor.tenant_id = item.tenant_id
        {where_clause}
        "#
    )
}

fn evidence_integrity_item_sqlite_sql(where_clause: &str) -> String {
    format!(
        r#"
        SELECT
            item.id,
            item.tenant_id,
            item.title,
            item.status AS evidence_status,
            item.sensitivity,
            item.owner_id,
            COALESCE(NULLIF(TRIM(COALESCE(owner.first_name, '') || ' ' || COALESCE(owner.last_name, '')), ''), owner.username) AS owner_display,
            item.file AS file_name,
            item.file_sha256 AS expected_sha256,
            item.last_calculated_sha256,
            CAST(item.last_integrity_checked_at AS TEXT) AS last_integrity_checked_at,
            item.integrity_status,
            item.integrity_mismatch,
            item.quarantine_status,
            item.integrity_checked_by_id,
            COALESCE(NULLIF(TRIM(COALESCE(checker.first_name, '') || ' ' || COALESCE(checker.last_name, '')), ''), checker.username) AS integrity_checked_by_display,
            item.integrity_result,
            item.integrity_error_class,
            item.integrity_review_note,
            item.valid_until,
            item.retention_until,
            item.retention_due_at,
            item.legal_hold_status,
            item.legal_hold_reason,
            item.legal_hold_set_by,
            COALESCE(NULLIF(TRIM(COALESCE(hold_setter.first_name, '') || ' ' || COALESCE(hold_setter.last_name, '')), ''), hold_setter.username) AS legal_hold_set_by_display,
            CAST(item.legal_hold_set_at AS TEXT) AS legal_hold_set_at,
            item.legal_hold_released_by,
            COALESCE(NULLIF(TRIM(COALESCE(hold_releaser.first_name, '') || ' ' || COALESCE(hold_releaser.last_name, '')), ''), hold_releaser.username) AS legal_hold_released_by_display,
            CAST(item.legal_hold_released_at AS TEXT) AS legal_hold_released_at,
            item.legal_hold_release_reason,
            item.disposition_status,
            item.disposition_due_at,
            item.disposition_decision,
            item.disposition_reason,
            item.disposition_decided_by,
            COALESCE(NULLIF(TRIM(COALESCE(disposition_actor.first_name, '') || ' ' || COALESCE(disposition_actor.last_name, '')), ''), disposition_actor.username) AS disposition_decided_by_display,
            CAST(item.disposition_decided_at AS TEXT) AS disposition_decided_at,
            item.disposition_blocked_reason,
            item.disposal_candidate,
            item.legal_hold_blocks_disposition,
            CAST(item.created_at AS TEXT) AS created_at,
            CAST(item.updated_at AS TEXT) AS updated_at
        FROM evidence_evidenceitem item
        LEFT JOIN accounts_user owner
            ON owner.id = item.owner_id AND owner.tenant_id = item.tenant_id
        LEFT JOIN accounts_user checker
            ON checker.id = item.integrity_checked_by_id AND checker.tenant_id = item.tenant_id
        LEFT JOIN accounts_user hold_setter
            ON hold_setter.id = item.legal_hold_set_by AND hold_setter.tenant_id = item.tenant_id
        LEFT JOIN accounts_user hold_releaser
            ON hold_releaser.id = item.legal_hold_released_by AND hold_releaser.tenant_id = item.tenant_id
        LEFT JOIN accounts_user disposition_actor
            ON disposition_actor.id = item.disposition_decided_by AND disposition_actor.tenant_id = item.tenant_id
        {where_clause}
        "#
    )
}

fn evidence_integrity_event_postgres_sql() -> &'static str {
    r#"
    SELECT event.id, event.tenant_id, event.evidence_id, event.event_type,
           event.actor_id,
           COALESCE(NULLIF(BTRIM(CONCAT(COALESCE(actor.first_name, ''), ' ', COALESCE(actor.last_name, ''))), ''), actor.username) AS actor_display,
           event.integrity_status, event.legal_hold_status, event.disposition_status,
           event.mismatch, event.error_class, event.detail_json::text AS detail_json_text,
           event.note, event.created_at::text AS created_at
    FROM evidence_integrity_event event
    LEFT JOIN accounts_user actor
        ON actor.id = event.actor_id AND actor.tenant_id = event.tenant_id
    WHERE event.tenant_id = $1 AND event.evidence_id = $2
    ORDER BY event.created_at DESC, event.id DESC
    LIMIT $3
    "#
}

fn evidence_integrity_event_sqlite_sql() -> &'static str {
    r#"
    SELECT event.id, event.tenant_id, event.evidence_id, event.event_type,
           event.actor_id,
           COALESCE(NULLIF(TRIM(COALESCE(actor.first_name, '') || ' ' || COALESCE(actor.last_name, '')), ''), actor.username) AS actor_display,
           event.integrity_status, event.legal_hold_status, event.disposition_status,
           event.mismatch, event.error_class, CAST(event.detail_json AS TEXT) AS detail_json_text,
           event.note, CAST(event.created_at AS TEXT) AS created_at
    FROM evidence_integrity_event event
    LEFT JOIN accounts_user actor
        ON actor.id = event.actor_id AND actor.tenant_id = event.tenant_id
    WHERE event.tenant_id = ?1 AND event.evidence_id = ?2
    ORDER BY event.created_at DESC, event.id DESC
    LIMIT ?3
    "#
}

fn evidence_storage_backend_config_postgres_select(where_clause: &str) -> String {
    format!(
        r#"
        SELECT id, tenant_id, backend_id, backend_type, display_name, status,
               endpoint_reference, region, bucket_name, key_prefix,
               access_key_secret_ref, secret_key_secret_ref, session_token_secret_ref,
               tls_required, allow_path_style, allowed_endpoint_policy,
               last_validation_at, last_validation_status, last_validation_error_class,
               created_at, updated_at, known_limitations
        FROM evidence_storage_backend_config
        {where_clause}
        "#
    )
}

fn evidence_storage_backend_config_sqlite_select(where_clause: &str) -> String {
    evidence_storage_backend_config_postgres_select(where_clause)
}

fn evidence_storage_backend_config_postgres_upsert_sql() -> &'static str {
    r#"
    INSERT INTO evidence_storage_backend_config (
        tenant_id, backend_id, backend_type, display_name, status,
        endpoint_reference, region, bucket_name, key_prefix,
        access_key_secret_ref, secret_key_secret_ref, session_token_secret_ref,
        tls_required, allow_path_style, allowed_endpoint_policy,
        created_by, created_at, updated_at, known_limitations
    )
    VALUES (
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
        (CURRENT_TIMESTAMP)::text,(CURRENT_TIMESTAMP)::text,$17
    )
    ON CONFLICT (tenant_id, backend_id) DO UPDATE SET
        backend_type = excluded.backend_type,
        display_name = excluded.display_name,
        status = excluded.status,
        endpoint_reference = excluded.endpoint_reference,
        region = excluded.region,
        bucket_name = excluded.bucket_name,
        key_prefix = excluded.key_prefix,
        access_key_secret_ref = excluded.access_key_secret_ref,
        secret_key_secret_ref = excluded.secret_key_secret_ref,
        session_token_secret_ref = excluded.session_token_secret_ref,
        tls_required = excluded.tls_required,
        allow_path_style = excluded.allow_path_style,
        allowed_endpoint_policy = excluded.allowed_endpoint_policy,
        updated_at = (CURRENT_TIMESTAMP)::text,
        known_limitations = excluded.known_limitations
    RETURNING id, tenant_id, backend_id, backend_type, display_name, status,
              endpoint_reference, region, bucket_name, key_prefix,
              access_key_secret_ref, secret_key_secret_ref, session_token_secret_ref,
              tls_required, allow_path_style, allowed_endpoint_policy,
              last_validation_at, last_validation_status, last_validation_error_class,
              created_at, updated_at, known_limitations
    "#
}

fn evidence_storage_backend_config_sqlite_upsert_sql() -> &'static str {
    r#"
    INSERT INTO evidence_storage_backend_config (
        tenant_id, backend_id, backend_type, display_name, status,
        endpoint_reference, region, bucket_name, key_prefix,
        access_key_secret_ref, secret_key_secret_ref, session_token_secret_ref,
        tls_required, allow_path_style, allowed_endpoint_policy,
        created_by, created_at, updated_at, known_limitations
    )
    VALUES (
        ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,
        datetime('now'),datetime('now'),?17
    )
    ON CONFLICT (tenant_id, backend_id) DO UPDATE SET
        backend_type = excluded.backend_type,
        display_name = excluded.display_name,
        status = excluded.status,
        endpoint_reference = excluded.endpoint_reference,
        region = excluded.region,
        bucket_name = excluded.bucket_name,
        key_prefix = excluded.key_prefix,
        access_key_secret_ref = excluded.access_key_secret_ref,
        secret_key_secret_ref = excluded.secret_key_secret_ref,
        session_token_secret_ref = excluded.session_token_secret_ref,
        tls_required = excluded.tls_required,
        allow_path_style = excluded.allow_path_style,
        allowed_endpoint_policy = excluded.allowed_endpoint_policy,
        updated_at = datetime('now'),
        known_limitations = excluded.known_limitations
    RETURNING id, tenant_id, backend_id, backend_type, display_name, status,
              endpoint_reference, region, bucket_name, key_prefix,
              access_key_secret_ref, secret_key_secret_ref, session_token_secret_ref,
              tls_required, allow_path_style, allowed_endpoint_policy,
              last_validation_at, last_validation_status, last_validation_error_class,
              created_at, updated_at, known_limitations
    "#
}

fn evidence_storage_secret_reference_status_postgres_select(where_clause: &str) -> String {
    format!(
        r#"
        SELECT id, tenant_id, backend_id, secret_reference, secret_ref_type,
               presence_status, last_checked_at, last_check_error_class, redacted_display_name
        FROM evidence_storage_secret_reference_status
        {where_clause}
        "#
    )
}

fn evidence_storage_secret_reference_status_sqlite_select(where_clause: &str) -> String {
    evidence_storage_secret_reference_status_postgres_select(where_clause)
}

fn evidence_storage_secret_reference_status_postgres_upsert_sql() -> &'static str {
    r#"
    INSERT INTO evidence_storage_secret_reference_status (
        tenant_id, backend_id, secret_reference, secret_ref_type, presence_status,
        last_checked_at, last_check_error_class, redacted_display_name
    )
    VALUES ($1,$2,$3,$4,$5,(CURRENT_TIMESTAMP)::text,'',$6)
    ON CONFLICT (tenant_id, backend_id, secret_ref_type) DO UPDATE SET
        secret_reference = excluded.secret_reference,
        presence_status = excluded.presence_status,
        last_checked_at = (CURRENT_TIMESTAMP)::text,
        last_check_error_class = '',
        redacted_display_name = excluded.redacted_display_name
    "#
}

fn evidence_storage_secret_reference_status_sqlite_upsert_sql() -> &'static str {
    r#"
    INSERT INTO evidence_storage_secret_reference_status (
        tenant_id, backend_id, secret_reference, secret_ref_type, presence_status,
        last_checked_at, last_check_error_class, redacted_display_name
    )
    VALUES (?1,?2,?3,?4,?5,datetime('now'),'',?6)
    ON CONFLICT (tenant_id, backend_id, secret_ref_type) DO UPDATE SET
        secret_reference = excluded.secret_reference,
        presence_status = excluded.presence_status,
        last_checked_at = datetime('now'),
        last_check_error_class = '',
        redacted_display_name = excluded.redacted_display_name
    "#
}

fn evidence_object_reference_postgres_select(where_clause: &str) -> String {
    format!(
        r#"
        SELECT id, tenant_id, evidence_id, backend_id, backend_type,
               object_key_redacted, object_key_sha256, object_reference_status,
               expected_sha256, contract_status, contract_sha256, contract_size_bytes,
               last_drill_at, last_drill_status, last_drill_error_class,
               created_at, updated_at
        FROM evidence_object_reference
        {where_clause}
        "#
    )
}

fn evidence_object_reference_sqlite_select(where_clause: &str) -> String {
    evidence_object_reference_postgres_select(where_clause)
}

fn evidence_object_reference_postgres_upsert_sql() -> &'static str {
    r#"
    INSERT INTO evidence_object_reference (
        tenant_id, evidence_id, backend_id, backend_type,
        object_key_redacted, object_key_sha256, object_reference_status,
        expected_sha256, contract_status, contract_sha256, contract_size_bytes,
        created_by, created_at, updated_at
    )
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,(CURRENT_TIMESTAMP)::text,(CURRENT_TIMESTAMP)::text)
    ON CONFLICT (tenant_id, evidence_id, backend_id) DO UPDATE SET
        backend_type = excluded.backend_type,
        object_key_redacted = excluded.object_key_redacted,
        object_key_sha256 = excluded.object_key_sha256,
        object_reference_status = excluded.object_reference_status,
        expected_sha256 = excluded.expected_sha256,
        contract_status = excluded.contract_status,
        contract_sha256 = excluded.contract_sha256,
        contract_size_bytes = excluded.contract_size_bytes,
        updated_at = (CURRENT_TIMESTAMP)::text
    RETURNING id, tenant_id, evidence_id, backend_id, backend_type,
              object_key_redacted, object_key_sha256, object_reference_status,
              expected_sha256, contract_status, contract_sha256, contract_size_bytes,
              last_drill_at, last_drill_status, last_drill_error_class,
              created_at, updated_at
    "#
}

fn evidence_object_reference_sqlite_upsert_sql() -> &'static str {
    r#"
    INSERT INTO evidence_object_reference (
        tenant_id, evidence_id, backend_id, backend_type,
        object_key_redacted, object_key_sha256, object_reference_status,
        expected_sha256, contract_status, contract_sha256, contract_size_bytes,
        created_by, created_at, updated_at
    )
    VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,datetime('now'),datetime('now'))
    ON CONFLICT (tenant_id, evidence_id, backend_id) DO UPDATE SET
        backend_type = excluded.backend_type,
        object_key_redacted = excluded.object_key_redacted,
        object_key_sha256 = excluded.object_key_sha256,
        object_reference_status = excluded.object_reference_status,
        expected_sha256 = excluded.expected_sha256,
        contract_status = excluded.contract_status,
        contract_sha256 = excluded.contract_sha256,
        contract_size_bytes = excluded.contract_size_bytes,
        updated_at = datetime('now')
    RETURNING id, tenant_id, evidence_id, backend_id, backend_type,
              object_key_redacted, object_key_sha256, object_reference_status,
              expected_sha256, contract_status, contract_sha256, contract_size_bytes,
              last_drill_at, last_drill_status, last_drill_error_class,
              created_at, updated_at
    "#
}

fn evidence_storage_backend_event_postgres_select(where_clause: &str) -> String {
    format!(
        r#"
        SELECT id, tenant_id, backend_id, evidence_id, event_type, actor_id,
               status, error_class, summary, detail_json::text AS detail_json_text,
               created_at
        FROM evidence_storage_backend_event
        {where_clause}
        "#
    )
}

fn evidence_storage_backend_event_sqlite_select(where_clause: &str) -> String {
    format!(
        r#"
        SELECT id, tenant_id, backend_id, evidence_id, event_type, actor_id,
               status, error_class, summary, CAST(detail_json AS TEXT) AS detail_json_text,
               created_at
        FROM evidence_storage_backend_event
        {where_clause}
        "#
    )
}

fn evidence_storage_backend_config_from_pg_row(
    row: PgRow,
) -> Result<EvidenceStorageBackendConfig, sqlx::Error> {
    Ok(EvidenceStorageBackendConfig {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        backend_id: row.try_get("backend_id")?,
        backend_type: row.try_get("backend_type")?,
        display_name: row.try_get("display_name")?,
        status: row.try_get("status")?,
        endpoint_reference: row.try_get("endpoint_reference")?,
        region: row.try_get("region")?,
        bucket_name: row.try_get("bucket_name")?,
        key_prefix: row.try_get("key_prefix")?,
        access_key_secret_ref: row.try_get("access_key_secret_ref")?,
        secret_key_secret_ref: row.try_get("secret_key_secret_ref")?,
        session_token_secret_ref: row.try_get("session_token_secret_ref")?,
        tls_required: row.try_get("tls_required")?,
        allow_path_style: row.try_get("allow_path_style")?,
        allowed_endpoint_policy: row.try_get("allowed_endpoint_policy")?,
        last_validation_at: row.try_get("last_validation_at")?,
        last_validation_status: row.try_get("last_validation_status")?,
        last_validation_error_class: row.try_get("last_validation_error_class")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        known_limitations: row.try_get("known_limitations")?,
    })
}

fn evidence_storage_backend_config_from_sqlite_row(
    row: SqliteRow,
) -> Result<EvidenceStorageBackendConfig, sqlx::Error> {
    Ok(EvidenceStorageBackendConfig {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        backend_id: row.try_get("backend_id")?,
        backend_type: row.try_get("backend_type")?,
        display_name: row.try_get("display_name")?,
        status: row.try_get("status")?,
        endpoint_reference: row.try_get("endpoint_reference")?,
        region: row.try_get("region")?,
        bucket_name: row.try_get("bucket_name")?,
        key_prefix: row.try_get("key_prefix")?,
        access_key_secret_ref: row.try_get("access_key_secret_ref")?,
        secret_key_secret_ref: row.try_get("secret_key_secret_ref")?,
        session_token_secret_ref: row.try_get("session_token_secret_ref")?,
        tls_required: row.try_get("tls_required")?,
        allow_path_style: row.try_get("allow_path_style")?,
        allowed_endpoint_policy: row.try_get("allowed_endpoint_policy")?,
        last_validation_at: row.try_get("last_validation_at")?,
        last_validation_status: row.try_get("last_validation_status")?,
        last_validation_error_class: row.try_get("last_validation_error_class")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        known_limitations: row.try_get("known_limitations")?,
    })
}

fn evidence_storage_secret_reference_status_from_pg_row(
    row: PgRow,
) -> Result<EvidenceStorageSecretReferenceStatus, sqlx::Error> {
    Ok(EvidenceStorageSecretReferenceStatus {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        backend_id: row.try_get("backend_id")?,
        secret_reference: row.try_get("secret_reference")?,
        secret_ref_type: row.try_get("secret_ref_type")?,
        presence_status: row.try_get("presence_status")?,
        last_checked_at: row.try_get("last_checked_at")?,
        last_check_error_class: row.try_get("last_check_error_class")?,
        redacted_display_name: row.try_get("redacted_display_name")?,
    })
}

fn evidence_storage_secret_reference_status_from_sqlite_row(
    row: SqliteRow,
) -> Result<EvidenceStorageSecretReferenceStatus, sqlx::Error> {
    Ok(EvidenceStorageSecretReferenceStatus {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        backend_id: row.try_get("backend_id")?,
        secret_reference: row.try_get("secret_reference")?,
        secret_ref_type: row.try_get("secret_ref_type")?,
        presence_status: row.try_get("presence_status")?,
        last_checked_at: row.try_get("last_checked_at")?,
        last_check_error_class: row.try_get("last_check_error_class")?,
        redacted_display_name: row.try_get("redacted_display_name")?,
    })
}

fn evidence_object_reference_from_pg_row(
    row: PgRow,
) -> Result<EvidenceObjectReference, sqlx::Error> {
    Ok(EvidenceObjectReference {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        evidence_id: row.try_get("evidence_id")?,
        backend_id: row.try_get("backend_id")?,
        backend_type: row.try_get("backend_type")?,
        object_key_redacted: row.try_get("object_key_redacted")?,
        object_key_sha256: row.try_get("object_key_sha256")?,
        object_reference_status: row.try_get("object_reference_status")?,
        expected_sha256: row.try_get("expected_sha256")?,
        contract_status: row.try_get("contract_status")?,
        contract_sha256: row.try_get("contract_sha256")?,
        contract_size_bytes: row.try_get("contract_size_bytes")?,
        last_drill_at: row.try_get("last_drill_at")?,
        last_drill_status: row.try_get("last_drill_status")?,
        last_drill_error_class: row.try_get("last_drill_error_class")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn evidence_object_reference_from_sqlite_row(
    row: SqliteRow,
) -> Result<EvidenceObjectReference, sqlx::Error> {
    Ok(EvidenceObjectReference {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        evidence_id: row.try_get("evidence_id")?,
        backend_id: row.try_get("backend_id")?,
        backend_type: row.try_get("backend_type")?,
        object_key_redacted: row.try_get("object_key_redacted")?,
        object_key_sha256: row.try_get("object_key_sha256")?,
        object_reference_status: row.try_get("object_reference_status")?,
        expected_sha256: row.try_get("expected_sha256")?,
        contract_status: row.try_get("contract_status")?,
        contract_sha256: row.try_get("contract_sha256")?,
        contract_size_bytes: row.try_get("contract_size_bytes")?,
        last_drill_at: row.try_get("last_drill_at")?,
        last_drill_status: row.try_get("last_drill_status")?,
        last_drill_error_class: row.try_get("last_drill_error_class")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn evidence_storage_backend_event_from_pg_row(
    row: PgRow,
) -> Result<EvidenceStorageBackendEvent, sqlx::Error> {
    let detail_text: String = row.try_get("detail_json_text")?;
    Ok(EvidenceStorageBackendEvent {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        backend_id: row.try_get("backend_id")?,
        evidence_id: row.try_get("evidence_id")?,
        event_type: row.try_get("event_type")?,
        actor_id: row.try_get("actor_id")?,
        status: row.try_get("status")?,
        error_class: row.try_get("error_class")?,
        summary: row.try_get("summary")?,
        detail: parse_json_value(&detail_text),
        created_at: row.try_get("created_at")?,
    })
}

fn evidence_storage_backend_event_from_sqlite_row(
    row: SqliteRow,
) -> Result<EvidenceStorageBackendEvent, sqlx::Error> {
    let detail_text: String = row.try_get("detail_json_text")?;
    Ok(EvidenceStorageBackendEvent {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        backend_id: row.try_get("backend_id")?,
        evidence_id: row.try_get("evidence_id")?,
        event_type: row.try_get("event_type")?,
        actor_id: row.try_get("actor_id")?,
        status: row.try_get("status")?,
        error_class: row.try_get("error_class")?,
        summary: row.try_get("summary")?,
        detail: parse_json_value(&detail_text),
        created_at: row.try_get("created_at")?,
    })
}

fn evidence_integrity_item_from_pg_row(row: PgRow) -> Result<EvidenceIntegrityItem, sqlx::Error> {
    let evidence_status: String = row.try_get("evidence_status")?;
    let integrity_status: String = row.try_get("integrity_status")?;
    let legal_hold_status: String = row.try_get("legal_hold_status")?;
    let disposition_status: String = row.try_get("disposition_status")?;
    let file_name: Option<String> = row.try_get("file_name")?;
    let expected_sha256: String = row.try_get("expected_sha256")?;
    Ok(EvidenceIntegrityItem {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        title: row.try_get("title")?,
        evidence_status: evidence_status.clone(),
        quality_status_label: evidence_status_label(&evidence_status).to_string(),
        sensitivity: row.try_get("sensitivity")?,
        owner_id: row.try_get("owner_id")?,
        owner_display: row.try_get("owner_display")?,
        artifact_reference_present: file_name
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty()),
        expected_sha256_present: !expected_sha256.trim().is_empty(),
        file_name,
        expected_sha256,
        last_calculated_sha256: row.try_get("last_calculated_sha256")?,
        last_integrity_checked_at: row.try_get("last_integrity_checked_at")?,
        integrity_status_label: integrity_status_label(&integrity_status).to_string(),
        integrity_status,
        integrity_mismatch: row.try_get("integrity_mismatch")?,
        quarantine_status: row.try_get("quarantine_status")?,
        integrity_checked_by_id: row.try_get("integrity_checked_by_id")?,
        integrity_checked_by_display: row.try_get("integrity_checked_by_display")?,
        integrity_result: row.try_get("integrity_result")?,
        integrity_error_class: row.try_get("integrity_error_class")?,
        integrity_review_note: row.try_get("integrity_review_note")?,
        valid_until: row.try_get("valid_until")?,
        retention_until: row.try_get("retention_until")?,
        retention_due_at: row.try_get("retention_due_at")?,
        legal_hold_status_label: legal_hold_status_label(&legal_hold_status).to_string(),
        legal_hold_status,
        legal_hold_reason: row.try_get("legal_hold_reason")?,
        legal_hold_set_by: row.try_get("legal_hold_set_by")?,
        legal_hold_set_by_display: row.try_get("legal_hold_set_by_display")?,
        legal_hold_set_at: row.try_get("legal_hold_set_at")?,
        legal_hold_released_by: row.try_get("legal_hold_released_by")?,
        legal_hold_released_by_display: row.try_get("legal_hold_released_by_display")?,
        legal_hold_released_at: row.try_get("legal_hold_released_at")?,
        legal_hold_release_reason: row.try_get("legal_hold_release_reason")?,
        disposition_status_label: disposition_status_label(&disposition_status).to_string(),
        disposition_status,
        disposition_due_at: row.try_get("disposition_due_at")?,
        disposition_decision: row.try_get("disposition_decision")?,
        disposition_reason: row.try_get("disposition_reason")?,
        disposition_decided_by: row.try_get("disposition_decided_by")?,
        disposition_decided_by_display: row.try_get("disposition_decided_by_display")?,
        disposition_decided_at: row.try_get("disposition_decided_at")?,
        disposition_blocked_reason: row.try_get("disposition_blocked_reason")?,
        disposal_candidate: row.try_get("disposal_candidate")?,
        legal_hold_blocks_disposition: row.try_get("legal_hold_blocks_disposition")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn evidence_integrity_item_from_sqlite_row(
    row: SqliteRow,
) -> Result<EvidenceIntegrityItem, sqlx::Error> {
    let evidence_status: String = row.try_get("evidence_status")?;
    let integrity_status: String = row.try_get("integrity_status")?;
    let legal_hold_status: String = row.try_get("legal_hold_status")?;
    let disposition_status: String = row.try_get("disposition_status")?;
    let file_name: Option<String> = row.try_get("file_name")?;
    let expected_sha256: String = row.try_get("expected_sha256")?;
    Ok(EvidenceIntegrityItem {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        title: row.try_get("title")?,
        evidence_status: evidence_status.clone(),
        quality_status_label: evidence_status_label(&evidence_status).to_string(),
        sensitivity: row.try_get("sensitivity")?,
        owner_id: row.try_get("owner_id")?,
        owner_display: row.try_get("owner_display")?,
        artifact_reference_present: file_name
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty()),
        expected_sha256_present: !expected_sha256.trim().is_empty(),
        file_name,
        expected_sha256,
        last_calculated_sha256: row.try_get("last_calculated_sha256")?,
        last_integrity_checked_at: row.try_get("last_integrity_checked_at")?,
        integrity_status_label: integrity_status_label(&integrity_status).to_string(),
        integrity_status,
        integrity_mismatch: row.try_get("integrity_mismatch")?,
        quarantine_status: row.try_get("quarantine_status")?,
        integrity_checked_by_id: row.try_get("integrity_checked_by_id")?,
        integrity_checked_by_display: row.try_get("integrity_checked_by_display")?,
        integrity_result: row.try_get("integrity_result")?,
        integrity_error_class: row.try_get("integrity_error_class")?,
        integrity_review_note: row.try_get("integrity_review_note")?,
        valid_until: row.try_get("valid_until")?,
        retention_until: row.try_get("retention_until")?,
        retention_due_at: row.try_get("retention_due_at")?,
        legal_hold_status_label: legal_hold_status_label(&legal_hold_status).to_string(),
        legal_hold_status,
        legal_hold_reason: row.try_get("legal_hold_reason")?,
        legal_hold_set_by: row.try_get("legal_hold_set_by")?,
        legal_hold_set_by_display: row.try_get("legal_hold_set_by_display")?,
        legal_hold_set_at: row.try_get("legal_hold_set_at")?,
        legal_hold_released_by: row.try_get("legal_hold_released_by")?,
        legal_hold_released_by_display: row.try_get("legal_hold_released_by_display")?,
        legal_hold_released_at: row.try_get("legal_hold_released_at")?,
        legal_hold_release_reason: row.try_get("legal_hold_release_reason")?,
        disposition_status_label: disposition_status_label(&disposition_status).to_string(),
        disposition_status,
        disposition_due_at: row.try_get("disposition_due_at")?,
        disposition_decision: row.try_get("disposition_decision")?,
        disposition_reason: row.try_get("disposition_reason")?,
        disposition_decided_by: row.try_get("disposition_decided_by")?,
        disposition_decided_by_display: row.try_get("disposition_decided_by_display")?,
        disposition_decided_at: row.try_get("disposition_decided_at")?,
        disposition_blocked_reason: row.try_get("disposition_blocked_reason")?,
        disposal_candidate: row.try_get("disposal_candidate")?,
        legal_hold_blocks_disposition: row.try_get("legal_hold_blocks_disposition")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn evidence_integrity_event_from_pg_row(row: PgRow) -> Result<EvidenceIntegrityEvent, sqlx::Error> {
    let detail_text: String = row.try_get("detail_json_text")?;
    Ok(EvidenceIntegrityEvent {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        evidence_id: row.try_get("evidence_id")?,
        event_type: row.try_get("event_type")?,
        actor_id: row.try_get("actor_id")?,
        actor_display: row.try_get("actor_display")?,
        integrity_status: row.try_get("integrity_status")?,
        legal_hold_status: row.try_get("legal_hold_status")?,
        disposition_status: row.try_get("disposition_status")?,
        mismatch: row.try_get("mismatch")?,
        error_class: row.try_get("error_class")?,
        detail: parse_json_value(&detail_text),
        note: row.try_get("note")?,
        created_at: row.try_get("created_at")?,
    })
}

fn evidence_integrity_event_from_sqlite_row(
    row: SqliteRow,
) -> Result<EvidenceIntegrityEvent, sqlx::Error> {
    let detail_text: String = row.try_get("detail_json_text")?;
    Ok(EvidenceIntegrityEvent {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        evidence_id: row.try_get("evidence_id")?,
        event_type: row.try_get("event_type")?,
        actor_id: row.try_get("actor_id")?,
        actor_display: row.try_get("actor_display")?,
        integrity_status: row.try_get("integrity_status")?,
        legal_hold_status: row.try_get("legal_hold_status")?,
        disposition_status: row.try_get("disposition_status")?,
        mismatch: row.try_get("mismatch")?,
        error_class: row.try_get("error_class")?,
        detail: parse_json_value(&detail_text),
        note: row.try_get("note")?,
        created_at: row.try_get("created_at")?,
    })
}

fn parse_json_value(value: &str) -> Value {
    serde_json::from_str(value).unwrap_or_else(|_| json!({}))
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

fn evidence_quality_from_overview(overview: EvidenceOverview) -> EvidenceQualityOverview {
    let total_items = overview.evidence_items.len() as i64;
    let approved_items = overview
        .evidence_items
        .iter()
        .filter(|item| item.status.eq_ignore_ascii_case("APPROVED"))
        .count() as i64;
    let reviewed_items = overview
        .evidence_items
        .iter()
        .filter(|item| item.reviewed_at.is_some())
        .count() as i64;
    let items_with_file = overview
        .evidence_items
        .iter()
        .filter(|item| {
            item.file_name
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
        })
        .count() as i64;
    let linked_items = overview
        .evidence_items
        .iter()
        .filter(|item| evidence_item_has_traceable_link(item))
        .count() as i64;
    let owner_assigned_items = overview
        .evidence_items
        .iter()
        .filter(|item| item.owner_id.is_some())
        .count() as i64;
    let today = Utc::now().date_naive();
    let items_with_hash = overview
        .evidence_items
        .iter()
        .filter(|item| !item.file_sha256.is_empty())
        .count() as i64;
    let expired_items = overview
        .evidence_items
        .iter()
        .filter(|item| evidence_date(item.valid_until.as_deref()).is_some_and(|date| date < today))
        .count() as i64;
    let expiring_items = overview
        .evidence_items
        .iter()
        .filter(|item| {
            evidence_date(item.valid_until.as_deref())
                .is_some_and(|date| date >= today && date <= today + Duration::days(30))
        })
        .count() as i64;
    let retention_defined_items = overview
        .evidence_items
        .iter()
        .filter(|item| item.retention_until.is_some())
        .count() as i64;
    let retention_due_items = overview
        .evidence_items
        .iter()
        .filter(|item| {
            evidence_date(item.retention_until.as_deref()).is_some_and(|date| date < today)
        })
        .count() as i64;
    let items = overview
        .evidence_items
        .iter()
        .map(evidence_quality_item)
        .collect::<Vec<_>>();
    let needs = overview
        .evidence_needs
        .iter()
        .map(evidence_quality_need)
        .collect::<Vec<_>>();
    let average_score = if items.is_empty() {
        0
    } else {
        items.iter().map(|item| item.quality_score).sum::<i64>() / items.len() as i64
    };
    EvidenceQualityOverview {
        summary: EvidenceQualitySummary {
            total_items,
            approved_items,
            reviewed_items,
            items_with_file,
            linked_items,
            owner_assigned_items,
            items_with_hash,
            expired_items,
            expiring_items,
            retention_defined_items,
            retention_due_items,
            open_needs: overview.need_summary.open,
            partial_needs: overview.need_summary.partial,
            covered_needs: overview.need_summary.covered,
            average_score,
            maturity_label: evidence_quality_level(average_score).to_string(),
        },
        items,
        needs,
    }
}

fn evidence_quality_item(item: &EvidenceItemSummary) -> EvidenceQualityItem {
    let mut score = 0;
    let mut issues = Vec::new();
    if item.status.eq_ignore_ascii_case("APPROVED") {
        score += 35;
    } else if item.status.eq_ignore_ascii_case("SUBMITTED") {
        score += 20;
        issues.push("Evidence ist eingereicht, aber noch nicht freigegeben.".to_string());
    } else {
        score += 5;
        issues.push("Evidence ist noch nicht im Review-/Freigabezustand.".to_string());
    }
    if item.reviewed_at.is_some() {
        score += 20;
    } else {
        issues.push("Fachlicher Review-Zeitpunkt fehlt.".to_string());
    }
    if item
        .file_name
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
    {
        score += 15;
    } else {
        issues.push("Datei oder Artefaktreferenz fehlt.".to_string());
    }
    if evidence_item_has_traceable_link(item) {
        score += 15;
    } else {
        issues.push(
            "Traceability zu Requirement, Control, Incident oder Evidence-Key fehlt.".to_string(),
        );
    }
    if item.owner_id.is_some() {
        score += 10;
    } else {
        issues.push("Owner fehlt.".to_string());
    }
    if !item.review_notes.trim().is_empty() {
        score += 5;
    } else {
        issues.push("Review-Notiz fehlt.".to_string());
    }
    let today = Utc::now().date_naive();
    if item.file_name.is_some() && item.file_sha256.is_empty() {
        score -= 10;
        issues.push("SHA-256-Integritaetsnachweis fuer die Datei fehlt.".to_string());
    }
    match evidence_date(item.valid_until.as_deref()) {
        Some(date) if date < today => {
            score -= 20;
            issues
                .push("Evidence ist abgelaufen und muss erneuert oder ersetzt werden.".to_string());
        }
        Some(date) if date <= today + Duration::days(30) => {
            score -= 5;
            issues.push("Evidence laeuft innerhalb von 30 Tagen ab.".to_string());
        }
        Some(_) => {}
        None => {
            score -= 5;
            issues.push("Gueltigkeitsdatum fehlt.".to_string());
        }
    }
    if item.retention_until.is_none() {
        score -= 5;
        issues.push("Aufbewahrungsfrist fehlt.".to_string());
    }
    if item.retention_until.is_some() && item.retention_reason.trim().is_empty() {
        score -= 3;
        issues.push("Begruendung der Aufbewahrungsfrist fehlt.".to_string());
    }
    if evidence_date(item.retention_until.as_deref()).is_some_and(|date| date < today) {
        score -= 5;
        issues.push(
            "Aufbewahrungsfrist ist erreicht; Legal Hold oder kontrollierte Disposition pruefen."
                .to_string(),
        );
    }
    let score = score.max(0);
    EvidenceQualityItem {
        id: item.id,
        title: item.title.clone(),
        status: item.status.clone(),
        status_label: item.status_label.clone(),
        quality_score: score,
        quality_level: evidence_quality_level(score).to_string(),
        issues,
        href: format!("/evidence/?evidence_id={}", item.id),
        owner_display: item.owner_display.clone(),
        reviewed_at: item.reviewed_at.clone(),
        file_name: item.file_name.clone(),
        linked_requirement: item.linked_requirement.clone(),
        version_number: item.version_number,
        sensitivity: item.sensitivity.clone(),
        valid_until: item.valid_until.clone(),
        retention_until: item.retention_until.clone(),
    }
}

fn evidence_date(value: Option<&str>) -> Option<NaiveDate> {
    value.and_then(|value| NaiveDate::parse_from_str(value, "%Y-%m-%d").ok())
}

fn evidence_quality_need(need: &RequirementEvidenceNeedSummary) -> EvidenceQualityNeed {
    let mut issues = Vec::new();
    let quality_level = if need.status.eq_ignore_ascii_case("COVERED") && need.covered_count > 0 {
        "reif"
    } else if need.covered_count > 0 || need.status.eq_ignore_ascii_case("PARTIAL") {
        issues.push("Evidence Need ist nur teilweise abgedeckt.".to_string());
        "teilweise"
    } else {
        issues.push("Evidence Need ist offen und ohne abdeckenden Nachweis.".to_string());
        "offen"
    };
    if need.is_mandatory && need.covered_count == 0 {
        issues.push("Pflichtnachweis fehlt.".to_string());
    }
    EvidenceQualityNeed {
        id: need.id,
        title: need.title.clone(),
        requirement_code: need.requirement_code.clone(),
        status: need.status.clone(),
        status_label: need.status_label.clone(),
        covered_count: need.covered_count,
        quality_level: quality_level.to_string(),
        issues,
        href: format!("/evidence/?need_id={}", need.id),
    }
}

fn evidence_item_has_traceable_link(item: &EvidenceItemSummary) -> bool {
    item.requirement_id.is_some()
        || item.control_id.is_some()
        || item.incident_id.is_some()
        || !item.linked_requirement.trim().is_empty()
}

fn evidence_quality_level(score: i64) -> &'static str {
    match score {
        85..=i64::MAX => "reif",
        65..=84 => "belastbar",
        40..=64 => "lueckenhaft",
        _ => "kritisch",
    }
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

async fn create_evidence_item_postgres(
    pool: &PgPool,
    tenant_id: i64,
    owner_id: i64,
    payload: EvidenceItemCreateRequest,
) -> anyhow::Result<EvidenceItemSummary> {
    validate_evidence_item_refs_postgres(pool, tenant_id, &payload).await?;
    let title = normalize_required_text(&payload.title, "Evidence-Titel")?;
    let status = normalize_evidence_status(payload.status.as_deref());
    let linked_requirement =
        linked_requirement_for_postgres(pool, payload.requirement_id, &payload.linked_requirement)
            .await?;
    let description = payload.description.trim().to_string();
    let review_notes = payload.review_notes.trim().to_string();
    let file_name = payload.file_name.clone();
    let version_number =
        next_evidence_version_postgres(pool, tenant_id, payload.supersedes_id).await?;
    let file_sha256 = normalize_file_sha256(&payload.file_sha256)?;
    let valid_until = normalize_evidence_date(payload.valid_until.as_deref(), "Gueltig bis")?;
    let retention_until =
        normalize_evidence_date(payload.retention_until.as_deref(), "Aufbewahren bis")?;
    validate_evidence_lifecycle_dates(valid_until.as_deref(), retention_until.as_deref())?;
    let sensitivity = normalize_evidence_sensitivity(&payload.sensitivity)?;
    let retention_reason = payload.retention_reason.trim().to_string();
    let id: i64 = sqlx::query_scalar(
        r#"
        INSERT INTO evidence_evidenceitem (
            tenant_id,
            session_id,
            domain_id,
            measure_id,
            requirement_id,
            control_id,
            incident_id,
            title,
            description,
            linked_requirement,
            file,
            version_number,
            supersedes_id,
            file_sha256,
            valid_until,
            retention_until,
            retention_reason,
            sensitivity,
            status,
            owner_id,
            review_notes,
            reviewed_by_id,
            reviewed_at,
            created_at,
            updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, NULL, NULL, NOW(), NOW())
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(payload.session_id)
    .bind(payload.domain_id)
    .bind(payload.measure_id)
    .bind(payload.requirement_id)
    .bind(payload.control_id)
    .bind(payload.incident_id)
    .bind(title)
    .bind(description)
    .bind(linked_requirement)
    .bind(file_name)
    .bind(version_number)
    .bind(payload.supersedes_id)
    .bind(file_sha256)
    .bind(valid_until)
    .bind(retention_until)
    .bind(retention_reason)
    .bind(sensitivity)
    .bind(status)
    .bind(owner_id)
    .bind(review_notes)
    .fetch_one(pool)
    .await
    .context("PostgreSQL-Evidence konnte nicht erstellt werden")?;

    evidence_item_by_id_postgres(pool, tenant_id, id).await
}

async fn create_evidence_item_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    owner_id: i64,
    payload: EvidenceItemCreateRequest,
) -> anyhow::Result<EvidenceItemSummary> {
    validate_evidence_item_refs_sqlite(pool, tenant_id, &payload).await?;
    let title = normalize_required_text(&payload.title, "Evidence-Titel")?;
    let status = normalize_evidence_status(payload.status.as_deref());
    let linked_requirement =
        linked_requirement_for_sqlite(pool, payload.requirement_id, &payload.linked_requirement)
            .await?;
    let description = payload.description.trim().to_string();
    let review_notes = payload.review_notes.trim().to_string();
    let file_name = payload.file_name.clone();
    let version_number =
        next_evidence_version_sqlite(pool, tenant_id, payload.supersedes_id).await?;
    let file_sha256 = normalize_file_sha256(&payload.file_sha256)?;
    let valid_until = normalize_evidence_date(payload.valid_until.as_deref(), "Gueltig bis")?;
    let retention_until =
        normalize_evidence_date(payload.retention_until.as_deref(), "Aufbewahren bis")?;
    validate_evidence_lifecycle_dates(valid_until.as_deref(), retention_until.as_deref())?;
    let sensitivity = normalize_evidence_sensitivity(&payload.sensitivity)?;
    let retention_reason = payload.retention_reason.trim().to_string();
    let result = sqlx::query(
        r#"
        INSERT INTO evidence_evidenceitem (
            tenant_id,
            session_id,
            domain_id,
            measure_id,
            requirement_id,
            control_id,
            incident_id,
            title,
            description,
            linked_requirement,
            file,
            version_number,
            supersedes_id,
            file_sha256,
            valid_until,
            retention_until,
            retention_reason,
            sensitivity,
            status,
            owner_id,
            review_notes,
            reviewed_by_id,
            reviewed_at,
            created_at,
            updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, NULL, NULL, datetime('now'), datetime('now'))
        "#,
    )
    .bind(tenant_id)
    .bind(payload.session_id)
    .bind(payload.domain_id)
    .bind(payload.measure_id)
    .bind(payload.requirement_id)
    .bind(payload.control_id)
    .bind(payload.incident_id)
    .bind(title)
    .bind(description)
    .bind(linked_requirement)
    .bind(file_name)
    .bind(version_number)
    .bind(payload.supersedes_id)
    .bind(file_sha256)
    .bind(valid_until)
    .bind(retention_until)
    .bind(retention_reason)
    .bind(sensitivity)
    .bind(status)
    .bind(owner_id)
    .bind(review_notes)
    .execute(pool)
    .await
    .context("SQLite-Evidence konnte nicht erstellt werden")?;

    evidence_item_by_id_sqlite(pool, tenant_id, result.last_insert_rowid()).await
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
            item.control_id,
            item.incident_id,
            incident.title AS incident_title,
            mv.program_name AS mapping_program_name,
            mv.version AS mapping_version,
            src.authority AS source_authority,
            src.citation AS source_citation,
            src.title AS source_title,
            item.title,
            item.description,
            item.linked_requirement,
            item.file AS file_name,
            item.version_number,
            item.supersedes_id,
            item.file_sha256,
            item.valid_until,
            item.retention_until,
            item.retention_reason,
            item.sensitivity,
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
        LEFT JOIN incidents_incident incident
            ON incident.id = item.incident_id AND incident.tenant_id = item.tenant_id
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
            item.control_id,
            item.incident_id,
            incident.title AS incident_title,
            mv.program_name AS mapping_program_name,
            mv.version AS mapping_version,
            src.authority AS source_authority,
            src.citation AS source_citation,
            src.title AS source_title,
            item.title,
            item.description,
            item.linked_requirement,
            item.file AS file_name,
            item.version_number,
            item.supersedes_id,
            item.file_sha256,
            item.valid_until,
            item.retention_until,
            item.retention_reason,
            item.sensitivity,
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
        LEFT JOIN incidents_incident incident
            ON incident.id = item.incident_id AND incident.tenant_id = item.tenant_id
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

async fn list_evidence_items_for_incident_postgres(
    pool: &PgPool,
    tenant_id: i64,
    incident_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<EvidenceItemSummary>> {
    let scan_limit = limit.saturating_mul(10).max(limit).max(100);
    let items = list_evidence_items_postgres(pool, tenant_id, None, scan_limit).await?;
    Ok(items
        .into_iter()
        .filter(|item| item.incident_id == Some(incident_id))
        .take(limit.max(0) as usize)
        .collect())
}

async fn list_evidence_items_for_incident_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    incident_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<EvidenceItemSummary>> {
    let scan_limit = limit.saturating_mul(10).max(limit).max(100);
    let items = list_evidence_items_sqlite(pool, tenant_id, None, scan_limit).await?;
    Ok(items
        .into_iter()
        .filter(|item| item.incident_id == Some(incident_id))
        .take(limit.max(0) as usize)
        .collect())
}

async fn evidence_item_by_id_postgres(
    pool: &PgPool,
    tenant_id: i64,
    evidence_id: i64,
) -> anyhow::Result<EvidenceItemSummary> {
    let row = sqlx::query(evidence_item_detail_postgres_sql())
        .bind(tenant_id)
        .bind(evidence_id)
        .fetch_one(pool)
        .await
        .context("PostgreSQL-Evidence konnte nicht gelesen werden")?;
    evidence_item_from_pg_row(row).map_err(Into::into)
}

async fn evidence_item_by_id_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    evidence_id: i64,
) -> anyhow::Result<EvidenceItemSummary> {
    let row = sqlx::query(evidence_item_detail_sqlite_sql())
        .bind(tenant_id)
        .bind(evidence_id)
        .fetch_one(pool)
        .await
        .context("SQLite-Evidence konnte nicht gelesen werden")?;
    evidence_item_from_sqlite_row(row).map_err(Into::into)
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

fn evidence_item_detail_postgres_sql() -> &'static str {
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
        item.control_id,
        item.incident_id,
        incident.title AS incident_title,
        mv.program_name AS mapping_program_name,
        mv.version AS mapping_version,
        src.authority AS source_authority,
        src.citation AS source_citation,
        src.title AS source_title,
        item.title,
        item.description,
        item.linked_requirement,
        item.file AS file_name,
        item.version_number,
        item.supersedes_id,
        item.file_sha256,
        item.valid_until,
        item.retention_until,
        item.retention_reason,
        item.sensitivity,
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
    LEFT JOIN incidents_incident incident
        ON incident.id = item.incident_id AND incident.tenant_id = item.tenant_id
    LEFT JOIN requirements_app_mappingversion mv
        ON mv.id = req.mapping_version_id
    LEFT JOIN requirements_app_regulatorysource src
        ON src.id = req.primary_source_id
    LEFT JOIN accounts_user owner
        ON owner.id = item.owner_id AND owner.tenant_id = item.tenant_id
    LEFT JOIN accounts_user reviewer
        ON reviewer.id = item.reviewed_by_id AND reviewer.tenant_id = item.tenant_id
    WHERE item.tenant_id = $1 AND item.id = $2
    "#
}

fn evidence_item_detail_sqlite_sql() -> &'static str {
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
        item.control_id,
        item.incident_id,
        incident.title AS incident_title,
        mv.program_name AS mapping_program_name,
        mv.version AS mapping_version,
        src.authority AS source_authority,
        src.citation AS source_citation,
        src.title AS source_title,
        item.title,
        item.description,
        item.linked_requirement,
        item.file AS file_name,
        item.version_number,
        item.supersedes_id,
        item.file_sha256,
        item.valid_until,
        item.retention_until,
        item.retention_reason,
        item.sensitivity,
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
    LEFT JOIN incidents_incident incident
        ON incident.id = item.incident_id AND incident.tenant_id = item.tenant_id
    LEFT JOIN requirements_app_mappingversion mv
        ON mv.id = req.mapping_version_id
    LEFT JOIN requirements_app_regulatorysource src
        ON src.id = req.primary_source_id
    LEFT JOIN accounts_user owner
        ON owner.id = item.owner_id AND owner.tenant_id = item.tenant_id
    LEFT JOIN accounts_user reviewer
        ON reviewer.id = item.reviewed_by_id AND reviewer.tenant_id = item.tenant_id
    WHERE item.tenant_id = ?1 AND item.id = ?2
    "#
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
        control_id: row.try_get("control_id")?,
        incident_id: row.try_get("incident_id")?,
        incident_title: row.try_get("incident_title")?,
        mapping_program_name: row.try_get("mapping_program_name")?,
        mapping_version: row.try_get("mapping_version")?,
        source_authority: row.try_get("source_authority")?,
        source_citation: row.try_get("source_citation")?,
        source_title: row.try_get("source_title")?,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        linked_requirement: row.try_get("linked_requirement")?,
        file_name: row.try_get("file_name")?,
        version_number: row.try_get("version_number")?,
        supersedes_id: row.try_get("supersedes_id")?,
        file_sha256: row.try_get("file_sha256")?,
        valid_until: row.try_get("valid_until")?,
        retention_until: row.try_get("retention_until")?,
        retention_reason: row.try_get("retention_reason")?,
        sensitivity: row.try_get("sensitivity")?,
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
        control_id: row.try_get("control_id")?,
        incident_id: row.try_get("incident_id")?,
        incident_title: row.try_get("incident_title")?,
        mapping_program_name: row.try_get("mapping_program_name")?,
        mapping_version: row.try_get("mapping_version")?,
        source_authority: row.try_get("source_authority")?,
        source_citation: row.try_get("source_citation")?,
        source_title: row.try_get("source_title")?,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        linked_requirement: row.try_get("linked_requirement")?,
        file_name: row.try_get("file_name")?,
        version_number: row.try_get("version_number")?,
        supersedes_id: row.try_get("supersedes_id")?,
        file_sha256: row.try_get("file_sha256")?,
        valid_until: row.try_get("valid_until")?,
        retention_until: row.try_get("retention_until")?,
        retention_reason: row.try_get("retention_reason")?,
        sensitivity: row.try_get("sensitivity")?,
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

async fn validate_evidence_item_refs_postgres(
    pool: &PgPool,
    tenant_id: i64,
    payload: &EvidenceItemCreateRequest,
) -> anyhow::Result<()> {
    if let Some(session_id) = payload.session_id {
        if !session_exists_postgres(pool, tenant_id, session_id).await? {
            bail!("Assessment-Session {session_id} wurde nicht gefunden.");
        }
    }
    if let Some(measure_id) = payload.measure_id {
        let exists: Option<i64> = sqlx::query_scalar(
            r#"
            SELECT measure.id
            FROM wizard_generatedmeasure measure
            JOIN wizard_assessmentsession session
                ON session.id = measure.session_id
            WHERE measure.id = $1 AND session.tenant_id = $2
            "#,
        )
        .bind(measure_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-Massnahme fuer Evidence konnte nicht validiert werden")?;
        if exists.is_none() {
            bail!("Massnahme {measure_id} wurde fuer diesen Tenant nicht gefunden.");
        }
    }
    if let Some(incident_id) = payload.incident_id {
        let exists: Option<i64> = sqlx::query_scalar(
            "SELECT id FROM incidents_incident WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(incident_id)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-Incident fuer Evidence konnte nicht validiert werden")?;
        if exists.is_none() {
            bail!("Incident {incident_id} wurde fuer diesen Tenant nicht gefunden.");
        }
    }
    if let Some(control_id) = payload.control_id {
        let exists: Option<i64> = sqlx::query_scalar(
            "SELECT id FROM iscy_control_control WHERE id = $1 AND is_active = TRUE",
        )
        .bind(control_id)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-ISCY-Control fuer Evidence konnte nicht validiert werden")?;
        if exists.is_none() {
            bail!("ISCY-Control {control_id} wurde nicht gefunden.");
        }
    }
    Ok(())
}

async fn validate_evidence_item_refs_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    payload: &EvidenceItemCreateRequest,
) -> anyhow::Result<()> {
    if let Some(session_id) = payload.session_id {
        if !session_exists_sqlite(pool, tenant_id, session_id).await? {
            bail!("Assessment-Session {session_id} wurde nicht gefunden.");
        }
    }
    if let Some(measure_id) = payload.measure_id {
        let exists: Option<i64> = sqlx::query_scalar(
            r#"
            SELECT measure.id
            FROM wizard_generatedmeasure measure
            JOIN wizard_assessmentsession session
                ON session.id = measure.session_id
            WHERE measure.id = ?1 AND session.tenant_id = ?2
            "#,
        )
        .bind(measure_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
        .context("SQLite-Massnahme fuer Evidence konnte nicht validiert werden")?;
        if exists.is_none() {
            bail!("Massnahme {measure_id} wurde fuer diesen Tenant nicht gefunden.");
        }
    }
    if let Some(incident_id) = payload.incident_id {
        let exists: Option<i64> = sqlx::query_scalar(
            "SELECT id FROM incidents_incident WHERE tenant_id = ?1 AND id = ?2",
        )
        .bind(tenant_id)
        .bind(incident_id)
        .fetch_optional(pool)
        .await
        .context("SQLite-Incident fuer Evidence konnte nicht validiert werden")?;
        if exists.is_none() {
            bail!("Incident {incident_id} wurde fuer diesen Tenant nicht gefunden.");
        }
    }
    if let Some(control_id) = payload.control_id {
        let exists: Option<i64> = sqlx::query_scalar(
            "SELECT id FROM iscy_control_control WHERE id = ?1 AND is_active = 1",
        )
        .bind(control_id)
        .fetch_optional(pool)
        .await
        .context("SQLite-ISCY-Control fuer Evidence konnte nicht validiert werden")?;
        if exists.is_none() {
            bail!("ISCY-Control {control_id} wurde nicht gefunden.");
        }
    }
    Ok(())
}

async fn next_evidence_version_postgres(
    pool: &PgPool,
    tenant_id: i64,
    supersedes_id: Option<i64>,
) -> anyhow::Result<i64> {
    let Some(supersedes_id) = supersedes_id else {
        return Ok(1);
    };
    let previous: Option<i64> = sqlx::query_scalar(
        "SELECT version_number FROM evidence_evidenceitem WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(supersedes_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-Evidence-Vorgaenger konnte nicht validiert werden")?;
    let version = previous
        .map(|version| version + 1)
        .ok_or_else(|| anyhow::anyhow!("Evidence-Vorgaenger wurde nicht gefunden."))?;
    let successor_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM evidence_evidenceitem WHERE tenant_id = $1 AND supersedes_id = $2)",
    )
    .bind(tenant_id)
    .bind(supersedes_id)
    .fetch_one(pool)
    .await
    .context("PostgreSQL-Evidence-Versionskette konnte nicht validiert werden")?;
    if successor_exists {
        bail!("Evidence-Vorgaenger wurde bereits ersetzt.");
    }
    Ok(version)
}

async fn next_evidence_version_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    supersedes_id: Option<i64>,
) -> anyhow::Result<i64> {
    let Some(supersedes_id) = supersedes_id else {
        return Ok(1);
    };
    let previous: Option<i64> = sqlx::query_scalar(
        "SELECT version_number FROM evidence_evidenceitem WHERE tenant_id = ?1 AND id = ?2",
    )
    .bind(tenant_id)
    .bind(supersedes_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-Evidence-Vorgaenger konnte nicht validiert werden")?;
    let version = previous
        .map(|version| version + 1)
        .ok_or_else(|| anyhow::anyhow!("Evidence-Vorgaenger wurde nicht gefunden."))?;
    let successor_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM evidence_evidenceitem WHERE tenant_id = ?1 AND supersedes_id = ?2)",
    )
    .bind(tenant_id)
    .bind(supersedes_id)
    .fetch_one(pool)
    .await
    .context("SQLite-Evidence-Versionskette konnte nicht validiert werden")?;
    if successor_exists {
        bail!("Evidence-Vorgaenger wurde bereits ersetzt.");
    }
    Ok(version)
}

fn normalize_file_sha256(value: &str) -> anyhow::Result<String> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty() {
        return Ok(value);
    }
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("SHA-256 muss aus genau 64 Hex-Zeichen bestehen.");
    }
    Ok(value)
}

fn normalize_evidence_date(value: Option<&str>, label: &str) -> anyhow::Result<Option<String>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .with_context(|| format!("{label} muss ein gueltiges Datum im Format YYYY-MM-DD sein."))?;
    Ok(Some(value.to_string()))
}

fn validate_evidence_lifecycle_dates(
    valid_until: Option<&str>,
    retention_until: Option<&str>,
) -> anyhow::Result<()> {
    let (Some(valid_until), Some(retention_until)) = (valid_until, retention_until) else {
        return Ok(());
    };
    if retention_until < valid_until {
        bail!("Aufbewahren bis darf nicht vor Gueltig bis liegen.");
    }
    Ok(())
}

fn normalize_evidence_sensitivity(value: &str) -> anyhow::Result<String> {
    let value = value.trim().to_ascii_uppercase();
    let value = if value.is_empty() {
        "INTERNAL".to_string()
    } else {
        value
    };
    if !matches!(
        value.as_str(),
        "PUBLIC" | "INTERNAL" | "CONFIDENTIAL" | "RESTRICTED"
    ) {
        bail!("Evidence-Schutzklasse ist ungueltig.");
    }
    Ok(value)
}

async fn linked_requirement_for_postgres(
    pool: &PgPool,
    requirement_id: Option<i64>,
    fallback: &str,
) -> anyhow::Result<String> {
    let fallback = fallback.trim();
    if !fallback.is_empty() {
        return Ok(fallback.to_string());
    }
    let Some(requirement_id) = requirement_id else {
        return Ok(String::new());
    };
    let row = sqlx::query(
        "SELECT framework, code FROM requirements_app_requirement WHERE id = $1 AND is_active = TRUE",
    )
    .bind(requirement_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-Requirement fuer Evidence konnte nicht gelesen werden")?;
    match row {
        Some(row) => Ok(format!(
            "{} {}",
            row.try_get::<String, _>("framework")?,
            row.try_get::<String, _>("code")?
        )),
        None => bail!("Requirement {requirement_id} wurde nicht gefunden."),
    }
}

async fn linked_requirement_for_sqlite(
    pool: &SqlitePool,
    requirement_id: Option<i64>,
    fallback: &str,
) -> anyhow::Result<String> {
    let fallback = fallback.trim();
    if !fallback.is_empty() {
        return Ok(fallback.to_string());
    }
    let Some(requirement_id) = requirement_id else {
        return Ok(String::new());
    };
    let row = sqlx::query(
        "SELECT framework, code FROM requirements_app_requirement WHERE id = ?1 AND is_active = 1",
    )
    .bind(requirement_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-Requirement fuer Evidence konnte nicht gelesen werden")?;
    match row {
        Some(row) => Ok(format!(
            "{} {}",
            row.try_get::<String, _>("framework")?,
            row.try_get::<String, _>("code")?
        )),
        None => bail!("Requirement {requirement_id} wurde nicht gefunden."),
    }
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

fn normalize_required_text<'a>(value: &'a str, label: &str) -> anyhow::Result<&'a str> {
    let value = value.trim();
    if value.is_empty() {
        bail!("{label} darf nicht leer sein.");
    }
    Ok(value)
}

fn normalize_evidence_status(value: Option<&str>) -> &'static str {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("DRAFT")
        .to_ascii_uppercase()
        .as_str()
    {
        "DRAFT" => "DRAFT",
        "SUBMITTED" => "SUBMITTED",
        "APPROVED" => "APPROVED",
        "REJECTED" => "REJECTED",
        _ => "DRAFT",
    }
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
