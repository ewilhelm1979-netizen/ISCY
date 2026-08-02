use crate::{
    evidence_object_storage::{redacted_object_key, BACKEND_S3_COMPATIBLE},
    evidence_s3_runtime::{canonical_object_key, generate_object_id},
    evidence_store::EvidenceStore,
};
use anyhow::{bail, Context};
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::{postgres::PgRow, sqlite::SqliteRow, Row};

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceS3RuntimeObject {
    pub id: i64,
    pub tenant_id: i64,
    pub evidence_id: i64,
    pub backend_id: String,
    pub opaque_object_id: String,
    pub canonical_key_sha256: String,
    pub object_key_redacted: String,
    pub upload_status: String,
    pub runtime_verification_status: String,
    pub object_size_bytes: Option<i64>,
    pub object_sha256: String,
    pub content_type: String,
    pub last_runtime_operation_at: Option<String>,
    pub last_runtime_error_class: String,
    pub orphan_review_required: bool,
    pub remote_delete_verified_at: Option<String>,
    pub tombstone_status: String,
    pub created_at: String,
    pub updated_at: String,
}

impl EvidenceS3RuntimeObject {
    pub fn canonical_key(&self, key_prefix: &str) -> anyhow::Result<String> {
        let key = canonical_object_key(
            key_prefix,
            self.tenant_id,
            self.evidence_id,
            &self.opaque_object_id,
        )
        .map_err(anyhow::Error::from)?;
        if crate::evidence_object_storage::full_sha256(&key) != self.canonical_key_sha256 {
            bail!("s3_runtime:canonical_key_hash_mismatch");
        }
        Ok(key)
    }
}

impl EvidenceStore {
    pub async fn record_s3_live_validation(
        &self,
        tenant_id: i64,
        backend_id: &str,
        actor_id: i64,
        successful: bool,
        error_class: &str,
    ) -> anyhow::Result<bool> {
        let status = if successful { "ready" } else { "error" };
        let error_class = safe_error_class(error_class);
        match self {
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                let updated = sqlx::query("UPDATE evidence_storage_backend_config SET status=$3, last_validation_at=(CURRENT_TIMESTAMP)::text, last_validation_status=$3, last_validation_error_class=$4, updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$1 AND backend_id=$2 AND backend_type='s3_compatible'")
                    .bind(tenant_id).bind(backend_id).bind(status).bind(&error_class).execute(&mut *tx).await?.rows_affected();
                if updated == 0 {
                    tx.rollback().await?;
                    return Ok(false);
                }
                insert_event_postgres(&mut tx, StorageRuntimeEvent {
                    tenant_id, backend_id, evidence_id: None, actor_id,
                    event_type: "storage_backend_live_validated", status,
                    error_class: &error_class,
                    detail: json!({"dns_revalidated": true, "secrets_resolved": successful, "secrets_exposed": false}),
                }).await?;
                tx.commit().await?;
            }
            Self::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                let updated = sqlx::query("UPDATE evidence_storage_backend_config SET status=?3, last_validation_at=datetime('now'), last_validation_status=?3, last_validation_error_class=?4, updated_at=datetime('now') WHERE tenant_id=?1 AND backend_id=?2 AND backend_type='s3_compatible'")
                    .bind(tenant_id).bind(backend_id).bind(status).bind(&error_class).execute(&mut *tx).await?.rows_affected();
                if updated == 0 {
                    tx.rollback().await?;
                    return Ok(false);
                }
                insert_event_sqlite(&mut tx, StorageRuntimeEvent {
                    tenant_id, backend_id, evidence_id: None, actor_id,
                    event_type: "storage_backend_live_validated", status,
                    error_class: &error_class,
                    detail: json!({"dns_revalidated": true, "secrets_resolved": successful, "secrets_exposed": false}),
                }).await?;
                tx.commit().await?;
            }
        }
        Ok(true)
    }

    pub async fn reserve_s3_runtime_object(
        &self,
        tenant_id: i64,
        evidence_id: i64,
        backend_id: &str,
        actor_id: i64,
        expected_sha256: &str,
        content_type: &str,
    ) -> anyhow::Result<EvidenceS3RuntimeObject> {
        if let Some(existing) = self.s3_runtime_object(tenant_id, evidence_id).await? {
            if existing.backend_id == backend_id {
                return Ok(existing);
            }
            bail!("s3_runtime:object_reference_backend_conflict");
        }
        let backend = self
            .evidence_storage_backend_config(tenant_id, backend_id)
            .await?
            .filter(|config| config.backend_type == BACKEND_S3_COMPATIBLE)
            .ok_or_else(|| anyhow::anyhow!("s3_runtime:backend_not_ready"))?;
        let object_id = generate_object_id()?;
        let canonical_key =
            canonical_object_key(&backend.key_prefix, tenant_id, evidence_id, &object_id)?;
        let key_hash = crate::evidence_object_storage::full_sha256(&canonical_key);
        let key_redacted = redacted_object_key(&canonical_key);
        let content_type = normalize_content_type(content_type);
        let expected_sha256 = normalize_sha256(expected_sha256)?;
        match self {
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                ensure_evidence_exists_postgres(&mut tx, tenant_id, evidence_id).await?;
                sqlx::query(
                    r#"
                    INSERT INTO evidence_object_reference (
                        tenant_id, evidence_id, backend_id, backend_type,
                        object_key_redacted, object_key_sha256, object_reference_status,
                        expected_sha256, contract_status, contract_sha256, created_by
                    ) VALUES ($1,$2,$3,'s3_compatible',$4,$5,'upload_pending',$6,'metadata_only','',$7)
                    ON CONFLICT (tenant_id, evidence_id, backend_id) DO NOTHING
                    "#,
                )
                .bind(tenant_id)
                .bind(evidence_id)
                .bind(backend_id)
                .bind(&key_redacted)
                .bind(&key_hash)
                .bind(&expected_sha256)
                .bind(actor_id)
                .execute(&mut *tx)
                .await?;
                sqlx::query(
                    r#"
                    INSERT INTO evidence_s3_runtime_object (
                        tenant_id, evidence_id, backend_id, opaque_object_id,
                        canonical_key_sha256, upload_status, runtime_verification_status,
                        object_sha256, content_type, created_by
                    ) VALUES ($1,$2,$3,$4,$5,'upload_pending','verification_required',$6,$7,$8)
                    ON CONFLICT (tenant_id, evidence_id, backend_id) DO NOTHING
                    "#,
                )
                .bind(tenant_id)
                .bind(evidence_id)
                .bind(backend_id)
                .bind(&object_id)
                .bind(&key_hash)
                .bind(&expected_sha256)
                .bind(&content_type)
                .bind(actor_id)
                .execute(&mut *tx)
                .await?;
                insert_event_postgres(
                    &mut tx,
                    StorageRuntimeEvent {
                        tenant_id,
                        backend_id,
                        evidence_id: Some(evidence_id),
                        actor_id,
                        event_type: "storage_object_upload_started",
                        status: "upload_pending",
                        error_class: "",
                        detail: json!({"object_key_redacted": key_redacted, "object_key_hash_present": true}),
                    },
                )
                .await?;
                tx.commit().await?;
            }
            Self::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                ensure_evidence_exists_sqlite(&mut tx, tenant_id, evidence_id).await?;
                sqlx::query(
                    r#"
                    INSERT INTO evidence_object_reference (
                        tenant_id, evidence_id, backend_id, backend_type,
                        object_key_redacted, object_key_sha256, object_reference_status,
                        expected_sha256, contract_status, contract_sha256, created_by
                    ) VALUES (?1,?2,?3,'s3_compatible',?4,?5,'upload_pending',?6,'metadata_only','',?7)
                    ON CONFLICT (tenant_id, evidence_id, backend_id) DO NOTHING
                    "#,
                )
                .bind(tenant_id)
                .bind(evidence_id)
                .bind(backend_id)
                .bind(&key_redacted)
                .bind(&key_hash)
                .bind(&expected_sha256)
                .bind(actor_id)
                .execute(&mut *tx)
                .await?;
                sqlx::query(
                    r#"
                    INSERT INTO evidence_s3_runtime_object (
                        tenant_id, evidence_id, backend_id, opaque_object_id,
                        canonical_key_sha256, upload_status, runtime_verification_status,
                        object_sha256, content_type, created_by
                    ) VALUES (?1,?2,?3,?4,?5,'upload_pending','verification_required',?6,?7,?8)
                    ON CONFLICT (tenant_id, evidence_id, backend_id) DO NOTHING
                    "#,
                )
                .bind(tenant_id)
                .bind(evidence_id)
                .bind(backend_id)
                .bind(&object_id)
                .bind(&key_hash)
                .bind(&expected_sha256)
                .bind(&content_type)
                .bind(actor_id)
                .execute(&mut *tx)
                .await?;
                insert_event_sqlite(
                    &mut tx,
                    StorageRuntimeEvent {
                        tenant_id,
                        backend_id,
                        evidence_id: Some(evidence_id),
                        actor_id,
                        event_type: "storage_object_upload_started",
                        status: "upload_pending",
                        error_class: "",
                        detail: json!({"object_key_redacted": key_redacted, "object_key_hash_present": true}),
                    },
                )
                .await?;
                tx.commit().await?;
            }
        }
        self.s3_runtime_object(tenant_id, evidence_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("s3_runtime:object_reference_missing"))
    }

    pub async fn s3_runtime_object(
        &self,
        tenant_id: i64,
        evidence_id: i64,
    ) -> anyhow::Result<Option<EvidenceS3RuntimeObject>> {
        match self {
            Self::Postgres(pool) => {
                let row = sqlx::query(&runtime_select(
                    "WHERE runtime.tenant_id = $1 AND runtime.evidence_id = $2",
                ))
                .bind(tenant_id)
                .bind(evidence_id)
                .fetch_optional(pool)
                .await?;
                row.map(runtime_from_pg_row).transpose().map_err(Into::into)
            }
            Self::Sqlite(pool) => {
                let row = sqlx::query(&runtime_select(
                    "WHERE runtime.tenant_id = ?1 AND runtime.evidence_id = ?2",
                ))
                .bind(tenant_id)
                .bind(evidence_id)
                .fetch_optional(pool)
                .await?;
                row.map(runtime_from_sqlite_row)
                    .transpose()
                    .map_err(Into::into)
            }
        }
    }

    pub async fn s3_runtime_objects(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<EvidenceS3RuntimeObject>> {
        let limit = limit.clamp(1, 500);
        match self {
            Self::Postgres(pool) => {
                let rows = sqlx::query(&runtime_select(
                    "WHERE runtime.tenant_id = $1 ORDER BY runtime.updated_at DESC LIMIT $2",
                ))
                .bind(tenant_id)
                .bind(limit)
                .fetch_all(pool)
                .await?;
                rows.into_iter()
                    .map(runtime_from_pg_row)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(Into::into)
            }
            Self::Sqlite(pool) => {
                let rows = sqlx::query(&runtime_select(
                    "WHERE runtime.tenant_id = ?1 ORDER BY runtime.updated_at DESC LIMIT ?2",
                ))
                .bind(tenant_id)
                .bind(limit)
                .fetch_all(pool)
                .await?;
                rows.into_iter()
                    .map(runtime_from_sqlite_row)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(Into::into)
            }
        }
    }

    pub async fn complete_s3_upload(
        &self,
        tenant_id: i64,
        evidence_id: i64,
        actor_id: i64,
        size_bytes: i64,
        sha256: &str,
    ) -> anyhow::Result<Option<EvidenceS3RuntimeObject>> {
        let sha256 = normalize_sha256(sha256)?;
        match self {
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                let backend_id: Option<String> = sqlx::query_scalar(
                    "SELECT backend_id FROM evidence_s3_runtime_object WHERE tenant_id=$1 AND evidence_id=$2 FOR UPDATE",
                )
                .bind(tenant_id)
                .bind(evidence_id)
                .fetch_optional(&mut *tx)
                .await?;
                let Some(backend_id) = backend_id else {
                    return Ok(None);
                };
                sqlx::query(
                    r#"UPDATE evidence_s3_runtime_object SET upload_status='upload_completed', runtime_verification_status='verification_required', object_size_bytes=$3, object_sha256=$4, last_runtime_operation_at=(CURRENT_TIMESTAMP)::text, last_runtime_error_class='', orphan_review_required=FALSE, updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$1 AND evidence_id=$2"#,
                ).bind(tenant_id).bind(evidence_id).bind(size_bytes).bind(&sha256).execute(&mut *tx).await?;
                sqlx::query(
                    "UPDATE evidence_object_reference SET object_reference_status='upload_completed', expected_sha256=$3, contract_status='present', contract_sha256=$3, contract_size_bytes=$4, updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$1 AND evidence_id=$2 AND backend_id=$5",
                ).bind(tenant_id).bind(evidence_id).bind(&sha256).bind(size_bytes).bind(&backend_id).execute(&mut *tx).await?;
                sqlx::query(
                    "UPDATE evidence_evidenceitem SET file_sha256=$3, storage_backend='s3_compatible', storage_object_reference=(SELECT opaque_object_id FROM evidence_s3_runtime_object WHERE tenant_id=$1 AND evidence_id=$2), updated_at=NOW() WHERE tenant_id=$1 AND id=$2",
                ).bind(tenant_id).bind(evidence_id).bind(&sha256).execute(&mut *tx).await?;
                insert_event_postgres(
                    &mut tx,
                    StorageRuntimeEvent {
                        tenant_id,
                        backend_id: &backend_id,
                        evidence_id: Some(evidence_id),
                        actor_id,
                        event_type: "storage_object_upload_completed",
                        status: "upload_completed",
                        error_class: "",
                        detail: json!({"size_bytes": size_bytes, "sha256_present": true}),
                    },
                )
                .await?;
                tx.commit().await?;
            }
            Self::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                let backend_id: Option<String> = sqlx::query_scalar(
                    "SELECT backend_id FROM evidence_s3_runtime_object WHERE tenant_id=?1 AND evidence_id=?2",
                ).bind(tenant_id).bind(evidence_id).fetch_optional(&mut *tx).await?;
                let Some(backend_id) = backend_id else {
                    return Ok(None);
                };
                sqlx::query(
                    "UPDATE evidence_s3_runtime_object SET upload_status='upload_completed', runtime_verification_status='verification_required', object_size_bytes=?3, object_sha256=?4, last_runtime_operation_at=datetime('now'), last_runtime_error_class='', orphan_review_required=0, updated_at=datetime('now') WHERE tenant_id=?1 AND evidence_id=?2",
                ).bind(tenant_id).bind(evidence_id).bind(size_bytes).bind(&sha256).execute(&mut *tx).await?;
                sqlx::query(
                    "UPDATE evidence_object_reference SET object_reference_status='upload_completed', expected_sha256=?3, contract_status='present', contract_sha256=?3, contract_size_bytes=?4, updated_at=datetime('now') WHERE tenant_id=?1 AND evidence_id=?2 AND backend_id=?5",
                ).bind(tenant_id).bind(evidence_id).bind(&sha256).bind(size_bytes).bind(&backend_id).execute(&mut *tx).await?;
                sqlx::query(
                    "UPDATE evidence_evidenceitem SET file_sha256=?3, storage_backend='s3_compatible', storage_object_reference=(SELECT opaque_object_id FROM evidence_s3_runtime_object WHERE tenant_id=?1 AND evidence_id=?2), updated_at=datetime('now') WHERE tenant_id=?1 AND id=?2",
                ).bind(tenant_id).bind(evidence_id).bind(&sha256).execute(&mut *tx).await?;
                insert_event_sqlite(
                    &mut tx,
                    StorageRuntimeEvent {
                        tenant_id,
                        backend_id: &backend_id,
                        evidence_id: Some(evidence_id),
                        actor_id,
                        event_type: "storage_object_upload_completed",
                        status: "upload_completed",
                        error_class: "",
                        detail: json!({"size_bytes": size_bytes, "sha256_present": true}),
                    },
                )
                .await?;
                tx.commit().await?;
            }
        }
        self.s3_runtime_object(tenant_id, evidence_id).await
    }

    pub async fn fail_s3_runtime_operation(
        &self,
        tenant_id: i64,
        evidence_id: i64,
        actor_id: i64,
        operation: &str,
        error_class: &str,
        orphan_review_required: bool,
    ) -> anyhow::Result<Option<EvidenceS3RuntimeObject>> {
        let event_type = safe_event_type(operation);
        let error_class = safe_error_class(error_class);
        match self {
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                let backend_id: Option<String> = sqlx::query_scalar("SELECT backend_id FROM evidence_s3_runtime_object WHERE tenant_id=$1 AND evidence_id=$2 FOR UPDATE")
                    .bind(tenant_id).bind(evidence_id).fetch_optional(&mut *tx).await?;
                let Some(backend_id) = backend_id else {
                    return Ok(None);
                };
                sqlx::query("UPDATE evidence_s3_runtime_object SET upload_status=CASE WHEN $3='upload' THEN 'upload_failed' ELSE upload_status END, runtime_verification_status=CASE WHEN $3 IN ('verify','drill') THEN 'check_failed' ELSE runtime_verification_status END, last_runtime_operation_at=(CURRENT_TIMESTAMP)::text, last_runtime_error_class=$4, orphan_review_required=$5, updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$1 AND evidence_id=$2")
                    .bind(tenant_id).bind(evidence_id).bind(operation).bind(&error_class).bind(orphan_review_required).execute(&mut *tx).await?;
                insert_event_postgres(
                    &mut tx,
                    StorageRuntimeEvent {
                        tenant_id,
                        backend_id: &backend_id,
                        evidence_id: Some(evidence_id),
                        actor_id,
                        event_type,
                        status: "failed",
                        error_class: &error_class,
                        detail: json!({"orphan_review_required": orphan_review_required}),
                    },
                )
                .await?;
                tx.commit().await?;
            }
            Self::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                let backend_id: Option<String> = sqlx::query_scalar("SELECT backend_id FROM evidence_s3_runtime_object WHERE tenant_id=?1 AND evidence_id=?2")
                    .bind(tenant_id).bind(evidence_id).fetch_optional(&mut *tx).await?;
                let Some(backend_id) = backend_id else {
                    return Ok(None);
                };
                sqlx::query("UPDATE evidence_s3_runtime_object SET upload_status=CASE WHEN ?3='upload' THEN 'upload_failed' ELSE upload_status END, runtime_verification_status=CASE WHEN ?3 IN ('verify','drill') THEN 'check_failed' ELSE runtime_verification_status END, last_runtime_operation_at=datetime('now'), last_runtime_error_class=?4, orphan_review_required=?5, updated_at=datetime('now') WHERE tenant_id=?1 AND evidence_id=?2")
                    .bind(tenant_id).bind(evidence_id).bind(operation).bind(&error_class).bind(orphan_review_required).execute(&mut *tx).await?;
                insert_event_sqlite(
                    &mut tx,
                    StorageRuntimeEvent {
                        tenant_id,
                        backend_id: &backend_id,
                        evidence_id: Some(evidence_id),
                        actor_id,
                        event_type,
                        status: "failed",
                        error_class: &error_class,
                        detail: json!({"orphan_review_required": orphan_review_required}),
                    },
                )
                .await?;
                tx.commit().await?;
            }
        }
        self.s3_runtime_object(tenant_id, evidence_id).await
    }

    pub async fn complete_s3_verification(
        &self,
        tenant_id: i64,
        evidence_id: i64,
        actor_id: i64,
        calculated_sha256: &str,
        size_bytes: i64,
        hash_matches: bool,
    ) -> anyhow::Result<Option<EvidenceS3RuntimeObject>> {
        let calculated_sha256 = normalize_sha256(calculated_sha256)?;
        let status = if hash_matches { "verified" } else { "mismatch" };
        let error_class = if hash_matches { "" } else { "hash_mismatch" };
        match self {
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                let backend_id: Option<String> = sqlx::query_scalar("SELECT backend_id FROM evidence_s3_runtime_object WHERE tenant_id=$1 AND evidence_id=$2 FOR UPDATE")
                    .bind(tenant_id).bind(evidence_id).fetch_optional(&mut *tx).await?;
                let Some(backend_id) = backend_id else {
                    return Ok(None);
                };
                sqlx::query("UPDATE evidence_s3_runtime_object SET runtime_verification_status=$3, object_size_bytes=$4, last_runtime_operation_at=(CURRENT_TIMESTAMP)::text, last_runtime_error_class=$5, updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$1 AND evidence_id=$2")
                    .bind(tenant_id).bind(evidence_id).bind(status).bind(size_bytes).bind(error_class).execute(&mut *tx).await?;
                sqlx::query("UPDATE evidence_object_reference SET last_drill_at=(CURRENT_TIMESTAMP)::text, last_drill_status=$3, last_drill_error_class=$4, contract_sha256=$5, contract_size_bytes=$6, updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$1 AND evidence_id=$2 AND backend_id=$7")
                    .bind(tenant_id).bind(evidence_id).bind(if hash_matches {"valid"} else {"mismatch"}).bind(error_class).bind(&calculated_sha256).bind(size_bytes).bind(&backend_id).execute(&mut *tx).await?;
                insert_event_postgres(
                    &mut tx,
                    StorageRuntimeEvent {
                        tenant_id,
                        backend_id: &backend_id,
                        evidence_id: Some(evidence_id),
                        actor_id,
                        event_type: "storage_object_drill_completed",
                        status,
                        error_class,
                        detail: json!({"size_bytes": size_bytes, "hash_matches": hash_matches}),
                    },
                )
                .await?;
                tx.commit().await?;
            }
            Self::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                let backend_id: Option<String> = sqlx::query_scalar("SELECT backend_id FROM evidence_s3_runtime_object WHERE tenant_id=?1 AND evidence_id=?2")
                    .bind(tenant_id).bind(evidence_id).fetch_optional(&mut *tx).await?;
                let Some(backend_id) = backend_id else {
                    return Ok(None);
                };
                sqlx::query("UPDATE evidence_s3_runtime_object SET runtime_verification_status=?3, object_size_bytes=?4, last_runtime_operation_at=datetime('now'), last_runtime_error_class=?5, updated_at=datetime('now') WHERE tenant_id=?1 AND evidence_id=?2")
                    .bind(tenant_id).bind(evidence_id).bind(status).bind(size_bytes).bind(error_class).execute(&mut *tx).await?;
                sqlx::query("UPDATE evidence_object_reference SET last_drill_at=datetime('now'), last_drill_status=?3, last_drill_error_class=?4, contract_sha256=?5, contract_size_bytes=?6, updated_at=datetime('now') WHERE tenant_id=?1 AND evidence_id=?2 AND backend_id=?7")
                    .bind(tenant_id).bind(evidence_id).bind(if hash_matches {"valid"} else {"mismatch"}).bind(error_class).bind(&calculated_sha256).bind(size_bytes).bind(&backend_id).execute(&mut *tx).await?;
                insert_event_sqlite(
                    &mut tx,
                    StorageRuntimeEvent {
                        tenant_id,
                        backend_id: &backend_id,
                        evidence_id: Some(evidence_id),
                        actor_id,
                        event_type: "storage_object_drill_completed",
                        status,
                        error_class,
                        detail: json!({"size_bytes": size_bytes, "hash_matches": hash_matches}),
                    },
                )
                .await?;
                tx.commit().await?;
            }
        }
        self.s3_runtime_object(tenant_id, evidence_id).await
    }

    pub async fn complete_s3_delete(
        &self,
        tenant_id: i64,
        evidence_id: i64,
        actor_id: i64,
        already_missing: bool,
    ) -> anyhow::Result<Option<EvidenceS3RuntimeObject>> {
        let status = if already_missing {
            "object_already_missing"
        } else {
            "delete_verified"
        };
        match self {
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                let backend_id: Option<String> = sqlx::query_scalar("SELECT backend_id FROM evidence_s3_runtime_object WHERE tenant_id=$1 AND evidence_id=$2 FOR UPDATE")
                    .bind(tenant_id).bind(evidence_id).fetch_optional(&mut *tx).await?;
                let Some(backend_id) = backend_id else {
                    return Ok(None);
                };
                sqlx::query("UPDATE evidence_s3_runtime_object SET upload_status='deleted', runtime_verification_status='object_missing', remote_delete_verified_at=(CURRENT_TIMESTAMP)::text, tombstone_status=$3, last_runtime_operation_at=(CURRENT_TIMESTAMP)::text, last_runtime_error_class='', orphan_review_required=FALSE, updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$1 AND evidence_id=$2")
                    .bind(tenant_id).bind(evidence_id).bind(status).execute(&mut *tx).await?;
                sqlx::query("UPDATE evidence_object_reference SET object_reference_status='deleted_tombstone', contract_status='missing', last_drill_status='missing_artifact', last_drill_error_class='object_missing', updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$1 AND evidence_id=$2 AND backend_id=$3")
                    .bind(tenant_id).bind(evidence_id).bind(&backend_id).execute(&mut *tx).await?;
                insert_event_postgres(
                    &mut tx,
                    StorageRuntimeEvent {
                        tenant_id,
                        backend_id: &backend_id,
                        evidence_id: Some(evidence_id),
                        actor_id,
                        event_type: "storage_object_delete_completed",
                        status,
                        error_class: "",
                        detail: json!({"delete_verified": true, "already_missing": already_missing}),
                    },
                )
                .await?;
                tx.commit().await?;
            }
            Self::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                let backend_id: Option<String> = sqlx::query_scalar("SELECT backend_id FROM evidence_s3_runtime_object WHERE tenant_id=?1 AND evidence_id=?2")
                    .bind(tenant_id).bind(evidence_id).fetch_optional(&mut *tx).await?;
                let Some(backend_id) = backend_id else {
                    return Ok(None);
                };
                sqlx::query("UPDATE evidence_s3_runtime_object SET upload_status='deleted', runtime_verification_status='object_missing', remote_delete_verified_at=datetime('now'), tombstone_status=?3, last_runtime_operation_at=datetime('now'), last_runtime_error_class='', orphan_review_required=0, updated_at=datetime('now') WHERE tenant_id=?1 AND evidence_id=?2")
                    .bind(tenant_id).bind(evidence_id).bind(status).execute(&mut *tx).await?;
                sqlx::query("UPDATE evidence_object_reference SET object_reference_status='deleted_tombstone', contract_status='missing', last_drill_status='missing_artifact', last_drill_error_class='object_missing', updated_at=datetime('now') WHERE tenant_id=?1 AND evidence_id=?2 AND backend_id=?3")
                    .bind(tenant_id).bind(evidence_id).bind(&backend_id).execute(&mut *tx).await?;
                insert_event_sqlite(
                    &mut tx,
                    StorageRuntimeEvent {
                        tenant_id,
                        backend_id: &backend_id,
                        evidence_id: Some(evidence_id),
                        actor_id,
                        event_type: "storage_object_delete_completed",
                        status,
                        error_class: "",
                        detail: json!({"delete_verified": true, "already_missing": already_missing}),
                    },
                )
                .await?;
                tx.commit().await?;
            }
        }
        self.s3_runtime_object(tenant_id, evidence_id).await
    }

    pub async fn claim_s3_delete(&self, tenant_id: i64, evidence_id: i64) -> anyhow::Result<bool> {
        let rows_affected = match self {
            Self::Postgres(pool) => sqlx::query(
                r#"
                UPDATE evidence_s3_runtime_object
                SET upload_status = 'delete_in_progress',
                    last_runtime_operation_at = (CURRENT_TIMESTAMP)::text,
                    last_runtime_error_class = '',
                    updated_at = (CURRENT_TIMESTAMP)::text
                WHERE tenant_id = $1 AND evidence_id = $2
                  AND (
                    upload_status = 'upload_completed'
                    OR (
                      upload_status = 'delete_in_progress'
                      AND updated_at::timestamptz < CURRENT_TIMESTAMP - INTERVAL '10 minutes'
                    )
                  )
                "#,
            )
            .bind(tenant_id)
            .bind(evidence_id)
            .execute(pool)
            .await?
            .rows_affected(),
            Self::Sqlite(pool) => sqlx::query(
                r#"
                UPDATE evidence_s3_runtime_object
                SET upload_status = 'delete_in_progress',
                    last_runtime_operation_at = datetime('now'),
                    last_runtime_error_class = '',
                    updated_at = datetime('now')
                WHERE tenant_id = ?1 AND evidence_id = ?2
                  AND (
                    upload_status = 'upload_completed'
                    OR (
                      upload_status = 'delete_in_progress'
                      AND datetime(updated_at) < datetime('now', '-10 minutes')
                    )
                  )
                "#,
            )
            .bind(tenant_id)
            .bind(evidence_id)
            .execute(pool)
            .await?
            .rows_affected(),
        };
        Ok(rows_affected == 1)
    }

    pub async fn release_s3_delete_claim(
        &self,
        tenant_id: i64,
        evidence_id: i64,
        error_class: &str,
    ) -> anyhow::Result<()> {
        match self {
            Self::Postgres(pool) => {
                sqlx::query("UPDATE evidence_s3_runtime_object SET upload_status='upload_completed', last_runtime_error_class=$3, updated_at=(CURRENT_TIMESTAMP)::text WHERE tenant_id=$1 AND evidence_id=$2 AND upload_status='delete_in_progress'")
                    .bind(tenant_id).bind(evidence_id).bind(error_class).execute(pool).await?;
            }
            Self::Sqlite(pool) => {
                sqlx::query("UPDATE evidence_s3_runtime_object SET upload_status='upload_completed', last_runtime_error_class=?3, updated_at=datetime('now') WHERE tenant_id=?1 AND evidence_id=?2 AND upload_status='delete_in_progress'")
                    .bind(tenant_id).bind(evidence_id).bind(error_class).execute(pool).await?;
            }
        }
        Ok(())
    }
}

fn runtime_select(where_clause: &str) -> String {
    format!(
        r#"
        SELECT runtime.id, runtime.tenant_id, runtime.evidence_id, runtime.backend_id,
               runtime.opaque_object_id, runtime.canonical_key_sha256,
               object_ref.object_key_redacted, runtime.upload_status,
               runtime.runtime_verification_status, runtime.object_size_bytes,
               runtime.object_sha256, runtime.content_type,
               runtime.last_runtime_operation_at, runtime.last_runtime_error_class,
               runtime.orphan_review_required, runtime.remote_delete_verified_at,
               runtime.tombstone_status, runtime.created_at, runtime.updated_at
        FROM evidence_s3_runtime_object runtime
        JOIN evidence_object_reference object_ref
          ON object_ref.tenant_id=runtime.tenant_id
         AND object_ref.evidence_id=runtime.evidence_id
         AND object_ref.backend_id=runtime.backend_id
        {where_clause}
    "#
    )
}

fn runtime_from_pg_row(row: PgRow) -> Result<EvidenceS3RuntimeObject, sqlx::Error> {
    Ok(EvidenceS3RuntimeObject {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        evidence_id: row.try_get("evidence_id")?,
        backend_id: row.try_get("backend_id")?,
        opaque_object_id: row.try_get("opaque_object_id")?,
        canonical_key_sha256: row.try_get("canonical_key_sha256")?,
        object_key_redacted: row.try_get("object_key_redacted")?,
        upload_status: row.try_get("upload_status")?,
        runtime_verification_status: row.try_get("runtime_verification_status")?,
        object_size_bytes: row.try_get("object_size_bytes")?,
        object_sha256: row.try_get("object_sha256")?,
        content_type: row.try_get("content_type")?,
        last_runtime_operation_at: row.try_get("last_runtime_operation_at")?,
        last_runtime_error_class: row.try_get("last_runtime_error_class")?,
        orphan_review_required: row.try_get("orphan_review_required")?,
        remote_delete_verified_at: row.try_get("remote_delete_verified_at")?,
        tombstone_status: row.try_get("tombstone_status")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn runtime_from_sqlite_row(row: SqliteRow) -> Result<EvidenceS3RuntimeObject, sqlx::Error> {
    Ok(EvidenceS3RuntimeObject {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        evidence_id: row.try_get("evidence_id")?,
        backend_id: row.try_get("backend_id")?,
        opaque_object_id: row.try_get("opaque_object_id")?,
        canonical_key_sha256: row.try_get("canonical_key_sha256")?,
        object_key_redacted: row.try_get("object_key_redacted")?,
        upload_status: row.try_get("upload_status")?,
        runtime_verification_status: row.try_get("runtime_verification_status")?,
        object_size_bytes: row.try_get("object_size_bytes")?,
        object_sha256: row.try_get("object_sha256")?,
        content_type: row.try_get("content_type")?,
        last_runtime_operation_at: row.try_get("last_runtime_operation_at")?,
        last_runtime_error_class: row.try_get("last_runtime_error_class")?,
        orphan_review_required: row.try_get("orphan_review_required")?,
        remote_delete_verified_at: row.try_get("remote_delete_verified_at")?,
        tombstone_status: row.try_get("tombstone_status")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

async fn ensure_evidence_exists_postgres(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    evidence_id: i64,
) -> anyhow::Result<()> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM evidence_evidenceitem WHERE tenant_id=$1 AND id=$2)",
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .fetch_one(&mut **tx)
    .await?;
    if exists {
        Ok(())
    } else {
        bail!("s3_runtime:evidence_not_found")
    }
}

async fn ensure_evidence_exists_sqlite(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    tenant_id: i64,
    evidence_id: i64,
) -> anyhow::Result<()> {
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM evidence_evidenceitem WHERE tenant_id=?1 AND id=?2",
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .fetch_one(&mut **tx)
    .await?;
    if exists == 1 {
        Ok(())
    } else {
        bail!("s3_runtime:evidence_not_found")
    }
}

struct StorageRuntimeEvent<'a> {
    tenant_id: i64,
    backend_id: &'a str,
    evidence_id: Option<i64>,
    actor_id: i64,
    event_type: &'a str,
    status: &'a str,
    error_class: &'a str,
    detail: Value,
}

async fn insert_event_postgres(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    event: StorageRuntimeEvent<'_>,
) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO evidence_storage_backend_event (tenant_id,backend_id,evidence_id,event_type,actor_id,status,error_class,summary,detail_json) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind(event.tenant_id).bind(event.backend_id).bind(event.evidence_id).bind(event.event_type).bind(event.actor_id)
        .bind(event.status).bind(event.error_class).bind(event_summary(event.event_type, event.status)).bind(event.detail)
        .execute(&mut **tx).await.context("S3-Runtime-Audit konnte nicht gespeichert werden")?;
    Ok(())
}

async fn insert_event_sqlite(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    event: StorageRuntimeEvent<'_>,
) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO evidence_storage_backend_event (tenant_id,backend_id,evidence_id,event_type,actor_id,status,error_class,summary,detail_json) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)")
        .bind(event.tenant_id).bind(event.backend_id).bind(event.evidence_id).bind(event.event_type).bind(event.actor_id)
        .bind(event.status).bind(event.error_class).bind(event_summary(event.event_type, event.status)).bind(event.detail.to_string())
        .execute(&mut **tx).await.context("S3-Runtime-Audit konnte nicht gespeichert werden")?;
    Ok(())
}

fn normalize_sha256(value: &str) -> anyhow::Result<String> {
    let value = value.trim().to_ascii_lowercase();
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(value)
    } else {
        bail!("s3_runtime:invalid_sha256")
    }
}

fn normalize_content_type(value: &str) -> String {
    value
        .trim()
        .chars()
        .filter(|ch| ch.is_ascii_graphic())
        .take(128)
        .collect::<String>()
}

fn safe_error_class(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || *ch == '_')
        .take(64)
        .collect()
}

fn safe_event_type(operation: &str) -> &'static str {
    match operation {
        "upload" => "storage_object_upload_failed",
        "verify" | "drill" => "storage_object_drill_failed",
        "delete" => "storage_object_delete_failed",
        _ => "storage_runtime_operation_failed",
    }
}

fn event_summary(event_type: &str, status: &str) -> String {
    format!("S3-Runtime-Ereignis {event_type}: {status}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db_admin::{run_sqlite_migrations, seed_sqlite_demo};
    use sqlx::sqlite::SqlitePoolOptions;

    #[tokio::test]
    async fn runtime_reference_is_tenant_scoped_and_preserves_only_opaque_locator() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        run_sqlite_migrations(&pool).await.unwrap();
        seed_sqlite_demo(&pool).await.unwrap();
        sqlx::query("INSERT INTO evidence_storage_backend_config (tenant_id,backend_id,backend_type,display_name,status,endpoint_reference,region,bucket_name,key_prefix,access_key_secret_ref,secret_key_secret_ref,allow_path_style,allowed_endpoint_policy) VALUES (1,'minio-test','s3_compatible','MinIO Test','ready','http://127.0.0.1:9000','us-east-1','iscy-test','iscy','env:ISCY_EVIDENCE_OBJECT_STORAGE_ACCESS_KEY','env:ISCY_EVIDENCE_OBJECT_STORAGE_SECRET_KEY',1,'local_dev_only')")
            .execute(&pool).await.unwrap();
        let store = EvidenceStore::from_sqlite_pool(pool.clone());
        let runtime = store
            .reserve_s3_runtime_object(1, 1, "minio-test", 1, &"a".repeat(64), "text/plain")
            .await
            .unwrap();
        assert_eq!(runtime.tenant_id, 1);
        assert_eq!(runtime.opaque_object_id.len(), 32);
        assert!(!runtime.object_key_redacted.contains("tenants/1/evidence/1"));
        assert!(store.s3_runtime_object(2, 1).await.unwrap().is_none());
        let completed = store
            .complete_s3_upload(1, 1, 1, 12, &"a".repeat(64))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(completed.upload_status, "upload_completed");
        assert!(store.claim_s3_delete(1, 1).await.unwrap());
        assert!(!store.claim_s3_delete(1, 1).await.unwrap());
        assert!(!store.claim_s3_delete(2, 1).await.unwrap());
        store
            .release_s3_delete_claim(1, 1, "backend_unavailable")
            .await
            .unwrap();
        assert!(store.claim_s3_delete(1, 1).await.unwrap());
        let stored_ref: String = sqlx::query_scalar(
            "SELECT storage_object_reference FROM evidence_evidenceitem WHERE tenant_id=1 AND id=1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(stored_ref, runtime.opaque_object_id);
    }
}
