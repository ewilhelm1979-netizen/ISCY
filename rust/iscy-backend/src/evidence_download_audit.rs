//! Committed tenant-bound download decisions. No locator or secret payloads.
use crate::{evidence_store::EvidenceStore, request_context::AuthenticatedTenantContext};
use serde_json::json;

#[derive(Clone, Copy)]
pub enum DownloadBackend {
    Local,
    S3Compatible { hash_verified: bool },
}

impl DownloadBackend {
    fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::S3Compatible { .. } => "s3_compatible",
        }
    }
}

#[derive(Clone, Copy)]
pub enum DownloadDecision {
    Prepared(usize),
    Denied(&'static str),
}

impl DownloadDecision {
    pub fn labels(self) -> (&'static str, &'static str) {
        match self {
            Self::Prepared(_) => ("allow", "response_prepared"),
            Self::Denied(reason) => ("deny", reason),
        }
    }
}

pub async fn record_download_decision(
    store: &EvidenceStore,
    context: &AuthenticatedTenantContext,
    evidence_id: i64,
    decision: DownloadDecision,
    backend: DownloadBackend,
) -> anyhow::Result<bool> {
    let (label, reason) = decision.labels();
    let event_type = match (backend, label) {
        (DownloadBackend::Local, "allow") => "local_download_allowed",
        (DownloadBackend::Local, _) => "local_download_denied",
        (DownloadBackend::S3Compatible { .. }, "allow") => "storage_object_downloaded",
        (DownloadBackend::S3Compatible { .. }, _) => "storage_object_download_denied",
    };
    let mut detail = json!({
        "schema_version": 1, "storage_backend": backend.label(), "decision": label,
        "reason": reason, "response_delivery_confirmed": false,
    });
    if let DownloadDecision::Prepared(size_bytes) = decision {
        detail["size_bytes"] = json!(size_bytes);
        if let DownloadBackend::S3Compatible { hash_verified } = backend {
            detail["hash_verified"] = json!(hash_verified);
            detail["object_key_exposed"] = json!(false);
        }
    }
    // INSERT SELECT scopes the write itself, including when the object vanished
    // between the lookup and this statement. A suppressed insert is not success.
    match store {
        EvidenceStore::Postgres(pool) => {
            let mut tx = pool.begin().await?;
            let result = sqlx::query(
                "INSERT INTO evidence_integrity_event (tenant_id, evidence_id, event_type, actor_id, detail_json) \
                 SELECT tenant_id, id, $3, $4, $5::jsonb FROM evidence_evidenceitem WHERE tenant_id = $1 AND id = $2"
            ).bind(context.tenant_id).bind(evidence_id).bind(event_type).bind(context.user_id).bind(detail.to_string()).execute(&mut *tx).await?;
            if result.rows_affected() != 1 {
                return Ok(false);
            }
            tx.commit().await?;
        }
        EvidenceStore::Sqlite(pool) => {
            let mut tx = pool.begin().await?;
            let result = sqlx::query(
                "INSERT INTO evidence_integrity_event (tenant_id, evidence_id, event_type, actor_id, detail_json) \
                 SELECT tenant_id, id, ?3, ?4, ?5 FROM evidence_evidenceitem WHERE tenant_id = ?1 AND id = ?2"
            ).bind(context.tenant_id).bind(evidence_id).bind(event_type).bind(context.user_id).bind(detail.to_string()).execute(&mut *tx).await?;
            if result.rows_affected() != 1 {
                return Ok(false);
            }
            tx.commit().await?;
        }
    }
    Ok(true)
}
