use std::{
    fs,
    path::{Component, Path as FsPath, PathBuf},
};

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{
        header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE},
        HeaderMap, HeaderName, HeaderValue, StatusCode,
    },
    response::{IntoResponse, Response},
    Json,
};
use iscy_backend::{
    evidence_download_audit::{record_download_decision, DownloadBackend, DownloadDecision},
    evidence_store::EvidenceStore,
    request_context::AuthenticatedTenantContext,
    AppState,
};
use serde_json::json;
use sqlx::{postgres::PgRow, sqlite::SqliteRow, Row};

const SESSION_COOKIE_NAME: &str = "iscy_session";
const X_CONTENT_TYPE_OPTIONS: HeaderName = HeaderName::from_static("x-content-type-options");

#[derive(Debug, Clone)]
struct EvidenceDownloadRecord {
    id: i64,
    title: String,
    file_name: String,
    sensitivity: String,
    owner_id: Option<i64>,
    reviewed_by_id: Option<i64>,
}

pub async fn download_evidence(
    Path(evidence_id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let context = match authenticated_context(&state, &headers).await {
        Ok(context) => context,
        Err(response) => {
            audit_download(None, evidence_id, None, "deny", "authentication_failed");
            return *response;
        }
    };

    download_evidence_for_context(state, evidence_id, context).await
}

async fn authenticated_context(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedTenantContext, Box<Response>> {
    let Some(token) = session_token_from_headers(headers) else {
        return Err(Box::new(error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_required",
            "Evidence-Downloads benoetigen eine gueltige ISCY-Session.",
        )));
    };
    let Some(store) = state.auth_store.as_ref() else {
        return Err(Box::new(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
            "Rust-Authentifizierung ist nicht konfiguriert.",
        )));
    };

    match store.resolve_session(&token).await {
        Ok(Some(session)) => Ok(session.tenant_context()),
        Ok(None) => Err(Box::new(error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_session",
            "ISCY-Session ist ungueltig oder abgelaufen.",
        ))),
        Err(_) => Err(Box::new(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "authentication_error",
            "ISCY-Session konnte nicht sicher validiert werden.",
        ))),
    }
}

async fn download_evidence_for_context(
    state: AppState,
    evidence_id: i64,
    context: AuthenticatedTenantContext,
) -> Response {
    if evidence_id < 1 {
        audit_download(
            Some(&context),
            evidence_id,
            None,
            "deny",
            "invalid_evidence_id",
        );
        return evidence_not_found_response();
    }

    let Some(store) = state.evidence_store.as_ref() else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "evidence_store_unavailable",
            "Rust-Evidence-Store ist nicht konfiguriert.",
        );
    };
    let record = match load_evidence_record(store, context.tenant_id, evidence_id).await {
        Ok(Some(record)) => record,
        Ok(None) => {
            audit_download(
                Some(&context),
                evidence_id,
                None,
                "deny",
                "not_found_or_foreign_tenant",
            );
            return evidence_not_found_response();
        }
        Err(_) => {
            audit_download(Some(&context), evidence_id, None, "deny", "database_error");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "evidence_database_error",
                "Evidence konnte nicht sicher gelesen werden.",
            );
        }
    };

    if !evidence_download_allowed(&context, &record) {
        let response = error_response(
            StatusCode::FORBIDDEN,
            "evidence_download_forbidden",
            "Diese Evidence-Schutzklasse darf mit der aktuellen Rolle nicht heruntergeladen werden.",
        );
        return audited_response(
            store,
            &context,
            &record,
            DownloadDecision::Denied("insufficient_sensitivity_permission"),
            response,
        )
        .await;
    }

    let Some(media_root) = state.evidence_media_root.as_ref() else {
        let response = error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "evidence_storage_unavailable",
            "Evidence-Dateispeicher ist nicht konfiguriert.",
        );
        return audited_response(
            store,
            &context,
            &record,
            DownloadDecision::Denied("storage_unavailable"),
            response,
        )
        .await;
    };
    let file_path = match resolve_evidence_path(media_root, &record.file_name) {
        Ok(path) => path,
        Err(PathResolutionError::NotFound | PathResolutionError::Unsafe) => {
            return audited_response(
                store,
                &context,
                &record,
                DownloadDecision::Denied("file_missing_or_unsafe"),
                evidence_not_found_response(),
            )
            .await;
        }
        Err(PathResolutionError::Storage) => {
            let response = error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "evidence_storage_error",
                "Evidence-Datei konnte nicht sicher aufgeloest werden.",
            );
            return audited_response(
                store,
                &context,
                &record,
                DownloadDecision::Denied("storage_error"),
                response,
            )
            .await;
        }
    };

    let read_path = file_path.clone();
    let file_bytes = match tokio::task::spawn_blocking(move || fs::read(read_path)).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(err)) if err.kind() == std::io::ErrorKind::NotFound => {
            return audited_response(
                store,
                &context,
                &record,
                DownloadDecision::Denied("file_missing"),
                evidence_not_found_response(),
            )
            .await;
        }
        Ok(Err(_)) | Err(_) => {
            let response = error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "evidence_read_error",
                "Evidence-Datei konnte nicht sicher gelesen werden.",
            );
            return audited_response(
                store,
                &context,
                &record,
                DownloadDecision::Denied("file_read_error"),
                response,
            )
            .await;
        }
    };

    let file_length = file_bytes.len();
    let download_name = safe_download_name(&record, &file_path);
    let content_type = evidence_content_type(&download_name);
    let mut response = (StatusCode::OK, Bytes::from(file_bytes)).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    response
        .headers_mut()
        .insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    if let Ok(value) = HeaderValue::from_str(content_type) {
        response.headers_mut().insert(CONTENT_TYPE, value);
    }
    if let Ok(value) = HeaderValue::from_str(&format!("attachment; filename=\"{download_name}\"")) {
        response.headers_mut().insert(CONTENT_DISPOSITION, value);
    }
    if let Ok(value) = HeaderValue::from_str(&file_length.to_string()) {
        response.headers_mut().insert(CONTENT_LENGTH, value);
    }

    audited_response(
        store,
        &context,
        &record,
        DownloadDecision::Prepared(file_length),
        response,
    )
    .await
}

// A committed event records response preparation, not client receipt of bytes.
// Unknown/foreign objects and unauthenticated requests remain runtime-only:
// they must never create an event on another tenant's Evidence.
async fn audited_response(
    store: &EvidenceStore,
    context: &AuthenticatedTenantContext,
    record: &EvidenceDownloadRecord,
    decision: DownloadDecision,
    response: Response,
) -> Response {
    if !matches!(
        persist_download_decision(store, context, record.id, decision).await,
        Ok(true)
    ) {
        audit_download(
            Some(context),
            record.id,
            Some(&record.sensitivity),
            "deny",
            "audit_persistence_failed",
        );
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "evidence_audit_unavailable",
            "Evidence-Download konnte nicht sicher protokolliert werden.",
        );
    }
    let (label, reason) = decision.labels();
    audit_download(
        Some(context),
        record.id,
        Some(&record.sensitivity),
        label,
        reason,
    );
    response
}

async fn persist_download_decision(
    store: &EvidenceStore,
    context: &AuthenticatedTenantContext,
    evidence_id: i64,
    decision: DownloadDecision,
) -> anyhow::Result<bool> {
    record_download_decision(
        store,
        context,
        evidence_id,
        decision,
        DownloadBackend::Local,
    )
    .await
}

async fn load_evidence_record(
    store: &EvidenceStore,
    tenant_id: i64,
    evidence_id: i64,
) -> anyhow::Result<Option<EvidenceDownloadRecord>> {
    match store {
        EvidenceStore::Postgres(pool) => {
            let row = sqlx::query(
                r#"
                SELECT id, title, file AS file_name, sensitivity, owner_id, reviewed_by_id
                FROM evidence_evidenceitem
                WHERE tenant_id = $1 AND id = $2
                "#,
            )
            .bind(tenant_id)
            .bind(evidence_id)
            .fetch_optional(pool)
            .await?;
            row.map(evidence_record_from_pg_row)
                .transpose()
                .map_err(Into::into)
        }
        EvidenceStore::Sqlite(pool) => {
            let row = sqlx::query(
                r#"
                SELECT id, title, file AS file_name, sensitivity, owner_id, reviewed_by_id
                FROM evidence_evidenceitem
                WHERE tenant_id = ?1 AND id = ?2
                "#,
            )
            .bind(tenant_id)
            .bind(evidence_id)
            .fetch_optional(pool)
            .await?;
            row.map(evidence_record_from_sqlite_row)
                .transpose()
                .map_err(Into::into)
        }
    }
}

fn evidence_record_from_pg_row(row: PgRow) -> Result<EvidenceDownloadRecord, sqlx::Error> {
    Ok(EvidenceDownloadRecord {
        id: row.try_get("id")?,
        title: row.try_get("title")?,
        file_name: row
            .try_get::<Option<String>, _>("file_name")?
            .unwrap_or_default(),
        sensitivity: row.try_get("sensitivity")?,
        owner_id: row.try_get("owner_id")?,
        reviewed_by_id: row.try_get("reviewed_by_id")?,
    })
}

fn evidence_record_from_sqlite_row(row: SqliteRow) -> Result<EvidenceDownloadRecord, sqlx::Error> {
    Ok(EvidenceDownloadRecord {
        id: row.try_get("id")?,
        title: row.try_get("title")?,
        file_name: row
            .try_get::<Option<String>, _>("file_name")?
            .unwrap_or_default(),
        sensitivity: row.try_get("sensitivity")?,
        owner_id: row.try_get("owner_id")?,
        reviewed_by_id: row.try_get("reviewed_by_id")?,
    })
}

fn evidence_download_allowed(
    context: &AuthenticatedTenantContext,
    record: &EvidenceDownloadRecord,
) -> bool {
    if context.is_superuser
        || context.is_staff
        || record.owner_id == Some(context.user_id)
        || record.reviewed_by_id == Some(context.user_id)
    {
        return true;
    }

    match record.sensitivity.trim().to_ascii_uppercase().as_str() {
        "PUBLIC" | "INTERNAL" => true,
        "CONFIDENTIAL" => has_any_role(
            context,
            &[
                "ADMIN",
                "MANAGEMENT",
                "CISO",
                "ISMS_MANAGER",
                "COMPLIANCE_MANAGER",
                "AUDITOR",
            ],
        ),
        "RESTRICTED" => has_any_role(
            context,
            &["ADMIN", "CISO", "ISMS_MANAGER", "COMPLIANCE_MANAGER"],
        ),
        _ => false,
    }
}

fn has_any_role(context: &AuthenticatedTenantContext, roles: &[&str]) -> bool {
    roles.iter().any(|role| context.has_role(role))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathResolutionError {
    NotFound,
    Unsafe,
    Storage,
}

fn resolve_evidence_path(
    media_root: &FsPath,
    stored_path: &str,
) -> Result<PathBuf, PathResolutionError> {
    let stored_path = stored_path.trim();
    if stored_path.is_empty() {
        return Err(PathResolutionError::NotFound);
    }
    let relative = FsPath::new(stored_path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
    {
        return Err(PathResolutionError::Unsafe);
    }

    let canonical_root = media_root.canonicalize().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            PathResolutionError::NotFound
        } else {
            PathResolutionError::Storage
        }
    })?;
    let relative = strip_repeated_root_prefix(media_root, relative);
    let candidate = canonical_root.join(relative);
    let canonical_candidate = candidate.canonicalize().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            PathResolutionError::NotFound
        } else {
            PathResolutionError::Storage
        }
    })?;
    if !canonical_candidate.starts_with(&canonical_root) || !canonical_candidate.is_file() {
        return Err(PathResolutionError::Unsafe);
    }
    Ok(canonical_candidate)
}

fn strip_repeated_root_prefix<'a>(media_root: &FsPath, relative: &'a FsPath) -> &'a FsPath {
    let Some(root_name) = media_root.file_name() else {
        return relative;
    };
    relative.strip_prefix(root_name).unwrap_or(relative)
}

fn safe_download_name(record: &EvidenceDownloadRecord, path: &FsPath) -> String {
    let source = path
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(&record.title);
    let safe = source
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .take(160)
        .collect::<String>();
    let safe = safe.trim_matches('.');
    if safe.is_empty() {
        format!("evidence-{}.bin", record.id)
    } else {
        safe.to_string()
    }
}

fn evidence_content_type(file_name: &str) -> &'static str {
    match FsPath::new(file_name)
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("pdf") => "application/pdf",
        Some("json") => "application/json",
        Some("csv") => "text/csv; charset=utf-8",
        Some("txt") | Some("log") => "text/plain; charset=utf-8",
        Some("md") => "text/markdown; charset=utf-8",
        Some("xml") => "application/xml",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("xlsx") => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        Some("docx") => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        Some("zip") => "application/zip",
        _ => "application/octet-stream",
    }
}

fn session_token_from_headers(headers: &HeaderMap) -> Option<String> {
    bearer_token_from_headers(headers).or_else(|| session_cookie_from_headers(headers))
}

fn bearer_token_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn session_cookie_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get(COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|cookie| {
                let (name, value) = cookie.trim().split_once('=')?;
                (name == SESSION_COOKIE_NAME && !value.trim().is_empty())
                    .then(|| value.trim().to_string())
            })
        })
}

fn evidence_not_found_response() -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "evidence_not_found",
        "Evidence wurde fuer diesen Tenant nicht gefunden.",
    )
}

fn error_response(status: StatusCode, error_code: &'static str, message: &'static str) -> Response {
    (
        status,
        Json(json!({
            "accepted": false,
            "api_version": "v1",
            "error_code": error_code,
            "message": message,
        })),
    )
        .into_response()
}

fn audit_download(
    context: Option<&AuthenticatedTenantContext>,
    evidence_id: i64,
    sensitivity: Option<&str>,
    decision: &'static str,
    reason: &'static str,
) {
    let tenant_id = context.map(|value| value.tenant_id).unwrap_or_default();
    let user_id = context.map(|value| value.user_id).unwrap_or_default();
    let sensitivity = sensitivity
        .map(safe_log_value)
        .unwrap_or_else(|| "unknown".to_string());
    eprintln!(
        "security_event=evidence_download decision={decision} reason={reason} tenant_id={tenant_id} user_id={user_id} evidence_id={evidence_id} sensitivity={sensitivity}"
    );
}

fn safe_log_value(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '_')
        .take(32)
        .collect::<String>()
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use std::{fs, process};

    use axum::{
        body::to_bytes,
        extract::{Path, State},
        http::{header::AUTHORIZATION, HeaderMap, HeaderValue, StatusCode},
    };
    use iscy_backend::{
        evidence_store::EvidenceStore, request_context::AuthenticatedTenantContext, AppState,
    };
    use sqlx::{sqlite::SqlitePoolOptions, Row, SqlitePool};

    use super::{
        download_evidence, download_evidence_for_context, evidence_download_allowed,
        load_evidence_record, persist_download_decision, resolve_evidence_path,
        session_token_from_headers, DownloadDecision, EvidenceDownloadRecord, PathResolutionError,
    };

    fn context(user_id: i64, role: &str) -> AuthenticatedTenantContext {
        AuthenticatedTenantContext {
            tenant_id: 1,
            user_id,
            user_email: Some(format!("user-{user_id}@example.test")),
            roles: vec![role.to_string()],
            permissions: Vec::new(),
            is_staff: false,
            is_superuser: false,
        }
    }

    fn record(sensitivity: &str, owner_id: Option<i64>) -> EvidenceDownloadRecord {
        EvidenceDownloadRecord {
            id: 7,
            title: "Security Evidence".to_string(),
            file_name: "evidence/security.txt".to_string(),
            sensitivity: sensitivity.to_string(),
            owner_id,
            reviewed_by_id: None,
        }
    }

    async fn test_evidence_store(
        evidence_id: i64,
        tenant_id: i64,
        file_name: &str,
        sensitivity: &str,
    ) -> EvidenceStore {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        fixture_store(pool, evidence_id, tenant_id, file_name, sensitivity).await
    }

    async fn fixture_store(
        pool: SqlitePool,
        evidence_id: i64,
        tenant_id: i64,
        file_name: &str,
        sensitivity: &str,
    ) -> EvidenceStore {
        sqlx::query(
            r#"
            CREATE TABLE evidence_evidenceitem (
                id INTEGER PRIMARY KEY,
                tenant_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                file TEXT NULL,
                sensitivity TEXT NOT NULL,
                owner_id INTEGER NULL,
                reviewed_by_id INTEGER NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO evidence_evidenceitem (id, tenant_id, title, file, sensitivity) VALUES (?1, ?2, 'Test Evidence', ?3, ?4)",
        )
        .bind(evidence_id)
        .bind(tenant_id)
        .bind(file_name)
        .bind(sensitivity)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE evidence_integrity_event (
            id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL,
            evidence_id INTEGER NOT NULL, event_type TEXT NOT NULL, actor_id INTEGER,
            integrity_status TEXT NOT NULL DEFAULT '', legal_hold_status TEXT NOT NULL DEFAULT '',
            disposition_status TEXT NOT NULL DEFAULT '', mismatch BOOL NOT NULL DEFAULT 0,
            error_class TEXT NOT NULL DEFAULT '', detail_json TEXT NOT NULL DEFAULT '{}',
            note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
        )
        .execute(&pool)
        .await
        .unwrap();
        EvidenceStore::from_sqlite_pool(pool)
    }

    fn sqlite_pool(store: &EvidenceStore) -> &SqlitePool {
        match store {
            EvidenceStore::Sqlite(pool) => pool,
            _ => unreachable!(),
        }
    }

    fn temporary_root() -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "iscy-download-audit-{}-{}",
            process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        root
    }

    #[test]
    fn extracts_bearer_before_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer bearer-token"),
        );
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("iscy_session=cookie-token"),
        );

        assert_eq!(
            session_token_from_headers(&headers).as_deref(),
            Some("bearer-token")
        );
    }

    #[test]
    fn restricted_evidence_requires_privileged_role_or_ownership() {
        assert!(!evidence_download_allowed(
            &context(2, "CONTRIBUTOR"),
            &record("RESTRICTED", None)
        ));
        assert!(evidence_download_allowed(
            &context(2, "CISO"),
            &record("RESTRICTED", None)
        ));
        assert!(evidence_download_allowed(
            &context(2, "CONTRIBUTOR"),
            &record("RESTRICTED", Some(2))
        ));
    }

    #[test]
    fn confidential_evidence_allows_auditor_but_restricted_does_not() {
        let auditor = context(3, "AUDITOR");
        assert!(evidence_download_allowed(
            &auditor,
            &record("CONFIDENTIAL", None)
        ));
        assert!(!evidence_download_allowed(
            &auditor,
            &record("RESTRICTED", None)
        ));
    }

    #[test]
    fn rejects_path_traversal_and_absolute_paths() {
        let root = std::env::temp_dir();
        assert_eq!(
            resolve_evidence_path(&root, "../secret.txt"),
            Err(PathResolutionError::Unsafe)
        );
        assert_eq!(
            resolve_evidence_path(&root, "/etc/passwd"),
            Err(PathResolutionError::Unsafe)
        );
    }

    #[tokio::test]
    async fn tenant_scoped_lookup_hides_foreign_evidence() {
        let store = test_evidence_store(7, 2, "foreign.txt", "INTERNAL").await;
        assert!(load_evidence_record(&store, 1, 7).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn unauthenticated_handler_returns_unauthorized() {
        let response =
            download_evidence(Path(7), State(AppState::new(None)), HeaderMap::new()).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn download_enforces_role_path_and_private_headers() {
        let store = test_evidence_store(7, 1, "evidence/proof.txt", "RESTRICTED").await;
        let root = std::env::temp_dir().join(format!(
            "iscy-evidence-download-{}-{}",
            process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("evidence")).unwrap();
        fs::write(root.join("evidence/proof.txt"), b"proof").unwrap();
        let state = AppState::new(None)
            .with_evidence_store(Some(store.clone()))
            .with_evidence_media_root(Some(root.clone()));

        let denied =
            download_evidence_for_context(state.clone(), 7, context(2, "CONTRIBUTOR")).await;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);

        let allowed = download_evidence_for_context(state, 7, context(3, "CISO")).await;
        assert_eq!(allowed.status(), StatusCode::OK);
        assert_eq!(
            allowed
                .headers()
                .get(axum::http::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("private, no-store")
        );
        assert_eq!(
            allowed
                .headers()
                .get("x-content-type-options")
                .and_then(|value| value.to_str().ok()),
            Some("nosniff")
        );
        assert!(allowed
            .headers()
            .get(axum::http::header::CONTENT_DISPOSITION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("proof.txt")));

        assert_eq!(
            to_bytes(allowed.into_body(), 4096).await.unwrap(),
            &b"proof"[..]
        );
        let events = sqlx::query("SELECT tenant_id, evidence_id, actor_id, event_type, detail_json FROM evidence_integrity_event ORDER BY id").fetch_all(sqlite_pool(&store)).await.unwrap();
        assert_eq!(events.len(), 2);
        for row in &events {
            assert_eq!(row.get::<i64, _>("tenant_id"), 1);
            assert_eq!(row.get::<i64, _>("evidence_id"), 7);
            let detail = row.get::<String, _>("detail_json");
            for secret in [
                "proof.txt",
                "Test Evidence",
                "example.test",
                root.to_str().unwrap(),
            ] {
                assert!(!detail.contains(secret));
            }
        }
        assert_eq!(events[0].get::<i64, _>("actor_id"), 2);
        assert_eq!(
            events[0].get::<String, _>("event_type"),
            "local_download_denied"
        );
        assert_eq!(events[1].get::<i64, _>("actor_id"), 3);
        assert_eq!(
            events[1].get::<String, _>("event_type"),
            "local_download_allowed"
        );
        let detail: serde_json::Value =
            serde_json::from_str(&events[1].get::<String, _>("detail_json")).unwrap();
        assert_eq!(detail["reason"], "response_prepared");
        assert_eq!(detail["size_bytes"], 5);
        assert_eq!(detail["response_delivery_confirmed"], false);

        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn foreign_missing_and_forged_identity_requests_create_no_object_audit() {
        let store = test_evidence_store(7, 2, "foreign.txt", "PUBLIC").await;
        let state = AppState::new(None).with_evidence_store(Some(store.clone()));
        for id in [7, 999, -1] {
            assert_eq!(
                download_evidence_for_context(state.clone(), id, context(3, "ADMIN"))
                    .await
                    .status(),
                StatusCode::NOT_FOUND
            );
        }
        let mut headers = HeaderMap::new();
        headers.insert("x-iscy-tenant-id", HeaderValue::from_static("2"));
        headers.insert("x-iscy-user-id", HeaderValue::from_static("3"));
        assert_eq!(
            download_evidence(Path(7), State(state), headers)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert!(!persist_download_decision(
            &store,
            &context(3, "ADMIN"),
            7,
            DownloadDecision::Prepared(1)
        )
        .await
        .unwrap());
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM evidence_integrity_event")
            .fetch_one(sqlite_pool(&store))
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn audit_insert_suppression_and_commit_failure_withhold_file_bytes() {
        for fault in ["missing_table", "suppressed_insert", "failed_commit"] {
            let store = test_evidence_store(7, 1, "proof.txt", "INTERNAL").await;
            let pool = sqlite_pool(&store);
            match fault {
                "missing_table" => {
                    sqlx::query("DROP TABLE evidence_integrity_event")
                        .execute(pool)
                        .await
                        .unwrap();
                }
                "suppressed_insert" => {
                    sqlx::query("CREATE TRIGGER suppress_audit BEFORE INSERT ON evidence_integrity_event BEGIN SELECT RAISE(IGNORE); END").execute(pool).await.unwrap();
                }
                _ => {
                    sqlx::query("CREATE TABLE audit_parent(id INTEGER PRIMARY KEY)")
                        .execute(pool)
                        .await
                        .unwrap();
                    sqlx::query("CREATE TABLE audit_commit_guard(parent_id INTEGER REFERENCES audit_parent(id) DEFERRABLE INITIALLY DEFERRED)").execute(pool).await.unwrap();
                    sqlx::query("CREATE TRIGGER fail_audit_commit AFTER INSERT ON evidence_integrity_event BEGIN INSERT INTO audit_commit_guard VALUES (999); END").execute(pool).await.unwrap();
                }
            }
            let root = temporary_root();
            fs::write(root.join("proof.txt"), b"PRIVATE EVIDENCE BYTES").unwrap();
            let state = AppState::new(None)
                .with_evidence_store(Some(store.clone()))
                .with_evidence_media_root(Some(root.clone()));
            let response = download_evidence_for_context(state, 7, context(3, "CISO")).await;
            assert_eq!(
                response.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "{fault}"
            );
            let body = to_bytes(response.into_body(), 4096).await.unwrap();
            let detail: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(detail["error_code"], "evidence_audit_unavailable");
            assert!(!String::from_utf8_lossy(&body).contains("PRIVATE EVIDENCE BYTES"));
            if fault != "missing_table" {
                let count: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM evidence_integrity_event")
                        .fetch_one(pool)
                        .await
                        .unwrap();
                assert_eq!(count, 0, "{fault}");
            }
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[tokio::test]
    async fn committed_download_audit_survives_store_reopen() {
        let root = temporary_root();
        let url = format!("sqlite://{}?mode=rwc", root.join("audit.sqlite3").display());
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let store = fixture_store(pool.clone(), 7, 1, "proof.txt", "INTERNAL").await;
        assert!(persist_download_decision(
            &store,
            &context(3, "CISO"),
            7,
            DownloadDecision::Prepared(5)
        )
        .await
        .unwrap());
        pool.close().await;
        drop(store);
        let reopened = SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let row = sqlx::query(
            "SELECT tenant_id,evidence_id,actor_id,event_type FROM evidence_integrity_event",
        )
        .fetch_one(&reopened)
        .await
        .unwrap();
        assert_eq!(row.get::<i64, _>("tenant_id"), 1);
        assert_eq!(row.get::<i64, _>("evidence_id"), 7);
        assert_eq!(row.get::<i64, _>("actor_id"), 3);
        assert_eq!(row.get::<String, _>("event_type"), "local_download_allowed");
        reopened.close().await;
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn manipulated_stored_path_is_not_downloaded() {
        let store = test_evidence_store(8, 1, "../secret.txt", "INTERNAL").await;
        let root = std::env::temp_dir().join(format!(
            "iscy-evidence-path-{}-{}",
            process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let state = AppState::new(None)
            .with_evidence_store(Some(store.clone()))
            .with_evidence_media_root(Some(root.clone()));

        let response = download_evidence_for_context(state, 8, context(2, "CONTRIBUTOR")).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let detail: String = sqlx::query_scalar(
            "SELECT detail_json FROM evidence_integrity_event WHERE tenant_id=1 AND evidence_id=8",
        )
        .fetch_one(sqlite_pool(&store))
        .await
        .unwrap();
        let detail: serde_json::Value = serde_json::from_str(&detail).unwrap();
        assert_eq!(detail["reason"], "file_missing_or_unsafe");
        assert_eq!(detail["decision"], "deny");
        assert!(!detail.to_string().contains("secret.txt"));

        fs::remove_dir_all(root).unwrap();
    }
}
