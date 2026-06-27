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
    evidence_store::EvidenceStore, request_context::AuthenticatedTenantContext, AppState,
};
use serde_json::json;
use sqlx::Row;

const SESSION_COOKIE_NAME: &str = "iscy_session";
const X_CONTENT_TYPE_OPTIONS: HeaderName = HeaderName::from_static("x-content-type-options");

#[derive(Debug, Clone)]
struct EvidenceDownloadRecord {
    id: i64,
    title: String,
    file_name: String,
    sensitivity: String,
    status: String,
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
            return response;
        }
    };

    download_evidence_for_context(state, evidence_id, context).await
}

async fn authenticated_context(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedTenantContext, Response> {
    let Some(token) = session_token_from_headers(headers) else {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_required",
            "Evidence-Downloads benoetigen eine gueltige ISCY-Session.",
        ));
    };
    let Some(store) = state.auth_store.as_ref() else {
        return Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
            "Rust-Authentifizierung ist nicht konfiguriert.",
        ));
    };

    match store.resolve_session(&token).await {
        Ok(Some(session)) => Ok(session.tenant_context()),
        Ok(None) => Err(error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_session",
            "ISCY-Session ist ungueltig oder abgelaufen.",
        )),
        Err(_) => Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "authentication_error",
            "ISCY-Session konnte nicht sicher validiert werden.",
        )),
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
            audit_download(
                Some(&context),
                evidence_id,
                None,
                "deny",
                "database_error",
            );
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "evidence_database_error",
                "Evidence konnte nicht sicher gelesen werden.",
            );
        }
    };

    if !evidence_download_allowed(&context, &record) {
        audit_download(
            Some(&context),
            record.id,
            Some(&record.sensitivity),
            "deny",
            "insufficient_sensitivity_permission",
        );
        return error_response(
            StatusCode::FORBIDDEN,
            "evidence_download_forbidden",
            "Diese Evidence-Schutzklasse darf mit der aktuellen Rolle nicht heruntergeladen werden.",
        );
    }

    let Some(media_root) = state.evidence_media_root.as_ref() else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "evidence_storage_unavailable",
            "Evidence-Dateispeicher ist nicht konfiguriert.",
        );
    };
    let file_path = match resolve_evidence_path(media_root, &record.file_name) {
        Ok(path) => path,
        Err(PathResolutionError::NotFound | PathResolutionError::Unsafe) => {
            audit_download(
                Some(&context),
                record.id,
                Some(&record.sensitivity),
                "deny",
                "file_missing_or_unsafe",
            );
            return evidence_not_found_response();
        }
        Err(PathResolutionError::Storage) => {
            audit_download(
                Some(&context),
                record.id,
                Some(&record.sensitivity),
                "deny",
                "storage_error",
            );
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "evidence_storage_error",
                "Evidence-Datei konnte nicht sicher aufgeloest werden.",
            );
        }
    };

    let read_path = file_path.clone();
    let file_bytes = match tokio::task::spawn_blocking(move || fs::read(read_path)).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(err)) if err.kind() == std::io::ErrorKind::NotFound => {
            audit_download(
                Some(&context),
                record.id,
                Some(&record.sensitivity),
                "deny",
                "file_missing",
            );
            return evidence_not_found_response();
        }
        Ok(Err(_)) | Err(_) => {
            audit_download(
                Some(&context),
                record.id,
                Some(&record.sensitivity),
                "deny",
                "file_read_error",
            );
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "evidence_read_error",
                "Evidence-Datei konnte nicht sicher gelesen werden.",
            );
        }
    };

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
    if let Ok(value) = HeaderValue::from_str(&response.body().size_hint().lower().to_string()) {
        response.headers_mut().insert(CONTENT_LENGTH, value);
    }

    audit_download(
        Some(&context),
        record.id,
        Some(&record.sensitivity),
        "allow",
        "authorized",
    );
    response
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
                SELECT id, title, file AS file_name, sensitivity, status, owner_id, reviewed_by_id
                FROM evidence_evidenceitem
                WHERE tenant_id = $1 AND id = $2
                "#,
            )
            .bind(tenant_id)
            .bind(evidence_id)
            .fetch_optional(pool)
            .await?;
            row.map(evidence_record_from_row).transpose().map_err(Into::into)
        }
        EvidenceStore::Sqlite(pool) => {
            let row = sqlx::query(
                r#"
                SELECT id, title, file AS file_name, sensitivity, status, owner_id, reviewed_by_id
                FROM evidence_evidenceitem
                WHERE tenant_id = ?1 AND id = ?2
                "#,
            )
            .bind(tenant_id)
            .bind(evidence_id)
            .fetch_optional(pool)
            .await?;
            row.map(evidence_record_from_row).transpose().map_err(Into::into)
        }
    }
}

fn evidence_record_from_row<R>(row: R) -> Result<EvidenceDownloadRecord, sqlx::Error>
where
    R: Row,
    for<'c> &'c str: sqlx::ColumnIndex<R>,
    String: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    i64: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    Option<i64>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    Option<String>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    Ok(EvidenceDownloadRecord {
        id: row.try_get("id")?,
        title: row.try_get("title")?,
        file_name: row.try_get::<Option<String>, _>("file_name")?.unwrap_or_default(),
        sensitivity: row.try_get("sensitivity")?,
        status: row.try_get("status")?,
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
            &[
                "ADMIN",
                "CISO",
                "ISMS_MANAGER",
                "COMPLIANCE_MANAGER",
            ],
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
        || relative.components().any(|component| {
            !matches!(component, Component::Normal(_) | Component::CurDir)
        })
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
    let mut safe = source
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
    safe = safe.trim_matches('.').to_string();
    if safe.is_empty() {
        format!("evidence-{}.bin", record.id)
    } else {
        safe
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
        extract::{Path, State},
        http::{header::AUTHORIZATION, HeaderMap, HeaderValue, StatusCode},
    };
    use iscy_backend::{
        evidence_store::EvidenceStore, request_context::AuthenticatedTenantContext, AppState,
    };
    use sqlx::sqlite::SqlitePoolOptions;

    use super::{
        download_evidence, download_evidence_for_context, evidence_download_allowed,
        load_evidence_record, resolve_evidence_path, session_token_from_headers,
        EvidenceDownloadRecord, PathResolutionError,
    };

    fn context(user_id: i64, role: &str) -> AuthenticatedTenantContext {
        AuthenticatedTenantContext {
            tenant_id: 1,
            user_id,
            user_email: Some(format!("user-{user_id}@example.test")),
            roles: vec![role.to_string()],
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
            status: "APPROVED".to_string(),
            owner_id,
            reviewed_by_id: None,
        }
    }

    #[test]
    fn extracts_bearer_before_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer bearer-token"));
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
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            r#"
            CREATE TABLE evidence_evidenceitem (
                id INTEGER PRIMARY KEY,
                tenant_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                file TEXT NULL,
                sensitivity TEXT NOT NULL,
                status TEXT NOT NULL,
                owner_id INTEGER NULL,
                reviewed_by_id INTEGER NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO evidence_evidenceitem (id, tenant_id, title, file, sensitivity, status) VALUES (7, 2, 'Foreign', 'foreign.txt', 'INTERNAL', 'APPROVED')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let store = EvidenceStore::from_sqlite_pool(pool);
        assert!(load_evidence_record(&store, 1, 7)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn unauthenticated_handler_returns_unauthorized() {
        let response = download_evidence(
            Path(7),
            State(AppState::new(None)),
            HeaderMap::new(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn download_enforces_role_path_and_private_headers() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            r#"
            CREATE TABLE evidence_evidenceitem (
                id INTEGER PRIMARY KEY,
                tenant_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                file TEXT NULL,
                sensitivity TEXT NOT NULL,
                status TEXT NOT NULL,
                owner_id INTEGER NULL,
                reviewed_by_id INTEGER NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO evidence_evidenceitem (id, tenant_id, title, file, sensitivity, status) VALUES (7, 1, 'Restricted', 'evidence/proof.txt', 'RESTRICTED', 'APPROVED')",
        )
        .execute(&pool)
        .await
        .unwrap();

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
            .with_evidence_store(Some(EvidenceStore::from_sqlite_pool(pool)))
            .with_evidence_media_root(Some(root.clone()));

        let denied = download_evidence_for_context(state.clone(), 7, context(2, "CONTRIBUTOR"))
            .await;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);

        let allowed = download_evidence_for_context(state, 7, context(3, "CISO")).await;
        assert_eq!(allowed.status(), StatusCode::OK);
        assert_eq!(
            allowed.headers().get(axum::http::header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("private, no-store"))
        );
        assert_eq!(
            allowed.headers().get("x-content-type-options"),
            Some(&HeaderValue::from_static("nosniff"))
        );
        assert!(allowed
            .headers()
            .get(axum::http::header::CONTENT_DISPOSITION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("proof.txt")));

        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn manipulated_stored_path_is_not_downloaded() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            r#"
            CREATE TABLE evidence_evidenceitem (
                id INTEGER PRIMARY KEY,
                tenant_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                file TEXT NULL,
                sensitivity TEXT NOT NULL,
                status TEXT NOT NULL,
                owner_id INTEGER NULL,
                reviewed_by_id INTEGER NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO evidence_evidenceitem (id, tenant_id, title, file, sensitivity, status) VALUES (8, 1, 'Manipulated', '../secret.txt', 'INTERNAL', 'APPROVED')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let root = std::env::temp_dir().join(format!("iscy-evidence-path-{}", process::id()));
        fs::create_dir_all(&root).unwrap();
        let state = AppState::new(None)
            .with_evidence_store(Some(EvidenceStore::from_sqlite_pool(pool)))
            .with_evidence_media_root(Some(root.clone()));

        let response = download_evidence_for_context(state, 8, context(2, "CONTRIBUTOR"))
            .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        fs::remove_dir_all(root).unwrap();
    }
}