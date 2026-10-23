//! Rust restoration of the pre-cutover SoA workflow, not a compliance decision.
use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use sqlx::{QueryBuilder, Row};

use crate::assessment_store::AssessmentStore;

#[derive(Debug, Serialize)]
pub struct SoaSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub title: String,
    pub version: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
pub struct SoaDocument {
    #[serde(flatten)]
    pub summary: SoaSummary,
    pub session_id: Option<i64>,
    pub approved_by_id: Option<i64>,
    pub approved_at: Option<String>,
    pub notes: String,
    pub entries: Vec<SoaEntry>,
}

#[derive(Debug, Serialize)]
pub struct SoaEntry {
    pub id: i64,
    pub soa_id: i64,
    pub requirement_id: i64,
    pub requirement_code: String,
    pub requirement_title: String,
    pub is_applicable: bool,
    pub justification: String,
    pub implementation_status: String,
    pub control_owner_id: Option<i64>,
    pub evidence_reference: String,
    pub notes: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoaGenerateRequest {
    pub title: Option<String>,
}

/// A complete control-review form, matching the former Django form contract.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoaEntryWriteRequest {
    pub is_applicable: bool,
    pub justification: String,
    pub implementation_status: String,
    pub control_owner_id: Option<i64>,
    pub evidence_reference: String,
    pub notes: String,
}

#[derive(Debug)]
struct InvalidSoaInput(&'static str);

impl std::fmt::Display for InvalidSoaInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for InvalidSoaInput {}

#[derive(Debug)]
struct LockedSoa;

impl std::fmt::Display for LockedSoa {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Nur eine SoA im Status DRAFT darf bearbeitet werden. Gepruefte und freigegebene Staende bleiben unveraendert.")
    }
}

impl std::error::Error for LockedSoa {}

// Only this module's new queries are shared. Existing stores are not refactored.
macro_rules! database {
    ($store:expr, $pool:ident, $db:ident, $body:block) => {
        match $store {
            AssessmentStore::Postgres($pool) => {
                type $db = sqlx::Postgres;
                $body
            }
            AssessmentStore::Sqlite($pool) => {
                type $db = sqlx::Sqlite;
                $body
            }
        }
    };
}

macro_rules! summary {
    ($row:ident) => {
        SoaSummary {
            id: $row.try_get("id")?,
            tenant_id: $row.try_get("tenant_id")?,
            title: $row.try_get("title")?,
            version: $row.try_get("version")?,
            status: $row.try_get("status")?,
            created_at: $row.try_get("created_at")?,
            updated_at: $row.try_get("updated_at")?,
        }
    };
}

const DOCUMENT_SELECT: &str = "SELECT d.id,d.tenant_id,d.title,d.version,d.status,
    CAST(d.created_at AS TEXT) AS created_at,CAST(d.updated_at AS TEXT) AS updated_at,
    d.session_id,d.approved_by_id,CAST(d.approved_at AS TEXT) AS approved_at,d.notes
    FROM assessments_soadocument d WHERE d.tenant_id=";

impl AssessmentStore {
    pub async fn soa_documents(&self, tenant_id: i64) -> anyhow::Result<Vec<SoaSummary>> {
        database!(self, pool, Db, {
            let rows = QueryBuilder::<Db>::new(DOCUMENT_SELECT)
                .push_bind(tenant_id)
                .push(" ORDER BY d.created_at DESC,d.id DESC LIMIT 200")
                .build()
                .fetch_all(pool)
                .await?;
            rows.into_iter()
                .map(|row| Ok(summary!(row)))
                .collect::<Result<Vec<_>, sqlx::Error>>()
                .map_err(Into::into)
        })
    }

    pub async fn soa_detail(
        &self,
        tenant_id: i64,
        document_id: i64,
    ) -> anyhow::Result<Option<SoaDocument>> {
        database!(self, pool, Db, {
            let Some(row) = QueryBuilder::<Db>::new(DOCUMENT_SELECT)
                .push_bind(tenant_id)
                .push(" AND d.id=")
                .push_bind(document_id)
                .build()
                .fetch_optional(pool)
                .await?
            else {
                return Ok(None);
            };
            let mut document = SoaDocument {
                summary: summary!(row),
                session_id: row.try_get("session_id")?,
                approved_by_id: row.try_get("approved_by_id")?,
                approved_at: row.try_get("approved_at")?,
                notes: row.try_get("notes")?,
                entries: Vec::new(),
            };
            let entries = QueryBuilder::<Db>::new(
                "SELECT e.id,e.soa_id,e.requirement_id,r.code,r.title,e.is_applicable,
                 e.justification,e.implementation_status,u.id AS control_owner_id,
                 e.evidence_reference,e.notes FROM assessments_soaentry e
                 JOIN assessments_soadocument d ON d.id=e.soa_id
                 JOIN requirements_app_requirement r ON r.id=e.requirement_id
                 LEFT JOIN accounts_user u ON u.id=e.control_owner_id AND u.tenant_id=d.tenant_id
                 WHERE d.tenant_id=",
            )
            .push_bind(tenant_id)
            .push(" AND d.id=")
            .push_bind(document_id)
            .push(" ORDER BY r.framework,r.code,r.id,e.id")
            .build()
            .fetch_all(pool)
            .await?;
            for row in entries {
                document.entries.push(SoaEntry {
                    id: row.try_get("id")?,
                    soa_id: row.try_get("soa_id")?,
                    requirement_id: row.try_get("requirement_id")?,
                    requirement_code: row.try_get("code")?,
                    requirement_title: row.try_get("title")?,
                    is_applicable: row.try_get("is_applicable")?,
                    justification: row.try_get("justification")?,
                    implementation_status: row.try_get("implementation_status")?,
                    control_owner_id: row.try_get("control_owner_id")?,
                    evidence_reference: row.try_get("evidence_reference")?,
                    notes: row.try_get("notes")?,
                });
            }
            Ok(Some(document))
        })
    }

    pub async fn generate_soa(
        &self,
        tenant_id: i64,
        actor_id: i64,
        request: SoaGenerateRequest,
    ) -> anyhow::Result<Option<i64>> {
        let requested_title = request.title.map(|title| title.trim().to_string());
        if requested_title.as_ref().is_some_and(|title| {
            title.is_empty() || title.chars().count() > 255 || title.contains('\0')
        }) {
            return Err(InvalidSoaInput("Der Titel muss 1 bis 255 Zeichen enthalten.").into());
        }
        database!(self, pool, Db, {
            let mut tx = pool.begin().await?;
            let Some(row) = QueryBuilder::<Db>::new(
                "SELECT t.name FROM organizations_tenant t JOIN accounts_user u ON u.tenant_id=t.id
                 WHERE t.id=",
            )
            .push_bind(tenant_id)
            .push(" AND u.id=")
            .push_bind(actor_id)
            .push(" AND u.is_active")
            .build()
            .fetch_optional(&mut *tx)
            .await?
            else {
                return Ok(None);
            };
            let tenant_name: String = row.try_get("name")?;
            let title = requested_title.unwrap_or_else(|| {
                format!("Statement of Applicability – {tenant_name}")
                    .chars()
                    .take(255)
                    .collect()
            });
            let id: i64 = QueryBuilder::<Db>::new(
                "INSERT INTO assessments_soadocument (tenant_id,title,version,status,notes,created_at,updated_at) VALUES (")
                .push_bind(tenant_id).push(",").push_bind(&title)
                .push(",'1.0','DRAFT','',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) RETURNING id")
                .build_query_scalar().fetch_optional(&mut *tx).await?
                .context("SoA-Dokument wurde nicht angelegt")?;
            // Capture the exact eligible catalog set, then require every insert.
            // A skipped/failed entry must not leave a partially generated document.
            let requirements: Vec<i64> = QueryBuilder::<Db>::new(
                "SELECT id FROM requirements_app_requirement WHERE framework='ISO27001' AND is_active ORDER BY code,id")
                .build_query_scalar().fetch_all(&mut *tx).await?;
            for requirement_id in requirements {
                let inserted = QueryBuilder::<Db>::new(
                    "INSERT INTO assessments_soaentry (soa_id,requirement_id,is_applicable,justification,
                     implementation_status,evidence_reference,notes,created_at,updated_at) VALUES (")
                    .push_bind(id).push(",").push_bind(requirement_id).push(",").push_bind(true)
                    .push(",'','NOT_STARTED','','',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)").build().execute(&mut *tx).await?;
                if inserted.rows_affected() != 1 {
                    bail!("SoA-Control wurde nicht angelegt");
                }
            }
            let audited = QueryBuilder::<Db>::new(
                "INSERT INTO assessments_soaauditevent (tenant_id,soa_id,actor_id,action) VALUES (",
            )
            .push_bind(tenant_id)
            .push(",")
            .push_bind(id)
            .push(",")
            .push_bind(actor_id)
            .push(",'soa_generated')")
            .build()
            .execute(&mut *tx)
            .await?;
            if audited.rows_affected() != 1 {
                bail!("SoA-Auditereignis wurde nicht angelegt");
            }
            tx.commit().await?;
            Ok(Some(id))
        })
    }

    pub async fn soa_entry_document(
        &self,
        tenant_id: i64,
        entry_id: i64,
    ) -> anyhow::Result<Option<i64>> {
        database!(self, pool, Db, {
            Ok(QueryBuilder::<Db>::new(
                "SELECT d.id FROM assessments_soadocument d
                JOIN assessments_soaentry e ON e.soa_id=d.id WHERE d.tenant_id=",
            )
            .push_bind(tenant_id)
            .push(" AND e.id=")
            .push_bind(entry_id)
            .build_query_scalar()
            .fetch_optional(pool)
            .await?)
        })
    }

    pub async fn update_soa_entry(
        &self,
        tenant_id: i64,
        actor_id: i64,
        entry_id: i64,
        request: SoaEntryWriteRequest,
    ) -> anyhow::Result<Option<i64>> {
        if !["NOT_STARTED", "PARTIAL", "IMPLEMENTED", "NOT_APPLICABLE"]
            .contains(&request.implementation_status.as_str())
        {
            return Err(InvalidSoaInput("Unbekannter Umsetzungsstatus.").into());
        }
        if [
            &request.justification,
            &request.evidence_reference,
            &request.notes,
        ]
        .into_iter()
        .any(|text| text.contains('\0'))
        {
            return Err(InvalidSoaInput("Textfelder duerfen kein NUL enthalten.").into());
        }
        database!(self, pool, Db, {
            let postgres = matches!(self, AssessmentStore::Postgres(_));
            let mut tx = if postgres {
                pool.begin().await?
            } else {
                // Serialize SQLite writers before reading the parent state.
                // SQLx still owns rollback-on-drop on errors and cancellation.
                pool.begin_with("BEGIN IMMEDIATE").await?
            };
            let mut parent = QueryBuilder::<Db>::new("SELECT d.id,d.status FROM assessments_soadocument d
                JOIN assessments_soaentry e ON e.soa_id=d.id JOIN accounts_user u ON u.tenant_id=d.tenant_id
                WHERE d.tenant_id=");
            parent
                .push_bind(tenant_id)
                .push(" AND e.id=")
                .push_bind(entry_id)
                .push(" AND u.id=")
                .push_bind(actor_id)
                .push(" AND u.is_active");
            if postgres {
                parent.push(" FOR UPDATE OF d");
            }
            let Some(row) = parent.build().fetch_optional(&mut *tx).await? else {
                return Ok(None);
            };
            let document_id: i64 = row.try_get("id")?;
            let status: String = row.try_get("status")?;
            if status != "DRAFT" {
                return Err(LockedSoa.into());
            }
            if let Some(owner) = request.control_owner_id {
                let exists =
                    QueryBuilder::<Db>::new("SELECT id FROM accounts_user WHERE tenant_id=")
                        .push_bind(tenant_id)
                        .push(" AND id=")
                        .push_bind(owner)
                        .build_query_scalar::<i64>()
                        .fetch_optional(&mut *tx)
                        .await?;
                if exists.is_none() {
                    return Err(InvalidSoaInput(
                        "Control-Owner gehoert nicht zum aktuellen Tenant.",
                    )
                    .into());
                }
            }
            let result = QueryBuilder::<Db>::new("UPDATE assessments_soaentry SET is_applicable=")
                .push_bind(request.is_applicable)
                .push(",justification=")
                .push_bind(request.justification)
                .push(",implementation_status=")
                .push_bind(request.implementation_status)
                .push(",control_owner_id=")
                .push_bind(request.control_owner_id)
                .push(",evidence_reference=")
                .push_bind(request.evidence_reference)
                .push(",notes=")
                .push_bind(request.notes)
                .push(",updated_at=CURRENT_TIMESTAMP WHERE id=")
                .push_bind(entry_id)
                .push(" AND soa_id=")
                .push_bind(document_id)
                .push(" AND soa_id IN (SELECT id FROM assessments_soadocument WHERE tenant_id=")
                .push_bind(tenant_id)
                .push(" AND status='DRAFT')")
                .build()
                .execute(&mut *tx)
                .await?;
            if result.rows_affected() != 1 {
                bail!("SoA-Control wurde nicht aktualisiert");
            }
            let audited = QueryBuilder::<Db>::new(
                "INSERT INTO assessments_soaauditevent (tenant_id,soa_id,actor_id,entry_id,action) VALUES (",
            )
            .push_bind(tenant_id)
            .push(",")
            .push_bind(document_id)
            .push(",")
            .push_bind(actor_id)
            .push(",")
            .push_bind(entry_id)
            .push(",'soa_entry_updated')")
            .build()
            .execute(&mut *tx)
            .await?;
            if audited.rows_affected() != 1 {
                bail!("SoA-Auditereignis wurde nicht angelegt");
            }
            tx.commit().await?;
            Ok(Some(document_id))
        })
    }
}

pub(crate) const SQLITE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS assessments_soadocument (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL REFERENCES organizations_tenant(id),
    session_id INTEGER NULL REFERENCES wizard_assessmentsession(id) ON DELETE SET NULL,
    title varchar(255) NOT NULL DEFAULT 'Statement of Applicability',
    version varchar(32) NOT NULL DEFAULT '1.0',
    status varchar(16) NOT NULL DEFAULT 'DRAFT',
    approved_by_id INTEGER NULL REFERENCES accounts_user(id) ON DELETE SET NULL,
    approved_at TEXT NULL,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_soa_document_tenant ON assessments_soadocument(tenant_id,id);
CREATE TABLE IF NOT EXISTS assessments_soaentry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    soa_id INTEGER NOT NULL REFERENCES assessments_soadocument(id) ON DELETE CASCADE,
    requirement_id INTEGER NOT NULL REFERENCES requirements_app_requirement(id),
    is_applicable bool NOT NULL DEFAULT 1,
    justification TEXT NOT NULL DEFAULT '',
    implementation_status varchar(20) NOT NULL DEFAULT 'NOT_STARTED',
    control_owner_id INTEGER NULL REFERENCES accounts_user(id) ON DELETE SET NULL,
    evidence_reference TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(soa_id,requirement_id)
);
CREATE INDEX IF NOT EXISTS idx_soa_entry_document ON assessments_soaentry(soa_id,id);
CREATE TABLE IF NOT EXISTS assessments_soaauditevent (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL REFERENCES organizations_tenant(id),
    soa_id INTEGER NOT NULL REFERENCES assessments_soadocument(id),
    actor_id INTEGER NOT NULL REFERENCES accounts_user(id),
    entry_id INTEGER NULL REFERENCES assessments_soaentry(id),
    action varchar(32) NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_soa_audit_tenant ON assessments_soaauditevent(tenant_id,soa_id,id);
"#;

pub(crate) const POSTGRES_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS assessments_soadocument (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES organizations_tenant(id),
    session_id BIGINT NULL REFERENCES wizard_assessmentsession(id) ON DELETE SET NULL,
    title varchar(255) NOT NULL DEFAULT 'Statement of Applicability',
    version varchar(32) NOT NULL DEFAULT '1.0',
    status varchar(16) NOT NULL DEFAULT 'DRAFT',
    approved_by_id BIGINT NULL REFERENCES accounts_user(id) ON DELETE SET NULL,
    approved_at TIMESTAMPTZ NULL,
    notes TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_soa_document_tenant ON assessments_soadocument(tenant_id,id);
CREATE TABLE IF NOT EXISTS assessments_soaentry (
    id BIGSERIAL PRIMARY KEY,
    soa_id BIGINT NOT NULL REFERENCES assessments_soadocument(id) ON DELETE CASCADE,
    requirement_id BIGINT NOT NULL REFERENCES requirements_app_requirement(id),
    is_applicable BOOLEAN NOT NULL DEFAULT TRUE,
    justification TEXT NOT NULL DEFAULT '',
    implementation_status varchar(20) NOT NULL DEFAULT 'NOT_STARTED',
    control_owner_id BIGINT NULL REFERENCES accounts_user(id) ON DELETE SET NULL,
    evidence_reference TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(soa_id,requirement_id)
);
CREATE INDEX IF NOT EXISTS idx_soa_entry_document ON assessments_soaentry(soa_id,id);
CREATE TABLE IF NOT EXISTS assessments_soaauditevent (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES organizations_tenant(id),
    soa_id BIGINT NOT NULL REFERENCES assessments_soadocument(id),
    actor_id BIGINT NOT NULL REFERENCES accounts_user(id),
    entry_id BIGINT NULL REFERENCES assessments_soaentry(id),
    action varchar(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_soa_audit_tenant ON assessments_soaauditevent(tenant_id,soa_id,id);
"#;

use axum::{
    extract::{Form, Json, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post, put},
    Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;

use crate::{
    authenticated_tenant_context, html_escape, request_context::AuthenticatedTenantContext,
    session_token_from_headers, web_page, write_permission_error, ApiErrorResponse, AppState,
    WebContext,
};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/assessments/soa", get(list).post(generate))
        .route("/api/v1/assessments/soa/{document_id}", get(detail))
        .route(
            "/api/v1/assessments/soa/entries/{entry_id}",
            put(update_entry),
        )
        .route("/assessments/soa/", get(web_list))
        .route("/assessments/soa/generate/", post(web_generate))
        .route("/assessments/soa/{document_id}/", get(web_detail))
        .route(
            "/assessments/soa/entry/{entry_id}/edit/",
            get(web_entry).post(web_update_entry),
        )
}

fn error(status: StatusCode, code: &'static str, message: &str) -> Response {
    (
        status,
        Json(ApiErrorResponse {
            accepted: false,
            api_version: "v1",
            error_code: code,
            message: message.to_string(),
        }),
    )
        .into_response()
}

fn store_error(err: anyhow::Error) -> Response {
    if let Some(invalid) = err.downcast_ref::<InvalidSoaInput>() {
        error(StatusCode::BAD_REQUEST, "invalid_soa_input", invalid.0)
    } else if err.is::<LockedSoa>() {
        error(
            StatusCode::CONFLICT,
            "soa_document_locked",
            &LockedSoa.to_string(),
        )
    } else {
        // Never return SQL, trigger diagnostics, credentials or internal paths.
        error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "SoA-Vorgang konnte nicht abgeschlossen werden.",
        )
    }
}

fn not_found() -> Response {
    error(
        StatusCode::NOT_FOUND,
        "soa_not_found",
        "SoA oder Control wurde fuer diesen Tenant nicht gefunden.",
    )
}

async fn access<'a>(
    state: &'a AppState,
    headers: &HeaderMap,
    write: bool,
) -> Result<(AuthenticatedTenantContext, &'a AssessmentStore), Response> {
    let context = authenticated_tenant_context(state, headers)
        .await
        .map_err(|err| error(err.status_code(), err.error_code(), err.message()))?;
    if write {
        if let Some(response) = write_permission_error(&context) {
            return Err(response);
        }
    }
    let store = state.assessment_store.as_ref().ok_or_else(|| {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_not_configured",
            "Rust-Assessment-Store ist nicht konfiguriert.",
        )
    })?;
    Ok((context, store))
}

async fn list(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (context, store) = match access(&state, &headers, false).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    match store.soa_documents(context.tenant_id).await {
        Ok(documents) => Json(json!({"api_version":"v1","tenant_id":context.tenant_id,"documents":documents,"limit":200})).into_response(),
        Err(err) => store_error(err),
    }
}

async fn generate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SoaGenerateRequest>,
) -> Response {
    let (context, store) = match access(&state, &headers, true).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    match store
        .generate_soa(context.tenant_id, context.user_id, request)
        .await
    {
        Ok(Some(id)) => (
            StatusCode::CREATED,
            Json(json!({"accepted":true,"api_version":"v1","document_id":id})),
        )
            .into_response(),
        Ok(None) => not_found(),
        Err(err) => store_error(err),
    }
}

async fn detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    let (context, store) = match access(&state, &headers, false).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    match store.soa_detail(context.tenant_id, id).await {
        Ok(Some(document)) => Json(json!({"api_version":"v1","document":document})).into_response(),
        Ok(None) => not_found(),
        Err(err) => store_error(err),
    }
}

async fn update_entry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(request): Json<SoaEntryWriteRequest>,
) -> Response {
    let (context, store) = match access(&state, &headers, true).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    match store
        .update_soa_entry(context.tenant_id, context.user_id, id, request)
        .await
    {
        Ok(Some(document_id)) => {
            Json(json!({"accepted":true,"api_version":"v1","document_id":document_id}))
                .into_response()
        }
        Ok(None) => not_found(),
        Err(err) => store_error(err),
    }
}

// Former Django forms required sessions and CSRF. Keep both properties in Rust.
// The derived token is purpose-separated and never discloses the session token.
fn form_mac(headers: &HeaderMap) -> Option<Hmac<Sha256>> {
    let token = session_token_from_headers(headers)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(token.as_bytes()).ok()?;
    mac.update(b"ISCY:soa:form:v1");
    Some(mac)
}

fn form_token(state: &AppState, headers: &HeaderMap) -> Option<String> {
    state.auth_store.as_ref()?;
    Some(BASE64.encode(form_mac(headers)?.finalize().into_bytes()))
}

fn valid_form_token(state: &AppState, headers: &HeaderMap, provided: &str) -> bool {
    if state.auth_store.is_none() || provided.len() != 44 {
        return false;
    }
    let (Some(mac), Ok(bytes)) = (form_mac(headers), BASE64.decode(provided)) else {
        return false;
    };
    mac.verify_slice(&bytes).is_ok()
}

fn csrf_error() -> Response {
    error(
        StatusCode::FORBIDDEN,
        "invalid_csrf_token",
        "Gueltige ISCY-Session und Formular-Token erforderlich.",
    )
}

fn page(context: &AuthenticatedTenantContext, body: &str) -> Response {
    let web_context = WebContext {
        tenant_id: context.tenant_id,
        user_id: context.user_id,
        user_email: context.user_email.clone(),
    };
    web_page(
        "Statement of Applicability",
        "/assessments/",
        Some(&web_context),
        body,
    )
    .into_response()
}

async fn web_list(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (context, store) = match access(&state, &headers, false).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let documents = match store.soa_documents(context.tenant_id).await {
        Ok(documents) => documents,
        Err(err) => return store_error(err),
    };
    let rows = documents
        .iter()
        .map(|document| {
            format!(
                "<tr><td><a href=\"/assessments/soa/{}/\">{}</a></td><td>{}</td><td>{}</td></tr>",
                document.id,
                html_escape(&document.title),
                html_escape(&document.version),
                html_escape(&document.status)
            )
        })
        .collect::<String>();
    let form = if context.can_write() {
        form_token(&state, &headers).map(|token| format!(r#"<form method="post" action="/assessments/soa/generate/"><input type="hidden" name="csrf_token" value="{}"><label>Titel (optional)<input name="title" maxlength="255"></label><button type="submit">Unabhaengigen Erstentwurf aus aktiven ISO27001-Requirements erzeugen</button><p>Dies erzeugt keine Nachfolgerversion eines gesperrten SoA-Dokuments. Der zugeordnete Versions-/Freigabeablauf ist noch nicht verfuegbar.</p></form>"#, html_escape(&token))).unwrap_or_else(|| "<p>Zum Schreiben im Browser ist eine ISCY-Session erforderlich.</p>".to_string())
    } else {
        String::new()
    };
    page(
        &context,
        &format!(
            r#"<section class="hero compact"><h1>Statement of Applicability</h1><p>Entwurf aus aktiven ISO27001-Requirements. Anwendbarkeit und Umsetzung je Control muessen Menschen pruefen. Keine automatische Konformitaetsentscheidung.</p></section><article class="panel wide">{}<p>Anzeige: die neuesten maximal 200 Dokumente dieses Tenants.</p><table><thead><tr><th>Dokument</th><th>Version</th><th>Status</th></tr></thead><tbody>{}</tbody></table></article>"#,
            form, rows
        ),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerateForm {
    csrf_token: String,
    title: Option<String>,
}

async fn web_generate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<GenerateForm>,
) -> Response {
    let (context, store) = match access(&state, &headers, true).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if !valid_form_token(&state, &headers, &form.csrf_token) {
        return csrf_error();
    }
    let request = SoaGenerateRequest {
        title: form.title.filter(|title| !title.trim().is_empty()),
    };
    match store
        .generate_soa(context.tenant_id, context.user_id, request)
        .await
    {
        Ok(Some(id)) => Redirect::to(&format!("/assessments/soa/{id}/")).into_response(),
        Ok(None) => not_found(),
        Err(err) => store_error(err),
    }
}

async fn web_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    let (context, store) = match access(&state, &headers, false).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let document = match store.soa_detail(context.tenant_id, id).await {
        Ok(Some(document)) => document,
        Ok(None) => return not_found(),
        Err(err) => return store_error(err),
    };
    let rows = document.entries.iter().map(|entry| {
        let action = if context.can_write() && document.summary.status == "DRAFT" { format!("<a href=\"/assessments/soa/entry/{}/edit/\">Pruefen / bearbeiten</a>", entry.id) } else { String::new() };
        format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>", html_escape(&entry.requirement_code), html_escape(&entry.requirement_title), if entry.is_applicable { "Ja" } else { "Nein" }, html_escape(&entry.implementation_status), html_escape(&entry.justification), html_escape(&entry.evidence_reference), action)
    }).collect::<String>();
    let applicable = document
        .entries
        .iter()
        .filter(|entry| entry.is_applicable)
        .count();
    let implemented = document
        .entries
        .iter()
        .filter(|entry| entry.is_applicable && entry.implementation_status == "IMPLEMENTED")
        .count();
    page(
        &context,
        &format!(
            r#"<section class="hero compact"><h1>{}</h1><p>Version {} · {} · {} Controls · {} anwendbar · {} umgesetzt</p><p>Entwurf und Entscheidungshilfe, keine automatische Konformitaetsentscheidung.</p><a href="/assessments/soa/">Alle SoA-Dokumente</a></section><article class="panel wide"><table><thead><tr><th>Control</th><th>Titel</th><th>Anwendbar</th><th>Status</th><th>Begruendung</th><th>Evidence-Verweis</th><th>Aktion</th></tr></thead><tbody>{}</tbody></table></article>"#,
            html_escape(&document.summary.title),
            html_escape(&document.summary.version),
            html_escape(&document.summary.status),
            document.entries.len(),
            applicable,
            implemented,
            rows
        ),
    )
}

async fn web_entry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    let (context, store) = match access(&state, &headers, true).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Some(token) = form_token(&state, &headers) else {
        return csrf_error();
    };
    let document_id = match store.soa_entry_document(context.tenant_id, id).await {
        Ok(Some(id)) => id,
        Ok(None) => return not_found(),
        Err(err) => return store_error(err),
    };
    let document = match store.soa_detail(context.tenant_id, document_id).await {
        Ok(Some(document)) => document,
        Ok(None) => return not_found(),
        Err(err) => return store_error(err),
    };
    if document.summary.status != "DRAFT" {
        return store_error(LockedSoa.into());
    }
    let Some(entry) = document.entries.iter().find(|entry| entry.id == id) else {
        return not_found();
    };
    let statuses = ["NOT_STARTED", "PARTIAL", "IMPLEMENTED", "NOT_APPLICABLE"]
        .iter()
        .map(|status| {
            format!(
                "<option value=\"{status}\"{}>{status}</option>",
                if entry.implementation_status == *status {
                    " selected"
                } else {
                    ""
                }
            )
        })
        .collect::<String>();
    page(
        &context,
        &format!(
            r#"<section class="hero compact"><h1>SoA-Control {}</h1><p>{}</p></section><article class="panel wide"><form method="post" action="/assessments/soa/entry/{}/edit/"><input type="hidden" name="csrf_token" value="{}"><label>Anwendbar<select name="is_applicable"><option value="true"{}>Ja</option><option value="false"{}>Nein</option></select></label><label>Begruendung<textarea name="justification">{}</textarea></label><label>Umsetzungsstatus<select name="implementation_status">{}</select></label><label>Control-Owner (User-ID dieses Tenants, optional)<input name="control_owner_id" value="{}"></label><label>Evidence-Verweis<textarea name="evidence_reference">{}</textarea></label><label>Notizen<textarea name="notes">{}</textarea></label><button type="submit">Control-Pruefung speichern</button></form></article>"#,
            html_escape(&entry.requirement_code),
            html_escape(&entry.requirement_title),
            id,
            html_escape(&token),
            if entry.is_applicable { " selected" } else { "" },
            if entry.is_applicable { "" } else { " selected" },
            html_escape(&entry.justification),
            statuses,
            entry
                .control_owner_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
            html_escape(&entry.evidence_reference),
            html_escape(&entry.notes)
        ),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryForm {
    csrf_token: String,
    is_applicable: bool,
    justification: String,
    implementation_status: String,
    control_owner_id: String,
    evidence_reference: String,
    notes: String,
}

async fn web_update_entry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Form(form): Form<EntryForm>,
) -> Response {
    let (context, store) = match access(&state, &headers, true).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if !valid_form_token(&state, &headers, &form.csrf_token) {
        return csrf_error();
    }
    let owner = if form.control_owner_id.trim().is_empty() {
        None
    } else {
        match form.control_owner_id.parse::<i64>() {
            Ok(id) if id > 0 => Some(id),
            _ => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "invalid_soa_input",
                    "Ungueltige Control-Owner-ID.",
                )
            }
        }
    };
    let request = SoaEntryWriteRequest {
        is_applicable: form.is_applicable,
        justification: form.justification,
        implementation_status: form.implementation_status,
        control_owner_id: owner,
        evidence_reference: form.evidence_reference,
        notes: form.notes,
    };
    match store
        .update_soa_entry(context.tenant_id, context.user_id, id, request)
        .await
    {
        Ok(Some(document_id)) => {
            Redirect::to(&format!("/assessments/soa/{document_id}/")).into_response()
        }
        Ok(None) => not_found(),
        Err(err) => store_error(err),
    }
}
