//! Application-route checks against an owned loopback HTTP storage fixture.
//! This does not replace the separate MinIO/signature interoperability gate.
use axum::{
    body::{to_bytes, Body, Bytes},
    http::{Request, StatusCode, Uri},
    routing::get,
    Router,
};
use iscy_backend::{
    app_router_with_state, db_admin,
    evidence_store::EvidenceStore,
    hardening::{AppMode, CommunitySecurityConfig},
    AppState,
};
use sha2::{Digest, Sha256};
use sqlx::{sqlite::SqlitePoolOptions, Row, SqlitePool};
use std::sync::{
    atomic::{AtomicU16, AtomicUsize, Ordering},
    Arc, Mutex, Once,
};
use tower::ServiceExt;

const CONTENT: &[u8] = b"synthetic private S3 evidence";
static ENVIRONMENT: Once = Once::new();
struct ServerGuard(tokio::task::JoinHandle<()>);
impl Drop for ServerGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct Fixture {
    app: Router,
    pool: SqlitePool,
    gets: Arc<AtomicUsize>,
    status: Arc<AtomicU16>,
    paths: Arc<Mutex<Vec<String>>>,
    key: String,
    expected_hash: String,
    _server: ServerGuard,
}
impl Fixture {
    async fn new() -> Self {
        // This integration-test binary has its own environment; no production
        // credentials are used or inspected. Values remain synthetic and fixed.
        ENVIRONMENT.call_once(|| {
            std::env::set_var("ISCY_EVIDENCE_ALLOW_LOCAL_TEST_ENDPOINT", "true");
            std::env::set_var(
                "ISCY_EVIDENCE_OBJECT_STORAGE_ACCESS_KEY",
                "synthetic-access",
            );
            std::env::set_var(
                "ISCY_EVIDENCE_OBJECT_STORAGE_SECRET_KEY",
                "synthetic-secret",
            );
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let gets = Arc::new(AtomicUsize::new(0));
        let status = Arc::new(AtomicU16::new(200));
        let paths = Arc::new(Mutex::new(Vec::new()));
        let (observed, response_status, observed_paths) =
            (gets.clone(), status.clone(), paths.clone());
        let service = Router::new().route(
            "/{*path}",
            get(move |uri: Uri| {
                let (observed, response_status, observed_paths) = (
                    observed.clone(),
                    response_status.clone(),
                    observed_paths.clone(),
                );
                async move {
                    observed.fetch_add(1, Ordering::SeqCst);
                    observed_paths.lock().unwrap().push(uri.path().to_string());
                    (
                        StatusCode::from_u16(response_status.load(Ordering::SeqCst)).unwrap(),
                        Bytes::from_static(CONTENT),
                    )
                }
            }),
        );
        let server = ServerGuard(tokio::spawn(async move {
            axum::serve(listener, service).await.unwrap();
        }));
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        db_admin::run_sqlite_migrations(&pool).await.unwrap();
        sqlx::query("INSERT INTO evidence_evidenceitem (id,tenant_id,title,sensitivity,status) VALUES (7,1,'PRIVATE TITLE','RESTRICTED','APPROVED'), (8,1,'No object','INTERNAL','APPROVED')").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO evidence_storage_backend_config (tenant_id,backend_id,backend_type,display_name,status,endpoint_reference,region,bucket_name,key_prefix,access_key_secret_ref,secret_key_secret_ref,allow_path_style,allowed_endpoint_policy,tls_required) VALUES (1,'audit-fixture','s3_compatible','Synthetischer Test','ready',?1,'us-east-1','audit-fixture','private-prefix','env:ISCY_EVIDENCE_OBJECT_STORAGE_ACCESS_KEY','env:ISCY_EVIDENCE_OBJECT_STORAGE_SECRET_KEY',1,'local_dev_only',0)").bind(endpoint).execute(&pool).await.unwrap();
        let store = EvidenceStore::from_sqlite_pool(pool.clone());
        let expected_hash = Sha256::digest(CONTENT)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let object = store
            .reserve_s3_runtime_object(1, 7, "audit-fixture", 3, &expected_hash, "text/plain")
            .await
            .unwrap();
        let key = object.canonical_key("private-prefix").unwrap();
        store
            .complete_s3_upload(1, 7, 3, CONTENT.len() as i64, &expected_hash)
            .await
            .unwrap()
            .unwrap();
        let app = app_router_with_state(
            AppState::default()
                .with_evidence_store(Some(store))
                .with_security_config(CommunitySecurityConfig::default()),
        );
        Self {
            app,
            pool,
            gets,
            status,
            paths,
            key,
            expected_hash,
            _server: server,
        }
    }
    async fn request(&self, id: i64, tenant: i64, role: Option<&str>) -> axum::response::Response {
        let mut builder = Request::builder().uri(format!("/api/v1/evidence/{id}/storage/download"));
        if let Some(role) = role {
            builder = builder
                .header("x-iscy-tenant-id", tenant.to_string())
                .header("x-iscy-user-id", "3")
                .header("x-iscy-roles", role);
        }
        self.app
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }
    async fn events(&self) -> Vec<sqlx::sqlite::SqliteRow> {
        sqlx::query("SELECT tenant_id,evidence_id,actor_id,event_type,detail_json FROM evidence_integrity_event WHERE event_type IN ('storage_object_downloaded','storage_object_download_denied') ORDER BY id").fetch_all(&self.pool).await.unwrap()
    }
    async fn reason(&self) -> String {
        let rows = self.events().await;
        let detail: serde_json::Value =
            serde_json::from_str(&rows.last().unwrap().get::<String, _>("detail_json")).unwrap();
        detail["reason"].as_str().unwrap().to_owned()
    }
}

#[tokio::test]
async fn s3_download_audit_enforces_auth_tenant_role_and_known_object_denials() {
    let f = Fixture::new().await;
    for (id, tenant, role, status) in [
        (7, 1, None, StatusCode::UNAUTHORIZED),
        (7, 2, Some("CISO"), StatusCode::NOT_FOUND),
        (999, 1, Some("ADMIN"), StatusCode::NOT_FOUND),
        (-1, 1, Some("ADMIN"), StatusCode::NOT_FOUND),
    ] {
        assert_eq!(f.request(id, tenant, role).await.status(), status);
    }
    assert!(f.events().await.is_empty());
    let production = app_router_with_state(
        AppState::default()
            .with_evidence_store(Some(EvidenceStore::from_sqlite_pool(f.pool.clone())))
            .with_security_config(CommunitySecurityConfig {
                app_mode: AppMode::Production,
                trust_identity_headers: false,
                ..CommunitySecurityConfig::default()
            }),
    );
    let forged = production
        .oneshot(
            Request::builder()
                .uri("/api/v1/evidence/7/storage/download?tenant_id=1&user_id=3")
                .header("x-iscy-tenant-id", "1")
                .header("x-iscy-user-id", "3")
                .header("x-iscy-roles", "CISO")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(forged.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(forged.into_body(), 4096).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "untrusted_identity_headers");
    assert!(f.events().await.is_empty());
    assert_eq!(
        f.request(7, 1, Some("CONTRIBUTOR")).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(f.reason().await, "insufficient_sensitivity_permission");
    assert_eq!(
        f.request(8, 1, Some("CISO")).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(f.reason().await, "object_reference_not_found");
    sqlx::query("UPDATE evidence_s3_runtime_object SET canonical_key_sha256=?1 WHERE tenant_id=1 AND evidence_id=7").bind("0".repeat(64)).execute(&f.pool).await.unwrap();
    assert_ne!(f.request(7, 1, Some("CISO")).await.status(), StatusCode::OK);
    assert_eq!(f.reason().await, "invalid_object_key");
    sqlx::query("UPDATE evidence_s3_runtime_object SET canonical_key_sha256=?1, upload_status='upload_pending' WHERE tenant_id=1 AND evidence_id=7").bind(iscy_backend::evidence_object_storage::full_sha256(&f.key)).execute(&f.pool).await.unwrap();
    assert_eq!(
        f.request(7, 1, Some("CISO")).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(f.reason().await, "object_reference_not_found");
    sqlx::query("UPDATE evidence_s3_runtime_object SET upload_status='upload_completed' WHERE tenant_id=1 AND evidence_id=7").execute(&f.pool).await.unwrap();
    sqlx::query("UPDATE evidence_storage_backend_config SET bucket_name='invalid/bucket' WHERE tenant_id=1 AND backend_id='audit-fixture'").execute(&f.pool).await.unwrap();
    assert_ne!(f.request(7, 1, Some("CISO")).await.status(), StatusCode::OK);
    assert_eq!(f.reason().await, "backend_unavailable");
    assert_eq!(f.gets.load(Ordering::SeqCst), 0);
    for row in f.events().await {
        assert_eq!(row.get::<i64, _>("tenant_id"), 1);
        assert_eq!(row.get::<i64, _>("actor_id"), 3);
        assert_eq!(
            row.get::<String, _>("event_type"),
            "storage_object_download_denied"
        );
    }
}

#[tokio::test]
async fn s3_download_audit_records_real_hash_result_and_redacts_locators() {
    let f = Fixture::new().await;
    let allowed = f.request(7, 1, Some("CISO")).await;
    assert_eq!(allowed.status(), StatusCode::OK);
    assert_eq!(
        allowed.headers()["cache-control"],
        "private, no-store, max-age=0"
    );
    assert_eq!(allowed.headers()["x-content-type-options"], "nosniff");
    assert_eq!(to_bytes(allowed.into_body(), 4096).await.unwrap(), CONTENT);
    assert_eq!(
        *f.paths.lock().unwrap(),
        [format!("/audit-fixture/{}", f.key)]
    );
    let events = f.events().await;
    assert_eq!(events.len(), 1);
    let row = &events[0];
    assert_eq!(row.get::<i64, _>("evidence_id"), 7);
    assert_eq!(
        row.get::<String, _>("event_type"),
        "storage_object_downloaded"
    );
    let raw = row.get::<String, _>("detail_json");
    let detail: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(detail["reason"], "response_prepared");
    assert_eq!(detail["hash_verified"], true);
    assert_eq!(detail["response_delivery_confirmed"], false);
    assert_eq!(detail["object_key_exposed"], false);
    assert_eq!(detail["size_bytes"], CONTENT.len());
    for value in [
        &f.key,
        "private-prefix",
        "PRIVATE TITLE",
        "synthetic-secret",
        "ISCY_EVIDENCE_OBJECT_STORAGE",
        "127.0.0.1",
    ] {
        assert!(!raw.contains(value));
    }
    sqlx::query("UPDATE evidence_s3_runtime_object SET object_sha256='' WHERE tenant_id=1 AND evidence_id=7").execute(&f.pool).await.unwrap();
    assert_eq!(f.request(7, 1, Some("CISO")).await.status(), StatusCode::OK);
    let rows = f.events().await;
    let detail: serde_json::Value =
        serde_json::from_str(&rows.last().unwrap().get::<String, _>("detail_json")).unwrap();
    assert_eq!(detail["hash_verified"], false);
    sqlx::query("UPDATE evidence_s3_runtime_object SET object_sha256=?1 WHERE tenant_id=1 AND evidence_id=7").bind("0".repeat(64)).execute(&f.pool).await.unwrap();
    assert_ne!(f.request(7, 1, Some("CISO")).await.status(), StatusCode::OK);
    assert_eq!(f.reason().await, "hash_mismatch");
    sqlx::query("UPDATE evidence_s3_runtime_object SET object_sha256=?1 WHERE tenant_id=1 AND evidence_id=7").bind(&f.expected_hash).execute(&f.pool).await.unwrap();
    f.status.store(404, Ordering::SeqCst);
    assert_eq!(
        f.request(7, 1, Some("CISO")).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(f.reason().await, "object_fetch_failed");
}

#[tokio::test]
async fn s3_download_audit_insert_and_commit_failures_never_release_bytes() {
    let f = Fixture::new().await;
    let scenarios=[
        ("CREATE TRIGGER audit_fault BEFORE INSERT ON evidence_integrity_event BEGIN SELECT RAISE(IGNORE); END", "DROP TRIGGER audit_fault"),
        ("CREATE TRIGGER audit_fault BEFORE INSERT ON evidence_integrity_event BEGIN SELECT RAISE(ABORT,'synthetic failure'); END", "DROP TRIGGER audit_fault"),
        ("CREATE TABLE audit_parent(id INTEGER PRIMARY KEY); CREATE TABLE audit_commit_guard(parent_id INTEGER REFERENCES audit_parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER audit_fault AFTER INSERT ON evidence_integrity_event BEGIN INSERT INTO audit_commit_guard VALUES(999); END", "DROP TRIGGER audit_fault"),
        ("DROP TABLE evidence_integrity_event", ""),
    ];
    for (fault, cleanup) in scenarios {
        sqlx::raw_sql(fault).execute(&f.pool).await.unwrap();
        let response = f.request(7, 1, Some("CISO")).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let detail: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(detail["error_code"], "evidence_audit_unavailable");
        assert!(!bytes.windows(CONTENT.len()).any(|window| window == CONTENT));
        if !cleanup.is_empty() {
            assert!(f.events().await.is_empty());
            assert_eq!(
                f.request(7, 1, Some("CONTRIBUTOR")).await.status(),
                StatusCode::SERVICE_UNAVAILABLE
            );
            assert!(f.events().await.is_empty());
            sqlx::raw_sql(cleanup).execute(&f.pool).await.unwrap();
        }
    }
    assert_eq!(f.gets.load(Ordering::SeqCst), 4);
}
