use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use iscy_backend::{
    app_router_with_state,
    auth_store::AuthStore,
    db_admin,
    hardening::{AppMode, CommunitySecurityConfig},
    import_store::ImportStore,
    AppState,
};
use serde_json::{json, Value};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::SqlitePoolOptions,
    PgPool, SqlitePool,
};
use tower::ServiceExt;

enum Database {
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

impl Database {
    async fn seed(&self) {
        let sql = "INSERT INTO organizations_tenant (id,name,slug) VALUES (42,'Date owner','date-owner'),(73,'Foreign dates','foreign-dates');
            INSERT INTO accounts_user (id,tenant_id,username,role) VALUES (4201,42,'date-admin','ADMIN'),(4202,42,'date-viewer','VIEWER'),(7301,73,'foreign-admin','ADMIN');
            INSERT INTO organizations_supplier (tenant_id,name,last_reviewed_at,next_review_due_at,notes) VALUES (73,'date-supplier','2020-01-02','2020-02-03','foreign unchanged');";
        match self {
            Self::Sqlite(pool) => {
                sqlx::raw_sql(sql).execute(pool).await.unwrap();
            }
            Self::Postgres(pool) => {
                sqlx::raw_sql(sql).execute(pool).await.unwrap();
            }
        }
    }

    fn stores(&self) -> (ImportStore, AuthStore) {
        match self {
            Self::Sqlite(pool) => (
                ImportStore::Sqlite(pool.clone()),
                AuthStore::Sqlite(pool.clone()),
            ),
            Self::Postgres(pool) => (
                ImportStore::Postgres(pool.clone()),
                AuthStore::Postgres(pool.clone()),
            ),
        }
    }

    async fn dates(&self, name: &str) -> (Option<String>, Option<String>) {
        match self {
            Self::Sqlite(pool) => sqlx::query_as("SELECT CAST(last_reviewed_at AS TEXT),CAST(next_review_due_at AS TEXT) FROM organizations_supplier WHERE tenant_id=42 AND name=?")
                .bind(name).fetch_one(pool).await.unwrap(),
            Self::Postgres(pool) => sqlx::query_as("SELECT last_reviewed_at::text,next_review_due_at::text FROM organizations_supplier WHERE tenant_id=42 AND name=$1")
                .bind(name).fetch_one(pool).await.unwrap(),
        }
    }

    async fn foreign_snapshot(&self) -> String {
        let sql = "SELECT CAST(id AS TEXT)||'|'||name||'|'||CAST(last_reviewed_at AS TEXT)||'|'||CAST(next_review_due_at AS TEXT)||'|'||notes||'|'||CAST(created_at AS TEXT)||'|'||CAST(updated_at AS TEXT) FROM organizations_supplier WHERE tenant_id=73";
        match self {
            Self::Sqlite(pool) => sqlx::query_scalar(sql).fetch_one(pool).await.unwrap(),
            Self::Postgres(pool) => sqlx::query_scalar(sql).fetch_one(pool).await.unwrap(),
        }
    }
}

async fn post(app: &Router, token: Option<&str>, row: Value) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/import-center/jobs?tenant_id=73&user_id=7301")
        .header("content-type", "application/json");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(
            request
                .body(Body::from(
                    json!({
                        "import_type":"suppliers", "replace_existing":false,
                        "tenant_id":73, "user_id":7301, "rows":[row]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn contract(database: &Database) {
    database.seed().await;
    let (imports, auth) = database.stores();
    let admin = auth.create_session(42, 4201).await.unwrap().unwrap();
    let viewer = auth.create_session(42, 4202).await.unwrap().unwrap();
    let app = app_router_with_state(
        AppState::default()
            .with_security_config(CommunitySecurityConfig {
                app_mode: AppMode::Production,
                trust_identity_headers: false,
                trusted_proxy_configured: false,
                secure_cookies: true,
                https_confirmed: false,
                hsts_enabled: false,
            })
            .with_auth_store(Some(auth))
            .with_import_store(Some(imports)),
    );
    let foreign_before = database.foreign_snapshot().await;
    // Production rejects untrusted identity headers outright, even with a
    // real bearer session. Do not turn on proxy trust to make a test pass.
    let response = app.clone().oneshot(Request::builder()
        .method("POST").uri("/api/v1/import-center/jobs")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", admin.token))
        .header("x-iscy-tenant-id", "73").header("x-iscy-user-id", "7301")
        .header("x-iscy-roles", "ADMIN")
        .body(Body::from(json!({"import_type":"suppliers","replace_existing":false,"rows":[{"name":"date-supplier"}]}).to_string())).unwrap())
        .await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(database.foreign_snapshot().await, foreign_before);
    for (token, expected) in [
        (None, StatusCode::UNAUTHORIZED),
        (Some(viewer.token.as_str()), StatusCode::FORBIDDEN),
    ] {
        let (status, _) = post(&app, token, json!({"name":"date-supplier"})).await;
        assert_eq!(status, expected);
        assert_eq!(database.foreign_snapshot().await, foreign_before);
    }
    let cases = [
        (
            json!({"name":"date-supplier"}),
            "date-supplier",
            None,
            None,
            1,
            0,
        ),
        (
            json!({"name":"date-supplier","last_reviewed_at":"2026-01-02","next_review_due_at":"2026-12-31"}),
            "date-supplier",
            Some("2026-01-02"),
            Some("2026-12-31"),
            0,
            1,
        ),
        (
            json!({"name":"dated-new","last_review":"2026-03-04","next_review":"2026-04-05"}),
            "dated-new",
            Some("2026-03-04"),
            Some("2026-04-05"),
            1,
            0,
        ),
        (
            json!({"name":"date-supplier","last_reviewed_at":" ","next_review_due_at":null}),
            "date-supplier",
            None,
            None,
            0,
            1,
        ),
    ];
    for (row, name, last, next, created, updated) in cases {
        let (status, response) = post(&app, Some(&admin.token), row).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "DATE_IMPORT_EXPECTED_SUCCESS: {response}"
        );
        assert_eq!(response["result"]["tenant_id"], 42);
        assert_eq!(response["result"]["created"], created);
        assert_eq!(response["result"]["updated"], updated);
        assert_eq!(response["result"]["skipped"], 0);
        assert_eq!(
            database.dates(name).await,
            (last.map(str::to_string), next.map(str::to_string))
        );
        assert_eq!(database.foreign_snapshot().await, foreign_before);
    }
    if matches!(database, Database::Postgres(_)) {
        for (field, value) in [
            ("last_reviewed_at", "2026-02-30"),
            ("next_review_due_at", "not-a-date"),
            (
                "last_reviewed_at",
                "2026-01-01');DROP TABLE organizations_supplier;--",
            ),
        ] {
            let before = database.dates("date-supplier").await;
            let mut row = json!({"name":"date-supplier"});
            row[field] = json!(value);
            let (status, response) = post(&app, Some(&admin.token), row).await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(response["error_code"], "database_error");
            assert_eq!(database.dates("date-supplier").await, before);
            assert_eq!(database.foreign_snapshot().await, foreign_before);
        }
    }
}

#[tokio::test]
async fn sqlite_supplier_date_null_update_alias_and_tenant_contract_is_unchanged() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db_admin::run_sqlite_migrations(&pool).await.unwrap();
    contract(&Database::Sqlite(pool.clone())).await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires a fresh disposable iscy_test_import_dates_* PostgreSQL database on loopback"]
async fn postgres_supplier_date_bindings_support_null_insert_update_and_tenant_scope() {
    let url =
        std::env::var("ISCY_TEST_POSTGRES_URL").expect("explicit disposable database required");
    let options = url
        .parse::<PgConnectOptions>()
        .unwrap_or_else(|_| panic!("invalid disposable database URL"));
    assert!(["127.0.0.1", "localhost"].contains(&options.get_host()));
    assert!(options
        .get_database()
        .unwrap_or_default()
        .starts_with("iscy_test_import_dates_"));
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 0, "refuse to reset/reuse an existing database");
    db_admin::run_db_admin_action(&url, db_admin::DbAdminAction::Migrate)
        .await
        .unwrap();
    let columns: Vec<(String,String)> = sqlx::query_as("SELECT column_name,data_type FROM information_schema.columns WHERE table_schema='public' AND table_name='organizations_supplier' AND column_name IN ('last_reviewed_at','next_review_due_at') ORDER BY column_name")
        .fetch_all(&pool).await.unwrap();
    assert_eq!(
        columns,
        vec![
            ("last_reviewed_at".to_string(), "date".to_string()),
            ("next_review_due_at".to_string(), "date".to_string())
        ]
    );
    contract(&Database::Postgres(pool.clone())).await;
    pool.close().await;
}
