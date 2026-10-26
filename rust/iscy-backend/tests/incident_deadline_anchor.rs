use std::collections::BTreeMap;

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use chrono::{DateTime, Duration};
use iscy_backend::{
    app_router_with_state,
    auth_store::AuthStore,
    db_admin,
    hardening::{AppMode, CommunitySecurityConfig},
    incident_store::IncidentStore,
    AppState,
};
use serde_json::{json, Value};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::SqlitePoolOptions,
    PgPool, Row, SqlitePool,
};
use tower::ServiceExt;

enum Database {
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

impl Database {
    async fn execute(&self, sql: &str) {
        match self {
            Self::Sqlite(pool) => {
                sqlx::raw_sql(sql).execute(pool).await.unwrap();
            }
            Self::Postgres(pool) => {
                sqlx::raw_sql(sql).execute(pool).await.unwrap();
            }
        }
    }

    async fn snapshot(&self, tenant: Option<i64>) -> BTreeMap<String, Vec<String>> {
        let mut result = BTreeMap::new();
        for table in ["incidents_incident", "incidents_incidentevent"] {
            let scope = tenant
                .map(|id| format!(" WHERE tenant_id={id}"))
                .unwrap_or_default();
            let rows = match self {
                Self::Sqlite(pool) => {
                    let columns = sqlx::query(&format!("PRAGMA table_info({table})"))
                        .fetch_all(pool)
                        .await
                        .unwrap();
                    let fields = columns
                        .iter()
                        .map(|row| {
                            let name: String = row.get("name");
                            assert!(name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
                            format!("'{name}',\"{name}\"")
                        })
                        .collect::<Vec<_>>()
                        .join(",");
                    sqlx::query_scalar(&format!(
                        "SELECT json_object({fields}) FROM {table}{scope} ORDER BY id"
                    ))
                    .fetch_all(pool)
                    .await
                    .unwrap()
                }
                Self::Postgres(pool) => sqlx::query_scalar(&format!(
                    "SELECT row_to_json(t)::text FROM {table} t{scope} ORDER BY id"
                ))
                .fetch_all(pool)
                .await
                .unwrap(),
            };
            result.insert(table.to_string(), rows);
        }
        result
    }

    async fn incident(&self, id: i64) -> Value {
        self.snapshot(None).await["incidents_incident"]
            .iter()
            .map(|raw| serde_json::from_str::<Value>(raw).unwrap())
            .find(|row| row["id"] == id)
            .unwrap()
    }

    async fn close(&self) {
        match self {
            Self::Sqlite(pool) => pool.close().await,
            Self::Postgres(pool) => pool.close().await,
        }
    }
}

struct Fixture {
    database: Database,
    app: Router,
    admin: String,
    viewer: String,
    foreign: String,
    own_id: i64,
    foreign_id: i64,
}

async fn request(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Value,
    forged: bool,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    if forged {
        request = request
            .header("x-iscy-tenant-id", "73")
            .header("x-iscy-user-id", "7301")
            .header("x-iscy-roles", "ADMIN");
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn fixture(database: Database) -> Fixture {
    database.execute("INSERT INTO organizations_tenant(id,name,slug) VALUES (42,'Deadline owner','deadline-owner'),(73,'Foreign incident','foreign-incident');
        INSERT INTO accounts_user(id,tenant_id,username,role) VALUES (4201,42,'f04-admin','ADMIN'),(4202,42,'f04-viewer','VIEWER'),(7301,73,'f04-foreign','ADMIN')").await;
    let (auth, incidents) = match &database {
        Database::Sqlite(pool) => (
            AuthStore::Sqlite(pool.clone()),
            IncidentStore::Sqlite(pool.clone()),
        ),
        Database::Postgres(pool) => (
            AuthStore::Postgres(pool.clone()),
            IncidentStore::Postgres(pool.clone()),
        ),
    };
    let admin = auth.create_session(42, 4201).await.unwrap().unwrap().token;
    let viewer = auth.create_session(42, 4202).await.unwrap().unwrap().token;
    let foreign = auth.create_session(73, 7301).await.unwrap().unwrap().token;
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
            .with_incident_store(Some(incidents)),
    );
    let mut ids = Vec::new();
    for token in [&admin, &foreign] {
        let (status, response) = request(
            &app,
            "POST",
            "/api/v1/incidents?tenant_id=73&user_id=7301",
            Some(token),
            json!({
                "title":"Synthetic deadline incident","summary":"Original summary",
                "detected_at":"2026-01-01T00:00:00Z","nis2_significance_status":"SIGNIFICANT",
                "early_warning_sent_at":"2026-01-02T00:00:00Z",
                "notification_sent_at":"2026-01-04T00:00:00Z",
                "final_report_sent_at":"2026-02-01T00:00:00Z",
                "authority_reference":"F04-SYNTHETIC-NOT-A-REAL-CASE"
            }),
            false,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "F04_FIXTURE_CREATE: {response}"
        );
        ids.push(response["incident"]["id"].as_i64().unwrap());
    }
    Fixture {
        database,
        app,
        admin,
        viewer,
        foreign,
        own_id: ids[0],
        foreign_id: ids[1],
    }
}

async fn sqlite_fixture() -> Fixture {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db_admin::run_sqlite_migrations(&pool).await.unwrap();
    fixture(Database::Sqlite(pool)).await
}

fn deadline_fields(row: &Value) -> Vec<Value> {
    [
        "detected_at",
        "early_warning_due_at",
        "notification_due_at",
        "final_report_due_at",
        "early_warning_sent_at",
        "notification_sent_at",
        "final_report_sent_at",
        "authority_reference",
    ]
    .iter()
    .map(|key| row[*key].clone())
    .collect()
}

async fn reject_clear_and_enforce_boundaries(f: &Fixture) {
    let before = f.database.snapshot(None).await;
    let uri = format!("/api/v1/incidents/{}?tenant_id=73&user_id=7301", f.own_id);
    for (token, expected) in [
        (None, StatusCode::UNAUTHORIZED),
        (Some(f.viewer.as_str()), StatusCode::FORBIDDEN),
        (Some(f.foreign.as_str()), StatusCode::NOT_FOUND),
    ] {
        let (status, _) = request(
            &f.app,
            "PATCH",
            &uri,
            token,
            json!({"summary":"must not write"}),
            false,
        )
        .await;
        assert_eq!(status, expected);
        assert_eq!(f.database.snapshot(None).await, before);
    }
    let (status, _) = request(
        &f.app,
        "PATCH",
        &format!("/api/v1/incidents/{}?tenant_id=42", f.foreign_id),
        Some(&f.admin),
        json!({"summary":"foreign target"}),
        false,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = request(
        &f.app,
        "PATCH",
        &uri,
        Some(&f.admin),
        json!({"detected_at":null}),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(f.database.snapshot(None).await, before);
    for payload in [
        json!({"detected_at":null}),
        json!({"detected_at":""}),
        json!({"detected_at":"   "}),
        json!({"detected_at":"\t\r\n"}),
        json!({"detected_at":null,"nis2_reportable":false}),
        json!({"detected_at":null,"nis2_significance_status":"NOT_SIGNIFICANT"}),
    ] {
        let (status, response) =
            request(&f.app, "PATCH", &uri, Some(&f.admin), payload, false).await;
        eprintln!("F04_CLEAR_RESULT status={status} response={response}");
        assert_eq!(
            f.database.snapshot(None).await,
            before,
            "F04_CLEAR_MUST_PRESERVE_INCIDENT_AND_AUDIT"
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response["error_code"], "incident_deadline_anchor_invalid");
    }
    // Legacy records can carry a SIGNIFICANT label but a stale false boolean.
    // A combined demotion/clear must not hide the existing relevant anchor.
    f.database
        .execute(&format!(
            "UPDATE incidents_incident SET nis2_reportable=FALSE WHERE tenant_id=42 AND id={}",
            f.own_id
        ))
        .await;
    let inconsistent_before = f.database.snapshot(None).await;
    let (status, response) = request(
        &f.app,
        "PATCH",
        &uri,
        Some(&f.admin),
        json!({"detected_at":null,"nis2_significance_status":"NOT_SIGNIFICANT"}),
        false,
    )
    .await;
    assert_eq!(
        f.database.snapshot(None).await,
        inconsistent_before,
        "F04_SIGNIFICANCE_FLAG_MISMATCH_MUST_NOT_ALLOW_CLEAR"
    );
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(response["error_code"], "incident_deadline_anchor_invalid");
    f.database
        .execute(&format!(
            "UPDATE incidents_incident SET nis2_reportable=TRUE WHERE tenant_id=42 AND id={}",
            f.own_id
        ))
        .await;
    assert_eq!(f.database.snapshot(None).await, before);
}

async fn web_empty_anchor_preserves_existing_value(f: &Fixture) {
    let full_before = f.database.snapshot(None).await;
    let before = f.database.incident(f.own_id).await;
    let foreign_before = f.database.snapshot(Some(73)).await;
    let events_before = f.database.snapshot(None).await["incidents_incidentevent"].clone();
    let build_request = |token: Option<&str>, forged: bool| {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("/incidents/{}?tenant_id=73&user_id=7301", f.own_id))
            .header("content-type", "application/x-www-form-urlencoded");
        if let Some(token) = token {
            request = request.header("cookie", format!("iscy_session={token}"));
        }
        if forged {
            request = request
                .header("x-iscy-tenant-id", "73")
                .header("x-iscy-user-id", "7301")
                .header("x-iscy-roles", "ADMIN");
        }
        request.body(Body::from("title=Synthetic+deadline+incident&summary=Must+not+clear&detected_at=&nis2_significance_status=SIGNIFICANT&nis2_reportable=on")).unwrap()
    };
    for (token, marker) in [
        (None, "Tenant-ID"),
        (Some(f.viewer.as_str()), "schreibende ISCY-Rolle"),
        (Some(f.foreign.as_str()), "wurde nicht gefunden"),
    ] {
        let response = f
            .app
            .clone()
            .oneshot(build_request(token, false))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK); // Existing HTML denial contract.
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        assert!(String::from_utf8(bytes.to_vec()).unwrap().contains(marker));
        assert_eq!(f.database.snapshot(None).await, full_before);
    }
    let response = f
        .app
        .clone()
        .oneshot(build_request(Some(&f.admin), true))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(f.database.snapshot(None).await, full_before);
    let response = f
        .app
        .clone()
        .oneshot(build_request(Some(&f.admin), false))
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    let after = f.database.incident(f.own_id).await;
    assert_eq!(deadline_fields(&after), deadline_fields(&before));
    let mut expected = before;
    expected["summary"] = json!("Must not clear");
    expected["updated_at"] = after["updated_at"].clone();
    assert_eq!(
        after, expected,
        "empty web date is already omitted, not a NULL patch"
    );
    assert_eq!(f.database.snapshot(Some(73)).await, foreign_before);
    assert_eq!(
        f.database.snapshot(None).await["incidents_incidentevent"],
        events_before
    );
}

async fn legacy_summary_keeps_deadlines(f: &Fixture) {
    let foreign_before = f.database.snapshot(Some(73)).await;
    for dues in [
        "'2001-01-02T00:00:00+00:00','2001-01-04T00:00:00+00:00','2001-01-31T00:00:00+00:00'",
        "NULL,NULL,NULL",
    ] {
        let values: Vec<_> = dues.split(',').collect();
        f.database
            .execute(&format!(
                "UPDATE incidents_incident SET detected_at=NULL,
            early_warning_due_at={},notification_due_at={},final_report_due_at={}
            WHERE tenant_id=42 AND id={}",
                values[0], values[1], values[2], f.own_id
            ))
            .await;
        let before = deadline_fields(&f.database.incident(f.own_id).await);
        for payload in [
            json!({"summary":"First unrelated update"}),
            json!({"status":"CONTAINED","summary":"Second unrelated update"}),
            json!({"detected_at":null}),
        ] {
            let (status, response) = request(
                &f.app,
                "PATCH",
                &format!("/api/v1/incidents/{}", f.own_id),
                Some(&f.admin),
                payload,
                false,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{response}");
            assert_eq!(
                deadline_fields(&f.database.incident(f.own_id).await),
                before,
                "F04_LEGACY_DEADLINES_MUST_NOT_MOVE"
            );
            assert_eq!(f.database.snapshot(Some(73)).await, foreign_before);
        }
    }
    // A legacy row has no authority to invent a new recognition time when
    // being newly classified as significant. No created_at/now backfill.
    let uri = format!("/api/v1/incidents/{}", f.own_id);
    let (status, _) = request(
        &f.app,
        "PATCH",
        &uri,
        Some(&f.admin),
        json!({"nis2_significance_status":"NOT_SIGNIFICANT"}),
        false,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let before = f.database.snapshot(None).await;
    let (status, response) = request(
        &f.app,
        "PATCH",
        &uri,
        Some(&f.admin),
        json!({"nis2_significance_status":"SIGNIFICANT"}),
        false,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "F04_NO_NEW_NOW_ANCHOR: {response}"
    );
    assert_eq!(f.database.snapshot(None).await, before);
}

async fn legitimate_correction_and_review(f: &Fixture) {
    let foreign_before = f.database.snapshot(Some(73)).await;
    let uri = format!("/api/v1/incidents/{}?tenant_id=73&user_id=7301", f.own_id);
    let original = f.database.incident(f.own_id).await;
    for payload in [
        json!({"summary":"Only summary"}),
        json!({"status":"CONTAINED"}),
        json!({"detected_at":"2026-01-01T02:00:00+02:00"}),
    ] {
        let (status, response) =
            request(&f.app, "PATCH", &uri, Some(&f.admin), payload, false).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        let current = f.database.incident(f.own_id).await;
        for field in [
            "early_warning_due_at",
            "notification_due_at",
            "final_report_due_at",
            "early_warning_sent_at",
            "notification_sent_at",
            "final_report_sent_at",
            "authority_reference",
        ] {
            assert_eq!(current[field], original[field], "{field}");
        }
    }
    let (status, response) = request(
        &f.app,
        "PATCH",
        &uri,
        Some(&f.admin),
        json!({"detected_at":"2026-01-02T00:00:00Z"}),
        false,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(
        response["incident"]["early_warning_due_at"],
        "2026-01-03T00:00:00+00:00"
    );
    assert_eq!(
        response["incident"]["notification_due_at"],
        "2026-01-05T00:00:00+00:00"
    );
    assert_eq!(
        response["incident"]["final_report_due_at"],
        "2026-02-01T00:00:00+00:00"
    );
    let (status,response)=request(&f.app,"PATCH",&uri,Some(&f.admin),json!({"nis2_significance_status":"NOT_SIGNIFICANT","nis2_significance_justification":"Synthetic reviewed classification"}),false).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["incident"]["review_state"], "IN_REVIEW");
    for field in [
        "early_warning_due_at",
        "notification_due_at",
        "final_report_due_at",
    ] {
        assert!(response["incident"][field].is_null());
    }
    let (status, response) = request(
        &f.app,
        "PATCH",
        &uri,
        Some(&f.admin),
        json!({"nis2_significance_status":"SIGNIFICANT"}),
        false,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    for field in [
        "early_warning_sent_at",
        "notification_sent_at",
        "final_report_sent_at",
        "authority_reference",
    ] {
        assert_eq!(response["incident"][field], original[field]);
    }
    assert_eq!(f.database.snapshot(Some(73)).await, foreign_before);
    let (status, response) = request(
        &f.app,
        "POST",
        "/api/v1/incidents",
        Some(&f.admin),
        json!({"title":"One-time creation anchor","nis2_reportable":true}),
        false,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{response}");
    let base = DateTime::parse_from_rfc3339(response["incident"]["detected_at"].as_str().unwrap())
        .unwrap();
    for (field, interval) in [
        ("early_warning_due_at", Duration::hours(24)),
        ("notification_due_at", Duration::hours(72)),
        ("final_report_due_at", Duration::days(30)),
    ] {
        let due =
            DateTime::parse_from_rfc3339(response["incident"][field].as_str().unwrap()).unwrap();
        assert_eq!(due - base, interval);
    }
}

#[tokio::test]
async fn sqlite_reportable_incident_cannot_clear_anchor_and_preserves_boundaries() {
    let f = sqlite_fixture().await;
    reject_clear_and_enforce_boundaries(&f).await;
    f.database.close().await;
}

#[tokio::test]
async fn sqlite_web_empty_anchor_preserves_deadlines_and_allows_summary_update() {
    let f = sqlite_fixture().await;
    web_empty_anchor_preserves_existing_value(&f).await;
    f.database.close().await;
}

#[tokio::test]
async fn sqlite_legacy_summary_does_not_replace_deadlines_with_now() {
    let f = sqlite_fixture().await;
    legacy_summary_keeps_deadlines(&f).await;
    f.database.close().await;
}

#[tokio::test]
async fn sqlite_legitimate_correction_review_and_creation_intervals_are_preserved() {
    let f = sqlite_fixture().await;
    legitimate_correction_and_review(&f).await;
    f.database.close().await;
}

#[tokio::test]
#[ignore = "requires a fresh disposable iscy_test_f04_* PostgreSQL database on loopback"]
async fn postgres_incident_anchor_api_web_legacy_and_review_contract() {
    let url =
        std::env::var("ISCY_TEST_POSTGRES_URL").expect("explicit disposable database required");
    let options = url
        .parse::<PgConnectOptions>()
        .unwrap_or_else(|_| panic!("invalid fixture URL"));
    assert!(["127.0.0.1", "localhost"].contains(&options.get_host()));
    assert!(options
        .get_database()
        .unwrap_or_default()
        .starts_with("iscy_test_f04_"));
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
        .unwrap();
    let tables: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(tables, 0, "refuse to reset/reuse an existing database");
    db_admin::run_db_admin_action(&url, db_admin::DbAdminAction::Migrate)
        .await
        .unwrap();
    let f = fixture(Database::Postgres(pool)).await;
    reject_clear_and_enforce_boundaries(&f).await;
    web_empty_anchor_preserves_existing_value(&f).await;
    legitimate_correction_and_review(&f).await;
    legacy_summary_keeps_deadlines(&f).await;
    f.database.close().await;
}
