use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use iscy_backend::{app_router_with_state, db_admin, report_store::ReportStore, AppState};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, sqlite::SqlitePoolOptions, PgPool, SqlitePool};
use std::time::Duration;
use tower::ServiceExt;

enum Database {
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

type AuditRow = (
    i64,
    i64,
    Option<i64>,
    String,
    String,
    Option<i64>,
    String,
    String,
);

impl Database {
    fn store(&self) -> ReportStore {
        match self {
            Self::Sqlite(pool) => ReportStore::from_sqlite_pool(pool.clone()),
            Self::Postgres(pool) => ReportStore::Postgres(pool.clone()),
        }
    }

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

    async fn fixture(&self) {
        self.execute(
            "INSERT INTO reports_managementreviewpackage
            (id,tenant_id,title,status,decision_notes,next_actions,created_at,updated_at)
            VALUES (21,42,'F06 review','DRAFT','original notes','original actions',
                    '2001-01-01T00:00:00Z','2001-01-02T00:00:00Z'),
                   (22,99,'Foreign review','DRAFT','','',
                    '2001-01-01T00:00:00Z','2001-01-02T00:00:00Z');
            INSERT INTO management_review_audit_event
                (tenant_id,review_id,action,actor_id,detail,created_at)
            VALUES (42,21,'fixture_created',8,'preserve existing audit','2001-01-01T00:00:00Z')",
        )
        .await;
    }

    async fn reset(&self, approved: bool) {
        self.execute("DELETE FROM management_review_audit_event WHERE action='management_review_status_changed'").await;
        let approval = if approved {
            "status='APPROVED',approved_by_id=8,approved_at='2001-01-01T12:00:00Z'"
        } else {
            "status='DRAFT',approved_by_id=NULL,approved_at=NULL"
        };
        self.execute(&format!(
            "UPDATE reports_managementreviewpackage SET {approval},
            decision_notes='original notes',next_actions='original actions',
            updated_at='2001-01-02T00:00:00Z' WHERE id=21 AND tenant_id=42"
        ))
        .await;
    }

    async fn review(&self, tenant: i64, id: i64) -> Value {
        serde_json::to_value(
            self.store()
                .management_review_detail(tenant, id)
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap()
    }

    async fn audits(&self) -> Vec<AuditRow> {
        let sql = "SELECT id,tenant_id,review_id,template_type,action,actor_id,detail,
                          CAST(created_at AS TEXT) FROM management_review_audit_event ORDER BY id";
        match self {
            Self::Sqlite(pool) => sqlx::query_as(sql).fetch_all(pool).await.unwrap(),
            Self::Postgres(pool) => sqlx::query_as(sql).fetch_all(pool).await.unwrap(),
        }
    }

    async fn fault(&self, update: bool, silent: bool) {
        let (table, operation) = if update {
            ("reports_managementreviewpackage", "UPDATE")
        } else {
            ("management_review_audit_event", "INSERT")
        };
        match self {
            Self::Sqlite(_) => {
                let failure = if silent {
                    "RAISE(IGNORE)"
                } else {
                    "RAISE(ABORT,'F06_SYNTHETIC_SQL_DETAIL')"
                };
                self.execute(&format!(
                    "CREATE TRIGGER iscy_f06_fault BEFORE {operation} ON {table}
                    BEGIN SELECT {failure}; END"
                ))
                .await;
            }
            Self::Postgres(_) => {
                let failure = if silent {
                    "RETURN NULL;"
                } else {
                    "RAISE EXCEPTION 'F06_SYNTHETIC_SQL_DETAIL';"
                };
                self.execute(&format!(
                    "CREATE FUNCTION iscy_f06_fault() RETURNS trigger LANGUAGE plpgsql
                    AS $$ BEGIN {failure} END $$;
                    CREATE TRIGGER iscy_f06_fault BEFORE {operation} ON {table}
                    FOR EACH ROW EXECUTE FUNCTION iscy_f06_fault()"
                ))
                .await;
            }
        }
    }

    async fn clear_fault(&self, update: bool) {
        match self {
            Self::Sqlite(_) => self.execute("DROP TRIGGER iscy_f06_fault").await,
            Self::Postgres(_) => {
                let table = if update {
                    "reports_managementreviewpackage"
                } else {
                    "management_review_audit_event"
                };
                self.execute(&format!(
                    "DROP TRIGGER iscy_f06_fault ON {table}; DROP FUNCTION iscy_f06_fault()"
                ))
                .await;
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Surface {
    Reports,
    Management,
    Web,
}

impl Surface {
    async fn request(
        self,
        app: &Router,
        id: i64,
        status: &str,
        identity: Option<&str>,
        notes: bool,
    ) -> (StatusCode, String) {
        let (method, uri, content_type, body) = match self {
            Self::Reports | Self::Management => {
                let prefix = if matches!(self, Self::Reports) {
                    "/api/v1/reports/management-reviews"
                } else {
                    "/api/v1/management/reviews"
                };
                let mut payload = json!({"status":status});
                if notes {
                    payload["decision_notes"] = json!("changed notes");
                    payload["next_actions"] = json!("changed actions");
                }
                (
                    "PATCH",
                    format!("{prefix}/{id}"),
                    "application/json",
                    payload.to_string(),
                )
            }
            Self::Web => {
                // Display/query identity must never authorize or scope the mutation.
                let uri = format!("/management-reviews/{id}/status?tenant_id=99&user_id=9");
                let mut body = format!("status={status}");
                if notes {
                    body.push_str("&decision_notes=changed+notes&next_actions=changed+actions");
                }
                ("POST", uri, "application/x-www-form-urlencoded", body)
            }
        };
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", content_type);
        if let Some(role) = identity {
            request = request
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .header("x-iscy-roles", role);
        }
        let response = tokio::time::timeout(
            Duration::from_secs(10),
            app.clone().oneshot(request.body(Body::from(body)).unwrap()),
        )
        .await
        .expect("F06: single-connection pool must not deadlock")
        .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    fn success(self) -> StatusCode {
        if matches!(self, Self::Web) {
            StatusCode::SEE_OTHER
        } else {
            StatusCode::OK
        }
    }
}

async fn assert_contract(db: Database) {
    db.fixture().await;
    let app = app_router_with_state(AppState::default().with_report_store(Some(db.store())));
    let foreign = db.review(99, 22).await;
    for surface in [Surface::Reports, Surface::Management, Surface::Web] {
        db.reset(false).await;
        let original = db.review(42, 21).await;
        let old_audit = db.audits().await;
        let (status, _) = surface
            .request(&app, 21, "approved", Some("ADMIN"), true)
            .await;
        assert_eq!(status, surface.success(), "{surface:?}");
        let approved = db.review(42, 21).await;
        assert_eq!(approved["status"], "APPROVED");
        assert_eq!(approved["approved_by_id"], 7);
        assert!(approved["approved_at"].is_string());
        assert_eq!(approved["decision_notes"], "changed notes");
        assert_eq!(approved["next_actions"], "changed actions");
        assert_ne!(approved["updated_at"], original["updated_at"]);
        assert_eq!(approved["created_at"], original["created_at"]);
        let audit = db.audits().await;
        assert_eq!(audit.len(), old_audit.len() + 1);
        assert_eq!(&audit[..old_audit.len()], old_audit.as_slice());
        let event = audit.last().unwrap();
        assert_eq!(
            (
                event.1,
                event.2,
                event.3.as_str(),
                event.4.as_str(),
                event.5
            ),
            (
                42,
                Some(21),
                "",
                "management_review_status_changed",
                Some(7)
            )
        );
        assert_eq!(
            serde_json::from_str::<Value>(&event.6).unwrap(),
            json!({"status":"APPROVED"})
        );
        let (status, _) = surface
            .request(&app, 21, "in-review", Some("ADMIN"), false)
            .await;
        assert_eq!(status, surface.success());
        let review = db.review(42, 21).await;
        assert_eq!(review["status"], "IN_REVIEW");
        assert_eq!(review["approved_by_id"], Value::Null);
        assert_eq!(review["approved_at"], Value::Null);
        assert_eq!(review["decision_notes"], "changed notes");
        assert_eq!(review["next_actions"], "changed actions");
        assert_eq!(db.audits().await.len(), old_audit.len() + 2);
        eprintln!("F06 {surface:?}: legitimate approval/reversion and exact audit passed");

        for (approved, update, silent) in [
            (false, false, false),
            (true, false, false),
            (false, true, false),
            (false, false, true),
        ] {
            db.reset(approved).await;
            let before = db.review(42, 21).await;
            let audits = db.audits().await;
            db.fault(update, silent).await;
            let requested = if approved { "DRAFT" } else { "APPROVED" };
            let (status, body) = surface
                .request(&app, 21, requested, Some("ADMIN"), true)
                .await;
            // Observe persisted state before HTTP classification, so the old code
            // fails for the actual atomicity defect, not merely its old 400 status.
            assert_eq!(db.review(42, 21).await, before,
                "F06 {surface:?}: complete review rollback, approved={approved}, update={update}, silent={silent}");
            assert_eq!(db.audits().await, audits, "F06: no unilateral audit change");
            assert_eq!(
                status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "{surface:?}: {body}"
            );
            assert!(!body.contains("F06_SYNTHETIC_SQL_DETAIL"));
            if !matches!(surface, Surface::Web) {
                assert_eq!(
                    serde_json::from_str::<Value>(&body).unwrap()["error_code"],
                    "database_error"
                );
            }
            db.clear_fault(update).await;
            let (status, _) = surface
                .request(&app, 21, requested, Some("ADMIN"), true)
                .await;
            assert_eq!(status, surface.success(), "retry after rollback");
            assert_eq!(db.audits().await.len(), audits.len() + 1);
        }

        db.reset(false).await;
        let before = db.review(42, 21).await;
        let audits = db.audits().await;
        for (id, input, identity, expected) in [
            (9999, "APPROVED", Some("ADMIN"), StatusCode::NOT_FOUND),
            (22, "APPROVED", Some("ADMIN"), StatusCode::NOT_FOUND),
            (21, "APPROVED", None, StatusCode::UNAUTHORIZED),
            (21, "APPROVED", Some("VIEWER"), StatusCode::FORBIDDEN),
            (21, "ARCHIVED", Some("ADMIN"), StatusCode::BAD_REQUEST),
        ] {
            let (status, _) = surface.request(&app, id, input, identity, true).await;
            if matches!(surface, Surface::Web) {
                assert_ne!(status, StatusCode::SEE_OTHER);
            } else {
                assert_eq!(status, expected, "{surface:?}, {input}, {identity:?}, {id}");
            }
            assert_eq!(db.review(42, 21).await, before);
            assert_eq!(db.review(99, 22).await, foreign);
            assert_eq!(db.audits().await, audits);
        }
        assert_eq!(db.review(99, 22).await, foreign);
        eprintln!(
            "F06 {surface:?}: error/zero-row rollback, retry and authorization matrix passed"
        );
    }
}

#[tokio::test]
async fn management_review_sqlite_atomicity() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db_admin::run_sqlite_migrations(&pool).await.unwrap();
    assert_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
#[ignore = "requires an explicit fresh disposable ISCY_TEST_POSTGRES_URL named iscy_test_f06_*"]
async fn management_review_postgres_atomicity() {
    let url =
        std::env::var("ISCY_TEST_POSTGRES_URL").expect("fresh disposable PostgreSQL URL required");
    let parsed = reqwest::Url::parse(&url).expect("valid PostgreSQL URL required");
    assert!(
        matches!(parsed.scheme(), "postgres" | "postgresql")
            && matches!(parsed.host_str(), Some("127.0.0.1" | "localhost"))
            && parsed
                .path()
                .trim_start_matches('/')
                .starts_with("iscy_test_f06_"),
        "F06 requires an explicitly named isolated loopback test database"
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let tables: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        tables, 0,
        "F06 requires a new empty database, not an existing test/audit database"
    );
    pool.close().await;
    db_admin::run_db_admin_action(&url, db_admin::DbAdminAction::Migrate)
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    assert_contract(Database::Postgres(pool)).await;
}
