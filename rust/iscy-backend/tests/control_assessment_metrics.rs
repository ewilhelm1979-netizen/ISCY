use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use iscy_backend::{
    app_router_with_state,
    auth_store::AuthStore,
    control_store::ControlStore,
    db_admin,
    hardening::{AppMode, CommunitySecurityConfig},
    AppState,
};
use serde_json::Value;
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use tower::ServiceExt;

#[tokio::test]
#[ignore = "requires fresh disposable ISCY_TEST_METRICS_POSTGRES_URL"]
async fn postgres_metrics_preserve_unknown_state_and_tenant_bound_evidence() {
    let url = std::env::var("ISCY_TEST_METRICS_POSTGRES_URL").unwrap();
    let parsed = reqwest::Url::parse(&url).unwrap();
    assert!(matches!(parsed.host_str(), Some("127.0.0.1" | "localhost")));
    assert!(parsed.path().starts_with("/iscy_test_metrics_"));
    assert!(parsed
        .query_pairs()
        .all(|(key, value)| key == "sslmode" && value == "disable"));
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(3)
        .connect(&url)
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 0, "fixture must be fresh");
    db_admin::run_db_admin_action(&url, db_admin::DbAdminAction::Migrate)
        .await
        .unwrap();
    sqlx::raw_sql("INSERT INTO organizations_tenant(id,name,slug) VALUES(42,'PG metrics','pg-metrics'),(99,'PG foreign','pg-metrics-foreign');
        INSERT INTO iscy_control_tenantstatus(tenant_id,control_id,status,maturity_score,evidence_status) VALUES(42,1,'EFFECTIVE',4,'EVIDENCED');
        INSERT INTO evidence_evidenceitem(tenant_id,control_id,title,status) VALUES(99,1,'Foreign evidence','APPROVED');")
        .execute(&pool).await.unwrap();
    let store = ControlStore::Postgres(pool.clone());
    let library = store.library(42).await.unwrap();
    assert!(library.controls[0].has_status_record);
    assert!(!library.controls[1].has_status_record);
    assert_eq!(
        library.assessment_metrics.controls_without_status_record,
        26
    );
    assert_eq!(
        library
            .assessment_metrics
            .recorded_non_excluded_average_maturity,
        Some(4.0)
    );
    assert_eq!(library.assessment_metrics.controls_with_linked_evidence, 0);
    assert_eq!(library.assessment_metrics.verified_effective_controls, None);
    let foreign = store.library(99).await.unwrap();
    assert_eq!(
        foreign
            .assessment_metrics
            .recorded_non_excluded_average_maturity,
        None
    );
    assert_eq!(foreign.assessment_metrics.controls_with_linked_evidence, 1);
    pool.close().await;
}

async fn fixture() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db_admin::run_sqlite_migrations(&pool).await.unwrap();
    sqlx::raw_sql("INSERT INTO organizations_tenant(id,name,slug) VALUES(42,'Metrics','metrics'),(99,'Foreign','metrics-foreign');
        INSERT INTO accounts_user(id,tenant_id,username,role) VALUES(42,42,'metrics-reader','AUDITOR'),(99,99,'foreign-reader','AUDITOR');
        INSERT INTO iscy_control_tenantstatus(tenant_id,control_id,status,maturity_score,evidence_status,reviewed_at)
        VALUES(42,1,'EFFECTIVE',4,'EVIDENCED','2026-11-01'),(42,2,'IMPLEMENTED',2,'MISSING','2026-11-01'),(42,3,'NOT_APPLICABLE',5,'EVIDENCED','2026-11-01');
        INSERT INTO evidence_evidenceitem(tenant_id,control_id,title,status) VALUES(42,2,'Linked draft','DRAFT'),(99,1,'Foreign file','APPROVED');")
        .execute(&pool).await.unwrap();
    pool
}

#[tokio::test]
async fn declarations_links_and_unrecorded_reviews_remain_distinct_and_tenant_scoped() {
    let pool = fixture().await;
    let store = ControlStore::from_sqlite_pool(pool.clone());
    let library = store.library(42).await.unwrap();
    let metrics = &library.assessment_metrics;
    assert_eq!(metrics.declared_implemented_controls, 2);
    assert_eq!(metrics.declared_effective_controls, 1);
    assert_eq!(metrics.declared_evidenced_controls, 2);
    assert_eq!(metrics.controls_with_linked_evidence, 1);
    assert_eq!(metrics.not_applicable_controls, 1);
    assert_eq!(metrics.non_excluded_controls, 26);
    assert_eq!(metrics.controls_without_status_record, 24);
    assert_eq!(metrics.recorded_non_excluded_controls, 2);
    assert_eq!(metrics.recorded_non_excluded_average_maturity, Some(3.0));
    assert_eq!(metrics.verified_effective_controls, None);
    assert_eq!(
        library.covered_controls, 2,
        "legacy alias stays declarative"
    );
    assert_eq!(
        library.average_maturity, 0.41,
        "legacy denominator stays compatible"
    );
    let group = library
        .groups
        .iter()
        .find(|group| group.code == "GRC")
        .unwrap();
    assert_eq!(
        group
            .assessment_metrics
            .recorded_non_excluded_average_maturity,
        Some(3.0)
    );
    assert_eq!(group.assessment_metrics.not_applicable_controls, 1);
    assert_eq!(group.assessment_metrics.controls_with_linked_evidence, 1);
    let foreign = store.library(99).await.unwrap();
    assert_eq!(foreign.assessment_metrics.controls_with_linked_evidence, 1);
    assert_eq!(foreign.assessment_metrics.declared_effective_controls, 0);
    assert_eq!(
        foreign.assessment_metrics.controls_without_status_record,
        27
    );
    assert_eq!(
        foreign
            .assessment_metrics
            .recorded_non_excluded_average_maturity,
        None
    );
    assert_eq!(foreign.assessment_metrics.verified_effective_controls, None);
    // Even an approved linked artifact plus declared status is not a control review.
    sqlx::query("INSERT INTO evidence_evidenceitem(tenant_id,control_id,title,status) VALUES(42,1,'Reviewed document','APPROVED')").execute(&pool).await.unwrap();
    assert_eq!(
        store
            .library(42)
            .await
            .unwrap()
            .assessment_metrics
            .verified_effective_controls,
        None
    );
}

#[tokio::test]
async fn all_excluded_and_empty_libraries_have_no_maturity_denominator_or_verified_zero() {
    let pool = fixture().await;
    sqlx::raw_sql("INSERT INTO iscy_control_tenantstatus(tenant_id,control_id,status,maturity_score,evidence_status)
        SELECT 42,id,'NOT_APPLICABLE',5,'MISSING' FROM iscy_control_control WHERE 1
        ON CONFLICT(tenant_id,control_id) DO UPDATE SET status='NOT_APPLICABLE',maturity_score=5;")
        .execute(&pool).await.unwrap();
    let store = ControlStore::from_sqlite_pool(pool.clone());
    let metrics = store.library(42).await.unwrap().assessment_metrics;
    assert_eq!(metrics.non_excluded_controls, 0);
    assert_eq!(metrics.not_applicable_controls, 27);
    assert_eq!(metrics.recorded_non_excluded_average_maturity, None);
    assert_eq!(metrics.verified_effective_controls, None);
    sqlx::query("UPDATE iscy_control_control SET is_active=0")
        .execute(&pool)
        .await
        .unwrap();
    let empty = store.library(42).await.unwrap();
    assert_eq!(empty.total_controls, 0);
    assert!(empty.groups.is_empty());
    assert_eq!(
        empty
            .assessment_metrics
            .recorded_non_excluded_average_maturity,
        None
    );
    assert_eq!(empty.assessment_metrics.verified_effective_controls, None);
}

#[tokio::test]
async fn api_and_web_explain_declarations_and_do_not_turn_edit_dates_into_reviews() {
    let pool = fixture().await;
    let auth = AuthStore::from_sqlite_pool(pool.clone());
    let token = auth.create_session(42, 42).await.unwrap().unwrap().token;
    let foreign_token = auth.create_session(99, 99).await.unwrap().unwrap().token;
    let app = app_router_with_state(
        AppState::default()
            .with_security_config(CommunitySecurityConfig {
                app_mode: AppMode::Production,
                trust_identity_headers: false,
                ..CommunitySecurityConfig::default()
            })
            .with_auth_store(Some(auth))
            .with_control_store(Some(ControlStore::from_sqlite_pool(pool.clone()))),
    );
    let before:String=sqlx::query_scalar("SELECT json_group_array(json_array(tenant_id,control_id,status,maturity_score,evidence_status,reviewed_at,updated_at)) FROM iscy_control_tenantstatus").fetch_one(&pool).await.unwrap();
    let request = |path: &str, token: &str| {
        Request::builder()
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    };
    let response = app
        .clone()
        .oneshot(request("/api/v1/controls?tenant_id=99", &token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 200000).await.unwrap()).unwrap();
    assert_eq!(
        value["assessment_metrics"]["declared_effective_controls"],
        1
    );
    assert_eq!(
        value["assessment_metrics"]["verified_effective_controls"],
        Value::Null
    );
    let foreign = app
        .clone()
        .oneshot(request("/api/v1/controls?tenant_id=42", &foreign_token))
        .await
        .unwrap();
    let value: Value =
        serde_json::from_slice(&to_bytes(foreign.into_body(), 200000).await.unwrap()).unwrap();
    assert_eq!(
        value["assessment_metrics"]["declared_effective_controls"],
        0
    );
    let anonymous = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/controls")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    let response = app.oneshot(request("/controls/", &token)).await.unwrap();
    let body = String::from_utf8(
        to_bytes(response.into_body(), 200000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    for text in [
        "Umgesetzt laut Angabe",
        "Wirksam laut Angabe",
        "Mit Evidence verknuepft",
        "Gepruefte Wirksamkeit",
        "Nicht erfasst",
        "Gespeicherte Reife ohne N/A",
    ] {
        assert!(body.contains(text), "missing {text}");
    }
    assert!(!body.contains("<span>Abgedeckt</span>"));
    let after:String=sqlx::query_scalar("SELECT json_group_array(json_array(tenant_id,control_id,status,maturity_score,evidence_status,reviewed_at,updated_at)) FROM iscy_control_tenantstatus").fetch_one(&pool).await.unwrap();
    assert_eq!(
        before, after,
        "read-model changes never rewrite declarations"
    );
}
