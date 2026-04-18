use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use iscy_backend::{
    app_router, app_router_with_state, assessment_store::AssessmentStore, asset_store::AssetStore,
    cve_store::CveStore, dashboard_store::DashboardStore, evidence_store::EvidenceStore,
    process_store::ProcessStore, report_store::ReportStore, risk_store::RiskStore,
    roadmap_store::RoadmapStore, tenant_store::TenantStore, AppState,
};
use sqlx::{sqlite::SqlitePoolOptions, Row, SqlitePool};
use tower::util::ServiceExt;

#[tokio::test]
async fn health_endpoint_returns_ok() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn health_alias_endpoint_returns_ok() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn context_whoami_returns_anonymous_context_without_headers() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/context/whoami")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["api_version"], "v1");
    assert_eq!(payload["authenticated"], false);
    assert_eq!(payload["tenant_id"], serde_json::Value::Null);
    assert_eq!(payload["user_id"], serde_json::Value::Null);
}

#[tokio::test]
async fn context_whoami_reads_tenant_and_user_headers() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/context/whoami")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .header("x-iscy-user-email", "security@example.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["authenticated"], true);
    assert_eq!(payload["tenant_id"], 42);
    assert_eq!(payload["user_id"], 7);
    assert_eq!(payload["user_email"], "security@example.test");
}

#[tokio::test]
async fn context_whoami_rejects_invalid_tenant_header() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/context/whoami")
                .header("x-iscy-tenant-id", "tenant-a")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["accepted"], false);
    assert_eq!(payload["api_version"], "v1");
    assert_eq!(payload["error_code"], "invalid_tenant_id");
}

#[tokio::test]
async fn context_tenant_requires_user_header() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/context/tenant")
                .header("x-iscy-tenant-id", "42")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["accepted"], false);
    assert_eq!(payload["api_version"], "v1");
    assert_eq!(payload["error_code"], "missing_user_context");
}

#[tokio::test]
async fn context_tenant_requires_tenant_header() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/context/tenant")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["accepted"], false);
    assert_eq!(payload["api_version"], "v1");
    assert_eq!(payload["error_code"], "missing_tenant_context");
}

#[tokio::test]
async fn context_tenant_returns_authenticated_tenant_context() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/context/tenant")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .header("x-iscy-user-email", "security@example.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["api_version"], "v1");
    assert_eq!(payload["authenticated"], true);
    assert_eq!(payload["tenant_id"], 42);
    assert_eq!(payload["user_id"], 7);
    assert_eq!(payload["user_email"], "security@example.test");
    assert_eq!(
        payload["authorization_model"],
        "header-bridged-django-context-v1"
    );
}

#[tokio::test]
async fn organization_tenant_profile_requires_authenticated_tenant_context() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/organizations/tenant-profile")
                .header("x-iscy-tenant-id", "42")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "missing_user_context");
}

#[tokio::test]
async fn organization_tenant_profile_requires_configured_database() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/organizations/tenant-profile")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "database_not_configured");
}

#[tokio::test]
async fn organization_tenant_profile_returns_tenant_from_database() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_tenant_table(&pool).await;
    insert_tenant(&pool).await;
    let app = app_router_with_state(AppState::with_stores(
        None,
        Some(TenantStore::from_sqlite_pool(pool.clone())),
    ));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/organizations/tenant-profile")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["api_version"], "v1");
    assert_eq!(payload["tenant"]["id"], 42);
    assert_eq!(payload["tenant"]["name"], "Tenant SOC");
    assert_eq!(payload["tenant"]["slug"], "tenant-soc");
    assert_eq!(payload["tenant"]["operation_countries"][0], "DE");
    assert_eq!(payload["tenant"]["sector"], "MSSP");
    assert_eq!(payload["tenant"]["nis2_relevant"], true);
    assert_eq!(payload["tenant"]["uses_ai_systems"], true);
}

#[tokio::test]
async fn organization_tenant_profile_returns_not_found_for_unknown_tenant() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_tenant_table(&pool).await;
    let app = app_router_with_state(AppState::with_stores(
        None,
        Some(TenantStore::from_sqlite_pool(pool.clone())),
    ));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/organizations/tenant-profile")
                .header("x-iscy-tenant-id", "99")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "tenant_not_found");
}

#[tokio::test]
async fn dashboard_summary_requires_authenticated_tenant_context() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/dashboard/summary")
                .header("x-iscy-tenant-id", "42")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "missing_user_context");
}

#[tokio::test]
async fn dashboard_summary_requires_configured_database() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/dashboard/summary")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "database_not_configured");
}

#[tokio::test]
async fn dashboard_summary_returns_counts_from_database() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_dashboard_tables(&pool).await;
    insert_dashboard_fixture(&pool).await;
    let app = app_router_with_state(
        AppState::default()
            .with_dashboard_store(Some(DashboardStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/dashboard/summary")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["api_version"], "v1");
    assert_eq!(payload["tenant_id"], 42);
    assert_eq!(payload["process_count"], 2);
    assert_eq!(payload["asset_count"], 3);
    assert_eq!(payload["open_risk_count"], 2);
    assert_eq!(payload["evidence_count"], 4);
    assert_eq!(payload["open_task_count"], 2);
    assert_eq!(payload["latest_report"]["id"], 11);
    assert_eq!(payload["latest_report"]["title"], "April Readiness");
    assert_eq!(payload["latest_report"]["iso_readiness_percent"], 78);
    assert_eq!(payload["latest_report"]["nis2_readiness_percent"], 82);
}

#[tokio::test]
async fn asset_inventory_requires_authenticated_tenant_context() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/assets/information-assets")
                .header("x-iscy-tenant-id", "42")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "missing_user_context");
}

#[tokio::test]
async fn asset_inventory_requires_configured_database() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/assets/information-assets")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "database_not_configured");
}

#[tokio::test]
async fn asset_inventory_returns_tenant_assets_from_database() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_asset_tables(&pool).await;
    insert_asset_fixture(&pool).await;
    let app = app_router_with_state(
        AppState::default().with_asset_store(Some(AssetStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/assets/information-assets")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["api_version"], "v1");
    assert_eq!(payload["tenant_id"], 42);
    assert_eq!(payload["assets"].as_array().unwrap().len(), 2);
    assert_eq!(payload["assets"][0]["name"], "Customer Portal");
    assert_eq!(payload["assets"][0]["asset_type_label"], "Anwendung");
    assert_eq!(payload["assets"][0]["criticality_label"], "Hoch");
    assert_eq!(
        payload["assets"][0]["business_unit_name"],
        "Digital Services"
    );
    assert_eq!(payload["assets"][0]["owner_display"], "Ada Lovelace");
    assert_eq!(payload["assets"][0]["is_in_scope"], true);
    assert_eq!(payload["assets"][1]["name"], "Data Lake");
    assert_eq!(
        payload["assets"][1]["business_unit_name"],
        serde_json::Value::Null
    );
}

#[tokio::test]
async fn process_register_requires_authenticated_tenant_context() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/processes")
                .header("x-iscy-tenant-id", "42")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "missing_user_context");
}

#[tokio::test]
async fn process_register_requires_configured_database() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/processes")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "database_not_configured");
}

#[tokio::test]
async fn process_register_returns_tenant_processes_from_database() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_process_tables(&pool).await;
    insert_process_fixture(&pool).await;
    let app = app_router_with_state(
        AppState::default().with_process_store(Some(ProcessStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/processes")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["api_version"], "v1");
    assert_eq!(payload["tenant_id"], 42);
    assert_eq!(payload["processes"].as_array().unwrap().len(), 2);
    assert_eq!(payload["processes"][0]["name"], "Incident Intake");
    assert_eq!(
        payload["processes"][0]["status_label"],
        "Vorhanden, aber unvollständig"
    );
    assert_eq!(
        payload["processes"][0]["business_unit_name"],
        "Security Operations"
    );
    assert_eq!(payload["processes"][0]["owner_display"], "Ada Lovelace");
    assert_eq!(payload["processes"][0]["documented"], true);
    assert_eq!(payload["processes"][1]["name"], "Triage");
}

#[tokio::test]
async fn process_detail_returns_process_from_database() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_process_tables(&pool).await;
    insert_process_fixture(&pool).await;
    let app = app_router_with_state(
        AppState::default().with_process_store(Some(ProcessStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/processes/10")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["api_version"], "v1");
    assert_eq!(payload["process"]["id"], 10);
    assert_eq!(payload["process"]["tenant_id"], 42);
    assert_eq!(payload["process"]["name"], "Incident Intake");
    assert_eq!(payload["process"]["description"], "SOC intake process");
    assert_eq!(payload["process"]["reviewed_at"], "2026-04-18");
    assert_eq!(payload["process"]["evidenced"], false);
}

#[tokio::test]
async fn process_detail_blocks_foreign_tenant_process() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_process_tables(&pool).await;
    insert_process_fixture(&pool).await;
    let app = app_router_with_state(
        AppState::default().with_process_store(Some(ProcessStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/processes/12")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "process_not_found");
}

#[tokio::test]
async fn risk_register_requires_authenticated_tenant_context() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/risks")
                .header("x-iscy-tenant-id", "42")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "missing_user_context");
}

#[tokio::test]
async fn risk_register_requires_configured_database() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/risks")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "database_not_configured");
}

#[tokio::test]
async fn risk_register_returns_tenant_risks_from_database() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_risk_tables(&pool).await;
    insert_risk_fixture(&pool).await;
    let app = app_router_with_state(
        AppState::default().with_risk_store(Some(RiskStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/risks")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["api_version"], "v1");
    assert_eq!(payload["tenant_id"], 42);
    assert_eq!(payload["risks"].as_array().unwrap().len(), 2);
    assert_eq!(payload["risks"][0]["title"], "Credential Phishing");
    assert_eq!(payload["risks"][0]["score"], 20);
    assert_eq!(payload["risks"][0]["risk_level"], "CRITICAL");
    assert_eq!(payload["risks"][0]["risk_level_label"], "Kritisch");
    assert_eq!(payload["risks"][0]["category_name"], "Cyber Risk");
    assert_eq!(payload["risks"][0]["process_name"], "Incident Intake");
    assert_eq!(payload["risks"][0]["asset_name"], "Customer Portal");
    assert_eq!(payload["risks"][0]["owner_display"], "Ada Lovelace");
    assert_eq!(payload["risks"][1]["title"], "Supplier Delay");
}

#[tokio::test]
async fn risk_detail_returns_risk_from_database() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_risk_tables(&pool).await;
    insert_risk_fixture(&pool).await;
    let app = app_router_with_state(
        AppState::default().with_risk_store(Some(RiskStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/risks/10")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["api_version"], "v1");
    assert_eq!(payload["risk"]["id"], 10);
    assert_eq!(payload["risk"]["tenant_id"], 42);
    assert_eq!(payload["risk"]["title"], "Credential Phishing");
    assert_eq!(
        payload["risk"]["description"],
        "Credential theft can disrupt SOC operations"
    );
    assert_eq!(payload["risk"]["impact_label"], "5 – Kritisch");
    assert_eq!(payload["risk"]["likelihood_label"], "4 – Wahrscheinlich");
    assert_eq!(payload["risk"]["residual_score"], 6);
    assert_eq!(payload["risk"]["treatment_strategy_label"], "Mindern");
    assert_eq!(payload["risk"]["review_date"], "2026-05-01");
}

#[tokio::test]
async fn risk_detail_blocks_foreign_tenant_risk() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_risk_tables(&pool).await;
    insert_risk_fixture(&pool).await;
    let app = app_router_with_state(
        AppState::default().with_risk_store(Some(RiskStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/risks/12")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "risk_not_found");
}

#[tokio::test]
async fn evidence_overview_requires_authenticated_tenant_context() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/evidence")
                .header("x-iscy-tenant-id", "42")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "missing_user_context");
}

#[tokio::test]
async fn evidence_overview_requires_configured_database() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/evidence")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "database_not_configured");
}

#[tokio::test]
async fn evidence_overview_returns_tenant_evidence_from_database() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_evidence_tables(&pool).await;
    insert_evidence_fixture(&pool).await;
    let app = app_router_with_state(
        AppState::default()
            .with_evidence_store(Some(EvidenceStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/evidence")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["api_version"], "v1");
    assert_eq!(payload["tenant_id"], 42);
    assert_eq!(payload["session_id"], serde_json::Value::Null);
    assert_eq!(payload["evidence_items"].as_array().unwrap().len(), 2);
    assert_eq!(
        payload["evidence_items"][0]["title"],
        "MFA Rollout Screenshot"
    );
    assert_eq!(payload["evidence_items"][0]["status_label"], "Freigegeben");
    assert_eq!(
        payload["evidence_items"][0]["owner_display"],
        "Ada Lovelace"
    );
    assert_eq!(
        payload["evidence_items"][0]["requirement_framework"],
        "ISO27001"
    );
    assert_eq!(payload["evidence_items"][0]["mapping_program_name"], "ISCY");
    assert_eq!(payload["evidence_needs"].as_array().unwrap().len(), 3);
    assert_eq!(payload["need_summary"]["open"], 1);
    assert_eq!(payload["need_summary"]["partial"], 1);
    assert_eq!(payload["need_summary"]["covered"], 1);
}

#[tokio::test]
async fn evidence_overview_filters_by_session() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_evidence_tables(&pool).await;
    insert_evidence_fixture(&pool).await;
    let app = app_router_with_state(
        AppState::default()
            .with_evidence_store(Some(EvidenceStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/evidence?session_id=100")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["session_id"], 100);
    assert_eq!(payload["evidence_items"].as_array().unwrap().len(), 1);
    assert_eq!(payload["evidence_items"][0]["session_id"], 100);
    assert_eq!(payload["evidence_needs"].as_array().unwrap().len(), 2);
    assert_eq!(payload["need_summary"]["open"], 1);
    assert_eq!(payload["need_summary"]["partial"], 0);
    assert_eq!(payload["need_summary"]["covered"], 1);
}

#[tokio::test]
async fn assessment_applicability_requires_authenticated_tenant_context() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/assessments/applicability")
                .header("x-iscy-tenant-id", "42")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "missing_user_context");
}

#[tokio::test]
async fn assessment_applicability_requires_configured_database() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/assessments/applicability")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "database_not_configured");
}

#[tokio::test]
async fn assessment_applicability_returns_tenant_rows_from_database() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_assessment_tables(&pool).await;
    insert_assessment_fixture(&pool).await;
    let app = app_router_with_state(
        AppState::default()
            .with_assessment_store(Some(AssessmentStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/assessments/applicability")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["api_version"], "v1");
    assert_eq!(payload["tenant_id"], 42);
    assert_eq!(payload["items"].as_array().unwrap().len(), 1);
    assert_eq!(payload["items"][0]["tenant_name"], "Tenant SOC");
    assert_eq!(payload["items"][0]["sector"], "MSSP");
    assert_eq!(
        payload["items"][0]["status_label"],
        "Voraussichtlich relevant"
    );
}

#[tokio::test]
async fn assessment_register_requires_authenticated_tenant_context() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/assessments")
                .header("x-iscy-tenant-id", "42")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "missing_user_context");
}

#[tokio::test]
async fn assessment_register_requires_configured_database() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/assessments")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "database_not_configured");
}

#[tokio::test]
async fn assessment_register_returns_tenant_assessments_from_database() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_assessment_tables(&pool).await;
    insert_assessment_fixture(&pool).await;
    let app = app_router_with_state(
        AppState::default()
            .with_assessment_store(Some(AssessmentStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/assessments")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["tenant_id"], 42);
    assert_eq!(payload["items"].as_array().unwrap().len(), 2);
    assert_eq!(payload["items"][0]["process_name"], "Incident Intake");
    assert_eq!(payload["items"][0]["requirement_framework"], "ISO27001");
    assert_eq!(payload["items"][0]["status_label"], "Teilweise erfüllt");
    assert_eq!(payload["items"][0]["owner_display"], "Ada Lovelace");
    assert_eq!(payload["items"][1]["requirement_code"], "21.2");
}

#[tokio::test]
async fn assessment_measures_requires_authenticated_tenant_context() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/assessments/measures")
                .header("x-iscy-tenant-id", "42")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "missing_user_context");
}

#[tokio::test]
async fn assessment_measures_requires_configured_database() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/assessments/measures")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "database_not_configured");
}

#[tokio::test]
async fn assessment_measures_return_tenant_measures_from_database() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_assessment_tables(&pool).await;
    insert_assessment_fixture(&pool).await;
    let app = app_router_with_state(
        AppState::default()
            .with_assessment_store(Some(AssessmentStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/assessments/measures")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["tenant_id"], 42);
    assert_eq!(payload["items"].as_array().unwrap().len(), 2);
    assert_eq!(payload["items"][0]["title"], "Policy aktualisieren");
    assert_eq!(payload["items"][0]["status_label"], "Done");
    assert_eq!(payload["items"][1]["title"], "MFA ausrollen");
    assert_eq!(payload["items"][1]["priority_label"], "High");
    assert_eq!(payload["items"][1]["status_label"], "Open");
    assert_eq!(payload["items"][1]["due_date"], "2026-05-01");
}

#[tokio::test]
async fn roadmap_plans_requires_authenticated_tenant_context() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/roadmap/plans")
                .header("x-iscy-tenant-id", "42")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "missing_user_context");
}

#[tokio::test]
async fn roadmap_plans_requires_configured_database() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/roadmap/plans")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "database_not_configured");
}

#[tokio::test]
async fn roadmap_plans_return_tenant_roadmaps_from_database() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_roadmap_tables(&pool).await;
    insert_roadmap_fixture(&pool).await;
    let app = app_router_with_state(
        AppState::default().with_roadmap_store(Some(RoadmapStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/roadmap/plans")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["api_version"], "v1");
    assert_eq!(payload["tenant_id"], 42);
    assert_eq!(payload["plans"].as_array().unwrap().len(), 2);
    assert_eq!(payload["plans"][0]["title"], "Security Roadmap");
    assert_eq!(payload["plans"][0]["tenant_name"], "Tenant SOC");
    assert_eq!(payload["plans"][0]["phase_count"], 2);
    assert_eq!(payload["plans"][0]["task_count"], 3);
    assert_eq!(payload["plans"][0]["open_task_count"], 2);
    assert_eq!(payload["plans"][1]["title"], "Earlier Roadmap");
}

#[tokio::test]
async fn roadmap_plan_detail_returns_tenant_roadmap_tree_from_database() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_roadmap_tables(&pool).await;
    insert_roadmap_fixture(&pool).await;
    let app = app_router_with_state(
        AppState::default().with_roadmap_store(Some(RoadmapStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/roadmap/plans/10")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["api_version"], "v1");
    assert_eq!(payload["plan"]["id"], 10);
    assert_eq!(payload["plan"]["tenant_id"], 42);
    assert_eq!(payload["plan"]["title"], "Security Roadmap");
    assert_eq!(payload["phases"].as_array().unwrap().len(), 2);
    assert_eq!(payload["phases"][0]["name"], "Governance");
    assert_eq!(payload["phases"][0]["task_count"], 2);
    assert_eq!(payload["tasks"].as_array().unwrap().len(), 3);
    assert_eq!(payload["tasks"][0]["title"], "Policy aktualisieren");
    assert_eq!(payload["tasks"][0]["status_label"], "Offen");
    assert_eq!(payload["tasks"][1]["incoming_dependency_count"], 1);
    assert_eq!(payload["dependencies"].as_array().unwrap().len(), 1);
    assert_eq!(
        payload["dependencies"][0]["predecessor_title"],
        "Policy aktualisieren"
    );
    assert_eq!(
        payload["dependencies"][0]["dependency_type_label"],
        "Finish-to-Start"
    );
}

#[tokio::test]
async fn roadmap_plan_detail_blocks_foreign_tenant_roadmap() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_roadmap_tables(&pool).await;
    insert_roadmap_fixture(&pool).await;
    let app = app_router_with_state(
        AppState::default().with_roadmap_store(Some(RoadmapStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/roadmap/plans/12")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "roadmap_not_found");
}

#[tokio::test]
async fn report_snapshots_require_authenticated_tenant_context() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/reports/snapshots")
                .header("x-iscy-tenant-id", "42")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "missing_user_context");
}

#[tokio::test]
async fn report_snapshots_require_configured_database() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/reports/snapshots")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "database_not_configured");
}

#[tokio::test]
async fn report_snapshots_return_tenant_reports_from_database() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_report_table(&pool).await;
    insert_report_fixture(&pool).await;
    let app = app_router_with_state(
        AppState::default().with_report_store(Some(ReportStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/reports/snapshots")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["api_version"], "v1");
    assert_eq!(payload["tenant_id"], 42);
    assert_eq!(payload["reports"].as_array().unwrap().len(), 2);
    assert_eq!(payload["reports"][0]["id"], 11);
    assert_eq!(payload["reports"][0]["title"], "April Readiness");
    assert_eq!(payload["reports"][0]["iso_readiness_percent"], 78);
    assert_eq!(payload["reports"][1]["id"], 10);
}

#[tokio::test]
async fn report_snapshot_detail_returns_report_from_database() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_report_table(&pool).await;
    insert_report_fixture(&pool).await;
    let app = app_router_with_state(
        AppState::default().with_report_store(Some(ReportStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/reports/snapshots/11")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["api_version"], "v1");
    assert_eq!(payload["report"]["id"], 11);
    assert_eq!(payload["report"]["tenant_id"], 42);
    assert_eq!(
        payload["report"]["executive_summary"],
        "April Executive Summary"
    );
    assert_eq!(payload["report"]["kritis_readiness_percent"], 33);
    assert_eq!(
        payload["report"]["compliance_versions_json"]["ISO27001"]["version"],
        "2022"
    );
    assert_eq!(
        payload["report"]["top_measures_json"][0]["title"],
        "MFA einfuehren"
    );
    assert_eq!(
        payload["report"]["domain_scores_json"][0]["domain"],
        "Governance"
    );
}

#[tokio::test]
async fn report_snapshot_detail_blocks_foreign_tenant_report() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_report_table(&pool).await;
    insert_report_fixture(&pool).await;
    let app = app_router_with_state(
        AppState::default().with_report_store(Some(ReportStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/reports/snapshots/12")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "report_not_found");
}

#[tokio::test]
async fn rust_web_surface_routes_return_ok() {
    let paths = vec![
        "/",
        "/login/",
        "/navigator/",
        "/dashboard/",
        "/catalog/",
        "/reports/",
        "/roadmap/",
        "/evidence/",
        "/assets/",
        "/imports/",
        "/processes/",
        "/requirements/",
        "/risks/",
        "/assessments/",
        "/organizations/",
        "/product-security/",
        "/cves/",
    ];
    for path in paths {
        let response = app_router()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "path {}", path);
    }
}

#[tokio::test]
async fn nvd_import_endpoint_normalizes_cve_id() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/nvd/import")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"cve_id":" cve-2026-9999 "}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn nvd_normalize_endpoint_returns_versioned_payload() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/nvd/normalize")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"cve_id":" cve-2026-4242 "}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["accepted"], true);
    assert_eq!(payload["api_version"], "v1");
    assert_eq!(payload["cve_id"], "CVE-2026-4242");
}

#[tokio::test]
async fn nvd_normalize_endpoint_rejects_invalid_cve_id_with_error_code() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/nvd/normalize")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"cve_id":"not-a-cve"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["accepted"], false);
    assert_eq!(payload["api_version"], "v1");
    assert_eq!(payload["error_code"], "invalid_cve_id");
}

#[tokio::test]
async fn nvd_upsert_endpoint_requires_configured_database() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/nvd/upsert")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"cve":{"id":"CVE-2026-4242"}}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["accepted"], false);
    assert_eq!(payload["api_version"], "v1");
    assert_eq!(payload["error_code"], "database_not_configured");
}

#[tokio::test]
async fn nvd_upsert_endpoint_persists_cve_record() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_cverecord_table(&pool).await;
    let app = app_router_with_state(AppState::new(Some(CveStore::from_sqlite_pool(
        pool.clone(),
    ))));

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/nvd/upsert")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{
                        "cve": {
                            "id": " cve-2026-4242 ",
                            "descriptions": [{"lang": "en", "value": "Rust persisted CVE"}],
                            "metrics": {
                                "cvssMetricV31": [{
                                    "baseSeverity": "HIGH",
                                    "cvssData": {
                                        "baseScore": 8.1,
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                                    }
                                }]
                            },
                            "weaknesses": [{"description": [{"value": "CWE-79"}]}],
                            "references": [{"url": "https://example.test/cve"}],
                            "configurations": [],
                            "published": "2026-01-01T00:00:00.000Z",
                            "lastModified": "2026-01-02T00:00:00.000Z"
                        },
                        "raw_payload": {"source": "test"}
                    }"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["accepted"], true);
    assert_eq!(payload["api_version"], "v1");
    assert_eq!(payload["cve_id"], "CVE-2026-4242");
    assert_eq!(payload["persisted"], true);

    let row = sqlx::query(
        r#"
        SELECT cve_id, description, severity, weakness_ids_json, references_json, raw_json
        FROM vulnerability_intelligence_cverecord
        WHERE cve_id = ?
        "#,
    )
    .bind("CVE-2026-4242")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("cve_id"), "CVE-2026-4242");
    assert_eq!(row.get::<String, _>("description"), "Rust persisted CVE");
    assert_eq!(row.get::<String, _>("severity"), "HIGH");
    assert_eq!(row.get::<String, _>("weakness_ids_json"), r#"["CWE-79"]"#);
    assert_eq!(
        row.get::<String, _>("references_json"),
        r#"["https://example.test/cve"]"#
    );
    assert_eq!(row.get::<String, _>("raw_json"), r#"{"source":"test"}"#);
}

#[tokio::test]
async fn llm_generate_endpoint_returns_ok() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/llm/generate")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"prompt":"hello world","max_tokens":64}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn risk_priority_endpoint_returns_ok() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/risk/priority")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"score":9.8,"exposure":"INTERNET","criticality":"CRITICAL","epss_score":0.95,"in_kev_catalog":true,"exploit_maturity":"ACTIVE","affects_critical_service":true,"nis2_relevant":true}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn guidance_evaluate_endpoint_returns_ok() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/guidance/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"description_present":true,"sector_present":true,"applicability_count":1,"process_count":3,"risk_count":1,"assessment_count":1,"measure_count":0,"measure_open_count":1,"requirement_count":4}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn report_cve_summary_endpoint_returns_ok() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/reports/cve-summary")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"total":10,"critical":2,"with_risk":4,"llm_generated":5,"nis2":3,"kev":2}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

async fn create_asset_tables(pool: &SqlitePool) {
    sqlx::query(
        r#"
        CREATE TABLE organizations_businessunit (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            name varchar(255) NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE accounts_user (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            username varchar(150) NOT NULL,
            first_name varchar(150) NOT NULL,
            last_name varchar(150) NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE assets_app_informationasset (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            business_unit_id INTEGER NULL,
            owner_id INTEGER NULL,
            name varchar(255) NOT NULL,
            asset_type varchar(24) NOT NULL,
            criticality varchar(16) NOT NULL,
            description TEXT NOT NULL,
            confidentiality varchar(32) NOT NULL,
            integrity varchar(32) NOT NULL,
            availability varchar(32) NOT NULL,
            lifecycle_status varchar(64) NOT NULL,
            is_in_scope bool NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_asset_fixture(pool: &SqlitePool) {
    sqlx::query(
        r#"
        INSERT INTO organizations_businessunit (id, tenant_id, name)
        VALUES (1, 42, 'Digital Services'), (2, 99, 'Foreign BU')
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO accounts_user (id, tenant_id, username, first_name, last_name)
        VALUES
            (7, 42, 'ada', 'Ada', 'Lovelace'),
            (8, 42, 'grace', '', '')
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO assets_app_informationasset (
            id,
            tenant_id,
            business_unit_id,
            owner_id,
            name,
            asset_type,
            criticality,
            description,
            confidentiality,
            integrity,
            availability,
            lifecycle_status,
            is_in_scope,
            created_at,
            updated_at
        )
        VALUES
            (
                10,
                42,
                1,
                7,
                'Customer Portal',
                'APPLICATION',
                'HIGH',
                'External customer platform',
                'HIGH',
                'HIGH',
                'MEDIUM',
                'active',
                1,
                '2026-04-01T10:00:00Z',
                '2026-04-01T11:00:00Z'
            ),
            (
                11,
                42,
                NULL,
                8,
                'Data Lake',
                'DATA',
                'VERY_HIGH',
                'Analytics data store',
                'VERY_HIGH',
                'HIGH',
                'HIGH',
                'active',
                1,
                '2026-04-02T10:00:00Z',
                '2026-04-02T11:00:00Z'
            ),
            (
                12,
                99,
                2,
                7,
                'Foreign CRM',
                'SERVICE',
                'LOW',
                'Foreign tenant asset',
                'LOW',
                'LOW',
                'LOW',
                'retired',
                0,
                '2026-04-03T10:00:00Z',
                '2026-04-03T11:00:00Z'
            )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn create_process_tables(pool: &SqlitePool) {
    sqlx::query(
        r#"
        CREATE TABLE organizations_businessunit (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            name varchar(255) NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE accounts_user (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            username varchar(150) NOT NULL,
            first_name varchar(150) NOT NULL,
            last_name varchar(150) NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE processes_process (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            business_unit_id INTEGER NULL,
            owner_id INTEGER NULL,
            name varchar(255) NOT NULL,
            scope varchar(255) NOT NULL,
            description TEXT NOT NULL,
            status varchar(32) NOT NULL,
            documented bool NOT NULL,
            approved bool NOT NULL,
            communicated bool NOT NULL,
            implemented bool NOT NULL,
            effective bool NOT NULL,
            evidenced bool NOT NULL,
            reviewed_at date NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_process_fixture(pool: &SqlitePool) {
    sqlx::query(
        r#"
        INSERT INTO organizations_businessunit (id, tenant_id, name)
        VALUES (1, 42, 'Security Operations'), (2, 99, 'Foreign BU')
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO accounts_user (id, tenant_id, username, first_name, last_name)
        VALUES
            (7, 42, 'ada', 'Ada', 'Lovelace'),
            (8, 42, 'grace', '', '')
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO processes_process (
            id,
            tenant_id,
            business_unit_id,
            owner_id,
            name,
            scope,
            description,
            status,
            documented,
            approved,
            communicated,
            implemented,
            effective,
            evidenced,
            reviewed_at,
            created_at,
            updated_at
        )
        VALUES
            (
                10,
                42,
                1,
                7,
                'Incident Intake',
                'SOC',
                'SOC intake process',
                'PARTIAL',
                1,
                1,
                1,
                1,
                0,
                0,
                '2026-04-18',
                '2026-04-18T10:00:00Z',
                '2026-04-18T11:00:00Z'
            ),
            (
                11,
                42,
                NULL,
                8,
                'Triage',
                'Security Operations',
                'Alert triage process',
                'INFORMAL',
                1,
                0,
                1,
                0,
                0,
                0,
                NULL,
                '2026-04-19T10:00:00Z',
                '2026-04-19T11:00:00Z'
            ),
            (
                12,
                99,
                2,
                7,
                'Foreign Process',
                'Other',
                'Foreign tenant process',
                'SUFFICIENT',
                1,
                1,
                1,
                1,
                1,
                1,
                '2026-04-20',
                '2026-04-20T10:00:00Z',
                '2026-04-20T11:00:00Z'
            )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn create_risk_tables(pool: &SqlitePool) {
    sqlx::query(
        r#"
        CREATE TABLE risks_riskcategory (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            name varchar(128) NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE processes_process (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            name varchar(255) NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE assets_app_informationasset (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            name varchar(255) NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE accounts_user (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            username varchar(150) NOT NULL,
            first_name varchar(150) NOT NULL,
            last_name varchar(150) NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE risks_risk (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            category_id INTEGER NULL,
            process_id INTEGER NULL,
            asset_id INTEGER NULL,
            owner_id INTEGER NULL,
            title varchar(255) NOT NULL,
            description TEXT NOT NULL,
            threat TEXT NOT NULL,
            vulnerability TEXT NOT NULL,
            impact INTEGER NOT NULL,
            likelihood INTEGER NOT NULL,
            residual_impact INTEGER NULL,
            residual_likelihood INTEGER NULL,
            status varchar(16) NOT NULL,
            treatment_strategy varchar(16) NOT NULL,
            treatment_plan TEXT NOT NULL,
            treatment_due_date date NULL,
            accepted_by_id INTEGER NULL,
            accepted_at TEXT NULL,
            review_date date NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_risk_fixture(pool: &SqlitePool) {
    sqlx::query(
        r#"
        INSERT INTO risks_riskcategory (id, tenant_id, name)
        VALUES (1, 42, 'Cyber Risk'), (2, 99, 'Foreign Category')
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO processes_process (id, tenant_id, name)
        VALUES (1, 42, 'Incident Intake'), (2, 99, 'Foreign Process')
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO assets_app_informationasset (id, tenant_id, name)
        VALUES (1, 42, 'Customer Portal'), (2, 99, 'Foreign Asset')
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO accounts_user (id, tenant_id, username, first_name, last_name)
        VALUES
            (7, 42, 'ada', 'Ada', 'Lovelace'),
            (8, 42, 'grace', '', ''),
            (9, 99, 'foreign', 'Foreign', 'User')
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO risks_risk (
            id,
            tenant_id,
            category_id,
            process_id,
            asset_id,
            owner_id,
            title,
            description,
            threat,
            vulnerability,
            impact,
            likelihood,
            residual_impact,
            residual_likelihood,
            status,
            treatment_strategy,
            treatment_plan,
            treatment_due_date,
            accepted_by_id,
            accepted_at,
            review_date,
            created_at,
            updated_at
        )
        VALUES
            (
                10,
                42,
                1,
                1,
                1,
                7,
                'Credential Phishing',
                'Credential theft can disrupt SOC operations',
                'Phishing campaign',
                'Weak MFA coverage',
                5,
                4,
                3,
                2,
                'TREATING',
                'MITIGATE',
                'Roll out phishing-resistant MFA',
                '2026-04-30',
                8,
                '2026-04-18T10:00:00Z',
                '2026-05-01',
                '2026-04-01T10:00:00Z',
                '2026-04-01T11:00:00Z'
            ),
            (
                11,
                42,
                NULL,
                NULL,
                NULL,
                NULL,
                'Supplier Delay',
                'Supplier delay can affect evidence collection',
                '',
                '',
                3,
                3,
                NULL,
                NULL,
                'IDENTIFIED',
                '',
                '',
                NULL,
                NULL,
                NULL,
                NULL,
                '2026-04-02T10:00:00Z',
                '2026-04-02T11:00:00Z'
            ),
            (
                12,
                99,
                2,
                2,
                2,
                9,
                'Foreign Risk',
                'Foreign tenant risk',
                '',
                '',
                5,
                5,
                NULL,
                NULL,
                'IDENTIFIED',
                '',
                '',
                NULL,
                NULL,
                NULL,
                NULL,
                '2026-04-03T10:00:00Z',
                '2026-04-03T11:00:00Z'
            )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn create_evidence_tables(pool: &SqlitePool) {
    sqlx::query(
        r#"
        CREATE TABLE accounts_user (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            username varchar(150) NOT NULL,
            first_name varchar(150) NOT NULL,
            last_name varchar(150) NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE wizard_generatedmeasure (
            id INTEGER PRIMARY KEY,
            title varchar(255) NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE requirements_app_mappingversion (
            id INTEGER PRIMARY KEY,
            framework varchar(32) NOT NULL,
            program_name varchar(64) NOT NULL,
            version varchar(32) NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE requirements_app_regulatorysource (
            id INTEGER PRIMARY KEY,
            authority varchar(128) NOT NULL,
            citation varchar(255) NOT NULL,
            title varchar(255) NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE requirements_app_requirement (
            id INTEGER PRIMARY KEY,
            framework varchar(32) NOT NULL,
            code varchar(64) NOT NULL,
            title varchar(255) NOT NULL,
            mapping_version_id INTEGER NULL,
            primary_source_id INTEGER NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE evidence_evidenceitem (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            session_id INTEGER NULL,
            domain_id INTEGER NULL,
            measure_id INTEGER NULL,
            requirement_id INTEGER NULL,
            title varchar(255) NOT NULL,
            description TEXT NOT NULL,
            linked_requirement varchar(128) NOT NULL,
            file varchar(100) NULL,
            status varchar(16) NOT NULL,
            owner_id INTEGER NULL,
            review_notes TEXT NOT NULL,
            reviewed_by_id INTEGER NULL,
            reviewed_at TEXT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE evidence_requirementevidenceneed (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            session_id INTEGER NULL,
            requirement_id INTEGER NOT NULL,
            title varchar(255) NOT NULL,
            description TEXT NOT NULL,
            is_mandatory bool NOT NULL,
            status varchar(16) NOT NULL,
            rationale TEXT NOT NULL,
            covered_count INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_evidence_fixture(pool: &SqlitePool) {
    sqlx::query(
        r#"
        INSERT INTO accounts_user (id, tenant_id, username, first_name, last_name)
        VALUES
            (7, 42, 'ada', 'Ada', 'Lovelace'),
            (8, 42, 'grace', '', ''),
            (9, 99, 'foreign', 'Foreign', 'User')
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO wizard_generatedmeasure (id, title)
        VALUES (1, 'MFA einführen')
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO requirements_app_mappingversion (id, framework, program_name, version)
        VALUES (1, 'ISO27001', 'ISCY', '2022')
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO requirements_app_regulatorysource (id, authority, citation, title)
        VALUES (1, 'ISO', 'A.5.17', 'Authentication information')
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO requirements_app_requirement (
            id,
            framework,
            code,
            title,
            mapping_version_id,
            primary_source_id
        )
        VALUES
            (1, 'ISO27001', 'A.5.17', 'Authentication Information', 1, 1),
            (2, 'NIS2', '21.2', 'Incident Handling', 1, NULL)
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO evidence_evidenceitem (
            id,
            tenant_id,
            session_id,
            domain_id,
            measure_id,
            requirement_id,
            title,
            description,
            linked_requirement,
            file,
            status,
            owner_id,
            review_notes,
            reviewed_by_id,
            reviewed_at,
            created_at,
            updated_at
        )
        VALUES
            (
                10,
                42,
                100,
                NULL,
                1,
                1,
                'MFA Rollout Screenshot',
                'Screenshot of enforced MFA policy',
                'ISO27001 A.5.17',
                'evidence/mfa.png',
                'APPROVED',
                7,
                'Looks good',
                8,
                '2026-04-18T12:00:00Z',
                '2026-04-18T10:00:00Z',
                '2026-04-18T12:00:00Z'
            ),
            (
                11,
                42,
                101,
                NULL,
                NULL,
                2,
                'Incident Playbook',
                'SOC incident handling playbook',
                'NIS2 21.2',
                NULL,
                'SUBMITTED',
                8,
                '',
                NULL,
                NULL,
                '2026-04-17T10:00:00Z',
                '2026-04-17T11:00:00Z'
            ),
            (
                12,
                99,
                102,
                NULL,
                NULL,
                1,
                'Foreign Evidence',
                'Foreign tenant evidence',
                'ISO27001 A.5.17',
                NULL,
                'DRAFT',
                9,
                '',
                NULL,
                NULL,
                '2026-04-16T10:00:00Z',
                '2026-04-16T11:00:00Z'
            )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO evidence_requirementevidenceneed (
            id,
            tenant_id,
            session_id,
            requirement_id,
            title,
            description,
            is_mandatory,
            status,
            rationale,
            covered_count,
            created_at,
            updated_at
        )
        VALUES
            (
                20,
                42,
                100,
                1,
                'Nachweis für ISO27001 A.5.17',
                'MFA policy evidence',
                1,
                'COVERED',
                'Evidence is approved',
                2,
                '2026-04-18T10:00:00Z',
                '2026-04-18T11:00:00Z'
            ),
            (
                21,
                42,
                100,
                2,
                'Nachweis für NIS2 21.2',
                'Incident process evidence',
                1,
                'OPEN',
                'Incident evidence missing',
                0,
                '2026-04-18T10:00:00Z',
                '2026-04-18T11:00:00Z'
            ),
            (
                22,
                42,
                101,
                2,
                'Nachweis für NIS2 21.2 Review',
                'Incident process evidence',
                1,
                'PARTIAL',
                'Incident evidence partly available',
                1,
                '2026-04-18T10:00:00Z',
                '2026-04-18T11:00:00Z'
            ),
            (
                23,
                99,
                102,
                1,
                'Foreign Need',
                'Foreign tenant evidence need',
                1,
                'OPEN',
                '',
                0,
                '2026-04-18T10:00:00Z',
                '2026-04-18T11:00:00Z'
            )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn create_assessment_tables(pool: &SqlitePool) {
    sqlx::query(
        r#"
        CREATE TABLE organizations_tenant (
            id INTEGER PRIMARY KEY,
            name varchar(255) NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE accounts_user (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            username varchar(150) NOT NULL,
            first_name varchar(150) NOT NULL,
            last_name varchar(150) NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE processes_process (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            name varchar(255) NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE requirements_app_requirement (
            id INTEGER PRIMARY KEY,
            framework varchar(32) NOT NULL,
            code varchar(64) NOT NULL,
            title varchar(255) NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE assessments_applicabilityassessment (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            sector varchar(255) NOT NULL,
            company_size varchar(255) NOT NULL,
            critical_services TEXT NOT NULL,
            supply_chain_role varchar(255) NOT NULL,
            status varchar(32) NOT NULL,
            reasoning TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE assessments_assessment (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            process_id INTEGER NOT NULL,
            requirement_id INTEGER NOT NULL,
            owner_id INTEGER NULL,
            status varchar(32) NOT NULL,
            score INTEGER NOT NULL,
            notes TEXT NOT NULL,
            evidence_summary TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE assessments_measure (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            assessment_id INTEGER NULL,
            owner_id INTEGER NULL,
            title varchar(255) NOT NULL,
            description TEXT NOT NULL,
            priority varchar(16) NOT NULL,
            status varchar(16) NOT NULL,
            due_date date NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_assessment_fixture(pool: &SqlitePool) {
    sqlx::query(
        r#"
        INSERT INTO organizations_tenant (id, name)
        VALUES (42, 'Tenant SOC'), (99, 'Foreign Tenant')
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO accounts_user (id, tenant_id, username, first_name, last_name)
        VALUES
            (7, 42, 'ada', 'Ada', 'Lovelace'),
            (8, 42, 'grace', '', ''),
            (9, 99, 'foreign', 'Foreign', 'User')
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO processes_process (id, tenant_id, name)
        VALUES
            (1, 42, 'Incident Intake'),
            (2, 99, 'Foreign Process')
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO requirements_app_requirement (id, framework, code, title)
        VALUES
            (1, 'ISO27001', 'A.5.17', 'Authentication Information'),
            (2, 'NIS2', '21.2', 'Incident Handling')
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO assessments_applicabilityassessment (
            id,
            tenant_id,
            sector,
            company_size,
            critical_services,
            supply_chain_role,
            status,
            reasoning,
            created_at,
            updated_at
        )
        VALUES
            (
                10,
                42,
                'MSSP',
                'medium',
                'Managed detection and response',
                'critical supplier',
                'RELEVANT',
                'Digital provider with critical customer services',
                '2026-04-18T10:00:00Z',
                '2026-04-18T11:00:00Z'
            ),
            (
                11,
                99,
                'Retail',
                'small',
                '',
                '',
                'NOT_DIRECTLY_RELEVANT',
                'Foreign tenant',
                '2026-04-19T10:00:00Z',
                '2026-04-19T11:00:00Z'
            )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO assessments_assessment (
            id,
            tenant_id,
            process_id,
            requirement_id,
            owner_id,
            status,
            score,
            notes,
            evidence_summary,
            created_at,
            updated_at
        )
        VALUES
            (
                20,
                42,
                1,
                1,
                7,
                'PARTIAL',
                3,
                'MFA rollout started',
                'Screenshots available',
                '2026-04-18T10:00:00Z',
                '2026-04-18T11:00:00Z'
            ),
            (
                21,
                42,
                1,
                2,
                NULL,
                'MISSING',
                0,
                '',
                '',
                '2026-04-19T10:00:00Z',
                '2026-04-19T11:00:00Z'
            ),
            (
                22,
                99,
                2,
                1,
                9,
                'FULFILLED',
                5,
                'Foreign',
                '',
                '2026-04-20T10:00:00Z',
                '2026-04-20T11:00:00Z'
            )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO assessments_measure (
            id,
            tenant_id,
            assessment_id,
            owner_id,
            title,
            description,
            priority,
            status,
            due_date,
            created_at,
            updated_at
        )
        VALUES
            (
                30,
                42,
                20,
                7,
                'MFA ausrollen',
                'Roll out phishing-resistant MFA',
                'HIGH',
                'OPEN',
                '2026-05-01',
                '2026-04-18T10:00:00Z',
                '2026-04-18T11:00:00Z'
            ),
            (
                31,
                42,
                NULL,
                8,
                'Policy aktualisieren',
                'Update access policy',
                'MEDIUM',
                'DONE',
                NULL,
                '2026-04-19T10:00:00Z',
                '2026-04-19T11:00:00Z'
            ),
            (
                32,
                99,
                22,
                9,
                'Foreign Measure',
                'Foreign tenant measure',
                'LOW',
                'OPEN',
                '2026-05-02',
                '2026-04-20T10:00:00Z',
                '2026-04-20T11:00:00Z'
            )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn create_roadmap_tables(pool: &SqlitePool) {
    sqlx::query(
        r#"
        CREATE TABLE organizations_tenant (
            id INTEGER PRIMARY KEY,
            name varchar(255) NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE roadmap_roadmapplan (
            id INTEGER PRIMARY KEY,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            tenant_id INTEGER NOT NULL,
            session_id INTEGER NOT NULL,
            title varchar(255) NOT NULL,
            summary TEXT NOT NULL,
            overall_priority varchar(32) NOT NULL,
            planned_start date NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE roadmap_roadmapphase (
            id INTEGER PRIMARY KEY,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            plan_id INTEGER NOT NULL,
            name varchar(255) NOT NULL,
            sort_order INTEGER NOT NULL,
            objective TEXT NOT NULL,
            duration_weeks INTEGER NOT NULL,
            planned_start date NULL,
            planned_end date NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE roadmap_roadmaptask (
            id INTEGER PRIMARY KEY,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            phase_id INTEGER NOT NULL,
            measure_id INTEGER NULL,
            title varchar(255) NOT NULL,
            description TEXT NOT NULL,
            priority varchar(32) NOT NULL,
            owner_role varchar(64) NOT NULL,
            due_in_days INTEGER NOT NULL,
            dependency_text TEXT NOT NULL,
            status varchar(16) NOT NULL,
            planned_start date NULL,
            due_date date NULL,
            notes TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE roadmap_roadmaptaskdependency (
            id INTEGER PRIMARY KEY,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            predecessor_id INTEGER NOT NULL,
            successor_id INTEGER NOT NULL,
            dependency_type varchar(2) NOT NULL,
            rationale varchar(255) NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_roadmap_fixture(pool: &SqlitePool) {
    sqlx::query(
        r#"
        INSERT INTO organizations_tenant (id, name)
        VALUES (42, 'Tenant SOC'), (99, 'Foreign Tenant')
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO roadmap_roadmapplan (
            id,
            created_at,
            updated_at,
            tenant_id,
            session_id,
            title,
            summary,
            overall_priority,
            planned_start
        )
        VALUES
            (
                10,
                '2026-04-18T10:00:00Z',
                '2026-04-18T11:00:00Z',
                42,
                100,
                'Security Roadmap',
                'Bring SOC controls to audit readiness',
                'HIGH',
                '2026-05-01'
            ),
            (
                11,
                '2026-04-01T10:00:00Z',
                '2026-04-01T11:00:00Z',
                42,
                101,
                'Earlier Roadmap',
                'Earlier planning wave',
                'MEDIUM',
                '2026-04-10'
            ),
            (
                12,
                '2026-04-19T10:00:00Z',
                '2026-04-19T11:00:00Z',
                99,
                102,
                'Foreign Roadmap',
                'Foreign tenant planning',
                'LOW',
                '2026-05-02'
            )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO roadmap_roadmapphase (
            id,
            created_at,
            updated_at,
            plan_id,
            name,
            sort_order,
            objective,
            duration_weeks,
            planned_start,
            planned_end
        )
        VALUES
            (
                101,
                '2026-04-18T10:00:00Z',
                '2026-04-18T11:00:00Z',
                10,
                'Governance',
                1,
                'Create ownership and policies',
                2,
                '2026-05-01',
                '2026-05-14'
            ),
            (
                102,
                '2026-04-18T10:00:00Z',
                '2026-04-18T11:00:00Z',
                10,
                'Audit Readiness',
                2,
                'Collect evidence and review controls',
                3,
                '2026-05-15',
                '2026-06-05'
            ),
            (
                111,
                '2026-04-01T10:00:00Z',
                '2026-04-01T11:00:00Z',
                11,
                'Discovery',
                1,
                'Initial discovery',
                1,
                '2026-04-10',
                '2026-04-17'
            ),
            (
                121,
                '2026-04-19T10:00:00Z',
                '2026-04-19T11:00:00Z',
                12,
                'Foreign Phase',
                1,
                'Foreign work',
                1,
                '2026-05-02',
                '2026-05-09'
            )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO roadmap_roadmaptask (
            id,
            created_at,
            updated_at,
            phase_id,
            measure_id,
            title,
            description,
            priority,
            owner_role,
            due_in_days,
            dependency_text,
            status,
            planned_start,
            due_date,
            notes
        )
        VALUES
            (
                1001,
                '2026-04-18T10:00:00Z',
                '2026-04-18T11:00:00Z',
                101,
                NULL,
                'Policy aktualisieren',
                'Update security policy',
                'HIGH',
                'CISO',
                14,
                '',
                'OPEN',
                '2026-05-01',
                '2026-05-01',
                ''
            ),
            (
                1002,
                '2026-04-18T10:00:00Z',
                '2026-04-18T11:00:00Z',
                101,
                NULL,
                'MFA ausrollen',
                'Roll out MFA',
                'CRITICAL',
                'IAM Lead',
                21,
                'Policy first',
                'IN_PROGRESS',
                '2026-05-02',
                '2026-05-10',
                'Pilot started'
            ),
            (
                1003,
                '2026-04-18T10:00:00Z',
                '2026-04-18T11:00:00Z',
                102,
                NULL,
                'Auditpaket vorbereiten',
                'Prepare audit package',
                'MEDIUM',
                'Compliance',
                30,
                '',
                'DONE',
                '2026-05-20',
                '2026-06-01',
                'Done'
            ),
            (
                1101,
                '2026-04-01T10:00:00Z',
                '2026-04-01T11:00:00Z',
                111,
                NULL,
                'Earlier Task',
                'Earlier work',
                'LOW',
                'Analyst',
                7,
                '',
                'OPEN',
                '2026-04-10',
                '2026-04-17',
                ''
            ),
            (
                1201,
                '2026-04-19T10:00:00Z',
                '2026-04-19T11:00:00Z',
                121,
                NULL,
                'Foreign Task',
                'Foreign tenant task',
                'LOW',
                'Owner',
                7,
                '',
                'OPEN',
                '2026-05-02',
                '2026-05-09',
                ''
            )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO roadmap_roadmaptaskdependency (
            id,
            created_at,
            updated_at,
            predecessor_id,
            successor_id,
            dependency_type,
            rationale
        )
        VALUES
            (
                5001,
                '2026-04-18T10:00:00Z',
                '2026-04-18T11:00:00Z',
                1001,
                1002,
                'FS',
                'Policy gates MFA rollout'
            )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn create_report_table(pool: &SqlitePool) {
    sqlx::query(
        r#"
        CREATE TABLE reports_reportsnapshot (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            session_id INTEGER NOT NULL,
            title varchar(255) NOT NULL,
            executive_summary TEXT NOT NULL,
            applicability_result varchar(255) NOT NULL,
            iso_readiness_percent INTEGER NOT NULL,
            nis2_readiness_percent INTEGER NOT NULL,
            kritis_readiness_percent INTEGER NOT NULL,
            cra_readiness_percent INTEGER NOT NULL,
            ai_act_readiness_percent INTEGER NOT NULL,
            iec62443_readiness_percent INTEGER NOT NULL,
            iso_sae_21434_readiness_percent INTEGER NOT NULL,
            regulatory_matrix_json TEXT NOT NULL,
            compliance_versions_json TEXT NOT NULL,
            product_security_json TEXT NOT NULL,
            top_gaps_json TEXT NOT NULL,
            top_measures_json TEXT NOT NULL,
            roadmap_summary TEXT NOT NULL,
            domain_scores_json TEXT NOT NULL,
            next_steps_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_report_fixture(pool: &SqlitePool) {
    sqlx::query(
        r#"
        INSERT INTO reports_reportsnapshot (
            id,
            tenant_id,
            session_id,
            title,
            executive_summary,
            applicability_result,
            iso_readiness_percent,
            nis2_readiness_percent,
            kritis_readiness_percent,
            cra_readiness_percent,
            ai_act_readiness_percent,
            iec62443_readiness_percent,
            iso_sae_21434_readiness_percent,
            regulatory_matrix_json,
            compliance_versions_json,
            product_security_json,
            top_gaps_json,
            top_measures_json,
            roadmap_summary,
            domain_scores_json,
            next_steps_json,
            created_at,
            updated_at
        )
        VALUES
            (
                10,
                42,
                100,
                'March Readiness',
                'March Executive Summary',
                'relevant',
                65,
                70,
                20,
                21,
                22,
                23,
                24,
                '{"overall":"medium"}',
                '{"ISO27001":{"version":"2022"}}',
                '{"sbom_required":true}',
                '[{"title":"Gap A"}]',
                '[{"title":"Patch Prozess"}]',
                '[{"name":"Phase 1"}]',
                '[{"domain":"Risk","score_percent":62}]',
                '{"dependencies":[]}',
                '2026-03-01T10:00:00Z',
                '2026-03-01T11:00:00Z'
            ),
            (
                11,
                42,
                101,
                'April Readiness',
                'April Executive Summary',
                'relevant',
                78,
                82,
                33,
                34,
                35,
                36,
                37,
                '{"overall":"high"}',
                '{"ISO27001":{"version":"2022"},"NIS2":{"version":"2024"}}',
                '{"sbom_required":true,"psirt":true}',
                '[{"title":"Gap B"}]',
                '[{"title":"MFA einfuehren","priority":"HIGH"}]',
                '[{"name":"Phase 2","duration_weeks":6}]',
                '[{"domain":"Governance","score_percent":82}]',
                '{"dependencies":[{"predecessor":"A","successor":"B"}]}',
                '2026-04-01T10:00:00Z',
                '2026-04-01T11:00:00Z'
            ),
            (
                12,
                99,
                102,
                'Other Tenant Readiness',
                'Other Executive Summary',
                'not_relevant',
                90,
                91,
                40,
                41,
                42,
                43,
                44,
                '{}',
                '{}',
                '{}',
                '[]',
                '[]',
                '[]',
                '[]',
                '{}',
                '2026-04-02T10:00:00Z',
                '2026-04-02T11:00:00Z'
            )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn create_dashboard_tables(pool: &SqlitePool) {
    sqlx::query(
        r#"
        CREATE TABLE processes_process (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE assets_app_informationasset (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE risks_risk (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            status varchar(16) NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE evidence_evidenceitem (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE roadmap_roadmapplan (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE roadmap_roadmapphase (
            id INTEGER PRIMARY KEY,
            plan_id INTEGER NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE roadmap_roadmaptask (
            id INTEGER PRIMARY KEY,
            phase_id INTEGER NOT NULL,
            status varchar(16) NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE reports_reportsnapshot (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            title varchar(255) NOT NULL,
            created_at TEXT NOT NULL,
            iso_readiness_percent INTEGER NOT NULL,
            nis2_readiness_percent INTEGER NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_dashboard_fixture(pool: &SqlitePool) {
    sqlx::query(
        r#"
        INSERT INTO processes_process (id, tenant_id)
        VALUES (1, 42), (2, 42), (3, 99)
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO assets_app_informationasset (id, tenant_id)
        VALUES (1, 42), (2, 42), (3, 42), (4, 99)
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO risks_risk (id, tenant_id, status)
        VALUES (1, 42, 'IDENTIFIED'), (2, 42, 'TREATING'), (3, 42, 'CLOSED'), (4, 99, 'IDENTIFIED')
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO evidence_evidenceitem (id, tenant_id)
        VALUES (1, 42), (2, 42), (3, 42), (4, 42), (5, 99)
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO roadmap_roadmapplan (id, tenant_id)
        VALUES (1, 42), (2, 99)
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO roadmap_roadmapphase (id, plan_id)
        VALUES (1, 1), (2, 2)
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO roadmap_roadmaptask (id, phase_id, status)
        VALUES (1, 1, 'OPEN'), (2, 1, 'DONE'), (3, 1, 'IN_PROGRESS'), (4, 2, 'OPEN')
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO reports_reportsnapshot (
            id,
            tenant_id,
            title,
            created_at,
            iso_readiness_percent,
            nis2_readiness_percent
        )
        VALUES
            (10, 42, 'March Readiness', '2026-03-01T10:00:00Z', 65, 70),
            (11, 42, 'April Readiness', '2026-04-01T10:00:00Z', 78, 82),
            (12, 99, 'Other Tenant Readiness', '2026-04-02T10:00:00Z', 90, 91)
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn create_cverecord_table(pool: &SqlitePool) {
    sqlx::query(
        r#"
        CREATE TABLE vulnerability_intelligence_cverecord (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            cve_id varchar(32) NOT NULL UNIQUE,
            source varchar(32) NOT NULL,
            description TEXT NOT NULL,
            cvss_score decimal NULL,
            cvss_vector varchar(255) NOT NULL,
            severity varchar(16) NOT NULL,
            weakness_ids_json TEXT NOT NULL,
            references_json TEXT NOT NULL,
            configurations_json TEXT NOT NULL,
            epss_score decimal NULL,
            in_kev_catalog bool NOT NULL,
            kev_date_added date NULL,
            kev_vendor_project varchar(255) NOT NULL,
            kev_product varchar(255) NOT NULL,
            kev_required_action TEXT NOT NULL,
            kev_known_ransomware bool NOT NULL,
            raw_json TEXT NOT NULL,
            published_at TEXT NULL,
            modified_at TEXT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn create_tenant_table(pool: &SqlitePool) {
    sqlx::query(
        r#"
        CREATE TABLE organizations_tenant (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            name varchar(255) NOT NULL,
            slug varchar(50) NOT NULL UNIQUE,
            country varchar(100) NOT NULL,
            operation_countries TEXT NOT NULL,
            description TEXT NOT NULL,
            sector varchar(64) NOT NULL,
            employee_count integer NOT NULL,
            annual_revenue_million decimal NOT NULL,
            balance_sheet_million decimal NOT NULL,
            critical_services TEXT NOT NULL,
            supply_chain_role varchar(255) NOT NULL,
            nis2_relevant bool NOT NULL,
            kritis_relevant bool NOT NULL,
            develops_digital_products bool NOT NULL,
            uses_ai_systems bool NOT NULL,
            ot_iacs_scope bool NOT NULL,
            automotive_scope bool NOT NULL,
            psirt_defined bool NOT NULL,
            sbom_required bool NOT NULL,
            product_security_scope TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_tenant(pool: &SqlitePool) {
    sqlx::query(
        r#"
        INSERT INTO organizations_tenant (
            id,
            created_at,
            updated_at,
            name,
            slug,
            country,
            operation_countries,
            description,
            sector,
            employee_count,
            annual_revenue_million,
            balance_sheet_million,
            critical_services,
            supply_chain_role,
            nis2_relevant,
            kritis_relevant,
            develops_digital_products,
            uses_ai_systems,
            ot_iacs_scope,
            automotive_scope,
            psirt_defined,
            sbom_required,
            product_security_scope
        )
        VALUES (
            42,
            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP,
            'Tenant SOC',
            'tenant-soc',
            'DE',
            '["DE","FR"]',
            'Tenant fuer SOC-Playbook-Test',
            'MSSP',
            250,
            '12.50',
            '9.25',
            'SOC und Incident Response',
            'Managed Security Provider',
            1,
            0,
            1,
            1,
            0,
            0,
            1,
            1,
            'Sichere Entwicklung und PSIRT'
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
}
