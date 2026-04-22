use axum::body::{to_bytes, Body};
use axum::http::{header::SET_COOKIE, Request, StatusCode};
use iscy_backend::{
    app_router, app_router_with_state, assessment_store::AssessmentStore, asset_store::AssetStore,
    auth_store::AuthStore, catalog_store::CatalogStore, cve_store::CveStore,
    dashboard_store::DashboardStore, db_admin, evidence_store::EvidenceStore,
    import_store::ImportStore, process_store::ProcessStore,
    product_security_store::ProductSecurityStore, report_store::ReportStore,
    requirement_store::RequirementStore, risk_store::RiskStore, roadmap_store::RoadmapStore,
    tenant_store::TenantStore, wizard_store::WizardStore, AppState,
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
        "rust-session-or-header-context-v1"
    );
}

#[tokio::test]
async fn rust_auth_session_creates_cookie_and_drives_web_context() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db_admin::run_sqlite_migrations(&pool).await.unwrap();
    db_admin::seed_sqlite_demo(&pool).await.unwrap();
    let app = app_router_with_state(
        AppState::default()
            .with_auth_store(Some(AuthStore::from_sqlite_pool(pool.clone())))
            .with_dashboard_store(Some(DashboardStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/sessions")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"tenant_id":1,"user_id":1}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let cookie = response
        .headers()
        .get(SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(cookie.starts_with("iscy_session="));
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["authenticated"], true);
    assert_eq!(payload["tenant_id"], 1);
    assert_eq!(payload["user"]["username"], "demo");
    assert_eq!(payload["authorization_model"], "rust-session-v1");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/session")
                .header("cookie", cookie.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["authenticated"], true);
    assert_eq!(payload["user_id"], 1);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/context/whoami")
                .header("cookie", cookie.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["authenticated"], true);
    assert_eq!(payload["tenant_id"], 1);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/context/tenant")
                .header("cookie", cookie.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["tenant_id"], 1);
    assert_eq!(
        payload["authorization_model"],
        "rust-session-or-header-context-v1"
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/dashboard/")
                .header("cookie", cookie.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("Rust Demo Readiness"));
    assert!(html.contains("Tenant 1"));
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
async fn catalog_domains_requires_authenticated_tenant_context() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/catalog/domains")
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
async fn catalog_domains_requires_configured_database() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/catalog/domains")
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
async fn catalog_domains_return_domain_question_tree_from_database() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_catalog_tables(&pool).await;
    insert_catalog_fixture(&pool).await;
    let app = app_router_with_state(
        AppState::default().with_catalog_store(Some(CatalogStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/catalog/domains")
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
    assert_eq!(payload["question_count"], 3);
    assert_eq!(payload["domains"].as_array().unwrap().len(), 2);
    assert_eq!(payload["domains"][0]["code"], "GOV");
    assert_eq!(payload["domains"][0]["question_count"], 2);
    assert_eq!(payload["domains"][0]["questions"][0]["code"], "GOV-APP-1");
    assert_eq!(
        payload["domains"][0]["questions"][0]["question_kind_label"],
        "Betroffenheit"
    );
}

#[tokio::test]
async fn requirement_library_requires_authenticated_tenant_context() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/requirements")
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
async fn requirement_library_requires_configured_database() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/requirements")
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
async fn requirement_library_returns_requirements_and_versions_from_database() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_requirement_tables(&pool).await;
    insert_requirement_fixture(&pool).await;
    let app = app_router_with_state(
        AppState::default()
            .with_requirement_store(Some(RequirementStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/requirements")
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
    assert_eq!(payload["requirements"].as_array().unwrap().len(), 2);
    assert_eq!(payload["requirements"][0]["framework"], "ISO27001");
    assert_eq!(payload["requirements"][0]["framework_label"], "ISO 27001");
    assert_eq!(
        payload["requirements"][0]["mapping_version"]["version"],
        "2022"
    );
    assert_eq!(
        payload["requirements"][0]["primary_source"]["authority"],
        "ISO"
    );
    assert_eq!(payload["mapping_versions"].as_array().unwrap().len(), 1);
    assert_eq!(payload["mapping_versions"][0]["source_count"], 1);
    assert_eq!(payload["mapping_versions"][0]["requirement_count"], 1);
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
async fn product_security_overview_requires_authenticated_tenant_context() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/product-security/overview")
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
async fn product_security_overview_requires_configured_database() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/product-security/overview")
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
async fn product_security_overview_returns_tenant_products_from_database() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_product_security_tables(&pool).await;
    insert_product_security_fixture(&pool).await;
    let app =
        app_router_with_state(AppState::default().with_product_security_store(Some(
            ProductSecurityStore::from_sqlite_pool(pool.clone()),
        )));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/product-security/overview")
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
    assert_eq!(payload["matrix"]["cra"]["applicable"], true);
    assert_eq!(payload["matrix"]["ai_act"]["applicable"], true);
    assert_eq!(payload["posture"]["products"], 1);
    assert_eq!(payload["posture"]["active_releases"], 1);
    assert_eq!(payload["posture"]["open_vulnerabilities"], 2);
    assert_eq!(payload["posture"]["critical_open_vulnerabilities"], 1);
    assert_eq!(payload["products"].as_array().unwrap().len(), 1);
    assert_eq!(payload["products"][0]["name"], "Sensor Gateway");
    assert_eq!(payload["products"][0]["family_name"], "Gateways");
    assert_eq!(payload["products"][0]["release_count"], 2);
    assert_eq!(payload["products"][0]["threat_model_count"], 1);
    assert_eq!(payload["products"][0]["tara_count"], 1);
    assert_eq!(payload["products"][0]["vulnerability_count"], 3);
    assert_eq!(payload["products"][0]["psirt_case_count"], 1);
    assert_eq!(payload["snapshots"][0]["product_name"], "Sensor Gateway");
    assert_eq!(payload["snapshots"][0]["cra_readiness_percent"], 72);
    assert_eq!(payload["snapshots"][0]["critical_vulnerability_count"], 1);
}

#[tokio::test]
async fn product_security_detail_returns_product_tree_from_database() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_product_security_tables(&pool).await;
    insert_product_security_fixture(&pool).await;
    let app =
        app_router_with_state(AppState::default().with_product_security_store(Some(
            ProductSecurityStore::from_sqlite_pool(pool.clone()),
        )));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/product-security/products/100")
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
    assert_eq!(payload["product"]["name"], "Sensor Gateway");
    assert_eq!(payload["releases"].as_array().unwrap().len(), 2);
    assert_eq!(payload["releases"][0]["status_label"], "Aktiv");
    assert_eq!(payload["components"][0]["name"], "Gateway Firmware");
    assert_eq!(payload["components"][0]["supplier_name"], "Secure Supplier");
    assert_eq!(payload["components"][0]["has_sbom"], true);
    assert_eq!(payload["threat_models"][0]["name"], "Gateway Threat Model");
    assert_eq!(payload["threat_models"][0]["scenario_count"], 1);
    assert_eq!(payload["threat_scenarios"], 1);
    assert_eq!(
        payload["taras"][0]["scenario_title"],
        "Unsigned firmware update"
    );
    assert_eq!(payload["vulnerabilities"].as_array().unwrap().len(), 3);
    assert_eq!(
        payload["vulnerabilities"][0]["component_name"],
        "Gateway Firmware"
    );
    assert_eq!(payload["ai_systems"][0]["name"], "Gateway Assistant");
    assert_eq!(payload["psirt_cases"][0]["case_id"], "PSIRT-1");
    assert_eq!(payload["advisories"][0]["advisory_id"], "ADV-1");
    assert_eq!(payload["snapshot"]["cra_readiness_percent"], 72);
    assert_eq!(payload["roadmap"]["title"], "Gateway Roadmap");
    assert_eq!(payload["roadmap_tasks"].as_array().unwrap().len(), 2);
    assert_eq!(
        payload["roadmap_tasks"][1]["related_vulnerability_title"],
        "Critical firmware exposure"
    );
}

#[tokio::test]
async fn product_security_detail_blocks_foreign_tenant_product() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_product_security_tables(&pool).await;
    insert_product_security_fixture(&pool).await;
    let app =
        app_router_with_state(AppState::default().with_product_security_store(Some(
            ProductSecurityStore::from_sqlite_pool(pool.clone()),
        )));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/product-security/products/101")
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
    assert_eq!(payload["error_code"], "product_not_found");
}

#[tokio::test]
async fn product_security_roadmap_returns_task_data_from_database() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_product_security_tables(&pool).await;
    insert_product_security_fixture(&pool).await;
    let app =
        app_router_with_state(AppState::default().with_product_security_store(Some(
            ProductSecurityStore::from_sqlite_pool(pool.clone()),
        )));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/product-security/products/100/roadmap")
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
    assert_eq!(payload["product"]["name"], "Sensor Gateway");
    assert_eq!(payload["roadmap"]["title"], "Gateway Roadmap");
    assert_eq!(payload["tasks"].as_array().unwrap().len(), 2);
    assert_eq!(payload["tasks"][0]["phase"], "GOVERNANCE");
    assert_eq!(payload["tasks"][0]["phase_label"], "Governance");
    assert_eq!(
        payload["tasks"][1]["title"],
        "Remediate critical firmware exposure"
    );
    assert_eq!(payload["snapshot"]["psirt_readiness_percent"], 55);
}

#[tokio::test]
async fn product_security_roadmap_task_update_updates_tenant_task() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_product_security_tables(&pool).await;
    insert_product_security_fixture(&pool).await;
    let app =
        app_router_with_state(AppState::default().with_product_security_store(Some(
            ProductSecurityStore::from_sqlite_pool(pool.clone()),
        )));

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/product-security/roadmap-tasks/901")
                .header("content-type", "application/json")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::from(
                    r#"{
                        "status": "DONE",
                        "priority": "MEDIUM",
                        "owner_role": "Product Security Office",
                        "due_in_days": 7,
                        "dependency_text": "Reviewed in planning"
                    }"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["api_version"], "v1");
    assert_eq!(payload["product_id"], 100);
    assert_eq!(payload["roadmap_id"], 900);
    assert_eq!(payload["task"]["id"], 901);
    assert_eq!(payload["task"]["status"], "DONE");
    assert_eq!(payload["task"]["status_label"], "Erledigt");
    assert_eq!(payload["task"]["priority"], "MEDIUM");
    assert_eq!(payload["task"]["owner_role"], "Product Security Office");
    assert_eq!(payload["task"]["due_in_days"], 7);
    assert_eq!(payload["task"]["dependency_text"], "Reviewed in planning");

    let row = sqlx::query(
        r#"
        SELECT status, priority, owner_role, due_in_days, dependency_text
        FROM product_security_productsecurityroadmaptask
        WHERE id = 901
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("status"), "DONE");
    assert_eq!(row.get::<String, _>("priority"), "MEDIUM");
    assert_eq!(
        row.get::<String, _>("owner_role"),
        "Product Security Office"
    );
    assert_eq!(row.get::<i64, _>("due_in_days"), 7);
    assert_eq!(
        row.get::<String, _>("dependency_text"),
        "Reviewed in planning"
    );
}

#[tokio::test]
async fn product_security_roadmap_task_update_blocks_foreign_tenant_task() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_product_security_tables(&pool).await;
    insert_product_security_fixture(&pool).await;
    let app =
        app_router_with_state(AppState::default().with_product_security_store(Some(
            ProductSecurityStore::from_sqlite_pool(pool.clone()),
        )));

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/product-security/roadmap-tasks/901")
                .header("content-type", "application/json")
                .header("x-iscy-tenant-id", "99")
                .header("x-iscy-user-id", "7")
                .body(Body::from(r#"{"status":"DONE"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        payload["error_code"],
        "product_security_roadmap_task_not_found"
    );
}

#[tokio::test]
async fn product_security_vulnerability_update_updates_tenant_vulnerability() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_product_security_tables(&pool).await;
    insert_product_security_fixture(&pool).await;
    let app =
        app_router_with_state(AppState::default().with_product_security_store(Some(
            ProductSecurityStore::from_sqlite_pool(pool.clone()),
        )));

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/product-security/vulnerabilities/500")
                .header("content-type", "application/json")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::from(
                    r#"{
                        "severity": "MEDIUM",
                        "status": "MITIGATED",
                        "remediation_due": "2026-06-15",
                        "summary": "Mitigated via firmware patch"
                    }"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["api_version"], "v1");
    assert_eq!(payload["product_id"], 100);
    assert_eq!(payload["vulnerability"]["id"], 500);
    assert_eq!(payload["vulnerability"]["severity"], "MEDIUM");
    assert_eq!(payload["vulnerability"]["severity_label"], "Mittel");
    assert_eq!(payload["vulnerability"]["status"], "MITIGATED");
    assert_eq!(payload["vulnerability"]["status_label"], "Mitigiert");
    assert_eq!(payload["vulnerability"]["remediation_due"], "2026-06-15");
    assert_eq!(
        payload["vulnerability"]["summary"],
        "Mitigated via firmware patch"
    );

    let row = sqlx::query(
        r#"
        SELECT severity, status, remediation_due, summary
        FROM product_security_vulnerability
        WHERE id = 500
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("severity"), "MEDIUM");
    assert_eq!(row.get::<String, _>("status"), "MITIGATED");
    assert_eq!(
        row.get::<Option<String>, _>("remediation_due").as_deref(),
        Some("2026-06-15")
    );
    assert_eq!(
        row.get::<String, _>("summary"),
        "Mitigated via firmware patch"
    );
}

#[tokio::test]
async fn product_security_vulnerability_update_blocks_foreign_tenant_vulnerability() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_product_security_tables(&pool).await;
    insert_product_security_fixture(&pool).await;
    let app =
        app_router_with_state(AppState::default().with_product_security_store(Some(
            ProductSecurityStore::from_sqlite_pool(pool.clone()),
        )));

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/product-security/vulnerabilities/500")
                .header("content-type", "application/json")
                .header("x-iscy-tenant-id", "99")
                .header("x-iscy-user-id", "7")
                .body(Body::from(r#"{"status":"FIXED"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        payload["error_code"],
        "product_security_vulnerability_not_found"
    );
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
async fn risk_create_persists_tenant_risk() {
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
                .method("POST")
                .uri("/api/v1/risks")
                .header("content-type", "application/json")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::from(
                    r#"{
                        "category_id": 1,
                        "process_id": 1,
                        "asset_id": 1,
                        "owner_id": 7,
                        "title": "Rust Created Risk",
                        "description": "Created through the Rust risk API",
                        "threat": "Credential stuffing",
                        "vulnerability": "Weak account lockout",
                        "impact": 4,
                        "likelihood": 3,
                        "residual_impact": 2,
                        "residual_likelihood": 2,
                        "status": "ANALYZING",
                        "treatment_strategy": "MITIGATE",
                        "treatment_plan": "Harden login controls",
                        "treatment_due_date": "2026-06-01",
                        "review_date": "2026-06-15"
                    }"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["api_version"], "v1");
    assert_eq!(payload["risk"]["tenant_id"], 42);
    assert_eq!(payload["risk"]["title"], "Rust Created Risk");
    assert_eq!(payload["risk"]["score"], 12);
    assert_eq!(payload["risk"]["risk_level"], "HIGH");
    assert_eq!(payload["risk"]["category_name"], "Cyber Risk");
    assert_eq!(payload["risk"]["owner_display"], "Ada Lovelace");
    assert_eq!(payload["risk"]["treatment_due_date"], "2026-06-01");

    let stored_title: String =
        sqlx::query_scalar("SELECT title FROM risks_risk WHERE tenant_id = 42 AND title = ?")
            .bind("Rust Created Risk")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored_title, "Rust Created Risk");
}

#[tokio::test]
async fn risk_update_updates_tenant_risk() {
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
                .method("PATCH")
                .uri("/api/v1/risks/10")
                .header("content-type", "application/json")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::from(
                    r#"{
                        "category_id": null,
                        "title": "Credential Phishing Updated",
                        "impact": 2,
                        "status": "CLOSED",
                        "residual_impact": null,
                        "review_date": null
                    }"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["risk"]["id"], 10);
    assert_eq!(payload["risk"]["title"], "Credential Phishing Updated");
    assert_eq!(payload["risk"]["category_id"], serde_json::Value::Null);
    assert_eq!(payload["risk"]["impact"], 2);
    assert_eq!(payload["risk"]["score"], 8);
    assert_eq!(payload["risk"]["status"], "CLOSED");
    assert_eq!(payload["risk"]["residual_impact"], serde_json::Value::Null);
    assert_eq!(payload["risk"]["review_date"], serde_json::Value::Null);

    let stored_status: String = sqlx::query_scalar("SELECT status FROM risks_risk WHERE id = 10")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored_status, "CLOSED");
}

#[tokio::test]
async fn risk_update_blocks_foreign_tenant_risk() {
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
                .method("PATCH")
                .uri("/api/v1/risks/12")
                .header("content-type", "application/json")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::from(r#"{"title": "Should not cross tenant"}"#))
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
async fn evidence_need_sync_creates_and_updates_session_needs() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_evidence_tables(&pool).await;
    insert_evidence_fixture(&pool).await;
    sqlx::query(
        r#"
        INSERT INTO requirements_app_requirement (
            id,
            framework,
            code,
            title,
            description,
            is_active,
            evidence_required,
            evidence_guidance,
            evidence_examples,
            sector_package,
            legal_reference,
            mapping_version_id,
            primary_source_id
        )
        VALUES (
            3,
            'NIS2',
            '21.3',
            'Digital Supplier Controls',
            'Manage digital supplier controls',
            1,
            1,
            '',
            'Supplier contracts and review records',
            'DIGITAL',
            'NIS2 Art. 21',
            1,
            NULL
        )
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();
    let app = app_router_with_state(
        AppState::default()
            .with_evidence_store(Some(EvidenceStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/evidence/sessions/100/needs/sync")
                .header("content-type", "application/json")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::from(
                    r#"{"covered_threshold":2,"partial_threshold":1}"#,
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
    assert_eq!(payload["session_id"], 100);
    assert_eq!(payload["created"], 1);
    assert_eq!(payload["updated"], 2);
    assert_eq!(payload["need_summary"]["open"], 1);
    assert_eq!(payload["need_summary"]["partial"], 2);
    assert_eq!(payload["need_summary"]["covered"], 0);

    let updated: (String, i64) = sqlx::query_as(
        r#"
        SELECT status, covered_count
        FROM evidence_requirementevidenceneed
        WHERE tenant_id = 42 AND session_id = 100 AND requirement_id = 1
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(updated.0, "PARTIAL");
    assert_eq!(updated.1, 1);

    let created_status: String = sqlx::query_scalar(
        r#"
        SELECT status
        FROM evidence_requirementevidenceneed
        WHERE tenant_id = 42 AND session_id = 100 AND requirement_id = 3
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(created_status, "OPEN");
}

#[tokio::test]
async fn evidence_need_sync_blocks_foreign_tenant_session() {
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
                .method("POST")
                .uri("/api/v1/evidence/sessions/102/needs/sync")
                .header("content-type", "application/json")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .body(Body::from(
                    r#"{"covered_threshold":2,"partial_threshold":1}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "evidence_session_not_found");
}

#[tokio::test]
async fn import_center_jobs_require_authenticated_tenant_context() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/import-center/jobs")
                .header("x-iscy-tenant-id", "42")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"import_type":"processes","replace_existing":false,"rows":[]}"#,
                ))
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
async fn import_center_jobs_require_configured_database() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/import-center/jobs")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"import_type":"processes","replace_existing":false,"rows":[]}"#,
                ))
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
async fn import_center_job_applies_process_rows_from_database() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_import_tables(&pool).await;
    insert_import_fixture(&pool).await;
    let app = app_router_with_state(
        AppState::default().with_import_store(Some(ImportStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/import-center/jobs")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"
                    {
                        "import_type": "processes",
                        "replace_existing": false,
                        "rows": [
                            {
                                "name": "Incident Intake",
                                "business_unit": "Security Operations",
                                "scope": "SOC",
                                "description": "Updated intake",
                                "status": "SUFFICIENT",
                                "documented": "yes",
                                "approved": "yes",
                                "communicated": "yes",
                                "implemented": "yes",
                                "effective": "yes",
                                "evidenced": "yes"
                            },
                            {
                                "name": "Vendor Review",
                                "business_unit": "Governance",
                                "scope": "Suppliers",
                                "description": "Review supplier risk",
                                "status": "PARTIAL",
                                "documented": true
                            },
                            {"name": ""}
                        ]
                    }
                    "#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["accepted"], true);
    assert_eq!(payload["result"]["tenant_id"], 42);
    assert_eq!(payload["result"]["created"], 1);
    assert_eq!(payload["result"]["updated"], 1);
    assert_eq!(payload["result"]["skipped"], 1);

    let process_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM processes_process WHERE tenant_id = 42")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(process_count, 2);
    let updated = sqlx::query(
        "SELECT status, evidenced FROM processes_process WHERE tenant_id = 42 AND name = 'Incident Intake'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let status: String = updated.try_get("status").unwrap();
    let evidenced: bool = updated.try_get("evidenced").unwrap();
    assert_eq!(status, "SUFFICIENT");
    assert!(evidenced);
    let governance_bu_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM organizations_businessunit WHERE tenant_id = 42 AND name = 'Governance'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(governance_bu_count, 1);
}

#[tokio::test]
async fn import_center_job_replaces_tenant_assets() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_import_tables(&pool).await;
    insert_import_fixture(&pool).await;
    let app = app_router_with_state(
        AppState::default().with_import_store(Some(ImportStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/import-center/jobs")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"
                    {
                        "import_type": "assets",
                        "replace_existing": true,
                        "rows": [
                            {
                                "name": "Customer Portal",
                                "business_unit": "Digital Services",
                                "asset_type": "APPLICATION",
                                "criticality": "HIGH",
                                "description": "External portal",
                                "confidentiality": "HIGH",
                                "integrity": "HIGH",
                                "availability": "MEDIUM",
                                "lifecycle_status": "active",
                                "in_scope": "yes"
                            },
                            {
                                "name": "Data Lake",
                                "asset_type": "DATA",
                                "criticality": "VERY_HIGH",
                                "description": "Analytics platform",
                                "in_scope": "no"
                            },
                            {"name": ""}
                        ]
                    }
                    "#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["result"]["created"], 2);
    assert_eq!(payload["result"]["updated"], 0);
    assert_eq!(payload["result"]["skipped"], 1);

    let asset_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM assets_app_informationasset WHERE tenant_id = 42")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(asset_count, 2);
    let old_asset_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM assets_app_informationasset WHERE tenant_id = 42 AND name = 'Legacy CRM'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(old_asset_count, 0);
    let data_lake = sqlx::query(
        "SELECT asset_type, criticality, is_in_scope FROM assets_app_informationasset WHERE tenant_id = 42 AND name = 'Data Lake'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let asset_type: String = data_lake.try_get("asset_type").unwrap();
    let criticality: String = data_lake.try_get("criticality").unwrap();
    let is_in_scope: bool = data_lake.try_get("is_in_scope").unwrap();
    assert_eq!(asset_type, "DATA");
    assert_eq!(criticality, "VERY_HIGH");
    assert!(!is_in_scope);
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
async fn roadmap_task_update_updates_tenant_task_from_database() {
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
                .method("PATCH")
                .uri("/api/v1/roadmap/tasks/1001")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"status":"DONE","planned_start":"2026-05-02","due_date":"2026-05-08","owner_role":"CISO Office","notes":"Closed in Rust"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["api_version"], "v1");
    assert_eq!(payload["plan_id"], 10);
    assert_eq!(payload["task"]["id"], 1001);
    assert_eq!(payload["task"]["status"], "DONE");
    assert_eq!(payload["task"]["status_label"], "Erledigt");
    assert_eq!(payload["task"]["owner_role"], "CISO Office");
    assert_eq!(payload["task"]["notes"], "Closed in Rust");

    let row =
        sqlx::query("SELECT status, owner_role, notes FROM roadmap_roadmaptask WHERE id = 1001")
            .fetch_one(&pool)
            .await
            .unwrap();
    let status: String = row.try_get("status").unwrap();
    let owner_role: String = row.try_get("owner_role").unwrap();
    let notes: String = row.try_get("notes").unwrap();
    assert_eq!(status, "DONE");
    assert_eq!(owner_role, "CISO Office");
    assert_eq!(notes, "Closed in Rust");
}

#[tokio::test]
async fn roadmap_task_update_blocks_foreign_tenant_task() {
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
                .method("PATCH")
                .uri("/api/v1/roadmap/tasks/1201")
                .header("x-iscy-tenant-id", "42")
                .header("x-iscy-user-id", "7")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"status":"DONE"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error_code"], "roadmap_task_not_found");
}

#[tokio::test]
async fn wizard_sessions_requires_authenticated_tenant_context() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/wizard/sessions")
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
async fn wizard_sessions_requires_configured_database() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/wizard/sessions")
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
async fn wizard_sessions_return_tenant_sessions_from_database() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_wizard_tables(&pool).await;
    insert_wizard_fixture(&pool).await;
    let app = app_router_with_state(
        AppState::default().with_wizard_store(Some(WizardStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/wizard/sessions")
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
    assert_eq!(payload["sessions"].as_array().unwrap().len(), 2);
    assert_eq!(payload["sessions"][0]["id"], 101);
    assert_eq!(
        payload["sessions"][0]["assessment_type_label"],
        "ISO-27001-Readiness bewerten"
    );
    assert_eq!(payload["sessions"][0]["started_by_display"], "Ada Lovelace");
    assert_eq!(payload["sessions"][1]["id"], 100);
}

#[tokio::test]
async fn wizard_results_return_full_result_tree_from_database() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_wizard_tables(&pool).await;
    insert_wizard_fixture(&pool).await;
    let app = app_router_with_state(
        AppState::default().with_wizard_store(Some(WizardStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/wizard/sessions/100/results")
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
    assert_eq!(payload["session"]["id"], 100);
    assert_eq!(payload["session"]["tenant_id"], 42);
    assert_eq!(payload["domain_scores"].as_array().unwrap().len(), 2);
    assert_eq!(payload["domain_scores"][0]["domain_name"], "Governance");
    assert_eq!(payload["gaps"].as_array().unwrap().len(), 1);
    assert_eq!(payload["gaps"][0]["severity_label"], "Hoch");
    assert_eq!(payload["measures"].as_array().unwrap().len(), 2);
    assert_eq!(payload["measures"][0]["priority_label"], "Kritisch");
    assert_eq!(payload["evidence_count"], 2);
    assert_eq!(payload["report"]["title"], "April Readiness");
    assert_eq!(
        payload["report"]["domain_scores_json"][0]["domain"],
        "Governance"
    );
    assert_eq!(payload["roadmap"]["plan"]["title"], "Security Roadmap");
    assert_eq!(payload["roadmap"]["phases"][0]["name"], "Governance Phase");
    assert_eq!(
        payload["roadmap"]["tasks"][0]["title"],
        "Policy aktualisieren"
    );
}

#[tokio::test]
async fn wizard_results_blocks_foreign_tenant_session() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    create_wizard_tables(&pool).await;
    insert_wizard_fixture(&pool).await;
    let app = app_router_with_state(
        AppState::default().with_wizard_store(Some(WizardStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/wizard/sessions/200/results")
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
    assert_eq!(payload["error_code"], "wizard_session_not_found");
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
async fn rust_web_dashboard_without_context_renders_context_form() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .uri("/dashboard/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("Tenant-ID"));
    assert!(html.contains("User-ID"));
    assert!(!html.contains("Rust-Web-Migrationsroute"));
}

#[tokio::test]
async fn rust_web_dashboard_renders_summary_from_database() {
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
                .uri("/dashboard/?tenant_id=42&user_id=7&user_email=ada%40example.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("Dashboard"));
    assert!(html.contains("Prozesse"));
    assert!(html.contains("April Readiness"));
    assert!(html.contains("ISO 78%"));
    assert!(html.contains("ada@example.test"));
    assert!(!html.contains("Rust-Web-Migrationsroute"));
}

#[tokio::test]
async fn rust_web_risks_renders_rows_from_database() {
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
                .uri("/risks/?tenant_id=42&user_id=7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("Credential Phishing"));
    assert!(html.contains("Kritisch"));
    assert!(html.contains("Ada Lovelace"));
    assert!(!html.contains("Rust-Web-Migrationsroute"));
}

#[tokio::test]
async fn rust_web_reports_renders_snapshots_from_database() {
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
                .uri("/reports/?tenant_id=42&user_id=7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("April Readiness"));
    assert!(html.contains("ISO"));
    assert!(html.contains("78%"));
    assert!(html.contains("82%"));
    assert!(!html.contains("Rust-Web-Migrationsroute"));
}

#[tokio::test]
async fn rust_web_roadmap_renders_plans_from_database() {
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
                .uri("/roadmap/?tenant_id=42&user_id=7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("Security Roadmap"));
    assert!(html.contains("HIGH"));
    assert!(html.contains("2026-05-01"));
    assert!(!html.contains("Foreign Roadmap"));
    assert!(!html.contains("Rust-Web-Migrationsroute"));
}

#[tokio::test]
async fn rust_web_assets_renders_inventory_from_database() {
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
                .uri("/assets/?tenant_id=42&user_id=7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("Customer Portal"));
    assert!(html.contains("Digital Services"));
    assert!(html.contains("Ada Lovelace"));
    assert!(html.contains("Anwendung"));
    assert!(!html.contains("Foreign BU"));
    assert!(!html.contains("Rust-Web-Migrationsroute"));
}

#[tokio::test]
async fn rust_web_processes_renders_register_from_database() {
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
                .uri("/processes/?tenant_id=42&user_id=7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("Incident Intake"));
    assert!(html.contains("Security Operations"));
    assert!(html.contains("Ada Lovelace"));
    assert!(html.contains("Vorhanden, aber unvollständig"));
    assert!(!html.contains("Foreign BU"));
    assert!(!html.contains("Rust-Web-Migrationsroute"));
}

#[tokio::test]
async fn rust_db_admin_migrates_and_seeds_demo_web_cutover_database() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();

    let applied = db_admin::run_sqlite_migrations(&pool).await.unwrap();
    assert_eq!(
        applied,
        vec![
            "0001_rust_operational_core",
            "0002_rust_product_security_core",
            "0003_rust_catalog_requirement_core",
            "0004_rust_auth_session_core"
        ]
    );
    assert!(
        db_admin::sqlite_table_exists(&pool, "iscy_schema_migrations")
            .await
            .unwrap()
    );
    assert!(
        db_admin::sqlite_table_exists(&pool, "reports_reportsnapshot")
            .await
            .unwrap()
    );
    assert!(
        db_admin::sqlite_table_exists(&pool, "product_security_product")
            .await
            .unwrap()
    );
    assert!(
        db_admin::sqlite_table_exists(&pool, "catalog_assessmentquestion")
            .await
            .unwrap()
    );
    assert!(
        db_admin::sqlite_table_exists(&pool, "requirements_app_requirementquestionmapping")
            .await
            .unwrap()
    );
    assert!(db_admin::sqlite_table_exists(&pool, "iscy_auth_session")
        .await
        .unwrap());

    let applied_again = db_admin::run_sqlite_migrations(&pool).await.unwrap();
    assert!(applied_again.is_empty());
    db_admin::seed_sqlite_demo(&pool).await.unwrap();
    db_admin::seed_sqlite_demo(&pool).await.unwrap();

    let app = app_router_with_state(
        AppState::default()
            .with_dashboard_store(Some(DashboardStore::from_sqlite_pool(pool.clone())))
            .with_report_store(Some(ReportStore::from_sqlite_pool(pool.clone())))
            .with_roadmap_store(Some(RoadmapStore::from_sqlite_pool(pool.clone())))
            .with_asset_store(Some(AssetStore::from_sqlite_pool(pool.clone())))
            .with_process_store(Some(ProcessStore::from_sqlite_pool(pool.clone())))
            .with_risk_store(Some(RiskStore::from_sqlite_pool(pool.clone())))
            .with_evidence_store(Some(EvidenceStore::from_sqlite_pool(pool.clone()))),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/dashboard/?tenant_id=1&user_id=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("Rust Demo Readiness"));
    assert!(html.contains("Offene Risiken"));

    let app = app_router_with_state(
        AppState::default()
            .with_roadmap_store(Some(RoadmapStore::from_sqlite_pool(pool.clone())))
            .with_asset_store(Some(AssetStore::from_sqlite_pool(pool.clone())))
            .with_process_store(Some(ProcessStore::from_sqlite_pool(pool.clone()))),
    );
    for (path, expected) in [
        ("/roadmap/?tenant_id=1&user_id=1", "Rust Cutover Roadmap"),
        ("/assets/?tenant_id=1&user_id=1", "Customer Portal"),
        ("/processes/?tenant_id=1&user_id=1", "Incident Intake"),
    ] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "path {path}");
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains(expected), "path {path}");
    }

    let app =
        app_router_with_state(AppState::default().with_product_security_store(Some(
            ProductSecurityStore::from_sqlite_pool(pool.clone()),
        )));
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/product-security/overview")
                .header("x-iscy-tenant-id", "1")
                .header("x-iscy-user-id", "1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["posture"]["products"], 1);
    assert_eq!(payload["posture"]["open_vulnerabilities"], 2);
    assert_eq!(payload["products"][0]["name"], "Rust Sensor Gateway");
    assert_eq!(payload["snapshots"][0]["cra_readiness_percent"], 73);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/product-security/products/1100/roadmap")
                .header("x-iscy-tenant-id", "1")
                .header("x-iscy-user-id", "1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["roadmap"]["title"], "Rust Gateway Roadmap");
    assert_eq!(payload["tasks"].as_array().unwrap().len(), 2);

    let app = app_router_with_state(
        AppState::default()
            .with_catalog_store(Some(CatalogStore::from_sqlite_pool(pool.clone())))
            .with_requirement_store(Some(RequirementStore::from_sqlite_pool(pool.clone()))),
    );
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/catalog/domains")
                .header("x-iscy-tenant-id", "1")
                .header("x-iscy-user-id", "1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["question_count"], 74);
    assert_eq!(payload["domains"].as_array().unwrap().len(), 19);
    assert_eq!(payload["domains"][0]["code"], "GOV");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/requirements")
                .header("x-iscy-tenant-id", "1")
                .header("x-iscy-user-id", "1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["requirements"].as_array().unwrap().len(), 39);
    assert_eq!(payload["mapping_versions"].as_array().unwrap().len(), 4);

    let mapping_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM requirements_app_requirementquestionmapping")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(mapping_count, 67);
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

async fn create_catalog_tables(pool: &SqlitePool) {
    sqlx::query(
        r#"
        CREATE TABLE catalog_assessmentdomain (
            id INTEGER PRIMARY KEY,
            code varchar(64) NOT NULL,
            name varchar(255) NOT NULL,
            description TEXT NOT NULL,
            weight INTEGER NOT NULL,
            sort_order INTEGER NOT NULL,
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
        CREATE TABLE catalog_assessmentquestion (
            id INTEGER PRIMARY KEY,
            domain_id INTEGER NULL,
            code varchar(64) NOT NULL,
            text varchar(500) NOT NULL,
            help_text TEXT NOT NULL,
            why_it_matters TEXT NOT NULL,
            question_kind varchar(20) NOT NULL,
            wizard_step varchar(20) NOT NULL,
            weight INTEGER NOT NULL,
            is_required bool NOT NULL,
            applies_to_iso27001 bool NOT NULL,
            applies_to_nis2 bool NOT NULL,
            applies_to_cra bool NOT NULL,
            applies_to_ai_act bool NOT NULL,
            applies_to_iec62443 bool NOT NULL,
            applies_to_iso_sae_21434 bool NOT NULL,
            applies_to_product_security bool NOT NULL,
            sort_order INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_catalog_fixture(pool: &SqlitePool) {
    sqlx::query(
        r#"
        INSERT INTO catalog_assessmentdomain (
            id,
            code,
            name,
            description,
            weight,
            sort_order,
            created_at,
            updated_at
        )
        VALUES
            (1, 'GOV', 'Governance', 'Governance controls', 10, 1, '2026-04-01T10:00:00Z', '2026-04-01T11:00:00Z'),
            (2, 'IAM', 'Identity Access', 'Identity controls', 10, 2, '2026-04-01T10:00:00Z', '2026-04-01T11:00:00Z')
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO catalog_assessmentquestion (
            id,
            domain_id,
            code,
            text,
            help_text,
            why_it_matters,
            question_kind,
            wizard_step,
            weight,
            is_required,
            applies_to_iso27001,
            applies_to_nis2,
            applies_to_cra,
            applies_to_ai_act,
            applies_to_iec62443,
            applies_to_iso_sae_21434,
            applies_to_product_security,
            sort_order,
            created_at,
            updated_at
        )
        VALUES
            (
                10,
                1,
                'GOV-APP-1',
                'Ist der NIS2-Scope geklaert?',
                'Scope help',
                'Scope matters',
                'APPLICABILITY',
                'applicability',
                10,
                1,
                1,
                1,
                0,
                0,
                0,
                0,
                0,
                1,
                '2026-04-01T10:00:00Z',
                '2026-04-01T11:00:00Z'
            ),
            (
                11,
                1,
                'GOV-MAT-1',
                'Sind Policies dokumentiert?',
                'Policy help',
                'Policy matters',
                'MATURITY',
                'maturity',
                10,
                1,
                1,
                1,
                1,
                0,
                0,
                0,
                0,
                2,
                '2026-04-01T10:00:00Z',
                '2026-04-01T11:00:00Z'
            ),
            (
                12,
                2,
                'IAM-MAT-1',
                'Ist MFA umgesetzt?',
                'MFA help',
                'MFA matters',
                'MATURITY',
                'maturity',
                10,
                1,
                1,
                1,
                0,
                0,
                0,
                0,
                1,
                1,
                '2026-04-01T10:00:00Z',
                '2026-04-01T11:00:00Z'
            )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn create_requirement_tables(pool: &SqlitePool) {
    sqlx::query(
        r#"
        CREATE TABLE requirements_app_mappingversion (
            id INTEGER PRIMARY KEY,
            framework varchar(32) NOT NULL,
            slug varchar(50) NOT NULL,
            title varchar(255) NOT NULL,
            version varchar(32) NOT NULL,
            program_name varchar(64) NOT NULL,
            status varchar(16) NOT NULL,
            effective_on date NULL,
            notes TEXT NOT NULL,
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
        CREATE TABLE requirements_app_regulatorysource (
            id INTEGER PRIMARY KEY,
            framework varchar(32) NOT NULL,
            mapping_version_id INTEGER NOT NULL,
            code varchar(64) NOT NULL,
            title varchar(255) NOT NULL,
            authority varchar(128) NOT NULL,
            citation varchar(255) NOT NULL,
            url varchar(200) NOT NULL,
            source_type varchar(32) NOT NULL,
            published_on date NULL,
            effective_on date NULL,
            notes TEXT NOT NULL,
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
        CREATE TABLE requirements_app_requirement (
            id INTEGER PRIMARY KEY,
            framework varchar(32) NOT NULL,
            code varchar(64) NOT NULL,
            title varchar(255) NOT NULL,
            domain varchar(255) NOT NULL,
            description TEXT NOT NULL,
            guidance TEXT NOT NULL,
            is_active bool NOT NULL,
            evidence_required bool NOT NULL,
            evidence_guidance TEXT NOT NULL,
            evidence_examples TEXT NOT NULL,
            sector_package varchar(64) NOT NULL,
            legal_reference varchar(128) NOT NULL,
            mapped_controls TEXT NOT NULL,
            mapping_rationale TEXT NOT NULL,
            coverage_level varchar(16) NOT NULL,
            mapping_version_id INTEGER NULL,
            primary_source_id INTEGER NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_requirement_fixture(pool: &SqlitePool) {
    sqlx::query(
        r#"
        INSERT INTO requirements_app_mappingversion (
            id,
            framework,
            slug,
            title,
            version,
            program_name,
            status,
            effective_on,
            notes,
            created_at,
            updated_at
        )
        VALUES
            (1, 'ISO27001', 'iso27001-2022', 'ISO 27001 Mapping', '2022', 'ISCY', 'ACTIVE', '2026-01-01', 'Active mapping', '2026-04-01T10:00:00Z', '2026-04-01T11:00:00Z'),
            (2, 'NIS2', 'nis2-draft', 'NIS2 Draft', 'draft', 'ISCY', 'DRAFT', NULL, 'Draft mapping', '2026-04-01T10:00:00Z', '2026-04-01T11:00:00Z')
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO requirements_app_regulatorysource (
            id,
            framework,
            mapping_version_id,
            code,
            title,
            authority,
            citation,
            url,
            source_type,
            published_on,
            effective_on,
            notes,
            created_at,
            updated_at
        )
        VALUES
            (
                10,
                'ISO27001',
                1,
                'A.5.17',
                'Authentication Information',
                'ISO',
                'ISO/IEC 27001:2022 A.5.17',
                'https://example.test/iso',
                'STANDARD',
                '2022-10-25',
                '2022-10-25',
                '',
                '2026-04-01T10:00:00Z',
                '2026-04-01T11:00:00Z'
            )
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
            domain,
            description,
            guidance,
            is_active,
            evidence_required,
            evidence_guidance,
            evidence_examples,
            sector_package,
            legal_reference,
            mapped_controls,
            mapping_rationale,
            coverage_level,
            mapping_version_id,
            primary_source_id,
            created_at,
            updated_at
        )
        VALUES
            (
                100,
                'ISO27001',
                'A.5.17',
                'Authentication Information',
                'Identity',
                'Protect authentication information',
                'Use MFA and vaulting',
                1,
                1,
                'MFA policy',
                'Policy, screenshots',
                'ALL',
                'ISO/IEC 27001:2022 A.5.17',
                '[]',
                'Primary identity control',
                'PRIMARY',
                1,
                10,
                '2026-04-01T10:00:00Z',
                '2026-04-01T11:00:00Z'
            ),
            (
                101,
                'NIS2',
                '21.2',
                'Incident Handling',
                'Incident Response',
                'Handle incidents',
                '',
                1,
                1,
                '',
                '',
                'ALL',
                'NIS2 Art. 21',
                '[]',
                '',
                'SUPPORTING',
                NULL,
                NULL,
                '2026-04-01T10:00:00Z',
                '2026-04-01T11:00:00Z'
            )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn create_import_tables(pool: &SqlitePool) {
    sqlx::query(
        r#"
        CREATE TABLE organizations_businessunit (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            owner_id INTEGER NULL,
            name varchar(255) NOT NULL,
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
        CREATE TABLE organizations_supplier (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            owner_id INTEGER NULL,
            name varchar(255) NOT NULL,
            service_description TEXT NOT NULL,
            criticality varchar(32) NOT NULL,
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

async fn insert_import_fixture(pool: &SqlitePool) {
    sqlx::query(
        r#"
        INSERT INTO organizations_businessunit (
            id,
            tenant_id,
            owner_id,
            name,
            created_at,
            updated_at
        )
        VALUES
            (1, 42, NULL, 'Security Operations', '2026-04-01T10:00:00Z', '2026-04-01T11:00:00Z'),
            (2, 42, NULL, 'Digital Services', '2026-04-01T10:00:00Z', '2026-04-01T11:00:00Z'),
            (3, 99, NULL, 'Foreign BU', '2026-04-01T10:00:00Z', '2026-04-01T11:00:00Z')
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
                NULL,
                'Incident Intake',
                'SOC',
                'SOC intake process',
                'PARTIAL',
                1,
                0,
                0,
                1,
                0,
                0,
                NULL,
                '2026-04-18T10:00:00Z',
                '2026-04-18T11:00:00Z'
            )
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
                20,
                42,
                2,
                NULL,
                'Legacy CRM',
                'APPLICATION',
                'LOW',
                'Legacy application',
                'LOW',
                'LOW',
                'LOW',
                'retired',
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

async fn create_product_security_tables(pool: &SqlitePool) {
    sqlx::query(
        r#"
        CREATE TABLE organizations_tenant (
            id INTEGER PRIMARY KEY,
            sector varchar(64) NOT NULL,
            develops_digital_products bool NOT NULL,
            uses_ai_systems bool NOT NULL,
            ot_iacs_scope bool NOT NULL,
            automotive_scope bool NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE organizations_supplier (
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
        CREATE TABLE product_security_productfamily (
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
        CREATE TABLE product_security_product (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            family_id INTEGER NULL,
            name varchar(255) NOT NULL,
            code varchar(100) NOT NULL,
            description TEXT NOT NULL,
            has_digital_elements bool NOT NULL,
            includes_ai bool NOT NULL,
            ot_iacs_context bool NOT NULL,
            automotive_context bool NOT NULL,
            support_window_months INTEGER NOT NULL,
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
        CREATE TABLE product_security_productrelease (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            version varchar(64) NOT NULL,
            status varchar(16) NOT NULL,
            release_date TEXT NULL,
            support_end_date TEXT NULL,
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
        CREATE TABLE product_security_component (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            supplier_id INTEGER NULL,
            name varchar(255) NOT NULL,
            component_type varchar(16) NOT NULL,
            version varchar(64) NOT NULL,
            is_open_source bool NOT NULL,
            has_sbom bool NOT NULL,
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
        CREATE TABLE product_security_aisystem (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            product_id INTEGER NULL,
            name varchar(255) NOT NULL,
            use_case TEXT NOT NULL,
            provider varchar(255) NOT NULL,
            risk_classification varchar(16) NOT NULL,
            in_scope bool NOT NULL,
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
        CREATE TABLE product_security_threatmodel (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            release_id INTEGER NULL,
            name varchar(255) NOT NULL,
            methodology varchar(100) NOT NULL,
            summary TEXT NOT NULL,
            status varchar(16) NOT NULL,
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
        CREATE TABLE product_security_threatscenario (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            threat_model_id INTEGER NOT NULL,
            component_id INTEGER NULL,
            title varchar(255) NOT NULL,
            category varchar(32) NOT NULL,
            attack_path TEXT NOT NULL,
            impact TEXT NOT NULL,
            severity varchar(16) NOT NULL,
            mitigation_status varchar(64) NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE product_security_tara (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            release_id INTEGER NULL,
            scenario_id INTEGER NULL,
            name varchar(255) NOT NULL,
            summary TEXT NOT NULL,
            attack_feasibility INTEGER NOT NULL,
            impact_score INTEGER NOT NULL,
            risk_score INTEGER NOT NULL,
            status varchar(16) NOT NULL,
            treatment_decision varchar(128) NOT NULL,
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
        CREATE TABLE product_security_vulnerability (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            release_id INTEGER NULL,
            component_id INTEGER NULL,
            title varchar(255) NOT NULL,
            cve varchar(50) NOT NULL,
            severity varchar(16) NOT NULL,
            status varchar(16) NOT NULL,
            remediation_due TEXT NULL,
            summary TEXT NOT NULL,
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
        CREATE TABLE product_security_psirtcase (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            release_id INTEGER NULL,
            vulnerability_id INTEGER NULL,
            case_id varchar(64) NOT NULL,
            title varchar(255) NOT NULL,
            severity varchar(16) NOT NULL,
            status varchar(20) NOT NULL,
            disclosure_due TEXT NULL,
            summary TEXT NOT NULL,
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
        CREATE TABLE product_security_securityadvisory (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            release_id INTEGER NULL,
            psirt_case_id INTEGER NULL,
            advisory_id varchar(64) NOT NULL,
            title varchar(255) NOT NULL,
            status varchar(16) NOT NULL,
            published_on TEXT NULL,
            summary TEXT NOT NULL,
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
        CREATE TABLE product_security_productsecuritysnapshot (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            cra_applicable bool NOT NULL,
            ai_act_applicable bool NOT NULL,
            iec62443_applicable bool NOT NULL,
            iso_sae_21434_applicable bool NOT NULL,
            cra_readiness_percent INTEGER NOT NULL,
            ai_act_readiness_percent INTEGER NOT NULL,
            iec62443_readiness_percent INTEGER NOT NULL,
            iso_sae_21434_readiness_percent INTEGER NOT NULL,
            threat_model_coverage_percent INTEGER NOT NULL,
            psirt_readiness_percent INTEGER NOT NULL,
            open_vulnerability_count INTEGER NOT NULL,
            critical_vulnerability_count INTEGER NOT NULL,
            summary TEXT NOT NULL,
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
        CREATE TABLE product_security_productsecurityroadmap (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            title varchar(255) NOT NULL,
            summary TEXT NOT NULL,
            generated_from_snapshot_id INTEGER NULL,
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
        CREATE TABLE product_security_productsecurityroadmaptask (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            roadmap_id INTEGER NOT NULL,
            related_release_id INTEGER NULL,
            related_vulnerability_id INTEGER NULL,
            phase varchar(16) NOT NULL,
            title varchar(255) NOT NULL,
            description TEXT NOT NULL,
            priority varchar(32) NOT NULL,
            owner_role varchar(64) NOT NULL,
            due_in_days INTEGER NOT NULL,
            dependency_text TEXT NOT NULL,
            status varchar(16) NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_product_security_fixture(pool: &SqlitePool) {
    sqlx::query(
        r#"
        INSERT INTO organizations_tenant (
            id, sector, develops_digital_products, uses_ai_systems, ot_iacs_scope, automotive_scope
        )
        VALUES
            (42, 'MANUFACTURING', 1, 1, 0, 0),
            (99, 'OTHER', 1, 0, 0, 0)
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO organizations_supplier (id, tenant_id, name)
        VALUES (50, 42, 'Secure Supplier')
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO product_security_productfamily (id, tenant_id, name)
        VALUES (10, 42, 'Gateways'), (11, 99, 'Foreign Family')
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO product_security_product (
            id,
            tenant_id,
            family_id,
            name,
            code,
            description,
            has_digital_elements,
            includes_ai,
            ot_iacs_context,
            automotive_context,
            support_window_months,
            created_at,
            updated_at
        )
        VALUES
            (
                100,
                42,
                10,
                'Sensor Gateway',
                'sensor-gateway',
                'Industrial edge device',
                1,
                1,
                1,
                0,
                36,
                '2026-04-18T10:00:00Z',
                '2026-04-18T11:00:00Z'
            ),
            (
                101,
                99,
                11,
                'Foreign Product',
                'foreign-product',
                'Other tenant',
                1,
                0,
                0,
                0,
                24,
                '2026-04-18T10:00:00Z',
                '2026-04-18T11:00:00Z'
            )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO product_security_productrelease (
            id,
            tenant_id,
            product_id,
            version,
            status,
            release_date,
            support_end_date,
            created_at,
            updated_at
        )
        VALUES
            (
                200,
                42,
                100,
                '1.0',
                'ACTIVE',
                '2026-04-01',
                '2028-04-01',
                '2026-04-18T10:00:00Z',
                '2026-04-18T11:00:00Z'
            ),
            (
                201,
                42,
                100,
                '0.9',
                'EOL',
                '2025-01-01',
                '2026-01-01',
                '2026-04-18T09:00:00Z',
                '2026-04-18T09:30:00Z'
            ),
            (
                202,
                99,
                101,
                '9.9',
                'ACTIVE',
                '2026-01-01',
                '2027-01-01',
                '2026-04-18T10:00:00Z',
                '2026-04-18T11:00:00Z'
            )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO product_security_component (
            id,
            tenant_id,
            product_id,
            supplier_id,
            name,
            component_type,
            version,
            is_open_source,
            has_sbom,
            created_at,
            updated_at
        )
        VALUES (
            250,
            42,
            100,
            50,
            'Gateway Firmware',
            'FIRMWARE',
            '1.0.3',
            0,
            1,
            '2026-04-18T10:00:00Z',
            '2026-04-18T11:00:00Z'
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO product_security_aisystem (
            id,
            tenant_id,
            product_id,
            name,
            use_case,
            provider,
            risk_classification,
            in_scope,
            created_at,
            updated_at
        )
        VALUES (
            260,
            42,
            100,
            'Gateway Assistant',
            'Firmware triage and support guidance',
            'Internal',
            'LIMITED',
            1,
            '2026-04-18T10:00:00Z',
            '2026-04-18T11:00:00Z'
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO product_security_threatmodel (
            id,
            tenant_id,
            product_id,
            release_id,
            name,
            methodology,
            summary,
            status,
            created_at,
            updated_at
        )
        VALUES (
            300,
            42,
            100,
            200,
            'Gateway Threat Model',
            'STRIDE',
            'Gateway threat model summary',
            'APPROVED',
            '2026-04-18T10:00:00Z',
            '2026-04-18T11:00:00Z'
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO product_security_threatscenario (
            id,
            tenant_id,
            threat_model_id,
            component_id,
            title,
            category,
            attack_path,
            impact,
            severity,
            mitigation_status
        )
        VALUES (
            301,
            42,
            300,
            250,
            'Unsigned firmware update',
            'TAMPERING',
            'Attacker replaces firmware package',
            'Remote code execution',
            'CRITICAL',
            'Open'
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO product_security_tara (
            id,
            tenant_id,
            product_id,
            release_id,
            scenario_id,
            name,
            summary,
            attack_feasibility,
            impact_score,
            risk_score,
            status,
            treatment_decision,
            created_at,
            updated_at
        )
        VALUES (
            400,
            42,
            100,
            200,
            301,
            'Gateway TARA',
            'TARA for firmware update abuse',
            3,
            4,
            12,
            'OPEN',
            'Mitigate in next firmware release',
            '2026-04-18T10:00:00Z',
            '2026-04-18T11:00:00Z'
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO product_security_vulnerability (
            id,
            tenant_id,
            product_id,
            release_id,
            component_id,
            title,
            cve,
            severity,
            status,
            remediation_due,
            summary,
            created_at,
            updated_at
        )
        VALUES
            (
                500,
                42,
                100,
                200,
                250,
                'Critical firmware exposure',
                'CVE-2026-0001',
                'CRITICAL',
                'OPEN',
                '2026-05-18',
                'Critical issue in firmware updater',
                '2026-04-18T10:00:00Z',
                '2026-04-18T11:00:00Z'
            ),
            (
                501,
                42,
                100,
                200,
                250,
                'Outdated dependency',
                '',
                'HIGH',
                'TRIAGED',
                '2026-06-01',
                'Dependency needs update',
                '2026-04-18T10:00:00Z',
                '2026-04-18T11:00:00Z'
            ),
            (
                502,
                42,
                100,
                200,
                250,
                'Fixed UI issue',
                '',
                'LOW',
                'FIXED',
                NULL,
                'Already fixed',
                '2026-04-18T10:00:00Z',
                '2026-04-18T11:00:00Z'
            )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO product_security_psirtcase (
            id,
            tenant_id,
            product_id,
            release_id,
            vulnerability_id,
            case_id,
            title,
            severity,
            status,
            disclosure_due,
            summary,
            created_at,
            updated_at
        )
        VALUES (
            600,
            42,
            100,
            200,
            500,
            'PSIRT-1',
            'Critical firmware disclosure',
            'CRITICAL',
            'TRIAGE',
            '2026-05-20',
            'PSIRT case for critical firmware exposure',
            '2026-04-18T10:00:00Z',
            '2026-04-18T11:00:00Z'
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO product_security_securityadvisory (
            id,
            tenant_id,
            product_id,
            release_id,
            psirt_case_id,
            advisory_id,
            title,
            status,
            published_on,
            summary,
            created_at,
            updated_at
        )
        VALUES (
            700,
            42,
            100,
            200,
            600,
            'ADV-1',
            'Gateway firmware advisory',
            'PUBLISHED',
            '2026-05-21',
            'Advisory for firmware exposure',
            '2026-04-18T10:00:00Z',
            '2026-04-18T11:00:00Z'
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO product_security_productsecuritysnapshot (
            id,
            tenant_id,
            product_id,
            cra_applicable,
            ai_act_applicable,
            iec62443_applicable,
            iso_sae_21434_applicable,
            cra_readiness_percent,
            ai_act_readiness_percent,
            iec62443_readiness_percent,
            iso_sae_21434_readiness_percent,
            threat_model_coverage_percent,
            psirt_readiness_percent,
            open_vulnerability_count,
            critical_vulnerability_count,
            summary,
            created_at,
            updated_at
        )
        VALUES (
            800,
            42,
            100,
            1,
            1,
            1,
            0,
            72,
            61,
            58,
            0,
            40,
            55,
            2,
            1,
            'Snapshot Tenant 42',
            '2026-04-18T10:00:00Z',
            '2026-04-18T11:00:00Z'
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO product_security_productsecurityroadmap (
            id,
            tenant_id,
            product_id,
            title,
            summary,
            generated_from_snapshot_id,
            created_at,
            updated_at
        )
        VALUES (
            900,
            42,
            100,
            'Gateway Roadmap',
            'Roadmap from Rust detail fixture',
            800,
            '2026-04-18T12:00:00Z',
            '2026-04-18T12:30:00Z'
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO product_security_productsecurityroadmaptask (
            id,
            tenant_id,
            roadmap_id,
            related_release_id,
            related_vulnerability_id,
            phase,
            title,
            description,
            priority,
            owner_role,
            due_in_days,
            dependency_text,
            status,
            created_at,
            updated_at
        )
        VALUES
            (
                901,
                42,
                900,
                200,
                NULL,
                'GOVERNANCE',
                'Define product security ownership',
                'Clarify owner roles and release gates',
                'HIGH',
                'Product Security Lead',
                30,
                '',
                'OPEN',
                '2026-04-18T12:00:00Z',
                '2026-04-18T12:30:00Z'
            ),
            (
                902,
                42,
                900,
                200,
                500,
                'RESPONSE',
                'Remediate critical firmware exposure',
                'Ship remediation and prepare disclosure',
                'CRITICAL',
                'PSIRT Lead',
                14,
                'Firmware patch readiness',
                'PLANNED',
                '2026-04-18T12:00:00Z',
                '2026-04-18T12:30:00Z'
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
        CREATE TABLE organizations_tenant (
            id INTEGER PRIMARY KEY,
            name varchar(255) NOT NULL,
            sector varchar(64) NOT NULL,
            kritis_relevant bool NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE wizard_assessmentsession (
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
            title varchar(255) NOT NULL,
            url varchar(200) NOT NULL
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
            description TEXT NOT NULL,
            is_active bool NOT NULL,
            evidence_required bool NOT NULL,
            evidence_guidance TEXT NOT NULL,
            evidence_examples TEXT NOT NULL,
            sector_package varchar(64) NOT NULL,
            legal_reference varchar(128) NOT NULL,
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
        INSERT INTO organizations_tenant (id, name, sector, kritis_relevant)
        VALUES
            (42, 'Tenant A', 'MSSP', 0),
            (99, 'Tenant B', 'OTHER', 0)
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO wizard_assessmentsession (id, tenant_id)
        VALUES
            (100, 42),
            (101, 42),
            (102, 99)
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
        INSERT INTO requirements_app_regulatorysource (id, authority, citation, title, url)
        VALUES (1, 'ISO', 'A.5.17', 'Authentication information', 'https://example.test/source')
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
            description,
            is_active,
            evidence_required,
            evidence_guidance,
            evidence_examples,
            sector_package,
            legal_reference,
            mapping_version_id,
            primary_source_id
        )
        VALUES
            (
                1,
                'ISO27001',
                'A.5.17',
                'Authentication Information',
                'Protect authentication information',
                1,
                1,
                'Collect MFA evidence',
                'MFA screenshots and policy approvals',
                'ALL',
                'ISO A.5.17',
                1,
                1
            ),
            (
                2,
                'NIS2',
                '21.2',
                'Incident Handling',
                'Manage security incidents',
                1,
                1,
                '',
                '',
                'ALL',
                '',
                1,
                NULL
            )
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

async fn create_wizard_tables(pool: &SqlitePool) {
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
        CREATE TABLE wizard_assessmentsession (
            id INTEGER PRIMARY KEY,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            tenant_id INTEGER NOT NULL,
            assessment_type varchar(24) NOT NULL,
            status varchar(20) NOT NULL,
            current_step varchar(24) NOT NULL,
            started_by_id INTEGER NULL,
            applicability_result varchar(64) NOT NULL,
            applicability_reasoning TEXT NOT NULL,
            executive_summary TEXT NOT NULL,
            progress_percent INTEGER NOT NULL,
            completed_at TEXT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE catalog_assessmentdomain (
            id INTEGER PRIMARY KEY,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            code varchar(64) NOT NULL,
            name varchar(255) NOT NULL,
            description TEXT NOT NULL,
            weight INTEGER NOT NULL,
            sort_order INTEGER NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE wizard_domainscore (
            id INTEGER PRIMARY KEY,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            session_id INTEGER NOT NULL,
            domain_id INTEGER NOT NULL,
            score_raw INTEGER NOT NULL,
            score_percent INTEGER NOT NULL,
            maturity_level varchar(64) NOT NULL,
            gap_level varchar(32) NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE wizard_generatedgap (
            id INTEGER PRIMARY KEY,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            session_id INTEGER NOT NULL,
            domain_id INTEGER NOT NULL,
            question_id INTEGER NULL,
            severity varchar(16) NOT NULL,
            title varchar(255) NOT NULL,
            description TEXT NOT NULL
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
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            session_id INTEGER NOT NULL,
            domain_id INTEGER NULL,
            question_id INTEGER NULL,
            title varchar(255) NOT NULL,
            description TEXT NOT NULL,
            priority varchar(16) NOT NULL,
            effort varchar(16) NOT NULL,
            measure_type varchar(20) NOT NULL,
            target_phase varchar(64) NOT NULL,
            owner_role varchar(64) NOT NULL,
            reason TEXT NOT NULL,
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
            tenant_id INTEGER NOT NULL,
            session_id INTEGER NULL
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

async fn insert_wizard_fixture(pool: &SqlitePool) {
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
            (9, 99, 'foreign', 'Foreign', 'User')
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO wizard_assessmentsession (
            id,
            created_at,
            updated_at,
            tenant_id,
            assessment_type,
            status,
            current_step,
            started_by_id,
            applicability_result,
            applicability_reasoning,
            executive_summary,
            progress_percent,
            completed_at
        )
        VALUES
            (
                100,
                '2026-04-17T10:00:00Z',
                '2026-04-17T11:00:00Z',
                42,
                'FULL',
                'COMPLETED',
                'results',
                7,
                'NIS2 relevant',
                'Critical managed service provider',
                'Executive summary from wizard',
                100,
                '2026-04-17T12:00:00Z'
            ),
            (
                101,
                '2026-04-18T10:00:00Z',
                '2026-04-18T11:00:00Z',
                42,
                'ISO_READINESS',
                'IN_PROGRESS',
                'maturity',
                7,
                '',
                '',
                '',
                75,
                NULL
            ),
            (
                200,
                '2026-04-19T10:00:00Z',
                '2026-04-19T11:00:00Z',
                99,
                'FULL',
                'COMPLETED',
                'results',
                9,
                'Foreign result',
                '',
                '',
                100,
                '2026-04-19T12:00:00Z'
            )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO catalog_assessmentdomain (
            id,
            created_at,
            updated_at,
            code,
            name,
            description,
            weight,
            sort_order
        )
        VALUES
            (1, '2026-04-01T10:00:00Z', '2026-04-01T11:00:00Z', 'GOV', 'Governance', '', 10, 1),
            (2, '2026-04-01T10:00:00Z', '2026-04-01T11:00:00Z', 'IAM', 'Identity Access', '', 10, 2)
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO wizard_domainscore (
            id,
            created_at,
            updated_at,
            session_id,
            domain_id,
            score_raw,
            score_percent,
            maturity_level,
            gap_level
        )
        VALUES
            (10, '2026-04-17T10:00:00Z', '2026-04-17T11:00:00Z', 100, 1, 8, 80, 'Managed', 'LOW'),
            (11, '2026-04-17T10:00:00Z', '2026-04-17T11:00:00Z', 100, 2, 4, 40, 'Basic', 'HIGH')
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO wizard_generatedgap (
            id,
            created_at,
            updated_at,
            session_id,
            domain_id,
            question_id,
            severity,
            title,
            description
        )
        VALUES
            (
                20,
                '2026-04-17T10:00:00Z',
                '2026-04-17T11:00:00Z',
                100,
                2,
                NULL,
                'HIGH',
                'MFA-Abdeckung fehlt',
                'MFA is not consistently enforced'
            )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO wizard_generatedmeasure (
            id,
            created_at,
            updated_at,
            session_id,
            domain_id,
            question_id,
            title,
            description,
            priority,
            effort,
            measure_type,
            target_phase,
            owner_role,
            reason,
            status
        )
        VALUES
            (
                30,
                '2026-04-17T10:00:00Z',
                '2026-04-17T11:00:00Z',
                100,
                2,
                NULL,
                'MFA ausrollen',
                'Roll out phishing-resistant MFA',
                'CRITICAL',
                'MEDIUM',
                'TECHNICAL',
                '30 Tage',
                'IAM Lead',
                'Identity gap',
                'OPEN'
            ),
            (
                31,
                '2026-04-17T10:00:00Z',
                '2026-04-17T11:00:00Z',
                100,
                1,
                NULL,
                'Policy aktualisieren',
                'Update security policy',
                'HIGH',
                'SMALL',
                'DOCUMENTARY',
                '30 Tage',
                'CISO',
                'Governance gap',
                'PLANNED'
            )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO evidence_evidenceitem (id, tenant_id, session_id)
        VALUES (1, 42, 100), (2, 42, 100), (3, 42, 101), (4, 99, 200)
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
                40,
                42,
                100,
                'April Readiness',
                'Report summary',
                'NIS2 relevant',
                80,
                75,
                30,
                20,
                10,
                15,
                25,
                '{"summary":"applicable"}',
                '{"ISO27001":{"framework":"ISO27001","version":"2022","title":"ISO","requirement_count":10,"source_count":1}}',
                '{"product_security_scope":"SOC platform"}',
                '[{"title":"MFA-Abdeckung fehlt"}]',
                '[{"title":"MFA ausrollen","priority":"CRITICAL"}]',
                '[{"name":"Governance"}]',
                '[{"domain":"Governance","score_percent":80,"maturity_level":"Managed"}]',
                '{"dependencies":[{"predecessor":"Policy","successor":"MFA","type":"FS","rationale":"Policy first"}],"next_30_days":[{"title":"MFA"}]}',
                '2026-04-17T10:00:00Z',
                '2026-04-17T11:00:00Z'
            )
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
                50,
                '2026-04-17T10:00:00Z',
                '2026-04-17T11:00:00Z',
                42,
                100,
                'Security Roadmap',
                'Roadmap summary',
                'HIGH',
                '2026-05-01'
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
                51,
                '2026-04-17T10:00:00Z',
                '2026-04-17T11:00:00Z',
                50,
                'Governance Phase',
                1,
                'Create governance',
                2,
                '2026-05-01',
                '2026-05-14'
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
                52,
                '2026-04-17T10:00:00Z',
                '2026-04-17T11:00:00Z',
                51,
                NULL,
                'Policy aktualisieren',
                'Update security policy',
                'HIGH',
                'CISO',
                14,
                '',
                'OPEN',
                '2026-05-01',
                '2026-05-07',
                ''
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
