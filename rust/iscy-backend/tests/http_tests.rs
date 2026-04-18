use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use iscy_backend::{
    app_router, app_router_with_state, cve_store::CveStore, dashboard_store::DashboardStore,
    report_store::ReportStore, tenant_store::TenantStore, AppState,
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
