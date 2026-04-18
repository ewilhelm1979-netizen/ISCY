use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use iscy_backend::app_router;
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
