use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use iscy_backend::app_router;
use serde_json::Value;
use tower::util::ServiceExt;

#[tokio::test]
async fn health_endpoint_returns_ok() {
    let response = app_router()
        .oneshot(Request::builder().uri("/health/live").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn health_alias_endpoint_returns_ok() {
    let response = app_router()
        .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
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
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload.get("accepted").and_then(Value::as_bool), Some(true));
    assert_eq!(payload.get("cve_id").and_then(Value::as_str), Some("CVE-2026-9999"));
    assert_eq!(payload.get("year").and_then(Value::as_u64), Some(2026));
    assert_eq!(payload.get("sequence").and_then(Value::as_u64), Some(9999));
    assert_eq!(payload.get("nvd_lookup_attempted").and_then(Value::as_bool), Some(false));
}

#[tokio::test]
async fn nvd_import_endpoint_rejects_invalid_cve_id() {
    let response = app_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/nvd/import")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"cve_id":"invalid"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload.get("accepted").and_then(Value::as_bool), Some(false));
    assert_eq!(payload.get("is_valid").and_then(Value::as_bool), Some(false));
    assert_eq!(payload.get("nvd_lookup_attempted").and_then(Value::as_bool), Some(false));
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
