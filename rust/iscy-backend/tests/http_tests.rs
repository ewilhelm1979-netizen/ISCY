use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use iscy_backend::{
    app_router, app_router_with_state, cve_store::CveStore, tenant_store::TenantStore, AppState,
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
