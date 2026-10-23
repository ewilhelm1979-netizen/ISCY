use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use iscy_backend::{
    app_router_with_state,
    assessment_store::AssessmentStore,
    auth_store::AuthStore,
    db_admin,
    hardening::{AppMode, CommunitySecurityConfig},
    import_store::ImportStore,
    soa::SoaEntryWriteRequest,
    AppState,
};
use serde_json::{json, Value};
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use tower::ServiceExt;

async fn fixture() -> (Router, SqlitePool, String) {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    fixture_with_pool(pool).await
}

async fn fixture_with_pool(pool: SqlitePool) -> (Router, SqlitePool, String) {
    db_admin::run_sqlite_migrations(&pool).await.unwrap();
    sqlx::raw_sql(
        "INSERT INTO organizations_tenant (id,name,slug) VALUES
         (42,'SoA Tenant','soa-tenant'),(99,'Foreign Tenant','foreign-soa');
         INSERT INTO accounts_user (id,tenant_id,username,role) VALUES
         (7,42,'soa-author','CONTRIBUTOR'),(8,99,'foreign-author','CONTRIBUTOR'),
         (9,42,'soa-reader','AUDITOR');
         INSERT INTO requirements_app_requirement (id,framework,code,title,is_active) VALUES
         (9001,'ISO27001','TEST-A.1','First active control',1),
         (9002,'ISO27001','TEST-A.2','Second active control',1),
         (9003,'ISO27001','TEST-A.3','Inactive control',0),
         (9004,'NIS2','TEST-NIS2','Different framework',1);",
    )
    .execute(&pool)
    .await
    .unwrap();
    let auth = AuthStore::from_sqlite_pool(pool.clone());
    let token = auth.create_session(42, 7).await.unwrap().unwrap().token;
    let app = app_router_with_state(
        AppState::default()
            .with_security_config(CommunitySecurityConfig {
                app_mode: AppMode::Production,
                trust_identity_headers: false,
                ..CommunitySecurityConfig::default()
            })
            .with_auth_store(Some(auth))
            .with_import_store(Some(ImportStore::from_sqlite_pool(pool.clone())))
            .with_assessment_store(Some(AssessmentStore::from_sqlite_pool(pool.clone()))),
    );
    (app, pool, token)
}

async fn generate(app: &Router, token: &str) -> (i64, Value) {
    let (status, generated) = request(
        app,
        "POST",
        "/api/v1/assessments/soa",
        Some(token),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = generated["document_id"].as_i64().unwrap();
    let (status, detail) = request(
        app,
        "GET",
        &format!("/api/v1/assessments/soa/{id}"),
        Some(token),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    (id, detail["document"].clone())
}

fn entry_payload(owner: Option<i64>) -> Value {
    json!({"is_applicable":false,"justification":"Human-reviewed exclusion <script>not executed</script>",
        "implementation_status":"NOT_APPLICABLE","control_owner_id":owner,
        "evidence_reference":"Reference only; never opened by the server","notes":"Review notes"})
}

async fn sqlite_snapshot(pool: &SqlitePool) -> Vec<String> {
    let mut result = Vec::new();
    for query in [
        "SELECT json_group_array(json_object('id',id,'tenant_id',tenant_id,'session_id',session_id,
         'title',title,'version',version,'status',status,'approved_by_id',approved_by_id,
         'approved_at',approved_at,'notes',notes,'created_at',created_at,'updated_at',updated_at))
         FROM (SELECT * FROM assessments_soadocument ORDER BY id)",
        "SELECT json_group_array(json_object('id',id,'soa_id',soa_id,'requirement_id',requirement_id,
         'is_applicable',is_applicable,'justification',justification,'implementation_status',implementation_status,
         'control_owner_id',control_owner_id,'evidence_reference',evidence_reference,'notes',notes,
         'created_at',created_at,'updated_at',updated_at))
         FROM (SELECT * FROM assessments_soaentry ORDER BY id)",
        "SELECT json_group_array(json_object('id',id,'tenant_id',tenant_id,'soa_id',soa_id,
         'actor_id',actor_id,'entry_id',entry_id,'action',action,'created_at',created_at))
         FROM (SELECT * FROM assessments_soaauditevent ORDER BY id)",
    ] {
        result.push(sqlx::query_scalar(query).fetch_one(pool).await.unwrap());
    }
    result
}

#[tokio::test]
async fn soa_reads_and_writes_enforce_real_sessions_roles_and_tenants() {
    let (app, pool, token) = fixture().await;
    let auth = AuthStore::from_sqlite_pool(pool.clone());
    let reader = auth.create_session(42, 9).await.unwrap().unwrap().token;
    let foreign = auth.create_session(99, 8).await.unwrap().unwrap().token;
    let (id, before) = generate(&app, &token).await;
    let entry = before["entries"][0]["id"].as_i64().unwrap();
    for (method, path, credential, payload, expected) in [
        (
            "POST",
            "/api/v1/assessments/soa".to_string(),
            &reader,
            json!({}),
            StatusCode::FORBIDDEN,
        ),
        (
            "PUT",
            format!("/api/v1/assessments/soa/entries/{entry}"),
            &reader,
            entry_payload(None),
            StatusCode::FORBIDDEN,
        ),
        (
            "GET",
            format!("/api/v1/assessments/soa/{id}?tenant_id=42&user_id=7"),
            &foreign,
            json!({}),
            StatusCode::NOT_FOUND,
        ),
        (
            "PUT",
            format!("/api/v1/assessments/soa/entries/{entry}?tenant_id=42"),
            &foreign,
            entry_payload(None),
            StatusCode::NOT_FOUND,
        ),
        (
            "PUT",
            format!("/api/v1/assessments/soa/entries/{entry}"),
            &token,
            entry_payload(Some(8)),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let (status, _) = request(&app, method, &path, Some(credential), payload).await;
        assert_eq!(status, expected, "{method} {path}");
    }
    let (status, after) = request(
        &app,
        "GET",
        &format!("/api/v1/assessments/soa/{id}"),
        Some(&reader),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(before, after["document"]);
    let (status, foreign_list) = request(
        &app,
        "GET",
        "/api/v1/assessments/soa?tenant_id=42&user_id=7",
        Some(&foreign),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(foreign_list["documents"].as_array().unwrap().is_empty());
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/assessments/soa")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {reader}"))
                .header("x-iscy-roles", "ADMIN")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn soa_control_review_persists_fields_without_auto_approval_or_catalog_mutation() {
    let (app, pool, token) = fixture().await;
    let (id, before) = generate(&app, &token).await;
    let entry = before["entries"][0]["id"].as_i64().unwrap();
    let mut payload = entry_payload(Some(7));
    payload["notes"] = Value::String("a".repeat(17_000));
    let (status, _) = request(
        &app,
        "PUT",
        &format!("/api/v1/assessments/soa/entries/{entry}"),
        Some(&token),
        payload.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, after) = request(
        &app,
        "GET",
        &format!("/api/v1/assessments/soa/{id}"),
        Some(&token),
        json!({}),
    )
    .await;
    assert_eq!(after["document"]["status"], "DRAFT");
    assert!(after["document"]["approved_by_id"].is_null());
    assert!(after["document"]["approved_at"].is_null());
    for field in [
        "is_applicable",
        "justification",
        "implementation_status",
        "control_owner_id",
        "evidence_reference",
        "notes",
    ] {
        assert_eq!(after["document"]["entries"][0][field], payload[field]);
    }
    let audit_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM assessments_soaauditevent WHERE tenant_id=42")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(audit_count, 2);
    let (_, repeated) = generate(&app, &token).await;
    assert_ne!(repeated["id"], after["document"]["id"]);
    assert_eq!(
        repeated["entries"][0]["implementation_status"],
        "NOT_STARTED"
    );
}

#[tokio::test]
async fn soa_generation_rolls_back_entry_and_audit_failures_including_silent_skips() {
    for (table, condition, failure) in [
        (
            "assessments_soaentry",
            "WHEN NEW.requirement_id=9002",
            "RAISE(ABORT,'SOA_SYNTHETIC_SQL_DETAIL')",
        ),
        (
            "assessments_soaentry",
            "WHEN NEW.requirement_id=9002",
            "RAISE(IGNORE)",
        ),
        (
            "assessments_soaauditevent",
            "",
            "RAISE(ABORT,'SOA_SYNTHETIC_SQL_DETAIL')",
        ),
        ("assessments_soaauditevent", "", "RAISE(IGNORE)"),
    ] {
        let (app, pool, token) = fixture().await;
        let before = sqlite_snapshot(&pool).await;
        sqlx::raw_sql(&format!("CREATE TRIGGER soa_fault BEFORE INSERT ON {table} {condition} BEGIN SELECT {failure}; END;")).execute(&pool).await.unwrap();
        let (status, response) = request(
            &app,
            "POST",
            "/api/v1/assessments/soa",
            Some(&token),
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(response["error_code"], "database_error");
        assert!(!response.to_string().contains("SOA_SYNTHETIC_SQL_DETAIL"));
        assert_eq!(sqlite_snapshot(&pool).await, before);
        for table in [
            "assessments_soadocument",
            "assessments_soaentry",
            "assessments_soaauditevent",
        ] {
            let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(count, 0, "partial {table} survived {failure}");
        }
        sqlx::raw_sql("DROP TRIGGER soa_fault")
            .execute(&pool)
            .await
            .unwrap();
        generate(&app, &token).await;
    }
}

#[tokio::test]
async fn soa_control_update_rolls_back_when_auditing_fails() {
    for failure in ["RAISE(ABORT,'SOA_SYNTHETIC_SQL_DETAIL')", "RAISE(IGNORE)"] {
        let (app, pool, token) = fixture().await;
        let (id, before) = generate(&app, &token).await;
        let entry = before["entries"][0]["id"].as_i64().unwrap();
        sqlx::query("UPDATE assessments_soaentry SET updated_at='2001-01-01T00:00:00Z' WHERE id=?")
            .bind(entry)
            .execute(&pool)
            .await
            .unwrap();
        let full_before = sqlite_snapshot(&pool).await;
        sqlx::raw_sql(&format!("CREATE TRIGGER soa_fault BEFORE INSERT ON assessments_soaauditevent BEGIN SELECT {failure}; END;")).execute(&pool).await.unwrap();
        let (status, _) = request(
            &app,
            "PUT",
            &format!("/api/v1/assessments/soa/entries/{entry}"),
            Some(&token),
            entry_payload(Some(7)),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        let (_, after) = request(
            &app,
            "GET",
            &format!("/api/v1/assessments/soa/{id}"),
            Some(&token),
            json!({}),
        )
        .await;
        assert_eq!(after["document"], before);
        assert_eq!(sqlite_snapshot(&pool).await, full_before);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM assessments_soaauditevent")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }
}

async fn web_request(
    app: &Router,
    method: &str,
    path: &str,
    token: &str,
    fields: &[(&str, &str)],
) -> (StatusCode, String, Option<String>) {
    let mut encoded = reqwest::Url::parse("http://localhost/").unwrap();
    encoded
        .query_pairs_mut()
        .extend_pairs(fields.iter().copied());
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("cookie", format!("iscy_session={token}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(encoded.query().unwrap_or("").to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .map(|header| header.to_str().unwrap().to_string());
    let body = String::from_utf8(
        to_bytes(response.into_body(), 1_000_000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    (status, body, location)
}

#[tokio::test]
async fn soa_web_forms_require_session_bound_csrf_and_escape_stored_content() {
    let (app, pool, token) = fixture().await;
    let (status, html, _) = web_request(&app, "GET", "/assessments/soa/", &token, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!html.contains(&token));
    let csrf = html
        .split("name=\"csrf_token\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let foreign = AuthStore::from_sqlite_pool(pool.clone())
        .create_session(99, 8)
        .await
        .unwrap()
        .unwrap()
        .token;
    for (credential, provided) in [(&token, "wrong"), (&foreign, csrf)] {
        let (status, _, _) = web_request(
            &app,
            "POST",
            "/assessments/soa/generate/",
            credential,
            &[("csrf_token", provided)],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let (status, _, location) = web_request(
        &app,
        "POST",
        "/assessments/soa/generate/",
        &token,
        &[
            ("csrf_token", csrf),
            ("title", "SoA <script>not executed</script>"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (status, html, _) =
        web_request(&app, "GET", location.as_deref().unwrap(), &token, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("&lt;script&gt;not executed&lt;/script&gt;"));
    assert!(!html.contains("<script>not executed</script>"));
    assert!(html.contains("/assessments/soa/entry/"));

    let entry_path = html
        .split("href=\"/assessments/soa/entry/")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let entry_path = format!("/assessments/soa/entry/{entry_path}");
    let (status, edit_html, _) = web_request(&app, "GET", &entry_path, &token, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!edit_html.contains(&token));
    let edit_csrf = edit_html
        .split("name=\"csrf_token\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let (status, _, edited_location) = web_request(
        &app,
        "POST",
        &entry_path,
        &token,
        &[
            ("csrf_token", edit_csrf),
            ("is_applicable", "false"),
            ("justification", "Reviewed <b>exclusion</b>"),
            ("implementation_status", "NOT_APPLICABLE"),
            ("control_owner_id", "7"),
            ("evidence_reference", "Synthetic reference"),
            ("notes", "Complete web edit roundtrip"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(edited_location, location);
    let (_, updated_html, _) =
        web_request(&app, "GET", location.as_deref().unwrap(), &token, &[]).await;
    assert!(updated_html.contains("Reviewed &lt;b&gt;exclusion&lt;/b&gt;"));
    assert!(!updated_html.contains("Reviewed <b>exclusion</b>"));
    let (_, landing, _) = web_request(&app, "GET", "/", &token, &[]).await;
    assert!(landing.contains("href=\"/assessments/soa/\""));
}

#[tokio::test]
async fn soa_input_validation_does_not_create_or_partially_mutate_documents() {
    let (app, pool, token) = fixture().await;
    for payload in [
        json!({"title":""}),
        json!({"title":"a".repeat(256)}),
        json!({"title":"nul\u{0}title"}),
        json!({"status":"APPROVED"}),
        json!({"tenant_id":99}),
        json!({"approved_by_id":7}),
    ] {
        let (status, _) = request(
            &app,
            "POST",
            "/api/v1/assessments/soa",
            Some(&token),
            payload,
        )
        .await;
        assert!(matches!(
            status,
            StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
        ));
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM assessments_soadocument")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    let (id, before) = generate(&app, &token).await;
    let entry = before["entries"][0]["id"].as_i64().unwrap();
    for field in ["implementation_status", "notes"] {
        let mut payload = entry_payload(None);
        payload[field] = if field == "notes" {
            json!("nul\u{0}notes")
        } else {
            json!("AUTOMATICALLY_CERTIFIED")
        };
        let (status, _) = request(
            &app,
            "PUT",
            &format!("/api/v1/assessments/soa/entries/{entry}"),
            Some(&token),
            payload,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let (_, after) = request(
        &app,
        "GET",
        &format!("/api/v1/assessments/soa/{id}"),
        Some(&token),
        json!({}),
    )
    .await;
    assert_eq!(after["document"], before);
}

async fn locked_state_probe(status: &str, web: bool) {
    let (app, pool, token) = fixture().await;
    let (id, document) = generate(&app, &token).await;
    let entry = document["entries"][0]["id"].as_i64().unwrap();
    let path = format!("/assessments/soa/entry/{entry}/edit/");
    // Capture a legitimate form before review begins to test validation-to-use.
    let (_, form, _) = web_request(&app, "GET", &path, &token, &[]).await;
    let csrf = form
        .split("name=\"csrf_token\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    sqlx::query(
        "UPDATE assessments_soadocument SET status=?,approved_by_id=7,
        approved_at='2001-01-01T00:00:00Z',updated_at='2001-01-02T00:00:00Z' WHERE id=?",
    )
    .bind(status)
    .bind(id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO assessments_soaauditevent (tenant_id,soa_id,actor_id,action,created_at)
        VALUES (42,?,7,'review_history_fixture','2001-01-01T00:00:00Z')",
    )
    .bind(id)
    .execute(&pool)
    .await
    .unwrap();
    let before = sqlite_snapshot(&pool).await;
    let actual = if web {
        web_request(
            &app,
            "POST",
            &path,
            &token,
            &[
                ("csrf_token", csrf),
                ("is_applicable", "false"),
                ("justification", "Forbidden overwrite"),
                ("implementation_status", "IMPLEMENTED"),
                ("control_owner_id", "7"),
                ("evidence_reference", "Changed reference"),
                ("notes", "Must not persist"),
            ],
        )
        .await
        .0
    } else {
        request(
            &app,
            "PUT",
            &format!("/api/v1/assessments/soa/entries/{entry}"),
            Some(&token),
            entry_payload(None),
        )
        .await
        .0
    };
    assert_eq!(
        actual,
        StatusCode::CONFLICT,
        "{status} must be immutable through {}",
        if web { "Web" } else { "API" }
    );
    assert_eq!(
        sqlite_snapshot(&pool).await,
        before,
        "preserve every SoA field, approval attribution and audit row"
    );
}

#[tokio::test]
async fn soa_locked_in_review_api_preserves_reviewed_data() {
    locked_state_probe("IN_REVIEW", false).await;
}

#[tokio::test]
async fn soa_locked_approved_api_preserves_approval_history() {
    locked_state_probe("APPROVED", false).await;
}

#[tokio::test]
async fn soa_locked_in_review_web_rechecks_a_previously_valid_form() {
    locked_state_probe("IN_REVIEW", true).await;
}

#[tokio::test]
async fn soa_locked_approved_web_rechecks_a_previously_valid_form() {
    locked_state_probe("APPROVED", true).await;
}

#[tokio::test]
async fn soa_locked_noncanonical_states_fail_closed() {
    for status in ["draft", "DRAFT ", "in_review", "APPROVED ", "UNKNOWN", ""] {
        locked_state_probe(status, false).await;
    }
}

#[tokio::test]
async fn soa_locked_direct_store_and_admin_cannot_bypass_status() {
    let (app, pool, token) = fixture().await;
    let (id, document) = generate(&app, &token).await;
    let entry = document["entries"][0]["id"].as_i64().unwrap();
    sqlx::query("UPDATE accounts_user SET role='ADMIN',is_staff=1,is_superuser=1 WHERE id=7")
        .execute(&pool)
        .await
        .unwrap();
    let store = AssessmentStore::from_sqlite_pool(pool.clone());
    for status in ["IN_REVIEW", "APPROVED"] {
        sqlx::query("UPDATE assessments_soadocument SET status=? WHERE id=?")
            .bind(status)
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        let before = sqlite_snapshot(&pool).await;
        let direct: SoaEntryWriteRequest = serde_json::from_value(entry_payload(Some(7))).unwrap();
        let failure = store
            .update_soa_entry(42, 7, entry, direct)
            .await
            .unwrap_err();
        assert!(failure.to_string().contains("DRAFT"));
        let (actual, body) = request(
            &app,
            "PUT",
            &format!("/api/v1/assessments/soa/entries/{entry}"),
            Some(&token),
            entry_payload(None),
        )
        .await;
        assert_eq!(actual, StatusCode::CONFLICT);
        assert_eq!(body["error_code"], "soa_document_locked");
        let (actual, _, _) = web_request(
            &app,
            "GET",
            &format!("/assessments/soa/entry/{entry}/edit/"),
            &token,
            &[],
        )
        .await;
        assert_eq!(actual, StatusCode::CONFLICT);
        let (actual, html, _) =
            web_request(&app, "GET", &format!("/assessments/soa/{id}/"), &token, &[]).await;
        assert_eq!(actual, StatusCode::OK);
        assert!(!html.contains(&format!("/entry/{entry}/edit/")));
        assert_eq!(sqlite_snapshot(&pool).await, before);
    }
}

#[tokio::test]
async fn soa_locked_import_aliases_cannot_replace_documents_or_history() {
    let (app, pool, token) = fixture().await;
    let (id, _) = generate(&app, &token).await;
    sqlx::query("UPDATE assessments_soadocument SET status='APPROVED',approved_by_id=7,approved_at='2001-01-01T00:00:00Z' WHERE id=?")
        .bind(id).execute(&pool).await.unwrap();
    let before = sqlite_snapshot(&pool).await;
    for alias in [
        "soa",
        "soa_entries",
        "soa_documents",
        "assessments_soaentry",
        "assessments_soadocument",
        " SOA ",
    ] {
        for (path, payload) in [
            (
                "/api/v1/import-center/jobs",
                json!({"import_type":alias,"replace_existing":true,"rows":[{"name":"Overwrite","status":"DRAFT","soa_id":id}]}),
            ),
            (
                "/api/v1/import-center/csv",
                json!({"import_type":alias,"replace_existing":true,"csv_data":"name,status,soa_id\nOverwrite,DRAFT,1\n"}),
            ),
        ] {
            let (status, response) = request(&app, "POST", path, Some(&token), payload).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path} {alias}");
            assert_eq!(response["error_code"], "invalid_import_type");
            assert_eq!(sqlite_snapshot(&pool).await, before);
        }
        let (status, html, _) = web_request(
            &app,
            "POST",
            "/imports/",
            &token,
            &[
                ("import_type", alias),
                ("replace_existing", "true"),
                ("csv_data", "name,status\nOverwrite,DRAFT\n"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("Nicht unterstuetzter Importtyp"));
        assert_eq!(sqlite_snapshot(&pool).await, before);
        for path in ["/api/v1/import-center/preview", "/imports/preview/"] {
            let boundary = "soa-test-boundary";
            let body=format!("--{boundary}\r\nContent-Disposition: form-data; name=\"import_type\"\r\n\r\n{alias}\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"action\"\r\n\r\nconfirm\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"replace_existing\"\r\n\r\ntrue\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"controls.csv\"\r\nContent-Type: text/csv\r\n\r\nname,status\nOverwrite,DRAFT\n\r\n--{boundary}--\r\n");
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header("authorization", format!("Bearer {token}"))
                        .header(
                            "content-type",
                            format!("multipart/form-data; boundary={boundary}"),
                        )
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 1_000_000).await.unwrap();
            let text = String::from_utf8(bytes.to_vec()).unwrap();
            assert_eq!(
                status,
                if path.starts_with("/api/") {
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::OK
                }
            );
            assert!(text.contains("Importtyp"), "{path}: {text}");
            assert_eq!(sqlite_snapshot(&pool).await, before);
        }
    }
}

#[tokio::test]
async fn soa_unknown_version_and_approval_fields_are_not_silently_accepted() {
    let (app, pool, token) = fixture().await;
    let (id, document) = generate(&app, &token).await;
    let entry = document["entries"][0]["id"].as_i64().unwrap();
    let (_, form, _) = web_request(
        &app,
        "GET",
        &format!("/assessments/soa/entry/{entry}/edit/"),
        &token,
        &[],
    )
    .await;
    let csrf = form
        .split("name=\"csrf_token\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let before = sqlite_snapshot(&pool).await;
    for field in ["status", "approved_by_id", "predecessor_id", "version"] {
        let (status, _, _) = web_request(
            &app,
            "POST",
            "/assessments/soa/generate/",
            &token,
            &[("csrf_token", csrf), (field, "1")],
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let (status, _, _) = web_request(
            &app,
            "POST",
            &format!("/assessments/soa/entry/{entry}/edit/"),
            &token,
            &[
                ("csrf_token", csrf),
                ("is_applicable", "true"),
                ("justification", ""),
                ("implementation_status", "NOT_STARTED"),
                ("control_owner_id", ""),
                ("evidence_reference", ""),
                ("notes", ""),
                (field, "1"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let mut payload = entry_payload(None);
        payload[field] = json!(1);
        assert_eq!(
            request(
                &app,
                "PUT",
                &format!("/api/v1/assessments/soa/entries/{entry}"),
                Some(&token),
                payload
            )
            .await
            .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            request(
                &app,
                "POST",
                "/api/v1/assessments/soa",
                Some(&token),
                json!({field:1})
            )
            .await
            .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(sqlite_snapshot(&pool).await, before);
    }
    assert!(id > 0);
}

#[tokio::test]
async fn soa_sqlite_concurrent_review_prevents_stale_draft_write() {
    use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};
    use std::{os::unix::fs::DirBuilderExt, time::Duration};
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("iscy-soa-lock-{}-{nonce}", std::process::id()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let pool = SqlitePoolOptions::new()
        .max_connections(3)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(directory.join("isolated.sqlite3"))
                .create_if_missing(true)
                .foreign_keys(true)
                .journal_mode(SqliteJournalMode::Wal)
                .busy_timeout(Duration::from_secs(5)),
        )
        .await
        .unwrap();
    let (app, pool, token) = fixture_with_pool(pool).await;
    let (id, document) = generate(&app, &token).await;
    let entry = document["entries"][0]["id"].as_i64().unwrap();
    let mut review = pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
    sqlx::query("UPDATE assessments_soadocument SET status='IN_REVIEW' WHERE id=?")
        .bind(id)
        .execute(&mut *review)
        .await
        .unwrap();
    let store = AssessmentStore::from_sqlite_pool(pool.clone());
    let (started, ready) = tokio::sync::oneshot::channel();
    let mut writer = tokio::spawn(async move {
        started.send(()).unwrap();
        store
            .update_soa_entry(
                42,
                7,
                entry,
                serde_json::from_value(entry_payload(None)).unwrap(),
            )
            .await
    });
    ready.await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut writer)
            .await
            .is_err(),
        "writer must not complete while another SQLite writer holds review transition"
    );
    review.commit().await.unwrap();
    let before = sqlite_snapshot(&pool).await;
    let failure = tokio::time::timeout(Duration::from_secs(10), writer)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(failure.to_string().contains("DRAFT"));
    assert_eq!(sqlite_snapshot(&pool).await, before);
    drop(app);
    pool.close().await;
    // Only this test's newly allocated, synthetic database is removed.
    std::fs::remove_file(directory.join("isolated.sqlite3")).unwrap();
    for suffix in ["isolated.sqlite3-wal", "isolated.sqlite3-shm"] {
        let path = directory.join(suffix);
        if path.exists() {
            std::fs::remove_file(path).unwrap();
        }
    }
    std::fs::remove_dir(directory).unwrap();
}

async fn request(
    app: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1_000_000).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

#[tokio::test]
async fn soa_routes_authenticate_before_reading_or_generating() {
    let (app, _, _) = fixture().await;
    for method in ["GET", "POST"] {
        let (status, _) = request(&app, method, "/api/v1/assessments/soa", None, json!({})).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "SoA {method} route must exist and authenticate"
        );
    }
}

#[tokio::test]
async fn soa_generation_restores_active_iso_controls_as_unreviewed_draft() {
    let (app, pool, token) = fixture().await;
    let (status, generated) = request(
        &app,
        "POST",
        "/api/v1/assessments/soa",
        Some(&token),
        json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "SoA generation must be connected to the Rust router"
    );
    let id = generated["document_id"].as_i64().unwrap();
    let (status, detail) = request(
        &app,
        "GET",
        &format!("/api/v1/assessments/soa/{id}"),
        Some(&token),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["document"]["status"], "DRAFT");
    let entries = detail["document"]["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    for entry in entries {
        assert!(entry["is_applicable"].as_bool().unwrap());
        assert_eq!(entry["implementation_status"], "NOT_STARTED");
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM requirements_app_requirement WHERE id BETWEEN 9001 AND 9004",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        count, 4,
        "generation must not mutate the requirements catalog"
    );
}

#[tokio::test]
async fn soa_generation_preserves_legacy_tables_without_timestamp_defaults() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    // Django auto_now[_add] timestamps were supplied by the ORM, not by SQL
    // defaults. Build these pre-existing tables before additive migration 0047.
    sqlx::raw_sql("CREATE TABLE assessments_soadocument (
        id INTEGER PRIMARY KEY AUTOINCREMENT,tenant_id BIGINT NOT NULL REFERENCES organizations_tenant(id),
        session_id BIGINT NULL,title varchar(255) NOT NULL,version varchar(32) NOT NULL,
        status varchar(16) NOT NULL,approved_by_id BIGINT NULL,approved_at TEXT NULL,
        notes TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
        CREATE TABLE assessments_soaentry (
        id INTEGER PRIMARY KEY AUTOINCREMENT,soa_id BIGINT NOT NULL REFERENCES assessments_soadocument(id),
        requirement_id BIGINT NOT NULL REFERENCES requirements_app_requirement(id),is_applicable BOOLEAN NOT NULL,
        justification TEXT NOT NULL,implementation_status varchar(20) NOT NULL,control_owner_id BIGINT NULL,
        evidence_reference TEXT NOT NULL,notes TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
        UNIQUE(soa_id,requirement_id));").execute(&pool).await.unwrap();
    let (app, pool, token) = fixture_with_pool(pool).await;
    sqlx::raw_sql("INSERT INTO assessments_soadocument
        (id,tenant_id,title,version,status,approved_by_id,approved_at,notes,created_at,updated_at)
        VALUES(5000,42,'Preserved legacy approval','2.3','APPROVED',7,'2001-01-01T00:00:00Z','Old notes','2000-01-01','2001-01-01');
        INSERT INTO assessments_soaentry
        (id,soa_id,requirement_id,is_applicable,justification,implementation_status,control_owner_id,evidence_reference,notes,created_at,updated_at)
        VALUES(6000,5000,9001,1,'Old decision','IMPLEMENTED',7,'Old reference','Old control','2000-01-01','2001-01-01');
        INSERT INTO assessments_soaauditevent (id,tenant_id,soa_id,actor_id,entry_id,action,created_at)
        VALUES(7000,42,5000,7,6000,'legacy_history_fixture','2001-01-01');").execute(&pool).await.unwrap();
    let before = sqlite_snapshot(&pool).await;
    let (new_id, new) = generate(&app, &token).await;
    assert_ne!(new_id, 5000);
    assert_eq!(new["status"], "DRAFT");
    for (before, after) in before.iter().zip(sqlite_snapshot(&pool).await) {
        let old: Value = serde_json::from_str(before).unwrap();
        let current: Value = serde_json::from_str(&after).unwrap();
        assert_eq!(
            old[0], current[0],
            "existing approved version and history must remain exact"
        );
    }
    sqlx::query(
        "DELETE FROM iscy_schema_migrations WHERE version='0047_rust_soa_cutover_restoration'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let before = sqlite_snapshot(&pool).await;
    db_admin::run_sqlite_migrations(&pool).await.unwrap();
    db_admin::run_sqlite_migrations(&pool).await.unwrap();
    assert_eq!(sqlite_snapshot(&pool).await, before);
}

#[tokio::test]
#[ignore = "requires an explicit fresh disposable ISCY_TEST_SOA_POSTGRES_URL"]
async fn soa_postgres_sessions_tenants_atomicity_and_restartable_schema() {
    use iscy_backend::db_admin::DbAdminAction;
    use sqlx::postgres::PgPoolOptions;
    let database_url = std::env::var("ISCY_TEST_SOA_POSTGRES_URL")
        .expect("ISCY_TEST_SOA_POSTGRES_URL must name a fresh disposable database");
    let parsed = reqwest::Url::parse(&database_url).unwrap();
    assert!(matches!(parsed.scheme(), "postgres" | "postgresql"));
    assert!(parsed.path().starts_with("/iscy_test_soa"));
    db_admin::run_db_admin_action(&database_url, DbAdminAction::Migrate)
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .unwrap();
    sqlx::raw_sql("INSERT INTO organizations_tenant (id,name,slug) VALUES
        (42,'PG SoA Tenant','pg-soa-tenant'),(99,'Foreign PG Tenant','foreign-pg-soa');
        INSERT INTO accounts_user (id,tenant_id,username,role) VALUES
        (7,42,'pg-soa-author','CONTRIBUTOR'),(8,99,'foreign-pg-author','CONTRIBUTOR'),(9,42,'pg-soa-reader','AUDITOR');
        INSERT INTO requirements_app_requirement (id,framework,code,title,is_active) VALUES
        (9001,'ISO27001','TEST-A.1','First active control',TRUE),
        (9002,'ISO27001','TEST-A.2','Second active control',TRUE),
        (9003,'ISO27001','TEST-A.3','Inactive control',FALSE),
        (9004,'NIS2','TEST-NIS2','Different framework',TRUE);")
        .execute(&pool).await.unwrap();
    sqlx::raw_sql("ALTER TABLE assessments_soadocument ALTER COLUMN created_at DROP DEFAULT, ALTER COLUMN updated_at DROP DEFAULT;
        ALTER TABLE assessments_soaentry ALTER COLUMN created_at DROP DEFAULT, ALTER COLUMN updated_at DROP DEFAULT;")
        .execute(&pool).await.unwrap();
    let auth = AuthStore::Postgres(pool.clone());
    let token = auth.create_session(42, 7).await.unwrap().unwrap().token;
    let reader = auth.create_session(42, 9).await.unwrap().unwrap().token;
    let foreign = auth.create_session(99, 8).await.unwrap().unwrap().token;
    let app = app_router_with_state(
        AppState::default()
            .with_security_config(CommunitySecurityConfig {
                app_mode: AppMode::Production,
                trust_identity_headers: false,
                ..CommunitySecurityConfig::default()
            })
            .with_auth_store(Some(auth))
            .with_assessment_store(Some(AssessmentStore::Postgres(pool.clone()))),
    );
    let (id, document) = generate(&app, &token).await;
    assert_eq!(document["status"], "DRAFT");
    assert_eq!(document["entries"].as_array().unwrap().len(), 2);
    let entry_id = document["entries"][0]["id"].as_i64().unwrap();
    let (status, _) = request(
        &app,
        "PUT",
        &format!("/api/v1/assessments/soa/entries/{entry_id}"),
        Some(&token),
        entry_payload(Some(7)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    for (credential, method, path, expected) in [
        (
            &reader,
            "POST",
            "/api/v1/assessments/soa".to_string(),
            StatusCode::FORBIDDEN,
        ),
        (
            &foreign,
            "GET",
            format!("/api/v1/assessments/soa/{id}?tenant_id=42"),
            StatusCode::NOT_FOUND,
        ),
        (
            &foreign,
            "PUT",
            format!("/api/v1/assessments/soa/entries/{entry_id}"),
            StatusCode::NOT_FOUND,
        ),
    ] {
        let payload = if method == "PUT" {
            entry_payload(None)
        } else {
            json!({})
        };
        let (status, _) = request(&app, method, &path, Some(credential), payload).await;
        assert_eq!(status, expected);
    }
    let (status, _) = request(
        &app,
        "PUT",
        &format!("/api/v1/assessments/soa/entries/{entry_id}"),
        Some(&token),
        entry_payload(Some(8)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    async fn snapshot(pool: &sqlx::PgPool) -> Vec<String> {
        let mut values = Vec::new();
        for table in [
            "assessments_soadocument",
            "assessments_soaentry",
            "assessments_soaauditevent",
        ] {
            values.push(
                sqlx::query_scalar(&format!(
                    "SELECT COALESCE(json_agg(t ORDER BY t.id),'[]'::json)::text FROM {table} t"
                ))
                .fetch_one(pool)
                .await
                .unwrap(),
            );
        }
        values
    }
    let before = snapshot(&pool).await;
    for (table, operation, condition) in [
        ("assessments_soadocument", "INSERT", ""),
        (
            "assessments_soaentry",
            "INSERT",
            "WHEN (NEW.requirement_id=9002)",
        ),
        ("assessments_soaauditevent", "INSERT", ""),
        ("assessments_soaentry", "UPDATE", ""),
    ] {
        for failure in [
            "RAISE EXCEPTION 'SOA_SYNTHETIC_SQL_DETAIL';",
            "RETURN NULL;",
        ] {
            sqlx::raw_sql(&format!("CREATE FUNCTION soa_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN {failure} END $$;
                CREATE TRIGGER soa_fault BEFORE {operation} ON {table} FOR EACH ROW {condition} EXECUTE FUNCTION soa_fault();"))
                .execute(&pool).await.unwrap();
            let (status, response) = if operation == "UPDATE" {
                request(
                    &app,
                    "PUT",
                    &format!("/api/v1/assessments/soa/entries/{entry_id}"),
                    Some(&token),
                    entry_payload(None),
                )
                .await
            } else {
                request(
                    &app,
                    "POST",
                    "/api/v1/assessments/soa",
                    Some(&token),
                    json!({}),
                )
                .await
            };
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(response["error_code"], "database_error");
            assert!(!response.to_string().contains("SOA_SYNTHETIC_SQL_DETAIL"));
            assert_eq!(
                snapshot(&pool).await,
                before,
                "{table} {operation} {failure}"
            );
            sqlx::raw_sql(&format!(
                "DROP TRIGGER soa_fault ON {table}; DROP FUNCTION soa_fault();"
            ))
            .execute(&pool)
            .await
            .unwrap();
        }
    }
    for failure in [
        "RAISE EXCEPTION 'SOA_SYNTHETIC_SQL_DETAIL';",
        "RETURN NULL;",
    ] {
        sqlx::raw_sql(&format!("CREATE FUNCTION soa_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN {failure} END $$;
            CREATE TRIGGER soa_fault BEFORE INSERT ON assessments_soaauditevent FOR EACH ROW EXECUTE FUNCTION soa_fault();"))
            .execute(&pool).await.unwrap();
        let (status, _) = request(
            &app,
            "PUT",
            &format!("/api/v1/assessments/soa/entries/{entry_id}"),
            Some(&token),
            entry_payload(None),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(snapshot(&pool).await, before);
        sqlx::raw_sql(
            "DROP TRIGGER soa_fault ON assessments_soaauditevent; DROP FUNCTION soa_fault();",
        )
        .execute(&pool)
        .await
        .unwrap();
    }
    // Reapply the additive migration with pre-existing SoA tables and data.
    sqlx::query(
        "DELETE FROM iscy_schema_migrations WHERE version='0047_rust_soa_cutover_restoration'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let migrated = db_admin::run_db_admin_action(&database_url, DbAdminAction::Migrate)
        .await
        .unwrap();
    assert_eq!(
        migrated.applied_migrations,
        vec!["0047_rust_soa_cutover_restoration"]
    );
    assert_eq!(snapshot(&pool).await, before);
    let restarted = db_admin::run_db_admin_action(&database_url, DbAdminAction::Migrate)
        .await
        .unwrap();
    assert!(restarted.applied_migrations.is_empty());
    assert_eq!(snapshot(&pool).await, before);

    // Separate physical connections prove both lock orderings, rather than
    // relying on the application's single-connection test pool to serialize.
    let observers = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .unwrap();
    async fn wait_for_lock(observer: &sqlx::PgPool, pid: i32) {
        tokio::time::timeout(std::time::Duration::from_secs(10),async {
            loop {
                let waiting:bool=sqlx::query_scalar("SELECT COALESCE(wait_event_type='Lock',FALSE) FROM pg_stat_activity WHERE pid=$1")
                    .bind(pid).fetch_one(observer).await.unwrap();
                if waiting { break; }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }).await.expect("expected physical PostgreSQL connection to wait on a row lock");
    }
    let writer_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let mut review = observers.begin().await.unwrap();
    sqlx::query("UPDATE assessments_soadocument SET status='IN_REVIEW' WHERE id=$1")
        .bind(id)
        .execute(&mut *review)
        .await
        .unwrap();
    let app_writer = app.clone();
    let writer_token = token.clone();
    let writer = tokio::spawn(async move {
        request(
            &app_writer,
            "PUT",
            &format!("/api/v1/assessments/soa/entries/{entry_id}"),
            Some(&writer_token),
            entry_payload(None),
        )
        .await
    });
    wait_for_lock(&observers, writer_pid).await;
    review.commit().await.unwrap();
    let (status, body) = tokio::time::timeout(std::time::Duration::from_secs(10), writer)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error_code"], "soa_document_locked");
    let reviewed = snapshot(&pool).await;
    assert_eq!(
        &reviewed[1..],
        &before[1..],
        "entry and audit tables unchanged by rejected stale writer"
    );
    let (_, protected_document) = request(
        &app,
        "GET",
        &format!("/api/v1/assessments/soa/{id}"),
        Some(&token),
        json!({}),
    )
    .await;

    // The other ordering: editor owns the parent first; reviewer must wait
    // until that DRAFT write and its mandatory audit have committed.
    let (next_id, next) = generate(&app, &token).await;
    let next_entry = next["entries"][0]["id"].as_i64().unwrap();
    let mut entry_blocker = observers.begin().await.unwrap();
    sqlx::query("SELECT id FROM assessments_soaentry WHERE id=$1 FOR UPDATE")
        .bind(next_entry)
        .fetch_one(&mut *entry_blocker)
        .await
        .unwrap();
    let app_writer = app.clone();
    let writer_token = token.clone();
    let writer = tokio::spawn(async move {
        request(
            &app_writer,
            "PUT",
            &format!("/api/v1/assessments/soa/entries/{next_entry}"),
            Some(&writer_token),
            entry_payload(Some(7)),
        )
        .await
    });
    wait_for_lock(&observers, writer_pid).await;
    let mut review = observers.begin().await.unwrap();
    let review_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *review)
        .await
        .unwrap();
    let reviewer = tokio::spawn(async move {
        sqlx::query("UPDATE assessments_soadocument SET status='IN_REVIEW' WHERE id=$1")
            .bind(next_id)
            .execute(&mut *review)
            .await
            .unwrap();
        review.commit().await.unwrap();
    });
    wait_for_lock(&observers, review_pid).await;
    entry_blocker.commit().await.unwrap();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(10), writer)
            .await
            .unwrap()
            .unwrap()
            .0,
        StatusCode::OK
    );
    tokio::time::timeout(std::time::Duration::from_secs(10), reviewer)
        .await
        .unwrap()
        .unwrap();
    let after_review = snapshot(&pool).await;
    assert_eq!(
        request(
            &app,
            "PUT",
            &format!("/api/v1/assessments/soa/entries/{next_entry}"),
            Some(&token),
            entry_payload(None)
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(snapshot(&pool).await, after_review);
    let (_, still_protected) = request(
        &app,
        "GET",
        &format!("/api/v1/assessments/soa/{id}"),
        Some(&token),
        json!({}),
    )
    .await;
    assert_eq!(still_protected, protected_document);
    for locked_status in ["IN_REVIEW", "APPROVED"] {
        let (protected_id, document) = generate(&app, &token).await;
        let entry = document["entries"][0]["id"].as_i64().unwrap();
        let edit_path = format!("/assessments/soa/entry/{entry}/edit/");
        let (_, form, _) = web_request(&app, "GET", &edit_path, &token, &[]).await;
        let csrf = form
            .split("name=\"csrf_token\" value=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        sqlx::query("UPDATE assessments_soadocument SET status=$1,approved_by_id=7,approved_at='2001-01-01T00:00:00Z',updated_at='2001-01-02T00:00:00Z' WHERE id=$2")
            .bind(locked_status).bind(protected_id).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO assessments_soaauditevent (tenant_id,soa_id,actor_id,entry_id,action,created_at) VALUES (42,$1,7,$2,'review_history_fixture','2001-01-01T00:00:00Z')")
            .bind(protected_id).bind(entry).execute(&pool).await.unwrap();
        let before = snapshot(&pool).await;
        assert_eq!(
            request(
                &app,
                "PUT",
                &format!("/api/v1/assessments/soa/entries/{entry}"),
                Some(&token),
                entry_payload(None)
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            web_request(
                &app,
                "POST",
                &edit_path,
                &token,
                &[
                    ("csrf_token", csrf),
                    ("is_applicable", "false"),
                    ("justification", "Cannot change approval"),
                    ("implementation_status", "IMPLEMENTED"),
                    ("control_owner_id", "7"),
                    ("evidence_reference", "New reference"),
                    ("notes", "Forbidden")
                ]
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            snapshot(&pool).await,
            before,
            "PostgreSQL {locked_status}: every field and history row must remain exact"
        );
    }
    observers.close().await;
}
