use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use iscy_backend::{
    app_router_with_state,
    auth_store::AuthStore,
    company_wizard::{CompanyProfile, RegulatoryContext, ROOT},
    db_admin,
    hardening::{AppMode, CommunitySecurityConfig},
    wizard_store::WizardStore,
    AppState,
};
use serde_json::Value;
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use tower::ServiceExt;

async fn fixture() -> (Router, SqlitePool, String) {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db_admin::run_sqlite_migrations(&pool).await.unwrap();
    sqlx::raw_sql("INSERT INTO organizations_tenant(id,name,slug) VALUES (42,'Company A','company-a'),(99,'Foreign B','foreign-b');
        INSERT INTO accounts_user(id,tenant_id,username,role) VALUES (7,42,'writer','CONTRIBUTOR'),(8,99,'foreign','CONTRIBUTOR'),(9,42,'reader','AUDITOR'),(10,42,'other','UNSUPPORTED');
        INSERT INTO wizard_assessmentsession(id,tenant_id,started_by_id,status,current_step,executive_summary,applicability_result)
        VALUES(500,42,7,'COMPLETED','results','Historical result','HISTORICAL');").execute(&pool).await.unwrap();
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
            .with_wizard_store(Some(WizardStore::from_sqlite_pool(pool.clone()))),
    );
    (app, pool, token)
}
fn encode(fields: &[(&str, String)]) -> String {
    let mut url = reqwest::Url::parse("http://fixture.invalid/").unwrap();
    url.query_pairs_mut()
        .extend_pairs(fields.iter().map(|(k, v)| (*k, v.as_str())));
    url.query().unwrap_or_default().to_owned()
}
async fn request(
    app: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: String,
) -> (StatusCode, String) {
    let mut r = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        r = r.header("authorization", format!("Bearer {token}"));
    }
    if method == "POST" {
        r = r.header("content-type", "application/x-www-form-urlencoded");
    }
    let response = app
        .clone()
        .oneshot(r.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = String::from_utf8(
        to_bytes(response.into_body(), 200000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    (status, body)
}
async fn form_csrf(app: &Router, token: &str) -> String {
    let (status, html) = request(app, "GET", ROOT, Some(token), String::new()).await;
    assert_eq!(status, StatusCode::OK, "{html}");
    html.split("name=\"csrf_token\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned()
}
async fn create(app: &Router, pool: &SqlitePool, token: &str) -> (i64, String) {
    let csrf = form_csrf(app, token).await;
    let (status, body) = request(
        app,
        "POST",
        ROOT,
        Some(token),
        encode(&[("csrf_token", csrf.clone())]),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    let id = sqlx::query_scalar("SELECT MAX(session_id) FROM wizard_companyprofile")
        .fetch_one(pool)
        .await
        .unwrap();
    (id, csrf)
}
fn payload(csrf: &str, revision: i64) -> Vec<(&'static str, String)> {
    [
        ("csrf_token", csrf.to_owned()),
        ("revision", revision.to_string()),
        ("company_name", "Acme <script>unsafe</script>".to_owned()),
        ("headquarters_country", "Deutschland".to_owned()),
        (
            "operation_countries",
            "DE, Österreich\nSchweiz\nde".to_owned(),
        ),
        (
            "geographic_scope",
            "Eigene EU-Niederlassung und Schweizer Markt".to_owned(),
        ),
        ("sector", "Gesundheitswesen".to_owned()),
        (
            "size_reference",
            "Geschaeftsjahr 2025, Einzelunternehmen; EUR".to_owned(),
        ),
        ("employee_count", String::new()),
        ("annual_revenue_million", String::new()),
        ("balance_sheet_million", "0".to_owned()),
        ("critical_services", "Versorgung".to_owned()),
        ("supply_chain_role", "Dienstleister".to_owned()),
        ("develops_digital_products", String::new()),
        ("uses_ai_systems", "yes".to_owned()),
        ("ot_iacs_scope", "no".to_owned()),
        ("automotive_scope", String::new()),
    ]
    .into()
}
async fn snapshot(pool: &SqlitePool) -> (String, String, i64, i64, i64) {
    (sqlx::query_scalar("SELECT COALESCE(json_group_array(json_object('id',session_id,'rev',revision,'json',profile_json)),'[]') FROM wizard_companyprofile ORDER BY session_id").fetch_one(pool).await.unwrap(),
     sqlx::query_scalar("SELECT COALESCE(json_group_array(json_object('id',id,'status',status,'step',current_step,'summary',executive_summary,'result',applicability_result,'updated',updated_at)),'[]') FROM wizard_assessmentsession ORDER BY id").fetch_one(pool).await.unwrap(),
     sqlx::query_scalar("SELECT COUNT(*) FROM wizard_profileevent").fetch_one(pool).await.unwrap(),
     sqlx::query_scalar("SELECT COUNT(*) FROM wizard_contextsnapshot").fetch_one(pool).await.unwrap(),
     sqlx::query_scalar("SELECT COUNT(*) FROM wizard_contextsnapshotevent").fetch_one(pool).await.unwrap())
}

#[tokio::test]
async fn company_profile_roundtrip_keeps_unknowns_distinct_and_escapes_html() {
    let (app, pool, token) = fixture().await;
    let (id, csrf) = create(&app, &pool, &token).await;
    let path = format!("{ROOT}{id}/");
    let before = snapshot(&pool).await;
    let (status, html) = request(&app, "GET", &path, Some(&token), String::new()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("noch offene Basisangaben"));
    assert_eq!(snapshot(&pool).await, before, "GET must not mutate a draft");
    let (status, body) = request(
        &app,
        "POST",
        &path,
        Some(&token),
        encode(&payload(&csrf, 1)),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    let store = WizardStore::from_sqlite_pool(pool.clone());
    let draft = store.company_draft(42, id).await.unwrap().unwrap();
    assert_eq!(draft.revision, 2);
    assert_eq!(draft.profile.employee_count, None);
    assert_eq!(draft.profile.annual_revenue_million, None);
    assert_eq!(draft.profile.balance_sheet_million, Some("0".to_owned()));
    assert_eq!(
        draft.profile.operation_countries,
        vec!["DE", "Österreich", "Schweiz"]
    );
    assert_eq!(draft.profile.develops_digital_products, None);
    assert_eq!(draft.profile.uses_ai_systems, Some(true));
    assert_eq!(draft.profile.ot_iacs_scope, Some(false));
    let (_, html) = request(&app, "GET", &path, Some(&token), String::new()).await;
    assert!(html.contains("Acme &lt;script&gt;unsafe&lt;/script&gt;"));
    assert!(!html.contains("Acme <script>"));
    assert!(html.contains("keine Nichtbetroffenheit"));
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT name FROM organizations_tenant WHERE id=42")
            .fetch_one(&pool)
            .await
            .unwrap(),
        "Company A"
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT executive_summary FROM wizard_assessmentsession WHERE id=500"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        "Historical result"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT progress_percent FROM wizard_assessmentsession WHERE id=?"
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );
}

#[tokio::test]
async fn company_wizard_enforces_sessions_roles_tenant_scope_and_csrf() {
    let (app, pool, token) = fixture().await;
    let (id, csrf) = create(&app, &pool, &token).await;
    let auth = AuthStore::from_sqlite_pool(pool.clone());
    let foreign = auth.create_session(99, 8).await.unwrap().unwrap().token;
    let reader = auth.create_session(42, 9).await.unwrap().unwrap().token;
    let other = auth.create_session(42, 10).await.unwrap().unwrap().token;
    let path = format!("{ROOT}{id}/");
    let before = snapshot(&pool).await;
    for (method, path, credential, body, expected) in [
        (
            "POST",
            ROOT.to_owned(),
            None,
            encode(&[("csrf_token", csrf.clone())]),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "POST",
            path.clone(),
            None,
            encode(&payload(&csrf, 1)),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "GET",
            ROOT.to_owned(),
            None,
            String::new(),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "GET",
            path.clone(),
            None,
            String::new(),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "GET",
            path.clone(),
            Some(other.as_str()),
            String::new(),
            StatusCode::FORBIDDEN,
        ),
        (
            "POST",
            path.clone(),
            Some(reader.as_str()),
            encode(&payload(&csrf, 1)),
            StatusCode::FORBIDDEN,
        ),
        (
            "POST",
            ROOT.to_owned(),
            Some(reader.as_str()),
            encode(&[("csrf_token", csrf.clone())]),
            StatusCode::FORBIDDEN,
        ),
        (
            "GET",
            format!("{path}?tenant_id=42&user_id=7"),
            Some(foreign.as_str()),
            String::new(),
            StatusCode::NOT_FOUND,
        ),
        (
            "POST",
            path.clone(),
            Some(foreign.as_str()),
            encode(&payload(&form_csrf(&app, &foreign).await, 1)),
            StatusCode::NOT_FOUND,
        ),
        (
            "POST",
            path.clone(),
            Some(token.as_str()),
            encode(&payload("incorrect", 1)),
            StatusCode::FORBIDDEN,
        ),
        (
            "POST",
            ROOT.to_owned(),
            Some(token.as_str()),
            encode(&[("csrf_token", String::new())]),
            StatusCode::FORBIDDEN,
        ),
    ] {
        let (status, body) = request(&app, method, &path, credential, body).await;
        assert_eq!(status, expected, "{method} {path}: {body}");
        assert_eq!(snapshot(&pool).await, before);
    }
    let (_, html) = request(&app, "GET", &path, Some(&reader), String::new()).await;
    assert!(html.contains("fieldset disabled"));
    assert!(!html.contains("Entwurf speichern</button>"));
    let (_, html) = request(&app, "GET", ROOT, Some(&foreign), String::new()).await;
    assert!(!html.contains("Company A"));
    let mut forged = payload(&csrf, 1);
    forged.push(("tenant_id", "99".to_owned()));
    assert!(request(&app, "POST", &path, Some(&token), encode(&forged))
        .await
        .0
        .is_client_error());
    assert_eq!(snapshot(&pool).await, before);
    let req = Request::builder()
        .uri(&path)
        .header("x-iscy-tenant-id", "42")
        .header("x-iscy-user-id", "7")
        .header("x-iscy-roles", "ADMIN");
    let response = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn saved_draft_has_cas_and_completed_or_legacy_sessions_remain_locked() {
    let (app, pool, token) = fixture().await;
    let (id, csrf) = create(&app, &pool, &token).await;
    let path = format!("{ROOT}{id}/");
    assert_eq!(
        request(
            &app,
            "POST",
            &path,
            Some(&token),
            encode(&payload(&csrf, 1))
        )
        .await
        .0,
        StatusCode::SEE_OTHER
    );
    let before = snapshot(&pool).await;
    assert_eq!(
        request(
            &app,
            "POST",
            &path,
            Some(&token),
            encode(&payload(&csrf, 1))
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(snapshot(&pool).await, before);
    sqlx::query("UPDATE wizard_assessmentsession SET status='COMPLETED' WHERE id=?")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    let locked = snapshot(&pool).await;
    assert_eq!(
        request(
            &app,
            "POST",
            &path,
            Some(&token),
            encode(&payload(&csrf, 2))
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(snapshot(&pool).await, locked);
    for method in ["GET", "POST"] {
        assert_eq!(
            request(
                &app,
                method,
                &format!("{ROOT}500/"),
                Some(&token),
                encode(&payload(&csrf, 1))
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
    }
}

#[tokio::test]
async fn invalid_company_inputs_are_rejected_without_side_effects_or_diagnostics() {
    let (app, pool, token) = fixture().await;
    let (id, csrf) = create(&app, &pool, &token).await;
    let path = format!("{ROOT}{id}/");
    let before = snapshot(&pool).await;
    for (field, value) in [
        ("employee_count", "-1".to_owned()),
        ("employee_count", "unknown".to_owned()),
        ("annual_revenue_million", "NaN".to_owned()),
        ("annual_revenue_million", "123.456".to_owned()),
        ("uses_ai_systems", "definitely".to_owned()),
        ("company_name", "x".repeat(256)),
        ("operation_countries", "DE,".repeat(51)),
        ("sector", "private\0value".to_owned()),
    ] {
        let mut fields = payload(&csrf, 1);
        fields.iter_mut().find(|(k, _)| *k == field).unwrap().1 = value;
        let (status, html) = request(&app, "POST", &path, Some(&token), encode(&fields)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{field}: {html}");
        assert_eq!(snapshot(&pool).await, before);
    }
    let oversized = "x".repeat(70000);
    assert_eq!(
        request(&app, "POST", &path, Some(&token), oversized)
            .await
            .0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[tokio::test]
async fn audit_failure_rolls_back_creation_and_save_and_redacts_database_errors() {
    let (app, pool, token) = fixture().await;
    let csrf = form_csrf(&app, &token).await;
    sqlx::raw_sql("CREATE TRIGGER fail_audit BEFORE INSERT ON wizard_profileevent BEGIN SELECT RAISE(ABORT,'PRIVATE-SQL-DIAGNOSTIC'); END;").execute(&pool).await.unwrap();
    let before = snapshot(&pool).await;
    let (status, body) = request(
        &app,
        "POST",
        ROOT,
        Some(&token),
        encode(&[("csrf_token", csrf.clone())]),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!body.contains("PRIVATE-SQL"));
    assert_eq!(snapshot(&pool).await, before);
    sqlx::raw_sql("DROP TRIGGER fail_audit;")
        .execute(&pool)
        .await
        .unwrap();
    let (id, csrf) = create(&app, &pool, &token).await;
    sqlx::raw_sql("CREATE TRIGGER fail_audit BEFORE INSERT ON wizard_profileevent BEGIN SELECT RAISE(ABORT,'PRIVATE-SQL-DIAGNOSTIC'); END;").execute(&pool).await.unwrap();
    let before = snapshot(&pool).await;
    let (status, body) = request(
        &app,
        "POST",
        &format!("{ROOT}{id}/"),
        Some(&token),
        encode(&payload(&csrf, 1)),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!body.contains("PRIVATE-SQL"));
    assert_eq!(snapshot(&pool).await, before);
}

#[tokio::test]
async fn foreign_actor_and_cross_tenant_foreign_keys_are_rejected() {
    let (app, pool, token) = fixture().await;
    let (id, _) = create(&app, &pool, &token).await;
    let store = WizardStore::from_sqlite_pool(pool.clone());
    let before = snapshot(&pool).await;
    assert!(store.create_company_draft(42, 8).await.unwrap().is_none());
    assert!(!store
        .save_company_draft(42, 8, id, 1, CompanyProfile::default())
        .await
        .unwrap());
    assert!(store.company_draft(99, id).await.unwrap().is_none());
    assert!(sqlx::query("INSERT INTO wizard_companyprofile(session_id,tenant_id,revision,profile_json) VALUES(500,99,1,'{}')").execute(&pool).await.is_err());
    assert_eq!(snapshot(&pool).await, before);
}

#[tokio::test]
async fn parallel_draft_saves_have_one_winner_and_one_audit_revision() {
    let (app, pool, token) = fixture().await;
    let (id, _) = create(&app, &pool, &token).await;
    let store = WizardStore::from_sqlite_pool(pool.clone());
    let (a, b) = tokio::join!(
        store.save_company_draft(
            42,
            7,
            id,
            1,
            CompanyProfile {
                sector: "A".to_owned(),
                ..CompanyProfile::default()
            }
        ),
        store.save_company_draft(
            42,
            7,
            id,
            1,
            CompanyProfile {
                sector: "B".to_owned(),
                ..CompanyProfile::default()
            }
        )
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(
        store.company_draft(42, id).await.unwrap().unwrap().revision,
        2
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM wizard_profileevent")
            .fetch_one(&pool)
            .await
            .unwrap(),
        2
    );
}

#[tokio::test]
async fn company_migration_is_restartable_and_preserves_historical_results() {
    let (_, pool, _) = fixture().await;
    let before = snapshot(&pool).await;
    assert!(db_admin::run_sqlite_migrations(&pool)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(snapshot(&pool).await, before);
    let version: String = sqlx::query_scalar(
        "SELECT version FROM iscy_schema_migrations ORDER BY version DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(version, "0050_rust_company_context_snapshot");
}

#[test]
fn zero_unknown_and_decimal_comma_are_preserved_without_float_rounding() {
    let p = CompanyProfile {
        employee_count: Some(0),
        annual_revenue_million: Some(" 1,20 ".to_owned()),
        ..CompanyProfile::default()
    }
    .normalize()
    .unwrap();
    assert_eq!(p.employee_count, Some(0));
    assert_eq!(p.annual_revenue_million, Some("1.20".to_owned()));
    let json: Value = serde_json::to_value(p).unwrap();
    assert_eq!(json["uses_ai_systems"], Value::Null);
}

#[tokio::test]
async fn validation_errors_and_conflicts_keep_submitted_values_visible_and_safe() {
    let (app, pool, token) = fixture().await;
    let (id, csrf) = create(&app, &pool, &token).await;
    let path = format!("{ROOT}{id}/");
    let before = snapshot(&pool).await;
    let mut fields = payload(&csrf, 1);
    fields
        .iter_mut()
        .find(|(k, _)| *k == "annual_revenue_million")
        .unwrap()
        .1 = "invalid-amount".to_owned();
    let (status, html) = request(&app, "POST", &path, Some(&token), encode(&fields)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(html.contains("invalid-amount"));
    assert!(html.contains("Acme &lt;script&gt;unsafe&lt;/script&gt;"));
    assert!(html.contains("Entwurf speichern</button>"));
    assert!(html.contains("Ihre Eingaben wurden nicht gespeichert"));
    assert_eq!(snapshot(&pool).await, before);
    assert_eq!(
        request(
            &app,
            "POST",
            &path,
            Some(&token),
            encode(&payload(&csrf, 1))
        )
        .await
        .0,
        StatusCode::SEE_OTHER
    );
    let (status, html) = request(&app, "POST", &path, Some(&token), encode(&fields)).await;
    // Fix the malformed field to reach the concurrency guard.
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(html.contains("invalid-amount"));
    let (status, html) = request(
        &app,
        "POST",
        &path,
        Some(&token),
        encode(&payload(&csrf, 1)),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(html.contains("Acme &lt;script&gt;unsafe&lt;/script&gt;"));
    assert!(html.contains("fieldset disabled"));
    assert!(!html.contains("Entwurf speichern</button>"));
}

#[tokio::test]
async fn company_profile_resumes_after_closing_and_reopening_the_database() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root =
        std::env::temp_dir().join(format!("iscy-wizard-resume-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let url = format!(
        "sqlite:///{}?mode=rwc",
        root.join("fixture.sqlite3").display()
    );
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    db_admin::run_sqlite_migrations(&pool).await.unwrap();
    sqlx::raw_sql("INSERT INTO organizations_tenant(id,name,slug) VALUES(42,'Resume','resume'); INSERT INTO accounts_user(id,tenant_id,username,role) VALUES(7,42,'writer','CONTRIBUTOR');").execute(&pool).await.unwrap();
    let store = WizardStore::from_sqlite_pool(pool.clone());
    let id = store.create_company_draft(42, 7).await.unwrap().unwrap();
    let profile = CompanyProfile {
        company_name: "Resumed company".to_owned(),
        operation_countries: vec!["Deutschland".to_owned(), "Indien".to_owned()],
        ..CompanyProfile::default()
    };
    assert!(store
        .save_company_draft(42, 7, id, 1, profile.clone())
        .await
        .unwrap());
    drop(store);
    pool.close().await;
    let reopened = WizardStore::connect(&url).await.unwrap();
    let draft = reopened.company_draft(42, id).await.unwrap().unwrap();
    assert_eq!(draft.revision, 2);
    assert_eq!(draft.profile, profile);
    if let WizardStore::Sqlite(pool) = reopened {
        pool.close().await;
    } else {
        unreachable!();
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
#[ignore = "requires a fresh disposable ISCY_TEST_COMPANY_WIZARD_POSTGRES_URL"]
async fn postgres_company_profile_migration_cas_and_audit_rollback() {
    let url = std::env::var("ISCY_TEST_COMPANY_WIZARD_POSTGRES_URL").unwrap();
    let parsed = reqwest::Url::parse(&url).unwrap();
    assert!(matches!(parsed.host_str(), Some("127.0.0.1" | "localhost")));
    assert!(parsed.path().starts_with("/iscy_test_wizard_"));
    assert!(parsed
        .query_pairs()
        .all(|(key, value)| key == "sslmode" && value == "disable"));
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(3)
        .connect(&url)
        .await
        .unwrap();
    let tables: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(tables, 0, "PostgreSQL fixture must be fresh and empty");
    let outcome = db_admin::run_db_admin_action(&url, db_admin::DbAdminAction::Migrate)
        .await
        .unwrap();
    assert_eq!(
        outcome.applied_migrations.last(),
        Some(&"0050_rust_company_context_snapshot")
    );
    sqlx::raw_sql("INSERT INTO organizations_tenant(id,name,slug) VALUES(42,'PG company','pg-company'),(99,'PG foreign','pg-foreign'); INSERT INTO accounts_user(id,tenant_id,username,role) VALUES(7,42,'writer','CONTRIBUTOR'),(8,99,'foreign','CONTRIBUTOR');").execute(&pool).await.unwrap();
    let store = WizardStore::Postgres(pool.clone());
    let id = store.create_company_draft(42, 7).await.unwrap().unwrap();
    let profile = CompanyProfile {
        assessment_goal: "ISO_READINESS".to_owned(),
        activity_context: "CROSS_BORDER".to_owned(),
        operation_countries: vec!["DE".to_owned(), "CH".to_owned()],
        annual_revenue_million: Some("1.20".to_owned()),
        regulatory_context: RegulatoryContext {
            established_in_germany: Some(true),
            cra_roles: vec!["IMPORTER".into()],
            ..Default::default()
        },
        ..CompanyProfile::default()
    };
    let (a, b) = tokio::join!(
        store.save_company_draft(42, 7, id, 1, profile.clone()),
        store.save_company_draft(42, 7, id, 1, profile.clone())
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(
        store.company_draft(42, id).await.unwrap().unwrap().profile,
        profile
    );
    assert!(store.company_draft(99, id).await.unwrap().is_none());
    assert!(!store
        .save_company_draft(42, 8, id, 2, CompanyProfile::default())
        .await
        .unwrap());
    assert!(sqlx::query("INSERT INTO wizard_companyprofile(session_id,tenant_id,revision,profile_json) VALUES($1,99,1,'{}')").bind(id).execute(&pool).await.is_err());
    sqlx::raw_sql("CREATE FUNCTION deny_context_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'PRIVATE-SNAPSHOT-AUDIT'; END $$; CREATE TRIGGER deny_context_audit BEFORE INSERT ON wizard_contextsnapshotevent FOR EACH ROW EXECUTE FUNCTION deny_context_audit();").execute(&pool).await.unwrap();
    assert!(store
        .freeze_company_context(42, 7, id, 2, "W2A-2026-11-03.1")
        .await
        .is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM wizard_contextsnapshot")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    sqlx::raw_sql("DROP TRIGGER deny_context_audit ON wizard_contextsnapshotevent; DROP FUNCTION deny_context_audit();").execute(&pool).await.unwrap();
    let (a, b) = tokio::join!(
        store.freeze_company_context(42, 7, id, 2, "W2A-2026-11-03.1"),
        store.freeze_company_context(42, 7, id, 2, "W2A-2026-11-03.1")
    );
    let frozen_id = a.unwrap().unwrap();
    assert_eq!(Some(frozen_id), b.unwrap());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM wizard_contextsnapshotevent")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    assert!(store
        .company_context_snapshot(99, id, frozen_id)
        .await
        .unwrap()
        .is_none());
    assert!(store
        .company_context_snapshot(42, id + 1, frozen_id)
        .await
        .unwrap()
        .is_none());
    let frozen_json: String =
        sqlx::query_scalar("SELECT snapshot_json FROM wizard_contextsnapshot WHERE id=$1")
            .bind(frozen_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::raw_sql("CREATE FUNCTION deny_profile_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'PRIVATE-AUDIT-FAILURE'; END $$; CREATE TRIGGER deny_profile_audit BEFORE INSERT ON wizard_profileevent FOR EACH ROW EXECUTE FUNCTION deny_profile_audit();").execute(&pool).await.unwrap();
    assert!(store
        .save_company_draft(42, 7, id, 2, CompanyProfile::default())
        .await
        .is_err());
    assert!(store.create_company_draft(42, 7).await.is_err());
    let retained = store.company_draft(42, id).await.unwrap().unwrap();
    assert_eq!(retained.profile, profile);
    assert_eq!(retained.revision, 2);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM wizard_assessmentsession")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM wizard_profileevent")
            .fetch_one(&pool)
            .await
            .unwrap(),
        2
    );
    let again = db_admin::run_db_admin_action(&url, db_admin::DbAdminAction::Migrate)
        .await
        .unwrap();
    assert!(again.applied_migrations.is_empty());
    assert!(
        sqlx::query_scalar::<_, String>(
            "SELECT snapshot_json FROM wizard_contextsnapshot WHERE id=$1"
        )
        .bind(frozen_id)
        .fetch_one(&pool)
        .await
        .unwrap()
            == frozen_json,
        "Frozen PostgreSQL snapshot changed"
    );
    sqlx::query("UPDATE wizard_assessmentsession SET status='COMPLETED' WHERE id=$1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(store
        .save_company_draft(42, 7, id, 2, CompanyProfile::default())
        .await
        .is_err());
    assert!(store
        .freeze_company_context(42, 7, id, 2, "W2A-2026-11-03.1")
        .await
        .is_err());
    assert!(store
        .company_context_snapshot(42, id, frozen_id)
        .await
        .unwrap()
        .is_some());
    drop(store);
    pool.close().await;
}

#[tokio::test]
async fn national_iso_context_roundtrips_and_review_keeps_zero_no_and_unknown_distinct() {
    let (app, pool, token) = fixture().await;
    let (id, csrf) = create(&app, &pool, &token).await;
    let mut fields = payload(&csrf, 1);
    for (key, value) in &mut fields {
        match *key {
            "operation_countries" | "headquarters_country" => *value = "DE".into(),
            "employee_count" => *value = "0".into(),
            "uses_ai_systems" => *value = "no".into(),
            _ => {}
        }
    }
    fields.push(("assessment_goal", "ISO_READINESS".into()));
    fields.push(("activity_context", "NATIONAL".into()));
    assert_eq!(
        request(
            &app,
            "POST",
            &format!("{ROOT}{id}/"),
            Some(&token),
            encode(&fields)
        )
        .await
        .0,
        StatusCode::SEE_OTHER
    );
    let store = WizardStore::from_sqlite_pool(pool.clone());
    let draft = store.company_draft(42, id).await.unwrap().unwrap();
    assert_eq!(draft.profile.assessment_goal, "ISO_READINESS");
    assert_eq!(draft.profile.activity_context, "NATIONAL");
    assert_eq!(draft.profile.operation_countries, vec!["DE"]);
    let before = snapshot(&pool).await;
    let (status, html) = request(
        &app,
        "GET",
        &format!("{ROOT}{id}/context/"),
        Some(&token),
        String::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    for text in [
        "Profilrevision 2",
        "ISO-Readiness",
        "Nationale Taetigkeit",
        "<th scope=\"row\">Mitarbeiterzahl</th><td>0</td>",
        "<th scope=\"row\">KI-Systeme</th><td>Nein</td>",
        "<th scope=\"row\">Digitale Produkte / Software</th><td>Unbekannt / noch offen</td>",
        "Scope, relevante Anforderungen und Risikobehandlung",
        "Versionierte Anforderungs-Pruefhinweise",
        "Kriterienversion W2A-2026-11-03.1",
        "data-screening-rule=\"ISO_ISMS_GOAL_V1\" data-screening-status=\"PLANNING_CHOICE\"",
        "data-screening-rule=\"DE_BSIG_SIZE_SIGNAL_V1\" data-screening-status=\"OPEN\"",
        "data-screening-rule=\"EU_CRA_PRODUCT_SIGNAL_V1\" data-screening-status=\"OPEN\"",
        "https://www.gesetze-im-internet.de/bsig_2025/__28.html",
        "Quellenabruf 2026-11-03",
        "&lt;script&gt;unsafe&lt;/script&gt;",
    ] {
        assert!(html.contains(text), "missing {text}");
    }
    assert!(!html.contains("<script>unsafe</script>"));
    assert_eq!(snapshot(&pool).await, before);
}

#[tokio::test]
async fn requirement_hints_follow_the_saved_revision_without_writing_decisions() {
    let (app, pool, token) = fixture().await;
    let (id, _) = create(&app, &pool, &token).await;
    let store = WizardStore::from_sqlite_pool(pool.clone());
    let profile = CompanyProfile {
        employee_count: Some(50),
        develops_digital_products: Some(true),
        ..Default::default()
    };
    assert!(store
        .save_company_draft(42, 7, id, 1, profile)
        .await
        .unwrap());
    let before = snapshot(&pool).await;
    let (status, body) = request(
        &app,
        "GET",
        &format!("{ROOT}{id}/context/"),
        Some(&token),
        String::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Profilrevision 2"));
    for rule in ["DE_BSIG_SIZE_SIGNAL_V1", "EU_CRA_PRODUCT_SIGNAL_V1"] {
        assert!(body.contains(&format!(
            "data-screening-rule=\"{rule}\" data-screening-status=\"REVIEW_HINT\""
        )));
    }
    assert_eq!(snapshot(&pool).await, before);
    assert!(store
        .save_company_draft(42, 7, id, 2, CompanyProfile::default())
        .await
        .unwrap());
    let before = snapshot(&pool).await;
    let (_, body) = request(
        &app,
        "GET",
        &format!("{ROOT}{id}/context/"),
        Some(&token),
        String::new(),
    )
    .await;
    assert!(body.contains("Profilrevision 3"));
    assert!(!body.contains("data-screening-status=\"REVIEW_HINT\""));
    assert_eq!(snapshot(&pool).await, before);
}

fn snapshot_payload(csrf: &str, revision: i64) -> String {
    encode(&[
        ("csrf_token", csrf.into()),
        ("revision", revision.to_string()),
        ("criteria_version", "W2A-2026-11-03.1".into()),
    ])
}

#[tokio::test]
async fn regulatory_case_facts_roundtrip_preserve_unknown_no_and_historical_snapshots() {
    let (app, pool, token) = fixture().await;
    let (id, csrf) = create(&app, &pool, &token).await;
    let path = format!("{ROOT}{id}/");
    let legacy_store = WizardStore::from_sqlite_pool(pool.clone());
    let legacy_snapshot = legacy_store
        .freeze_company_context(42, 7, id, 1, "W2A-2026-11-03.1")
        .await
        .unwrap()
        .unwrap();
    let mut fields = payload(&csrf, 1);
    fields.extend([
        ("regulatory_context_present", "1".into()),
        ("regulatory_scope", "<script>case</script>".into()),
        ("established_in_germany", "no".into()),
        ("bsig_annex_1_activity", "yes".into()),
        ("cra_eu_market", "yes".into()),
        ("cra_role_manufacturer", "yes".into()),
        ("cra_role_importer", "yes".into()),
        ("regulatory_notes", "<img src=x onerror=case>".into()),
    ]);
    assert_eq!(
        request(&app, "POST", &path, Some(&token), encode(&fields))
            .await
            .0,
        StatusCode::SEE_OTHER
    );
    let store = WizardStore::from_sqlite_pool(pool.clone());
    let draft = store.company_draft(42, id).await.unwrap().unwrap();
    assert_eq!(draft.revision, 2);
    let (_, legacy_html) = request(
        &app,
        "GET",
        &format!("{path}context/snapshots/{legacy_snapshot}/"),
        Some(&token),
        String::new(),
    )
    .await;
    assert!(
        legacy_html.contains("Profilrevision 1") && !legacy_html.contains("&lt;script&gt;case")
    );
    assert_eq!(
        draft.profile.regulatory_context.established_in_germany,
        Some(false)
    );
    assert_eq!(draft.profile.regulatory_context.bsig_annex_2_activity, None);
    assert_eq!(
        draft.profile.regulatory_context.cra_roles,
        vec!["MANUFACTURER", "IMPORTER"]
    );
    let before = snapshot(&pool).await;
    let (_, editor) = request(&app, "GET", &path, Some(&token), String::new()).await;
    assert!(editor.contains("name=\"cra_role_importer\" value=\"yes\" checked"));
    assert!(!editor.contains("CRA-Rollen (Codes"));
    let (_, html) = request(
        &app,
        "GET",
        &format!("{path}context/"),
        Some(&token),
        String::new(),
    )
    .await;
    assert!(html.contains("&lt;script&gt;case&lt;/script&gt;"));
    assert!(html.contains("Hersteller, Einfuehrer"));
    assert!(html
        .contains("<th scope=\"row\">Niederlassung in Deutschland laut Angabe</th><td>Nein</td>"));
    assert!(html.contains("<th scope=\"row\">Taetigkeit aus BSIG-Anlage 2 laut Angabe</th><td>Unbekannt / noch offen</td>"));
    assert!(!html.contains("<script>case</script>") && !html.contains("<img src=x onerror=case>"));
    assert!(snapshot(&pool).await == before, "GET changed stored data");
    let sid = store
        .freeze_company_context(42, 7, id, 2, "W2A-2026-11-03.1")
        .await
        .unwrap()
        .unwrap();
    // An old client omits the entire group: retain existing case facts.
    assert_eq!(
        request(
            &app,
            "POST",
            &path,
            Some(&token),
            encode(&payload(&csrf, 2))
        )
        .await
        .0,
        StatusCode::SEE_OTHER
    );
    let retained = store.company_draft(42, id).await.unwrap().unwrap();
    assert!(
        retained.profile.regulatory_context == draft.profile.regulatory_context,
        "Legacy form erased case facts"
    );
    // A current complete form can explicitly clear all new facts to unknown.
    let mut clear = payload(&csrf, 3);
    clear.push(("regulatory_context_present", "1".into()));
    assert_eq!(
        request(&app, "POST", &path, Some(&token), encode(&clear))
            .await
            .0,
        StatusCode::SEE_OTHER
    );
    assert!(
        store
            .company_draft(42, id)
            .await
            .unwrap()
            .unwrap()
            .profile
            .regulatory_context
            == RegulatoryContext::default()
    );
    let old = format!("{path}context/snapshots/{sid}/");
    let (_, html) = request(&app, "GET", &old, Some(&token), String::new()).await;
    assert!(
        html.contains("&lt;script&gt;case&lt;/script&gt;")
            && html.contains("Hersteller, Einfuehrer")
    );
    assert!(store
        .company_context_snapshot(99, id, sid)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn invalid_regulatory_case_inputs_leave_profile_and_audit_unchanged() {
    let (app, pool, token) = fixture().await;
    let (id, csrf) = create(&app, &pool, &token).await;
    let path = format!("{ROOT}{id}/");
    let before = snapshot(&pool).await;
    for (key, value) in [
        ("regulatory_scope", "x".repeat(256)),
        ("regulatory_notes", "x".repeat(2001)),
        ("regulatory_notes", "hidden\0value".into()),
        ("established_in_germany", "unknown".into()),
        ("bsig_annex_1_activity", "true".into()),
        ("cra_eu_market", "maybe".into()),
        ("cra_role_importer", "definitely".into()),
        ("regulatory_context_present", "2".into()),
    ] {
        let mut fields = payload(&csrf, 1);
        fields.push((key, value));
        let (status, html) = request(&app, "POST", &path, Some(&token), encode(&fields)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{key}");
        assert!(html.contains("Ihre Eingaben wurden nicht gespeichert"));
        assert!(
            snapshot(&pool).await == before,
            "Invalid case facts changed stored data"
        );
    }
    let mut fields = payload(&csrf, 1);
    fields.push(("regulatory_notes", "private-case-marker".into()));
    let auth = AuthStore::from_sqlite_pool(pool.clone());
    let foreign = auth.create_session(99, 8).await.unwrap().unwrap().token;
    let reader = auth.create_session(42, 9).await.unwrap().unwrap().token;
    for (session, status) in [
        (None, StatusCode::UNAUTHORIZED),
        (Some(reader.as_str()), StatusCode::FORBIDDEN),
        (Some(foreign.as_str()), StatusCode::FORBIDDEN),
    ] {
        assert_eq!(
            request(&app, "POST", &path, session, encode(&fields))
                .await
                .0,
            status
        );
        assert!(
            snapshot(&pool).await == before,
            "Rejected write changed case facts"
        );
    }
}

#[test]
fn regulatory_case_json_is_optional_bounded_and_closed_to_unknown_fields() {
    let old = serde_json::to_value(CompanyProfile::default()).unwrap();
    assert!(old.get("regulatory_context").is_none());
    let decoded: CompanyProfile = serde_json::from_value(old.clone()).unwrap();
    assert!(decoded.regulatory_context == RegulatoryContext::default());
    let mut forged = old.clone();
    forged["regulatory_context"] = serde_json::json!({"approved":true});
    assert!(serde_json::from_value::<CompanyProfile>(forged).is_err());
    for context in [
        RegulatoryContext {
            cra_roles: vec!["CERTIFIED".into()],
            ..Default::default()
        },
        RegulatoryContext {
            cra_roles: vec!["IMPORTER".into(); 7],
            ..Default::default()
        },
    ] {
        assert!(CompanyProfile {
            regulatory_context: context,
            ..Default::default()
        }
        .normalize()
        .is_err());
    }
    let normalized = CompanyProfile {
        regulatory_context: RegulatoryContext {
            cra_roles: vec![" importer ".into(), "IMPORTER".into()],
            established_in_germany: Some(false),
            notes: "Line one\r\nLine two".into(),
            ..Default::default()
        },
        ..Default::default()
    }
    .normalize()
    .unwrap();
    assert_eq!(normalized.regulatory_context.cra_roles, vec!["IMPORTER"]);
    assert!(normalized.regulatory_context.notes == "Line one\nLine two");
    let value = serde_json::to_value(normalized).unwrap();
    assert_eq!(value["regulatory_context"]["established_in_germany"], false);
}

#[tokio::test]
async fn saved_context_snapshots_freeze_facts_sources_and_revision_without_approval() {
    let (app, pool, token) = fixture().await;
    let (id, csrf) = create(&app, &pool, &token).await;
    let path = format!("{ROOT}{id}/context/snapshots/");
    assert_eq!(
        request(
            &app,
            "POST",
            &format!("{ROOT}{id}/"),
            Some(&token),
            encode(&payload(&csrf, 1))
        )
        .await
        .0,
        StatusCode::SEE_OTHER
    );
    let before_profile = sqlx::query_scalar::<_, String>(
        "SELECT profile_json FROM wizard_companyprofile WHERE session_id=?1",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    for _ in 0..2 {
        assert_eq!(
            request(
                &app,
                "POST",
                &path,
                Some(&token),
                snapshot_payload(&csrf, 2)
            )
            .await
            .0,
            StatusCode::SEE_OTHER
        );
    }
    let sid: i64 = sqlx::query_scalar("SELECT id FROM wizard_contextsnapshot WHERE session_id=?1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let raw: String =
        sqlx::query_scalar("SELECT snapshot_json FROM wizard_contextsnapshot WHERE id=?1")
            .bind(sid)
            .fetch_one(&pool)
            .await
            .unwrap();
    let frozen: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(frozen["profile_revision"], 2);
    assert_eq!(frozen["schema_version"], 1);
    assert_eq!(frozen["criteria"]["version"], "W2A-2026-11-03.1");
    assert_eq!(frozen["criteria"]["entries"].as_array().unwrap().len(), 3);
    assert_eq!(snapshot(&pool).await.3, 1);
    assert_eq!(snapshot(&pool).await.4, 1);
    let store = WizardStore::from_sqlite_pool(pool.clone());
    assert!(store
        .save_company_draft(
            42,
            7,
            id,
            2,
            CompanyProfile {
                company_name: "Updated name".into(),
                ..Default::default()
            }
        )
        .await
        .unwrap());
    let read = format!("{path}{sid}/");
    let before = snapshot(&pool).await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&read)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cache = response.headers()["cache-control"].to_str().unwrap();
    assert!(cache.contains("private") && cache.contains("no-store"));
    let html = String::from_utf8(
        to_bytes(response.into_body(), 200000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains("Profilrevision 2"));
    assert!(html.contains("&lt;script&gt;unsafe&lt;/script&gt;"));
    assert!(!html.contains("Updated name") && !html.contains("<script>unsafe</script>"));
    assert!(html.contains("Quellenabruf 2026-11-03"));
    assert!(snapshot(&pool).await == before, "Stored state changed");
    assert!(
        sqlx::query_scalar::<_, String>(
            "SELECT snapshot_json FROM wizard_contextsnapshot WHERE id=?1"
        )
        .bind(sid)
        .fetch_one(&pool)
        .await
        .unwrap()
            == raw,
        "Frozen snapshot changed"
    );
    assert!(
        serde_json::from_str::<Value>(&before_profile).unwrap() == frozen["profile"],
        "Frozen profile differs"
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT applicability_result FROM wizard_assessmentsession WHERE id=500"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        "HISTORICAL"
    );
    assert_eq!(
        request(&app, "POST", &read, Some(&token), String::new())
            .await
            .0,
        StatusCode::METHOD_NOT_ALLOWED
    );
}

#[tokio::test]
async fn snapshot_routes_enforce_auth_roles_csrf_tenants_catalog_and_parent_binding() {
    let (app, pool, token) = fixture().await;
    let (id, csrf) = create(&app, &pool, &token).await;
    let path = format!("{ROOT}{id}/context/snapshots/");
    let auth = AuthStore::from_sqlite_pool(pool.clone());
    let foreign = auth.create_session(99, 8).await.unwrap().unwrap().token;
    let reader = auth.create_session(42, 9).await.unwrap().unwrap().token;
    let denied = auth.create_session(42, 10).await.unwrap().unwrap().token;
    let foreign_csrf = form_csrf(&app, &foreign).await;
    assert_eq!(
        request(
            &app,
            "POST",
            &path,
            Some(&foreign),
            snapshot_payload(&foreign_csrf, 1)
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let before = snapshot(&pool).await;
    for (session, expected) in [
        (None, StatusCode::UNAUTHORIZED),
        (Some(reader.as_str()), StatusCode::FORBIDDEN),
        (Some(denied.as_str()), StatusCode::FORBIDDEN),
    ] {
        assert_eq!(
            request(&app, "POST", &path, session, snapshot_payload(&csrf, 1))
                .await
                .0,
            expected
        );
    }
    assert_eq!(
        request(
            &app,
            "POST",
            &path,
            Some(&token),
            snapshot_payload("invalid", 1)
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            &app,
            "POST",
            &path,
            Some(&token),
            snapshot_payload(&csrf, 9)
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        request(
            &app,
            "POST",
            &path,
            Some(&token),
            snapshot_payload(&csrf, 1).replace("W2A-2026-11-03.1", "OLD-CATALOG")
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert!(snapshot(&pool).await == before, "Stored state changed");
    assert_eq!(
        request(
            &app,
            "POST",
            &path,
            Some(&token),
            snapshot_payload(&csrf, 1)
        )
        .await
        .0,
        StatusCode::SEE_OTHER
    );
    let sid: i64 = sqlx::query_scalar("SELECT id FROM wizard_contextsnapshot WHERE session_id=?1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let read = format!("{path}{sid}/");
    for (session, expected) in [
        (None, StatusCode::UNAUTHORIZED),
        (Some(denied.as_str()), StatusCode::FORBIDDEN),
        (Some(foreign.as_str()), StatusCode::NOT_FOUND),
        (Some(reader.as_str()), StatusCode::OK),
    ] {
        assert_eq!(
            request(&app, "GET", &read, session, String::new()).await.0,
            expected
        );
    }
    let (other, _) = create(&app, &pool, &token).await;
    assert_eq!(
        request(
            &app,
            "GET",
            &format!("{ROOT}{other}/context/snapshots/{sid}/"),
            Some(&token),
            String::new()
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("{read}?tenant_id=99&user_id=8"))
                .header("authorization", format!("Bearer {reader}"))
                .header("x-iscy-tenant-id", "99")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let store = WizardStore::from_sqlite_pool(pool.clone());
    assert!(store
        .freeze_company_context(42, 8, id, 1, "W2A-2026-11-03.1")
        .await
        .unwrap()
        .is_none());
    sqlx::query(
        "UPDATE wizard_assessmentsession SET status='COMPLETED',current_step='results' WHERE id=?1",
    )
    .bind(id)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        request(
            &app,
            "POST",
            &path,
            Some(&token),
            snapshot_payload(&csrf, 1)
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        request(&app, "GET", &read, Some(&reader), String::new())
            .await
            .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn snapshot_creation_rolls_back_on_audit_failure_and_coalesces_parallel_posts() {
    let (app, pool, token) = fixture().await;
    let (id, csrf) = create(&app, &pool, &token).await;
    let path = format!("{ROOT}{id}/context/snapshots/");
    sqlx::raw_sql("CREATE TRIGGER deny_snapshot_audit BEFORE INSERT ON wizard_contextsnapshotevent BEGIN SELECT RAISE(ABORT,'PRIVATE-SNAPSHOT-AUDIT'); END;").execute(&pool).await.unwrap();
    let before = snapshot(&pool).await;
    let (status, body) = request(
        &app,
        "POST",
        &path,
        Some(&token),
        snapshot_payload(&csrf, 1),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!body.contains("PRIVATE-SNAPSHOT-AUDIT"));
    assert!(snapshot(&pool).await == before, "Stored state changed");
    sqlx::raw_sql("DROP TRIGGER deny_snapshot_audit;")
        .execute(&pool)
        .await
        .unwrap();
    let store = WizardStore::from_sqlite_pool(pool.clone());
    let (a, b) = tokio::join!(
        store.freeze_company_context(42, 7, id, 1, "W2A-2026-11-03.1"),
        store.freeze_company_context(42, 7, id, 1, "W2A-2026-11-03.1")
    );
    assert_eq!(a.unwrap(), b.unwrap());
    assert_eq!(snapshot(&pool).await.3, 1);
    assert_eq!(snapshot(&pool).await.4, 1);
    assert_eq!(snapshot(&pool).await.2, before.2);
}

#[tokio::test]
async fn snapshot_migration_upgrades_existing_profiles_and_is_restartable() {
    let (app, pool, token) = fixture().await;
    let (id, _) = create(&app, &pool, &token).await;
    let before = snapshot(&pool).await;
    sqlx::raw_sql("DROP TABLE wizard_contextsnapshotevent; DROP TABLE wizard_contextsnapshot; DELETE FROM iscy_schema_migrations WHERE version='0050_rust_company_context_snapshot';").execute(&pool).await.unwrap();
    let applied = db_admin::run_sqlite_migrations(&pool).await.unwrap();
    assert_eq!(applied, vec!["0050_rust_company_context_snapshot"]);
    assert!(snapshot(&pool).await == before, "Stored state changed");
    let store = WizardStore::from_sqlite_pool(pool.clone());
    let sid = store
        .freeze_company_context(42, 7, id, 1, "W2A-2026-11-03.1")
        .await
        .unwrap()
        .unwrap();
    let raw: String =
        sqlx::query_scalar("SELECT snapshot_json FROM wizard_contextsnapshot WHERE id=?1")
            .bind(sid)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(db_admin::run_sqlite_migrations(&pool)
        .await
        .unwrap()
        .is_empty());
    assert!(
        sqlx::query_scalar::<_, String>(
            "SELECT snapshot_json FROM wizard_contextsnapshot WHERE id=?1"
        )
        .bind(sid)
        .fetch_one(&pool)
        .await
        .unwrap()
            == raw,
        "Migration altered a saved snapshot"
    );
}

#[tokio::test]
async fn context_review_enforces_real_sessions_roles_tenants_and_read_only_methods() {
    let (app, pool, token) = fixture().await;
    let (id, _) = create(&app, &pool, &token).await;
    let path = format!("{ROOT}{id}/context/");
    let auth = AuthStore::from_sqlite_pool(pool.clone());
    let foreign = auth.create_session(99, 8).await.unwrap().unwrap().token;
    let forbidden = auth.create_session(42, 10).await.unwrap().unwrap().token;
    let reader = auth.create_session(42, 9).await.unwrap().unwrap().token;
    let before = snapshot(&pool).await;
    assert_eq!(
        request(&app, "GET", &path, None, String::new()).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(&app, "GET", &path, Some(&forbidden), String::new())
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(&app, "GET", &path, Some(&foreign), String::new())
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("{path}?tenant_id=99&user_id=8"))
                .header("authorization", format!("Bearer {reader}"))
                .header("x-iscy-tenant-id", "99")
                .header("x-iscy-user-id", "8")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("{path}?tenant_id=99&user_id=8"))
                .header("authorization", format!("Bearer {reader}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cache_control = response.headers()["cache-control"].to_str().unwrap();
    for required in ["private", "no-store"] {
        assert!(cache_control
            .split(',')
            .map(str::trim)
            .any(|value| value == required));
    }
    assert_eq!(
        request(&app, "POST", &path, Some(&token), String::new())
            .await
            .0,
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        request(
            &app,
            "GET",
            &format!("{ROOT}999999/context/"),
            Some(&token),
            String::new()
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert!(snapshot(&pool).await == before, "Stored state changed");
    sqlx::query(
        "UPDATE wizard_assessmentsession SET status='COMPLETED',current_step='results' WHERE id=?1",
    )
    .bind(id)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        request(&app, "GET", &path, Some(&reader), String::new())
            .await
            .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn legacy_profiles_default_to_open_context_and_invalid_choices_never_change_a_draft() {
    let legacy = serde_json::to_value(CompanyProfile::default()).unwrap();
    let mut old = legacy.as_object().unwrap().clone();
    old.remove("assessment_goal");
    old.remove("activity_context");
    let restored: CompanyProfile = serde_json::from_value(Value::Object(old.clone())).unwrap();
    assert_eq!(restored.assessment_goal, "");
    assert_eq!(restored.activity_context, "");
    let normalized = CompanyProfile {
        assessment_goal: " iso_readiness ".into(),
        activity_context: " national ".into(),
        ..CompanyProfile::default()
    }
    .normalize()
    .unwrap();
    assert_eq!(normalized.assessment_goal, "ISO_READINESS");
    assert_eq!(normalized.activity_context, "NATIONAL");
    let (app, pool, token) = fixture().await;
    let (id, csrf) = create(&app, &pool, &token).await;
    sqlx::query("UPDATE wizard_companyprofile SET profile_json=?1 WHERE session_id=?2")
        .bind(Value::Object(old).to_string())
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    let before = snapshot(&pool).await;
    let (status, body) = request(
        &app,
        "GET",
        &format!("{ROOT}{id}/context/"),
        Some(&token),
        String::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Zunaechst das Ziel des Durchlaufs festlegen"));
    for (key, value) in [
        ("assessment_goal", "CERTIFIED"),
        ("activity_context", "GLOBAL"),
    ] {
        let mut fields = payload(&csrf, 1);
        fields.push((key, value.into()));
        assert_eq!(
            request(
                &app,
                "POST",
                &format!("{ROOT}{id}/"),
                Some(&token),
                encode(&fields)
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        assert!(snapshot(&pool).await == before, "Stored state changed");
    }
}
