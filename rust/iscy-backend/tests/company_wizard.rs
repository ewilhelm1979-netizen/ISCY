use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use iscy_backend::{
    app_router_with_state,
    auth_store::AuthStore,
    company_wizard::{CompanyProfile, ROOT},
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
async fn snapshot(pool: &SqlitePool) -> (String, String, i64) {
    (sqlx::query_scalar("SELECT COALESCE(json_group_array(json_object('id',session_id,'rev',revision,'json',profile_json)),'[]') FROM wizard_companyprofile ORDER BY session_id").fetch_one(pool).await.unwrap(),
     sqlx::query_scalar("SELECT COALESCE(json_group_array(json_object('id',id,'status',status,'step',current_step,'summary',executive_summary,'result',applicability_result,'updated',updated_at)),'[]') FROM wizard_assessmentsession ORDER BY id").fetch_one(pool).await.unwrap(),
     sqlx::query_scalar("SELECT COUNT(*) FROM wizard_profileevent").fetch_one(pool).await.unwrap())
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
    assert_eq!(version, "0049_rust_iscy27_nis2_reference_correction");
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
        Some(&"0049_rust_iscy27_nis2_reference_correction")
    );
    sqlx::raw_sql("INSERT INTO organizations_tenant(id,name,slug) VALUES(42,'PG company','pg-company'),(99,'PG foreign','pg-foreign'); INSERT INTO accounts_user(id,tenant_id,username,role) VALUES(7,42,'writer','CONTRIBUTOR'),(8,99,'foreign','CONTRIBUTOR');").execute(&pool).await.unwrap();
    let store = WizardStore::Postgres(pool.clone());
    let id = store.create_company_draft(42, 7).await.unwrap().unwrap();
    let profile = CompanyProfile {
        operation_countries: vec!["DE".to_owned(), "CH".to_owned()],
        annual_revenue_million: Some("1.20".to_owned()),
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
    sqlx::query("UPDATE wizard_assessmentsession SET status='COMPLETED' WHERE id=$1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(store
        .save_company_draft(42, 7, id, 2, CompanyProfile::default())
        .await
        .is_err());
    drop(store);
    pool.close().await;
}
