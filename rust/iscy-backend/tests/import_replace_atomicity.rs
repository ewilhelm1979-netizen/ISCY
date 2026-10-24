use std::{
    collections::{BTreeMap, HashMap},
    io::{Cursor, Write},
};

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use iscy_backend::{
    app_router_with_state,
    auth_store::AuthStore,
    db_admin,
    hardening::{AppMode, CommunitySecurityConfig},
    import_store::{ImportJobRequest, ImportStore},
    AppState,
};
use serde_json::{json, Value};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::SqlitePoolOptions,
    PgPool, Row, SqlitePool,
};
use tower::ServiceExt;

const TYPES: [(&str, &str); 4] = [
    ("processes", "processes_process"),
    ("assets", "assets_app_informationasset"),
    ("suppliers", "organizations_supplier"),
    ("business_units", "organizations_businessunit"),
];

fn row(name: &str, unit: &str) -> HashMap<String, Value> {
    serde_json::from_value(json!({
        "name": name,
        "business_unit": unit,
        "description": "synthetic import fixture",
        "status": "PARTIAL",
        "criticality": "HIGH",
        "documented": true
    }))
    .unwrap()
}

fn job(import_type: &str, replace_existing: bool, names: &[&str]) -> ImportJobRequest {
    ImportJobRequest {
        import_type: import_type.to_string(),
        replace_existing,
        rows: names
            .iter()
            .enumerate()
            .map(|(index, name)| row(name, &format!("new-unit-{index}")))
            .collect(),
    }
}

async fn fixture() -> (SqlitePool, ImportStore) {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db_admin::run_sqlite_migrations(&pool).await.unwrap();
    sqlx::query("INSERT INTO organizations_tenant (id,name,slug) VALUES (42,'Import owner','import-owner'),(73,'Foreign tenant','foreign-import')")
        .execute(&pool).await.unwrap();
    let store = ImportStore::from_sqlite_pool(pool.clone());
    for tenant_id in [42, 73] {
        for (import_type, _) in TYPES.iter().rev() {
            store
                .apply_job(
                    tenant_id,
                    ImportJobRequest {
                        import_type: (*import_type).to_string(),
                        replace_existing: false,
                        rows: vec![row(&format!("old-{import_type}"), "old-unit")],
                    },
                )
                .await
                .unwrap();
        }
    }
    for (_, table) in TYPES {
        sqlx::query(&format!("UPDATE {table} SET created_at='2001-02-03T04:05:06Z',updated_at='2002-03-04T05:06:07Z'"))
            .execute(&pool).await.unwrap();
    }
    (pool, store)
}

async fn snapshot(pool: &SqlitePool, tenant_id: Option<i64>) -> BTreeMap<String, Vec<String>> {
    let mut result = BTreeMap::new();
    for (_, table) in TYPES {
        let columns = sqlx::query(&format!("PRAGMA table_info({table})"))
            .fetch_all(pool)
            .await
            .unwrap();
        let fields = columns
            .iter()
            .map(|row| {
                let name: String = row.get("name");
                assert!(name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'));
                format!("'{name}',\"{name}\"")
            })
            .collect::<Vec<_>>()
            .join(",");
        let scope = tenant_id
            .map(|id| format!(" WHERE tenant_id={id}"))
            .unwrap_or_default();
        let rows = sqlx::query_scalar(&format!(
            "SELECT json_object({fields}) FROM {table}{scope} ORDER BY id"
        ))
        .fetch_all(pool)
        .await
        .unwrap();
        result.insert(table.to_string(), rows);
    }
    result
}

#[tokio::test]
async fn sqlite_replace_failure_preserves_all_original_rows_and_helper_units() {
    for (import_type, table) in TYPES {
        for failed_index in [1, 0, 2] {
            let (pool, store) = fixture().await;
            let before = snapshot(&pool, None).await;
            let names = ["new-first", "new-middle", "new-last"];
            sqlx::query(&format!(
                "CREATE TRIGGER f07_insert_failure BEFORE INSERT ON {table} \
                 WHEN NEW.tenant_id=42 AND NEW.name='{}' \
                 BEGIN SELECT RAISE(ABORT,'f07 controlled insert failure'); END",
                names[failed_index]
            ))
            .execute(&pool)
            .await
            .unwrap();
            let error = store
                .apply_job(42, job(import_type, true, &names))
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("f07 controlled insert failure"));
            assert_eq!(
                snapshot(&pool, None).await,
                before,
                "{import_type}: failed row {failed_index} must roll back the complete replace"
            );
            eprintln!("F07_SQLITE_ROLLBACK_OK type={import_type} failed_index={failed_index}");
            pool.close().await;
        }
    }
}

#[tokio::test]
async fn sqlite_replace_success_preserves_counters_skips_and_foreign_tenant() {
    for (import_type, table) in TYPES {
        let (pool, store) = fixture().await;
        let foreign_before = snapshot(&pool, Some(73)).await;
        let result = store
            .apply_job(42, job(import_type, true, &["new-name", "new-name", ""]))
            .await
            .unwrap();
        assert_eq!(result.tenant_id, 42);
        assert_eq!(result.import_type, import_type);
        assert_eq!(result.row_count, 3);
        assert_eq!((result.created, result.updated, result.skipped), (1, 1, 1));
        let names: Vec<String> = sqlx::query_scalar(&format!(
            "SELECT name FROM {table} WHERE tenant_id=42 ORDER BY id"
        ))
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(names, ["new-name"]);
        assert_eq!(snapshot(&pool, Some(73)).await, foreign_before);
        eprintln!("F07_SQLITE_SUCCESS_OK type={import_type}");
        pool.close().await;
    }
}

#[tokio::test]
async fn sqlite_append_failure_retains_original_autocommit_and_partial_progress() {
    for (import_type, table) in TYPES {
        let (pool, store) = fixture().await;
        let before = snapshot(&pool, None).await;
        let foreign_before = snapshot(&pool, Some(73)).await;
        sqlx::query(&format!("CREATE TRIGGER f07_append_failure BEFORE INSERT ON {table} WHEN NEW.tenant_id=42 AND NEW.name='new-middle' BEGIN SELECT RAISE(ABORT,'f07 controlled append failure'); END"))
            .execute(&pool).await.unwrap();
        let error = store
            .apply_job(
                42,
                job(import_type, false, &["new-first", "new-middle", "new-last"]),
            )
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("f07 controlled append failure"));
        let after = snapshot(&pool, None).await;
        for (table, rows) in before {
            for row in rows {
                assert!(
                    after[&table].contains(&row),
                    "Append must retain old rows, including timestamps"
                );
            }
        }
        let names: Vec<String> = sqlx::query_scalar(&format!(
            "SELECT name FROM {table} WHERE tenant_id=42 ORDER BY id"
        ))
        .fetch_all(&pool)
        .await
        .unwrap();
        assert!(names.iter().any(|name| name == "new-first"));
        assert!(!names
            .iter()
            .any(|name| name == "new-middle" || name == "new-last"));
        assert_eq!(snapshot(&pool, Some(73)).await, foreign_before);
        eprintln!("F07_SQLITE_APPEND_AUTOCOMMIT_UNCHANGED_OK type={import_type}");
        pool.close().await;
    }
}

#[tokio::test]
async fn sqlite_empty_replace_and_unsupported_types_preserve_existing_contract() {
    for (import_type, table) in TYPES {
        let (pool, store) = fixture().await;
        let before = snapshot(&pool, None).await;
        for unsupported in ["soa", "assessments_soaentry", "assets;DELETE", "process"] {
            assert!(store
                .apply_job(42, job(unsupported, true, &["valid-name"]))
                .await
                .is_err());
            assert_eq!(snapshot(&pool, None).await, before);
        }
        let result = store
            .apply_job(42, job(import_type, false, &[""]))
            .await
            .unwrap();
        assert_eq!((result.created, result.updated, result.skipped), (0, 0, 1));
        assert_eq!(snapshot(&pool, None).await, before);
        let foreign_before = snapshot(&pool, Some(73)).await;
        let result = store
            .apply_job(42, job(import_type, true, &[]))
            .await
            .unwrap();
        assert_eq!(
            (
                result.row_count,
                result.created,
                result.updated,
                result.skipped
            ),
            (0, 0, 0, 0)
        );
        let count: i64 =
            sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE tenant_id=42"))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count, 0);
        assert_eq!(snapshot(&pool, Some(73)).await, foreign_before);
        pool.close().await;
    }
}

#[tokio::test]
async fn sqlite_replace_commit_failure_rolls_back_rows_and_trigger_side_effects() {
    for (import_type, table) in TYPES {
        let (pool, store) = fixture().await;
        let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(foreign_keys, 1);
        let before = snapshot(&pool, None).await;
        sqlx::raw_sql(&format!(
            "CREATE TABLE f07_commit_parent(id INTEGER PRIMARY KEY);
             CREATE TABLE f07_commit_child(parent_id INTEGER REFERENCES f07_commit_parent(id) DEFERRABLE INITIALLY DEFERRED);
             CREATE TRIGGER f07_deferred_failure AFTER INSERT ON {table}
             WHEN NEW.tenant_id=42 AND NEW.name='new-first'
             BEGIN INSERT INTO f07_commit_child(parent_id) VALUES(-1); END;"
        ))
        .execute(&pool)
        .await
        .unwrap();
        let error = store
            .apply_job(42, job(import_type, true, &["new-first", "new-last"]))
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("FOREIGN KEY constraint failed"));
        assert_eq!(
            snapshot(&pool, None).await,
            before,
            "{import_type}: failed commit"
        );
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM f07_commit_child")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
        eprintln!("F07_SQLITE_COMMIT_ROLLBACK_OK type={import_type}");
        pool.close().await;
    }
}

#[derive(Clone, Copy, Debug)]
enum ImportRoute {
    Json,
    Csv,
    WebCsv,
    WebPreviewCsv,
    WebPreviewXlsx,
}

impl ImportRoute {
    fn is_api(self) -> bool {
        matches!(self, Self::Json | Self::Csv)
    }

    fn upload(self) -> (&'static str, Vec<u8>) {
        if matches!(self, Self::WebPreviewXlsx) {
            ("f07.xlsx", xlsx_fixture())
        } else {
            ("f07.csv", csv_fixture().as_bytes().to_vec())
        }
    }
}

fn csv_fixture() -> &'static str {
    "Name,BusinessUnit\nnew-first,new-unit-0\nnew-middle,new-unit-1\nnew-last,new-unit-2\n"
}

fn xlsx_fixture() -> Vec<u8> {
    let rows = [
        ("Name", "BusinessUnit"),
        ("new-first", "new-unit-0"),
        ("new-middle", "new-unit-1"),
        ("new-last", "new-unit-2"),
    ];
    let mut sheet = String::from(
        r#"<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><dimension ref="A1:B4"/><sheetData>"#,
    );
    for (index, (name, unit)) in rows.iter().enumerate() {
        let number = index + 1;
        sheet.push_str(&format!(r#"<row r="{number}"><c r="A{number}" t="inlineStr"><is><t>{name}</t></is></c><c r="B{number}" t="inlineStr"><is><t>{unit}</t></is></c></row>"#));
    }
    sheet.push_str("</sheetData></worksheet>");
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, contents) in [
        (
            "[Content_Types].xml",
            r#"<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>"#,
        ),
        (
            "_rels/.rels",
            r#"<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>"#,
        ),
        (
            "xl/workbook.xml",
            r#"<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Import" sheetId="1" r:id="rId1"/></sheets></workbook>"#,
        ),
        (
            "xl/_rels/workbook.xml.rels",
            r#"<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>"#,
        ),
        ("xl/worksheets/sheet1.xml", sheet.as_str()),
    ] {
        writer
            .start_file(
                name,
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated),
            )
            .unwrap();
        writer.write_all(contents.as_bytes()).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn multipart(fields: &[(&str, String)], file: Option<(&str, &[u8])>) -> Vec<u8> {
    let mut body = Vec::new();
    for (key, value) in fields {
        body.extend_from_slice(format!("--f07-boundary\r\nContent-Disposition: form-data; name=\"{key}\"\r\n\r\n{value}\r\n").as_bytes());
    }
    if let Some((name, bytes)) = file {
        body.extend_from_slice(format!("--f07-boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes());
        body.extend_from_slice(bytes);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"--f07-boundary--\r\n");
    body
}

async fn route_request(
    app: &Router,
    route: ImportRoute,
    import_type: &str,
    token: Option<&str>,
    forged_headers: bool,
    preview_only: bool,
) -> (StatusCode, String) {
    let (path, content_type, body) = match route {
        ImportRoute::Json => (
            "/api/v1/import-center/jobs",
            "application/json",
            json!({"import_type":import_type,"replace_existing":true,"rows":job(import_type,true,&["new-first","new-middle","new-last"]).rows,"tenant_id":73,"user_id":7301}).to_string().into_bytes(),
        ),
        ImportRoute::Csv => (
            "/api/v1/import-center/csv",
            "application/json",
            json!({"import_type":import_type,"replace_existing":true,"csv_data":csv_fixture(),"tenant_id":73,"user_id":7301}).to_string().into_bytes(),
        ),
        ImportRoute::WebCsv => (
            "/imports/", "application/x-www-form-urlencoded",
            format!("import_type={import_type}&replace_existing=1&tenant_id=73&user_id=7301&csv_data=Name%2CBusinessUnit%0Anew-first%2Cnew-unit-0%0Anew-middle%2Cnew-unit-1%0Anew-last%2Cnew-unit-2%0A").into_bytes(),
        ),
        ImportRoute::WebPreviewCsv | ImportRoute::WebPreviewXlsx => {
            let (filename, bytes) = route.upload();
            let mut fields = vec![
                ("import_type", import_type.to_string()),
                ("replace_existing", "1".to_string()),
                ("action", if preview_only { "preview" } else { "confirm" }.to_string()),
                ("tenant_id", "73".to_string()),
                ("user_id", "7301".to_string()),
                ("map_name", "Name".to_string()),
                ("map_business_unit", "BusinessUnit".to_string()),
            ];
            if !preview_only {
                fields.push(("file_name", filename.to_string()));
                fields.push(("file_data_base64", BASE64.encode(&bytes)));
            }
            let file = preview_only.then_some((filename, bytes.as_slice()));
            ("/imports/preview/", "multipart/form-data; boundary=f07-boundary", multipart(&fields, file))
        }
    };
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("{path}?tenant_id=73&user_id=7301"))
        .header("content-type", content_type);
    if let Some(token) = token {
        request = if route.is_api() {
            request.header("authorization", format!("Bearer {token}"))
        } else {
            request.header("cookie", format!("iscy_session={token}"))
        };
    }
    if forged_headers {
        request = request
            .header("x-iscy-tenant-id", "73")
            .header("x-iscy-user-id", "7301")
            .header("x-iscy-roles", "ADMIN");
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[tokio::test]
async fn sqlite_production_api_csv_web_and_xlsx_confirm_share_atomic_boundary() {
    for (import_type, table) in TYPES {
        for route in [
            ImportRoute::Json,
            ImportRoute::Csv,
            ImportRoute::WebCsv,
            ImportRoute::WebPreviewCsv,
            ImportRoute::WebPreviewXlsx,
        ] {
            let (pool, store) = fixture().await;
            sqlx::raw_sql("INSERT INTO accounts_user(id,tenant_id,username,role) VALUES (4201,42,'f07-admin','ADMIN'),(4202,42,'f07-viewer','VIEWER'),(7301,73,'f07-foreign','ADMIN')")
                .execute(&pool).await.unwrap();
            let auth = AuthStore::from_sqlite_pool(pool.clone());
            let admin = auth.create_session(42, 4201).await.unwrap().unwrap().token;
            let viewer = auth.create_session(42, 4202).await.unwrap().unwrap().token;
            let app = app_router_with_state(
                AppState::default()
                    .with_security_config(CommunitySecurityConfig {
                        app_mode: AppMode::Production,
                        trust_identity_headers: false,
                        trusted_proxy_configured: false,
                        secure_cookies: true,
                        https_confirmed: false,
                        hsts_enabled: false,
                    })
                    .with_auth_store(Some(auth))
                    .with_import_store(Some(store)),
            );
            let before = snapshot(&pool, None).await;
            for credential in [None, Some(viewer.as_str())] {
                let (status, body) =
                    route_request(&app, route, import_type, credential, false, false).await;
                if route.is_api() {
                    assert_eq!(
                        status,
                        if credential.is_some() {
                            StatusCode::FORBIDDEN
                        } else {
                            StatusCode::UNAUTHORIZED
                        }
                    );
                } else {
                    assert_eq!(status, StatusCode::OK); // Existing HTML-error contract, not write success.
                    assert!(body.contains(if credential.is_some() {
                        "schreibende ISCY-Rolle"
                    } else {
                        "Tenant-ID"
                    }));
                }
                assert_eq!(
                    snapshot(&pool, None).await,
                    before,
                    "unauthorized {route:?}"
                );
            }
            let (status, _) =
                route_request(&app, route, import_type, Some(&admin), true, false).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(snapshot(&pool, None).await, before);
            if matches!(
                route,
                ImportRoute::WebPreviewCsv | ImportRoute::WebPreviewXlsx
            ) {
                let (status, body) =
                    route_request(&app, route, import_type, Some(&admin), false, true).await;
                assert_eq!(status, StatusCode::OK);
                assert!(
                    body.contains("Import-Vorschau") && body.contains("new-first"),
                    "{route:?}: {body}"
                );
                assert_eq!(
                    snapshot(&pool, None).await,
                    before,
                    "preview must not write"
                );
            }
            sqlx::query(&format!("CREATE TRIGGER f07_http_failure BEFORE INSERT ON {table} WHEN NEW.tenant_id=42 AND NEW.name='new-middle' BEGIN SELECT RAISE(ABORT,'F07_HTTP_CONTROLLED_FAULT'); END"))
                .execute(&pool).await.unwrap();
            let (status, body) =
                route_request(&app, route, import_type, Some(&admin), false, false).await;
            assert_eq!(
                status,
                if route.is_api() {
                    StatusCode::INTERNAL_SERVER_ERROR
                } else {
                    StatusCode::OK
                }
            );
            assert!(body.contains("F07_HTTP_CONTROLLED_FAULT"),"{route:?}: must reach the controlled second-row fault, not a parser/auth failure: {body}");
            assert_eq!(
                snapshot(&pool, None).await,
                before,
                "{import_type}/{route:?}: complete rollback"
            );
            sqlx::query("DROP TRIGGER f07_http_failure")
                .execute(&pool)
                .await
                .unwrap();
            let foreign_before = snapshot(&pool, Some(73)).await;
            let (status, body) =
                route_request(&app, route, import_type, Some(&admin), false, false).await;
            assert_eq!(status, StatusCode::OK);
            if route.is_api() {
                let response: Value = serde_json::from_str(&body).unwrap();
                assert_eq!(response["result"]["tenant_id"], 42);
                assert_eq!(response["result"]["created"], 3);
            } else {
                assert!(body.contains("Import uebernommen"), "{route:?}: {body}");
            }
            let names: Vec<String> = sqlx::query_scalar(&format!(
                "SELECT name FROM {table} WHERE tenant_id=42 ORDER BY id"
            ))
            .fetch_all(&pool)
            .await
            .unwrap();
            assert_eq!(names, ["new-first", "new-middle", "new-last"]);
            assert_eq!(snapshot(&pool, Some(73)).await, foreign_before);
            eprintln!(
                "F07_PRODUCTION_PATH_ROLLBACK_AND_SUCCESS_OK type={import_type} route={route:?}"
            );
            pool.close().await;
        }
    }
}

async fn postgres_fixture_rows(pool: &PgPool, tenant_id: i64, foreign_id: i64) -> ImportStore {
    for id in [tenant_id, foreign_id] {
        sqlx::query("INSERT INTO organizations_tenant (id,name,slug) VALUES ($1,$2,$3)")
            .bind(id)
            .bind(format!("Import fixture {id}"))
            .bind(format!("import-fixture-{id}"))
            .execute(pool)
            .await
            .unwrap();
    }
    let store = ImportStore::Postgres(pool.clone());
    for id in [tenant_id, foreign_id] {
        for (import_type, _) in TYPES.iter().rev() {
            store
                .apply_job(
                    id,
                    ImportJobRequest {
                        import_type: (*import_type).to_string(),
                        replace_existing: false,
                        rows: vec![row(&format!("old-{import_type}"), "old-unit")],
                    },
                )
                .await
                .unwrap();
        }
    }
    for (_, table) in TYPES {
        sqlx::query(&format!("UPDATE {table} SET created_at='2001-02-03T04:05:06Z',updated_at='2002-03-04T05:06:07Z' WHERE tenant_id IN ($1,$2)"))
            .bind(tenant_id).bind(foreign_id).execute(pool).await.unwrap();
    }
    store
}

async fn postgres_snapshot(pool: &PgPool, tenant_id: Option<i64>) -> BTreeMap<String, Vec<String>> {
    let mut result = BTreeMap::new();
    for (_, table) in TYPES {
        let scope = tenant_id
            .map(|id| format!(" WHERE tenant_id={id}"))
            .unwrap_or_default();
        let rows = sqlx::query_scalar(&format!(
            "SELECT row_to_json(t)::text FROM {table} t{scope} ORDER BY id"
        ))
        .fetch_all(pool)
        .await
        .unwrap();
        result.insert(table.to_string(), rows);
    }
    result
}

async fn postgres_failure_trigger(pool: &PgPool, table: &str, tenant_id: i64, name: &str) {
    assert!(TYPES.iter().any(|(_, allowed)| *allowed == table));
    assert!(["new-first", "new-middle", "new-last"].contains(&name));
    sqlx::query(&format!("CREATE FUNCTION f07_test_insert_failure() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.tenant_id={tenant_id} AND NEW.name='{name}' THEN RAISE EXCEPTION 'f07 controlled insert failure'; END IF; RETURN NEW; END$$"))
        .execute(pool).await.unwrap();
    sqlx::query(&format!("CREATE TRIGGER f07_test_insert_failure BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION f07_test_insert_failure()"))
        .execute(pool).await.unwrap();
}

async fn remove_postgres_failure_trigger(pool: &PgPool, table: &str) {
    assert!(TYPES.iter().any(|(_, allowed)| *allowed == table));
    sqlx::query(&format!("DROP TRIGGER f07_test_insert_failure ON {table}"))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION f07_test_insert_failure()")
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires a fresh disposable iscy_test_f07_* PostgreSQL database on loopback"]
async fn postgres_replace_is_atomic_and_append_retains_autocommit() {
    let database_url = std::env::var("ISCY_TEST_POSTGRES_URL")
        .expect("an explicit disposable PostgreSQL fixture URL is required");
    let options = database_url
        .parse::<PgConnectOptions>()
        .unwrap_or_else(|_| panic!("invalid disposable PostgreSQL URL"));
    assert!(
        ["127.0.0.1", "localhost"].contains(&options.get_host()),
        "loopback-only fixture required"
    );
    assert!(
        options
            .get_database()
            .unwrap_or_default()
            .starts_with("iscy_test_f07_"),
        "dedicated fixture database name required"
    );
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
        .unwrap();
    let table_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        table_count, 0,
        "refuse to reuse or reset an existing database"
    );
    db_admin::run_db_admin_action(&database_url, db_admin::DbAdminAction::Migrate)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE TABLE f07_commit_parent(id BIGINT PRIMARY KEY);
        CREATE TABLE f07_commit_child(parent_id BIGINT REFERENCES f07_commit_parent(id) DEFERRABLE INITIALLY DEFERRED)")
        .execute(&pool).await.unwrap();
    let mut case = 0_i64;
    for (import_type, table) in TYPES {
        for failed_index in [1, 0, 2] {
            case += 1;
            let tenant_id = 4200 + case;
            let store = postgres_fixture_rows(&pool, tenant_id, 7300 + case).await;
            let before = postgres_snapshot(&pool, None).await;
            let names = ["new-first", "new-middle", "new-last"];
            postgres_failure_trigger(&pool, table, tenant_id, names[failed_index]).await;
            let error = store
                .apply_job(tenant_id, job(import_type, true, &names))
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("f07 controlled insert failure"));
            assert_eq!(
                postgres_snapshot(&pool, None).await,
                before,
                "{import_type}: failed row {failed_index}"
            );
            remove_postgres_failure_trigger(&pool, table).await;
            eprintln!("F07_POSTGRES_ROLLBACK_OK type={import_type} failed_index={failed_index}");
        }
        case += 1;
        let tenant_id = 4200 + case;
        let foreign_id = 7300 + case;
        let store = postgres_fixture_rows(&pool, tenant_id, foreign_id).await;
        let foreign_before = postgres_snapshot(&pool, Some(foreign_id)).await;
        let result = store
            .apply_job(
                tenant_id,
                job(import_type, true, &["new-name", "new-name", ""]),
            )
            .await
            .unwrap();
        assert_eq!(
            (
                result.row_count,
                result.created,
                result.updated,
                result.skipped
            ),
            (3, 1, 1, 1)
        );
        let names: Vec<String> = sqlx::query_scalar(&format!(
            "SELECT name FROM {table} WHERE tenant_id=$1 ORDER BY id"
        ))
        .bind(tenant_id)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(names, ["new-name"]);
        assert_eq!(
            postgres_snapshot(&pool, Some(foreign_id)).await,
            foreign_before
        );
        eprintln!("F07_POSTGRES_SUCCESS_OK type={import_type}");

        case += 1;
        let tenant_id = 4200 + case;
        let foreign_id = 7300 + case;
        let store = postgres_fixture_rows(&pool, tenant_id, foreign_id).await;
        let before = postgres_snapshot(&pool, None).await;
        let foreign_before = postgres_snapshot(&pool, Some(foreign_id)).await;
        postgres_failure_trigger(&pool, table, tenant_id, "new-middle").await;
        let error = store
            .apply_job(
                tenant_id,
                job(import_type, false, &["new-first", "new-middle", "new-last"]),
            )
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("f07 controlled insert failure"));
        let after = postgres_snapshot(&pool, None).await;
        for (table, rows) in before {
            for row in rows {
                assert!(after[&table].contains(&row));
            }
        }
        let names: Vec<String> =
            sqlx::query_scalar(&format!("SELECT name FROM {table} WHERE tenant_id=$1"))
                .bind(tenant_id)
                .fetch_all(&pool)
                .await
                .unwrap();
        assert!(names.iter().any(|name| name == "new-first"));
        assert!(!names
            .iter()
            .any(|name| name == "new-middle" || name == "new-last"));
        assert_eq!(
            postgres_snapshot(&pool, Some(foreign_id)).await,
            foreign_before
        );
        remove_postgres_failure_trigger(&pool, table).await;
        eprintln!("F07_POSTGRES_APPEND_AUTOCOMMIT_UNCHANGED_OK type={import_type}");

        case += 1;
        let tenant_id = 4200 + case;
        let store = postgres_fixture_rows(&pool, tenant_id, 7300 + case).await;
        let before = postgres_snapshot(&pool, None).await;
        sqlx::query(&format!("CREATE FUNCTION f07_test_commit_failure() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.tenant_id={tenant_id} AND NEW.name='new-first' THEN INSERT INTO f07_commit_child(parent_id) VALUES(-1); END IF; RETURN NEW; END$$"))
            .execute(&pool).await.unwrap();
        sqlx::query(&format!("CREATE TRIGGER f07_test_commit_failure AFTER INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION f07_test_commit_failure()"))
            .execute(&pool).await.unwrap();
        let error = store
            .apply_job(
                tenant_id,
                job(import_type, true, &["new-first", "new-last"]),
            )
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("foreign key constraint"));
        assert_eq!(
            postgres_snapshot(&pool, None).await,
            before,
            "{import_type}: failed commit"
        );
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM f07_commit_child")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
        sqlx::query(&format!("DROP TRIGGER f07_test_commit_failure ON {table}"))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DROP FUNCTION f07_test_commit_failure()")
            .execute(&pool)
            .await
            .unwrap();
        eprintln!("F07_POSTGRES_COMMIT_ROLLBACK_OK type={import_type}");
    }
    pool.close().await;
}
