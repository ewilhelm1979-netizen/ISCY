use iscy_backend::db_admin::{self, DbAdminAction};
use sqlx::{sqlite::SqlitePoolOptions, Row, SqlitePool};

const VERSION: &str = "0049_rust_iscy27_nis2_reference_correction";
const EXPECTED: &[(i64, &str, &str)] = &[
    (1007, "NIS2-21-2E", "NIS2 Art. 21(2)(e)"),
    (1020, "NIS2-21-2E-G", "NIS2 Art. 21(2)(e), Art. 21(2)(g)"),
    (1026, "NIS2-21-2I-J", "NIS2 Art. 21(2)(i), Art. 21(2)(j)"),
    (1029, "NIS2-21-2I-ASSET", "NIS2 Art. 21(2)(i)"),
    (1035, "NIS2-21-2E-CHANGE", "NIS2 Art. 21(2)(e)"),
    (1042, "NIS2-21-2E-SDLC", "NIS2 Art. 21(2)(e)"),
    (1044, "NIS2-21-2D-SUPPLY", "NIS2 Art. 21(2)(d)"),
    (1048, "NIS2-21-2D-COMP", "NIS2 Art. 21(2)(d)"),
    (1072, "NIS2-21-2F-EFFECTIVENESS", "NIS2 Art. 21(2)(f)"),
    (1077, "NIS2-21-2I-HR", "NIS2 Art. 21(2)(i)"),
];

fn historical_mappings() -> &'static str {
    include_str!("../seeds/iscy27_controls_seed_sqlite.sql")
        .split(';')
        .find(|statement| statement.contains("INTO iscy_control_regulatorymapping"))
        .unwrap()
}

fn historical_postgres_mappings() -> &'static str {
    include_str!("../seeds/iscy27_controls_seed_postgres.sql")
        .split(';')
        .find(|statement| statement.contains("INTO iscy_control_regulatorymapping"))
        .unwrap()
}

async fn sqlite_fixture() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db_admin::run_sqlite_migrations(&pool).await.unwrap();
    pool
}

async fn revert_to_48(pool: &SqlitePool) {
    sqlx::query("DELETE FROM iscy_control_regulatorymapping")
        .execute(pool)
        .await
        .unwrap();
    sqlx::raw_sql(historical_mappings())
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM iscy_schema_migrations WHERE version=$1")
        .bind(VERSION)
        .execute(pool)
        .await
        .unwrap();
}

async fn sqlite_mapping_snapshot(pool: &SqlitePool) -> Vec<(i64, String)> {
    sqlx::query("SELECT id,json_array(control_id,framework,source_code,source_title,legal_reference,coverage_level,rationale,created_at,updated_at) AS value FROM iscy_control_regulatorymapping ORDER BY id")
        .fetch_all(pool).await.unwrap().iter()
        .map(|row| (row.get("id"), row.get("value"))).collect()
}

async fn status_snapshot(pool: &SqlitePool) -> String {
    sqlx::query_scalar("SELECT json_group_array(json_array(tenant_id,control_id,status,maturity_score,evidence_status,owner_id,notes,reviewed_at,created_at,updated_at)) FROM (SELECT * FROM iscy_control_tenantstatus ORDER BY tenant_id,control_id)")
        .fetch_one(pool).await.unwrap()
}

#[tokio::test]
async fn fresh_and_upgraded_sqlite_correct_all_ten_and_preserve_other_mappings_and_statuses() {
    let pool = sqlite_fixture().await;
    for &(id, code, reference) in EXPECTED {
        let actual: (String, String) = sqlx::query_as(
            "SELECT source_code,legal_reference FROM iscy_control_regulatorymapping WHERE id=$1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(actual, (code.into(), reference.into()));
    }
    let fresh = sqlite_mapping_snapshot(&pool).await;
    revert_to_48(&pool).await;
    let old = sqlite_mapping_snapshot(&pool).await;
    let statuses = status_snapshot(&pool).await;
    assert_eq!(
        db_admin::run_sqlite_migrations(&pool).await.unwrap(),
        vec![VERSION]
    );
    let upgraded = sqlite_mapping_snapshot(&pool).await;
    assert_eq!(upgraded.len(), 82);
    for (id, value) in &upgraded {
        if !EXPECTED.iter().any(|row| row.0 == *id) {
            assert_eq!(old.iter().find(|row| row.0 == *id).unwrap().1, *value);
        }
    }
    for &(id, code, reference) in EXPECTED {
        let actual: (String, String) = sqlx::query_as(
            "SELECT source_code,legal_reference FROM iscy_control_regulatorymapping WHERE id=$1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(actual, (code.into(), reference.into()));
    }
    assert_eq!(status_snapshot(&pool).await, statuses);
    assert_eq!(fresh.len(), upgraded.len());
    assert!(db_admin::run_sqlite_migrations(&pool)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(sqlite_mapping_snapshot(&pool).await, upgraded);
    // Simulate a crash after the atomic correction but before its receipt.
    sqlx::query("DELETE FROM iscy_schema_migrations WHERE version=$1")
        .bind(VERSION)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        db_admin::run_sqlite_migrations(&pool).await.unwrap(),
        vec![VERSION]
    );
    assert_eq!(sqlite_mapping_snapshot(&pool).await, upgraded);
}

#[tokio::test]
async fn customized_mapping_and_control_identity_are_preserved() {
    let pool = sqlite_fixture().await;
    revert_to_48(&pool).await;
    sqlx::raw_sql("UPDATE iscy_control_regulatorymapping SET rationale='Own assessment' WHERE id=1007;
        UPDATE iscy_control_regulatorymapping SET framework='CUSTOM' WHERE id=1026;
        UPDATE iscy_control_control SET code='OWN-12' WHERE id=12;
        UPDATE iscy_control_tenantstatus SET notes='Tenant decision',status='NOT_APPLICABLE' WHERE control_id=3;").execute(&pool).await.unwrap();
    let before = sqlite_mapping_snapshot(&pool).await;
    let statuses = status_snapshot(&pool).await;
    db_admin::run_sqlite_migrations(&pool).await.unwrap();
    let after = sqlite_mapping_snapshot(&pool).await;
    for id in [1007, 1026, 1035] {
        assert_eq!(
            before.iter().find(|row| row.0 == id),
            after.iter().find(|row| row.0 == id)
        );
    }
    assert_eq!(status_snapshot(&pool).await, statuses);
    let corrected: String =
        sqlx::query_scalar("SELECT source_code FROM iscy_control_regulatorymapping WHERE id=1077")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(corrected, "NIS2-21-2I-HR");
}

#[tokio::test]
async fn reference_collision_rolls_back_all_edits_and_does_not_register_the_migration() {
    let pool = sqlite_fixture().await;
    revert_to_48(&pool).await;
    sqlx::raw_sql("INSERT INTO iscy_control_regulatorymapping(id,control_id,framework,source_code,source_title,legal_reference,coverage_level,rationale)
        VALUES(9001,26,'NIS2','NIS2-21-2I-HR','Own reference','NIS2 Art. 21(2)(i)','PRIMARY','Keep this custom mapping');")
        .execute(&pool).await.unwrap();
    let before = sqlite_mapping_snapshot(&pool).await;
    assert!(db_admin::run_sqlite_migrations(&pool).await.is_err());
    assert_eq!(sqlite_mapping_snapshot(&pool).await, before);
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM iscy_schema_migrations WHERE version=$1")
            .bind(VERSION)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
    sqlx::query("DELETE FROM iscy_control_regulatorymapping WHERE id=9001")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        db_admin::run_sqlite_migrations(&pool).await.unwrap(),
        vec![VERSION]
    );
}

#[tokio::test]
#[ignore = "requires fresh disposable ISCY_TEST_REFERENCE_POSTGRES_URL"]
async fn postgres_fresh_upgrade_customization_collision_and_rerun() {
    let url = std::env::var("ISCY_TEST_REFERENCE_POSTGRES_URL").unwrap();
    let parsed = reqwest::Url::parse(&url).unwrap();
    assert!(matches!(parsed.host_str(), Some("127.0.0.1" | "localhost")));
    assert!(parsed.path().starts_with("/iscy_test_reference_"));
    assert!(parsed
        .query_pairs()
        .all(|(k, v)| k == "sslmode" && v == "disable"));
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
    assert_eq!(tables, 0, "fixture must be fresh and empty");
    db_admin::run_db_admin_action(&url, DbAdminAction::Migrate)
        .await
        .unwrap();
    for &(id, code, reference) in EXPECTED {
        let row: (String, String) = sqlx::query_as(
            "SELECT source_code,legal_reference FROM iscy_control_regulatorymapping WHERE id=$1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row, (code.into(), reference.into()));
    }
    sqlx::query("DELETE FROM iscy_control_regulatorymapping")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::raw_sql(historical_postgres_mappings())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM iscy_schema_migrations WHERE version=$1")
        .bind(VERSION)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::raw_sql("UPDATE iscy_control_regulatorymapping SET rationale='Own assessment' WHERE id=1007;
        INSERT INTO iscy_control_regulatorymapping(id,control_id,framework,source_code,source_title,legal_reference,coverage_level,rationale)
        VALUES(9001,26,'NIS2','NIS2-21-2I-HR','Own reference','NIS2 Art. 21(2)(i)','PRIMARY','Custom');").execute(&pool).await.unwrap();
    let before: String = sqlx::query_scalar(
        "SELECT json_agg(m ORDER BY id)::text FROM iscy_control_regulatorymapping m",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let statuses: String =
        sqlx::query_scalar("SELECT json_agg(s ORDER BY id)::text FROM iscy_control_tenantstatus s")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(db_admin::run_db_admin_action(&url, DbAdminAction::Migrate)
        .await
        .is_err());
    let after: String = sqlx::query_scalar(
        "SELECT json_agg(m ORDER BY id)::text FROM iscy_control_regulatorymapping m",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(before, after);
    sqlx::query("DELETE FROM iscy_control_regulatorymapping WHERE id=9001")
        .execute(&pool)
        .await
        .unwrap();
    let outcome = db_admin::run_db_admin_action(&url, DbAdminAction::Migrate)
        .await
        .unwrap();
    assert_eq!(outcome.applied_migrations, vec![VERSION]);
    for &(id, code, reference) in EXPECTED {
        if id == 1007 {
            continue;
        }
        let row: (String, String) = sqlx::query_as(
            "SELECT source_code,legal_reference FROM iscy_control_regulatorymapping WHERE id=$1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row, (code.into(), reference.into()));
    }
    let custom: String =
        sqlx::query_scalar("SELECT rationale FROM iscy_control_regulatorymapping WHERE id=1007")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(custom, "Own assessment");
    let after_statuses: String =
        sqlx::query_scalar("SELECT json_agg(s ORDER BY id)::text FROM iscy_control_tenantstatus s")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(statuses, after_statuses);
    assert!(db_admin::run_db_admin_action(&url, DbAdminAction::Migrate)
        .await
        .unwrap()
        .applied_migrations
        .is_empty());
    pool.close().await;
}
