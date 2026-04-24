use std::str::FromStr;

use anyhow::{bail, Context};
use chrono::Utc;
use sqlx::{
    postgres::{PgPool, PgPoolOptions},
    sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions},
    Row,
};

use crate::cve_store::normalize_database_url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbAdminAction {
    Migrate,
    SeedDemo,
    InitDemo,
}

#[derive(Debug, Clone)]
pub struct DbAdminOutcome {
    pub database_kind: &'static str,
    pub applied_migrations: Vec<&'static str>,
    pub seeded_demo: bool,
}

#[derive(Clone, Copy)]
struct Migration {
    version: &'static str,
    sqlite_sql: &'static str,
    postgres_sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        version: "0001_rust_operational_core",
        sqlite_sql: SQLITE_OPERATIONAL_CORE_SCHEMA,
        postgres_sql: POSTGRES_OPERATIONAL_CORE_SCHEMA,
    },
    Migration {
        version: "0002_rust_product_security_core",
        sqlite_sql: SQLITE_PRODUCT_SECURITY_SCHEMA,
        postgres_sql: POSTGRES_PRODUCT_SECURITY_SCHEMA,
    },
    Migration {
        version: "0003_rust_catalog_requirement_core",
        sqlite_sql: SQLITE_CATALOG_REQUIREMENT_SCHEMA,
        postgres_sql: POSTGRES_CATALOG_REQUIREMENT_SCHEMA,
    },
    Migration {
        version: "0004_rust_auth_session_core",
        sqlite_sql: SQLITE_AUTH_SESSION_SCHEMA,
        postgres_sql: POSTGRES_AUTH_SESSION_SCHEMA,
    },
    Migration {
        version: "0005_rust_auth_rbac_core",
        sqlite_sql: SQLITE_AUTH_RBAC_SCHEMA,
        postgres_sql: POSTGRES_AUTH_RBAC_SCHEMA,
    },
    Migration {
        version: "0006_rust_auth_group_permission_core",
        sqlite_sql: SQLITE_AUTH_GROUP_PERMISSION_SCHEMA,
        postgres_sql: POSTGRES_AUTH_GROUP_PERMISSION_SCHEMA,
    },
];

const SQLITE_CATALOG_REQUIREMENTS_SEED: &str =
    include_str!("../seeds/catalog_requirements_seed_sqlite.sql");
const POSTGRES_CATALOG_REQUIREMENTS_SEED: &str =
    include_str!("../seeds/catalog_requirements_seed_postgres.sql");

const SQLITE_AUTH_SESSION_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS iscy_auth_session (
    token varchar(128) PRIMARY KEY,
    tenant_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    user_email varchar(254) NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT NULL
);
CREATE INDEX IF NOT EXISTS idx_iscy_auth_session_user ON iscy_auth_session(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_iscy_auth_session_expires ON iscy_auth_session(expires_at);
"#;

const POSTGRES_AUTH_SESSION_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS iscy_auth_session (
    token varchar(128) PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    user_email varchar(254) NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT NULL
);
CREATE INDEX IF NOT EXISTS idx_iscy_auth_session_user ON iscy_auth_session(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_iscy_auth_session_expires ON iscy_auth_session(expires_at);
"#;

const SQLITE_AUTH_RBAC_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS accounts_role (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code varchar(32) NOT NULL UNIQUE,
    label varchar(100) NOT NULL,
    description TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS accounts_userrole (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    scope_tenant_id INTEGER NULL,
    granted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    granted_by_id INTEGER NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_userrole_unique_scope
    ON accounts_userrole(user_id, role_id, COALESCE(scope_tenant_id, 0));
CREATE INDEX IF NOT EXISTS idx_accounts_userrole_user ON accounts_userrole(user_id);
CREATE INDEX IF NOT EXISTS idx_accounts_userrole_scope ON accounts_userrole(scope_tenant_id);
"#;

const POSTGRES_AUTH_RBAC_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS accounts_role (
    id BIGSERIAL PRIMARY KEY,
    code varchar(32) NOT NULL UNIQUE,
    label varchar(100) NOT NULL,
    description TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS accounts_userrole (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    scope_tenant_id BIGINT NULL,
    granted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    granted_by_id BIGINT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_userrole_unique_scope
    ON accounts_userrole(user_id, role_id, COALESCE(scope_tenant_id, 0));
CREATE INDEX IF NOT EXISTS idx_accounts_userrole_user ON accounts_userrole(user_id);
CREATE INDEX IF NOT EXISTS idx_accounts_userrole_scope ON accounts_userrole(scope_tenant_id);
"#;

const SQLITE_AUTH_GROUP_PERMISSION_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS django_content_type (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_label varchar(100) NOT NULL,
    model varchar(100) NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS django_content_type_app_label_model_uniq
    ON django_content_type(app_label, model);
CREATE TABLE IF NOT EXISTS auth_permission (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name varchar(255) NOT NULL,
    content_type_id INTEGER NOT NULL,
    codename varchar(100) NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS auth_permission_content_type_codename_uniq
    ON auth_permission(content_type_id, codename);
CREATE TABLE IF NOT EXISTS auth_group (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name varchar(150) NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS auth_group_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS auth_group_permissions_group_permission_uniq
    ON auth_group_permissions(group_id, permission_id);
CREATE TABLE IF NOT EXISTS accounts_user_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    group_id INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS accounts_user_groups_user_group_uniq
    ON accounts_user_groups(user_id, group_id);
CREATE TABLE IF NOT EXISTS accounts_user_user_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS accounts_user_permissions_user_permission_uniq
    ON accounts_user_user_permissions(user_id, permission_id);
"#;

const POSTGRES_AUTH_GROUP_PERMISSION_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS django_content_type (
    id BIGSERIAL PRIMARY KEY,
    app_label varchar(100) NOT NULL,
    model varchar(100) NOT NULL,
    CONSTRAINT django_content_type_app_label_model_uniq UNIQUE (app_label, model)
);
CREATE TABLE IF NOT EXISTS auth_permission (
    id BIGSERIAL PRIMARY KEY,
    name varchar(255) NOT NULL,
    content_type_id BIGINT NOT NULL,
    codename varchar(100) NOT NULL,
    CONSTRAINT auth_permission_content_type_codename_uniq UNIQUE (content_type_id, codename)
);
CREATE TABLE IF NOT EXISTS auth_group (
    id BIGSERIAL PRIMARY KEY,
    name varchar(150) NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS auth_group_permissions (
    id BIGSERIAL PRIMARY KEY,
    group_id BIGINT NOT NULL,
    permission_id BIGINT NOT NULL,
    CONSTRAINT auth_group_permissions_group_permission_uniq UNIQUE (group_id, permission_id)
);
CREATE TABLE IF NOT EXISTS accounts_user_groups (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    group_id BIGINT NOT NULL,
    CONSTRAINT accounts_user_groups_user_group_uniq UNIQUE (user_id, group_id)
);
CREATE TABLE IF NOT EXISTS accounts_user_user_permissions (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    permission_id BIGINT NOT NULL,
    CONSTRAINT accounts_user_permissions_user_permission_uniq UNIQUE (user_id, permission_id)
);
"#;

pub async fn run_db_admin_action(
    database_url: &str,
    action: DbAdminAction,
) -> anyhow::Result<DbAdminOutcome> {
    let normalized_url = normalize_database_url(database_url);
    if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://") {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&normalized_url)
            .await
            .context("PostgreSQL-Verbindung fuer Rust-DB-Admin fehlgeschlagen")?;
        let mut applied_migrations = Vec::new();
        if matches!(action, DbAdminAction::Migrate | DbAdminAction::InitDemo) {
            applied_migrations = run_postgres_migrations(&pool).await?;
        }
        if matches!(action, DbAdminAction::SeedDemo | DbAdminAction::InitDemo) {
            seed_postgres_demo(&pool).await?;
        }
        return Ok(DbAdminOutcome {
            database_kind: "postgres",
            applied_migrations,
            seeded_demo: matches!(action, DbAdminAction::SeedDemo | DbAdminAction::InitDemo),
        });
    }
    if normalized_url.starts_with("sqlite:") {
        let options = SqliteConnectOptions::from_str(&normalized_url)
            .context("SQLite-DATABASE_URL konnte nicht gelesen werden")?
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .context("SQLite-Verbindung fuer Rust-DB-Admin fehlgeschlagen")?;
        let mut applied_migrations = Vec::new();
        if matches!(action, DbAdminAction::Migrate | DbAdminAction::InitDemo) {
            applied_migrations = run_sqlite_migrations(&pool).await?;
        }
        if matches!(action, DbAdminAction::SeedDemo | DbAdminAction::InitDemo) {
            seed_sqlite_demo(&pool).await?;
        }
        return Ok(DbAdminOutcome {
            database_kind: "sqlite",
            applied_migrations,
            seeded_demo: matches!(action, DbAdminAction::SeedDemo | DbAdminAction::InitDemo),
        });
    }
    bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-DB-Admin");
}

pub async fn run_sqlite_migrations(pool: &SqlitePool) -> anyhow::Result<Vec<&'static str>> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS iscy_schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .context("SQLite-Migrationstabelle konnte nicht erstellt werden")?;

    let mut applied = Vec::new();
    for migration in MIGRATIONS {
        if sqlite_migration_applied(pool, migration.version).await? {
            continue;
        }
        execute_sqlite_script(pool, migration.sqlite_sql)
            .await
            .with_context(|| format!("SQLite-Migration {} fehlgeschlagen", migration.version))?;
        sqlx::query("INSERT INTO iscy_schema_migrations (version, applied_at) VALUES (?, ?)")
            .bind(migration.version)
            .bind(Utc::now().to_rfc3339())
            .execute(pool)
            .await
            .with_context(|| {
                format!(
                    "SQLite-Migration {} konnte nicht registriert werden",
                    migration.version
                )
            })?;
        applied.push(migration.version);
    }
    Ok(applied)
}

pub async fn seed_sqlite_demo(pool: &SqlitePool) -> anyhow::Result<()> {
    execute_sqlite_script(pool, SQLITE_DEMO_SEED)
        .await
        .context("SQLite-Demo-Seed fehlgeschlagen")?;
    execute_sqlite_script(pool, SQLITE_CATALOG_REQUIREMENTS_SEED)
        .await
        .context("SQLite-Katalog-/Requirement-Seed fehlgeschlagen")
}

async fn run_postgres_migrations(pool: &PgPool) -> anyhow::Result<Vec<&'static str>> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS iscy_schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .context("PostgreSQL-Migrationstabelle konnte nicht erstellt werden")?;

    let mut applied = Vec::new();
    for migration in MIGRATIONS {
        if postgres_migration_applied(pool, migration.version).await? {
            continue;
        }
        execute_postgres_script(pool, migration.postgres_sql)
            .await
            .with_context(|| {
                format!("PostgreSQL-Migration {} fehlgeschlagen", migration.version)
            })?;
        sqlx::query("INSERT INTO iscy_schema_migrations (version, applied_at) VALUES ($1, $2)")
            .bind(migration.version)
            .bind(Utc::now().to_rfc3339())
            .execute(pool)
            .await
            .with_context(|| {
                format!(
                    "PostgreSQL-Migration {} konnte nicht registriert werden",
                    migration.version
                )
            })?;
        applied.push(migration.version);
    }
    Ok(applied)
}

async fn seed_postgres_demo(pool: &PgPool) -> anyhow::Result<()> {
    execute_postgres_script(pool, POSTGRES_DEMO_SEED)
        .await
        .context("PostgreSQL-Demo-Seed fehlgeschlagen")?;
    execute_postgres_script(pool, POSTGRES_CATALOG_REQUIREMENTS_SEED)
        .await
        .context("PostgreSQL-Katalog-/Requirement-Seed fehlgeschlagen")
}

async fn sqlite_migration_applied(pool: &SqlitePool, version: &str) -> anyhow::Result<bool> {
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM iscy_schema_migrations WHERE version = ?")
            .bind(version)
            .fetch_one(pool)
            .await
            .context("SQLite-Migrationsstatus konnte nicht gelesen werden")?;
    Ok(count > 0)
}

async fn postgres_migration_applied(pool: &PgPool, version: &str) -> anyhow::Result<bool> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM iscy_schema_migrations WHERE version = $1",
    )
    .bind(version)
    .fetch_one(pool)
    .await
    .context("PostgreSQL-Migrationsstatus konnte nicht gelesen werden")?;
    Ok(count > 0)
}

async fn execute_sqlite_script(pool: &SqlitePool, script: &str) -> anyhow::Result<()> {
    for statement in split_sql_script(script) {
        sqlx::query(&statement).execute(pool).await?;
    }
    Ok(())
}

async fn execute_postgres_script(pool: &PgPool, script: &str) -> anyhow::Result<()> {
    for statement in split_sql_script(script) {
        sqlx::query(&statement).execute(pool).await?;
    }
    Ok(())
}

fn split_sql_script(script: &str) -> Vec<String> {
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut chars = script.chars().peekable();
    let mut in_string = false;

    while let Some(ch) = chars.next() {
        match ch {
            '\'' => {
                current.push(ch);
                if in_string && chars.peek() == Some(&'\'') {
                    current.push(chars.next().expect("peeked escaped quote"));
                } else {
                    in_string = !in_string;
                }
            }
            ';' if !in_string => {
                if let Some(statement) = normalize_sql_statement(&current) {
                    statements.push(statement);
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    if let Some(statement) = normalize_sql_statement(&current) {
        statements.push(statement);
    }

    statements
}

fn normalize_sql_statement(statement: &str) -> Option<String> {
    let lines = statement
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("--"))
        .collect::<Vec<_>>();
    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
}

pub async fn sqlite_table_exists(pool: &SqlitePool, table_name: &str) -> anyhow::Result<bool> {
    let row = sqlx::query(
        "SELECT COUNT(*) AS table_count FROM sqlite_master WHERE type = 'table' AND name = ?",
    )
    .bind(table_name)
    .fetch_one(pool)
    .await
    .context("SQLite-Tabellenstatus konnte nicht gelesen werden")?;
    let count: i64 = row.try_get("table_count")?;
    Ok(count > 0)
}

const SQLITE_OPERATIONAL_CORE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS organizations_tenant (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name varchar(255) NOT NULL,
    slug varchar(50) NOT NULL UNIQUE,
    country varchar(100) NOT NULL DEFAULT '',
    operation_countries TEXT NOT NULL DEFAULT '[]',
    description TEXT NOT NULL DEFAULT '',
    sector varchar(64) NOT NULL DEFAULT 'OTHER',
    employee_count INTEGER NOT NULL DEFAULT 0,
    annual_revenue_million TEXT NOT NULL DEFAULT '0',
    balance_sheet_million TEXT NOT NULL DEFAULT '0',
    critical_services TEXT NOT NULL DEFAULT '',
    supply_chain_role varchar(255) NOT NULL DEFAULT '',
    nis2_relevant bool NOT NULL DEFAULT 0,
    kritis_relevant bool NOT NULL DEFAULT 0,
    develops_digital_products bool NOT NULL DEFAULT 0,
    uses_ai_systems bool NOT NULL DEFAULT 0,
    ot_iacs_scope bool NOT NULL DEFAULT 0,
    automotive_scope bool NOT NULL DEFAULT 0,
    psirt_defined bool NOT NULL DEFAULT 0,
    sbom_required bool NOT NULL DEFAULT 0,
    product_security_scope TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS accounts_user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    password varchar(128) NOT NULL DEFAULT '',
    last_login TEXT NULL,
    is_superuser bool NOT NULL DEFAULT 0,
    username varchar(150) NOT NULL UNIQUE,
    first_name varchar(150) NOT NULL DEFAULT '',
    last_name varchar(150) NOT NULL DEFAULT '',
    email varchar(254) NOT NULL DEFAULT '',
    is_staff bool NOT NULL DEFAULT 0,
    is_active bool NOT NULL DEFAULT 1,
    date_joined TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    role varchar(32) NOT NULL DEFAULT 'CONTRIBUTOR',
    job_title varchar(255) NOT NULL DEFAULT '',
    tenant_id INTEGER NULL
);
CREATE TABLE IF NOT EXISTS organizations_businessunit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    name varchar(255) NOT NULL,
    owner_id INTEGER NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS organizations_supplier (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    name varchar(255) NOT NULL,
    service_description TEXT NOT NULL DEFAULT '',
    criticality varchar(32) NOT NULL DEFAULT 'MEDIUM',
    owner_id INTEGER NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS processes_process (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    business_unit_id INTEGER NULL,
    owner_id INTEGER NULL,
    name varchar(255) NOT NULL,
    scope varchar(255) NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    status varchar(32) NOT NULL DEFAULT 'INFORMAL',
    documented bool NOT NULL DEFAULT 0,
    approved bool NOT NULL DEFAULT 0,
    communicated bool NOT NULL DEFAULT 0,
    implemented bool NOT NULL DEFAULT 0,
    effective bool NOT NULL DEFAULT 0,
    evidenced bool NOT NULL DEFAULT 0,
    reviewed_at date NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS assets_app_informationasset (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    business_unit_id INTEGER NULL,
    owner_id INTEGER NULL,
    name varchar(255) NOT NULL,
    asset_type varchar(24) NOT NULL DEFAULT 'OTHER',
    criticality varchar(16) NOT NULL DEFAULT 'MEDIUM',
    description TEXT NOT NULL DEFAULT '',
    confidentiality varchar(32) NOT NULL DEFAULT 'MEDIUM',
    integrity varchar(32) NOT NULL DEFAULT 'MEDIUM',
    availability varchar(32) NOT NULL DEFAULT 'MEDIUM',
    lifecycle_status varchar(64) NOT NULL DEFAULT 'active',
    is_in_scope bool NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS risks_riskcategory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    name varchar(128) NOT NULL
);
CREATE TABLE IF NOT EXISTS risks_risk (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    category_id INTEGER NULL,
    process_id INTEGER NULL,
    asset_id INTEGER NULL,
    owner_id INTEGER NULL,
    title varchar(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    threat TEXT NOT NULL DEFAULT '',
    vulnerability TEXT NOT NULL DEFAULT '',
    impact INTEGER NOT NULL DEFAULT 1,
    likelihood INTEGER NOT NULL DEFAULT 1,
    residual_impact INTEGER NULL,
    residual_likelihood INTEGER NULL,
    status varchar(16) NOT NULL DEFAULT 'IDENTIFIED',
    treatment_strategy varchar(16) NOT NULL DEFAULT 'MITIGATE',
    treatment_plan TEXT NOT NULL DEFAULT '',
    treatment_due_date date NULL,
    accepted_by_id INTEGER NULL,
    accepted_at TEXT NULL,
    review_date date NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS wizard_assessmentsession (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    started_by_id INTEGER NULL,
    assessment_type varchar(32) NOT NULL DEFAULT 'NIS2',
    status varchar(32) NOT NULL DEFAULT 'DRAFT',
    current_step varchar(32) NOT NULL DEFAULT 'applicability',
    applicability_result varchar(32) NOT NULL DEFAULT '',
    applicability_reasoning TEXT NOT NULL DEFAULT '',
    executive_summary TEXT NOT NULL DEFAULT '',
    progress_percent INTEGER NOT NULL DEFAULT 0,
    completed_at TEXT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS wizard_generatedmeasure (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NULL,
    domain_id INTEGER NULL,
    question_id INTEGER NULL,
    title varchar(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    priority varchar(16) NOT NULL DEFAULT 'MEDIUM',
    effort varchar(16) NOT NULL DEFAULT 'MEDIUM',
    measure_type varchar(32) NOT NULL DEFAULT 'CONTROL',
    target_phase varchar(255) NOT NULL DEFAULT '',
    owner_role varchar(255) NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    status varchar(16) NOT NULL DEFAULT 'OPEN',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS requirements_app_mappingversion (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    framework varchar(32) NOT NULL,
    slug varchar(50) NOT NULL DEFAULT '',
    title varchar(255) NOT NULL DEFAULT '',
    version varchar(32) NOT NULL,
    program_name varchar(64) NOT NULL DEFAULT '',
    status varchar(16) NOT NULL DEFAULT 'ACTIVE',
    effective_on date NULL,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS requirements_app_regulatorysource (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    framework varchar(32) NOT NULL,
    mapping_version_id INTEGER NULL,
    code varchar(64) NOT NULL DEFAULT '',
    title varchar(255) NOT NULL DEFAULT '',
    authority varchar(128) NOT NULL DEFAULT '',
    citation varchar(255) NOT NULL DEFAULT '',
    url varchar(200) NOT NULL DEFAULT '',
    source_type varchar(32) NOT NULL DEFAULT '',
    published_on date NULL,
    effective_on date NULL,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS requirements_app_requirement (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    framework varchar(32) NOT NULL,
    code varchar(64) NOT NULL,
    title varchar(255) NOT NULL DEFAULT '',
    domain varchar(255) NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    guidance TEXT NOT NULL DEFAULT '',
    is_active bool NOT NULL DEFAULT 1,
    evidence_required bool NOT NULL DEFAULT 1,
    evidence_guidance TEXT NOT NULL DEFAULT '',
    evidence_examples TEXT NOT NULL DEFAULT '',
    sector_package varchar(64) NOT NULL DEFAULT '',
    legal_reference varchar(128) NOT NULL DEFAULT '',
    mapped_controls TEXT NOT NULL DEFAULT '',
    mapping_rationale TEXT NOT NULL DEFAULT '',
    coverage_level varchar(16) NOT NULL DEFAULT 'FULL',
    mapping_version_id INTEGER NULL,
    primary_source_id INTEGER NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS evidence_evidenceitem (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    session_id INTEGER NULL,
    domain_id INTEGER NULL,
    measure_id INTEGER NULL,
    requirement_id INTEGER NULL,
    title varchar(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    linked_requirement varchar(128) NOT NULL DEFAULT '',
    file varchar(100) NULL,
    status varchar(16) NOT NULL DEFAULT 'DRAFT',
    owner_id INTEGER NULL,
    review_notes TEXT NOT NULL DEFAULT '',
    reviewed_by_id INTEGER NULL,
    reviewed_at TEXT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS evidence_requirementevidenceneed (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    session_id INTEGER NULL,
    requirement_id INTEGER NOT NULL,
    title varchar(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    is_mandatory bool NOT NULL DEFAULT 1,
    status varchar(16) NOT NULL DEFAULT 'OPEN',
    rationale TEXT NOT NULL DEFAULT '',
    covered_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS reports_reportsnapshot (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    session_id INTEGER NOT NULL,
    title varchar(255) NOT NULL,
    executive_summary TEXT NOT NULL DEFAULT '',
    applicability_result varchar(32) NOT NULL DEFAULT '',
    iso_readiness_percent INTEGER NOT NULL DEFAULT 0,
    nis2_readiness_percent INTEGER NOT NULL DEFAULT 0,
    kritis_readiness_percent INTEGER NOT NULL DEFAULT 0,
    cra_readiness_percent INTEGER NOT NULL DEFAULT 0,
    ai_act_readiness_percent INTEGER NOT NULL DEFAULT 0,
    iec62443_readiness_percent INTEGER NOT NULL DEFAULT 0,
    iso_sae_21434_readiness_percent INTEGER NOT NULL DEFAULT 0,
    regulatory_matrix_json TEXT NOT NULL DEFAULT '{}',
    compliance_versions_json TEXT NOT NULL DEFAULT '{}',
    product_security_json TEXT NOT NULL DEFAULT '{}',
    top_gaps_json TEXT NOT NULL DEFAULT '[]',
    top_measures_json TEXT NOT NULL DEFAULT '[]',
    roadmap_summary TEXT NOT NULL DEFAULT '[]',
    domain_scores_json TEXT NOT NULL DEFAULT '[]',
    next_steps_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS roadmap_roadmapplan (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    session_id INTEGER NOT NULL,
    title varchar(255) NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    overall_priority varchar(16) NOT NULL DEFAULT 'MEDIUM',
    planned_start date NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS roadmap_roadmapphase (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_id INTEGER NOT NULL,
    name varchar(255) NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 0,
    objective TEXT NOT NULL DEFAULT '',
    duration_weeks INTEGER NOT NULL DEFAULT 0,
    planned_start date NULL,
    planned_end date NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS roadmap_roadmaptask (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phase_id INTEGER NOT NULL,
    measure_id INTEGER NULL,
    title varchar(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    priority varchar(16) NOT NULL DEFAULT 'MEDIUM',
    owner_role varchar(255) NOT NULL DEFAULT '',
    due_in_days INTEGER NOT NULL DEFAULT 30,
    dependency_text TEXT NOT NULL DEFAULT '',
    status varchar(16) NOT NULL DEFAULT 'OPEN',
    planned_start date NULL,
    due_date date NULL,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS roadmap_roadmaptaskdependency (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    predecessor_id INTEGER NOT NULL,
    successor_id INTEGER NOT NULL,
    dependency_type varchar(16) NOT NULL DEFAULT 'BLOCKS',
    rationale TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS vulnerability_intelligence_cverecord (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    cve_id varchar(32) NOT NULL UNIQUE,
    source varchar(32) NOT NULL DEFAULT 'NVD',
    description TEXT NOT NULL DEFAULT '',
    cvss_score decimal NULL,
    cvss_vector varchar(255) NOT NULL DEFAULT '',
    severity varchar(16) NOT NULL DEFAULT 'UNKNOWN',
    weakness_ids_json TEXT NOT NULL DEFAULT '[]',
    references_json TEXT NOT NULL DEFAULT '[]',
    configurations_json TEXT NOT NULL DEFAULT '{}',
    epss_score decimal NULL,
    in_kev_catalog bool NOT NULL DEFAULT 0,
    kev_date_added date NULL,
    kev_vendor_project varchar(255) NOT NULL DEFAULT '',
    kev_product varchar(255) NOT NULL DEFAULT '',
    kev_required_action TEXT NOT NULL DEFAULT '',
    kev_known_ransomware bool NOT NULL DEFAULT 0,
    raw_json TEXT NOT NULL DEFAULT '{}',
    published_at TEXT NULL,
    modified_at TEXT NULL
);
CREATE TABLE IF NOT EXISTS vulnerability_intelligence_cveassessment (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    cve_id INTEGER NOT NULL,
    product_id INTEGER NULL,
    release_id INTEGER NULL,
    component_id INTEGER NULL,
    linked_vulnerability_id INTEGER NULL,
    related_risk_id INTEGER NULL,
    exposure varchar(16) NOT NULL DEFAULT 'UNKNOWN',
    asset_criticality varchar(16) NOT NULL DEFAULT 'MEDIUM',
    epss_score decimal NULL,
    in_kev_catalog bool NOT NULL DEFAULT 0,
    exploit_maturity varchar(16) NOT NULL DEFAULT 'UNKNOWN',
    affects_critical_service bool NOT NULL DEFAULT 0,
    nis2_relevant bool NOT NULL DEFAULT 0,
    nis2_impact_summary TEXT NOT NULL DEFAULT '',
    repository_name varchar(255) NOT NULL DEFAULT '',
    repository_url varchar(200) NOT NULL DEFAULT '',
    git_ref varchar(128) NOT NULL DEFAULT '',
    source_package varchar(255) NOT NULL DEFAULT '',
    source_package_version varchar(128) NOT NULL DEFAULT '',
    regulatory_tags_json TEXT NOT NULL DEFAULT '[]',
    deterministic_factors_json TEXT NOT NULL DEFAULT '{}',
    business_context TEXT NOT NULL DEFAULT '',
    existing_controls TEXT NOT NULL DEFAULT '',
    deterministic_priority varchar(16) NOT NULL DEFAULT 'MEDIUM',
    deterministic_due_days INTEGER NOT NULL DEFAULT 30,
    llm_backend varchar(32) NOT NULL DEFAULT 'rust_service',
    llm_model_name varchar(128) NOT NULL DEFAULT '',
    llm_status varchar(16) NOT NULL DEFAULT 'DISABLED',
    technical_summary TEXT NOT NULL DEFAULT '',
    business_impact TEXT NOT NULL DEFAULT '',
    attack_path TEXT NOT NULL DEFAULT '',
    management_summary TEXT NOT NULL DEFAULT '',
    recommended_actions_json TEXT NOT NULL DEFAULT '[]',
    evidence_needed_json TEXT NOT NULL DEFAULT '[]',
    raw_llm_json TEXT NOT NULL DEFAULT '{}',
    confidence varchar(16) NOT NULL DEFAULT 'medium',
    prompt_hash varchar(64) NOT NULL DEFAULT '',
    reviewed_by_id INTEGER NULL,
    reviewed_at TEXT NULL,
    review_notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_organizations_tenant_slug ON organizations_tenant(slug);
CREATE INDEX IF NOT EXISTS idx_accounts_user_tenant ON accounts_user(tenant_id);
CREATE INDEX IF NOT EXISTS idx_processes_tenant ON processes_process(tenant_id);
CREATE INDEX IF NOT EXISTS idx_assets_tenant ON assets_app_informationasset(tenant_id);
CREATE INDEX IF NOT EXISTS idx_risks_tenant ON risks_risk(tenant_id);
CREATE INDEX IF NOT EXISTS idx_evidence_items_tenant ON evidence_evidenceitem(tenant_id);
CREATE INDEX IF NOT EXISTS idx_evidence_needs_tenant ON evidence_requirementevidenceneed(tenant_id);
CREATE INDEX IF NOT EXISTS idx_reports_tenant ON reports_reportsnapshot(tenant_id);
CREATE INDEX IF NOT EXISTS idx_roadmap_plan_tenant ON roadmap_roadmapplan(tenant_id);
"#;

const POSTGRES_OPERATIONAL_CORE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS organizations_tenant (
    id BIGSERIAL PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name varchar(255) NOT NULL,
    slug varchar(50) NOT NULL UNIQUE,
    country varchar(100) NOT NULL DEFAULT '',
    operation_countries TEXT NOT NULL DEFAULT '[]',
    description TEXT NOT NULL DEFAULT '',
    sector varchar(64) NOT NULL DEFAULT 'OTHER',
    employee_count INTEGER NOT NULL DEFAULT 0,
    annual_revenue_million TEXT NOT NULL DEFAULT '0',
    balance_sheet_million TEXT NOT NULL DEFAULT '0',
    critical_services TEXT NOT NULL DEFAULT '',
    supply_chain_role varchar(255) NOT NULL DEFAULT '',
    nis2_relevant BOOLEAN NOT NULL DEFAULT FALSE,
    kritis_relevant BOOLEAN NOT NULL DEFAULT FALSE,
    develops_digital_products BOOLEAN NOT NULL DEFAULT FALSE,
    uses_ai_systems BOOLEAN NOT NULL DEFAULT FALSE,
    ot_iacs_scope BOOLEAN NOT NULL DEFAULT FALSE,
    automotive_scope BOOLEAN NOT NULL DEFAULT FALSE,
    psirt_defined BOOLEAN NOT NULL DEFAULT FALSE,
    sbom_required BOOLEAN NOT NULL DEFAULT FALSE,
    product_security_scope TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS accounts_user (
    id BIGSERIAL PRIMARY KEY,
    password varchar(128) NOT NULL DEFAULT '',
    last_login TEXT NULL,
    is_superuser BOOLEAN NOT NULL DEFAULT FALSE,
    username varchar(150) NOT NULL UNIQUE,
    first_name varchar(150) NOT NULL DEFAULT '',
    last_name varchar(150) NOT NULL DEFAULT '',
    email varchar(254) NOT NULL DEFAULT '',
    is_staff BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    date_joined TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    role varchar(32) NOT NULL DEFAULT 'CONTRIBUTOR',
    job_title varchar(255) NOT NULL DEFAULT '',
    tenant_id BIGINT NULL
);
CREATE TABLE IF NOT EXISTS organizations_businessunit (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    name varchar(255) NOT NULL,
    owner_id BIGINT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS organizations_supplier (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    name varchar(255) NOT NULL,
    service_description TEXT NOT NULL DEFAULT '',
    criticality varchar(32) NOT NULL DEFAULT 'MEDIUM',
    owner_id BIGINT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS processes_process (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    business_unit_id BIGINT NULL,
    owner_id BIGINT NULL,
    name varchar(255) NOT NULL,
    scope varchar(255) NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    status varchar(32) NOT NULL DEFAULT 'INFORMAL',
    documented BOOLEAN NOT NULL DEFAULT FALSE,
    approved BOOLEAN NOT NULL DEFAULT FALSE,
    communicated BOOLEAN NOT NULL DEFAULT FALSE,
    implemented BOOLEAN NOT NULL DEFAULT FALSE,
    effective BOOLEAN NOT NULL DEFAULT FALSE,
    evidenced BOOLEAN NOT NULL DEFAULT FALSE,
    reviewed_at date NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS assets_app_informationasset (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    business_unit_id BIGINT NULL,
    owner_id BIGINT NULL,
    name varchar(255) NOT NULL,
    asset_type varchar(24) NOT NULL DEFAULT 'OTHER',
    criticality varchar(16) NOT NULL DEFAULT 'MEDIUM',
    description TEXT NOT NULL DEFAULT '',
    confidentiality varchar(32) NOT NULL DEFAULT 'MEDIUM',
    integrity varchar(32) NOT NULL DEFAULT 'MEDIUM',
    availability varchar(32) NOT NULL DEFAULT 'MEDIUM',
    lifecycle_status varchar(64) NOT NULL DEFAULT 'active',
    is_in_scope BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS risks_riskcategory (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    name varchar(128) NOT NULL
);
CREATE TABLE IF NOT EXISTS risks_risk (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    category_id BIGINT NULL,
    process_id BIGINT NULL,
    asset_id BIGINT NULL,
    owner_id BIGINT NULL,
    title varchar(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    threat TEXT NOT NULL DEFAULT '',
    vulnerability TEXT NOT NULL DEFAULT '',
    impact INTEGER NOT NULL DEFAULT 1,
    likelihood INTEGER NOT NULL DEFAULT 1,
    residual_impact INTEGER NULL,
    residual_likelihood INTEGER NULL,
    status varchar(16) NOT NULL DEFAULT 'IDENTIFIED',
    treatment_strategy varchar(16) NOT NULL DEFAULT 'MITIGATE',
    treatment_plan TEXT NOT NULL DEFAULT '',
    treatment_due_date date NULL,
    accepted_by_id BIGINT NULL,
    accepted_at TEXT NULL,
    review_date date NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS wizard_assessmentsession (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    started_by_id BIGINT NULL,
    assessment_type varchar(32) NOT NULL DEFAULT 'NIS2',
    status varchar(32) NOT NULL DEFAULT 'DRAFT',
    current_step varchar(32) NOT NULL DEFAULT 'applicability',
    applicability_result varchar(32) NOT NULL DEFAULT '',
    applicability_reasoning TEXT NOT NULL DEFAULT '',
    executive_summary TEXT NOT NULL DEFAULT '',
    progress_percent INTEGER NOT NULL DEFAULT 0,
    completed_at TEXT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS wizard_generatedmeasure (
    id BIGSERIAL PRIMARY KEY,
    session_id BIGINT NULL,
    domain_id BIGINT NULL,
    question_id BIGINT NULL,
    title varchar(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    priority varchar(16) NOT NULL DEFAULT 'MEDIUM',
    effort varchar(16) NOT NULL DEFAULT 'MEDIUM',
    measure_type varchar(32) NOT NULL DEFAULT 'CONTROL',
    target_phase varchar(255) NOT NULL DEFAULT '',
    owner_role varchar(255) NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    status varchar(16) NOT NULL DEFAULT 'OPEN',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS requirements_app_mappingversion (
    id BIGSERIAL PRIMARY KEY,
    framework varchar(32) NOT NULL,
    slug varchar(50) NOT NULL DEFAULT '',
    title varchar(255) NOT NULL DEFAULT '',
    version varchar(32) NOT NULL,
    program_name varchar(64) NOT NULL DEFAULT '',
    status varchar(16) NOT NULL DEFAULT 'ACTIVE',
    effective_on date NULL,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS requirements_app_regulatorysource (
    id BIGSERIAL PRIMARY KEY,
    framework varchar(32) NOT NULL,
    mapping_version_id BIGINT NULL,
    code varchar(64) NOT NULL DEFAULT '',
    title varchar(255) NOT NULL DEFAULT '',
    authority varchar(128) NOT NULL DEFAULT '',
    citation varchar(255) NOT NULL DEFAULT '',
    url varchar(200) NOT NULL DEFAULT '',
    source_type varchar(32) NOT NULL DEFAULT '',
    published_on date NULL,
    effective_on date NULL,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS requirements_app_requirement (
    id BIGSERIAL PRIMARY KEY,
    framework varchar(32) NOT NULL,
    code varchar(64) NOT NULL,
    title varchar(255) NOT NULL DEFAULT '',
    domain varchar(255) NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    guidance TEXT NOT NULL DEFAULT '',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    evidence_required BOOLEAN NOT NULL DEFAULT TRUE,
    evidence_guidance TEXT NOT NULL DEFAULT '',
    evidence_examples TEXT NOT NULL DEFAULT '',
    sector_package varchar(64) NOT NULL DEFAULT '',
    legal_reference varchar(128) NOT NULL DEFAULT '',
    mapped_controls TEXT NOT NULL DEFAULT '',
    mapping_rationale TEXT NOT NULL DEFAULT '',
    coverage_level varchar(16) NOT NULL DEFAULT 'FULL',
    mapping_version_id BIGINT NULL,
    primary_source_id BIGINT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS evidence_evidenceitem (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    session_id BIGINT NULL,
    domain_id BIGINT NULL,
    measure_id BIGINT NULL,
    requirement_id BIGINT NULL,
    title varchar(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    linked_requirement varchar(128) NOT NULL DEFAULT '',
    file varchar(100) NULL,
    status varchar(16) NOT NULL DEFAULT 'DRAFT',
    owner_id BIGINT NULL,
    review_notes TEXT NOT NULL DEFAULT '',
    reviewed_by_id BIGINT NULL,
    reviewed_at TEXT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS evidence_requirementevidenceneed (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    session_id BIGINT NULL,
    requirement_id BIGINT NOT NULL,
    title varchar(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    is_mandatory BOOLEAN NOT NULL DEFAULT TRUE,
    status varchar(16) NOT NULL DEFAULT 'OPEN',
    rationale TEXT NOT NULL DEFAULT '',
    covered_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS reports_reportsnapshot (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    session_id BIGINT NOT NULL,
    title varchar(255) NOT NULL,
    executive_summary TEXT NOT NULL DEFAULT '',
    applicability_result varchar(32) NOT NULL DEFAULT '',
    iso_readiness_percent INTEGER NOT NULL DEFAULT 0,
    nis2_readiness_percent INTEGER NOT NULL DEFAULT 0,
    kritis_readiness_percent INTEGER NOT NULL DEFAULT 0,
    cra_readiness_percent INTEGER NOT NULL DEFAULT 0,
    ai_act_readiness_percent INTEGER NOT NULL DEFAULT 0,
    iec62443_readiness_percent INTEGER NOT NULL DEFAULT 0,
    iso_sae_21434_readiness_percent INTEGER NOT NULL DEFAULT 0,
    regulatory_matrix_json TEXT NOT NULL DEFAULT '{}',
    compliance_versions_json TEXT NOT NULL DEFAULT '{}',
    product_security_json TEXT NOT NULL DEFAULT '{}',
    top_gaps_json TEXT NOT NULL DEFAULT '[]',
    top_measures_json TEXT NOT NULL DEFAULT '[]',
    roadmap_summary TEXT NOT NULL DEFAULT '[]',
    domain_scores_json TEXT NOT NULL DEFAULT '[]',
    next_steps_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS roadmap_roadmapplan (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    session_id BIGINT NOT NULL,
    title varchar(255) NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    overall_priority varchar(16) NOT NULL DEFAULT 'MEDIUM',
    planned_start date NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS roadmap_roadmapphase (
    id BIGSERIAL PRIMARY KEY,
    plan_id BIGINT NOT NULL,
    name varchar(255) NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 0,
    objective TEXT NOT NULL DEFAULT '',
    duration_weeks INTEGER NOT NULL DEFAULT 0,
    planned_start date NULL,
    planned_end date NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS roadmap_roadmaptask (
    id BIGSERIAL PRIMARY KEY,
    phase_id BIGINT NOT NULL,
    measure_id BIGINT NULL,
    title varchar(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    priority varchar(16) NOT NULL DEFAULT 'MEDIUM',
    owner_role varchar(255) NOT NULL DEFAULT '',
    due_in_days INTEGER NOT NULL DEFAULT 30,
    dependency_text TEXT NOT NULL DEFAULT '',
    status varchar(16) NOT NULL DEFAULT 'OPEN',
    planned_start date NULL,
    due_date date NULL,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS roadmap_roadmaptaskdependency (
    id BIGSERIAL PRIMARY KEY,
    predecessor_id BIGINT NOT NULL,
    successor_id BIGINT NOT NULL,
    dependency_type varchar(16) NOT NULL DEFAULT 'BLOCKS',
    rationale TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS vulnerability_intelligence_cverecord (
    id BIGSERIAL PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    cve_id varchar(32) NOT NULL UNIQUE,
    source varchar(32) NOT NULL DEFAULT 'NVD',
    description TEXT NOT NULL DEFAULT '',
    cvss_score NUMERIC NULL,
    cvss_vector varchar(255) NOT NULL DEFAULT '',
    severity varchar(16) NOT NULL DEFAULT 'UNKNOWN',
    weakness_ids_json TEXT NOT NULL DEFAULT '[]',
    references_json TEXT NOT NULL DEFAULT '[]',
    configurations_json TEXT NOT NULL DEFAULT '{}',
    epss_score NUMERIC NULL,
    in_kev_catalog BOOLEAN NOT NULL DEFAULT FALSE,
    kev_date_added date NULL,
    kev_vendor_project varchar(255) NOT NULL DEFAULT '',
    kev_product varchar(255) NOT NULL DEFAULT '',
    kev_required_action TEXT NOT NULL DEFAULT '',
    kev_known_ransomware BOOLEAN NOT NULL DEFAULT FALSE,
    raw_json TEXT NOT NULL DEFAULT '{}',
    published_at TEXT NULL,
    modified_at TEXT NULL
);
CREATE TABLE IF NOT EXISTS vulnerability_intelligence_cveassessment (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    cve_id BIGINT NOT NULL,
    product_id BIGINT NULL,
    release_id BIGINT NULL,
    component_id BIGINT NULL,
    linked_vulnerability_id BIGINT NULL,
    related_risk_id BIGINT NULL,
    exposure varchar(16) NOT NULL DEFAULT 'UNKNOWN',
    asset_criticality varchar(16) NOT NULL DEFAULT 'MEDIUM',
    epss_score NUMERIC NULL,
    in_kev_catalog BOOLEAN NOT NULL DEFAULT FALSE,
    exploit_maturity varchar(16) NOT NULL DEFAULT 'UNKNOWN',
    affects_critical_service BOOLEAN NOT NULL DEFAULT FALSE,
    nis2_relevant BOOLEAN NOT NULL DEFAULT FALSE,
    nis2_impact_summary TEXT NOT NULL DEFAULT '',
    repository_name varchar(255) NOT NULL DEFAULT '',
    repository_url varchar(200) NOT NULL DEFAULT '',
    git_ref varchar(128) NOT NULL DEFAULT '',
    source_package varchar(255) NOT NULL DEFAULT '',
    source_package_version varchar(128) NOT NULL DEFAULT '',
    regulatory_tags_json TEXT NOT NULL DEFAULT '[]',
    deterministic_factors_json TEXT NOT NULL DEFAULT '{}',
    business_context TEXT NOT NULL DEFAULT '',
    existing_controls TEXT NOT NULL DEFAULT '',
    deterministic_priority varchar(16) NOT NULL DEFAULT 'MEDIUM',
    deterministic_due_days INTEGER NOT NULL DEFAULT 30,
    llm_backend varchar(32) NOT NULL DEFAULT 'rust_service',
    llm_model_name varchar(128) NOT NULL DEFAULT '',
    llm_status varchar(16) NOT NULL DEFAULT 'DISABLED',
    technical_summary TEXT NOT NULL DEFAULT '',
    business_impact TEXT NOT NULL DEFAULT '',
    attack_path TEXT NOT NULL DEFAULT '',
    management_summary TEXT NOT NULL DEFAULT '',
    recommended_actions_json TEXT NOT NULL DEFAULT '[]',
    evidence_needed_json TEXT NOT NULL DEFAULT '[]',
    raw_llm_json TEXT NOT NULL DEFAULT '{}',
    confidence varchar(16) NOT NULL DEFAULT 'medium',
    prompt_hash varchar(64) NOT NULL DEFAULT '',
    reviewed_by_id BIGINT NULL,
    reviewed_at TEXT NULL,
    review_notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_organizations_tenant_slug ON organizations_tenant(slug);
CREATE INDEX IF NOT EXISTS idx_accounts_user_tenant ON accounts_user(tenant_id);
CREATE INDEX IF NOT EXISTS idx_processes_tenant ON processes_process(tenant_id);
CREATE INDEX IF NOT EXISTS idx_assets_tenant ON assets_app_informationasset(tenant_id);
CREATE INDEX IF NOT EXISTS idx_risks_tenant ON risks_risk(tenant_id);
CREATE INDEX IF NOT EXISTS idx_evidence_items_tenant ON evidence_evidenceitem(tenant_id);
CREATE INDEX IF NOT EXISTS idx_evidence_needs_tenant ON evidence_requirementevidenceneed(tenant_id);
CREATE INDEX IF NOT EXISTS idx_reports_tenant ON reports_reportsnapshot(tenant_id);
CREATE INDEX IF NOT EXISTS idx_roadmap_plan_tenant ON roadmap_roadmapplan(tenant_id);
"#;

const SQLITE_PRODUCT_SECURITY_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS product_security_productfamily (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    name varchar(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS product_security_product (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    family_id INTEGER NULL,
    name varchar(255) NOT NULL,
    code varchar(100) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    has_digital_elements bool NOT NULL DEFAULT 1,
    includes_ai bool NOT NULL DEFAULT 0,
    ot_iacs_context bool NOT NULL DEFAULT 0,
    automotive_context bool NOT NULL DEFAULT 0,
    support_window_months INTEGER NOT NULL DEFAULT 24,
    regulatory_profile_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS product_security_productrelease (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    version varchar(64) NOT NULL,
    status varchar(16) NOT NULL DEFAULT 'PLANNED',
    release_date TEXT NULL,
    support_end_date TEXT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS product_security_component (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    supplier_id INTEGER NULL,
    name varchar(255) NOT NULL,
    component_type varchar(16) NOT NULL DEFAULT 'SOFTWARE',
    version varchar(64) NOT NULL DEFAULT '',
    is_open_source bool NOT NULL DEFAULT 0,
    has_sbom bool NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS product_security_aisystem (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    product_id INTEGER NULL,
    name varchar(255) NOT NULL,
    use_case TEXT NOT NULL DEFAULT '',
    provider varchar(255) NOT NULL DEFAULT '',
    risk_classification varchar(16) NOT NULL DEFAULT 'LIMITED',
    in_scope bool NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS product_security_threatmodel (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    release_id INTEGER NULL,
    name varchar(255) NOT NULL,
    methodology varchar(100) NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    status varchar(16) NOT NULL DEFAULT 'DRAFT',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS product_security_threatscenario (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    threat_model_id INTEGER NOT NULL,
    component_id INTEGER NULL,
    title varchar(255) NOT NULL,
    category varchar(32) NOT NULL DEFAULT '',
    attack_path TEXT NOT NULL DEFAULT '',
    impact TEXT NOT NULL DEFAULT '',
    severity varchar(16) NOT NULL DEFAULT 'MEDIUM',
    mitigation_status varchar(64) NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS product_security_tara (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    release_id INTEGER NULL,
    scenario_id INTEGER NULL,
    name varchar(255) NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    attack_feasibility INTEGER NOT NULL DEFAULT 1,
    impact_score INTEGER NOT NULL DEFAULT 1,
    risk_score INTEGER NOT NULL DEFAULT 1,
    status varchar(16) NOT NULL DEFAULT 'OPEN',
    treatment_decision varchar(128) NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS product_security_vulnerability (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    release_id INTEGER NULL,
    component_id INTEGER NULL,
    title varchar(255) NOT NULL,
    cve varchar(50) NOT NULL DEFAULT '',
    severity varchar(16) NOT NULL DEFAULT 'MEDIUM',
    status varchar(16) NOT NULL DEFAULT 'OPEN',
    remediation_due TEXT NULL,
    summary TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS product_security_psirtcase (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    release_id INTEGER NULL,
    vulnerability_id INTEGER NULL,
    case_id varchar(64) NOT NULL,
    title varchar(255) NOT NULL,
    severity varchar(16) NOT NULL DEFAULT 'MEDIUM',
    status varchar(20) NOT NULL DEFAULT 'TRIAGE',
    disclosure_due TEXT NULL,
    summary TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS product_security_securityadvisory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    release_id INTEGER NULL,
    psirt_case_id INTEGER NULL,
    advisory_id varchar(64) NOT NULL,
    title varchar(255) NOT NULL,
    status varchar(16) NOT NULL DEFAULT 'DRAFT',
    published_on TEXT NULL,
    summary TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS product_security_productsecuritysnapshot (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    cra_applicable bool NOT NULL DEFAULT 0,
    ai_act_applicable bool NOT NULL DEFAULT 0,
    iec62443_applicable bool NOT NULL DEFAULT 0,
    iso_sae_21434_applicable bool NOT NULL DEFAULT 0,
    cra_readiness_percent INTEGER NOT NULL DEFAULT 0,
    ai_act_readiness_percent INTEGER NOT NULL DEFAULT 0,
    iec62443_readiness_percent INTEGER NOT NULL DEFAULT 0,
    iso_sae_21434_readiness_percent INTEGER NOT NULL DEFAULT 0,
    threat_model_coverage_percent INTEGER NOT NULL DEFAULT 0,
    psirt_readiness_percent INTEGER NOT NULL DEFAULT 0,
    open_vulnerability_count INTEGER NOT NULL DEFAULT 0,
    critical_vulnerability_count INTEGER NOT NULL DEFAULT 0,
    summary TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS product_security_productsecurityroadmap (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    title varchar(255) NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    generated_from_snapshot_id INTEGER NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS product_security_productsecurityroadmaptask (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    roadmap_id INTEGER NOT NULL,
    related_release_id INTEGER NULL,
    related_vulnerability_id INTEGER NULL,
    phase varchar(16) NOT NULL DEFAULT 'GOVERNANCE',
    title varchar(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    priority varchar(32) NOT NULL DEFAULT 'MEDIUM',
    owner_role varchar(64) NOT NULL DEFAULT '',
    due_in_days INTEGER NOT NULL DEFAULT 30,
    dependency_text TEXT NOT NULL DEFAULT '',
    status varchar(16) NOT NULL DEFAULT 'OPEN',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_product_security_product_tenant ON product_security_product(tenant_id);
CREATE INDEX IF NOT EXISTS idx_product_security_release_tenant ON product_security_productrelease(tenant_id);
CREATE INDEX IF NOT EXISTS idx_product_security_vulnerability_tenant ON product_security_vulnerability(tenant_id);
CREATE INDEX IF NOT EXISTS idx_product_security_roadmap_tenant ON product_security_productsecurityroadmap(tenant_id);
"#;

const POSTGRES_PRODUCT_SECURITY_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS product_security_productfamily (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    name varchar(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS product_security_product (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    family_id BIGINT NULL,
    name varchar(255) NOT NULL,
    code varchar(100) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    has_digital_elements BOOLEAN NOT NULL DEFAULT TRUE,
    includes_ai BOOLEAN NOT NULL DEFAULT FALSE,
    ot_iacs_context BOOLEAN NOT NULL DEFAULT FALSE,
    automotive_context BOOLEAN NOT NULL DEFAULT FALSE,
    support_window_months INTEGER NOT NULL DEFAULT 24,
    regulatory_profile_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS product_security_productrelease (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    product_id BIGINT NOT NULL,
    version varchar(64) NOT NULL,
    status varchar(16) NOT NULL DEFAULT 'PLANNED',
    release_date TEXT NULL,
    support_end_date TEXT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS product_security_component (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    product_id BIGINT NOT NULL,
    supplier_id BIGINT NULL,
    name varchar(255) NOT NULL,
    component_type varchar(16) NOT NULL DEFAULT 'SOFTWARE',
    version varchar(64) NOT NULL DEFAULT '',
    is_open_source BOOLEAN NOT NULL DEFAULT FALSE,
    has_sbom BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS product_security_aisystem (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    product_id BIGINT NULL,
    name varchar(255) NOT NULL,
    use_case TEXT NOT NULL DEFAULT '',
    provider varchar(255) NOT NULL DEFAULT '',
    risk_classification varchar(16) NOT NULL DEFAULT 'LIMITED',
    in_scope BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS product_security_threatmodel (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    product_id BIGINT NOT NULL,
    release_id BIGINT NULL,
    name varchar(255) NOT NULL,
    methodology varchar(100) NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    status varchar(16) NOT NULL DEFAULT 'DRAFT',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS product_security_threatscenario (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    threat_model_id BIGINT NOT NULL,
    component_id BIGINT NULL,
    title varchar(255) NOT NULL,
    category varchar(32) NOT NULL DEFAULT '',
    attack_path TEXT NOT NULL DEFAULT '',
    impact TEXT NOT NULL DEFAULT '',
    severity varchar(16) NOT NULL DEFAULT 'MEDIUM',
    mitigation_status varchar(64) NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS product_security_tara (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    product_id BIGINT NOT NULL,
    release_id BIGINT NULL,
    scenario_id BIGINT NULL,
    name varchar(255) NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    attack_feasibility INTEGER NOT NULL DEFAULT 1,
    impact_score INTEGER NOT NULL DEFAULT 1,
    risk_score INTEGER NOT NULL DEFAULT 1,
    status varchar(16) NOT NULL DEFAULT 'OPEN',
    treatment_decision varchar(128) NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS product_security_vulnerability (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    product_id BIGINT NOT NULL,
    release_id BIGINT NULL,
    component_id BIGINT NULL,
    title varchar(255) NOT NULL,
    cve varchar(50) NOT NULL DEFAULT '',
    severity varchar(16) NOT NULL DEFAULT 'MEDIUM',
    status varchar(16) NOT NULL DEFAULT 'OPEN',
    remediation_due TEXT NULL,
    summary TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS product_security_psirtcase (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    product_id BIGINT NOT NULL,
    release_id BIGINT NULL,
    vulnerability_id BIGINT NULL,
    case_id varchar(64) NOT NULL,
    title varchar(255) NOT NULL,
    severity varchar(16) NOT NULL DEFAULT 'MEDIUM',
    status varchar(20) NOT NULL DEFAULT 'TRIAGE',
    disclosure_due TEXT NULL,
    summary TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS product_security_securityadvisory (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    product_id BIGINT NOT NULL,
    release_id BIGINT NULL,
    psirt_case_id BIGINT NULL,
    advisory_id varchar(64) NOT NULL,
    title varchar(255) NOT NULL,
    status varchar(16) NOT NULL DEFAULT 'DRAFT',
    published_on TEXT NULL,
    summary TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS product_security_productsecuritysnapshot (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    product_id BIGINT NOT NULL,
    cra_applicable BOOLEAN NOT NULL DEFAULT FALSE,
    ai_act_applicable BOOLEAN NOT NULL DEFAULT FALSE,
    iec62443_applicable BOOLEAN NOT NULL DEFAULT FALSE,
    iso_sae_21434_applicable BOOLEAN NOT NULL DEFAULT FALSE,
    cra_readiness_percent INTEGER NOT NULL DEFAULT 0,
    ai_act_readiness_percent INTEGER NOT NULL DEFAULT 0,
    iec62443_readiness_percent INTEGER NOT NULL DEFAULT 0,
    iso_sae_21434_readiness_percent INTEGER NOT NULL DEFAULT 0,
    threat_model_coverage_percent INTEGER NOT NULL DEFAULT 0,
    psirt_readiness_percent INTEGER NOT NULL DEFAULT 0,
    open_vulnerability_count INTEGER NOT NULL DEFAULT 0,
    critical_vulnerability_count INTEGER NOT NULL DEFAULT 0,
    summary TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS product_security_productsecurityroadmap (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    product_id BIGINT NOT NULL,
    title varchar(255) NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    generated_from_snapshot_id BIGINT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS product_security_productsecurityroadmaptask (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    roadmap_id BIGINT NOT NULL,
    related_release_id BIGINT NULL,
    related_vulnerability_id BIGINT NULL,
    phase varchar(16) NOT NULL DEFAULT 'GOVERNANCE',
    title varchar(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    priority varchar(32) NOT NULL DEFAULT 'MEDIUM',
    owner_role varchar(64) NOT NULL DEFAULT '',
    due_in_days INTEGER NOT NULL DEFAULT 30,
    dependency_text TEXT NOT NULL DEFAULT '',
    status varchar(16) NOT NULL DEFAULT 'OPEN',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_product_security_product_tenant ON product_security_product(tenant_id);
CREATE INDEX IF NOT EXISTS idx_product_security_release_tenant ON product_security_productrelease(tenant_id);
CREATE INDEX IF NOT EXISTS idx_product_security_vulnerability_tenant ON product_security_vulnerability(tenant_id);
CREATE INDEX IF NOT EXISTS idx_product_security_roadmap_tenant ON product_security_productsecurityroadmap(tenant_id);
"#;

const SQLITE_CATALOG_REQUIREMENT_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS catalog_assessmentdomain (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    code varchar(64) NOT NULL UNIQUE,
    name varchar(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    weight INTEGER NOT NULL DEFAULT 10,
    sort_order INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS catalog_assessmentquestion (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    code varchar(64) NOT NULL UNIQUE,
    text varchar(500) NOT NULL,
    help_text TEXT NOT NULL DEFAULT '',
    why_it_matters TEXT NOT NULL DEFAULT '',
    question_kind varchar(20) NOT NULL,
    wizard_step varchar(20) NOT NULL,
    weight INTEGER NOT NULL DEFAULT 10,
    is_required bool NOT NULL DEFAULT 1,
    applies_to_iso27001 bool NOT NULL DEFAULT 1,
    applies_to_nis2 bool NOT NULL DEFAULT 0,
    applies_to_cra bool NOT NULL DEFAULT 0,
    applies_to_ai_act bool NOT NULL DEFAULT 0,
    applies_to_iec62443 bool NOT NULL DEFAULT 0,
    applies_to_iso_sae_21434 bool NOT NULL DEFAULT 0,
    applies_to_product_security bool NOT NULL DEFAULT 0,
    sort_order INTEGER NOT NULL DEFAULT 0,
    domain_id INTEGER NULL
);
CREATE TABLE IF NOT EXISTS catalog_answeroption (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    slug varchar(64) NOT NULL,
    label varchar(255) NOT NULL,
    score INTEGER NOT NULL DEFAULT 0,
    description TEXT NOT NULL DEFAULT '',
    sort_order INTEGER NOT NULL DEFAULT 0,
    is_na bool NOT NULL DEFAULT 0,
    question_id INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS catalog_recommendationrule (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    max_score_threshold INTEGER NOT NULL DEFAULT 2,
    title varchar(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    priority varchar(16) NOT NULL DEFAULT 'MEDIUM',
    effort varchar(16) NOT NULL DEFAULT 'MEDIUM',
    measure_type varchar(20) NOT NULL DEFAULT 'ORGANIZATIONAL',
    owner_role varchar(64) NOT NULL DEFAULT '',
    target_phase varchar(64) NOT NULL DEFAULT '',
    sort_order INTEGER NOT NULL DEFAULT 0,
    question_id INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS requirements_app_requirementquestionmapping (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    strength varchar(16) NOT NULL DEFAULT 'PRIMARY',
    rationale TEXT NOT NULL DEFAULT '',
    mapping_version_id INTEGER NOT NULL,
    question_id INTEGER NOT NULL,
    requirement_id INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_catalog_question_domain ON catalog_assessmentquestion(domain_id);
CREATE INDEX IF NOT EXISTS idx_catalog_option_question ON catalog_answeroption(question_id);
CREATE INDEX IF NOT EXISTS idx_catalog_rule_question ON catalog_recommendationrule(question_id);
CREATE INDEX IF NOT EXISTS idx_requirement_question_mapping_requirement ON requirements_app_requirementquestionmapping(requirement_id);
CREATE INDEX IF NOT EXISTS idx_requirement_question_mapping_question ON requirements_app_requirementquestionmapping(question_id);
"#;

const POSTGRES_CATALOG_REQUIREMENT_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS catalog_assessmentdomain (
    id BIGSERIAL PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    code varchar(64) NOT NULL UNIQUE,
    name varchar(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    weight INTEGER NOT NULL DEFAULT 10,
    sort_order INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS catalog_assessmentquestion (
    id BIGSERIAL PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    code varchar(64) NOT NULL UNIQUE,
    text varchar(500) NOT NULL,
    help_text TEXT NOT NULL DEFAULT '',
    why_it_matters TEXT NOT NULL DEFAULT '',
    question_kind varchar(20) NOT NULL,
    wizard_step varchar(20) NOT NULL,
    weight INTEGER NOT NULL DEFAULT 10,
    is_required BOOLEAN NOT NULL DEFAULT TRUE,
    applies_to_iso27001 BOOLEAN NOT NULL DEFAULT TRUE,
    applies_to_nis2 BOOLEAN NOT NULL DEFAULT FALSE,
    applies_to_cra BOOLEAN NOT NULL DEFAULT FALSE,
    applies_to_ai_act BOOLEAN NOT NULL DEFAULT FALSE,
    applies_to_iec62443 BOOLEAN NOT NULL DEFAULT FALSE,
    applies_to_iso_sae_21434 BOOLEAN NOT NULL DEFAULT FALSE,
    applies_to_product_security BOOLEAN NOT NULL DEFAULT FALSE,
    sort_order INTEGER NOT NULL DEFAULT 0,
    domain_id BIGINT NULL
);
CREATE TABLE IF NOT EXISTS catalog_answeroption (
    id BIGSERIAL PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    slug varchar(64) NOT NULL,
    label varchar(255) NOT NULL,
    score INTEGER NOT NULL DEFAULT 0,
    description TEXT NOT NULL DEFAULT '',
    sort_order INTEGER NOT NULL DEFAULT 0,
    is_na BOOLEAN NOT NULL DEFAULT FALSE,
    question_id BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS catalog_recommendationrule (
    id BIGSERIAL PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    max_score_threshold INTEGER NOT NULL DEFAULT 2,
    title varchar(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    priority varchar(16) NOT NULL DEFAULT 'MEDIUM',
    effort varchar(16) NOT NULL DEFAULT 'MEDIUM',
    measure_type varchar(20) NOT NULL DEFAULT 'ORGANIZATIONAL',
    owner_role varchar(64) NOT NULL DEFAULT '',
    target_phase varchar(64) NOT NULL DEFAULT '',
    sort_order INTEGER NOT NULL DEFAULT 0,
    question_id BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS requirements_app_requirementquestionmapping (
    id BIGSERIAL PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    strength varchar(16) NOT NULL DEFAULT 'PRIMARY',
    rationale TEXT NOT NULL DEFAULT '',
    mapping_version_id BIGINT NOT NULL,
    question_id BIGINT NOT NULL,
    requirement_id BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_catalog_question_domain ON catalog_assessmentquestion(domain_id);
CREATE INDEX IF NOT EXISTS idx_catalog_option_question ON catalog_answeroption(question_id);
CREATE INDEX IF NOT EXISTS idx_catalog_rule_question ON catalog_recommendationrule(question_id);
CREATE INDEX IF NOT EXISTS idx_requirement_question_mapping_requirement ON requirements_app_requirementquestionmapping(requirement_id);
CREATE INDEX IF NOT EXISTS idx_requirement_question_mapping_question ON requirements_app_requirementquestionmapping(question_id);
"#;

const SQLITE_DEMO_SEED: &str = r#"
INSERT OR IGNORE INTO organizations_tenant (
    id, created_at, updated_at, name, slug, country, operation_countries, description, sector,
    employee_count, annual_revenue_million, balance_sheet_million, critical_services,
    supply_chain_role, nis2_relevant, kritis_relevant, develops_digital_products, uses_ai_systems,
    ot_iacs_scope, automotive_scope, psirt_defined, sbom_required, product_security_scope
) VALUES (
    1, '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z', 'ISCY Demo Tenant', 'demo',
    'DE', '["DE"]', 'Rust-only demo tenant', 'MSSP', 80, '12.50', '8.00',
    'Managed security services', 'B2B security provider', 1, 0, 1, 1, 0, 0, 1, 1,
    'Product security scope prepared for Rust cutover'
);
INSERT INTO accounts_user (
    id, password, username, first_name, last_name, email, is_staff, is_active, date_joined, role, job_title, tenant_id
) VALUES (
    1, 'pbkdf2_sha256$720000$iscy-demo-salt$dHYZBIWxS3abL+0r4Rp7w3kbLXLSAFUrGq/HaPlAVrY=',
    'admin', 'Demo', 'Admin', 'admin@example.com', 1, 1, '2026-04-22T10:00:00Z',
    'ADMIN', 'Security Lead', 1
) ON CONFLICT(id) DO UPDATE SET
    password = excluded.password,
    username = excluded.username,
    first_name = excluded.first_name,
    last_name = excluded.last_name,
    email = excluded.email,
    is_staff = excluded.is_staff,
    is_active = excluded.is_active,
    role = excluded.role,
    job_title = excluded.job_title,
    tenant_id = excluded.tenant_id;
INSERT OR IGNORE INTO accounts_role (code, label, description) VALUES
    ('ADMIN', 'Administrator', 'Full tenant administration and write access'),
    ('MANAGEMENT', 'Management', 'Management oversight'),
    ('CISO', 'CISO / Security Officer', 'Security leadership'),
    ('ISMS_MANAGER', 'ISMS Manager', 'ISMS program management'),
    ('COMPLIANCE_MANAGER', 'Compliance Manager', 'Compliance program management'),
    ('PROCESS_OWNER', 'Process Owner', 'Process ownership'),
    ('RISK_OWNER', 'Risk Owner', 'Risk ownership'),
    ('AUDITOR', 'Auditor', 'Read-only audit access'),
    ('CONTRIBUTOR', 'Contributor', 'Operational write access');
INSERT OR IGNORE INTO accounts_userrole (user_id, role_id, scope_tenant_id, granted_at, granted_by_id)
SELECT 1, id, 1, '2026-04-22T10:00:00Z', NULL FROM accounts_role WHERE code = 'ADMIN';
INSERT OR IGNORE INTO django_content_type (app_label, model) VALUES
    ('accounts', 'user'),
    ('accounts', 'role'),
    ('organizations', 'tenant');
INSERT OR IGNORE INTO auth_permission (name, content_type_id, codename)
SELECT 'Can view user', id, 'view_user' FROM django_content_type WHERE app_label = 'accounts' AND model = 'user';
INSERT OR IGNORE INTO auth_permission (name, content_type_id, codename)
SELECT 'Can add user', id, 'add_user' FROM django_content_type WHERE app_label = 'accounts' AND model = 'user';
INSERT OR IGNORE INTO auth_permission (name, content_type_id, codename)
SELECT 'Can change user', id, 'change_user' FROM django_content_type WHERE app_label = 'accounts' AND model = 'user';
INSERT OR IGNORE INTO auth_permission (name, content_type_id, codename)
SELECT 'Can delete user', id, 'delete_user' FROM django_content_type WHERE app_label = 'accounts' AND model = 'user';
INSERT OR IGNORE INTO auth_permission (name, content_type_id, codename)
SELECT 'Can view role', id, 'view_role' FROM django_content_type WHERE app_label = 'accounts' AND model = 'role';
INSERT OR IGNORE INTO auth_permission (name, content_type_id, codename)
SELECT 'Can change tenant', id, 'change_tenant' FROM django_content_type WHERE app_label = 'organizations' AND model = 'tenant';
INSERT OR IGNORE INTO auth_group (name) VALUES
    ('Administrators'),
    ('Auditors'),
    ('Contributors');
INSERT OR IGNORE INTO auth_group_permissions (group_id, permission_id)
SELECT g.id, p.id
FROM auth_group g
JOIN auth_permission p ON 1 = 1
WHERE g.name = 'Administrators';
INSERT OR IGNORE INTO auth_group_permissions (group_id, permission_id)
SELECT g.id, p.id
FROM auth_group g
JOIN auth_permission p ON p.codename IN ('view_user', 'view_role')
WHERE g.name = 'Auditors';
INSERT OR IGNORE INTO auth_group_permissions (group_id, permission_id)
SELECT g.id, p.id
FROM auth_group g
JOIN auth_permission p ON p.codename IN ('view_user')
WHERE g.name = 'Contributors';
INSERT OR IGNORE INTO accounts_user_groups (user_id, group_id)
SELECT 1, id FROM auth_group WHERE name = 'Administrators';
INSERT OR IGNORE INTO organizations_businessunit (
    id, tenant_id, name, owner_id, created_at, updated_at
) VALUES (
    1, 1, 'Security Operations', 1, '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
);
INSERT OR IGNORE INTO processes_process (
    id, tenant_id, business_unit_id, owner_id, name, scope, description, status,
    documented, approved, communicated, implemented, effective, evidenced, reviewed_at, created_at, updated_at
) VALUES (
    1, 1, 1, 1, 'Incident Intake', 'SOC', 'SOC intake process', 'PARTIAL',
    1, 1, 1, 1, 0, 0, '2026-04-22', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
);
INSERT OR IGNORE INTO assets_app_informationasset (
    id, tenant_id, business_unit_id, owner_id, name, asset_type, criticality, description,
    confidentiality, integrity, availability, lifecycle_status, is_in_scope, created_at, updated_at
) VALUES (
    1, 1, 1, 1, 'Customer Portal', 'APPLICATION', 'HIGH', 'External customer platform',
    'HIGH', 'HIGH', 'MEDIUM', 'active', 1, '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
);
INSERT OR IGNORE INTO risks_riskcategory (id, tenant_id, name)
VALUES (1, 1, 'Cyber Risk');
INSERT OR IGNORE INTO risks_risk (
    id, tenant_id, category_id, process_id, asset_id, owner_id, title, description, threat,
    vulnerability, impact, likelihood, residual_impact, residual_likelihood, status,
    treatment_strategy, treatment_plan, treatment_due_date, accepted_by_id, accepted_at,
    review_date, created_at, updated_at
) VALUES (
    1, 1, 1, 1, 1, 1, 'Credential Phishing', 'Credential theft via phishing',
    'Phishing campaign', 'Weak MFA coverage', 5, 4, 3, 3, 'TREATING', 'MITIGATE',
    'Roll out phishing-resistant MFA', '2026-06-30', NULL, NULL, '2026-07-15',
    '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
);
INSERT OR IGNORE INTO wizard_assessmentsession (
    id, tenant_id, started_by_id, assessment_type, status, current_step, applicability_result,
    applicability_reasoning, executive_summary, progress_percent, completed_at, created_at, updated_at
) VALUES (
    1, 1, 1, 'NIS2', 'COMPLETED', 'results', 'relevant',
    'Demo tenant is relevant for NIS2 planning.', 'Rust demo assessment completed.',
    100, '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
);
INSERT OR IGNORE INTO requirements_app_mappingversion (
    id, framework, slug, title, version, program_name, status, effective_on, notes, created_at, updated_at
) VALUES (
    1, 'NIS2', 'nis2-demo', 'NIS2 Demo Mapping', '2024', 'NIS2', 'ACTIVE',
    '2026-01-01', 'Rust demo mapping.', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
);
INSERT OR IGNORE INTO requirements_app_regulatorysource (
    id, framework, mapping_version_id, code, title, authority, citation, url, source_type,
    published_on, effective_on, notes, created_at, updated_at
) VALUES (
    1, 'NIS2', 1, 'NIS2-21', 'Article 21', 'EU', 'NIS2 Article 21', '', 'LAW',
    NULL, '2024-10-18', '', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
);
INSERT OR IGNORE INTO requirements_app_requirement (
    id, framework, code, title, domain, description, guidance, is_active, evidence_required,
    evidence_guidance, evidence_examples, sector_package, legal_reference, mapped_controls,
    mapping_rationale, coverage_level, mapping_version_id, primary_source_id, created_at, updated_at
) VALUES (
    1, 'NIS2', 'NIS2-21-MFA', 'MFA for privileged access', 'Identity',
    'Privileged access should use strong authentication.', 'Implement MFA.',
    1, 1, 'Provide MFA policy and rollout evidence.', 'Policy, screenshots, reports',
    'MSSP', 'Art. 21', 'ISO A.5.15', 'Core access control mapping.', 'FULL', 1, 1,
    '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
);
INSERT OR IGNORE INTO evidence_evidenceitem (
    id, tenant_id, session_id, domain_id, measure_id, requirement_id, title, description,
    linked_requirement, file, status, owner_id, review_notes, reviewed_by_id, reviewed_at, created_at, updated_at
) VALUES (
    1, 1, 1, NULL, NULL, 1, 'MFA rollout evidence', 'Initial MFA rollout evidence.',
    'NIS2-21-MFA', NULL, 'APPROVED', 1, 'Looks ready for demo.', 1, '2026-04-22T10:00:00Z',
    '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
);
INSERT OR IGNORE INTO evidence_requirementevidenceneed (
    id, tenant_id, session_id, requirement_id, title, description, is_mandatory, status,
    rationale, covered_count, created_at, updated_at
) VALUES (
    1, 1, 1, 1, 'MFA rollout evidence needed', 'Upload rollout artefacts.', 1,
    'COVERED', 'Demo evidence is present.', 1, '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
);
INSERT OR IGNORE INTO reports_reportsnapshot (
    id, tenant_id, session_id, title, executive_summary, applicability_result,
    iso_readiness_percent, nis2_readiness_percent, kritis_readiness_percent, cra_readiness_percent,
    ai_act_readiness_percent, iec62443_readiness_percent, iso_sae_21434_readiness_percent,
    regulatory_matrix_json, compliance_versions_json, product_security_json, top_gaps_json,
    top_measures_json, roadmap_summary, domain_scores_json, next_steps_json, created_at, updated_at
) VALUES (
    1, 1, 1, 'Rust Demo Readiness', 'Initial Rust demo readiness snapshot.', 'relevant',
    72, 81, 20, 35, 30, 25, 28, '{"overall":"medium"}', '{"NIS2":{"version":"2024"}}',
    '{"sbom_required":true}', '[{"title":"MFA rollout gap"}]',
    '[{"title":"Complete MFA rollout","priority":"HIGH"}]', '[{"name":"Phase 1"}]',
    '[{"domain":"Identity","score_percent":81}]', '{"dependencies":[]}',
    '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
);
INSERT OR IGNORE INTO roadmap_roadmapplan (
    id, tenant_id, session_id, title, summary, overall_priority, planned_start, created_at, updated_at
) VALUES (
    1, 1, 1, 'Rust Cutover Roadmap', 'Complete Rust operational cutover path.',
    'HIGH', '2026-05-01', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
);
INSERT OR IGNORE INTO roadmap_roadmapphase (
    id, plan_id, name, sort_order, objective, duration_weeks, planned_start, planned_end, created_at, updated_at
) VALUES (
    1, 1, 'Operational Core', 1, 'Run ISCY core flows from Rust.', 2,
    '2026-05-01', '2026-05-14', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
);
INSERT OR IGNORE INTO roadmap_roadmaptask (
    id, phase_id, measure_id, title, description, priority, owner_role, due_in_days,
    dependency_text, status, planned_start, due_date, notes, created_at, updated_at
) VALUES (
    1, 1, NULL, 'Replace Django migration dependency', 'Move schema bootstrap into Rust.',
    'HIGH', 'Rust Engineer', 14, '', 'OPEN', '2026-05-01', '2026-05-14', '',
    '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
);
INSERT OR IGNORE INTO organizations_supplier (id, tenant_id, name, service_description, criticality, owner_id, created_at, updated_at)
VALUES (1000, 1, 'Rust Secure Supplier', 'Firmware component supplier', 'HIGH', 1, '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z');
INSERT OR IGNORE INTO product_security_productfamily (id, tenant_id, name, description, created_at, updated_at)
VALUES (1000, 1, 'Rust Gateways', 'Rust-native secure product family', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z');
INSERT OR IGNORE INTO product_security_product (
    id, tenant_id, family_id, name, code, description, has_digital_elements, includes_ai,
    ot_iacs_context, automotive_context, support_window_months, regulatory_profile_json,
    created_at, updated_at
) VALUES (
    1100, 1, 1000, 'Rust Sensor Gateway', 'rust-sensor-gateway',
    'Rust demo industrial edge device', 1, 1, 1, 0, 36, '{}',
    '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
);
INSERT OR IGNORE INTO product_security_productrelease (
    id, tenant_id, product_id, version, status, release_date, support_end_date, created_at, updated_at
) VALUES
    (1200, 1, 1100, '1.0', 'ACTIVE', '2026-04-01', '2028-04-01', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'),
    (1201, 1, 1100, '0.9', 'EOL', '2025-01-01', '2026-01-01', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z');
INSERT OR IGNORE INTO product_security_component (
    id, tenant_id, product_id, supplier_id, name, component_type, version, is_open_source, has_sbom, created_at, updated_at
) VALUES (
    1250, 1, 1100, 1000, 'Rust Gateway Firmware', 'FIRMWARE', '1.0.3',
    0, 1, '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
);
INSERT OR IGNORE INTO product_security_aisystem (
    id, tenant_id, product_id, name, use_case, provider, risk_classification, in_scope, created_at, updated_at
) VALUES (
    1260, 1, 1100, 'Rust Gateway Assistant', 'Firmware triage and support guidance',
    'Internal', 'LIMITED', 1, '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
);
INSERT OR IGNORE INTO product_security_threatmodel (
    id, tenant_id, product_id, release_id, name, methodology, summary, status, created_at, updated_at
) VALUES (
    1300, 1, 1100, 1200, 'Rust Gateway Threat Model', 'STRIDE',
    'Rust demo threat model summary', 'APPROVED', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
);
INSERT OR IGNORE INTO product_security_threatscenario (
    id, tenant_id, threat_model_id, component_id, title, category, attack_path, impact,
    severity, mitigation_status, created_at, updated_at
) VALUES (
    1301, 1, 1300, 1250, 'Unsigned Rust firmware update', 'TAMPERING',
    'Attacker replaces firmware package', 'Remote code execution', 'CRITICAL', 'Open',
    '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
);
INSERT OR IGNORE INTO product_security_tara (
    id, tenant_id, product_id, release_id, scenario_id, name, summary, attack_feasibility,
    impact_score, risk_score, status, treatment_decision, created_at, updated_at
) VALUES (
    1400, 1, 1100, 1200, 1301, 'Rust Gateway TARA', 'TARA for firmware update abuse',
    3, 4, 12, 'OPEN', 'Mitigate in next firmware release',
    '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
);
INSERT OR IGNORE INTO product_security_vulnerability (
    id, tenant_id, product_id, release_id, component_id, title, cve, severity, status,
    remediation_due, summary, created_at, updated_at
) VALUES
    (1500, 1, 1100, 1200, 1250, 'Rust critical firmware exposure', 'CVE-2026-0001', 'CRITICAL', 'OPEN', '2026-05-18', 'Critical issue in firmware updater', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'),
    (1501, 1, 1100, 1200, 1250, 'Rust outdated dependency', '', 'HIGH', 'TRIAGED', '2026-06-01', 'Dependency needs update', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'),
    (1502, 1, 1100, 1200, 1250, 'Rust fixed UI issue', '', 'LOW', 'FIXED', NULL, 'Already fixed', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z');
INSERT OR IGNORE INTO product_security_psirtcase (
    id, tenant_id, product_id, release_id, vulnerability_id, case_id, title, severity,
    status, disclosure_due, summary, created_at, updated_at
) VALUES (
    1600, 1, 1100, 1200, 1500, 'RUST-PSIRT-1', 'Rust critical firmware disclosure',
    'CRITICAL', 'TRIAGE', '2026-05-20', 'PSIRT case for Rust firmware exposure',
    '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
);
INSERT OR IGNORE INTO product_security_securityadvisory (
    id, tenant_id, product_id, release_id, psirt_case_id, advisory_id, title, status,
    published_on, summary, created_at, updated_at
) VALUES (
    1700, 1, 1100, 1200, 1600, 'RUST-ADV-1', 'Rust gateway firmware advisory',
    'PUBLISHED', '2026-05-21', 'Advisory for Rust firmware exposure',
    '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
);
INSERT OR IGNORE INTO product_security_productsecuritysnapshot (
    id, tenant_id, product_id, cra_applicable, ai_act_applicable, iec62443_applicable,
    iso_sae_21434_applicable, cra_readiness_percent, ai_act_readiness_percent,
    iec62443_readiness_percent, iso_sae_21434_readiness_percent,
    threat_model_coverage_percent, psirt_readiness_percent, open_vulnerability_count,
    critical_vulnerability_count, summary, created_at, updated_at
) VALUES (
    1800, 1, 1100, 1, 1, 1, 0, 73, 62, 59, 0, 41, 56, 2, 1,
    'Rust Product Security snapshot', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
);
INSERT OR IGNORE INTO product_security_productsecurityroadmap (
    id, tenant_id, product_id, title, summary, generated_from_snapshot_id, created_at, updated_at
) VALUES (
    1900, 1, 1100, 'Rust Gateway Roadmap', 'Roadmap from Rust DB bootstrap',
    1800, '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
);
INSERT OR IGNORE INTO product_security_productsecurityroadmaptask (
    id, tenant_id, roadmap_id, related_release_id, related_vulnerability_id, phase, title,
    description, priority, owner_role, due_in_days, dependency_text, status, created_at, updated_at
) VALUES
    (1901, 1, 1900, 1200, NULL, 'GOVERNANCE', 'Define Rust product security ownership', 'Clarify owner roles and release gates', 'HIGH', 'Product Security Lead', 30, '', 'OPEN', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'),
    (1902, 1, 1900, 1200, 1500, 'RESPONSE', 'Remediate Rust critical firmware exposure', 'Ship remediation and prepare disclosure', 'CRITICAL', 'PSIRT Lead', 14, 'Firmware patch readiness', 'PLANNED', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z');
"#;

const POSTGRES_DEMO_SEED: &str = r#"
INSERT INTO organizations_tenant (
    id, created_at, updated_at, name, slug, country, operation_countries, description, sector,
    employee_count, annual_revenue_million, balance_sheet_million, critical_services,
    supply_chain_role, nis2_relevant, kritis_relevant, develops_digital_products, uses_ai_systems,
    ot_iacs_scope, automotive_scope, psirt_defined, sbom_required, product_security_scope
) VALUES (
    1, '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z', 'ISCY Demo Tenant', 'demo',
    'DE', '["DE"]', 'Rust-only demo tenant', 'MSSP', 80, '12.50', '8.00',
    'Managed security services', 'B2B security provider', TRUE, FALSE, TRUE, TRUE, FALSE, FALSE, TRUE, TRUE,
    'Product security scope prepared for Rust cutover'
) ON CONFLICT (id) DO NOTHING;
INSERT INTO accounts_user (
    id, password, username, first_name, last_name, email, is_staff, is_active, date_joined, role, job_title, tenant_id
) VALUES (
    1, 'pbkdf2_sha256$720000$iscy-demo-salt$dHYZBIWxS3abL+0r4Rp7w3kbLXLSAFUrGq/HaPlAVrY=',
    'admin', 'Demo', 'Admin', 'admin@example.com', TRUE, TRUE, '2026-04-22T10:00:00Z',
    'ADMIN', 'Security Lead', 1
) ON CONFLICT (id) DO UPDATE SET
    password = EXCLUDED.password,
    username = EXCLUDED.username,
    first_name = EXCLUDED.first_name,
    last_name = EXCLUDED.last_name,
    email = EXCLUDED.email,
    is_staff = EXCLUDED.is_staff,
    is_active = EXCLUDED.is_active,
    role = EXCLUDED.role,
    job_title = EXCLUDED.job_title,
    tenant_id = EXCLUDED.tenant_id;
INSERT INTO accounts_role (code, label, description) VALUES
    ('ADMIN', 'Administrator', 'Full tenant administration and write access'),
    ('MANAGEMENT', 'Management', 'Management oversight'),
    ('CISO', 'CISO / Security Officer', 'Security leadership'),
    ('ISMS_MANAGER', 'ISMS Manager', 'ISMS program management'),
    ('COMPLIANCE_MANAGER', 'Compliance Manager', 'Compliance program management'),
    ('PROCESS_OWNER', 'Process Owner', 'Process ownership'),
    ('RISK_OWNER', 'Risk Owner', 'Risk ownership'),
    ('AUDITOR', 'Auditor', 'Read-only audit access'),
    ('CONTRIBUTOR', 'Contributor', 'Operational write access')
ON CONFLICT (code) DO UPDATE SET
    label = EXCLUDED.label,
    description = EXCLUDED.description;
INSERT INTO accounts_userrole (user_id, role_id, scope_tenant_id, granted_at, granted_by_id)
SELECT 1, id, 1, '2026-04-22T10:00:00Z', NULL FROM accounts_role WHERE code = 'ADMIN'
ON CONFLICT DO NOTHING;
INSERT INTO django_content_type (app_label, model) VALUES
    ('accounts', 'user'),
    ('accounts', 'role'),
    ('organizations', 'tenant')
ON CONFLICT (app_label, model) DO NOTHING;
INSERT INTO auth_permission (name, content_type_id, codename)
SELECT 'Can view user', id, 'view_user' FROM django_content_type WHERE app_label = 'accounts' AND model = 'user'
ON CONFLICT (content_type_id, codename) DO NOTHING;
INSERT INTO auth_permission (name, content_type_id, codename)
SELECT 'Can add user', id, 'add_user' FROM django_content_type WHERE app_label = 'accounts' AND model = 'user'
ON CONFLICT (content_type_id, codename) DO NOTHING;
INSERT INTO auth_permission (name, content_type_id, codename)
SELECT 'Can change user', id, 'change_user' FROM django_content_type WHERE app_label = 'accounts' AND model = 'user'
ON CONFLICT (content_type_id, codename) DO NOTHING;
INSERT INTO auth_permission (name, content_type_id, codename)
SELECT 'Can delete user', id, 'delete_user' FROM django_content_type WHERE app_label = 'accounts' AND model = 'user'
ON CONFLICT (content_type_id, codename) DO NOTHING;
INSERT INTO auth_permission (name, content_type_id, codename)
SELECT 'Can view role', id, 'view_role' FROM django_content_type WHERE app_label = 'accounts' AND model = 'role'
ON CONFLICT (content_type_id, codename) DO NOTHING;
INSERT INTO auth_permission (name, content_type_id, codename)
SELECT 'Can change tenant', id, 'change_tenant' FROM django_content_type WHERE app_label = 'organizations' AND model = 'tenant'
ON CONFLICT (content_type_id, codename) DO NOTHING;
INSERT INTO auth_group (name) VALUES
    ('Administrators'),
    ('Auditors'),
    ('Contributors')
ON CONFLICT (name) DO NOTHING;
INSERT INTO auth_group_permissions (group_id, permission_id)
SELECT g.id, p.id
FROM auth_group g
JOIN auth_permission p ON TRUE
WHERE g.name = 'Administrators'
ON CONFLICT DO NOTHING;
INSERT INTO auth_group_permissions (group_id, permission_id)
SELECT g.id, p.id
FROM auth_group g
JOIN auth_permission p ON p.codename IN ('view_user', 'view_role')
WHERE g.name = 'Auditors'
ON CONFLICT DO NOTHING;
INSERT INTO auth_group_permissions (group_id, permission_id)
SELECT g.id, p.id
FROM auth_group g
JOIN auth_permission p ON p.codename IN ('view_user')
WHERE g.name = 'Contributors'
ON CONFLICT DO NOTHING;
INSERT INTO accounts_user_groups (user_id, group_id)
SELECT 1, id FROM auth_group WHERE name = 'Administrators'
ON CONFLICT DO NOTHING;
INSERT INTO organizations_businessunit (
    id, tenant_id, name, owner_id, created_at, updated_at
) VALUES (
    1, 1, 'Security Operations', 1, '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
) ON CONFLICT (id) DO NOTHING;
INSERT INTO processes_process (
    id, tenant_id, business_unit_id, owner_id, name, scope, description, status,
    documented, approved, communicated, implemented, effective, evidenced, reviewed_at, created_at, updated_at
) VALUES (
    1, 1, 1, 1, 'Incident Intake', 'SOC', 'SOC intake process', 'PARTIAL',
    TRUE, TRUE, TRUE, TRUE, FALSE, FALSE, '2026-04-22', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
) ON CONFLICT (id) DO NOTHING;
INSERT INTO assets_app_informationasset (
    id, tenant_id, business_unit_id, owner_id, name, asset_type, criticality, description,
    confidentiality, integrity, availability, lifecycle_status, is_in_scope, created_at, updated_at
) VALUES (
    1, 1, 1, 1, 'Customer Portal', 'APPLICATION', 'HIGH', 'External customer platform',
    'HIGH', 'HIGH', 'MEDIUM', 'active', TRUE, '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
) ON CONFLICT (id) DO NOTHING;
INSERT INTO risks_riskcategory (id, tenant_id, name)
VALUES (1, 1, 'Cyber Risk') ON CONFLICT (id) DO NOTHING;
INSERT INTO risks_risk (
    id, tenant_id, category_id, process_id, asset_id, owner_id, title, description, threat,
    vulnerability, impact, likelihood, residual_impact, residual_likelihood, status,
    treatment_strategy, treatment_plan, treatment_due_date, accepted_by_id, accepted_at,
    review_date, created_at, updated_at
) VALUES (
    1, 1, 1, 1, 1, 1, 'Credential Phishing', 'Credential theft via phishing',
    'Phishing campaign', 'Weak MFA coverage', 5, 4, 3, 3, 'TREATING', 'MITIGATE',
    'Roll out phishing-resistant MFA', '2026-06-30', NULL, NULL, '2026-07-15',
    '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
) ON CONFLICT (id) DO NOTHING;
INSERT INTO wizard_assessmentsession (
    id, tenant_id, started_by_id, assessment_type, status, current_step, applicability_result,
    applicability_reasoning, executive_summary, progress_percent, completed_at, created_at, updated_at
) VALUES (
    1, 1, 1, 'NIS2', 'COMPLETED', 'results', 'relevant',
    'Demo tenant is relevant for NIS2 planning.', 'Rust demo assessment completed.',
    100, '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
) ON CONFLICT (id) DO NOTHING;
INSERT INTO requirements_app_mappingversion (
    id, framework, slug, title, version, program_name, status, effective_on, notes, created_at, updated_at
) VALUES (
    1, 'NIS2', 'nis2-demo', 'NIS2 Demo Mapping', '2024', 'NIS2', 'ACTIVE',
    '2026-01-01', 'Rust demo mapping.', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
) ON CONFLICT (id) DO NOTHING;
INSERT INTO requirements_app_regulatorysource (
    id, framework, mapping_version_id, code, title, authority, citation, url, source_type,
    published_on, effective_on, notes, created_at, updated_at
) VALUES (
    1, 'NIS2', 1, 'NIS2-21', 'Article 21', 'EU', 'NIS2 Article 21', '', 'LAW',
    NULL, '2024-10-18', '', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
) ON CONFLICT (id) DO NOTHING;
INSERT INTO requirements_app_requirement (
    id, framework, code, title, domain, description, guidance, is_active, evidence_required,
    evidence_guidance, evidence_examples, sector_package, legal_reference, mapped_controls,
    mapping_rationale, coverage_level, mapping_version_id, primary_source_id, created_at, updated_at
) VALUES (
    1, 'NIS2', 'NIS2-21-MFA', 'MFA for privileged access', 'Identity',
    'Privileged access should use strong authentication.', 'Implement MFA.',
    TRUE, TRUE, 'Provide MFA policy and rollout evidence.', 'Policy, screenshots, reports',
    'MSSP', 'Art. 21', 'ISO A.5.15', 'Core access control mapping.', 'FULL', 1, 1,
    '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
) ON CONFLICT (id) DO NOTHING;
INSERT INTO evidence_evidenceitem (
    id, tenant_id, session_id, domain_id, measure_id, requirement_id, title, description,
    linked_requirement, file, status, owner_id, review_notes, reviewed_by_id, reviewed_at, created_at, updated_at
) VALUES (
    1, 1, 1, NULL, NULL, 1, 'MFA rollout evidence', 'Initial MFA rollout evidence.',
    'NIS2-21-MFA', NULL, 'APPROVED', 1, 'Looks ready for demo.', 1, '2026-04-22T10:00:00Z',
    '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
) ON CONFLICT (id) DO NOTHING;
INSERT INTO evidence_requirementevidenceneed (
    id, tenant_id, session_id, requirement_id, title, description, is_mandatory, status,
    rationale, covered_count, created_at, updated_at
) VALUES (
    1, 1, 1, 1, 'MFA rollout evidence needed', 'Upload rollout artefacts.', TRUE,
    'COVERED', 'Demo evidence is present.', 1, '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
) ON CONFLICT (id) DO NOTHING;
INSERT INTO reports_reportsnapshot (
    id, tenant_id, session_id, title, executive_summary, applicability_result,
    iso_readiness_percent, nis2_readiness_percent, kritis_readiness_percent, cra_readiness_percent,
    ai_act_readiness_percent, iec62443_readiness_percent, iso_sae_21434_readiness_percent,
    regulatory_matrix_json, compliance_versions_json, product_security_json, top_gaps_json,
    top_measures_json, roadmap_summary, domain_scores_json, next_steps_json, created_at, updated_at
) VALUES (
    1, 1, 1, 'Rust Demo Readiness', 'Initial Rust demo readiness snapshot.', 'relevant',
    72, 81, 20, 35, 30, 25, 28, '{"overall":"medium"}', '{"NIS2":{"version":"2024"}}',
    '{"sbom_required":true}', '[{"title":"MFA rollout gap"}]',
    '[{"title":"Complete MFA rollout","priority":"HIGH"}]', '[{"name":"Phase 1"}]',
    '[{"domain":"Identity","score_percent":81}]', '{"dependencies":[]}',
    '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
) ON CONFLICT (id) DO NOTHING;
INSERT INTO roadmap_roadmapplan (
    id, tenant_id, session_id, title, summary, overall_priority, planned_start, created_at, updated_at
) VALUES (
    1, 1, 1, 'Rust Cutover Roadmap', 'Complete Rust operational cutover path.',
    'HIGH', '2026-05-01', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
) ON CONFLICT (id) DO NOTHING;
INSERT INTO roadmap_roadmapphase (
    id, plan_id, name, sort_order, objective, duration_weeks, planned_start, planned_end, created_at, updated_at
) VALUES (
    1, 1, 'Operational Core', 1, 'Run ISCY core flows from Rust.', 2,
    '2026-05-01', '2026-05-14', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
) ON CONFLICT (id) DO NOTHING;
INSERT INTO roadmap_roadmaptask (
    id, phase_id, measure_id, title, description, priority, owner_role, due_in_days,
    dependency_text, status, planned_start, due_date, notes, created_at, updated_at
) VALUES (
    1, 1, NULL, 'Replace Django migration dependency', 'Move schema bootstrap into Rust.',
    'HIGH', 'Rust Engineer', 14, '', 'OPEN', '2026-05-01', '2026-05-14', '',
    '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
) ON CONFLICT (id) DO NOTHING;
INSERT INTO organizations_supplier (id, tenant_id, name, service_description, criticality, owner_id, created_at, updated_at)
VALUES (1000, 1, 'Rust Secure Supplier', 'Firmware component supplier', 'HIGH', 1, '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z')
ON CONFLICT (id) DO NOTHING;
INSERT INTO product_security_productfamily (id, tenant_id, name, description, created_at, updated_at)
VALUES (1000, 1, 'Rust Gateways', 'Rust-native secure product family', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z')
ON CONFLICT (id) DO NOTHING;
INSERT INTO product_security_product (
    id, tenant_id, family_id, name, code, description, has_digital_elements, includes_ai,
    ot_iacs_context, automotive_context, support_window_months, regulatory_profile_json,
    created_at, updated_at
) VALUES (
    1100, 1, 1000, 'Rust Sensor Gateway', 'rust-sensor-gateway',
    'Rust demo industrial edge device', TRUE, TRUE, TRUE, FALSE, 36, '{}',
    '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
) ON CONFLICT (id) DO NOTHING;
INSERT INTO product_security_productrelease (
    id, tenant_id, product_id, version, status, release_date, support_end_date, created_at, updated_at
) VALUES
    (1200, 1, 1100, '1.0', 'ACTIVE', '2026-04-01', '2028-04-01', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'),
    (1201, 1, 1100, '0.9', 'EOL', '2025-01-01', '2026-01-01', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z')
ON CONFLICT (id) DO NOTHING;
INSERT INTO product_security_component (
    id, tenant_id, product_id, supplier_id, name, component_type, version, is_open_source, has_sbom, created_at, updated_at
) VALUES (
    1250, 1, 1100, 1000, 'Rust Gateway Firmware', 'FIRMWARE', '1.0.3',
    FALSE, TRUE, '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
) ON CONFLICT (id) DO NOTHING;
INSERT INTO product_security_aisystem (
    id, tenant_id, product_id, name, use_case, provider, risk_classification, in_scope, created_at, updated_at
) VALUES (
    1260, 1, 1100, 'Rust Gateway Assistant', 'Firmware triage and support guidance',
    'Internal', 'LIMITED', TRUE, '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
) ON CONFLICT (id) DO NOTHING;
INSERT INTO product_security_threatmodel (
    id, tenant_id, product_id, release_id, name, methodology, summary, status, created_at, updated_at
) VALUES (
    1300, 1, 1100, 1200, 'Rust Gateway Threat Model', 'STRIDE',
    'Rust demo threat model summary', 'APPROVED', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
) ON CONFLICT (id) DO NOTHING;
INSERT INTO product_security_threatscenario (
    id, tenant_id, threat_model_id, component_id, title, category, attack_path, impact,
    severity, mitigation_status, created_at, updated_at
) VALUES (
    1301, 1, 1300, 1250, 'Unsigned Rust firmware update', 'TAMPERING',
    'Attacker replaces firmware package', 'Remote code execution', 'CRITICAL', 'Open',
    '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
) ON CONFLICT (id) DO NOTHING;
INSERT INTO product_security_tara (
    id, tenant_id, product_id, release_id, scenario_id, name, summary, attack_feasibility,
    impact_score, risk_score, status, treatment_decision, created_at, updated_at
) VALUES (
    1400, 1, 1100, 1200, 1301, 'Rust Gateway TARA', 'TARA for firmware update abuse',
    3, 4, 12, 'OPEN', 'Mitigate in next firmware release',
    '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
) ON CONFLICT (id) DO NOTHING;
INSERT INTO product_security_vulnerability (
    id, tenant_id, product_id, release_id, component_id, title, cve, severity, status,
    remediation_due, summary, created_at, updated_at
) VALUES
    (1500, 1, 1100, 1200, 1250, 'Rust critical firmware exposure', 'CVE-2026-0001', 'CRITICAL', 'OPEN', '2026-05-18', 'Critical issue in firmware updater', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'),
    (1501, 1, 1100, 1200, 1250, 'Rust outdated dependency', '', 'HIGH', 'TRIAGED', '2026-06-01', 'Dependency needs update', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'),
    (1502, 1, 1100, 1200, 1250, 'Rust fixed UI issue', '', 'LOW', 'FIXED', NULL, 'Already fixed', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z')
ON CONFLICT (id) DO NOTHING;
INSERT INTO product_security_psirtcase (
    id, tenant_id, product_id, release_id, vulnerability_id, case_id, title, severity,
    status, disclosure_due, summary, created_at, updated_at
) VALUES (
    1600, 1, 1100, 1200, 1500, 'RUST-PSIRT-1', 'Rust critical firmware disclosure',
    'CRITICAL', 'TRIAGE', '2026-05-20', 'PSIRT case for Rust firmware exposure',
    '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
) ON CONFLICT (id) DO NOTHING;
INSERT INTO product_security_securityadvisory (
    id, tenant_id, product_id, release_id, psirt_case_id, advisory_id, title, status,
    published_on, summary, created_at, updated_at
) VALUES (
    1700, 1, 1100, 1200, 1600, 'RUST-ADV-1', 'Rust gateway firmware advisory',
    'PUBLISHED', '2026-05-21', 'Advisory for Rust firmware exposure',
    '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
) ON CONFLICT (id) DO NOTHING;
INSERT INTO product_security_productsecuritysnapshot (
    id, tenant_id, product_id, cra_applicable, ai_act_applicable, iec62443_applicable,
    iso_sae_21434_applicable, cra_readiness_percent, ai_act_readiness_percent,
    iec62443_readiness_percent, iso_sae_21434_readiness_percent,
    threat_model_coverage_percent, psirt_readiness_percent, open_vulnerability_count,
    critical_vulnerability_count, summary, created_at, updated_at
) VALUES (
    1800, 1, 1100, TRUE, TRUE, TRUE, FALSE, 73, 62, 59, 0, 41, 56, 2, 1,
    'Rust Product Security snapshot', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
) ON CONFLICT (id) DO NOTHING;
INSERT INTO product_security_productsecurityroadmap (
    id, tenant_id, product_id, title, summary, generated_from_snapshot_id, created_at, updated_at
) VALUES (
    1900, 1, 1100, 'Rust Gateway Roadmap', 'Roadmap from Rust DB bootstrap',
    1800, '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'
) ON CONFLICT (id) DO NOTHING;
INSERT INTO product_security_productsecurityroadmaptask (
    id, tenant_id, roadmap_id, related_release_id, related_vulnerability_id, phase, title,
    description, priority, owner_role, due_in_days, dependency_text, status, created_at, updated_at
) VALUES
    (1901, 1, 1900, 1200, NULL, 'GOVERNANCE', 'Define Rust product security ownership', 'Clarify owner roles and release gates', 'HIGH', 'Product Security Lead', 30, '', 'OPEN', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z'),
    (1902, 1, 1900, 1200, 1500, 'RESPONSE', 'Remediate Rust critical firmware exposure', 'Ship remediation and prepare disclosure', 'CRITICAL', 'PSIRT Lead', 14, 'Firmware patch readiness', 'PLANNED', '2026-04-22T10:00:00Z', '2026-04-22T10:00:00Z')
ON CONFLICT (id) DO NOTHING;
"#;

#[cfg(test)]
mod tests {
    use super::split_sql_script;

    #[test]
    fn split_sql_script_keeps_semicolons_inside_strings() {
        let statements = split_sql_script(
            "INSERT INTO example (text) VALUES ('alpha; beta');\n\
             INSERT INTO example (text) VALUES ('it''s ok');",
        );

        assert_eq!(statements.len(), 2);
        assert_eq!(
            statements[0],
            "INSERT INTO example (text) VALUES ('alpha; beta')"
        );
        assert_eq!(
            statements[1],
            "INSERT INTO example (text) VALUES ('it''s ok')"
        );
    }
}
