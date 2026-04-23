use std::{fs::File, io::Read};

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Row,
};

use crate::{
    auth_store::{make_django_pbkdf2_sha256_password, roles_from_codes},
    cve_store::normalize_database_url,
};

#[derive(Clone)]
pub enum AccountStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountRole {
    pub id: i64,
    pub code: String,
    pub label: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountGroup {
    pub id: i64,
    pub name: String,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountPermission {
    pub id: i64,
    pub codename: String,
    pub name: String,
    pub app_label: String,
    pub model: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountUser {
    pub id: i64,
    pub tenant_id: Option<i64>,
    pub username: String,
    pub display_name: String,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub role: String,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
    pub job_title: String,
    pub is_staff: bool,
    pub is_superuser: bool,
    pub is_active: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccountUserWriteRequest {
    pub username: Option<String>,
    pub password: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub email: Option<String>,
    pub role: Option<String>,
    pub roles: Option<Vec<String>>,
    pub groups: Option<Vec<String>>,
    pub job_title: Option<String>,
    pub is_staff: Option<bool>,
    pub is_superuser: Option<bool>,
    pub is_active: Option<bool>,
}

impl AccountStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Account-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Account-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-Account-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn list_users(&self, tenant_id: i64) -> anyhow::Result<Vec<AccountUser>> {
        match self {
            Self::Postgres(pool) => {
                let rows = sqlx::query(account_users_postgres_sql())
                    .bind(tenant_id)
                    .fetch_all(pool)
                    .await
                    .context("PostgreSQL-Account-User konnten nicht gelesen werden")?;
                rows.into_iter()
                    .map(user_from_pg_row)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(Into::into)
            }
            Self::Sqlite(pool) => {
                let rows = sqlx::query(account_users_sqlite_sql())
                    .bind(tenant_id)
                    .fetch_all(pool)
                    .await
                    .context("SQLite-Account-User konnten nicht gelesen werden")?;
                rows.into_iter()
                    .map(user_from_sqlite_row)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(Into::into)
            }
        }
    }

    pub async fn list_roles(&self) -> anyhow::Result<Vec<AccountRole>> {
        match self {
            Self::Postgres(pool) => {
                let rows = sqlx::query(account_roles_sql())
                    .fetch_all(pool)
                    .await
                    .context("PostgreSQL-Account-Rollen konnten nicht gelesen werden")?;
                rows.into_iter()
                    .map(role_from_pg_row)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(Into::into)
            }
            Self::Sqlite(pool) => {
                let rows = sqlx::query(account_roles_sql())
                    .fetch_all(pool)
                    .await
                    .context("SQLite-Account-Rollen konnten nicht gelesen werden")?;
                rows.into_iter()
                    .map(role_from_sqlite_row)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(Into::into)
            }
        }
    }

    pub async fn list_groups(&self) -> anyhow::Result<Vec<AccountGroup>> {
        match self {
            Self::Postgres(pool) => {
                let rows = sqlx::query(account_groups_postgres_sql())
                    .fetch_all(pool)
                    .await
                    .context("PostgreSQL-Account-Gruppen konnten nicht gelesen werden")?;
                rows.into_iter()
                    .map(group_from_pg_row)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(Into::into)
            }
            Self::Sqlite(pool) => {
                let rows = sqlx::query(account_groups_sqlite_sql())
                    .fetch_all(pool)
                    .await
                    .context("SQLite-Account-Gruppen konnten nicht gelesen werden")?;
                rows.into_iter()
                    .map(group_from_sqlite_row)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(Into::into)
            }
        }
    }

    pub async fn list_permissions(&self) -> anyhow::Result<Vec<AccountPermission>> {
        match self {
            Self::Postgres(pool) => {
                let rows = sqlx::query(account_permissions_sql())
                    .fetch_all(pool)
                    .await
                    .context("PostgreSQL-Account-Permissions konnten nicht gelesen werden")?;
                rows.into_iter()
                    .map(permission_from_pg_row)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(Into::into)
            }
            Self::Sqlite(pool) => {
                let rows = sqlx::query(account_permissions_sql())
                    .fetch_all(pool)
                    .await
                    .context("SQLite-Account-Permissions konnten nicht gelesen werden")?;
                rows.into_iter()
                    .map(permission_from_sqlite_row)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(Into::into)
            }
        }
    }

    pub async fn create_user(
        &self,
        tenant_id: i64,
        granted_by_id: i64,
        payload: AccountUserWriteRequest,
    ) -> anyhow::Result<AccountUser> {
        let username = required_text(payload.username.as_deref(), "username")?;
        let password = required_text(payload.password.as_deref(), "password")?;
        let roles = role_codes_for_create(payload.role.as_deref(), payload.roles.as_deref());
        let groups = payload
            .groups
            .as_deref()
            .map(group_names_from_list)
            .unwrap_or_default();
        let legacy_role = roles
            .first()
            .cloned()
            .unwrap_or_else(|| "CONTRIBUTOR".to_string());
        let password_hash = make_django_pbkdf2_sha256_password(&password, &generate_salt()?);
        let first_name = optional_text(payload.first_name.as_deref()).unwrap_or_default();
        let last_name = optional_text(payload.last_name.as_deref()).unwrap_or_default();
        let email = optional_text(payload.email.as_deref()).unwrap_or_default();
        let job_title = optional_text(payload.job_title.as_deref()).unwrap_or_default();
        let is_staff = payload.is_staff.unwrap_or(false);
        let is_superuser = payload.is_superuser.unwrap_or(false);
        let is_active = payload.is_active.unwrap_or(true);

        match self {
            Self::Postgres(pool) => {
                ensure_roles_exist_postgres(pool, &roles).await?;
                ensure_groups_exist_postgres(pool, &groups).await?;
                let row = sqlx::query(
                    r#"
                    INSERT INTO accounts_user (
                        password, is_superuser, username, first_name, last_name, email,
                        is_staff, is_active, date_joined, role, job_title, tenant_id
                    ) VALUES (
                        $1, $2, $3, $4, $5, $6,
                        $7, $8, NOW(), $9, $10, $11
                    )
                    RETURNING id
                    "#,
                )
                .bind(&password_hash)
                .bind(is_superuser)
                .bind(&username)
                .bind(&first_name)
                .bind(&last_name)
                .bind(&email)
                .bind(is_staff)
                .bind(is_active)
                .bind(&legacy_role)
                .bind(&job_title)
                .bind(tenant_id)
                .fetch_one(pool)
                .await
                .context("PostgreSQL-Account-User konnte nicht erstellt werden")?;
                let user_id: i64 = row.try_get("id")?;
                replace_user_roles_postgres(pool, tenant_id, user_id, granted_by_id, &roles)
                    .await?;
                replace_user_groups_postgres(pool, user_id, &groups).await?;
                self.user_detail(tenant_id, user_id)
                    .await?
                    .context("Erstellter Account-User wurde nicht gefunden")
            }
            Self::Sqlite(pool) => {
                ensure_roles_exist_sqlite(pool, &roles).await?;
                ensure_groups_exist_sqlite(pool, &groups).await?;
                let row = sqlx::query(
                    r#"
                    INSERT INTO accounts_user (
                        password, is_superuser, username, first_name, last_name, email,
                        is_staff, is_active, date_joined, role, job_title, tenant_id
                    ) VALUES (
                        ?1, ?2, ?3, ?4, ?5, ?6,
                        ?7, ?8, datetime('now'), ?9, ?10, ?11
                    )
                    RETURNING id
                    "#,
                )
                .bind(&password_hash)
                .bind(is_superuser)
                .bind(&username)
                .bind(&first_name)
                .bind(&last_name)
                .bind(&email)
                .bind(is_staff)
                .bind(is_active)
                .bind(&legacy_role)
                .bind(&job_title)
                .bind(tenant_id)
                .fetch_one(pool)
                .await
                .context("SQLite-Account-User konnte nicht erstellt werden")?;
                let user_id: i64 = row.try_get("id")?;
                replace_user_roles_sqlite(pool, tenant_id, user_id, granted_by_id, &roles).await?;
                replace_user_groups_sqlite(pool, user_id, &groups).await?;
                self.user_detail(tenant_id, user_id)
                    .await?
                    .context("Erstellter Account-User wurde nicht gefunden")
            }
        }
    }

    pub async fn update_user(
        &self,
        tenant_id: i64,
        user_id: i64,
        granted_by_id: i64,
        payload: AccountUserWriteRequest,
    ) -> anyhow::Result<Option<AccountUser>> {
        let Some(existing) = self.user_detail(tenant_id, user_id).await? else {
            return Ok(None);
        };
        let roles = payload
            .roles
            .as_deref()
            .map(role_codes_from_list)
            .or_else(|| {
                payload
                    .role
                    .as_deref()
                    .map(|role| vec![normalize_role(role)])
            });
        let groups = payload.groups.as_deref().map(group_names_from_list);
        let legacy_role = roles
            .as_ref()
            .and_then(|roles| roles.first().cloned())
            .or_else(|| payload.role.as_deref().map(normalize_role))
            .unwrap_or(existing.role);
        let username = match payload.username.as_deref() {
            Some(username) => required_text(Some(username), "username")?,
            None => existing.username,
        };
        let first_name = text_update(payload.first_name.as_deref()).unwrap_or(existing.first_name);
        let last_name = text_update(payload.last_name.as_deref()).unwrap_or(existing.last_name);
        let email = text_update(payload.email.as_deref()).unwrap_or(existing.email);
        let job_title = text_update(payload.job_title.as_deref()).unwrap_or(existing.job_title);
        let is_staff = payload.is_staff.unwrap_or(existing.is_staff);
        let is_superuser = payload.is_superuser.unwrap_or(existing.is_superuser);
        let is_active = payload.is_active.unwrap_or(existing.is_active);
        let password_hash = if let Some(password) = optional_text(payload.password.as_deref()) {
            Some(make_django_pbkdf2_sha256_password(
                &password,
                &generate_salt()?,
            ))
        } else {
            None
        };

        match self {
            Self::Postgres(pool) => {
                if let Some(roles) = roles.as_ref() {
                    ensure_roles_exist_postgres(pool, roles).await?;
                }
                if let Some(groups) = groups.as_ref() {
                    ensure_groups_exist_postgres(pool, groups).await?;
                }
                sqlx::query(
                    r#"
                    UPDATE accounts_user
                    SET password = COALESCE($3, password),
                        is_superuser = $4,
                        username = $5,
                        first_name = $6,
                        last_name = $7,
                        email = $8,
                        is_staff = $9,
                        is_active = $10,
                        role = $11,
                        job_title = $12
                    WHERE id = $1 AND tenant_id = $2
                    "#,
                )
                .bind(user_id)
                .bind(tenant_id)
                .bind(password_hash.as_deref())
                .bind(is_superuser)
                .bind(&username)
                .bind(&first_name)
                .bind(&last_name)
                .bind(&email)
                .bind(is_staff)
                .bind(is_active)
                .bind(&legacy_role)
                .bind(&job_title)
                .execute(pool)
                .await
                .context("PostgreSQL-Account-User konnte nicht aktualisiert werden")?;
                if let Some(roles) = roles {
                    replace_user_roles_postgres(pool, tenant_id, user_id, granted_by_id, &roles)
                        .await?;
                }
                if let Some(groups) = groups {
                    replace_user_groups_postgres(pool, user_id, &groups).await?;
                }
            }
            Self::Sqlite(pool) => {
                if let Some(roles) = roles.as_ref() {
                    ensure_roles_exist_sqlite(pool, roles).await?;
                }
                if let Some(groups) = groups.as_ref() {
                    ensure_groups_exist_sqlite(pool, groups).await?;
                }
                sqlx::query(
                    r#"
                    UPDATE accounts_user
                    SET password = COALESCE(?3, password),
                        is_superuser = ?4,
                        username = ?5,
                        first_name = ?6,
                        last_name = ?7,
                        email = ?8,
                        is_staff = ?9,
                        is_active = ?10,
                        role = ?11,
                        job_title = ?12
                    WHERE id = ?1 AND tenant_id = ?2
                    "#,
                )
                .bind(user_id)
                .bind(tenant_id)
                .bind(password_hash.as_deref())
                .bind(is_superuser)
                .bind(&username)
                .bind(&first_name)
                .bind(&last_name)
                .bind(&email)
                .bind(is_staff)
                .bind(is_active)
                .bind(&legacy_role)
                .bind(&job_title)
                .execute(pool)
                .await
                .context("SQLite-Account-User konnte nicht aktualisiert werden")?;
                if let Some(roles) = roles {
                    replace_user_roles_sqlite(pool, tenant_id, user_id, granted_by_id, &roles)
                        .await?;
                }
                if let Some(groups) = groups {
                    replace_user_groups_sqlite(pool, user_id, &groups).await?;
                }
            }
        }
        self.user_detail(tenant_id, user_id).await
    }

    async fn user_detail(
        &self,
        tenant_id: i64,
        user_id: i64,
    ) -> anyhow::Result<Option<AccountUser>> {
        match self {
            Self::Postgres(pool) => {
                let row = sqlx::query(account_user_detail_postgres_sql())
                    .bind(tenant_id)
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await
                    .context("PostgreSQL-Account-User konnte nicht gelesen werden")?;
                row.map(user_from_pg_row).transpose().map_err(Into::into)
            }
            Self::Sqlite(pool) => {
                let row = sqlx::query(account_user_detail_sqlite_sql())
                    .bind(tenant_id)
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await
                    .context("SQLite-Account-User konnte nicht gelesen werden")?;
                row.map(user_from_sqlite_row)
                    .transpose()
                    .map_err(Into::into)
            }
        }
    }
}

fn account_roles_sql() -> &'static str {
    "SELECT id, code, label, description FROM accounts_role ORDER BY code"
}

fn account_groups_postgres_sql() -> &'static str {
    r#"
    SELECT
        g.id,
        g.name,
        COALESCE(string_agg(p.codename, ',' ORDER BY p.codename), '') AS permission_codes
    FROM auth_group g
    LEFT JOIN auth_group_permissions gp ON gp.group_id = g.id
    LEFT JOIN auth_permission p ON p.id = gp.permission_id
    GROUP BY g.id, g.name
    ORDER BY g.name
    "#
}

fn account_groups_sqlite_sql() -> &'static str {
    r#"
    SELECT
        g.id,
        g.name,
        COALESCE((
            SELECT group_concat(permission_code, ',')
            FROM (
                SELECT DISTINCT p.codename AS permission_code
                FROM auth_group_permissions gp
                JOIN auth_permission p ON p.id = gp.permission_id
                WHERE gp.group_id = g.id
                ORDER BY p.codename
            )
        ), '') AS permission_codes
    FROM auth_group g
    ORDER BY g.name
    "#
}

fn account_permissions_sql() -> &'static str {
    r#"
    SELECT p.id, p.codename, p.name, ct.app_label, ct.model
    FROM auth_permission p
    JOIN django_content_type ct ON ct.id = p.content_type_id
    ORDER BY ct.app_label, ct.model, p.codename
    "#
}

fn account_users_postgres_sql() -> &'static str {
    r#"
    SELECT
        u.id, u.tenant_id, u.username, u.first_name, u.last_name, u.email, u.role,
        COALESCE((
            SELECT string_agg(role_code, ',' ORDER BY role_code)
            FROM (
                SELECT DISTINCT r.code AS role_code
                FROM accounts_userrole ur
                JOIN accounts_role r ON r.id = ur.role_id
                WHERE ur.user_id = u.id
                  AND (ur.scope_tenant_id IS NULL OR ur.scope_tenant_id = $1)
            ) scoped_roles
        ), '') AS role_codes,
        COALESCE((
            SELECT string_agg(group_name, ',' ORDER BY group_name)
            FROM (
                SELECT DISTINCT g.name AS group_name
                FROM accounts_user_groups ug
                JOIN auth_group g ON g.id = ug.group_id
                WHERE ug.user_id = u.id
            ) user_groups
        ), '') AS group_names,
        u.job_title, u.is_staff, u.is_superuser, u.is_active
    FROM accounts_user u
    WHERE u.tenant_id = $1 OR (u.tenant_id IS NULL AND u.is_superuser = TRUE)
    ORDER BY u.is_active DESC, u.username
    "#
}

fn account_users_sqlite_sql() -> &'static str {
    r#"
    SELECT
        u.id, u.tenant_id, u.username, u.first_name, u.last_name, u.email, u.role,
        COALESCE((
            SELECT group_concat(role_code, ',')
            FROM (
                SELECT DISTINCT r.code AS role_code
                FROM accounts_userrole ur
                JOIN accounts_role r ON r.id = ur.role_id
                WHERE ur.user_id = u.id
                  AND (ur.scope_tenant_id IS NULL OR ur.scope_tenant_id = ?1)
                ORDER BY r.code
            )
        ), '') AS role_codes,
        COALESCE((
            SELECT group_concat(group_name, ',')
            FROM (
                SELECT DISTINCT g.name AS group_name
                FROM accounts_user_groups ug
                JOIN auth_group g ON g.id = ug.group_id
                WHERE ug.user_id = u.id
                ORDER BY g.name
            )
        ), '') AS group_names,
        u.job_title, u.is_staff, u.is_superuser, u.is_active
    FROM accounts_user u
    WHERE u.tenant_id = ?1 OR (u.tenant_id IS NULL AND u.is_superuser = 1)
    ORDER BY u.is_active DESC, u.username
    "#
}

fn account_user_detail_postgres_sql() -> &'static str {
    r#"
    SELECT *
    FROM (
        SELECT
            u.id, u.tenant_id, u.username, u.first_name, u.last_name, u.email, u.role,
            COALESCE((
                SELECT string_agg(role_code, ',' ORDER BY role_code)
                FROM (
                    SELECT DISTINCT r.code AS role_code
                    FROM accounts_userrole ur
                    JOIN accounts_role r ON r.id = ur.role_id
                    WHERE ur.user_id = u.id
                      AND (ur.scope_tenant_id IS NULL OR ur.scope_tenant_id = $1)
                ) scoped_roles
            ), '') AS role_codes,
            COALESCE((
                SELECT string_agg(group_name, ',' ORDER BY group_name)
                FROM (
                    SELECT DISTINCT g.name AS group_name
                    FROM accounts_user_groups ug
                    JOIN auth_group g ON g.id = ug.group_id
                    WHERE ug.user_id = u.id
                ) user_groups
            ), '') AS group_names,
            u.job_title, u.is_staff, u.is_superuser, u.is_active
        FROM accounts_user u
        WHERE u.id = $2
          AND (u.tenant_id = $1 OR (u.tenant_id IS NULL AND u.is_superuser = TRUE))
    ) scoped_user
    "#
}

fn account_user_detail_sqlite_sql() -> &'static str {
    r#"
    SELECT *
    FROM (
        SELECT
            u.id, u.tenant_id, u.username, u.first_name, u.last_name, u.email, u.role,
            COALESCE((
                SELECT group_concat(role_code, ',')
                FROM (
                    SELECT DISTINCT r.code AS role_code
                    FROM accounts_userrole ur
                    JOIN accounts_role r ON r.id = ur.role_id
                    WHERE ur.user_id = u.id
                      AND (ur.scope_tenant_id IS NULL OR ur.scope_tenant_id = ?1)
                    ORDER BY r.code
                )
            ), '') AS role_codes,
            COALESCE((
                SELECT group_concat(group_name, ',')
                FROM (
                    SELECT DISTINCT g.name AS group_name
                    FROM accounts_user_groups ug
                    JOIN auth_group g ON g.id = ug.group_id
                    WHERE ug.user_id = u.id
                    ORDER BY g.name
                )
            ), '') AS group_names,
            u.job_title, u.is_staff, u.is_superuser, u.is_active
        FROM accounts_user u
        WHERE u.id = ?2
          AND (u.tenant_id = ?1 OR (u.tenant_id IS NULL AND u.is_superuser = 1))
    ) scoped_user
    "#
}

async fn ensure_roles_exist_postgres(pool: &PgPool, roles: &[String]) -> anyhow::Result<()> {
    for role in roles.iter().filter(|role| !role.is_empty()) {
        let role_id: Option<i64> =
            sqlx::query_scalar("SELECT id FROM accounts_role WHERE code = $1")
                .bind(role)
                .fetch_optional(pool)
                .await
                .context("PostgreSQL-Account-Rolle konnte nicht validiert werden")?;
        if role_id.is_none() {
            bail!("Account-Feld roles enthaelt unbekannte Rolle {role}");
        }
    }
    Ok(())
}

async fn ensure_roles_exist_sqlite(pool: &SqlitePool, roles: &[String]) -> anyhow::Result<()> {
    for role in roles.iter().filter(|role| !role.is_empty()) {
        let role_id: Option<i64> =
            sqlx::query_scalar("SELECT id FROM accounts_role WHERE code = ?1")
                .bind(role)
                .fetch_optional(pool)
                .await
                .context("SQLite-Account-Rolle konnte nicht validiert werden")?;
        if role_id.is_none() {
            bail!("Account-Feld roles enthaelt unbekannte Rolle {role}");
        }
    }
    Ok(())
}

async fn ensure_groups_exist_postgres(pool: &PgPool, groups: &[String]) -> anyhow::Result<()> {
    for group in groups.iter().filter(|group| !group.is_empty()) {
        let group_id: Option<i64> = sqlx::query_scalar("SELECT id FROM auth_group WHERE name = $1")
            .bind(group)
            .fetch_optional(pool)
            .await
            .context("PostgreSQL-Account-Gruppe konnte nicht validiert werden")?;
        if group_id.is_none() {
            bail!("Account-Feld groups enthaelt unbekannte Gruppe {group}");
        }
    }
    Ok(())
}

async fn ensure_groups_exist_sqlite(pool: &SqlitePool, groups: &[String]) -> anyhow::Result<()> {
    for group in groups.iter().filter(|group| !group.is_empty()) {
        let group_id: Option<i64> = sqlx::query_scalar("SELECT id FROM auth_group WHERE name = ?1")
            .bind(group)
            .fetch_optional(pool)
            .await
            .context("SQLite-Account-Gruppe konnte nicht validiert werden")?;
        if group_id.is_none() {
            bail!("Account-Feld groups enthaelt unbekannte Gruppe {group}");
        }
    }
    Ok(())
}

async fn replace_user_roles_postgres(
    pool: &PgPool,
    tenant_id: i64,
    user_id: i64,
    granted_by_id: i64,
    roles: &[String],
) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM accounts_userrole WHERE user_id = $1 AND scope_tenant_id = $2")
        .bind(user_id)
        .bind(tenant_id)
        .execute(pool)
        .await
        .context("PostgreSQL-Account-Rollen konnten nicht entfernt werden")?;
    for role in roles {
        sqlx::query(
            r#"
            INSERT INTO accounts_userrole (user_id, role_id, scope_tenant_id, granted_at, granted_by_id)
            SELECT $1, id, $2, NOW(), $3 FROM accounts_role WHERE code = $4
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(granted_by_id)
        .bind(role)
        .execute(pool)
        .await
        .context("PostgreSQL-Account-Rolle konnte nicht vergeben werden")?;
    }
    Ok(())
}

async fn replace_user_roles_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    user_id: i64,
    granted_by_id: i64,
    roles: &[String],
) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM accounts_userrole WHERE user_id = ?1 AND scope_tenant_id = ?2")
        .bind(user_id)
        .bind(tenant_id)
        .execute(pool)
        .await
        .context("SQLite-Account-Rollen konnten nicht entfernt werden")?;
    for role in roles {
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO accounts_userrole (user_id, role_id, scope_tenant_id, granted_at, granted_by_id)
            SELECT ?1, id, ?2, datetime('now'), ?3 FROM accounts_role WHERE code = ?4
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(granted_by_id)
        .bind(role)
        .execute(pool)
        .await
        .context("SQLite-Account-Rolle konnte nicht vergeben werden")?;
    }
    Ok(())
}

async fn replace_user_groups_postgres(
    pool: &PgPool,
    user_id: i64,
    groups: &[String],
) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM accounts_user_groups WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .context("PostgreSQL-Account-Gruppen konnten nicht entfernt werden")?;
    for group in groups {
        sqlx::query(
            r#"
            INSERT INTO accounts_user_groups (user_id, group_id)
            SELECT $1, id FROM auth_group WHERE name = $2
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(user_id)
        .bind(group)
        .execute(pool)
        .await
        .context("PostgreSQL-Account-Gruppe konnte nicht zugeordnet werden")?;
    }
    Ok(())
}

async fn replace_user_groups_sqlite(
    pool: &SqlitePool,
    user_id: i64,
    groups: &[String],
) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM accounts_user_groups WHERE user_id = ?1")
        .bind(user_id)
        .execute(pool)
        .await
        .context("SQLite-Account-Gruppen konnten nicht entfernt werden")?;
    for group in groups {
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO accounts_user_groups (user_id, group_id)
            SELECT ?1, id FROM auth_group WHERE name = ?2
            "#,
        )
        .bind(user_id)
        .bind(group)
        .execute(pool)
        .await
        .context("SQLite-Account-Gruppe konnte nicht zugeordnet werden")?;
    }
    Ok(())
}

fn user_from_pg_row(row: PgRow) -> Result<AccountUser, sqlx::Error> {
    let first_name: String = row.try_get("first_name")?;
    let last_name: String = row.try_get("last_name")?;
    let username: String = row.try_get("username")?;
    let role: String = row.try_get("role")?;
    let role_codes: String = row.try_get("role_codes")?;
    let group_names: String = row.try_get("group_names")?;
    let is_superuser: bool = row.try_get("is_superuser")?;
    Ok(AccountUser {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        display_name: display_name(&first_name, &last_name, &username),
        username,
        first_name,
        last_name,
        email: row.try_get("email")?,
        roles: roles_from_codes(&role, &role_codes, is_superuser),
        groups: names_from_csv(&group_names),
        role,
        job_title: row.try_get("job_title")?,
        is_staff: row.try_get("is_staff")?,
        is_superuser,
        is_active: row.try_get("is_active")?,
    })
}

fn user_from_sqlite_row(row: SqliteRow) -> Result<AccountUser, sqlx::Error> {
    let first_name: String = row.try_get("first_name")?;
    let last_name: String = row.try_get("last_name")?;
    let username: String = row.try_get("username")?;
    let role: String = row.try_get("role")?;
    let role_codes: String = row.try_get("role_codes")?;
    let group_names: String = row.try_get("group_names")?;
    let is_superuser: bool = row.try_get("is_superuser")?;
    Ok(AccountUser {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        display_name: display_name(&first_name, &last_name, &username),
        username,
        first_name,
        last_name,
        email: row.try_get("email")?,
        roles: roles_from_codes(&role, &role_codes, is_superuser),
        groups: names_from_csv(&group_names),
        role,
        job_title: row.try_get("job_title")?,
        is_staff: row.try_get("is_staff")?,
        is_superuser,
        is_active: row.try_get("is_active")?,
    })
}

fn role_from_pg_row(row: PgRow) -> Result<AccountRole, sqlx::Error> {
    Ok(AccountRole {
        id: row.try_get("id")?,
        code: row.try_get("code")?,
        label: row.try_get("label")?,
        description: row.try_get("description")?,
    })
}

fn role_from_sqlite_row(row: SqliteRow) -> Result<AccountRole, sqlx::Error> {
    Ok(AccountRole {
        id: row.try_get("id")?,
        code: row.try_get("code")?,
        label: row.try_get("label")?,
        description: row.try_get("description")?,
    })
}

fn group_from_pg_row(row: PgRow) -> Result<AccountGroup, sqlx::Error> {
    let permission_codes: String = row.try_get("permission_codes")?;
    Ok(AccountGroup {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        permissions: names_from_csv(&permission_codes),
    })
}

fn group_from_sqlite_row(row: SqliteRow) -> Result<AccountGroup, sqlx::Error> {
    let permission_codes: String = row.try_get("permission_codes")?;
    Ok(AccountGroup {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        permissions: names_from_csv(&permission_codes),
    })
}

fn permission_from_pg_row(row: PgRow) -> Result<AccountPermission, sqlx::Error> {
    Ok(AccountPermission {
        id: row.try_get("id")?,
        codename: row.try_get("codename")?,
        name: row.try_get("name")?,
        app_label: row.try_get("app_label")?,
        model: row.try_get("model")?,
    })
}

fn permission_from_sqlite_row(row: SqliteRow) -> Result<AccountPermission, sqlx::Error> {
    Ok(AccountPermission {
        id: row.try_get("id")?,
        codename: row.try_get("codename")?,
        name: row.try_get("name")?,
        app_label: row.try_get("app_label")?,
        model: row.try_get("model")?,
    })
}

fn required_text(value: Option<&str>, field: &'static str) -> anyhow::Result<String> {
    optional_text(value)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Account-Feld {field} wird fuer diese Operation benoetigt"))
}

fn optional_text(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn text_update(value: Option<&str>) -> Option<String> {
    value.map(str::trim).map(ToString::to_string)
}

fn role_codes_for_create(role: Option<&str>, roles: Option<&[String]>) -> Vec<String> {
    let mut role_codes = roles.map(role_codes_from_list).unwrap_or_default();
    if role_codes.is_empty() {
        role_codes.push(
            role.map(normalize_role)
                .unwrap_or_else(|| "CONTRIBUTOR".to_string()),
        );
    }
    role_codes
}

fn role_codes_from_list(roles: &[String]) -> Vec<String> {
    roles.iter().fold(Vec::new(), |mut normalized, role| {
        let role = normalize_role(role);
        if !role.is_empty() && !normalized.iter().any(|existing| existing == &role) {
            normalized.push(role);
        }
        normalized
    })
}

fn group_names_from_list(groups: &[String]) -> Vec<String> {
    groups.iter().fold(Vec::new(), |mut normalized, group| {
        let group = group.trim().to_string();
        if !group.is_empty() && !normalized.iter().any(|existing| existing == &group) {
            normalized.push(group);
        }
        normalized
    })
}

fn names_from_csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn normalize_role(role: &str) -> String {
    role.trim().to_ascii_uppercase()
}

fn display_name(first_name: &str, last_name: &str, username: &str) -> String {
    let full_name = format!("{} {}", first_name.trim(), last_name.trim())
        .trim()
        .to_string();
    if full_name.is_empty() {
        username.to_string()
    } else {
        full_name
    }
}

fn generate_salt() -> anyhow::Result<String> {
    let mut bytes = [0_u8; 16];
    File::open("/dev/urandom")
        .context("Account-Passwort-Saltquelle /dev/urandom konnte nicht geoeffnet werden")?
        .read_exact(&mut bytes)
        .context("Account-Passwort-Salt konnte nicht erzeugt werden")?;
    Ok(hex_encode(&bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{display_name, group_names_from_list, role_codes_for_create, role_codes_from_list};

    #[test]
    fn account_roles_normalize_and_deduplicate() {
        assert_eq!(
            role_codes_from_list(&[
                "admin".to_string(),
                "ADMIN".to_string(),
                " risk_owner ".to_string()
            ]),
            vec!["ADMIN", "RISK_OWNER"]
        );
        assert_eq!(
            role_codes_for_create(Some("auditor"), None),
            vec!["AUDITOR"]
        );
        assert_eq!(role_codes_for_create(None, None), vec!["CONTRIBUTOR"]);
    }

    #[test]
    fn account_display_name_prefers_full_name() {
        assert_eq!(display_name("Ada", "Lovelace", "ada"), "Ada Lovelace");
        assert_eq!(display_name("", "", "admin"), "admin");
    }

    #[test]
    fn account_groups_trim_and_deduplicate() {
        assert_eq!(
            group_names_from_list(&[
                " Administrators ".to_string(),
                "Administrators".to_string(),
                "Auditors".to_string()
            ]),
            vec!["Administrators", "Auditors"]
        );
    }
}
