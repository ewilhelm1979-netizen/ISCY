use std::{cmp, fs::File, io::Read};

use anyhow::{bail, Context};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Row,
};

use crate::{cve_store::normalize_database_url, request_context::AuthenticatedTenantContext};

#[derive(Clone)]
pub enum AuthStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize)]
pub struct AuthUser {
    pub id: i64,
    pub tenant_id: i64,
    pub username: String,
    pub display_name: String,
    pub email: String,
    pub role: String,
    pub job_title: String,
    pub is_staff: bool,
    pub is_superuser: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthSession {
    pub token: String,
    pub tenant_id: i64,
    pub user_id: i64,
    pub user_email: Option<String>,
    pub expires_at: String,
    pub user: AuthUser,
}

struct AuthLoginCandidate {
    user: AuthUser,
    password_hash: String,
}

impl AuthStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Auth-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Auth-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-Auth-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn create_session(
        &self,
        tenant_id: i64,
        user_id: i64,
    ) -> anyhow::Result<Option<AuthSession>> {
        if tenant_id < 1 || user_id < 1 {
            return Ok(None);
        }
        let Some(user) = self.active_user_for_tenant(tenant_id, user_id).await? else {
            return Ok(None);
        };
        self.insert_session_for_user(user).await.map(Some)
    }

    pub async fn create_session_for_login(
        &self,
        tenant_id: Option<i64>,
        username_or_email: &str,
        password: &str,
    ) -> anyhow::Result<Option<AuthSession>> {
        let username_or_email = username_or_email.trim();
        if username_or_email.is_empty() || password.is_empty() {
            return Ok(None);
        }
        let Some(candidate) = self
            .active_user_for_login(tenant_id, username_or_email)
            .await?
        else {
            return Ok(None);
        };
        if !verify_django_pbkdf2_sha256_password(password, &candidate.password_hash) {
            return Ok(None);
        }
        self.insert_session_for_user(candidate.user).await.map(Some)
    }

    async fn insert_session_for_user(&self, user: AuthUser) -> anyhow::Result<AuthSession> {
        let token = generate_session_token()?;
        let created_at = Utc::now().to_rfc3339();
        let expires_at = (Utc::now() + Duration::hours(8)).to_rfc3339();
        let tenant_id = user.tenant_id;
        let user_id = user.id;
        let user_email = non_empty(user.email.clone());

        match self {
            Self::Postgres(pool) => {
                sqlx::query(
                    r#"
                    INSERT INTO iscy_auth_session
                        (token, tenant_id, user_id, user_email, created_at, expires_at, revoked_at)
                    VALUES ($1, $2, $3, $4, $5, $6, NULL)
                    "#,
                )
                .bind(&token)
                .bind(tenant_id)
                .bind(user_id)
                .bind(user_email.as_deref().unwrap_or(""))
                .bind(&created_at)
                .bind(&expires_at)
                .execute(pool)
                .await
                .context("PostgreSQL-Rust-Session konnte nicht erstellt werden")?;
            }
            Self::Sqlite(pool) => {
                sqlx::query(
                    r#"
                    INSERT INTO iscy_auth_session
                        (token, tenant_id, user_id, user_email, created_at, expires_at, revoked_at)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)
                    "#,
                )
                .bind(&token)
                .bind(tenant_id)
                .bind(user_id)
                .bind(user_email.as_deref().unwrap_or(""))
                .bind(&created_at)
                .bind(&expires_at)
                .execute(pool)
                .await
                .context("SQLite-Rust-Session konnte nicht erstellt werden")?;
            }
        }

        Ok(AuthSession {
            token,
            tenant_id,
            user_id,
            user_email,
            expires_at,
            user,
        })
    }

    pub async fn resolve_session(&self, token: &str) -> anyhow::Result<Option<AuthSession>> {
        let token = token.trim();
        if token.is_empty() {
            return Ok(None);
        }
        let now = Utc::now().to_rfc3339();
        match self {
            Self::Postgres(pool) => {
                let row = sqlx::query(session_select_postgres_sql())
                    .bind(token)
                    .bind(&now)
                    .fetch_optional(pool)
                    .await
                    .context("PostgreSQL-Rust-Session konnte nicht gelesen werden")?;
                row.map(session_from_pg_row).transpose().map_err(Into::into)
            }
            Self::Sqlite(pool) => {
                let row = sqlx::query(session_select_sqlite_sql())
                    .bind(token)
                    .bind(&now)
                    .fetch_optional(pool)
                    .await
                    .context("SQLite-Rust-Session konnte nicht gelesen werden")?;
                row.map(session_from_sqlite_row)
                    .transpose()
                    .map_err(Into::into)
            }
        }
    }

    pub async fn revoke_session(&self, token: &str) -> anyhow::Result<bool> {
        let token = token.trim();
        if token.is_empty() {
            return Ok(false);
        }
        let revoked_at = Utc::now().to_rfc3339();
        let rows = match self {
            Self::Postgres(pool) => sqlx::query(
                "UPDATE iscy_auth_session SET revoked_at = $1 WHERE token = $2 AND revoked_at IS NULL",
            )
            .bind(&revoked_at)
            .bind(token)
            .execute(pool)
            .await
            .context("PostgreSQL-Rust-Session konnte nicht beendet werden")?
            .rows_affected(),
            Self::Sqlite(pool) => sqlx::query(
                "UPDATE iscy_auth_session SET revoked_at = ?1 WHERE token = ?2 AND revoked_at IS NULL",
            )
            .bind(&revoked_at)
            .bind(token)
            .execute(pool)
            .await
            .context("SQLite-Rust-Session konnte nicht beendet werden")?
            .rows_affected(),
        };
        Ok(rows > 0)
    }

    async fn active_user_for_tenant(
        &self,
        tenant_id: i64,
        user_id: i64,
    ) -> anyhow::Result<Option<AuthUser>> {
        match self {
            Self::Postgres(pool) => {
                let row = sqlx::query(active_user_postgres_sql())
                    .bind(tenant_id)
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await
                    .context("PostgreSQL-User konnte nicht fuer Rust-Session gelesen werden")?;
                row.map(user_from_pg_row).transpose().map_err(Into::into)
            }
            Self::Sqlite(pool) => {
                let row = sqlx::query(active_user_sqlite_sql())
                    .bind(tenant_id)
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await
                    .context("SQLite-User konnte nicht fuer Rust-Session gelesen werden")?;
                row.map(user_from_sqlite_row)
                    .transpose()
                    .map_err(Into::into)
            }
        }
    }

    async fn active_user_for_login(
        &self,
        tenant_id: Option<i64>,
        username_or_email: &str,
    ) -> anyhow::Result<Option<AuthLoginCandidate>> {
        match self {
            Self::Postgres(pool) => {
                let row = sqlx::query(login_user_postgres_sql())
                    .bind(username_or_email)
                    .bind(tenant_id)
                    .fetch_optional(pool)
                    .await
                    .context("PostgreSQL-User konnte nicht fuer Rust-Login gelesen werden")?;
                row.map(login_candidate_from_pg_row)
                    .transpose()
                    .map_err(Into::into)
            }
            Self::Sqlite(pool) => {
                let row = sqlx::query(login_user_sqlite_sql())
                    .bind(username_or_email)
                    .bind(tenant_id)
                    .fetch_optional(pool)
                    .await
                    .context("SQLite-User konnte nicht fuer Rust-Login gelesen werden")?;
                row.map(login_candidate_from_sqlite_row)
                    .transpose()
                    .map_err(Into::into)
            }
        }
    }
}

impl AuthSession {
    pub fn tenant_context(&self) -> AuthenticatedTenantContext {
        AuthenticatedTenantContext {
            tenant_id: self.tenant_id,
            user_id: self.user_id,
            user_email: self.user_email.clone(),
        }
    }
}

fn active_user_postgres_sql() -> &'static str {
    r#"
    SELECT
        id,
        COALESCE(tenant_id, $1)::bigint AS tenant_id,
        username,
        first_name,
        last_name,
        email,
        role,
        job_title,
        is_staff,
        is_superuser
    FROM accounts_user
    WHERE id = $2
      AND is_active = TRUE
      AND (tenant_id = $1 OR (tenant_id IS NULL AND is_superuser = TRUE))
    "#
}

fn active_user_sqlite_sql() -> &'static str {
    r#"
    SELECT
        id,
        COALESCE(tenant_id, ?1) AS tenant_id,
        username,
        first_name,
        last_name,
        email,
        role,
        job_title,
        is_staff,
        is_superuser
    FROM accounts_user
    WHERE id = ?2
      AND is_active = 1
      AND (tenant_id = ?1 OR (tenant_id IS NULL AND is_superuser = 1))
    "#
}

fn login_user_postgres_sql() -> &'static str {
    r#"
    SELECT
        id,
        COALESCE(tenant_id, $2, 1)::bigint AS tenant_id,
        username,
        first_name,
        last_name,
        email,
        role,
        job_title,
        is_staff,
        is_superuser,
        password
    FROM accounts_user
    WHERE is_active = TRUE
      AND (LOWER(username) = LOWER($1) OR LOWER(email) = LOWER($1))
      AND ($2::bigint IS NULL OR tenant_id = $2 OR (tenant_id IS NULL AND is_superuser = TRUE))
    ORDER BY CASE WHEN tenant_id = $2 THEN 0 ELSE 1 END, id
    LIMIT 1
    "#
}

fn login_user_sqlite_sql() -> &'static str {
    r#"
    SELECT
        id,
        COALESCE(tenant_id, ?2, 1) AS tenant_id,
        username,
        first_name,
        last_name,
        email,
        role,
        job_title,
        is_staff,
        is_superuser,
        password
    FROM accounts_user
    WHERE is_active = 1
      AND (LOWER(username) = LOWER(?1) OR LOWER(email) = LOWER(?1))
      AND (?2 IS NULL OR tenant_id = ?2 OR (tenant_id IS NULL AND is_superuser = 1))
    ORDER BY CASE WHEN tenant_id = ?2 THEN 0 ELSE 1 END, id
    LIMIT 1
    "#
}

fn session_select_postgres_sql() -> &'static str {
    r#"
    SELECT
        s.token,
        s.tenant_id,
        s.user_id,
        COALESCE(NULLIF(s.user_email, ''), u.email) AS user_email,
        s.expires_at,
        u.id,
        COALESCE(u.tenant_id, s.tenant_id)::bigint AS user_tenant_id,
        u.username,
        u.first_name,
        u.last_name,
        u.email,
        u.role,
        u.job_title,
        u.is_staff,
        u.is_superuser
    FROM iscy_auth_session s
    JOIN accounts_user u ON u.id = s.user_id
    WHERE s.token = $1
      AND s.revoked_at IS NULL
      AND s.expires_at > $2
      AND u.is_active = TRUE
      AND (u.tenant_id = s.tenant_id OR (u.tenant_id IS NULL AND u.is_superuser = TRUE))
    "#
}

fn session_select_sqlite_sql() -> &'static str {
    r#"
    SELECT
        s.token,
        s.tenant_id,
        s.user_id,
        COALESCE(NULLIF(s.user_email, ''), u.email) AS user_email,
        s.expires_at,
        u.id,
        COALESCE(u.tenant_id, s.tenant_id) AS user_tenant_id,
        u.username,
        u.first_name,
        u.last_name,
        u.email,
        u.role,
        u.job_title,
        u.is_staff,
        u.is_superuser
    FROM iscy_auth_session s
    JOIN accounts_user u ON u.id = s.user_id
    WHERE s.token = ?1
      AND s.revoked_at IS NULL
      AND s.expires_at > ?2
      AND u.is_active = 1
      AND (u.tenant_id = s.tenant_id OR (u.tenant_id IS NULL AND u.is_superuser = 1))
    "#
}

fn user_from_pg_row(row: PgRow) -> Result<AuthUser, sqlx::Error> {
    let first_name: String = row.try_get("first_name")?;
    let last_name: String = row.try_get("last_name")?;
    let username: String = row.try_get("username")?;
    Ok(AuthUser {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        display_name: display_name(&first_name, &last_name, &username),
        username,
        email: row.try_get("email")?,
        role: row.try_get("role")?,
        job_title: row.try_get("job_title")?,
        is_staff: row.try_get("is_staff")?,
        is_superuser: row.try_get("is_superuser")?,
    })
}

fn user_from_sqlite_row(row: SqliteRow) -> Result<AuthUser, sqlx::Error> {
    let first_name: String = row.try_get("first_name")?;
    let last_name: String = row.try_get("last_name")?;
    let username: String = row.try_get("username")?;
    Ok(AuthUser {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        display_name: display_name(&first_name, &last_name, &username),
        username,
        email: row.try_get("email")?,
        role: row.try_get("role")?,
        job_title: row.try_get("job_title")?,
        is_staff: row.try_get("is_staff")?,
        is_superuser: row.try_get("is_superuser")?,
    })
}

fn login_candidate_from_pg_row(row: PgRow) -> Result<AuthLoginCandidate, sqlx::Error> {
    let password_hash: String = row.try_get("password")?;
    Ok(AuthLoginCandidate {
        user: user_from_pg_row(row)?,
        password_hash,
    })
}

fn login_candidate_from_sqlite_row(row: SqliteRow) -> Result<AuthLoginCandidate, sqlx::Error> {
    let password_hash: String = row.try_get("password")?;
    Ok(AuthLoginCandidate {
        user: user_from_sqlite_row(row)?,
        password_hash,
    })
}

fn session_from_pg_row(row: PgRow) -> Result<AuthSession, sqlx::Error> {
    let user_email: String = row.try_get("user_email")?;
    let first_name: String = row.try_get("first_name")?;
    let last_name: String = row.try_get("last_name")?;
    let username: String = row.try_get("username")?;
    let user = AuthUser {
        id: row.try_get("id")?,
        tenant_id: row.try_get("user_tenant_id")?,
        display_name: display_name(&first_name, &last_name, &username),
        username,
        email: row.try_get("email")?,
        role: row.try_get("role")?,
        job_title: row.try_get("job_title")?,
        is_staff: row.try_get("is_staff")?,
        is_superuser: row.try_get("is_superuser")?,
    };
    Ok(AuthSession {
        token: row.try_get("token")?,
        tenant_id: row.try_get("tenant_id")?,
        user_id: row.try_get("user_id")?,
        user_email: non_empty(user_email),
        expires_at: row.try_get("expires_at")?,
        user,
    })
}

fn session_from_sqlite_row(row: SqliteRow) -> Result<AuthSession, sqlx::Error> {
    let user_email: String = row.try_get("user_email")?;
    let first_name: String = row.try_get("first_name")?;
    let last_name: String = row.try_get("last_name")?;
    let username: String = row.try_get("username")?;
    let user = AuthUser {
        id: row.try_get("id")?,
        tenant_id: row.try_get("user_tenant_id")?,
        display_name: display_name(&first_name, &last_name, &username),
        username,
        email: row.try_get("email")?,
        role: row.try_get("role")?,
        job_title: row.try_get("job_title")?,
        is_staff: row.try_get("is_staff")?,
        is_superuser: row.try_get("is_superuser")?,
    };
    Ok(AuthSession {
        token: row.try_get("token")?,
        tenant_id: row.try_get("tenant_id")?,
        user_id: row.try_get("user_id")?,
        user_email: non_empty(user_email),
        expires_at: row.try_get("expires_at")?,
        user,
    })
}

fn verify_django_pbkdf2_sha256_password(password: &str, encoded: &str) -> bool {
    let parts = encoded.split('$').collect::<Vec<_>>();
    if parts.len() != 4 || parts[0] != "pbkdf2_sha256" {
        return false;
    }
    let Ok(iterations) = parts[1].parse::<u32>() else {
        return false;
    };
    if iterations == 0 {
        return false;
    }
    let Ok(expected) = BASE64_STANDARD.decode(parts[3]) else {
        return false;
    };
    if expected.is_empty() {
        return false;
    }
    let actual = pbkdf2_hmac_sha256(
        password.as_bytes(),
        parts[2].as_bytes(),
        iterations,
        expected.len(),
    );
    constant_time_eq(&actual, &expected)
}

fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, output_len: usize) -> Vec<u8> {
    let mut output = vec![0_u8; output_len];
    let mut block_index = 1_u32;
    let mut offset = 0_usize;

    while offset < output_len {
        let mut mac = HmacSha256::new_from_slice(password).expect("HMAC accepts any key length");
        mac.update(salt);
        mac.update(&block_index.to_be_bytes());
        let mut u = mac.finalize().into_bytes().to_vec();
        let mut block = u.clone();

        for _ in 1..iterations {
            let mut mac =
                HmacSha256::new_from_slice(password).expect("HMAC accepts any key length");
            mac.update(&u);
            u = mac.finalize().into_bytes().to_vec();
            for (left, right) in block.iter_mut().zip(u.iter()) {
                *left ^= *right;
            }
        }

        let take = cmp::min(block.len(), output_len - offset);
        output[offset..offset + take].copy_from_slice(&block[..take]);
        offset += take;
        block_index = block_index.saturating_add(1);
    }

    output
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (left_byte, right_byte) in left.iter().zip(right.iter()) {
        diff |= left_byte ^ right_byte;
    }
    diff == 0
}

fn generate_session_token() -> anyhow::Result<String> {
    let mut bytes = [0_u8; 32];
    File::open("/dev/urandom")
        .context("Rust-Session-Zufallsquelle /dev/urandom konnte nicht geoeffnet werden")?
        .read_exact(&mut bytes)
        .context("Rust-Session-Token konnte nicht erzeugt werden")?;
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

fn non_empty(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{display_name, hex_encode, verify_django_pbkdf2_sha256_password};

    #[test]
    fn hex_encode_writes_lowercase_hex() {
        assert_eq!(hex_encode(&[0, 10, 16, 255]), "000a10ff");
    }

    #[test]
    fn display_name_prefers_full_name() {
        assert_eq!(display_name("Ada", "Lovelace", "ada"), "Ada Lovelace");
        assert_eq!(display_name("", " ", "demo"), "demo");
    }

    #[test]
    fn verifies_django_pbkdf2_sha256_passwords() {
        let encoded = "pbkdf2_sha256$1$salt$Eg+2z/z4syxD5yJSVsT4N6hlSMkszDVICAWYfLcL4Xs=";
        assert!(verify_django_pbkdf2_sha256_password("password", encoded));
        assert!(!verify_django_pbkdf2_sha256_password(
            "wrong-password",
            encoded
        ));
        assert!(!verify_django_pbkdf2_sha256_password(
            "password",
            "argon2$1$salt$hash"
        ));
    }
}
