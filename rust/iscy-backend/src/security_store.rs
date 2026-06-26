use std::time::Duration as StdDuration;

use anyhow::{bail, Context};
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::{
    postgres::{PgPool, PgPoolOptions},
    sqlite::{SqlitePool, SqlitePoolOptions},
    Row,
};

use crate::cve_store::normalize_database_url;

#[derive(Clone)]
pub enum SecurityStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone)]
struct LoginRateLimitRow {
    failures: i64,
    first_failure_at: DateTime<Utc>,
    blocked_until: Option<DateTime<Utc>>,
}

impl SecurityStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Security-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Security-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-Security-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn login_rate_limit_remaining_block(
        &self,
        key: &str,
        window: StdDuration,
    ) -> anyhow::Result<Option<StdDuration>> {
        let Some(row) = self.login_rate_limit_row(key).await? else {
            return Ok(None);
        };
        let now = Utc::now();
        if let Some(blocked_until) = row.blocked_until {
            if blocked_until > now {
                return Ok((blocked_until - now).to_std().ok());
            }
        }
        if is_older_than(row.first_failure_at, now, window) {
            self.clear_login_limit(key).await?;
        }
        Ok(None)
    }

    pub async fn record_login_failure(
        &self,
        key: &str,
        tenant_id: Option<i64>,
        username: &str,
        max_failures: u32,
        window: StdDuration,
        block: StdDuration,
    ) -> anyhow::Result<()> {
        let now = Utc::now();
        let row = self.login_rate_limit_row(key).await?;
        let (failures, first_failure_at) = match row {
            Some(row) if !is_older_than(row.first_failure_at, now, window) => {
                (row.failures.saturating_add(1), row.first_failure_at)
            }
            _ => (1, now),
        };
        let blocked_until = if failures >= i64::from(max_failures) {
            Some(now + duration_from_std(block))
        } else {
            None
        };
        self.upsert_login_limit(
            key,
            tenant_id,
            username,
            failures,
            first_failure_at,
            blocked_until,
        )
        .await
    }

    pub async fn clear_login_limit(&self, key: &str) -> anyhow::Result<()> {
        match self {
            Self::Postgres(pool) => {
                sqlx::query("DELETE FROM iscy_security_login_rate_limit WHERE key = $1")
                    .bind(key)
                    .execute(pool)
                    .await
                    .context("PostgreSQL-Login-Rate-Limit konnte nicht geloescht werden")?;
            }
            Self::Sqlite(pool) => {
                sqlx::query("DELETE FROM iscy_security_login_rate_limit WHERE key = ?1")
                    .bind(key)
                    .execute(pool)
                    .await
                    .context("SQLite-Login-Rate-Limit konnte nicht geloescht werden")?;
            }
        }
        Ok(())
    }

    pub async fn consume_hmac_nonce(
        &self,
        scope: &str,
        nonce: &str,
        max_age: StdDuration,
    ) -> anyhow::Result<bool> {
        let now = Utc::now();
        let expires_at = now + duration_from_std(max_age);
        let nonce_hash = nonce_hash(scope, nonce);
        self.prune_hmac_nonces(now).await?;
        let inserted = match self {
            Self::Postgres(pool) => sqlx::query(
                r#"
                    INSERT INTO iscy_security_hmac_nonce
                        (scope, nonce_hash, observed_at, expires_at)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT(scope, nonce_hash) DO NOTHING
                    "#,
            )
            .bind(scope.trim())
            .bind(&nonce_hash)
            .bind(now.to_rfc3339())
            .bind(expires_at.to_rfc3339())
            .execute(pool)
            .await
            .context("PostgreSQL-HMAC-Nonce konnte nicht gespeichert werden")?
            .rows_affected(),
            Self::Sqlite(pool) => sqlx::query(
                r#"
                    INSERT OR IGNORE INTO iscy_security_hmac_nonce
                        (scope, nonce_hash, observed_at, expires_at)
                    VALUES (?1, ?2, ?3, ?4)
                    "#,
            )
            .bind(scope.trim())
            .bind(&nonce_hash)
            .bind(now.to_rfc3339())
            .bind(expires_at.to_rfc3339())
            .execute(pool)
            .await
            .context("SQLite-HMAC-Nonce konnte nicht gespeichert werden")?
            .rows_affected(),
        };
        Ok(inserted > 0)
    }

    async fn login_rate_limit_row(&self, key: &str) -> anyhow::Result<Option<LoginRateLimitRow>> {
        match self {
            Self::Postgres(pool) => {
                let row = sqlx::query(
                    r#"
                    SELECT failures, first_failure_at, blocked_until
                    FROM iscy_security_login_rate_limit
                    WHERE key = $1
                    "#,
                )
                .bind(key)
                .fetch_optional(pool)
                .await
                .context("PostgreSQL-Login-Rate-Limit konnte nicht gelesen werden")?;
                row.map(|row| {
                    login_rate_limit_row_from_values(
                        row.try_get("failures")?,
                        row.try_get("first_failure_at")?,
                        row.try_get("blocked_until")?,
                    )
                })
                .transpose()
            }
            Self::Sqlite(pool) => {
                let row = sqlx::query(
                    r#"
                    SELECT failures, first_failure_at, blocked_until
                    FROM iscy_security_login_rate_limit
                    WHERE key = ?1
                    "#,
                )
                .bind(key)
                .fetch_optional(pool)
                .await
                .context("SQLite-Login-Rate-Limit konnte nicht gelesen werden")?;
                row.map(|row| {
                    login_rate_limit_row_from_values(
                        row.try_get("failures")?,
                        row.try_get("first_failure_at")?,
                        row.try_get("blocked_until")?,
                    )
                })
                .transpose()
            }
        }
    }

    async fn upsert_login_limit(
        &self,
        key: &str,
        tenant_id: Option<i64>,
        username: &str,
        failures: i64,
        first_failure_at: DateTime<Utc>,
        blocked_until: Option<DateTime<Utc>>,
    ) -> anyhow::Result<()> {
        match self {
            Self::Postgres(pool) => {
                sqlx::query(
                    r#"
                    INSERT INTO iscy_security_login_rate_limit
                        (key, tenant_id, username, failures, first_failure_at, blocked_until, updated_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                    ON CONFLICT(key) DO UPDATE SET
                        tenant_id = EXCLUDED.tenant_id,
                        username = EXCLUDED.username,
                        failures = EXCLUDED.failures,
                        first_failure_at = EXCLUDED.first_failure_at,
                        blocked_until = EXCLUDED.blocked_until,
                        updated_at = EXCLUDED.updated_at
                    "#,
                )
                .bind(key)
                .bind(tenant_id)
                .bind(normalized_username(username))
                .bind(failures)
                .bind(first_failure_at.to_rfc3339())
                .bind(blocked_until.map(|value| value.to_rfc3339()))
                .bind(Utc::now().to_rfc3339())
                .execute(pool)
                .await
                .context("PostgreSQL-Login-Rate-Limit konnte nicht gespeichert werden")?;
            }
            Self::Sqlite(pool) => {
                sqlx::query(
                    r#"
                    INSERT INTO iscy_security_login_rate_limit
                        (key, tenant_id, username, failures, first_failure_at, blocked_until, updated_at)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                    ON CONFLICT(key) DO UPDATE SET
                        tenant_id = excluded.tenant_id,
                        username = excluded.username,
                        failures = excluded.failures,
                        first_failure_at = excluded.first_failure_at,
                        blocked_until = excluded.blocked_until,
                        updated_at = excluded.updated_at
                    "#,
                )
                .bind(key)
                .bind(tenant_id)
                .bind(normalized_username(username))
                .bind(failures)
                .bind(first_failure_at.to_rfc3339())
                .bind(blocked_until.map(|value| value.to_rfc3339()))
                .bind(Utc::now().to_rfc3339())
                .execute(pool)
                .await
                .context("SQLite-Login-Rate-Limit konnte nicht gespeichert werden")?;
            }
        }
        Ok(())
    }

    async fn prune_hmac_nonces(&self, now: DateTime<Utc>) -> anyhow::Result<()> {
        match self {
            Self::Postgres(pool) => {
                sqlx::query("DELETE FROM iscy_security_hmac_nonce WHERE expires_at <= $1")
                    .bind(now.to_rfc3339())
                    .execute(pool)
                    .await
                    .context("PostgreSQL-HMAC-Nonce-Pruning fehlgeschlagen")?;
            }
            Self::Sqlite(pool) => {
                sqlx::query("DELETE FROM iscy_security_hmac_nonce WHERE expires_at <= ?1")
                    .bind(now.to_rfc3339())
                    .execute(pool)
                    .await
                    .context("SQLite-HMAC-Nonce-Pruning fehlgeschlagen")?;
            }
        }
        Ok(())
    }
}

fn normalized_username(username: &str) -> String {
    username.trim().to_ascii_lowercase()
}

fn login_rate_limit_row_from_values(
    failures: i64,
    first_failure_at: String,
    blocked_until: Option<String>,
) -> anyhow::Result<LoginRateLimitRow> {
    Ok(LoginRateLimitRow {
        failures,
        first_failure_at: parse_rfc3339(&first_failure_at)?,
        blocked_until: blocked_until
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .map(parse_rfc3339)
            .transpose()?,
    })
}

fn parse_rfc3339(value: &str) -> anyhow::Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value.trim())
        .with_context(|| format!("Zeitstempel konnte nicht gelesen werden: {value}"))?
        .with_timezone(&Utc))
}

fn is_older_than(observed_at: DateTime<Utc>, now: DateTime<Utc>, window: StdDuration) -> bool {
    now - observed_at > duration_from_std(window)
}

fn duration_from_std(value: StdDuration) -> Duration {
    Duration::from_std(value).unwrap_or_else(|_| Duration::seconds(i64::MAX))
}

fn nonce_hash(scope: &str, nonce: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(scope.trim().as_bytes());
    hasher.update(b"\0");
    hasher.update(nonce.trim().as_bytes());
    hex_encode(&hasher.finalize())
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
