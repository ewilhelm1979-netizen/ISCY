use std::{env, fs, net::SocketAddr, str::FromStr};

use anyhow::{bail, Context};
use axum::{
    body::Body,
    extract::State,
    http::{
        header::{
            CACHE_CONTROL, REFERRER_POLICY, STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS,
        },
        HeaderMap, HeaderValue, Request, StatusCode,
    },
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use sqlx::{
    postgres::PgPoolOptions,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    Row,
};

use crate::{cve_store::normalize_database_url, db_admin::DbAdminAction};

const DEMO_PASSWORD_HASH: &str =
    "pbkdf2_sha256$720000$iscy-demo-salt$dHYZBIWxS3abL+0r4Rp7w3kbLXLSAFUrGq/HaPlAVrY=";

const IDENTITY_HEADERS: &[&str] = &[
    "x-iscy-tenant-id",
    "x-iscy-user-id",
    "x-iscy-user-email",
    "x-iscy-roles",
    "x-iscy-is-staff",
    "x-iscy-is-superuser",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppMode {
    Development,
    Demo,
    Production,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommunitySecurityConfig {
    pub app_mode: AppMode,
    pub trust_identity_headers: bool,
    pub trusted_proxy_configured: bool,
    pub secure_cookies: bool,
    pub https_confirmed: bool,
    pub hsts_enabled: bool,
}

impl Default for CommunitySecurityConfig {
    fn default() -> Self {
        Self {
            app_mode: AppMode::Development,
            trust_identity_headers: true,
            trusted_proxy_configured: false,
            secure_cookies: false,
            https_confirmed: false,
            hsts_enabled: false,
        }
    }
}

impl AppMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Demo => "demo",
            Self::Production => "production",
        }
    }

    pub fn is_production(self) -> bool {
        matches!(self, Self::Production)
    }
}

impl FromStr for AppMode {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "dev" | "development" | "local" => Ok(Self::Development),
            "demo" => Ok(Self::Demo),
            "prod" | "production" => Ok(Self::Production),
            other => bail!(
                "ISCY_APP_MODE ist ungueltig: {other}. Erlaubt sind development, demo, production."
            ),
        }
    }
}

impl CommunitySecurityConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let app_mode = env_value_any(&["ISCY_APP_MODE", "ISCY_ENV", "APP_ENV"])
            .as_deref()
            .unwrap_or("development")
            .parse::<AppMode>()?;
        let production = app_mode.is_production();
        Ok(Self {
            app_mode,
            trust_identity_headers: env_bool("ISCY_TRUST_PROXY_IDENTITY_HEADERS")
                .unwrap_or(!production),
            trusted_proxy_configured: env_bool("ISCY_TRUSTED_PROXY_CONFIGURED").unwrap_or(false),
            secure_cookies: env_bool("ISCY_SECURE_COOKIES").unwrap_or(production),
            https_confirmed: env_bool("ISCY_HTTPS_CONFIRMED").unwrap_or(false),
            hsts_enabled: env_bool("ISCY_HSTS_ENABLED").unwrap_or(false),
        })
    }

    #[cfg(test)]
    pub fn production_for_tests() -> Self {
        Self {
            app_mode: AppMode::Production,
            trust_identity_headers: false,
            trusted_proxy_configured: false,
            secure_cookies: true,
            https_confirmed: false,
            hsts_enabled: false,
        }
    }

    pub fn cookie_secure_suffix(&self) -> &'static str {
        if self.secure_cookies {
            "; Secure"
        } else {
            ""
        }
    }

    pub fn mode_label(&self) -> &'static str {
        self.app_mode.as_str()
    }
}

pub fn assert_db_admin_action_allowed(
    config: &CommunitySecurityConfig,
    action: DbAdminAction,
) -> anyhow::Result<()> {
    if config.app_mode.is_production()
        && matches!(action, DbAdminAction::SeedDemo | DbAdminAction::InitDemo)
    {
        bail!(
            "Production-Preflight blockiert Demo-Seeding. Nutze DbAdminAction::Migrate und einen separaten Initial-Admin-Prozess."
        );
    }
    Ok(())
}

pub async fn run_production_preflight(
    config: &CommunitySecurityConfig,
    bind_addr: &SocketAddr,
    database_url: Option<&str>,
) -> anyhow::Result<()> {
    if config.hsts_enabled && !config.https_confirmed {
        bail!("ISCY_HSTS_ENABLED darf nur mit ISCY_HTTPS_CONFIRMED=1 aktiviert werden.");
    }

    if !config.app_mode.is_production() {
        return Ok(());
    }

    let database_url = database_url
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Production-Preflight: DATABASE_URL fehlt."))?;
    ensure_supported_database_url(database_url)?;
    ensure_no_example_secret("DATABASE_URL", database_url)?;

    if bind_addr.ip().is_unspecified() && !config.trusted_proxy_configured {
        bail!(
            "Production-Preflight: RUST_BACKEND_BIND nutzt eine oeffentliche Bind-Adresse. Setze ISCY_TRUSTED_PROXY_CONFIGURED=1, wenn ein sicher konfigurierter Reverse Proxy davor steht."
        );
    }
    if config.trust_identity_headers && !config.trusted_proxy_configured {
        bail!(
            "Production-Preflight: Identity-Header duerfen nur mit ISCY_TRUSTED_PROXY_CONFIGURED=1 vertraut werden."
        );
    }
    if !config.secure_cookies {
        bail!("Production-Preflight: ISCY_SECURE_COOKIES muss fuer Production aktiv sein.");
    }
    if env_bool("ISCY_DEMO_SEED").unwrap_or(false) {
        bail!("Production-Preflight: ISCY_DEMO_SEED darf in Production nicht aktiv sein.");
    }

    let alertmanager_token = secret_value("ISCY_ALERTMANAGER_TOKEN")?
        .ok_or_else(|| anyhow::anyhow!("Production-Preflight: ISCY_ALERTMANAGER_TOKEN oder ISCY_ALERTMANAGER_TOKEN_FILE fehlt."))?;
    ensure_strong_secret("ISCY_ALERTMANAGER_TOKEN", &alertmanager_token)?;

    if demo_credentials_present(database_url).await? {
        bail!(
            "Production-Preflight: bekannte Demo-Zugangsdaten sind in accounts_user aktiv. Bitte Demo-User deaktivieren oder Passwoerter rotieren."
        );
    }

    Ok(())
}

pub fn secret_value(name: &str) -> anyhow::Result<Option<String>> {
    if let Some(value) = env_value(name) {
        return Ok(Some(value));
    }
    let file_name = format!("{name}_FILE");
    let Some(path) = env_value(&file_name) else {
        return Ok(None);
    };
    let value = fs::read_to_string(&path)
        .with_context(|| format!("{file_name} konnte nicht gelesen werden"))?;
    Ok(Some(value.trim().to_string()).filter(|value| !value.is_empty()))
}

pub fn identity_headers_trusted(config: &CommunitySecurityConfig, headers: &HeaderMap) -> bool {
    config.trust_identity_headers || !has_identity_header(headers)
}

pub async fn community_security_headers(
    State(config): State<CommunitySecurityConfig>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if !identity_headers_trusted(&config, request.headers()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "accepted": false,
                "api_version": "v1",
                "error_code": "untrusted_identity_headers",
                "message": "ISCY akzeptiert x-iscy-* Identity-Header nur von einem explizit vertrauenswuerdigen Reverse Proxy."
            })),
        )
            .into_response();
    }

    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
        ),
    );
    if config.hsts_enabled && config.https_confirmed {
        headers.insert(
            STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=15552000; includeSubDomains"),
        );
    }
    response
}

fn env_value(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_value_any(names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| env_value(name))
}

fn env_bool(name: &str) -> Option<bool> {
    env_value(name).map(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn ensure_supported_database_url(database_url: &str) -> anyhow::Result<()> {
    let normalized = normalize_database_url(database_url);
    if normalized.starts_with("sqlite:")
        || normalized.starts_with("postgres://")
        || normalized.starts_with("postgresql://")
    {
        return Ok(());
    }
    bail!("Production-Preflight: DATABASE_URL nutzt ein nicht unterstuetztes Schema.");
}

fn ensure_no_example_secret(name: &str, value: &str) -> anyhow::Result<()> {
    let lower = value.to_ascii_lowercase();
    if ["change-me", "changeme", "example", "password", "secret"]
        .iter()
        .any(|marker| lower.contains(marker))
    {
        bail!("Production-Preflight: {name} enthaelt einen Beispiel- oder Platzhalterwert.");
    }
    Ok(())
}

fn ensure_strong_secret(name: &str, value: &str) -> anyhow::Result<()> {
    let trimmed = value.trim();
    ensure_no_example_secret(name, trimmed)?;
    if trimmed.len() < 24 {
        bail!("Production-Preflight: {name} muss mindestens 24 Zeichen lang sein.");
    }
    Ok(())
}

fn has_identity_header(headers: &HeaderMap) -> bool {
    IDENTITY_HEADERS
        .iter()
        .any(|header_name| headers.contains_key(*header_name))
}

async fn demo_credentials_present(database_url: &str) -> anyhow::Result<bool> {
    let normalized = normalize_database_url(database_url);
    if normalized.starts_with("sqlite:") {
        let options = SqliteConnectOptions::from_str(&normalized)
            .context("Production-Preflight: SQLite-DATABASE_URL ist ungueltig")?;
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .context("Production-Preflight: SQLite-Datenbank konnte nicht geoeffnet werden")?;
        let row = sqlx::query(
            r#"
            SELECT COUNT(*) AS demo_count
            FROM sqlite_master
            WHERE type = 'table' AND name = 'accounts_user'
            "#,
        )
        .fetch_one(&pool)
        .await?;
        let table_count: i64 = row.try_get("demo_count")?;
        if table_count == 0 {
            return Ok(false);
        }
        let row = sqlx::query(
            r#"
            SELECT COUNT(*) AS demo_count
            FROM accounts_user
            WHERE username IN ('admin', 'ops-alertmanager')
              AND password = ?
              AND COALESCE(is_active, 1) != 0
            "#,
        )
        .bind(DEMO_PASSWORD_HASH)
        .fetch_one(&pool)
        .await?;
        let count: i64 = row.try_get("demo_count")?;
        return Ok(count > 0);
    }

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&normalized)
        .await
        .context("Production-Preflight: PostgreSQL-Datenbank konnte nicht geoeffnet werden")?;
    let exists: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = 'public' AND table_name = 'accounts_user'
        )
        "#,
    )
    .fetch_one(&pool)
    .await?;
    if !exists {
        return Ok(false);
    }
    let count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)::bigint
        FROM accounts_user
        WHERE username IN ('admin', 'ops-alertmanager')
          AND password = $1
          AND COALESCE(is_active, TRUE) = TRUE
        "#,
    )
    .bind(DEMO_PASSWORD_HASH)
    .fetch_one(&pool)
    .await?;
    Ok(count > 0)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use axum::http::{HeaderMap, HeaderValue};

    use crate::db_admin::DbAdminAction;

    use super::{
        assert_db_admin_action_allowed, identity_headers_trusted, run_production_preflight,
        AppMode, CommunitySecurityConfig,
    };

    #[test]
    fn production_config_does_not_trust_identity_headers_by_default() {
        let config = CommunitySecurityConfig::production_for_tests();
        let mut headers = HeaderMap::new();
        headers.insert("x-iscy-tenant-id", HeaderValue::from_static("42"));

        assert_eq!(config.app_mode, AppMode::Production);
        assert!(!identity_headers_trusted(&config, &headers));
    }

    #[test]
    fn development_config_accepts_legacy_identity_headers() {
        let config = CommunitySecurityConfig::default();
        let mut headers = HeaderMap::new();
        headers.insert("x-iscy-user-id", HeaderValue::from_static("7"));

        assert!(identity_headers_trusted(&config, &headers));
    }

    #[test]
    fn production_blocks_demo_seed_actions() {
        let config = CommunitySecurityConfig::production_for_tests();

        assert!(assert_db_admin_action_allowed(&config, DbAdminAction::InitDemo).is_err());
        assert!(assert_db_admin_action_allowed(&config, DbAdminAction::SeedDemo).is_err());
        assert!(assert_db_admin_action_allowed(&config, DbAdminAction::Migrate).is_ok());
    }

    #[tokio::test]
    async fn preflight_rejects_hsts_without_https_confirmation() {
        let config = CommunitySecurityConfig {
            hsts_enabled: true,
            ..CommunitySecurityConfig::default()
        };
        let bind_addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();

        let result = run_production_preflight(&config, &bind_addr, None).await;

        assert!(result
            .unwrap_err()
            .to_string()
            .contains("ISCY_HSTS_ENABLED"));
    }

    #[tokio::test]
    async fn production_preflight_rejects_public_bind_without_trusted_proxy() {
        let config = CommunitySecurityConfig::production_for_tests();
        let bind_addr: SocketAddr = "0.0.0.0:9000".parse().unwrap();

        let result =
            run_production_preflight(&config, &bind_addr, Some("sqlite:///tmp/iscy-prod.sqlite3"))
                .await;

        assert!(result
            .unwrap_err()
            .to_string()
            .contains("ISCY_TRUSTED_PROXY_CONFIGURED"));
    }
}
