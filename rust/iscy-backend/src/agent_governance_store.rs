use std::{env, time::Duration};

use anyhow::{bail, Context};
use chrono::{DateTime, Duration as ChronoDuration, NaiveDateTime, Utc};
use hmac::{Hmac, Mac};
use reqwest::{redirect::Policy as RedirectPolicy, Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Row,
};

use crate::cve_store::normalize_database_url;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub enum AgentGovernanceStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentPolicyWriteRequest {
    pub name: String,
    pub description: String,
    pub scope_type: String,
    pub scope_value: String,
    pub expected_device_count: i64,
    pub heartbeat_max_age_hours: i64,
    pub minimum_zero_trust_score: i64,
    pub max_critical_findings: i64,
    pub max_high_findings: i64,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentPolicyProfile {
    pub id: i64,
    pub tenant_id: i64,
    pub name: String,
    pub description: String,
    pub scope_type: String,
    pub scope_value: String,
    pub expected_device_count: i64,
    pub heartbeat_max_age_hours: i64,
    pub minimum_zero_trust_score: i64,
    pub max_critical_findings: i64,
    pub max_high_findings: i64,
    pub enabled: bool,
    pub created_by_id: Option<i64>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentPolicyEvaluation {
    pub policy_id: i64,
    pub policy_name: String,
    pub scope_type: String,
    pub scope_value: String,
    pub expected_device_count: i64,
    pub matched_device_count: i64,
    pub active_device_count: i64,
    pub fresh_device_count: i64,
    pub missing_device_count: i64,
    pub coverage_percent: i64,
    pub average_zero_trust_score: i64,
    pub critical_finding_count: i64,
    pub high_finding_count: i64,
    pub compliant: bool,
    pub level: String,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AgentFleetCoverageSummary {
    pub total_policies: i64,
    pub compliant_policies: i64,
    pub warning_policies: i64,
    pub critical_policies: i64,
    pub expected_devices_across_scopes: i64,
    pub fresh_devices_across_scopes: i64,
    pub coverage_percent: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentNotificationChannelWriteRequest {
    pub name: String,
    pub endpoint_url: String,
    pub minimum_level: String,
    #[serde(default)]
    pub event_types: Vec<String>,
    pub auth_type: String,
    pub secret_env_name: String,
    pub cooldown_minutes: i64,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentNotificationChannel {
    pub id: i64,
    pub tenant_id: i64,
    pub name: String,
    pub channel_type: String,
    pub endpoint_url: String,
    pub minimum_level: String,
    pub event_types: Vec<String>,
    pub auth_type: String,
    pub secret_env_name: String,
    pub secret_available: bool,
    pub cooldown_minutes: i64,
    pub enabled: bool,
    pub created_by_id: Option<i64>,
    pub last_success_at: Option<String>,
    pub last_failure_at: Option<String>,
    pub last_error: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentNotificationDelivery {
    pub id: i64,
    pub tenant_id: i64,
    pub channel_id: i64,
    pub policy_id: Option<i64>,
    pub event_key: String,
    pub event_type: String,
    pub level: String,
    pub status: String,
    pub response_status: Option<i64>,
    pub error_message: String,
    pub payload: Value,
    pub created_at: String,
    pub delivered_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentFleetGovernanceOverview {
    pub tenant_id: i64,
    pub summary: AgentFleetCoverageSummary,
    pub policies: Vec<AgentPolicyProfile>,
    pub evaluations: Vec<AgentPolicyEvaluation>,
    pub notification_channels: Vec<AgentNotificationChannel>,
    pub recent_deliveries: Vec<AgentNotificationDelivery>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AgentNotificationDispatchResult {
    pub tenant_id: i64,
    pub evaluated_policies: i64,
    pub policy_violations: i64,
    pub enabled_channels: i64,
    pub sent: i64,
    pub failed: i64,
    pub suppressed: i64,
    pub deliveries: Vec<AgentNotificationDelivery>,
}

#[derive(Debug, Clone)]
struct AgentPolicyDeviceSignal {
    os_family: String,
    deployment_channel: String,
    enrollment_status: String,
    zero_trust_score: i64,
    last_seen_at: Option<String>,
    critical_finding_count: i64,
    high_finding_count: i64,
    asset_type: Option<String>,
    business_unit_id: Option<i64>,
    business_unit_name: Option<String>,
}

struct DeliveryAttempt {
    status: &'static str,
    response_status: Option<i64>,
    error_message: String,
}

impl AgentGovernanceStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Agent-Governance fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Agent-Governance fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Agent-Governance")
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn list_policies(&self, tenant_id: i64) -> anyhow::Result<Vec<AgentPolicyProfile>> {
        match self {
            Self::Postgres(pool) => list_policies_postgres(pool, tenant_id).await,
            Self::Sqlite(pool) => list_policies_sqlite(pool, tenant_id).await,
        }
    }

    pub async fn create_policy(
        &self,
        tenant_id: i64,
        created_by_id: Option<i64>,
        payload: AgentPolicyWriteRequest,
    ) -> anyhow::Result<AgentPolicyProfile> {
        let payload = validate_policy_payload(payload)?;
        match self {
            Self::Postgres(pool) => {
                create_policy_postgres(pool, tenant_id, created_by_id, &payload).await
            }
            Self::Sqlite(pool) => {
                create_policy_sqlite(pool, tenant_id, created_by_id, &payload).await
            }
        }
    }

    pub async fn update_policy(
        &self,
        tenant_id: i64,
        policy_id: i64,
        payload: AgentPolicyWriteRequest,
    ) -> anyhow::Result<Option<AgentPolicyProfile>> {
        let payload = validate_policy_payload(payload)?;
        match self {
            Self::Postgres(pool) => {
                update_policy_postgres(pool, tenant_id, policy_id, &payload).await
            }
            Self::Sqlite(pool) => update_policy_sqlite(pool, tenant_id, policy_id, &payload).await,
        }
    }

    pub async fn evaluate_policies(
        &self,
        tenant_id: i64,
    ) -> anyhow::Result<Vec<AgentPolicyEvaluation>> {
        let policies = self.list_policies(tenant_id).await?;
        let devices = match self {
            Self::Postgres(pool) => policy_device_signals_postgres(pool, tenant_id).await?,
            Self::Sqlite(pool) => policy_device_signals_sqlite(pool, tenant_id).await?,
        };
        Ok(policies
            .iter()
            .filter(|policy| policy.enabled)
            .map(|policy| evaluate_policy(policy, &devices))
            .collect())
    }

    pub async fn fleet_governance_overview(
        &self,
        tenant_id: i64,
        include_channels: bool,
    ) -> anyhow::Result<AgentFleetGovernanceOverview> {
        let policies = self.list_policies(tenant_id).await?;
        let evaluations = self.evaluate_policies(tenant_id).await?;
        let summary = coverage_summary(&evaluations);
        let notification_channels = if include_channels {
            self.list_notification_channels(tenant_id).await?
        } else {
            Vec::new()
        };
        let recent_deliveries = if include_channels {
            self.list_notification_deliveries(tenant_id, 25).await?
        } else {
            Vec::new()
        };
        Ok(AgentFleetGovernanceOverview {
            tenant_id,
            summary,
            policies,
            evaluations,
            notification_channels,
            recent_deliveries,
        })
    }

    pub async fn list_notification_channels(
        &self,
        tenant_id: i64,
    ) -> anyhow::Result<Vec<AgentNotificationChannel>> {
        match self {
            Self::Postgres(pool) => list_channels_postgres(pool, tenant_id).await,
            Self::Sqlite(pool) => list_channels_sqlite(pool, tenant_id).await,
        }
    }

    pub async fn create_notification_channel(
        &self,
        tenant_id: i64,
        created_by_id: Option<i64>,
        payload: AgentNotificationChannelWriteRequest,
    ) -> anyhow::Result<AgentNotificationChannel> {
        let payload = validate_channel_payload(payload)?;
        match self {
            Self::Postgres(pool) => {
                create_channel_postgres(pool, tenant_id, created_by_id, &payload).await
            }
            Self::Sqlite(pool) => {
                create_channel_sqlite(pool, tenant_id, created_by_id, &payload).await
            }
        }
    }

    pub async fn update_notification_channel(
        &self,
        tenant_id: i64,
        channel_id: i64,
        payload: AgentNotificationChannelWriteRequest,
    ) -> anyhow::Result<Option<AgentNotificationChannel>> {
        let payload = validate_channel_payload(payload)?;
        match self {
            Self::Postgres(pool) => {
                update_channel_postgres(pool, tenant_id, channel_id, &payload).await
            }
            Self::Sqlite(pool) => {
                update_channel_sqlite(pool, tenant_id, channel_id, &payload).await
            }
        }
    }

    pub async fn list_notification_deliveries(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<AgentNotificationDelivery>> {
        let limit = limit.clamp(1, 500);
        match self {
            Self::Postgres(pool) => list_deliveries_postgres(pool, tenant_id, limit).await,
            Self::Sqlite(pool) => list_deliveries_sqlite(pool, tenant_id, limit).await,
        }
    }

    pub async fn notification_tenant_ids(&self) -> anyhow::Result<Vec<i64>> {
        match self {
            Self::Postgres(pool) => notification_tenant_ids_postgres(pool).await,
            Self::Sqlite(pool) => notification_tenant_ids_sqlite(pool).await,
        }
    }

    pub async fn dispatch_policy_notifications(
        &self,
        tenant_id: i64,
    ) -> anyhow::Result<AgentNotificationDispatchResult> {
        let evaluations = self.evaluate_policies(tenant_id).await?;
        let channels = self
            .list_notification_channels(tenant_id)
            .await?
            .into_iter()
            .filter(|channel| channel.enabled)
            .collect::<Vec<_>>();
        let violations = evaluations
            .iter()
            .filter(|evaluation| !evaluation.compliant)
            .collect::<Vec<_>>();
        let mut result = AgentNotificationDispatchResult {
            tenant_id,
            evaluated_policies: evaluations.len() as i64,
            policy_violations: violations.len() as i64,
            enabled_channels: channels.len() as i64,
            ..AgentNotificationDispatchResult::default()
        };
        if channels.is_empty() || violations.is_empty() {
            return Ok(result);
        }

        let client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .redirect(RedirectPolicy::none())
            .build()
            .context("Notification-HTTP-Client konnte nicht erstellt werden")?;

        for channel in &channels {
            if !channel
                .event_types
                .iter()
                .any(|event_type| event_type == "AGENT_POLICY")
            {
                continue;
            }
            for evaluation in &violations {
                if level_rank(&evaluation.level) < level_rank(&channel.minimum_level) {
                    continue;
                }
                let event_key =
                    format!("AGENT_POLICY:{}:{}", evaluation.policy_id, evaluation.level);
                if self
                    .recent_successful_delivery(
                        tenant_id,
                        channel.id,
                        &event_key,
                        channel.cooldown_minutes,
                    )
                    .await?
                {
                    result.suppressed += 1;
                    continue;
                }
                let payload = notification_payload(tenant_id, &event_key, evaluation);
                let payload_json = serde_json::to_string(&payload)?;
                let attempt = deliver_webhook(&client, channel, &event_key, &payload_json).await;
                let delivery = self
                    .record_delivery(
                        tenant_id,
                        channel.id,
                        Some(evaluation.policy_id),
                        &event_key,
                        &evaluation.level,
                        &payload,
                        &attempt,
                    )
                    .await?;
                if attempt.status == "SENT" {
                    result.sent += 1;
                } else {
                    result.failed += 1;
                }
                result.deliveries.push(delivery);
            }
        }
        Ok(result)
    }

    async fn recent_successful_delivery(
        &self,
        tenant_id: i64,
        channel_id: i64,
        event_key: &str,
        cooldown_minutes: i64,
    ) -> anyhow::Result<bool> {
        match self {
            Self::Postgres(pool) => {
                recent_delivery_postgres(pool, tenant_id, channel_id, event_key, cooldown_minutes)
                    .await
            }
            Self::Sqlite(pool) => {
                recent_delivery_sqlite(pool, tenant_id, channel_id, event_key, cooldown_minutes)
                    .await
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn record_delivery(
        &self,
        tenant_id: i64,
        channel_id: i64,
        policy_id: Option<i64>,
        event_key: &str,
        level: &str,
        payload: &Value,
        attempt: &DeliveryAttempt,
    ) -> anyhow::Result<AgentNotificationDelivery> {
        match self {
            Self::Postgres(pool) => {
                record_delivery_postgres(
                    pool, tenant_id, channel_id, policy_id, event_key, level, payload, attempt,
                )
                .await
            }
            Self::Sqlite(pool) => {
                record_delivery_sqlite(
                    pool, tenant_id, channel_id, policy_id, event_key, level, payload, attempt,
                )
                .await
            }
        }
    }
}

fn validate_policy_payload(
    mut payload: AgentPolicyWriteRequest,
) -> anyhow::Result<AgentPolicyWriteRequest> {
    payload.name = payload.name.trim().to_string();
    payload.description = payload.description.trim().to_string();
    payload.scope_type = payload.scope_type.trim().to_ascii_uppercase();
    payload.scope_value = payload.scope_value.trim().to_string();
    if payload.name.is_empty() || payload.name.len() > 128 {
        bail!("Agent-Policy-Name muss 1 bis 128 Zeichen enthalten");
    }
    if !matches!(
        payload.scope_type.as_str(),
        "TENANT" | "OS_FAMILY" | "ASSET_TYPE" | "BUSINESS_UNIT" | "DEPLOYMENT_CHANNEL"
    ) {
        bail!("Unbekannter Agent-Policy-Scope");
    }
    if payload.scope_type == "TENANT" {
        payload.scope_value.clear();
    } else if payload.scope_value.is_empty() {
        bail!("Der gewaehlte Agent-Policy-Scope benoetigt einen Scope-Wert");
    }
    if !(1..=100_000).contains(&payload.expected_device_count) {
        bail!("Agent-Policy expected_device_count muss zwischen 1 und 100000 liegen");
    }
    if !(1..=8_760).contains(&payload.heartbeat_max_age_hours) {
        bail!("Agent-Policy heartbeat_max_age_hours muss zwischen 1 und 8760 liegen");
    }
    if !(0..=100).contains(&payload.minimum_zero_trust_score) {
        bail!("Agent-Policy minimum_zero_trust_score muss zwischen 0 und 100 liegen");
    }
    if !(0..=100_000).contains(&payload.max_critical_findings)
        || !(0..=100_000).contains(&payload.max_high_findings)
    {
        bail!("Agent-Policy Finding-Grenzwerte muessen zwischen 0 und 100000 liegen");
    }
    Ok(payload)
}

fn validate_channel_payload(
    mut payload: AgentNotificationChannelWriteRequest,
) -> anyhow::Result<AgentNotificationChannelWriteRequest> {
    payload.name = payload.name.trim().to_string();
    payload.endpoint_url = payload.endpoint_url.trim().to_string();
    payload.minimum_level = payload.minimum_level.trim().to_ascii_uppercase();
    payload.auth_type = payload.auth_type.trim().to_ascii_uppercase();
    payload.secret_env_name = payload.secret_env_name.trim().to_string();
    if payload.name.is_empty() || payload.name.len() > 128 {
        bail!("Notification-Kanalname muss 1 bis 128 Zeichen enthalten");
    }
    validate_webhook_url(&payload.endpoint_url)?;
    if !matches!(payload.minimum_level.as_str(), "WARN" | "CRITICAL") {
        bail!("Notification minimum_level muss WARN oder CRITICAL sein");
    }
    payload.event_types = payload
        .event_types
        .iter()
        .map(|value| value.trim().to_ascii_uppercase())
        .filter(|value| !value.is_empty())
        .fold(Vec::<String>::new(), |mut values, value| {
            if !values.contains(&value) {
                values.push(value);
            }
            values
        });
    if payload.event_types.is_empty() {
        payload.event_types.push("AGENT_POLICY".to_string());
    }
    if payload
        .event_types
        .iter()
        .any(|event_type| event_type != "AGENT_POLICY")
    {
        bail!("Derzeit wird nur der Notification-Event AGENT_POLICY unterstuetzt");
    }
    if !matches!(
        payload.auth_type.as_str(),
        "NONE" | "BEARER" | "HMAC_SHA256"
    ) {
        bail!("Notification auth_type muss NONE, BEARER oder HMAC_SHA256 sein");
    }
    if payload.auth_type == "NONE" {
        payload.secret_env_name.clear();
    } else if !valid_env_name(&payload.secret_env_name) {
        bail!(
            "Notification-Secret muss als gueltiger Environment-Variablenname referenziert werden"
        );
    }
    if !(1..=10_080).contains(&payload.cooldown_minutes) {
        bail!("Notification-Cooldown muss zwischen 1 und 10080 Minuten liegen");
    }
    Ok(payload)
}

fn validate_webhook_url(raw_url: &str) -> anyhow::Result<Url> {
    let url = Url::parse(raw_url).context("Notification-Webhook-URL ist ungueltig")?;
    if !url.username().is_empty() || url.password().is_some() {
        bail!("Notification-Webhook-URL darf keine Zugangsdaten enthalten");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Notification-Webhook-URL benoetigt einen Host"))?;
    let allow_http = env_flag("ISCY_NOTIFICATION_ALLOW_HTTP") || is_loopback_host(host);
    if url.scheme() != "https" && !(url.scheme() == "http" && allow_http) {
        bail!("Notification-Webhook muss HTTPS nutzen; lokales HTTP braucht ISCY_NOTIFICATION_ALLOW_HTTP=1");
    }
    if env::var("ISCY_APP_MODE")
        .unwrap_or_else(|_| "development".to_string())
        .eq_ignore_ascii_case("production")
    {
        let allowed_hosts = env::var("ISCY_NOTIFICATION_WEBHOOK_ALLOWED_HOSTS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_ascii_lowercase)
            .collect::<Vec<_>>();
        if allowed_hosts.is_empty()
            || !allowed_hosts
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(host))
        {
            bail!("Produktive Notification-Webhooks benoetigen einen Host in ISCY_NOTIFICATION_WEBHOOK_ALLOWED_HOSTS");
        }
    }
    Ok(url)
}

fn valid_env_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .next()
            .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
        && value
            .chars()
            .all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn env_flag(name: &str) -> bool {
    env::var(name).ok().is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || matches!(host, "127.0.0.1" | "::1")
}

fn evaluate_policy(
    policy: &AgentPolicyProfile,
    devices: &[AgentPolicyDeviceSignal],
) -> AgentPolicyEvaluation {
    let matched = devices
        .iter()
        .filter(|device| policy_matches_device(policy, device))
        .collect::<Vec<_>>();
    let active = matched
        .iter()
        .copied()
        .filter(|device| device.enrollment_status.eq_ignore_ascii_case("ACTIVE"))
        .collect::<Vec<_>>();
    let fresh = active
        .iter()
        .copied()
        .filter(|device| {
            heartbeat_is_fresh(
                device.last_seen_at.as_deref(),
                policy.heartbeat_max_age_hours,
            )
        })
        .collect::<Vec<_>>();
    let average_score = if active.is_empty() {
        100
    } else {
        active
            .iter()
            .map(|device| device.zero_trust_score)
            .sum::<i64>()
            / active.len() as i64
    };
    let critical_findings = active
        .iter()
        .map(|device| device.critical_finding_count)
        .sum::<i64>();
    let high_findings = active
        .iter()
        .map(|device| device.high_finding_count)
        .sum::<i64>();
    let fresh_count = fresh.len() as i64;
    let missing_count = (policy.expected_device_count - fresh_count).max(0);
    let coverage_percent = ((fresh_count * 100) / policy.expected_device_count).clamp(0, 100);
    let mut issues = Vec::new();
    if fresh_count < policy.expected_device_count {
        issues.push(format!(
            "Sollabdeckung verfehlt: {fresh_count}/{} Devices melden innerhalb von {} Stunden.",
            policy.expected_device_count, policy.heartbeat_max_age_hours
        ));
    }
    if average_score < policy.minimum_zero_trust_score {
        issues.push(format!(
            "Flottenscore {average_score}% liegt unter dem Zielwert {}%.",
            policy.minimum_zero_trust_score
        ));
    }
    if critical_findings > policy.max_critical_findings {
        issues.push(format!(
            "{critical_findings} kritische Findings ueberschreiten den Grenzwert {}.",
            policy.max_critical_findings
        ));
    }
    if high_findings > policy.max_high_findings {
        issues.push(format!(
            "{high_findings} hohe Findings ueberschreiten den Grenzwert {}.",
            policy.max_high_findings
        ));
    }
    let level = if critical_findings > policy.max_critical_findings
        || (policy.expected_device_count > 0 && fresh_count == 0)
    {
        "CRITICAL"
    } else if issues.is_empty() {
        "OK"
    } else {
        "WARN"
    };
    AgentPolicyEvaluation {
        policy_id: policy.id,
        policy_name: policy.name.clone(),
        scope_type: policy.scope_type.clone(),
        scope_value: policy.scope_value.clone(),
        expected_device_count: policy.expected_device_count,
        matched_device_count: matched.len() as i64,
        active_device_count: active.len() as i64,
        fresh_device_count: fresh_count,
        missing_device_count: missing_count,
        coverage_percent,
        average_zero_trust_score: average_score,
        critical_finding_count: critical_findings,
        high_finding_count: high_findings,
        compliant: issues.is_empty(),
        level: level.to_string(),
        issues,
    }
}

fn policy_matches_device(policy: &AgentPolicyProfile, device: &AgentPolicyDeviceSignal) -> bool {
    match policy.scope_type.as_str() {
        "TENANT" => true,
        "OS_FAMILY" => device.os_family.eq_ignore_ascii_case(&policy.scope_value),
        "ASSET_TYPE" => device
            .asset_type
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case(&policy.scope_value)),
        "BUSINESS_UNIT" => {
            policy
                .scope_value
                .parse::<i64>()
                .ok()
                .is_some_and(|id| device.business_unit_id == Some(id))
                || device
                    .business_unit_name
                    .as_deref()
                    .is_some_and(|value| value.eq_ignore_ascii_case(&policy.scope_value))
        }
        "DEPLOYMENT_CHANNEL" => device
            .deployment_channel
            .eq_ignore_ascii_case(&policy.scope_value),
        _ => false,
    }
}

fn heartbeat_is_fresh(last_seen_at: Option<&str>, max_age_hours: i64) -> bool {
    let Some(last_seen_at) = last_seen_at.and_then(parse_database_timestamp) else {
        return false;
    };
    last_seen_at >= Utc::now() - ChronoDuration::hours(max_age_hours)
}

fn parse_database_timestamp(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .or_else(|| {
            DateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f%#z")
                .ok()
                .map(|timestamp| timestamp.with_timezone(&Utc))
        })
        .or_else(|| {
            NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f")
                .ok()
                .map(|timestamp| timestamp.and_utc())
        })
}

fn coverage_summary(evaluations: &[AgentPolicyEvaluation]) -> AgentFleetCoverageSummary {
    let expected = evaluations
        .iter()
        .map(|evaluation| evaluation.expected_device_count)
        .sum::<i64>();
    let fresh = evaluations
        .iter()
        .map(|evaluation| {
            evaluation
                .fresh_device_count
                .min(evaluation.expected_device_count)
        })
        .sum::<i64>();
    AgentFleetCoverageSummary {
        total_policies: evaluations.len() as i64,
        compliant_policies: evaluations
            .iter()
            .filter(|evaluation| evaluation.compliant)
            .count() as i64,
        warning_policies: evaluations
            .iter()
            .filter(|evaluation| evaluation.level == "WARN")
            .count() as i64,
        critical_policies: evaluations
            .iter()
            .filter(|evaluation| evaluation.level == "CRITICAL")
            .count() as i64,
        expected_devices_across_scopes: expected,
        fresh_devices_across_scopes: fresh,
        coverage_percent: if expected == 0 {
            0
        } else {
            ((fresh * 100) / expected).clamp(0, 100)
        },
    }
}

fn notification_payload(
    tenant_id: i64,
    event_key: &str,
    evaluation: &AgentPolicyEvaluation,
) -> Value {
    json!({
        "specversion": "1.0",
        "type": "iscy.agent.policy.violation",
        "source": format!("iscy://tenant/{tenant_id}/agent-fleet"),
        "id": event_key,
        "time": Utc::now().to_rfc3339(),
        "subject": format!("agent-policy/{}", evaluation.policy_id),
        "data": evaluation,
    })
}

async fn deliver_webhook(
    client: &Client,
    channel: &AgentNotificationChannel,
    event_key: &str,
    payload_json: &str,
) -> DeliveryAttempt {
    let url = match validate_webhook_url(&channel.endpoint_url) {
        Ok(url) => url,
        Err(err) => return failed_attempt(err.to_string()),
    };
    let secret = if channel.auth_type == "NONE" {
        None
    } else {
        match env::var(&channel.secret_env_name)
            .ok()
            .filter(|value| !value.trim().is_empty())
        {
            Some(secret) => Some(secret),
            None => {
                return failed_attempt(format!(
                    "Secret-Referenz {} ist nicht gesetzt",
                    channel.secret_env_name
                ))
            }
        }
    };

    const MAX_ATTEMPTS: usize = 3;
    for attempt in 0..MAX_ATTEMPTS {
        let mut request = client
            .post(url.clone())
            .header("content-type", "application/cloudevents+json")
            .header("user-agent", "iscy-rust-notifier/0.3")
            .header("x-iscy-event-key", event_key)
            .body(payload_json.to_string());
        if let Some(secret) = secret.as_deref() {
            if channel.auth_type == "BEARER" {
                request = request.bearer_auth(secret);
            } else if channel.auth_type == "HMAC_SHA256" {
                let timestamp = Utc::now().timestamp().to_string();
                let message = format!("{timestamp}.{payload_json}");
                let mut mac = match <HmacSha256 as Mac>::new_from_slice(secret.as_bytes()) {
                    Ok(mac) => mac,
                    Err(_) => return failed_attempt("HMAC-Secret ist ungueltig".to_string()),
                };
                mac.update(message.as_bytes());
                request = request
                    .header("x-iscy-notification-timestamp", timestamp)
                    .header(
                        "x-iscy-notification-signature",
                        format!("sha256={}", hex_encode(&mac.finalize().into_bytes())),
                    );
            }
        }

        match request.send().await {
            Ok(response) if response.status().is_success() => {
                return DeliveryAttempt {
                    status: "SENT",
                    response_status: Some(i64::from(response.status().as_u16())),
                    error_message: String::new(),
                };
            }
            Ok(response) => {
                let status = response.status().as_u16();
                if webhook_retryable_status(status) && attempt + 1 < MAX_ATTEMPTS {
                    tokio::time::sleep(webhook_retry_delay(attempt)).await;
                    continue;
                }
                return failed_http_attempt(status);
            }
            Err(err) => {
                let retryable = err.is_timeout() || err.is_connect() || err.is_request();
                if retryable && attempt + 1 < MAX_ATTEMPTS {
                    tokio::time::sleep(webhook_retry_delay(attempt)).await;
                    continue;
                }
                return failed_attempt(format!("Webhook-Zustellung fehlgeschlagen: {err}"));
            }
        }
    }
    failed_attempt("Webhook-Zustellung ohne Ergebnis beendet".to_string())
}

fn webhook_retryable_status(status: u16) -> bool {
    matches!(status, 429 | 500 | 502 | 503 | 504)
}

fn webhook_retry_delay(attempt: usize) -> Duration {
    Duration::from_millis(100 * (attempt as u64 + 1))
}

fn failed_http_attempt(status: u16) -> DeliveryAttempt {
    DeliveryAttempt {
        status: "FAILED",
        response_status: Some(i64::from(status)),
        error_message: format!("Webhook antwortete mit HTTP {status}"),
    }
}

fn failed_attempt(message: String) -> DeliveryAttempt {
    DeliveryAttempt {
        status: "FAILED",
        response_status: None,
        error_message: truncate(&message, 1000),
    }
}

fn level_rank(level: &str) -> i64 {
    match level.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" | "DANGER" => 2,
        "WARN" | "WARNING" => 1,
        _ => 0,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn truncate(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

fn json_string_array(value: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(value).unwrap_or_default()
}

fn secret_available(auth_type: &str, secret_env_name: &str) -> bool {
    auth_type == "NONE"
        || env::var(secret_env_name)
            .ok()
            .is_some_and(|value| !value.trim().is_empty())
}

fn policy_select_sql() -> &'static str {
    "id, tenant_id, name, description, scope_type, scope_value, expected_device_count, heartbeat_max_age_hours, minimum_zero_trust_score, max_critical_findings, max_high_findings, enabled, created_by_id, created_at, updated_at"
}

fn channel_select_sql() -> &'static str {
    "id, tenant_id, name, channel_type, endpoint_url, minimum_level, event_types_json, auth_type, secret_env_name, cooldown_minutes, enabled, created_by_id, last_success_at, last_failure_at, last_error, created_at, updated_at"
}

fn delivery_select_sql() -> &'static str {
    "id, tenant_id, channel_id, policy_id, event_key, event_type, level, status, response_status, error_message, payload_json, created_at, delivered_at"
}

async fn list_policies_postgres(
    pool: &PgPool,
    tenant_id: i64,
) -> anyhow::Result<Vec<AgentPolicyProfile>> {
    let rows = sqlx::query(&format!(
        "SELECT {} FROM zero_trust_agent_policy_profile WHERE tenant_id = $1 ORDER BY enabled DESC, name, id",
        policy_select_sql()
    ))
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .context("PostgreSQL-Agent-Policies konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(policy_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_policies_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
) -> anyhow::Result<Vec<AgentPolicyProfile>> {
    let rows = sqlx::query(&format!(
        "SELECT {} FROM zero_trust_agent_policy_profile WHERE tenant_id = ?1 ORDER BY enabled DESC, name, id",
        policy_select_sql()
    ))
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .context("SQLite-Agent-Policies konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(policy_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn create_policy_postgres(
    pool: &PgPool,
    tenant_id: i64,
    created_by_id: Option<i64>,
    payload: &AgentPolicyWriteRequest,
) -> anyhow::Result<AgentPolicyProfile> {
    let row = sqlx::query(&format!(
        "INSERT INTO zero_trust_agent_policy_profile (tenant_id, name, description, scope_type, scope_value, expected_device_count, heartbeat_max_age_hours, minimum_zero_trust_score, max_critical_findings, max_high_findings, enabled, created_by_id, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,CURRENT_TIMESTAMP::text,CURRENT_TIMESTAMP::text) RETURNING {}",
        policy_select_sql()
    ))
    .bind(tenant_id)
    .bind(&payload.name)
    .bind(&payload.description)
    .bind(&payload.scope_type)
    .bind(&payload.scope_value)
    .bind(payload.expected_device_count)
    .bind(payload.heartbeat_max_age_hours)
    .bind(payload.minimum_zero_trust_score)
    .bind(payload.max_critical_findings)
    .bind(payload.max_high_findings)
    .bind(payload.enabled)
    .bind(created_by_id)
    .fetch_one(pool)
    .await
    .context("PostgreSQL-Agent-Policy konnte nicht erstellt werden")?;
    policy_from_pg_row(row).map_err(Into::into)
}

async fn create_policy_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    created_by_id: Option<i64>,
    payload: &AgentPolicyWriteRequest,
) -> anyhow::Result<AgentPolicyProfile> {
    let row = sqlx::query(&format!(
        "INSERT INTO zero_trust_agent_policy_profile (tenant_id, name, description, scope_type, scope_value, expected_device_count, heartbeat_max_age_hours, minimum_zero_trust_score, max_critical_findings, max_high_findings, enabled, created_by_id, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) RETURNING {}",
        policy_select_sql()
    ))
    .bind(tenant_id)
    .bind(&payload.name)
    .bind(&payload.description)
    .bind(&payload.scope_type)
    .bind(&payload.scope_value)
    .bind(payload.expected_device_count)
    .bind(payload.heartbeat_max_age_hours)
    .bind(payload.minimum_zero_trust_score)
    .bind(payload.max_critical_findings)
    .bind(payload.max_high_findings)
    .bind(payload.enabled)
    .bind(created_by_id)
    .fetch_one(pool)
    .await
    .context("SQLite-Agent-Policy konnte nicht erstellt werden")?;
    policy_from_sqlite_row(row).map_err(Into::into)
}

async fn update_policy_postgres(
    pool: &PgPool,
    tenant_id: i64,
    policy_id: i64,
    payload: &AgentPolicyWriteRequest,
) -> anyhow::Result<Option<AgentPolicyProfile>> {
    let row = sqlx::query(&format!(
        "UPDATE zero_trust_agent_policy_profile SET name=$1, description=$2, scope_type=$3, scope_value=$4, expected_device_count=$5, heartbeat_max_age_hours=$6, minimum_zero_trust_score=$7, max_critical_findings=$8, max_high_findings=$9, enabled=$10, updated_at=CURRENT_TIMESTAMP::text WHERE tenant_id=$11 AND id=$12 RETURNING {}",
        policy_select_sql()
    ))
    .bind(&payload.name)
    .bind(&payload.description)
    .bind(&payload.scope_type)
    .bind(&payload.scope_value)
    .bind(payload.expected_device_count)
    .bind(payload.heartbeat_max_age_hours)
    .bind(payload.minimum_zero_trust_score)
    .bind(payload.max_critical_findings)
    .bind(payload.max_high_findings)
    .bind(payload.enabled)
    .bind(tenant_id)
    .bind(policy_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-Agent-Policy konnte nicht aktualisiert werden")?;
    row.map(policy_from_pg_row).transpose().map_err(Into::into)
}

async fn update_policy_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    policy_id: i64,
    payload: &AgentPolicyWriteRequest,
) -> anyhow::Result<Option<AgentPolicyProfile>> {
    let row = sqlx::query(&format!(
        "UPDATE zero_trust_agent_policy_profile SET name=?1, description=?2, scope_type=?3, scope_value=?4, expected_device_count=?5, heartbeat_max_age_hours=?6, minimum_zero_trust_score=?7, max_critical_findings=?8, max_high_findings=?9, enabled=?10, updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?11 AND id=?12 RETURNING {}",
        policy_select_sql()
    ))
    .bind(&payload.name)
    .bind(&payload.description)
    .bind(&payload.scope_type)
    .bind(&payload.scope_value)
    .bind(payload.expected_device_count)
    .bind(payload.heartbeat_max_age_hours)
    .bind(payload.minimum_zero_trust_score)
    .bind(payload.max_critical_findings)
    .bind(payload.max_high_findings)
    .bind(payload.enabled)
    .bind(tenant_id)
    .bind(policy_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-Agent-Policy konnte nicht aktualisiert werden")?;
    row.map(policy_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

async fn policy_device_signals_postgres(
    pool: &PgPool,
    tenant_id: i64,
) -> anyhow::Result<Vec<AgentPolicyDeviceSignal>> {
    let rows = sqlx::query(policy_device_signals_postgres_sql())
        .bind(tenant_id)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Agent-Policy-Devices konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(device_signal_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn policy_device_signals_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
) -> anyhow::Result<Vec<AgentPolicyDeviceSignal>> {
    let rows = sqlx::query(policy_device_signals_sqlite_sql())
        .bind(tenant_id)
        .fetch_all(pool)
        .await
        .context("SQLite-Agent-Policy-Devices konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(device_signal_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn policy_device_signals_postgres_sql() -> &'static str {
    r#"
    SELECT device.id, device.os_family, device.deployment_channel, device.enrollment_status,
        device.zero_trust_score, device.last_seen_at, asset.asset_type,
        asset.business_unit_id, business_unit.name AS business_unit_name,
        (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.tenant_id = device.tenant_id AND finding.device_id = device.id AND finding.status NOT IN ('RESOLVED','ACCEPTED','OBSERVED') AND finding.severity = 'CRITICAL')::bigint AS critical_finding_count,
        (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.tenant_id = device.tenant_id AND finding.device_id = device.id AND finding.status NOT IN ('RESOLVED','ACCEPTED','OBSERVED') AND finding.severity = 'HIGH')::bigint AS high_finding_count
    FROM zero_trust_agent_device device
    LEFT JOIN assets_app_informationasset asset ON asset.id = device.asset_id AND asset.tenant_id = device.tenant_id
    LEFT JOIN organizations_businessunit business_unit ON business_unit.id = asset.business_unit_id AND business_unit.tenant_id = device.tenant_id
    WHERE device.tenant_id = $1
    ORDER BY device.id
    "#
}

fn policy_device_signals_sqlite_sql() -> &'static str {
    r#"
    SELECT device.id, device.os_family, device.deployment_channel, device.enrollment_status,
        device.zero_trust_score, device.last_seen_at, asset.asset_type,
        asset.business_unit_id, business_unit.name AS business_unit_name,
        (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.tenant_id = device.tenant_id AND finding.device_id = device.id AND finding.status NOT IN ('RESOLVED','ACCEPTED','OBSERVED') AND finding.severity = 'CRITICAL') AS critical_finding_count,
        (SELECT COUNT(*) FROM zero_trust_agent_finding finding WHERE finding.tenant_id = device.tenant_id AND finding.device_id = device.id AND finding.status NOT IN ('RESOLVED','ACCEPTED','OBSERVED') AND finding.severity = 'HIGH') AS high_finding_count
    FROM zero_trust_agent_device device
    LEFT JOIN assets_app_informationasset asset ON asset.id = device.asset_id AND asset.tenant_id = device.tenant_id
    LEFT JOIN organizations_businessunit business_unit ON business_unit.id = asset.business_unit_id AND business_unit.tenant_id = device.tenant_id
    WHERE device.tenant_id = ?1
    ORDER BY device.id
    "#
}

async fn list_channels_postgres(
    pool: &PgPool,
    tenant_id: i64,
) -> anyhow::Result<Vec<AgentNotificationChannel>> {
    let rows = sqlx::query(&format!(
        "SELECT {} FROM zero_trust_agent_notification_channel WHERE tenant_id=$1 ORDER BY enabled DESC, name, id",
        channel_select_sql()
    ))
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .context("PostgreSQL-Notification-Kanaele konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(channel_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_channels_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
) -> anyhow::Result<Vec<AgentNotificationChannel>> {
    let rows = sqlx::query(&format!(
        "SELECT {} FROM zero_trust_agent_notification_channel WHERE tenant_id=?1 ORDER BY enabled DESC, name, id",
        channel_select_sql()
    ))
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .context("SQLite-Notification-Kanaele konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(channel_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn create_channel_postgres(
    pool: &PgPool,
    tenant_id: i64,
    created_by_id: Option<i64>,
    payload: &AgentNotificationChannelWriteRequest,
) -> anyhow::Result<AgentNotificationChannel> {
    let row = sqlx::query(&format!(
        "INSERT INTO zero_trust_agent_notification_channel (tenant_id,name,channel_type,endpoint_url,minimum_level,event_types_json,auth_type,secret_env_name,cooldown_minutes,enabled,created_by_id,created_at,updated_at) VALUES ($1,$2,'WEBHOOK',$3,$4,$5,$6,$7,$8,$9,$10,CURRENT_TIMESTAMP::text,CURRENT_TIMESTAMP::text) RETURNING {}",
        channel_select_sql()
    ))
    .bind(tenant_id)
    .bind(&payload.name)
    .bind(&payload.endpoint_url)
    .bind(&payload.minimum_level)
    .bind(serde_json::to_string(&payload.event_types)?)
    .bind(&payload.auth_type)
    .bind(&payload.secret_env_name)
    .bind(payload.cooldown_minutes)
    .bind(payload.enabled)
    .bind(created_by_id)
    .fetch_one(pool)
    .await
    .context("PostgreSQL-Notification-Kanal konnte nicht erstellt werden")?;
    channel_from_pg_row(row).map_err(Into::into)
}

async fn create_channel_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    created_by_id: Option<i64>,
    payload: &AgentNotificationChannelWriteRequest,
) -> anyhow::Result<AgentNotificationChannel> {
    let row = sqlx::query(&format!(
        "INSERT INTO zero_trust_agent_notification_channel (tenant_id,name,channel_type,endpoint_url,minimum_level,event_types_json,auth_type,secret_env_name,cooldown_minutes,enabled,created_by_id,created_at,updated_at) VALUES (?1,?2,'WEBHOOK',?3,?4,?5,?6,?7,?8,?9,?10,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) RETURNING {}",
        channel_select_sql()
    ))
    .bind(tenant_id)
    .bind(&payload.name)
    .bind(&payload.endpoint_url)
    .bind(&payload.minimum_level)
    .bind(serde_json::to_string(&payload.event_types)?)
    .bind(&payload.auth_type)
    .bind(&payload.secret_env_name)
    .bind(payload.cooldown_minutes)
    .bind(payload.enabled)
    .bind(created_by_id)
    .fetch_one(pool)
    .await
    .context("SQLite-Notification-Kanal konnte nicht erstellt werden")?;
    channel_from_sqlite_row(row).map_err(Into::into)
}

async fn update_channel_postgres(
    pool: &PgPool,
    tenant_id: i64,
    channel_id: i64,
    payload: &AgentNotificationChannelWriteRequest,
) -> anyhow::Result<Option<AgentNotificationChannel>> {
    let row = sqlx::query(&format!(
        "UPDATE zero_trust_agent_notification_channel SET name=$1, endpoint_url=$2, minimum_level=$3, event_types_json=$4, auth_type=$5, secret_env_name=$6, cooldown_minutes=$7, enabled=$8, updated_at=CURRENT_TIMESTAMP::text WHERE tenant_id=$9 AND id=$10 RETURNING {}",
        channel_select_sql()
    ))
    .bind(&payload.name)
    .bind(&payload.endpoint_url)
    .bind(&payload.minimum_level)
    .bind(serde_json::to_string(&payload.event_types)?)
    .bind(&payload.auth_type)
    .bind(&payload.secret_env_name)
    .bind(payload.cooldown_minutes)
    .bind(payload.enabled)
    .bind(tenant_id)
    .bind(channel_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-Notification-Kanal konnte nicht aktualisiert werden")?;
    row.map(channel_from_pg_row).transpose().map_err(Into::into)
}

async fn update_channel_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    channel_id: i64,
    payload: &AgentNotificationChannelWriteRequest,
) -> anyhow::Result<Option<AgentNotificationChannel>> {
    let row = sqlx::query(&format!(
        "UPDATE zero_trust_agent_notification_channel SET name=?1, endpoint_url=?2, minimum_level=?3, event_types_json=?4, auth_type=?5, secret_env_name=?6, cooldown_minutes=?7, enabled=?8, updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?9 AND id=?10 RETURNING {}",
        channel_select_sql()
    ))
    .bind(&payload.name)
    .bind(&payload.endpoint_url)
    .bind(&payload.minimum_level)
    .bind(serde_json::to_string(&payload.event_types)?)
    .bind(&payload.auth_type)
    .bind(&payload.secret_env_name)
    .bind(payload.cooldown_minutes)
    .bind(payload.enabled)
    .bind(tenant_id)
    .bind(channel_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-Notification-Kanal konnte nicht aktualisiert werden")?;
    row.map(channel_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

async fn list_deliveries_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AgentNotificationDelivery>> {
    let rows = sqlx::query(&format!(
        "SELECT {} FROM zero_trust_agent_notification_delivery WHERE tenant_id=$1 ORDER BY created_at DESC, id DESC LIMIT $2",
        delivery_select_sql()
    ))
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("PostgreSQL-Notification-Deliveries konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(delivery_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_deliveries_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AgentNotificationDelivery>> {
    let rows = sqlx::query(&format!(
        "SELECT {} FROM zero_trust_agent_notification_delivery WHERE tenant_id=?1 ORDER BY created_at DESC, id DESC LIMIT ?2",
        delivery_select_sql()
    ))
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("SQLite-Notification-Deliveries konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(delivery_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn notification_tenant_ids_postgres(pool: &PgPool) -> anyhow::Result<Vec<i64>> {
    sqlx::query_scalar(
        "SELECT DISTINCT tenant_id FROM zero_trust_agent_notification_channel WHERE enabled=TRUE ORDER BY tenant_id",
    )
    .fetch_all(pool)
    .await
    .context("PostgreSQL-Notification-Tenants konnten nicht gelesen werden")
}

async fn notification_tenant_ids_sqlite(pool: &SqlitePool) -> anyhow::Result<Vec<i64>> {
    sqlx::query_scalar(
        "SELECT DISTINCT tenant_id FROM zero_trust_agent_notification_channel WHERE enabled=1 ORDER BY tenant_id",
    )
    .fetch_all(pool)
    .await
    .context("SQLite-Notification-Tenants konnten nicht gelesen werden")
}

async fn recent_delivery_postgres(
    pool: &PgPool,
    tenant_id: i64,
    channel_id: i64,
    event_key: &str,
    cooldown_minutes: i64,
) -> anyhow::Result<bool> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM zero_trust_agent_notification_delivery WHERE tenant_id=$1 AND channel_id=$2 AND event_key=$3 AND status='SENT' AND created_at::timestamp >= CURRENT_TIMESTAMP - ($4::text || ' minutes')::interval",
    )
    .bind(tenant_id)
    .bind(channel_id)
    .bind(event_key)
    .bind(cooldown_minutes)
    .fetch_one(pool)
    .await
    .context("PostgreSQL-Notification-Cooldown konnte nicht geprueft werden")?;
    Ok(count > 0)
}

async fn recent_delivery_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    channel_id: i64,
    event_key: &str,
    cooldown_minutes: i64,
) -> anyhow::Result<bool> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM zero_trust_agent_notification_delivery WHERE tenant_id=?1 AND channel_id=?2 AND event_key=?3 AND status='SENT' AND created_at >= datetime('now', '-' || ?4 || ' minutes')",
    )
    .bind(tenant_id)
    .bind(channel_id)
    .bind(event_key)
    .bind(cooldown_minutes)
    .fetch_one(pool)
    .await
    .context("SQLite-Notification-Cooldown konnte nicht geprueft werden")?;
    Ok(count > 0)
}

#[allow(clippy::too_many_arguments)]
async fn record_delivery_postgres(
    pool: &PgPool,
    tenant_id: i64,
    channel_id: i64,
    policy_id: Option<i64>,
    event_key: &str,
    level: &str,
    payload: &Value,
    attempt: &DeliveryAttempt,
) -> anyhow::Result<AgentNotificationDelivery> {
    let payload_json = serde_json::to_string(payload)?;
    let row = sqlx::query(&format!(
        "INSERT INTO zero_trust_agent_notification_delivery (tenant_id,channel_id,policy_id,event_key,event_type,level,status,response_status,error_message,payload_json,created_at,delivered_at) VALUES ($1,$2,$3,$4,'AGENT_POLICY',$5,$6,$7,$8,$9,CURRENT_TIMESTAMP::text,CASE WHEN $6='SENT' THEN CURRENT_TIMESTAMP::text ELSE NULL END) RETURNING {}",
        delivery_select_sql()
    ))
    .bind(tenant_id)
    .bind(channel_id)
    .bind(policy_id)
    .bind(event_key)
    .bind(level)
    .bind(attempt.status)
    .bind(attempt.response_status)
    .bind(&attempt.error_message)
    .bind(payload_json)
    .fetch_one(pool)
    .await
    .context("PostgreSQL-Notification-Delivery konnte nicht gespeichert werden")?;
    update_channel_delivery_state_postgres(pool, tenant_id, channel_id, attempt).await?;
    delivery_from_pg_row(row).map_err(Into::into)
}

#[allow(clippy::too_many_arguments)]
async fn record_delivery_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    channel_id: i64,
    policy_id: Option<i64>,
    event_key: &str,
    level: &str,
    payload: &Value,
    attempt: &DeliveryAttempt,
) -> anyhow::Result<AgentNotificationDelivery> {
    let payload_json = serde_json::to_string(payload)?;
    let row = sqlx::query(&format!(
        "INSERT INTO zero_trust_agent_notification_delivery (tenant_id,channel_id,policy_id,event_key,event_type,level,status,response_status,error_message,payload_json,created_at,delivered_at) VALUES (?1,?2,?3,?4,'AGENT_POLICY',?5,?6,?7,?8,?9,CURRENT_TIMESTAMP,CASE WHEN ?6='SENT' THEN CURRENT_TIMESTAMP ELSE NULL END) RETURNING {}",
        delivery_select_sql()
    ))
    .bind(tenant_id)
    .bind(channel_id)
    .bind(policy_id)
    .bind(event_key)
    .bind(level)
    .bind(attempt.status)
    .bind(attempt.response_status)
    .bind(&attempt.error_message)
    .bind(payload_json)
    .fetch_one(pool)
    .await
    .context("SQLite-Notification-Delivery konnte nicht gespeichert werden")?;
    update_channel_delivery_state_sqlite(pool, tenant_id, channel_id, attempt).await?;
    delivery_from_sqlite_row(row).map_err(Into::into)
}

async fn update_channel_delivery_state_postgres(
    pool: &PgPool,
    tenant_id: i64,
    channel_id: i64,
    attempt: &DeliveryAttempt,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE zero_trust_agent_notification_channel SET last_success_at=CASE WHEN $1='SENT' THEN CURRENT_TIMESTAMP::text ELSE last_success_at END, last_failure_at=CASE WHEN $1='FAILED' THEN CURRENT_TIMESTAMP::text ELSE last_failure_at END, last_error=CASE WHEN $1='SENT' THEN '' ELSE $2 END, updated_at=CURRENT_TIMESTAMP::text WHERE tenant_id=$3 AND id=$4",
    )
    .bind(attempt.status)
    .bind(&attempt.error_message)
    .bind(tenant_id)
    .bind(channel_id)
    .execute(pool)
    .await
    .context("PostgreSQL-Notification-Kanalstatus konnte nicht aktualisiert werden")?;
    Ok(())
}

async fn update_channel_delivery_state_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    channel_id: i64,
    attempt: &DeliveryAttempt,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE zero_trust_agent_notification_channel SET last_success_at=CASE WHEN ?1='SENT' THEN CURRENT_TIMESTAMP ELSE last_success_at END, last_failure_at=CASE WHEN ?1='FAILED' THEN CURRENT_TIMESTAMP ELSE last_failure_at END, last_error=CASE WHEN ?1='SENT' THEN '' ELSE ?2 END, updated_at=CURRENT_TIMESTAMP WHERE tenant_id=?3 AND id=?4",
    )
    .bind(attempt.status)
    .bind(&attempt.error_message)
    .bind(tenant_id)
    .bind(channel_id)
    .execute(pool)
    .await
    .context("SQLite-Notification-Kanalstatus konnte nicht aktualisiert werden")?;
    Ok(())
}

fn policy_from_pg_row(row: PgRow) -> Result<AgentPolicyProfile, sqlx::Error> {
    Ok(AgentPolicyProfile {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        scope_type: row.try_get("scope_type")?,
        scope_value: row.try_get("scope_value")?,
        expected_device_count: row.try_get("expected_device_count")?,
        heartbeat_max_age_hours: row.try_get("heartbeat_max_age_hours")?,
        minimum_zero_trust_score: row.try_get("minimum_zero_trust_score")?,
        max_critical_findings: row.try_get("max_critical_findings")?,
        max_high_findings: row.try_get("max_high_findings")?,
        enabled: row.try_get("enabled")?,
        created_by_id: row.try_get("created_by_id")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn policy_from_sqlite_row(row: SqliteRow) -> Result<AgentPolicyProfile, sqlx::Error> {
    Ok(AgentPolicyProfile {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        scope_type: row.try_get("scope_type")?,
        scope_value: row.try_get("scope_value")?,
        expected_device_count: row.try_get("expected_device_count")?,
        heartbeat_max_age_hours: row.try_get("heartbeat_max_age_hours")?,
        minimum_zero_trust_score: row.try_get("minimum_zero_trust_score")?,
        max_critical_findings: row.try_get("max_critical_findings")?,
        max_high_findings: row.try_get("max_high_findings")?,
        enabled: row.try_get("enabled")?,
        created_by_id: row.try_get("created_by_id")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn channel_from_pg_row(row: PgRow) -> Result<AgentNotificationChannel, sqlx::Error> {
    let auth_type: String = row.try_get("auth_type")?;
    let secret_env_name: String = row.try_get("secret_env_name")?;
    Ok(AgentNotificationChannel {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        name: row.try_get("name")?,
        channel_type: row.try_get("channel_type")?,
        endpoint_url: row.try_get("endpoint_url")?,
        minimum_level: row.try_get("minimum_level")?,
        event_types: json_string_array(&row.try_get::<String, _>("event_types_json")?),
        auth_type: auth_type.clone(),
        secret_env_name: secret_env_name.clone(),
        secret_available: secret_available(&auth_type, &secret_env_name),
        cooldown_minutes: row.try_get("cooldown_minutes")?,
        enabled: row.try_get("enabled")?,
        created_by_id: row.try_get("created_by_id")?,
        last_success_at: row.try_get("last_success_at")?,
        last_failure_at: row.try_get("last_failure_at")?,
        last_error: row.try_get("last_error")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn channel_from_sqlite_row(row: SqliteRow) -> Result<AgentNotificationChannel, sqlx::Error> {
    let auth_type: String = row.try_get("auth_type")?;
    let secret_env_name: String = row.try_get("secret_env_name")?;
    Ok(AgentNotificationChannel {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        name: row.try_get("name")?,
        channel_type: row.try_get("channel_type")?,
        endpoint_url: row.try_get("endpoint_url")?,
        minimum_level: row.try_get("minimum_level")?,
        event_types: json_string_array(&row.try_get::<String, _>("event_types_json")?),
        auth_type: auth_type.clone(),
        secret_env_name: secret_env_name.clone(),
        secret_available: secret_available(&auth_type, &secret_env_name),
        cooldown_minutes: row.try_get("cooldown_minutes")?,
        enabled: row.try_get("enabled")?,
        created_by_id: row.try_get("created_by_id")?,
        last_success_at: row.try_get("last_success_at")?,
        last_failure_at: row.try_get("last_failure_at")?,
        last_error: row.try_get("last_error")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn delivery_from_pg_row(row: PgRow) -> Result<AgentNotificationDelivery, sqlx::Error> {
    Ok(AgentNotificationDelivery {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        channel_id: row.try_get("channel_id")?,
        policy_id: row.try_get("policy_id")?,
        event_key: row.try_get("event_key")?,
        event_type: row.try_get("event_type")?,
        level: row.try_get("level")?,
        status: row.try_get("status")?,
        response_status: row.try_get("response_status")?,
        error_message: row.try_get("error_message")?,
        payload: serde_json::from_str(&row.try_get::<String, _>("payload_json")?)
            .unwrap_or_else(|_| json!({})),
        created_at: row.try_get("created_at")?,
        delivered_at: row.try_get("delivered_at")?,
    })
}

fn delivery_from_sqlite_row(row: SqliteRow) -> Result<AgentNotificationDelivery, sqlx::Error> {
    Ok(AgentNotificationDelivery {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        channel_id: row.try_get("channel_id")?,
        policy_id: row.try_get("policy_id")?,
        event_key: row.try_get("event_key")?,
        event_type: row.try_get("event_type")?,
        level: row.try_get("level")?,
        status: row.try_get("status")?,
        response_status: row.try_get("response_status")?,
        error_message: row.try_get("error_message")?,
        payload: serde_json::from_str(&row.try_get::<String, _>("payload_json")?)
            .unwrap_or_else(|_| json!({})),
        created_at: row.try_get("created_at")?,
        delivered_at: row.try_get("delivered_at")?,
    })
}

fn device_signal_from_pg_row(row: PgRow) -> Result<AgentPolicyDeviceSignal, sqlx::Error> {
    Ok(AgentPolicyDeviceSignal {
        os_family: row.try_get("os_family")?,
        deployment_channel: row.try_get("deployment_channel")?,
        enrollment_status: row.try_get("enrollment_status")?,
        zero_trust_score: row.try_get("zero_trust_score")?,
        last_seen_at: row.try_get("last_seen_at")?,
        critical_finding_count: row.try_get("critical_finding_count")?,
        high_finding_count: row.try_get("high_finding_count")?,
        asset_type: row.try_get("asset_type")?,
        business_unit_id: row.try_get("business_unit_id")?,
        business_unit_name: row.try_get("business_unit_name")?,
    })
}

fn device_signal_from_sqlite_row(row: SqliteRow) -> Result<AgentPolicyDeviceSignal, sqlx::Error> {
    Ok(AgentPolicyDeviceSignal {
        os_family: row.try_get("os_family")?,
        deployment_channel: row.try_get("deployment_channel")?,
        enrollment_status: row.try_get("enrollment_status")?,
        zero_trust_score: row.try_get("zero_trust_score")?,
        last_seen_at: row.try_get("last_seen_at")?,
        critical_finding_count: row.try_get("critical_finding_count")?,
        high_finding_count: row.try_get("high_finding_count")?,
        asset_type: row.try_get("asset_type")?,
        business_unit_id: row.try_get("business_unit_id")?,
        business_unit_name: row.try_get("business_unit_name")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_validation_normalizes_tenant_scope() {
        let policy = validate_policy_payload(AgentPolicyWriteRequest {
            name: " Tenant baseline ".to_string(),
            description: String::new(),
            scope_type: "tenant".to_string(),
            scope_value: "ignored".to_string(),
            expected_device_count: 1,
            heartbeat_max_age_hours: 24,
            minimum_zero_trust_score: 80,
            max_critical_findings: 0,
            max_high_findings: 0,
            enabled: true,
        })
        .unwrap();
        assert_eq!(policy.name, "Tenant baseline");
        assert_eq!(policy.scope_type, "TENANT");
        assert!(policy.scope_value.is_empty());
    }

    #[test]
    fn webhook_and_secret_validation_rejects_unsafe_values() {
        assert!(validate_webhook_url("file:///tmp/notification").is_err());
        assert!(validate_webhook_url("http://127.0.0.1:9000/hook").is_ok());
        assert!(valid_env_name("ISCY_NOTIFY_SECRET"));
        assert!(!valid_env_name("ISCY-NOTIFY-SECRET"));
        for status in [429, 500, 502, 503, 504] {
            assert!(webhook_retryable_status(status));
        }
        for status in [400, 401, 403, 404, 422] {
            assert!(!webhook_retryable_status(status));
        }
    }
}
