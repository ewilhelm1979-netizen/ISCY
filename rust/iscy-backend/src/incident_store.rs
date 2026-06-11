use anyhow::{bail, Context};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Row,
};

use crate::cve_store::normalize_database_url;

#[derive(Clone)]
pub enum IncidentStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Serialize)]
pub struct IncidentSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub reporter_id: Option<i64>,
    pub reporter_display: Option<String>,
    pub owner_id: Option<i64>,
    pub owner_display: Option<String>,
    pub related_risk_id: Option<i64>,
    pub related_risk_title: Option<String>,
    pub related_asset_id: Option<i64>,
    pub related_asset_name: Option<String>,
    pub related_process_id: Option<i64>,
    pub related_process_name: Option<String>,
    pub title: String,
    pub summary: String,
    pub incident_type: String,
    pub incident_type_label: String,
    pub runbook_template: String,
    pub severity: String,
    pub severity_label: String,
    pub status: String,
    pub status_label: String,
    pub detected_at: Option<String>,
    pub confirmed_at: Option<String>,
    pub contained_at: Option<String>,
    pub resolved_at: Option<String>,
    pub nis2_reportable: bool,
    pub nis2_reportability_label: String,
    pub early_warning_due_at: Option<String>,
    pub early_warning_sent_at: Option<String>,
    pub early_warning_state: String,
    pub early_warning_state_label: String,
    pub notification_due_at: Option<String>,
    pub notification_sent_at: Option<String>,
    pub notification_state: String,
    pub notification_state_label: String,
    pub final_report_due_at: Option<String>,
    pub final_report_sent_at: Option<String>,
    pub final_report_state: String,
    pub final_report_state_label: String,
    pub authority_reference: String,
    pub stakeholder_summary: String,
    pub lessons_learned: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct IncidentEventSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub incident_id: i64,
    pub actor_id: Option<i64>,
    pub actor_display: Option<String>,
    pub event_type: String,
    pub event_type_label: String,
    pub summary: String,
    pub detail: String,
    pub from_status: Option<String>,
    pub from_status_label: Option<String>,
    pub to_status: Option<String>,
    pub to_status_label: Option<String>,
    pub evidence_item_id: Option<i64>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct IncidentRunbookTemplateSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub slug: String,
    pub title: String,
    pub description: String,
    pub incident_type: String,
    pub incident_type_label: String,
    pub severity: String,
    pub severity_label: String,
    pub body: String,
    pub is_active: bool,
    pub sort_order: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IncidentWriteRequest {
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub reporter_id: Option<Option<i64>>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub owner_id: Option<Option<i64>>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub related_risk_id: Option<Option<i64>>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub related_asset_id: Option<Option<i64>>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub related_process_id: Option<Option<i64>>,
    pub title: Option<String>,
    pub summary: Option<String>,
    pub incident_type: Option<String>,
    pub runbook_template: Option<String>,
    pub severity: Option<String>,
    pub status: Option<String>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub detected_at: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub confirmed_at: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub contained_at: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub resolved_at: Option<Option<String>>,
    pub nis2_reportable: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub early_warning_sent_at: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub notification_sent_at: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub final_report_sent_at: Option<Option<String>>,
    pub authority_reference: Option<String>,
    pub stakeholder_summary: Option<String>,
    pub lessons_learned: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IncidentWriteResult {
    pub incident: IncidentSummary,
    pub events: Vec<IncidentEventSummary>,
}

#[derive(Debug, Clone)]
pub struct IncidentEventWriteRequest {
    pub event_type: String,
    pub summary: String,
    pub detail: String,
    pub from_status: Option<String>,
    pub to_status: Option<String>,
    pub evidence_item_id: Option<i64>,
}

impl IncidentEventWriteRequest {
    pub fn created(title: &str) -> Self {
        Self {
            event_type: "CREATED".to_string(),
            summary: format!("Fallakte '{}' angelegt.", limit_chars(title, 180)),
            detail: "Incident wurde als neue ISCY-Fallakte erfasst.".to_string(),
            from_status: None,
            to_status: None,
            evidence_item_id: None,
        }
    }

    pub fn status_changed(
        from_status: &str,
        to_status: &str,
        from_label: &str,
        to_label: &str,
    ) -> Self {
        Self {
            event_type: "STATUS_CHANGED".to_string(),
            summary: format!("Status von {} auf {} geaendert.", from_label, to_label),
            detail: "Statuswechsel wurde ueber den Rust-Incident-Workflow dokumentiert."
                .to_string(),
            from_status: Some(from_status.to_string()),
            to_status: Some(to_status.to_string()),
            evidence_item_id: None,
        }
    }

    pub fn evidence_uploaded(evidence_item_id: i64, title: &str) -> Self {
        Self {
            event_type: "EVIDENCE_UPLOADED".to_string(),
            summary: format!("Evidence '{}' hinzugefuegt.", limit_chars(title, 180)),
            detail: "Evidence wurde direkt mit dieser Fallakte verknuepft.".to_string(),
            from_status: None,
            to_status: None,
            evidence_item_id: Some(evidence_item_id),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum TenantRelation {
    User,
    Risk,
    Asset,
    Process,
}

fn deserialize_double_option<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

impl IncidentStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Incident-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Incident-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-Incident-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn list_incidents(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<IncidentSummary>> {
        match self {
            Self::Postgres(pool) => list_incidents_postgres(pool, tenant_id, limit).await,
            Self::Sqlite(pool) => list_incidents_sqlite(pool, tenant_id, limit).await,
        }
    }

    pub async fn incident_detail(
        &self,
        tenant_id: i64,
        incident_id: i64,
    ) -> anyhow::Result<Option<IncidentSummary>> {
        match self {
            Self::Postgres(pool) => incident_detail_postgres(pool, tenant_id, incident_id).await,
            Self::Sqlite(pool) => incident_detail_sqlite(pool, tenant_id, incident_id).await,
        }
    }

    pub async fn list_incident_events(
        &self,
        tenant_id: i64,
        incident_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<IncidentEventSummary>> {
        match self {
            Self::Postgres(pool) => {
                list_incident_events_postgres(pool, tenant_id, incident_id, limit).await
            }
            Self::Sqlite(pool) => {
                list_incident_events_sqlite(pool, tenant_id, incident_id, limit).await
            }
        }
    }

    pub async fn list_runbook_templates(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<IncidentRunbookTemplateSummary>> {
        match self {
            Self::Postgres(pool) => list_runbook_templates_postgres(pool, tenant_id, limit).await,
            Self::Sqlite(pool) => list_runbook_templates_sqlite(pool, tenant_id, limit).await,
        }
    }

    pub async fn append_incident_event(
        &self,
        tenant_id: i64,
        incident_id: i64,
        actor_id: Option<i64>,
        payload: IncidentEventWriteRequest,
    ) -> anyhow::Result<IncidentEventSummary> {
        match self {
            Self::Postgres(pool) => {
                append_incident_event_postgres(pool, tenant_id, incident_id, actor_id, payload)
                    .await
            }
            Self::Sqlite(pool) => {
                append_incident_event_sqlite(pool, tenant_id, incident_id, actor_id, payload).await
            }
        }
    }

    pub async fn create_incident(
        &self,
        tenant_id: i64,
        actor_id: Option<i64>,
        payload: IncidentWriteRequest,
    ) -> anyhow::Result<IncidentWriteResult> {
        match self {
            Self::Postgres(pool) => {
                create_incident_postgres(pool, tenant_id, actor_id, payload).await
            }
            Self::Sqlite(pool) => create_incident_sqlite(pool, tenant_id, actor_id, payload).await,
        }
    }

    pub async fn update_incident(
        &self,
        tenant_id: i64,
        incident_id: i64,
        actor_id: Option<i64>,
        payload: IncidentWriteRequest,
    ) -> anyhow::Result<Option<IncidentWriteResult>> {
        match self {
            Self::Postgres(pool) => {
                update_incident_postgres(pool, tenant_id, incident_id, actor_id, payload).await
            }
            Self::Sqlite(pool) => {
                update_incident_sqlite(pool, tenant_id, incident_id, actor_id, payload).await
            }
        }
    }
}

async fn list_runbook_templates_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<IncidentRunbookTemplateSummary>> {
    let rows = sqlx::query(
        r#"
        SELECT
            id,
            tenant_id,
            slug,
            title,
            description,
            incident_type,
            severity,
            body,
            is_active,
            sort_order::bigint AS sort_order,
            created_at::text AS created_at,
            updated_at::text AS updated_at
        FROM incidents_runbooktemplate
        WHERE tenant_id = $1 AND is_active = TRUE
        ORDER BY sort_order ASC, title ASC, id ASC
        LIMIT $2
        "#,
    )
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("PostgreSQL-Incident-Runbook-Templates konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(runbook_template_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_runbook_templates_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<IncidentRunbookTemplateSummary>> {
    let rows = sqlx::query(
        r#"
        SELECT
            id,
            tenant_id,
            slug,
            title,
            description,
            incident_type,
            severity,
            body,
            is_active,
            sort_order,
            CAST(created_at AS TEXT) AS created_at,
            CAST(updated_at AS TEXT) AS updated_at
        FROM incidents_runbooktemplate
        WHERE tenant_id = ?1 AND is_active = 1
        ORDER BY sort_order ASC, title ASC, id ASC
        LIMIT ?2
        "#,
    )
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("SQLite-Incident-Runbook-Templates konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(runbook_template_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_incidents_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<IncidentSummary>> {
    let sql = incident_select_postgres_sql("WHERE incident.tenant_id = $1", "$2");
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Incidentliste konnte nicht gelesen werden")?;
    rows.into_iter()
        .map(summary_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_incidents_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<IncidentSummary>> {
    let sql = incident_select_sqlite_sql("WHERE incident.tenant_id = ?1", "?2");
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("SQLite-Incidentliste konnte nicht gelesen werden")?;
    rows.into_iter()
        .map(summary_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn incident_detail_postgres(
    pool: &PgPool,
    tenant_id: i64,
    incident_id: i64,
) -> anyhow::Result<Option<IncidentSummary>> {
    let sql =
        incident_select_postgres_sql("WHERE incident.tenant_id = $1 AND incident.id = $2", "1");
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(incident_id)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-Incidentdetail konnte nicht gelesen werden")?;
    row.map(summary_from_pg_row).transpose().map_err(Into::into)
}

async fn incident_detail_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    incident_id: i64,
) -> anyhow::Result<Option<IncidentSummary>> {
    let sql = incident_select_sqlite_sql("WHERE incident.tenant_id = ?1 AND incident.id = ?2", "1");
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(incident_id)
        .fetch_optional(pool)
        .await
        .context("SQLite-Incidentdetail konnte nicht gelesen werden")?;
    row.map(summary_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

async fn list_incident_events_postgres(
    pool: &PgPool,
    tenant_id: i64,
    incident_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<IncidentEventSummary>> {
    ensure_incident_exists_postgres(pool, tenant_id, incident_id).await?;
    let rows = sqlx::query(
        r#"
        SELECT
            event.id,
            event.tenant_id,
            event.incident_id,
            event.actor_id,
            actor.username AS actor_username,
            actor.first_name AS actor_first_name,
            actor.last_name AS actor_last_name,
            event.event_type,
            event.summary,
            event.detail,
            event.from_status,
            event.to_status,
            event.evidence_item_id,
            event.created_at::text AS created_at
        FROM incidents_incidentevent event
        LEFT JOIN accounts_user actor
            ON actor.id = event.actor_id AND actor.tenant_id = event.tenant_id
        WHERE event.tenant_id = $1 AND event.incident_id = $2
        ORDER BY event.created_at DESC, event.id DESC
        LIMIT $3
        "#,
    )
    .bind(tenant_id)
    .bind(incident_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("PostgreSQL-Incident-Timeline konnte nicht gelesen werden")?;
    rows.into_iter()
        .map(event_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_incident_events_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    incident_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<IncidentEventSummary>> {
    ensure_incident_exists_sqlite(pool, tenant_id, incident_id).await?;
    let rows = sqlx::query(
        r#"
        SELECT
            event.id,
            event.tenant_id,
            event.incident_id,
            event.actor_id,
            actor.username AS actor_username,
            actor.first_name AS actor_first_name,
            actor.last_name AS actor_last_name,
            event.event_type,
            event.summary,
            event.detail,
            event.from_status,
            event.to_status,
            event.evidence_item_id,
            CAST(event.created_at AS TEXT) AS created_at
        FROM incidents_incidentevent event
        LEFT JOIN accounts_user actor
            ON actor.id = event.actor_id AND actor.tenant_id = event.tenant_id
        WHERE event.tenant_id = ?1 AND event.incident_id = ?2
        ORDER BY event.created_at DESC, event.id DESC
        LIMIT ?3
        "#,
    )
    .bind(tenant_id)
    .bind(incident_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("SQLite-Incident-Timeline konnte nicht gelesen werden")?;
    rows.into_iter()
        .map(event_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn append_incident_event_postgres(
    pool: &PgPool,
    tenant_id: i64,
    incident_id: i64,
    actor_id: Option<i64>,
    payload: IncidentEventWriteRequest,
) -> anyhow::Result<IncidentEventSummary> {
    ensure_incident_exists_postgres(pool, tenant_id, incident_id).await?;
    let event = NormalizedIncidentEvent::from_payload(actor_id, payload);
    let row = sqlx::query(
        r#"
        INSERT INTO incidents_incidentevent (
            tenant_id, incident_id, actor_id, event_type, summary, detail,
            from_status, to_status, evidence_item_id, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(incident_id)
    .bind(event.actor_id)
    .bind(&event.event_type)
    .bind(&event.summary)
    .bind(&event.detail)
    .bind(event.from_status.as_deref())
    .bind(event.to_status.as_deref())
    .bind(event.evidence_item_id)
    .bind(&event.created_at)
    .fetch_one(pool)
    .await
    .context("PostgreSQL-Incident-Event konnte nicht gespeichert werden")?;
    let id: i64 = row.try_get("id")?;
    incident_event_detail_postgres(pool, tenant_id, incident_id, id)
        .await?
        .context("Neu angelegtes Incident-Event konnte nicht gelesen werden")
}

async fn append_incident_event_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    incident_id: i64,
    actor_id: Option<i64>,
    payload: IncidentEventWriteRequest,
) -> anyhow::Result<IncidentEventSummary> {
    ensure_incident_exists_sqlite(pool, tenant_id, incident_id).await?;
    let event = NormalizedIncidentEvent::from_payload(actor_id, payload);
    let result = sqlx::query(
        r#"
        INSERT INTO incidents_incidentevent (
            tenant_id, incident_id, actor_id, event_type, summary, detail,
            from_status, to_status, evidence_item_id, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        "#,
    )
    .bind(tenant_id)
    .bind(incident_id)
    .bind(event.actor_id)
    .bind(&event.event_type)
    .bind(&event.summary)
    .bind(&event.detail)
    .bind(event.from_status.as_deref())
    .bind(event.to_status.as_deref())
    .bind(event.evidence_item_id)
    .bind(&event.created_at)
    .execute(pool)
    .await
    .context("SQLite-Incident-Event konnte nicht gespeichert werden")?;
    let id = result.last_insert_rowid();
    incident_event_detail_sqlite(pool, tenant_id, incident_id, id)
        .await?
        .context("Neu angelegtes Incident-Event konnte nicht gelesen werden")
}

async fn incident_event_detail_postgres(
    pool: &PgPool,
    tenant_id: i64,
    incident_id: i64,
    event_id: i64,
) -> anyhow::Result<Option<IncidentEventSummary>> {
    let row = sqlx::query(
        r#"
        SELECT
            event.id,
            event.tenant_id,
            event.incident_id,
            event.actor_id,
            actor.username AS actor_username,
            actor.first_name AS actor_first_name,
            actor.last_name AS actor_last_name,
            event.event_type,
            event.summary,
            event.detail,
            event.from_status,
            event.to_status,
            event.evidence_item_id,
            event.created_at::text AS created_at
        FROM incidents_incidentevent event
        LEFT JOIN accounts_user actor
            ON actor.id = event.actor_id AND actor.tenant_id = event.tenant_id
        WHERE event.tenant_id = $1 AND event.incident_id = $2 AND event.id = $3
        "#,
    )
    .bind(tenant_id)
    .bind(incident_id)
    .bind(event_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-Incident-Event konnte nicht gelesen werden")?;
    row.map(event_from_pg_row).transpose().map_err(Into::into)
}

async fn incident_event_detail_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    incident_id: i64,
    event_id: i64,
) -> anyhow::Result<Option<IncidentEventSummary>> {
    let row = sqlx::query(
        r#"
        SELECT
            event.id,
            event.tenant_id,
            event.incident_id,
            event.actor_id,
            actor.username AS actor_username,
            actor.first_name AS actor_first_name,
            actor.last_name AS actor_last_name,
            event.event_type,
            event.summary,
            event.detail,
            event.from_status,
            event.to_status,
            event.evidence_item_id,
            CAST(event.created_at AS TEXT) AS created_at
        FROM incidents_incidentevent event
        LEFT JOIN accounts_user actor
            ON actor.id = event.actor_id AND actor.tenant_id = event.tenant_id
        WHERE event.tenant_id = ?1 AND event.incident_id = ?2 AND event.id = ?3
        "#,
    )
    .bind(tenant_id)
    .bind(incident_id)
    .bind(event_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-Incident-Event konnte nicht gelesen werden")?;
    row.map(event_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

async fn ensure_incident_exists_postgres(
    pool: &PgPool,
    tenant_id: i64,
    incident_id: i64,
) -> anyhow::Result<()> {
    let exists: Option<i64> =
        sqlx::query_scalar("SELECT id FROM incidents_incident WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(incident_id)
            .fetch_optional(pool)
            .await?;
    if exists.is_none() {
        bail!("Incident {} wurde nicht gefunden.", incident_id);
    }
    Ok(())
}

async fn ensure_incident_exists_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    incident_id: i64,
) -> anyhow::Result<()> {
    let exists: Option<i64> =
        sqlx::query_scalar("SELECT id FROM incidents_incident WHERE tenant_id = ?1 AND id = ?2")
            .bind(tenant_id)
            .bind(incident_id)
            .fetch_optional(pool)
            .await?;
    if exists.is_none() {
        bail!("Incident {} wurde nicht gefunden.", incident_id);
    }
    Ok(())
}

async fn create_incident_postgres(
    pool: &PgPool,
    tenant_id: i64,
    actor_id: Option<i64>,
    payload: IncidentWriteRequest,
) -> anyhow::Result<IncidentWriteResult> {
    let write = NewIncident::from_create_payload(payload)?;
    validate_relations_postgres(pool, tenant_id, &write).await?;
    let row = sqlx::query(
        r#"
        INSERT INTO incidents_incident (
            tenant_id, reporter_id, owner_id, related_risk_id, related_asset_id,
            related_process_id, title, summary, incident_type, runbook_template, severity, status, detected_at,
            confirmed_at, contained_at, resolved_at, nis2_reportable,
            early_warning_due_at, early_warning_sent_at, notification_due_at,
            notification_sent_at, final_report_due_at, final_report_sent_at,
            authority_reference, stakeholder_summary, lessons_learned, created_at, updated_at
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
            $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28
        )
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(write.reporter_id)
    .bind(write.owner_id)
    .bind(write.related_risk_id)
    .bind(write.related_asset_id)
    .bind(write.related_process_id)
    .bind(&write.title)
    .bind(&write.summary)
    .bind(&write.incident_type)
    .bind(&write.runbook_template)
    .bind(&write.severity)
    .bind(&write.status)
    .bind(write.detected_at.as_deref())
    .bind(write.confirmed_at.as_deref())
    .bind(write.contained_at.as_deref())
    .bind(write.resolved_at.as_deref())
    .bind(write.nis2_reportable)
    .bind(write.early_warning_due_at.as_deref())
    .bind(write.early_warning_sent_at.as_deref())
    .bind(write.notification_due_at.as_deref())
    .bind(write.notification_sent_at.as_deref())
    .bind(write.final_report_due_at.as_deref())
    .bind(write.final_report_sent_at.as_deref())
    .bind(&write.authority_reference)
    .bind(&write.stakeholder_summary)
    .bind(&write.lessons_learned)
    .bind(&write.now)
    .bind(&write.now)
    .fetch_one(pool)
    .await
    .context("PostgreSQL-Incident konnte nicht angelegt werden")?;
    let id: i64 = row.try_get("id")?;
    let incident = incident_detail_postgres(pool, tenant_id, id)
        .await?
        .context("Neu angelegter Incident konnte nicht gelesen werden")?;
    let event = append_incident_event_postgres(
        pool,
        tenant_id,
        id,
        actor_id,
        IncidentEventWriteRequest::created(&incident.title),
    )
    .await?;
    Ok(IncidentWriteResult {
        incident,
        events: vec![event],
    })
}

async fn create_incident_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    actor_id: Option<i64>,
    payload: IncidentWriteRequest,
) -> anyhow::Result<IncidentWriteResult> {
    let write = NewIncident::from_create_payload(payload)?;
    validate_relations_sqlite(pool, tenant_id, &write).await?;
    let result = sqlx::query(
        r#"
        INSERT INTO incidents_incident (
            tenant_id, reporter_id, owner_id, related_risk_id, related_asset_id,
            related_process_id, title, summary, incident_type, runbook_template, severity, status, detected_at,
            confirmed_at, contained_at, resolved_at, nis2_reportable,
            early_warning_due_at, early_warning_sent_at, notification_due_at,
            notification_sent_at, final_report_due_at, final_report_sent_at,
            authority_reference, stakeholder_summary, lessons_learned, created_at, updated_at
        )
        VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
            ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28
        )
        "#,
    )
    .bind(tenant_id)
    .bind(write.reporter_id)
    .bind(write.owner_id)
    .bind(write.related_risk_id)
    .bind(write.related_asset_id)
    .bind(write.related_process_id)
    .bind(&write.title)
    .bind(&write.summary)
    .bind(&write.incident_type)
    .bind(&write.runbook_template)
    .bind(&write.severity)
    .bind(&write.status)
    .bind(write.detected_at.as_deref())
    .bind(write.confirmed_at.as_deref())
    .bind(write.contained_at.as_deref())
    .bind(write.resolved_at.as_deref())
    .bind(write.nis2_reportable)
    .bind(write.early_warning_due_at.as_deref())
    .bind(write.early_warning_sent_at.as_deref())
    .bind(write.notification_due_at.as_deref())
    .bind(write.notification_sent_at.as_deref())
    .bind(write.final_report_due_at.as_deref())
    .bind(write.final_report_sent_at.as_deref())
    .bind(&write.authority_reference)
    .bind(&write.stakeholder_summary)
    .bind(&write.lessons_learned)
    .bind(&write.now)
    .bind(&write.now)
    .execute(pool)
    .await
    .context("SQLite-Incident konnte nicht angelegt werden")?;
    let id = result.last_insert_rowid();
    let incident = incident_detail_sqlite(pool, tenant_id, id)
        .await?
        .context("Neu angelegter Incident konnte nicht gelesen werden")?;
    let event = append_incident_event_sqlite(
        pool,
        tenant_id,
        id,
        actor_id,
        IncidentEventWriteRequest::created(&incident.title),
    )
    .await?;
    Ok(IncidentWriteResult {
        incident,
        events: vec![event],
    })
}

async fn update_incident_postgres(
    pool: &PgPool,
    tenant_id: i64,
    incident_id: i64,
    actor_id: Option<i64>,
    payload: IncidentWriteRequest,
) -> anyhow::Result<Option<IncidentWriteResult>> {
    let Some(current) = incident_detail_postgres(pool, tenant_id, incident_id).await? else {
        return Ok(None);
    };
    let write = ExistingIncident::from_update_payload(current.clone(), payload)?;
    validate_relations_postgres(pool, tenant_id, &write.as_new_incident()).await?;
    sqlx::query(
        r#"
        UPDATE incidents_incident
        SET reporter_id = $3, owner_id = $4, related_risk_id = $5, related_asset_id = $6,
            related_process_id = $7, title = $8, summary = $9, incident_type = $10,
            runbook_template = $11, severity = $12, status = $13, detected_at = $14,
            confirmed_at = $15, contained_at = $16, resolved_at = $17, nis2_reportable = $18,
            early_warning_due_at = $19, early_warning_sent_at = $20,
            notification_due_at = $21, notification_sent_at = $22, final_report_due_at = $23,
            final_report_sent_at = $24, authority_reference = $25,
            stakeholder_summary = $26, lessons_learned = $27, updated_at = $28
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(incident_id)
    .bind(write.reporter_id)
    .bind(write.owner_id)
    .bind(write.related_risk_id)
    .bind(write.related_asset_id)
    .bind(write.related_process_id)
    .bind(&write.title)
    .bind(&write.summary)
    .bind(&write.incident_type)
    .bind(&write.runbook_template)
    .bind(&write.severity)
    .bind(&write.status)
    .bind(write.detected_at.as_deref())
    .bind(write.confirmed_at.as_deref())
    .bind(write.contained_at.as_deref())
    .bind(write.resolved_at.as_deref())
    .bind(write.nis2_reportable)
    .bind(write.early_warning_due_at.as_deref())
    .bind(write.early_warning_sent_at.as_deref())
    .bind(write.notification_due_at.as_deref())
    .bind(write.notification_sent_at.as_deref())
    .bind(write.final_report_due_at.as_deref())
    .bind(write.final_report_sent_at.as_deref())
    .bind(&write.authority_reference)
    .bind(&write.stakeholder_summary)
    .bind(&write.lessons_learned)
    .bind(&write.now)
    .execute(pool)
    .await
    .context("PostgreSQL-Incident konnte nicht aktualisiert werden")?;
    let incident = incident_detail_postgres(pool, tenant_id, incident_id)
        .await?
        .context("Aktualisierter Incident konnte nicht gelesen werden")?;
    let events = incident_update_events_postgres(
        pool,
        tenant_id,
        incident_id,
        actor_id,
        &current,
        &incident,
    )
    .await?;
    Ok(Some(IncidentWriteResult { incident, events }))
}

async fn update_incident_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    incident_id: i64,
    actor_id: Option<i64>,
    payload: IncidentWriteRequest,
) -> anyhow::Result<Option<IncidentWriteResult>> {
    let Some(current) = incident_detail_sqlite(pool, tenant_id, incident_id).await? else {
        return Ok(None);
    };
    let write = ExistingIncident::from_update_payload(current.clone(), payload)?;
    validate_relations_sqlite(pool, tenant_id, &write.as_new_incident()).await?;
    sqlx::query(
        r#"
        UPDATE incidents_incident
        SET reporter_id = ?3, owner_id = ?4, related_risk_id = ?5, related_asset_id = ?6,
            related_process_id = ?7, title = ?8, summary = ?9, incident_type = ?10,
            runbook_template = ?11, severity = ?12, status = ?13, detected_at = ?14,
            confirmed_at = ?15, contained_at = ?16, resolved_at = ?17, nis2_reportable = ?18,
            early_warning_due_at = ?19, early_warning_sent_at = ?20,
            notification_due_at = ?21, notification_sent_at = ?22, final_report_due_at = ?23,
            final_report_sent_at = ?24, authority_reference = ?25,
            stakeholder_summary = ?26, lessons_learned = ?27, updated_at = ?28
        WHERE tenant_id = ?1 AND id = ?2
        "#,
    )
    .bind(tenant_id)
    .bind(incident_id)
    .bind(write.reporter_id)
    .bind(write.owner_id)
    .bind(write.related_risk_id)
    .bind(write.related_asset_id)
    .bind(write.related_process_id)
    .bind(&write.title)
    .bind(&write.summary)
    .bind(&write.incident_type)
    .bind(&write.runbook_template)
    .bind(&write.severity)
    .bind(&write.status)
    .bind(write.detected_at.as_deref())
    .bind(write.confirmed_at.as_deref())
    .bind(write.contained_at.as_deref())
    .bind(write.resolved_at.as_deref())
    .bind(write.nis2_reportable)
    .bind(write.early_warning_due_at.as_deref())
    .bind(write.early_warning_sent_at.as_deref())
    .bind(write.notification_due_at.as_deref())
    .bind(write.notification_sent_at.as_deref())
    .bind(write.final_report_due_at.as_deref())
    .bind(write.final_report_sent_at.as_deref())
    .bind(&write.authority_reference)
    .bind(&write.stakeholder_summary)
    .bind(&write.lessons_learned)
    .bind(&write.now)
    .execute(pool)
    .await
    .context("SQLite-Incident konnte nicht aktualisiert werden")?;
    let incident = incident_detail_sqlite(pool, tenant_id, incident_id)
        .await?
        .context("Aktualisierter Incident konnte nicht gelesen werden")?;
    let events =
        incident_update_events_sqlite(pool, tenant_id, incident_id, actor_id, &current, &incident)
            .await?;
    Ok(Some(IncidentWriteResult { incident, events }))
}

#[derive(Debug, Clone)]
struct NewIncident {
    reporter_id: Option<i64>,
    owner_id: Option<i64>,
    related_risk_id: Option<i64>,
    related_asset_id: Option<i64>,
    related_process_id: Option<i64>,
    title: String,
    summary: String,
    incident_type: String,
    runbook_template: String,
    severity: String,
    status: String,
    detected_at: Option<String>,
    confirmed_at: Option<String>,
    contained_at: Option<String>,
    resolved_at: Option<String>,
    nis2_reportable: bool,
    early_warning_due_at: Option<String>,
    early_warning_sent_at: Option<String>,
    notification_due_at: Option<String>,
    notification_sent_at: Option<String>,
    final_report_due_at: Option<String>,
    final_report_sent_at: Option<String>,
    authority_reference: String,
    stakeholder_summary: String,
    lessons_learned: String,
    now: String,
}

#[derive(Debug, Clone)]
struct ExistingIncident {
    reporter_id: Option<i64>,
    owner_id: Option<i64>,
    related_risk_id: Option<i64>,
    related_asset_id: Option<i64>,
    related_process_id: Option<i64>,
    title: String,
    summary: String,
    incident_type: String,
    runbook_template: String,
    severity: String,
    status: String,
    detected_at: Option<String>,
    confirmed_at: Option<String>,
    contained_at: Option<String>,
    resolved_at: Option<String>,
    nis2_reportable: bool,
    early_warning_due_at: Option<String>,
    early_warning_sent_at: Option<String>,
    notification_due_at: Option<String>,
    notification_sent_at: Option<String>,
    final_report_due_at: Option<String>,
    final_report_sent_at: Option<String>,
    authority_reference: String,
    stakeholder_summary: String,
    lessons_learned: String,
    now: String,
}

#[derive(Debug, Clone)]
struct NormalizedIncidentEvent {
    actor_id: Option<i64>,
    event_type: String,
    summary: String,
    detail: String,
    from_status: Option<String>,
    to_status: Option<String>,
    evidence_item_id: Option<i64>,
    created_at: String,
}

impl NormalizedIncidentEvent {
    fn from_payload(actor_id: Option<i64>, payload: IncidentEventWriteRequest) -> Self {
        Self {
            actor_id,
            event_type: normalize_event_type(&payload.event_type),
            summary: normalize_event_summary(&payload.summary),
            detail: normalize_optional_text(Some(&payload.detail)),
            from_status: payload
                .from_status
                .as_deref()
                .map(|value| normalize_status(Some(value))),
            to_status: payload
                .to_status
                .as_deref()
                .map(|value| normalize_status(Some(value))),
            evidence_item_id: payload.evidence_item_id,
            created_at: Utc::now().to_rfc3339(),
        }
    }
}

async fn incident_update_events_postgres(
    pool: &PgPool,
    tenant_id: i64,
    incident_id: i64,
    actor_id: Option<i64>,
    current: &IncidentSummary,
    updated: &IncidentSummary,
) -> anyhow::Result<Vec<IncidentEventSummary>> {
    let mut events = Vec::new();
    if current.status != updated.status {
        events.push(
            append_incident_event_postgres(
                pool,
                tenant_id,
                incident_id,
                actor_id,
                IncidentEventWriteRequest::status_changed(
                    &current.status,
                    &updated.status,
                    &current.status_label,
                    &updated.status_label,
                ),
            )
            .await?,
        );
    }
    Ok(events)
}

async fn incident_update_events_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    incident_id: i64,
    actor_id: Option<i64>,
    current: &IncidentSummary,
    updated: &IncidentSummary,
) -> anyhow::Result<Vec<IncidentEventSummary>> {
    let mut events = Vec::new();
    if current.status != updated.status {
        events.push(
            append_incident_event_sqlite(
                pool,
                tenant_id,
                incident_id,
                actor_id,
                IncidentEventWriteRequest::status_changed(
                    &current.status,
                    &updated.status,
                    &current.status_label,
                    &updated.status_label,
                ),
            )
            .await?,
        );
    }
    Ok(events)
}

impl NewIncident {
    fn from_create_payload(payload: IncidentWriteRequest) -> anyhow::Result<Self> {
        let now = Utc::now().to_rfc3339();
        let title = normalize_required_text(payload.title.as_deref(), "Incident-Titel")?;
        let summary = normalize_optional_text(payload.summary.as_deref());
        let incident_type = normalize_incident_type(payload.incident_type.as_deref());
        let runbook_template =
            normalize_runbook_template(payload.runbook_template.as_deref(), &incident_type);
        let severity = normalize_severity(payload.severity.as_deref());
        let status = normalize_status(payload.status.as_deref());
        let detected_at = normalize_optional_datetime(payload.detected_at.flatten().as_deref())?
            .or_else(|| Some(now.clone()));
        let confirmed_at = normalize_optional_datetime(payload.confirmed_at.flatten().as_deref())?;
        let contained_at = normalize_optional_datetime(payload.contained_at.flatten().as_deref())?;
        let resolved_at = normalize_optional_datetime(payload.resolved_at.flatten().as_deref())?;
        let nis2_reportable = payload.nis2_reportable.unwrap_or(false);
        let deadlines = nis2_deadlines(nis2_reportable, detected_at.as_deref());
        Ok(Self {
            reporter_id: payload.reporter_id.flatten(),
            owner_id: payload.owner_id.flatten(),
            related_risk_id: payload.related_risk_id.flatten(),
            related_asset_id: payload.related_asset_id.flatten(),
            related_process_id: payload.related_process_id.flatten(),
            title,
            summary,
            incident_type,
            runbook_template,
            severity,
            status,
            detected_at,
            confirmed_at,
            contained_at,
            resolved_at,
            nis2_reportable,
            early_warning_due_at: deadlines.early_warning_due_at,
            early_warning_sent_at: normalize_optional_datetime(
                payload.early_warning_sent_at.flatten().as_deref(),
            )?,
            notification_due_at: deadlines.notification_due_at,
            notification_sent_at: normalize_optional_datetime(
                payload.notification_sent_at.flatten().as_deref(),
            )?,
            final_report_due_at: deadlines.final_report_due_at,
            final_report_sent_at: normalize_optional_datetime(
                payload.final_report_sent_at.flatten().as_deref(),
            )?,
            authority_reference: normalize_optional_text(payload.authority_reference.as_deref()),
            stakeholder_summary: normalize_optional_text(payload.stakeholder_summary.as_deref()),
            lessons_learned: normalize_optional_text(payload.lessons_learned.as_deref()),
            now,
        })
    }
}

impl ExistingIncident {
    fn from_update_payload(
        current: IncidentSummary,
        payload: IncidentWriteRequest,
    ) -> anyhow::Result<Self> {
        let now = Utc::now().to_rfc3339();
        let title = match payload.title {
            Some(title) => normalize_required_text(Some(&title), "Incident-Titel")?,
            None => current.title,
        };
        let summary = payload
            .summary
            .map(|value| normalize_optional_text(Some(&value)))
            .unwrap_or(current.summary);
        let incident_type = payload
            .incident_type
            .map(|value| normalize_incident_type(Some(&value)))
            .unwrap_or(current.incident_type);
        let runbook_template = payload
            .runbook_template
            .map(|value| normalize_runbook_template(Some(&value), &incident_type))
            .unwrap_or(current.runbook_template);
        let severity = payload
            .severity
            .map(|value| normalize_severity(Some(&value)))
            .unwrap_or(current.severity);
        let status = payload
            .status
            .map(|value| normalize_status(Some(&value)))
            .unwrap_or(current.status);
        let detected_at = match payload.detected_at {
            Some(value) => normalize_optional_datetime(value.as_deref())?,
            None => current.detected_at,
        };
        let confirmed_at = match payload.confirmed_at {
            Some(value) => normalize_optional_datetime(value.as_deref())?,
            None => current.confirmed_at,
        };
        let contained_at = match payload.contained_at {
            Some(value) => normalize_optional_datetime(value.as_deref())?,
            None => current.contained_at,
        };
        let resolved_at = match payload.resolved_at {
            Some(value) => normalize_optional_datetime(value.as_deref())?,
            None => current.resolved_at,
        };
        let nis2_reportable = payload.nis2_reportable.unwrap_or(current.nis2_reportable);
        let deadlines = nis2_deadlines(nis2_reportable, detected_at.as_deref());
        Ok(Self {
            reporter_id: payload.reporter_id.unwrap_or(current.reporter_id),
            owner_id: payload.owner_id.unwrap_or(current.owner_id),
            related_risk_id: payload.related_risk_id.unwrap_or(current.related_risk_id),
            related_asset_id: payload.related_asset_id.unwrap_or(current.related_asset_id),
            related_process_id: payload
                .related_process_id
                .unwrap_or(current.related_process_id),
            title,
            summary,
            incident_type,
            runbook_template,
            severity,
            status,
            detected_at,
            confirmed_at,
            contained_at,
            resolved_at,
            nis2_reportable,
            early_warning_due_at: deadlines.early_warning_due_at,
            early_warning_sent_at: match payload.early_warning_sent_at {
                Some(value) => normalize_optional_datetime(value.as_deref())?,
                None => current.early_warning_sent_at,
            },
            notification_due_at: deadlines.notification_due_at,
            notification_sent_at: match payload.notification_sent_at {
                Some(value) => normalize_optional_datetime(value.as_deref())?,
                None => current.notification_sent_at,
            },
            final_report_due_at: deadlines.final_report_due_at,
            final_report_sent_at: match payload.final_report_sent_at {
                Some(value) => normalize_optional_datetime(value.as_deref())?,
                None => current.final_report_sent_at,
            },
            authority_reference: payload
                .authority_reference
                .map(|value| normalize_optional_text(Some(&value)))
                .unwrap_or(current.authority_reference),
            stakeholder_summary: payload
                .stakeholder_summary
                .map(|value| normalize_optional_text(Some(&value)))
                .unwrap_or(current.stakeholder_summary),
            lessons_learned: payload
                .lessons_learned
                .map(|value| normalize_optional_text(Some(&value)))
                .unwrap_or(current.lessons_learned),
            now,
        })
    }

    fn as_new_incident(&self) -> NewIncident {
        NewIncident {
            reporter_id: self.reporter_id,
            owner_id: self.owner_id,
            related_risk_id: self.related_risk_id,
            related_asset_id: self.related_asset_id,
            related_process_id: self.related_process_id,
            title: self.title.clone(),
            summary: self.summary.clone(),
            incident_type: self.incident_type.clone(),
            runbook_template: self.runbook_template.clone(),
            severity: self.severity.clone(),
            status: self.status.clone(),
            detected_at: self.detected_at.clone(),
            confirmed_at: self.confirmed_at.clone(),
            contained_at: self.contained_at.clone(),
            resolved_at: self.resolved_at.clone(),
            nis2_reportable: self.nis2_reportable,
            early_warning_due_at: self.early_warning_due_at.clone(),
            early_warning_sent_at: self.early_warning_sent_at.clone(),
            notification_due_at: self.notification_due_at.clone(),
            notification_sent_at: self.notification_sent_at.clone(),
            final_report_due_at: self.final_report_due_at.clone(),
            final_report_sent_at: self.final_report_sent_at.clone(),
            authority_reference: self.authority_reference.clone(),
            stakeholder_summary: self.stakeholder_summary.clone(),
            lessons_learned: self.lessons_learned.clone(),
            now: self.now.clone(),
        }
    }
}

struct NIS2Deadlines {
    early_warning_due_at: Option<String>,
    notification_due_at: Option<String>,
    final_report_due_at: Option<String>,
}

fn nis2_deadlines(nis2_reportable: bool, detected_at: Option<&str>) -> NIS2Deadlines {
    if !nis2_reportable {
        return NIS2Deadlines {
            early_warning_due_at: None,
            notification_due_at: None,
            final_report_due_at: None,
        };
    }
    let base = detected_at
        .and_then(parse_datetime)
        .unwrap_or_else(Utc::now);
    NIS2Deadlines {
        early_warning_due_at: Some((base + Duration::hours(24)).to_rfc3339()),
        notification_due_at: Some((base + Duration::hours(72)).to_rfc3339()),
        final_report_due_at: Some((base + Duration::days(30)).to_rfc3339()),
    }
}

async fn validate_relations_postgres(
    pool: &PgPool,
    tenant_id: i64,
    incident: &NewIncident,
) -> anyhow::Result<()> {
    validate_relation_postgres(pool, tenant_id, incident.reporter_id, TenantRelation::User).await?;
    validate_relation_postgres(pool, tenant_id, incident.owner_id, TenantRelation::User).await?;
    validate_relation_postgres(
        pool,
        tenant_id,
        incident.related_risk_id,
        TenantRelation::Risk,
    )
    .await?;
    validate_relation_postgres(
        pool,
        tenant_id,
        incident.related_asset_id,
        TenantRelation::Asset,
    )
    .await?;
    validate_relation_postgres(
        pool,
        tenant_id,
        incident.related_process_id,
        TenantRelation::Process,
    )
    .await
}

async fn validate_relations_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    incident: &NewIncident,
) -> anyhow::Result<()> {
    validate_relation_sqlite(pool, tenant_id, incident.reporter_id, TenantRelation::User).await?;
    validate_relation_sqlite(pool, tenant_id, incident.owner_id, TenantRelation::User).await?;
    validate_relation_sqlite(
        pool,
        tenant_id,
        incident.related_risk_id,
        TenantRelation::Risk,
    )
    .await?;
    validate_relation_sqlite(
        pool,
        tenant_id,
        incident.related_asset_id,
        TenantRelation::Asset,
    )
    .await?;
    validate_relation_sqlite(
        pool,
        tenant_id,
        incident.related_process_id,
        TenantRelation::Process,
    )
    .await
}

async fn validate_relation_postgres(
    pool: &PgPool,
    tenant_id: i64,
    id: Option<i64>,
    relation: TenantRelation,
) -> anyhow::Result<()> {
    let Some(id) = id else {
        return Ok(());
    };
    let sql = match relation {
        TenantRelation::User => {
            "SELECT 1::BIGINT FROM accounts_user WHERE tenant_id = $1 AND id = $2"
        }
        TenantRelation::Risk => "SELECT 1::BIGINT FROM risks_risk WHERE tenant_id = $1 AND id = $2",
        TenantRelation::Asset => {
            "SELECT 1::BIGINT FROM assets_app_informationasset WHERE tenant_id = $1 AND id = $2"
        }
        TenantRelation::Process => {
            "SELECT 1::BIGINT FROM processes_process WHERE tenant_id = $1 AND id = $2"
        }
    };
    let exists: Option<i64> = sqlx::query_scalar(sql)
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await?;
    if exists.is_none() {
        bail!(
            "Incident-Bezug {:?}={} gehoert nicht zum Tenant",
            relation,
            id
        );
    }
    Ok(())
}

async fn validate_relation_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    id: Option<i64>,
    relation: TenantRelation,
) -> anyhow::Result<()> {
    let Some(id) = id else {
        return Ok(());
    };
    let sql = match relation {
        TenantRelation::User => "SELECT 1 FROM accounts_user WHERE tenant_id = ? AND id = ?",
        TenantRelation::Risk => "SELECT 1 FROM risks_risk WHERE tenant_id = ? AND id = ?",
        TenantRelation::Asset => {
            "SELECT 1 FROM assets_app_informationasset WHERE tenant_id = ? AND id = ?"
        }
        TenantRelation::Process => "SELECT 1 FROM processes_process WHERE tenant_id = ? AND id = ?",
    };
    let exists: Option<i64> = sqlx::query_scalar(sql)
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await?;
    if exists.is_none() {
        bail!(
            "Incident-Bezug {:?}={} gehoert nicht zum Tenant",
            relation,
            id
        );
    }
    Ok(())
}

fn incident_select_postgres_sql(where_clause: &str, limit_placeholder: &str) -> String {
    format!(
        r#"
        SELECT
            incident.id,
            incident.tenant_id,
            incident.reporter_id,
            reporter.username AS reporter_username,
            reporter.first_name AS reporter_first_name,
            reporter.last_name AS reporter_last_name,
            incident.owner_id,
            owner.username AS owner_username,
            owner.first_name AS owner_first_name,
            owner.last_name AS owner_last_name,
            incident.related_risk_id,
            risk.title AS related_risk_title,
            incident.related_asset_id,
            asset.name AS related_asset_name,
            incident.related_process_id,
            proc.name AS related_process_name,
            incident.title,
            incident.summary,
            incident.incident_type,
            incident.runbook_template,
            incident.severity,
            incident.status,
            incident.detected_at::text AS detected_at,
            incident.confirmed_at::text AS confirmed_at,
            incident.contained_at::text AS contained_at,
            incident.resolved_at::text AS resolved_at,
            incident.nis2_reportable,
            incident.early_warning_due_at::text AS early_warning_due_at,
            incident.early_warning_sent_at::text AS early_warning_sent_at,
            incident.notification_due_at::text AS notification_due_at,
            incident.notification_sent_at::text AS notification_sent_at,
            incident.final_report_due_at::text AS final_report_due_at,
            incident.final_report_sent_at::text AS final_report_sent_at,
            incident.authority_reference,
            incident.stakeholder_summary,
            incident.lessons_learned,
            incident.created_at::text AS created_at,
            incident.updated_at::text AS updated_at
        FROM incidents_incident incident
        LEFT JOIN accounts_user reporter ON reporter.id = incident.reporter_id AND reporter.tenant_id = incident.tenant_id
        LEFT JOIN accounts_user owner ON owner.id = incident.owner_id AND owner.tenant_id = incident.tenant_id
        LEFT JOIN risks_risk risk ON risk.id = incident.related_risk_id AND risk.tenant_id = incident.tenant_id
        LEFT JOIN assets_app_informationasset asset ON asset.id = incident.related_asset_id AND asset.tenant_id = incident.tenant_id
        LEFT JOIN processes_process proc ON proc.id = incident.related_process_id AND proc.tenant_id = incident.tenant_id
        {where_clause}
        ORDER BY
            CASE incident.severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END,
            incident.detected_at DESC NULLS LAST,
            incident.id DESC
        LIMIT {limit_placeholder}
        "#
    )
}

fn incident_select_sqlite_sql(where_clause: &str, limit_placeholder: &str) -> String {
    format!(
        r#"
        SELECT
            incident.id,
            incident.tenant_id,
            incident.reporter_id,
            reporter.username AS reporter_username,
            reporter.first_name AS reporter_first_name,
            reporter.last_name AS reporter_last_name,
            incident.owner_id,
            owner.username AS owner_username,
            owner.first_name AS owner_first_name,
            owner.last_name AS owner_last_name,
            incident.related_risk_id,
            risk.title AS related_risk_title,
            incident.related_asset_id,
            asset.name AS related_asset_name,
            incident.related_process_id,
            proc.name AS related_process_name,
            incident.title,
            incident.summary,
            incident.incident_type,
            incident.runbook_template,
            incident.severity,
            incident.status,
            CAST(incident.detected_at AS TEXT) AS detected_at,
            CAST(incident.confirmed_at AS TEXT) AS confirmed_at,
            CAST(incident.contained_at AS TEXT) AS contained_at,
            CAST(incident.resolved_at AS TEXT) AS resolved_at,
            incident.nis2_reportable,
            CAST(incident.early_warning_due_at AS TEXT) AS early_warning_due_at,
            CAST(incident.early_warning_sent_at AS TEXT) AS early_warning_sent_at,
            CAST(incident.notification_due_at AS TEXT) AS notification_due_at,
            CAST(incident.notification_sent_at AS TEXT) AS notification_sent_at,
            CAST(incident.final_report_due_at AS TEXT) AS final_report_due_at,
            CAST(incident.final_report_sent_at AS TEXT) AS final_report_sent_at,
            incident.authority_reference,
            incident.stakeholder_summary,
            incident.lessons_learned,
            CAST(incident.created_at AS TEXT) AS created_at,
            CAST(incident.updated_at AS TEXT) AS updated_at
        FROM incidents_incident incident
        LEFT JOIN accounts_user reporter ON reporter.id = incident.reporter_id AND reporter.tenant_id = incident.tenant_id
        LEFT JOIN accounts_user owner ON owner.id = incident.owner_id AND owner.tenant_id = incident.tenant_id
        LEFT JOIN risks_risk risk ON risk.id = incident.related_risk_id AND risk.tenant_id = incident.tenant_id
        LEFT JOIN assets_app_informationasset asset ON asset.id = incident.related_asset_id AND asset.tenant_id = incident.tenant_id
        LEFT JOIN processes_process proc ON proc.id = incident.related_process_id AND proc.tenant_id = incident.tenant_id
        {where_clause}
        ORDER BY
            CASE incident.severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END,
            incident.detected_at DESC,
            incident.id DESC
        LIMIT {limit_placeholder}
        "#
    )
}

fn summary_from_pg_row(row: PgRow) -> Result<IncidentSummary, sqlx::Error> {
    let severity: String = row.try_get("severity")?;
    let status: String = row.try_get("status")?;
    let incident_type: String = row.try_get("incident_type")?;
    let nis2_reportable: bool = row.try_get("nis2_reportable")?;
    let early_warning_due_at: Option<String> = row.try_get("early_warning_due_at")?;
    let early_warning_sent_at: Option<String> = row.try_get("early_warning_sent_at")?;
    let notification_due_at: Option<String> = row.try_get("notification_due_at")?;
    let notification_sent_at: Option<String> = row.try_get("notification_sent_at")?;
    let final_report_due_at: Option<String> = row.try_get("final_report_due_at")?;
    let final_report_sent_at: Option<String> = row.try_get("final_report_sent_at")?;
    let early_warning_state = deadline_state(&early_warning_due_at, &early_warning_sent_at);
    let notification_state = deadline_state(&notification_due_at, &notification_sent_at);
    let final_report_state = deadline_state(&final_report_due_at, &final_report_sent_at);
    Ok(IncidentSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        reporter_id: row.try_get("reporter_id")?,
        reporter_display: user_display(
            row.try_get("reporter_username")?,
            row.try_get("reporter_first_name")?,
            row.try_get("reporter_last_name")?,
        ),
        owner_id: row.try_get("owner_id")?,
        owner_display: user_display(
            row.try_get("owner_username")?,
            row.try_get("owner_first_name")?,
            row.try_get("owner_last_name")?,
        ),
        related_risk_id: row.try_get("related_risk_id")?,
        related_risk_title: row.try_get("related_risk_title")?,
        related_asset_id: row.try_get("related_asset_id")?,
        related_asset_name: row.try_get("related_asset_name")?,
        related_process_id: row.try_get("related_process_id")?,
        related_process_name: row.try_get("related_process_name")?,
        title: row.try_get("title")?,
        summary: row.try_get("summary")?,
        incident_type_label: incident_type_label(&incident_type).to_string(),
        incident_type,
        runbook_template: row.try_get("runbook_template")?,
        severity_label: severity_label(&severity).to_string(),
        severity,
        status_label: status_label(&status).to_string(),
        status,
        detected_at: row.try_get("detected_at")?,
        confirmed_at: row.try_get("confirmed_at")?,
        contained_at: row.try_get("contained_at")?,
        resolved_at: row.try_get("resolved_at")?,
        nis2_reportability_label: reportability_label(nis2_reportable).to_string(),
        nis2_reportable,
        early_warning_due_at,
        early_warning_sent_at,
        early_warning_state_label: deadline_state_label(&early_warning_state).to_string(),
        early_warning_state,
        notification_due_at,
        notification_sent_at,
        notification_state_label: deadline_state_label(&notification_state).to_string(),
        notification_state,
        final_report_due_at,
        final_report_sent_at,
        final_report_state_label: deadline_state_label(&final_report_state).to_string(),
        final_report_state,
        authority_reference: row.try_get("authority_reference")?,
        stakeholder_summary: row.try_get("stakeholder_summary")?,
        lessons_learned: row.try_get("lessons_learned")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn summary_from_sqlite_row(row: SqliteRow) -> Result<IncidentSummary, sqlx::Error> {
    let severity: String = row.try_get("severity")?;
    let status: String = row.try_get("status")?;
    let incident_type: String = row.try_get("incident_type")?;
    let nis2_reportable: bool = row.try_get("nis2_reportable")?;
    let early_warning_due_at: Option<String> = row.try_get("early_warning_due_at")?;
    let early_warning_sent_at: Option<String> = row.try_get("early_warning_sent_at")?;
    let notification_due_at: Option<String> = row.try_get("notification_due_at")?;
    let notification_sent_at: Option<String> = row.try_get("notification_sent_at")?;
    let final_report_due_at: Option<String> = row.try_get("final_report_due_at")?;
    let final_report_sent_at: Option<String> = row.try_get("final_report_sent_at")?;
    let early_warning_state = deadline_state(&early_warning_due_at, &early_warning_sent_at);
    let notification_state = deadline_state(&notification_due_at, &notification_sent_at);
    let final_report_state = deadline_state(&final_report_due_at, &final_report_sent_at);
    Ok(IncidentSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        reporter_id: row.try_get("reporter_id")?,
        reporter_display: user_display(
            row.try_get("reporter_username")?,
            row.try_get("reporter_first_name")?,
            row.try_get("reporter_last_name")?,
        ),
        owner_id: row.try_get("owner_id")?,
        owner_display: user_display(
            row.try_get("owner_username")?,
            row.try_get("owner_first_name")?,
            row.try_get("owner_last_name")?,
        ),
        related_risk_id: row.try_get("related_risk_id")?,
        related_risk_title: row.try_get("related_risk_title")?,
        related_asset_id: row.try_get("related_asset_id")?,
        related_asset_name: row.try_get("related_asset_name")?,
        related_process_id: row.try_get("related_process_id")?,
        related_process_name: row.try_get("related_process_name")?,
        title: row.try_get("title")?,
        summary: row.try_get("summary")?,
        incident_type_label: incident_type_label(&incident_type).to_string(),
        incident_type,
        runbook_template: row.try_get("runbook_template")?,
        severity_label: severity_label(&severity).to_string(),
        severity,
        status_label: status_label(&status).to_string(),
        status,
        detected_at: row.try_get("detected_at")?,
        confirmed_at: row.try_get("confirmed_at")?,
        contained_at: row.try_get("contained_at")?,
        resolved_at: row.try_get("resolved_at")?,
        nis2_reportability_label: reportability_label(nis2_reportable).to_string(),
        nis2_reportable,
        early_warning_due_at,
        early_warning_sent_at,
        early_warning_state_label: deadline_state_label(&early_warning_state).to_string(),
        early_warning_state,
        notification_due_at,
        notification_sent_at,
        notification_state_label: deadline_state_label(&notification_state).to_string(),
        notification_state,
        final_report_due_at,
        final_report_sent_at,
        final_report_state_label: deadline_state_label(&final_report_state).to_string(),
        final_report_state,
        authority_reference: row.try_get("authority_reference")?,
        stakeholder_summary: row.try_get("stakeholder_summary")?,
        lessons_learned: row.try_get("lessons_learned")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn runbook_template_from_pg_row(row: PgRow) -> Result<IncidentRunbookTemplateSummary, sqlx::Error> {
    let incident_type: String = row.try_get("incident_type")?;
    let severity: String = row.try_get("severity")?;
    Ok(IncidentRunbookTemplateSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        slug: row.try_get("slug")?,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        incident_type_label: incident_type_label(&incident_type).to_string(),
        incident_type,
        severity_label: severity_label(&severity).to_string(),
        severity,
        body: row.try_get("body")?,
        is_active: row.try_get("is_active")?,
        sort_order: row.try_get("sort_order")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn runbook_template_from_sqlite_row(
    row: SqliteRow,
) -> Result<IncidentRunbookTemplateSummary, sqlx::Error> {
    let incident_type: String = row.try_get("incident_type")?;
    let severity: String = row.try_get("severity")?;
    Ok(IncidentRunbookTemplateSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        slug: row.try_get("slug")?,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        incident_type_label: incident_type_label(&incident_type).to_string(),
        incident_type,
        severity_label: severity_label(&severity).to_string(),
        severity,
        body: row.try_get("body")?,
        is_active: row.try_get("is_active")?,
        sort_order: row.try_get("sort_order")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn event_from_pg_row(row: PgRow) -> Result<IncidentEventSummary, sqlx::Error> {
    let event_type: String = row.try_get("event_type")?;
    let from_status: Option<String> = row.try_get("from_status")?;
    let to_status: Option<String> = row.try_get("to_status")?;
    Ok(IncidentEventSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        incident_id: row.try_get("incident_id")?,
        actor_id: row.try_get("actor_id")?,
        actor_display: user_display(
            row.try_get("actor_username")?,
            row.try_get("actor_first_name")?,
            row.try_get("actor_last_name")?,
        ),
        event_type_label: event_type_label(&event_type).to_string(),
        event_type,
        summary: row.try_get("summary")?,
        detail: row.try_get("detail")?,
        from_status_label: from_status.as_deref().map(status_label).map(str::to_string),
        from_status,
        to_status_label: to_status.as_deref().map(status_label).map(str::to_string),
        to_status,
        evidence_item_id: row.try_get("evidence_item_id")?,
        created_at: row.try_get("created_at")?,
    })
}

fn event_from_sqlite_row(row: SqliteRow) -> Result<IncidentEventSummary, sqlx::Error> {
    let event_type: String = row.try_get("event_type")?;
    let from_status: Option<String> = row.try_get("from_status")?;
    let to_status: Option<String> = row.try_get("to_status")?;
    Ok(IncidentEventSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        incident_id: row.try_get("incident_id")?,
        actor_id: row.try_get("actor_id")?,
        actor_display: user_display(
            row.try_get("actor_username")?,
            row.try_get("actor_first_name")?,
            row.try_get("actor_last_name")?,
        ),
        event_type_label: event_type_label(&event_type).to_string(),
        event_type,
        summary: row.try_get("summary")?,
        detail: row.try_get("detail")?,
        from_status_label: from_status.as_deref().map(status_label).map(str::to_string),
        from_status,
        to_status_label: to_status.as_deref().map(status_label).map(str::to_string),
        to_status,
        evidence_item_id: row.try_get("evidence_item_id")?,
        created_at: row.try_get("created_at")?,
    })
}

fn normalize_required_text(value: Option<&str>, label: &str) -> anyhow::Result<String> {
    let normalized = normalize_optional_text(value);
    if normalized.is_empty() {
        bail!("{label} darf nicht leer sein");
    }
    Ok(normalized)
}

fn normalize_optional_text(value: Option<&str>) -> String {
    value.unwrap_or("").trim().to_string()
}

fn normalize_event_type(value: &str) -> String {
    match value.trim().to_uppercase().as_str() {
        "CREATED" => "CREATED".to_string(),
        "STATUS_CHANGED" => "STATUS_CHANGED".to_string(),
        "EVIDENCE_UPLOADED" => "EVIDENCE_UPLOADED".to_string(),
        "TIMELINE_NOTE" => "TIMELINE_NOTE".to_string(),
        _ => "TIMELINE_NOTE".to_string(),
    }
}

fn normalize_event_summary(value: &str) -> String {
    let normalized = normalize_optional_text(Some(value));
    if normalized.is_empty() {
        return "Incident-Ereignis dokumentiert.".to_string();
    }
    limit_chars(&normalized, 255)
}

fn limit_chars(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

fn normalize_incident_type(value: Option<&str>) -> String {
    match value.unwrap_or("GENERAL").trim().to_uppercase().as_str() {
        "PHISHING" => "PHISHING".to_string(),
        "MALWARE" => "MALWARE".to_string(),
        "DATA_BREACH" => "DATA_BREACH".to_string(),
        "OUTAGE" => "OUTAGE".to_string(),
        "SUPPLIER" => "SUPPLIER".to_string(),
        "VULNERABILITY" => "VULNERABILITY".to_string(),
        _ => "GENERAL".to_string(),
    }
}

fn normalize_runbook_template(value: Option<&str>, incident_type: &str) -> String {
    let normalized = normalize_optional_text(value);
    if normalized.is_empty() {
        return runbook_template_for(incident_type).to_string();
    }
    normalized
}

fn runbook_template_for(incident_type: &str) -> &'static str {
    match incident_type {
        "PHISHING" => {
            "1. Scope: betroffene Postfaecher, URLs, Absender und Zeitfenster erfassen.\n2. Eindaemmung: URLs blocken, Mails zurueckrufen, kompromittierte Sessions widerrufen.\n3. Identitaet: MFA/Passwort-Reset, Token-Review und privilegierte Konten pruefen.\n4. Meldung: Betroffenheit, Datenarten und NIS2-Fristen bewerten.\n5. Abschluss: Awareness-, Mail-Gateway- und Detection-Regeln aktualisieren."
        }
        "MALWARE" => {
            "1. Scope: betroffene Hosts, Hashes, Prozesse und C2-Indikatoren sichern.\n2. Eindaemmung: Hosts isolieren, IOC-Blocklisten verteilen und Backups schuetzen.\n3. Analyse: Entry Point, Persistenz, Lateralmovement und Datenabfluss pruefen.\n4. Wiederherstellung: Systeme neu aufsetzen oder bereinigen, Monitoring erhoehen.\n5. Abschluss: Controls, EDR-Regeln und Patch-Status aktualisieren."
        }
        "DATA_BREACH" => {
            "1. Scope: Datenarten, betroffene Personen/Systeme und Zeitraum bestimmen.\n2. Eindaemmung: Zugriff stoppen, Berechtigungen entziehen und Logs sichern.\n3. Bewertung: Meldepflichten nach NIS2/DSGVO und Kundenpflichten entscheiden.\n4. Kommunikation: Legal, Datenschutz, Management und Kunden abgestimmt informieren.\n5. Abschluss: Root Cause, Control-Gaps und Nachweise dokumentieren."
        }
        "OUTAGE" => {
            "1. Scope: betroffene Services, SLAs, kritische Prozesse und Nutzerkreis erfassen.\n2. Stabilisierung: Workarounds, Failover und Wiederanlauf priorisieren.\n3. Ursache: Infrastruktur, Changes, Abhaengigkeiten und Kapazitaeten pruefen.\n4. Kommunikation: Status, ETA und Auswirkungen fuer Stakeholder aktualisieren.\n5. Abschluss: Resilienz-, Monitoring- und Recovery-Massnahmen nachziehen."
        }
        "SUPPLIER" => {
            "1. Scope: betroffene Lieferanten, Services, Datenfluesse und Vertraege erfassen.\n2. Eindaemmung: Schnittstellen, Zugriffe und Abhaengigkeiten kontrollieren.\n3. Nachweise: Lieferantenstatement, IOCs, SLA-Auswirkung und Audit-Trails sichern.\n4. Bewertung: NIS2/KRITIS-Auswirkung und Kundenkommunikation festlegen.\n5. Abschluss: Third-Party-Risiko, Vertragscontrols und Exit-Optionen aktualisieren."
        }
        "VULNERABILITY" => {
            "1. Scope: betroffene Produkte, Versionen, Assets und Exposure erfassen.\n2. Priorisierung: CVSS, EPSS, KEV, Exploit-Reife und Business-Kontext bewerten.\n3. Eindaemmung: Workarounds, WAF/EDR-Regeln und Netzwerkbegrenzung setzen.\n4. Behebung: Patch, Upgrade oder Konfigurationsfix mit Evidence verknuepfen.\n5. Abschluss: Risiko, SBOM/Product-Security und Detection-Content aktualisieren."
        }
        _ => {
            "1. Scope: betroffene Systeme, Prozesse, Personen und Zeitraum erfassen.\n2. Eindaemmung: unmittelbare Schutzmassnahmen und Verantwortliche festlegen.\n3. Bewertung: Schweregrad, NIS2-Relevanz, Datenbezug und Business Impact pruefen.\n4. Kommunikation: Owner, Management, Legal und externe Stellen abstimmen.\n5. Abschluss: Root Cause, Evidence, Lessons Learned und Massnahmen dokumentieren."
        }
    }
}

fn incident_type_label(incident_type: &str) -> &'static str {
    match incident_type {
        "PHISHING" => "Phishing",
        "MALWARE" => "Malware",
        "DATA_BREACH" => "Datenabfluss",
        "OUTAGE" => "Ausfall",
        "SUPPLIER" => "Lieferant",
        "VULNERABILITY" => "Schwachstelle",
        _ => "Allgemein",
    }
}

fn normalize_severity(value: Option<&str>) -> String {
    match value.unwrap_or("MEDIUM").trim().to_uppercase().as_str() {
        "CRITICAL" => "CRITICAL".to_string(),
        "HIGH" => "HIGH".to_string(),
        "LOW" => "LOW".to_string(),
        "INFO" => "INFO".to_string(),
        _ => "MEDIUM".to_string(),
    }
}

fn normalize_status(value: Option<&str>) -> String {
    match value.unwrap_or("TRIAGE").trim().to_uppercase().as_str() {
        "TRIAGE" => "TRIAGE".to_string(),
        "CONFIRMED" => "CONFIRMED".to_string(),
        "CONTAINED" => "CONTAINED".to_string(),
        "RESOLVED" => "RESOLVED".to_string(),
        "CLOSED" => "CLOSED".to_string(),
        _ => "TRIAGE".to_string(),
    }
}

fn normalize_optional_datetime(value: Option<&str>) -> anyhow::Result<Option<String>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    parse_datetime(value)
        .map(|datetime| Some(datetime.to_rfc3339()))
        .with_context(|| format!("Zeitpunkt '{value}' muss RFC3339 oder YYYY-MM-DD sein"))
}

fn parse_datetime(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|datetime| datetime.with_timezone(&Utc))
        .or_else(|| {
            NaiveDate::parse_from_str(value, "%Y-%m-%d")
                .ok()
                .and_then(|date| date.and_hms_opt(0, 0, 0))
                .map(|datetime| datetime.and_utc())
        })
}

fn deadline_state(due_at: &Option<String>, sent_at: &Option<String>) -> String {
    if sent_at.is_some() {
        return "SENT".to_string();
    }
    let Some(due_at) = due_at.as_deref().and_then(parse_datetime) else {
        return "NOT_APPLICABLE".to_string();
    };
    let now = Utc::now();
    if due_at < now {
        "OVERDUE".to_string()
    } else if due_at <= now + Duration::hours(12) {
        "DUE_SOON".to_string()
    } else {
        "PENDING".to_string()
    }
}

fn severity_label(value: &str) -> &'static str {
    match value {
        "CRITICAL" => "Kritisch",
        "HIGH" => "Hoch",
        "MEDIUM" => "Mittel",
        "LOW" => "Niedrig",
        "INFO" => "Info",
        _ => "Mittel",
    }
}

fn status_label(value: &str) -> &'static str {
    match value {
        "TRIAGE" => "Triage",
        "CONFIRMED" => "Bestaetigt",
        "CONTAINED" => "Eingedaemmt",
        "RESOLVED" => "Behoben",
        "CLOSED" => "Geschlossen",
        _ => "Triage",
    }
}

fn event_type_label(value: &str) -> &'static str {
    match value {
        "CREATED" => "Angelegt",
        "STATUS_CHANGED" => "Statuswechsel",
        "EVIDENCE_UPLOADED" => "Evidence",
        "TIMELINE_NOTE" => "Notiz",
        _ => "Timeline",
    }
}

fn deadline_state_label(value: &str) -> &'static str {
    match value {
        "SENT" => "Gemeldet",
        "OVERDUE" => "Ueberfaellig",
        "DUE_SOON" => "Faellig bald",
        "PENDING" => "Ausstehend",
        _ => "Nicht relevant",
    }
}

fn reportability_label(value: bool) -> &'static str {
    if value {
        "NIS2 meldepflichtig"
    } else {
        "Noch nicht NIS2 meldepflichtig"
    }
}

fn user_display(
    username: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
) -> Option<String> {
    let full_name = format!(
        "{} {}",
        first_name.unwrap_or_default().trim(),
        last_name.unwrap_or_default().trim()
    )
    .trim()
    .to_string();
    if !full_name.is_empty() {
        Some(full_name)
    } else {
        username.filter(|value| !value.trim().is_empty())
    }
}
