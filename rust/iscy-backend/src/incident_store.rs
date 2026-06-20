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
pub struct IncidentAlertmanagerMetrics {
    pub total: i64,
    pub open: i64,
    pub triage: i64,
    pub critical_open: i64,
    pub resolved: i64,
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
    pub nis2_significance_status: String,
    pub nis2_significance_label: String,
    pub nis2_significance_criteria: String,
    pub nis2_significance_justification: String,
    pub nis2_significance_reference: String,
    pub nis2_significance_assessed_at: Option<String>,
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
    pub review_state: String,
    pub review_state_label: String,
    pub reviewed_by_id: Option<i64>,
    pub reviewed_by_display: Option<String>,
    pub reviewed_at: Option<String>,
    pub review_notes: String,
    pub approved_by_id: Option<i64>,
    pub approved_by_display: Option<String>,
    pub approved_at: Option<String>,
    pub approval_notes: String,
    pub report_package_version: String,
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
    pub is_export_highlight: bool,
    pub export_note: String,
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

#[derive(Debug, Clone, Serialize)]
pub struct IncidentRunbookStepSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub incident_id: i64,
    pub step_number: i64,
    pub title: String,
    pub detail: String,
    pub is_done: bool,
    pub done_at: Option<String>,
    pub done_by_id: Option<i64>,
    pub done_by_display: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IncidentRunbookTemplateWriteRequest {
    pub slug: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub incident_type: Option<String>,
    pub severity: Option<String>,
    pub body: Option<String>,
    pub is_active: Option<bool>,
    pub sort_order: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IncidentRunbookStepUpdateResult {
    pub step: IncidentRunbookStepSummary,
    pub event: IncidentEventSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct IncidentReviewUpdateResult {
    pub incident: IncidentSummary,
    pub event: IncidentEventSummary,
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
    pub nis2_significance_status: Option<String>,
    pub nis2_significance_criteria: Option<String>,
    pub nis2_significance_justification: Option<String>,
    pub nis2_significance_reference: Option<String>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub nis2_significance_assessed_at: Option<Option<String>>,
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

    pub fn timeline_note(summary: Option<&str>, detail: &str) -> Self {
        let detail = detail.trim();
        let summary = summary
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| {
                let preview = limit_chars(detail, 120);
                if preview.is_empty() {
                    "Notiz zur Fallakte dokumentiert.".to_string()
                } else {
                    format!("Notiz: {preview}")
                }
            });
        Self {
            event_type: "TIMELINE_NOTE".to_string(),
            summary,
            detail: detail.to_string(),
            from_status: None,
            to_status: None,
            evidence_item_id: None,
        }
    }

    pub fn runbook_step_changed(title: &str, is_done: bool) -> Self {
        let action = if is_done {
            "erledigt"
        } else {
            "wieder geoeffnet"
        };
        Self {
            event_type: "RUNBOOK_STEP_UPDATED".to_string(),
            summary: format!("Runbook-Schritt {}: {}", action, limit_chars(title, 160)),
            detail: format!(
                "Runbook-Schritt '{}' wurde {}.",
                limit_chars(title, 220),
                action
            ),
            from_status: None,
            to_status: None,
            evidence_item_id: None,
        }
    }

    pub fn runbook_step_reordered(title: &str, direction_label: &str) -> Self {
        Self {
            event_type: "RUNBOOK_STEP_UPDATED".to_string(),
            summary: format!(
                "Runbook-Schritt verschoben ({}): {}",
                direction_label,
                limit_chars(title, 150)
            ),
            detail: format!(
                "Runbook-Schritt '{}' wurde in der Bearbeitungsreihenfolge verschoben.",
                limit_chars(title, 220)
            ),
            from_status: None,
            to_status: None,
            evidence_item_id: None,
        }
    }

    pub fn review_state_changed(state_label: &str, notes: &str) -> Self {
        let normalized_notes = normalize_optional_text(Some(notes));
        let detail = if normalized_notes.is_empty() {
            format!("Meldepaket-Review wurde auf '{}' gesetzt.", state_label)
        } else {
            format!(
                "Meldepaket-Review wurde auf '{}' gesetzt. Notiz: {}",
                state_label,
                limit_chars(&normalized_notes, 700)
            )
        };
        Self {
            event_type: "INCIDENT_REVIEW_UPDATED".to_string(),
            summary: format!("Meldepaket-Review: {state_label}"),
            detail,
            from_status: None,
            to_status: None,
            evidence_item_id: None,
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

    pub async fn list_runbook_templates_admin(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<IncidentRunbookTemplateSummary>> {
        match self {
            Self::Postgres(pool) => {
                list_runbook_templates_admin_postgres(pool, tenant_id, limit).await
            }
            Self::Sqlite(pool) => list_runbook_templates_admin_sqlite(pool, tenant_id, limit).await,
        }
    }

    pub async fn create_runbook_template(
        &self,
        tenant_id: i64,
        payload: IncidentRunbookTemplateWriteRequest,
    ) -> anyhow::Result<IncidentRunbookTemplateSummary> {
        match self {
            Self::Postgres(pool) => {
                create_runbook_template_postgres(pool, tenant_id, payload).await
            }
            Self::Sqlite(pool) => create_runbook_template_sqlite(pool, tenant_id, payload).await,
        }
    }

    pub async fn update_runbook_template(
        &self,
        tenant_id: i64,
        template_id: i64,
        payload: IncidentRunbookTemplateWriteRequest,
    ) -> anyhow::Result<Option<IncidentRunbookTemplateSummary>> {
        match self {
            Self::Postgres(pool) => {
                update_runbook_template_postgres(pool, tenant_id, template_id, payload).await
            }
            Self::Sqlite(pool) => {
                update_runbook_template_sqlite(pool, tenant_id, template_id, payload).await
            }
        }
    }

    pub async fn deactivate_runbook_template(
        &self,
        tenant_id: i64,
        template_id: i64,
    ) -> anyhow::Result<Option<IncidentRunbookTemplateSummary>> {
        match self {
            Self::Postgres(pool) => {
                deactivate_runbook_template_postgres(pool, tenant_id, template_id).await
            }
            Self::Sqlite(pool) => {
                deactivate_runbook_template_sqlite(pool, tenant_id, template_id).await
            }
        }
    }

    pub async fn list_runbook_steps(
        &self,
        tenant_id: i64,
        incident_id: i64,
    ) -> anyhow::Result<Vec<IncidentRunbookStepSummary>> {
        match self {
            Self::Postgres(pool) => list_runbook_steps_postgres(pool, tenant_id, incident_id).await,
            Self::Sqlite(pool) => list_runbook_steps_sqlite(pool, tenant_id, incident_id).await,
        }
    }

    pub async fn set_runbook_step_done(
        &self,
        tenant_id: i64,
        incident_id: i64,
        step_id: i64,
        actor_id: Option<i64>,
        is_done: bool,
    ) -> anyhow::Result<Option<IncidentRunbookStepUpdateResult>> {
        match self {
            Self::Postgres(pool) => {
                set_runbook_step_done_postgres(
                    pool,
                    tenant_id,
                    incident_id,
                    step_id,
                    actor_id,
                    is_done,
                )
                .await
            }
            Self::Sqlite(pool) => {
                set_runbook_step_done_sqlite(
                    pool,
                    tenant_id,
                    incident_id,
                    step_id,
                    actor_id,
                    is_done,
                )
                .await
            }
        }
    }

    pub async fn move_runbook_step(
        &self,
        tenant_id: i64,
        incident_id: i64,
        step_id: i64,
        actor_id: Option<i64>,
        direction: &str,
    ) -> anyhow::Result<Option<IncidentRunbookStepUpdateResult>> {
        match self {
            Self::Postgres(pool) => {
                move_runbook_step_postgres(
                    pool,
                    tenant_id,
                    incident_id,
                    step_id,
                    actor_id,
                    direction,
                )
                .await
            }
            Self::Sqlite(pool) => {
                move_runbook_step_sqlite(pool, tenant_id, incident_id, step_id, actor_id, direction)
                    .await
            }
        }
    }

    pub async fn update_incident_review_state(
        &self,
        tenant_id: i64,
        incident_id: i64,
        actor_id: i64,
        action: &str,
        notes: Option<&str>,
    ) -> anyhow::Result<Option<IncidentReviewUpdateResult>> {
        match self {
            Self::Postgres(pool) => {
                update_incident_review_state_postgres(
                    pool,
                    tenant_id,
                    incident_id,
                    actor_id,
                    action,
                    notes,
                )
                .await
            }
            Self::Sqlite(pool) => {
                update_incident_review_state_sqlite(
                    pool,
                    tenant_id,
                    incident_id,
                    actor_id,
                    action,
                    notes,
                )
                .await
            }
        }
    }

    pub async fn update_incident_event_export_marker(
        &self,
        tenant_id: i64,
        incident_id: i64,
        event_id: i64,
        is_export_highlight: bool,
        export_note: Option<&str>,
    ) -> anyhow::Result<Option<IncidentEventSummary>> {
        match self {
            Self::Postgres(pool) => {
                update_incident_event_export_marker_postgres(
                    pool,
                    tenant_id,
                    incident_id,
                    event_id,
                    is_export_highlight,
                    export_note,
                )
                .await
            }
            Self::Sqlite(pool) => {
                update_incident_event_export_marker_sqlite(
                    pool,
                    tenant_id,
                    incident_id,
                    event_id,
                    is_export_highlight,
                    export_note,
                )
                .await
            }
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

    pub async fn alertmanager_metrics(
        &self,
        tenant_id: i64,
    ) -> anyhow::Result<IncidentAlertmanagerMetrics> {
        match self {
            Self::Postgres(pool) => alertmanager_metrics_postgres(pool, tenant_id).await,
            Self::Sqlite(pool) => alertmanager_metrics_sqlite(pool, tenant_id).await,
        }
    }

    pub async fn open_alertmanager_incident_by_reference(
        &self,
        tenant_id: i64,
        authority_reference: &str,
    ) -> anyhow::Result<Option<IncidentSummary>> {
        match self {
            Self::Postgres(pool) => {
                open_alertmanager_incident_by_reference_postgres(
                    pool,
                    tenant_id,
                    authority_reference,
                )
                .await
            }
            Self::Sqlite(pool) => {
                open_alertmanager_incident_by_reference_sqlite(pool, tenant_id, authority_reference)
                    .await
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

async fn list_runbook_templates_admin_postgres(
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
        WHERE tenant_id = $1
        ORDER BY is_active DESC, sort_order ASC, title ASC, id ASC
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

async fn list_runbook_templates_admin_sqlite(
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
        WHERE tenant_id = ?1
        ORDER BY is_active DESC, sort_order ASC, title ASC, id ASC
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

async fn create_runbook_template_postgres(
    pool: &PgPool,
    tenant_id: i64,
    payload: IncidentRunbookTemplateWriteRequest,
) -> anyhow::Result<IncidentRunbookTemplateSummary> {
    let write = NormalizedRunbookTemplate::from_payload(payload)?;
    let now = Utc::now().to_rfc3339();
    let row = sqlx::query(
        r#"
        INSERT INTO incidents_runbooktemplate (
            tenant_id, slug, title, description, incident_type, severity,
            body, is_active, sort_order, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(&write.slug)
    .bind(&write.title)
    .bind(&write.description)
    .bind(&write.incident_type)
    .bind(&write.severity)
    .bind(&write.body)
    .bind(write.is_active)
    .bind(write.sort_order)
    .bind(&now)
    .fetch_one(pool)
    .await
    .context("PostgreSQL-Runbook-Template konnte nicht angelegt werden")?;
    let id: i64 = row.try_get("id")?;
    runbook_template_detail_postgres(pool, tenant_id, id)
        .await?
        .context("Neu angelegtes Runbook-Template konnte nicht gelesen werden")
}

async fn create_runbook_template_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    payload: IncidentRunbookTemplateWriteRequest,
) -> anyhow::Result<IncidentRunbookTemplateSummary> {
    let write = NormalizedRunbookTemplate::from_payload(payload)?;
    let now = Utc::now().to_rfc3339();
    let result = sqlx::query(
        r#"
        INSERT INTO incidents_runbooktemplate (
            tenant_id, slug, title, description, incident_type, severity,
            body, is_active, sort_order, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)
        "#,
    )
    .bind(tenant_id)
    .bind(&write.slug)
    .bind(&write.title)
    .bind(&write.description)
    .bind(&write.incident_type)
    .bind(&write.severity)
    .bind(&write.body)
    .bind(write.is_active)
    .bind(write.sort_order)
    .bind(&now)
    .execute(pool)
    .await
    .context("SQLite-Runbook-Template konnte nicht angelegt werden")?;
    runbook_template_detail_sqlite(pool, tenant_id, result.last_insert_rowid())
        .await?
        .context("Neu angelegtes Runbook-Template konnte nicht gelesen werden")
}

async fn update_runbook_template_postgres(
    pool: &PgPool,
    tenant_id: i64,
    template_id: i64,
    payload: IncidentRunbookTemplateWriteRequest,
) -> anyhow::Result<Option<IncidentRunbookTemplateSummary>> {
    let write = NormalizedRunbookTemplate::from_payload(payload)?;
    let now = Utc::now().to_rfc3339();
    let result = sqlx::query(
        r#"
        UPDATE incidents_runbooktemplate
        SET slug = $3, title = $4, description = $5, incident_type = $6,
            severity = $7, body = $8, is_active = $9, sort_order = $10,
            updated_at = $11
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(template_id)
    .bind(&write.slug)
    .bind(&write.title)
    .bind(&write.description)
    .bind(&write.incident_type)
    .bind(&write.severity)
    .bind(&write.body)
    .bind(write.is_active)
    .bind(write.sort_order)
    .bind(&now)
    .execute(pool)
    .await
    .context("PostgreSQL-Runbook-Template konnte nicht aktualisiert werden")?;
    if result.rows_affected() == 0 {
        return Ok(None);
    }
    runbook_template_detail_postgres(pool, tenant_id, template_id).await
}

async fn update_runbook_template_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    template_id: i64,
    payload: IncidentRunbookTemplateWriteRequest,
) -> anyhow::Result<Option<IncidentRunbookTemplateSummary>> {
    let write = NormalizedRunbookTemplate::from_payload(payload)?;
    let now = Utc::now().to_rfc3339();
    let result = sqlx::query(
        r#"
        UPDATE incidents_runbooktemplate
        SET slug = ?3, title = ?4, description = ?5, incident_type = ?6,
            severity = ?7, body = ?8, is_active = ?9, sort_order = ?10,
            updated_at = ?11
        WHERE tenant_id = ?1 AND id = ?2
        "#,
    )
    .bind(tenant_id)
    .bind(template_id)
    .bind(&write.slug)
    .bind(&write.title)
    .bind(&write.description)
    .bind(&write.incident_type)
    .bind(&write.severity)
    .bind(&write.body)
    .bind(write.is_active)
    .bind(write.sort_order)
    .bind(&now)
    .execute(pool)
    .await
    .context("SQLite-Runbook-Template konnte nicht aktualisiert werden")?;
    if result.rows_affected() == 0 {
        return Ok(None);
    }
    runbook_template_detail_sqlite(pool, tenant_id, template_id).await
}

async fn deactivate_runbook_template_postgres(
    pool: &PgPool,
    tenant_id: i64,
    template_id: i64,
) -> anyhow::Result<Option<IncidentRunbookTemplateSummary>> {
    let now = Utc::now().to_rfc3339();
    let result = sqlx::query(
        r#"
        UPDATE incidents_runbooktemplate
        SET is_active = FALSE, updated_at = $3
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(template_id)
    .bind(&now)
    .execute(pool)
    .await
    .context("PostgreSQL-Runbook-Template konnte nicht deaktiviert werden")?;
    if result.rows_affected() == 0 {
        return Ok(None);
    }
    runbook_template_detail_postgres(pool, tenant_id, template_id).await
}

async fn deactivate_runbook_template_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    template_id: i64,
) -> anyhow::Result<Option<IncidentRunbookTemplateSummary>> {
    let now = Utc::now().to_rfc3339();
    let result = sqlx::query(
        r#"
        UPDATE incidents_runbooktemplate
        SET is_active = 0, updated_at = ?3
        WHERE tenant_id = ?1 AND id = ?2
        "#,
    )
    .bind(tenant_id)
    .bind(template_id)
    .bind(&now)
    .execute(pool)
    .await
    .context("SQLite-Runbook-Template konnte nicht deaktiviert werden")?;
    if result.rows_affected() == 0 {
        return Ok(None);
    }
    runbook_template_detail_sqlite(pool, tenant_id, template_id).await
}

async fn runbook_template_detail_postgres(
    pool: &PgPool,
    tenant_id: i64,
    template_id: i64,
) -> anyhow::Result<Option<IncidentRunbookTemplateSummary>> {
    let row = sqlx::query(
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
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(template_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-Runbook-Template konnte nicht gelesen werden")?;
    row.map(runbook_template_from_pg_row)
        .transpose()
        .map_err(Into::into)
}

async fn runbook_template_detail_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    template_id: i64,
) -> anyhow::Result<Option<IncidentRunbookTemplateSummary>> {
    let row = sqlx::query(
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
        WHERE tenant_id = ?1 AND id = ?2
        "#,
    )
    .bind(tenant_id)
    .bind(template_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-Runbook-Template konnte nicht gelesen werden")?;
    row.map(runbook_template_from_sqlite_row)
        .transpose()
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

async fn alertmanager_metrics_postgres(
    pool: &PgPool,
    tenant_id: i64,
) -> anyhow::Result<IncidentAlertmanagerMetrics> {
    let row = sqlx::query(
        r#"
        SELECT
            COUNT(*)::bigint AS total,
            COALESCE(SUM(CASE WHEN status NOT IN ('RESOLVED', 'CLOSED') THEN 1 ELSE 0 END), 0)::bigint AS open,
            COALESCE(SUM(CASE WHEN status = 'TRIAGE' THEN 1 ELSE 0 END), 0)::bigint AS triage,
            COALESCE(SUM(CASE WHEN status NOT IN ('RESOLVED', 'CLOSED') AND severity = 'CRITICAL' THEN 1 ELSE 0 END), 0)::bigint AS critical_open,
            COALESCE(SUM(CASE WHEN status IN ('RESOLVED', 'CLOSED') THEN 1 ELSE 0 END), 0)::bigint AS resolved
        FROM incidents_incident
        WHERE tenant_id = $1 AND authority_reference LIKE 'Alertmanager:%'
        "#,
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .context("PostgreSQL-Alertmanager-Incident-Metriken konnten nicht gelesen werden")?;
    Ok(IncidentAlertmanagerMetrics {
        total: row.try_get("total")?,
        open: row.try_get("open")?,
        triage: row.try_get("triage")?,
        critical_open: row.try_get("critical_open")?,
        resolved: row.try_get("resolved")?,
    })
}

async fn alertmanager_metrics_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
) -> anyhow::Result<IncidentAlertmanagerMetrics> {
    let row = sqlx::query(
        r#"
        SELECT
            COUNT(*) AS total,
            COALESCE(SUM(CASE WHEN status NOT IN ('RESOLVED', 'CLOSED') THEN 1 ELSE 0 END), 0) AS open,
            COALESCE(SUM(CASE WHEN status = 'TRIAGE' THEN 1 ELSE 0 END), 0) AS triage,
            COALESCE(SUM(CASE WHEN status NOT IN ('RESOLVED', 'CLOSED') AND severity = 'CRITICAL' THEN 1 ELSE 0 END), 0) AS critical_open,
            COALESCE(SUM(CASE WHEN status IN ('RESOLVED', 'CLOSED') THEN 1 ELSE 0 END), 0) AS resolved
        FROM incidents_incident
        WHERE tenant_id = ?1 AND authority_reference LIKE 'Alertmanager:%'
        "#,
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .context("SQLite-Alertmanager-Incident-Metriken konnten nicht gelesen werden")?;
    Ok(IncidentAlertmanagerMetrics {
        total: row.try_get("total")?,
        open: row.try_get("open")?,
        triage: row.try_get("triage")?,
        critical_open: row.try_get("critical_open")?,
        resolved: row.try_get("resolved")?,
    })
}

async fn open_alertmanager_incident_by_reference_postgres(
    pool: &PgPool,
    tenant_id: i64,
    authority_reference: &str,
) -> anyhow::Result<Option<IncidentSummary>> {
    let sql = incident_select_postgres_sql(
        "WHERE incident.tenant_id = $1 AND incident.authority_reference = $2 AND incident.status NOT IN ('RESOLVED', 'CLOSED')",
        "1",
    );
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(authority_reference)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-Alertmanager-Incident-Deduplizierung konnte nicht gelesen werden")?;
    row.map(summary_from_pg_row).transpose().map_err(Into::into)
}

async fn open_alertmanager_incident_by_reference_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    authority_reference: &str,
) -> anyhow::Result<Option<IncidentSummary>> {
    let sql = incident_select_sqlite_sql(
        "WHERE incident.tenant_id = ?1 AND incident.authority_reference = ?2 AND incident.status NOT IN ('RESOLVED', 'CLOSED')",
        "1",
    );
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(authority_reference)
        .fetch_optional(pool)
        .await
        .context("SQLite-Alertmanager-Incident-Deduplizierung konnte nicht gelesen werden")?;
    row.map(summary_from_sqlite_row)
        .transpose()
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
            event.is_export_highlight,
            event.export_note,
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
            event.is_export_highlight,
            event.export_note,
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
            event.is_export_highlight,
            event.export_note,
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
            event.is_export_highlight,
            event.export_note,
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

async fn update_incident_event_export_marker_postgres(
    pool: &PgPool,
    tenant_id: i64,
    incident_id: i64,
    event_id: i64,
    is_export_highlight: bool,
    export_note: Option<&str>,
) -> anyhow::Result<Option<IncidentEventSummary>> {
    let export_note = limit_chars(&normalize_optional_text(export_note), 1000);
    let result = sqlx::query(
        r#"
        UPDATE incidents_incidentevent
        SET is_export_highlight = $4, export_note = $5
        WHERE tenant_id = $1 AND incident_id = $2 AND id = $3
        "#,
    )
    .bind(tenant_id)
    .bind(incident_id)
    .bind(event_id)
    .bind(is_export_highlight)
    .bind(&export_note)
    .execute(pool)
    .await
    .context("PostgreSQL-Incident-Event-Marker konnte nicht aktualisiert werden")?;
    if result.rows_affected() == 0 {
        return Ok(None);
    }
    incident_event_detail_postgres(pool, tenant_id, incident_id, event_id).await
}

async fn update_incident_event_export_marker_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    incident_id: i64,
    event_id: i64,
    is_export_highlight: bool,
    export_note: Option<&str>,
) -> anyhow::Result<Option<IncidentEventSummary>> {
    let export_note = limit_chars(&normalize_optional_text(export_note), 1000);
    let result = sqlx::query(
        r#"
        UPDATE incidents_incidentevent
        SET is_export_highlight = ?4, export_note = ?5
        WHERE tenant_id = ?1 AND incident_id = ?2 AND id = ?3
        "#,
    )
    .bind(tenant_id)
    .bind(incident_id)
    .bind(event_id)
    .bind(is_export_highlight)
    .bind(&export_note)
    .execute(pool)
    .await
    .context("SQLite-Incident-Event-Marker konnte nicht aktualisiert werden")?;
    if result.rows_affected() == 0 {
        return Ok(None);
    }
    incident_event_detail_sqlite(pool, tenant_id, incident_id, event_id).await
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

async fn list_runbook_steps_postgres(
    pool: &PgPool,
    tenant_id: i64,
    incident_id: i64,
) -> anyhow::Result<Vec<IncidentRunbookStepSummary>> {
    let incident = incident_detail_postgres(pool, tenant_id, incident_id)
        .await?
        .with_context(|| format!("Incident {} wurde nicht gefunden.", incident_id))?;
    ensure_runbook_steps_postgres(pool, tenant_id, incident_id, &incident.runbook_template).await?;
    let rows = sqlx::query(
        r#"
        SELECT
            step.id,
            step.tenant_id,
            step.incident_id,
            step.step_number::bigint AS step_number,
            step.title,
            step.detail,
            step.is_done,
            step.done_at::text AS done_at,
            step.done_by_id,
            actor.username AS done_by_username,
            actor.first_name AS done_by_first_name,
            actor.last_name AS done_by_last_name,
            step.created_at::text AS created_at,
            step.updated_at::text AS updated_at
        FROM incidents_runbookstep step
        LEFT JOIN accounts_user actor
            ON actor.id = step.done_by_id AND actor.tenant_id = step.tenant_id
        WHERE step.tenant_id = $1 AND step.incident_id = $2
        ORDER BY step.step_number ASC, step.id ASC
        "#,
    )
    .bind(tenant_id)
    .bind(incident_id)
    .fetch_all(pool)
    .await
    .context("PostgreSQL-Runbook-Schritte konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(runbook_step_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_runbook_steps_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    incident_id: i64,
) -> anyhow::Result<Vec<IncidentRunbookStepSummary>> {
    let incident = incident_detail_sqlite(pool, tenant_id, incident_id)
        .await?
        .with_context(|| format!("Incident {} wurde nicht gefunden.", incident_id))?;
    ensure_runbook_steps_sqlite(pool, tenant_id, incident_id, &incident.runbook_template).await?;
    let rows = sqlx::query(
        r#"
        SELECT
            step.id,
            step.tenant_id,
            step.incident_id,
            step.step_number,
            step.title,
            step.detail,
            step.is_done,
            CAST(step.done_at AS TEXT) AS done_at,
            step.done_by_id,
            actor.username AS done_by_username,
            actor.first_name AS done_by_first_name,
            actor.last_name AS done_by_last_name,
            CAST(step.created_at AS TEXT) AS created_at,
            CAST(step.updated_at AS TEXT) AS updated_at
        FROM incidents_runbookstep step
        LEFT JOIN accounts_user actor
            ON actor.id = step.done_by_id AND actor.tenant_id = step.tenant_id
        WHERE step.tenant_id = ?1 AND step.incident_id = ?2
        ORDER BY step.step_number ASC, step.id ASC
        "#,
    )
    .bind(tenant_id)
    .bind(incident_id)
    .fetch_all(pool)
    .await
    .context("SQLite-Runbook-Schritte konnten nicht gelesen werden")?;
    rows.into_iter()
        .map(runbook_step_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn ensure_runbook_steps_postgres(
    pool: &PgPool,
    tenant_id: i64,
    incident_id: i64,
    runbook_template: &str,
) -> anyhow::Result<()> {
    let existing_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM incidents_runbookstep WHERE tenant_id = $1 AND incident_id = $2",
    )
    .bind(tenant_id)
    .bind(incident_id)
    .fetch_one(pool)
    .await?;
    if existing_count > 0 {
        return Ok(());
    }
    let now = Utc::now().to_rfc3339();
    for (index, step) in runbook_steps_from_template(runbook_template)
        .into_iter()
        .enumerate()
    {
        sqlx::query(
            r#"
            INSERT INTO incidents_runbookstep (
                tenant_id, incident_id, step_number, title, detail,
                is_done, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, FALSE, $6, $6)
            ON CONFLICT (tenant_id, incident_id, step_number) DO NOTHING
            "#,
        )
        .bind(tenant_id)
        .bind(incident_id)
        .bind((index + 1) as i64)
        .bind(&step.title)
        .bind(&step.detail)
        .bind(&now)
        .execute(pool)
        .await
        .context("PostgreSQL-Runbook-Schritt konnte nicht angelegt werden")?;
    }
    Ok(())
}

async fn ensure_runbook_steps_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    incident_id: i64,
    runbook_template: &str,
) -> anyhow::Result<()> {
    let existing_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM incidents_runbookstep WHERE tenant_id = ?1 AND incident_id = ?2",
    )
    .bind(tenant_id)
    .bind(incident_id)
    .fetch_one(pool)
    .await?;
    if existing_count > 0 {
        return Ok(());
    }
    let now = Utc::now().to_rfc3339();
    for (index, step) in runbook_steps_from_template(runbook_template)
        .into_iter()
        .enumerate()
    {
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO incidents_runbookstep (
                tenant_id, incident_id, step_number, title, detail,
                is_done, created_at, updated_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?6)
            "#,
        )
        .bind(tenant_id)
        .bind(incident_id)
        .bind((index + 1) as i64)
        .bind(&step.title)
        .bind(&step.detail)
        .bind(&now)
        .execute(pool)
        .await
        .context("SQLite-Runbook-Schritt konnte nicht angelegt werden")?;
    }
    Ok(())
}

async fn set_runbook_step_done_postgres(
    pool: &PgPool,
    tenant_id: i64,
    incident_id: i64,
    step_id: i64,
    actor_id: Option<i64>,
    is_done: bool,
) -> anyhow::Result<Option<IncidentRunbookStepUpdateResult>> {
    let incident = incident_detail_postgres(pool, tenant_id, incident_id)
        .await?
        .with_context(|| format!("Incident {} wurde nicht gefunden.", incident_id))?;
    ensure_runbook_steps_postgres(pool, tenant_id, incident_id, &incident.runbook_template).await?;
    let now = Utc::now().to_rfc3339();
    let result = sqlx::query(
        r#"
        UPDATE incidents_runbookstep
        SET is_done = $4,
            done_at = CASE WHEN $4 THEN $5 ELSE NULL END,
            done_by_id = CASE WHEN $4 THEN $6 ELSE NULL END,
            updated_at = $5
        WHERE tenant_id = $1 AND incident_id = $2 AND id = $3
        "#,
    )
    .bind(tenant_id)
    .bind(incident_id)
    .bind(step_id)
    .bind(is_done)
    .bind(&now)
    .bind(actor_id)
    .execute(pool)
    .await
    .context("PostgreSQL-Runbook-Schritt konnte nicht aktualisiert werden")?;
    if result.rows_affected() == 0 {
        return Ok(None);
    }
    let step = runbook_step_detail_postgres(pool, tenant_id, incident_id, step_id)
        .await?
        .context("Aktualisierter Runbook-Schritt konnte nicht gelesen werden")?;
    let event = append_incident_event_postgres(
        pool,
        tenant_id,
        incident_id,
        actor_id,
        IncidentEventWriteRequest::runbook_step_changed(&step.title, step.is_done),
    )
    .await?;
    Ok(Some(IncidentRunbookStepUpdateResult { step, event }))
}

async fn set_runbook_step_done_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    incident_id: i64,
    step_id: i64,
    actor_id: Option<i64>,
    is_done: bool,
) -> anyhow::Result<Option<IncidentRunbookStepUpdateResult>> {
    let incident = incident_detail_sqlite(pool, tenant_id, incident_id)
        .await?
        .with_context(|| format!("Incident {} wurde nicht gefunden.", incident_id))?;
    ensure_runbook_steps_sqlite(pool, tenant_id, incident_id, &incident.runbook_template).await?;
    let now = Utc::now().to_rfc3339();
    let result = sqlx::query(
        r#"
        UPDATE incidents_runbookstep
        SET is_done = ?4,
            done_at = CASE WHEN ?4 THEN ?5 ELSE NULL END,
            done_by_id = CASE WHEN ?4 THEN ?6 ELSE NULL END,
            updated_at = ?5
        WHERE tenant_id = ?1 AND incident_id = ?2 AND id = ?3
        "#,
    )
    .bind(tenant_id)
    .bind(incident_id)
    .bind(step_id)
    .bind(is_done)
    .bind(&now)
    .bind(actor_id)
    .execute(pool)
    .await
    .context("SQLite-Runbook-Schritt konnte nicht aktualisiert werden")?;
    if result.rows_affected() == 0 {
        return Ok(None);
    }
    let step = runbook_step_detail_sqlite(pool, tenant_id, incident_id, step_id)
        .await?
        .context("Aktualisierter Runbook-Schritt konnte nicht gelesen werden")?;
    let event = append_incident_event_sqlite(
        pool,
        tenant_id,
        incident_id,
        actor_id,
        IncidentEventWriteRequest::runbook_step_changed(&step.title, step.is_done),
    )
    .await?;
    Ok(Some(IncidentRunbookStepUpdateResult { step, event }))
}

async fn move_runbook_step_postgres(
    pool: &PgPool,
    tenant_id: i64,
    incident_id: i64,
    step_id: i64,
    actor_id: Option<i64>,
    direction: &str,
) -> anyhow::Result<Option<IncidentRunbookStepUpdateResult>> {
    let incident = incident_detail_postgres(pool, tenant_id, incident_id)
        .await?
        .with_context(|| format!("Incident {} wurde nicht gefunden.", incident_id))?;
    ensure_runbook_steps_postgres(pool, tenant_id, incident_id, &incident.runbook_template).await?;
    let Some(current) = runbook_step_detail_postgres(pool, tenant_id, incident_id, step_id).await?
    else {
        return Ok(None);
    };
    let direction = RunbookMoveDirection::from_value(direction);
    let neighbor_row = sqlx::query(direction.postgres_neighbor_sql())
        .bind(tenant_id)
        .bind(incident_id)
        .bind(current.step_number)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-benachbarter Runbook-Schritt konnte nicht gelesen werden")?;
    let Some(neighbor_row) = neighbor_row else {
        return Ok(None);
    };
    let neighbor_id: i64 = neighbor_row.try_get("id")?;
    let neighbor_number: i64 = neighbor_row.try_get("step_number")?;
    let now = Utc::now().to_rfc3339();
    let temporary_number = -step_id.abs();
    sqlx::query(
        r#"
        UPDATE incidents_runbookstep
        SET step_number = $4, updated_at = $5
        WHERE tenant_id = $1 AND incident_id = $2 AND id = $3
        "#,
    )
    .bind(tenant_id)
    .bind(incident_id)
    .bind(step_id)
    .bind(temporary_number)
    .bind(&now)
    .execute(pool)
    .await
    .context("PostgreSQL-Runbook-Schritt konnte nicht temporaer verschoben werden")?;
    sqlx::query(
        r#"
        UPDATE incidents_runbookstep
        SET step_number = $4, updated_at = $5
        WHERE tenant_id = $1 AND incident_id = $2 AND id = $3
        "#,
    )
    .bind(tenant_id)
    .bind(incident_id)
    .bind(neighbor_id)
    .bind(current.step_number)
    .bind(&now)
    .execute(pool)
    .await
    .context("PostgreSQL-benachbarter Runbook-Schritt konnte nicht verschoben werden")?;
    sqlx::query(
        r#"
        UPDATE incidents_runbookstep
        SET step_number = $4, updated_at = $5
        WHERE tenant_id = $1 AND incident_id = $2 AND id = $3
        "#,
    )
    .bind(tenant_id)
    .bind(incident_id)
    .bind(step_id)
    .bind(neighbor_number)
    .bind(&now)
    .execute(pool)
    .await
    .context("PostgreSQL-Runbook-Schritt konnte nicht final verschoben werden")?;
    let step = runbook_step_detail_postgres(pool, tenant_id, incident_id, step_id)
        .await?
        .context("Verschobener Runbook-Schritt konnte nicht gelesen werden")?;
    let event = append_incident_event_postgres(
        pool,
        tenant_id,
        incident_id,
        actor_id,
        IncidentEventWriteRequest::runbook_step_reordered(&step.title, direction.label()),
    )
    .await?;
    Ok(Some(IncidentRunbookStepUpdateResult { step, event }))
}

async fn move_runbook_step_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    incident_id: i64,
    step_id: i64,
    actor_id: Option<i64>,
    direction: &str,
) -> anyhow::Result<Option<IncidentRunbookStepUpdateResult>> {
    let incident = incident_detail_sqlite(pool, tenant_id, incident_id)
        .await?
        .with_context(|| format!("Incident {} wurde nicht gefunden.", incident_id))?;
    ensure_runbook_steps_sqlite(pool, tenant_id, incident_id, &incident.runbook_template).await?;
    let Some(current) = runbook_step_detail_sqlite(pool, tenant_id, incident_id, step_id).await?
    else {
        return Ok(None);
    };
    let direction = RunbookMoveDirection::from_value(direction);
    let neighbor_row = sqlx::query(direction.sqlite_neighbor_sql())
        .bind(tenant_id)
        .bind(incident_id)
        .bind(current.step_number)
        .fetch_optional(pool)
        .await
        .context("SQLite-benachbarter Runbook-Schritt konnte nicht gelesen werden")?;
    let Some(neighbor_row) = neighbor_row else {
        return Ok(None);
    };
    let neighbor_id: i64 = neighbor_row.try_get("id")?;
    let neighbor_number: i64 = neighbor_row.try_get("step_number")?;
    let now = Utc::now().to_rfc3339();
    let temporary_number = -step_id.abs();
    sqlx::query(
        r#"
        UPDATE incidents_runbookstep
        SET step_number = ?4, updated_at = ?5
        WHERE tenant_id = ?1 AND incident_id = ?2 AND id = ?3
        "#,
    )
    .bind(tenant_id)
    .bind(incident_id)
    .bind(step_id)
    .bind(temporary_number)
    .bind(&now)
    .execute(pool)
    .await
    .context("SQLite-Runbook-Schritt konnte nicht temporaer verschoben werden")?;
    sqlx::query(
        r#"
        UPDATE incidents_runbookstep
        SET step_number = ?4, updated_at = ?5
        WHERE tenant_id = ?1 AND incident_id = ?2 AND id = ?3
        "#,
    )
    .bind(tenant_id)
    .bind(incident_id)
    .bind(neighbor_id)
    .bind(current.step_number)
    .bind(&now)
    .execute(pool)
    .await
    .context("SQLite-benachbarter Runbook-Schritt konnte nicht verschoben werden")?;
    sqlx::query(
        r#"
        UPDATE incidents_runbookstep
        SET step_number = ?4, updated_at = ?5
        WHERE tenant_id = ?1 AND incident_id = ?2 AND id = ?3
        "#,
    )
    .bind(tenant_id)
    .bind(incident_id)
    .bind(step_id)
    .bind(neighbor_number)
    .bind(&now)
    .execute(pool)
    .await
    .context("SQLite-Runbook-Schritt konnte nicht final verschoben werden")?;
    let step = runbook_step_detail_sqlite(pool, tenant_id, incident_id, step_id)
        .await?
        .context("Verschobener Runbook-Schritt konnte nicht gelesen werden")?;
    let event = append_incident_event_sqlite(
        pool,
        tenant_id,
        incident_id,
        actor_id,
        IncidentEventWriteRequest::runbook_step_reordered(&step.title, direction.label()),
    )
    .await?;
    Ok(Some(IncidentRunbookStepUpdateResult { step, event }))
}

async fn runbook_step_detail_postgres(
    pool: &PgPool,
    tenant_id: i64,
    incident_id: i64,
    step_id: i64,
) -> anyhow::Result<Option<IncidentRunbookStepSummary>> {
    let row = sqlx::query(
        r#"
        SELECT
            step.id,
            step.tenant_id,
            step.incident_id,
            step.step_number::bigint AS step_number,
            step.title,
            step.detail,
            step.is_done,
            step.done_at::text AS done_at,
            step.done_by_id,
            actor.username AS done_by_username,
            actor.first_name AS done_by_first_name,
            actor.last_name AS done_by_last_name,
            step.created_at::text AS created_at,
            step.updated_at::text AS updated_at
        FROM incidents_runbookstep step
        LEFT JOIN accounts_user actor
            ON actor.id = step.done_by_id AND actor.tenant_id = step.tenant_id
        WHERE step.tenant_id = $1 AND step.incident_id = $2 AND step.id = $3
        "#,
    )
    .bind(tenant_id)
    .bind(incident_id)
    .bind(step_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-Runbook-Schritt konnte nicht gelesen werden")?;
    row.map(runbook_step_from_pg_row)
        .transpose()
        .map_err(Into::into)
}

async fn runbook_step_detail_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    incident_id: i64,
    step_id: i64,
) -> anyhow::Result<Option<IncidentRunbookStepSummary>> {
    let row = sqlx::query(
        r#"
        SELECT
            step.id,
            step.tenant_id,
            step.incident_id,
            step.step_number,
            step.title,
            step.detail,
            step.is_done,
            CAST(step.done_at AS TEXT) AS done_at,
            step.done_by_id,
            actor.username AS done_by_username,
            actor.first_name AS done_by_first_name,
            actor.last_name AS done_by_last_name,
            CAST(step.created_at AS TEXT) AS created_at,
            CAST(step.updated_at AS TEXT) AS updated_at
        FROM incidents_runbookstep step
        LEFT JOIN accounts_user actor
            ON actor.id = step.done_by_id AND actor.tenant_id = step.tenant_id
        WHERE step.tenant_id = ?1 AND step.incident_id = ?2 AND step.id = ?3
        "#,
    )
    .bind(tenant_id)
    .bind(incident_id)
    .bind(step_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-Runbook-Schritt konnte nicht gelesen werden")?;
    row.map(runbook_step_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
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
            nis2_significance_status, nis2_significance_criteria, nis2_significance_justification,
            nis2_significance_reference, nis2_significance_assessed_at,
            early_warning_due_at, early_warning_sent_at, notification_due_at,
            notification_sent_at, final_report_due_at, final_report_sent_at,
            authority_reference, stakeholder_summary, lessons_learned, review_state,
            review_notes, created_at, updated_at
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
            $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30,
            $31, $32, $33, $34, $35
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
    .bind(&write.nis2_significance_status)
    .bind(&write.nis2_significance_criteria)
    .bind(&write.nis2_significance_justification)
    .bind(&write.nis2_significance_reference)
    .bind(write.nis2_significance_assessed_at.as_deref())
    .bind(write.early_warning_due_at.as_deref())
    .bind(write.early_warning_sent_at.as_deref())
    .bind(write.notification_due_at.as_deref())
    .bind(write.notification_sent_at.as_deref())
    .bind(write.final_report_due_at.as_deref())
    .bind(write.final_report_sent_at.as_deref())
    .bind(&write.authority_reference)
    .bind(&write.stakeholder_summary)
    .bind(&write.lessons_learned)
    .bind(&write.review_state)
    .bind(&write.review_notes)
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
            nis2_significance_status, nis2_significance_criteria, nis2_significance_justification,
            nis2_significance_reference, nis2_significance_assessed_at,
            early_warning_due_at, early_warning_sent_at, notification_due_at,
            notification_sent_at, final_report_due_at, final_report_sent_at,
            authority_reference, stakeholder_summary, lessons_learned, review_state,
            review_notes, created_at, updated_at
        )
        VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
            ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30,
            ?31, ?32, ?33, ?34, ?35
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
    .bind(&write.nis2_significance_status)
    .bind(&write.nis2_significance_criteria)
    .bind(&write.nis2_significance_justification)
    .bind(&write.nis2_significance_reference)
    .bind(write.nis2_significance_assessed_at.as_deref())
    .bind(write.early_warning_due_at.as_deref())
    .bind(write.early_warning_sent_at.as_deref())
    .bind(write.notification_due_at.as_deref())
    .bind(write.notification_sent_at.as_deref())
    .bind(write.final_report_due_at.as_deref())
    .bind(write.final_report_sent_at.as_deref())
    .bind(&write.authority_reference)
    .bind(&write.stakeholder_summary)
    .bind(&write.lessons_learned)
    .bind(&write.review_state)
    .bind(&write.review_notes)
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
            nis2_significance_status = $19, nis2_significance_criteria = $20,
            nis2_significance_justification = $21, nis2_significance_reference = $22,
            nis2_significance_assessed_at = $23,
            early_warning_due_at = $24, early_warning_sent_at = $25,
            notification_due_at = $26, notification_sent_at = $27, final_report_due_at = $28,
            final_report_sent_at = $29, authority_reference = $30,
            stakeholder_summary = $31, lessons_learned = $32, review_state = $33,
            review_notes = $34, updated_at = $35
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
    .bind(&write.nis2_significance_status)
    .bind(&write.nis2_significance_criteria)
    .bind(&write.nis2_significance_justification)
    .bind(&write.nis2_significance_reference)
    .bind(write.nis2_significance_assessed_at.as_deref())
    .bind(write.early_warning_due_at.as_deref())
    .bind(write.early_warning_sent_at.as_deref())
    .bind(write.notification_due_at.as_deref())
    .bind(write.notification_sent_at.as_deref())
    .bind(write.final_report_due_at.as_deref())
    .bind(write.final_report_sent_at.as_deref())
    .bind(&write.authority_reference)
    .bind(&write.stakeholder_summary)
    .bind(&write.lessons_learned)
    .bind(&write.review_state)
    .bind(&write.review_notes)
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
            nis2_significance_status = ?19, nis2_significance_criteria = ?20,
            nis2_significance_justification = ?21, nis2_significance_reference = ?22,
            nis2_significance_assessed_at = ?23,
            early_warning_due_at = ?24, early_warning_sent_at = ?25,
            notification_due_at = ?26, notification_sent_at = ?27, final_report_due_at = ?28,
            final_report_sent_at = ?29, authority_reference = ?30,
            stakeholder_summary = ?31, lessons_learned = ?32, review_state = ?33,
            review_notes = ?34, updated_at = ?35
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
    .bind(&write.nis2_significance_status)
    .bind(&write.nis2_significance_criteria)
    .bind(&write.nis2_significance_justification)
    .bind(&write.nis2_significance_reference)
    .bind(write.nis2_significance_assessed_at.as_deref())
    .bind(write.early_warning_due_at.as_deref())
    .bind(write.early_warning_sent_at.as_deref())
    .bind(write.notification_due_at.as_deref())
    .bind(write.notification_sent_at.as_deref())
    .bind(write.final_report_due_at.as_deref())
    .bind(write.final_report_sent_at.as_deref())
    .bind(&write.authority_reference)
    .bind(&write.stakeholder_summary)
    .bind(&write.lessons_learned)
    .bind(&write.review_state)
    .bind(&write.review_notes)
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
    nis2_significance_status: String,
    nis2_significance_criteria: String,
    nis2_significance_justification: String,
    nis2_significance_reference: String,
    nis2_significance_assessed_at: Option<String>,
    early_warning_due_at: Option<String>,
    early_warning_sent_at: Option<String>,
    notification_due_at: Option<String>,
    notification_sent_at: Option<String>,
    final_report_due_at: Option<String>,
    final_report_sent_at: Option<String>,
    authority_reference: String,
    stakeholder_summary: String,
    lessons_learned: String,
    review_state: String,
    review_notes: String,
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
    nis2_significance_status: String,
    nis2_significance_criteria: String,
    nis2_significance_justification: String,
    nis2_significance_reference: String,
    nis2_significance_assessed_at: Option<String>,
    early_warning_due_at: Option<String>,
    early_warning_sent_at: Option<String>,
    notification_due_at: Option<String>,
    notification_sent_at: Option<String>,
    final_report_due_at: Option<String>,
    final_report_sent_at: Option<String>,
    authority_reference: String,
    stakeholder_summary: String,
    lessons_learned: String,
    review_state: String,
    review_notes: String,
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

#[derive(Debug, Clone, Copy)]
enum RunbookMoveDirection {
    Up,
    Down,
}

impl RunbookMoveDirection {
    fn from_value(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "up" | "move_up" => Self::Up,
            _ => Self::Down,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Up => "nach oben",
            Self::Down => "nach unten",
        }
    }

    fn postgres_neighbor_sql(self) -> &'static str {
        match self {
            Self::Up => {
                r#"
                SELECT id, step_number::bigint AS step_number
                FROM incidents_runbookstep
                WHERE tenant_id = $1 AND incident_id = $2 AND step_number < $3
                ORDER BY step_number DESC, id DESC
                LIMIT 1
                "#
            }
            Self::Down => {
                r#"
                SELECT id, step_number::bigint AS step_number
                FROM incidents_runbookstep
                WHERE tenant_id = $1 AND incident_id = $2 AND step_number > $3
                ORDER BY step_number ASC, id ASC
                LIMIT 1
                "#
            }
        }
    }

    fn sqlite_neighbor_sql(self) -> &'static str {
        match self {
            Self::Up => {
                r#"
                SELECT id, step_number
                FROM incidents_runbookstep
                WHERE tenant_id = ?1 AND incident_id = ?2 AND step_number < ?3
                ORDER BY step_number DESC, id DESC
                LIMIT 1
                "#
            }
            Self::Down => {
                r#"
                SELECT id, step_number
                FROM incidents_runbookstep
                WHERE tenant_id = ?1 AND incident_id = ?2 AND step_number > ?3
                ORDER BY step_number ASC, id ASC
                LIMIT 1
                "#
            }
        }
    }
}

#[derive(Debug, Clone)]
struct ReviewTransition {
    state: String,
    notes: String,
    set_review_actor: bool,
    set_review_notes: bool,
    set_approval_actor: bool,
    set_approval_notes: bool,
    clear_review: bool,
}

impl ReviewTransition {
    fn from_action(action: &str, notes: Option<&str>) -> Self {
        let notes = limit_chars(&normalize_optional_text(notes), 2000);
        match action.trim().to_ascii_lowercase().as_str() {
            "request_review" | "submit" | "in_review" => Self {
                state: "IN_REVIEW".to_string(),
                notes,
                set_review_actor: false,
                set_review_notes: true,
                set_approval_actor: false,
                set_approval_notes: false,
                clear_review: false,
            },
            "review" | "reviewed" | "mark_reviewed" => Self {
                state: "REVIEWED".to_string(),
                notes,
                set_review_actor: true,
                set_review_notes: true,
                set_approval_actor: false,
                set_approval_notes: false,
                clear_review: false,
            },
            "approve" | "approved" => Self {
                state: "APPROVED".to_string(),
                notes,
                set_review_actor: false,
                set_review_notes: false,
                set_approval_actor: true,
                set_approval_notes: true,
                clear_review: false,
            },
            "changes_requested" | "request_changes" | "reject" => Self {
                state: "CHANGES_REQUESTED".to_string(),
                notes,
                set_review_actor: true,
                set_review_notes: true,
                set_approval_actor: false,
                set_approval_notes: false,
                clear_review: true,
            },
            "reopen" | "draft" | "reset" => Self {
                state: "DRAFT".to_string(),
                notes,
                set_review_actor: false,
                set_review_notes: true,
                set_approval_actor: false,
                set_approval_notes: false,
                clear_review: true,
            },
            _ => Self {
                state: "IN_REVIEW".to_string(),
                notes,
                set_review_actor: false,
                set_review_notes: true,
                set_approval_actor: false,
                set_approval_notes: false,
                clear_review: false,
            },
        }
    }
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
    if current.nis2_significance_status != updated.nis2_significance_status
        || current.nis2_reportable != updated.nis2_reportable
    {
        events.push(
            append_incident_event_postgres(
                pool,
                tenant_id,
                incident_id,
                actor_id,
                IncidentEventWriteRequest::timeline_note(
                    Some("NIS2-Erheblichkeit bewertet"),
                    &format!(
                        "NIS2-Erheblichkeitsstatus von '{}' auf '{}' geaendert. Meldepflicht: {}.",
                        current.nis2_significance_label,
                        updated.nis2_significance_label,
                        if updated.nis2_reportable {
                            "ja"
                        } else {
                            "nein"
                        },
                    ),
                ),
            )
            .await?,
        );
    }
    if current.review_state != updated.review_state {
        events.push(
            append_incident_event_postgres(
                pool,
                tenant_id,
                incident_id,
                actor_id,
                IncidentEventWriteRequest::review_state_changed(
                    &updated.review_state_label,
                    &updated.review_notes,
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
    if current.nis2_significance_status != updated.nis2_significance_status
        || current.nis2_reportable != updated.nis2_reportable
    {
        events.push(
            append_incident_event_sqlite(
                pool,
                tenant_id,
                incident_id,
                actor_id,
                IncidentEventWriteRequest::timeline_note(
                    Some("NIS2-Erheblichkeit bewertet"),
                    &format!(
                        "NIS2-Erheblichkeitsstatus von '{}' auf '{}' geaendert. Meldepflicht: {}.",
                        current.nis2_significance_label,
                        updated.nis2_significance_label,
                        if updated.nis2_reportable {
                            "ja"
                        } else {
                            "nein"
                        },
                    ),
                ),
            )
            .await?,
        );
    }
    if current.review_state != updated.review_state {
        events.push(
            append_incident_event_sqlite(
                pool,
                tenant_id,
                incident_id,
                actor_id,
                IncidentEventWriteRequest::review_state_changed(
                    &updated.review_state_label,
                    &updated.review_notes,
                ),
            )
            .await?,
        );
    }
    Ok(events)
}

async fn update_incident_review_state_postgres(
    pool: &PgPool,
    tenant_id: i64,
    incident_id: i64,
    actor_id: i64,
    action: &str,
    notes: Option<&str>,
) -> anyhow::Result<Option<IncidentReviewUpdateResult>> {
    if incident_detail_postgres(pool, tenant_id, incident_id)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    let transition = ReviewTransition::from_action(action, notes);
    let now = Utc::now().to_rfc3339();
    let result = sqlx::query(
        r#"
        UPDATE incidents_incident
        SET review_state = $3,
            reviewed_by_id = CASE WHEN $4 THEN $9 WHEN $8 THEN NULL ELSE reviewed_by_id END,
            reviewed_at = CASE WHEN $4 THEN $10 WHEN $8 THEN NULL ELSE reviewed_at END,
            review_notes = CASE WHEN $5 THEN $11 ELSE review_notes END,
            approved_by_id = CASE WHEN $6 THEN $9 WHEN $8 THEN NULL ELSE approved_by_id END,
            approved_at = CASE WHEN $6 THEN $10 WHEN $8 THEN NULL ELSE approved_at END,
            approval_notes = CASE WHEN $7 THEN $11 WHEN $8 THEN '' ELSE approval_notes END,
            updated_at = $10
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(incident_id)
    .bind(&transition.state)
    .bind(transition.set_review_actor)
    .bind(transition.set_review_notes)
    .bind(transition.set_approval_actor)
    .bind(transition.set_approval_notes)
    .bind(transition.clear_review)
    .bind(actor_id)
    .bind(&now)
    .bind(&transition.notes)
    .execute(pool)
    .await
    .context("PostgreSQL-Incident-Review konnte nicht aktualisiert werden")?;
    if result.rows_affected() == 0 {
        return Ok(None);
    }
    let incident = incident_detail_postgres(pool, tenant_id, incident_id)
        .await?
        .context("Aktualisierter Incident-Review konnte nicht gelesen werden")?;
    let event = append_incident_event_postgres(
        pool,
        tenant_id,
        incident_id,
        Some(actor_id),
        IncidentEventWriteRequest::review_state_changed(
            &incident.review_state_label,
            &transition.notes,
        ),
    )
    .await?;
    Ok(Some(IncidentReviewUpdateResult { incident, event }))
}

async fn update_incident_review_state_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    incident_id: i64,
    actor_id: i64,
    action: &str,
    notes: Option<&str>,
) -> anyhow::Result<Option<IncidentReviewUpdateResult>> {
    if incident_detail_sqlite(pool, tenant_id, incident_id)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    let transition = ReviewTransition::from_action(action, notes);
    let now = Utc::now().to_rfc3339();
    let result = sqlx::query(
        r#"
        UPDATE incidents_incident
        SET review_state = ?3,
            reviewed_by_id = CASE WHEN ?4 THEN ?9 WHEN ?8 THEN NULL ELSE reviewed_by_id END,
            reviewed_at = CASE WHEN ?4 THEN ?10 WHEN ?8 THEN NULL ELSE reviewed_at END,
            review_notes = CASE WHEN ?5 THEN ?11 ELSE review_notes END,
            approved_by_id = CASE WHEN ?6 THEN ?9 WHEN ?8 THEN NULL ELSE approved_by_id END,
            approved_at = CASE WHEN ?6 THEN ?10 WHEN ?8 THEN NULL ELSE approved_at END,
            approval_notes = CASE WHEN ?7 THEN ?11 WHEN ?8 THEN '' ELSE approval_notes END,
            updated_at = ?10
        WHERE tenant_id = ?1 AND id = ?2
        "#,
    )
    .bind(tenant_id)
    .bind(incident_id)
    .bind(&transition.state)
    .bind(transition.set_review_actor)
    .bind(transition.set_review_notes)
    .bind(transition.set_approval_actor)
    .bind(transition.set_approval_notes)
    .bind(transition.clear_review)
    .bind(actor_id)
    .bind(&now)
    .bind(&transition.notes)
    .execute(pool)
    .await
    .context("SQLite-Incident-Review konnte nicht aktualisiert werden")?;
    if result.rows_affected() == 0 {
        return Ok(None);
    }
    let incident = incident_detail_sqlite(pool, tenant_id, incident_id)
        .await?
        .context("Aktualisierter Incident-Review konnte nicht gelesen werden")?;
    let event = append_incident_event_sqlite(
        pool,
        tenant_id,
        incident_id,
        Some(actor_id),
        IncidentEventWriteRequest::review_state_changed(
            &incident.review_state_label,
            &transition.notes,
        ),
    )
    .await?;
    Ok(Some(IncidentReviewUpdateResult { incident, event }))
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
        let legacy_nis2_reportable = payload.nis2_reportable.unwrap_or(false);
        let nis2_significance_status = normalize_nis2_significance_status(
            payload.nis2_significance_status.as_deref(),
            legacy_nis2_reportable,
        );
        let nis2_reportable = nis2_significance_status == "SIGNIFICANT";
        let nis2_significance_criteria =
            normalize_nis2_significance_text(payload.nis2_significance_criteria.as_deref());
        let nis2_significance_justification =
            normalize_nis2_significance_text(payload.nis2_significance_justification.as_deref());
        let nis2_significance_reference = normalize_nis2_significance_reference(
            payload.nis2_significance_reference.as_deref(),
            &nis2_significance_status,
        );
        let nis2_significance_assessed_at = normalize_optional_datetime(
            payload.nis2_significance_assessed_at.flatten().as_deref(),
        )?
        .or_else(|| {
            if nis2_significance_status != "NOT_ASSESSED" {
                Some(now.clone())
            } else {
                None
            }
        });
        let deadlines = nis2_deadlines(nis2_reportable, detected_at.as_deref());
        let review_state =
            review_state_for_significance_decision(&nis2_significance_status, None, None);
        let review_notes =
            review_notes_for_significance_decision(&nis2_significance_status, &review_state, "");
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
            nis2_significance_status,
            nis2_significance_criteria,
            nis2_significance_justification,
            nis2_significance_reference,
            nis2_significance_assessed_at,
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
            review_state,
            review_notes,
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
        let nis2_significance_status = normalize_nis2_significance_status_for_update(
            payload.nis2_significance_status.as_deref(),
            payload.nis2_reportable,
            &current.nis2_significance_status,
        );
        let nis2_reportable = nis2_significance_status == "SIGNIFICANT";
        let nis2_significance_criteria = payload
            .nis2_significance_criteria
            .map(|value| normalize_nis2_significance_text(Some(&value)))
            .unwrap_or(current.nis2_significance_criteria);
        let nis2_significance_justification = payload
            .nis2_significance_justification
            .map(|value| normalize_nis2_significance_text(Some(&value)))
            .unwrap_or(current.nis2_significance_justification);
        let nis2_significance_reference = payload
            .nis2_significance_reference
            .map(|value| {
                normalize_nis2_significance_reference(Some(&value), &nis2_significance_status)
            })
            .unwrap_or_else(|| {
                normalize_nis2_significance_reference(
                    Some(&current.nis2_significance_reference),
                    &nis2_significance_status,
                )
            });
        let nis2_significance_assessed_at = match payload.nis2_significance_assessed_at {
            Some(value) => normalize_optional_datetime(value.as_deref())?,
            None if nis2_significance_status != current.nis2_significance_status
                && nis2_significance_status != "NOT_ASSESSED" =>
            {
                Some(now.clone())
            }
            None if nis2_significance_status == "NOT_ASSESSED" => None,
            None => current.nis2_significance_assessed_at,
        };
        let deadlines = nis2_deadlines(nis2_reportable, detected_at.as_deref());
        let review_state = review_state_for_significance_decision(
            &nis2_significance_status,
            Some(&current.nis2_significance_status),
            Some(&current.review_state),
        );
        let review_notes = review_notes_for_significance_decision(
            &nis2_significance_status,
            &review_state,
            &current.review_notes,
        );
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
            nis2_significance_status,
            nis2_significance_criteria,
            nis2_significance_justification,
            nis2_significance_reference,
            nis2_significance_assessed_at,
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
            review_state,
            review_notes,
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
            nis2_significance_status: self.nis2_significance_status.clone(),
            nis2_significance_criteria: self.nis2_significance_criteria.clone(),
            nis2_significance_justification: self.nis2_significance_justification.clone(),
            nis2_significance_reference: self.nis2_significance_reference.clone(),
            nis2_significance_assessed_at: self.nis2_significance_assessed_at.clone(),
            early_warning_due_at: self.early_warning_due_at.clone(),
            early_warning_sent_at: self.early_warning_sent_at.clone(),
            notification_due_at: self.notification_due_at.clone(),
            notification_sent_at: self.notification_sent_at.clone(),
            final_report_due_at: self.final_report_due_at.clone(),
            final_report_sent_at: self.final_report_sent_at.clone(),
            authority_reference: self.authority_reference.clone(),
            stakeholder_summary: self.stakeholder_summary.clone(),
            lessons_learned: self.lessons_learned.clone(),
            review_state: self.review_state.clone(),
            review_notes: self.review_notes.clone(),
            now: self.now.clone(),
        }
    }
}

const NOT_SIGNIFICANT_REVIEW_NOTE: &str =
    "Nicht erheblicher Sicherheitsvorfall: fachliche Review/Freigabe erforderlich.";

fn review_state_for_significance_decision(
    significance_status: &str,
    previous_significance_status: Option<&str>,
    current_review_state: Option<&str>,
) -> String {
    let current_review_state = current_review_state.unwrap_or("DRAFT");
    if significance_status == "NOT_SIGNIFICANT" {
        let approved_same_decision = previous_significance_status == Some("NOT_SIGNIFICANT")
            && current_review_state == "APPROVED";
        if approved_same_decision {
            return "APPROVED".to_string();
        }
        return "IN_REVIEW".to_string();
    }
    current_review_state.to_string()
}

fn review_notes_for_significance_decision(
    significance_status: &str,
    review_state: &str,
    current_review_notes: &str,
) -> String {
    if significance_status == "NOT_SIGNIFICANT"
        && review_state == "IN_REVIEW"
        && current_review_notes.trim().is_empty()
    {
        return NOT_SIGNIFICANT_REVIEW_NOTE.to_string();
    }
    current_review_notes.to_string()
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
            incident.nis2_significance_status,
            incident.nis2_significance_criteria,
            incident.nis2_significance_justification,
            incident.nis2_significance_reference,
            incident.nis2_significance_assessed_at::text AS nis2_significance_assessed_at,
            incident.early_warning_due_at::text AS early_warning_due_at,
            incident.early_warning_sent_at::text AS early_warning_sent_at,
            incident.notification_due_at::text AS notification_due_at,
            incident.notification_sent_at::text AS notification_sent_at,
            incident.final_report_due_at::text AS final_report_due_at,
            incident.final_report_sent_at::text AS final_report_sent_at,
            incident.authority_reference,
            incident.stakeholder_summary,
            incident.lessons_learned,
            incident.review_state,
            incident.reviewed_by_id,
            reviewer.username AS reviewer_username,
            reviewer.first_name AS reviewer_first_name,
            reviewer.last_name AS reviewer_last_name,
            incident.reviewed_at::text AS reviewed_at,
            incident.review_notes,
            incident.approved_by_id,
            approver.username AS approver_username,
            approver.first_name AS approver_first_name,
            approver.last_name AS approver_last_name,
            incident.approved_at::text AS approved_at,
            incident.approval_notes,
            incident.report_package_version,
            incident.created_at::text AS created_at,
            incident.updated_at::text AS updated_at
        FROM incidents_incident incident
        LEFT JOIN accounts_user reporter ON reporter.id = incident.reporter_id AND reporter.tenant_id = incident.tenant_id
        LEFT JOIN accounts_user owner ON owner.id = incident.owner_id AND owner.tenant_id = incident.tenant_id
        LEFT JOIN accounts_user reviewer ON reviewer.id = incident.reviewed_by_id AND reviewer.tenant_id = incident.tenant_id
        LEFT JOIN accounts_user approver ON approver.id = incident.approved_by_id AND approver.tenant_id = incident.tenant_id
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
            incident.nis2_significance_status,
            incident.nis2_significance_criteria,
            incident.nis2_significance_justification,
            incident.nis2_significance_reference,
            CAST(incident.nis2_significance_assessed_at AS TEXT) AS nis2_significance_assessed_at,
            CAST(incident.early_warning_due_at AS TEXT) AS early_warning_due_at,
            CAST(incident.early_warning_sent_at AS TEXT) AS early_warning_sent_at,
            CAST(incident.notification_due_at AS TEXT) AS notification_due_at,
            CAST(incident.notification_sent_at AS TEXT) AS notification_sent_at,
            CAST(incident.final_report_due_at AS TEXT) AS final_report_due_at,
            CAST(incident.final_report_sent_at AS TEXT) AS final_report_sent_at,
            incident.authority_reference,
            incident.stakeholder_summary,
            incident.lessons_learned,
            incident.review_state,
            incident.reviewed_by_id,
            reviewer.username AS reviewer_username,
            reviewer.first_name AS reviewer_first_name,
            reviewer.last_name AS reviewer_last_name,
            CAST(incident.reviewed_at AS TEXT) AS reviewed_at,
            incident.review_notes,
            incident.approved_by_id,
            approver.username AS approver_username,
            approver.first_name AS approver_first_name,
            approver.last_name AS approver_last_name,
            CAST(incident.approved_at AS TEXT) AS approved_at,
            incident.approval_notes,
            incident.report_package_version,
            CAST(incident.created_at AS TEXT) AS created_at,
            CAST(incident.updated_at AS TEXT) AS updated_at
        FROM incidents_incident incident
        LEFT JOIN accounts_user reporter ON reporter.id = incident.reporter_id AND reporter.tenant_id = incident.tenant_id
        LEFT JOIN accounts_user owner ON owner.id = incident.owner_id AND owner.tenant_id = incident.tenant_id
        LEFT JOIN accounts_user reviewer ON reviewer.id = incident.reviewed_by_id AND reviewer.tenant_id = incident.tenant_id
        LEFT JOIN accounts_user approver ON approver.id = incident.approved_by_id AND approver.tenant_id = incident.tenant_id
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
    let review_state: String = row.try_get("review_state")?;
    let nis2_significance_status: String = row.try_get("nis2_significance_status")?;
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
        nis2_significance_label: nis2_significance_label(&nis2_significance_status).to_string(),
        nis2_significance_status,
        nis2_significance_criteria: row.try_get("nis2_significance_criteria")?,
        nis2_significance_justification: row.try_get("nis2_significance_justification")?,
        nis2_significance_reference: row.try_get("nis2_significance_reference")?,
        nis2_significance_assessed_at: row.try_get("nis2_significance_assessed_at")?,
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
        review_state_label: review_state_label(&review_state).to_string(),
        review_state,
        reviewed_by_id: row.try_get("reviewed_by_id")?,
        reviewed_by_display: user_display(
            row.try_get("reviewer_username")?,
            row.try_get("reviewer_first_name")?,
            row.try_get("reviewer_last_name")?,
        ),
        reviewed_at: row.try_get("reviewed_at")?,
        review_notes: row.try_get("review_notes")?,
        approved_by_id: row.try_get("approved_by_id")?,
        approved_by_display: user_display(
            row.try_get("approver_username")?,
            row.try_get("approver_first_name")?,
            row.try_get("approver_last_name")?,
        ),
        approved_at: row.try_get("approved_at")?,
        approval_notes: row.try_get("approval_notes")?,
        report_package_version: row.try_get("report_package_version")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn summary_from_sqlite_row(row: SqliteRow) -> Result<IncidentSummary, sqlx::Error> {
    let severity: String = row.try_get("severity")?;
    let status: String = row.try_get("status")?;
    let incident_type: String = row.try_get("incident_type")?;
    let review_state: String = row.try_get("review_state")?;
    let nis2_significance_status: String = row.try_get("nis2_significance_status")?;
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
        nis2_significance_label: nis2_significance_label(&nis2_significance_status).to_string(),
        nis2_significance_status,
        nis2_significance_criteria: row.try_get("nis2_significance_criteria")?,
        nis2_significance_justification: row.try_get("nis2_significance_justification")?,
        nis2_significance_reference: row.try_get("nis2_significance_reference")?,
        nis2_significance_assessed_at: row.try_get("nis2_significance_assessed_at")?,
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
        review_state_label: review_state_label(&review_state).to_string(),
        review_state,
        reviewed_by_id: row.try_get("reviewed_by_id")?,
        reviewed_by_display: user_display(
            row.try_get("reviewer_username")?,
            row.try_get("reviewer_first_name")?,
            row.try_get("reviewer_last_name")?,
        ),
        reviewed_at: row.try_get("reviewed_at")?,
        review_notes: row.try_get("review_notes")?,
        approved_by_id: row.try_get("approved_by_id")?,
        approved_by_display: user_display(
            row.try_get("approver_username")?,
            row.try_get("approver_first_name")?,
            row.try_get("approver_last_name")?,
        ),
        approved_at: row.try_get("approved_at")?,
        approval_notes: row.try_get("approval_notes")?,
        report_package_version: row.try_get("report_package_version")?,
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
        is_export_highlight: row.try_get("is_export_highlight")?,
        export_note: row.try_get("export_note")?,
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
        is_export_highlight: row.try_get("is_export_highlight")?,
        export_note: row.try_get("export_note")?,
        created_at: row.try_get("created_at")?,
    })
}

fn runbook_step_from_pg_row(row: PgRow) -> Result<IncidentRunbookStepSummary, sqlx::Error> {
    Ok(IncidentRunbookStepSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        incident_id: row.try_get("incident_id")?,
        step_number: row.try_get("step_number")?,
        title: row.try_get("title")?,
        detail: row.try_get("detail")?,
        is_done: row.try_get("is_done")?,
        done_at: row.try_get("done_at")?,
        done_by_id: row.try_get("done_by_id")?,
        done_by_display: user_display(
            row.try_get("done_by_username")?,
            row.try_get("done_by_first_name")?,
            row.try_get("done_by_last_name")?,
        ),
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn runbook_step_from_sqlite_row(row: SqliteRow) -> Result<IncidentRunbookStepSummary, sqlx::Error> {
    Ok(IncidentRunbookStepSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        incident_id: row.try_get("incident_id")?,
        step_number: row.try_get("step_number")?,
        title: row.try_get("title")?,
        detail: row.try_get("detail")?,
        is_done: row.try_get("is_done")?,
        done_at: row.try_get("done_at")?,
        done_by_id: row.try_get("done_by_id")?,
        done_by_display: user_display(
            row.try_get("done_by_username")?,
            row.try_get("done_by_first_name")?,
            row.try_get("done_by_last_name")?,
        ),
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

#[derive(Debug, Clone)]
struct NormalizedRunbookTemplate {
    slug: String,
    title: String,
    description: String,
    incident_type: String,
    severity: String,
    body: String,
    is_active: bool,
    sort_order: i64,
}

impl NormalizedRunbookTemplate {
    fn from_payload(payload: IncidentRunbookTemplateWriteRequest) -> anyhow::Result<Self> {
        let title = normalize_required_text(payload.title.as_deref(), "Runbook-Titel")?;
        let body = normalize_required_text(payload.body.as_deref(), "Runbook-Inhalt")?;
        let slug = normalize_runbook_slug(payload.slug.as_deref(), &title)?;
        Ok(Self {
            slug,
            title,
            description: normalize_optional_text(payload.description.as_deref()),
            incident_type: normalize_incident_type(payload.incident_type.as_deref()),
            severity: normalize_severity(payload.severity.as_deref()),
            body,
            is_active: payload.is_active.unwrap_or(true),
            sort_order: payload.sort_order.unwrap_or(100).max(0),
        })
    }
}

#[derive(Debug, Clone)]
struct ParsedRunbookStep {
    title: String,
    detail: String,
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
        "RUNBOOK_STEP_UPDATED" => "RUNBOOK_STEP_UPDATED".to_string(),
        "INCIDENT_REVIEW_UPDATED" => "INCIDENT_REVIEW_UPDATED".to_string(),
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

fn normalize_runbook_slug(value: Option<&str>, title: &str) -> anyhow::Result<String> {
    let source = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(title);
    let mut slug = String::new();
    let mut last_was_dash = false;
    for ch in source.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            last_was_dash = false;
        } else if !last_was_dash && !slug.is_empty() {
            slug.push('-');
            last_was_dash = true;
        }
        if slug.len() >= 80 {
            break;
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() {
        bail!("Runbook-Slug darf nicht leer sein");
    }
    Ok(slug)
}

fn runbook_steps_from_template(runbook_template: &str) -> Vec<ParsedRunbookStep> {
    let mut raw_steps = runbook_template
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if raw_steps.len() <= 1 && runbook_template.contains(';') {
        raw_steps = runbook_template
            .split(';')
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect();
    }
    let mut steps = raw_steps
        .into_iter()
        .map(|line| normalize_runbook_step_line(&line))
        .filter(|line| !line.is_empty())
        .map(|line| {
            let (title, detail) = split_runbook_step_title_detail(&line);
            ParsedRunbookStep { title, detail }
        })
        .collect::<Vec<_>>();
    if steps.is_empty() {
        steps.push(ParsedRunbookStep {
            title: "Incident bewerten und naechste Massnahme festlegen".to_string(),
            detail: String::new(),
        });
    }
    steps
}

fn normalize_runbook_step_line(line: &str) -> String {
    let mut value = line.trim();
    value = value.trim_start_matches(|ch: char| ch == '-' || ch == '*' || ch.is_whitespace());
    let mut chars = value.char_indices().peekable();
    let mut cut_at = 0;
    while let Some((idx, ch)) = chars.peek().copied() {
        if ch.is_ascii_digit() {
            cut_at = idx + ch.len_utf8();
            chars.next();
            continue;
        }
        if matches!(ch, '.' | ')' | ':' | '-') {
            cut_at = idx + ch.len_utf8();
            chars.next();
        }
        break;
    }
    if cut_at > 0 {
        value = &value[cut_at..];
    }
    value
        .trim_start_matches(|ch: char| {
            ch == '.' || ch == ')' || ch == ':' || ch == '-' || ch.is_whitespace()
        })
        .trim()
        .to_string()
}

fn split_runbook_step_title_detail(line: &str) -> (String, String) {
    let mut parts = line.splitn(2, ':');
    let title = parts.next().unwrap_or("").trim();
    let detail = parts.next().unwrap_or("").trim();
    if title.is_empty() {
        (limit_chars(line.trim(), 255), String::new())
    } else {
        (limit_chars(title, 255), detail.to_string())
    }
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
            "1. Scope: betroffene Postfaecher, URLs, Absender und Zeitfenster erfassen.\n2. Eindaemmung: URLs blocken, Mails zurueckrufen, kompromittierte Sessions widerrufen.\n3. Identitaet: MFA/Passwort-Reset, Token-Review und privilegierte Konten pruefen.\n4. Erheblichkeit: Betroffenheit, Datenarten und NIS2-Meldepflicht bewerten.\n5. Abschluss: Awareness-, Mail-Gateway- und Detection-Regeln aktualisieren."
        }
        "MALWARE" => {
            "1. Scope: betroffene Hosts, Hashes, Prozesse und C2-Indikatoren sichern.\n2. Eindaemmung: Hosts isolieren, IOC-Blocklisten verteilen und Backups schuetzen.\n3. Analyse: Entry Point, Persistenz, Lateralmovement und Datenabfluss pruefen.\n4. Wiederherstellung: Systeme neu aufsetzen oder bereinigen, Monitoring erhoehen.\n5. Abschluss: Controls, EDR-Regeln und Patch-Status aktualisieren."
        }
        "DATA_BREACH" => {
            "1. Scope: Datenarten, betroffene Personen/Systeme und Zeitraum bestimmen.\n2. Eindaemmung: Zugriff stoppen, Berechtigungen entziehen und Logs sichern.\n3. Bewertung: NIS2-Erheblichkeit, DSGVO-Meldepflicht und Kundenpflichten entscheiden.\n4. Kommunikation: Legal, Datenschutz, Management und Kunden abgestimmt informieren.\n5. Abschluss: Root Cause, Control-Gaps und Nachweise dokumentieren."
        }
        "OUTAGE" => {
            "1. Scope: betroffene Services, SLAs, kritische Prozesse und Nutzerkreis erfassen.\n2. Stabilisierung: Workarounds, Failover und Wiederanlauf priorisieren.\n3. Ursache: Infrastruktur, Changes, Abhaengigkeiten und Kapazitaeten pruefen.\n4. Kommunikation: Status, ETA und Auswirkungen fuer Stakeholder aktualisieren.\n5. Abschluss: Resilienz-, Monitoring- und Recovery-Massnahmen nachziehen."
        }
        "SUPPLIER" => {
            "1. Scope: betroffene Lieferanten, Services, Datenfluesse und Vertraege erfassen.\n2. Eindaemmung: Schnittstellen, Zugriffe und Abhaengigkeiten kontrollieren.\n3. Nachweise: Lieferantenstatement, IOCs, SLA-Auswirkung und Audit-Trails sichern.\n4. Bewertung: NIS2-Erheblichkeit, KRITIS-Auswirkung und Kundenkommunikation festlegen.\n5. Abschluss: Third-Party-Risiko, Vertragscontrols und Exit-Optionen aktualisieren."
        }
        "VULNERABILITY" => {
            "1. Scope: betroffene Produkte, Versionen, Assets und Exposure erfassen.\n2. Priorisierung: CVSS, EPSS, KEV, Exploit-Reife und Business-Kontext bewerten.\n3. Eindaemmung: Workarounds, WAF/EDR-Regeln und Netzwerkbegrenzung setzen.\n4. Behebung: Patch, Upgrade oder Konfigurationsfix mit Evidence verknuepfen.\n5. Abschluss: Risiko, SBOM/Product-Security und Detection-Content aktualisieren."
        }
        _ => {
            "1. Scope: betroffene Systeme, Prozesse, Personen und Zeitraum erfassen.\n2. Eindaemmung: unmittelbare Schutzmassnahmen und Verantwortliche festlegen.\n3. Bewertung: Schweregrad, NIS2-Erheblichkeit, Datenbezug und Business Impact pruefen.\n4. Kommunikation: Owner, Management, Legal und externe Stellen abstimmen.\n5. Abschluss: Root Cause, Evidence, Lessons Learned und Massnahmen dokumentieren."
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

fn normalize_nis2_significance_status(value: Option<&str>, legacy_reportable: bool) -> String {
    let normalized = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_uppercase());
    match normalized.as_deref() {
        Some("NOT_SIGNIFICANT") => "NOT_SIGNIFICANT".to_string(),
        Some("LIKELY_SIGNIFICANT") => "LIKELY_SIGNIFICANT".to_string(),
        Some("SIGNIFICANT") => "SIGNIFICANT".to_string(),
        Some("NOT_ASSESSED") => "NOT_ASSESSED".to_string(),
        _ if legacy_reportable => "SIGNIFICANT".to_string(),
        _ => "NOT_ASSESSED".to_string(),
    }
}

fn normalize_nis2_significance_status_for_update(
    value: Option<&str>,
    legacy_reportable: Option<bool>,
    current: &str,
) -> String {
    let normalized = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_uppercase());
    match normalized.as_deref() {
        Some("NOT_SIGNIFICANT") => "NOT_SIGNIFICANT".to_string(),
        Some("LIKELY_SIGNIFICANT") => "LIKELY_SIGNIFICANT".to_string(),
        Some("SIGNIFICANT") => "SIGNIFICANT".to_string(),
        Some("NOT_ASSESSED") => "NOT_ASSESSED".to_string(),
        _ => match legacy_reportable {
            Some(true) => "SIGNIFICANT".to_string(),
            Some(false) if current == "SIGNIFICANT" => "NOT_SIGNIFICANT".to_string(),
            Some(false) => current.to_string(),
            None => current.to_string(),
        },
    }
}

fn normalize_nis2_significance_text(value: Option<&str>) -> String {
    limit_chars(&normalize_optional_text(value), 4000)
}

fn normalize_nis2_significance_reference(value: Option<&str>, status: &str) -> String {
    let value = normalize_optional_text(value);
    if !value.is_empty() {
        return limit_chars(&value, 1000);
    }
    if status == "NOT_ASSESSED" {
        String::new()
    } else {
        "NIS2 Article 23; Commission Implementing Regulation (EU) 2024/2690 Article 3 as best-practice".to_string()
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

fn review_state_label(value: &str) -> &'static str {
    match value {
        "DRAFT" => "Entwurf",
        "IN_REVIEW" => "In Review",
        "REVIEWED" => "Geprueft",
        "APPROVED" => "Freigegeben",
        "CHANGES_REQUESTED" => "Aenderungen angefordert",
        _ => "Entwurf",
    }
}

fn event_type_label(value: &str) -> &'static str {
    match value {
        "CREATED" => "Angelegt",
        "STATUS_CHANGED" => "Statuswechsel",
        "EVIDENCE_UPLOADED" => "Evidence",
        "RUNBOOK_STEP_UPDATED" => "Runbook",
        "INCIDENT_REVIEW_UPDATED" => "Review",
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

fn nis2_significance_label(value: &str) -> &'static str {
    match value {
        "NOT_SIGNIFICANT" => "Nicht erheblich",
        "LIKELY_SIGNIFICANT" => "Wahrscheinlich erheblich",
        "SIGNIFICANT" => "Erheblich / NIS2 meldepflichtig",
        _ => "Nicht bewertet",
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
