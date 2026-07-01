use anyhow::{bail, Context};
use chrono::{NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Postgres, Row, Sqlite, Transaction,
};

use crate::cve_store::normalize_database_url;

#[derive(Clone)]
pub enum AiGovernanceStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Serialize)]
pub struct AiGovernanceOverview {
    pub tenant_id: i64,
    pub summary: AiGovernanceSummary,
    pub systems: Vec<AiGovernanceSystemSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiGovernanceSummary {
    pub total_systems: i64,
    pub high_risk_systems: i64,
    pub not_assessed_systems: i64,
    pub review_due_systems: i64,
    pub evidence_missing: i64,
    pub open_governance_gaps: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiGovernanceSystemSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub product_id: Option<i64>,
    pub product_name: Option<String>,
    pub owner_id: Option<i64>,
    pub owner_display: Option<String>,
    pub name: String,
    pub purpose: String,
    pub model_provider: String,
    pub model_name: String,
    pub model_version: String,
    pub deployment_context: String,
    pub data_categories: String,
    pub decision_impact: String,
    pub human_oversight: String,
    pub ai_act_classification: String,
    pub ai_act_classification_label: String,
    pub criticality: String,
    pub criticality_label: String,
    pub status: String,
    pub status_label: String,
    pub logging_required: bool,
    pub transparency_required: bool,
    pub cybersecurity_required: bool,
    pub monitoring_plan: String,
    pub evidence_key: String,
    pub risk_summary: String,
    pub next_review_due_at: Option<String>,
    pub notes: String,
    pub evidence_count: i64,
    pub approved_evidence_count: i64,
    pub open_requirement_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiGovernanceSystemDetail {
    pub system: AiGovernanceSystemSummary,
    pub requirements: Vec<AiGovernanceRequirementSummary>,
    pub risks: Vec<AiGovernanceRiskLink>,
    pub roadmap_tasks: Vec<AiGovernanceRoadmapTaskLink>,
    pub incidents: Vec<AiGovernanceIncidentLink>,
    pub changes: Vec<AiGovernanceChangeLink>,
    pub link_audit: Vec<AiGovernanceLinkAuditEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiGovernanceRiskLink {
    pub id: i64,
    pub title: String,
    pub status: String,
    pub owner_display: Option<String>,
    pub score: i64,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiGovernanceRoadmapTaskLink {
    pub id: i64,
    pub title: String,
    pub status: String,
    pub status_label: String,
    pub due_date: Option<String>,
    pub phase_name: String,
    pub plan_title: String,
    pub origin_key: String,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiGovernanceIncidentLink {
    pub id: i64,
    pub title: String,
    pub status: String,
    pub severity: String,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiGovernanceChangeLink {
    pub id: i64,
    pub title: String,
    pub status: String,
    pub change_type: String,
    pub planned_at: Option<String>,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiGovernanceLinkAuditEntry {
    pub id: i64,
    pub entity_type: String,
    pub entity_id: i64,
    pub action: String,
    pub actor_id: i64,
    pub detail: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiGovernanceLinkCandidates {
    pub risks: Vec<AiGovernanceRiskLink>,
    pub roadmap_tasks: Vec<AiGovernanceRoadmapTaskLink>,
    pub incidents: Vec<AiGovernanceIncidentLink>,
    pub changes: Vec<AiGovernanceChangeLink>,
    pub roadmap_phases: Vec<AiGovernanceRoadmapPhaseCandidate>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiGovernanceRoadmapPhaseCandidate {
    pub id: i64,
    pub name: String,
    pub plan_title: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiGovernanceLinkKind {
    Risk,
    RoadmapTask,
    Incident,
    Change,
}

impl AiGovernanceLinkKind {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "risk" | "risks" => Some(Self::Risk),
            "roadmap-task" | "roadmap-tasks" | "task" | "tasks" => Some(Self::RoadmapTask),
            "incident" | "incidents" => Some(Self::Incident),
            "change" | "changes" => Some(Self::Change),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Risk => "risk",
            Self::RoadmapTask => "roadmap_task",
            Self::Incident => "incident",
            Self::Change => "change",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AiGovernanceLinkMutation {
    Created,
    Removed,
    AlreadyExists,
    NotFound,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiGovernanceGapTaskResult {
    pub created: bool,
    pub requirement_key: String,
    pub task: AiGovernanceRoadmapTaskLink,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiGovernanceRequirementSummary {
    pub key: String,
    pub label: String,
    pub status: String,
    pub status_label: String,
    pub detail: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AiGovernanceSystemCreateRequest {
    pub product_id: Option<i64>,
    pub owner_id: Option<i64>,
    pub name: String,
    #[serde(default)]
    pub purpose: String,
    #[serde(default)]
    pub model_provider: String,
    #[serde(default)]
    pub model_name: String,
    #[serde(default)]
    pub model_version: String,
    #[serde(default)]
    pub deployment_context: String,
    #[serde(default)]
    pub data_categories: String,
    #[serde(default)]
    pub decision_impact: String,
    #[serde(default)]
    pub human_oversight: String,
    pub ai_act_classification: Option<String>,
    pub criticality: Option<String>,
    pub status: Option<String>,
    pub logging_required: Option<bool>,
    pub transparency_required: Option<bool>,
    pub cybersecurity_required: Option<bool>,
    #[serde(default)]
    pub monitoring_plan: String,
    pub evidence_key: Option<String>,
    #[serde(default)]
    pub risk_summary: String,
    pub next_review_due_at: Option<String>,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AiGovernanceSystemUpdateRequest {
    pub product_id: Option<i64>,
    pub owner_id: Option<i64>,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub model_provider: Option<String>,
    pub model_name: Option<String>,
    pub model_version: Option<String>,
    pub deployment_context: Option<String>,
    pub data_categories: Option<String>,
    pub decision_impact: Option<String>,
    pub human_oversight: Option<String>,
    pub ai_act_classification: Option<String>,
    pub criticality: Option<String>,
    pub status: Option<String>,
    pub logging_required: Option<bool>,
    pub transparency_required: Option<bool>,
    pub cybersecurity_required: Option<bool>,
    pub monitoring_plan: Option<String>,
    pub evidence_key: Option<String>,
    pub risk_summary: Option<String>,
    pub next_review_due_at: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiGovernanceSystemWriteResult {
    pub system: AiGovernanceSystemSummary,
    pub requirements: Vec<AiGovernanceRequirementSummary>,
}

impl AiGovernanceStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer AI-Governance-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer AI-Governance-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-AI-Governance-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn overview(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<AiGovernanceOverview> {
        let systems = match self {
            Self::Postgres(pool) => list_systems_postgres(pool, tenant_id, limit).await?,
            Self::Sqlite(pool) => list_systems_sqlite(pool, tenant_id, limit).await?,
        };
        let summary = ai_governance_summary(&systems);
        Ok(AiGovernanceOverview {
            tenant_id,
            summary,
            systems,
        })
    }

    pub async fn detail(
        &self,
        tenant_id: i64,
        system_id: i64,
    ) -> anyhow::Result<Option<AiGovernanceSystemDetail>> {
        let system = match self {
            Self::Postgres(pool) => system_detail_postgres(pool, tenant_id, system_id).await?,
            Self::Sqlite(pool) => system_detail_sqlite(pool, tenant_id, system_id).await?,
        };
        let Some(system) = system else {
            return Ok(None);
        };
        let (risks, roadmap_tasks, incidents, changes, link_audit) = match self {
            Self::Postgres(pool) => (
                linked_risks_postgres(pool, tenant_id, system_id).await?,
                linked_roadmap_tasks_postgres(pool, tenant_id, system_id).await?,
                linked_incidents_postgres(pool, tenant_id, system_id).await?,
                linked_changes_postgres(pool, tenant_id, system_id).await?,
                link_audit_postgres(pool, tenant_id, system_id).await?,
            ),
            Self::Sqlite(pool) => (
                linked_risks_sqlite(pool, tenant_id, system_id).await?,
                linked_roadmap_tasks_sqlite(pool, tenant_id, system_id).await?,
                linked_incidents_sqlite(pool, tenant_id, system_id).await?,
                linked_changes_sqlite(pool, tenant_id, system_id).await?,
                link_audit_sqlite(pool, tenant_id, system_id).await?,
            ),
        };
        Ok(Some(AiGovernanceSystemDetail {
            requirements: ai_governance_requirements(&system),
            system,
            risks,
            roadmap_tasks,
            incidents,
            changes,
            link_audit,
        }))
    }

    pub async fn create_system(
        &self,
        tenant_id: i64,
        payload: AiGovernanceSystemCreateRequest,
    ) -> anyhow::Result<AiGovernanceSystemWriteResult> {
        let name = clean_required(&payload.name, "AI-System-Name")?;
        let ai_act_classification = normalize_ai_act_classification(
            payload
                .ai_act_classification
                .as_deref()
                .unwrap_or("NOT_ASSESSED"),
        );
        let criticality = normalize_criticality(payload.criticality.as_deref().unwrap_or("MEDIUM"));
        let status = normalize_status(payload.status.as_deref().unwrap_or("IN_REVIEW"));
        let evidence_key = payload
            .evidence_key
            .as_deref()
            .map(clean_text)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| format!("AI-GOV:SYSTEM:{}", slug_key(&name)));
        match self {
            Self::Postgres(pool) => {
                validate_system_relations_postgres(
                    pool,
                    tenant_id,
                    payload.product_id,
                    payload.owner_id,
                )
                .await?;
            }
            Self::Sqlite(pool) => {
                validate_system_relations_sqlite(
                    pool,
                    tenant_id,
                    payload.product_id,
                    payload.owner_id,
                )
                .await?;
            }
        }
        let system_id = match self {
            Self::Postgres(pool) => {
                create_system_postgres(
                    pool,
                    tenant_id,
                    &payload,
                    &name,
                    &ai_act_classification,
                    &criticality,
                    &status,
                    &evidence_key,
                )
                .await?
            }
            Self::Sqlite(pool) => {
                create_system_sqlite(
                    pool,
                    tenant_id,
                    &payload,
                    &name,
                    &ai_act_classification,
                    &criticality,
                    &status,
                    &evidence_key,
                )
                .await?
            }
        };
        self.detail(tenant_id, system_id)
            .await?
            .map(|detail| AiGovernanceSystemWriteResult {
                system: detail.system,
                requirements: detail.requirements,
            })
            .context("Angelegtes AI-Governance-System konnte nicht gelesen werden")
    }

    pub async fn update_system(
        &self,
        tenant_id: i64,
        system_id: i64,
        payload: AiGovernanceSystemUpdateRequest,
    ) -> anyhow::Result<Option<AiGovernanceSystemWriteResult>> {
        let Some(existing) = self
            .detail(tenant_id, system_id)
            .await?
            .map(|detail| detail.system)
        else {
            return Ok(None);
        };
        let next = merged_update(existing, payload)?;
        match self {
            Self::Postgres(pool) => {
                validate_system_relations_postgres(pool, tenant_id, next.product_id, next.owner_id)
                    .await?;
                update_system_postgres(pool, &next).await?;
            }
            Self::Sqlite(pool) => {
                validate_system_relations_sqlite(pool, tenant_id, next.product_id, next.owner_id)
                    .await?;
                update_system_sqlite(pool, &next).await?;
            }
        };
        Ok(self
            .detail(tenant_id, system_id)
            .await?
            .map(|detail| AiGovernanceSystemWriteResult {
                system: detail.system,
                requirements: detail.requirements,
            }))
    }

    pub async fn link_candidates(
        &self,
        tenant_id: i64,
        system_id: i64,
    ) -> anyhow::Result<Option<AiGovernanceLinkCandidates>> {
        if self.detail(tenant_id, system_id).await?.is_none() {
            return Ok(None);
        }
        let candidates = match self {
            Self::Postgres(pool) => AiGovernanceLinkCandidates {
                risks: candidate_risks_postgres(pool, tenant_id, system_id).await?,
                roadmap_tasks: candidate_roadmap_tasks_postgres(pool, tenant_id, system_id).await?,
                incidents: candidate_incidents_postgres(pool, tenant_id, system_id).await?,
                changes: candidate_changes_postgres(pool, tenant_id, system_id).await?,
                roadmap_phases: roadmap_phases_postgres(pool, tenant_id).await?,
            },
            Self::Sqlite(pool) => AiGovernanceLinkCandidates {
                risks: candidate_risks_sqlite(pool, tenant_id, system_id).await?,
                roadmap_tasks: candidate_roadmap_tasks_sqlite(pool, tenant_id, system_id).await?,
                incidents: candidate_incidents_sqlite(pool, tenant_id, system_id).await?,
                changes: candidate_changes_sqlite(pool, tenant_id, system_id).await?,
                roadmap_phases: roadmap_phases_sqlite(pool, tenant_id).await?,
            },
        };
        Ok(Some(candidates))
    }

    pub async fn add_link(
        &self,
        tenant_id: i64,
        system_id: i64,
        kind: AiGovernanceLinkKind,
        entity_id: i64,
        actor_id: i64,
    ) -> anyhow::Result<AiGovernanceLinkMutation> {
        match self {
            Self::Postgres(pool) => {
                add_link_postgres(pool, tenant_id, system_id, kind, entity_id, actor_id).await
            }
            Self::Sqlite(pool) => {
                add_link_sqlite(pool, tenant_id, system_id, kind, entity_id, actor_id).await
            }
        }
    }

    pub async fn remove_link(
        &self,
        tenant_id: i64,
        system_id: i64,
        kind: AiGovernanceLinkKind,
        entity_id: i64,
        actor_id: i64,
    ) -> anyhow::Result<AiGovernanceLinkMutation> {
        match self {
            Self::Postgres(pool) => {
                remove_link_postgres(pool, tenant_id, system_id, kind, entity_id, actor_id).await
            }
            Self::Sqlite(pool) => {
                remove_link_sqlite(pool, tenant_id, system_id, kind, entity_id, actor_id).await
            }
        }
    }

    pub async fn create_task_from_gap(
        &self,
        tenant_id: i64,
        system_id: i64,
        requirement_key: &str,
        phase_id: i64,
        actor_id: i64,
    ) -> anyhow::Result<Option<AiGovernanceGapTaskResult>> {
        let Some(detail) = self.detail(tenant_id, system_id).await? else {
            return Ok(None);
        };
        let requirement_key = clean_text(requirement_key);
        let requirement = detail
            .requirements
            .iter()
            .find(|requirement| requirement.key == requirement_key && requirement.status == "GAP")
            .context("Nur offene AI-Governance-Gaps koennen als Roadmap-Task erzeugt werden")?;
        let origin_key = format!("AI-GOV:{tenant_id}:{system_id}:{}", requirement.key);
        let task = match self {
            Self::Postgres(pool) => {
                create_gap_task_postgres(
                    pool,
                    tenant_id,
                    phase_id,
                    &detail.system,
                    requirement,
                    &origin_key,
                )
                .await?
            }
            Self::Sqlite(pool) => {
                create_gap_task_sqlite(
                    pool,
                    tenant_id,
                    phase_id,
                    &detail.system,
                    requirement,
                    &origin_key,
                )
                .await?
            }
        };
        let (task, created) =
            task.context("Roadmap-Phase wurde fuer diesen Tenant nicht gefunden")?;
        let mutation = self
            .add_link(
                tenant_id,
                system_id,
                AiGovernanceLinkKind::RoadmapTask,
                task.id,
                actor_id,
            )
            .await?;
        if created {
            match self {
                Self::Postgres(pool) => {
                    insert_audit_postgres(
                        pool,
                        tenant_id,
                        system_id,
                        AiGovernanceLinkKind::RoadmapTask,
                        task.id,
                        "TASK_CREATED",
                        actor_id,
                        &format!(
                            "Roadmap-Task aus AI-Governance-Gap {} erzeugt.",
                            requirement.key
                        ),
                    )
                    .await?;
                }
                Self::Sqlite(pool) => {
                    insert_audit_sqlite(
                        pool,
                        tenant_id,
                        system_id,
                        AiGovernanceLinkKind::RoadmapTask,
                        task.id,
                        "TASK_CREATED",
                        actor_id,
                        &format!(
                            "Roadmap-Task aus AI-Governance-Gap {} erzeugt.",
                            requirement.key
                        ),
                    )
                    .await?;
                }
            }
        } else if mutation == AiGovernanceLinkMutation::NotFound {
            bail!("Vorhandener Roadmap-Task konnte nicht tenantgebunden verknuepft werden");
        }
        Ok(Some(AiGovernanceGapTaskResult {
            created,
            requirement_key,
            task,
        }))
    }
}

fn link_table(kind: AiGovernanceLinkKind) -> (&'static str, &'static str) {
    match kind {
        AiGovernanceLinkKind::Risk => ("ai_governance_system_risk", "risk_id"),
        AiGovernanceLinkKind::RoadmapTask => {
            ("ai_governance_system_roadmap_task", "roadmap_task_id")
        }
        AiGovernanceLinkKind::Incident => ("ai_governance_system_incident", "incident_id"),
        AiGovernanceLinkKind::Change => ("ai_governance_system_change", "change_id"),
    }
}

async fn validate_system_relations_postgres(
    pool: &PgPool,
    tenant_id: i64,
    product_id: Option<i64>,
    owner_id: Option<i64>,
) -> anyhow::Result<()> {
    if let Some(product_id) = product_id.filter(|id| *id > 0) {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM product_security_product WHERE tenant_id = $1 AND id = $2)",
        )
        .bind(tenant_id)
        .bind(product_id)
        .fetch_one(pool)
        .await?;
        if !exists {
            bail!("AI-Governance-Produkt wurde fuer diesen Tenant nicht gefunden");
        }
    }
    if let Some(owner_id) = owner_id.filter(|id| *id > 0) {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM accounts_user WHERE tenant_id = $1 AND id = $2)",
        )
        .bind(tenant_id)
        .bind(owner_id)
        .fetch_one(pool)
        .await?;
        if !exists {
            bail!("AI-Governance-Owner wurde fuer diesen Tenant nicht gefunden");
        }
    }
    Ok(())
}

async fn validate_system_relations_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    product_id: Option<i64>,
    owner_id: Option<i64>,
) -> anyhow::Result<()> {
    if let Some(product_id) = product_id.filter(|id| *id > 0) {
        let exists: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM product_security_product WHERE tenant_id = ? AND id = ?)",
        )
        .bind(tenant_id)
        .bind(product_id)
        .fetch_one(pool)
        .await?;
        if exists == 0 {
            bail!("AI-Governance-Produkt wurde fuer diesen Tenant nicht gefunden");
        }
    }
    if let Some(owner_id) = owner_id.filter(|id| *id > 0) {
        let exists: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM accounts_user WHERE tenant_id = ? AND id = ?)",
        )
        .bind(tenant_id)
        .bind(owner_id)
        .fetch_one(pool)
        .await?;
        if exists == 0 {
            bail!("AI-Governance-Owner wurde fuer diesen Tenant nicht gefunden");
        }
    }
    Ok(())
}

async fn system_exists_postgres(
    pool: &PgPool,
    tenant_id: i64,
    system_id: i64,
) -> anyhow::Result<bool> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM ai_governance_system WHERE tenant_id = $1 AND id = $2)",
    )
    .bind(tenant_id)
    .bind(system_id)
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}

async fn system_exists_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    system_id: i64,
) -> anyhow::Result<bool> {
    let exists: i64 = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM ai_governance_system WHERE tenant_id = ? AND id = ?)",
    )
    .bind(tenant_id)
    .bind(system_id)
    .fetch_one(pool)
    .await?;
    Ok(exists != 0)
}

async fn entity_exists_postgres(
    pool: &PgPool,
    tenant_id: i64,
    kind: AiGovernanceLinkKind,
    entity_id: i64,
) -> anyhow::Result<bool> {
    let sql = match kind {
        AiGovernanceLinkKind::Risk => {
            "SELECT EXISTS(SELECT 1 FROM risks_risk WHERE tenant_id = $1 AND id = $2)"
        }
        AiGovernanceLinkKind::RoadmapTask => {
            "SELECT EXISTS(SELECT 1 FROM roadmap_roadmaptask task JOIN roadmap_roadmapphase phase ON phase.id = task.phase_id JOIN roadmap_roadmapplan plan ON plan.id = phase.plan_id WHERE plan.tenant_id = $1 AND task.id = $2)"
        }
        AiGovernanceLinkKind::Incident => {
            "SELECT EXISTS(SELECT 1 FROM incidents_incident WHERE tenant_id = $1 AND id = $2)"
        }
        AiGovernanceLinkKind::Change => {
            "SELECT EXISTS(SELECT 1 FROM changes_change WHERE tenant_id = $1 AND id = $2)"
        }
    };
    sqlx::query_scalar(sql)
        .bind(tenant_id)
        .bind(entity_id)
        .fetch_one(pool)
        .await
        .map_err(Into::into)
}

async fn entity_exists_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    kind: AiGovernanceLinkKind,
    entity_id: i64,
) -> anyhow::Result<bool> {
    let sql = match kind {
        AiGovernanceLinkKind::Risk => {
            "SELECT EXISTS(SELECT 1 FROM risks_risk WHERE tenant_id = ? AND id = ?)"
        }
        AiGovernanceLinkKind::RoadmapTask => {
            "SELECT EXISTS(SELECT 1 FROM roadmap_roadmaptask task JOIN roadmap_roadmapphase phase ON phase.id = task.phase_id JOIN roadmap_roadmapplan plan ON plan.id = phase.plan_id WHERE plan.tenant_id = ? AND task.id = ?)"
        }
        AiGovernanceLinkKind::Incident => {
            "SELECT EXISTS(SELECT 1 FROM incidents_incident WHERE tenant_id = ? AND id = ?)"
        }
        AiGovernanceLinkKind::Change => {
            "SELECT EXISTS(SELECT 1 FROM changes_change WHERE tenant_id = ? AND id = ?)"
        }
    };
    let exists: i64 = sqlx::query_scalar(sql)
        .bind(tenant_id)
        .bind(entity_id)
        .fetch_one(pool)
        .await?;
    Ok(exists != 0)
}

async fn add_link_postgres(
    pool: &PgPool,
    tenant_id: i64,
    system_id: i64,
    kind: AiGovernanceLinkKind,
    entity_id: i64,
    actor_id: i64,
) -> anyhow::Result<AiGovernanceLinkMutation> {
    if entity_id <= 0
        || !system_exists_postgres(pool, tenant_id, system_id).await?
        || !entity_exists_postgres(pool, tenant_id, kind, entity_id).await?
    {
        return Ok(AiGovernanceLinkMutation::NotFound);
    }
    let (table, column) = link_table(kind);
    let mut tx = pool.begin().await?;
    let result = sqlx::query(&format!(
        "INSERT INTO {table} (tenant_id, system_id, {column}, created_by_id, created_at) VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP) ON CONFLICT DO NOTHING"
    ))
    .bind(tenant_id)
    .bind(system_id)
    .bind(entity_id)
    .bind(actor_id)
    .execute(&mut *tx)
    .await
    .context("PostgreSQL-AI-Governance-Verknuepfung konnte nicht angelegt werden")?;
    if result.rows_affected() == 0 {
        return Ok(AiGovernanceLinkMutation::AlreadyExists);
    }
    insert_audit_postgres_tx(
        &mut tx,
        tenant_id,
        system_id,
        kind,
        entity_id,
        "LINKED",
        actor_id,
        "Governance-Objekt mit AI-System verknuepft.",
    )
    .await?;
    tx.commit().await?;
    Ok(AiGovernanceLinkMutation::Created)
}

async fn add_link_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    system_id: i64,
    kind: AiGovernanceLinkKind,
    entity_id: i64,
    actor_id: i64,
) -> anyhow::Result<AiGovernanceLinkMutation> {
    if entity_id <= 0
        || !system_exists_sqlite(pool, tenant_id, system_id).await?
        || !entity_exists_sqlite(pool, tenant_id, kind, entity_id).await?
    {
        return Ok(AiGovernanceLinkMutation::NotFound);
    }
    let (table, column) = link_table(kind);
    let mut tx = pool.begin().await?;
    let result = sqlx::query(&format!(
        "INSERT INTO {table} (tenant_id, system_id, {column}, created_by_id, created_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT DO NOTHING"
    ))
    .bind(tenant_id)
    .bind(system_id)
    .bind(entity_id)
    .bind(actor_id)
    .execute(&mut *tx)
    .await
    .context("SQLite-AI-Governance-Verknuepfung konnte nicht angelegt werden")?;
    if result.rows_affected() == 0 {
        return Ok(AiGovernanceLinkMutation::AlreadyExists);
    }
    insert_audit_sqlite_tx(
        &mut tx,
        tenant_id,
        system_id,
        kind,
        entity_id,
        "LINKED",
        actor_id,
        "Governance-Objekt mit AI-System verknuepft.",
    )
    .await?;
    tx.commit().await?;
    Ok(AiGovernanceLinkMutation::Created)
}

async fn remove_link_postgres(
    pool: &PgPool,
    tenant_id: i64,
    system_id: i64,
    kind: AiGovernanceLinkKind,
    entity_id: i64,
    actor_id: i64,
) -> anyhow::Result<AiGovernanceLinkMutation> {
    if !system_exists_postgres(pool, tenant_id, system_id).await? {
        return Ok(AiGovernanceLinkMutation::NotFound);
    }
    let (table, column) = link_table(kind);
    let mut tx = pool.begin().await?;
    let result = sqlx::query(&format!(
        "DELETE FROM {table} WHERE tenant_id = $1 AND system_id = $2 AND {column} = $3"
    ))
    .bind(tenant_id)
    .bind(system_id)
    .bind(entity_id)
    .execute(&mut *tx)
    .await?;
    if result.rows_affected() == 0 {
        return Ok(AiGovernanceLinkMutation::NotFound);
    }
    insert_audit_postgres_tx(
        &mut tx,
        tenant_id,
        system_id,
        kind,
        entity_id,
        "UNLINKED",
        actor_id,
        "Governance-Objekt vom AI-System entfernt.",
    )
    .await?;
    tx.commit().await?;
    Ok(AiGovernanceLinkMutation::Removed)
}

async fn remove_link_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    system_id: i64,
    kind: AiGovernanceLinkKind,
    entity_id: i64,
    actor_id: i64,
) -> anyhow::Result<AiGovernanceLinkMutation> {
    if !system_exists_sqlite(pool, tenant_id, system_id).await? {
        return Ok(AiGovernanceLinkMutation::NotFound);
    }
    let (table, column) = link_table(kind);
    let mut tx = pool.begin().await?;
    let result = sqlx::query(&format!(
        "DELETE FROM {table} WHERE tenant_id = ? AND system_id = ? AND {column} = ?"
    ))
    .bind(tenant_id)
    .bind(system_id)
    .bind(entity_id)
    .execute(&mut *tx)
    .await?;
    if result.rows_affected() == 0 {
        return Ok(AiGovernanceLinkMutation::NotFound);
    }
    insert_audit_sqlite_tx(
        &mut tx,
        tenant_id,
        system_id,
        kind,
        entity_id,
        "UNLINKED",
        actor_id,
        "Governance-Objekt vom AI-System entfernt.",
    )
    .await?;
    tx.commit().await?;
    Ok(AiGovernanceLinkMutation::Removed)
}

#[allow(clippy::too_many_arguments)]
async fn insert_audit_postgres_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    system_id: i64,
    kind: AiGovernanceLinkKind,
    entity_id: i64,
    action: &str,
    actor_id: i64,
    detail: &str,
) -> anyhow::Result<()> {
    let result = sqlx::query(
        r#"
        INSERT INTO ai_governance_link_audit (
            tenant_id, system_id, entity_type, entity_id, action, actor_id, detail, created_at
        )
        SELECT $1, system.id, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP
        FROM ai_governance_system system
        WHERE system.tenant_id = $1 AND system.id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(system_id)
    .bind(kind.as_str())
    .bind(entity_id)
    .bind(action)
    .bind(actor_id)
    .bind(detail)
    .execute(&mut **tx)
    .await?;
    if result.rows_affected() != 1 {
        bail!("AI-Governance-Audit konnte nicht tenantgebunden angelegt werden");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn insert_audit_sqlite_tx(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    system_id: i64,
    kind: AiGovernanceLinkKind,
    entity_id: i64,
    action: &str,
    actor_id: i64,
    detail: &str,
) -> anyhow::Result<()> {
    let result = sqlx::query(
        r#"
        INSERT INTO ai_governance_link_audit (
            tenant_id, system_id, entity_type, entity_id, action, actor_id, detail, created_at
        )
        SELECT ?, system.id, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP
        FROM ai_governance_system system
        WHERE system.tenant_id = ? AND system.id = ?
        "#,
    )
    .bind(tenant_id)
    .bind(kind.as_str())
    .bind(entity_id)
    .bind(action)
    .bind(actor_id)
    .bind(detail)
    .bind(tenant_id)
    .bind(system_id)
    .execute(&mut **tx)
    .await?;
    if result.rows_affected() != 1 {
        bail!("AI-Governance-Audit konnte nicht tenantgebunden angelegt werden");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn insert_audit_postgres(
    pool: &PgPool,
    tenant_id: i64,
    system_id: i64,
    kind: AiGovernanceLinkKind,
    entity_id: i64,
    action: &str,
    actor_id: i64,
    detail: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO ai_governance_link_audit (
            tenant_id, system_id, entity_type, entity_id, action, actor_id, detail, created_at
        )
        SELECT $1, system.id, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP
        FROM ai_governance_system system
        WHERE system.tenant_id = $1 AND system.id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(system_id)
    .bind(kind.as_str())
    .bind(entity_id)
    .bind(action)
    .bind(actor_id)
    .bind(detail)
    .execute(pool)
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn insert_audit_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    system_id: i64,
    kind: AiGovernanceLinkKind,
    entity_id: i64,
    action: &str,
    actor_id: i64,
    detail: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO ai_governance_link_audit (
            tenant_id, system_id, entity_type, entity_id, action, actor_id, detail, created_at
        )
        SELECT ?, system.id, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP
        FROM ai_governance_system system
        WHERE system.tenant_id = ? AND system.id = ?
        "#,
    )
    .bind(tenant_id)
    .bind(kind.as_str())
    .bind(entity_id)
    .bind(action)
    .bind(actor_id)
    .bind(detail)
    .bind(tenant_id)
    .bind(system_id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn linked_risks_postgres(
    pool: &PgPool,
    tenant_id: i64,
    system_id: i64,
) -> anyhow::Result<Vec<AiGovernanceRiskLink>> {
    risk_links_postgres(pool, tenant_id, system_id, true).await
}

async fn candidate_risks_postgres(
    pool: &PgPool,
    tenant_id: i64,
    system_id: i64,
) -> anyhow::Result<Vec<AiGovernanceRiskLink>> {
    risk_links_postgres(pool, tenant_id, system_id, false).await
}

async fn risk_links_postgres(
    pool: &PgPool,
    tenant_id: i64,
    system_id: i64,
    linked: bool,
) -> anyhow::Result<Vec<AiGovernanceRiskLink>> {
    let relation = if linked {
        "JOIN ai_governance_system_risk link ON link.risk_id = risk.id AND link.tenant_id = risk.tenant_id AND link.system_id = $2"
    } else {
        "LEFT JOIN ai_governance_system_risk link ON link.risk_id = risk.id AND link.tenant_id = risk.tenant_id AND link.system_id = $2"
    };
    let predicate = if linked {
        "link.id IS NOT NULL"
    } else {
        "link.id IS NULL"
    };
    let rows = sqlx::query(&format!(
        r#"SELECT risk.id, risk.title, risk.status,
        COALESCE(NULLIF(BTRIM(CONCAT(COALESCE(owner.first_name, ''), ' ', COALESCE(owner.last_name, ''))), ''), owner.username) AS owner_display,
        (risk.impact * risk.likelihood)::bigint AS score, link.created_at::text AS link_created_at
        FROM risks_risk risk {relation}
        LEFT JOIN accounts_user owner ON owner.id = risk.owner_id AND owner.tenant_id = risk.tenant_id
        WHERE risk.tenant_id = $1 AND {predicate}
        ORDER BY score DESC, risk.id DESC LIMIT 200"#
    ))
    .bind(tenant_id)
    .bind(system_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(risk_link_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn linked_risks_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    system_id: i64,
) -> anyhow::Result<Vec<AiGovernanceRiskLink>> {
    risk_links_sqlite(pool, tenant_id, system_id, true).await
}

async fn candidate_risks_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    system_id: i64,
) -> anyhow::Result<Vec<AiGovernanceRiskLink>> {
    risk_links_sqlite(pool, tenant_id, system_id, false).await
}

async fn risk_links_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    system_id: i64,
    linked: bool,
) -> anyhow::Result<Vec<AiGovernanceRiskLink>> {
    let relation = if linked {
        "JOIN ai_governance_system_risk link ON link.risk_id = risk.id AND link.tenant_id = risk.tenant_id AND link.system_id = ?"
    } else {
        "LEFT JOIN ai_governance_system_risk link ON link.risk_id = risk.id AND link.tenant_id = risk.tenant_id AND link.system_id = ?"
    };
    let predicate = if linked {
        "link.id IS NOT NULL"
    } else {
        "link.id IS NULL"
    };
    let rows = sqlx::query(&format!(
        r#"SELECT risk.id, risk.title, risk.status,
        COALESCE(NULLIF(TRIM(COALESCE(owner.first_name, '') || ' ' || COALESCE(owner.last_name, '')), ''), owner.username) AS owner_display,
        risk.impact * risk.likelihood AS score, CAST(link.created_at AS TEXT) AS link_created_at
        FROM risks_risk risk {relation}
        LEFT JOIN accounts_user owner ON owner.id = risk.owner_id AND owner.tenant_id = risk.tenant_id
        WHERE risk.tenant_id = ? AND {predicate}
        ORDER BY score DESC, risk.id DESC LIMIT 200"#
    ))
    .bind(system_id)
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(risk_link_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn risk_link_from_pg_row(row: PgRow) -> Result<AiGovernanceRiskLink, sqlx::Error> {
    Ok(AiGovernanceRiskLink {
        id: row.try_get("id")?,
        title: row.try_get("title")?,
        status: row.try_get("status")?,
        owner_display: row.try_get("owner_display")?,
        score: row.try_get("score")?,
        created_at: row.try_get("link_created_at")?,
    })
}

fn risk_link_from_sqlite_row(row: SqliteRow) -> Result<AiGovernanceRiskLink, sqlx::Error> {
    Ok(AiGovernanceRiskLink {
        id: row.try_get("id")?,
        title: row.try_get("title")?,
        status: row.try_get("status")?,
        owner_display: row.try_get("owner_display")?,
        score: row.try_get("score")?,
        created_at: row.try_get("link_created_at")?,
    })
}

async fn linked_roadmap_tasks_postgres(
    pool: &PgPool,
    tenant_id: i64,
    system_id: i64,
) -> anyhow::Result<Vec<AiGovernanceRoadmapTaskLink>> {
    roadmap_task_links_postgres(pool, tenant_id, system_id, true).await
}

async fn candidate_roadmap_tasks_postgres(
    pool: &PgPool,
    tenant_id: i64,
    system_id: i64,
) -> anyhow::Result<Vec<AiGovernanceRoadmapTaskLink>> {
    roadmap_task_links_postgres(pool, tenant_id, system_id, false).await
}

async fn roadmap_task_links_postgres(
    pool: &PgPool,
    tenant_id: i64,
    system_id: i64,
    linked: bool,
) -> anyhow::Result<Vec<AiGovernanceRoadmapTaskLink>> {
    let relation = if linked {
        "JOIN ai_governance_system_roadmap_task link ON link.roadmap_task_id = task.id AND link.tenant_id = plan.tenant_id AND link.system_id = $2"
    } else {
        "LEFT JOIN ai_governance_system_roadmap_task link ON link.roadmap_task_id = task.id AND link.tenant_id = plan.tenant_id AND link.system_id = $2"
    };
    let predicate = if linked {
        "link.id IS NOT NULL"
    } else {
        "link.id IS NULL"
    };
    let rows = sqlx::query(&format!(
        r#"SELECT task.id, task.title, task.status, task.due_date::text AS due_date,
        phase.name AS phase_name, plan.title AS plan_title, task.origin_key,
        link.created_at::text AS link_created_at
        FROM roadmap_roadmaptask task
        JOIN roadmap_roadmapphase phase ON phase.id = task.phase_id
        JOIN roadmap_roadmapplan plan ON plan.id = phase.plan_id
        {relation}
        WHERE plan.tenant_id = $1 AND {predicate}
        ORDER BY task.due_date ASC, task.id DESC LIMIT 200"#
    ))
    .bind(tenant_id)
    .bind(system_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(roadmap_task_link_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn linked_roadmap_tasks_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    system_id: i64,
) -> anyhow::Result<Vec<AiGovernanceRoadmapTaskLink>> {
    roadmap_task_links_sqlite(pool, tenant_id, system_id, true).await
}

async fn candidate_roadmap_tasks_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    system_id: i64,
) -> anyhow::Result<Vec<AiGovernanceRoadmapTaskLink>> {
    roadmap_task_links_sqlite(pool, tenant_id, system_id, false).await
}

async fn roadmap_task_links_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    system_id: i64,
    linked: bool,
) -> anyhow::Result<Vec<AiGovernanceRoadmapTaskLink>> {
    let relation = if linked {
        "JOIN ai_governance_system_roadmap_task link ON link.roadmap_task_id = task.id AND link.tenant_id = plan.tenant_id AND link.system_id = ?"
    } else {
        "LEFT JOIN ai_governance_system_roadmap_task link ON link.roadmap_task_id = task.id AND link.tenant_id = plan.tenant_id AND link.system_id = ?"
    };
    let predicate = if linked {
        "link.id IS NOT NULL"
    } else {
        "link.id IS NULL"
    };
    let rows = sqlx::query(&format!(
        r#"SELECT task.id, task.title, task.status, CAST(task.due_date AS TEXT) AS due_date,
        phase.name AS phase_name, plan.title AS plan_title, task.origin_key,
        CAST(link.created_at AS TEXT) AS link_created_at
        FROM roadmap_roadmaptask task
        JOIN roadmap_roadmapphase phase ON phase.id = task.phase_id
        JOIN roadmap_roadmapplan plan ON plan.id = phase.plan_id
        {relation}
        WHERE plan.tenant_id = ? AND {predicate}
        ORDER BY task.due_date ASC, task.id DESC LIMIT 200"#
    ))
    .bind(system_id)
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(roadmap_task_link_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn roadmap_task_link_from_pg_row(row: PgRow) -> Result<AiGovernanceRoadmapTaskLink, sqlx::Error> {
    let status: String = row.try_get("status")?;
    Ok(AiGovernanceRoadmapTaskLink {
        id: row.try_get("id")?,
        title: row.try_get("title")?,
        status_label: roadmap_status_label(&status).to_string(),
        status,
        due_date: row.try_get("due_date")?,
        phase_name: row.try_get("phase_name")?,
        plan_title: row.try_get("plan_title")?,
        origin_key: row.try_get("origin_key")?,
        created_at: row.try_get("link_created_at")?,
    })
}

fn roadmap_task_link_from_sqlite_row(
    row: SqliteRow,
) -> Result<AiGovernanceRoadmapTaskLink, sqlx::Error> {
    let status: String = row.try_get("status")?;
    Ok(AiGovernanceRoadmapTaskLink {
        id: row.try_get("id")?,
        title: row.try_get("title")?,
        status_label: roadmap_status_label(&status).to_string(),
        status,
        due_date: row.try_get("due_date")?,
        phase_name: row.try_get("phase_name")?,
        plan_title: row.try_get("plan_title")?,
        origin_key: row.try_get("origin_key")?,
        created_at: row.try_get("link_created_at")?,
    })
}

async fn linked_incidents_postgres(
    pool: &PgPool,
    tenant_id: i64,
    system_id: i64,
) -> anyhow::Result<Vec<AiGovernanceIncidentLink>> {
    incident_links_postgres(pool, tenant_id, system_id, true).await
}

async fn candidate_incidents_postgres(
    pool: &PgPool,
    tenant_id: i64,
    system_id: i64,
) -> anyhow::Result<Vec<AiGovernanceIncidentLink>> {
    incident_links_postgres(pool, tenant_id, system_id, false).await
}

async fn incident_links_postgres(
    pool: &PgPool,
    tenant_id: i64,
    system_id: i64,
    linked: bool,
) -> anyhow::Result<Vec<AiGovernanceIncidentLink>> {
    let relation = if linked {
        "JOIN ai_governance_system_incident link ON link.incident_id = incident.id AND link.tenant_id = incident.tenant_id AND link.system_id = $2"
    } else {
        "LEFT JOIN ai_governance_system_incident link ON link.incident_id = incident.id AND link.tenant_id = incident.tenant_id AND link.system_id = $2"
    };
    let predicate = if linked {
        "link.id IS NOT NULL"
    } else {
        "link.id IS NULL"
    };
    let rows = sqlx::query(&format!(
        "SELECT incident.id, incident.title, incident.status, incident.severity, link.created_at::text AS link_created_at FROM incidents_incident incident {relation} WHERE incident.tenant_id = $1 AND {predicate} ORDER BY incident.updated_at DESC, incident.id DESC LIMIT 200"
    ))
    .bind(tenant_id).bind(system_id).fetch_all(pool).await?;
    rows.into_iter()
        .map(incident_link_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn linked_incidents_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    system_id: i64,
) -> anyhow::Result<Vec<AiGovernanceIncidentLink>> {
    incident_links_sqlite(pool, tenant_id, system_id, true).await
}

async fn candidate_incidents_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    system_id: i64,
) -> anyhow::Result<Vec<AiGovernanceIncidentLink>> {
    incident_links_sqlite(pool, tenant_id, system_id, false).await
}

async fn incident_links_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    system_id: i64,
    linked: bool,
) -> anyhow::Result<Vec<AiGovernanceIncidentLink>> {
    let relation = if linked {
        "JOIN ai_governance_system_incident link ON link.incident_id = incident.id AND link.tenant_id = incident.tenant_id AND link.system_id = ?"
    } else {
        "LEFT JOIN ai_governance_system_incident link ON link.incident_id = incident.id AND link.tenant_id = incident.tenant_id AND link.system_id = ?"
    };
    let predicate = if linked {
        "link.id IS NOT NULL"
    } else {
        "link.id IS NULL"
    };
    let rows = sqlx::query(&format!(
        "SELECT incident.id, incident.title, incident.status, incident.severity, CAST(link.created_at AS TEXT) AS link_created_at FROM incidents_incident incident {relation} WHERE incident.tenant_id = ? AND {predicate} ORDER BY incident.updated_at DESC, incident.id DESC LIMIT 200"
    ))
    .bind(system_id).bind(tenant_id).fetch_all(pool).await?;
    rows.into_iter()
        .map(incident_link_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn incident_link_from_pg_row(row: PgRow) -> Result<AiGovernanceIncidentLink, sqlx::Error> {
    Ok(AiGovernanceIncidentLink {
        id: row.try_get("id")?,
        title: row.try_get("title")?,
        status: row.try_get("status")?,
        severity: row.try_get("severity")?,
        created_at: row.try_get("link_created_at")?,
    })
}

fn incident_link_from_sqlite_row(row: SqliteRow) -> Result<AiGovernanceIncidentLink, sqlx::Error> {
    Ok(AiGovernanceIncidentLink {
        id: row.try_get("id")?,
        title: row.try_get("title")?,
        status: row.try_get("status")?,
        severity: row.try_get("severity")?,
        created_at: row.try_get("link_created_at")?,
    })
}

async fn linked_changes_postgres(
    pool: &PgPool,
    tenant_id: i64,
    system_id: i64,
) -> anyhow::Result<Vec<AiGovernanceChangeLink>> {
    change_links_postgres(pool, tenant_id, system_id, true).await
}

async fn candidate_changes_postgres(
    pool: &PgPool,
    tenant_id: i64,
    system_id: i64,
) -> anyhow::Result<Vec<AiGovernanceChangeLink>> {
    change_links_postgres(pool, tenant_id, system_id, false).await
}

async fn change_links_postgres(
    pool: &PgPool,
    tenant_id: i64,
    system_id: i64,
    linked: bool,
) -> anyhow::Result<Vec<AiGovernanceChangeLink>> {
    let relation = if linked {
        "JOIN ai_governance_system_change link ON link.change_id = change.id AND link.tenant_id = change.tenant_id AND link.system_id = $2"
    } else {
        "LEFT JOIN ai_governance_system_change link ON link.change_id = change.id AND link.tenant_id = change.tenant_id AND link.system_id = $2"
    };
    let predicate = if linked {
        "link.id IS NOT NULL"
    } else {
        "link.id IS NULL"
    };
    let rows = sqlx::query(&format!(
        "SELECT change.id, change.title, change.status, change.change_type, change.planned_at, link.created_at::text AS link_created_at FROM changes_change change {relation} WHERE change.tenant_id = $1 AND {predicate} ORDER BY change.updated_at DESC, change.id DESC LIMIT 200"
    ))
    .bind(tenant_id).bind(system_id).fetch_all(pool).await?;
    rows.into_iter()
        .map(change_link_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn linked_changes_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    system_id: i64,
) -> anyhow::Result<Vec<AiGovernanceChangeLink>> {
    change_links_sqlite(pool, tenant_id, system_id, true).await
}

async fn candidate_changes_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    system_id: i64,
) -> anyhow::Result<Vec<AiGovernanceChangeLink>> {
    change_links_sqlite(pool, tenant_id, system_id, false).await
}

async fn change_links_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    system_id: i64,
    linked: bool,
) -> anyhow::Result<Vec<AiGovernanceChangeLink>> {
    let relation = if linked {
        "JOIN ai_governance_system_change link ON link.change_id = change.id AND link.tenant_id = change.tenant_id AND link.system_id = ?"
    } else {
        "LEFT JOIN ai_governance_system_change link ON link.change_id = change.id AND link.tenant_id = change.tenant_id AND link.system_id = ?"
    };
    let predicate = if linked {
        "link.id IS NOT NULL"
    } else {
        "link.id IS NULL"
    };
    let rows = sqlx::query(&format!(
        "SELECT change.id, change.title, change.status, change.change_type, CAST(change.planned_at AS TEXT) AS planned_at, CAST(link.created_at AS TEXT) AS link_created_at FROM changes_change change {relation} WHERE change.tenant_id = ? AND {predicate} ORDER BY change.updated_at DESC, change.id DESC LIMIT 200"
    ))
    .bind(system_id).bind(tenant_id).fetch_all(pool).await?;
    rows.into_iter()
        .map(change_link_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn change_link_from_pg_row(row: PgRow) -> Result<AiGovernanceChangeLink, sqlx::Error> {
    Ok(AiGovernanceChangeLink {
        id: row.try_get("id")?,
        title: row.try_get("title")?,
        status: row.try_get("status")?,
        change_type: row.try_get("change_type")?,
        planned_at: row.try_get("planned_at")?,
        created_at: row.try_get("link_created_at")?,
    })
}

fn change_link_from_sqlite_row(row: SqliteRow) -> Result<AiGovernanceChangeLink, sqlx::Error> {
    Ok(AiGovernanceChangeLink {
        id: row.try_get("id")?,
        title: row.try_get("title")?,
        status: row.try_get("status")?,
        change_type: row.try_get("change_type")?,
        planned_at: row.try_get("planned_at")?,
        created_at: row.try_get("link_created_at")?,
    })
}

async fn link_audit_postgres(
    pool: &PgPool,
    tenant_id: i64,
    system_id: i64,
) -> anyhow::Result<Vec<AiGovernanceLinkAuditEntry>> {
    let rows = sqlx::query(
        "SELECT id, entity_type, entity_id, action, actor_id, detail, created_at::text AS created_at FROM ai_governance_link_audit WHERE tenant_id = $1 AND system_id = $2 ORDER BY created_at DESC, id DESC LIMIT 50",
    ).bind(tenant_id).bind(system_id).fetch_all(pool).await?;
    rows.into_iter()
        .map(audit_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn link_audit_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    system_id: i64,
) -> anyhow::Result<Vec<AiGovernanceLinkAuditEntry>> {
    let rows = sqlx::query(
        "SELECT id, entity_type, entity_id, action, actor_id, detail, CAST(created_at AS TEXT) AS created_at FROM ai_governance_link_audit WHERE tenant_id = ? AND system_id = ? ORDER BY created_at DESC, id DESC LIMIT 50",
    ).bind(tenant_id).bind(system_id).fetch_all(pool).await?;
    rows.into_iter()
        .map(audit_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn audit_from_pg_row(row: PgRow) -> Result<AiGovernanceLinkAuditEntry, sqlx::Error> {
    Ok(AiGovernanceLinkAuditEntry {
        id: row.try_get("id")?,
        entity_type: row.try_get("entity_type")?,
        entity_id: row.try_get("entity_id")?,
        action: row.try_get("action")?,
        actor_id: row.try_get("actor_id")?,
        detail: row.try_get("detail")?,
        created_at: row.try_get("created_at")?,
    })
}

fn audit_from_sqlite_row(row: SqliteRow) -> Result<AiGovernanceLinkAuditEntry, sqlx::Error> {
    Ok(AiGovernanceLinkAuditEntry {
        id: row.try_get("id")?,
        entity_type: row.try_get("entity_type")?,
        entity_id: row.try_get("entity_id")?,
        action: row.try_get("action")?,
        actor_id: row.try_get("actor_id")?,
        detail: row.try_get("detail")?,
        created_at: row.try_get("created_at")?,
    })
}

async fn roadmap_phases_postgres(
    pool: &PgPool,
    tenant_id: i64,
) -> anyhow::Result<Vec<AiGovernanceRoadmapPhaseCandidate>> {
    let rows = sqlx::query(
        "SELECT phase.id, phase.name, plan.title AS plan_title FROM roadmap_roadmapphase phase JOIN roadmap_roadmapplan plan ON plan.id = phase.plan_id WHERE plan.tenant_id = $1 ORDER BY plan.updated_at DESC, phase.sort_order ASC LIMIT 200",
    ).bind(tenant_id).fetch_all(pool).await?;
    rows.into_iter()
        .map(|row| {
            Ok(AiGovernanceRoadmapPhaseCandidate {
                id: row.try_get("id")?,
                name: row.try_get("name")?,
                plan_title: row.try_get("plan_title")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map_err(Into::into)
}

async fn roadmap_phases_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
) -> anyhow::Result<Vec<AiGovernanceRoadmapPhaseCandidate>> {
    let rows = sqlx::query(
        "SELECT phase.id, phase.name, plan.title AS plan_title FROM roadmap_roadmapphase phase JOIN roadmap_roadmapplan plan ON plan.id = phase.plan_id WHERE plan.tenant_id = ? ORDER BY plan.updated_at DESC, phase.sort_order ASC LIMIT 200",
    ).bind(tenant_id).fetch_all(pool).await?;
    rows.into_iter()
        .map(|row| {
            Ok(AiGovernanceRoadmapPhaseCandidate {
                id: row.try_get("id")?,
                name: row.try_get("name")?,
                plan_title: row.try_get("plan_title")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map_err(Into::into)
}

async fn create_gap_task_postgres(
    pool: &PgPool,
    tenant_id: i64,
    phase_id: i64,
    system: &AiGovernanceSystemSummary,
    requirement: &AiGovernanceRequirementSummary,
    origin_key: &str,
) -> anyhow::Result<Option<(AiGovernanceRoadmapTaskLink, bool)>> {
    let title = format!("AI Governance: {} - {}", system.name, requirement.label);
    let priority = if matches!(system.criticality.as_str(), "CRITICAL" | "HIGH") {
        "HIGH"
    } else {
        "MEDIUM"
    };
    let inserted_id: Option<i64> = sqlx::query_scalar(
        r#"
        INSERT INTO roadmap_roadmaptask (
            phase_id, measure_id, title, description, priority, owner_role, due_in_days,
            dependency_text, status, planned_start, due_date, notes, origin_key,
            created_at, updated_at
        )
        SELECT phase.id, NULL, $3, $4, $5, 'AI Governance Owner', 30, '', 'OPEN',
               CURRENT_DATE, (CURRENT_DATE + INTERVAL '30 days')::date,
               $6, $7, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
        FROM roadmap_roadmapphase phase
        JOIN roadmap_roadmapplan plan ON plan.id = phase.plan_id
        WHERE phase.id = $1 AND plan.tenant_id = $2
        ON CONFLICT DO NOTHING
        RETURNING id
        "#,
    )
    .bind(phase_id)
    .bind(tenant_id)
    .bind(&title)
    .bind(&requirement.detail)
    .bind(priority)
    .bind(format!(
        "Ursprung: AI-Governance-System {} / Gap {}.",
        system.id, requirement.key
    ))
    .bind(origin_key)
    .fetch_optional(pool)
    .await?;
    let created = inserted_id.is_some();
    let task_id = match inserted_id {
        Some(id) => id,
        None => {
            let phase_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM roadmap_roadmapphase phase JOIN roadmap_roadmapplan plan ON plan.id = phase.plan_id WHERE phase.id = $1 AND plan.tenant_id = $2)")
                .bind(phase_id).bind(tenant_id).fetch_one(pool).await?;
            if !phase_exists {
                return Ok(None);
            }
            sqlx::query_scalar("SELECT task.id FROM roadmap_roadmaptask task JOIN roadmap_roadmapphase phase ON phase.id = task.phase_id JOIN roadmap_roadmapplan plan ON plan.id = phase.plan_id WHERE plan.tenant_id = $1 AND task.origin_key = $2")
                .bind(tenant_id).bind(origin_key).fetch_one(pool).await?
        }
    };
    let task = roadmap_task_by_id_postgres(pool, tenant_id, task_id)
        .await?
        .context("Roadmap-Task konnte nicht gelesen werden")?;
    Ok(Some((task, created)))
}

async fn create_gap_task_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    phase_id: i64,
    system: &AiGovernanceSystemSummary,
    requirement: &AiGovernanceRequirementSummary,
    origin_key: &str,
) -> anyhow::Result<Option<(AiGovernanceRoadmapTaskLink, bool)>> {
    let title = format!("AI Governance: {} - {}", system.name, requirement.label);
    let priority = if matches!(system.criticality.as_str(), "CRITICAL" | "HIGH") {
        "HIGH"
    } else {
        "MEDIUM"
    };
    let inserted_id: Option<i64> = sqlx::query_scalar(
        r#"
        INSERT INTO roadmap_roadmaptask (
            phase_id, measure_id, title, description, priority, owner_role, due_in_days,
            dependency_text, status, planned_start, due_date, notes, origin_key,
            created_at, updated_at
        )
        SELECT phase.id, NULL, ?, ?, ?, 'AI Governance Owner', 30, '', 'OPEN',
               DATE('now'), DATE('now', '+30 days'), ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
        FROM roadmap_roadmapphase phase
        JOIN roadmap_roadmapplan plan ON plan.id = phase.plan_id
        WHERE phase.id = ? AND plan.tenant_id = ?
        ON CONFLICT DO NOTHING
        RETURNING id
        "#,
    )
    .bind(&title)
    .bind(&requirement.detail)
    .bind(priority)
    .bind(format!(
        "Ursprung: AI-Governance-System {} / Gap {}.",
        system.id, requirement.key
    ))
    .bind(origin_key)
    .bind(phase_id)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;
    let created = inserted_id.is_some();
    let task_id = match inserted_id {
        Some(id) => id,
        None => {
            let phase_exists: i64 = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM roadmap_roadmapphase phase JOIN roadmap_roadmapplan plan ON plan.id = phase.plan_id WHERE phase.id = ? AND plan.tenant_id = ?)")
                .bind(phase_id).bind(tenant_id).fetch_one(pool).await?;
            if phase_exists == 0 {
                return Ok(None);
            }
            sqlx::query_scalar("SELECT task.id FROM roadmap_roadmaptask task JOIN roadmap_roadmapphase phase ON phase.id = task.phase_id JOIN roadmap_roadmapplan plan ON plan.id = phase.plan_id WHERE plan.tenant_id = ? AND task.origin_key = ?")
                .bind(tenant_id).bind(origin_key).fetch_one(pool).await?
        }
    };
    let task = roadmap_task_by_id_sqlite(pool, tenant_id, task_id)
        .await?
        .context("Roadmap-Task konnte nicht gelesen werden")?;
    Ok(Some((task, created)))
}

async fn roadmap_task_by_id_postgres(
    pool: &PgPool,
    tenant_id: i64,
    task_id: i64,
) -> anyhow::Result<Option<AiGovernanceRoadmapTaskLink>> {
    let row = sqlx::query(
        "SELECT task.id, task.title, task.status, task.due_date::text AS due_date, phase.name AS phase_name, plan.title AS plan_title, task.origin_key, NULL::text AS link_created_at FROM roadmap_roadmaptask task JOIN roadmap_roadmapphase phase ON phase.id = task.phase_id JOIN roadmap_roadmapplan plan ON plan.id = phase.plan_id WHERE plan.tenant_id = $1 AND task.id = $2",
    ).bind(tenant_id).bind(task_id).fetch_optional(pool).await?;
    row.map(roadmap_task_link_from_pg_row)
        .transpose()
        .map_err(Into::into)
}

async fn roadmap_task_by_id_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    task_id: i64,
) -> anyhow::Result<Option<AiGovernanceRoadmapTaskLink>> {
    let row = sqlx::query(
        "SELECT task.id, task.title, task.status, CAST(task.due_date AS TEXT) AS due_date, phase.name AS phase_name, plan.title AS plan_title, task.origin_key, NULL AS link_created_at FROM roadmap_roadmaptask task JOIN roadmap_roadmapphase phase ON phase.id = task.phase_id JOIN roadmap_roadmapplan plan ON plan.id = phase.plan_id WHERE plan.tenant_id = ? AND task.id = ?",
    ).bind(tenant_id).bind(task_id).fetch_optional(pool).await?;
    row.map(roadmap_task_link_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

fn roadmap_status_label(value: &str) -> &'static str {
    match value {
        "IN_PROGRESS" => "In Arbeit",
        "BLOCKED" => "Blockiert",
        "DONE" => "Erledigt",
        _ => "Offen",
    }
}

async fn list_systems_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AiGovernanceSystemSummary>> {
    let query = format!(
        "{POSTGRES_AI_GOVERNANCE_SELECT}
WHERE system.tenant_id = $1
ORDER BY
    CASE UPPER(system.ai_act_classification)
        WHEN 'PROHIBITED' THEN 6
        WHEN 'HIGH_RISK' THEN 5
        WHEN 'NOT_ASSESSED' THEN 4
        WHEN 'LIMITED_RISK' THEN 3
        WHEN 'MINIMAL_RISK' THEN 2
        ELSE 1
    END DESC,
    COALESCE(system.next_review_due_at, '9999-12-31') ASC,
    system.name ASC
LIMIT $2"
    );
    let rows = sqlx::query(&query)
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-AI-Governance-Register konnte nicht gelesen werden")?;
    rows.into_iter()
        .map(ai_system_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_systems_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AiGovernanceSystemSummary>> {
    let query = format!(
        "{SQLITE_AI_GOVERNANCE_SELECT}
WHERE system.tenant_id = ?
ORDER BY
    CASE UPPER(system.ai_act_classification)
        WHEN 'PROHIBITED' THEN 6
        WHEN 'HIGH_RISK' THEN 5
        WHEN 'NOT_ASSESSED' THEN 4
        WHEN 'LIMITED_RISK' THEN 3
        WHEN 'MINIMAL_RISK' THEN 2
        ELSE 1
    END DESC,
    COALESCE(system.next_review_due_at, '9999-12-31') ASC,
    system.name ASC
LIMIT ?"
    );
    let rows = sqlx::query(&query)
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("SQLite-AI-Governance-Register konnte nicht gelesen werden")?;
    rows.into_iter()
        .map(ai_system_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn system_detail_postgres(
    pool: &PgPool,
    tenant_id: i64,
    system_id: i64,
) -> anyhow::Result<Option<AiGovernanceSystemSummary>> {
    let query =
        format!("{POSTGRES_AI_GOVERNANCE_SELECT}\nWHERE system.tenant_id = $1 AND system.id = $2");
    let row = sqlx::query(&query)
        .bind(tenant_id)
        .bind(system_id)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-AI-Governance-Detail konnte nicht gelesen werden")?;
    row.map(ai_system_from_pg_row)
        .transpose()
        .map_err(Into::into)
}

async fn system_detail_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    system_id: i64,
) -> anyhow::Result<Option<AiGovernanceSystemSummary>> {
    let query =
        format!("{SQLITE_AI_GOVERNANCE_SELECT}\nWHERE system.tenant_id = ? AND system.id = ?");
    let row = sqlx::query(&query)
        .bind(tenant_id)
        .bind(system_id)
        .fetch_optional(pool)
        .await
        .context("SQLite-AI-Governance-Detail konnte nicht gelesen werden")?;
    row.map(ai_system_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

#[allow(clippy::too_many_arguments)]
async fn create_system_postgres(
    pool: &PgPool,
    tenant_id: i64,
    payload: &AiGovernanceSystemCreateRequest,
    name: &str,
    ai_act_classification: &str,
    criticality: &str,
    status: &str,
    evidence_key: &str,
) -> anyhow::Result<i64> {
    sqlx::query_scalar(
        r#"
        INSERT INTO ai_governance_system (
            tenant_id, product_id, owner_id, name, purpose, model_provider, model_name,
            model_version, deployment_context, data_categories, decision_impact,
            human_oversight, ai_act_classification, criticality, status, logging_required,
            transparency_required, cybersecurity_required, monitoring_plan, evidence_key,
            risk_summary, next_review_due_at, notes, created_at, updated_at
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
            $17, $18, $19, $20, $21, $22, $23, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
        )
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(payload.product_id.filter(|id| *id > 0))
    .bind(payload.owner_id.filter(|id| *id > 0))
    .bind(name)
    .bind(clean_text(&payload.purpose))
    .bind(clean_text(&payload.model_provider))
    .bind(clean_text(&payload.model_name))
    .bind(clean_text(&payload.model_version))
    .bind(clean_text(&payload.deployment_context))
    .bind(clean_text(&payload.data_categories))
    .bind(clean_text(&payload.decision_impact))
    .bind(clean_text(&payload.human_oversight))
    .bind(ai_act_classification)
    .bind(criticality)
    .bind(status)
    .bind(payload.logging_required.unwrap_or(false))
    .bind(payload.transparency_required.unwrap_or(false))
    .bind(payload.cybersecurity_required.unwrap_or(true))
    .bind(clean_text(&payload.monitoring_plan))
    .bind(evidence_key)
    .bind(clean_text(&payload.risk_summary))
    .bind(clean_optional_date(&payload.next_review_due_at))
    .bind(clean_text(&payload.notes))
    .fetch_one(pool)
    .await
    .context("PostgreSQL-AI-Governance-System konnte nicht angelegt werden")
}

#[allow(clippy::too_many_arguments)]
async fn create_system_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    payload: &AiGovernanceSystemCreateRequest,
    name: &str,
    ai_act_classification: &str,
    criticality: &str,
    status: &str,
    evidence_key: &str,
) -> anyhow::Result<i64> {
    sqlx::query(
        r#"
        INSERT INTO ai_governance_system (
            tenant_id, product_id, owner_id, name, purpose, model_provider, model_name,
            model_version, deployment_context, data_categories, decision_impact,
            human_oversight, ai_act_classification, criticality, status, logging_required,
            transparency_required, cybersecurity_required, monitoring_plan, evidence_key,
            risk_summary, next_review_due_at, notes, created_at, updated_at
        )
        VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
        )
        "#,
    )
    .bind(tenant_id)
    .bind(payload.product_id.filter(|id| *id > 0))
    .bind(payload.owner_id.filter(|id| *id > 0))
    .bind(name)
    .bind(clean_text(&payload.purpose))
    .bind(clean_text(&payload.model_provider))
    .bind(clean_text(&payload.model_name))
    .bind(clean_text(&payload.model_version))
    .bind(clean_text(&payload.deployment_context))
    .bind(clean_text(&payload.data_categories))
    .bind(clean_text(&payload.decision_impact))
    .bind(clean_text(&payload.human_oversight))
    .bind(ai_act_classification)
    .bind(criticality)
    .bind(status)
    .bind(payload.logging_required.unwrap_or(false))
    .bind(payload.transparency_required.unwrap_or(false))
    .bind(payload.cybersecurity_required.unwrap_or(true))
    .bind(clean_text(&payload.monitoring_plan))
    .bind(evidence_key)
    .bind(clean_text(&payload.risk_summary))
    .bind(clean_optional_date(&payload.next_review_due_at))
    .bind(clean_text(&payload.notes))
    .execute(pool)
    .await
    .context("SQLite-AI-Governance-System konnte nicht angelegt werden")?;

    sqlx::query_scalar("SELECT last_insert_rowid()")
        .fetch_one(pool)
        .await
        .context("SQLite-ID fuer AI-Governance-System konnte nicht gelesen werden")
}

async fn update_system_postgres(
    pool: &PgPool,
    system: &AiGovernanceSystemSummary,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        UPDATE ai_governance_system
        SET product_id = $3,
            owner_id = $4,
            name = $5,
            purpose = $6,
            model_provider = $7,
            model_name = $8,
            model_version = $9,
            deployment_context = $10,
            data_categories = $11,
            decision_impact = $12,
            human_oversight = $13,
            ai_act_classification = $14,
            criticality = $15,
            status = $16,
            logging_required = $17,
            transparency_required = $18,
            cybersecurity_required = $19,
            monitoring_plan = $20,
            evidence_key = $21,
            risk_summary = $22,
            next_review_due_at = $23,
            notes = $24,
            updated_at = CURRENT_TIMESTAMP
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(system.tenant_id)
    .bind(system.id)
    .bind(system.product_id)
    .bind(system.owner_id)
    .bind(&system.name)
    .bind(&system.purpose)
    .bind(&system.model_provider)
    .bind(&system.model_name)
    .bind(&system.model_version)
    .bind(&system.deployment_context)
    .bind(&system.data_categories)
    .bind(&system.decision_impact)
    .bind(&system.human_oversight)
    .bind(&system.ai_act_classification)
    .bind(&system.criticality)
    .bind(&system.status)
    .bind(system.logging_required)
    .bind(system.transparency_required)
    .bind(system.cybersecurity_required)
    .bind(&system.monitoring_plan)
    .bind(&system.evidence_key)
    .bind(&system.risk_summary)
    .bind(&system.next_review_due_at)
    .bind(&system.notes)
    .execute(pool)
    .await
    .context("PostgreSQL-AI-Governance-System konnte nicht aktualisiert werden")?;
    Ok(())
}

async fn update_system_sqlite(
    pool: &SqlitePool,
    system: &AiGovernanceSystemSummary,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        UPDATE ai_governance_system
        SET product_id = ?3,
            owner_id = ?4,
            name = ?5,
            purpose = ?6,
            model_provider = ?7,
            model_name = ?8,
            model_version = ?9,
            deployment_context = ?10,
            data_categories = ?11,
            decision_impact = ?12,
            human_oversight = ?13,
            ai_act_classification = ?14,
            criticality = ?15,
            status = ?16,
            logging_required = ?17,
            transparency_required = ?18,
            cybersecurity_required = ?19,
            monitoring_plan = ?20,
            evidence_key = ?21,
            risk_summary = ?22,
            next_review_due_at = ?23,
            notes = ?24,
            updated_at = CURRENT_TIMESTAMP
        WHERE tenant_id = ?1 AND id = ?2
        "#,
    )
    .bind(system.tenant_id)
    .bind(system.id)
    .bind(system.product_id)
    .bind(system.owner_id)
    .bind(&system.name)
    .bind(&system.purpose)
    .bind(&system.model_provider)
    .bind(&system.model_name)
    .bind(&system.model_version)
    .bind(&system.deployment_context)
    .bind(&system.data_categories)
    .bind(&system.decision_impact)
    .bind(&system.human_oversight)
    .bind(&system.ai_act_classification)
    .bind(&system.criticality)
    .bind(&system.status)
    .bind(system.logging_required)
    .bind(system.transparency_required)
    .bind(system.cybersecurity_required)
    .bind(&system.monitoring_plan)
    .bind(&system.evidence_key)
    .bind(&system.risk_summary)
    .bind(&system.next_review_due_at)
    .bind(&system.notes)
    .execute(pool)
    .await
    .context("SQLite-AI-Governance-System konnte nicht aktualisiert werden")?;
    Ok(())
}

const POSTGRES_AI_GOVERNANCE_SELECT: &str = r#"
SELECT
    system.id,
    system.tenant_id,
    system.product_id,
    product.name AS product_name,
    system.owner_id,
    COALESCE(
        NULLIF(BTRIM(CONCAT(COALESCE(owner.first_name, ''), ' ', COALESCE(owner.last_name, ''))), ''),
        owner.username
    ) AS owner_display,
    system.name,
    system.purpose,
    system.model_provider,
    system.model_name,
    system.model_version,
    system.deployment_context,
    system.data_categories,
    system.decision_impact,
    system.human_oversight,
    system.ai_act_classification,
    system.criticality,
    system.status,
    system.logging_required,
    system.transparency_required,
    system.cybersecurity_required,
    system.monitoring_plan,
    system.evidence_key,
    system.risk_summary,
    system.next_review_due_at,
    system.notes,
    system.created_at::text AS created_at,
    system.updated_at::text AS updated_at,
    COALESCE(evidence_stats.evidence_count, 0) AS evidence_count,
    COALESCE(evidence_stats.approved_evidence_count, 0) AS approved_evidence_count
FROM ai_governance_system system
LEFT JOIN product_security_product product
    ON product.id = system.product_id AND product.tenant_id = system.tenant_id
LEFT JOIN accounts_user owner
    ON owner.id = system.owner_id AND owner.tenant_id = system.tenant_id
LEFT JOIN (
    SELECT
        tenant_id,
        linked_requirement,
        COUNT(*) AS evidence_count,
        SUM(CASE WHEN UPPER(status) = 'APPROVED' THEN 1 ELSE 0 END) AS approved_evidence_count
    FROM evidence_evidenceitem
    GROUP BY tenant_id, linked_requirement
) evidence_stats
    ON evidence_stats.tenant_id = system.tenant_id
    AND evidence_stats.linked_requirement = system.evidence_key
"#;

const SQLITE_AI_GOVERNANCE_SELECT: &str = r#"
SELECT
    system.id,
    system.tenant_id,
    system.product_id,
    product.name AS product_name,
    system.owner_id,
    COALESCE(
        NULLIF(TRIM(COALESCE(owner.first_name, '') || ' ' || COALESCE(owner.last_name, '')), ''),
        owner.username
    ) AS owner_display,
    system.name,
    system.purpose,
    system.model_provider,
    system.model_name,
    system.model_version,
    system.deployment_context,
    system.data_categories,
    system.decision_impact,
    system.human_oversight,
    system.ai_act_classification,
    system.criticality,
    system.status,
    system.logging_required,
    system.transparency_required,
    system.cybersecurity_required,
    system.monitoring_plan,
    system.evidence_key,
    system.risk_summary,
    system.next_review_due_at,
    system.notes,
    CAST(system.created_at AS TEXT) AS created_at,
    CAST(system.updated_at AS TEXT) AS updated_at,
    COALESCE(evidence_stats.evidence_count, 0) AS evidence_count,
    COALESCE(evidence_stats.approved_evidence_count, 0) AS approved_evidence_count
FROM ai_governance_system system
LEFT JOIN product_security_product product
    ON product.id = system.product_id AND product.tenant_id = system.tenant_id
LEFT JOIN accounts_user owner
    ON owner.id = system.owner_id AND owner.tenant_id = system.tenant_id
LEFT JOIN (
    SELECT
        tenant_id,
        linked_requirement,
        COUNT(*) AS evidence_count,
        SUM(CASE WHEN UPPER(status) = 'APPROVED' THEN 1 ELSE 0 END) AS approved_evidence_count
    FROM evidence_evidenceitem
    GROUP BY tenant_id, linked_requirement
) evidence_stats
    ON evidence_stats.tenant_id = system.tenant_id
    AND evidence_stats.linked_requirement = system.evidence_key
"#;

fn ai_system_from_pg_row(row: PgRow) -> Result<AiGovernanceSystemSummary, sqlx::Error> {
    let ai_act_classification: String = row.try_get("ai_act_classification")?;
    let criticality: String = row.try_get("criticality")?;
    let status: String = row.try_get("status")?;
    let mut system = AiGovernanceSystemSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        product_name: row.try_get("product_name")?,
        owner_id: row.try_get("owner_id")?,
        owner_display: row.try_get("owner_display")?,
        name: row.try_get("name")?,
        purpose: row.try_get("purpose")?,
        model_provider: row.try_get("model_provider")?,
        model_name: row.try_get("model_name")?,
        model_version: row.try_get("model_version")?,
        deployment_context: row.try_get("deployment_context")?,
        data_categories: row.try_get("data_categories")?,
        decision_impact: row.try_get("decision_impact")?,
        human_oversight: row.try_get("human_oversight")?,
        ai_act_classification_label: ai_act_classification_label(&ai_act_classification),
        ai_act_classification,
        criticality_label: criticality_label(&criticality),
        criticality,
        status_label: status_label(&status),
        status,
        logging_required: row.try_get("logging_required")?,
        transparency_required: row.try_get("transparency_required")?,
        cybersecurity_required: row.try_get("cybersecurity_required")?,
        monitoring_plan: row.try_get("monitoring_plan")?,
        evidence_key: row.try_get("evidence_key")?,
        risk_summary: row.try_get("risk_summary")?,
        next_review_due_at: row.try_get("next_review_due_at")?,
        notes: row.try_get("notes")?,
        evidence_count: row.try_get("evidence_count")?,
        approved_evidence_count: row.try_get("approved_evidence_count")?,
        open_requirement_count: 0,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    };
    system.open_requirement_count = ai_governance_requirements(&system)
        .iter()
        .filter(|requirement| requirement.status == "GAP")
        .count() as i64;
    Ok(system)
}

fn ai_system_from_sqlite_row(row: SqliteRow) -> Result<AiGovernanceSystemSummary, sqlx::Error> {
    let ai_act_classification: String = row.try_get("ai_act_classification")?;
    let criticality: String = row.try_get("criticality")?;
    let status: String = row.try_get("status")?;
    let mut system = AiGovernanceSystemSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        product_name: row.try_get("product_name")?,
        owner_id: row.try_get("owner_id")?,
        owner_display: row.try_get("owner_display")?,
        name: row.try_get("name")?,
        purpose: row.try_get("purpose")?,
        model_provider: row.try_get("model_provider")?,
        model_name: row.try_get("model_name")?,
        model_version: row.try_get("model_version")?,
        deployment_context: row.try_get("deployment_context")?,
        data_categories: row.try_get("data_categories")?,
        decision_impact: row.try_get("decision_impact")?,
        human_oversight: row.try_get("human_oversight")?,
        ai_act_classification_label: ai_act_classification_label(&ai_act_classification),
        ai_act_classification,
        criticality_label: criticality_label(&criticality),
        criticality,
        status_label: status_label(&status),
        status,
        logging_required: row.try_get("logging_required")?,
        transparency_required: row.try_get("transparency_required")?,
        cybersecurity_required: row.try_get("cybersecurity_required")?,
        monitoring_plan: row.try_get("monitoring_plan")?,
        evidence_key: row.try_get("evidence_key")?,
        risk_summary: row.try_get("risk_summary")?,
        next_review_due_at: row.try_get("next_review_due_at")?,
        notes: row.try_get("notes")?,
        evidence_count: row.try_get("evidence_count")?,
        approved_evidence_count: row.try_get("approved_evidence_count")?,
        open_requirement_count: 0,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    };
    system.open_requirement_count = ai_governance_requirements(&system)
        .iter()
        .filter(|requirement| requirement.status == "GAP")
        .count() as i64;
    Ok(system)
}

fn ai_governance_summary(systems: &[AiGovernanceSystemSummary]) -> AiGovernanceSummary {
    AiGovernanceSummary {
        total_systems: systems.len() as i64,
        high_risk_systems: systems
            .iter()
            .filter(|system| {
                matches!(
                    system.ai_act_classification.as_str(),
                    "HIGH_RISK" | "PROHIBITED"
                )
            })
            .count() as i64,
        not_assessed_systems: systems
            .iter()
            .filter(|system| system.ai_act_classification == "NOT_ASSESSED")
            .count() as i64,
        review_due_systems: systems.iter().filter(|system| review_due(system)).count() as i64,
        evidence_missing: systems
            .iter()
            .filter(|system| system.evidence_count == 0)
            .count() as i64,
        open_governance_gaps: systems
            .iter()
            .map(|system| system.open_requirement_count)
            .sum(),
    }
}

pub fn ai_governance_requirements(
    system: &AiGovernanceSystemSummary,
) -> Vec<AiGovernanceRequirementSummary> {
    let high_risk = matches!(
        system.ai_act_classification.as_str(),
        "HIGH_RISK" | "PROHIBITED"
    );
    let limited_or_high = matches!(
        system.ai_act_classification.as_str(),
        "LIMITED_RISK" | "HIGH_RISK" | "PROHIBITED"
    );
    vec![
        requirement(
            "classification",
            "AI-Act-Einstufung",
            if system.ai_act_classification == "NOT_ASSESSED" {
                "GAP"
            } else {
                "OK"
            },
            if system.ai_act_classification == "NOT_ASSESSED" {
                "Einstufung offen; Scope, Zweck, Betroffenheit und Ausnahmen bewerten."
            } else {
                "Einstufung dokumentiert."
            },
        ),
        requirement(
            "risk_management",
            "Risikomanagement",
            if system.risk_summary.trim().is_empty() {
                "GAP"
            } else {
                "OK"
            },
            if system.risk_summary.trim().is_empty() {
                "Risikoannahmen, Fehlgebrauch und Auswirkungen sind noch nicht zusammengefasst."
            } else {
                "Risikosummary vorhanden."
            },
        ),
        requirement(
            "human_oversight",
            "Human Oversight",
            if high_risk && system.human_oversight.trim().is_empty() {
                "GAP"
            } else if system.human_oversight.trim().is_empty() {
                "WATCH"
            } else {
                "OK"
            },
            if system.human_oversight.trim().is_empty() {
                "Oversight-Modell, Eskalation und Verantwortlichkeit ergaenzen."
            } else {
                "Oversight-Modell dokumentiert."
            },
        ),
        requirement(
            "logging",
            "Logging & Nachvollziehbarkeit",
            if high_risk && !system.logging_required {
                "GAP"
            } else if system.logging_required {
                "OK"
            } else {
                "WATCH"
            },
            if system.logging_required {
                "Logging-Anforderung gesetzt."
            } else {
                "Logging-Bedarf fuer Betrieb, Audit und Incident-Kontext bewerten."
            },
        ),
        requirement(
            "transparency",
            "Transparenz",
            if limited_or_high && !system.transparency_required {
                "GAP"
            } else if system.transparency_required {
                "OK"
            } else {
                "WATCH"
            },
            if system.transparency_required {
                "Transparenzanforderung gesetzt."
            } else {
                "Nutzerinformation, Zweck und Grenzen des Systems pruefen."
            },
        ),
        requirement(
            "cybersecurity",
            "Cybersecurity & Robustheit",
            if high_risk && !system.cybersecurity_required {
                "GAP"
            } else if system.cybersecurity_required {
                "OK"
            } else {
                "WATCH"
            },
            if system.cybersecurity_required {
                "Cybersecurity-Anforderung gesetzt."
            } else {
                "Robustheit, Missbrauchsschutz und Manipulationsresistenz bewerten."
            },
        ),
        requirement(
            "monitoring",
            "Monitoring & Evidence",
            if system.monitoring_plan.trim().is_empty() || system.evidence_count == 0 {
                "GAP"
            } else {
                "OK"
            },
            if system.evidence_count == 0 {
                "Monitoringplan oder Evidence fehlen; Nachweis mit Evidence-Key verknuepfen."
            } else {
                "Evidence-Spur vorhanden."
            },
        ),
    ]
}

fn requirement(
    key: &str,
    label: &str,
    status: &str,
    detail: &str,
) -> AiGovernanceRequirementSummary {
    AiGovernanceRequirementSummary {
        key: key.to_string(),
        label: label.to_string(),
        status: status.to_string(),
        status_label: requirement_status_label(status).to_string(),
        detail: detail.to_string(),
    }
}

fn merged_update(
    mut existing: AiGovernanceSystemSummary,
    payload: AiGovernanceSystemUpdateRequest,
) -> anyhow::Result<AiGovernanceSystemSummary> {
    if let Some(name) = payload.name {
        existing.name = clean_required(&name, "AI-System-Name")?;
    }
    if let Some(product_id) = payload.product_id {
        existing.product_id = (product_id > 0).then_some(product_id);
    }
    if let Some(owner_id) = payload.owner_id {
        existing.owner_id = (owner_id > 0).then_some(owner_id);
    }
    if let Some(value) = payload.purpose {
        existing.purpose = clean_text(&value);
    }
    if let Some(value) = payload.model_provider {
        existing.model_provider = clean_text(&value);
    }
    if let Some(value) = payload.model_name {
        existing.model_name = clean_text(&value);
    }
    if let Some(value) = payload.model_version {
        existing.model_version = clean_text(&value);
    }
    if let Some(value) = payload.deployment_context {
        existing.deployment_context = clean_text(&value);
    }
    if let Some(value) = payload.data_categories {
        existing.data_categories = clean_text(&value);
    }
    if let Some(value) = payload.decision_impact {
        existing.decision_impact = clean_text(&value);
    }
    if let Some(value) = payload.human_oversight {
        existing.human_oversight = clean_text(&value);
    }
    if let Some(value) = payload.ai_act_classification {
        existing.ai_act_classification = normalize_ai_act_classification(&value);
        existing.ai_act_classification_label =
            ai_act_classification_label(&existing.ai_act_classification);
    }
    if let Some(value) = payload.criticality {
        existing.criticality = normalize_criticality(&value);
        existing.criticality_label = criticality_label(&existing.criticality);
    }
    if let Some(value) = payload.status {
        existing.status = normalize_status(&value);
        existing.status_label = status_label(&existing.status);
    }
    if let Some(value) = payload.logging_required {
        existing.logging_required = value;
    }
    if let Some(value) = payload.transparency_required {
        existing.transparency_required = value;
    }
    if let Some(value) = payload.cybersecurity_required {
        existing.cybersecurity_required = value;
    }
    if let Some(value) = payload.monitoring_plan {
        existing.monitoring_plan = clean_text(&value);
    }
    if let Some(value) = payload.evidence_key {
        existing.evidence_key = clean_text(&value);
    }
    if let Some(value) = payload.risk_summary {
        existing.risk_summary = clean_text(&value);
    }
    if let Some(value) = payload.next_review_due_at {
        existing.next_review_due_at = clean_optional_date(&Some(value));
    }
    if let Some(value) = payload.notes {
        existing.notes = clean_text(&value);
    }
    Ok(existing)
}

fn review_due(system: &AiGovernanceSystemSummary) -> bool {
    let Some(value) = system.next_review_due_at.as_deref() else {
        return false;
    };
    let date_part = value.get(..10).unwrap_or(value);
    let Ok(review_date) = NaiveDate::parse_from_str(date_part, "%Y-%m-%d") else {
        return false;
    };
    review_date <= Utc::now().date_naive()
}

fn clean_required(value: &str, label: &str) -> anyhow::Result<String> {
    let value = clean_text(value);
    if value.is_empty() {
        bail!("{label} darf nicht leer sein");
    }
    Ok(value)
}

fn clean_text(value: &str) -> String {
    value.trim().to_string()
}

fn clean_optional_date(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(clean_text)
        .filter(|value| !value.is_empty())
}

fn normalize_ai_act_classification(value: &str) -> String {
    match value.trim().to_ascii_uppercase().replace('-', "_").as_str() {
        "PROHIBITED" | "UNACCEPTABLE" => "PROHIBITED",
        "HIGH" | "HIGH_RISK" => "HIGH_RISK",
        "LIMITED" | "LIMITED_RISK" => "LIMITED_RISK",
        "LOW" | "MINIMAL" | "MINIMAL_RISK" => "MINIMAL_RISK",
        "OUT_OF_SCOPE" | "NOT_IN_SCOPE" => "NOT_IN_SCOPE",
        _ => "NOT_ASSESSED",
    }
    .to_string()
}

fn normalize_criticality(value: &str) -> String {
    match value.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => "CRITICAL",
        "HIGH" => "HIGH",
        "LOW" => "LOW",
        _ => "MEDIUM",
    }
    .to_string()
}

fn normalize_status(value: &str) -> String {
    match value.trim().to_ascii_uppercase().replace('-', "_").as_str() {
        "DRAFT" => "DRAFT",
        "APPROVED" => "APPROVED",
        "RETIRED" => "RETIRED",
        _ => "IN_REVIEW",
    }
    .to_string()
}

fn ai_act_classification_label(value: &str) -> String {
    match value {
        "PROHIBITED" => "Verboten / nicht freigegeben",
        "HIGH_RISK" => "High Risk",
        "LIMITED_RISK" => "Limited Risk",
        "MINIMAL_RISK" => "Minimal Risk",
        "NOT_IN_SCOPE" => "Nicht im Scope",
        _ => "Nicht bewertet",
    }
    .to_string()
}

fn criticality_label(value: &str) -> String {
    match value {
        "CRITICAL" => "Kritisch",
        "HIGH" => "Hoch",
        "LOW" => "Niedrig",
        _ => "Mittel",
    }
    .to_string()
}

fn status_label(value: &str) -> String {
    match value {
        "DRAFT" => "Entwurf",
        "APPROVED" => "Freigegeben",
        "RETIRED" => "Stillgelegt",
        _ => "In Review",
    }
    .to_string()
}

fn requirement_status_label(value: &str) -> &'static str {
    match value {
        "OK" => "OK",
        "WATCH" => "Pruefen",
        _ => "Gap",
    }
}

fn slug_key(value: &str) -> String {
    let mut key = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    while key.contains("--") {
        key = key.replace("--", "-");
    }
    key.trim_matches('-').to_string()
}
