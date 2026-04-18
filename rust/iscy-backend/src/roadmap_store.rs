use anyhow::{bail, Context};
use serde::Serialize;
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Row,
};

use crate::cve_store::normalize_database_url;

#[derive(Clone)]
pub enum RoadmapStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Serialize)]
pub struct RoadmapPlanSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub tenant_name: String,
    pub session_id: i64,
    pub title: String,
    pub summary: String,
    pub overall_priority: String,
    pub planned_start: Option<String>,
    pub phase_count: i64,
    pub task_count: i64,
    pub open_task_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RoadmapPhaseSummary {
    pub id: i64,
    pub plan_id: i64,
    pub name: String,
    pub sort_order: i64,
    pub objective: String,
    pub duration_weeks: i64,
    pub planned_start: Option<String>,
    pub planned_end: Option<String>,
    pub task_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RoadmapTaskSummary {
    pub id: i64,
    pub phase_id: i64,
    pub phase_name: String,
    pub measure_id: Option<i64>,
    pub title: String,
    pub description: String,
    pub priority: String,
    pub owner_role: String,
    pub due_in_days: i64,
    pub dependency_text: String,
    pub status: String,
    pub status_label: String,
    pub planned_start: Option<String>,
    pub due_date: Option<String>,
    pub notes: String,
    pub incoming_dependency_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RoadmapTaskDependencySummary {
    pub id: i64,
    pub predecessor_id: i64,
    pub predecessor_title: String,
    pub successor_id: i64,
    pub successor_title: String,
    pub dependency_type: String,
    pub dependency_type_label: String,
    pub rationale: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RoadmapPlanDetail {
    pub plan: RoadmapPlanSummary,
    pub phases: Vec<RoadmapPhaseSummary>,
    pub tasks: Vec<RoadmapTaskSummary>,
    pub dependencies: Vec<RoadmapTaskDependencySummary>,
}

impl RoadmapStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Roadmap-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Roadmap-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-Roadmap-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn list_plans(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<RoadmapPlanSummary>> {
        match self {
            Self::Postgres(pool) => list_plans_postgres(pool, tenant_id, limit).await,
            Self::Sqlite(pool) => list_plans_sqlite(pool, tenant_id, limit).await,
        }
    }

    pub async fn plan_detail(
        &self,
        tenant_id: i64,
        plan_id: i64,
    ) -> anyhow::Result<Option<RoadmapPlanDetail>> {
        match self {
            Self::Postgres(pool) => plan_detail_postgres(pool, tenant_id, plan_id).await,
            Self::Sqlite(pool) => plan_detail_sqlite(pool, tenant_id, plan_id).await,
        }
    }
}

async fn list_plans_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<RoadmapPlanSummary>> {
    let rows = sqlx::query(plan_list_postgres_sql())
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Roadmapliste konnte nicht gelesen werden")?;

    rows.into_iter()
        .map(plan_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn list_plans_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<RoadmapPlanSummary>> {
    let rows = sqlx::query(plan_list_sqlite_sql())
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("SQLite-Roadmapliste konnte nicht gelesen werden")?;

    rows.into_iter()
        .map(plan_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn plan_detail_postgres(
    pool: &PgPool,
    tenant_id: i64,
    plan_id: i64,
) -> anyhow::Result<Option<RoadmapPlanDetail>> {
    let plan = sqlx::query(plan_detail_postgres_sql())
        .bind(tenant_id)
        .bind(plan_id)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-Roadmapdetail konnte nicht gelesen werden")?
        .map(plan_from_pg_row)
        .transpose()?;

    let Some(plan) = plan else {
        return Ok(None);
    };

    let phases = sqlx::query(phases_postgres_sql())
        .bind(plan_id)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Roadmapphasen konnten nicht gelesen werden")?
        .into_iter()
        .map(phase_from_pg_row)
        .collect::<Result<Vec<_>, _>>()?;

    let tasks = sqlx::query(tasks_postgres_sql())
        .bind(plan_id)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Roadmaptasks konnten nicht gelesen werden")?
        .into_iter()
        .map(task_from_pg_row)
        .collect::<Result<Vec<_>, _>>()?;

    let dependencies = sqlx::query(dependencies_postgres_sql())
        .bind(plan_id)
        .bind(100_i64)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Roadmapabhaengigkeiten konnten nicht gelesen werden")?
        .into_iter()
        .map(dependency_from_pg_row)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Some(RoadmapPlanDetail {
        plan,
        phases,
        tasks,
        dependencies,
    }))
}

async fn plan_detail_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    plan_id: i64,
) -> anyhow::Result<Option<RoadmapPlanDetail>> {
    let plan = sqlx::query(plan_detail_sqlite_sql())
        .bind(tenant_id)
        .bind(plan_id)
        .fetch_optional(pool)
        .await
        .context("SQLite-Roadmapdetail konnte nicht gelesen werden")?
        .map(plan_from_sqlite_row)
        .transpose()?;

    let Some(plan) = plan else {
        return Ok(None);
    };

    let phases = sqlx::query(phases_sqlite_sql())
        .bind(plan_id)
        .fetch_all(pool)
        .await
        .context("SQLite-Roadmapphasen konnten nicht gelesen werden")?
        .into_iter()
        .map(phase_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()?;

    let tasks = sqlx::query(tasks_sqlite_sql())
        .bind(plan_id)
        .fetch_all(pool)
        .await
        .context("SQLite-Roadmaptasks konnten nicht gelesen werden")?
        .into_iter()
        .map(task_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()?;

    let dependencies = sqlx::query(dependencies_sqlite_sql())
        .bind(plan_id)
        .bind(100_i64)
        .fetch_all(pool)
        .await
        .context("SQLite-Roadmapabhaengigkeiten konnten nicht gelesen werden")?
        .into_iter()
        .map(dependency_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Some(RoadmapPlanDetail {
        plan,
        phases,
        tasks,
        dependencies,
    }))
}

fn plan_from_pg_row(row: PgRow) -> Result<RoadmapPlanSummary, sqlx::Error> {
    Ok(RoadmapPlanSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        tenant_name: row.try_get("tenant_name")?,
        session_id: row.try_get("session_id")?,
        title: row.try_get("title")?,
        summary: row.try_get("summary")?,
        overall_priority: row.try_get("overall_priority")?,
        planned_start: row.try_get("planned_start")?,
        phase_count: row.try_get("phase_count")?,
        task_count: row.try_get("task_count")?,
        open_task_count: row.try_get("open_task_count")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn plan_from_sqlite_row(row: SqliteRow) -> Result<RoadmapPlanSummary, sqlx::Error> {
    Ok(RoadmapPlanSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        tenant_name: row.try_get("tenant_name")?,
        session_id: row.try_get("session_id")?,
        title: row.try_get("title")?,
        summary: row.try_get("summary")?,
        overall_priority: row.try_get("overall_priority")?,
        planned_start: row.try_get("planned_start")?,
        phase_count: row.try_get("phase_count")?,
        task_count: row.try_get("task_count")?,
        open_task_count: row.try_get("open_task_count")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn phase_from_pg_row(row: PgRow) -> Result<RoadmapPhaseSummary, sqlx::Error> {
    Ok(RoadmapPhaseSummary {
        id: row.try_get("id")?,
        plan_id: row.try_get("plan_id")?,
        name: row.try_get("name")?,
        sort_order: row.try_get("sort_order")?,
        objective: row.try_get("objective")?,
        duration_weeks: row.try_get("duration_weeks")?,
        planned_start: row.try_get("planned_start")?,
        planned_end: row.try_get("planned_end")?,
        task_count: row.try_get("task_count")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn phase_from_sqlite_row(row: SqliteRow) -> Result<RoadmapPhaseSummary, sqlx::Error> {
    Ok(RoadmapPhaseSummary {
        id: row.try_get("id")?,
        plan_id: row.try_get("plan_id")?,
        name: row.try_get("name")?,
        sort_order: row.try_get("sort_order")?,
        objective: row.try_get("objective")?,
        duration_weeks: row.try_get("duration_weeks")?,
        planned_start: row.try_get("planned_start")?,
        planned_end: row.try_get("planned_end")?,
        task_count: row.try_get("task_count")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn task_from_pg_row(row: PgRow) -> Result<RoadmapTaskSummary, sqlx::Error> {
    let status: String = row.try_get("status")?;
    Ok(RoadmapTaskSummary {
        id: row.try_get("id")?,
        phase_id: row.try_get("phase_id")?,
        phase_name: row.try_get("phase_name")?,
        measure_id: row.try_get("measure_id")?,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        priority: row.try_get("priority")?,
        owner_role: row.try_get("owner_role")?,
        due_in_days: row.try_get("due_in_days")?,
        dependency_text: row.try_get("dependency_text")?,
        status_label: task_status_label(&status).to_string(),
        status,
        planned_start: row.try_get("planned_start")?,
        due_date: row.try_get("due_date")?,
        notes: row.try_get("notes")?,
        incoming_dependency_count: row.try_get("incoming_dependency_count")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn task_from_sqlite_row(row: SqliteRow) -> Result<RoadmapTaskSummary, sqlx::Error> {
    let status: String = row.try_get("status")?;
    Ok(RoadmapTaskSummary {
        id: row.try_get("id")?,
        phase_id: row.try_get("phase_id")?,
        phase_name: row.try_get("phase_name")?,
        measure_id: row.try_get("measure_id")?,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        priority: row.try_get("priority")?,
        owner_role: row.try_get("owner_role")?,
        due_in_days: row.try_get("due_in_days")?,
        dependency_text: row.try_get("dependency_text")?,
        status_label: task_status_label(&status).to_string(),
        status,
        planned_start: row.try_get("planned_start")?,
        due_date: row.try_get("due_date")?,
        notes: row.try_get("notes")?,
        incoming_dependency_count: row.try_get("incoming_dependency_count")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn dependency_from_pg_row(row: PgRow) -> Result<RoadmapTaskDependencySummary, sqlx::Error> {
    let dependency_type: String = row.try_get("dependency_type")?;
    Ok(RoadmapTaskDependencySummary {
        id: row.try_get("id")?,
        predecessor_id: row.try_get("predecessor_id")?,
        predecessor_title: row.try_get("predecessor_title")?,
        successor_id: row.try_get("successor_id")?,
        successor_title: row.try_get("successor_title")?,
        dependency_type_label: dependency_type_label(&dependency_type).to_string(),
        dependency_type,
        rationale: row.try_get("rationale")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn dependency_from_sqlite_row(row: SqliteRow) -> Result<RoadmapTaskDependencySummary, sqlx::Error> {
    let dependency_type: String = row.try_get("dependency_type")?;
    Ok(RoadmapTaskDependencySummary {
        id: row.try_get("id")?,
        predecessor_id: row.try_get("predecessor_id")?,
        predecessor_title: row.try_get("predecessor_title")?,
        successor_id: row.try_get("successor_id")?,
        successor_title: row.try_get("successor_title")?,
        dependency_type_label: dependency_type_label(&dependency_type).to_string(),
        dependency_type,
        rationale: row.try_get("rationale")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn plan_list_postgres_sql() -> &'static str {
    r#"
    SELECT
        plan.id,
        plan.tenant_id,
        tenant.name AS tenant_name,
        plan.session_id,
        plan.title,
        plan.summary,
        plan.overall_priority,
        plan.planned_start::text AS planned_start,
        COUNT(DISTINCT phase.id)::bigint AS phase_count,
        COUNT(DISTINCT task.id)::bigint AS task_count,
        COUNT(DISTINCT CASE WHEN task.status != 'DONE' THEN task.id END)::bigint AS open_task_count,
        plan.created_at::text AS created_at,
        plan.updated_at::text AS updated_at
    FROM roadmap_roadmapplan plan
    JOIN organizations_tenant tenant ON tenant.id = plan.tenant_id
    LEFT JOIN roadmap_roadmapphase phase ON phase.plan_id = plan.id
    LEFT JOIN roadmap_roadmaptask task ON task.phase_id = phase.id
    WHERE plan.tenant_id = $1
    GROUP BY
        plan.id,
        plan.tenant_id,
        tenant.name,
        plan.session_id,
        plan.title,
        plan.summary,
        plan.overall_priority,
        plan.planned_start,
        plan.created_at,
        plan.updated_at
    ORDER BY plan.created_at DESC, plan.id DESC
    LIMIT $2
    "#
}

fn plan_list_sqlite_sql() -> &'static str {
    r#"
    SELECT
        plan.id,
        plan.tenant_id,
        tenant.name AS tenant_name,
        plan.session_id,
        plan.title,
        plan.summary,
        plan.overall_priority,
        CAST(plan.planned_start AS TEXT) AS planned_start,
        COUNT(DISTINCT phase.id) AS phase_count,
        COUNT(DISTINCT task.id) AS task_count,
        COUNT(DISTINCT CASE WHEN task.status != 'DONE' THEN task.id END) AS open_task_count,
        CAST(plan.created_at AS TEXT) AS created_at,
        CAST(plan.updated_at AS TEXT) AS updated_at
    FROM roadmap_roadmapplan plan
    JOIN organizations_tenant tenant ON tenant.id = plan.tenant_id
    LEFT JOIN roadmap_roadmapphase phase ON phase.plan_id = plan.id
    LEFT JOIN roadmap_roadmaptask task ON task.phase_id = phase.id
    WHERE plan.tenant_id = ?
    GROUP BY
        plan.id,
        plan.tenant_id,
        tenant.name,
        plan.session_id,
        plan.title,
        plan.summary,
        plan.overall_priority,
        plan.planned_start,
        plan.created_at,
        plan.updated_at
    ORDER BY plan.created_at DESC, plan.id DESC
    LIMIT ?
    "#
}

fn plan_detail_postgres_sql() -> &'static str {
    r#"
    SELECT
        plan.id,
        plan.tenant_id,
        tenant.name AS tenant_name,
        plan.session_id,
        plan.title,
        plan.summary,
        plan.overall_priority,
        plan.planned_start::text AS planned_start,
        COUNT(DISTINCT phase.id)::bigint AS phase_count,
        COUNT(DISTINCT task.id)::bigint AS task_count,
        COUNT(DISTINCT CASE WHEN task.status != 'DONE' THEN task.id END)::bigint AS open_task_count,
        plan.created_at::text AS created_at,
        plan.updated_at::text AS updated_at
    FROM roadmap_roadmapplan plan
    JOIN organizations_tenant tenant ON tenant.id = plan.tenant_id
    LEFT JOIN roadmap_roadmapphase phase ON phase.plan_id = plan.id
    LEFT JOIN roadmap_roadmaptask task ON task.phase_id = phase.id
    WHERE plan.tenant_id = $1 AND plan.id = $2
    GROUP BY
        plan.id,
        plan.tenant_id,
        tenant.name,
        plan.session_id,
        plan.title,
        plan.summary,
        plan.overall_priority,
        plan.planned_start,
        plan.created_at,
        plan.updated_at
    "#
}

fn plan_detail_sqlite_sql() -> &'static str {
    r#"
    SELECT
        plan.id,
        plan.tenant_id,
        tenant.name AS tenant_name,
        plan.session_id,
        plan.title,
        plan.summary,
        plan.overall_priority,
        CAST(plan.planned_start AS TEXT) AS planned_start,
        COUNT(DISTINCT phase.id) AS phase_count,
        COUNT(DISTINCT task.id) AS task_count,
        COUNT(DISTINCT CASE WHEN task.status != 'DONE' THEN task.id END) AS open_task_count,
        CAST(plan.created_at AS TEXT) AS created_at,
        CAST(plan.updated_at AS TEXT) AS updated_at
    FROM roadmap_roadmapplan plan
    JOIN organizations_tenant tenant ON tenant.id = plan.tenant_id
    LEFT JOIN roadmap_roadmapphase phase ON phase.plan_id = plan.id
    LEFT JOIN roadmap_roadmaptask task ON task.phase_id = phase.id
    WHERE plan.tenant_id = ? AND plan.id = ?
    GROUP BY
        plan.id,
        plan.tenant_id,
        tenant.name,
        plan.session_id,
        plan.title,
        plan.summary,
        plan.overall_priority,
        plan.planned_start,
        plan.created_at,
        plan.updated_at
    "#
}

fn phases_postgres_sql() -> &'static str {
    r#"
    SELECT
        phase.id,
        phase.plan_id,
        phase.name,
        phase.sort_order::bigint AS sort_order,
        phase.objective,
        phase.duration_weeks::bigint AS duration_weeks,
        phase.planned_start::text AS planned_start,
        phase.planned_end::text AS planned_end,
        COUNT(task.id)::bigint AS task_count,
        phase.created_at::text AS created_at,
        phase.updated_at::text AS updated_at
    FROM roadmap_roadmapphase phase
    LEFT JOIN roadmap_roadmaptask task ON task.phase_id = phase.id
    WHERE phase.plan_id = $1
    GROUP BY
        phase.id,
        phase.plan_id,
        phase.name,
        phase.sort_order,
        phase.objective,
        phase.duration_weeks,
        phase.planned_start,
        phase.planned_end,
        phase.created_at,
        phase.updated_at
    ORDER BY phase.sort_order ASC, phase.id ASC
    "#
}

fn phases_sqlite_sql() -> &'static str {
    r#"
    SELECT
        phase.id,
        phase.plan_id,
        phase.name,
        phase.sort_order,
        phase.objective,
        phase.duration_weeks,
        CAST(phase.planned_start AS TEXT) AS planned_start,
        CAST(phase.planned_end AS TEXT) AS planned_end,
        COUNT(task.id) AS task_count,
        CAST(phase.created_at AS TEXT) AS created_at,
        CAST(phase.updated_at AS TEXT) AS updated_at
    FROM roadmap_roadmapphase phase
    LEFT JOIN roadmap_roadmaptask task ON task.phase_id = phase.id
    WHERE phase.plan_id = ?
    GROUP BY
        phase.id,
        phase.plan_id,
        phase.name,
        phase.sort_order,
        phase.objective,
        phase.duration_weeks,
        phase.planned_start,
        phase.planned_end,
        phase.created_at,
        phase.updated_at
    ORDER BY phase.sort_order ASC, phase.id ASC
    "#
}

fn tasks_postgres_sql() -> &'static str {
    r#"
    SELECT
        task.id,
        task.phase_id,
        phase.name AS phase_name,
        task.measure_id,
        task.title,
        task.description,
        task.priority,
        task.owner_role,
        task.due_in_days::bigint AS due_in_days,
        task.dependency_text,
        task.status,
        task.planned_start::text AS planned_start,
        task.due_date::text AS due_date,
        task.notes,
        (
            SELECT COUNT(*)::bigint
            FROM roadmap_roadmaptaskdependency dep
            WHERE dep.successor_id = task.id
        ) AS incoming_dependency_count,
        task.created_at::text AS created_at,
        task.updated_at::text AS updated_at
    FROM roadmap_roadmaptask task
    JOIN roadmap_roadmapphase phase ON phase.id = task.phase_id
    WHERE phase.plan_id = $1
    ORDER BY task.due_date ASC, task.priority ASC, task.id ASC
    "#
}

fn tasks_sqlite_sql() -> &'static str {
    r#"
    SELECT
        task.id,
        task.phase_id,
        phase.name AS phase_name,
        task.measure_id,
        task.title,
        task.description,
        task.priority,
        task.owner_role,
        task.due_in_days,
        task.dependency_text,
        task.status,
        CAST(task.planned_start AS TEXT) AS planned_start,
        CAST(task.due_date AS TEXT) AS due_date,
        task.notes,
        (
            SELECT COUNT(*)
            FROM roadmap_roadmaptaskdependency dep
            WHERE dep.successor_id = task.id
        ) AS incoming_dependency_count,
        CAST(task.created_at AS TEXT) AS created_at,
        CAST(task.updated_at AS TEXT) AS updated_at
    FROM roadmap_roadmaptask task
    JOIN roadmap_roadmapphase phase ON phase.id = task.phase_id
    WHERE phase.plan_id = ?
    ORDER BY task.due_date ASC, task.priority ASC, task.id ASC
    "#
}

fn dependencies_postgres_sql() -> &'static str {
    r#"
    SELECT
        dep.id,
        dep.predecessor_id,
        predecessor.title AS predecessor_title,
        dep.successor_id,
        successor.title AS successor_title,
        dep.dependency_type,
        dep.rationale,
        dep.created_at::text AS created_at,
        dep.updated_at::text AS updated_at
    FROM roadmap_roadmaptaskdependency dep
    JOIN roadmap_roadmaptask predecessor ON predecessor.id = dep.predecessor_id
    JOIN roadmap_roadmaptask successor ON successor.id = dep.successor_id
    JOIN roadmap_roadmapphase successor_phase ON successor_phase.id = successor.phase_id
    WHERE successor_phase.plan_id = $1
    ORDER BY dep.predecessor_id ASC, dep.successor_id ASC
    LIMIT $2
    "#
}

fn dependencies_sqlite_sql() -> &'static str {
    r#"
    SELECT
        dep.id,
        dep.predecessor_id,
        predecessor.title AS predecessor_title,
        dep.successor_id,
        successor.title AS successor_title,
        dep.dependency_type,
        dep.rationale,
        CAST(dep.created_at AS TEXT) AS created_at,
        CAST(dep.updated_at AS TEXT) AS updated_at
    FROM roadmap_roadmaptaskdependency dep
    JOIN roadmap_roadmaptask predecessor ON predecessor.id = dep.predecessor_id
    JOIN roadmap_roadmaptask successor ON successor.id = dep.successor_id
    JOIN roadmap_roadmapphase successor_phase ON successor_phase.id = successor.phase_id
    WHERE successor_phase.plan_id = ?
    ORDER BY dep.predecessor_id ASC, dep.successor_id ASC
    LIMIT ?
    "#
}

fn task_status_label(status: &str) -> &'static str {
    match status {
        "OPEN" => "Offen",
        "PLANNED" => "Geplant",
        "IN_PROGRESS" => "In Umsetzung",
        "BLOCKED" => "Blockiert",
        "DONE" => "Erledigt",
        _ => "Unbekannt",
    }
}

fn dependency_type_label(dependency_type: &str) -> &'static str {
    match dependency_type {
        "FS" => "Finish-to-Start",
        "SS" => "Start-to-Start",
        _ => "Unbekannt",
    }
}
