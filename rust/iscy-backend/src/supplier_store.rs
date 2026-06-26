use anyhow::{bail, Context};
use chrono::{NaiveDate, Utc};
use serde::Serialize;
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Row,
};

use crate::cve_store::normalize_database_url;

#[derive(Clone)]
pub enum SupplierStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Serialize)]
pub struct SupplierRiskOverview {
    pub tenant_id: i64,
    pub summary: SupplierRiskSummary,
    pub suppliers: Vec<SupplierRiskSummaryRow>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SupplierRiskSummary {
    pub total_suppliers: i64,
    pub critical_suppliers: i64,
    pub high_risk_suppliers: i64,
    pub overdue_reviews: i64,
    pub missing_evidence: i64,
    pub open_risks: i64,
    pub open_vulnerabilities: i64,
    pub average_score: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SupplierRiskSummaryRow {
    pub id: i64,
    pub tenant_id: i64,
    pub name: String,
    pub service_description: String,
    pub criticality: String,
    pub criticality_label: String,
    pub owner_id: Option<i64>,
    pub owner_display: Option<String>,
    pub contact_email: String,
    pub contract_reference: String,
    pub data_categories: String,
    pub regions: String,
    pub exit_dependency: String,
    pub regulatory_scope: String,
    pub regulatory_flags: Vec<String>,
    pub review_status: String,
    pub review_status_label: String,
    pub last_reviewed_at: Option<String>,
    pub next_review_due_at: Option<String>,
    pub evidence_required: bool,
    pub notes: String,
    pub component_count: i64,
    pub product_count: i64,
    pub open_vulnerability_count: i64,
    pub critical_vulnerability_count: i64,
    pub open_risk_count: i64,
    pub evidence_count: i64,
    pub approved_evidence_count: i64,
    pub score: i64,
    pub score_label: String,
    pub issues: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl SupplierStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Supplier-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Supplier-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-Supplier-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn overview(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<SupplierRiskOverview> {
        let suppliers = match self {
            Self::Postgres(pool) => list_suppliers_postgres(pool, tenant_id, limit).await?,
            Self::Sqlite(pool) => list_suppliers_sqlite(pool, tenant_id, limit).await?,
        };
        let summary = supplier_summary(&suppliers);
        Ok(SupplierRiskOverview {
            tenant_id,
            summary,
            suppliers,
        })
    }

    pub async fn detail(
        &self,
        tenant_id: i64,
        supplier_id: i64,
    ) -> anyhow::Result<Option<SupplierRiskSummaryRow>> {
        let suppliers = match self {
            Self::Postgres(pool) => supplier_detail_postgres(pool, tenant_id, supplier_id).await?,
            Self::Sqlite(pool) => supplier_detail_sqlite(pool, tenant_id, supplier_id).await?,
        };
        Ok(suppliers)
    }
}

async fn list_suppliers_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<SupplierRiskSummaryRow>> {
    let query = format!(
        "{POSTGRES_SUPPLIER_SELECT}
WHERE supplier.tenant_id = $1
ORDER BY
    CASE UPPER(supplier.criticality)
        WHEN 'CRITICAL' THEN 5
        WHEN 'VERY_HIGH' THEN 5
        WHEN 'HIGH' THEN 4
        WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 2
        ELSE 1
    END DESC,
    supplier.name ASC
LIMIT $2"
    );
    let rows = sqlx::query(&query)
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Supplier-Register konnte nicht gelesen werden")?;
    rows.into_iter()
        .map(supplier_from_pg_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn supplier_detail_postgres(
    pool: &PgPool,
    tenant_id: i64,
    supplier_id: i64,
) -> anyhow::Result<Option<SupplierRiskSummaryRow>> {
    let query =
        format!("{POSTGRES_SUPPLIER_SELECT}\nWHERE supplier.tenant_id = $1 AND supplier.id = $2");
    let row = sqlx::query(&query)
        .bind(tenant_id)
        .bind(supplier_id)
        .fetch_optional(pool)
        .await
        .context("PostgreSQL-Supplier-Detail konnte nicht gelesen werden")?;
    row.map(supplier_from_pg_row)
        .transpose()
        .map_err(Into::into)
}

async fn list_suppliers_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<SupplierRiskSummaryRow>> {
    let query = format!(
        "{SQLITE_SUPPLIER_SELECT}
WHERE supplier.tenant_id = ?
ORDER BY
    CASE UPPER(supplier.criticality)
        WHEN 'CRITICAL' THEN 5
        WHEN 'VERY_HIGH' THEN 5
        WHEN 'HIGH' THEN 4
        WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 2
        ELSE 1
    END DESC,
    supplier.name ASC
LIMIT ?"
    );
    let rows = sqlx::query(&query)
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("SQLite-Supplier-Register konnte nicht gelesen werden")?;
    rows.into_iter()
        .map(supplier_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn supplier_detail_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    supplier_id: i64,
) -> anyhow::Result<Option<SupplierRiskSummaryRow>> {
    let query =
        format!("{SQLITE_SUPPLIER_SELECT}\nWHERE supplier.tenant_id = ? AND supplier.id = ?");
    let row = sqlx::query(&query)
        .bind(tenant_id)
        .bind(supplier_id)
        .fetch_optional(pool)
        .await
        .context("SQLite-Supplier-Detail konnte nicht gelesen werden")?;
    row.map(supplier_from_sqlite_row)
        .transpose()
        .map_err(Into::into)
}

const POSTGRES_SUPPLIER_SELECT: &str = r#"
SELECT
    supplier.id,
    supplier.tenant_id,
    supplier.name,
    supplier.service_description,
    supplier.criticality,
    supplier.owner_id,
    COALESCE(
        NULLIF(BTRIM(CONCAT(COALESCE(owner.first_name, ''), ' ', COALESCE(owner.last_name, ''))), ''),
        owner.username
    ) AS owner_display,
    supplier.contact_email,
    supplier.contract_reference,
    supplier.data_categories,
    supplier.regions,
    supplier.exit_dependency,
    supplier.regulatory_scope,
    supplier.review_status,
    supplier.last_reviewed_at::text AS last_reviewed_at,
    supplier.next_review_due_at::text AS next_review_due_at,
    supplier.evidence_required,
    supplier.notes,
    supplier.created_at::text AS created_at,
    supplier.updated_at::text AS updated_at,
    COALESCE(component_stats.component_count, 0) AS component_count,
    COALESCE(component_stats.product_count, 0) AS product_count,
    COALESCE(vulnerability_stats.open_vulnerability_count, 0) AS open_vulnerability_count,
    COALESCE(vulnerability_stats.critical_vulnerability_count, 0) AS critical_vulnerability_count,
    COALESCE(risk_stats.open_risk_count, 0) AS open_risk_count,
    COALESCE(evidence_stats.evidence_count, 0) AS evidence_count,
    COALESCE(evidence_stats.approved_evidence_count, 0) AS approved_evidence_count
FROM organizations_supplier supplier
LEFT JOIN accounts_user owner
    ON owner.id = supplier.owner_id
    AND (owner.tenant_id = supplier.tenant_id OR owner.tenant_id IS NULL)
LEFT JOIN (
    SELECT tenant_id, supplier_id, COUNT(*) AS component_count, COUNT(DISTINCT product_id) AS product_count
    FROM product_security_component
    WHERE supplier_id IS NOT NULL
    GROUP BY tenant_id, supplier_id
) component_stats
    ON component_stats.tenant_id = supplier.tenant_id AND component_stats.supplier_id = supplier.id
LEFT JOIN (
    SELECT component.tenant_id, component.supplier_id,
           COUNT(*) FILTER (WHERE UPPER(vulnerability.status) NOT IN ('FIXED', 'CLOSED', 'RESOLVED', 'ACCEPTED')) AS open_vulnerability_count,
           COUNT(*) FILTER (
               WHERE UPPER(vulnerability.status) NOT IN ('FIXED', 'CLOSED', 'RESOLVED', 'ACCEPTED')
                 AND UPPER(vulnerability.severity) = 'CRITICAL'
           ) AS critical_vulnerability_count
    FROM product_security_component component
    JOIN product_security_vulnerability vulnerability
        ON vulnerability.component_id = component.id
        AND vulnerability.tenant_id = component.tenant_id
    WHERE component.supplier_id IS NOT NULL
    GROUP BY component.tenant_id, component.supplier_id
) vulnerability_stats
    ON vulnerability_stats.tenant_id = supplier.tenant_id AND vulnerability_stats.supplier_id = supplier.id
LEFT JOIN (
    SELECT supplier_inner.id AS supplier_id,
           supplier_inner.tenant_id,
           COUNT(risk.id) AS open_risk_count
    FROM organizations_supplier supplier_inner
    LEFT JOIN risks_risk risk
        ON risk.tenant_id = supplier_inner.tenant_id
        AND UPPER(risk.status) NOT IN ('CLOSED', 'ACCEPTED')
        AND (
            LOWER(COALESCE(risk.title, '') || ' ' || COALESCE(risk.description, '') || ' ' || COALESCE(risk.treatment_plan, ''))
                LIKE '%' || LOWER(supplier_inner.name) || '%'
            OR (
                LOWER(COALESCE(risk.title, '') || ' ' || COALESCE(risk.description, '')) LIKE '%supplier%'
                AND UPPER(supplier_inner.criticality) IN ('CRITICAL', 'VERY_HIGH', 'HIGH')
            )
        )
    GROUP BY supplier_inner.id, supplier_inner.tenant_id
) risk_stats
    ON risk_stats.tenant_id = supplier.tenant_id AND risk_stats.supplier_id = supplier.id
LEFT JOIN (
    SELECT supplier_inner.id AS supplier_id,
           supplier_inner.tenant_id,
           COUNT(evidence.id) AS evidence_count,
           COUNT(evidence.id) FILTER (WHERE UPPER(evidence.status) = 'APPROVED') AS approved_evidence_count
    FROM organizations_supplier supplier_inner
    LEFT JOIN evidence_evidenceitem evidence
        ON evidence.tenant_id = supplier_inner.tenant_id
        AND (
            evidence.linked_requirement = 'SUPPLIER:' || supplier_inner.id::text
            OR LOWER(evidence.linked_requirement) = LOWER('SUPPLIER:' || supplier_inner.name)
            OR LOWER(evidence.title) LIKE '%' || LOWER(supplier_inner.name) || '%'
        )
    GROUP BY supplier_inner.id, supplier_inner.tenant_id
) evidence_stats
    ON evidence_stats.tenant_id = supplier.tenant_id AND evidence_stats.supplier_id = supplier.id
"#;

const SQLITE_SUPPLIER_SELECT: &str = r#"
SELECT
    supplier.id,
    supplier.tenant_id,
    supplier.name,
    supplier.service_description,
    supplier.criticality,
    supplier.owner_id,
    COALESCE(
        NULLIF(TRIM(COALESCE(owner.first_name, '') || ' ' || COALESCE(owner.last_name, '')), ''),
        owner.username
    ) AS owner_display,
    supplier.contact_email,
    supplier.contract_reference,
    supplier.data_categories,
    supplier.regions,
    supplier.exit_dependency,
    supplier.regulatory_scope,
    supplier.review_status,
    CAST(supplier.last_reviewed_at AS TEXT) AS last_reviewed_at,
    CAST(supplier.next_review_due_at AS TEXT) AS next_review_due_at,
    supplier.evidence_required,
    supplier.notes,
    CAST(supplier.created_at AS TEXT) AS created_at,
    CAST(supplier.updated_at AS TEXT) AS updated_at,
    COALESCE(component_stats.component_count, 0) AS component_count,
    COALESCE(component_stats.product_count, 0) AS product_count,
    COALESCE(vulnerability_stats.open_vulnerability_count, 0) AS open_vulnerability_count,
    COALESCE(vulnerability_stats.critical_vulnerability_count, 0) AS critical_vulnerability_count,
    COALESCE(risk_stats.open_risk_count, 0) AS open_risk_count,
    COALESCE(evidence_stats.evidence_count, 0) AS evidence_count,
    COALESCE(evidence_stats.approved_evidence_count, 0) AS approved_evidence_count
FROM organizations_supplier supplier
LEFT JOIN accounts_user owner
    ON owner.id = supplier.owner_id
    AND (owner.tenant_id = supplier.tenant_id OR owner.tenant_id IS NULL)
LEFT JOIN (
    SELECT tenant_id, supplier_id, COUNT(*) AS component_count, COUNT(DISTINCT product_id) AS product_count
    FROM product_security_component
    WHERE supplier_id IS NOT NULL
    GROUP BY tenant_id, supplier_id
) component_stats
    ON component_stats.tenant_id = supplier.tenant_id AND component_stats.supplier_id = supplier.id
LEFT JOIN (
    SELECT component.tenant_id, component.supplier_id,
           SUM(CASE WHEN UPPER(vulnerability.status) NOT IN ('FIXED', 'CLOSED', 'RESOLVED', 'ACCEPTED') THEN 1 ELSE 0 END) AS open_vulnerability_count,
           SUM(CASE
               WHEN UPPER(vulnerability.status) NOT IN ('FIXED', 'CLOSED', 'RESOLVED', 'ACCEPTED')
                AND UPPER(vulnerability.severity) = 'CRITICAL'
               THEN 1 ELSE 0 END
           ) AS critical_vulnerability_count
    FROM product_security_component component
    JOIN product_security_vulnerability vulnerability
        ON vulnerability.component_id = component.id
        AND vulnerability.tenant_id = component.tenant_id
    WHERE component.supplier_id IS NOT NULL
    GROUP BY component.tenant_id, component.supplier_id
) vulnerability_stats
    ON vulnerability_stats.tenant_id = supplier.tenant_id AND vulnerability_stats.supplier_id = supplier.id
LEFT JOIN (
    SELECT supplier_inner.id AS supplier_id,
           supplier_inner.tenant_id,
           COUNT(risk.id) AS open_risk_count
    FROM organizations_supplier supplier_inner
    LEFT JOIN risks_risk risk
        ON risk.tenant_id = supplier_inner.tenant_id
        AND UPPER(risk.status) NOT IN ('CLOSED', 'ACCEPTED')
        AND (
            LOWER(COALESCE(risk.title, '') || ' ' || COALESCE(risk.description, '') || ' ' || COALESCE(risk.treatment_plan, ''))
                LIKE '%' || LOWER(supplier_inner.name) || '%'
            OR (
                LOWER(COALESCE(risk.title, '') || ' ' || COALESCE(risk.description, '')) LIKE '%supplier%'
                AND UPPER(supplier_inner.criticality) IN ('CRITICAL', 'VERY_HIGH', 'HIGH')
            )
        )
    GROUP BY supplier_inner.id, supplier_inner.tenant_id
) risk_stats
    ON risk_stats.tenant_id = supplier.tenant_id AND risk_stats.supplier_id = supplier.id
LEFT JOIN (
    SELECT supplier_inner.id AS supplier_id,
           supplier_inner.tenant_id,
           COUNT(evidence.id) AS evidence_count,
           SUM(CASE WHEN UPPER(evidence.status) = 'APPROVED' THEN 1 ELSE 0 END) AS approved_evidence_count
    FROM organizations_supplier supplier_inner
    LEFT JOIN evidence_evidenceitem evidence
        ON evidence.tenant_id = supplier_inner.tenant_id
        AND (
            evidence.linked_requirement = 'SUPPLIER:' || supplier_inner.id
            OR LOWER(evidence.linked_requirement) = LOWER('SUPPLIER:' || supplier_inner.name)
            OR LOWER(evidence.title) LIKE '%' || LOWER(supplier_inner.name) || '%'
        )
    GROUP BY supplier_inner.id, supplier_inner.tenant_id
) evidence_stats
    ON evidence_stats.tenant_id = supplier.tenant_id AND evidence_stats.supplier_id = supplier.id
"#;

fn supplier_from_pg_row(row: PgRow) -> Result<SupplierRiskSummaryRow, sqlx::Error> {
    let raw = RawSupplierRow {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        name: row.try_get("name")?,
        service_description: row.try_get("service_description")?,
        criticality: row.try_get("criticality")?,
        owner_id: row.try_get("owner_id")?,
        owner_display: row.try_get("owner_display")?,
        contact_email: row.try_get("contact_email")?,
        contract_reference: row.try_get("contract_reference")?,
        data_categories: row.try_get("data_categories")?,
        regions: row.try_get("regions")?,
        exit_dependency: row.try_get("exit_dependency")?,
        regulatory_scope: row.try_get("regulatory_scope")?,
        review_status: row.try_get("review_status")?,
        last_reviewed_at: row.try_get("last_reviewed_at")?,
        next_review_due_at: row.try_get("next_review_due_at")?,
        evidence_required: row.try_get("evidence_required")?,
        notes: row.try_get("notes")?,
        component_count: row.try_get("component_count")?,
        product_count: row.try_get("product_count")?,
        open_vulnerability_count: row.try_get("open_vulnerability_count")?,
        critical_vulnerability_count: row.try_get("critical_vulnerability_count")?,
        open_risk_count: row.try_get("open_risk_count")?,
        evidence_count: row.try_get("evidence_count")?,
        approved_evidence_count: row.try_get("approved_evidence_count")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    };
    Ok(supplier_from_raw(raw))
}

fn supplier_from_sqlite_row(row: SqliteRow) -> Result<SupplierRiskSummaryRow, sqlx::Error> {
    let raw = RawSupplierRow {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        name: row.try_get("name")?,
        service_description: row.try_get("service_description")?,
        criticality: row.try_get("criticality")?,
        owner_id: row.try_get("owner_id")?,
        owner_display: row.try_get("owner_display")?,
        contact_email: row.try_get("contact_email")?,
        contract_reference: row.try_get("contract_reference")?,
        data_categories: row.try_get("data_categories")?,
        regions: row.try_get("regions")?,
        exit_dependency: row.try_get("exit_dependency")?,
        regulatory_scope: row.try_get("regulatory_scope")?,
        review_status: row.try_get("review_status")?,
        last_reviewed_at: row.try_get("last_reviewed_at")?,
        next_review_due_at: row.try_get("next_review_due_at")?,
        evidence_required: row.try_get("evidence_required")?,
        notes: row.try_get("notes")?,
        component_count: row.try_get("component_count")?,
        product_count: row.try_get("product_count")?,
        open_vulnerability_count: row.try_get("open_vulnerability_count")?,
        critical_vulnerability_count: row.try_get("critical_vulnerability_count")?,
        open_risk_count: row.try_get("open_risk_count")?,
        evidence_count: row.try_get("evidence_count")?,
        approved_evidence_count: row.try_get("approved_evidence_count")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    };
    Ok(supplier_from_raw(raw))
}

struct RawSupplierRow {
    id: i64,
    tenant_id: i64,
    name: String,
    service_description: String,
    criticality: String,
    owner_id: Option<i64>,
    owner_display: Option<String>,
    contact_email: String,
    contract_reference: String,
    data_categories: String,
    regions: String,
    exit_dependency: String,
    regulatory_scope: String,
    review_status: String,
    last_reviewed_at: Option<String>,
    next_review_due_at: Option<String>,
    evidence_required: bool,
    notes: String,
    component_count: i64,
    product_count: i64,
    open_vulnerability_count: i64,
    critical_vulnerability_count: i64,
    open_risk_count: i64,
    evidence_count: i64,
    approved_evidence_count: i64,
    created_at: String,
    updated_at: String,
}

fn supplier_from_raw(raw: RawSupplierRow) -> SupplierRiskSummaryRow {
    let regulatory_flags = supplier_regulatory_flags(&raw);
    let issues = supplier_issues(&raw);
    let score = supplier_score(&raw, &issues);
    SupplierRiskSummaryRow {
        id: raw.id,
        tenant_id: raw.tenant_id,
        name: raw.name,
        service_description: raw.service_description,
        criticality_label: supplier_criticality_label(&raw.criticality).to_string(),
        criticality: normalize_upper(&raw.criticality),
        owner_id: raw.owner_id,
        owner_display: raw.owner_display,
        contact_email: raw.contact_email,
        contract_reference: raw.contract_reference,
        data_categories: raw.data_categories,
        regions: raw.regions,
        exit_dependency: raw.exit_dependency,
        regulatory_scope: raw.regulatory_scope,
        regulatory_flags,
        review_status_label: supplier_review_status_label(&raw.review_status).to_string(),
        review_status: normalize_upper(&raw.review_status),
        last_reviewed_at: raw.last_reviewed_at,
        next_review_due_at: raw.next_review_due_at,
        evidence_required: raw.evidence_required,
        notes: raw.notes,
        component_count: raw.component_count,
        product_count: raw.product_count,
        open_vulnerability_count: raw.open_vulnerability_count,
        critical_vulnerability_count: raw.critical_vulnerability_count,
        open_risk_count: raw.open_risk_count,
        evidence_count: raw.evidence_count,
        approved_evidence_count: raw.approved_evidence_count,
        score,
        score_label: supplier_score_label(score).to_string(),
        issues,
        created_at: raw.created_at,
        updated_at: raw.updated_at,
    }
}

fn supplier_summary(suppliers: &[SupplierRiskSummaryRow]) -> SupplierRiskSummary {
    let total_suppliers = suppliers.len() as i64;
    let critical_suppliers = suppliers
        .iter()
        .filter(|supplier| is_high_criticality(&supplier.criticality))
        .count() as i64;
    let high_risk_suppliers = suppliers
        .iter()
        .filter(|supplier| supplier.score < 60 || supplier.critical_vulnerability_count > 0)
        .count() as i64;
    let overdue_reviews = suppliers
        .iter()
        .filter(|supplier| is_overdue(supplier.next_review_due_at.as_deref()))
        .count() as i64;
    let missing_evidence = suppliers
        .iter()
        .filter(|supplier| supplier.evidence_required && supplier.approved_evidence_count == 0)
        .count() as i64;
    let open_risks = suppliers
        .iter()
        .map(|supplier| supplier.open_risk_count)
        .sum::<i64>();
    let open_vulnerabilities = suppliers
        .iter()
        .map(|supplier| supplier.open_vulnerability_count)
        .sum::<i64>();
    let average_score = if total_suppliers == 0 {
        0
    } else {
        suppliers.iter().map(|supplier| supplier.score).sum::<i64>() / total_suppliers
    };
    SupplierRiskSummary {
        total_suppliers,
        critical_suppliers,
        high_risk_suppliers,
        overdue_reviews,
        missing_evidence,
        open_risks,
        open_vulnerabilities,
        average_score,
    }
}

fn supplier_issues(raw: &RawSupplierRow) -> Vec<String> {
    let mut issues = Vec::new();
    if raw.critical_vulnerability_count > 0 {
        issues.push("Kritische offene Produkt-/Komponenten-Schwachstellen vorhanden.".to_string());
    } else if raw.open_vulnerability_count > 0 {
        issues.push("Offene Produkt-/Komponenten-Schwachstellen vorhanden.".to_string());
    }
    if is_overdue(raw.next_review_due_at.as_deref()) {
        issues.push("Supplier-Review ist ueberfaellig.".to_string());
    }
    if raw.evidence_required && raw.approved_evidence_count == 0 {
        issues.push("Freigegebene Supplier-Evidence fehlt.".to_string());
    }
    if is_high_criticality(&raw.criticality) && raw.open_risk_count == 0 {
        issues.push("Supplier-Risiko ist fuer kritischen Supplier nicht dokumentiert.".to_string());
    }
    if !matches!(
        normalize_upper(&raw.review_status).as_str(),
        "APPROVED" | "REVIEWED"
    ) {
        issues.push("Supplier-Review ist nicht freigegeben.".to_string());
    }
    if raw.owner_id.is_none() {
        issues.push("Owner fehlt.".to_string());
    }
    if raw.contract_reference.trim().is_empty() {
        issues.push("Vertrags-/Security-Annex-Referenz fehlt.".to_string());
    }
    if raw.contact_email.trim().is_empty() {
        issues.push("Security-Kontakt fehlt.".to_string());
    }
    if raw.regulatory_scope.trim().is_empty() {
        issues.push("Regulatorischer Scope fehlt.".to_string());
    }
    if is_high_criticality(&raw.criticality) && raw.data_categories.trim().is_empty() {
        issues.push("Datenarten fehlen fuer kritischen Supplier.".to_string());
    }
    if raw.evidence_required && raw.regions.trim().is_empty() {
        issues.push("Regionen/Leistungsorte fehlen.".to_string());
    }
    if is_high_criticality(&raw.criticality) && raw.exit_dependency.trim().is_empty() {
        issues.push("Exit-Abhaengigkeit oder Exit-Strategie fehlt.".to_string());
    }
    issues
}

fn supplier_score(raw: &RawSupplierRow, issues: &[String]) -> i64 {
    let mut score = 100;
    for issue in issues {
        score -= match issue.as_str() {
            "Kritische offene Produkt-/Komponenten-Schwachstellen vorhanden." => 22,
            "Supplier-Review ist ueberfaellig." => 20,
            "Freigegebene Supplier-Evidence fehlt." => 18,
            "Supplier-Risiko ist fuer kritischen Supplier nicht dokumentiert." => 12,
            "Exit-Abhaengigkeit oder Exit-Strategie fehlt." => 10,
            "Vertrags-/Security-Annex-Referenz fehlt." => 10,
            "Supplier-Review ist nicht freigegeben." => 10,
            "Datenarten fehlen fuer kritischen Supplier." => 8,
            "Offene Produkt-/Komponenten-Schwachstellen vorhanden." => 8,
            "Security-Kontakt fehlt." => 6,
            "Regionen/Leistungsorte fehlen." => 6,
            "Regulatorischer Scope fehlt." => 6,
            "Owner fehlt." => 6,
            _ => 4,
        };
    }
    if raw.component_count > 0 && raw.approved_evidence_count > 0 {
        score += 5;
    }
    score.clamp(0, 100)
}

fn supplier_regulatory_flags(raw: &RawSupplierRow) -> Vec<String> {
    let mut flags = Vec::new();
    let scope = raw.regulatory_scope.to_ascii_uppercase();
    for flag in ["NIS2", "DORA", "CRA", "DSGVO", "TISAX", "AI_ACT"] {
        if scope.contains(flag) {
            flags.push(flag.replace('_', " "));
        }
    }
    if flags.iter().all(|flag| flag != "CRA") && raw.component_count > 0 {
        flags.push("CRA".to_string());
    }
    if flags.iter().all(|flag| flag != "DSGVO") && !raw.data_categories.trim().is_empty() {
        flags.push("DSGVO".to_string());
    }
    if flags.iter().all(|flag| flag != "NIS2") && is_high_criticality(&raw.criticality) {
        flags.push("NIS2".to_string());
    }
    flags.sort();
    flags.dedup();
    flags
}

fn supplier_criticality_label(criticality: &str) -> &'static str {
    match normalize_upper(criticality).as_str() {
        "CRITICAL" | "VERY_HIGH" => "Kritisch",
        "HIGH" => "Hoch",
        "MEDIUM" => "Mittel",
        "LOW" => "Niedrig",
        _ => "Nicht bewertet",
    }
}

fn supplier_review_status_label(status: &str) -> &'static str {
    match normalize_upper(status).as_str() {
        "APPROVED" => "Freigegeben",
        "REVIEWED" => "Geprueft",
        "IN_REVIEW" => "In Review",
        "REJECTED" => "Abgelehnt",
        "NOT_REVIEWED" => "Nicht geprueft",
        _ => "Nicht bewertet",
    }
}

fn supplier_score_label(score: i64) -> &'static str {
    if score >= 80 {
        "Belastbar"
    } else if score >= 60 {
        "Beobachten"
    } else if score >= 40 {
        "Handlungsbedarf"
    } else {
        "Kritisch"
    }
}

fn normalize_upper(value: &str) -> String {
    value.trim().to_ascii_uppercase()
}

fn is_high_criticality(criticality: &str) -> bool {
    matches!(
        normalize_upper(criticality).as_str(),
        "CRITICAL" | "VERY_HIGH" | "HIGH"
    )
}

fn is_overdue(date_value: Option<&str>) -> bool {
    let Some(date_value) = date_value.map(str::trim).filter(|value| !value.is_empty()) else {
        return false;
    };
    let Ok(date) = NaiveDate::parse_from_str(date_value, "%Y-%m-%d") else {
        return false;
    };
    date < Utc::now().date_naive()
}
