use anyhow::{bail, Context};
use serde::Serialize;
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Row,
};

use crate::cve_store::normalize_database_url;

#[derive(Clone)]
pub enum ProductSecurityStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityMatrixItem {
    pub applicable: bool,
    pub label: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityMatrix {
    pub cra: ProductSecurityMatrixItem,
    pub ai_act: ProductSecurityMatrixItem,
    pub iec62443: ProductSecurityMatrixItem,
    pub iso_sae_21434: ProductSecurityMatrixItem,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityPosture {
    pub products: i64,
    pub active_releases: i64,
    pub threat_models: i64,
    pub taras: i64,
    pub open_vulnerabilities: i64,
    pub critical_open_vulnerabilities: i64,
    pub psirt_cases_open: i64,
    pub published_advisories: i64,
    pub avg_threat_model_coverage: i64,
    pub avg_psirt_readiness: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductListItem {
    pub id: i64,
    pub tenant_id: i64,
    pub family_id: Option<i64>,
    pub family_name: Option<String>,
    pub name: String,
    pub code: String,
    pub description: String,
    pub has_digital_elements: bool,
    pub includes_ai: bool,
    pub ot_iacs_context: bool,
    pub automotive_context: bool,
    pub support_window_months: i64,
    pub release_count: i64,
    pub threat_model_count: i64,
    pub tara_count: i64,
    pub vulnerability_count: i64,
    pub psirt_case_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecuritySnapshotSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub product_id: i64,
    pub product_name: String,
    pub cra_applicable: bool,
    pub ai_act_applicable: bool,
    pub iec62443_applicable: bool,
    pub iso_sae_21434_applicable: bool,
    pub cra_readiness_percent: i64,
    pub ai_act_readiness_percent: i64,
    pub iec62443_readiness_percent: i64,
    pub iso_sae_21434_readiness_percent: i64,
    pub threat_model_coverage_percent: i64,
    pub psirt_readiness_percent: i64,
    pub open_vulnerability_count: i64,
    pub critical_vulnerability_count: i64,
    pub summary: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityOverview {
    pub tenant_id: i64,
    pub matrix: ProductSecurityMatrix,
    pub posture: ProductSecurityPosture,
    pub products: Vec<ProductListItem>,
    pub snapshots: Vec<ProductSecuritySnapshotSummary>,
}

#[derive(Debug, Clone)]
struct TenantProductSecurityContext {
    sector: String,
    develops_digital_products: bool,
    uses_ai_systems: bool,
    ot_iacs_scope: bool,
    automotive_scope: bool,
}

impl ProductSecurityStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Product-Security-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Product-Security-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Rust-Product-Security-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn overview(
        &self,
        tenant_id: i64,
        product_limit: i64,
        snapshot_limit: i64,
    ) -> anyhow::Result<Option<ProductSecurityOverview>> {
        match self {
            Self::Postgres(pool) => {
                overview_postgres(pool, tenant_id, product_limit, snapshot_limit).await
            }
            Self::Sqlite(pool) => {
                overview_sqlite(pool, tenant_id, product_limit, snapshot_limit).await
            }
        }
    }
}

async fn overview_postgres(
    pool: &PgPool,
    tenant_id: i64,
    product_limit: i64,
    snapshot_limit: i64,
) -> anyhow::Result<Option<ProductSecurityOverview>> {
    let Some(context) = sqlx::query(
        r#"
        SELECT sector, develops_digital_products, uses_ai_systems, ot_iacs_scope, automotive_scope
        FROM organizations_tenant
        WHERE id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .context("PostgreSQL-Product-Security-Tenantkontext konnte nicht gelesen werden")?
    .map(tenant_context_from_pg_row)
    .transpose()?
    else {
        return Ok(None);
    };

    let products = sqlx::query(product_list_postgres_sql())
        .bind(tenant_id)
        .bind(product_limit)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Produktliste konnte nicht gelesen werden")?
        .into_iter()
        .map(product_from_pg_row)
        .collect::<Result<Vec<_>, _>>()?;

    let snapshots = sqlx::query(snapshot_list_postgres_sql())
        .bind(tenant_id)
        .bind(snapshot_limit)
        .fetch_all(pool)
        .await
        .context("PostgreSQL-Product-Security-Snapshots konnten nicht gelesen werden")?
        .into_iter()
        .map(snapshot_from_pg_row)
        .collect::<Result<Vec<_>, _>>()?;

    let posture = sqlx::query(posture_postgres_sql())
        .bind(tenant_id)
        .fetch_one(pool)
        .await
        .context("PostgreSQL-Product-Security-Posture konnte nicht gelesen werden")
        .and_then(posture_from_pg_row)?;

    Ok(Some(ProductSecurityOverview {
        tenant_id,
        matrix: build_matrix(&context),
        posture,
        products,
        snapshots,
    }))
}

async fn overview_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    product_limit: i64,
    snapshot_limit: i64,
) -> anyhow::Result<Option<ProductSecurityOverview>> {
    let Some(context) = sqlx::query(
        r#"
        SELECT sector, develops_digital_products, uses_ai_systems, ot_iacs_scope, automotive_scope
        FROM organizations_tenant
        WHERE id = ?
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .context("SQLite-Product-Security-Tenantkontext konnte nicht gelesen werden")?
    .map(tenant_context_from_sqlite_row)
    .transpose()?
    else {
        return Ok(None);
    };

    let products = sqlx::query(product_list_sqlite_sql())
        .bind(tenant_id)
        .bind(product_limit)
        .fetch_all(pool)
        .await
        .context("SQLite-Produktliste konnte nicht gelesen werden")?
        .into_iter()
        .map(product_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()?;

    let snapshots = sqlx::query(snapshot_list_sqlite_sql())
        .bind(tenant_id)
        .bind(snapshot_limit)
        .fetch_all(pool)
        .await
        .context("SQLite-Product-Security-Snapshots konnten nicht gelesen werden")?
        .into_iter()
        .map(snapshot_from_sqlite_row)
        .collect::<Result<Vec<_>, _>>()?;

    let posture = sqlx::query(posture_sqlite_sql())
        .bind(tenant_id)
        .bind(tenant_id)
        .bind(tenant_id)
        .bind(tenant_id)
        .bind(tenant_id)
        .bind(tenant_id)
        .bind(tenant_id)
        .bind(tenant_id)
        .bind(tenant_id)
        .bind(tenant_id)
        .fetch_one(pool)
        .await
        .context("SQLite-Product-Security-Posture konnte nicht gelesen werden")
        .and_then(posture_from_sqlite_row)?;

    Ok(Some(ProductSecurityOverview {
        tenant_id,
        matrix: build_matrix(&context),
        posture,
        products,
        snapshots,
    }))
}

fn product_list_postgres_sql() -> &'static str {
    r#"
    SELECT
        product.id,
        product.tenant_id,
        product.family_id,
        family.name AS family_name,
        product.name,
        product.code,
        product.description,
        product.has_digital_elements,
        product.includes_ai,
        product.ot_iacs_context,
        product.automotive_context,
        product.support_window_months,
        (SELECT COUNT(*) FROM product_security_productrelease rel WHERE rel.product_id = product.id AND rel.tenant_id = product.tenant_id) AS release_count,
        (SELECT COUNT(*) FROM product_security_threatmodel tm WHERE tm.product_id = product.id AND tm.tenant_id = product.tenant_id) AS threat_model_count,
        (SELECT COUNT(*) FROM product_security_tara tara WHERE tara.product_id = product.id AND tara.tenant_id = product.tenant_id) AS tara_count,
        (SELECT COUNT(*) FROM product_security_vulnerability vuln WHERE vuln.product_id = product.id AND vuln.tenant_id = product.tenant_id) AS vulnerability_count,
        (SELECT COUNT(*) FROM product_security_psirtcase psirt WHERE psirt.product_id = product.id AND psirt.tenant_id = product.tenant_id) AS psirt_case_count,
        product.created_at::text AS created_at,
        product.updated_at::text AS updated_at
    FROM product_security_product product
    LEFT JOIN product_security_productfamily family
        ON family.id = product.family_id AND family.tenant_id = product.tenant_id
    WHERE product.tenant_id = $1
    ORDER BY product.name ASC, product.id ASC
    LIMIT $2
    "#
}

fn product_list_sqlite_sql() -> &'static str {
    r#"
    SELECT
        product.id,
        product.tenant_id,
        product.family_id,
        family.name AS family_name,
        product.name,
        product.code,
        product.description,
        product.has_digital_elements,
        product.includes_ai,
        product.ot_iacs_context,
        product.automotive_context,
        product.support_window_months,
        (SELECT COUNT(*) FROM product_security_productrelease rel WHERE rel.product_id = product.id AND rel.tenant_id = product.tenant_id) AS release_count,
        (SELECT COUNT(*) FROM product_security_threatmodel tm WHERE tm.product_id = product.id AND tm.tenant_id = product.tenant_id) AS threat_model_count,
        (SELECT COUNT(*) FROM product_security_tara tara WHERE tara.product_id = product.id AND tara.tenant_id = product.tenant_id) AS tara_count,
        (SELECT COUNT(*) FROM product_security_vulnerability vuln WHERE vuln.product_id = product.id AND vuln.tenant_id = product.tenant_id) AS vulnerability_count,
        (SELECT COUNT(*) FROM product_security_psirtcase psirt WHERE psirt.product_id = product.id AND psirt.tenant_id = product.tenant_id) AS psirt_case_count,
        CAST(product.created_at AS TEXT) AS created_at,
        CAST(product.updated_at AS TEXT) AS updated_at
    FROM product_security_product product
    LEFT JOIN product_security_productfamily family
        ON family.id = product.family_id AND family.tenant_id = product.tenant_id
    WHERE product.tenant_id = ?
    ORDER BY product.name ASC, product.id ASC
    LIMIT ?
    "#
}

fn snapshot_list_postgres_sql() -> &'static str {
    r#"
    SELECT
        snapshot.id,
        snapshot.tenant_id,
        snapshot.product_id,
        product.name AS product_name,
        snapshot.cra_applicable,
        snapshot.ai_act_applicable,
        snapshot.iec62443_applicable,
        snapshot.iso_sae_21434_applicable,
        snapshot.cra_readiness_percent,
        snapshot.ai_act_readiness_percent,
        snapshot.iec62443_readiness_percent,
        snapshot.iso_sae_21434_readiness_percent,
        snapshot.threat_model_coverage_percent,
        snapshot.psirt_readiness_percent,
        snapshot.open_vulnerability_count,
        snapshot.critical_vulnerability_count,
        snapshot.summary,
        snapshot.created_at::text AS created_at,
        snapshot.updated_at::text AS updated_at
    FROM product_security_productsecuritysnapshot snapshot
    INNER JOIN product_security_product product
        ON product.id = snapshot.product_id AND product.tenant_id = snapshot.tenant_id
    WHERE snapshot.tenant_id = $1
    ORDER BY snapshot.created_at DESC, snapshot.id DESC
    LIMIT $2
    "#
}

fn snapshot_list_sqlite_sql() -> &'static str {
    r#"
    SELECT
        snapshot.id,
        snapshot.tenant_id,
        snapshot.product_id,
        product.name AS product_name,
        snapshot.cra_applicable,
        snapshot.ai_act_applicable,
        snapshot.iec62443_applicable,
        snapshot.iso_sae_21434_applicable,
        snapshot.cra_readiness_percent,
        snapshot.ai_act_readiness_percent,
        snapshot.iec62443_readiness_percent,
        snapshot.iso_sae_21434_readiness_percent,
        snapshot.threat_model_coverage_percent,
        snapshot.psirt_readiness_percent,
        snapshot.open_vulnerability_count,
        snapshot.critical_vulnerability_count,
        snapshot.summary,
        CAST(snapshot.created_at AS TEXT) AS created_at,
        CAST(snapshot.updated_at AS TEXT) AS updated_at
    FROM product_security_productsecuritysnapshot snapshot
    INNER JOIN product_security_product product
        ON product.id = snapshot.product_id AND product.tenant_id = snapshot.tenant_id
    WHERE snapshot.tenant_id = ?
    ORDER BY snapshot.created_at DESC, snapshot.id DESC
    LIMIT ?
    "#
}

fn posture_postgres_sql() -> &'static str {
    r#"
    SELECT
        (SELECT COUNT(*) FROM product_security_product WHERE tenant_id = $1) AS products,
        (SELECT COUNT(*) FROM product_security_productrelease WHERE tenant_id = $1 AND status = 'ACTIVE') AS active_releases,
        (SELECT COUNT(*) FROM product_security_threatmodel WHERE tenant_id = $1) AS threat_models,
        (SELECT COUNT(*) FROM product_security_tara WHERE tenant_id = $1) AS taras,
        (SELECT COUNT(*) FROM product_security_vulnerability WHERE tenant_id = $1 AND status NOT IN ('FIXED', 'ACCEPTED')) AS open_vulnerabilities,
        (SELECT COUNT(*) FROM product_security_vulnerability WHERE tenant_id = $1 AND status NOT IN ('FIXED', 'ACCEPTED') AND severity = 'CRITICAL') AS critical_open_vulnerabilities,
        (SELECT COUNT(*) FROM product_security_psirtcase WHERE tenant_id = $1 AND status <> 'CLOSED') AS psirt_cases_open,
        (SELECT COUNT(*) FROM product_security_securityadvisory WHERE tenant_id = $1 AND status = 'PUBLISHED') AS published_advisories,
        COALESCE((SELECT CAST(AVG(threat_model_coverage_percent) AS BIGINT) FROM product_security_productsecuritysnapshot WHERE tenant_id = $1), 0) AS avg_threat_model_coverage,
        COALESCE((SELECT CAST(AVG(psirt_readiness_percent) AS BIGINT) FROM product_security_productsecuritysnapshot WHERE tenant_id = $1), 0) AS avg_psirt_readiness
    "#
}

fn posture_sqlite_sql() -> &'static str {
    r#"
    SELECT
        (SELECT COUNT(*) FROM product_security_product WHERE tenant_id = ?) AS products,
        (SELECT COUNT(*) FROM product_security_productrelease WHERE tenant_id = ? AND status = 'ACTIVE') AS active_releases,
        (SELECT COUNT(*) FROM product_security_threatmodel WHERE tenant_id = ? ) AS threat_models,
        (SELECT COUNT(*) FROM product_security_tara WHERE tenant_id = ?) AS taras,
        (SELECT COUNT(*) FROM product_security_vulnerability WHERE tenant_id = ? AND status NOT IN ('FIXED', 'ACCEPTED')) AS open_vulnerabilities,
        (SELECT COUNT(*) FROM product_security_vulnerability WHERE tenant_id = ? AND status NOT IN ('FIXED', 'ACCEPTED') AND severity = 'CRITICAL') AS critical_open_vulnerabilities,
        (SELECT COUNT(*) FROM product_security_psirtcase WHERE tenant_id = ? AND status <> 'CLOSED') AS psirt_cases_open,
        (SELECT COUNT(*) FROM product_security_securityadvisory WHERE tenant_id = ? AND status = 'PUBLISHED') AS published_advisories,
        COALESCE((SELECT CAST(AVG(threat_model_coverage_percent) AS INTEGER) FROM product_security_productsecuritysnapshot WHERE tenant_id = ?), 0) AS avg_threat_model_coverage,
        COALESCE((SELECT CAST(AVG(psirt_readiness_percent) AS INTEGER) FROM product_security_productsecuritysnapshot WHERE tenant_id = ?), 0) AS avg_psirt_readiness
    "#
}

fn tenant_context_from_pg_row(row: PgRow) -> Result<TenantProductSecurityContext, sqlx::Error> {
    Ok(TenantProductSecurityContext {
        sector: row.try_get("sector")?,
        develops_digital_products: row.try_get("develops_digital_products")?,
        uses_ai_systems: row.try_get("uses_ai_systems")?,
        ot_iacs_scope: row.try_get("ot_iacs_scope")?,
        automotive_scope: row.try_get("automotive_scope")?,
    })
}

fn tenant_context_from_sqlite_row(
    row: SqliteRow,
) -> Result<TenantProductSecurityContext, sqlx::Error> {
    Ok(TenantProductSecurityContext {
        sector: row.try_get("sector")?,
        develops_digital_products: row.try_get("develops_digital_products")?,
        uses_ai_systems: row.try_get("uses_ai_systems")?,
        ot_iacs_scope: row.try_get("ot_iacs_scope")?,
        automotive_scope: row.try_get("automotive_scope")?,
    })
}

fn product_from_pg_row(row: PgRow) -> Result<ProductListItem, sqlx::Error> {
    Ok(ProductListItem {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        family_id: row.try_get("family_id")?,
        family_name: row.try_get("family_name")?,
        name: row.try_get("name")?,
        code: row.try_get("code")?,
        description: row.try_get("description")?,
        has_digital_elements: row.try_get("has_digital_elements")?,
        includes_ai: row.try_get("includes_ai")?,
        ot_iacs_context: row.try_get("ot_iacs_context")?,
        automotive_context: row.try_get("automotive_context")?,
        support_window_months: row.try_get("support_window_months")?,
        release_count: row.try_get("release_count")?,
        threat_model_count: row.try_get("threat_model_count")?,
        tara_count: row.try_get("tara_count")?,
        vulnerability_count: row.try_get("vulnerability_count")?,
        psirt_case_count: row.try_get("psirt_case_count")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn product_from_sqlite_row(row: SqliteRow) -> Result<ProductListItem, sqlx::Error> {
    Ok(ProductListItem {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        family_id: row.try_get("family_id")?,
        family_name: row.try_get("family_name")?,
        name: row.try_get("name")?,
        code: row.try_get("code")?,
        description: row.try_get("description")?,
        has_digital_elements: row.try_get("has_digital_elements")?,
        includes_ai: row.try_get("includes_ai")?,
        ot_iacs_context: row.try_get("ot_iacs_context")?,
        automotive_context: row.try_get("automotive_context")?,
        support_window_months: row.try_get("support_window_months")?,
        release_count: row.try_get("release_count")?,
        threat_model_count: row.try_get("threat_model_count")?,
        tara_count: row.try_get("tara_count")?,
        vulnerability_count: row.try_get("vulnerability_count")?,
        psirt_case_count: row.try_get("psirt_case_count")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn snapshot_from_pg_row(row: PgRow) -> Result<ProductSecuritySnapshotSummary, sqlx::Error> {
    Ok(ProductSecuritySnapshotSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        product_name: row.try_get("product_name")?,
        cra_applicable: row.try_get("cra_applicable")?,
        ai_act_applicable: row.try_get("ai_act_applicable")?,
        iec62443_applicable: row.try_get("iec62443_applicable")?,
        iso_sae_21434_applicable: row.try_get("iso_sae_21434_applicable")?,
        cra_readiness_percent: row.try_get("cra_readiness_percent")?,
        ai_act_readiness_percent: row.try_get("ai_act_readiness_percent")?,
        iec62443_readiness_percent: row.try_get("iec62443_readiness_percent")?,
        iso_sae_21434_readiness_percent: row.try_get("iso_sae_21434_readiness_percent")?,
        threat_model_coverage_percent: row.try_get("threat_model_coverage_percent")?,
        psirt_readiness_percent: row.try_get("psirt_readiness_percent")?,
        open_vulnerability_count: row.try_get("open_vulnerability_count")?,
        critical_vulnerability_count: row.try_get("critical_vulnerability_count")?,
        summary: row.try_get("summary")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn snapshot_from_sqlite_row(row: SqliteRow) -> Result<ProductSecuritySnapshotSummary, sqlx::Error> {
    Ok(ProductSecuritySnapshotSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        product_name: row.try_get("product_name")?,
        cra_applicable: row.try_get("cra_applicable")?,
        ai_act_applicable: row.try_get("ai_act_applicable")?,
        iec62443_applicable: row.try_get("iec62443_applicable")?,
        iso_sae_21434_applicable: row.try_get("iso_sae_21434_applicable")?,
        cra_readiness_percent: row.try_get("cra_readiness_percent")?,
        ai_act_readiness_percent: row.try_get("ai_act_readiness_percent")?,
        iec62443_readiness_percent: row.try_get("iec62443_readiness_percent")?,
        iso_sae_21434_readiness_percent: row.try_get("iso_sae_21434_readiness_percent")?,
        threat_model_coverage_percent: row.try_get("threat_model_coverage_percent")?,
        psirt_readiness_percent: row.try_get("psirt_readiness_percent")?,
        open_vulnerability_count: row.try_get("open_vulnerability_count")?,
        critical_vulnerability_count: row.try_get("critical_vulnerability_count")?,
        summary: row.try_get("summary")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn posture_from_pg_row(row: PgRow) -> anyhow::Result<ProductSecurityPosture> {
    Ok(ProductSecurityPosture {
        products: row.try_get("products")?,
        active_releases: row.try_get("active_releases")?,
        threat_models: row.try_get("threat_models")?,
        taras: row.try_get("taras")?,
        open_vulnerabilities: row.try_get("open_vulnerabilities")?,
        critical_open_vulnerabilities: row.try_get("critical_open_vulnerabilities")?,
        psirt_cases_open: row.try_get("psirt_cases_open")?,
        published_advisories: row.try_get("published_advisories")?,
        avg_threat_model_coverage: row.try_get("avg_threat_model_coverage")?,
        avg_psirt_readiness: row.try_get("avg_psirt_readiness")?,
    })
}

fn posture_from_sqlite_row(row: SqliteRow) -> anyhow::Result<ProductSecurityPosture> {
    Ok(ProductSecurityPosture {
        products: row.try_get("products")?,
        active_releases: row.try_get("active_releases")?,
        threat_models: row.try_get("threat_models")?,
        taras: row.try_get("taras")?,
        open_vulnerabilities: row.try_get("open_vulnerabilities")?,
        critical_open_vulnerabilities: row.try_get("critical_open_vulnerabilities")?,
        psirt_cases_open: row.try_get("psirt_cases_open")?,
        published_advisories: row.try_get("published_advisories")?,
        avg_threat_model_coverage: row.try_get("avg_threat_model_coverage")?,
        avg_psirt_readiness: row.try_get("avg_psirt_readiness")?,
    })
}

fn build_matrix(context: &TenantProductSecurityContext) -> ProductSecurityMatrix {
    let cra = context.develops_digital_products;
    let ai_act = context.uses_ai_systems;
    let iec62443 = context.ot_iacs_scope || is_industrial_sector(&context.sector);
    let iso_sae_21434 = context.automotive_scope;
    let active = [
        (cra, "CRA"),
        (ai_act, "AI Act"),
        (iec62443, "IEC 62443"),
        (iso_sae_21434, "ISO/SAE 21434"),
    ]
    .into_iter()
    .filter_map(|(enabled, label)| enabled.then_some(label))
    .collect::<Vec<_>>();

    ProductSecurityMatrix {
        cra: ProductSecurityMatrixItem {
            applicable: cra,
            label: "CRA".to_string(),
            reason: if cra {
                "Relevant fuer Produkte mit digitalen Elementen und deren Lifecycle.".to_string()
            } else {
                "Derzeit kein klarer Product-with-Digital-Elements-Fokus erkennbar.".to_string()
            },
        },
        ai_act: ProductSecurityMatrixItem {
            applicable: ai_act,
            label: "AI Act".to_string(),
            reason: if ai_act {
                "AI-Systeme/Modelle/Funktionen sind im Scope und erfordern Governance und Dokumentation.".to_string()
            } else {
                "Kein AI-System-/Modell-Scope angegeben.".to_string()
            },
        },
        iec62443: ProductSecurityMatrixItem {
            applicable: iec62443,
            label: "IEC 62443".to_string(),
            reason: if iec62443 {
                "OT-/IACS-/Industrie- oder kritische Anlagenkontexte im Scope.".to_string()
            } else {
                "Kein expliziter OT-/IACS-Kontext im Scope.".to_string()
            },
        },
        iso_sae_21434: ProductSecurityMatrixItem {
            applicable: iso_sae_21434,
            label: "ISO/SAE 21434".to_string(),
            reason: if iso_sae_21434 {
                "Automotive-/Fahrzeug-/E/E-Kontext angegeben.".to_string()
            } else {
                "Kein Automotive-/Fahrzeugkontext im Scope.".to_string()
            },
        },
        summary: if active.is_empty() {
            if context.develops_digital_products {
                "Es werden digitale Produkte entwickelt; mindestens CRA-/Secure-Development-Readiness sollte bewertet werden.".to_string()
            } else {
                "Kein ausgepraegter Product-Security-Scope angegeben. Fokus bleibt auf Enterprise-ISMS.".to_string()
            }
        } else {
            format!(
                "Product Security ist relevant. Aktive Regime/Standards: {}.",
                active.join(", ")
            )
        },
    }
}

fn is_industrial_sector(sector: &str) -> bool {
    matches!(
        sector,
        "ENERGY" | "HYDROGEN" | "DRINKING_WATER" | "WASTEWATER" | "CHEMICALS" | "MANUFACTURING"
    )
}
