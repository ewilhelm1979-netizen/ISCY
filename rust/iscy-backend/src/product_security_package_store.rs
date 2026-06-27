use anyhow::{bail, Context};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{postgres::PgRow, sqlite::SqliteRow, Row};

use crate::product_security_store::{
    ProductSecurityCveRiskReviewSummary, ProductSecurityDetail, ProductSecurityStore,
};

#[derive(Debug, Clone, Deserialize)]
pub struct ProductSecurityEvidencePackageCreateRequest {
    pub product_id: i64,
    pub release_id: Option<i64>,
    pub psirt_case_id: Option<i64>,
    pub package_type: String,
    pub title: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProductSecurityEvidencePackageReviewRequest {
    pub status: String,
    pub decision: String,
    pub review_notes: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityEvidencePackageSummary {
    pub id: i64,
    pub tenant_id: i64,
    pub product_id: i64,
    pub product_name: String,
    pub release_id: Option<i64>,
    pub release_version: Option<String>,
    pub psirt_case_id: Option<i64>,
    pub psirt_case_identifier: Option<String>,
    pub supersedes_id: Option<i64>,
    pub package_type: String,
    pub package_type_label: String,
    pub version_number: i64,
    pub title: String,
    pub status: String,
    pub status_label: String,
    pub decision: String,
    pub decision_label: String,
    pub readiness_percent: i64,
    pub blocker_count: i64,
    pub warning_count: i64,
    pub summary: String,
    pub review_notes: String,
    pub created_by_id: Option<i64>,
    pub reviewed_by_id: Option<i64>,
    pub reviewed_at: Option<String>,
    pub approved_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityEvidencePackageItem {
    pub id: i64,
    pub tenant_id: i64,
    pub package_id: i64,
    pub category: String,
    pub category_label: String,
    pub source_type: String,
    pub source_id: Option<i64>,
    pub reference_key: String,
    pub title: String,
    pub status: String,
    pub status_label: String,
    pub required: bool,
    pub blocker: bool,
    pub detail: String,
    pub href: String,
    pub metadata: Value,
    pub sort_order: i64,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductSecurityEvidencePackageDetail {
    pub package: ProductSecurityEvidencePackageSummary,
    pub items: Vec<ProductSecurityEvidencePackageItem>,
    pub snapshot: Value,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ProductSecurityEvidencePackageMetrics {
    pub total: i64,
    pub draft: i64,
    pub in_review: i64,
    pub approved: i64,
    pub changes_requested: i64,
    pub packages_with_blockers: i64,
}

#[derive(Debug, Clone)]
struct PackageDraftItem {
    category: String,
    source_type: String,
    source_id: Option<i64>,
    reference_key: String,
    title: String,
    status: String,
    required: bool,
    blocker: bool,
    detail: String,
    href: String,
    metadata: Value,
    sort_order: i64,
}

#[derive(Debug)]
struct PackageDraft {
    product_id: i64,
    release_id: Option<i64>,
    psirt_case_id: Option<i64>,
    supersedes_id: Option<i64>,
    package_type: String,
    version_number: i64,
    title: String,
    readiness_percent: i64,
    blocker_count: i64,
    warning_count: i64,
    summary: String,
    snapshot: Value,
    items: Vec<PackageDraftItem>,
}

#[derive(Debug)]
struct PackageImportArtifact {
    id: i64,
    file_name: String,
    document_id: String,
    format_name: String,
    format_version: String,
    validation_status: String,
    component_count: i64,
    matched_component_count: i64,
    created_at: String,
}

#[derive(Debug)]
struct PackageEvidenceReference {
    id: i64,
    title: String,
    status: String,
    file_name: Option<String>,
    created_at: String,
}

impl ProductSecurityStore {
    pub async fn evidence_packages(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<ProductSecurityEvidencePackageSummary>> {
        let limit = limit.clamp(1, 1000);
        match self {
            Self::Postgres(pool) => {
                let rows = sqlx::query(&format!(
                    "{} WHERE package.tenant_id=$1 ORDER BY package.created_at DESC, package.id DESC LIMIT $2",
                    package_summary_select_sql(true)
                ))
                .bind(tenant_id)
                .bind(limit)
                .fetch_all(pool)
                .await
                .context("PostgreSQL-Evidence-Pakete konnten nicht gelesen werden")?;
                rows.into_iter()
                    .map(package_from_pg_row)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(Into::into)
            }
            Self::Sqlite(pool) => {
                let rows = sqlx::query(&format!(
                    "{} WHERE package.tenant_id=?1 ORDER BY package.created_at DESC, package.id DESC LIMIT ?2",
                    package_summary_select_sql(false)
                ))
                .bind(tenant_id)
                .bind(limit)
                .fetch_all(pool)
                .await
                .context("SQLite-Evidence-Pakete konnten nicht gelesen werden")?;
                rows.into_iter()
                    .map(package_from_sqlite_row)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(Into::into)
            }
        }
    }

    pub async fn evidence_package_detail(
        &self,
        tenant_id: i64,
        package_id: i64,
    ) -> anyhow::Result<Option<ProductSecurityEvidencePackageDetail>> {
        let package = match self {
            Self::Postgres(pool) => sqlx::query(&format!(
                "{} WHERE package.tenant_id=$1 AND package.id=$2",
                package_summary_select_sql(true)
            ))
            .bind(tenant_id)
            .bind(package_id)
            .fetch_optional(pool)
            .await
            .context("PostgreSQL-Evidence-Paket konnte nicht gelesen werden")?
            .map(package_from_pg_row)
            .transpose()?,
            Self::Sqlite(pool) => sqlx::query(&format!(
                "{} WHERE package.tenant_id=?1 AND package.id=?2",
                package_summary_select_sql(false)
            ))
            .bind(tenant_id)
            .bind(package_id)
            .fetch_optional(pool)
            .await
            .context("SQLite-Evidence-Paket konnte nicht gelesen werden")?
            .map(package_from_sqlite_row)
            .transpose()?,
        };
        let Some(package) = package else {
            return Ok(None);
        };
        let (items, snapshot) = match self {
            Self::Postgres(pool) => {
                let items = sqlx::query(package_items_postgres_sql())
                    .bind(tenant_id)
                    .bind(package_id)
                    .fetch_all(pool)
                    .await
                    .context("PostgreSQL-Evidence-Paketpositionen konnten nicht gelesen werden")?
                    .into_iter()
                    .map(package_item_from_pg_row)
                    .collect::<Result<Vec<_>, _>>()?;
                let raw: String = sqlx::query_scalar(
                    "SELECT snapshot_json FROM product_security_evidencepackage WHERE tenant_id=$1 AND id=$2",
                )
                .bind(tenant_id)
                .bind(package_id)
                .fetch_one(pool)
                .await?;
                (items, parse_json_object(&raw))
            }
            Self::Sqlite(pool) => {
                let items = sqlx::query(package_items_sqlite_sql())
                    .bind(tenant_id)
                    .bind(package_id)
                    .fetch_all(pool)
                    .await
                    .context("SQLite-Evidence-Paketpositionen konnten nicht gelesen werden")?
                    .into_iter()
                    .map(package_item_from_sqlite_row)
                    .collect::<Result<Vec<_>, _>>()?;
                let raw: String = sqlx::query_scalar(
                    "SELECT snapshot_json FROM product_security_evidencepackage WHERE tenant_id=?1 AND id=?2",
                )
                .bind(tenant_id)
                .bind(package_id)
                .fetch_one(pool)
                .await?;
                (items, parse_json_object(&raw))
            }
        };
        Ok(Some(ProductSecurityEvidencePackageDetail {
            package,
            items,
            snapshot,
        }))
    }

    pub async fn create_evidence_package(
        &self,
        tenant_id: i64,
        user_id: i64,
        payload: ProductSecurityEvidencePackageCreateRequest,
    ) -> anyhow::Result<ProductSecurityEvidencePackageDetail> {
        self.create_evidence_package_version(tenant_id, user_id, payload, None)
            .await
    }

    pub async fn refresh_evidence_package(
        &self,
        tenant_id: i64,
        package_id: i64,
        user_id: i64,
    ) -> anyhow::Result<Option<ProductSecurityEvidencePackageDetail>> {
        let Some(current) = self.evidence_package_detail(tenant_id, package_id).await? else {
            return Ok(None);
        };
        let payload = ProductSecurityEvidencePackageCreateRequest {
            product_id: current.package.product_id,
            release_id: current.package.release_id,
            psirt_case_id: current.package.psirt_case_id,
            package_type: current.package.package_type,
            title: Some(current.package.title),
        };
        self.create_evidence_package_version(tenant_id, user_id, payload, Some(package_id))
            .await
            .map(Some)
    }

    pub async fn review_evidence_package(
        &self,
        tenant_id: i64,
        package_id: i64,
        user_id: i64,
        payload: ProductSecurityEvidencePackageReviewRequest,
    ) -> anyhow::Result<Option<ProductSecurityEvidencePackageDetail>> {
        let Some(current) = self.evidence_package_detail(tenant_id, package_id).await? else {
            return Ok(None);
        };
        let payload = validate_review_payload(payload, &current.package)?;
        match self {
            Self::Postgres(pool) => {
                sqlx::query(
                    r#"UPDATE product_security_evidencepackage
                       SET status=$1, decision=$2, review_notes=$3,
                           reviewed_by_id=CASE WHEN $1='DRAFT' THEN NULL ELSE $4 END,
                           reviewed_at=CASE WHEN $1='DRAFT' THEN NULL ELSE CURRENT_TIMESTAMP::text END,
                           approved_at=CASE WHEN $1='APPROVED' THEN CURRENT_TIMESTAMP::text ELSE NULL END,
                           updated_at=CURRENT_TIMESTAMP::text
                       WHERE tenant_id=$5 AND id=$6"#,
                )
                .bind(&payload.status)
                .bind(&payload.decision)
                .bind(&payload.review_notes)
                .bind(user_id)
                .bind(tenant_id)
                .bind(package_id)
                .execute(pool)
                .await
                .context("PostgreSQL-Evidence-Paketreview konnte nicht gespeichert werden")?;
            }
            Self::Sqlite(pool) => {
                sqlx::query(
                    r#"UPDATE product_security_evidencepackage
                       SET status=?1, decision=?2, review_notes=?3,
                           reviewed_by_id=CASE WHEN ?1='DRAFT' THEN NULL ELSE ?4 END,
                           reviewed_at=CASE WHEN ?1='DRAFT' THEN NULL ELSE CURRENT_TIMESTAMP END,
                           approved_at=CASE WHEN ?1='APPROVED' THEN CURRENT_TIMESTAMP ELSE NULL END,
                           updated_at=CURRENT_TIMESTAMP
                       WHERE tenant_id=?5 AND id=?6"#,
                )
                .bind(&payload.status)
                .bind(&payload.decision)
                .bind(&payload.review_notes)
                .bind(user_id)
                .bind(tenant_id)
                .bind(package_id)
                .execute(pool)
                .await
                .context("SQLite-Evidence-Paketreview konnte nicht gespeichert werden")?;
            }
        }
        self.evidence_package_detail(tenant_id, package_id).await
    }

    pub async fn evidence_package_metrics(
        &self,
        tenant_id: i64,
    ) -> anyhow::Result<ProductSecurityEvidencePackageMetrics> {
        let packages = self.evidence_packages(tenant_id, 1000).await?;
        Ok(ProductSecurityEvidencePackageMetrics {
            total: packages.len() as i64,
            draft: packages
                .iter()
                .filter(|item| item.status == "DRAFT")
                .count() as i64,
            in_review: packages
                .iter()
                .filter(|item| item.status == "IN_REVIEW")
                .count() as i64,
            approved: packages
                .iter()
                .filter(|item| item.status == "APPROVED")
                .count() as i64,
            changes_requested: packages
                .iter()
                .filter(|item| item.status == "CHANGES_REQUESTED")
                .count() as i64,
            packages_with_blockers: packages
                .iter()
                .filter(|item| item.blocker_count > 0 && item.status != "ARCHIVED")
                .count() as i64,
        })
    }

    async fn create_evidence_package_version(
        &self,
        tenant_id: i64,
        user_id: i64,
        payload: ProductSecurityEvidencePackageCreateRequest,
        supersedes_id: Option<i64>,
    ) -> anyhow::Result<ProductSecurityEvidencePackageDetail> {
        let payload = validate_create_payload(payload)?;
        let detail = self
            .detail(tenant_id, payload.product_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Produkt wurde fuer diesen Tenant nicht gefunden"))?;
        let package_type = payload.package_type.as_str();
        let release = payload
            .release_id
            .and_then(|id| detail.releases.iter().find(|item| item.id == id));
        let psirt_case = payload
            .psirt_case_id
            .and_then(|id| detail.psirt_cases.iter().find(|item| item.id == id));
        if payload.release_id.is_some() && release.is_none() {
            bail!("Release wurde fuer Produkt und Tenant nicht gefunden");
        }
        if payload.psirt_case_id.is_some() && psirt_case.is_none() {
            bail!("PSIRT-Case wurde fuer Produkt und Tenant nicht gefunden");
        }
        if package_type == "RELEASE" && release.is_none() {
            bail!("Ein Release-Evidence-Paket benoetigt release_id");
        }
        if package_type == "PSIRT" && psirt_case.is_none() {
            bail!("Ein PSIRT-Evidence-Paket benoetigt psirt_case_id");
        }
        let effective_release_id = release
            .map(|item| item.id)
            .or_else(|| psirt_case.and_then(|item| item.release_id));
        let version_number = self
            .next_evidence_package_version(
                tenant_id,
                package_type,
                payload.product_id,
                effective_release_id,
                payload.psirt_case_id,
            )
            .await?;
        let sbom = self
            .latest_package_import(tenant_id, payload.product_id, "SBOM")
            .await?;
        let evidence_key =
            package_evidence_key(package_type, effective_release_id, payload.psirt_case_id);
        let evidence = self
            .package_evidence_references(tenant_id, &evidence_key)
            .await?;
        let risk_reviews = self
            .overview(tenant_id, 500, 1)
            .await?
            .map(|overview| {
                overview
                    .cve_risk_review_queue
                    .into_iter()
                    .filter(|item| item.product_id == Some(payload.product_id))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let draft = build_package_draft(
            &detail,
            &payload,
            effective_release_id,
            supersedes_id,
            version_number,
            sbom,
            evidence,
            risk_reviews,
        )?;
        let package_id = match self {
            Self::Postgres(pool) => {
                insert_package_postgres(pool, tenant_id, user_id, &draft).await?
            }
            Self::Sqlite(pool) => insert_package_sqlite(pool, tenant_id, user_id, &draft).await?,
        };
        self.evidence_package_detail(tenant_id, package_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Erstelltes Evidence-Paket konnte nicht gelesen werden"))
    }

    async fn next_evidence_package_version(
        &self,
        tenant_id: i64,
        package_type: &str,
        product_id: i64,
        release_id: Option<i64>,
        psirt_case_id: Option<i64>,
    ) -> anyhow::Result<i64> {
        let current = match self {
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(
                    r#"SELECT COALESCE(MAX(version_number),0)
                   FROM product_security_evidencepackage
                   WHERE tenant_id=$1 AND package_type=$2 AND product_id=$3
                     AND release_id IS NOT DISTINCT FROM $4
                     AND psirt_case_id IS NOT DISTINCT FROM $5"#,
                )
                .bind(tenant_id)
                .bind(package_type)
                .bind(product_id)
                .bind(release_id)
                .bind(psirt_case_id)
                .fetch_one(pool)
                .await?
            }
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(
                    r#"SELECT COALESCE(MAX(version_number),0)
                   FROM product_security_evidencepackage
                   WHERE tenant_id=?1 AND package_type=?2 AND product_id=?3
                     AND (release_id=?4 OR (release_id IS NULL AND ?4 IS NULL))
                     AND (psirt_case_id=?5 OR (psirt_case_id IS NULL AND ?5 IS NULL))"#,
                )
                .bind(tenant_id)
                .bind(package_type)
                .bind(product_id)
                .bind(release_id)
                .bind(psirt_case_id)
                .fetch_one(pool)
                .await?
            }
        };
        Ok(current + 1)
    }

    async fn latest_package_import(
        &self,
        tenant_id: i64,
        product_id: i64,
        artifact_type: &str,
    ) -> anyhow::Result<Option<PackageImportArtifact>> {
        let artifact = match self {
            Self::Postgres(pool) => sqlx::query(
                r#"SELECT id,file_name,document_id,format_name,format_version,validation_status,
                          component_count,matched_component_count,created_at::text AS created_at
                   FROM product_security_importartifact
                   WHERE tenant_id=$1 AND product_id=$2 AND artifact_type=$3
                     AND validation_status <> 'INVALID'
                   ORDER BY created_at DESC,id DESC LIMIT 1"#,
            )
            .bind(tenant_id)
            .bind(product_id)
            .bind(artifact_type)
            .fetch_optional(pool)
            .await
            .context("PostgreSQL-Importartefakt fuer Evidence-Paket konnte nicht gelesen werden")?
            .map(import_from_pg_row)
            .transpose()?,
            Self::Sqlite(pool) => sqlx::query(
                r#"SELECT id,file_name,document_id,format_name,format_version,validation_status,
                          component_count,matched_component_count,CAST(created_at AS TEXT) AS created_at
                   FROM product_security_importartifact
                   WHERE tenant_id=?1 AND product_id=?2 AND artifact_type=?3
                     AND validation_status <> 'INVALID'
                   ORDER BY created_at DESC,id DESC LIMIT 1"#,
            )
            .bind(tenant_id)
            .bind(product_id)
            .bind(artifact_type)
            .fetch_optional(pool)
            .await
            .context("SQLite-Importartefakt fuer Evidence-Paket konnte nicht gelesen werden")?
            .map(import_from_sqlite_row)
            .transpose()?,
        };
        Ok(artifact)
    }

    async fn package_evidence_references(
        &self,
        tenant_id: i64,
        evidence_key: &str,
    ) -> anyhow::Result<Vec<PackageEvidenceReference>> {
        let references = match self {
            Self::Postgres(pool) => sqlx::query(
                r#"SELECT id,title,status,file AS file_name,created_at::text AS created_at
                   FROM evidence_evidenceitem
                   WHERE tenant_id=$1 AND linked_requirement=$2
                   ORDER BY created_at DESC,id DESC"#,
            )
            .bind(tenant_id)
            .bind(evidence_key)
            .fetch_all(pool)
            .await
            .context("PostgreSQL-Evidence fuer Product-Security-Paket konnte nicht gelesen werden")?
            .into_iter()
            .map(evidence_from_pg_row)
            .collect::<Result<Vec<_>, _>>()?,
            Self::Sqlite(pool) => sqlx::query(
                r#"SELECT id,title,status,file AS file_name,CAST(created_at AS TEXT) AS created_at
                   FROM evidence_evidenceitem
                   WHERE tenant_id=?1 AND linked_requirement=?2
                   ORDER BY created_at DESC,id DESC"#,
            )
            .bind(tenant_id)
            .bind(evidence_key)
            .fetch_all(pool)
            .await
            .context("SQLite-Evidence fuer Product-Security-Paket konnte nicht gelesen werden")?
            .into_iter()
            .map(evidence_from_sqlite_row)
            .collect::<Result<Vec<_>, _>>()?,
        };
        Ok(references)
    }
}

#[allow(clippy::too_many_arguments)]
fn build_package_draft(
    detail: &ProductSecurityDetail,
    payload: &ProductSecurityEvidencePackageCreateRequest,
    release_id: Option<i64>,
    supersedes_id: Option<i64>,
    version_number: i64,
    sbom: Option<PackageImportArtifact>,
    evidence: Vec<PackageEvidenceReference>,
    risk_reviews: Vec<ProductSecurityCveRiskReviewSummary>,
) -> anyhow::Result<PackageDraft> {
    let package_type = payload.package_type.as_str();
    let release = release_id.and_then(|id| detail.releases.iter().find(|item| item.id == id));
    let psirt_case = payload
        .psirt_case_id
        .and_then(|id| detail.psirt_cases.iter().find(|item| item.id == id));
    let title = payload
        .title
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| match package_type {
            "PSIRT" => format!(
                "PSIRT Evidence Package {}",
                psirt_case
                    .map(|item| item.case_id.as_str())
                    .unwrap_or("unbekannt")
            ),
            _ => format!(
                "Release Evidence Package {} {}",
                detail.product.name,
                release
                    .map(|item| item.version.as_str())
                    .unwrap_or("unbekannt")
            ),
        });
    let evidence_key = package_evidence_key(package_type, release_id, payload.psirt_case_id);
    let mut items = Vec::new();
    let mut sort_order = 10_i64;

    if let Some(release) = release {
        push_draft_item(
            &mut items,
            &mut sort_order,
            "RELEASE",
            "RELEASE",
            Some(release.id),
            format!("PRODUCT_SECURITY:RELEASE:{}", release.id),
            format!("Release {}", release.version),
            "READY",
            true,
            false,
            format!(
                "Status {}; Release-Datum {}.",
                release.status_label,
                release.release_date.as_deref().unwrap_or("nicht gesetzt")
            ),
            "/product-security/".to_string(),
            json!({
                "version": release.version,
                "status": release.status,
                "release_date": release.release_date,
                "support_end_date": release.support_end_date,
            }),
        );
        let support_ready = release
            .support_end_date
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
        push_draft_item(
            &mut items,
            &mut sort_order,
            "LIFECYCLE",
            "RELEASE",
            Some(release.id),
            format!("PRODUCT_SECURITY:RELEASE:{}:SUPPORT", release.id),
            "Support-Ende und Update-Zeitraum".to_string(),
            if support_ready { "READY" } else { "MISSING" },
            true,
            !support_ready,
            release
                .support_end_date
                .as_deref()
                .map(|value| format!("Support-Ende: {value}."))
                .unwrap_or_else(|| {
                    "Support-Ende ist nicht dokumentiert; die Produktvorgabe ersetzt kein konkretes Release-Datum."
                        .to_string()
                }),
            "/product-security/".to_string(),
            json!({"support_end_date": release.support_end_date}),
        );
    }

    if let Some(case) = psirt_case {
        let closed = matches!(case.status.as_str(), "CLOSED" | "RESOLVED" | "PUBLISHED");
        push_draft_item(
            &mut items,
            &mut sort_order,
            "PSIRT",
            "PSIRT_CASE",
            Some(case.id),
            format!("PRODUCT_SECURITY:PSIRT:{}", case.id),
            format!("{} · {}", case.case_id, case.title),
            if closed { "READY" } else { "WARN" },
            true,
            false,
            format!(
                "Severity {}; Status {}; Disclosure-Faelligkeit {}.",
                case.severity_label,
                case.status_label,
                case.disclosure_due.as_deref().unwrap_or("nicht gesetzt")
            ),
            "/product-security/".to_string(),
            json!({
                "case_id": case.case_id,
                "severity": case.severity,
                "status": case.status,
                "disclosure_due": case.disclosure_due,
            }),
        );
    }

    match sbom {
        Some(sbom) => {
            let complete_match =
                sbom.component_count == 0 || sbom.matched_component_count >= sbom.component_count;
            push_draft_item(
                &mut items,
                &mut sort_order,
                "SBOM",
                "IMPORT_ARTIFACT",
                Some(sbom.id),
                format!("PRODUCT_SECURITY:IMPORT:{}", sbom.id),
                format!("SBOM {}", sbom.file_name),
                if complete_match { "READY" } else { "WARN" },
                true,
                false,
                format!(
                    "{} {} · Validierung {} · {}/{} Komponenten zugeordnet.",
                    sbom.format_name,
                    sbom.format_version,
                    sbom.validation_status,
                    sbom.matched_component_count,
                    sbom.component_count
                ),
                format!("/product-security/imports/{}", sbom.id),
                json!({
                    "artifact_id": sbom.id,
                    "document_id": sbom.document_id,
                    "format": sbom.format_name,
                    "format_version": sbom.format_version,
                    "validation_status": sbom.validation_status,
                    "component_count": sbom.component_count,
                    "matched_component_count": sbom.matched_component_count,
                    "created_at": sbom.created_at,
                }),
            );
        }
        None => push_draft_item(
            &mut items,
            &mut sort_order,
            "SBOM",
            "IMPORT_ARTIFACT",
            None,
            format!("PRODUCT_SECURITY:PRODUCT:{}:SBOM", detail.product.id),
            "Validierte SBOM".to_string(),
            "MISSING",
            true,
            true,
            "Kein valides CycloneDX-/SPDX-Importartefakt fuer dieses Produkt vorhanden."
                .to_string(),
            "/product-security/".to_string(),
            json!({}),
        ),
    }

    let scoped_vulnerabilities = detail
        .vulnerabilities
        .iter()
        .filter(|vulnerability| {
            if let Some(case) = psirt_case {
                if let Some(vulnerability_id) = case.vulnerability_id {
                    return vulnerability.id == vulnerability_id;
                }
            }
            release_id.is_none()
                || vulnerability.release_id.is_none()
                || vulnerability.release_id == release_id
        })
        .collect::<Vec<_>>();
    if scoped_vulnerabilities.is_empty() {
        push_draft_item(
            &mut items,
            &mut sort_order,
            "VEX",
            "VULNERABILITY_SET",
            None,
            format!("{evidence_key}:VEX"),
            "VEX-/Schwachstellenlage".to_string(),
            "READY",
            true,
            false,
            "Im Paket-Scope sind keine bekannten Product-Security-Schwachstellen erfasst."
                .to_string(),
            "/product-security/".to_string(),
            json!({"vulnerability_count": 0}),
        );
    } else {
        for vulnerability in &scoped_vulnerabilities {
            let severe = matches!(vulnerability.severity.as_str(), "CRITICAL" | "HIGH");
            let open = !matches!(
                vulnerability.status.as_str(),
                "CLOSED" | "RESOLVED" | "FIXED" | "ACCEPTED"
            );
            let vex_complete = vulnerability.vex_status != "UNDER_INVESTIGATION"
                && !vulnerability.vex_justification.trim().is_empty()
                && (vulnerability.vex_status != "FIXED"
                    || !vulnerability.fixed_version.trim().is_empty());
            let blocker = severe
                && open
                && matches!(
                    vulnerability.vex_status.as_str(),
                    "AFFECTED" | "UNDER_INVESTIGATION"
                );
            let status = if blocker {
                "BLOCKED"
            } else if vex_complete {
                "READY"
            } else {
                "WARN"
            };
            push_draft_item(
                &mut items,
                &mut sort_order,
                "VEX",
                "VULNERABILITY",
                Some(vulnerability.id),
                if vulnerability.cve.trim().is_empty() {
                    format!("PRODUCT_SECURITY:VULNERABILITY:{}", vulnerability.id)
                } else {
                    format!("PRODUCT_SECURITY:CVE:{}", vulnerability.cve)
                },
                if vulnerability.cve.trim().is_empty() {
                    vulnerability.title.clone()
                } else {
                    format!("{} · {}", vulnerability.cve, vulnerability.title)
                },
                status,
                true,
                blocker,
                format!(
                    "Severity {}; Status {}; VEX {}{}.",
                    vulnerability.severity_label,
                    vulnerability.status_label,
                    vulnerability.vex_status_label,
                    if vulnerability.vex_justification.trim().is_empty() {
                        "; Begruendung fehlt"
                    } else {
                        ""
                    }
                ),
                "/product-security/".to_string(),
                json!({
                    "cve": vulnerability.cve,
                    "severity": vulnerability.severity,
                    "status": vulnerability.status,
                    "vex_status": vulnerability.vex_status,
                    "vex_justification": vulnerability.vex_justification,
                    "fixed_version": vulnerability.fixed_version,
                    "vex_updated_at": vulnerability.vex_updated_at,
                }),
            );
        }
    }

    let scoped_advisories = detail
        .advisories
        .iter()
        .filter(|advisory| {
            payload
                .psirt_case_id
                .is_some_and(|id| advisory.psirt_case_id == Some(id))
                || (payload.psirt_case_id.is_none()
                    && (release_id.is_none()
                        || advisory.release_id.is_none()
                        || advisory.release_id == release_id))
        })
        .collect::<Vec<_>>();
    let advisory_required = package_type == "PSIRT"
        || scoped_vulnerabilities.iter().any(|vulnerability| {
            vulnerability.vex_status == "AFFECTED"
                && matches!(vulnerability.severity.as_str(), "CRITICAL" | "HIGH")
        });
    if scoped_advisories.is_empty() {
        push_draft_item(
            &mut items,
            &mut sort_order,
            "ADVISORY",
            "ADVISORY_SET",
            None,
            format!("{evidence_key}:ADVISORY"),
            "Security Advisory / CSAF".to_string(),
            if advisory_required { "MISSING" } else { "INFO" },
            advisory_required,
            advisory_required,
            if advisory_required {
                "Fuer den betroffenen PSIRT-/VEX-Scope fehlt ein Security Advisory."
            } else {
                "Im aktuellen Scope ist kein Advisory erforderlich dokumentiert."
            }
            .to_string(),
            "/product-security/".to_string(),
            json!({}),
        );
    } else {
        for advisory in &scoped_advisories {
            let published = matches!(advisory.status.as_str(), "PUBLISHED" | "FINAL" | "INTERIM");
            let blocker = advisory_required && !published;
            push_draft_item(
                &mut items,
                &mut sort_order,
                "ADVISORY",
                "SECURITY_ADVISORY",
                Some(advisory.id),
                if advisory.csaf_document_id.trim().is_empty() {
                    format!("PRODUCT_SECURITY:ADVISORY:{}", advisory.id)
                } else {
                    advisory.csaf_document_id.clone()
                },
                format!("{} · {}", advisory.advisory_id, advisory.title),
                if blocker {
                    "BLOCKED"
                } else if published {
                    "READY"
                } else {
                    "WARN"
                },
                advisory_required,
                blocker,
                format!(
                    "Status {}; CSAF-Profil {}; Revision {}.",
                    advisory.status_label,
                    empty_as_dash(&advisory.csaf_profile),
                    empty_as_dash(&advisory.csaf_revision)
                ),
                "/product-security/".to_string(),
                json!({
                    "advisory_id": advisory.advisory_id,
                    "status": advisory.status,
                    "published_on": advisory.published_on,
                    "csaf_document_id": advisory.csaf_document_id,
                    "csaf_profile": advisory.csaf_profile,
                    "csaf_revision": advisory.csaf_revision,
                    "cves": advisory.cve_list,
                }),
            );
        }
    }

    for review in risk_reviews {
        let relevant = scoped_vulnerabilities.iter().any(|vulnerability| {
            !vulnerability.cve.trim().is_empty()
                && vulnerability.cve.eq_ignore_ascii_case(&review.cve)
        });
        if !relevant {
            continue;
        }
        let blocker = review.risk_id.is_none();
        push_draft_item(
            &mut items,
            &mut sort_order,
            "RISK",
            "CVE_RISK",
            review.risk_id,
            review.evidence_key.clone(),
            review
                .risk_title
                .clone()
                .unwrap_or_else(|| format!("Risiko fuer {} fehlt", review.cve)),
            if blocker { "MISSING" } else { "READY" },
            true,
            blocker,
            format!(
                "CVE {}; Risiko {}; Evidence {}.",
                review.cve,
                review.risk_status_label,
                if review.evidence_missing {
                    "fehlt"
                } else {
                    "vorhanden"
                }
            ),
            review
                .risk_id
                .map(|id| format!("/risks/{id}"))
                .unwrap_or_else(|| "/product-security/".to_string()),
            json!({
                "cve": review.cve,
                "risk_id": review.risk_id,
                "risk_status": review.risk_status,
                "roadmap_task_id": review.roadmap_task_id,
                "evidence_count": review.evidence_count,
            }),
        );
    }

    for task in detail.roadmap_tasks.iter().filter(|task| {
        (release_id.is_none()
            || task.related_release_id.is_none()
            || task.related_release_id == release_id)
            && !matches!(task.status.as_str(), "DONE" | "CLOSED" | "CANCELLED")
    }) {
        let blocker = matches!(task.priority.as_str(), "CRITICAL" | "HIGH");
        push_draft_item(
            &mut items,
            &mut sort_order,
            "ROADMAP",
            "ROADMAP_TASK",
            Some(task.id),
            format!("PRODUCT_SECURITY:ROADMAP_TASK:{}", task.id),
            task.title.clone(),
            if blocker { "BLOCKED" } else { "WARN" },
            false,
            blocker,
            format!(
                "Prioritaet {}; Status {}; Owner {}; faellig in {} Tagen.",
                task.priority, task.status_label, task.owner_role, task.due_in_days
            ),
            "/product-security/".to_string(),
            json!({
                "priority": task.priority,
                "status": task.status,
                "owner_role": task.owner_role,
                "due_in_days": task.due_in_days,
            }),
        );
    }

    if evidence.is_empty() {
        push_draft_item(
            &mut items,
            &mut sort_order,
            "EVIDENCE",
            "EVIDENCE_ITEM",
            None,
            evidence_key.clone(),
            "Ergaenzende Freigabe-Evidence".to_string(),
            "WARN",
            false,
            false,
            "Noch kein expliziter Nachweis fuer diesen Release-/PSIRT-Scope verknuepft."
                .to_string(),
            format!(
                "/evidence/?linked_requirement={}",
                percent_encode_query_value(&evidence_key)
            ),
            json!({"linked_requirement": evidence_key}),
        );
    } else {
        for evidence in evidence {
            let ready = matches!(
                evidence.status.as_str(),
                "APPROVED" | "ACCEPTED" | "SUBMITTED"
            ) && evidence
                .file_name
                .as_deref()
                .is_some_and(|file| !file.is_empty());
            push_draft_item(
                &mut items,
                &mut sort_order,
                "EVIDENCE",
                "EVIDENCE_ITEM",
                Some(evidence.id),
                evidence_key.clone(),
                evidence.title,
                if ready { "READY" } else { "WARN" },
                false,
                false,
                format!(
                    "Status {}; Datei {}; angelegt {}.",
                    evidence.status,
                    evidence.file_name.as_deref().unwrap_or("fehlt"),
                    evidence.created_at
                ),
                "/evidence/".to_string(),
                json!({
                    "status": evidence.status,
                    "file_name": evidence.file_name,
                    "created_at": evidence.created_at,
                }),
            );
        }
    }

    let required_count = items.iter().filter(|item| item.required).count() as i64;
    let ready_required = items
        .iter()
        .filter(|item| item.required && item.status == "READY")
        .count() as i64;
    let readiness_percent = if required_count == 0 {
        100
    } else {
        (ready_required * 100 / required_count).clamp(0, 100)
    };
    let blocker_count = items.iter().filter(|item| item.blocker).count() as i64;
    let warning_count = items
        .iter()
        .filter(|item| !item.blocker && matches!(item.status.as_str(), "WARN" | "MISSING"))
        .count() as i64;
    let summary = format!(
        "{}% Nachweisreife; {} Blocker; {} Hinweise; {} eingefrorene Positionen.",
        readiness_percent,
        blocker_count,
        warning_count,
        items.len()
    );
    let snapshot = json!({
        "generated_at": Utc::now().to_rfc3339(),
        "product": {
            "id": detail.product.id,
            "name": detail.product.name,
            "code": detail.product.code,
            "has_digital_elements": detail.product.has_digital_elements,
            "support_window_months": detail.product.support_window_months,
        },
        "scope": {
            "package_type": package_type,
            "release_id": release_id,
            "release_version": release.map(|item| item.version.clone()),
            "psirt_case_id": payload.psirt_case_id,
            "psirt_case_identifier": psirt_case.map(|item| item.case_id.clone()),
            "evidence_key": evidence_key,
        },
        "readiness": {
            "percent": readiness_percent,
            "required_items": required_count,
            "ready_required_items": ready_required,
            "blockers": blocker_count,
            "warnings": warning_count,
        },
        "counts": {
            "components": detail.components.len(),
            "vulnerabilities": scoped_vulnerabilities.len(),
            "advisories": scoped_advisories.len(),
            "psirt_cases": detail.psirt_cases.len(),
            "roadmap_tasks": detail.roadmap_tasks.len(),
            "items": items.len(),
        },
        "notice": "Decision support only; no legal advice, certification, conformity assessment, or audit opinion.",
    });
    Ok(PackageDraft {
        product_id: detail.product.id,
        release_id,
        psirt_case_id: payload.psirt_case_id,
        supersedes_id,
        package_type: package_type.to_string(),
        version_number,
        title,
        readiness_percent,
        blocker_count,
        warning_count,
        summary,
        snapshot,
        items,
    })
}

#[allow(clippy::too_many_arguments)]
fn push_draft_item(
    items: &mut Vec<PackageDraftItem>,
    sort_order: &mut i64,
    category: &str,
    source_type: &str,
    source_id: Option<i64>,
    reference_key: String,
    title: String,
    status: &str,
    required: bool,
    blocker: bool,
    detail: String,
    href: String,
    metadata: Value,
) {
    items.push(PackageDraftItem {
        category: category.to_string(),
        source_type: source_type.to_string(),
        source_id,
        reference_key,
        title,
        status: status.to_string(),
        required,
        blocker,
        detail,
        href,
        metadata,
        sort_order: *sort_order,
    });
    *sort_order += 10;
}

fn validate_create_payload(
    mut payload: ProductSecurityEvidencePackageCreateRequest,
) -> anyhow::Result<ProductSecurityEvidencePackageCreateRequest> {
    payload.package_type = payload.package_type.trim().to_ascii_uppercase();
    if !matches!(payload.package_type.as_str(), "RELEASE" | "PSIRT") {
        bail!("package_type muss RELEASE oder PSIRT sein");
    }
    if payload.product_id <= 0 {
        bail!("product_id muss positiv sein");
    }
    payload.title = payload
        .title
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if payload
        .title
        .as_ref()
        .is_some_and(|value| value.len() > 255)
    {
        bail!("Paket-Titel darf hoechstens 255 Zeichen haben");
    }
    Ok(payload)
}

fn validate_review_payload(
    mut payload: ProductSecurityEvidencePackageReviewRequest,
    package: &ProductSecurityEvidencePackageSummary,
) -> anyhow::Result<ProductSecurityEvidencePackageReviewRequest> {
    payload.status = payload.status.trim().to_ascii_uppercase();
    payload.decision = payload.decision.trim().to_ascii_uppercase();
    payload.review_notes = payload.review_notes.trim().to_string();
    if !matches!(
        payload.status.as_str(),
        "DRAFT" | "IN_REVIEW" | "CHANGES_REQUESTED" | "APPROVED" | "ARCHIVED"
    ) {
        bail!("Ungueltiger Evidence-Paketstatus");
    }
    if !matches!(
        payload.decision.as_str(),
        "PENDING" | "APPROVED" | "CONDITIONAL" | "REJECTED"
    ) {
        bail!("Ungueltige Evidence-Paketentscheidung");
    }
    if payload.review_notes.len() > 4000 {
        bail!("Review-Notiz darf hoechstens 4000 Zeichen haben");
    }
    if payload.status == "APPROVED" {
        match payload.decision.as_str() {
            "APPROVED" if package.blocker_count > 0 => bail!(
                "Uneingeschraenkte Freigabe ist mit {} offenen Blockern nicht moeglich",
                package.blocker_count
            ),
            "CONDITIONAL" if payload.review_notes.is_empty() => {
                bail!("Bedingte Freigabe benoetigt dokumentierte Auflagen")
            }
            "APPROVED" | "CONDITIONAL" => {}
            _ => bail!("Freigegebene Pakete benoetigen APPROVED oder CONDITIONAL"),
        }
    }
    if payload.status == "CHANGES_REQUESTED" && payload.review_notes.is_empty() {
        bail!("Aenderungsanforderungen benoetigen eine Review-Notiz");
    }
    Ok(payload)
}

fn package_evidence_key(
    package_type: &str,
    release_id: Option<i64>,
    psirt_case_id: Option<i64>,
) -> String {
    if package_type == "PSIRT" {
        format!(
            "PRODUCT_SECURITY:PSIRT:{}",
            psirt_case_id.unwrap_or_default()
        )
    } else {
        format!(
            "PRODUCT_SECURITY:RELEASE:{}",
            release_id.unwrap_or_default()
        )
    }
}

fn empty_as_dash(value: &str) -> &str {
    if value.trim().is_empty() {
        "-"
    } else {
        value
    }
}

fn percent_encode_query_value(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                vec![byte as char]
            }
            _ => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}

async fn insert_package_postgres(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    user_id: i64,
    draft: &PackageDraft,
) -> anyhow::Result<i64> {
    let mut transaction = pool.begin().await?;
    let snapshot_json = serde_json::to_string(&draft.snapshot)?;
    let package_id: i64 = sqlx::query_scalar(
        r#"INSERT INTO product_security_evidencepackage (
               tenant_id,product_id,release_id,psirt_case_id,supersedes_id,package_type,
               version_number,title,status,decision,readiness_percent,blocker_count,
               warning_count,summary,review_notes,snapshot_json,created_by_id,created_at,updated_at
           ) VALUES (
               $1,$2,$3,$4,$5,$6,$7,$8,'DRAFT','PENDING',$9,$10,$11,$12,'',$13,$14,
               CURRENT_TIMESTAMP::text,CURRENT_TIMESTAMP::text
           ) RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(draft.product_id)
    .bind(draft.release_id)
    .bind(draft.psirt_case_id)
    .bind(draft.supersedes_id)
    .bind(&draft.package_type)
    .bind(draft.version_number)
    .bind(&draft.title)
    .bind(draft.readiness_percent)
    .bind(draft.blocker_count)
    .bind(draft.warning_count)
    .bind(&draft.summary)
    .bind(snapshot_json)
    .bind(user_id)
    .fetch_one(&mut *transaction)
    .await
    .context("PostgreSQL-Evidence-Paket konnte nicht erstellt werden")?;
    for item in &draft.items {
        sqlx::query(
            r#"INSERT INTO product_security_evidencepackageitem (
                   tenant_id,package_id,category,source_type,source_id,reference_key,title,status,
                   required,blocker,detail,href,metadata_json,sort_order,created_at
               ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,CURRENT_TIMESTAMP::text)"#,
        )
        .bind(tenant_id)
        .bind(package_id)
        .bind(&item.category)
        .bind(&item.source_type)
        .bind(item.source_id)
        .bind(&item.reference_key)
        .bind(&item.title)
        .bind(&item.status)
        .bind(item.required)
        .bind(item.blocker)
        .bind(&item.detail)
        .bind(&item.href)
        .bind(serde_json::to_string(&item.metadata)?)
        .bind(item.sort_order)
        .execute(&mut *transaction)
        .await
        .context("PostgreSQL-Evidence-Paketposition konnte nicht erstellt werden")?;
    }
    transaction.commit().await?;
    Ok(package_id)
}

async fn insert_package_sqlite(
    pool: &sqlx::SqlitePool,
    tenant_id: i64,
    user_id: i64,
    draft: &PackageDraft,
) -> anyhow::Result<i64> {
    let mut transaction = pool.begin().await?;
    let snapshot_json = serde_json::to_string(&draft.snapshot)?;
    let result = sqlx::query(
        r#"INSERT INTO product_security_evidencepackage (
               tenant_id,product_id,release_id,psirt_case_id,supersedes_id,package_type,
               version_number,title,status,decision,readiness_percent,blocker_count,
               warning_count,summary,review_notes,snapshot_json,created_by_id,created_at,updated_at
           ) VALUES (
               ?1,?2,?3,?4,?5,?6,?7,?8,'DRAFT','PENDING',?9,?10,?11,?12,'',?13,?14,
               CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
           )"#,
    )
    .bind(tenant_id)
    .bind(draft.product_id)
    .bind(draft.release_id)
    .bind(draft.psirt_case_id)
    .bind(draft.supersedes_id)
    .bind(&draft.package_type)
    .bind(draft.version_number)
    .bind(&draft.title)
    .bind(draft.readiness_percent)
    .bind(draft.blocker_count)
    .bind(draft.warning_count)
    .bind(&draft.summary)
    .bind(snapshot_json)
    .bind(user_id)
    .execute(&mut *transaction)
    .await
    .context("SQLite-Evidence-Paket konnte nicht erstellt werden")?;
    let package_id = result.last_insert_rowid();
    for item in &draft.items {
        sqlx::query(
            r#"INSERT INTO product_security_evidencepackageitem (
                   tenant_id,package_id,category,source_type,source_id,reference_key,title,status,
                   required,blocker,detail,href,metadata_json,sort_order,created_at
               ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,CURRENT_TIMESTAMP)"#,
        )
        .bind(tenant_id)
        .bind(package_id)
        .bind(&item.category)
        .bind(&item.source_type)
        .bind(item.source_id)
        .bind(&item.reference_key)
        .bind(&item.title)
        .bind(&item.status)
        .bind(item.required)
        .bind(item.blocker)
        .bind(&item.detail)
        .bind(&item.href)
        .bind(serde_json::to_string(&item.metadata)?)
        .bind(item.sort_order)
        .execute(&mut *transaction)
        .await
        .context("SQLite-Evidence-Paketposition konnte nicht erstellt werden")?;
    }
    transaction.commit().await?;
    Ok(package_id)
}

fn package_summary_select_sql(postgres: bool) -> String {
    let timestamps = if postgres {
        "package.reviewed_at::text AS reviewed_at, package.approved_at::text AS approved_at, package.created_at::text AS created_at, package.updated_at::text AS updated_at"
    } else {
        "CAST(package.reviewed_at AS TEXT) AS reviewed_at, CAST(package.approved_at AS TEXT) AS approved_at, CAST(package.created_at AS TEXT) AS created_at, CAST(package.updated_at AS TEXT) AS updated_at"
    };
    format!(
        r#"SELECT
               package.id,package.tenant_id,package.product_id,product.name AS product_name,
               package.release_id,release.version AS release_version,
               package.psirt_case_id,psirt.case_id AS psirt_case_identifier,
               package.supersedes_id,package.package_type,package.version_number,package.title,
               package.status,package.decision,package.readiness_percent,package.blocker_count,
               package.warning_count,package.summary,package.review_notes,package.created_by_id,
               package.reviewed_by_id,{timestamps}
           FROM product_security_evidencepackage package
           INNER JOIN product_security_product product
             ON product.id=package.product_id AND product.tenant_id=package.tenant_id
           LEFT JOIN product_security_productrelease release
             ON release.id=package.release_id AND release.tenant_id=package.tenant_id
           LEFT JOIN product_security_psirtcase psirt
             ON psirt.id=package.psirt_case_id AND psirt.tenant_id=package.tenant_id"#
    )
}

fn package_items_postgres_sql() -> &'static str {
    r#"SELECT id,tenant_id,package_id,category,source_type,source_id,reference_key,title,status,
              required,blocker,detail,href,metadata_json,sort_order,created_at::text AS created_at
       FROM product_security_evidencepackageitem
       WHERE tenant_id=$1 AND package_id=$2 ORDER BY sort_order,id"#
}

fn package_items_sqlite_sql() -> &'static str {
    r#"SELECT id,tenant_id,package_id,category,source_type,source_id,reference_key,title,status,
              required,blocker,detail,href,metadata_json,sort_order,CAST(created_at AS TEXT) AS created_at
       FROM product_security_evidencepackageitem
       WHERE tenant_id=?1 AND package_id=?2 ORDER BY sort_order,id"#
}

fn package_from_pg_row(row: PgRow) -> Result<ProductSecurityEvidencePackageSummary, sqlx::Error> {
    package_from_row(&row)
}

fn package_from_sqlite_row(
    row: SqliteRow,
) -> Result<ProductSecurityEvidencePackageSummary, sqlx::Error> {
    package_from_row(&row)
}

fn package_from_row<R: Row>(row: &R) -> Result<ProductSecurityEvidencePackageSummary, sqlx::Error>
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    i64: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    bool: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    String: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    let package_type: String = row.try_get("package_type")?;
    let status: String = row.try_get("status")?;
    let decision: String = row.try_get("decision")?;
    Ok(ProductSecurityEvidencePackageSummary {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        product_id: row.try_get("product_id")?,
        product_name: row.try_get("product_name")?,
        release_id: row.try_get("release_id")?,
        release_version: row.try_get("release_version")?,
        psirt_case_id: row.try_get("psirt_case_id")?,
        psirt_case_identifier: row.try_get("psirt_case_identifier")?,
        supersedes_id: row.try_get("supersedes_id")?,
        package_type_label: package_type_label(&package_type).to_string(),
        package_type,
        version_number: row.try_get("version_number")?,
        title: row.try_get("title")?,
        status_label: package_status_label(&status).to_string(),
        status,
        decision_label: package_decision_label(&decision).to_string(),
        decision,
        readiness_percent: row.try_get("readiness_percent")?,
        blocker_count: row.try_get("blocker_count")?,
        warning_count: row.try_get("warning_count")?,
        summary: row.try_get("summary")?,
        review_notes: row.try_get("review_notes")?,
        created_by_id: row.try_get("created_by_id")?,
        reviewed_by_id: row.try_get("reviewed_by_id")?,
        reviewed_at: row.try_get("reviewed_at")?,
        approved_at: row.try_get("approved_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn package_item_from_pg_row(row: PgRow) -> Result<ProductSecurityEvidencePackageItem, sqlx::Error> {
    package_item_from_row(&row)
}

fn package_item_from_sqlite_row(
    row: SqliteRow,
) -> Result<ProductSecurityEvidencePackageItem, sqlx::Error> {
    package_item_from_row(&row)
}

fn package_item_from_row<R: Row>(row: &R) -> Result<ProductSecurityEvidencePackageItem, sqlx::Error>
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    i64: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    bool: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    String: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    let category: String = row.try_get("category")?;
    let status: String = row.try_get("status")?;
    let raw_metadata: String = row.try_get("metadata_json")?;
    Ok(ProductSecurityEvidencePackageItem {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        package_id: row.try_get("package_id")?,
        category_label: package_category_label(&category).to_string(),
        category,
        source_type: row.try_get("source_type")?,
        source_id: row.try_get("source_id")?,
        reference_key: row.try_get("reference_key")?,
        title: row.try_get("title")?,
        status_label: package_item_status_label(&status).to_string(),
        status,
        required: row.try_get("required")?,
        blocker: row.try_get("blocker")?,
        detail: row.try_get("detail")?,
        href: row.try_get("href")?,
        metadata: parse_json_object(&raw_metadata),
        sort_order: row.try_get("sort_order")?,
        created_at: row.try_get("created_at")?,
    })
}

fn import_from_pg_row(row: PgRow) -> Result<PackageImportArtifact, sqlx::Error> {
    import_from_row(&row)
}

fn import_from_sqlite_row(row: SqliteRow) -> Result<PackageImportArtifact, sqlx::Error> {
    import_from_row(&row)
}

fn import_from_row<R: Row>(row: &R) -> Result<PackageImportArtifact, sqlx::Error>
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    i64: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    String: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    Ok(PackageImportArtifact {
        id: row.try_get("id")?,
        file_name: row.try_get("file_name")?,
        document_id: row.try_get("document_id")?,
        format_name: row.try_get("format_name")?,
        format_version: row.try_get("format_version")?,
        validation_status: row.try_get("validation_status")?,
        component_count: row.try_get("component_count")?,
        matched_component_count: row.try_get("matched_component_count")?,
        created_at: row.try_get("created_at")?,
    })
}

fn evidence_from_pg_row(row: PgRow) -> Result<PackageEvidenceReference, sqlx::Error> {
    evidence_from_row(&row)
}

fn evidence_from_sqlite_row(row: SqliteRow) -> Result<PackageEvidenceReference, sqlx::Error> {
    evidence_from_row(&row)
}

fn evidence_from_row<R: Row>(row: &R) -> Result<PackageEvidenceReference, sqlx::Error>
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    i64: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    String: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    Ok(PackageEvidenceReference {
        id: row.try_get("id")?,
        title: row.try_get("title")?,
        status: row.try_get("status")?,
        file_name: row.try_get("file_name")?,
        created_at: row.try_get("created_at")?,
    })
}

fn parse_json_object(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap_or_else(|_| json!({}))
}

fn package_type_label(value: &str) -> &'static str {
    match value {
        "PSIRT" => "PSIRT-Freigabe",
        _ => "Release-Freigabe",
    }
}

fn package_status_label(value: &str) -> &'static str {
    match value {
        "IN_REVIEW" => "In Review",
        "CHANGES_REQUESTED" => "Aenderung angefordert",
        "APPROVED" => "Freigegeben",
        "ARCHIVED" => "Archiviert",
        _ => "Entwurf",
    }
}

fn package_decision_label(value: &str) -> &'static str {
    match value {
        "APPROVED" => "Freigegeben",
        "CONDITIONAL" => "Bedingt freigegeben",
        "REJECTED" => "Abgelehnt",
        _ => "Offen",
    }
}

fn package_category_label(value: &str) -> &'static str {
    match value {
        "RELEASE" => "Release",
        "LIFECYCLE" => "Lifecycle",
        "SBOM" => "SBOM",
        "VEX" => "VEX / Schwachstellen",
        "ADVISORY" => "Advisory / CSAF",
        "PSIRT" => "PSIRT",
        "RISK" => "Risiko",
        "ROADMAP" => "Roadmap",
        "EVIDENCE" => "Evidence",
        _ => "Sonstiges",
    }
}

fn package_item_status_label(value: &str) -> &'static str {
    match value {
        "READY" => "Bereit",
        "MISSING" => "Fehlt",
        "WARN" => "Pruefen",
        "BLOCKED" => "Blockiert",
        _ => "Info",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_payload_and_review_gates_are_conservative() {
        let payload = validate_create_payload(ProductSecurityEvidencePackageCreateRequest {
            product_id: 1,
            release_id: Some(2),
            psirt_case_id: None,
            package_type: " release ".to_string(),
            title: Some("  Release 1.2  ".to_string()),
        })
        .unwrap();
        assert_eq!(payload.package_type, "RELEASE");
        assert_eq!(payload.title.as_deref(), Some("Release 1.2"));

        let package = ProductSecurityEvidencePackageSummary {
            id: 1,
            tenant_id: 1,
            product_id: 1,
            product_name: "Demo".to_string(),
            release_id: Some(2),
            release_version: Some("1.2".to_string()),
            psirt_case_id: None,
            psirt_case_identifier: None,
            supersedes_id: None,
            package_type: "RELEASE".to_string(),
            package_type_label: "Release-Freigabe".to_string(),
            version_number: 1,
            title: "Release 1.2".to_string(),
            status: "DRAFT".to_string(),
            status_label: "Entwurf".to_string(),
            decision: "PENDING".to_string(),
            decision_label: "Offen".to_string(),
            readiness_percent: 50,
            blocker_count: 2,
            warning_count: 1,
            summary: String::new(),
            review_notes: String::new(),
            created_by_id: Some(1),
            reviewed_by_id: None,
            reviewed_at: None,
            approved_at: None,
            created_at: String::new(),
            updated_at: String::new(),
        };
        assert!(validate_review_payload(
            ProductSecurityEvidencePackageReviewRequest {
                status: "APPROVED".to_string(),
                decision: "APPROVED".to_string(),
                review_notes: String::new(),
            },
            &package,
        )
        .is_err());
        assert!(validate_review_payload(
            ProductSecurityEvidencePackageReviewRequest {
                status: "APPROVED".to_string(),
                decision: "CONDITIONAL".to_string(),
                review_notes: "Open blockers accepted until 2026-07-01".to_string(),
            },
            &package,
        )
        .is_ok());
    }
}
