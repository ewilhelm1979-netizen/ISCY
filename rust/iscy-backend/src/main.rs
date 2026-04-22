use std::net::SocketAddr;

use iscy_backend::{
    app_router_with_state,
    assessment_store::AssessmentStore,
    asset_store::AssetStore,
    catalog_store::CatalogStore,
    cve_store::CveStore,
    dashboard_store::DashboardStore,
    db_admin::{run_db_admin_action, DbAdminAction},
    evidence_store::EvidenceStore,
    import_store::ImportStore,
    process_store::ProcessStore,
    product_security_store::ProductSecurityStore,
    report_store::ReportStore,
    requirement_store::RequirementStore,
    risk_store::RiskStore,
    roadmap_store::RoadmapStore,
    tenant_store::TenantStore,
    wizard_store::WizardStore,
    AppState,
};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if let Some(command) = std::env::args().nth(1) {
        match command.as_str() {
            "migrate" => {
                run_database_admin(DbAdminAction::Migrate).await?;
                return Ok(());
            }
            "seed-demo" => {
                run_database_admin(DbAdminAction::SeedDemo).await?;
                return Ok(());
            }
            "init-demo" => {
                run_database_admin(DbAdminAction::InitDemo).await?;
                return Ok(());
            }
            "help" | "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            unknown => anyhow::bail!(
                "Unbekannter iscy-backend Command: {unknown}. Nutze --help fuer Optionen."
            ),
        }
    }

    let addr: SocketAddr = std::env::var("RUST_BACKEND_BIND")
        .unwrap_or_else(|_| "0.0.0.0:9000".to_string())
        .parse()?;
    let (
        cve_store,
        tenant_store,
        dashboard_store,
        report_store,
        requirement_store,
        asset_store,
        catalog_store,
        process_store,
        risk_store,
        evidence_store,
        import_store,
        assessment_store,
        roadmap_store,
        wizard_store,
        product_security_store,
    ) = match std::env::var("DATABASE_URL") {
        Ok(database_url) if !database_url.trim().is_empty() => {
            let cve_store = CveStore::connect(&database_url).await?;
            let tenant_store = TenantStore::connect(&database_url).await?;
            let dashboard_store = DashboardStore::connect(&database_url).await?;
            let report_store = ReportStore::connect(&database_url).await?;
            let requirement_store = RequirementStore::connect(&database_url).await?;
            let asset_store = AssetStore::connect(&database_url).await?;
            let catalog_store = CatalogStore::connect(&database_url).await?;
            let process_store = ProcessStore::connect(&database_url).await?;
            let risk_store = RiskStore::connect(&database_url).await?;
            let evidence_store = EvidenceStore::connect(&database_url).await?;
            let import_store = ImportStore::connect(&database_url).await?;
            let assessment_store = AssessmentStore::connect(&database_url).await?;
            let roadmap_store = RoadmapStore::connect(&database_url).await?;
            let wizard_store = WizardStore::connect(&database_url).await?;
            let product_security_store = ProductSecurityStore::connect(&database_url).await?;
            (
                Some(cve_store),
                Some(tenant_store),
                Some(dashboard_store),
                Some(report_store),
                Some(requirement_store),
                Some(asset_store),
                Some(catalog_store),
                Some(process_store),
                Some(risk_store),
                Some(evidence_store),
                Some(import_store),
                Some(assessment_store),
                Some(roadmap_store),
                Some(wizard_store),
                Some(product_security_store),
            )
        }
        _ => (
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None,
        ),
    };
    let state = AppState::with_stores(cve_store, tenant_store)
        .with_dashboard_store(dashboard_store)
        .with_report_store(report_store)
        .with_requirement_store(requirement_store)
        .with_asset_store(asset_store)
        .with_catalog_store(catalog_store)
        .with_process_store(process_store)
        .with_risk_store(risk_store)
        .with_evidence_store(evidence_store)
        .with_import_store(import_store)
        .with_assessment_store(assessment_store)
        .with_roadmap_store(roadmap_store)
        .with_wizard_store(wizard_store)
        .with_product_security_store(product_security_store);

    let listener = TcpListener::bind(addr).await?;
    println!("ISCY Rust backend listening on http://{}", addr);
    axum::serve(listener, app_router_with_state(state)).await?;
    Ok(())
}

async fn run_database_admin(action: DbAdminAction) -> anyhow::Result<()> {
    let database_url = std::env::var("DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "sqlite:///db.sqlite3".to_string());
    let outcome = run_db_admin_action(&database_url, action).await?;
    println!(
        "ISCY Rust DB admin completed: kind={}, migrations_applied={}, demo_seeded={}",
        outcome.database_kind,
        outcome.applied_migrations.len(),
        outcome.seeded_demo
    );
    if !outcome.applied_migrations.is_empty() {
        println!(
            "Applied migrations: {}",
            outcome.applied_migrations.join(", ")
        );
    }
    Ok(())
}

fn print_usage() {
    println!(
        "ISCY Rust backend\n\nCommands:\n  migrate    Apply Rust-owned DB migrations\n  seed-demo  Seed Rust demo data into an already migrated DB\n  init-demo  Apply migrations and seed demo data\n\nWithout a command the HTTP server starts."
    );
}
