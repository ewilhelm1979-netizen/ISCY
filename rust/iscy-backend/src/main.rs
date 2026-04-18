use std::net::SocketAddr;

use iscy_backend::{
    app_router_with_state, cve_store::CveStore, dashboard_store::DashboardStore,
    report_store::ReportStore, tenant_store::TenantStore, AppState,
};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr: SocketAddr = std::env::var("RUST_BACKEND_BIND")
        .unwrap_or_else(|_| "0.0.0.0:9000".to_string())
        .parse()?;
    let (cve_store, tenant_store, dashboard_store, report_store) =
        match std::env::var("DATABASE_URL") {
            Ok(database_url) if !database_url.trim().is_empty() => {
                let cve_store = CveStore::connect(&database_url).await?;
                let tenant_store = TenantStore::connect(&database_url).await?;
                let dashboard_store = DashboardStore::connect(&database_url).await?;
                let report_store = ReportStore::connect(&database_url).await?;
                (
                    Some(cve_store),
                    Some(tenant_store),
                    Some(dashboard_store),
                    Some(report_store),
                )
            }
            _ => (None, None, None, None),
        };
    let state = AppState::with_stores(cve_store, tenant_store)
        .with_dashboard_store(dashboard_store)
        .with_report_store(report_store);

    let listener = TcpListener::bind(addr).await?;
    println!("ISCY Rust backend listening on http://{}", addr);
    axum::serve(listener, app_router_with_state(state)).await?;
    Ok(())
}
