mod evidence_download;
mod security_boundary;

use std::{future::IntoFuture, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use axum::{middleware, routing::get, Router};
use iscy_backend::{
    account_store::AccountStore,
    agent_governance_store::AgentGovernanceStore,
    agent_pki_store::AgentPkiStore,
    agent_release_store::AgentReleaseStore,
    agent_rollout_store::AgentRolloutStore,
    agent_store::AgentStore,
    ai_governance_store::AiGovernanceStore,
    app_router_with_state,
    assessment_store::AssessmentStore,
    asset_store::AssetStore,
    auth_store::AuthStore,
    catalog_store::CatalogStore,
    change_store::ChangeStore,
    control_store::ControlStore,
    cve_store::CveStore,
    dashboard_store::DashboardStore,
    db_admin::{bootstrap_initial_admin, run_db_admin_action, DbAdminAction, InitialAdminConfig},
    evidence_store::EvidenceStore,
    hardening::{
        assert_db_admin_action_allowed, run_production_preflight, CommunitySecurityConfig,
    },
    import_store::ImportStore,
    incident_store::IncidentStore,
    process_store::ProcessStore,
    product_security_store::ProductSecurityStore,
    report_store::ReportStore,
    requirement_store::RequirementStore,
    risk_store::RiskStore,
    roadmap_store::RoadmapStore,
    security_store::SecurityStore,
    supplier_product_security_store::SupplierProductSecurityStore,
    supplier_store::SupplierStore,
    tenant_store::TenantStore,
    threat_intelligence_store::ThreatIntelligenceStore,
    vulnerability_intelligence::{
        run_feed_sync, FeedSyncRequest, OfficialVulnerabilityFeedTransport,
        VulnerabilityFeedTransport, SOURCE_CISA_KEV, SOURCE_FIRST_EPSS, SOURCE_NVD,
    },
    wizard_store::WizardStore,
    AppState,
};
use security_boundary::sanitize_legacy_identity_query;
use tokio::{net::TcpListener, sync::watch, task::JoinHandle};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let security_config = CommunitySecurityConfig::from_env()?;
    if let Some(command) = std::env::args().nth(1) {
        match command.as_str() {
            "migrate" => {
                run_database_admin(DbAdminAction::Migrate).await?;
                return Ok(());
            }
            "seed-demo" => {
                assert_db_admin_action_allowed(&security_config, DbAdminAction::SeedDemo)?;
                run_database_admin(DbAdminAction::SeedDemo).await?;
                return Ok(());
            }
            "init-demo" => {
                assert_db_admin_action_allowed(&security_config, DbAdminAction::InitDemo)?;
                run_database_admin(DbAdminAction::InitDemo).await?;
                return Ok(());
            }
            "init-admin" => {
                run_database_admin(DbAdminAction::Migrate).await?;
                run_initial_admin().await?;
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
        .unwrap_or_else(|_| "127.0.0.1:9000".to_string())
        .parse()?;
    let database_url = std::env::var("DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty());
    run_production_preflight(&security_config, &addr, database_url.as_deref()).await?;
    let (
        cve_store,
        account_store,
        agent_governance_store,
        agent_pki_store,
        agent_release_store,
        agent_rollout_store,
        agent_store,
        auth_store,
        tenant_store,
        dashboard_store,
        report_store,
        requirement_store,
        asset_store,
        catalog_store,
        change_store,
        control_store,
        process_store,
        risk_store,
        evidence_store,
        incident_store,
        import_store,
        assessment_store,
        roadmap_store,
        security_store,
        supplier_store,
        supplier_product_security_store,
        wizard_store,
        product_security_store,
        ai_governance_store,
    ) = match database_url.as_deref() {
        Some(database_url) => {
            let cve_store = CveStore::connect(database_url).await?;
            let account_store = AccountStore::connect(database_url).await?;
            let agent_governance_store = AgentGovernanceStore::connect(database_url).await?;
            let agent_pki_store = AgentPkiStore::connect(database_url).await?;
            let agent_release_store = AgentReleaseStore::connect(database_url).await?;
            let agent_rollout_store = AgentRolloutStore::connect(database_url).await?;
            let agent_store = AgentStore::connect(database_url).await?;
            let auth_store = AuthStore::connect(database_url).await?;
            let tenant_store = TenantStore::connect(database_url).await?;
            let dashboard_store = DashboardStore::connect(database_url).await?;
            let report_store = ReportStore::connect(database_url).await?;
            let requirement_store = RequirementStore::connect(database_url).await?;
            let asset_store = AssetStore::connect(database_url).await?;
            let catalog_store = CatalogStore::connect(database_url).await?;
            let change_store = ChangeStore::connect(database_url).await?;
            let control_store = ControlStore::connect(database_url).await?;
            let process_store = ProcessStore::connect(database_url).await?;
            let risk_store = RiskStore::connect(database_url).await?;
            let evidence_store = EvidenceStore::connect(database_url).await?;
            let incident_store = IncidentStore::connect(database_url).await?;
            let import_store = ImportStore::connect(database_url).await?;
            let assessment_store = AssessmentStore::connect(database_url).await?;
            let roadmap_store = RoadmapStore::connect(database_url).await?;
            let security_store = SecurityStore::connect(database_url).await?;
            let supplier_store = SupplierStore::connect(database_url).await?;
            let supplier_product_security_store =
                SupplierProductSecurityStore::connect(database_url).await?;
            let wizard_store = WizardStore::connect(database_url).await?;
            let product_security_store = ProductSecurityStore::connect(database_url).await?;
            let ai_governance_store = AiGovernanceStore::connect(database_url).await?;
            (
                Some(cve_store),
                Some(account_store),
                Some(agent_governance_store),
                Some(agent_pki_store),
                Some(agent_release_store),
                Some(agent_rollout_store),
                Some(agent_store),
                Some(auth_store),
                Some(tenant_store),
                Some(dashboard_store),
                Some(report_store),
                Some(requirement_store),
                Some(asset_store),
                Some(catalog_store),
                Some(change_store),
                Some(control_store),
                Some(process_store),
                Some(risk_store),
                Some(evidence_store),
                Some(incident_store),
                Some(import_store),
                Some(assessment_store),
                Some(roadmap_store),
                Some(security_store),
                Some(supplier_store),
                Some(supplier_product_security_store),
                Some(wizard_store),
                Some(product_security_store),
                Some(ai_governance_store),
            )
        }
        _ => (
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None,
        ),
    };
    let notification_worker_store = agent_governance_store.clone();
    let vulnerability_worker_store = cve_store.clone();
    let vulnerability_feed_transport: Option<Arc<dyn VulnerabilityFeedTransport>> =
        match OfficialVulnerabilityFeedTransport::from_environment() {
            Ok(transport) => Some(Arc::new(transport)),
            Err(_) => {
                eprintln!(
                    "ISCY Vulnerability-Intelligence-Transport konnte nicht initialisiert werden. Feed-Sync bleibt deaktiviert."
                );
                None
            }
        };
    let threat_intelligence_store = match database_url.as_deref() {
        Some(database_url) => Some(ThreatIntelligenceStore::connect(database_url).await?),
        None => None,
    };
    let state = AppState::with_stores(cve_store, tenant_store)
        .with_account_store(account_store)
        .with_agent_governance_store(agent_governance_store)
        .with_agent_pki_store(agent_pki_store)
        .with_agent_release_store(agent_release_store)
        .with_agent_rollout_store(agent_rollout_store)
        .with_agent_store(agent_store)
        .with_auth_store(auth_store)
        .with_dashboard_store(dashboard_store)
        .with_report_store(report_store)
        .with_requirement_store(requirement_store)
        .with_asset_store(asset_store)
        .with_catalog_store(catalog_store)
        .with_change_store(change_store)
        .with_control_store(control_store)
        .with_process_store(process_store)
        .with_risk_store(risk_store)
        .with_evidence_store(evidence_store)
        .with_incident_store(incident_store)
        .with_evidence_media_root(Some(evidence_media_root_from_env()))
        .with_import_store(import_store)
        .with_assessment_store(assessment_store)
        .with_roadmap_store(roadmap_store)
        .with_security_store(security_store)
        .with_supplier_store(supplier_store)
        .with_supplier_product_security_store(supplier_product_security_store)
        .with_wizard_store(wizard_store)
        .with_product_security_store(product_security_store)
        .with_ai_governance_store(ai_governance_store)
        .with_threat_intelligence_store(threat_intelligence_store)
        .with_vulnerability_feed_transport(vulnerability_feed_transport.clone())
        .with_database_url(database_url)
        .with_security_config(security_config.clone());

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let notification_worker =
        start_agent_notification_worker(notification_worker_store, shutdown_rx.clone());
    let vulnerability_worker = start_vulnerability_intelligence_worker(
        vulnerability_worker_store,
        vulnerability_feed_transport,
        shutdown_rx.clone(),
    );

    let listener = TcpListener::bind(addr).await?;
    println!("ISCY Rust backend listening on http://{}", addr);
    let evidence_download_router = Router::new()
        .route(
            "/api/v1/evidence/{evidence_id}/download",
            get(evidence_download::download_evidence),
        )
        .route(
            "/evidence/{evidence_id}/download",
            get(evidence_download::download_evidence),
        )
        .with_state(state.clone());
    let shutdown_state = state.clone();
    let app = evidence_download_router
        .merge(app_router_with_state(state))
        .layer(middleware::from_fn_with_state(
            security_config,
            sanitize_legacy_identity_query,
        ));
    let mut server = Box::pin(
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal(shutdown_state, shutdown_tx.clone()))
            .into_future(),
    );
    let mut shutdown_observer = shutdown_rx;
    let serve_result: anyhow::Result<()> = tokio::select! {
        result = server.as_mut() => result.map_err(anyhow::Error::from),
        changed = shutdown_observer.changed() => {
            match changed {
                Ok(()) => {
                    let timeout = shutdown_timeout();
                    match tokio::time::timeout(timeout, server.as_mut()).await {
                        Ok(result) => result.map_err(anyhow::Error::from),
                        Err(_) => Err(anyhow::anyhow!(
                            "Graceful-Shutdown-Timeout nach {} Sekunden",
                            timeout.as_secs()
                        )),
                    }
                }
                Err(_) => Err(anyhow::anyhow!(
                    "Shutdown-Signal-Kanal wurde unerwartet geschlossen"
                )),
            }
        }
    };
    let _ = shutdown_tx.send(true);
    if let Some(worker) = notification_worker {
        tokio::time::timeout(Duration::from_secs(10), worker)
            .await
            .map_err(|_| anyhow::anyhow!("Notification-Worker-Shutdown-Timeout"))??;
    }
    if let Some(worker) = vulnerability_worker {
        tokio::time::timeout(Duration::from_secs(10), worker)
            .await
            .map_err(|_| anyhow::anyhow!("Vulnerability-Intelligence-Worker-Shutdown-Timeout"))??;
    }
    serve_result
}

fn start_vulnerability_intelligence_worker(
    store: Option<CveStore>,
    transport: Option<Arc<dyn VulnerabilityFeedTransport>>,
    mut shutdown: watch::Receiver<bool>,
) -> Option<JoinHandle<()>> {
    let store = store?;
    let transport = transport?;
    let interval_seconds = std::env::var("ISCY_VULNERABILITY_SYNC_INTERVAL_SECONDS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(0);
    if interval_seconds == 0 {
        return None;
    }
    let interval_seconds = interval_seconds.clamp(7_200, 604_800);
    Some(tokio::spawn(async move {
        let period = Duration::from_secs(interval_seconds);
        let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                    continue;
                }
                _ = interval.tick() => {}
            }
            for source in [SOURCE_NVD, SOURCE_CISA_KEV, SOURCE_FIRST_EPSS] {
                let result = run_feed_sync(
                    &store,
                    transport.as_ref(),
                    FeedSyncRequest {
                        sources: vec![source.to_string()],
                        max_records: None,
                    },
                    "SCHEDULED",
                    None,
                )
                .await;
                match result {
                    Ok(batch) => {
                        if let Some(result) = batch.results.first() {
                            println!(
                                "ISCY Vulnerability-Intelligence source={} processed={} unchanged={}",
                                result.source, result.processed_count, result.unchanged_count
                            );
                        }
                    }
                    Err(error) => eprintln!(
                        "ISCY Vulnerability-Intelligence source={source} failed_code={}",
                        error.code()
                    ),
                }
            }
        }
    }))
}

fn start_agent_notification_worker(
    store: Option<AgentGovernanceStore>,
    mut shutdown: watch::Receiver<bool>,
) -> Option<JoinHandle<()>> {
    let store = store?;
    let interval_seconds = std::env::var("ISCY_AGENT_NOTIFICATION_INTERVAL_SECONDS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(300);
    if interval_seconds == 0 {
        return None;
    }
    let interval_seconds = interval_seconds.max(60);
    Some(tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_seconds));
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                    continue;
                }
                _ = interval.tick() => {}
            }
            let tenant_ids = match store.notification_tenant_ids().await {
                Ok(tenant_ids) => tenant_ids,
                Err(err) => {
                    eprintln!("ISCY Agent-Notification-Worker konnte Tenants nicht lesen: {err}");
                    continue;
                }
            };
            for tenant_id in tenant_ids {
                match store.dispatch_notifications(tenant_id).await {
                    Ok(result) if result.sent > 0 || result.failed > 0 => println!(
                        "ISCY Notifications tenant={tenant_id} sent={} failed={} suppressed={}",
                        result.sent, result.failed, result.suppressed
                    ),
                    Ok(_) => {}
                    Err(err) => eprintln!(
                        "ISCY Notification-Worker tenant={tenant_id} fehlgeschlagen: {err}"
                    ),
                }
            }
        }
    }))
}

async fn shutdown_signal(state: AppState, shutdown_tx: watch::Sender<bool>) {
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate => {}
    }
    state.mark_not_ready();
    let _ = shutdown_tx.send(true);
}

fn shutdown_timeout() -> Duration {
    let seconds = std::env::var("ISCY_SHUTDOWN_TIMEOUT_SECONDS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(30)
        .clamp(5, 120);
    Duration::from_secs(seconds)
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

fn evidence_media_root_from_env() -> PathBuf {
    std::env::var("ISCY_MEDIA_ROOT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("MEDIA_ROOT")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("media"))
}

async fn run_initial_admin() -> anyhow::Result<()> {
    let database_url = std::env::var("DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "sqlite:///db.sqlite3".to_string());
    let password = iscy_backend::hardening::secret_value("ISCY_INITIAL_ADMIN_PASSWORD")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "ISCY_INITIAL_ADMIN_PASSWORD oder ISCY_INITIAL_ADMIN_PASSWORD_FILE fehlt."
            )
        })?;
    let config = InitialAdminConfig {
        tenant_name: env_or("ISCY_INITIAL_ADMIN_TENANT_NAME", "ISCY Production Tenant"),
        tenant_slug: env_or("ISCY_INITIAL_ADMIN_TENANT_SLUG", "iscy-production"),
        username: env_or("ISCY_INITIAL_ADMIN_USERNAME", "iscy-admin"),
        password,
        email: env_or("ISCY_INITIAL_ADMIN_EMAIL", "iscy-admin@example.local"),
        first_name: env_or("ISCY_INITIAL_ADMIN_FIRST_NAME", "ISCY"),
        last_name: env_or("ISCY_INITIAL_ADMIN_LAST_NAME", "Admin"),
    };
    let outcome = bootstrap_initial_admin(&database_url, config).await?;
    println!(
        "ISCY Initial-Admin completed: kind={}, tenant_id={}, user_id={}, username={}, created={}",
        outcome.database_kind,
        outcome.tenant_id,
        outcome.user_id,
        outcome.username,
        outcome.created
    );
    Ok(())
}

fn env_or(name: &str, fallback: &str) -> String {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

fn print_usage() {
    println!(
        "ISCY Rust backend\n\nCommands:\n  migrate      Apply Rust-owned DB migrations\n  seed-demo    Seed Rust demo data into an already migrated DB\n  init-demo    Apply migrations and seed demo data\n  init-admin   Apply migrations and create an initial production admin from ISCY_INITIAL_ADMIN_* env vars\n\nWithout a command the HTTP server starts."
    );
}
