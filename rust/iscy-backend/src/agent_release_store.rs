use anyhow::{bail, Context};
use chrono::Utc;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow},
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteRow},
    Row,
};

use crate::cve_store::normalize_database_url;

const CHECKSUM_STATUS_CALCULATED: &str = "calculated";
const CHECKSUM_STATUS_VERIFIED: &str = "verified";
const CHECKSUM_STATUS_MISMATCH: &str = "mismatch";
const SIGNATURE_STATUS_UNSIGNED: &str = "unsigned";
const SIGNATURE_STATUS_NOT_CONFIGURED: &str = "not_configured";
const PROVENANCE_STATUS_INCOMPLETE: &str = "incomplete";

#[derive(Clone)]
pub enum AgentReleaseStore {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Clone, Copy)]
struct AgentArtifactSource {
    artifact_id: &'static str,
    artifact_name: &'static str,
    artifact_type: &'static str,
    target_os: &'static str,
    target_arch: &'static str,
    package_format: &'static str,
    content_type: &'static str,
    artifact_reference: &'static str,
    known_limitations: &'static str,
    content: &'static [u8],
}

struct VerificationEventInput<'a> {
    tenant_id: i64,
    artifact_id: &'a str,
    event_type: &'a str,
    actor_id: Option<i64>,
    status: &'a str,
    summary: &'a str,
    error_class: &'a str,
}

const AGENT_ARTIFACT_SOURCES: &[AgentArtifactSource] = &[
    AgentArtifactSource {
        artifact_id: "agent-deployment-readme",
        artifact_name: "Agent Deployment README",
        artifact_type: "config_template",
        target_os: "all",
        target_arch: "any",
        package_format: "text",
        content_type: "text/markdown",
        artifact_reference: "deploy/agent/README.md",
        known_limitations: "Dokumentationsartefakt; keine produktive Signatur in diesem Stand.",
        content: include_bytes!("../../../deploy/agent/README.md"),
    },
    AgentArtifactSource {
        artifact_id: "agent-systemd-service",
        artifact_name: "Linux systemd Service",
        artifact_type: "systemd_unit",
        target_os: "linux",
        target_arch: "any",
        package_format: "text",
        content_type: "text/plain",
        artifact_reference: "deploy/agent/systemd/iscy-agent.service",
        known_limitations:
            "Deployment-Unit fuer vorhandenes Agent-Binary; nicht produktiv signiert.",
        content: include_bytes!("../../../deploy/agent/systemd/iscy-agent.service"),
    },
    AgentArtifactSource {
        artifact_id: "agent-systemd-timer",
        artifact_name: "Linux systemd Timer",
        artifact_type: "systemd_unit",
        target_os: "linux",
        target_arch: "any",
        package_format: "text",
        content_type: "text/plain",
        artifact_reference: "deploy/agent/systemd/iscy-agent.timer",
        known_limitations: "Timer-Unit fuer periodischen Betrieb; nicht produktiv signiert.",
        content: include_bytes!("../../../deploy/agent/systemd/iscy-agent.timer"),
    },
    AgentArtifactSource {
        artifact_id: "agent-systemd-env-example",
        artifact_name: "Linux systemd Environment Beispiel",
        artifact_type: "config_template",
        target_os: "linux",
        target_arch: "any",
        package_format: "text",
        content_type: "text/plain",
        artifact_reference: "deploy/agent/systemd/iscy-agent.env.example",
        known_limitations:
            "Beispielkonfiguration ohne Secrets; nicht fuer produktive Geheimnisse gedacht.",
        content: include_bytes!("../../../deploy/agent/systemd/iscy-agent.env.example"),
    },
    AgentArtifactSource {
        artifact_id: "agent-nixos-module",
        artifact_name: "NixOS Agent Modul",
        artifact_type: "nixos_module",
        target_os: "nixos",
        target_arch: "any",
        package_format: "nix_module",
        content_type: "text/plain",
        artifact_reference: "deploy/agent/nixos/iscy-agent.nix",
        known_limitations:
            "Deklaratives Modul fuer vorhandenes Agent-Binary; keine externe Attestation.",
        content: include_bytes!("../../../deploy/agent/nixos/iscy-agent.nix"),
    },
    AgentArtifactSource {
        artifact_id: "agent-windows-task-installer",
        artifact_name: "Windows Scheduled Task Installer",
        artifact_type: "powershell_script",
        target_os: "windows",
        target_arch: "any",
        package_format: "script",
        content_type: "text/plain",
        artifact_reference: "deploy/agent/windows/install-iscy-agent-task.ps1",
        known_limitations:
            "PowerShell-Deployment-Skript; keine MSI-/Authenticode-Produktionssignatur.",
        content: include_bytes!("../../../deploy/agent/windows/install-iscy-agent-task.ps1"),
    },
    AgentArtifactSource {
        artifact_id: "agent-macos-launchdaemon",
        artifact_name: "macOS LaunchDaemon",
        artifact_type: "macos_launchdaemon",
        target_os: "macos",
        target_arch: "any",
        package_format: "text",
        content_type: "application/xml",
        artifact_reference: "deploy/agent/macos/com.iscy.agent.plist",
        known_limitations:
            "LaunchDaemon-Beispiel fuer vorhandenes Agent-Binary; keine PKG-Produktionssignatur.",
        content: include_bytes!("../../../deploy/agent/macos/com.iscy.agent.plist"),
    },
];

#[derive(Debug, Clone, Serialize)]
pub struct AgentReleaseArtifact {
    pub id: i64,
    pub tenant_id: i64,
    pub artifact_id: String,
    pub artifact_name: String,
    pub artifact_type: String,
    pub target_os: String,
    pub target_arch: String,
    pub package_format: String,
    pub version: String,
    pub build_profile: String,
    pub git_commit: String,
    pub source_branch: String,
    pub created_at: String,
    pub sha256: String,
    pub size_bytes: i64,
    pub content_type: String,
    pub artifact_reference: String,
    pub signature_status: String,
    pub provenance_status: String,
    pub verification_status: String,
    pub known_limitations: String,
    pub metadata_json: Value,
    pub last_checked_at: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentArtifactSignature {
    pub id: i64,
    pub tenant_id: i64,
    pub artifact_id: String,
    pub signature_algorithm: String,
    pub signature_type: String,
    pub signature_reference: String,
    pub signer_identity: String,
    pub signer_fingerprint: String,
    pub signature_created_at: Option<String>,
    pub signature_verified_at: Option<String>,
    pub signature_status: String,
    pub verification_error_class: String,
    pub verification_summary: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentReleaseProvenance {
    pub id: i64,
    pub tenant_id: i64,
    pub provenance_id: String,
    pub artifact_id: String,
    pub git_commit: String,
    pub source_repository: String,
    pub source_branch: String,
    pub build_workflow: String,
    pub build_run_id: String,
    pub build_started_at: Option<String>,
    pub build_finished_at: Option<String>,
    pub builder_identity: String,
    pub build_environment: String,
    pub dependency_lock_hash: String,
    pub cargo_lock_hash: String,
    pub nix_flake_lock_hash: String,
    pub source_tree_hash: String,
    pub ci_status: String,
    pub codeql_status: String,
    pub cargo_audit_status: String,
    pub cargo_deny_status: String,
    pub provenance_status: String,
    pub attestation_reference: String,
    pub generated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentArtifactVerificationEvent {
    pub id: i64,
    pub tenant_id: i64,
    pub artifact_id: String,
    pub event_type: String,
    pub actor_id: Option<i64>,
    pub status: String,
    pub summary: String,
    pub error_class: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentReleaseArtifactDetail {
    pub artifact: AgentReleaseArtifact,
    pub signature: Option<AgentArtifactSignature>,
    pub provenance: Option<AgentReleaseProvenance>,
    pub recent_events: Vec<AgentArtifactVerificationEvent>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentArtifactRefreshResult {
    pub tenant_id: i64,
    pub refreshed: i64,
    pub artifacts: Vec<AgentReleaseArtifact>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentArtifactVerificationResult {
    pub tenant_id: i64,
    pub artifact_id: String,
    pub status: String,
    pub summary: String,
    pub artifact: AgentReleaseArtifact,
}

impl AgentReleaseStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let normalized_url = normalize_database_url(database_url);
        if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://")
        {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("PostgreSQL-Verbindung fuer Agent-Release-Store fehlgeschlagen")?;
            return Ok(Self::Postgres(pool));
        }
        if normalized_url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&normalized_url)
                .await
                .context("SQLite-Verbindung fuer Agent-Release-Store fehlgeschlagen")?;
            return Ok(Self::Sqlite(pool));
        }
        bail!("Nicht unterstuetztes DATABASE_URL-Schema fuer Agent-Release-Store");
    }

    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }

    pub async fn list_artifacts(
        &self,
        tenant_id: i64,
        limit: i64,
        target_os: Option<&str>,
    ) -> anyhow::Result<Vec<AgentReleaseArtifact>> {
        let limit = clamp_limit(limit);
        match self {
            Self::Postgres(pool) => {
                list_artifacts_postgres(pool, tenant_id, limit, target_os).await
            }
            Self::Sqlite(pool) => list_artifacts_sqlite(pool, tenant_id, limit, target_os).await,
        }
    }

    pub async fn artifact_detail(
        &self,
        tenant_id: i64,
        artifact_id: &str,
    ) -> anyhow::Result<Option<AgentReleaseArtifactDetail>> {
        match self {
            Self::Postgres(pool) => artifact_detail_postgres(pool, tenant_id, artifact_id).await,
            Self::Sqlite(pool) => artifact_detail_sqlite(pool, tenant_id, artifact_id).await,
        }
    }

    pub async fn refresh_artifacts(
        &self,
        tenant_id: i64,
        actor_id: i64,
    ) -> anyhow::Result<AgentArtifactRefreshResult> {
        match self {
            Self::Postgres(pool) => refresh_artifacts_postgres(pool, tenant_id, actor_id).await,
            Self::Sqlite(pool) => refresh_artifacts_sqlite(pool, tenant_id, actor_id).await,
        }
    }

    pub async fn verify_checksum(
        &self,
        tenant_id: i64,
        actor_id: i64,
        artifact_id: &str,
    ) -> anyhow::Result<Option<AgentArtifactVerificationResult>> {
        match self {
            Self::Postgres(pool) => {
                verify_checksum_postgres(pool, tenant_id, actor_id, artifact_id).await
            }
            Self::Sqlite(pool) => {
                verify_checksum_sqlite(pool, tenant_id, actor_id, artifact_id).await
            }
        }
    }

    pub async fn verify_signature(
        &self,
        tenant_id: i64,
        actor_id: i64,
        artifact_id: &str,
    ) -> anyhow::Result<Option<AgentArtifactVerificationResult>> {
        match self {
            Self::Postgres(pool) => {
                verify_signature_postgres(pool, tenant_id, actor_id, artifact_id).await
            }
            Self::Sqlite(pool) => {
                verify_signature_sqlite(pool, tenant_id, actor_id, artifact_id).await
            }
        }
    }

    pub async fn list_provenance(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<AgentReleaseProvenance>> {
        let limit = clamp_limit(limit);
        match self {
            Self::Postgres(pool) => list_provenance_postgres(pool, tenant_id, limit).await,
            Self::Sqlite(pool) => list_provenance_sqlite(pool, tenant_id, limit).await,
        }
    }

    pub async fn provenance_detail(
        &self,
        tenant_id: i64,
        provenance_id: &str,
    ) -> anyhow::Result<Option<AgentReleaseProvenance>> {
        match self {
            Self::Postgres(pool) => {
                provenance_detail_postgres(pool, tenant_id, provenance_id).await
            }
            Self::Sqlite(pool) => provenance_detail_sqlite(pool, tenant_id, provenance_id).await,
        }
    }

    pub async fn artifact_provenance(
        &self,
        tenant_id: i64,
        artifact_id: &str,
    ) -> anyhow::Result<Option<AgentReleaseProvenance>> {
        match self {
            Self::Postgres(pool) => {
                artifact_provenance_postgres(pool, tenant_id, artifact_id).await
            }
            Self::Sqlite(pool) => artifact_provenance_sqlite(pool, tenant_id, artifact_id).await,
        }
    }

    pub async fn onboarding_artifacts(
        &self,
        tenant_id: i64,
        os_family: Option<&str>,
    ) -> anyhow::Result<Vec<AgentReleaseArtifact>> {
        let target_os = os_family.and_then(onboarding_target_os);
        self.list_artifacts(tenant_id, 20, target_os.as_deref())
            .await
    }
}

fn clamp_limit(limit: i64) -> i64 {
    limit.clamp(1, 100)
}

fn onboarding_target_os(os_family: &str) -> Option<String> {
    match os_family.trim().to_ascii_uppercase().as_str() {
        "WINDOWS" => Some("windows".to_string()),
        "LINUX" => Some("linux".to_string()),
        "MACOS" => Some("macos".to_string()),
        "NIXOS" => Some("nixos".to_string()),
        _ => None,
    }
}

fn source_by_artifact_id(artifact_id: &str) -> Option<AgentArtifactSource> {
    AGENT_ARTIFACT_SOURCES
        .iter()
        .copied()
        .find(|source| source.artifact_id == artifact_id)
}

fn artifact_sha256(source: AgentArtifactSource) -> String {
    let mut hasher = Sha256::new();
    hasher.update(source.content);
    format!("{:x}", hasher.finalize())
}

fn build_hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn source_tree_hash() -> String {
    let mut hasher = Sha256::new();
    for source in AGENT_ARTIFACT_SOURCES {
        hasher.update(source.artifact_reference.as_bytes());
        hasher.update(source.content);
    }
    format!("{:x}", hasher.finalize())
}

fn build_metadata(source: AgentArtifactSource) -> Value {
    json!({
        "modell": "Agent-Artefaktmanifest",
        "hinweis": "Metadaten und SHA-256 werden aus einer festen Repo-Artefakt-Allowlist erzeugt.",
        "artifact_reference": source.artifact_reference,
        "contains_secret_material": false,
        "production_signature": false,
        "external_attestation": false
    })
}

fn provenance_metadata(source: AgentArtifactSource) -> AgentReleaseProvenance {
    let repository = option_env!("GITHUB_REPOSITORY")
        .unwrap_or("ewilhelm1979-netizen/ISCY")
        .to_string();
    let source_branch = option_env!("GITHUB_REF_NAME")
        .unwrap_or("unknown")
        .to_string();
    let git_commit = option_env!("GITHUB_SHA").unwrap_or("unknown").to_string();
    let workflow = option_env!("GITHUB_WORKFLOW")
        .unwrap_or("not_available")
        .to_string();
    let run_id = option_env!("GITHUB_RUN_ID").unwrap_or("").to_string();
    let generated_at = Utc::now().to_rfc3339();
    AgentReleaseProvenance {
        id: 0,
        tenant_id: 0,
        provenance_id: format!("prov-{}", source.artifact_id),
        artifact_id: source.artifact_id.to_string(),
        git_commit,
        source_repository: repository,
        source_branch,
        build_workflow: workflow,
        build_run_id: run_id,
        build_started_at: None,
        build_finished_at: None,
        builder_identity: option_env!("GITHUB_ACTOR")
            .unwrap_or("not_available")
            .to_string(),
        build_environment: "rust-backend-embedded-manifest".to_string(),
        dependency_lock_hash: build_hash(include_bytes!("../Cargo.lock")),
        cargo_lock_hash: build_hash(include_bytes!("../Cargo.lock")),
        nix_flake_lock_hash: build_hash(include_bytes!("../../../flake.lock")),
        source_tree_hash: source_tree_hash(),
        ci_status: "not_available".to_string(),
        codeql_status: "not_available".to_string(),
        cargo_audit_status: "not_available".to_string(),
        cargo_deny_status: "not_available".to_string(),
        provenance_status: PROVENANCE_STATUS_INCOMPLETE.to_string(),
        attestation_reference: String::new(),
        generated_at,
    }
}

fn artifact_values(source: AgentArtifactSource, tenant_id: i64) -> AgentReleaseArtifact {
    let now = Utc::now().to_rfc3339();
    AgentReleaseArtifact {
        id: 0,
        tenant_id,
        artifact_id: source.artifact_id.to_string(),
        artifact_name: source.artifact_name.to_string(),
        artifact_type: source.artifact_type.to_string(),
        target_os: source.target_os.to_string(),
        target_arch: source.target_arch.to_string(),
        package_format: source.package_format.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        build_profile: option_env!("ISCY_BUILD_PROFILE")
            .unwrap_or("unknown")
            .to_string(),
        git_commit: option_env!("GITHUB_SHA").unwrap_or("unknown").to_string(),
        source_branch: option_env!("GITHUB_REF_NAME")
            .unwrap_or("unknown")
            .to_string(),
        created_at: now.clone(),
        sha256: artifact_sha256(source),
        size_bytes: source.content.len() as i64,
        content_type: source.content_type.to_string(),
        artifact_reference: source.artifact_reference.to_string(),
        signature_status: SIGNATURE_STATUS_UNSIGNED.to_string(),
        provenance_status: PROVENANCE_STATUS_INCOMPLETE.to_string(),
        verification_status: CHECKSUM_STATUS_CALCULATED.to_string(),
        known_limitations: source.known_limitations.to_string(),
        metadata_json: build_metadata(source),
        last_checked_at: None,
        updated_at: now,
    }
}

async fn refresh_artifacts_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    actor_id: i64,
) -> anyhow::Result<AgentArtifactRefreshResult> {
    let mut refreshed = 0;
    for source in AGENT_ARTIFACT_SOURCES {
        upsert_artifact_sqlite(pool, tenant_id, *source).await?;
        upsert_signature_sqlite(pool, tenant_id, source.artifact_id).await?;
        upsert_provenance_sqlite(pool, tenant_id, *source).await?;
        insert_event_sqlite(
            pool,
            VerificationEventInput {
                tenant_id,
                artifact_id: source.artifact_id,
                event_type: "manifest_refreshed",
                actor_id: Some(actor_id),
                status: CHECKSUM_STATUS_CALCULATED,
                summary: "Artefaktmanifest aus sicherer Allowlist aktualisiert.",
                error_class: "",
            },
        )
        .await?;
        refreshed += 1;
    }
    let artifacts = list_artifacts_sqlite(pool, tenant_id, 100, None).await?;
    Ok(AgentArtifactRefreshResult {
        tenant_id,
        refreshed,
        artifacts,
    })
}

async fn refresh_artifacts_postgres(
    pool: &PgPool,
    tenant_id: i64,
    actor_id: i64,
) -> anyhow::Result<AgentArtifactRefreshResult> {
    let mut refreshed = 0;
    for source in AGENT_ARTIFACT_SOURCES {
        upsert_artifact_postgres(pool, tenant_id, *source).await?;
        upsert_signature_postgres(pool, tenant_id, source.artifact_id).await?;
        upsert_provenance_postgres(pool, tenant_id, *source).await?;
        insert_event_postgres(
            pool,
            VerificationEventInput {
                tenant_id,
                artifact_id: source.artifact_id,
                event_type: "manifest_refreshed",
                actor_id: Some(actor_id),
                status: CHECKSUM_STATUS_CALCULATED,
                summary: "Artefaktmanifest aus sicherer Allowlist aktualisiert.",
                error_class: "",
            },
        )
        .await?;
        refreshed += 1;
    }
    let artifacts = list_artifacts_postgres(pool, tenant_id, 100, None).await?;
    Ok(AgentArtifactRefreshResult {
        tenant_id,
        refreshed,
        artifacts,
    })
}

async fn upsert_artifact_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    source: AgentArtifactSource,
) -> anyhow::Result<()> {
    let artifact = artifact_values(source, tenant_id);
    sqlx::query(
        r#"
        INSERT INTO agent_release_artifact (
            tenant_id, artifact_id, artifact_name, artifact_type, target_os, target_arch,
            package_format, version, build_profile, git_commit, source_branch, created_at,
            sha256, size_bytes, content_type, artifact_reference, signature_status,
            provenance_status, verification_status, known_limitations, metadata_json,
            last_checked_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (tenant_id, artifact_id) DO UPDATE SET
            artifact_name = excluded.artifact_name,
            artifact_type = excluded.artifact_type,
            target_os = excluded.target_os,
            target_arch = excluded.target_arch,
            package_format = excluded.package_format,
            version = excluded.version,
            build_profile = excluded.build_profile,
            git_commit = excluded.git_commit,
            source_branch = excluded.source_branch,
            sha256 = excluded.sha256,
            size_bytes = excluded.size_bytes,
            content_type = excluded.content_type,
            artifact_reference = excluded.artifact_reference,
            provenance_status = excluded.provenance_status,
            verification_status = excluded.verification_status,
            known_limitations = excluded.known_limitations,
            metadata_json = excluded.metadata_json,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(artifact.tenant_id)
    .bind(&artifact.artifact_id)
    .bind(&artifact.artifact_name)
    .bind(&artifact.artifact_type)
    .bind(&artifact.target_os)
    .bind(&artifact.target_arch)
    .bind(&artifact.package_format)
    .bind(&artifact.version)
    .bind(&artifact.build_profile)
    .bind(&artifact.git_commit)
    .bind(&artifact.source_branch)
    .bind(&artifact.created_at)
    .bind(&artifact.sha256)
    .bind(artifact.size_bytes)
    .bind(&artifact.content_type)
    .bind(&artifact.artifact_reference)
    .bind(&artifact.signature_status)
    .bind(&artifact.provenance_status)
    .bind(&artifact.verification_status)
    .bind(&artifact.known_limitations)
    .bind(artifact.metadata_json.to_string())
    .bind(&artifact.last_checked_at)
    .bind(&artifact.updated_at)
    .execute(pool)
    .await
    .context("SQLite-Agent-Artefaktmanifest konnte nicht aktualisiert werden")?;
    Ok(())
}

async fn upsert_artifact_postgres(
    pool: &PgPool,
    tenant_id: i64,
    source: AgentArtifactSource,
) -> anyhow::Result<()> {
    let artifact = artifact_values(source, tenant_id);
    sqlx::query(
        r#"
        INSERT INTO agent_release_artifact (
            tenant_id, artifact_id, artifact_name, artifact_type, target_os, target_arch,
            package_format, version, build_profile, git_commit, source_branch, created_at,
            sha256, size_bytes, content_type, artifact_reference, signature_status,
            provenance_status, verification_status, known_limitations, metadata_json,
            last_checked_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)
        ON CONFLICT (tenant_id, artifact_id) DO UPDATE SET
            artifact_name = excluded.artifact_name,
            artifact_type = excluded.artifact_type,
            target_os = excluded.target_os,
            target_arch = excluded.target_arch,
            package_format = excluded.package_format,
            version = excluded.version,
            build_profile = excluded.build_profile,
            git_commit = excluded.git_commit,
            source_branch = excluded.source_branch,
            sha256 = excluded.sha256,
            size_bytes = excluded.size_bytes,
            content_type = excluded.content_type,
            artifact_reference = excluded.artifact_reference,
            provenance_status = excluded.provenance_status,
            verification_status = excluded.verification_status,
            known_limitations = excluded.known_limitations,
            metadata_json = excluded.metadata_json,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(artifact.tenant_id)
    .bind(&artifact.artifact_id)
    .bind(&artifact.artifact_name)
    .bind(&artifact.artifact_type)
    .bind(&artifact.target_os)
    .bind(&artifact.target_arch)
    .bind(&artifact.package_format)
    .bind(&artifact.version)
    .bind(&artifact.build_profile)
    .bind(&artifact.git_commit)
    .bind(&artifact.source_branch)
    .bind(&artifact.created_at)
    .bind(&artifact.sha256)
    .bind(artifact.size_bytes)
    .bind(&artifact.content_type)
    .bind(&artifact.artifact_reference)
    .bind(&artifact.signature_status)
    .bind(&artifact.provenance_status)
    .bind(&artifact.verification_status)
    .bind(&artifact.known_limitations)
    .bind(artifact.metadata_json.to_string())
    .bind(&artifact.last_checked_at)
    .bind(&artifact.updated_at)
    .execute(pool)
    .await
    .context("PostgreSQL-Agent-Artefaktmanifest konnte nicht aktualisiert werden")?;
    Ok(())
}

async fn upsert_signature_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    artifact_id: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO agent_artifact_signature (
            tenant_id, artifact_id, signature_algorithm, signature_type, signature_reference,
            signer_identity, signer_fingerprint, signature_status,
            verification_error_class, verification_summary, created_at, updated_at
        )
        VALUES (?, ?, '', 'future_codesign', '', '', '', 'unsigned', '', 'Keine produktive Signatur konfiguriert.', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ON CONFLICT (tenant_id, artifact_id) DO NOTHING
        "#,
    )
    .bind(tenant_id)
    .bind(artifact_id)
    .execute(pool)
    .await
    .context("SQLite-Agent-Signaturmetadaten konnten nicht initialisiert werden")?;
    Ok(())
}

async fn upsert_signature_postgres(
    pool: &PgPool,
    tenant_id: i64,
    artifact_id: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO agent_artifact_signature (
            tenant_id, artifact_id, signature_algorithm, signature_type, signature_reference,
            signer_identity, signer_fingerprint, signature_status,
            verification_error_class, verification_summary, created_at, updated_at
        )
        VALUES ($1, $2, '', 'future_codesign', '', '', '', 'unsigned', '', 'Keine produktive Signatur konfiguriert.', (CURRENT_TIMESTAMP)::text, (CURRENT_TIMESTAMP)::text)
        ON CONFLICT (tenant_id, artifact_id) DO NOTHING
        "#,
    )
    .bind(tenant_id)
    .bind(artifact_id)
    .execute(pool)
    .await
    .context("PostgreSQL-Agent-Signaturmetadaten konnten nicht initialisiert werden")?;
    Ok(())
}

async fn upsert_provenance_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    source: AgentArtifactSource,
) -> anyhow::Result<()> {
    let provenance = provenance_metadata(source);
    sqlx::query(provenance_upsert_sqlite())
        .bind(tenant_id)
        .bind(&provenance.provenance_id)
        .bind(&provenance.artifact_id)
        .bind(&provenance.git_commit)
        .bind(&provenance.source_repository)
        .bind(&provenance.source_branch)
        .bind(&provenance.build_workflow)
        .bind(&provenance.build_run_id)
        .bind(&provenance.build_started_at)
        .bind(&provenance.build_finished_at)
        .bind(&provenance.builder_identity)
        .bind(&provenance.build_environment)
        .bind(&provenance.dependency_lock_hash)
        .bind(&provenance.cargo_lock_hash)
        .bind(&provenance.nix_flake_lock_hash)
        .bind(&provenance.source_tree_hash)
        .bind(&provenance.ci_status)
        .bind(&provenance.codeql_status)
        .bind(&provenance.cargo_audit_status)
        .bind(&provenance.cargo_deny_status)
        .bind(&provenance.provenance_status)
        .bind(&provenance.attestation_reference)
        .bind(&provenance.generated_at)
        .execute(pool)
        .await
        .context("SQLite-Agent-Provenance konnte nicht aktualisiert werden")?;
    Ok(())
}

async fn upsert_provenance_postgres(
    pool: &PgPool,
    tenant_id: i64,
    source: AgentArtifactSource,
) -> anyhow::Result<()> {
    let provenance = provenance_metadata(source);
    sqlx::query(provenance_upsert_postgres())
        .bind(tenant_id)
        .bind(&provenance.provenance_id)
        .bind(&provenance.artifact_id)
        .bind(&provenance.git_commit)
        .bind(&provenance.source_repository)
        .bind(&provenance.source_branch)
        .bind(&provenance.build_workflow)
        .bind(&provenance.build_run_id)
        .bind(&provenance.build_started_at)
        .bind(&provenance.build_finished_at)
        .bind(&provenance.builder_identity)
        .bind(&provenance.build_environment)
        .bind(&provenance.dependency_lock_hash)
        .bind(&provenance.cargo_lock_hash)
        .bind(&provenance.nix_flake_lock_hash)
        .bind(&provenance.source_tree_hash)
        .bind(&provenance.ci_status)
        .bind(&provenance.codeql_status)
        .bind(&provenance.cargo_audit_status)
        .bind(&provenance.cargo_deny_status)
        .bind(&provenance.provenance_status)
        .bind(&provenance.attestation_reference)
        .bind(&provenance.generated_at)
        .execute(pool)
        .await
        .context("PostgreSQL-Agent-Provenance konnte nicht aktualisiert werden")?;
    Ok(())
}

fn provenance_upsert_sqlite() -> &'static str {
    r#"
    INSERT INTO agent_release_provenance (
        tenant_id, provenance_id, artifact_id, git_commit, source_repository, source_branch,
        build_workflow, build_run_id, build_started_at, build_finished_at, builder_identity,
        build_environment, dependency_lock_hash, cargo_lock_hash, nix_flake_lock_hash,
        source_tree_hash, ci_status, codeql_status, cargo_audit_status, cargo_deny_status,
        provenance_status, attestation_reference, generated_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT (tenant_id, provenance_id) DO UPDATE SET
        git_commit = excluded.git_commit,
        source_repository = excluded.source_repository,
        source_branch = excluded.source_branch,
        build_workflow = excluded.build_workflow,
        build_run_id = excluded.build_run_id,
        builder_identity = excluded.builder_identity,
        build_environment = excluded.build_environment,
        dependency_lock_hash = excluded.dependency_lock_hash,
        cargo_lock_hash = excluded.cargo_lock_hash,
        nix_flake_lock_hash = excluded.nix_flake_lock_hash,
        source_tree_hash = excluded.source_tree_hash,
        ci_status = excluded.ci_status,
        codeql_status = excluded.codeql_status,
        cargo_audit_status = excluded.cargo_audit_status,
        cargo_deny_status = excluded.cargo_deny_status,
        provenance_status = excluded.provenance_status,
        attestation_reference = excluded.attestation_reference,
        generated_at = excluded.generated_at
    "#
}

fn provenance_upsert_postgres() -> &'static str {
    r#"
    INSERT INTO agent_release_provenance (
        tenant_id, provenance_id, artifact_id, git_commit, source_repository, source_branch,
        build_workflow, build_run_id, build_started_at, build_finished_at, builder_identity,
        build_environment, dependency_lock_hash, cargo_lock_hash, nix_flake_lock_hash,
        source_tree_hash, ci_status, codeql_status, cargo_audit_status, cargo_deny_status,
        provenance_status, attestation_reference, generated_at
    )
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)
    ON CONFLICT (tenant_id, provenance_id) DO UPDATE SET
        git_commit = excluded.git_commit,
        source_repository = excluded.source_repository,
        source_branch = excluded.source_branch,
        build_workflow = excluded.build_workflow,
        build_run_id = excluded.build_run_id,
        builder_identity = excluded.builder_identity,
        build_environment = excluded.build_environment,
        dependency_lock_hash = excluded.dependency_lock_hash,
        cargo_lock_hash = excluded.cargo_lock_hash,
        nix_flake_lock_hash = excluded.nix_flake_lock_hash,
        source_tree_hash = excluded.source_tree_hash,
        ci_status = excluded.ci_status,
        codeql_status = excluded.codeql_status,
        cargo_audit_status = excluded.cargo_audit_status,
        cargo_deny_status = excluded.cargo_deny_status,
        provenance_status = excluded.provenance_status,
        attestation_reference = excluded.attestation_reference,
        generated_at = excluded.generated_at
    "#
}

async fn verify_checksum_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    actor_id: i64,
    artifact_id: &str,
) -> anyhow::Result<Option<AgentArtifactVerificationResult>> {
    let Some(artifact) = get_artifact_sqlite(pool, tenant_id, artifact_id).await? else {
        return Ok(None);
    };
    let Some(source) = source_by_artifact_id(&artifact.artifact_id) else {
        return Ok(Some(
            update_checksum_status_sqlite(
                pool,
                tenant_id,
                actor_id,
                artifact,
                CHECKSUM_STATUS_MISMATCH,
                "Artefakt ist nicht in der sicheren Allowlist enthalten.",
                "artifact_not_allowlisted",
            )
            .await?,
        ));
    };
    let expected = artifact_sha256(source);
    let (status, summary, error_class) = if expected == artifact.sha256 {
        (
            CHECKSUM_STATUS_VERIFIED,
            "SHA-256-Pruefsumme stimmt mit dem allowlist-basierten Build-Artefakt ueberein.",
            "",
        )
    } else {
        (
            CHECKSUM_STATUS_MISMATCH,
            "SHA-256-Pruefsumme weicht vom allowlist-basierten Build-Artefakt ab.",
            "checksum_mismatch",
        )
    };
    Ok(Some(
        update_checksum_status_sqlite(
            pool,
            tenant_id,
            actor_id,
            artifact,
            status,
            summary,
            error_class,
        )
        .await?,
    ))
}

async fn verify_checksum_postgres(
    pool: &PgPool,
    tenant_id: i64,
    actor_id: i64,
    artifact_id: &str,
) -> anyhow::Result<Option<AgentArtifactVerificationResult>> {
    let Some(artifact) = get_artifact_postgres(pool, tenant_id, artifact_id).await? else {
        return Ok(None);
    };
    let Some(source) = source_by_artifact_id(&artifact.artifact_id) else {
        return Ok(Some(
            update_checksum_status_postgres(
                pool,
                tenant_id,
                actor_id,
                artifact,
                CHECKSUM_STATUS_MISMATCH,
                "Artefakt ist nicht in der sicheren Allowlist enthalten.",
                "artifact_not_allowlisted",
            )
            .await?,
        ));
    };
    let expected = artifact_sha256(source);
    let (status, summary, error_class) = if expected == artifact.sha256 {
        (
            CHECKSUM_STATUS_VERIFIED,
            "SHA-256-Pruefsumme stimmt mit dem allowlist-basierten Build-Artefakt ueberein.",
            "",
        )
    } else {
        (
            CHECKSUM_STATUS_MISMATCH,
            "SHA-256-Pruefsumme weicht vom allowlist-basierten Build-Artefakt ab.",
            "checksum_mismatch",
        )
    };
    Ok(Some(
        update_checksum_status_postgres(
            pool,
            tenant_id,
            actor_id,
            artifact,
            status,
            summary,
            error_class,
        )
        .await?,
    ))
}

async fn update_checksum_status_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    actor_id: i64,
    artifact: AgentReleaseArtifact,
    status: &str,
    summary: &str,
    error_class: &str,
) -> anyhow::Result<AgentArtifactVerificationResult> {
    sqlx::query(
        "UPDATE agent_release_artifact SET verification_status = ?, last_checked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE tenant_id = ? AND artifact_id = ?",
    )
    .bind(status)
    .bind(tenant_id)
    .bind(&artifact.artifact_id)
    .execute(pool)
    .await
    .context("SQLite-Agent-Artefaktpruefung konnte nicht gespeichert werden")?;
    insert_event_sqlite(
        pool,
        VerificationEventInput {
            tenant_id,
            artifact_id: &artifact.artifact_id,
            event_type: if status == CHECKSUM_STATUS_VERIFIED {
                "checksum_verified"
            } else {
                "checksum_mismatch"
            },
            actor_id: Some(actor_id),
            status,
            summary,
            error_class,
        },
    )
    .await?;
    let artifact = get_artifact_sqlite(pool, tenant_id, &artifact.artifact_id)
        .await?
        .context("Aktualisiertes Agent-Artefakt wurde nicht gefunden")?;
    Ok(AgentArtifactVerificationResult {
        tenant_id,
        artifact_id: artifact.artifact_id.clone(),
        status: status.to_string(),
        summary: summary.to_string(),
        artifact,
    })
}

async fn update_checksum_status_postgres(
    pool: &PgPool,
    tenant_id: i64,
    actor_id: i64,
    artifact: AgentReleaseArtifact,
    status: &str,
    summary: &str,
    error_class: &str,
) -> anyhow::Result<AgentArtifactVerificationResult> {
    sqlx::query(
        "UPDATE agent_release_artifact SET verification_status = $1, last_checked_at = (CURRENT_TIMESTAMP)::text, updated_at = (CURRENT_TIMESTAMP)::text WHERE tenant_id = $2 AND artifact_id = $3",
    )
    .bind(status)
    .bind(tenant_id)
    .bind(&artifact.artifact_id)
    .execute(pool)
    .await
    .context("PostgreSQL-Agent-Artefaktpruefung konnte nicht gespeichert werden")?;
    insert_event_postgres(
        pool,
        VerificationEventInput {
            tenant_id,
            artifact_id: &artifact.artifact_id,
            event_type: if status == CHECKSUM_STATUS_VERIFIED {
                "checksum_verified"
            } else {
                "checksum_mismatch"
            },
            actor_id: Some(actor_id),
            status,
            summary,
            error_class,
        },
    )
    .await?;
    let artifact = get_artifact_postgres(pool, tenant_id, &artifact.artifact_id)
        .await?
        .context("Aktualisiertes Agent-Artefakt wurde nicht gefunden")?;
    Ok(AgentArtifactVerificationResult {
        tenant_id,
        artifact_id: artifact.artifact_id.clone(),
        status: status.to_string(),
        summary: summary.to_string(),
        artifact,
    })
}

async fn verify_signature_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    actor_id: i64,
    artifact_id: &str,
) -> anyhow::Result<Option<AgentArtifactVerificationResult>> {
    let Some(artifact) = get_artifact_sqlite(pool, tenant_id, artifact_id).await? else {
        return Ok(None);
    };
    Ok(Some(
        update_signature_status_sqlite(
            pool,
            tenant_id,
            actor_id,
            artifact,
            SIGNATURE_STATUS_NOT_CONFIGURED,
            "Produktive Signaturpruefung ist fuer dieses Artefakt noch nicht konfiguriert.",
            "signature_not_configured",
        )
        .await?,
    ))
}

async fn verify_signature_postgres(
    pool: &PgPool,
    tenant_id: i64,
    actor_id: i64,
    artifact_id: &str,
) -> anyhow::Result<Option<AgentArtifactVerificationResult>> {
    let Some(artifact) = get_artifact_postgres(pool, tenant_id, artifact_id).await? else {
        return Ok(None);
    };
    Ok(Some(
        update_signature_status_postgres(
            pool,
            tenant_id,
            actor_id,
            artifact,
            SIGNATURE_STATUS_NOT_CONFIGURED,
            "Produktive Signaturpruefung ist fuer dieses Artefakt noch nicht konfiguriert.",
            "signature_not_configured",
        )
        .await?,
    ))
}

async fn update_signature_status_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    actor_id: i64,
    artifact: AgentReleaseArtifact,
    status: &str,
    summary: &str,
    error_class: &str,
) -> anyhow::Result<AgentArtifactVerificationResult> {
    sqlx::query(
        "UPDATE agent_artifact_signature SET signature_status = ?, signature_verified_at = CURRENT_TIMESTAMP, verification_error_class = ?, verification_summary = ?, updated_at = CURRENT_TIMESTAMP WHERE tenant_id = ? AND artifact_id = ?",
    )
    .bind(status)
    .bind(error_class)
    .bind(summary)
    .bind(tenant_id)
    .bind(&artifact.artifact_id)
    .execute(pool)
    .await
    .context("SQLite-Agent-Signaturstatus konnte nicht gespeichert werden")?;
    sqlx::query(
        "UPDATE agent_release_artifact SET signature_status = ?, last_checked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE tenant_id = ? AND artifact_id = ?",
    )
    .bind(status)
    .bind(tenant_id)
    .bind(&artifact.artifact_id)
    .execute(pool)
    .await
    .context("SQLite-Agent-Artefaktsignatur konnte nicht aktualisiert werden")?;
    insert_event_sqlite(
        pool,
        VerificationEventInput {
            tenant_id,
            artifact_id: &artifact.artifact_id,
            event_type: "signature_verification_failed",
            actor_id: Some(actor_id),
            status,
            summary,
            error_class,
        },
    )
    .await?;
    let artifact = get_artifact_sqlite(pool, tenant_id, &artifact.artifact_id)
        .await?
        .context("Aktualisiertes Agent-Artefakt wurde nicht gefunden")?;
    Ok(AgentArtifactVerificationResult {
        tenant_id,
        artifact_id: artifact.artifact_id.clone(),
        status: status.to_string(),
        summary: summary.to_string(),
        artifact,
    })
}

async fn update_signature_status_postgres(
    pool: &PgPool,
    tenant_id: i64,
    actor_id: i64,
    artifact: AgentReleaseArtifact,
    status: &str,
    summary: &str,
    error_class: &str,
) -> anyhow::Result<AgentArtifactVerificationResult> {
    sqlx::query(
        "UPDATE agent_artifact_signature SET signature_status = $1, signature_verified_at = (CURRENT_TIMESTAMP)::text, verification_error_class = $2, verification_summary = $3, updated_at = (CURRENT_TIMESTAMP)::text WHERE tenant_id = $4 AND artifact_id = $5",
    )
    .bind(status)
    .bind(error_class)
    .bind(summary)
    .bind(tenant_id)
    .bind(&artifact.artifact_id)
    .execute(pool)
    .await
    .context("PostgreSQL-Agent-Signaturstatus konnte nicht gespeichert werden")?;
    sqlx::query(
        "UPDATE agent_release_artifact SET signature_status = $1, last_checked_at = (CURRENT_TIMESTAMP)::text, updated_at = (CURRENT_TIMESTAMP)::text WHERE tenant_id = $2 AND artifact_id = $3",
    )
    .bind(status)
    .bind(tenant_id)
    .bind(&artifact.artifact_id)
    .execute(pool)
    .await
    .context("PostgreSQL-Agent-Artefaktsignatur konnte nicht aktualisiert werden")?;
    insert_event_postgres(
        pool,
        VerificationEventInput {
            tenant_id,
            artifact_id: &artifact.artifact_id,
            event_type: "signature_verification_failed",
            actor_id: Some(actor_id),
            status,
            summary,
            error_class,
        },
    )
    .await?;
    let artifact = get_artifact_postgres(pool, tenant_id, &artifact.artifact_id)
        .await?
        .context("Aktualisiertes Agent-Artefakt wurde nicht gefunden")?;
    Ok(AgentArtifactVerificationResult {
        tenant_id,
        artifact_id: artifact.artifact_id.clone(),
        status: status.to_string(),
        summary: summary.to_string(),
        artifact,
    })
}

async fn get_artifact_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    artifact_id: &str,
) -> anyhow::Result<Option<AgentReleaseArtifact>> {
    let sql = artifact_select_sqlite("WHERE tenant_id = ? AND artifact_id = ?");
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(artifact_id)
        .fetch_optional(pool)
        .await?;
    row.map(artifact_from_sqlite_row).transpose()
}

async fn get_artifact_postgres(
    pool: &PgPool,
    tenant_id: i64,
    artifact_id: &str,
) -> anyhow::Result<Option<AgentReleaseArtifact>> {
    let sql = artifact_select_postgres("WHERE tenant_id = $1 AND artifact_id = $2");
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(artifact_id)
        .fetch_optional(pool)
        .await?;
    row.map(artifact_from_pg_row).transpose()
}

async fn list_artifacts_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
    target_os: Option<&str>,
) -> anyhow::Result<Vec<AgentReleaseArtifact>> {
    let rows = if let Some(target_os) = target_os {
        let sql = artifact_select_sqlite(
            "WHERE tenant_id = ? AND (target_os = ? OR target_os = 'all') ORDER BY artifact_name LIMIT ?",
        );
        sqlx::query(&sql)
            .bind(tenant_id)
            .bind(target_os)
            .bind(limit)
            .fetch_all(pool)
            .await?
    } else {
        let sql = artifact_select_sqlite("WHERE tenant_id = ? ORDER BY artifact_name LIMIT ?");
        sqlx::query(&sql)
            .bind(tenant_id)
            .bind(limit)
            .fetch_all(pool)
            .await?
    };
    rows.into_iter().map(artifact_from_sqlite_row).collect()
}

async fn list_artifacts_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
    target_os: Option<&str>,
) -> anyhow::Result<Vec<AgentReleaseArtifact>> {
    let rows = if let Some(target_os) = target_os {
        let sql = artifact_select_postgres(
            "WHERE tenant_id = $1 AND (target_os = $2 OR target_os = 'all') ORDER BY artifact_name LIMIT $3",
        );
        sqlx::query(&sql)
            .bind(tenant_id)
            .bind(target_os)
            .bind(limit)
            .fetch_all(pool)
            .await?
    } else {
        let sql = artifact_select_postgres("WHERE tenant_id = $1 ORDER BY artifact_name LIMIT $2");
        sqlx::query(&sql)
            .bind(tenant_id)
            .bind(limit)
            .fetch_all(pool)
            .await?
    };
    rows.into_iter().map(artifact_from_pg_row).collect()
}

fn artifact_select_sqlite(where_clause: &str) -> String {
    format!(
        r#"
        SELECT id, tenant_id, artifact_id, artifact_name, artifact_type, target_os, target_arch,
               package_format, version, build_profile, git_commit, source_branch, created_at,
               sha256, size_bytes, content_type, artifact_reference, signature_status,
               provenance_status, verification_status, known_limitations, metadata_json,
               last_checked_at, updated_at
        FROM agent_release_artifact
        {where_clause}
        "#
    )
}

fn artifact_select_postgres(where_clause: &str) -> String {
    artifact_select_sqlite(where_clause)
}

async fn artifact_detail_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    artifact_id: &str,
) -> anyhow::Result<Option<AgentReleaseArtifactDetail>> {
    let Some(artifact) = get_artifact_sqlite(pool, tenant_id, artifact_id).await? else {
        return Ok(None);
    };
    let signature = get_signature_sqlite(pool, tenant_id, artifact_id).await?;
    let provenance = artifact_provenance_sqlite(pool, tenant_id, artifact_id).await?;
    let recent_events = list_events_sqlite(pool, tenant_id, artifact_id, 20).await?;
    Ok(Some(AgentReleaseArtifactDetail {
        artifact,
        signature,
        provenance,
        recent_events,
    }))
}

async fn artifact_detail_postgres(
    pool: &PgPool,
    tenant_id: i64,
    artifact_id: &str,
) -> anyhow::Result<Option<AgentReleaseArtifactDetail>> {
    let Some(artifact) = get_artifact_postgres(pool, tenant_id, artifact_id).await? else {
        return Ok(None);
    };
    let signature = get_signature_postgres(pool, tenant_id, artifact_id).await?;
    let provenance = artifact_provenance_postgres(pool, tenant_id, artifact_id).await?;
    let recent_events = list_events_postgres(pool, tenant_id, artifact_id, 20).await?;
    Ok(Some(AgentReleaseArtifactDetail {
        artifact,
        signature,
        provenance,
        recent_events,
    }))
}

async fn get_signature_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    artifact_id: &str,
) -> anyhow::Result<Option<AgentArtifactSignature>> {
    let sql = signature_select_sql("WHERE tenant_id = ? AND artifact_id = ?");
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(artifact_id)
        .fetch_optional(pool)
        .await?;
    row.map(signature_from_sqlite_row).transpose()
}

async fn get_signature_postgres(
    pool: &PgPool,
    tenant_id: i64,
    artifact_id: &str,
) -> anyhow::Result<Option<AgentArtifactSignature>> {
    let sql = signature_select_sql("WHERE tenant_id = $1 AND artifact_id = $2");
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(artifact_id)
        .fetch_optional(pool)
        .await?;
    row.map(signature_from_pg_row).transpose()
}

fn signature_select_sql(where_clause: &str) -> String {
    format!(
        r#"
        SELECT id, tenant_id, artifact_id, signature_algorithm, signature_type,
               signature_reference, signer_identity, signer_fingerprint,
               signature_created_at, signature_verified_at, signature_status,
               verification_error_class, verification_summary, created_at, updated_at
        FROM agent_artifact_signature
        {where_clause}
        "#
    )
}

async fn list_provenance_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AgentReleaseProvenance>> {
    let sql = provenance_select_sql(
        "WHERE tenant_id = ? ORDER BY generated_at DESC, provenance_id LIMIT ?",
    );
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await?;
    rows.into_iter().map(provenance_from_sqlite_row).collect()
}

async fn list_provenance_postgres(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<AgentReleaseProvenance>> {
    let sql = provenance_select_sql(
        "WHERE tenant_id = $1 ORDER BY generated_at DESC, provenance_id LIMIT $2",
    );
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await?;
    rows.into_iter().map(provenance_from_pg_row).collect()
}

async fn provenance_detail_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    provenance_id: &str,
) -> anyhow::Result<Option<AgentReleaseProvenance>> {
    let sql = provenance_select_sql("WHERE tenant_id = ? AND provenance_id = ?");
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(provenance_id)
        .fetch_optional(pool)
        .await?;
    row.map(provenance_from_sqlite_row).transpose()
}

async fn provenance_detail_postgres(
    pool: &PgPool,
    tenant_id: i64,
    provenance_id: &str,
) -> anyhow::Result<Option<AgentReleaseProvenance>> {
    let sql = provenance_select_sql("WHERE tenant_id = $1 AND provenance_id = $2");
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(provenance_id)
        .fetch_optional(pool)
        .await?;
    row.map(provenance_from_pg_row).transpose()
}

async fn artifact_provenance_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    artifact_id: &str,
) -> anyhow::Result<Option<AgentReleaseProvenance>> {
    let sql = provenance_select_sql(
        "WHERE tenant_id = ? AND artifact_id = ? ORDER BY generated_at DESC LIMIT 1",
    );
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(artifact_id)
        .fetch_optional(pool)
        .await?;
    row.map(provenance_from_sqlite_row).transpose()
}

async fn artifact_provenance_postgres(
    pool: &PgPool,
    tenant_id: i64,
    artifact_id: &str,
) -> anyhow::Result<Option<AgentReleaseProvenance>> {
    let sql = provenance_select_sql(
        "WHERE tenant_id = $1 AND artifact_id = $2 ORDER BY generated_at DESC LIMIT 1",
    );
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(artifact_id)
        .fetch_optional(pool)
        .await?;
    row.map(provenance_from_pg_row).transpose()
}

fn provenance_select_sql(where_clause: &str) -> String {
    format!(
        r#"
        SELECT id, tenant_id, provenance_id, artifact_id, git_commit, source_repository,
               source_branch, build_workflow, build_run_id, build_started_at,
               build_finished_at, builder_identity, build_environment, dependency_lock_hash,
               cargo_lock_hash, nix_flake_lock_hash, source_tree_hash, ci_status,
               codeql_status, cargo_audit_status, cargo_deny_status, provenance_status,
               attestation_reference, generated_at
        FROM agent_release_provenance
        {where_clause}
        "#
    )
}

async fn list_events_sqlite(
    pool: &SqlitePool,
    tenant_id: i64,
    artifact_id: &str,
    limit: i64,
) -> anyhow::Result<Vec<AgentArtifactVerificationEvent>> {
    let sql = event_select_sql(
        "WHERE tenant_id = ? AND artifact_id = ? ORDER BY created_at DESC LIMIT ?",
    );
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(artifact_id)
        .bind(limit)
        .fetch_all(pool)
        .await?;
    rows.into_iter().map(event_from_sqlite_row).collect()
}

async fn list_events_postgres(
    pool: &PgPool,
    tenant_id: i64,
    artifact_id: &str,
    limit: i64,
) -> anyhow::Result<Vec<AgentArtifactVerificationEvent>> {
    let sql = event_select_sql(
        "WHERE tenant_id = $1 AND artifact_id = $2 ORDER BY created_at DESC LIMIT $3",
    );
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(artifact_id)
        .bind(limit)
        .fetch_all(pool)
        .await?;
    rows.into_iter().map(event_from_pg_row).collect()
}

fn event_select_sql(where_clause: &str) -> String {
    format!(
        r#"
        SELECT id, tenant_id, artifact_id, event_type, actor_id, status, summary, error_class, created_at
        FROM agent_artifact_verification_event
        {where_clause}
        "#
    )
}

async fn insert_event_sqlite(
    pool: &SqlitePool,
    event: VerificationEventInput<'_>,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO agent_artifact_verification_event (
            tenant_id, artifact_id, event_type, actor_id, status, summary, error_class, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        "#,
    )
    .bind(event.tenant_id)
    .bind(event.artifact_id)
    .bind(event.event_type)
    .bind(event.actor_id)
    .bind(event.status)
    .bind(event.summary)
    .bind(event.error_class)
    .execute(pool)
    .await
    .context("SQLite-Agent-Artefakt-Audit konnte nicht geschrieben werden")?;
    Ok(())
}

async fn insert_event_postgres(
    pool: &PgPool,
    event: VerificationEventInput<'_>,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO agent_artifact_verification_event (
            tenant_id, artifact_id, event_type, actor_id, status, summary, error_class, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, (CURRENT_TIMESTAMP)::text)
        "#,
    )
    .bind(event.tenant_id)
    .bind(event.artifact_id)
    .bind(event.event_type)
    .bind(event.actor_id)
    .bind(event.status)
    .bind(event.summary)
    .bind(event.error_class)
    .execute(pool)
    .await
    .context("PostgreSQL-Agent-Artefakt-Audit konnte nicht geschrieben werden")?;
    Ok(())
}

fn artifact_from_sqlite_row(row: SqliteRow) -> anyhow::Result<AgentReleaseArtifact> {
    Ok(AgentReleaseArtifact {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        artifact_id: row.try_get("artifact_id")?,
        artifact_name: row.try_get("artifact_name")?,
        artifact_type: row.try_get("artifact_type")?,
        target_os: row.try_get("target_os")?,
        target_arch: row.try_get("target_arch")?,
        package_format: row.try_get("package_format")?,
        version: row.try_get("version")?,
        build_profile: row.try_get("build_profile")?,
        git_commit: row.try_get("git_commit")?,
        source_branch: row.try_get("source_branch")?,
        created_at: row.try_get("created_at")?,
        sha256: row.try_get("sha256")?,
        size_bytes: row.try_get("size_bytes")?,
        content_type: row.try_get("content_type")?,
        artifact_reference: row.try_get("artifact_reference")?,
        signature_status: row.try_get("signature_status")?,
        provenance_status: row.try_get("provenance_status")?,
        verification_status: row.try_get("verification_status")?,
        known_limitations: row.try_get("known_limitations")?,
        metadata_json: parse_json_object(row.try_get("metadata_json")?),
        last_checked_at: row.try_get("last_checked_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn artifact_from_pg_row(row: PgRow) -> anyhow::Result<AgentReleaseArtifact> {
    Ok(AgentReleaseArtifact {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        artifact_id: row.try_get("artifact_id")?,
        artifact_name: row.try_get("artifact_name")?,
        artifact_type: row.try_get("artifact_type")?,
        target_os: row.try_get("target_os")?,
        target_arch: row.try_get("target_arch")?,
        package_format: row.try_get("package_format")?,
        version: row.try_get("version")?,
        build_profile: row.try_get("build_profile")?,
        git_commit: row.try_get("git_commit")?,
        source_branch: row.try_get("source_branch")?,
        created_at: row.try_get("created_at")?,
        sha256: row.try_get("sha256")?,
        size_bytes: row.try_get("size_bytes")?,
        content_type: row.try_get("content_type")?,
        artifact_reference: row.try_get("artifact_reference")?,
        signature_status: row.try_get("signature_status")?,
        provenance_status: row.try_get("provenance_status")?,
        verification_status: row.try_get("verification_status")?,
        known_limitations: row.try_get("known_limitations")?,
        metadata_json: parse_json_object(row.try_get("metadata_json")?),
        last_checked_at: row.try_get("last_checked_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn signature_from_sqlite_row(row: SqliteRow) -> anyhow::Result<AgentArtifactSignature> {
    Ok(AgentArtifactSignature {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        artifact_id: row.try_get("artifact_id")?,
        signature_algorithm: row.try_get("signature_algorithm")?,
        signature_type: row.try_get("signature_type")?,
        signature_reference: row.try_get("signature_reference")?,
        signer_identity: row.try_get("signer_identity")?,
        signer_fingerprint: row.try_get("signer_fingerprint")?,
        signature_created_at: row.try_get("signature_created_at")?,
        signature_verified_at: row.try_get("signature_verified_at")?,
        signature_status: row.try_get("signature_status")?,
        verification_error_class: row.try_get("verification_error_class")?,
        verification_summary: row.try_get("verification_summary")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn signature_from_pg_row(row: PgRow) -> anyhow::Result<AgentArtifactSignature> {
    Ok(AgentArtifactSignature {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        artifact_id: row.try_get("artifact_id")?,
        signature_algorithm: row.try_get("signature_algorithm")?,
        signature_type: row.try_get("signature_type")?,
        signature_reference: row.try_get("signature_reference")?,
        signer_identity: row.try_get("signer_identity")?,
        signer_fingerprint: row.try_get("signer_fingerprint")?,
        signature_created_at: row.try_get("signature_created_at")?,
        signature_verified_at: row.try_get("signature_verified_at")?,
        signature_status: row.try_get("signature_status")?,
        verification_error_class: row.try_get("verification_error_class")?,
        verification_summary: row.try_get("verification_summary")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn provenance_from_sqlite_row(row: SqliteRow) -> anyhow::Result<AgentReleaseProvenance> {
    Ok(AgentReleaseProvenance {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        provenance_id: row.try_get("provenance_id")?,
        artifact_id: row.try_get("artifact_id")?,
        git_commit: row.try_get("git_commit")?,
        source_repository: row.try_get("source_repository")?,
        source_branch: row.try_get("source_branch")?,
        build_workflow: row.try_get("build_workflow")?,
        build_run_id: row.try_get("build_run_id")?,
        build_started_at: row.try_get("build_started_at")?,
        build_finished_at: row.try_get("build_finished_at")?,
        builder_identity: row.try_get("builder_identity")?,
        build_environment: row.try_get("build_environment")?,
        dependency_lock_hash: row.try_get("dependency_lock_hash")?,
        cargo_lock_hash: row.try_get("cargo_lock_hash")?,
        nix_flake_lock_hash: row.try_get("nix_flake_lock_hash")?,
        source_tree_hash: row.try_get("source_tree_hash")?,
        ci_status: row.try_get("ci_status")?,
        codeql_status: row.try_get("codeql_status")?,
        cargo_audit_status: row.try_get("cargo_audit_status")?,
        cargo_deny_status: row.try_get("cargo_deny_status")?,
        provenance_status: row.try_get("provenance_status")?,
        attestation_reference: row.try_get("attestation_reference")?,
        generated_at: row.try_get("generated_at")?,
    })
}

fn provenance_from_pg_row(row: PgRow) -> anyhow::Result<AgentReleaseProvenance> {
    Ok(AgentReleaseProvenance {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        provenance_id: row.try_get("provenance_id")?,
        artifact_id: row.try_get("artifact_id")?,
        git_commit: row.try_get("git_commit")?,
        source_repository: row.try_get("source_repository")?,
        source_branch: row.try_get("source_branch")?,
        build_workflow: row.try_get("build_workflow")?,
        build_run_id: row.try_get("build_run_id")?,
        build_started_at: row.try_get("build_started_at")?,
        build_finished_at: row.try_get("build_finished_at")?,
        builder_identity: row.try_get("builder_identity")?,
        build_environment: row.try_get("build_environment")?,
        dependency_lock_hash: row.try_get("dependency_lock_hash")?,
        cargo_lock_hash: row.try_get("cargo_lock_hash")?,
        nix_flake_lock_hash: row.try_get("nix_flake_lock_hash")?,
        source_tree_hash: row.try_get("source_tree_hash")?,
        ci_status: row.try_get("ci_status")?,
        codeql_status: row.try_get("codeql_status")?,
        cargo_audit_status: row.try_get("cargo_audit_status")?,
        cargo_deny_status: row.try_get("cargo_deny_status")?,
        provenance_status: row.try_get("provenance_status")?,
        attestation_reference: row.try_get("attestation_reference")?,
        generated_at: row.try_get("generated_at")?,
    })
}

fn event_from_sqlite_row(row: SqliteRow) -> anyhow::Result<AgentArtifactVerificationEvent> {
    Ok(AgentArtifactVerificationEvent {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        artifact_id: row.try_get("artifact_id")?,
        event_type: row.try_get("event_type")?,
        actor_id: row.try_get("actor_id")?,
        status: row.try_get("status")?,
        summary: row.try_get("summary")?,
        error_class: row.try_get("error_class")?,
        created_at: row.try_get("created_at")?,
    })
}

fn event_from_pg_row(row: PgRow) -> anyhow::Result<AgentArtifactVerificationEvent> {
    Ok(AgentArtifactVerificationEvent {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        artifact_id: row.try_get("artifact_id")?,
        event_type: row.try_get("event_type")?,
        actor_id: row.try_get("actor_id")?,
        status: row.try_get("status")?,
        summary: row.try_get("summary")?,
        error_class: row.try_get("error_class")?,
        created_at: row.try_get("created_at")?,
    })
}

fn parse_json_object(raw: String) -> Value {
    serde_json::from_str(&raw).unwrap_or_else(|_| json!({}))
}
