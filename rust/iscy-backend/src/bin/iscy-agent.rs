use std::{
    env, fs,
    path::{Path as FsPath, PathBuf},
    process::Command,
    time::Duration,
};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug)]
struct AgentConfig {
    backend_url: String,
    tenant_id: i64,
    user_id: i64,
    enrollment_token: Option<String>,
    agent_secret: Option<String>,
    mtls_fingerprint: Option<String>,
    state_path: PathBuf,
    queue_dir: PathBuf,
    queue_max_files: usize,
    dry_run: bool,
    self_test: bool,
}

#[derive(Debug, Clone, Serialize)]
struct DeviceInventory {
    asset_id: Option<i64>,
    stable_device_id: String,
    hostname: String,
    os_family: String,
    os_version: String,
    architecture: String,
    agent_version: String,
    deployment_channel: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentState {
    tenant_id: i64,
    stable_device_id: String,
    device_id: i64,
    agent_secret: Option<String>,
    updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct QueuedReport {
    queued_at: String,
    device_id: i64,
    heartbeat: Value,
    findings: Value,
}

#[derive(Debug)]
enum ReportFailure {
    Retryable(String),
    Fatal(String),
}

fn main() -> anyhow::Result<()> {
    let config = parse_config()?;
    let inventory = collect_inventory();
    let heartbeat = heartbeat_payload(&inventory);
    let findings = findings_payload(&inventory);

    if config.self_test || config.dry_run {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "inventory": inventory,
                "heartbeat": heartbeat,
                "findings": findings,
                "auth": {
                    "uses_enrollment_token": config.enrollment_token.is_some(),
                    "uses_agent_secret": config.agent_secret.is_some(),
                    "mtls_fingerprint_set": config.mtls_fingerprint.is_some()
                },
                "runtime": {
                    "state_path": config.state_path,
                    "queue_dir": config.queue_dir,
                    "queue_max_files": config.queue_max_files
                }
            }))?
        );
        return Ok(());
    }

    let client = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()?;
    let base_url = config.backend_url.trim_end_matches('/');
    let existing_state = load_agent_state(&config.state_path)?;
    if let Some(state) = existing_state.as_ref() {
        if state.tenant_id != config.tenant_id
            || state.stable_device_id != inventory.stable_device_id
        {
            anyhow::bail!(
                "Agent state belongs to a different tenant or stable device ID: {}",
                config.state_path.display()
            );
        }
    }

    let (device_id, agent_secret) = if let Some(state) = existing_state {
        (
            state.device_id,
            config.agent_secret.clone().or(state.agent_secret),
        )
    } else {
        enroll_agent(&client, base_url, &config, &inventory)?
    };
    persist_agent_state(
        &config.state_path,
        &AgentState {
            tenant_id: config.tenant_id,
            stable_device_id: inventory.stable_device_id.clone(),
            device_id,
            agent_secret: agent_secret.clone(),
            updated_at: Utc::now().to_rfc3339(),
        },
    )?;

    match flush_queued_reports(
        &client,
        base_url,
        &config,
        agent_secret.as_deref(),
        device_id,
    ) {
        Ok(flushed) if flushed > 0 => println!("ISCY agent flushed {flushed} queued report(s)"),
        Ok(_) => {}
        Err(ReportFailure::Retryable(message)) => {
            eprintln!("ISCY agent queue remains pending: {message}");
        }
        Err(ReportFailure::Fatal(message)) => anyhow::bail!(message),
    }

    let report = QueuedReport {
        queued_at: Utc::now().to_rfc3339(),
        device_id,
        heartbeat,
        findings,
    };
    match send_report(&client, base_url, &config, agent_secret.as_deref(), &report) {
        Ok(()) => println!("ISCY agent reported posture for device {device_id}"),
        Err(ReportFailure::Retryable(message)) => {
            let queued_path = enqueue_report(&config, &report)?;
            println!(
                "ISCY agent queued posture for device {device_id} at {}: {message}",
                queued_path.display()
            );
        }
        Err(ReportFailure::Fatal(message)) => anyhow::bail!(message),
    }
    Ok(())
}

fn enroll_agent(
    client: &reqwest::blocking::Client,
    base_url: &str,
    config: &AgentConfig,
    inventory: &DeviceInventory,
) -> anyhow::Result<(i64, Option<String>)> {
    let mut enroll_request = client
        .post(format!("{base_url}/api/v1/agents/enroll"))
        .header("x-iscy-tenant-id", config.tenant_id.to_string());
    if let Some(enrollment_token) = config.enrollment_token.as_deref() {
        enroll_request = enroll_request.header("x-iscy-agent-enrollment-token", enrollment_token);
    } else {
        enroll_request = enroll_request.header("x-iscy-user-id", config.user_id.to_string());
    }
    enroll_request = with_optional_mtls(enroll_request, config.mtls_fingerprint.as_deref());
    let enroll_response: Value = enroll_request
        .json(&inventory)
        .send()?
        .error_for_status()?
        .json()?;
    let device_id = enroll_response
        .get("device")
        .and_then(|device| device.get("id"))
        .and_then(Value::as_i64)
        .ok_or_else(|| anyhow::anyhow!("Agent enrollment response did not include device.id"))?;
    let agent_secret = enroll_response
        .get("agent_secret")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| config.agent_secret.clone());
    Ok((device_id, agent_secret))
}

fn parse_config() -> anyhow::Result<AgentConfig> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let self_test = args.iter().any(|arg| arg == "--self-test");
    let dry_run = args.iter().any(|arg| arg == "--dry-run");
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_usage();
        std::process::exit(0);
    }

    let backend_url = arg_value(&args, "--backend-url")
        .or_else(|| env::var("ISCY_BACKEND_URL").ok())
        .unwrap_or_else(|| "http://127.0.0.1:9000".to_string());
    let tenant_id = arg_value(&args, "--tenant-id")
        .or_else(|| env::var("ISCY_TENANT_ID").ok())
        .unwrap_or_else(|| "1".to_string())
        .parse::<i64>()?;
    let user_id = arg_value(&args, "--user-id")
        .or_else(|| env::var("ISCY_USER_ID").ok())
        .unwrap_or_else(|| "1".to_string())
        .parse::<i64>()?;
    let state_path = arg_value(&args, "--state-path")
        .or_else(|| env::var("ISCY_AGENT_STATE_PATH").ok())
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(default_agent_state_path);
    let queue_dir = arg_value(&args, "--queue-dir")
        .or_else(|| env::var("ISCY_AGENT_QUEUE_DIR").ok())
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            state_path
                .parent()
                .unwrap_or_else(|| FsPath::new("."))
                .join("queue")
        });
    let queue_max_files = arg_value(&args, "--queue-max-files")
        .or_else(|| env::var("ISCY_AGENT_QUEUE_MAX_FILES").ok())
        .unwrap_or_else(|| "100".to_string())
        .parse::<usize>()?;
    if !(1..=10_000).contains(&queue_max_files) {
        anyhow::bail!("ISCY_AGENT_QUEUE_MAX_FILES must be between 1 and 10000");
    }

    Ok(AgentConfig {
        backend_url,
        tenant_id,
        user_id,
        enrollment_token: arg_value(&args, "--enrollment-token")
            .or_else(|| env::var("ISCY_AGENT_ENROLLMENT_TOKEN").ok())
            .filter(|value| !value.trim().is_empty()),
        agent_secret: arg_value(&args, "--agent-secret")
            .or_else(|| env::var("ISCY_AGENT_SECRET").ok())
            .filter(|value| !value.trim().is_empty()),
        mtls_fingerprint: arg_value(&args, "--mtls-fingerprint")
            .or_else(|| env::var("ISCY_AGENT_MTLS_FINGERPRINT").ok())
            .filter(|value| !value.trim().is_empty()),
        state_path,
        queue_dir,
        queue_max_files,
        dry_run,
        self_test,
    })
}

fn default_agent_state_path() -> PathBuf {
    if let Ok(path) = env::var("XDG_STATE_HOME") {
        if !path.trim().is_empty() {
            return PathBuf::from(path).join("iscy-agent/state.json");
        }
    }
    if let Ok(path) = env::var("LOCALAPPDATA") {
        if !path.trim().is_empty() {
            return PathBuf::from(path).join("ISCY/Agent/state.json");
        }
    }
    if let Ok(path) = env::var("HOME") {
        if !path.trim().is_empty() {
            return PathBuf::from(path).join(".local/state/iscy-agent/state.json");
        }
    }
    env::temp_dir().join("iscy-agent/state.json")
}

fn load_agent_state(path: &FsPath) -> anyhow::Result<Option<AgentState>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|err| anyhow::anyhow!("Agent state {} is invalid: {err}", path.display()))
}

fn persist_agent_state(path: &FsPath, state: &AgentState) -> anyhow::Result<()> {
    secure_write_json(path, state)
}

fn secure_write_json<T: Serialize>(path: &FsPath, value: &T) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent)?;
    set_directory_permissions(parent)?;
    let temp_path = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&temp_path, serde_json::to_vec_pretty(value)?)?;
    set_file_permissions(&temp_path)?;
    #[cfg(windows)]
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(&temp_path, path)?;
    set_file_permissions(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_directory_permissions(path: &FsPath) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_directory_permissions(_path: &FsPath) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_file_permissions(path: &FsPath) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &FsPath) -> anyhow::Result<()> {
    Ok(())
}

fn send_report(
    client: &reqwest::blocking::Client,
    base_url: &str,
    config: &AgentConfig,
    agent_secret: Option<&str>,
    report: &QueuedReport,
) -> Result<(), ReportFailure> {
    let heartbeat_request = authenticated_agent_request(
        client.post(format!(
            "{base_url}/api/v1/agents/devices/{}/heartbeat",
            report.device_id
        )),
        config,
        agent_secret,
    );
    send_agent_json(heartbeat_request, &report.heartbeat, "heartbeat")?;
    let findings_request = authenticated_agent_request(
        client.post(format!(
            "{base_url}/api/v1/agents/devices/{}/findings",
            report.device_id
        )),
        config,
        agent_secret,
    );
    send_agent_json(findings_request, &report.findings, "findings")
}

fn send_agent_json(
    request: reqwest::blocking::RequestBuilder,
    payload: &Value,
    kind: &str,
) -> Result<(), ReportFailure> {
    let response = request
        .json(payload)
        .send()
        .map_err(|err| ReportFailure::Retryable(format!("Agent {kind} transport failed: {err}")))?;
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    let detail = response.text().unwrap_or_default();
    let message = format!("Agent {kind} rejected with HTTP {status}: {detail}");
    if status.is_server_error() || status.as_u16() == 429 {
        Err(ReportFailure::Retryable(message))
    } else {
        Err(ReportFailure::Fatal(message))
    }
}

fn enqueue_report(config: &AgentConfig, report: &QueuedReport) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(&config.queue_dir)?;
    set_directory_permissions(&config.queue_dir)?;
    let mut files = queued_report_files(&config.queue_dir)?;
    while files.len() >= config.queue_max_files {
        if let Some(oldest) = files.first().cloned() {
            fs::remove_file(&oldest)?;
            files.remove(0);
        }
    }
    let nonce = Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or_else(|| Utc::now().timestamp_millis() * 1_000_000);
    let path = config
        .queue_dir
        .join(format!("{nonce:020}-{}.json", std::process::id()));
    secure_write_json(&path, report)?;
    Ok(path)
}

fn queued_report_files(queue_dir: &FsPath) -> anyhow::Result<Vec<PathBuf>> {
    if !queue_dir.exists() {
        return Ok(Vec::new());
    }
    let mut files = fs::read_dir(queue_dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    files.sort();
    Ok(files)
}

fn flush_queued_reports(
    client: &reqwest::blocking::Client,
    base_url: &str,
    config: &AgentConfig,
    agent_secret: Option<&str>,
    device_id: i64,
) -> Result<usize, ReportFailure> {
    let files = queued_report_files(&config.queue_dir)
        .map_err(|err| ReportFailure::Fatal(format!("Agent queue could not be read: {err}")))?;
    let mut flushed = 0;
    for path in files {
        let report = match fs::read(&path)
            .map_err(|err| err.to_string())
            .and_then(|bytes| {
                serde_json::from_slice::<QueuedReport>(&bytes).map_err(|err| err.to_string())
            }) {
            Ok(report) if report.device_id == device_id => report,
            Ok(_) | Err(_) => {
                let invalid_path = path.with_extension("invalid");
                fs::rename(&path, &invalid_path).map_err(|err| {
                    ReportFailure::Fatal(format!(
                        "Invalid queue entry could not be isolated: {err}"
                    ))
                })?;
                continue;
            }
        };
        send_report(client, base_url, config, agent_secret, &report)?;
        fs::remove_file(&path).map_err(|err| {
            ReportFailure::Fatal(format!("Flushed queue entry could not be removed: {err}"))
        })?;
        flushed += 1;
    }
    Ok(flushed)
}

fn authenticated_agent_request(
    request: reqwest::blocking::RequestBuilder,
    config: &AgentConfig,
    agent_secret: Option<&str>,
) -> reqwest::blocking::RequestBuilder {
    let request = request.header("x-iscy-tenant-id", config.tenant_id.to_string());
    let request = if let Some(agent_secret) = agent_secret {
        request.header("x-iscy-agent-secret", agent_secret)
    } else {
        request.header("x-iscy-user-id", config.user_id.to_string())
    };
    with_optional_mtls(request, config.mtls_fingerprint.as_deref())
}

fn with_optional_mtls(
    request: reqwest::blocking::RequestBuilder,
    mtls_fingerprint: Option<&str>,
) -> reqwest::blocking::RequestBuilder {
    if let Some(mtls_fingerprint) = mtls_fingerprint {
        return request.header("x-iscy-agent-mtls-fingerprint", mtls_fingerprint);
    }
    request
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

fn collect_inventory() -> DeviceInventory {
    let hostname = hostname();
    let os_family = env::consts::OS.to_string();
    let architecture = env::consts::ARCH.to_string();
    let os_version = os_version(&os_family);
    let stable_device_id = env::var("ISCY_AGENT_DEVICE_ID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("{hostname}-{os_family}-{architecture}"));
    DeviceInventory {
        asset_id: env::var("ISCY_ASSET_ID")
            .ok()
            .and_then(|value| value.parse::<i64>().ok()),
        stable_device_id,
        hostname,
        os_family,
        os_version,
        architecture,
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        deployment_channel: env::var("ISCY_AGENT_CHANNEL").unwrap_or_else(|_| "manual".to_string()),
    }
}

fn heartbeat_payload(inventory: &DeviceInventory) -> Value {
    json!({
        "agent_version": &inventory.agent_version,
        "status": "OK",
        "summary": {
            "hostname": &inventory.hostname,
            "os_family": &inventory.os_family,
            "os_version": &inventory.os_version,
            "architecture": &inventory.architecture,
            "collector_mode": "read_only"
        }
    })
}

fn findings_payload(inventory: &DeviceInventory) -> Value {
    let mut findings = vec![os_inventory_finding(inventory)];
    findings.push(disk_encryption_finding(inventory));
    findings.push(platform_integrity_finding(inventory));
    findings.push(host_firewall_finding(inventory));
    findings.push(mdm_enrollment_finding(inventory));
    findings.push(endpoint_protection_finding(inventory));
    json!({ "findings": findings })
}

fn os_inventory_finding(inventory: &DeviceInventory) -> Value {
    finding(
        FindingSpec {
            check_id: "device.os_patch_level",
            pillar: "DEVICES",
            severity: "INFO",
            status: "OBSERVED",
            title: "OS posture inventory captured",
            description: "Read-only agent captured OS and architecture posture metadata.",
            recommendation:
                "Correlate this endpoint inventory with MDM or patch-management compliance evidence.",
        },
        json!({
            "hostname": &inventory.hostname,
            "os_family": &inventory.os_family,
            "os_version": &inventory.os_version,
            "architecture": &inventory.architecture,
            "agent_version": &inventory.agent_version,
            "collector": "os_inventory"
        }),
    )
}

fn disk_encryption_finding(inventory: &DeviceInventory) -> Value {
    let signal = match inventory.os_family.as_str() {
        "linux" => linux_disk_encryption_signal(),
        "macos" => macos_filevault_signal(),
        "windows" => windows_bitlocker_signal(),
        other => PostureSignal::unknown(
            "platform_unsupported",
            json!({ "os_family": other, "collector": "disk_encryption" }),
        ),
    };
    signal.to_finding(
        "device.disk_encryption",
        "DEVICES",
        "HIGH",
        "Disk encryption enabled",
        "Endpoint storage encryption could not be confirmed by the read-only collector.",
        "Enable BitLocker, FileVault or LUKS and connect encryption evidence to ISCY.",
    )
}

fn platform_integrity_finding(inventory: &DeviceInventory) -> Value {
    let signal = match inventory.os_family.as_str() {
        "linux" => linux_secure_boot_signal(),
        "macos" => macos_platform_integrity_signal(),
        "windows" => windows_secure_boot_signal(),
        other => PostureSignal::unknown(
            "platform_unsupported",
            json!({ "os_family": other, "collector": "platform_integrity" }),
        ),
    };
    signal.to_finding(
        "device.secure_boot",
        "DEVICES",
        "MEDIUM",
        "Secure boot posture",
        "Secure boot or comparable platform-integrity posture could not be confirmed.",
        "Enable secure boot or document compensating controls for unsupported hosts.",
    )
}

fn host_firewall_finding(inventory: &DeviceInventory) -> Value {
    let signal = match inventory.os_family.as_str() {
        "linux" => linux_firewall_signal(),
        "macos" => macos_firewall_signal(),
        "windows" => windows_firewall_signal(),
        other => PostureSignal::unknown(
            "platform_unsupported",
            json!({ "os_family": other, "collector": "host_firewall" }),
        ),
    };
    signal.to_finding(
        "network.host_firewall",
        "NETWORKS",
        "MEDIUM",
        "Host firewall enabled",
        "Host firewall policy could not be confirmed by the read-only collector.",
        "Enable host firewall policy and store policy evidence.",
    )
}

fn mdm_enrollment_finding(inventory: &DeviceInventory) -> Value {
    let signal = match inventory.os_family.as_str() {
        "linux" => linux_management_signal(),
        "macos" => macos_mdm_signal(),
        "windows" => windows_mdm_signal(),
        other => PostureSignal::unknown(
            "platform_unsupported",
            json!({ "os_family": other, "collector": "mdm_enrollment" }),
        ),
    };
    signal.to_finding(
        "identity.mdm_enrollment",
        "IDENTITY",
        "HIGH",
        "Managed device enrollment",
        "Managed device enrollment or endpoint-management signal could not be confirmed.",
        "Enroll devices into Intune, Jamf or an equivalent MDM and map compliance state into ISCY.",
    )
}

fn endpoint_protection_finding(inventory: &DeviceInventory) -> Value {
    let signal = match inventory.os_family.as_str() {
        "linux" => linux_endpoint_protection_signal(),
        "macos" => macos_endpoint_protection_signal(),
        "windows" => windows_endpoint_protection_signal(),
        other => PostureSignal::unknown(
            "platform_unsupported",
            json!({ "os_family": other, "collector": "endpoint_protection" }),
        ),
    };
    signal.to_finding(
        "device.endpoint_protection",
        "DEVICES",
        "HIGH",
        "Endpoint protection present",
        "Endpoint protection or EDR health could not be confirmed by the read-only collector.",
        "Deploy and monitor EDR or endpoint protection and ingest health evidence.",
    )
}

#[derive(Debug, Clone)]
struct PostureSignal {
    detected: Option<bool>,
    method: &'static str,
    evidence: Value,
}

impl PostureSignal {
    fn observed(method: &'static str, evidence: Value) -> Self {
        Self {
            detected: Some(true),
            method,
            evidence,
        }
    }

    fn missing(method: &'static str, evidence: Value) -> Self {
        Self {
            detected: Some(false),
            method,
            evidence,
        }
    }

    fn unknown(method: &'static str, evidence: Value) -> Self {
        Self {
            detected: None,
            method,
            evidence,
        }
    }

    fn to_finding(
        &self,
        check_id: &'static str,
        pillar: &'static str,
        gap_severity: &'static str,
        title: &'static str,
        missing_description: &'static str,
        recommendation: &'static str,
    ) -> Value {
        let (severity, status, description) = match self.detected {
            Some(true) => (
                "INFO",
                "OBSERVED",
                "Read-only collector observed a local posture signal for this control.",
            ),
            Some(false) => (gap_severity, "OPEN", missing_description),
            None => (
                gap_severity,
                "OPEN",
                "Read-only collector could not determine this posture signal on the endpoint.",
            ),
        };
        let mut evidence = self.evidence.clone();
        if let Some(evidence_object) = evidence.as_object_mut() {
            evidence_object.insert("method".to_string(), json!(self.method));
            evidence_object.insert("detected".to_string(), json!(self.detected));
            evidence_object.insert("collector_mode".to_string(), json!("read_only"));
        }
        finding(
            FindingSpec {
                check_id,
                pillar,
                severity,
                status,
                title,
                description,
                recommendation,
            },
            evidence,
        )
    }
}

#[derive(Debug, Clone, Copy)]
struct FindingSpec {
    check_id: &'static str,
    pillar: &'static str,
    severity: &'static str,
    status: &'static str,
    title: &'static str,
    description: &'static str,
    recommendation: &'static str,
}

fn finding(spec: FindingSpec, evidence: Value) -> Value {
    json!({
        "check_id": spec.check_id,
        "pillar": spec.pillar,
        "severity": spec.severity,
        "status": spec.status,
        "title": spec.title,
        "description": spec.description,
        "recommendation": spec.recommendation,
        "evidence": evidence
    })
}

fn linux_disk_encryption_signal() -> PostureSignal {
    let root_mount = command_output("findmnt", &["-no", "SOURCE,FSTYPE", "/"])
        .or_else(linux_root_mount_from_proc);
    let luks_devices = linux_luks_devices();
    let root_encrypted = root_mount
        .as_deref()
        .map(root_mount_looks_encrypted)
        .unwrap_or(false);
    if root_encrypted || !luks_devices.is_empty() {
        return PostureSignal::observed(
            "linux_luks_findmnt",
            json!({ "root_mount": root_mount, "luks_devices": luks_devices }),
        );
    }
    if root_mount.is_some() {
        return PostureSignal::missing(
            "linux_luks_findmnt",
            json!({ "root_mount": root_mount, "luks_devices": luks_devices }),
        );
    }
    PostureSignal::unknown(
        "linux_luks_findmnt",
        json!({ "root_mount": null, "luks_devices": luks_devices }),
    )
}

fn linux_root_mount_from_proc() -> Option<String> {
    let content = fs::read_to_string("/proc/mounts").ok()?;
    content.lines().find_map(|line| {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        (parts.len() >= 3 && parts[1] == "/").then(|| format!("{} {}", parts[0], parts[2]))
    })
}

fn root_mount_looks_encrypted(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.contains("/dev/mapper")
        || value.contains("crypt")
        || value.contains("luks")
        || value.contains("dm-")
}

fn linux_luks_devices() -> Vec<String> {
    let Ok(entries) = fs::read_dir("/sys/block") else {
        return Vec::new();
    };
    let mut devices = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("dm-") {
            continue;
        }
        let uuid_path = entry.path().join("dm/uuid");
        let Ok(uuid) = fs::read_to_string(uuid_path) else {
            continue;
        };
        if uuid.to_ascii_lowercase().contains("crypt") || uuid.to_ascii_lowercase().contains("luks")
        {
            devices.push(name);
        }
    }
    devices
}

fn linux_secure_boot_signal() -> PostureSignal {
    match linux_secure_boot_enabled() {
        Some(true) => {
            PostureSignal::observed("linux_efi_secureboot", json!({ "secure_boot": true }))
        }
        Some(false) => {
            PostureSignal::missing("linux_efi_secureboot", json!({ "secure_boot": false }))
        }
        None => PostureSignal::unknown(
            "linux_efi_secureboot",
            json!({ "secure_boot": null, "reason": "efi_variable_unavailable" }),
        ),
    }
}

fn linux_secure_boot_enabled() -> Option<bool> {
    let entries = fs::read_dir("/sys/firmware/efi/efivars").ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("SecureBoot-") {
            continue;
        }
        let bytes = fs::read(entry.path()).ok()?;
        if bytes.len() >= 5 {
            return Some(bytes[4] == 1);
        }
    }
    None
}

fn linux_firewall_signal() -> PostureSignal {
    let active_services = active_systemd_services(&["firewalld", "ufw", "nftables"]);
    let ufw = command_output("ufw", &["status"]).unwrap_or_default();
    let nft_rules = command_output("nft", &["list", "ruleset"]).unwrap_or_default();
    let iptables_rules = command_output("iptables", &["-S"]).unwrap_or_default();
    let detected = !active_services.is_empty()
        || ufw.to_ascii_lowercase().contains("status: active")
        || !nft_rules.trim().is_empty()
        || iptables_rules.lines().any(|line| line.starts_with("-A "));
    if detected {
        return PostureSignal::observed(
            "linux_firewall_services",
            json!({ "active_services": active_services, "ufw": ufw, "nft_rules_present": !nft_rules.trim().is_empty(), "iptables_rules_present": iptables_rules.lines().any(|line| line.starts_with("-A ")) }),
        );
    }
    PostureSignal::missing(
        "linux_firewall_services",
        json!({ "active_services": active_services, "ufw": ufw, "nft_rules_present": false, "iptables_rules_present": false }),
    )
}

fn linux_management_signal() -> PostureSignal {
    let active_services = active_systemd_services(&[
        "osqueryd",
        "puppet",
        "chef-client",
        "salt-minion",
        "waagent",
        "amazon-ssm-agent",
        "google-osconfig-agent",
        "tacticalagent",
        "meshagent",
    ]);
    let paths = existing_paths(&[
        "/etc/osquery",
        "/opt/osquery",
        "/opt/puppetlabs",
        "/etc/salt",
        "/opt/tanium",
        "/var/lib/waagent",
        "/var/lib/amazon/ssm",
    ]);
    if !active_services.is_empty() || !paths.is_empty() {
        return PostureSignal::observed(
            "linux_management_agent",
            json!({ "active_services": active_services, "paths": paths }),
        );
    }
    PostureSignal::missing(
        "linux_management_agent",
        json!({ "active_services": active_services, "paths": paths }),
    )
}

fn linux_endpoint_protection_signal() -> PostureSignal {
    let active_services = active_systemd_services(&[
        "falcon-sensor",
        "mdatp",
        "wazuh-agent",
        "osqueryd",
        "sentinelone",
        "auditd",
        "carbonblack",
        "cbdaemon",
    ]);
    let paths = existing_paths(&[
        "/opt/CrowdStrike",
        "/opt/microsoft/mdatp",
        "/var/ossec",
        "/opt/sentinelone",
        "/etc/audit",
        "/var/lib/osquery",
    ]);
    if !active_services.is_empty() || !paths.is_empty() {
        return PostureSignal::observed(
            "linux_edr_agent",
            json!({ "active_services": active_services, "paths": paths }),
        );
    }
    PostureSignal::missing(
        "linux_edr_agent",
        json!({ "active_services": active_services, "paths": paths }),
    )
}

fn active_systemd_services(service_names: &[&str]) -> Vec<String> {
    service_names
        .iter()
        .filter_map(|service| {
            let output = command_output("systemctl", &["is-active", service])?;
            (output.trim() == "active").then(|| (*service).to_string())
        })
        .collect()
}

fn existing_paths(paths: &[&str]) -> Vec<String> {
    paths
        .iter()
        .filter(|path| FsPath::new(path).exists())
        .map(|path| (*path).to_string())
        .collect()
}

fn macos_filevault_signal() -> PostureSignal {
    let output = command_output("fdesetup", &["status"]);
    match output.as_deref().map(str::to_ascii_lowercase) {
        Some(value) if value.contains("filevault is on") => {
            PostureSignal::observed("macos_fdesetup", json!({ "output": output }))
        }
        Some(value) if value.contains("filevault is off") => {
            PostureSignal::missing("macos_fdesetup", json!({ "output": output }))
        }
        Some(_) => PostureSignal::unknown("macos_fdesetup", json!({ "output": output })),
        None => PostureSignal::unknown(
            "macos_fdesetup",
            json!({ "reason": "command_unavailable_or_denied" }),
        ),
    }
}

fn macos_platform_integrity_signal() -> PostureSignal {
    let sip = command_output("csrutil", &["status"]);
    let authenticated_root = command_output("csrutil", &["authenticated-root", "status"]);
    let sip_enabled = sip
        .as_deref()
        .map(|value| value.to_ascii_lowercase().contains("enabled"))
        .unwrap_or(false);
    let root_enabled = authenticated_root
        .as_deref()
        .map(|value| value.to_ascii_lowercase().contains("enabled"))
        .unwrap_or(false);
    if sip_enabled || root_enabled {
        return PostureSignal::observed(
            "macos_platform_integrity",
            json!({ "sip": sip, "authenticated_root": authenticated_root }),
        );
    }
    if sip.is_some() || authenticated_root.is_some() {
        return PostureSignal::missing(
            "macos_platform_integrity",
            json!({ "sip": sip, "authenticated_root": authenticated_root }),
        );
    }
    PostureSignal::unknown(
        "macos_platform_integrity",
        json!({ "reason": "command_unavailable_or_denied" }),
    )
}

fn macos_firewall_signal() -> PostureSignal {
    let output = command_output(
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        &["--getglobalstate"],
    );
    match output.as_deref().map(str::to_ascii_lowercase) {
        Some(value) if value.contains("enabled") => {
            PostureSignal::observed("macos_socketfilterfw", json!({ "output": output }))
        }
        Some(value) if value.contains("disabled") => {
            PostureSignal::missing("macos_socketfilterfw", json!({ "output": output }))
        }
        Some(_) => PostureSignal::unknown("macos_socketfilterfw", json!({ "output": output })),
        None => PostureSignal::unknown(
            "macos_socketfilterfw",
            json!({ "reason": "command_unavailable_or_denied" }),
        ),
    }
}

fn macos_mdm_signal() -> PostureSignal {
    let output = command_output("profiles", &["status", "-type", "enrollment"]);
    match output.as_deref().map(str::to_ascii_lowercase) {
        Some(value)
            if value.contains("mdm enrollment: yes") || value.contains("enrolled via dep: yes") =>
        {
            PostureSignal::observed("macos_profiles_mdm", json!({ "output": output }))
        }
        Some(value) if value.contains("mdm enrollment: no") => {
            PostureSignal::missing("macos_profiles_mdm", json!({ "output": output }))
        }
        Some(_) => PostureSignal::unknown("macos_profiles_mdm", json!({ "output": output })),
        None => PostureSignal::unknown(
            "macos_profiles_mdm",
            json!({ "reason": "command_unavailable_or_denied" }),
        ),
    }
}

fn macos_endpoint_protection_signal() -> PostureSignal {
    let paths = existing_paths(&[
        "/Library/LaunchDaemons/com.crowdstrike.falcon.Agent.plist",
        "/Library/LaunchDaemons/com.microsoft.wdav.plist",
        "/Library/LaunchDaemons/com.sentinelone.sentineld.plist",
        "/Library/LaunchDaemons/com.jamf.management.daemon.plist",
        "/Applications/Windows Defender.app",
        "/Applications/CrowdStrike Falcon.app",
    ]);
    if !paths.is_empty() {
        return PostureSignal::observed("macos_edr_paths", json!({ "paths": paths }));
    }
    PostureSignal::missing("macos_edr_paths", json!({ "paths": paths }))
}

fn windows_bitlocker_signal() -> PostureSignal {
    let output = powershell_output(
        "$v = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue; if ($v) { $v.ProtectionStatus }",
    )
    .or_else(|| command_output("manage-bde", &["-status", "C:"]));
    match output.as_deref().map(str::to_ascii_lowercase) {
        Some(value) if bitlocker_output_reports_enabled(&value) => {
            PostureSignal::observed("windows_bitlocker", json!({ "output": output }))
        }
        Some(value) if bitlocker_output_reports_disabled(&value) => {
            PostureSignal::missing("windows_bitlocker", json!({ "output": output }))
        }
        Some(_) => PostureSignal::unknown("windows_bitlocker", json!({ "output": output })),
        None => PostureSignal::unknown(
            "windows_bitlocker",
            json!({ "reason": "command_unavailable_or_denied" }),
        ),
    }
}

fn bitlocker_output_reports_enabled(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.lines().any(|line| {
        let line = line.trim();
        line == "on"
            || line.contains("protectionstatus") && line.ends_with("on")
            || line.contains("protection status:") && line.contains("protection on")
            || line.contains("percentage encrypted:")
                && bitlocker_percentage(line)
                    .map(|percentage| percentage >= 99.9)
                    .unwrap_or(false)
    })
}

fn bitlocker_output_reports_disabled(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.lines().any(|line| {
        let line = line.trim();
        line == "off"
            || line.contains("protectionstatus") && line.ends_with("off")
            || line.contains("protection status:") && line.contains("protection off")
            || line.contains("percentage encrypted:")
                && bitlocker_percentage(line)
                    .map(|percentage| percentage <= 0.1)
                    .unwrap_or(false)
    })
}

fn bitlocker_percentage(line: &str) -> Option<f64> {
    let (_, value) = line.split_once(':')?;
    let number = value
        .trim()
        .trim_end_matches('%')
        .split_whitespace()
        .next()?;
    number.parse::<f64>().ok()
}

fn windows_secure_boot_signal() -> PostureSignal {
    let output = powershell_output("Confirm-SecureBootUEFI -ErrorAction SilentlyContinue");
    match output.as_deref().map(str::trim) {
        Some("True") => PostureSignal::observed("windows_secure_boot", json!({ "output": output })),
        Some("False") => PostureSignal::missing("windows_secure_boot", json!({ "output": output })),
        Some(_) => PostureSignal::unknown("windows_secure_boot", json!({ "output": output })),
        None => PostureSignal::unknown(
            "windows_secure_boot",
            json!({ "reason": "command_unavailable_or_denied" }),
        ),
    }
}

fn windows_firewall_signal() -> PostureSignal {
    let output = powershell_output(
        "Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object { $_.Enabled }",
    );
    let bools = parse_bool_lines(output.as_deref().unwrap_or_default());
    if !bools.is_empty() && bools.iter().all(|value| *value) {
        return PostureSignal::observed("windows_firewall_profile", json!({ "output": output }));
    }
    if !bools.is_empty() {
        return PostureSignal::missing("windows_firewall_profile", json!({ "output": output }));
    }
    PostureSignal::unknown(
        "windows_firewall_profile",
        json!({ "reason": "command_unavailable_or_denied" }),
    )
}

fn windows_mdm_signal() -> PostureSignal {
    let output = powershell_output(
        "$items = Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Enrollments' -ErrorAction SilentlyContinue; if ($items) { 'ENROLLMENT_KEYS=' + $items.Count } else { 'ENROLLMENT_KEYS=0' }",
    );
    match output.as_deref() {
        Some(value) if value.contains("ENROLLMENT_KEYS=0") => {
            PostureSignal::missing("windows_mdm_registry", json!({ "output": output }))
        }
        Some(value) if value.contains("ENROLLMENT_KEYS=") => {
            PostureSignal::observed("windows_mdm_registry", json!({ "output": output }))
        }
        Some(_) => PostureSignal::unknown("windows_mdm_registry", json!({ "output": output })),
        None => PostureSignal::unknown(
            "windows_mdm_registry",
            json!({ "reason": "command_unavailable_or_denied" }),
        ),
    }
}

fn windows_endpoint_protection_signal() -> PostureSignal {
    let defender = powershell_output(
        "$s = Get-MpComputerStatus -ErrorAction SilentlyContinue; if ($s) { 'AM=' + $s.AMServiceEnabled + ';RTP=' + $s.RealTimeProtectionEnabled }",
    );
    match defender.as_deref().map(str::to_ascii_lowercase) {
        Some(value) if value.contains("am=true") && value.contains("rtp=true") => {
            PostureSignal::observed("windows_defender_status", json!({ "output": defender }))
        }
        Some(value) if value.contains("am=false") || value.contains("rtp=false") => {
            PostureSignal::missing("windows_defender_status", json!({ "output": defender }))
        }
        Some(_) => PostureSignal::unknown("windows_defender_status", json!({ "output": defender })),
        None => PostureSignal::unknown(
            "windows_defender_status",
            json!({ "reason": "command_unavailable_or_denied" }),
        ),
    }
}

fn powershell_output(script: &str) -> Option<String> {
    command_output(
        "powershell",
        &[
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
    )
    .or_else(|| {
        command_output(
            "powershell.exe",
            &[
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
        )
    })
}

fn parse_bool_lines(output: &str) -> Vec<bool> {
    output
        .lines()
        .filter_map(|line| match line.trim().to_ascii_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        })
        .collect()
}

fn hostname() -> String {
    env::var("HOSTNAME")
        .or_else(|_| env::var("COMPUTERNAME"))
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| command_output("hostname", &[]))
        .unwrap_or_else(|| "unknown-host".to_string())
}

fn os_version(os_family: &str) -> String {
    match os_family {
        "linux" => linux_os_release()
            .or_else(|| command_output("uname", &["-sr"]))
            .unwrap_or_else(|| "linux".to_string()),
        "macos" => command_output("sw_vers", &["-productVersion"])
            .map(|version| format!("macOS {version}"))
            .unwrap_or_else(|| "macos".to_string()),
        "windows" => command_output("cmd", &["/C", "ver"]).unwrap_or_else(|| "windows".to_string()),
        other => other.to_string(),
    }
}

fn linux_os_release() -> Option<String> {
    let content = fs::read_to_string("/etc/os-release").ok()?;
    content.lines().find_map(|line| {
        let value = line.strip_prefix("PRETTY_NAME=")?;
        Some(value.trim_matches('"').to_string())
    })
}

fn command_output(command: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(command).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!text.is_empty()).then_some(text)
}

fn print_usage() {
    println!(
        "ISCY Agent\n\nOptions:\n  --backend-url URL          ISCY backend URL\n  --tenant-id ID             Tenant ID\n  --user-id ID               User ID for local/admin intake fallback\n  --enrollment-token TOKEN   One-time or scoped enrollment token\n  --agent-secret SECRET      Existing or newly rotated agent secret\n  --mtls-fingerprint FP      Client certificate fingerprint forwarded by mTLS proxy\n  --state-path PATH          Persisted device ID and secret state\n  --queue-dir PATH           Offline report queue directory\n  --queue-max-files COUNT    Maximum queued reports (1-10000, default 100)\n  --dry-run                  Print payloads without sending or writing state\n  --self-test                Print local inventory and exit without side effects\n\nEnvironment:\n  ISCY_BACKEND_URL, ISCY_TENANT_ID, ISCY_USER_ID, ISCY_AGENT_ENROLLMENT_TOKEN, ISCY_AGENT_SECRET, ISCY_AGENT_MTLS_FINGERPRINT, ISCY_AGENT_STATE_PATH, ISCY_AGENT_QUEUE_DIR, ISCY_AGENT_QUEUE_MAX_FILES, ISCY_AGENT_DEVICE_ID, ISCY_ASSET_ID"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_runtime_dir(name: &str) -> PathBuf {
        let nonce = Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or_else(|| Utc::now().timestamp_millis() * 1_000_000);
        env::temp_dir().join(format!("iscy-agent-{name}-{}-{nonce}", std::process::id()))
    }

    fn test_config(root: &FsPath, queue_max_files: usize) -> AgentConfig {
        AgentConfig {
            backend_url: "http://127.0.0.1:9000".to_string(),
            tenant_id: 1,
            user_id: 1,
            enrollment_token: None,
            agent_secret: None,
            mtls_fingerprint: None,
            state_path: root.join("state.json"),
            queue_dir: root.join("queue"),
            queue_max_files,
            dry_run: false,
            self_test: false,
        }
    }

    fn test_report(device_id: i64, sequence: i64) -> QueuedReport {
        QueuedReport {
            queued_at: format!("2026-06-27T00:00:{sequence:02}Z"),
            device_id,
            heartbeat: json!({ "sequence": sequence }),
            findings: json!({ "findings": [], "sequence": sequence }),
        }
    }

    fn test_inventory(os_family: &str) -> DeviceInventory {
        DeviceInventory {
            asset_id: None,
            stable_device_id: format!("test-{os_family}"),
            hostname: "test-host".to_string(),
            os_family: os_family.to_string(),
            os_version: "test-os".to_string(),
            architecture: "x86_64".to_string(),
            agent_version: "0.3.0".to_string(),
            deployment_channel: "test".to_string(),
        }
    }

    #[test]
    fn bool_line_parser_reads_powershell_boolean_output() {
        assert_eq!(
            parse_bool_lines("True\nFalse\nignored\ntrue"),
            vec![true, false, true]
        );
    }

    #[test]
    fn root_mount_parser_detects_encrypted_linux_roots() {
        assert!(root_mount_looks_encrypted("/dev/mapper/cryptroot ext4"));
        assert!(root_mount_looks_encrypted("/dev/dm-0 btrfs"));
        assert!(!root_mount_looks_encrypted("/dev/nvme0n1p2 ext4"));
    }

    #[test]
    fn bitlocker_parser_does_not_treat_protection_off_as_on() {
        assert!(bitlocker_output_reports_enabled(
            "Protection Status: Protection On"
        ));
        assert!(bitlocker_output_reports_enabled("On"));
        assert!(!bitlocker_output_reports_enabled(
            "Protection Status: Protection Off"
        ));
        assert!(bitlocker_output_reports_disabled(
            "Protection Status: Protection Off"
        ));
    }

    #[test]
    fn findings_payload_contains_zero_trust_collectors() {
        let payload = findings_payload(&test_inventory("linux"));
        let findings = payload["findings"].as_array().unwrap();
        let check_ids = findings
            .iter()
            .filter_map(|finding| finding["check_id"].as_str())
            .collect::<Vec<_>>();
        assert!(check_ids.contains(&"device.os_patch_level"));
        assert!(check_ids.contains(&"device.disk_encryption"));
        assert!(check_ids.contains(&"device.secure_boot"));
        assert!(check_ids.contains(&"network.host_firewall"));
        assert!(check_ids.contains(&"identity.mdm_enrollment"));
        assert!(check_ids.contains(&"device.endpoint_protection"));
    }

    #[test]
    fn persisted_agent_state_roundtrips() {
        let root = test_runtime_dir("state");
        let path = root.join("state.json");
        let state = AgentState {
            tenant_id: 7,
            stable_device_id: "workstation-7".to_string(),
            device_id: 42,
            agent_secret: Some("iscy_agent_test".to_string()),
            updated_at: "2026-06-27T00:00:00Z".to_string(),
        };

        persist_agent_state(&path, &state).unwrap();
        let loaded = load_agent_state(&path).unwrap().unwrap();

        assert_eq!(loaded.tenant_id, 7);
        assert_eq!(loaded.stable_device_id, "workstation-7");
        assert_eq!(loaded.device_id, 42);
        assert_eq!(loaded.agent_secret.as_deref(), Some("iscy_agent_test"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn offline_queue_is_bounded_and_keeps_newest_reports() {
        let root = test_runtime_dir("queue");
        let config = test_config(&root, 2);

        let first = enqueue_report(&config, &test_report(9, 1)).unwrap();
        std::thread::sleep(Duration::from_millis(1));
        let second = enqueue_report(&config, &test_report(9, 2)).unwrap();
        std::thread::sleep(Duration::from_millis(1));
        let third = enqueue_report(&config, &test_report(9, 3)).unwrap();
        let files = queued_report_files(&config.queue_dir).unwrap();

        assert_eq!(files.len(), 2);
        assert!(!first.exists());
        assert!(second.exists());
        assert!(third.exists());
        let sequences = files
            .iter()
            .map(|path| {
                let report: QueuedReport =
                    serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
                report.heartbeat["sequence"].as_i64().unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(sequences, vec![2, 3]);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_offline_queue_entries_are_isolated() {
        let root = test_runtime_dir("invalid-queue");
        let config = test_config(&root, 10);
        fs::create_dir_all(&config.queue_dir).unwrap();
        let malformed = config.queue_dir.join("0001.json");
        fs::write(&malformed, b"not-json").unwrap();
        let client = reqwest::blocking::Client::new();

        let flushed =
            flush_queued_reports(&client, "http://127.0.0.1:1", &config, Some("unused"), 9)
                .unwrap();

        assert_eq!(flushed, 0);
        assert!(!malformed.exists());
        assert!(config.queue_dir.join("0001.invalid").exists());
        assert!(queued_report_files(&config.queue_dir).unwrap().is_empty());

        fs::remove_dir_all(root).unwrap();
    }
}
