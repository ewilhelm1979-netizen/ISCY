use std::{env, fs, process::Command};

use serde::Serialize;
use serde_json::{json, Value};

#[derive(Debug)]
struct AgentConfig {
    backend_url: String,
    tenant_id: i64,
    user_id: i64,
    enrollment_token: Option<String>,
    agent_secret: Option<String>,
    mtls_fingerprint: Option<String>,
    dry_run: bool,
    self_test: bool,
}

#[derive(Debug, Serialize)]
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
                }
            }))?
        );
        return Ok(());
    }

    let client = reqwest::blocking::Client::builder().build()?;
    let base_url = config.backend_url.trim_end_matches('/');
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

    let heartbeat_request = authenticated_agent_request(
        client.post(format!(
            "{base_url}/api/v1/agents/devices/{device_id}/heartbeat"
        )),
        &config,
        agent_secret.as_deref(),
    );
    heartbeat_request
        .json(&heartbeat)
        .send()?
        .error_for_status()?;

    let findings_request = authenticated_agent_request(
        client.post(format!(
            "{base_url}/api/v1/agents/devices/{device_id}/findings"
        )),
        &config,
        agent_secret.as_deref(),
    );
    findings_request
        .json(&findings)
        .send()?
        .error_for_status()?;

    println!("ISCY agent reported posture for device {device_id}");
    Ok(())
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
        dry_run,
        self_test,
    })
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
        "agent_version": inventory.agent_version,
        "status": "OK",
        "summary": {
            "hostname": inventory.hostname,
            "os_family": inventory.os_family,
            "os_version": inventory.os_version,
            "architecture": inventory.architecture,
            "collector_mode": "read_only"
        }
    })
}

fn findings_payload(inventory: &DeviceInventory) -> Value {
    json!({
        "findings": [
            {
                "check_id": "device.os_patch_level",
                "pillar": "DEVICES",
                "severity": "INFO",
                "status": "OBSERVED",
                "title": "OS posture inventory captured",
                "description": "Read-only agent captured OS and architecture posture metadata.",
                "recommendation": "Correlate this endpoint inventory with MDM or patch-management compliance evidence.",
                "evidence": {
                    "hostname": inventory.hostname,
                    "os_family": inventory.os_family,
                    "os_version": inventory.os_version,
                    "architecture": inventory.architecture,
                    "agent_version": inventory.agent_version
                }
            }
        ]
    })
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
        "ISCY Agent\n\nOptions:\n  --backend-url URL          ISCY backend URL\n  --tenant-id ID             Tenant ID\n  --user-id ID               User ID for local/admin intake fallback\n  --enrollment-token TOKEN   One-time or scoped enrollment token\n  --agent-secret SECRET      Existing agent secret for secret-based intake\n  --mtls-fingerprint FP      Client certificate fingerprint forwarded by mTLS proxy\n  --dry-run                  Print payloads without sending\n  --self-test                Print local inventory and exit\n\nEnvironment:\n  ISCY_BACKEND_URL, ISCY_TENANT_ID, ISCY_USER_ID, ISCY_AGENT_ENROLLMENT_TOKEN, ISCY_AGENT_SECRET, ISCY_AGENT_MTLS_FINGERPRINT, ISCY_AGENT_DEVICE_ID, ISCY_ASSET_ID"
    );
}
