use std::{fs, process::Command};

#[cfg(unix)]
#[test]
fn launch_commands_validate_before_any_service_or_file_mutation() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/startup/test_launchers.sh");
    let result = Command::new("bash")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .arg(script)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn deployed_agent_preflight_exits_before_host_collection_network_or_state_writes() {
    let root = std::env::temp_dir().join(format!("iscy-agent-cli-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let token = root.join("token");
    fs::write(&token, "synthetic-private-token\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let output = Command::new(env!("CARGO_BIN_EXE_iscy-agent"))
        .env_clear()
        // No collectors can execute through PATH. This endpoint must not be contacted.
        .env("PATH", root.join("missing-bin"))
        .args(["--check", "--backend-url", "http://127.0.0.1:1"])
        .arg("--enrollment-token-file")
        .arg(&token)
        .arg("--state-path")
        .arg(root.join("state.json"))
        .arg("--queue-dir")
        .arg(root.join("queue"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    let stdout = String::from_utf8(output.stdout).unwrap();
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["credentials_configured"], true);
    assert_eq!(report["inventory_collected"], false);
    assert_eq!(report["network_checked"], false);
    assert!(!stdout.contains("synthetic-private-token"));
    assert!(!stdout.contains(root.to_str().unwrap()));
    assert!(!root.join("state.json").exists());
    assert!(!root.join("queue").exists());
    assert_eq!(
        fs::read_to_string(token).unwrap(),
        "synthetic-private-token\n"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn mistyped_agent_option_cannot_trigger_inventory_enrollment_or_secret_disclosure() {
    let output = Command::new(env!("CARGO_BIN_EXE_iscy-agent"))
        .env_clear()
        .args(["--chek", "--enrollment-token", "synthetic-private-token"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("Unknown agent option"));
    assert!(!stderr.contains("synthetic-private-token"));
}
