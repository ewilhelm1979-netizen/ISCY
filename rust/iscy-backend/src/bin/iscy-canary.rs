use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use chrono::Utc;
use serde_json::{json, Value};

fn normalize_legacy(input: &str) -> String {
    input.trim().to_uppercase()
}

fn nvd_api_key() -> String {
    env::var("NVD_API_KEY").unwrap_or_default()
}

fn nvd_endpoint(nvd_url: &str) -> String {
    format!("{}/rest/json/cves/2.0", nvd_url.trim_end_matches('/'))
}

fn fetch_nvd_cve(
    client: &reqwest::blocking::Client,
    nvd_url: &str,
    cve_id: &str,
) -> anyhow::Result<(Value, Value)> {
    let mut req = client
        .get(nvd_endpoint(nvd_url))
        .query(&[("cveId", cve_id.to_string())]);
    let api_key = nvd_api_key();
    if !api_key.is_empty() {
        req = req.header("apiKey", api_key);
    }

    let response = req.send()?;
    if !response.status().is_success() {
        anyhow::bail!(
            "NVD request fuer {} fehlgeschlagen mit HTTP {}",
            cve_id,
            response.status()
        );
    }
    let payload: Value = response.json()?;
    let cve = payload["vulnerabilities"]
        .as_array()
        .and_then(|items| items.first())
        .and_then(|entry| entry.get("cve"))
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Keine CVE-Daten fuer {} gefunden", cve_id))?;
    Ok((cve, payload))
}

fn post_nvd_upsert(
    client: &reqwest::blocking::Client,
    rust_endpoint: &str,
    cve: &Value,
    raw_payload: &Value,
) -> anyhow::Result<Value> {
    let cve_id = cve.get("id").and_then(Value::as_str).unwrap_or("");
    let response = client
        .post(rust_endpoint)
        .json(&json!({ "cve": cve, "raw_payload": raw_payload }))
        .send()?;
    if !response.status().is_success() {
        anyhow::bail!(
            "Rust-Upsert fehlgeschlagen fuer {} mit HTTP {}",
            cve_id,
            response.status()
        );
    }
    Ok(response.json()?)
}

fn cmd_parity(args: &[String]) -> anyhow::Result<()> {
    let mut out_dir = PathBuf::from("reports/canary");
    let mut cves: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--out-dir" && i + 1 < args.len() {
            out_dir = PathBuf::from(&args[i + 1]);
            i += 2;
            continue;
        }
        cves.push(args[i].clone());
        i += 1;
    }
    if cves.is_empty() {
        anyhow::bail!("Keine CVE-IDs übergeben.");
    }

    fs::create_dir_all(&out_dir)?;
    let stamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();

    let mut rows = Vec::new();
    let mut mismatches = 0_u64;
    for raw in &cves {
        let legacy = normalize_legacy(raw);
        let rust_norm = normalize_legacy(raw);
        let is_match = legacy == rust_norm;
        if !is_match {
            mismatches += 1;
        }
        rows.push(json!({
            "raw": raw,
            "legacy_normalized": legacy,
            "rust_normalized": rust_norm,
            "match": is_match,
        }));
    }

    let total = rows.len() as u64;
    let summary = json!({
        "generated_at_utc": stamp,
        "total": total,
        "mismatches": mismatches,
        "match_rate_percent": if total > 0 { (((total - mismatches) as f64 / total as f64) * 100.0 * 100.0).round() / 100.0 } else { 0.0 },
        "rows": rows,
    });

    let json_path = out_dir.join(format!("nvd_canary_parity_{}.json", stamp));
    fs::write(&json_path, serde_json::to_string_pretty(&summary)? + "\n")?;

    let csv_path = out_dir.join(format!("nvd_canary_parity_{}.csv", stamp));
    let mut f = fs::File::create(&csv_path)?;
    writeln!(f, "raw,legacy_normalized,rust_normalized,match")?;
    if let Some(arr) = summary["rows"].as_array() {
        for row in arr {
            writeln!(
                f,
                "{},{},{},{}",
                row["raw"].as_str().unwrap_or(""),
                row["legacy_normalized"].as_str().unwrap_or(""),
                row["rust_normalized"].as_str().unwrap_or(""),
                row["match"].as_bool().unwrap_or(false)
            )?;
        }
    }

    println!(
        "Canary-Parity-Report erstellt: {} | {} | Mismatches: {}",
        json_path.display(),
        csv_path.display(),
        mismatches
    );
    Ok(())
}

fn cmd_trend(args: &[String]) -> anyhow::Result<()> {
    let mut reports_dir = PathBuf::from("reports/canary");
    let mut window: usize = 30;
    let mut threshold: f64 = 0.5;
    let mut enforce_gate = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--reports-dir" if i + 1 < args.len() => {
                reports_dir = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--window" if i + 1 < args.len() => {
                window = args[i + 1].parse::<usize>().unwrap_or(30).max(1);
                i += 2;
            }
            "--max-mismatch-rate" if i + 1 < args.len() => {
                threshold = args[i + 1].parse::<f64>().unwrap_or(0.5);
                i += 2;
            }
            "--enforce-gate" => {
                enforce_gate = true;
                i += 1;
            }
            _ => i += 1,
        }
    }

    if !reports_dir.exists() {
        anyhow::bail!(
            "Reports-Verzeichnis nicht gefunden: {}",
            reports_dir.display()
        );
    }

    let mut files: Vec<PathBuf> = fs::read_dir(&reports_dir)?
        .filter_map(|e| e.ok().map(|x| x.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("nvd_canary_parity_") && n.ends_with(".json"))
                .unwrap_or(false)
        })
        .collect();
    files.sort();
    if files.is_empty() {
        anyhow::bail!(
            "Keine Parity-Reports gefunden in: {}",
            reports_dir.display()
        );
    }

    let start = files.len().saturating_sub(window);
    let selected = &files[start..];

    let mut rates: Vec<f64> = Vec::new();
    let mut totals: u64 = 0;
    let mut mismatches: u64 = 0;

    for file in selected {
        let raw = fs::read_to_string(file)?;
        let payload: serde_json::Value = serde_json::from_str(&raw)?;
        let total = payload["total"].as_u64().unwrap_or(0);
        let mismatch = payload["mismatches"].as_u64().unwrap_or(0);
        let rate = if total > 0 {
            (mismatch as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        rates.push(rate);
        totals += total;
        mismatches += mismatch;
    }

    let last_rate = *rates.last().unwrap_or(&0.0);
    let avg_rate = if rates.is_empty() {
        0.0
    } else {
        rates.iter().sum::<f64>() / rates.len() as f64
    };
    let max_rate = rates.iter().copied().fold(0.0, f64::max);
    let gate_ok = last_rate <= threshold;

    let stamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let summary = json!({
        "generated_at_utc": stamp,
        "window_size": selected.len(),
        "total_rows": totals,
        "total_mismatches": mismatches,
        "last_mismatch_rate_percent": (last_rate * 10000.0).round() / 10000.0,
        "avg_mismatch_rate_percent": (avg_rate * 10000.0).round() / 10000.0,
        "max_mismatch_rate_percent": (max_rate * 10000.0).round() / 10000.0,
        "threshold_percent": threshold,
        "gate_ok": gate_ok,
    });

    let out_file = reports_dir.join(format!("nvd_canary_trend_{}.json", stamp));
    fs::write(&out_file, serde_json::to_string_pretty(&summary)? + "\n")?;
    println!("Canary-Trend geschrieben: {}", out_file.display());
    println!(
        "window={} last={}% avg={}% max={}% threshold={}% gate_ok={}",
        summary["window_size"],
        summary["last_mismatch_rate_percent"],
        summary["avg_mismatch_rate_percent"],
        summary["max_mismatch_rate_percent"],
        threshold,
        gate_ok
    );

    if enforce_gate && !gate_ok {
        anyhow::bail!(
            "Gate verletzt: last mismatch-rate {} > threshold {}",
            summary["last_mismatch_rate_percent"],
            threshold
        );
    }

    Ok(())
}

fn cmd_import(args: &[String]) -> anyhow::Result<()> {
    let mut backend_url =
        env::var("RUST_BACKEND_URL").unwrap_or_else(|_| "http://127.0.0.1:9000".to_string());
    let mut nvd_url =
        env::var("NVD_BASE_URL").unwrap_or_else(|_| "https://services.nvd.nist.gov".to_string());
    let mut cves: Vec<String> = Vec::new();
    let mut skip_healthcheck = false;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--backend-url" && i + 1 < args.len() {
            backend_url = args[i + 1].trim_end_matches('/').to_string();
            i += 2;
            continue;
        }
        if args[i] == "--nvd-url" && i + 1 < args.len() {
            nvd_url = args[i + 1].trim_end_matches('/').to_string();
            i += 2;
            continue;
        }
        if args[i] == "--skip-healthcheck" {
            skip_healthcheck = true;
            i += 1;
            continue;
        }
        cves.push(args[i].clone());
        i += 1;
    }
    if cves.is_empty() {
        anyhow::bail!("Keine CVE-IDs übergeben.");
    }

    let endpoint = format!("{}/api/v1/nvd/upsert", backend_url.trim_end_matches('/'));
    let client = reqwest::blocking::Client::new();
    if !skip_healthcheck {
        let health_url = format!("{}/health", backend_url.trim_end_matches('/'));
        let health_resp = client.get(&health_url).send()?;
        if !health_resp.status().is_success() {
            anyhow::bail!(
                "Rust-Backend Healthcheck fehlgeschlagen mit HTTP {}",
                health_resp.status()
            );
        }
    }
    let mut imported = 0_u64;

    for cve in cves {
        let normalized = normalize_legacy(&cve);
        let (cve_payload, raw_payload) = fetch_nvd_cve(&client, &nvd_url, &normalized)?;
        let body = post_nvd_upsert(&client, &endpoint, &cve_payload, &raw_payload)?;
        println!("{}", serde_json::to_string(&body)?);
        imported += 1;
    }

    println!("Import abgeschlossen. CVEs verarbeitet: {}", imported);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn import_collection(
    nvd_url: &str,
    rust_url: &str,
    has_kev: bool,
    cve_tag: &str,
    cpe_name: &str,
    last_mod_start: &str,
    last_mod_end: &str,
    results_per_page: usize,
    max_pages: usize,
    skip_healthcheck: bool,
) -> anyhow::Result<()> {
    let nvd_api_key = nvd_api_key();
    let client = reqwest::blocking::Client::new();
    let nvd_endpoint = nvd_endpoint(nvd_url);
    let rust_endpoint = format!("{}/api/v1/nvd/upsert", rust_url.trim_end_matches('/'));

    if !skip_healthcheck {
        let health_resp = client
            .get(format!("{}/health", rust_url.trim_end_matches('/')))
            .send()?;
        if !health_resp.status().is_success() {
            anyhow::bail!(
                "Rust-Backend Healthcheck fehlgeschlagen mit HTTP {}",
                health_resp.status()
            );
        }
    }

    let mut start_index: usize = 0;
    let mut seen_records: usize = 0;
    let mut imported_records: usize = 0;
    let mut page: usize = 0;

    while page < max_pages {
        let mut req = client.get(&nvd_endpoint).query(&[
            ("resultsPerPage", results_per_page.to_string()),
            ("startIndex", start_index.to_string()),
        ]);
        if has_kev {
            req = req.query(&[("hasKev", String::from("true"))]);
        }
        if !cve_tag.is_empty() {
            req = req.query(&[("cveTag", cve_tag.to_string())]);
        }
        if !cpe_name.is_empty() {
            req = req.query(&[("cpeName", cpe_name.to_string())]);
        }
        if !last_mod_start.is_empty() && !last_mod_end.is_empty() {
            req = req.query(&[
                ("lastModStartDate", last_mod_start.to_string()),
                ("lastModEndDate", last_mod_end.to_string()),
            ]);
        }
        if !nvd_api_key.is_empty() {
            req = req.header("apiKey", nvd_api_key.clone());
        }

        let response = req.send()?;
        if !response.status().is_success() {
            anyhow::bail!("NVD request fehlgeschlagen mit HTTP {}", response.status());
        }
        let payload: serde_json::Value = response.json()?;
        let vulnerabilities = payload["vulnerabilities"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if vulnerabilities.is_empty() {
            break;
        }

        for v in vulnerabilities {
            let cve = &v["cve"];
            let cve_id = cve["id"].as_str().unwrap_or("").trim().to_string();
            if cve_id.is_empty() {
                continue;
            }
            post_nvd_upsert(&client, &rust_endpoint, cve, &payload)?;
            imported_records += 1;
            seen_records += 1;
        }

        start_index += results_per_page;
        page += 1;
    }

    println!(
        "{{\"seen_records\":{},\"imported_records\":{},\"max_pages\":{},\"results_per_page\":{}}}",
        seen_records, imported_records, max_pages, results_per_page
    );
    Ok(())
}

fn cmd_import_collection(args: &[String]) -> anyhow::Result<()> {
    let rust_url =
        env::var("RUST_BACKEND_URL").unwrap_or_else(|_| "http://127.0.0.1:9000".to_string());
    let nvd_url =
        env::var("NVD_BASE_URL").unwrap_or_else(|_| "https://services.nvd.nist.gov".to_string());
    let mut cve_tag = String::new();
    let mut cpe_name = String::new();
    let mut has_kev = false;
    let mut last_mod_start = String::new();
    let mut last_mod_end = String::new();
    let mut results_per_page = 2000_usize;
    let mut max_pages = 1_usize;
    let mut skip_healthcheck = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--cve-tag" if i + 1 < args.len() => {
                cve_tag = args[i + 1].clone();
                i += 2;
            }
            "--cpe-name" if i + 1 < args.len() => {
                cpe_name = args[i + 1].clone();
                i += 2;
            }
            "--has-kev" => {
                has_kev = true;
                i += 1;
            }
            "--last-mod-start-date" if i + 1 < args.len() => {
                last_mod_start = args[i + 1].clone();
                i += 2;
            }
            "--last-mod-end-date" if i + 1 < args.len() => {
                last_mod_end = args[i + 1].clone();
                i += 2;
            }
            "--results-per-page" if i + 1 < args.len() => {
                results_per_page = args[i + 1].parse::<usize>().unwrap_or(2000).max(1);
                i += 2;
            }
            "--max-pages" if i + 1 < args.len() => {
                max_pages = args[i + 1].parse::<usize>().unwrap_or(1).max(1);
                i += 2;
            }
            "--skip-healthcheck" => {
                skip_healthcheck = true;
                i += 1;
            }
            _ => i += 1,
        }
    }

    if !last_mod_start.is_empty() && last_mod_end.is_empty() {
        anyhow::bail!("Bei --last-mod-start-date ist --last-mod-end-date erforderlich.");
    }

    import_collection(
        &nvd_url,
        &rust_url,
        has_kev,
        &cve_tag,
        &cpe_name,
        &last_mod_start,
        &last_mod_end,
        results_per_page,
        max_pages,
        skip_healthcheck,
    )
}

fn cmd_sync_recent(args: &[String]) -> anyhow::Result<()> {
    let mut hours = 24_i64;
    let mut cve_tag = String::new();
    let mut cpe_name = String::new();
    let mut has_kev = false;
    let mut results_per_page = 2000_usize;
    let mut max_pages = 2_usize;
    let mut skip_healthcheck = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--hours" if i + 1 < args.len() => {
                hours = args[i + 1].parse::<i64>().unwrap_or(24).max(1);
                i += 2;
            }
            "--cve-tag" if i + 1 < args.len() => {
                cve_tag = args[i + 1].clone();
                i += 2;
            }
            "--cpe-name" if i + 1 < args.len() => {
                cpe_name = args[i + 1].clone();
                i += 2;
            }
            "--has-kev" => {
                has_kev = true;
                i += 1;
            }
            "--results-per-page" if i + 1 < args.len() => {
                results_per_page = args[i + 1].parse::<usize>().unwrap_or(2000).max(1);
                i += 2;
            }
            "--max-pages" if i + 1 < args.len() => {
                max_pages = args[i + 1].parse::<usize>().unwrap_or(2).max(1);
                i += 2;
            }
            "--skip-healthcheck" => {
                skip_healthcheck = true;
                i += 1;
            }
            _ => i += 1,
        }
    }

    let end = Utc::now();
    let start = end - chrono::Duration::hours(hours);
    let start_iso = start.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let end_iso = end.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let rust_url =
        env::var("RUST_BACKEND_URL").unwrap_or_else(|_| "http://127.0.0.1:9000".to_string());
    let nvd_url =
        env::var("NVD_BASE_URL").unwrap_or_else(|_| "https://services.nvd.nist.gov".to_string());
    import_collection(
        &nvd_url,
        &rust_url,
        has_kev,
        &cve_tag,
        &cpe_name,
        &start_iso,
        &end_iso,
        results_per_page,
        max_pages,
        skip_healthcheck,
    )
}

fn main() -> anyhow::Result<()> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        anyhow::bail!(
            "Usage: iscy-canary <parity|trend|import|import-collection|sync-recent> [args]"
        );
    }
    let cmd = args.remove(0);
    match cmd.as_str() {
        "parity" => cmd_parity(&args),
        "trend" => cmd_trend(&args),
        "import" => cmd_import(&args),
        "import-collection" => cmd_import_collection(&args),
        "sync-recent" => cmd_sync_recent(&args),
        _ => anyhow::bail!("Unbekannter Subcommand: {}", cmd),
    }
}
