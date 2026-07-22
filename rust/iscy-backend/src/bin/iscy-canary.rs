use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use chrono::Utc;
use iscy_backend::{
    cve_store::CveStore,
    vulnerability_intelligence::{
        import_single_nvd_cve, run_feed_sync, FeedSyncRequest, OfficialVulnerabilityFeedTransport,
        SOURCE_NVD,
    },
};
use serde_json::json;

fn normalize_legacy(input: &str) -> String {
    input.trim().to_uppercase()
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

fn database_url() -> String {
    env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:///db.sqlite3".to_string())
}

fn parse_import_args(args: &[String]) -> anyhow::Result<Vec<String>> {
    if args.iter().any(|value| value.starts_with("--")) {
        anyhow::bail!(
            "Der gehaertete Einzelimport akzeptiert keine URL- oder Transportoptionen. Nur CVE-IDs sind zulaessig."
        );
    }
    if args.is_empty() {
        anyhow::bail!("Keine CVE-IDs uebergeben.");
    }
    Ok(args.to_vec())
}

fn parse_sync_args(args: &[String]) -> anyhow::Result<usize> {
    let mut max_records = 5_000_usize;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--max-records" if index + 1 < args.len() => {
                max_records = args[index + 1]
                    .parse::<usize>()
                    .map_err(|_| anyhow::anyhow!("--max-records muss eine positive Zahl sein."))?;
                if max_records == 0 || max_records > 20_000 {
                    anyhow::bail!("--max-records muss zwischen 1 und 20000 liegen.");
                }
                index += 2;
            }
            option => {
                anyhow::bail!(
                    "Nicht unterstuetzte Legacy-Option: {option}. Der gehaertete Delta-Sync akzeptiert nur --max-records und verwendet den persistenten Checkpoint."
                );
            }
        }
    }
    Ok(max_records)
}

async fn cmd_import(args: &[String]) -> anyhow::Result<()> {
    let cves = parse_import_args(args)?;
    let store = CveStore::connect(&database_url()).await?;
    let transport = OfficialVulnerabilityFeedTransport::from_environment()?;
    let mut imported = 0_usize;
    for cve in cves {
        let result = import_single_nvd_cve(&store, &transport, &cve, None).await?;
        println!("{}", serde_json::to_string(&result)?);
        imported += 1;
    }
    println!("Import abgeschlossen. CVEs verarbeitet: {imported}");
    Ok(())
}

async fn cmd_sync(args: &[String]) -> anyhow::Result<()> {
    let max_records = parse_sync_args(args)?;
    let store = CveStore::connect(&database_url()).await?;
    let transport = OfficialVulnerabilityFeedTransport::from_environment()?;
    let result = run_feed_sync(
        &store,
        &transport,
        FeedSyncRequest {
            sources: vec![SOURCE_NVD.to_string()],
            max_records: Some(max_records),
        },
        "CLI",
        None,
    )
    .await?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
        "import" => cmd_import(&args).await,
        "import-collection" | "sync-recent" => cmd_sync(&args).await,
        _ => anyhow::bail!("Unbekannter Subcommand: {}", cmd),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_import_args, parse_sync_args};

    #[test]
    fn hardened_import_rejects_legacy_transport_options() {
        let args = vec![
            "--nvd-url".to_string(),
            "https://example.invalid".to_string(),
            "CVE-2026-1234".to_string(),
        ];
        assert!(parse_import_args(&args).is_err());
    }

    #[test]
    fn hardened_sync_accepts_only_bounded_record_limit() {
        assert_eq!(
            parse_sync_args(&["--max-records".to_string(), "250".to_string()]).unwrap(),
            250
        );
        assert!(parse_sync_args(&["--max-records".to_string(), "0".to_string()]).is_err());
        assert!(parse_sync_args(&["--hours".to_string(), "24".to_string()]).is_err());
    }
}
