use axum::{extract::Json, response::Html, routing::{get, post}, Router};
use serde::{Deserialize, Serialize};
use std::env;
use std::time::Duration;

#[derive(Debug, Deserialize)]
pub struct NvdImportRequest {
    pub cve_id: String,
}

#[derive(Debug, Serialize)]
pub struct NvdImportResponse {
    pub accepted: bool,
    pub cve_id: String,
    pub source: &'static str,
    pub is_valid: bool,
    pub year: Option<u16>,
    pub sequence: Option<u32>,
    pub message: String,
    pub nvd_lookup_attempted: bool,
    pub nvd_match_found: Option<bool>,
    pub nvd_total_results: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct LlmGenerateRequest {
    pub prompt: String,
    pub max_tokens: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct LlmGenerateResponse {
    pub backend: &'static str,
    pub model: &'static str,
    pub result: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct RiskPriorityRequest {
    pub score: f64,
    pub exposure: String,
    pub criticality: String,
    pub epss_score: Option<f64>,
    pub in_kev_catalog: bool,
    pub exploit_maturity: String,
    pub affects_critical_service: bool,
    pub nis2_relevant: bool,
}

#[derive(Debug, Serialize)]
pub struct RiskPriorityResponse {
    pub priority: String,
    pub due_days: u16,
    pub effective_score: f64,
}

#[derive(Debug, Deserialize)]
pub struct GuidanceEvaluateRequest {
    pub description_present: bool,
    pub sector_present: bool,
    pub applicability_count: u32,
    pub process_count: u32,
    pub risk_count: u32,
    pub assessment_count: u32,
    pub measure_count: u32,
    pub measure_open_count: u32,
    pub requirement_count: u32,
}

#[derive(Debug, Serialize)]
pub struct GuidanceEvaluateResponse {
    pub current_step_code: Option<String>,
    pub summary: String,
    pub next_action_text: String,
    pub todo_items: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct CveSummaryRequest {
    pub total: u32,
    pub critical: u32,
    pub with_risk: u32,
    pub llm_generated: u32,
    pub nis2: u32,
    pub kev: u32,
}

#[derive(Debug, Serialize)]
pub struct CveSummaryResponse {
    pub total: u32,
    pub critical: u32,
    pub with_risk: u32,
    pub llm_generated: u32,
    pub nis2: u32,
    pub kev: u32,
    pub risk_hotspot_score: f64,
}

pub fn normalize_cve_id(input: &str) -> String {
    input.trim().to_uppercase()
}

pub fn parse_cve_id(input: &str) -> Option<(u16, u32)> {
    let normalized = normalize_cve_id(input);
    let mut parts = normalized.split('-');
    let prefix = parts.next()?;
    let year_str = parts.next()?;
    let sequence_str = parts.next()?;
    if parts.next().is_some() || prefix != "CVE" {
        return None;
    }
    if year_str.len() != 4 || sequence_str.len() < 4 {
        return None;
    }
    let year = year_str.parse::<u16>().ok()?;
    let sequence = sequence_str.parse::<u32>().ok()?;
    Some((year, sequence))
}

fn nvd_lookup_enabled() -> bool {
    matches!(
        env::var("RUST_NVD_VERIFY")
            .unwrap_or_else(|_| "false".to_string())
            .trim()
            .to_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

async fn fetch_nvd_match(cve_id: &str) -> Result<(bool, u64), String> {
    let nvd_base_url = env::var("NVD_BASE_URL").unwrap_or_else(|_| "https://services.nvd.nist.gov".to_string());
    let endpoint = format!("{}/rest/json/cves/2.0", nvd_base_url.trim_end_matches('/'));
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP-Client Fehler: {e}"))?
        .get(endpoint)
        .query(&[("cveId", cve_id)])
        .send()
        .await
        .map_err(|e| format!("NVD-Abfrage fehlgeschlagen: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("NVD-Abfrage fehlgeschlagen mit HTTP {}", response.status()));
    }
    let payload: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("NVD-Antwort konnte nicht geparsed werden: {e}"))?;
    let total = payload["totalResults"].as_u64().unwrap_or(0);
    Ok((total > 0, total))
}

async fn health_live() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "service": "iscy-rust-backend" }))
}

async fn web_index() -> Html<String> {
    Html(
        r#"<!doctype html>
<html lang="de">
<head><meta charset="utf-8"><title>ISCY Rust Web</title></head>
<body>
  <h1>ISCY Rust Web Surface</h1>
  <p>Diese Rust-Route bildet die Django-Weboberfläche schrittweise nach.</p>
  <ul>
    <li><a href="/dashboard/">Dashboard</a></li>
    <li><a href="/catalog/">Catalog</a></li>
    <li><a href="/reports/">Reports</a></li>
    <li><a href="/cves/">Vulnerability Intelligence</a></li>
  </ul>
</body>
</html>"#
            .to_string(),
    )
}

async fn web_placeholder(path: &'static str, title: &'static str) -> Html<String> {
    Html(format!(
        "<!doctype html><html lang=\"de\"><head><meta charset=\"utf-8\"><title>{title}</title></head><body><h1>{title}</h1><p>Rust-Web-Migrationsroute für <code>{path}</code>.</p></body></html>"
    ))
}

async fn web_login() -> Html<String> {
    web_placeholder("/login/", "Login").await
}
async fn web_dashboard() -> Html<String> {
    web_placeholder("/dashboard/", "Dashboard").await
}
async fn web_catalog() -> Html<String> {
    web_placeholder("/catalog/", "Catalog").await
}
async fn web_reports() -> Html<String> {
    web_placeholder("/reports/", "Reports").await
}
async fn web_roadmap() -> Html<String> {
    web_placeholder("/roadmap/", "Roadmap").await
}
async fn web_evidence() -> Html<String> {
    web_placeholder("/evidence/", "Evidence").await
}
async fn web_assets() -> Html<String> {
    web_placeholder("/assets/", "Assets").await
}
async fn web_imports() -> Html<String> {
    web_placeholder("/imports/", "Imports").await
}
async fn web_processes() -> Html<String> {
    web_placeholder("/processes/", "Processes").await
}
async fn web_requirements() -> Html<String> {
    web_placeholder("/requirements/", "Requirements").await
}
async fn web_risks() -> Html<String> {
    web_placeholder("/risks/", "Risks").await
}
async fn web_assessments() -> Html<String> {
    web_placeholder("/assessments/", "Assessments").await
}
async fn web_organizations() -> Html<String> {
    web_placeholder("/organizations/", "Organizations").await
}
async fn web_product_security() -> Html<String> {
    web_placeholder("/product-security/", "Product Security").await
}
async fn web_cves() -> Html<String> {
    web_placeholder("/cves/", "Vulnerability Intelligence").await
}
async fn web_navigator() -> Html<String> {
    web_placeholder("/navigator/", "Guidance Navigator").await
}

async fn nvd_import(Json(payload): Json<NvdImportRequest>) -> Json<NvdImportResponse> {
    let normalized = normalize_cve_id(&payload.cve_id);
    let parsed = parse_cve_id(&normalized);
    let (year, sequence) = parsed.unwrap_or((0, 0));
    let is_valid = parsed.is_some();
    let verify_nvd = nvd_lookup_enabled();
    let mut nvd_lookup_attempted = false;
    let mut nvd_match_found = None;
    let mut nvd_total_results = None;
    let message = if is_valid {
        if verify_nvd {
            nvd_lookup_attempted = true;
            match fetch_nvd_match(&normalized).await {
                Ok((found, total)) => {
                    nvd_match_found = Some(found);
                    nvd_total_results = Some(total);
                    if found {
                        format!("CVE-ID validiert und NVD-Treffer bestätigt ({} Treffer).", total)
                    } else {
                        "CVE-ID validiert, aber NVD lieferte keinen Treffer.".to_string()
                    }
                }
                Err(err) => format!("CVE-ID validiert, NVD-Verify fehlgeschlagen: {err}"),
            }
        } else {
            "CVE-ID validiert und für Import vorgemerkt.".to_string()
        }
    } else {
        "Ungültige CVE-ID. Erwartetes Format: CVE-YYYY-NNNN...".to_string()
    };
    Json(NvdImportResponse {
        accepted: is_valid,
        cve_id: normalized,
        source: "NVD",
        is_valid,
        year: if is_valid { Some(year) } else { None },
        sequence: if is_valid { Some(sequence) } else { None },
        message,
        nvd_lookup_attempted,
        nvd_match_found,
        nvd_total_results,
    })
}

async fn llm_generate(Json(payload): Json<LlmGenerateRequest>) -> Json<LlmGenerateResponse> {
    let excerpt: String = payload.prompt.chars().take(240).collect();
    let max_tokens = payload.max_tokens.unwrap_or(900);
    Json(LlmGenerateResponse {
        backend: "rust_service",
        model: "iscy-rust-llm-stub-v1",
        result: serde_json::json!({
            "technical_summary": format!("Rust-LLM Stub analysed prompt excerpt: {}", excerpt),
            "business_impact": "Potential operational and compliance impact identified; verify with domain experts.",
            "attack_path": "Unknown until full threat-context and exploit chain are provided.",
            "management_summary": "Prioritize patching, compensating controls, and evidence collection.",
            "recommended_actions": [
                "Validate affected assets and versions",
                "Apply vendor patch or workaround",
                "Add detection rule and monitoring"
            ],
            "evidence_needed": [
                "Asset inventory with affected versions",
                "Patch deployment report",
                "SOC detection and incident logs"
            ],
            "confidence": "medium",
            "max_tokens_requested": max_tokens
        }),
    })
}

async fn risk_priority(Json(payload): Json<RiskPriorityRequest>) -> Json<RiskPriorityResponse> {
    let mut bump = 0.0_f64;
    if payload.exposure == "INTERNET" {
        bump += 1.5;
    } else if payload.exposure == "CUSTOMER" {
        bump += 1.0;
    }
    if payload.criticality == "CRITICAL" {
        bump += 1.5;
    } else if payload.criticality == "HIGH" {
        bump += 1.0;
    }
    if let Some(epss) = payload.epss_score {
        if epss >= 0.90 {
            bump += 2.0;
        } else if epss >= 0.50 {
            bump += 1.0;
        } else if epss >= 0.20 {
            bump += 0.5;
        }
    }
    if payload.in_kev_catalog {
        bump += 2.5;
    }
    if payload.exploit_maturity == "AUTOMATED" {
        bump += 2.0;
    } else if payload.exploit_maturity == "ACTIVE" {
        bump += 1.5;
    } else if payload.exploit_maturity == "POC" {
        bump += 0.5;
    }
    if payload.affects_critical_service {
        bump += 1.5;
    }
    if payload.nis2_relevant {
        bump += 1.0;
    }
    let effective = payload.score + bump;
    let (priority, due_days) = if effective >= 9.5 {
        ("CRITICAL".to_string(), 7)
    } else if effective >= 8.0 {
        ("HIGH".to_string(), 14)
    } else if effective >= 6.0 {
        ("MEDIUM".to_string(), 30)
    } else {
        ("LOW".to_string(), 60)
    };
    Json(RiskPriorityResponse {
        priority,
        due_days,
        effective_score: (effective * 100.0).round() / 100.0,
    })
}

async fn guidance_evaluate(Json(payload): Json<GuidanceEvaluateRequest>) -> Json<GuidanceEvaluateResponse> {
    let mut todo_items: Vec<String> = Vec::new();
    if payload.applicability_count == 0 {
        todo_items.push("Betroffenheitsanalyse anlegen".to_string());
    }
    if !payload.description_present {
        todo_items.push("ISMS-Scope und Unternehmensbeschreibung pflegen".to_string());
    }
    if payload.process_count < 3 {
        todo_items.push(format!("Noch {} kritische Prozesse erfassen", 3 - payload.process_count));
    }
    if payload.risk_count < 1 {
        todo_items.push("Mindestens ein Risiko dokumentieren".to_string());
    }
    if payload.assessment_count < 1 {
        todo_items.push("Erstes Assessment durchführen".to_string());
    }
    if payload.measure_count < 1 {
        todo_items.push("Mindestens eine Incident-nahe Maßnahme dokumentieren (SOC-Playbook)".to_string());
    }
    if payload.measure_open_count > 0 {
        todo_items.push(format!("{} offene Maßnahmen nachverfolgen", payload.measure_open_count));
    }

    let steps = vec![
        ("applicability_checked", payload.applicability_count >= 1),
        ("company_scope_defined", payload.description_present && payload.sector_present),
        ("requirements_available", payload.requirement_count >= 4),
        ("initial_processes_captured", payload.process_count >= 3),
        ("initial_risks_captured", payload.risk_count >= 1),
        ("initial_assessment_done", payload.assessment_count >= 1),
        ("soc_phishing_playbook_applied", payload.measure_count >= 1),
    ];

    let current_step_code = steps.iter().find(|(_, done)| !*done).map(|(code, _)| code.to_string());
    let (summary, next_action_text) = match current_step_code.as_deref() {
        Some("applicability_checked") => (
            "Starten Sie mit der Betroffenheitsanalyse. Erst damit wird klar, ob ISO-27001-Readiness ausreicht oder NIS2-/KRITIS-Nähe vertieft werden sollte.".to_string(),
            "Bewerten Sie Sektor, Größe, kritische Dienstleistungen und Lieferkettenrolle.".to_string(),
        ),
        Some("company_scope_defined") => (
            "Definieren Sie den Scope des ISMS. Ohne Scope sind spätere Bewertungen fachlich unscharf und für Audits schwer belastbar.".to_string(),
            "Pflegen Sie Beschreibung, Zielbild, Sektor und kritische Leistungen des Unternehmens.".to_string(),
        ),
        Some("requirements_available") => (
            "Es fehlen Requirement-Grundlagen. Ohne die ISCY Requirement Library ist kein belastbares Mapping gegen ISO 27001 oder NIS2 moeglich.".to_string(),
            "Stellen Sie sicher, dass die ISCY Requirement Library initial geladen wurde.".to_string(),
        ),
        Some("initial_processes_captured") => (
            format!("Derzeit sind {} Prozesse erfasst. Für einen belastbaren Einstieg sollten mindestens 3 kritische Prozesse dokumentiert werden.", payload.process_count),
            "Erfassen Sie die wichtigsten Geschäfts- oder IT-Prozesse inklusive Owner und Kritikalität.".to_string(),
        ),
        Some("initial_risks_captured") => (
            format!("Derzeit sind {} Risiken erfasst. Ohne erste Risiken bleibt die Ableitung von Maßnahmen zu flach.", payload.risk_count),
            "Erfassen Sie mindestens ein initiales Risiko zu einem kritischen Prozess oder Asset.".to_string(),
        ),
        Some("initial_assessment_done") => (
            format!("Es gibt aktuell {} Assessments und {} offene Maßnahmen. Erst Assessments zeigen, was ausreichend ist und wo echte Gaps bestehen.", payload.assessment_count, payload.measure_open_count),
            "Starten Sie die erste Prozess- oder Requirement-Bewertung.".to_string(),
        ),
        Some("soc_phishing_playbook_applied") => (
            format!("Für den Tenant sind bisher {} Maßnahmen dokumentiert. Das SOC-Playbook gilt als praktisch verankert, wenn mindestens eine Maßnahme als Incident-Reaktion nachvollziehbar erfasst ist.", payload.measure_count),
            "Erfassen Sie eine konkrete Incident-Maßnahme (z. B. Mail-Containment, Session-Entzug oder Konto-Absicherung) inklusive Priorität und Status.".to_string(),
        ),
        _ => (
            "Alle aktuell definierten Guided Steps sind abgeschlossen.".to_string(),
            "Nächster sinnvoller Schritt: Evidenzen, Reviews und Audit-Vorbereitung vertiefen.".to_string(),
        ),
    };

    Json(GuidanceEvaluateResponse {
        current_step_code,
        summary,
        next_action_text,
        todo_items,
    })
}

async fn report_cve_summary(Json(payload): Json<CveSummaryRequest>) -> Json<CveSummaryResponse> {
    let total = payload.total.max(1) as f64;
    let critical_ratio = payload.critical as f64 / total;
    let kev_ratio = payload.kev as f64 / total;
    let nis2_ratio = payload.nis2 as f64 / total;
    let score = ((critical_ratio * 0.5) + (kev_ratio * 0.3) + (nis2_ratio * 0.2)) * 100.0;
    Json(CveSummaryResponse {
        total: payload.total,
        critical: payload.critical,
        with_risk: payload.with_risk,
        llm_generated: payload.llm_generated,
        nis2: payload.nis2,
        kev: payload.kev,
        risk_hotspot_score: (score * 100.0).round() / 100.0,
    })
}

pub fn app_router() -> Router {
    Router::new()
        .route("/health", get(health_live))
        .route("/health/ready", get(health_live))
        .route("/health/live", get(health_live))
        .route("/", get(web_index))
        .route("/login/", get(web_login))
        .route("/navigator/", get(web_navigator))
        .route("/dashboard/", get(web_dashboard))
        .route("/catalog/", get(web_catalog))
        .route("/reports/", get(web_reports))
        .route("/roadmap/", get(web_roadmap))
        .route("/evidence/", get(web_evidence))
        .route("/assets/", get(web_assets))
        .route("/imports/", get(web_imports))
        .route("/processes/", get(web_processes))
        .route("/requirements/", get(web_requirements))
        .route("/risks/", get(web_risks))
        .route("/assessments/", get(web_assessments))
        .route("/organizations/", get(web_organizations))
        .route("/product-security/", get(web_product_security))
        .route("/cves/", get(web_cves))
        .route("/api/v1/nvd/import", post(nvd_import))
        .route("/api/v1/llm/generate", post(llm_generate))
        .route("/api/v1/risk/priority", post(risk_priority))
        .route("/api/v1/guidance/evaluate", post(guidance_evaluate))
        .route("/api/v1/reports/cve-summary", post(report_cve_summary))
}

#[cfg(test)]
mod tests {
    use super::{normalize_cve_id, parse_cve_id};

    #[test]
    fn normalize_cve_id_uppercases_and_trims() {
        assert_eq!(normalize_cve_id(" cve-2026-1234 "), "CVE-2026-1234");
    }

    #[test]
    fn parse_cve_id_accepts_valid_identifier() {
        assert_eq!(parse_cve_id(" cve-2026-1234 "), Some((2026, 1234)));
    }

    #[test]
    fn parse_cve_id_rejects_invalid_identifier() {
        assert_eq!(parse_cve_id("NOT-A-CVE"), None);
        assert_eq!(parse_cve_id("CVE-20-12"), None);
    }
}
