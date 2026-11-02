//! Read-only views over existing assessment runs. Identity never comes from URLs.
use crate::{
    auth_error_response, authenticated_tenant_context, html_escape,
    request_context::AuthenticatedTenantContext,
    web_error_page, web_page,
    wizard_store::{WizardResultsSummary, WizardSessionSummary},
    AppState, WebContext,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

const ACTIVE: &str = "/assessments/";
fn web_context(context: &AuthenticatedTenantContext) -> WebContext {
    WebContext {
        tenant_id: context.tenant_id,
        user_id: context.user_id,
        user_email: context.user_email.clone(),
    }
}
fn allowed(context: &AuthenticatedTenantContext) -> bool {
    context.can_write()
        || context.has_permission("wizard.view_assessmentsession")
        || ["AUDITOR", "READ_ONLY", "VIEWER"]
            .iter()
            .any(|role| context.has_role(role))
}
fn error(context: &AuthenticatedTenantContext, status: StatusCode, message: &str) -> Response {
    (
        status,
        web_error_page(
            "Assessment-Durchlaeufe",
            ACTIVE,
            &web_context(context),
            message,
        ),
    )
        .into_response()
}
fn page(context: &AuthenticatedTenantContext, body: &str) -> Response {
    let mut response = web_page(
        "Assessment-Durchlaeufe",
        ACTIVE,
        Some(&web_context(context)),
        body,
    )
    .into_response();
    response
        .headers_mut()
        .insert("cache-control", "private, no-store".parse().unwrap());
    response
}
fn heading(session: &WizardSessionSummary) -> String {
    format!(
        "{} · Durchlauf {}",
        html_escape(&session.assessment_type_label),
        session.id
    )
}

pub(crate) async fn sessions(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(err) => return auth_error_response(err),
    };
    if !allowed(&context) {
        return error(
            &context,
            StatusCode::FORBIDDEN,
            "Diese Rolle darf Assessment-Durchlaeufe nicht lesen.",
        );
    }
    let Some(store) = state.wizard_store.as_ref() else {
        return error(
            &context,
            StatusCode::SERVICE_UNAVAILABLE,
            "Assessment-Daten sind derzeit nicht verfuegbar.",
        );
    };
    let items = match store.list_sessions(context.tenant_id, 50).await {
        Ok(items) => items,
        Err(_) => {
            return error(
                &context,
                StatusCode::INTERNAL_SERVER_ERROR,
                "Assessment-Daten konnten nicht sicher gelesen werden.",
            )
        }
    };
    let rows = items.iter().map(|item| format!(r#"<tr><td><a href="/assessments/runs/{}/">{}</a></td><td>{}</td><td>{}</td><td><progress max="100" value="{}" aria-label="Fortschritt Durchlauf {}">{} %</progress> {} %</td><td>{}</td><td>{}</td></tr>"#,
        item.id,heading(item),html_escape(&item.status_label),html_escape(&item.current_step_label),item.progress_percent.clamp(0,100),item.id,item.progress_percent.clamp(0,100),item.progress_percent.clamp(0,100),html_escape(item.started_by_display.as_deref().unwrap_or("–")),html_escape(&item.updated_at))).collect::<String>();
    let rows = if rows.is_empty() {
        "<tr><td colspan=\"6\">Keine Assessment-Durchlaeufe vorhanden.</td></tr>".to_owned()
    } else {
        rows
    };
    page(
        &context,
        &format!(
            r#"<section class="hero compact"><h1>Assessment-Durchlaeufe</h1><p>Vorhandene Bewertungen und ihre Ergebnisse ansehen.</p><p><a href="/assessments/company-wizard/">Unternehmensprofil im internationalen Wizard erfassen / fortsetzen</a></p><p><a href="/assessments/">Zum Assessment-Register</a> · <a href="/assessments/soa/">Statement of Applicability</a></p></section><section class="panel wide"><h2>Vorhandene Durchlaeufe</h2><p>Die letzten 50 aktualisierten Durchlaeufe werden angezeigt.</p><table><caption>Assessment-Durchlaeufe des angemeldeten Mandanten</caption><thead><tr><th scope="col">Durchlauf</th><th scope="col">Status</th><th scope="col">Schritt</th><th scope="col">Fortschritt</th><th scope="col">Gestartet von</th><th scope="col">Aktualisiert</th></tr></thead><tbody>{rows}</tbody></table></section>"#
        ),
    )
}

pub(crate) async fn results(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Response {
    let context = match authenticated_tenant_context(&state, &headers).await {
        Ok(context) => context,
        Err(err) => return auth_error_response(err),
    };
    if !allowed(&context) {
        return error(
            &context,
            StatusCode::FORBIDDEN,
            "Diese Rolle darf Assessment-Durchlaeufe nicht lesen.",
        );
    }
    if id < 1 {
        return error(
            &context,
            StatusCode::NOT_FOUND,
            "Assessment-Durchlauf wurde nicht gefunden.",
        );
    }
    let Some(store) = state.wizard_store.as_ref() else {
        return error(
            &context,
            StatusCode::SERVICE_UNAVAILABLE,
            "Assessment-Daten sind derzeit nicht verfuegbar.",
        );
    };
    let summary = match store.session_summary(context.tenant_id, id).await {
        Ok(Some(summary)) => summary,
        Ok(None) => {
            return error(
                &context,
                StatusCode::NOT_FOUND,
                "Assessment-Durchlauf wurde nicht gefunden.",
            )
        }
        Err(_) => {
            return error(
                &context,
                StatusCode::INTERNAL_SERVER_ERROR,
                "Assessment-Ergebnisse konnten nicht sicher gelesen werden.",
            )
        }
    };
    match store.has_detailed_results().await {
        Ok(false) => {
            return page(
                &context,
                &format!(
                    r#"<section class="hero compact"><h1>{}</h1><p>{} · {}</p><a href="/assessments/runs/">Alle Durchlaeufe</a></section><section class="panel wide"><h2>Zusammenfassung</h2><p>{}</p><h3>Anwendbarkeit</h3><p>{}</p><p>{}</p><p role="status">Die Detailauswertung ist fuer diesen Datenbestand nicht verfuegbar. Angezeigt werden die gespeicherten Angaben zum Durchlauf.</p></section>"#,
                    heading(&summary),
                    html_escape(&summary.status_label),
                    html_escape(&summary.current_step_label),
                    html_escape(&summary.executive_summary),
                    html_escape(&summary.applicability_result),
                    html_escape(&summary.applicability_reasoning)
                ),
            )
        }
        Ok(true) => {}
        Err(_) => {
            return error(
                &context,
                StatusCode::INTERNAL_SERVER_ERROR,
                "Assessment-Ergebnisse konnten nicht sicher gelesen werden.",
            )
        }
    }
    match store.results(context.tenant_id, id).await {
        Ok(Some(result)) => page(&context, &render_results(&result)),
        Ok(None) => error(
            &context,
            StatusCode::NOT_FOUND,
            "Assessment-Durchlauf wurde nicht gefunden.",
        ),
        Err(_) => error(
            &context,
            StatusCode::INTERNAL_SERVER_ERROR,
            "Assessment-Ergebnisse konnten nicht sicher gelesen werden.",
        ),
    }
}
fn render_results(result: &WizardResultsSummary) -> String {
    let s = &result.session;
    let scores = result
        .domain_scores
        .iter()
        .map(|item| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{} %</td><td>{}</td><td>{}</td></tr>",
                html_escape(&item.domain_code),
                html_escape(&item.domain_name),
                item.score_percent,
                html_escape(&item.maturity_level),
                html_escape(&item.gap_level)
            )
        })
        .collect::<String>();
    let gaps = result
        .gaps
        .iter()
        .map(|item| {
            format!(
                "<li><h3>{}</h3><p>{} · {}</p><p>{}</p></li>",
                html_escape(&item.title),
                html_escape(&item.domain_name),
                html_escape(&item.severity_label),
                html_escape(&item.description)
            )
        })
        .collect::<String>();
    let measures = result
        .measures
        .iter()
        .map(|item| {
            format!(
                "<li><h3>{}</h3><p>{} · {} · {}</p><p>{}</p><p>{}</p></li>",
                html_escape(&item.title),
                html_escape(&item.priority_label),
                html_escape(&item.status_label),
                html_escape(&item.effort_label),
                html_escape(&item.description),
                html_escape(&item.reason)
            )
        })
        .collect::<String>();
    let report = result
        .report
        .as_ref()
        .map(|item| {
            format!(
                "<p>Report: {} · <a href=\"/reports/\">Zu Reports</a></p>",
                html_escape(&item.title)
            )
        })
        .unwrap_or_else(|| "<p>Kein Report verknuepft.</p>".to_owned());
    let roadmap = result
        .roadmap
        .as_ref()
        .map(|item| {
            format!(
                "<p>Roadmap: {} · <a href=\"/roadmap/\">Zur Roadmap</a></p>",
                html_escape(&item.plan.title)
            )
        })
        .unwrap_or_else(|| "<p>Keine Roadmap verknuepft.</p>".to_owned());
    format!(
        r#"<section class="hero compact"><h1>{}</h1><p>{} · {}</p><a href="/assessments/runs/">Alle Durchlaeufe</a></section>
<section class="panel wide"><h2>Zusammenfassung</h2><p>{}</p><h3>Anwendbarkeit</h3><p>{}</p><p>{}</p><p>Verknuepfte Nachweise: {}</p>{report}{roadmap}</section>
<section class="panel wide"><h2>Domain-Bewertungen</h2><table><caption>Gespeicherte Domain-Bewertungen</caption><thead><tr><th scope="col">Code</th><th scope="col">Domain</th><th scope="col">Bewertung</th><th scope="col">Reifegrad</th><th scope="col">Luecke</th></tr></thead><tbody>{}</tbody></table></section>
<section class="panel wide"><h2>Erkannte Luecken</h2><p>Bis zu 20 gespeicherte Eintraege.</p><ul>{}</ul></section><section class="panel wide"><h2>Empfohlene Massnahmen</h2><p>Bis zu 20 gespeicherte Eintraege.</p><ul>{}</ul></section>"#,
        heading(s),
        html_escape(&s.status_label),
        html_escape(&s.current_step_label),
        html_escape(&s.executive_summary),
        html_escape(&s.applicability_result),
        html_escape(&s.applicability_reasoning),
        result.evidence_count,
        if scores.is_empty() {
            "<tr><td colspan=\"5\">Keine Domain-Bewertungen vorhanden.</td></tr>".to_owned()
        } else {
            scores
        },
        if gaps.is_empty() {
            "<li>Keine gespeicherten Luecken vorhanden.</li>".to_owned()
        } else {
            gaps
        },
        if measures.is_empty() {
            "<li>Keine gespeicherten Massnahmen vorhanden.</li>".to_owned()
        } else {
            measures
        }
    )
}
