//! W1: resumable company-profile drafts. No regulatory decision is inferred.
use axum::{
    extract::{DefaultBodyLimit, Form, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::{QueryBuilder, Row};

use crate::{
    auth_error_response, authenticated_tenant_context, html_escape,
    request_context::AuthenticatedTenantContext, session_token_from_headers, web_page,
    wizard_store::WizardStore, AppState, WebContext,
};

pub const ROOT: &str = "/assessments/company-wizard/";

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CompanyProfile {
    pub company_name: String,
    pub headquarters_country: String,
    pub operation_countries: Vec<String>,
    pub geographic_scope: String,
    pub sector: String,
    pub size_reference: String,
    pub employee_count: Option<i64>,
    pub annual_revenue_million: Option<String>,
    pub balance_sheet_million: Option<String>,
    pub critical_services: String,
    pub supply_chain_role: String,
    pub develops_digital_products: Option<bool>,
    pub uses_ai_systems: Option<bool>,
    pub ot_iacs_scope: Option<bool>,
    pub automotive_scope: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct CompanyDraft {
    pub id: i64,
    pub revision: i64,
    pub editable: bool,
    pub profile: CompanyProfile,
}

#[derive(Debug)]
pub enum DraftError {
    Invalid(&'static str),
    Conflict,
}
impl std::fmt::Display for DraftError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => f.write_str(message),
            Self::Conflict => f.write_str("Der Entwurf wurde inzwischen geaendert oder ist gesperrt. Bitte neu laden; Ihre Eingaben wurden nicht gespeichert."),
        }
    }
}
impl std::error::Error for DraftError {}

impl CompanyProfile {
    pub fn normalize(mut self) -> anyhow::Result<Self> {
        for (text, max) in [
            (&mut self.company_name, 255),
            (&mut self.headquarters_country, 80),
            (&mut self.sector, 255),
            (&mut self.size_reference, 2000),
            (&mut self.geographic_scope, 2000),
            (&mut self.critical_services, 2000),
            (&mut self.supply_chain_role, 2000),
        ] {
            *text = text.trim().to_owned();
            if text.chars().count() > max
                || text
                    .chars()
                    .any(|c| c.is_control() && c != '\n' && c != '\t')
            {
                return Err(DraftError::Invalid(
                    "Ein Textfeld ist zu lang oder enthaelt unzulaessige Steuerzeichen.",
                )
                .into());
            }
        }
        if self
            .employee_count
            .is_some_and(|n| !(0..=1_000_000_000).contains(&n))
        {
            return Err(DraftError::Invalid("Mitarbeiterzahl muss eine ganze Zahl zwischen 0 und 1000000000 sein; leer bedeutet unbekannt.").into());
        }
        for value in [
            &mut self.annual_revenue_million,
            &mut self.balance_sheet_million,
        ] {
            *value = value
                .take()
                .map(|v| v.trim().replace(',', "."))
                .filter(|v| !v.is_empty());
            if let Some(text) = value {
                let parts = text.split('.').collect::<Vec<_>>();
                if parts.len() > 2
                    || parts[0].is_empty()
                    || parts[0].len() > 9
                    || !parts[0].bytes().all(|b| b.is_ascii_digit())
                    || (parts.len() == 2
                        && (parts[1].is_empty()
                            || parts[1].len() > 2
                            || !parts[1].bytes().all(|b| b.is_ascii_digit())))
                {
                    return Err(DraftError::Invalid("Umsatz/Bilanz bitte in Mio. EUR mit maximal zwei Nachkommastellen angeben, ohne Tausendertrennzeichen; leer bedeutet unbekannt.").into());
                }
            }
        }
        if self.operation_countries.len() > 50 {
            return Err(DraftError::Invalid("Maximal 50 operative Laender pro Entwurf.").into());
        }
        let mut countries = Vec::<String>::new();
        for value in self.operation_countries {
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            if value.chars().count() > 80 || value.chars().any(char::is_control) {
                return Err(DraftError::Invalid(
                    "Laenderangaben muessen 1 bis 80 Zeichen ohne Steuerzeichen enthalten.",
                )
                .into());
            }
            if !countries
                .iter()
                .any(|old| old.to_lowercase() == value.to_lowercase())
            {
                countries.push(value.to_owned());
            }
        }
        self.operation_countries = countries;
        if serde_json::to_vec(&self)?.len() > 16384 {
            return Err(
                DraftError::Invalid("Das Unternehmensprofil ist insgesamt zu gross.").into(),
            );
        }
        Ok(self)
    }
}

macro_rules! database {
    ($store:expr, $pool:ident, $db:ident, $body:block) => {
        match $store {
            WizardStore::Postgres($pool) => {
                type $db = sqlx::Postgres;
                $body
            }
            WizardStore::Sqlite($pool) => {
                type $db = sqlx::Sqlite;
                $body
            }
        }
    };
}

const SELECT_DRAFT: &str = "SELECT p.session_id,p.revision,p.profile_json,s.status,s.current_step
 FROM wizard_companyprofile p JOIN wizard_assessmentsession s
 ON s.id=p.session_id AND s.tenant_id=p.tenant_id WHERE p.tenant_id=";

impl WizardStore {
    pub async fn company_drafts(&self, tenant_id: i64) -> anyhow::Result<Vec<CompanyDraft>> {
        database!(self, pool, Db, {
            let rows = QueryBuilder::<Db>::new(SELECT_DRAFT)
                .push_bind(tenant_id)
                .push(" ORDER BY p.updated_at DESC,p.session_id DESC LIMIT 50")
                .build()
                .fetch_all(pool)
                .await?;
            rows.into_iter()
                .map(|row| {
                    Ok(CompanyDraft {
                        id: row.try_get("session_id")?,
                        revision: row.try_get("revision")?,
                        editable: ["DRAFT", "IN_PROGRESS"]
                            .contains(&row.try_get::<String, _>("status")?.as_str())
                            && row.try_get::<String, _>("current_step")? == "profile",
                        profile: serde_json::from_str(&row.try_get::<String, _>("profile_json")?)?,
                    })
                })
                .collect()
        })
    }
    pub async fn company_draft(
        &self,
        tenant_id: i64,
        id: i64,
    ) -> anyhow::Result<Option<CompanyDraft>> {
        database!(self, pool, Db, {
            let row = QueryBuilder::<Db>::new(SELECT_DRAFT)
                .push_bind(tenant_id)
                .push(" AND p.session_id=")
                .push_bind(id)
                .build()
                .fetch_optional(pool)
                .await?;
            row.map(|row| {
                Ok(CompanyDraft {
                    id: row.try_get("session_id")?,
                    revision: row.try_get("revision")?,
                    editable: ["DRAFT", "IN_PROGRESS"]
                        .contains(&row.try_get::<String, _>("status")?.as_str())
                        && row.try_get::<String, _>("current_step")? == "profile",
                    profile: serde_json::from_str(&row.try_get::<String, _>("profile_json")?)?,
                })
            })
            .transpose()
        })
    }
    pub async fn create_company_draft(
        &self,
        tenant_id: i64,
        actor_id: i64,
    ) -> anyhow::Result<Option<i64>> {
        database!(self, pool, Db, {
            let mut tx = pool.begin().await?;
            let name: Option<String> = QueryBuilder::<Db>::new(
                "SELECT t.name FROM organizations_tenant t
                JOIN accounts_user u ON u.tenant_id=t.id WHERE t.id=",
            )
            .push_bind(tenant_id)
            .push(" AND u.id=")
            .push_bind(actor_id)
            .push(" AND u.is_active")
            .build_query_scalar()
            .fetch_optional(&mut *tx)
            .await?;
            let Some(name) = name else {
                return Ok(None);
            };
            let profile = CompanyProfile {
                company_name: name,
                ..CompanyProfile::default()
            }
            .normalize()?;
            let id: i64 = QueryBuilder::<Db>::new(
                "INSERT INTO wizard_assessmentsession
                (tenant_id,started_by_id,assessment_type,status,current_step,progress_percent)
                VALUES (",
            )
            .push_bind(tenant_id)
            .push(",")
            .push_bind(actor_id)
            .push(",'APPLICABILITY','DRAFT','profile',0) RETURNING id")
            .build_query_scalar()
            .fetch_one(&mut *tx)
            .await?;
            QueryBuilder::<Db>::new("INSERT INTO wizard_companyprofile (tenant_id,session_id,revision,profile_json) VALUES (")
                .push_bind(tenant_id).push(",").push_bind(id).push(",1,").push_bind(serde_json::to_string(&profile)?).push(")")
                .build().execute(&mut *tx).await?;
            QueryBuilder::<Db>::new("INSERT INTO wizard_profileevent (tenant_id,session_id,actor_id,revision,action) VALUES (")
                .push_bind(tenant_id).push(",").push_bind(id).push(",").push_bind(actor_id)
                .push(",1,'CREATED')").build().execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(Some(id))
        })
    }
    pub async fn save_company_draft(
        &self,
        tenant_id: i64,
        actor_id: i64,
        id: i64,
        revision: i64,
        profile: CompanyProfile,
    ) -> anyhow::Result<bool> {
        if revision < 1 {
            return Err(DraftError::Invalid("Ungueltige Entwurfsversion.").into());
        }
        let profile = profile.normalize()?;
        database!(self, pool, Db, {
            let postgres = matches!(self, WizardStore::Postgres(_));
            let mut tx = if postgres {
                pool.begin().await?
            } else {
                pool.begin_with("BEGIN IMMEDIATE").await?
            };
            let mut parent = QueryBuilder::<Db>::new("SELECT s.status,s.current_step,p.revision
                FROM wizard_assessmentsession s JOIN wizard_companyprofile p ON p.session_id=s.id AND p.tenant_id=s.tenant_id
                JOIN accounts_user u ON u.tenant_id=s.tenant_id WHERE s.tenant_id=");
            parent
                .push_bind(tenant_id)
                .push(" AND s.id=")
                .push_bind(id)
                .push(" AND u.id=")
                .push_bind(actor_id)
                .push(" AND u.is_active");
            if postgres {
                parent.push(" FOR UPDATE OF s,p");
            }
            let Some(row) = parent.build().fetch_optional(&mut *tx).await? else {
                return Ok(false);
            };
            if !["DRAFT", "IN_PROGRESS"].contains(&row.try_get::<String, _>("status")?.as_str())
                || row.try_get::<String, _>("current_step")? != "profile"
                || row.try_get::<i64, _>("revision")? != revision
            {
                return Err(DraftError::Conflict.into());
            }
            let changed = QueryBuilder::<Db>::new("UPDATE wizard_companyprofile SET profile_json=")
                .push_bind(serde_json::to_string(&profile)?)
                .push(",revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=")
                .push_bind(tenant_id)
                .push(" AND session_id=")
                .push_bind(id)
                .push(" AND revision=")
                .push_bind(revision)
                .build()
                .execute(&mut *tx)
                .await?
                .rows_affected();
            if changed != 1 {
                return Err(DraftError::Conflict.into());
            }
            QueryBuilder::<Db>::new("UPDATE wizard_assessmentsession SET status='IN_PROGRESS',updated_at=CURRENT_TIMESTAMP WHERE tenant_id=")
                .push_bind(tenant_id).push(" AND id=").push_bind(id).build().execute(&mut *tx).await?;
            QueryBuilder::<Db>::new("INSERT INTO wizard_profileevent (tenant_id,session_id,actor_id,revision,action) VALUES (")
                .push_bind(tenant_id).push(",").push_bind(id).push(",").push_bind(actor_id)
                .push(",").push_bind(revision+1).push(",'SAVED')").build().execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(true)
        })
    }
}

pub(crate) const SQLITE_SCHEMA: &str = r#"
CREATE UNIQUE INDEX IF NOT EXISTS idx_wizard_session_tenant ON wizard_assessmentsession(id,tenant_id);
CREATE TABLE IF NOT EXISTS wizard_companyprofile (
    session_id INTEGER PRIMARY KEY,
    tenant_id INTEGER NOT NULL REFERENCES organizations_tenant(id),
    revision BIGINT NOT NULL CHECK(revision>0),
    profile_json TEXT NOT NULL CHECK(length(profile_json)<=16384),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(session_id,tenant_id) REFERENCES wizard_assessmentsession(id,tenant_id)
);
CREATE INDEX IF NOT EXISTS idx_wizard_profile_tenant ON wizard_companyprofile(tenant_id,session_id);
CREATE TABLE IF NOT EXISTS wizard_profileevent (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL REFERENCES organizations_tenant(id),
    session_id INTEGER NOT NULL,
    actor_id INTEGER NOT NULL REFERENCES accounts_user(id),
    revision BIGINT NOT NULL CHECK(revision>0),
    action TEXT NOT NULL CHECK(action IN ('CREATED','SAVED')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(session_id,tenant_id) REFERENCES wizard_assessmentsession(id,tenant_id)
);
CREATE INDEX IF NOT EXISTS idx_wizard_profile_event_tenant ON wizard_profileevent(tenant_id,session_id,id);
"#;
// Both databases use text snapshots/timestamps; no lossy numeric coercion.
pub(crate) const POSTGRES_SCHEMA: &str = r#"
CREATE UNIQUE INDEX IF NOT EXISTS idx_wizard_session_tenant ON wizard_assessmentsession(id,tenant_id);
CREATE TABLE IF NOT EXISTS wizard_companyprofile (
    session_id BIGINT PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES organizations_tenant(id),
    revision BIGINT NOT NULL CHECK(revision>0),
    profile_json TEXT NOT NULL CHECK(length(profile_json)<=16384),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(session_id,tenant_id) REFERENCES wizard_assessmentsession(id,tenant_id)
);
CREATE INDEX IF NOT EXISTS idx_wizard_profile_tenant ON wizard_companyprofile(tenant_id,session_id);
CREATE TABLE IF NOT EXISTS wizard_profileevent (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES organizations_tenant(id),
    session_id BIGINT NOT NULL,
    actor_id BIGINT NOT NULL REFERENCES accounts_user(id),
    revision BIGINT NOT NULL CHECK(revision>0),
    action TEXT NOT NULL CHECK(action IN ('CREATED','SAVED')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(session_id,tenant_id) REFERENCES wizard_assessmentsession(id,tenant_id)
);
CREATE INDEX IF NOT EXISTS idx_wizard_profile_event_tenant ON wizard_profileevent(tenant_id,session_id,id);
"#;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(ROOT, get(index).post(create))
        .route("/assessments/company-wizard/{id}/", get(edit).post(save))
        .layer(DefaultBodyLimit::max(65536))
}

fn page(context: &AuthenticatedTenantContext, body: &str) -> Response {
    let context = WebContext {
        tenant_id: context.tenant_id,
        user_id: context.user_id,
        user_email: context.user_email.clone(),
    };
    let mut response =
        web_page("Unternehmens-Wizard", "/assessments/", Some(&context), body).into_response();
    response
        .headers_mut()
        .insert("cache-control", "private, no-store".parse().unwrap());
    response
}
fn error(status: StatusCode, message: &str) -> Response {
    (status, message.to_owned()).into_response()
}
fn store_error(err: anyhow::Error) -> Response {
    if let Some(err) = err.downcast_ref::<DraftError>() {
        error(
            if matches!(err, DraftError::Conflict) {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_REQUEST
            },
            &err.to_string(),
        )
    } else {
        error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unternehmensentwurf konnte nicht sicher verarbeitet werden.",
        )
    }
}
async fn access(
    state: &AppState,
    headers: &HeaderMap,
    write: bool,
) -> Result<(AuthenticatedTenantContext, WizardStore), Box<Response>> {
    let context = authenticated_tenant_context(state, headers)
        .await
        .map_err(|err| Box::new(auth_error_response(err)))?;
    let read = context.can_write()
        || context.has_permission("wizard.view_assessmentsession")
        || ["AUDITOR", "READ_ONLY", "VIEWER"]
            .iter()
            .any(|r| context.has_role(r));
    if (write && !context.can_write()) || (!write && !read) {
        return Err(Box::new(error(
            StatusCode::FORBIDDEN,
            "Diese Rolle darf den Unternehmensentwurf nicht bearbeiten beziehungsweise lesen.",
        )));
    }
    let store = state.wizard_store.clone().ok_or_else(|| {
        Box::new(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Unternehmensentwuerfe sind derzeit nicht verfuegbar.",
        ))
    })?;
    Ok((context, store))
}
fn form_mac(headers: &HeaderMap) -> Option<Hmac<Sha256>> {
    let token = session_token_from_headers(headers)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(token.as_bytes()).ok()?;
    mac.update(b"ISCY:company-wizard:form:v1");
    Some(mac)
}
fn form_token(state: &AppState, headers: &HeaderMap) -> Option<String> {
    state.auth_store.as_ref()?;
    Some(BASE64.encode(form_mac(headers)?.finalize().into_bytes()))
}
fn valid_form_token(state: &AppState, headers: &HeaderMap, provided: &str) -> bool {
    if state.auth_store.is_none() || provided.len() != 44 {
        return false;
    }
    let (Some(mac), Ok(bytes)) = (form_mac(headers), BASE64.decode(provided)) else {
        return false;
    };
    mac.verify_slice(&bytes).is_ok()
}

async fn index(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (context, store) = match access(&state, &headers, false).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let drafts = match store.company_drafts(context.tenant_id).await {
        Ok(v) => v,
        Err(e) => return store_error(e),
    };
    let create = if context.can_write() {
        form_token(&state,&headers).map(|token|format!(r#"<form method="post" action="{ROOT}"><input type="hidden" name="csrf_token" value="{}"><button type="submit">Neuen Unternehmensentwurf anlegen</button></form>"#,html_escape(&token))).unwrap_or_else(||"<p>Zum Anlegen bitte mit einer ISCY-Session anmelden.</p>".to_owned())
    } else {
        String::new()
    };
    let rows= drafts.iter().map(|d|format!("<li><a href=\"{ROOT}{}/\">{} · Entwurf {} fortsetzen / ansehen</a> · Version {}</li>",d.id,html_escape(&d.profile.company_name),d.id,d.revision)).collect::<String>();
    page(
        &context,
        &format!(
            r#"<section class="hero compact"><h1>Unternehmens- und Betroffenheits-Wizard</h1><p>Fuer nationale Unternehmen und solche mit grenzueberschreitenden Taetigkeiten.</p><p>1. Unternehmensprofil · 2. Betroffenheit (noch offen) · 3. Ergebnis und Massnahmen (noch offen)</p><p>Speichern Sie bekannte Unternehmensdaten und setzen Sie den Entwurf spaeter fort. Dieser Schritt erzeugt keine rechtliche Betroffenheitsentscheidung.</p><a href="/assessments/runs/">Vorhandene Assessment-Ergebnisse</a></section><section class="panel wide"><h2>Unternehmensentwuerfe</h2>{create}<p>Die letzten 50 Entwuerfe dieses Mandanten:</p><ul>{rows}</ul></section>"#
        ),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateForm {
    csrf_token: String,
}
async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateForm>,
) -> Response {
    let (context, store) = match access(&state, &headers, true).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    if !valid_form_token(&state, &headers, &form.csrf_token) {
        return error(
            StatusCode::FORBIDDEN,
            "Gueltige ISCY-Session und Formular-Token erforderlich.",
        );
    }
    match store
        .create_company_draft(context.tenant_id, context.user_id)
        .await
    {
        Ok(Some(id)) => Redirect::to(&format!("{ROOT}{id}/")).into_response(),
        Ok(None) => error(
            StatusCode::NOT_FOUND,
            "Unternehmensentwurf wurde nicht gefunden.",
        ),
        Err(e) => store_error(e),
    }
}
fn input(name: &str, label: &str, value: &str, kind: &str, max: usize) -> String {
    format!(
        r#"<label>{label}<input type="{kind}" name="{name}" value="{}" maxlength="{max}"></label>"#,
        html_escape(value)
    )
}
fn textarea(name: &str, label: &str, value: &str, max: usize) -> String {
    format!(
        r#"<label>{label}<textarea name="{name}" maxlength="{max}">{}</textarea></label>"#,
        html_escape(value)
    )
}
fn tri_state(name: &str, label: &str, value: Option<bool>) -> String {
    let options = [("", "Noch unbekannt"), ("yes", "Ja"), ("no", "Nein")]
        .iter()
        .map(|(key, text)| {
            format!(
                "<option value=\"{key}\"{}>{text}</option>",
                if *key == value.map(|v| if v { "yes" } else { "no" }).unwrap_or("") {
                    " selected"
                } else {
                    ""
                }
            )
        })
        .collect::<String>();
    format!(r#"<label>{label}<select name="{name}">{options}</select></label>"#)
}
async fn edit(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<i64>) -> Response {
    let (context, store) = match access(&state, &headers, false).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let draft = match store.company_draft(context.tenant_id, id).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return error(
                StatusCode::NOT_FOUND,
                "Unternehmensentwurf wurde nicht gefunden.",
            )
        }
        Err(e) => return store_error(e),
    };
    render_editor(&state, &headers, &context, &draft, None, None)
}
fn render_editor(
    state: &AppState,
    headers: &HeaderMap,
    context: &AuthenticatedTenantContext,
    draft: &CompanyDraft,
    submitted: Option<&ProfileForm>,
    problem: Option<&str>,
) -> Response {
    let id = draft.id;
    let p = &draft.profile;
    let stored = ProfileForm::from_draft(draft);
    let f = submitted.unwrap_or(&stored);
    let mut fields = String::new();
    fields += &input(
        "company_name",
        "Unternehmen / betrachtete Rechtseinheit",
        &f.company_name,
        "text",
        255,
    );
    fields += &input(
        "headquarters_country",
        "Staat des Hauptsitzes (Land oder Laendercode)",
        &f.headquarters_country,
        "text",
        80,
    );
    fields += &textarea(
        "operation_countries",
        "Operative Laender (ein Land pro Zeile oder durch Komma getrennt)",
        &f.operation_countries,
        4096,
    );
    fields += &textarea(
        "geographic_scope",
        "Niederlassungen, angebotene Maerkte und Bezug zur betrachteten Rechtseinheit",
        &f.geographic_scope,
        2000,
    );
    fields += &input(
        "sector",
        "Sektor und konkrete Taetigkeit",
        &f.sector,
        "text",
        255,
    );
    fields += &input(
        "employee_count",
        "Mitarbeiterzahl (leer = unbekannt)",
        &f.employee_count,
        "number",
        10,
    );
    fields += &input(
        "annual_revenue_million",
        "Jahresumsatz in Mio. EUR (leer = unbekannt)",
        &f.annual_revenue_million,
        "text",
        12,
    );
    fields += &input(
        "balance_sheet_million",
        "Bilanzsumme in Mio. EUR (leer = unbekannt)",
        &f.balance_sheet_million,
        "text",
        12,
    );
    fields += &textarea("size_reference", "Bezugsjahr/Stichtag, betrachteter Unternehmensverbund und Waehrungsumrechnung der Groessenangaben", &f.size_reference, 2000);
    fields += "<p>Finanzwerte beziehen sich auf Mio. EUR. Falls Ausgangswaehrung oder Umrechnung unklar ist, lassen Sie die Zahlen offen und notieren Sie die Grundlage. Es erfolgt keine automatische Schwellenwertpruefung.</p>";
    fields += &textarea(
        "critical_services",
        "Kritische Dienste / Leistungen",
        &f.critical_services,
        2000,
    );
    fields += &textarea(
        "supply_chain_role",
        "Lieferkettenrolle / verbundene Unternehmen und Groessenbezug",
        &f.supply_chain_role,
        2000,
    );
    fields += &tri_state(
        "develops_digital_products",
        "Produkte mit digitalen Elementen / Software",
        optional_bool(&f.develops_digital_products).ok().flatten(),
    );
    fields += &tri_state(
        "uses_ai_systems",
        "Nutzung oder Bereitstellung von KI-Systemen",
        optional_bool(&f.uses_ai_systems).ok().flatten(),
    );
    fields += &tri_state(
        "ot_iacs_scope",
        "OT-/IACS-/Industriekontext",
        optional_bool(&f.ot_iacs_scope).ok().flatten(),
    );
    fields += &tri_state(
        "automotive_scope",
        "Automotive-Kontext",
        optional_bool(&f.automotive_scope).ok().flatten(),
    );
    let form = if context.can_write() && draft.editable {
        form_token(state,headers).map(|token|format!(r#"<form method="post" action="{ROOT}{id}/"><input type="hidden" name="csrf_token" value="{}"><input type="hidden" name="revision" value="{}">{fields}<button type="submit">Entwurf speichern</button></form>"#,html_escape(&token),f.revision)).unwrap_or_else(||"<p>Zum Bearbeiten bitte mit einer ISCY-Session anmelden.</p>".to_owned())
    } else {
        format!("<p>Lesemodus: Dieser Entwurf kann hier nicht bearbeitet werden.</p><fieldset disabled><legend>Gespeichertes Unternehmensprofil</legend>{fields}</fieldset>")
    };
    let missing = [
        (p.company_name.is_empty(), "Unternehmen / Rechtseinheit"),
        (
            p.size_reference.is_empty(),
            "Bezugsgrundlage der Groessenangaben",
        ),
        (p.headquarters_country.is_empty(), "Hauptsitz"),
        (p.operation_countries.is_empty(), "operative Laender"),
        (p.sector.is_empty(), "konkrete Taetigkeit"),
        (p.employee_count.is_none(), "Mitarbeiterzahl"),
        (p.annual_revenue_million.is_none(), "Umsatz"),
        (p.balance_sheet_million.is_none(), "Bilanzsumme"),
    ]
    .iter()
    .filter(|(missing, _)| *missing)
    .map(|(_, label)| *label)
    .collect::<Vec<_>>();
    let notice = problem.map(|message| format!("<p role=\"alert\">{}</p><p>Ihre Eingaben wurden nicht gespeichert. <a href=\"{ROOT}{id}/\">Gespeicherten Entwurf neu laden</a></p>",html_escape(message))).unwrap_or_default();
    page(
        context,
        &format!(
            r#"<section class="hero compact"><h1>Unternehmensprofil · Entwurf {id}</h1><p>Gespeicherte Version {} · Schritt 1: Profil</p><a href="{ROOT}">Alle Unternehmensentwuerfe</a></section><section class="panel wide">{notice}<p role="status">Im gespeicherten Entwurf noch offene Basisangaben: {}. Leere Werte und „Noch unbekannt“ ergeben keine Nichtbetroffenheit.</p><p>Laenderangaben werden als Ihre Eingaben gespeichert. Rechtsraumzuordnung, Groessen-/Gruppenregeln und konkrete Pflichten sind noch fachlich zu pruefen. Das Organisations-Stammprofil und fruehere Ergebnisse werden nicht veraendert.</p>{form}</section>"#,
            draft.revision,
            if missing.is_empty() {
                "keine; fachliche Einordnung steht noch aus".to_owned()
            } else {
                missing.join(", ")
            }
        ),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileForm {
    csrf_token: String,
    revision: i64,
    company_name: String,
    headquarters_country: String,
    operation_countries: String,
    geographic_scope: String,
    sector: String,
    size_reference: String,
    employee_count: String,
    annual_revenue_million: String,
    balance_sheet_million: String,
    critical_services: String,
    supply_chain_role: String,
    develops_digital_products: String,
    uses_ai_systems: String,
    ot_iacs_scope: String,
    automotive_scope: String,
}
fn optional_bool(value: &str) -> anyhow::Result<Option<bool>> {
    match value {
        "" => Ok(None),
        "yes" => Ok(Some(true)),
        "no" => Ok(Some(false)),
        _ => Err(DraftError::Invalid(
            "Ungueltige Auswahl; bitte Ja, Nein oder Noch unbekannt waehlen.",
        )
        .into()),
    }
}
impl ProfileForm {
    fn from_draft(draft: &CompanyDraft) -> Self {
        let p = &draft.profile;
        let flag = |v: Option<bool>| {
            v.map(|b| if b { "yes" } else { "no" })
                .unwrap_or("")
                .to_owned()
        };
        Self {
            csrf_token: String::new(),
            revision: draft.revision,
            company_name: p.company_name.clone(),
            headquarters_country: p.headquarters_country.clone(),
            operation_countries: p.operation_countries.join("\n"),
            geographic_scope: p.geographic_scope.clone(),
            sector: p.sector.clone(),
            size_reference: p.size_reference.clone(),
            employee_count: p.employee_count.map(|v| v.to_string()).unwrap_or_default(),
            annual_revenue_million: p.annual_revenue_million.clone().unwrap_or_default(),
            balance_sheet_million: p.balance_sheet_million.clone().unwrap_or_default(),
            critical_services: p.critical_services.clone(),
            supply_chain_role: p.supply_chain_role.clone(),
            develops_digital_products: flag(p.develops_digital_products),
            uses_ai_systems: flag(p.uses_ai_systems),
            ot_iacs_scope: flag(p.ot_iacs_scope),
            automotive_scope: flag(p.automotive_scope),
        }
    }
    fn profile(&self) -> anyhow::Result<CompanyProfile> {
        Ok(CompanyProfile {
            company_name: self.company_name.clone(),
            headquarters_country: self.headquarters_country.clone(),
            operation_countries: self
                .operation_countries
                .split([',', '\n', '\r'])
                .map(str::to_owned)
                .collect(),
            geographic_scope: self.geographic_scope.clone(),
            sector: self.sector.clone(),
            size_reference: self.size_reference.clone(),
            employee_count: if self.employee_count.trim().is_empty() {
                None
            } else {
                Some(self.employee_count.trim().parse().map_err(|_| {
                    DraftError::Invalid("Mitarbeiterzahl muss eine ganze Zahl sein.")
                })?)
            },
            annual_revenue_million: Some(self.annual_revenue_million.clone()),
            balance_sheet_million: Some(self.balance_sheet_million.clone()),
            critical_services: self.critical_services.clone(),
            supply_chain_role: self.supply_chain_role.clone(),
            develops_digital_products: optional_bool(&self.develops_digital_products)?,
            uses_ai_systems: optional_bool(&self.uses_ai_systems)?,
            ot_iacs_scope: optional_bool(&self.ot_iacs_scope)?,
            automotive_scope: optional_bool(&self.automotive_scope)?,
        })
    }
}
async fn save(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Form(form): Form<ProfileForm>,
) -> Response {
    let (context, store) = match access(&state, &headers, true).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    if !valid_form_token(&state, &headers, &form.csrf_token) {
        return error(
            StatusCode::FORBIDDEN,
            "Gueltige ISCY-Session und Formular-Token erforderlich.",
        );
    }
    let mut draft = match store.company_draft(context.tenant_id, id).await {
        Ok(Some(draft)) => draft,
        Ok(None) => {
            return error(
                StatusCode::NOT_FOUND,
                "Unternehmensentwurf wurde nicht gefunden.",
            )
        }
        Err(e) => return store_error(e),
    };
    let input_error = |draft: &CompanyDraft, err: &DraftError| {
        let status = if matches!(err, DraftError::Conflict) {
            StatusCode::CONFLICT
        } else {
            StatusCode::BAD_REQUEST
        };
        (
            status,
            render_editor(
                &state,
                &headers,
                &context,
                draft,
                Some(&form),
                Some(&err.to_string()),
            ),
        )
            .into_response()
    };
    let profile = match form.profile() {
        Ok(p) => p,
        Err(e) => {
            return if let Some(err) = e.downcast_ref::<DraftError>() {
                input_error(&draft, err)
            } else {
                store_error(e)
            }
        }
    };
    match store
        .save_company_draft(
            context.tenant_id,
            context.user_id,
            id,
            form.revision,
            profile,
        )
        .await
    {
        Ok(true) => Redirect::to(&format!("{ROOT}{id}/")).into_response(),
        Ok(false) => error(
            StatusCode::NOT_FOUND,
            "Unternehmensentwurf wurde nicht gefunden.",
        ),
        Err(e) => {
            if let Some(err) = e.downcast_ref::<DraftError>() {
                if matches!(err, DraftError::Conflict) {
                    draft.editable = false;
                }
                input_error(&draft, err)
            } else {
                store_error(e)
            }
        }
    }
}
