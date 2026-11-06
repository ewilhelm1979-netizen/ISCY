//! Tenant-bound, append-only application snapshots; no approval or legal decision.
use super::*;
use axum::routing::post;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    schema_version: u8,
    profile_revision: i64,
    profile: CompanyProfile,
    criteria: screening::FrozenCriteria,
}

#[derive(Debug)]
pub struct SavedContextSnapshot {
    pub id: i64,
    pub profile_revision: i64,
    pub criteria_version: String,
    pub created_at: String,
    payload: Payload,
}

impl WizardStore {
    pub async fn freeze_company_context(
        &self,
        tenant_id: i64,
        actor_id: i64,
        session_id: i64,
        revision: i64,
        criteria_version: &str,
    ) -> anyhow::Result<Option<i64>> {
        if revision < 1 || criteria_version != screening::VERSION {
            return Err(DraftError::Conflict.into());
        }
        database!(self, pool, Db, {
            let postgres = matches!(self, WizardStore::Postgres(_));
            let mut tx = if postgres {
                pool.begin().await?
            } else {
                pool.begin_with("BEGIN IMMEDIATE").await?
            };
            let mut query = QueryBuilder::<Db>::new("SELECT s.status,s.current_step,p.revision,p.profile_json FROM wizard_assessmentsession s JOIN wizard_companyprofile p ON p.session_id=s.id AND p.tenant_id=s.tenant_id JOIN accounts_user u ON u.tenant_id=s.tenant_id WHERE s.tenant_id=");
            query
                .push_bind(tenant_id)
                .push(" AND s.id=")
                .push_bind(session_id)
                .push(" AND u.id=")
                .push_bind(actor_id)
                .push(" AND u.is_active");
            if postgres {
                query.push(" FOR UPDATE OF s,p");
            }
            let Some(row) = query.build().fetch_optional(&mut *tx).await? else {
                return Ok(None);
            };
            if !["DRAFT", "IN_PROGRESS"].contains(&row.try_get::<String, _>("status")?.as_str())
                || row.try_get::<String, _>("current_step")? != "profile"
                || row.try_get::<i64, _>("revision")? != revision
            {
                return Err(DraftError::Conflict.into());
            }
            // Serializes against profile saves and other snapshot requests on both databases.
            let existing =
                QueryBuilder::<Db>::new("SELECT id FROM wizard_contextsnapshot WHERE tenant_id=")
                    .push_bind(tenant_id)
                    .push(" AND session_id=")
                    .push_bind(session_id)
                    .push(" AND profile_revision=")
                    .push_bind(revision)
                    .push(" AND criteria_version=")
                    .push_bind(criteria_version)
                    .build_query_scalar::<i64>()
                    .fetch_optional(&mut *tx)
                    .await?;
            if let Some(id) = existing {
                tx.commit().await?;
                return Ok(Some(id));
            }
            let profile: CompanyProfile =
                serde_json::from_str(&row.try_get::<String, _>("profile_json")?)?;
            let criteria = screening::freeze(&profile);
            let payload = serde_json::to_string(&Payload {
                schema_version: 1,
                profile_revision: revision,
                profile,
                criteria,
            })?;
            if payload.len() > 65536 {
                return Err(DraftError::Invalid("Der Pruefstand ist zu gross.").into());
            }
            let id: i64 = QueryBuilder::<Db>::new("INSERT INTO wizard_contextsnapshot (tenant_id,session_id,actor_id,profile_revision,criteria_version,snapshot_json) VALUES (")
                .push_bind(tenant_id).push(",").push_bind(session_id).push(",").push_bind(actor_id)
                .push(",").push_bind(revision).push(",").push_bind(criteria_version).push(",").push_bind(payload)
                .push(") RETURNING id").build_query_scalar().fetch_one(&mut *tx).await?;
            QueryBuilder::<Db>::new("INSERT INTO wizard_contextsnapshotevent (tenant_id,snapshot_id,actor_id,action) VALUES (")
                .push_bind(tenant_id).push(",").push_bind(id).push(",").push_bind(actor_id)
                .push(",'CREATED')").build().execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(Some(id))
        })
    }

    pub async fn company_context_snapshots(
        &self,
        tenant_id: i64,
        session_id: i64,
    ) -> anyhow::Result<Vec<(i64, i64, String)>> {
        database!(self, pool, Db, {
            let rows = QueryBuilder::<Db>::new("SELECT id,profile_revision,criteria_version FROM wizard_contextsnapshot WHERE tenant_id=")
                .push_bind(tenant_id).push(" AND session_id=").push_bind(session_id)
                .push(" ORDER BY id DESC LIMIT 50").build().fetch_all(pool).await?;
            rows.into_iter()
                .map(|r| {
                    Ok((
                        r.try_get("id")?,
                        r.try_get("profile_revision")?,
                        r.try_get("criteria_version")?,
                    ))
                })
                .collect()
        })
    }

    pub async fn company_context_snapshot(
        &self,
        tenant_id: i64,
        session_id: i64,
        id: i64,
    ) -> anyhow::Result<Option<SavedContextSnapshot>> {
        database!(self, pool, Db, {
            let row = QueryBuilder::<Db>::new("SELECT c.id,c.profile_revision,c.criteria_version,c.created_at,c.snapshot_json FROM wizard_contextsnapshot c JOIN wizard_assessmentsession s ON s.id=c.session_id AND s.tenant_id=c.tenant_id WHERE c.tenant_id=")
                .push_bind(tenant_id).push(" AND c.session_id=").push_bind(session_id)
                .push(" AND c.id=").push_bind(id).build().fetch_optional(pool).await?;
            row.map(|r| {
                let raw: String = r.try_get("snapshot_json")?;
                anyhow::ensure!(raw.len() <= 65536, "Invalid context snapshot size");
                let payload: Payload = serde_json::from_str(&raw)?;
                let revision: i64 = r.try_get("profile_revision")?;
                let version: String = r.try_get("criteria_version")?;
                anyhow::ensure!(
                    payload.schema_version == 1
                        && payload.profile_revision == revision
                        && payload.criteria.version == version,
                    "Invalid context snapshot binding"
                );
                Ok(SavedContextSnapshot {
                    id: r.try_get("id")?,
                    profile_revision: revision,
                    criteria_version: version,
                    created_at: r.try_get("created_at")?,
                    payload,
                })
            })
            .transpose()
        })
    }
}

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/assessments/company-wizard/{id}/context/snapshots/",
            post(create),
        )
        .route(
            "/assessments/company-wizard/{id}/context/snapshots/{snapshot_id}/",
            get(view),
        )
}

pub(super) async fn controls(
    state: &AppState,
    headers: &HeaderMap,
    context: &AuthenticatedTenantContext,
    store: &WizardStore,
    draft: &CompanyDraft,
) -> anyhow::Result<String> {
    let form = if context.can_write() && draft.editable {
        form_token(state,headers).map(|csrf| format!(r#"<form method="post" action="{ROOT}{}/context/snapshots/"><input type="hidden" name="csrf_token" value="{}"><input type="hidden" name="revision" value="{}"><input type="hidden" name="criteria_version" value="{}"><button type="submit">Diesen Pruefstand dauerhaft speichern</button></form>"#,draft.id,html_escape(&csrf),draft.revision,screening::VERSION)).unwrap_or_default()
    } else {
        String::new()
    };
    let rows = store.company_context_snapshots(context.tenant_id,draft.id).await?.iter().map(|(id,rev,version)| format!(r#"<li><a href="{ROOT}{}/context/snapshots/{id}/">Pruefstand {id} · Profilrevision {rev}</a> · {}</li>"#,draft.id,html_escape(version))).collect::<String>();
    Ok(format!(
        r#"<section class="panel wide"><h2>Gespeicherte Pruefstaende</h2><p>Ein Pruefstand haelt die gespeicherten Angaben, Kriterien, Quellen und Hinweise fest. Speichern bestaetigt keine fachliche Pruefung, Rechtspflicht oder Freigabe. Nicht gespeicherte Formulareingaben sind nicht enthalten.</p>{form}<p>Die letzten 50 Pruefstaende:</p><ul>{rows}</ul></section>"#
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotForm {
    csrf_token: String,
    revision: i64,
    criteria_version: String,
}

async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Form(form): Form<SnapshotForm>,
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
        .freeze_company_context(
            context.tenant_id,
            context.user_id,
            id,
            form.revision,
            &form.criteria_version,
        )
        .await
    {
        Ok(Some(snapshot_id)) => {
            Redirect::to(&format!("{ROOT}{id}/context/snapshots/{snapshot_id}/")).into_response()
        }
        Ok(None) => error(
            StatusCode::NOT_FOUND,
            "Unternehmensentwurf wurde nicht gefunden.",
        ),
        Err(e) => store_error(e),
    }
}

async fn view(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, snapshot_id)): Path<(i64, i64)>,
) -> Response {
    let (context, store) = match access(&state, &headers, false).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let saved = match store
        .company_context_snapshot(context.tenant_id, id, snapshot_id)
        .await
    {
        Ok(Some(v)) => v,
        Ok(None) => return error(StatusCode::NOT_FOUND, "Pruefstand wurde nicht gefunden."),
        Err(e) => return store_error(e),
    };
    let (rows, _) = context_facts(&saved.payload.profile);
    let criteria = screening::render_frozen(&saved.payload.criteria);
    page(
        &context,
        &format!(
            r#"<section class="hero compact"><h1>Gespeicherter Unternehmens-Pruefstand {snapshot_id}</h1><p>Profilrevision {} · Kriterien {} · gespeichert {}</p><p>Festgehaltener Fakten- und Hinweisstand; keine fachliche Bestaetigung oder Freigabe. Spaetere Profil- und Kriterienaenderungen veraendern diesen Stand nicht.</p><a href="{ROOT}{id}/context/">Zum aktuellen Unternehmenskontext</a></section><section class="panel wide"><h2>Festgehaltene Kontextfakten</h2><table><thead><tr><th>Angabe</th><th>Wert</th><th>Erfassungsstand</th></tr></thead><tbody>{rows}</tbody></table></section>{criteria}"#,
            saved.profile_revision,
            html_escape(&saved.criteria_version),
            html_escape(&saved.created_at)
        ),
    )
}

pub(crate) const SQLITE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS wizard_contextsnapshot (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 tenant_id INTEGER NOT NULL REFERENCES organizations_tenant(id),
 session_id INTEGER NOT NULL,
 actor_id INTEGER NOT NULL REFERENCES accounts_user(id),
 profile_revision BIGINT NOT NULL CHECK(profile_revision>0),
 criteria_version TEXT NOT NULL CHECK(length(criteria_version) BETWEEN 1 AND 64),
 snapshot_json TEXT NOT NULL CHECK(length(snapshot_json)<=65536),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(id,tenant_id), UNIQUE(tenant_id,session_id,profile_revision,criteria_version),
 FOREIGN KEY(session_id,tenant_id) REFERENCES wizard_assessmentsession(id,tenant_id)
);
CREATE TABLE IF NOT EXISTS wizard_contextsnapshotevent (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 tenant_id INTEGER NOT NULL REFERENCES organizations_tenant(id),
 snapshot_id INTEGER NOT NULL,
 actor_id INTEGER NOT NULL REFERENCES accounts_user(id),
 action TEXT NOT NULL CHECK(action='CREATED'),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(snapshot_id,tenant_id) REFERENCES wizard_contextsnapshot(id,tenant_id)
);
CREATE INDEX IF NOT EXISTS idx_context_snapshot_tenant ON wizard_contextsnapshot(tenant_id,session_id,id);
CREATE INDEX IF NOT EXISTS idx_context_snapshot_event_tenant ON wizard_contextsnapshotevent(tenant_id,snapshot_id);
"#;
pub(crate) const POSTGRES_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS wizard_contextsnapshot (
 id BIGSERIAL PRIMARY KEY,
 tenant_id BIGINT NOT NULL REFERENCES organizations_tenant(id),
 session_id BIGINT NOT NULL,
 actor_id BIGINT NOT NULL REFERENCES accounts_user(id),
 profile_revision BIGINT NOT NULL CHECK(profile_revision>0),
 criteria_version TEXT NOT NULL CHECK(length(criteria_version) BETWEEN 1 AND 64),
 snapshot_json TEXT NOT NULL CHECK(length(snapshot_json)<=65536),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(id,tenant_id), UNIQUE(tenant_id,session_id,profile_revision,criteria_version),
 FOREIGN KEY(session_id,tenant_id) REFERENCES wizard_assessmentsession(id,tenant_id)
);
CREATE TABLE IF NOT EXISTS wizard_contextsnapshotevent (
 id BIGSERIAL PRIMARY KEY,
 tenant_id BIGINT NOT NULL REFERENCES organizations_tenant(id),
 snapshot_id BIGINT NOT NULL,
 actor_id BIGINT NOT NULL REFERENCES accounts_user(id),
 action TEXT NOT NULL CHECK(action='CREATED'),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(snapshot_id,tenant_id) REFERENCES wizard_contextsnapshot(id,tenant_id)
);
CREATE INDEX IF NOT EXISTS idx_context_snapshot_tenant ON wizard_contextsnapshot(tenant_id,session_id,id);
CREATE INDEX IF NOT EXISTS idx_context_snapshot_event_tenant ON wizard_contextsnapshotevent(tenant_id,snapshot_id);
"#;
