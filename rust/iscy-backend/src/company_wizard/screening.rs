//! Bounded review signals from declared facts, never applicability decisions.
use super::CompanyProfile;
use crate::html_escape;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

pub(super) const VERSION: &str = "W2A-2026-11-03.1";
const CHECKED_ON: &str = "2026-11-03";

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ReviewState {
    PlanningChoice,
    ReviewHint,
    Open,
}
impl ReviewState {
    fn label(&self) -> &str {
        match self {
            Self::PlanningChoice => "ISMS-Pfad gewaehlt",
            Self::ReviewHint => "Vertiefte Pruefung angezeigt",
            Self::Open => "Fachlich offen",
        }
    }
    fn code(&self) -> &str {
        match self {
            Self::PlanningChoice => "PLANNING_CHOICE",
            Self::ReviewHint => "REVIEW_HINT",
            Self::Open => "OPEN",
        }
    }
}

struct Entry {
    id: &'static str,
    title: &'static str,
    source_version: &'static str,
    source_url: &'static str,
    criterion: &'static str,
    state: ReviewState,
    reason: &'static str,
    questions: &'static [&'static str],
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FrozenCriteria {
    pub version: String,
    checked_on: String,
    entries: Vec<FrozenEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FrozenEntry {
    id: String,
    title: String,
    source_version: String,
    source_url: String,
    criterion: String,
    state: ReviewState,
    state_label: String,
    reason: String,
    questions: Vec<String>,
}

pub(super) fn freeze(profile: &CompanyProfile) -> FrozenCriteria {
    FrozenCriteria {
        version: VERSION.into(),
        checked_on: CHECKED_ON.into(),
        entries: entries(profile)
            .into_iter()
            .map(|e| FrozenEntry {
                id: e.id.into(),
                title: e.title.into(),
                source_version: e.source_version.into(),
                source_url: e.source_url.into(),
                criterion: e.criterion.into(),
                state_label: e.state.label().into(),
                state: e.state,
                reason: e.reason.into(),
                questions: e.questions.iter().map(|q| (*q).into()).collect(),
            })
            .collect(),
    }
}

fn over_ten(value: &Option<String>) -> bool {
    value
        .as_deref()
        .and_then(|s| s.parse::<Decimal>().ok())
        .is_some_and(|n| n > Decimal::from(10))
}

fn entries(p: &CompanyProfile) -> [Entry; 3] {
    let iso_selected = matches!(p.assessment_goal.as_str(), "ISO_READINESS" | "ISMS");
    let employee_signal = p.employee_count.is_some_and(|n| n >= 50);
    let finance_signal = over_ten(&p.annual_revenue_million) && over_ten(&p.balance_sheet_million);
    [
        Entry {
            id: "ISO_ISMS_GOAL_V1",
            title: "ISO-/ISMS-Planung",
            source_version: "ISO/IEC 27001:2022, Amendment 1:2024; ISO-Produktinformation",
            source_url: "https://www.iso.org/standard/27001",
            criterion: "Nur das ausdruecklich gespeicherte Ziel ISO-Readiness oder ISMS waehlt diesen Planungspfad; Groesse und Auslandsaktivitaet sind keine Zugangshuerde.",
            state: if iso_selected { ReviewState::PlanningChoice } else { ReviewState::Open },
            reason: if iso_selected {
                "Das gespeicherte Ziel waehlt die ISMS-Planung. Dies belegt weder eine Zertifizierungspflicht noch Normerfuellung."
            } else {
                "Das gespeicherte Ziel waehlt noch keinen ISO-/ISMS-Planungspfad. Vertragliche, geschaeftliche oder risikobezogene Gruende bleiben gesondert zu klaeren."
            },
            questions: &[
                "Welche Einheit, Prozesse, Informationen und Abhaengigkeiten umfasst der ISMS-Scope?",
                "Welche Anforderungen und Risiken begruenden notwendige Controls und den spaeteren SoA-Entwurf?",
            ],
        },
        Entry {
            id: "DE_BSIG_SIZE_SIGNAL_V1",
            title: "Deutschland: BSIG-Groessenhinweis",
            source_version: "BSIG, § 28 Abs. 1 bis 8; konsolidierter Abrufstand",
            source_url: "https://www.gesetze-im-internet.de/bsig_2025/__28.html",
            criterion: "Deklarierte Mitarbeiterzahl ab 50 ODER Umsatz UND Bilanz jeweils ueber 10 Mio. EUR erzeugen ausschliesslich einen Groessenhinweis. Keine Verbundaggregation oder Einrichtungszuordnung.",
            state: if employee_signal || finance_signal { ReviewState::ReviewHint } else { ReviewState::Open },
            reason: if employee_signal {
                "Die deklarierte Mitarbeiterzahl erreicht den Hinweisschwellenwert. Deutschlandbezug und Einrichtungsart sind damit nicht festgestellt."
            } else if finance_signal {
                "Beide deklarierten Finanzwerte ueberschreiten den Hinweisschwellenwert. Bezugsgrundlage und Deutschlandbezug sind damit nicht bestaetigt."
            } else {
                "Die Rohangaben ergeben keinen Groessenhinweis oder sind unvollstaendig. Sonderfaelle und Verbunddaten koennen dennoch relevant sein; keine Nichtbetroffenheit ableiten."
            },
            questions: &[
                "Besteht fuer die betrachtete Einheit ein relevanter Deutschlandbezug, und welche konkrete Einrichtungsart bzw. Taetigkeit nach Anlagen 1/2 liegt vor?",
                "Welche Bezugsperiode, Partner-/Verbunddaten und Unabhaengigkeitsumstaende nach § 28 Abs. 4 sind zu pruefen?",
                "Greifen groessenunabhaengige Sonderfaelle, sektorale Regeln oder Ausnahmen nach § 28?",
            ],
        },
        Entry {
            id: "EU_CRA_PRODUCT_SIGNAL_V1",
            title: "EU: CRA-Produktkontext",
            source_version: "VO (EU) 2024/2847; Kommissionszusammenfassung zu Art. 2/3 und gestaffelter Anwendung",
            source_url: "https://digital-strategy.ec.europa.eu/en/policies/cra-summary",
            criterion: "Eine Ja-Angabe zu eigener Entwicklung digitaler Produkte/Software ist ein Anlass zur Produkt-/Rollenpruefung. Nein und unbekannt schliessen andere Wirtschaftsakteursrollen nicht aus.",
            state: if p.develops_digital_products == Some(true) { ReviewState::ReviewHint } else { ReviewState::Open },
            reason: match p.develops_digital_products {
                Some(true) => "Eigene digitale Produkte sind angegeben. Produkt, Marktbereitstellung und konkrete Rolle bleiben zu bestaetigen.",
                Some(false) => "Keine eigene Entwicklung angegeben. Einfuhr, Vertrieb oder andere relevante Rollen sind dadurch nicht ausgeschlossen.",
                None => "Der digitale Produktkontext ist noch unbekannt; eine negative Einordnung ist nicht moeglich.",
            },
            questions: &[
                "Welches Produkt, welche Vernetzung, EU-Marktbereitstellung und Wirtschaftsakteursrolle liegen konkret vor?",
                "Welche Produktausnahmen und zeitlich gestaffelten Vorschriften gelten fuer diesen Fall?",
            ],
        },
    ]
}

pub(super) fn render(profile: &CompanyProfile) -> String {
    render_frozen(&freeze(profile))
}

pub(super) fn render_frozen(frozen: &FrozenCriteria) -> String {
    let cards = frozen.entries.iter().map(|entry| {
        let questions = entry.questions.iter().map(|q| format!("<li>{}</li>", html_escape(q))).collect::<String>();
        let source = if reqwest::Url::parse(&entry.source_url).is_ok_and(|u| u.scheme() == "https" && u.host_str().is_some() && u.username().is_empty() && u.password().is_none()) {
            format!(r#"<a href="{}" rel="noreferrer">{}</a>"#, html_escape(&entry.source_url), html_escape(&entry.source_version))
        } else { html_escape(&entry.source_version) };
        format!(r#"<article data-screening-rule="{}" data-screening-status="{}"><h3>{}</h3><p><strong>{}</strong></p><p>Kriterium: {}</p><p>Begruendung aus den gespeicherten Angaben: {}</p><p>Quelle: {source} · Quellenabruf {}</p><ul>{questions}</ul></article>"#,
            html_escape(&entry.id), entry.state.code(), html_escape(&entry.title), html_escape(&entry.state_label),
            html_escape(&entry.criterion), html_escape(&entry.reason), html_escape(&frozen.checked_on))
    }).collect::<String>();
    format!(
        r#"<section class="panel wide"><h2>Versionierte Anforderungs-Pruefhinweise</h2><p>Kriterienversion {} · Quellenabruf {}. Ein Quellenabrufdatum ist kein gesetzliches Inkrafttretensdatum; spaetere Quellen- und Kriterienaenderungen brauchen eine neue Version.</p>{cards}<p>Dies ist eine begrenzte Pruefliste fuer ISO-/ISMS-Planung, einen deutschen BSIG-Groessenhinweis und CRA-Produktkontext. Weitere Regelwerke und Rechtsraeume sind fachlich offen. Laenderfreitext, Taetigkeit und Profilvollstaendigkeit bestaetigen keine Rechtsraumzuordnung oder Betroffenheit. Fachliche Pruefung, Begruendung und menschliche Bestaetigung sind weitere Schritte; es entstehen keine Rechtspflicht, Nichtbetroffenheitsentscheidung, SoA oder Massnahmen.</p></section>"#,
        html_escape(&frozen.version),
        html_escape(&frozen.checked_on)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_criteria_roundtrip_preserves_old_hints_and_escapes_stored_content() {
        let p = CompanyProfile {
            assessment_goal: "ISO_READINESS".into(),
            ..Default::default()
        };
        let frozen = freeze(&p);
        let raw = serde_json::to_string(&frozen).unwrap();
        let restored: FrozenCriteria = serde_json::from_str(&raw).unwrap();
        assert!(
            render_frozen(&frozen) == render_frozen(&restored),
            "Frozen criteria changed"
        );
        assert_ne!(render_frozen(&restored), render(&CompanyProfile::default()));
        let mut changed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        changed["entries"][0]["source_url"] = "javascript:alert(1)".into();
        changed["entries"][0]["title"] = "<script>fixture</script>".into();
        changed["version"] = "<img src=x onerror=fixture>".into();
        let changed: FrozenCriteria = serde_json::from_value(changed).unwrap();
        let html = render_frozen(&changed);
        assert!(!html.contains("href=\"javascript:") && !html.contains("<script>fixture</script>"));
        assert!(html.contains("&lt;script&gt;fixture&lt;/script&gt;") && html.contains("&lt;img"));
    }

    #[test]
    fn national_and_cross_border_iso_paths_need_no_size_or_second_country() {
        for goal in ["ISO_READINESS", "ISMS"] {
            for geography in ["", "NATIONAL", "CROSS_BORDER"] {
                let profile = CompanyProfile {
                    assessment_goal: goal.into(),
                    activity_context: geography.into(),
                    employee_count: Some(0),
                    ..Default::default()
                };
                assert_eq!(entries(&profile)[0].state, ReviewState::PlanningChoice);
            }
        }
        for goal in ["", "ORIENTATION"] {
            assert_eq!(
                entries(&CompanyProfile {
                    assessment_goal: goal.into(),
                    ..Default::default()
                })[0]
                    .state,
                ReviewState::Open
            );
        }
    }

    #[test]
    fn bsig_hint_observes_exact_employee_and_combined_financial_boundaries() {
        for (case, (employees, revenue, balance, expected)) in [
            (Some(49), Some("10.00"), Some("10.00"), false),
            (Some(50), None, None, true),
            (Some(0), Some("10.01"), Some("10.00"), false),
            (Some(0), Some("10.00"), Some("10.01"), false),
            (None, Some("10.01"), Some("10.01"), true),
            (None, Some("99.99"), None, false),
            (Some(0), Some("0"), Some("0"), false),
            (None, Some("invalid"), Some("99"), false),
        ]
        .into_iter()
        .enumerate()
        {
            let p = CompanyProfile {
                employee_count: employees,
                annual_revenue_million: revenue.map(str::to_owned),
                balance_sheet_million: balance.map(str::to_owned),
                ..Default::default()
            };
            assert_eq!(
                entries(&p)[1].state == ReviewState::ReviewHint,
                expected,
                "BSIG boundary case {case}"
            );
        }
    }

    #[test]
    fn no_and_unknown_product_answers_keep_distinct_reasons_and_never_exclude() {
        let texts = [None, Some(false), Some(true)].map(|answer| {
            let p = CompanyProfile {
                develops_digital_products: answer,
                ..Default::default()
            };
            let [_, _, entry] = entries(&p);
            assert_eq!(
                entry.state,
                if answer == Some(true) {
                    ReviewState::ReviewHint
                } else {
                    ReviewState::Open
                }
            );
            entry.reason
        });
        assert_ne!(texts[0], texts[1]);
        assert_ne!(texts[1], texts[2]);
    }

    #[test]
    fn country_and_sector_free_text_cannot_establish_jurisdiction_or_hide_open_rules() {
        let baseline = CompanyProfile::default();
        let forged = CompanyProfile {
            headquarters_country: "DE<script>unsafe</script>".into(),
            operation_countries: vec!["USA".into()],
            sector: "critical DNS provider".into(),
            ..Default::default()
        };
        assert_eq!(render(&baseline), render(&forged));
        for entry in entries(&forged) {
            assert_eq!(entry.state, ReviewState::Open);
            assert!(entry.source_url.starts_with("https://"));
            assert!(!entry.questions.is_empty());
        }
    }
}
