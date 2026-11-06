//! Declared case facts only; no jurisdiction, applicability or approval decision.
use super::DraftError;
use serde::{Deserialize, Serialize};

pub(super) const CRA_ROLES: &[(&str, &str)] = &[
    ("MANUFACTURER", "Hersteller"),
    ("AUTHORIZED_REPRESENTATIVE", "Bevollmaechtigter"),
    ("IMPORTER", "Einfuehrer"),
    ("DISTRIBUTOR", "Haendler"),
    ("OPEN_SOURCE_STEWARD", "Open-Source-Software-Steward"),
    ("OTHER", "Andere / noch konkretisieren"),
];

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct RegulatoryContext {
    pub activity_scope: String,
    pub established_in_germany: Option<bool>,
    pub bsig_annex_1_activity: Option<bool>,
    pub bsig_annex_2_activity: Option<bool>,
    pub cra_eu_market: Option<bool>,
    pub cra_roles: Vec<String>,
    pub notes: String,
}

impl RegulatoryContext {
    pub(super) fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    pub(super) fn normalize(mut self) -> anyhow::Result<Self> {
        for (text, max) in [(&mut self.activity_scope, 255), (&mut self.notes, 2000)] {
            *text = text.replace("\r\n", "\n").trim().to_owned();
            if text.chars().count() > max
                || text
                    .chars()
                    .any(|c| c.is_control() && c != '\n' && c != '\t')
            {
                return Err(DraftError::Invalid(
                    "Einzelfallangabe ist zu lang oder enthaelt unzulaessige Steuerzeichen.",
                )
                .into());
            }
        }
        if self.cra_roles.len() > CRA_ROLES.len() {
            return Err(DraftError::Invalid("Zu viele CRA-Rollenangaben.").into());
        }
        let mut roles = Vec::new();
        for value in self.cra_roles {
            let value = value.trim().to_ascii_uppercase();
            if value.is_empty() {
                continue;
            }
            if !CRA_ROLES.iter().any(|(key, _)| *key == value) {
                return Err(DraftError::Invalid(
                    "Ungueltige CRA-Rollenangabe; bitte die angegebenen Rollencodes verwenden.",
                )
                .into());
            }
            if !roles.contains(&value) {
                roles.push(value);
            }
        }
        self.cra_roles = roles;
        Ok(self)
    }

    pub(super) fn facts(&self) -> Vec<(&'static str, String)> {
        let flag = |v: Option<bool>| {
            v.map(|b| if b { "Ja" } else { "Nein" }.to_owned())
                .unwrap_or_default()
        };
        vec![
            (
                "Einzelfall: betrachtete Dienste / Produkte",
                self.activity_scope.clone(),
            ),
            (
                "Niederlassung in Deutschland laut Angabe",
                flag(self.established_in_germany),
            ),
            (
                "Taetigkeit aus BSIG-Anlage 1 laut Angabe",
                flag(self.bsig_annex_1_activity),
            ),
            (
                "Taetigkeit aus BSIG-Anlage 2 laut Angabe",
                flag(self.bsig_annex_2_activity),
            ),
            (
                "Digitale Produkte fuer den EU-Markt laut Angabe",
                flag(self.cra_eu_market),
            ),
            (
                "CRA-Rollen laut Angabe",
                self.cra_roles
                    .iter()
                    .map(|value| {
                        CRA_ROLES
                            .iter()
                            .find(|(key, _)| *key == value)
                            .map(|(_, label)| *label)
                            .unwrap_or(value)
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
            (
                "Einzelfall: Grundlage und offene Fragen",
                self.notes.clone(),
            ),
        ]
    }
}
