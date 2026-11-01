# Internationaler Unternehmens- und Betroffenheits-Wizard

Stand dieser Bestandsaufnahme: Rust-main `a4382bff90cc7c8080a3b60d8f8c208f86b6bca0`.
Der urspruengliche Unternehmens-Wizard ist **nicht vollstaendig wiederhergestellt**.
Der Agenten-Wizard `/zero-trust/onboarding/` ist ein eigenstaendiger Ablauf.

## Belegte Ausgangsbasis

Die letzte Django-Basis vor dem vollstaendigen Rust-Cutover ist Commit
`417312ed3565558aa93637f078e1e185c2e4291e`. Dort liegen unter `apps/wizard/`
Modelle, Forms, Views und Services; `templates/wizard/` enthaelt Start,
Profil, Betroffenheit, Scope, Reifegrad und Ergebnisse. Quellen sind ueber
`git show <commit>:<pfad>` weiterhin pruefbar.

Der damalige Ablauf erfasste Assessment-Art, Sektor, operative Laender,
Mitarbeiterzahl, Umsatz/Bilanz, kritische Dienste, Lieferkettenrolle sowie
Produkt-/KI-/OT-/Automotive-Kontext. Die damalige Betroffenheitsindikation
und generierten Massnahmen sind historische Regeln, keine aktuelle
juristische Validierung oder automatische Konformitaetsentscheidung.

Aktuell bieten `/assessments/runs/`, `/assessments/runs/{id}/` und die
GET-APIs unter `/api/v1/wizard/sessions` vorhandene Durchlaeufe lesend an.
Ein neuer Durchlauf kann darueber nicht angelegt, schrittweise beantwortet,
fortgesetzt oder neu bewertet werden. Frische Rust-Datenbanken besitzen
nicht alle historischen Detailtabellen; die Leseseite kennzeichnet diese
Grenze. Bestehende Antworten/Ergebnisse muessen bei jeder Migration erhalten
bleiben. Die bestehende Onboarding-CTA zur Betroffenheitsanalyse belegt
keinen vorhandenen schreibenden Wizard.

## Naechste fachliche Meilensteine

| Meilenstein | Konkretes Abnahmeziel | Status |
| --- | --- | --- |
| W1 Profil und Fortsetzen | Mehrere operative Laender, Niederlassungen/Marktbezug und Sektor/Unternehmensdaten erfassen; tenantgebunden speichern, Entwurf fortsetzen, unvollstaendige Angaben sichtbar halten | offen |
| W2 Fachliche Betroffenheit | Je Rechtsraum/Regelwerk versionierte Kriterien und offizielle Quellen mit Gueltigkeitsdatum; Antworten, Begruendung und offene Prueffragen sichtbar; fehlende Daten ergeben keine pauschale Nichtbetroffenheit | offen |
| W3 Ergebnis und Umsetzung | Nachvollziehbare Indikation, menschliche Pruefung, priorisierte Massnahmen und explizite Report-/Roadmap-Uebernahme; historische Ergebnisse bleiben versioniert | offen |

Internationale Praesenz allein darf keine pauschale globale Betroffenheit
oder Nichtbetroffenheit ergeben. W2 muss Rechtsraum, konkrete Taetigkeit,
Groesse, Ausnahmen und relevante Markt-/Niederlassungsbeziehungen getrennt
beurteilen. Alte Schwellenwerte oder Laenderlisten werden nicht ungeprueft
uebernommen. Noch nicht unterstuetzte Jurisdiktionen erscheinen als
**fachlich offen**, nicht als negatives Ergebnis.

Zur Fertigabnahme gehoeren ausser den fachlich geprueften Referenzfaellen
Tests fuer fehlende Angaben/Grenzwerte, unberechtigte und fremde
Mandantenzugriffe, manipulierte IDs, CSRF, parallele Aenderungen,
Unterbrechung/Fortsetzung und Erhalt alter Daten auf SQLite/PostgreSQL.
Die Bedienabnahme fuehrt einen echten neuen Unternehmensdurchlauf vom
Profil bis zum begruendeten Ergebnis aus. Die bestehende lesende Abnahme
ersetzt das nicht.
