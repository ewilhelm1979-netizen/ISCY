# Unternehmens- und Betroffenheits-Wizard

Stand: W1-Wiederherstellung; fachliche Praezisierung vom 02.11.2026 auf Main `b18afb256219f27176ac654b084a82b978a7a3af`.
Der urspruengliche Unternehmens-Wizard ist **nicht vollstaendig wiederhergestellt**.
Der Agenten-Wizard `/zero-trust/onboarding/` ist ein eigenstaendiger Ablauf.

Fortschreibung 03.11.2026: Ziel und geografischer Kontext werden jetzt
ausdruecklich erfasst; eine revisionsbezogene lesende
[Kontextpruefung](COMPANY_CONTEXT_REVIEW.md) zeigt Fakten und offene Angaben.
Dies ist ein erster W2a-Faktenbaustein, keine Betroffenheitsregel oder SoA-Ableitung.

Die Kontextansicht ergaenzt jetzt drei [versionierte Pruefhinweise mit Quellen](COMPANY_REQUIREMENT_SCREENING.md).
Sie unterscheiden Planung, positive Hinweise und offene Sachverhalte;
fallbezogene Rechtsraum-/Rollenpruefung und bestaetigte Entscheidungen bleiben offen.

Der Wizard richtet sich an nationale Unternehmen und an solche mit
moeglichen oder bestaetigten grenzueberschreitenden Taetigkeiten. Ein
nationaler Fall braucht keinen zweiten Rechtsraum. Unbekannte Angaben
bleiben offen. Die fruehere Kurzbezeichnung „international“ war zu eng.

Eine SoA ist das Zielartefakt des ISO-orientierten Pfads. Sie benoetigt
zusaetzlich Scope, relevante Anforderungen, Risikobehandlung und
begruendete Controls. Der recherchierte Zielpfad samt Codebefunden und
W2a/W2b/W2c-Abnahmen steht in
[Unternehmenskontext bis zur SoA](COMPANY_CONTEXT_TO_SOA_RESEARCH.md).

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
bleiben. Der neue W1-Einstieg ist davon getrennt: `/assessments/company-wizard/`.

## Naechste fachliche Meilensteine

| Meilenstein | Konkretes Abnahmeziel | Status |
| --- | --- | --- |
| W1 Profil und Fortsetzen | Mehrere operative Laender, Niederlassungen/Marktbezug und Sektor/Unternehmensdaten erfassen; tenantgebunden speichern, Entwurf fortsetzen, unvollstaendige Angaben sichtbar halten | implementiert; Review/CI separat |
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


## W1 benutzen

Voraussetzung ist die regulär angewendete Migration 0048 ueber den
bestehenden Deployment-/Migrationsweg. Es findet keine automatische
Produktivaktivierung durch den Wizard statt.

1. Mit einer schreibberechtigten ISCY-Session unter **Assessments →
   Unternehmens-Wizard starten / fortsetzen** einen neuen Entwurf anlegen.
2. Die betrachtete Rechtseinheit, Hauptsitz, operative Laender, konkrete
   Taetigkeit und bekannten Groessenangaben erfassen. Bezugsjahr/Stichtag,
   Unternehmensverbund und gegebenenfalls Waehrungsumrechnung dokumentieren.
3. Produkt-, KI-, OT- und Automotive-Kontext jeweils mit Ja, Nein oder
   Noch unbekannt beantworten. Leere Zahlen bleiben unbekannt; explizite
   Nullwerte und Nein werden davon unterschieden.
4. **Entwurf speichern**. Die Liste zeigt maximal die letzten 50 Entwuerfe
   dieses Mandanten und fuehrt zur gespeicherten Fassung zurueck, auch nach
   Schliessen/Neuoefnen der Datenbank.

Laendernamen beziehungsweise Laendercodes werden in W1 als deklarierte
Angaben gespeichert. Es gibt noch keine automatische Rechtsraumzuordnung.
Finanzwerte sind Dezimaltexte in Mio. EUR mit maximal zwei Nachkommastellen;
W1 rechnet keine Waehrungen um und leitet keine gesetzlichen Schwellen ab.
Unbekannte Werte nicht schaetzen. Auch voll ausgefuellte Basisangaben
bedeuten weder eine abgeschlossene Bewertung noch Nichtbetroffenheit.

Neue Entwuerfe besitzen einen eigenen Snapshot, der das Organisations-
Stammprofil und fruehere Assessment-Ergebnisse nicht aendert. Migration
`0048_rust_company_wizard_profile` ergaenzt Speicher und Audit fuer SQLite
und PostgreSQL. Speichern verwendet einen Versionsvergleich und sperrt
abgeschlossene/fremde Schritte. Validierungsfehler zeigen die eingegebenen
Werte erneut; bei Versionskonflikten bleiben die eingereichten Werte lesbar,
und die aktuelle gespeicherte Fassung muss bewusst neu geladen werden.
Auditmetadaten (Akteur, Aktion, Version) werden atomar mitgeschrieben;
ein Auditfehler rollt die Aenderung zurueck. Es entsteht damit kein
vollstaendiges Archiv aller Zwischenfassungen eines Entwurfs.

Leser/Auditoren sehen die gespeicherten Angaben ohne Schreibformular.
Schreiben erfordert eine gueltige ISCY-Session, Schreibrolle und den
zweckgebundenen Formulartoken. Fremde Mandanten-/Akteur-IDs aus URL oder
Formular ersetzen den authentifizierten Kontext nicht.
W2/W3 bleiben offen; W1 erzeugt keine Bewertungen, Massnahmen, Reports,
Roadmap-Aufgaben oder automatische Governance-Entscheidungen.
