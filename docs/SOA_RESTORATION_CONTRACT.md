# SoA-Wiederherstellung: Schreibgrenze und offener Versionsablauf

## Umfang und Herkunft

Die fruehere Django-Anwendung enthielt eine echte SoA-Erzeugung, Detailansicht
und Control-Bearbeitung. Beleg: Elternstand
`417312ed3565558aa93637f078e1e185c2e4291e` des Rust-Cutovers
`b12db820ebac1c633873193eb7507ecc96d41319`, insbesondere
`apps/assessments/v20_views.py`, `soa_models.py` und `urls.py`.

Die Rust-Wiederherstellung verwendet weiterhin die historischen Tabellen
`assessments_soadocument` und `assessments_soaentry`. Die additive Migration
veraendert bestehende Dokumente und Eintraege nicht. Eine eigene Audit-Tabelle
erfasst neue Erzeugungs- und Bearbeitungsvorgaenge in derselben Transaktion.
Historische Freigabeereignisse werden dadurch nicht nachtraeglich erfunden.

Die Erzeugung uebernimmt aktive `ISO27001`-Requirements als anwendbare,
noch nicht umgesetzte Controls (`NOT_STARTED`) in einen `DRAFT`. Sie ist keine
automatische Konformitaetsentscheidung und kein impliziter Wizard-Abschluss.
Die drei Wizard-Modi werden als eigener Wiederherstellungsumfang behandelt.

## Verbindliche Eigentuemervorgabe

Am 15.10.2026 wurde ausdruecklich entschieden:

- `IN_REVIEW` und `APPROVED` duerfen nicht direkt veraendert werden.
- Eine spaetere Aenderung benoetigt einen neuen, eindeutig zugeordneten
  `DRAFT` und einen erneuten regulaeren Pruef-/Freigabeprozess.
- Die bisherige Version, ihre Auditdaten und ihre Freigabehistorie bleiben
  unveraendert erhalten.
- Falls die erforderliche Versionsarchitektur noch fehlt, zuerst die kleine
  sichere Schreibsperre umsetzen und die Erweiterung getrennt dokumentieren.

Diese begrenzte Umsetzung fuehrt deshalb KEINE automatische Rueckstufung,
Loeschung von Freigaben, privilegierte Schreibausnahme oder scheinbare
Nachfolgerversion ein.

## Gemeinsame Schreibgrenze

Nur der exakte gespeicherte Status `DRAFT` ist bearbeitbar. `IN_REVIEW`,
`APPROVED` und unbekannte oder abweichend kodierte Zustaende sind geschlossen.

Die verbindliche Kontrolle liegt in `AssessmentStore::update_soa_entry`:

- authentisierter Tenant und Actor aus dem Serverkontext, nicht aus Query/Form;
- Tenant-Bindung auch im SQL, einschliesslich Control-Owner;
- Statuspruefung innerhalb derselben Transaktion wie Aenderung und Audit;
- PostgreSQL-Sperre der Dokumentzeile bis zum Transaktionsende;
- SQLite-`BEGIN IMMEDIATE` vor der Statusabfrage, mit SQLx-Rollback bei Abbruch;
- abschliessender `DRAFT`-Praedikat am UPDATE-Sink;
- genau eine bestaetigte Aenderung und genau ein bestaetigtes Auditereignis;
- Rollback bei Fehlern und still unterdrueckten Schreiboperationen.

Bei einem eigenen, aber gesperrten Dokument ist die Antwort `409` mit
`soa_document_locked`. Fehlende Authentisierung, fehlende Schreibrolle und
fremde Objekte bleiben getrennte Fehler; fremde Dokumentstatus werden nicht
offengelegt. Ein zuvor gueltiges Webformular ist keine dauerhafte
Schreibberechtigung: der Submit prueft den aktuellen Zustand erneut.

## Erfasste Pfade

| Pfad | Verhalten |
|---|---|
| `GET/POST /api/v1/assessments/soa` | Tenantliste / neuer eigenstaendiger Erstentwurf |
| `GET /api/v1/assessments/soa/{id}` | Tenantgebundene Detailansicht |
| `PUT /api/v1/assessments/soa/entries/{id}` | Vollstaendiges Control-Formular, gemeinsame Schreibsperre |
| `/assessments/soa/` und `.../generate/` | Webliste / session- und CSRF-gebundene Erzeugung |
| `/assessments/soa/{id}/` | Webdetail, gesperrte Dokumente ohne Bearbeitungsaktion |
| `/assessments/soa/entry/{id}/edit/` | GET/POST nur fuer bearbeitbare Drafts; Submit revalidiert |
| Import-Center JSON/CSV/Web | Keine SoA-Importart; Alias-/Tabellennamen bleiben unzulaessig |

Das Import-Center akzeptiert weiterhin nur Business Units, Processes,
Suppliers und Assets. Es wird kein neuer SoA-Importer eingefuehrt. Auch
`replace_existing=true` darf eine nicht unterstuetzte Importart nicht in
einen Loesch- oder Schreibpfad umdeuten. Zukuenftige SoA-Importe muessen diese
Schreibgrenze erhalten und eine ausdrueckliche Versionsstrategie besitzen.

API-Schreibzugriffe benoetigen die vorhandenen serverseitigen Rollenregeln.
Webformulare benoetigen zusaetzlich eine gueltige ISCY-Session und einen daran
gebundenen CSRF-Token; produktive Identitaet kommt niemals aus URL-Parametern.
Privilegierte Rollen umgehen die Dokument-Schreibsperre nicht.

## Bewusst noch nicht implementierter Nachfolgeprozess

Im bisherigen Rust-Stand fehlen eine Vorgaengerbeziehung, ein unveraenderlicher
Versions-Snapshot und eine vollstaendige SoA-Pruef-/Freigabe-API. Ein freies
`version`-Textfeld sowie `status`, `approved_by_id` und `approved_at` ersetzen
diese Architektur nicht. Die bisherigen Auditzeilen enthalten keine alten
Control-Inhalte und erlauben deshalb keine Rekonstruktion ueberschriebener
Freigabestaende.

`POST /api/v1/assessments/soa` ist ausschliesslich ein neuer eigenstaendiger
Erstentwurf aus dem aktiven Katalog, KEIN Kopier-/Nachfolgeendpunkt. Es gibt
keine zulaessige Anweisung, damit ein gesperrtes Dokument zu ersetzen oder
eine Vorgaengerbeziehung zu behaupten. Unbekannte Eingabefelder fuer Tenant,
Status, Freigabe oder Vorgaenger werden abgelehnt. Die historische Vorgabe
`version='1.0'` ist keine implementierte Versionsnummernvergabe.

Eine gesonderte, vor Umsetzung zu pruefende Erweiterung muss mindestens:

1. die Vorgaengerversion unverwechselbar und tenantgebunden referenzieren;
2. alte freigegebene Inhalte, Quellenbezuege, Actor-/Zeitangaben und Audits
   unveraendert erhalten, auch bei Katalogaenderungen;
3. neue Entwuerfe ohne uebernommene Freigabe anlegen und nachvollziehbar
   durch einen autorisierten Pruef-/Freigabeprozess fuehren;
4. Nummerierung, parallele Entwuerfe, Ueberarbeitung und Ablehnung fachlich
   festlegen, statt diese Regeln beilaufig im Router zu erfinden;
5. SQLite/PostgreSQL, API/Web/Import, Nebenlaeufigkeit, Rechte, Tenant-Grenzen,
   Rollback und Altbestandsmigration mit Regressionen absichern.

Bis dahin ist die Aenderung eines gesperrten SoA-Dokuments bewusst nicht als
vollstaendig wiederhergestellter End-to-End-Versionsworkflow freigegeben.
Direkte Eingriffe eines Datenbankbetreibers und externe Katalogadministration
sind keine durch diese kleine Anwendungssperre abgesicherte Versionsarchitektur.
Ein vollstaendiger historischer Snapshot-Vertrag bleibt ein eigener Arbeitspunkt.
