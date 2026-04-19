# ISCY Full-Rewrite nach Rust – Team-Roadmap

## Ziel

ISCY schrittweise von Django/Python auf Rust ueberfuehren, ohne Fachfunktionalitaet zu verlieren.

## Vorgehen (Strangler Pattern)

### Phase 1 – Foundation (jetzt)

- Rust-Service `rust/iscy-backend` mit Health und erstem API-Endpunkt
- Build/Test in Team-Workflow integrieren
- API-Vertraege fuer Migration definieren

### Phase 2 – Parallelbetrieb

- NVD-Import/Sync als Rust-Worker migrieren
- Django ruft Rust-Service ueber HTTP/gRPC auf
- Ergebnisvergleich Python vs Rust (Canary)
- Bridge-Command vorhanden: `import_nvd_cves_via_rust` (Rust-Normalisierung + Python-NVD-Upsert)
- Canary-Command vorhanden: `import_nvd_cves_canary` (Paritaetsvergleich Python vs Rust, optional strict)
- Parity-Report vorhanden: `report_nvd_canary_parity` (JSON/CSV-Ausgabe)

### Phase 3 – Domänenmigration

- nacheinander: Vulnerability-Intelligence -> Guidance -> Reports
- jede Migration mit Feature-Parity-Check, Data-Mapping und Rollback-Pfad

### Phase 4 – Cutover

- Python-Endpunkte stilllegen
- Rust-Service als System of Record
- verbleibende Django-Teile entfernen

## Engineering-Gates pro Phase

1. Unit + Integration Tests gruen
2. API-Kontrakte stabil
3. Performance-Benchmark dokumentiert
4. Security-Review abgeschlossen
5. Rollback getestet

## Stand 2026-04-18

- Rust-Backend ist in CI mit Format, Clippy und Tests verdrahtet.
- NVD-CVE-Normalisierung, Collection/Recent-Import und Einzel-CVE-Upsert laufen ueber Rust.
- Rust schreibt CVERecord-Daten direkt in die bestehende Django-Tabelle `vulnerability_intelligence_cverecord`.
- Django bleibt aktuell noch Kompatibilitaets-/Web-Schicht und liest nach Rust-Upserts bestehende Models zurueck.
- Rust hat einen ersten Request-Kontext-Vertrag fuer Tenant/User-Header:
  - `GET /api/v1/context/whoami` fuer Diagnose/Bridge-Kontext
  - `GET /api/v1/context/tenant` als Muster fuer geschuetzte tenantgebundene Rust-Routen
- `organizations` hat den ersten echten App-Read-Slice in Rust:
  - `GET /api/v1/organizations/tenant-profile` liest das Tenant-Profil ueber den Rust-Tenant-Store
  - die Route ist durch `X-ISCY-User-ID` und `X-ISCY-Tenant-ID` geschuetzt
- `dashboard` bekommt den naechsten Read-Slice in Rust:
  - `GET /api/v1/dashboard/summary` liefert tenantgebundene Zaehler fuer Prozesse, Assets, offene Risiken, Evidenzen, offene Roadmap-Tasks und den neuesten Report
  - die Route nutzt denselben geschuetzten Tenant-Kontext wie die Organizations-API
  - Django kann die Dashboard-KPI-Zeile ueber `DASHBOARD_SUMMARY_BACKEND=rust_service` aus Rust lesen und faellt im Nicht-Strict-Modus auf lokale ORM-Zaehler zurueck
- `reports` hat erste tenantgeschuetzte Read-APIs in Rust:
  - `GET /api/v1/reports/snapshots` liefert die ReportSnapshot-Liste fuer den aktuellen Tenant
  - `GET /api/v1/reports/snapshots/{report_id}` liefert ReportSnapshot-Details inklusive Readiness-Prozenten und JSON-Auswertungen
  - Django kann die Report-Liste und die Report-Detailseite ueber `REPORT_SNAPSHOT_BACKEND=rust_service` aus Rust lesen und im Nicht-Strict-Modus auf lokale ORM-Reports zurueckfallen
- `assets_app` hat den naechsten tenantgeschuetzten Read-Slice in Rust:
  - `GET /api/v1/assets/information-assets` liefert das Asset-Register inklusive Business-Unit- und Owner-Anzeige fuer den aktuellen Tenant
  - Django kann die Asset-Liste ueber `ASSET_INVENTORY_BACKEND=rust_service` aus Rust lesen und im Nicht-Strict-Modus auf lokale ORM-Assets zurueckfallen
- `processes` hat tenantgeschuetzte Read-APIs in Rust:
  - `GET /api/v1/processes` liefert das Prozessregister inklusive Business-Unit-, Owner- und Status-Anzeige fuer den aktuellen Tenant
  - `GET /api/v1/processes/{process_id}` liefert die Prozessdetaildaten fuer die 10-Dimensionen-Ansicht
  - Django kann Prozessliste und Prozessdetail ueber `PROCESS_REGISTER_BACKEND=rust_service` aus Rust lesen und im Nicht-Strict-Modus auf lokale ORM-Prozesse zurueckfallen
- `risks` hat tenantgeschuetzte Read-APIs in Rust:
  - `GET /api/v1/risks` liefert das Risikoregister inklusive Kategorie, Prozess, Asset, Owner, Score und Risikolevel fuer den aktuellen Tenant
  - `GET /api/v1/risks/{risk_id}` liefert die Risikodetaildaten fuer Bewertung und Behandlung
  - Django kann Risikoliste und Risikodetail ueber `RISK_REGISTER_BACKEND=rust_service` aus Rust lesen und im Nicht-Strict-Modus auf lokale ORM-Risiken zurueckfallen
- `evidence` hat die erste tenantgeschuetzte Read-API in Rust:
  - `GET /api/v1/evidence` liefert Evidenzliste, Nachweispflichten und Coverage-Summary fuer den aktuellen Tenant
  - optional filtert `session_id` die Evidenzen und Nachweispflichten auf eine Assessment-Session
  - Django kann die Evidence-Liste ueber `EVIDENCE_REGISTER_BACKEND=rust_service` aus Rust lesen und im Nicht-Strict-Modus auf lokale ORM-Evidenzen zurueckfallen
- `assessments` hat erste tenantgeschuetzte Listen-APIs in Rust:
  - `GET /api/v1/assessments/applicability` liefert Betroffenheitsanalysen fuer den aktuellen Tenant
  - `GET /api/v1/assessments` liefert Prozess-/Requirement-Assessments inklusive Prozess-, Requirement- und Owner-Anzeige
  - `GET /api/v1/assessments/measures` liefert Massnahmen inklusive Assessment- und Owner-Anzeige
  - Django kann die drei Listen ueber `ASSESSMENT_REGISTER_BACKEND=rust_service` aus Rust lesen und im Nicht-Strict-Modus auf lokale ORM-Daten zurueckfallen
- `catalog` und `requirements_app` haben tenantkontext-geschuetzte Read-APIs in Rust:
  - `GET /api/v1/catalog/domains` liefert Domaenen inklusive eingebetteter Fragen und Gesamtzaehler
  - `GET /api/v1/requirements` liefert Requirements inklusive Mapping-Versionen und Primaerquellen
  - Django kann Fragenkatalog und Requirement Library ueber `CATALOG_BACKEND=rust_service` und `REQUIREMENTS_BACKEND=rust_service` aus Rust lesen und im Nicht-Strict-Modus auf lokale ORM-Daten zurueckfallen
- `roadmap` hat tenantgeschuetzte Read-/Update-APIs in Rust:
  - `GET /api/v1/roadmap/plans` liefert Roadmap-Planlisten inklusive Phasen-/Task-Zaehlern fuer den aktuellen Tenant
  - `GET /api/v1/roadmap/plans/{plan_id}` liefert den Plan-Detailbaum mit Phasen, Tasks und Abhaengigkeiten
  - `PATCH /api/v1/roadmap/tasks/{task_id}` aktualisiert Status, Termine, Owner-Rolle und Notizen tenantgeschuetzt
  - Django kann Liste, Detail, Kanban, Task-Updates sowie PDF/PNG-Exportdaten ueber `ROADMAP_REGISTER_BACKEND=rust_service` aus Rust bedienen und im Nicht-Strict-Modus auf lokale ORM-Daten zurueckfallen
- `wizard` hat tenantgeschuetzte Read-/Result-APIs in Rust:
  - `GET /api/v1/wizard/sessions` liefert die Assessment-Session-Historie fuer den aktuellen Tenant
  - `GET /api/v1/wizard/sessions/{session_id}/results` liefert Ergebnisdaten inklusive Domain-Scores, Gaps, Massnahmen, Evidenzzaehler, Report und Roadmap-Detailbaum
  - Django kann Wizard-Start und Ergebnisansicht ueber `WIZARD_RESULTS_BACKEND=rust_service` aus Rust lesen und im Nicht-Strict-Modus auf lokale ORM-Daten zurueckfallen
- `import_center` hat tenantgeschuetzte Importjob-Writes in Rust:
  - `POST /api/v1/import-center/jobs` legt gemappte Business-Units, Prozesse, Lieferanten und Assets an oder aktualisiert sie; optional ersetzt es vorhandene Eintraege dieses Typs
  - Django behaelt Datei-Upload, CSV/XLSX-Parsing und Mapping-Vorschau, uebergibt den bestaetigten Import aber ueber `IMPORT_CENTER_BACKEND=rust_service` an Rust
- `product_security` hat die erste tenantgeschuetzte Read-API in Rust:
  - `GET /api/v1/product-security/overview` liefert Product-Security-Matrix, Posture-Kennzahlen, Produktliste und letzte Snapshots fuer den aktuellen Tenant
  - Django kann die Product-Security-Liste ueber `PRODUCT_SECURITY_BACKEND=rust_service` aus Rust lesen und im Nicht-Strict-Modus auf lokale ORM-Daten zurueckfallen

## App-Migrationsreihenfolge

Die Apps werden nicht alle gleichzeitig ersetzt. Jede Zeile bekommt eigene Rust-Routen, Tests, Datenzugriff und danach erst Django-Cutover.

| Reihenfolge | Apps | Ziel in Rust | Warum diese Reihenfolge |
| --- | --- | --- | --- |
| 1 | `core`, `accounts`, `organizations` | Auth-/Tenant-Kontext, Berechtigungen, Tenant-Read-APIs | Ohne diese Basis waeren alle weiteren App-Endpunkte unsicher oder doppelt implementiert. |
| 2 | `vulnerability_intelligence`, `reports`, `dashboard` | Read-/Summary-APIs, CVE-Importe, Reporting | Bereits angefangen; hoher Nutzen, gut testbar, wenig Form-UI-Abhaengigkeit. |
| 3 | `guidance`, `requirements_app`, `catalog` | Regel-/Katalogdaten, Guided Journey Evaluation | Viel Fachlogik, aber vergleichsweise klare Datenmodelle. |
| 4 | `product_security`, `assets_app`, `processes`, `risks` | Tenant-gebundene CRUD-APIs und Bewertungslogik | Stark miteinander verknuepft; profitiert von fertiger Tenant-Schicht. |
| 5 | `assessments`, `evidence`, `roadmap`, `import_center`, `wizard` | Workflows, Writes, Importjobs, Evidence/Assessment-Flows | Hohe UI-/Form- und Workflow-Dichte; braucht stabile Rust-Basis. |
| 6 | Django-Web/Admin-Reste | Abschalten oder durch Rust-Web/Frontend ersetzen | Erst nach Funktionsparitaet sinnvoll. |

## Dauer grob

Diese Schaetzung gilt fuer einen kontrollierten Strangler-Umbau mit Tests und laufender CI:

- Rust-Core + Auth/Tenant/App-API-Basis: ca. 2-4 Arbeitstage
- Read-only APIs fuer Dashboard, Reports, CVE, Guidance: ca. 1-2 Wochen
- Schreibende APIs fuer Assets, Prozesse, Risiken, Assessments, Evidence: ca. 2-4 Wochen
- Weboberflaeche/Admin-Ersatz und finaler Django-Cutover: ca. 2-4 Wochen

Realistisch: Ein belastbarer Rust-Core kann schnell wachsen; die komplette Django-Abloesung aller Apps ist eher ein mehrwoechiges Projekt. Der sichere Weg ist: pro App ein Rust-API-Slice, Tests gruen, Django-Route umschalten, alten Python-Pfad entfernen.
