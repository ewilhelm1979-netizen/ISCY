# AI Governance in ISCY

ISCY fuehrt AI-Systeme als tenantgebundene Governance-Objekte. Das Modul unter `/ai-governance/` verbindet Inventar, AI-Act-Einstufung, Human Oversight, Monitoring, Evidence und fachliche Betriebsobjekte. Es unterstuetzt Governance- und Review-Arbeit, ersetzt aber weder Rechtsberatung noch eine Konformitaetsbewertung oder Zertifizierung.

## Verknuepfte Objekte

Ein AI-System kann mit den kanonischen ISCY-Objekten fuer Risiken, Roadmap-Tasks, Incidents und Changes verbunden werden. Die Detailansicht zeigt:

- Risiko, Bewertung, Owner und Status
- Roadmap-Task, Status, Faelligkeit, Plan und Phase
- Incident, Severity und Status
- Change, Typ, Status und geplanter Zeitpunkt
- berechnete offene AI-Governance-Gaps
- die letzten Link- und Unlink-Auditereignisse

Risiken, Roadmap-Tasks und Incidents verwenden die bestehenden Plattformtabellen. Migration `0027_rust_ai_governance_links` ergaenzt ein kleines allgemeines `changes_change`-Register, weil vor diesem Block kein kanonisches Change-Objekt existierte. Es ist kein AI-spezifisches Parallelmodell und bildet noch keinen vollstaendigen Change-Management-Prozess ab.

Der Change-Kern ist bewusst auf Liste, Anlage und Detailansicht begrenzt. Er akzeptiert die Typen `STANDARD`, `NORMAL` und `EMERGENCY`, die Status `PLANNED`, `IN_REVIEW`, `APPROVED`, `IMPLEMENTED`, `FAILED`, `ROLLED_BACK` und `CANCELLED` sowie Datumswerte als `YYYY-MM-DD` oder RFC-3339-Zeitpunkt. Owner werden tenantgebunden validiert. Freigabegates, CAB-Workflow, Rollback-Ausfuehrung und Change-Kalender bleiben ausserhalb dieses Blocks.

## API

- `GET /api/v1/ai-governance/systems/{id}` liefert Anforderungen und aktuelle Verknuepfungen.
- `GET /api/v1/ai-governance/systems/{id}/link-candidates` liefert nur Ziele desselben Tenants, die noch nicht verknuepft sind.
- `POST /api/v1/ai-governance/systems/{id}/links/{type}/{object_id}` legt einen Link an.
- `DELETE /api/v1/ai-governance/systems/{id}/links/{type}/{object_id}` entfernt einen Link.
- `POST /api/v1/ai-governance/systems/{id}/gap-tasks` erzeugt nach ausdruecklicher Nutzeraktion einen Roadmap-Task.
- `GET` und `POST /api/v1/changes` lesen beziehungsweise erzeugen kanonische Changes.
- `GET /api/v1/changes/{id}` liest einen Change tenantgebunden.

Gueltige Linktypen sind `risk`, `roadmap-task`, `incident` und `change`.

## Gap-Tasks

Nur Anforderungen mit Status `GAP` koennen als Task erzeugt werden. Der Nutzer waehlt eine vorhandene Roadmap-Phase seines Tenants. ISCY dokumentiert den Ursprung in `notes` und verwendet den stabilen Schluessel `AI-GOV:{tenant_id}:{system_id}:{requirement_key}`. Ein eindeutiger Datenbankindex verhindert doppelte Tasks auch bei wiederholten oder parallelen Anfragen. Ein vorhandener Task wird wiederverwendet und mit dem AI-System verbunden.

## Security- und Tenant-Grenzen

- Lesen erfordert einen authentifizierten Tenant-Kontext.
- Anlegen, Entfernen und Task-Erzeugung erfordern eine schreibende Rolle.
- AI-System und Zielobjekt werden mit `tenant_id` bereits in der SQL-Abfrage eingeschraenkt.
- Fremde oder manipulierte IDs werden nicht verknuepft und liefern keine fremden Objektdaten.
- Eindeutige Linkindizes verhindern doppelte Beziehungen.
- Link beziehungsweise Unlink und zugehoeriger Audit-Eintrag werden atomar mit Actor, Objekttyp, Objekt-ID, Aktion und Zeitpunkt persistiert.

Die Rust-Schemata folgen beim Verzicht auf nachtraegliche Foreign Keys dem bestehenden ISCY-Datenbankstil. Neue Links koennen ausschliesslich nach tenantgebundener Existenzpruefung angelegt werden; ISCY bietet fuer die verknuepften Zielobjekte in diesem Stand keine loeschenden API-Routen an. Direkte, ausserhalb von ISCY ausgefuehrte Datenbankloeschungen sind kein unterstuetzter Integrationspfad und muessen betrieblich verhindert werden.

## Management Review und Export

Neue Management-Review-Pakete frieren fuer jedes AI-System Klasse, Kritikalitaet, Status, Review-Termin, Evidence-Zahl und die Anzahl verknuepfter Risiken, Roadmap-Tasks, Incidents und Changes ein. Webansicht sowie Markdown-, HTML-, PDF- und JSON-Export verwenden diesen Snapshot. Spaetere Linkaenderungen veraendern bereits erzeugte Pakete nicht.

Migration `0027_rust_ai_governance_links` ist additiv. Bereits migrierte Datenbanken ueberspringen sie anhand von `iscy_schema_migrations`; SQLite prueft die beiden neuen Spalten vor dem Anlegen, damit auch ein Wiederanlauf nach einer unvollstaendigen Strukturvorbereitung keine vorhandenen Daten oder Spalten ueberschreibt.
