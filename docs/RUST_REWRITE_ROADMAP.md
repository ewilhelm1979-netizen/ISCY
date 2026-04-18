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
