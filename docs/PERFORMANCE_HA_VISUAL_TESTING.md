# Performance-, HA- und Visual-Regression-Tests

Stand: ISCY Unreleased / Rust 0.3.22

Diese Tests erkennen grobe Betriebs- und UI-Regressionen vor einem spaeteren
Release Candidate. Sie sind keine SLA-Zusage, kein Produktionslasttest und kein
Nachweis fuer beliebige Skalierbarkeit oder vollstaendige Hochverfuegbarkeit.

## Architekturmatrix

| Bereich | Zustand | Mehrinstanz-Grenze |
| --- | --- | --- |
| Rust/Axum HTTP-Routen | ueberwiegend stateless | Fachobjekte und Sessions liegen in der Datenbank; ein zufaelliger `instance_id` und Startup-Zeitpunkt sind prozesslokal. |
| Login-Rate-Limit | datenbankgebunden mit prozesslokalem Fallback | Mit Security-Store instanzuebergreifend; ohne Store nur Einzelprozess-Schutz. |
| Auth-Sessions | datenbankgebunden | PostgreSQL erlaubt Session-Nutzung ueber beide Testinstanzen. |
| PostgreSQL | datenbankgebunden | Im Test geteilter Datenbestand; PostgreSQL selbst ist nur eine Einzelinstanz und damit ein Single Point of Failure. |
| SQLite | datei- und prozessgebunden | Ausschliesslich Single-Instance; kein HA-Backend. |
| lokaler Evidence-Storage | host-/volumegebunden | Nicht als HA-faehig eingestuft. |
| S3-kompatibler Evidence-Storage | datenbank- und object-storage-gebunden | Cross-Read zwischen zwei Backends wird mit MinIO geprueft; MinIO selbst ist im Test eine Einzelinstanz. |
| Notification-Dispatch | periodischer Worker, DB-Claims | Atomare tenant-/kanalgebundene Claims verhindern doppelte Zustellung. Der HA-Test deaktiviert externe Zustellung; Parallelitaet bleibt durch Rust-/DB-Tests abgedeckt. |
| Evidence-Integrity-Worker | manueller, begrenzter Worker | Ein tenantgebundener DB-Claim mit begrenzter Lease verhindert parallele Laeufe. Es wird kein fiktiver Scheduler eingefuehrt. |
| Evidence-Disposition | manueller Freigabeprozess | Approval, Reason und Legal Hold bleiben Pflicht. S3-DELETE nutzt einen atomaren, lease-gebundenen Claim und idempotente Tombstone-Finalisierung. |
| Signal-/Policy-/Fleet-Auswertung | manuell und datenbankgebunden | Notification-Claims und stabile Signal-Keys verhindern doppelte Side Effects. |
| Migrationen | separates Admin-Kommando | PostgreSQL-Migrationen werden mit einem Advisory Lock maximal 60 Sekunden serialisiert; SQLite bleibt Single-Instance. |
| Operations-/Prometheus-Signale | Runtime plus DB-Aggregate | Keine Request-Payloads, User-Profile, Connection Strings oder Secrets. |
| nginx | Reverse Proxy | Zwei Backend-Upstreams werden getestet; nginx selbst bleibt eine Einzelinstanz. |
| GUI-Screenshots | Nix-/Playwright-Testpfad | 34 feste Baselines, zwei Viewports, keine automatische Aktualisierung in CI. |

## Systempruefungen

- `GET /health/live` beantwortet nur, ob der Prozess lebt. Ein kurzer DB-Ausfall
  macht den Prozess nicht kuenstlich tot.
- `GET /health/ready` prueft Annahmebereitschaft, DB-Erreichbarkeit und den
  vollstaendigen Migrationsstand. Fehler liefern HTTP 503 und nur sichere
  Fehlerklassen.
- `GET /health/startup` liefert den nicht sensitiven zufaelligen
  Prozess-Identifier und den Startzeitpunkt.
- SIGINT/SIGTERM schalten zuerst Readiness ab. Axum beendet neue Annahme und
  laesst laufende Requests begrenzt auslaufen. Der konfigurierbare Timeout
  `ISCY_SHUTDOWN_TIMEOUT_SECONDS` ist auf 5 bis 120 Sekunden begrenzt; Default
  sind 30 Sekunden. Der Notification-Worker beendet seinen aktuellen Zyklus
  und stoppt danach.

## Performance-Smoke

`make performance-smoke` startet eine wegwerfbare PostgreSQL-16-/MinIO-/
Zwei-Backend-Topologie und verwendet ausschliesslich Demo-/synthetische Daten.
Maximal vier Requests laufen parallel. Gemessen werden Health/Readiness,
typische Leseansichten, Regulatory-Preview, ein kleiner idempotenter
Roadmap-Write sowie S3-Upload, GET und Restore-/Hash-Pruefung.

Der Bericht unter `artifacts/performance/` enthaelt JSON und Markdown mit
Request-Anzahl, Testdauer, Durchsatz, Timeouts, DB-/Service-Unavailable-Antworten,
Erfolgen, Fehlern, p50, p95, p99, Maximum und Budgetstatus.
Maschinenspezifische Messwerte werden nicht in der Produktdatenbank gespeichert.

| Kategorie | p95-CI-Grenze |
| --- | ---: |
| Liveness/Readiness | 500 ms |
| typische Lesewege | 1.000 ms |
| Review-/Snapshot-Preview | 2.500 ms |
| kleine Schreiboperation | 2.000 ms |
| S3-Lifecycle je Operation | 2.500 ms |

Jede gueltige Anfrage muss ohne 5xx enden. Timeouts, HTTP-Fehler oder eine
Budgetueberschreitung machen den Test rot. Diese bewusst grosszuegigen Grenzen
sind CI-Regressionsbudgets und keine Produktions-SLOs.

## Zwei-Instanzen-Test

`make ha-integration` verwendet `tests/resilience/docker-compose.ha.yml`:

- PostgreSQL 16
- das bereits gepinnte MinIO und `mc`
- Backend A und B aus demselben hardened Image
- nginx 1.31 mit zwei Upstreams
- ausschliesslich Dummy-Credentials und Loopback-veroeffentlichte Testports

Der Test schreibt ueber A und liest ueber B, laedt Evidence ueber A in MinIO,
laedt und verifiziert sie ueber B, erzeugt Regulatory-Previews ueber beide
Instanzen und prueft Failover in beide Richtungen. Beide Backend-Stopps verwenden
SIGTERM und muessen mit Exitcode 0 enden. Danach wird die Daten- und
Object-Storage-Konsistenz erneut geprueft.

Ein zweites leeres PostgreSQL-Testschema startet zwei Migrationen nahezu
gleichzeitig. Der Advisory Lock muss exakt einen konsistenten Satz von 39
Migrationen hinterlassen; beide Aufrufe muessen erfolgreich enden.

Der Test belegt nur den geprueften Anwendungsbetrieb mit gemeinsamem PostgreSQL
und S3-kompatiblem Storage. Er belegt keine PostgreSQL-, MinIO- oder nginx-HA,
keine Multi-Region-Architektur und keine automatische horizontale Skalierung.

Der nginx-1.31-Pfad nutzt unveraendert die bestehenden Proxy-, Header- und
Timeout-Grenzen. Die wirksamen Stage-, Production- und HA-Konfigurationen
werden syntaktisch geprueft; Performance-Smoke und Zwei-Instanzen-Test decken
Proxy-Requests, Sessions, S3-Evidence und Failover ab. Die Messwerte bleiben
CI-Regressionsbudgets und sind keine Produktions-SLOs.

## PostgreSQL-18-Kompatibilitaet

Der PostgreSQL-16-HA- und Performancepfad bleibt unveraendert. Der zweite
Schritt im bestehenden CI-Job `ha-integration` fuehrt getrennt
`make postgresql-18-compatibility` aus. Er prueft PostgreSQL 18 nicht als
Cluster oder neuen Standard, sondern als frische Zielinstanz fuer einen
logischen PostgreSQL-16-zu-18-Forward-Restore.

Die Testtopologie liegt unter `tests/postgresql/` und verwendet fuer PG16 und
PG18 unterschiedliche Wegwerfvolumes sowie die versionsrichtigen Mountziele.
Sie prueft Fresh Bootstrap, Restart, alle 44 Migrationen, den Advisory Lock,
Health/Auth/Fachsmokes, Custom- und Betreiberbackup-Restore, dynamische
Tabellen-/Inhalts-/Sequenz-/Constraint-Vergleiche und Media-Integritaet.
Details und die Rollback-Grenze stehen in
`docs/POSTGRESQL_18_COMPATIBILITY.md`.

## Visuelle Regression

Playwright und Chromium stammen aus dem durch `flake.lock` gepinnten Nixpkgs-
Stand. Der aktuelle Testpfad verwendet Playwright 1.56.1 als reine
Entwicklungs-/CI-Abhaengigkeit; Produktivimage und Rust-Runtime enthalten kein
Browser-Tooling. Ausschliesslich fuer diese Testumgebung setzt eine erzeugte
Fontconfig `DejaVu Sans` aus demselben Nixpkgs-Stand als deterministische
Schrift; die produktive Schriftkonfiguration bleibt unveraendert.

`make visual-regression` prueft feste Demo-Daten, Sprache `de-DE`, Zeitzone
`Europe/Berlin`, deaktivierte Animationen und die Viewports 1440 x 1200 sowie
1024 x 900. Baselines liegen unter `tests/visual/baselines/`.

Erfasst werden Login, Dashboard/Betriebsuebersicht, Organisation, Management-
und Regulatory Reviews, Evidence Quality und Integrity, Object-Storage-Status,
Supplier Review, Supplier/Product Security, Product Security/PSIRT, AI
Governance, Zero Trust/Fleet, Agent-Provenance, PKI/CSR/mTLS, Cross-Domain
Notifications, Continuous Vulnerability Intelligence und Roadmap.

Die Pixel-Toleranz ist auf `threshold = 0.15` und maximal 0,3 Prozent
abweichende Pixel begrenzt. Zusaetzlich schlagen 500-Seiten, leere
Hauptcontainer, horizontaler Ueberlauf, abgeschnittene Tabellenueberschriften
und sichtbare Secrets/Object Keys fehl. CI aktualisiert Baselines nie.

Bewusste Aktualisierung nach menschlicher Sichtpruefung:

```bash
nix develop --command make visual-baselines
nix develop --command make visual-regression
```

Bei Abweichungen enthaelt das CI-Artefakt aktuelle Aufnahme, Baseline,
Diff-Bild, Trace und JSON-Report.

## CI und Grenzen

Die Jobs `performance-smoke`, `ha-integration` und `visual-regression` sind von
den bestehenden Rust-, Nix-, MinIO-, Compose-, Docker- und Supply-Chain-Checks
getrennt. Alle Jobs haben harte Zeitlimits und bereinigen ihre Wegwerfcontainer
und Testdaten.

Der Job `release-candidate-check` aggregiert die bestehenden Pflichtjobs. Er
fuehrt die teuren Topologien nicht erneut aus, sondern scheitert, sobald ein
benoetigter Job fehlschlaegt, abgebrochen oder uebersprungen wurde. Danach
validiert er nur die deterministischen RC-Metadaten, 44 Migrationen, 40
Baselines, Screenshot-Referenzen, Checksums und den Sensitive-Data-Scan.

Bekannte Grenzen:

- Die Stores verwenden derzeit modulbezogene SQLx-Pools. Die Smoke-Parallelitaet
  bleibt deshalb bewusst klein; Pool-Sharing ist ein spaeterer, separat zu
  messender Architekturumbau.
- PostgreSQL, MinIO und nginx sind in der Testtopologie jeweils Einzelinstanzen.
- Es gibt keinen produktiven Chaos-, Langzeit-, Multi-Region- oder
  Kapazitaetstest.
- CPU-/RSS-Werte werden wegen nicht vergleichbarer CI-Runner nicht als Budget
  verwendet.
- Testsignale sind technische Entscheidungshilfen, keine Rechtsberatung,
  Zertifizierung, Konformitaetsentscheidung oder SLA-Zusage.
