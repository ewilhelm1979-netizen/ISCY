# ISCY V23.7.18 / Rust 0.3.14

ISCY ist eine ISMS-/Cybersecurity-Plattform mit ISO 27001-, NIS2- und KRITIS-Unterstuetzung, Incident-/Meldeworkflow, Product Security, Zero-Trust-Agent-Posture, lokalem CVE-Enrichment und lokalem LLM-Betrieb.

Der Runtime-Cutover nach Rust ist abgeschlossen: Die produktive Anwendung laeuft ueber den Rust-Axum-Service in `rust/iscy-backend`. Die fruehere Django/Python-Anwendung, ihre Templates, Settings, Requirements und Startpfade wurden aus dem Repository entfernt.

## Projekt- und Pruefhinweis

Dieses Projekt wurde mit Unterstuetzung von OpenAI Codex entwickelt, iterativ migriert und technisch/fachlich plausibilisiert. Die fachliche Pruefung orientiert sich an offiziellen Quellen und aktuellen Sicherheitspraktiken zu NIS2, DORA, Cyber Resilience Act, EU AI Act, DSGVO, ISO-27001-ISMS-Arbeit, CVE-/SBOM-/CSAF-Verarbeitung, Evidence-Steuerung, Incident Response und risikobasierter Roadmap-Planung.

Der Stand ist damit fachlich konsistent und nach aktuellem Architekturverstaendnis sinnvoll aufgebaut: ISCY trennt keine Regulierungen in Silos, sondern verbindet Controls, Risiken, Assets, Product Security, Incidents, Evidence und Roadmap-Arbeit in einem nachvollziehbaren Governance-Modell. Das ersetzt keine externe Zertifizierung, Rechtsberatung oder formale Auditfreigabe, schafft aber eine belastbare fachliche Arbeitsbasis.

Fachliche Referenzen:

- NIS2: [Richtlinie (EU) 2022/2555](https://eur-lex.europa.eu/eli/dir/2022/2555/oj), insbesondere Cybersecurity-Risikomanagement und Meldepflichten fuer erhebliche Sicherheitsvorfaelle
- NIS2-Erheblichkeitskriterien: [Durchfuehrungsverordnung (EU) 2024/2690](https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj), insbesondere Art. 3 als Best-Practice-Referenz fuer die Einstufung erheblicher Sicherheitsvorfaelle
- DORA: [Verordnung (EU) 2022/2554](https://eur-lex.europa.eu/eli/reg/2022/2554/oj), insbesondere IKT-Risikomanagement, Incident Management, Resilienztests und IKT-Drittparteienrisiko
- Cyber Resilience Act: [Verordnung (EU) 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj), insbesondere Product Security, Support-Zeitraeume, Vulnerability Handling und Security Updates
- EU AI Act: [Verordnung (EU) 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj), insbesondere Risk Management, Logging, Transparenz, Robustheit und Cybersecurity fuer Hochrisiko-KI

## ISCY lokal auf NixOS starten

```bash
./start.sh
```

Danach ist die Rust-Weboberflaeche unter `http://127.0.0.1:9000/login/` erreichbar.

Demo-Login:

```text
admin / Admin123!
```

Ohne Wrapper:

```bash
nix run .#iscy-backend -- init-demo
DATABASE_URL=sqlite:///db.sqlite3 RUST_BACKEND_BIND=127.0.0.1:9000 nix run .#iscy-backend
```

Healthcheck:

```bash
curl -fsS http://127.0.0.1:9000/health
```

Maschinenlesbarer Betriebsstatus:

```bash
curl -fsS http://127.0.0.1:9000/status/operations.json
curl -fsS http://127.0.0.1:9000/metrics
```

Alertmanager-Webhook fuer Betriebsalarme:

```bash
curl -fsS -X POST http://127.0.0.1:9000/api/v1/operations/alertmanager \
  -H 'content-type: application/json' \
  -d '{"receiver":"iscy-operations","status":"firing","alerts":[]}'
```

Ohne Tenant-/User-Kontext normalisiert der Webhook Alerts nur. Mit schreibendem Tenant-Kontext legt ISCY fuer firing Alerts automatisch Incident-Fallakten, verknuepfte Evidence und Timeline-Eintraege an. Wiederholte firing Alerts werden dedupliziert, resolved Alerts schliessen die passende offene Fallakte automatisch. Optional kann `ISCY_ALERTMANAGER_REQUIRE_RESOLUTION_REVIEW=1` gesetzt werden; dann markiert ISCY resolved Alert-Fallakten ohne Root Cause/Lessons Learned als Review-Pflicht. Das Monitoring-Beispiel sendet fuer lokale Demo-Stacks bereits `x-iscy-tenant-id: 1`, `x-iscy-user-id: 2` und `x-iscy-roles: CONTRIBUTOR`; User `2` ist der per Demo-Seed angelegte technische Operations-User `ops-alertmanager`.

Mit Tenant-Kontext liefert ISCY zusaetzlich fachliche Drilldowns fuer ISCY-27-Gaps, CVE-Review-Rueckstand, Evidence-Luecken, Migrationen, Runtime-Flags und Modulstatus:

```bash
curl -fsS -H 'x-iscy-tenant-id: 1' -H 'x-iscy-user-id: 1' \
  'http://127.0.0.1:9000/api/v1/status/operations?tenant_id=1&user_id=1'
curl -fsS -H 'x-iscy-tenant-id: 1' -H 'x-iscy-user-id: 1' \
  'http://127.0.0.1:9000/api/v1/status/metrics?tenant_id=1&user_id=1'
```

Prometheus-/Grafana-Betrieb: [docs/OPERATIONS_MONITORING.md](docs/OPERATIONS_MONITORING.md)

Monitoring-Artefakte fuer den direkten Betrieb:

- Prometheus Scrape Config: [deploy/monitoring/prometheus/iscy-scrape.yml](deploy/monitoring/prometheus/iscy-scrape.yml)
- Prometheus Alert Rules: [deploy/monitoring/prometheus/iscy-operations-alerts.yml](deploy/monitoring/prometheus/iscy-operations-alerts.yml)
- Alertmanager Routing-Beispiel: [deploy/monitoring/alertmanager/iscy-alertmanager.yml](deploy/monitoring/alertmanager/iscy-alertmanager.yml)
- Grafana Dashboard JSON: [deploy/monitoring/grafana/iscy-operations-dashboard.json](deploy/monitoring/grafana/iscy-operations-dashboard.json) inklusive Alert-Incidents mit konfigurierbarer `iscy_base_url`, konkretem Incident-Drilldown, Product-Security-Coverage, CVE-Review-Trend und Importvalidierung
- Monitoring Compose Stack: [deploy/monitoring/docker-compose.yml](deploy/monitoring/docker-compose.yml)
- NixOS Monitoring Modulbeispiel: [deploy/monitoring/nixos/iscy-monitoring.nix](deploy/monitoring/nixos/iscy-monitoring.nix)
- NixOS Beispielhost: [deploy/monitoring/nixos/example-host.nix](deploy/monitoring/nixos/example-host.nix)

Kurzpruefung fuer Betrieb und Regression:

```bash
nix develop --command make rust-smoke
nix develop --command make team-test
```

## Docker Compose

Development:

```bash
cp .env.development.example .env
make dev-up
```

App: `http://127.0.0.1:9000`

Stage:

```bash
cp .env.stage.example .env
make stage-up
```

App via Nginx: `http://127.0.0.1:8080`

Production:

```bash
cp .env.production.example .env
make prod-readiness
make prod-up
```

App via Nginx: `http://127.0.0.1`

## Rust Backend

Wichtige lokale Befehle:

```bash
make rust-build
make rust-test
make rust-smoke
make team-test
```

`make team-test` ist jetzt ein Rust-only Gate aus Rust-Tests und HTTP-Smoke.

Das Backend stellt serverseitige Weboberflaechen und APIs fuer die migrierten Produktbereiche bereit, unter anderem:

- `/dashboard/`
- `/navigator/`
- `/zero-trust/`
- `/catalog/`
- `/requirements/`
- `/assessments/`
- `/organizations/`
- `/risks/`
- `/incidents/`
- `/operations/incidents/`
- `/evidence/`
- `/reports/`
- `/roadmap/`
- `/assets/`
- `/imports/`
- `/processes/`
- `/product-security/`
- `/cves/`
- `/admin/users/`

Incidents werden als Rust-Fallakten unter `/incidents/` gefuehrt. Detailseiten unter `/incidents/{id}` erlauben die Bearbeitung von Typ, Runbook, Status, Severity, Erheblichkeitsentscheidung, Meldezeitpunkten und Behoerdenreferenz; Statuswechsel, NIS2-Erheblichkeitsbewertungen, Review-Anforderungen, Anlage, manuelle Timeline-Notizen und incidentbezogene Evidence-Uploads werden als Timeline-/Audit-Events in der Fallakte dokumentiert. Die Detailseite fuehrt den Entscheidungsfluss sichtbar von Vorfall ueber Erheblichkeit und Bearbeitung bis zum Meldepaket. ISCY trennt bewusst den Security Incident vom erheblichen Sicherheitsvorfall: Die Status `Nicht bewertet`, `Nicht erheblich`, `Wahrscheinlich erheblich` und `Erheblich / NIS2 meldepflichtig` koennen mit Kriterien, Begruendung, Referenz und Bewertungszeitpunkt dokumentiert werden. Wird ein Fall als `Nicht erheblich` entschieden, setzt ISCY die Fallakte automatisch in den Review-Status, bis die Nicht-Meldeentscheidung fachlich freigegeben ist. Die 24h-/72h-/30-Tage-Fristen werden erst aktiv, wenn die Bewertung auf `Erheblich / NIS2 meldepflichtig` steht. Das Dashboard zeigt Incidents ohne abgeschlossene Erheblichkeitsbewertung als klickbare Kachel und oeffnet direkt die gefilterte Incident-Liste. Tenantbezogene Runbook-Vorlagen stehen ueber `/api/v1/incidents/runbook-templates` und im Incident-Formular bereit. Verknuepfte Evidence wird direkt in der Fallakte angezeigt und kann dort hochgeladen werden. Alertmanager-firing Alerts werden per Fingerprint oder Alertname dedupliziert, resolved Alerts schliessen offene Alert-Fallakten automatisch, und `/operations/incidents/` zeigt offene, kritische, Triage- und resolved Alert-Faelle mit direkten Filtern (`alert_filter=open|critical|resolved`) sowie optionaler Review-Pflicht fuer fehlende Root-Cause-/Lessons-Learned-Dokumentation. Das NIS2-Meldepaket inklusive Erheblichkeitsentscheidung, regulatorischer NIS2/DORA/DSGVO-Entscheidungsmatrix und Audit-Timeline kann als Markdown, HTML oder PDF ueber `/incidents/{id}/nis2-export`, `/incidents/{id}/nis2-export.html`, `/incidents/{id}/nis2-export.pdf` sowie die entsprechenden `/api/v1/incidents/{id}/...` Endpunkte exportiert werden. Zusaetzlich stehen DORA-Pruefpakete ueber `/incidents/{id}/dora-export(.html|.pdf)` und DSGVO-Pruefpakete ueber `/incidents/{id}/dsgvo-export(.html|.pdf)` bereit.

Product Security wird unter `/product-security/` als Rust-Arbeitsbereich gefuehrt. CSAF-, CycloneDX- und SPDX-Importe werden historisiert, validiert und ueber Detailseiten mit Validierungsfehlern sowie Komponenten-Matches angezeigt. CVE-Asset-Korrelationen koennen vorgeschlagen, akzeptiert oder abgelehnt werden; akzeptierte Korrelationen erzeugen bei Bedarf Risiko- und Roadmap-Arbeit mit stabilem Evidence-Key. Das Dashboard zeigt offene CVE-Reviews und fehlende Evidence, buendelt automatisch erzeugte CVE-Risiken in einer Review-Queue, filtert nach offenen Reviews, fehlender Evidence oder fehlendem Risiko, bietet Bulk-Aktionen fuer ausgewaehlte CVE-Reviews und verlinkt Evidence-Uploads nach dem Speichern zur Ausgangsseite zurueck. Die Product-Security-Trends sind zusaetzlich ueber Prometheus-Metriken fuer Coverage, Importvalidierung, Trend-Signale und Snapshot-Verlauf verfuegbar.

Evidence-Links aus Risks, Roadmap, Incidents und Product Security fuellen Titel, Beschreibung, Linked Requirement, Status und Ruecksprungziel vor. Dadurch kann ein Nachweis direkt aus dem fachlichen Kontext erstellt werden und landet nach dem Upload wieder dort, wo die Arbeit begonnen hat.

## Strategische Weiterentwicklung

Die Rust-Migration ist abgeschlossen. Die naechste Produktagenda liegt in [docs/ISCY_STRATEGIC_ROADMAP.md](docs/ISCY_STRATEGIC_ROADMAP.md) und priorisiert:

1. Regulatorisches Organisationsprofil
2. Management-Review- und Audit-Paket
3. Evidence-Qualitaet und Nachweisreife
4. Third-Party- und Supplier-Risk
5. Product-Security-Reife mit VEX, SBOM-Diff und CRA-Readiness
6. AI-Governance-Modul
7. Agent-Flottenbetrieb und Benachrichtigungen

## Zero-Trust Agent

ISCY `0.3.14` enthaelt einen read-only Agent fuer Windows, macOS und Linux. Der Agent meldet Inventar, Heartbeats sowie OS-/MDM-/EDR- und Zero-Trust-Findings an die Rust-Plattform. Die Plattform stellt dazu `/zero-trust/` sowie API-Endpunkte unter `/api/v1/agents/...` bereit.

Die produktive Agent-Aufnahme ist gehaertet:

- Admins erstellen Enrollment-Token ueber `POST /api/v1/agents/enrollment-tokens`.
- Agenten enrollen mit `x-iscy-agent-enrollment-token` und erhalten einmalig ein Agent-Secret.
- Heartbeats und Findings koennen danach mit `x-iscy-agent-secret` gemeldet werden.
- Optional kann ein mTLS-Client-Zertifikat per Fingerprint an Token und Agent gebunden werden.

Die lokalen Collector-Module pruefen read-only:

- OS-Baseline und Patch-Inventar
- Datentraeger-Verschluesselung: BitLocker, FileVault oder LUKS
- Secure Boot beziehungsweise Plattformintegritaet
- Host-Firewall
- MDM-/Endpoint-Management-Signale
- Endpoint Protection beziehungsweise EDR-Signale

Die Webansicht `/zero-trust/` zeigt neben Score, Devices und Findings jetzt auch den naechsten fachlichen Fokus, Score-Badges und Severity-Badges fuer eine schnellere Priorisierung.

Lokaler Payload-Test:

```bash
nix run .#iscy-agent -- --self-test
```

Meldung an eine lokale Instanz:

```bash
ISCY_BACKEND_URL=http://127.0.0.1:9000 \
ISCY_TENANT_ID=1 \
ISCY_USER_ID=1 \
nix run .#iscy-agent
```

Token-basierter Agent-Lauf:

```bash
ISCY_BACKEND_URL=http://127.0.0.1:9000 \
ISCY_TENANT_ID=1 \
ISCY_AGENT_ENROLLMENT_TOKEN=<token> \
nix run .#iscy-agent
```

Windows-Build aus dem Rust-Code:

```powershell
cargo build --release --manifest-path rust/iscy-backend/Cargo.toml --bin iscy-agent
.\rust\iscy-backend\target\release\iscy-agent.exe --self-test
```

## Vulnerability Feeds

Rust-CLI:

```bash
RUST_BACKEND_URL=http://127.0.0.1:9000 cargo run --manifest-path rust/iscy-backend/Cargo.toml --bin iscy-canary -- import-collection --has-kev --max-pages 2
RUST_BACKEND_URL=http://127.0.0.1:9000 cargo run --manifest-path rust/iscy-backend/Cargo.toml --bin iscy-canary -- sync-recent --hours 24 --max-pages 2
RUST_BACKEND_URL=http://127.0.0.1:9000 cargo run --manifest-path rust/iscy-backend/Cargo.toml --bin iscy-canary -- import CVE-2026-1234
```

NVD-Konfiguration:

```text
NVD_API_BASE_URL=https://services.nvd.nist.gov
NVD_API_KEY=
```

Fuer lokale Tests und air-gapped Prueflaeufe kann `NVD_API_BASE_URL` auch auf eine einzelne NVD-JSON-Datei zeigen, zum Beispiel `file:///tmp/nvd-response.json`.

## CI

GitHub Actions prueft:

- Rust-Formatierung
- Clippy
- Rust-Backend-Tests
- Rust-DB-/HTTP-Smoke
- Nix-Rust-App-Smoke
- Compose-Konfigurationen fuer Development, Stage, Production und LLM-Profil

## Dokumentation

- Handbuch: `docs/ISCY_Handbuch.md`
- PDF-Handbuch reproduzierbar erzeugen: `make docs-pdf`
- Strategische Produktroadmap: `docs/ISCY_STRATEGIC_ROADMAP.md`
- GUI-Screenshots: `docs/GUI_SCREENSHOTS.md`
- Zero-Trust-Agent: `docs/ZERO_TRUST_AGENT.md`
- Proxmox-Produktiv-Runbook: `docs/PROXMOX_PRODUCTION_RUNBOOK.md`
- Rust-Cutover-Status: `docs/RUST_CUTOVER_STATUS.md`
- Rust-Abloese-Checkliste: `docs/RUST_ABLOESE_CHECKLISTE.md`
