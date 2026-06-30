# ISCY – Projekt-Completion-Backlog (Production Readiness)

## Aktueller Produktstand

- Rust-only Runtime ist abgeschlossen.
- Das regulatorische Organisationsprofil ist als Tenant-Web-/API-Pfad umgesetzt und fuehrt NIS2, KRITIS, DORA, DSGVO, CRA, AI Act, TISAX und ISO-27001-Zielbild in einer zentralen Matrix zusammen.
- Product Security verarbeitet CSAF-/CycloneDX-/SPDX-Importe, CVE-Asset-Korrelationen, automatisch erzeugte CVE-Risiken, Product-Security-Roadmap-Tasks, VEX-Entscheidungen, SBOM-Diffs und CRA-Readiness je Produkt.
- AI Governance ist als eigenes Rust-Web-/API-Modul umgesetzt und fuehrt AI-Systeme mit AI-Act-Klasse, Kritikalitaet, Review-Faelligkeit, Monitoringplan, Risikosummary, Evidence-Key und berechneten Governance-Gaps.
- Die Product-Security-Weboberflaeche zeigt offene CVE-Reviews, fehlende Evidence, CRA-Readiness, SBOM-Diff-Einstiege und eine gebuendelte CVE-Risiko-Review-Queue mit Filtern und Bulk-Aktionen.
- Evidence-Uploads koennen direkt aus fachlichen Kontexten gestartet werden und fuehren nach dem Speichern zur Ausgangsseite zurueck; Evidence-Quality bewertet Nachweisreife, offene Issues und Evidence-Needs. Version, SHA-256, Gueltigkeit, Retention und Schutzklasse werden mit Migration `0024_rust_evidence_lifecycle` persistiert und in Incident-/Regulatory-Exporten ausgewiesen.
- Management-Review-Pakete koennen als Markdown, HTML, PDF und JSON exportiert werden und enthalten Ruecklinks zu Risiko, Control, Evidence, Incident und Roadmap.
- Third-Party-/Supplier-Risk ist als Rust-Web-/API-Modul umgesetzt und bewertet Lieferanten aus Kritikalitaet, Vertrags-/Security-Annex-Bezug, Datenarten, Regionen, Exit-Abhaengigkeit, regulatorischem Scope, Review-Faelligkeit, Evidence, Produktkomponenten, offenen Schwachstellen und dokumentierten Risiken.
- Agent Fleet Governance bewertet Sollbestand, Heartbeat-Freshness, Mindestscore und Finding-Grenzwerte je Tenant-, OS-, Asset-, Business-Unit- oder Deployment-Scope. Sichere Policy-Webhooks besitzen Cooldown, transiente Retries und Delivery-Audit.
- Product-Security-Evidence-Pakete frieren Release-/PSIRT-Nachweise versioniert ein, bewerten Readiness und Blocker, erzwingen dokumentierte Reviewentscheidungen und exportieren Markdown, HTML, PDF sowie JSON.
- Der Rust-only-Betrieb liefert Statusseite, JSON-Drilldown, Prometheus-Metriken, Alertmanager-Webhook mit optionaler Incident-/Evidence-Persistenz, AI-Governance-Signale, Grafana-Dashboard inklusive Product-Security-Panels, Compose-Beispiel und NixOS-Modul samt Beispielhost.

## Prioritaet P0 (vor breitem Produktivrollout)

1. Secrets-Management statt Plain `.env`
2. TLS-Absicherung und HSTS
3. Logging-/Error-Pipeline und Alarm-Eskalation produktiv anbinden
4. Regelmaessige Backup- und Restore-Drills
5. Rollen-/Rechtekonzept und Admin-Hardening
6. Legal-Hold- und dokumentierter Loesch-/Disposition-Workflow auf den vorhandenen Evidence-Retention-Metadaten

## Prioritaet P1 (direkt danach)

1. CI-Gates erweitern (team-test als Pflicht)
2. Security-Scans fuer Dependencies/Container
3. Betriebshandbuch + Incident-Runbooks
4. Performance-Baselines und Lasttests
5. Product-Security-Import-Schemaabdeckung mit offiziellen CSAF/SPDX/CycloneDX-Testkorpora erweitern

## Prioritaet P2 (Reifegrad / Skalierung)

1. UI-Designsystem modularisieren (CSS aus `base.html` extrahieren)
2. Visuelle Regressionstests
3. Dedizierte Review-Ansichten fuer groessere PSIRT-/Risk-Teams
4. Optional: Rust-Nebenservice fuer Performance-kritische Teilbereiche

## Strategische Produktagenda

Die technische Rust-Migration ist abgeschlossen. Die fachliche Weiterentwicklung wird in `docs/ISCY_STRATEGIC_ROADMAP.md` gefuehrt.

Die dort priorisierten naechsten Produktbereiche sind:

1. Zero-Trust-Agent-Onboarding als gefuehrten, sicheren Admin-Workflow vereinfachen
2. Notifications auf Evidence, CVE-Reviews, Incident-Entscheidungen und Roadmap erweitern
3. Supplier-Review-Workflow mit Freigabehistorie, Unterauftragnehmern und Exit-Tests
