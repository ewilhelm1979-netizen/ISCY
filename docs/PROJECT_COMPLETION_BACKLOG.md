# ISCY – Projekt-Completion-Backlog (Production Readiness)

## Aktueller Produktstand

- Rust-only Runtime ist abgeschlossen.
- Das regulatorische Organisationsprofil ist als Tenant-Web-/API-Pfad umgesetzt und fuehrt NIS2, KRITIS, DORA, DSGVO, CRA, AI Act, TISAX und ISO-27001-Zielbild in einer zentralen Matrix zusammen.
- Product Security verarbeitet CSAF-/CycloneDX-/SPDX-Importe, CVE-Asset-Korrelationen, automatisch erzeugte CVE-Risiken und Product-Security-Roadmap-Tasks.
- Die Product-Security-Weboberflaeche zeigt offene CVE-Reviews, fehlende Evidence und eine gebuendelte CVE-Risiko-Review-Queue mit Filtern und Bulk-Aktionen.
- Evidence-Uploads koennen direkt aus fachlichen Kontexten gestartet werden und fuehren nach dem Speichern zur Ausgangsseite zurueck.
- Der Rust-only-Betrieb liefert Statusseite, JSON-Drilldown, Prometheus-Metriken, Alertmanager-Webhook mit optionaler Incident-/Evidence-Persistenz, Grafana-Dashboard inklusive Product-Security-Panels, Compose-Beispiel und NixOS-Modul samt Beispielhost.

## Prioritaet P0 (vor breitem Produktivrollout)

1. Secrets-Management statt Plain `.env`
2. TLS-Absicherung und HSTS
3. Logging-/Error-Pipeline und Alarm-Eskalation produktiv anbinden
4. Regelmaessige Backup- und Restore-Drills
5. Rollen-/Rechtekonzept und Admin-Hardening
6. Auditierbare Retention- und Exportregeln fuer Evidence-Dateien

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

1. Management-Review- und Audit-Paket
2. Evidence-Qualitaet und Nachweisreife
3. Third-Party- und Supplier-Risk
4. Product-Security-Reife mit VEX, SBOM-Diff und CRA-Readiness
5. AI-Governance-Modul
6. Agent-Flottenbetrieb und Benachrichtigungen
