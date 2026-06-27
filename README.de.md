# ISCY

[English](README.md)

ISCY ist eine selbst gehostete Open-Source-Plattform für Cybersecurity Governance, ISMS, Product Security, AI Governance und regulatorische Nachweise.

Die Plattform verbindet Risiken, Controls, Assets, Incidents, Evidence, Lieferanten, SBOM, CSAF, VEX und CVE in einem gemeinsamen, auditierbaren Arbeitsmodell. Der produktive Kern ist in Rust mit Axum umgesetzt und unterstützt NixOS- sowie Docker-basierte Betriebsmodelle.

## Schwerpunkte

- ISO 27001, NIS2, DORA, CRA, EU AI Act, DSGVO und KRITIS
- Risiko-, Control-, Evidence- und Incident-Management
- Product Security, SBOM, VEX, CSAF und CVE
- Supplier Risk und Management Reviews
- AI Governance und Zero-Trust-Posture
- Auditierbare Exporte, Monitoring und Betriebsstatus

## Schnellstart

```bash
./start.sh
```

Die Weboberfläche ist anschließend unter `http://127.0.0.1:9000/login/` erreichbar.

Für Docker stehen getrennte Beispiele für Development, Stage und Production zur Verfügung. Vor einem Produktivbetrieb müssen die Hardening-, TLS-, Proxy- und Secret-Vorgaben geprüft werden.

## Sicherheit und Mitarbeit

Bitte vor Änderungen lesen:

- [AGENTS.md](AGENTS.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)

ISCY befindet sich in einer frühen Community-Adoptionsphase und wurde bisher nicht unabhängig zertifiziert oder pentestiert. Regulatorische Unterstützung ersetzt keine Rechtsberatung, Zertifizierung oder Auditfreigabe.

## Dokumentation

- [Handbuch](docs/ISCY_Handbuch.md)
- [Strategische Roadmap](docs/ISCY_STRATEGIC_ROADMAP.md)
- [GUI-Screenshots](docs/GUI_SCREENSHOTS.md)
- [Zero-Trust-Agent](docs/ZERO_TRUST_AGENT.md)
- [Operations Monitoring](docs/OPERATIONS_MONITORING.md)
- [Release Notes](docs/releases/)

## Lizenz

ISCY steht unter der GNU Affero General Public License v3.0 only (`AGPL-3.0-only`).
