# ISCY Strategic Roadmap

Stand: 2026-06-27

Diese Roadmap beschreibt die fachlich sinnvollen naechsten Ausbaustufen nach dem Rust-only-Cutover. Sie ersetzt die alte Rust-Migrationsroadmap nicht, sondern beginnt danach: ISCY ist technisch auf Rust umgestellt und soll nun fachlich reifer, pruefbarer und im Betrieb wirksamer werden.

## Leitgedanke

ISCY soll keine Regulierungssilos bauen. Die Plattform soll Organisationen, Assets, Suppliers, Produkte, Controls, Risiken, Evidence, Incidents, Product Security, AI Governance, Agent-Posture und Roadmap-Arbeit so verbinden, dass neue regulatorische Anforderungen als Mapping und Entscheidungspfad aufgenommen werden koennen.

Die fachliche Ausrichtung orientiert sich an:

- NIS2 und der Einstufung erheblicher Sicherheitsvorfaelle
- DORA fuer IKT-Risikomanagement, IKT-Vorfaelle und IKT-Drittparteienrisiko
- DSGVO fuer Datenschutzverletzungen und Betroffenenrisiken
- Cyber Resilience Act fuer Product Security, Vulnerability Handling, Support und Security Updates
- EU AI Act fuer KI-Inventar, Klassifizierung, Logging, Transparenz, Human Oversight, Robustheit und Cybersecurity
- ISO 27001, TISAX, NIST CSF 2.0 sowie CSAF, CycloneDX und SPDX als praktische Struktur- und Nachweisreferenzen

## Prioritaet 1: Regulatorisches Organisationsprofil

Ziel: ISCY soll pro Tenant zentral verstehen, in welchem regulatorischen Kontext die Organisation arbeitet.

Status: In V23.7.19 als Rust-Web-/API-Pfad umgesetzt.

Umgesetzt:

- Organisationsprofil mit strukturierten Angaben zu Branche, Laendern, Groesse, kritischen Services, NIS2-Scope, KRITIS-Bezug, DORA-Finanzsektor- oder IKT-Drittparteienbezug, DSGVO-Rolle, CRA-Produktbezug, AI-Act-Relevanz, TISAX-Scope und ISO-27001-Zielbild.
- Schreibbare Weboberflaeche unter `/organizations/`.
- API-Pfad `GET` und `PATCH /api/v1/organizations/tenant-profile`.
- Regulatorische Matrix fuer aktive Pfade, Begruendung und naechsten fachlichen Schritt.
- Demo-Seed und Migration `0018_rust_tenant_regulatory_profile`.

Naechste Vertiefung:

- Incident-, Control-, Evidence- und Product-Security-Flows noch staerker aus diesem Profil vorsteuern.
- NIS2-/DORA-/DSGVO-Pruefpakete kontextsensitiv vorausfuellen, statt generische Hinweise zu erzeugen.
- Dashboard-Badges fuer regulatorische Betroffenheit anzeigen.

Erfolgskriterium:

- Ein Tenant kann auf einen Blick erkennen, welche regulatorischen Pfade aktiv sind und warum.

## Prioritaet 2: Management-Review- und Audit-Paket

Ziel: ISCY soll aus vorhandenen Daten automatisch ein Management-Review- und Audit-Paket erzeugen.

Status: In V23.7.20 als Rust-Web-/API-Pfad und persistierter Audit-Snapshot umgesetzt; V23.7.21 ergaenzt Exporte und Snapshot-Ruecklinks.

Umgesetzt:

- Weboberflaeche unter `/management-reviews/`.
- API-Pfade `GET` und `POST /api/v1/reports/management-reviews`.
- API-Pfade `GET` und `PATCH /api/v1/reports/management-reviews/{review_id}` fuer Detail und Status.
- Persistierte Review-Pakete mit Zeitraum, Status, Executive Summary, Entscheidung, naechsten Massnahmen, freigebendem User und Freigabezeitpunkt.
- Automatisch erzeugter Snapshot mit Kennzahlen, Top-Risiken, ISCY-27-Control-Gaps, Evidence-Luecken, Incident-Entscheidungen, Roadmap-Fokus, Product-Security-Lage und Agent-Posture.
- Direkte Ruecklinks aus Snapshot-Zeilen zu Risiken, Controls, Evidence, Incidents und Roadmap.
- Export als Markdown, HTML, PDF und JSON.
- Demo-Seed und Migration `0019_rust_management_review_packages`.

Naechste Vertiefung:

- Review-Templates fuer Quartal, internes Audit, Management Review nach ISO 27001 und regulatorische Steering-Sitzung.

Erfolgskriterium:

- Ein Management-Review kann direkt aus ISCY vorbereitet, geprueft und auditierbar abgelegt werden.

## Prioritaet 3: Evidence-Qualitaet und Nachweisreife

Ziel: Evidence soll nicht nur vorhanden sein, sondern belastbar bewertet werden.

Status: In V23.7.21 als Evidence-Quality-API und Webansicht umgesetzt; am 2026-06-27 um den persistierten Evidence-Lifecycle erweitert.

Umgesetzt:

- Weboberflaeche unter `/evidence/quality/`.
- API-Pfad `GET /api/v1/evidence/quality`.
- Evidence-Quality-Score je Evidence Item aus Status, Review, Datei-/Artefaktreferenz, Traceability, Owner und Review-Notiz.
- Issue-Queue fuer fehlende Datei, fehlenden Review, fehlenden Owner, fehlende Traceability oder fehlende Review-Notiz.
- Evidence-Need-Reife mit offen, teilweise und abgedeckt.
- Migration `0024_rust_evidence_lifecycle` fuer serverseitige Versionsketten, SHA-256, Gueltigkeit, Aufbewahrungsfrist/-begruendung und Schutzklasse.
- Automatische SHA-256-Bildung bei Datei-Uploads; der Hash wird nicht aus Client-Eingaben uebernommen.
- Tenantgebundene Versionskette ueber `supersedes_id`; pro Vorgaenger ist genau ein direkter Nachfolger zulaessig.
- Schutzklassen `PUBLIC`, `INTERNAL`, `CONFIDENTIAL` und `RESTRICTED`.
- Quality-Issues und Betriebszentrale fuer abgelaufene, bald ablaufende, ungehashte oder ohne Retention gefuehrte Evidence.
- Incident-/NIS2-/DORA-/DSGVO-Exporte weisen Version, Schutzklasse, Gueltigkeit und SHA-256 aus.

Naechste Vertiefung:

- Periodische Re-Hash-Pruefung gespeicherter Dateien und Quarantaene bei Integritaetsabweichung.
- Legal-Hold-, Freigabe- und dokumentierter Loesch-/Disposition-Workflow nach Ende der Retention.
- Optionales S3-/Objektspeicher-Backend inklusive Restore- und Integritaetsdrill.

Erfolgskriterium:

- ISCY unterscheidet zwischen "Nachweis existiert" und "Nachweis ist aktuell, vertrauenswuerdig und reviewt".

## Prioritaet 4: Third-Party- und Supplier-Risk

Ziel: Lieferanten, Cloud-, SaaS-, IKT- und Produktzulieferer sollen als eigener Risikobereich sichtbar werden.

Status: In V23.7.22 als Supplier-Risk-API und Webansicht umgesetzt.

Umgesetzt:

- Weboberflaeche unter `/suppliers/`.
- API-Pfade `GET /api/v1/suppliers` und `GET /api/v1/suppliers/{id}`.
- Supplier-Register mit Kritikalitaet, Services, Vertragsbezug, Security-Kontakt, Datenarten, Regionen, Exit-Abhaengigkeit, regulatorischem Scope, Review-Status, Review-Faelligkeit und Notes.
- Automatische Signale aus Produktkomponenten, offenen Product-Security-Schwachstellen, Supplier-bezogenen Risiken und Supplier-Evidence.
- DORA-IKT-Drittparteienbezug, NIS2-Supply-Chain-Bezug, CRA-Komponenten-/Herstellerbezug, DSGVO-Datenbezug und TISAX-Lieferkettennachweise werden als gemeinsame Flags sichtbar.
- Score- und Issue-Logik fuer kritische CVEs, ueberfaellige Reviews, fehlende Evidence, fehlenden Security-Kontakt, fehlende Exit-Strategie und fehlende Risikodokumentation.
- Evidence-Vorbefuellung mit stabilem Linked Requirement `SUPPLIER:{id}`.

Naechste Vertiefung:

- Supplier-Controls direkt mit ISCY-27 Control 15/16 und Evidence Needs verbinden.
- Supplier-Reviews als eigener Review-Workflow mit Freigabehistorie ausbauen.
- Vertragslaufzeiten, Unterauftragnehmer, Datenuebermittlungen und Exit-Tests granular versionieren.

Erfolgskriterium:

- ISCY kann zeigen, welche externen Abhaengigkeiten kritisch sind, welche Nachweise fehlen und welche Risiken daraus entstehen.

## Prioritaet 5: Product-Security-Reife (umgesetzt in V23.7.23)

Ziel: Der bestehende Product-Security-Bereich soll von Import/Korrelation zu einem echten PSIRT-/CRA-Arbeitsplatz wachsen.

Umgesetzt:

- VEX-Status je Schwachstelle aufnehmen: affected, not affected, fixed, under investigation.
- SBOM-Diff zwischen Importstaenden anzeigen.
- CRA-Readiness je Produkt aus SBOM, VEX/CVE-Triage, PSIRT/Advisories, Threat/TARA und Lifecycle ableiten.

Noch ausbaufähig:

- Security-Update- und Support-Ende je Produkt/Version pflegen.
- Supplier-Advisory- und Herstellerfeeds je Produkt verknuepfen.

Erfolgskriterium:

- ISCY kann fuer ein Produkt nachvollziehbar zeigen, welche Schwachstellen relevant sind, welche nicht, welche Releases betroffen sind und welche CRA-/PSIRT-Arbeit offen ist.

## Prioritaet 6: AI-Governance-Modul (umgesetzt in V23.7.24)

Ziel: KI-Systeme sollen als eigene Governance-Objekte in ISCY sichtbar werden.

Umgesetzt:

- Weboberflaeche unter `/ai-governance/`.
- API-Pfade `GET` und `POST /api/v1/ai-governance/systems`.
- API-Pfade `GET` und `PATCH /api/v1/ai-governance/systems/{id}`.
- KI-System-Inventar mit Zweck, Produktbezug, Owner, Datenarten, Modellquelle, Anbieter, Einsatzbereich, Kritikalitaet, Status und Review-Faelligkeit.
- AI-Act-Klassifizierung: nicht bewertet, verboten/nicht freigegeben, High Risk, Limited Risk, Minimal Risk oder nicht im Scope.
- Berechnete Governance-Anforderungen fuer Klassifizierung, Risikomanagement, Human Oversight, Logging, Transparenz, Cybersecurity/Robustheit sowie Monitoring/Evidence.
- Evidence-Vorbefuellung ueber stabile AI-Governance-Evidence-Keys.
- Rust-only-Betriebssignale fuer nicht bewertete AI-Systeme, faellige Reviews, fehlende Evidence und offene Governance-Gaps.

Naechste Vertiefung:

- Roadmap-Tasks automatisch aus AI-Governance-Gaps erzeugen.
- Risiko-Register direkt an AI-Systeme koppeln.
- AI-Incident-/Change-Verknuepfung fuer produktive AI-Systeme ausbauen.

Erfolgskriterium:

- ISCY kann KI-Systeme nicht nur inventarisieren, sondern ihre Governance-, Sicherheits- und Nachweislage steuerbar machen.

## Prioritaet 7: Agent-Flottenbetrieb und Benachrichtigungen

Ziel: Der Zero-Trust-Agent soll vom lokalen Collector zum betrieblich verwaltbaren Flottenbaustein wachsen.

Umsetzungsidee:

- systemd-Service, Windows-Service und macOS-LaunchAgent-Beispiele bereitstellen.
- Enrollment-Token und Agent-Secrets rotieren.
- Offline-Queue fuer Findings und Heartbeats ergaenzen.
- Agent-Policy-Profile pro Tenant oder Asset-Gruppe pflegen.
- Benachrichtigungen fuer ablaufende Evidence, offene CVE-Reviews, offene Nicht-Meldeentscheidungen, Agent-Posture-Abweichungen und Roadmap-Tasks einbauen.

Erfolgskriterium:

- Agenten koennen realistisch in mehreren Systemen betrieben werden, und wichtige ISCY-Signale gehen nicht im Dashboard unter.

## Empfohlene Umsetzungsreihenfolge

1. Agent-Flottenbetrieb und Benachrichtigungen fuer Skalierung und Alltagstauglichkeit.
2. Product-Security-Evidence-Pakete fuer Release-/PSIRT-Freigaben.
3. AI-Governance vertiefen: Risiken, Roadmap-Tasks, Incidents und Changes direkt an AI-Systeme koppeln.
4. Supplier-Reviews granularisieren: Freigabehistorie, Unterauftragnehmer, Exit-Tests und Vertragslaufzeiten.
5. Management-Review-Templates und kontextsensitive NIS2-/DORA-/DSGVO-Pruefpakete.
6. Evidence-Disposition, periodische Re-Hash-Pruefung und optionales Objektspeicher-Backend.

## Verbleibende Roadmap

| Horizont | Arbeitspaket | Ergebnis |
| --- | --- | --- |
| Jetzt | Agent-Flottenbetrieb, Secret-Rotation, Offline-Queue und Benachrichtigungen | Agenten sind auf mehreren Endpoints betrieblich verwaltbar und kritische Signale werden aktiv zugestellt. |
| Jetzt | Product-Security-Evidence-Pakete und Produkt-Lifecycle | Release-/PSIRT-Freigaben enthalten SBOM, VEX, Advisories, Support-Ende, offene Risiken und Evidence. |
| Danach | AI-Governance-Verknuepfungen | AI-Systeme sind direkt mit Risiken, Roadmap-Tasks, Incidents und Changes verbunden. |
| Danach | Supplier-Review-Workflow | Kritische Lieferanten erhalten Freigabehistorie, Unterauftragnehmer, Vertragsfristen und Exit-Test-Nachweise. |
| Danach | Management-/Regulatory-Templates | Wiederholbare Quartals-, Audit-, NIS2-, DORA- und DSGVO-Pakete werden kontextsensitiv erzeugt. |
| Reifegrad | Evidence-Disposition und Objektspeicher | Legal Hold, kontrollierte Loeschung, periodische Integritaetspruefung und Storage-Restore sind auditierbar. |
| Reifegrad | Performance, HA und visuelle Regression | Lastgrenzen, Mehrinstanzbetrieb und UI-Regressionen sind messbar abgesichert. |

## Abgrenzung

Diese Roadmap ist eine fachliche Produktagenda. Sie ist keine Rechtsberatung, keine Zertifizierung und kein Ersatz fuer eine formale Auditplanung. Sie beschreibt, welche Funktionen ISCY sinnvoll weiter abrunden, damit die Plattform als ISMS-, Product-Security-, Evidence-, Incident- und Governance-Werkzeug konsistent bleibt.
