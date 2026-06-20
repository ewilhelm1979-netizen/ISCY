# ISCY Strategic Roadmap

Stand: 2026-06-20

Diese Roadmap beschreibt die fachlich sinnvollen naechsten Ausbaustufen nach dem Rust-only-Cutover. Sie ersetzt die alte Rust-Migrationsroadmap nicht, sondern beginnt danach: ISCY ist technisch auf Rust umgestellt und soll nun fachlich reifer, pruefbarer und im Betrieb wirksamer werden.

## Leitgedanke

ISCY soll keine Regulierungssilos bauen. Die Plattform soll Organisationen, Assets, Produkte, Controls, Risiken, Evidence, Incidents, Product Security, Agent-Posture und Roadmap-Arbeit so verbinden, dass neue regulatorische Anforderungen als Mapping und Entscheidungspfad aufgenommen werden koennen.

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

Umsetzungsidee:

- Quartals- oder Stichtagsreport mit Top-Risiken, offenen ISCY-27-Gaps, Evidence-Luecken, offenen CVE-Reviews, Incident-Entscheidungen, Roadmap-Fortschritt, Agent-Posture und Product-Security-Lage.
- Export als Markdown, HTML, PDF und spaeter JSON.
- Review-Freigabe mit Verantwortlichem, Datum, Ergebnis und naechsten Massnahmen.
- Verlinkung zu Evidence, Controls, Risiken, Roadmap-Tasks und Incident-Fallakten.

Erfolgskriterium:

- Ein Management-Review kann direkt aus ISCY vorbereitet, geprueft und auditierbar abgelegt werden.

## Prioritaet 3: Evidence-Qualitaet und Nachweisreife

Ziel: Evidence soll nicht nur vorhanden sein, sondern belastbar bewertet werden.

Umsetzungsidee:

- Evidence um Gueltigkeit, Ablaufdatum, Nachweisquelle, Owner, Review-Status, Hash, Version, Sensitivitaet und Retention-Klasse erweitern.
- Evidence-Health je Control, Risiko, Incident, Product-Security-Finding und Roadmap-Task berechnen.
- Warnungen fuer ablaufende oder ungepruefte Nachweise anzeigen.
- Exportpakete sollen Evidence-Qualitaet und fehlende Nachweise explizit ausweisen.

Erfolgskriterium:

- ISCY unterscheidet zwischen "Nachweis existiert" und "Nachweis ist aktuell, vertrauenswuerdig und reviewt".

## Prioritaet 4: Third-Party- und Supplier-Risk

Ziel: Lieferanten, Cloud-, SaaS-, IKT- und Produktzulieferer sollen als eigener Risikobereich sichtbar werden.

Umsetzungsidee:

- Supplier-Register mit Kritikalitaet, Services, Vertragsbezug, Ansprechpartnern, Datenarten, Regionen, Exit-Abhaengigkeit und regulatorischem Bezug.
- Zuordnung zu Controls, Assets, Produkten, Prozessen, Risiken und Evidence.
- DORA-IKT-Drittparteienbezug, NIS2-Supply-Chain-Bezug, CRA-Komponenten-/Herstellerbezug und TISAX-Lieferkettennachweise abbilden.
- Supplier-Reviews, SLA-/Security-Anforderungen, Zertifikate, Attestierungen, SBOMs, CSAF-Feeds und Exit-Strategien hinterlegen.

Erfolgskriterium:

- ISCY kann zeigen, welche externen Abhaengigkeiten kritisch sind, welche Nachweise fehlen und welche Risiken daraus entstehen.

## Prioritaet 5: Product-Security-Reife

Ziel: Der bestehende Product-Security-Bereich soll von Import/Korrelation zu einem echten PSIRT-/CRA-Arbeitsplatz wachsen.

Umsetzungsidee:

- VEX-Status je Komponente und CVE aufnehmen: affected, not affected, fixed, under investigation.
- SBOM-Diff zwischen Produktversionen anzeigen.
- Security-Update- und Support-Ende je Produkt/Version pflegen.
- CRA-Readiness je Produkt aus CSAF, SBOM, CVE-Reviews, Evidence, Vulnerability Handling und Update-Prozess ableiten.
- Supplier-Advisory- und Herstellerfeeds je Produkt verknuepfen.

Erfolgskriterium:

- ISCY kann fuer ein Produkt nachvollziehbar zeigen, welche Schwachstellen relevant sind, welche nicht, welche Releases betroffen sind und welche CRA-/PSIRT-Arbeit offen ist.

## Prioritaet 6: AI-Governance-Modul

Ziel: KI-Systeme sollen als eigene Governance-Objekte in ISCY sichtbar werden.

Umsetzungsidee:

- KI-System-Inventar mit Zweck, Owner, Datenarten, Modellquelle, Anbieter, Einsatzbereich und Kritikalitaet.
- AI-Act-Klassifizierung: verboten, hochriskant, begrenztes Risiko, minimales Risiko oder nicht relevant.
- Anforderungen fuer Logging, Transparenz, Human Oversight, Robustheit, Security, Datenqualitaet und Monitoring verknuepfen.
- Risiken, Evidence, Incidents und Roadmap-Tasks direkt an KI-Systeme koppeln.

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

1. Management-Review-/Audit-Paket als sichtbarer Governance-Nutzen.
2. Evidence-Qualitaet, damit Reports und Audits belastbarer werden.
3. Third-Party-/Supplier-Risk, weil externe Abhaengigkeiten fuer NIS2, DORA, ISO 27001, CRA und TISAX zentral sind.
4. Product-Security-Reife mit VEX, SBOM-Diff und CRA-Readiness.
5. AI-Governance-Modul als aktueller, aber klar abgegrenzter Erweiterungsbereich.
6. Agent-Flottenbetrieb und Benachrichtigungen fuer Skalierung und Alltagstauglichkeit.

## Abgrenzung

Diese Roadmap ist eine fachliche Produktagenda. Sie ist keine Rechtsberatung, keine Zertifizierung und kein Ersatz fuer eine formale Auditplanung. Sie beschreibt, welche Funktionen ISCY sinnvoll weiter abrunden, damit die Plattform als ISMS-, Product-Security-, Evidence-, Incident- und Governance-Werkzeug konsistent bleibt.
