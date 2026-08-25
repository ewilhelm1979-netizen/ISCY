# Machinery & CRA Safety-Security Co-Engineering – Phase 1

Status: `development_unreleased`, Phase 1. Diese Funktion unterstützt die
strukturierte technische Dokumentation. Sie ist keine Rechtsberatung, keine
Zertifizierung und keine automatische CE- oder Konformitätsentscheidung.

## Architektur und Sicherheitsinvariante

Safety und Cybersecurity bleiben getrennte Fachbewertungen. Ein Cyberereignis
wird nur über eine explizite, typisierte `safety_security_interaction` mit einer
Safety Function und einem Hazard verbunden:

```text
kanonische Cyber-Quelle → Security Consequence → Safety Function → Hazard
                       → Maßnahmen → vorhandene Evidence
```

Es gibt keine gemeinsame numerische Risk Engine und keine automatische
Normabdeckung. `CLOSED` beendet nur den Interaction-Workflow. Es bedeutet weder
„safe“ noch „compliant“. Erst ein strukturell vollständiger Stand ohne offene
fachliche Blocker erreicht die menschliche Bewertungsgrenze
`READY_FOR_HUMAN_REVIEW`; `human_assessment` bleibt in jedem Zustand
`REQUIRED`.

## Regulatorischer Referenzrahmen

- Die Maschinenverordnung (EU) 2023/1230 wird allgemein ab 20. Januar 2027
  angewendet. Das offizielle EUR-Lex-Korrigendum zu Artikel 54 Absatz 2
  berichtigt den ursprünglichen Termin:
  <https://eur-lex.europa.eu/eli/reg/2023/1230/corrigendum/2023-07-04/oj/eng>.
  Anhang III 1.1.9 adressiert den Schutz gegen Korrumpierung; 1.2.1 die
  Sicherheit und Zuverlässigkeit von Steuerungen. Verordnungstext:
  <https://eur-lex.europa.eu/eli/reg/2023/1230/oj/eng>
- Der Cyber Resilience Act (EU) 2024/2847 verlangt unter anderem eine
  Cybersecurity-Risikobewertung und technische Dokumentation. Die
  Meldepflichten nach Artikel 14 gelten ab 11. September 2026, die allgemeine
  Anwendung ab 11. Dezember 2027. Quelle:
  <https://eur-lex.europa.eu/legal-content/en/TXT/?uri=CELEX:32024R2847>

Applicability wird deshalb pro Product und Rechtsakt ausschließlich durch
Menschen als `NOT_ASSESSED`, `REVIEW_REQUIRED`, `IN_SCOPE` oder `OUT_OF_SCOPE`
mit Begründung und Revision dokumentiert. Organisationsdaten führen zu keiner
automatischen Produktentscheidung.

## Domainobjekte

- `product_regulatory_applicability`: produktbezogene CRA-/MVO-Einordnung.
- `machinery_product_profile`: Intended Purpose, foreseeable use/misuse,
  Umgebung, Lifecycle, menschliche Interaktion, Connectivity und
  Safety-Software-/Steuerungskontext.
- `product_safety_function`: bounded, tenantgebundene Funktionen mit stabiler
  Kennung, Owner, Status und Revision.
- `product_safety_hazard`: qualitative, methodenoffene Hazard-Dokumentation.
- `product_safety_assessment`: unveränderliche Assessment-Revisionen; eine
  neue Bewertung setzt die erwartete Hazard-Revision voraus.
- `safety_security_interaction`: genau eine durch Foreign Key oder
  serverseitige Ownership validierte Cyberquelle pro Datensatz.
- `product_regulatory_requirement`: produktbezogene Implementierungs- und
  Review-Metadaten, die auf den bestehenden Requirement-Katalog zeigen.
- `product_safety_standard_reference`: nur Identifier, Edition, Titel, Status,
  Scope, Quelle und Reviewzeitpunkt.
- `product_component_safety_context`: Safety-Metadaten zu einer bestehenden
  Product-Security-Komponente; SBOM-Inhalte werden nicht dupliziert.
- `product_safety_evidence_link`: Links auf vorhandene Evidence-Metadaten; kein
  zweiter Storage und keine Evidence-Bytes in Audit-Events.
- `product_safety_audit_event`: begrenzte transaktionale Domain-Auditspur.

Die Requirement-Referenzen
`EU-2023-1230-ANNEX-III-1.1.9` und
`EU-2023-1230-ANNEX-III-1.2.1` erweitern den bestehenden
`requirements_app_requirement`-Katalog. Produktstatus, Safety Functions,
Hazards, Controls und Evidence werden über schmale Relationen verknüpft.

## Standards und Crosswalk-Grenze

Phase 1 speichert ausschließlich Referenzmetadaten für EN ISO 12100 sowie IEC
62443-3-3, IEC 62443-4-1 und IEC 62443-4-2. Die Quellen sind die offiziellen
Katalogseiten von [ISO](https://www.iso.org/standard/51528.html) und
[IEC](https://webstore.iec.ch/en/publication/7033). Normtexte, Tabellen und
Anforderungen werden nicht kopiert. `prEN 50742` bleibt `DRAFT`; ISCY behauptet
weder Harmonisierung noch Konformitätsvermutung. Ein späterer Crosswalk darf
nur referenziell sein und keine Prozent- oder Compliance-Aussage berechnen.

## Tenant, RBAC, Audit und Concurrency

Jede Store-Abfrage bindet den authentifizierten Tenant. Product, Owner,
Safety Function, Hazard, Evidence und Cyberquelle werden serverseitig im
gleichen Tenant validiert; eine Tenant-ID im Request-Body wird nicht
akzeptiert. Rollen:

| Rolle | Lesen | Applicability/Safety | Interactions | Evidence/Review |
| --- | --- | --- | --- | --- |
| Admin/Staff/Superuser | ja | ja | ja | ja |
| `SECURITY_ADMIN` | ja | nein | ja | ja |
| `COMPLIANCE_MANAGER` | ja | ja | nein | ja |
| `SOC_ANALYST` | ja | nein | ja, aber kein finaler Status | nein |
| `AUDITOR` | ja | nein | nein | nur Metadaten lesen |

PostgreSQL verwendet Row Locks, Revisionen und Unique Constraints. SQLite
serialisiert Writes mit der bestehenden Store-Lockstrategie. Mutation und
Audit laufen in derselben Transaktion; ein Auditfehler rollt die Mutation
zurück. Evidence-Dubletten werden durch `(tenant_id, evidence_id, target_key)`
verhindert, auch wenn andere Zielspalten `NULL` sind.

## API und Readiness

Die API-Version bleibt `v1`. Der Einstieg ist
`GET /api/v1/product-conformity/products/{product_id}`. Unter den Pfaden
`product-conformity` und `product-safety` stehen Applicability,
Maschinenprofil, Requirements, Readiness, Safety Functions, Hazards,
Assessments, typisierte Interactions und Evidence-Link/Unlink zur Verfügung.
JSON-Payloads lehnen unbekannte Felder ab und begrenzen Freitext.

Die Readiness zeigt vorhandene und fehlende Daten, offene Hazards,
mitigation-required Interactions, Evidence-Gaps und offene Reviews. Die
Entscheidung ist deterministisch und fail-closed:

| Technical-Documentation-Status | Bedingung |
| --- | --- |
| `EVIDENCE_GAPS` | Applicability, Maschinenprofil, aktive Safety Function, Hazard, Requirement-Referenz oder Evidence fehlt; auch ein expliziter Requirement-Status `EVIDENCE_GAPS` blockiert. |
| `ASSESSMENT_IN_PROGRESS` | Die strukturellen Pflichtdaten und Evidence sind vorhanden, aber ein Hazard, eine Applicability-/Requirement-Review oder eine `MITIGATION_REQUIRED`-Interaction ist offen. |
| `READY_FOR_HUMAN_REVIEW` | Keine strukturelle Lücke und kein offener fachlicher Blocker; die menschliche Abschlussprüfung ist weiterhin erforderlich. |

`human_assessment` ist in allen drei Zuständen `REQUIRED`. Die GUI zeigt
`READY_FOR_HUMAN_REVIEW` bewusst als Warn-/Review-Badge und nicht als grüne
Endfreigabe. Die Readiness berechnet keine Compliance-Zahl und behauptet keine
Rechts-, CE-, Safety-, CRA-, MVO- oder Normkonformität. Die
Technical-Documentation-Preview verweist auf Product Description, Intended
Purpose, Rechtsakte, Cyber- und Safety-Kontext, SBOM/VEX/TARA, Supplier
Evidence, Controls und offene Reviews; ein eingefrorenes Technical
Documentation Package ist ausdrücklich nicht Teil dieser Phase.

## Threat Model und bewusste Grenzen

Abgedeckt sind Cross-Tenant-IDOR, fremde indirekte Referenzen, Mass Assignment,
RBAC-Eskalation, XSS-Ausgabe, bounded Input, stale revisions, lost updates,
Deduplizierung und Audit-Rollback. Typisierte Cyber-FKs vermeiden eine freie
polymorphe ID. Phase 1 eröffnet keine Netzwerk-, URL-Fetch- oder SSRF-Fläche.

Nicht enthalten sind automatische Rechtsprüfung, CE-Erklärung, Normabdeckung,
FMEA/HAZOP/FMEDA, SIL-/PL-Berechnung, Endpoint Monitoring, Patchen oder Active
Response.

## Zukünftige lokal-aegis-Grenze

Die spätere Anbindung der `lokal-aegis-platform` ist nur als explizite,
tenantgebundene Adapter-/API-Grenze vorgesehen. Dieser Stand enthält keine
Dependency, Runtime-, Netzwerk- oder Datenbankkopplung, keinen HTTP-/gRPC-
Client, kein LLM, kein RAG und keine Action. ISCY bleibt eigenständig. Spätere
Vorschläge müssten weiterhin authentifiziert, autorisiert, tenantgebunden,
auditierbar und gegebenenfalls menschlich freigegeben werden.
