# ISCY V23.7.34 - Development Notes

Status: Development / Unreleased.

Basis: `V23.7.33`.

Dieser Entwicklungsstand wurde noch nicht veroeffentlicht. Es gibt noch keinen
Tag und noch kein GitHub Release fuer V23.7.34. Aenderungen werden bis zur
Release-Vorbereitung unter Unreleased dokumentiert.

## Ausgangsbasis

- veroeffentlichter Stable Release: `V23.7.33`
- Release-ID: `371373238`
- Tagziel: `2820f19f5fa33069db81e05c10949f2558948d04`
- V23.7.33 ist Latest, nicht Draft und nicht Prerelease
- sechs Release-Assets wurden im Published-Snapshot `release/published/V23.7.33.json` gebunden

## Development-Grenze

V23.7.34 beginnt ohne uebernommenen Release-Candidate-Status. Teststatus und
Reproduzierbarkeitsstatus sind auf erneute Validierung zurueckgesetzt. Ein
Release-Bundle darf im Status `development_unreleased` nicht erzeugt werden.

## SoA-Rust-Wiederherstellung und Schreibschutz

- additive Migration `0047_rust_soa_cutover_restoration` fuer SQLite und PostgreSQL;
  bestehende SoA-Dokumente, Controls und Freigabeinformationen bleiben erhalten
- eigenstaendige Erstentwuerfe aus aktiven ISO27001-Requirements, tenantgebundene
  API-/Webansichten und transaktional auditierte Control-Bearbeitung
- nur exaktes `DRAFT` ist bearbeitbar; `IN_REVIEW`, `APPROVED` und unbekannte
  Zustaende sind auch bei veralteten Formularen und parallelen Schreibern gesperrt
- keine SoA-Importart und keine privilegierte Ausnahme; kein neuer Entwurf darf
  als implementierte Nachfolgeversion ausgegeben werden
- Vorgaengerzuordnung, historische Snapshots und der vollstaendige erneute
  SoA-Pruef-/Freigabeablauf bleiben gesonderte Arbeit gemaess
  `docs/SOA_RESTORATION_CONTRACT.md`; keine automatische Konformitaetsentscheidung

## JSON-Dependency-Wartung

- gezieltes Lockfile-Update von `serde_json 1.0.151` auf `1.0.154` ohne
  zusaetzliche transitive Pakete oder Cargo-Featureaenderungen
- aktive Features bleiben `std` und `raw_value`; ungueltiges UTF-8 wird
  weiterhin abgewiesen, seine gemeldete Fehlerposition wurde upstream korrigiert
- Handbuch, Migrationen und freigegebener SBOM-Snapshot bleiben unveraendert;
  Development-Manifest und Pruefsummen werden zum Lockfile abgeglichen

## TLS-Dependency-Sicherheitskorrektur

- minimale Lockfile-Updates auf `rustls-webpki 0.103.16` und
  `webpki-roots 1.0.10` fuer `RUSTSEC-2026-0382` und `RUSTSEC-2026-0381`
  (beide `CVE-2026-111943`): zurueckgezogene emSign-Zertifikatsketten werden
  im aktualisierten Verifier abgewiesen und der betroffene gebuendelte Root
  entfernt
- Reqwest-/SQLx-Versionen, Cargo-Features und die inaktive Quinn-/HTTP3-Kante
  unveraendert; keine neuen Security-Ausnahmen
- betrifft zertifikatsvalidierende TLS-Clients; deaktivierte Zertifikatspruefung
  oder unverschluesselte Verbindungen werden dadurch nicht abgesichert
- der minimale gepatchte Root-Stand uebernimmt auch die upstream entfernten
  `SecureSign Root CA12` und `Atos TrustedRoot 2011` sowie vier neue Roots;
  spezifische betriebliche Zertifikatsketten benoetigen eine gesonderte Pruefung

## Machinery & CRA Safety-Security Co-Engineering – Phase 1

- additive Migration `0046_rust_machinery_cra_safety_security_foundation` für
  SQLite und PostgreSQL; Bestandsprodukte bleiben unklassifiziert
- produktbezogene CRA-/MVO-Applicability, Maschinenprofil, Safety Functions,
  Hazards, versionierte Assessments und typisierte Safety/Security-Interactions
- Wiederverwendung bestehender Products, Components, Requirements, Controls,
  Cyber Risks, Product-Security-Quellen und Evidence
- tenantgebundene API v1, RBAC, transaktionales Audit, Revision-/Concurrency-
  Schutz, bounded Input und XSS-sichere Webansichten
- `Safety & Conformity` Overview und Product Detail mit vier neuen
  viewport-spezifischen Visual-Baselines
- allgemeiner Anwendungstermin der Maschinenverordnung (EU) 2023/1230 gemäß
  offiziellem EUR-Lex-Korrigendum zu Artikel 54: 20. Januar 2027
- deterministische, fail-closed Technical-Documentation-Readiness mit
  `EVIDENCE_GAPS`, `ASSESSMENT_IN_PROGRESS` und der nicht freigebenden Grenze
  `READY_FOR_HUMAN_REVIEW`; `human_assessment` bleibt immer `REQUIRED`

Dieser Development-Stand erzeugt keine Rechtsberatung, Zertifizierung,
CE-Freigabe, Safety-/Cybersecurity- oder Konformitätsentscheidung. Standards
werden nur als Referenzmetadaten geführt. Es wurde keine lokal-aegis-,
Netzwerk-, LLM-, RAG- oder Action-Kopplung eingeführt.
