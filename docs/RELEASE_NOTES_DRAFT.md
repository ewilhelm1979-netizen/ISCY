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
