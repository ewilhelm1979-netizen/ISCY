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

## Unternehmens-Wizard: Ziel und Kontextpruefung

- validierte optionale Profilangaben fuer Orientierung/ISO-Readiness/ISMS
  und noch unbekannte/nationale/grenzueberschreitende Taetigkeit
- neue lesende tenantgebundene Kontextpruefung an der gespeicherten Revision;
  offene Angaben, 0 und Nein bleiben unterscheidbar
- vorhandene Profil-CAS-/CSRF-/Auditgrenzen erhalten; keine Migration oder
  neue Rechtsentscheidung; aeltere JSON-Profile lesbar, Downgradegrenze dokumentiert
- Bedienung und Grenzen in `docs/COMPANY_CONTEXT_REVIEW.md`

## Unternehmens-Wizard: dauerhaft gespeicherte Pruefstaende

- additive Migration 0050 fuer SQLite/PostgreSQL speichert Profilrevision,
  damalige Kriterien und Quellen samt atomarem Anlageaudit
- ausdrueckliche Anlage mit Session/Schreibrolle/CSRF und Revisions-/
  Kriterienabgleich; doppelte Anfragen erzeugen denselben Stand
- historische tenantgebundene Ansicht berechnet alte Hinweise nicht neu;
  keine fachliche Bestaetigung, Freigabe, SoA oder Massnahme
- Bedienung und Grenzen in `docs/COMPANY_CONTEXT_SNAPSHOTS.md`

## Unternehmens-Wizard: versionierte Anforderungs-Pruefhinweise

- drei begrenzte Kriterien fuer ISO-/ISMS-Planung, deutschen BSIG-Groessenhinweis
  und CRA-Produktkontext an der aktuell gespeicherten Profilrevision
- Quellenabruf, Kriterienversion, Begruendung und offene Prueffragen sichtbar;
  Nein, kleine und unbekannte Angaben erzeugen keine Nichtbetroffenheit
- lesend in bestehender Kontextansicht, keine Migration, neue Profilfelder,
  historische Entscheidung oder automatische SoA; Details in
  `docs/COMPANY_REQUIREMENT_SCREENING.md`

## Abhaengigkeiten: korrigierter Tabellenparser

- `calamine` von 0.37.0 auf 0.38.0 aktualisiert; behebt den von
  [RustSec RUSTSEC-2026-0436](https://rustsec.org/advisories/RUSTSEC-2026-0436.html)
  gemeldeten Panic-/OOM-Fehler im CFB/OLE2-Parser. Daraus folgt keine Aussage
  zur Erreichbarkeit dieses Parserpfads ueber einen ISCY-Endpunkt.
- [Upstream-Release 0.38.0](https://github.com/tafia/calamine/releases/tag/v0.38.0)
  geprueft: MIT-Lizenz und Rust-Mindestversion 1.88 bleiben erhalten;
  ausschliesslich dieses crates.io-Paket samt Registry-Pruefsumme im Lockfile
  geaendert, keine neuen transitiven Pakete oder Advisory-Ausnahmen.
- bestehende Importgroessen-/Archivgrenzen und unterstuetzte Formate erhalten;
  veroeffentlichter SBOM-Snapshot bleibt gemaess Development-Lifecycle historisch.

## ISCY-27: Aussagekraeftige Bewertungskennzahlen

- additive `assessment_metrics` fuer Library und Gruppen trennen deklarierte
  Umsetzung/Wirksamkeit/Nachweisstatus, Evidence-Verknuepfungen und N/A
- gespeicherte Reife ohne N/A und ohne fehlende Statusstaende; offener
  Wert bei fehlendem Nenner; gepruefte
  Wirksamkeit bleibt ausdruecklich nicht erfasst statt automatisch bestaetigt
- Control-Ansicht und Beschriftungen praezisiert; alte API-Felder und
  gespeicherte Entscheidungen erhalten; keine Migration
- Datenvertrag und Grenzen in `docs/ISCY27_ASSESSMENT_METRICS.md`

## ISCY-27: NIS2-Referenzkorrektur

- additive Migration `0049_rust_iscy27_nis2_reference_correction` fuer
  SQLite/PostgreSQL korrigiert zehn unveraenderte Originalzuordnungen
- exakter Inhalts-/Control-Abgleich erhaelt eigene Anpassungen; ein
  Konflikt verwirft alle Korrekturen und verhindert das Migrationsreceipt
- historische Seeds und Mandantenbewertungen bleiben erhalten; Details,
  Grenzen und Operatorhinweise in `docs/ISCY27_REFERENCE_CORRECTION.md`

## Fachliche Praezisierung: Unternehmenskontext bis zur SoA

- Wizard-Bezeichnung schliesst nationale Unternehmen ausdruecklich ein;
  grenzueberschreitende Taetigkeiten sind ein Kontextmerkmal
- primaerquellenbasierte Recherche und Codeabgleich fuer Scope,
  Anforderungen, Risiken, Controls und SoA; fehlende Modulverbindungen,
  Referenzkatalog-Abdeckung und naechste Abnahmefaelle dokumentiert
- ISCY-27 mit 27 Controls / 82 Mappings inventarisiert; konkrete
  NIS2-Referenzerrata und Grenzen der Status-/Reifegradkennzahlen samt
  spaeterem versioniertem Reparaturpfad dokumentiert
- keine neue Rechtsregel, SoA-Auswahlentscheidung, Migration oder Freigabe;
  bestehende Schreib- und Tenantgrenzen erhalten

## Unternehmens-Wizard W1: Profil erfassen und fortsetzen

- neuer Einstieg `/assessments/company-wizard/` fuer tenantgebundene
  Unternehmensentwuerfe mit Hauptsitz/operativen Laendern, Taetigkeit,
  Groessen-/Bezugsangaben sowie Produkt-/KI-/OT-/Automotive-Kontext
- unbekannte Zahlen/Antworten bleiben von Null/Nein unterscheidbar;
  Fehler behalten die Eingaben, Versionskonflikte verhindern Ueberschreiben
- additive Migration `0048_rust_company_wizard_profile` fuer SQLite und
  PostgreSQL; transaktionale Auditmetadaten, abgeschlossene Staende gesperrt
- Session-/Rollen-/CSRF-Pruefung; keine Aenderung des Organisations-Stammprofils
  oder historischer Ergebnisse. Fachliche Betroffenheitsregeln und
  Ergebnis-/Massnahmenuebernahme bleiben W2/W3 und werden nicht vorgetaeuscht.

## Vorhandene Assessment-Durchlaeufe im Web

- neue authentifizierte Leseseiten `/assessments/runs/` und
  `/assessments/runs/{id}/`, verlinkt ueber Startseite und Assessment-Register
- Status, Fortschritt, vorhandene Bewertungen, Luecken, Massnahmen und
  Report-/Roadmap-Verweise mit tenantgebundenen Eltern- und Detailabfragen;
  fremde Startpersonen werden ausgeblendet, Freitext wird HTML-escaped
- frische Datenbestaende zeigen eine ausdruecklich gekennzeichnete
  Zusammenfassung; unvollstaendige Detailschichten bleiben Fehler
- Rollen-/Sessionpruefung, keine URL-Identitaet oder neue Schreibfunktion;
  keine Migration, Schemaerzeugung oder automatische Ergebnisgenerierung;
  der schreibende Assessment-Wizard bleibt eigener offener Scope

## Dauerhafte Auditspur fuer lokale Evidence-Downloads

- Dieselbe tenantgebundene Commit-Pruefung gilt jetzt auch fuer den
  S3-Runtime-Download. Sein bisheriger Ereignistyp `storage_object_downloaded`
  bleibt erhalten; `storage_object_download_denied` ergaenzt bekannte
  Ablehnungen. `hash_verified` bildet einen echten Vergleich mit erwartetem
  Hash ab; historische leere Hash-Metadaten erzeugen keinen falschen PASS.
- Die Security-Middleware erhaelt das explizite `private, no-store` dieser
  Antworten und ergaenzt weiter `max-age=0`.
- S3-Laufzeitlogs enthalten nur Backend, Entscheidung und festen Grund.
  Benutzer-, Mandanten- und Evidence-IDs bleiben im geschuetzten
  Datenbank-Audit und werden nicht zusaetzlich ins Prozesslog geschrieben.
- Beide lokalen `/evidence/{id}/download`-Routen schreiben Entscheidungen
  fuer bekannte tenant-eigene Objekte in `evidence_integrity_event`.
- Dateibytes werden nur nach genau einem gespeicherten und erfolgreich
  committeten Freigabeereignis zurueckgegeben; Auditfehler liefern HTTP 503.
- Das Ereignis belegt Antwortvorbereitung, keine Zustellbestaetigung.
  Dateipfade, Titel, Inhalte, E-Mail-Adressen und Sessionwerte werden nicht
  gespeichert. Tenant-/Actor-IDs stammen aus dem validierten Sessionkontext.
- Keine Migration oder neue Abhaengigkeit. Unauthentifizierte/fremde
  Objektzugriffe erzeugen keine objektbezogene persistente Historie.

## Eindeutige Herkunft der regelbasierten CVE-Assistenz

- feste Generatoridentitaet und versionierte Stub-Provenance fuer
  `POST /api/v1/llm/generate` und neue CVE-Assessments;
  `inference_performed=false`, keine angewendete Modellkonfiguration
- neuer Status `STUB_GENERATED` mit Anzeige `Regelbasiert (Stub)`;
  historische `GENERATED`-Ausgaben bleiben unveraendert, der bestehende
  `llm_generated`-Kompatibilitaetszaehler umfasst beide Assistenzformen
- die Runtime-Anzeige unterscheidet verfuegbaren Stub und fehlende
  Modellruntime; `LOCAL_LLM_*` kann weder Modellidentitaet noch geladene
  Modell-/GPU-Parameter vortaeuschen
- deaktivierte Neugenerierung erhaelt bestehende Ausgabe- und Herkunftsdaten;
  keine neue Migration, Modellinferenz, RAG-Integration oder aktive Gegenmassnahme

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

## Tokio-Runtime-Wartung

- gezieltes Lockfile-Update von `tokio 1.53.1` auf `1.53.3` mit upstream
  korrigierter Timer-, Task-, Channel- und I/O-Sicherheitsabwicklung;
  `1.53.2` wird wegen `RUSTSEC-2026-0386` nicht als Zielstand verwendet
- keine weiteren Dependency- oder Cargo-Featureaenderungen; MSRV und
  bestehende Tenant-, Authentifizierungs- und Audit-Grenzen bleiben unveraendert
- Development-Metadaten und Pruefsummen zum Lockfile abgeglichen;
  Handbuch, Migrationen, freigegebener SBOM-Snapshot und Published-Artefakte
  bleiben unveraendert

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
