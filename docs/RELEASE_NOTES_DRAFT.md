# ISCY V23.7.31 - Development Notes

Status: Development / Unreleased.

Basis: `V23.7.30` (`1c07af4e7cd196076220479d394242a3df589714`).

Dieser Entwicklungsstand wurde noch nicht veroeffentlicht. Es gibt noch keinen
Tag und noch kein GitHub Release fuer `V23.7.31`. Implementierte Aenderungen
werden bis zur naechsten Release-Vorbereitung unter Unreleased dokumentiert.

## Fortbestehende Basis

ISCY bleibt eine selbst gehostete, local-first und datenschutzbewusste
Open-Source-Plattform unter `AGPL-3.0-only`. Der veroeffentlichte Stand
`V23.7.30` bleibt unveraendert und ist im Repository unter
`release/published/V23.7.30.json` als Metadaten-Snapshot dokumentiert.

Die vorhandenen Governance- und Nachweisfunktionen unterstuetzen unter anderem
ISO 27001, NIS2, KRITIS, DORA, den Cyber Resilience Act, den EU AI Act und die
DSGVO. Diese Unterstuetzung ist keine Rechtsberatung, Zertifizierung,
Konformitaetsentscheidung oder automatische Behoerdenmeldung.

## Entwicklungsgrenzen

- In diesem Stand wird kein Release-Bundle vorbereitet oder erzeugt.
- `V23.7.31` besitzt noch keinen Release Candidate und keine Stable-/Latest-
  Freigabe.
- Neue Produktfunktionen werden nach ihrer Implementierung und Pruefung unter
  `Unreleased` dokumentiert.
- Native Threat Intelligence und Security Observations - Phase 1 sind in
  diesem Entwicklungsstand implementiert, aber noch nicht veroeffentlicht.
- Continuous Vulnerability Intelligence und Software Hygiene - Phase 1 sind
  in diesem Entwicklungsstand implementiert, aber noch nicht veroeffentlicht.

## Continuous Vulnerability Intelligence und Software Hygiene - Phase 1

- gehaerteter NVD-2.0-Einzel-/Deltapfad mit Pagination, UTC-Overlap,
  persistentem Checkpoint, Lease, begrenztem Retry und sicherem Laufstatus
- atomare CISA-KEV- und gebatchte FIRST-EPSS-Anreicherung vorhandener globaler
  CVE-Referenzdaten mit Provenance und Schutz neuerer Modelldaten
- konservative tenantgebundene CPE-/Versionskorrelation vorhandener Assets,
  Komponenten und SBOM-Importe; vorhandene Product-Security-Vulnerability-
  Findings werden bei kanonischem Produktbezug wiederverwendet, reine
  Asset-Matches bleiben pruefbare Korrelationen
- erklaerbare passive Priorisierung mit CVSS, KEV, EPSS, Assetkritikalitaet,
  Datenalter, VEX und dokumentierten Compensating Controls
- feste offizielle HTTPS-Quellen und DNS-/SSRF-, Redirect-, Timeout-,
  Kompressions-, Payload-, Parser- und Secret-Grenzen
- transaktionales Lease-Fencing, KEV-Count-/Rollback-Pruefung, faire
  EPSS-Batchrotation und pruefpflichtige komplexe NVD-CPE-Kontexte
- globale Checkpoint-/Fenster-Zeitpunkte und anfordernde Plattform-Actor-IDs bleiben fuer
  Tenantrollen redigiert
- keine automatische Security Observation, kein Incident, keine Evidence,
  kein Agentenbefehl und keine aktive Reaktion; EOL/EOS und weitergehende
  Software-Policy bleiben ohne belastbare Quelle Phase 2

## Native Threat Intelligence und Security Observations - Phase 1

- tenantgebundene, lokal validierte Indicators fuer IPv4, IPv6, Domains, URLs
  und SHA-256 mit Provenance, Confidence, Gueltigkeit, Lifecycle und
  Klassifizierung
- normalisierte, begrenzte Security Observations aus manueller Erfassung oder
  vorhandenen Agent-/Vulnerability-Findings; die vorhandenen Findings bleiben
  kanonisch
- manuelle, triagierbare Indicator-Links mit transaktionaler Auditspur und
  tenantlokaler Deduplizierung
- Rollen `SOC_ANALYST` und `SECURITY_ADMIN` sowie granulare direkte und
  gruppenbasierte Permissions ohne automatische Zuweisung an Bestandsrollen
- Rust-API und Webarbeitsbereich `/security-observations/`
- keine externen Feeds oder Netzwerk-Lookups, keine Raw-Logs, keine
  automatische Incident-/Evidence-Erzeugung und keine aktive Reaktion

## Technische Basis

- Internes Rust-Paket: `0.3.22`
- Rust-Haupttoolchain: `1.97.0`
- MSRV und portabler Release-Builder: Rust `1.88.0`
- PostgreSQL 16 bleibt der Standard.
- PostgreSQL 18.4 bleibt ein zusaetzlicher Kompatibilitaetspfad.
- Aktuell 43 fortlaufende Migrationen, `0001` bis `0043`
- 40 Visual-Baselines
- Signaturstatus: `unsigned`
- Provenance-Status: `prepared_unsigned`
