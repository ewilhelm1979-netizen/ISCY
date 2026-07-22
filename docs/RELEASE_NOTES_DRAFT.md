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
- Neue Produktfunktionen werden erst nach ihrer Implementierung und Pruefung
  unter `Unreleased` dokumentiert.
- Native Threat Intelligence und Security Observations werden durch diese
  Lifecycle-Umstellung noch nicht als implementiert ausgewiesen.

## Technische Basis

- Internes Rust-Paket: `0.3.22`
- Rust-Haupttoolchain: `1.97.0`
- MSRV und portabler Release-Builder: Rust `1.88.0`
- PostgreSQL 16 bleibt der Standard.
- PostgreSQL 18.4 bleibt ein zusaetzlicher Kompatibilitaetspfad.
- Aktuell 41 fortlaufende Migrationen, `0001` bis `0041`
- 36 Visual-Baselines
- Signaturstatus: `unsigned`
- Provenance-Status: `prepared_unsigned`
