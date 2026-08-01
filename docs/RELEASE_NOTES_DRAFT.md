# ISCY V23.7.32 - Development Notes

Status: Development / Unreleased.

Basis: `V23.7.31` (`c595795296633ce4152aa0e817b063ee88c7028a`).

Dieser Entwicklungsstand wurde noch nicht veroeffentlicht. Es gibt noch keinen
Tag und noch kein GitHub Release fuer `V23.7.32`. Aenderungen werden bis zur
getrennten Release-Vorbereitung unter Unreleased dokumentiert.

## Veröffentlichte Basis

`V23.7.31` ist als GitHub Release mit sechs Assets veroeffentlicht. Der
verifizierte Metadaten-Snapshot liegt unter
`release/published/V23.7.31.json`. Er dokumentiert Release-ID, Tagziel,
Zeitpunkt, Status, Assetgroessen, Medientypen, Download-URLs und die durch
kontrollierten Download verifizierten SHA-256-Werte. Der Snapshot ist
Metadaten-Evidence und keine kryptografische Attestation.

## Seit der Basis gemergter Entwicklungsstand

Der aktuelle Entwicklungsstand enthaelt die nach `V23.7.31` gemergten
Aenderungen aus PR `#94`, `#95` und `#96`:

- file-basierte Produktionssecrets und fail-closed Secret-Hygiene;
- einen kontrollierten Dependency- und nixpkgs-Refresh mit aktualisierten
  Release-Metadaten und SBOM;
- fail-closed CI-Artefakt-Hygiene fuer isolierte synthetische Visual- und
  Performance-Artefakte sowie den gepinnten `actions/upload-artifact`-Stand
  `7.0.1`.

Diese Auflistung ist eine Scope-Abgrenzung fuer die weitere Entwicklung. Sie
ist noch kein Release-Nachweis. Migrationen, Visual-Baselines, Workflows,
Dependencies, SBOM, Handbuch und Release-Bundle muessen in einem separaten
Release-PR erneut gegen den dann aktuellen Commit validiert werden.

## Lifecycle-Grenzen

- Das Root-Manifest steht auf `development_unreleased`.
- In diesem Stand wird kein Release-Bundle vorbereitet oder erzeugt.
- `V23.7.31`, sein Tag und sein Published-Snapshot werden nicht veraendert
  oder erneut vorbereitet.
- Es wird keine Signatur, Attestation, VEX-Aussage, Zertifizierung,
  Schwachstellenfreiheit oder Release-Freigabe behauptet.
- Die menschliche Security-, Betriebs- und Release-Review bleibt erforderlich.
