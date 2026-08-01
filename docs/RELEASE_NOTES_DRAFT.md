# ISCY V23.7.33 - Development Notes

Status: Development / Unreleased.

Basis: `V23.7.32` (`76fa7384bf25e8eaab87f98377cb1db10d4432da`).

Dieser Entwicklungsstand wurde noch nicht veroeffentlicht. Es gibt noch keinen
Tag und noch kein GitHub Release fuer `V23.7.33`. Aenderungen werden bis zur
getrennten Release-Vorbereitung unter Unreleased dokumentiert.

## Veröffentlichte Basis

`V23.7.32` wurde als GitHub Release `363588955` mit sechs Assets
veroeffentlicht. Der kontrolliert heruntergeladene und per SHA-256
rueckverifizierte Metadaten-Snapshot liegt unter
`release/published/V23.7.32.json`. Er dokumentiert Tagziel,
Veroeffentlichungszeitpunkt, Status, Asset-IDs, Groessen, Medientypen,
Download-URLs und die verifizierten SHA-256-Werte.

Der Snapshot ist Metadaten-Evidence und keine kryptografische Attestation. Das
Release und seine Artefakte sind unsigniert. Die CycloneDX-SBOM bildet den
finalen Dependency-Graph ab und ist reproduzierbar; ihr deterministischer
Metadatenzeitstempel folgt dem bestehenden Repository-Vertrag. Sie ist weder
eine Attestation noch eine VEX- oder Schwachstellenfreiheitsaussage.

## Entwicklungsstand seit der Basis

Dieser Lifecycle-Stand enthaelt gegenueber dem veroeffentlichten
`V23.7.32`-Commit keine Produktfunktion, Migration, Dependency-Aktualisierung,
Visual-Baseline oder Release-Artefaktaenderung. Kuenftige Aenderungen fuer
`V23.7.33` muessen unter Unreleased dokumentiert und in einer separaten
Release-Vorbereitung vollstaendig neu validiert werden.

## Lifecycle-Grenzen

- Das Root-Manifest steht auf `development_unreleased` mit `git:HEAD` und dem
  veroeffentlichten V23.7.32-Commit als `source_base_commit`.
- Teststatus und Release-Artefakt-Reproduzierbarkeit sind auf erneute
  Development- beziehungsweise Release-Validierung zurueckgesetzt.
- In diesem Status kann fuer `V23.7.33` kein Release-Bundle erzeugt werden.
- `V23.7.32` kann als bereits veroeffentlichte Version nicht erneut vorbereitet
  oder ueberschrieben werden.
- Tag, GitHub Release, Assets und Published-Snapshot von `V23.7.32` werden
  nicht veraendert.
- Es wird keine Signatur, Attestation, VEX-Aussage, Zertifizierung,
  Schwachstellenfreiheit oder Release-Freigabe behauptet.
- Die menschliche Security-, Betriebs- und Release-Review bleibt erforderlich.
