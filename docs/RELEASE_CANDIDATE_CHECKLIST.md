# ISCY Development- und Release-Candidate-Checkliste

Diese Checkliste beschreibt den kontrollierten Development-Zyklus fuer
`V23.7.34` und die davon getrennte spaetere Release-Candidate-Vorbereitung.
Sie ist ein technischer und fachlicher Review-Nachweis, keine Freigabe,
Zertifizierung, Rechtsberatung oder automatische Veroeffentlichung.

## Verifizierter Ausgangsstand

- Repository: `ewilhelm1979-netizen/ISCY`
- Post-Release-Branch: `chore/post-release-v23.7.33`
- veroeffentlichte Basis: `V23.7.33`
- Basis-Commit und Tagziel:
  `2820f19f5fa33069db81e05c10949f2558948d04`
- GitHub Release-ID: `371373238`
- Veroeffentlichungszeitpunkt: `2026-08-16T16:23:51Z`
- GitHub-Status am Snapshot: Latest, nicht Draft, nicht Prerelease,
  `immutable=false`
- Published-Snapshot: `release/published/V23.7.33.json`
- SHA-256 des Published-Snapshots:
  `77901251fbed207a113871567450480a3f36e5804a9d9a06dd664cae115a09bf`
- Development-Zielversion: `V23.7.34`
- Root-Lifecycle: `development_unreleased`
- Root-Quellmarker: `git:HEAD`; `source_date_epoch` und `binary_sha256`
  bleiben im getrackten Manifest `null`
- internes Rust-Paket: `0.3.22`
- Lizenz: `AGPL-3.0-only`
- Migrationen: 45, fortlaufend `0001` bis `0045`
- Visual Regression: 42 versionierte Baselines

Der Tag `V23.7.33` muss exakt auf den oben dokumentierten Commit zeigen. Ein
fehlender oder abweichender Basis-Tag sowie ein unerwartet vorhandener
`V23.7.34`-Tag brechen die Metadatenpruefung fail-closed ab.

## V23.7.33-Publikationsnachweis

`V23.7.33` wurde aus dem Merge-Commit reproduzierbar gebaut, als Stable/Latest
veroeffentlicht und mit exakt sechs Assets gebunden:

1. `iscy-backend`
2. `iscy-backend.cdx.json`
3. `ISCY_Handbuch.pdf`
4. `release-manifest.json`
5. `RELEASE_NOTES.md`
6. `SHA256SUMS`

Der Published-Snapshot bindet Release-ID, Tagziel, Publikationszeitpunkt,
Asset-IDs, Groessen, Medientypen und SHA-256-Werte. Er ist Metadaten-Evidence
und keine kryptografische Attestation. Signaturstatus und Provenance bleiben
`unsigned` beziehungsweise `prepared_unsigned`.

Der Publish-Workflow erreichte die Veroeffentlichung erfolgreich. Seine
abschliessende Latest-Verifikation verwendete jedoch das von der installierten
`gh`-CLI nicht angebotene JSON-Feld `isLatest`. Die Repository-Korrektur nutzt
stattdessen den GitHub-REST-Endpunkt `releases/latest`. Der veroeffentlichte
Tag und die Release-Assets werden dadurch nicht veraendert.

## Development-Lifecycle V23.7.34

Der Post-Release-Schritt veraendert keine Produktfunktion, API, Migration,
Visual-Baseline oder bereits veroeffentlichtes V23.7.33-Artefakt. Er:

- dokumentiert die tatsaechliche V23.7.33-Publikation,
- oeffnet `V23.7.34` als `development_unreleased`,
- setzt den Teststatus auf `development_validation_required`,
- setzt die Release-Reproduzierbarkeit auf `not_prepared`,
- blockiert Release-Bundle-Erzeugung im Development-Status,
- blockiert die erneute Vorbereitung bereits publizierter Versionen.

Erst ein separater Release-Prep-PR darf V23.7.34 auf
`prepared_not_published` setzen und alle Release-Nachweise neu erbringen.

## Toolchain- und Supply-Chain-Inventar

| Bereich | Verifizierter Stand | Grenze |
| --- | --- | --- |
| Rust-Paket | `iscy-backend 0.3.22`, Edition 2021 | keine Versionsanhebung |
| MSRV | Rust `1.88.0` | eigener Locked-Check |
| Produkt-Build/Test/Clippy | Rust `1.97.0` | getrennt von MSRV und Nix |
| portabler Builder | digest-gepinntes Rust `1.88` Bookworm | zwei cachefreie Builds bei Release-Prep |
| Nix-Entwicklung | Rust `1.95.0` aus `nixos-26.05` | Build-/Testpfad |
| nixpkgs Lock | Commit `8b8c811c7c2541c30382c5de7ed26be055569c60` | `nixos-26.05` bleibt Kanalgrenze |
| direkte Runtime-Dependencies | `base64 0.23.1`, `calamine 0.36.1` | kontrollierte Patch-Updates |
| Actions Checkout | `actions/checkout 7.0.1` per Commit-SHA | unveraenderlicher Pin |
| Rust Tool Action | `taiki-e/install-action 2.85.10` per Commit-SHA | unveraenderlicher Pin |
| Quellen/Lizenzen | Cargo-Deny-/Audit-Gates | keine unbekannten Quellen oder stillen Ausnahmen |

Die dokumentierte `RUSTSEC-2023-0071`-Ausnahme bleibt auf den deaktivierten
optionalen Dependency-Pfad begrenzt. Ihre Existenz ist keine Aussage ueber
Schwachstellenfreiheit; eine unbeabsichtigte Aktivierung muss fail-closed
blockiert werden.

## Pflicht-CI fuer Release-Vorbereitung

Der Release-Candidate-Aggregator hat exakt elf Pflichtabhaengigkeiten:

1. `secret-scan`
2. `rust-backend-tests`
3. `rust-msrv-1-88`
4. `rust-bootstrap-smoke`
5. `nix-rust-smoke`
6. `object-storage-integration`
7. `performance-smoke`
8. `ha-integration`
9. `visual-regression`
10. `docker-config`
11. `release-binary-portability`

Zusaetzlich werden CodeQL fuer Actions, JavaScript/TypeScript und Rust sowie
der Aggregationsjob `release-candidate-check` erwartet.

## Datenbank- und Betriebsgrenzen

- PostgreSQL 16 bleibt Standard.
- PostgreSQL 18.4 ist ein zusaetzlicher Kompatibilitaetspfad.
- Der Upgrade-Nachweis 16 -> 18 erfolgt logisch per Dump/Restore; kein
  In-place-Upgrade wird behauptet.
- SQLite bleibt ein Single-Instance-Pfad.
- Lokaler Evidence Storage ist kein Mehrinstanz-/HA-Pfad.
- S3-kompatibler Evidence Storage wird isoliert getestet; CI verwendet keine
  produktiven Cloud-Credentials.
- PostgreSQL, MinIO und nginx sind ohne Betreiber-Cluster weiterhin moegliche
  Single Points of Failure; keine Multi-Region-HA wird behauptet.

## Secret- und Artefakt-Hygiene

- Produktionssecrets werden fail-closed aus erlaubten Quellen geladen.
- Secret-Dateien muessen regulaer, symlinkfrei, groessenbegrenzt und ohne
  Group-/Other-Rechte sein.
- Logs duerfen keine Credentials, Tokens, privaten Schluessel oder lokalen
  Secret-Pfade ausgeben.
- Performance- und Visual-Rohdaten sind vom Upload-Staging getrennt.
- Upload-Artefakte werden auf Dateityp, Pfad, Groesse, Anzahl, Sensitive-Data-
  Marker und erwartete Schemas begrenzt.
- Release-Binaries muessen ohne RPATH/RUNPATH und ohne lokale Buildpfade sein.

## Reproduzierbarer Pruefpfad

Wichtige Einzelgates:

- [ ] `nix develop --command make secrets`
- [ ] `nix develop --command make check`
- [ ] `nix develop --command make docker-check`
- [ ] `nix develop --command make object-storage-integration`
- [ ] `nix develop --command make performance-smoke`
- [ ] `nix develop --command make ha-integration`
- [ ] `nix develop --command make postgresql-18-compatibility`
- [ ] `nix develop --command make visual-regression`
- [ ] `nix develop --command make release-binary-gate`
- [ ] `nix develop --command make release-candidate-metadata-check`
- [ ] `nix develop --command make release-candidate-check`
- [ ] `cargo audit`
- [ ] `cargo deny check advisories licenses sources`
- [ ] `nix flake check`
- [ ] Actionlint, ShellCheck, Checksums und `git diff --check`

Ein fehlender Docker-Daemon, Testdienst oder eine nicht erreichbare
Wegwerf-Datenbank ist ein Blocker und darf nicht als erfolgreicher Test
umgedeutet werden.

## Deterministische Release-Artefakte

Im aktuellen Status `development_unreleased` muss
`make release-candidate-artifacts` abbrechen und darf kein Bundle erzeugen.
Nur im spaeteren Status `prepared_not_published` und nach erneuter Validierung
darf ein Release-Bundle mit exakt den sechs oben genannten Dateien entstehen.

Der spaetere portable Release-Build muss zwei byteidentische Builds aufweisen,
einen regulaeren x86_64-glibc-ELF-Interpreter verwenden, kein RPATH/RUNPATH
enthalten und in einem sauberen Debian-Bookworm-Slim-Runtime-Test ohne Nix,
Rust, Cargo oder Compiler starten.

## Bekannte Betriebsgrenzen

- keine automatische Zertifizierung oder Rechtsberatung,
- keine automatische DORA-Konformitaetsbewertung,
- keine automatische CRA-Konformitaetsbewertung oder CE-Freigabe,
- keine automatische VEX-Aussage,
- keine Aussage ueber Schwachstellenfreiheit,
- kein universelles Linux-Binary; der Release-Binary-Pfad ist x86_64 glibc.

`V23.7.33`, sein Tag, seine sechs Assets und der Published-Snapshot bleiben
unveraendert. V23.7.34 ist ausschliesslich der neue Development-Zyklus.
