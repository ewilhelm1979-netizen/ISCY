# ISCY Release-Candidate-Checkliste V23.7.32

Diese Checkliste dokumentiert die reproduzierbare, publikationsneutrale
Vorbereitung von `V23.7.32`. Sie ist ein technischer und fachlicher
Review-Nachweis, keine Freigabe, Zertifizierung, Rechtsberatung oder
automatische Veroeffentlichung.

## Verifizierter Ausgangsstand

- Repository: `ewilhelm1979-netizen/ISCY`
- Branch: `release/v23.7.32`
- Synchronisationszeit: `2026-08-01T14:21:27Z`
- Start-Commit: `fcbf0a8add68a6656311598820303f3e994b895d`
- Merge-Base mit `main`: `fcbf0a8add68a6656311598820303f3e994b895d`
- `main` und `origin/main`: Divergenz `0/0` beim Branchstart
- veroeffentlichter Vorgaenger: `V23.7.31`
- Tagziel des Vorgaengers:
  `c595795296633ce4152aa0e817b063ee88c7028a`
- GitHub Release-ID des Vorgaengers: `358600823`
- unveraenderlicher Metadaten-Snapshot:
  `release/published/V23.7.31.json`
- SHA-256 des Snapshots:
  `f480b2d3a19e687e0c1ae6831a9c7f44531f879e07fa2b524d5b0e40423743af`
- Zielversion: `V23.7.32`
- Root-Lifecycle: `prepared_not_published`
- Root-Quellmarker: `git:HEAD`; `source_date_epoch` und `binary_sha256`
  bleiben im getrackten Manifest `null`
- internes Rust-Paket: `0.3.22`
- Lizenz: `AGPL-3.0-only`
- Migrationen: 45, fortlaufend `0001` bis `0045`
- Visual Regression: 42 unveraenderte Baselines

PR `#97` wurde als Merge-Commit `fcbf0a8add68a6656311598820303f3e994b895d`
auf `main` verifiziert. Der lokale Tag `V23.7.31` zeigt exakt auf den
dokumentierten Basiscommit. Ein fehlender oder abweichender Vorgaenger-Tag
sowie ein unerwartet vorhandener `V23.7.32`-Tag brechen die Metadatenpruefung
fail-closed ab.

## Tatsächlicher Scope seit V23.7.31

Der Diff vom Vorgaenger-Tag bis zum Branchstart enthaelt vier abgeschlossene
Wartungsbloecke:

1. PR `#94`: Secret-Hygiene und file-basierte Produktionssecrets.
2. PR `#95`: kontrollierter Rust-Dependency- und nixpkgs-Refresh mit
   regenerierter SBOM und transaktionalen Release-Metadaten.
3. PR `#96`: fail-closed Aufbereitung synthetischer Performance-/Visual-CI-
   Artefakte und Pin von `actions/upload-artifact` auf `7.0.1`.
4. PR `#97`: Published-Snapshot-/Lifecycle-Infrastruktur sowie verpflichtender
   Tag-Fetch und fail-closed Tagzielpruefung im Aggregationsjob.

Dieser Release-PR veraendert keine Produktfunktion, API, Migration,
Visual-Baseline, direkte Runtime-Dependency, Containerbasis oder aktive
Response-Funktion. Die einzige zusaetzliche Lockfile-Aenderung hebt
`event-listener` im vorhandenen SQLx-Graph auf die fehlerbereinigte
Patch-Version `5.4.2`; der Funktionsumfang bleibt eingefroren.

## Toolchain- und Dependency-Inventar

| Bereich | Verifizierter Stand | Grenze |
| --- | --- | --- |
| Rust-Paket | `iscy-backend 0.3.22`, Edition 2021 | keine Versionsanhebung |
| MSRV | Rust `1.88.0` | eigener Locked-Check |
| Produkt-Build/Test/Clippy | Rust `1.97.0` | getrennt von MSRV und Nix |
| portabler Builder | digest-gepinntes Rust `1.88` Bookworm | zwei cachefreie Builds |
| Nix-Entwicklung | Rust `1.95.0` aus `nixos-26.05` | nur Build-/Testpfad |
| nixpkgs | `21ea275a7c46aef9d4d6ddc962e6d562e9d94183` | Lockfile und NarHash verbindlich |
| direkte Aenderung | `base64 0.23.0`, nur Feature `std` | Default-Features deaktiviert |
| aktualisierte Aufloesungen | `anyhow 1.0.104`, `serde 1.0.229`, `serde_json 1.0.151`, `tokio 1.53.1` | Lockfile verbindlich |
| Security-Patch im SQLx-Graph | `event-listener 5.4.2`; `concurrent-queue` entfaellt | behebt `RUSTSEC-2026-0221` ohne Ignore-Regel |
| Makro-Aufloesung | `serde_derive` ueber `syn 3.0.3`; `syn 2.0.117` bleibt parallel | keine globale Major-Erzwingung |
| transitive base64-Nutzer | `base64 0.22.1` ueber `hyper-util`, `reqwest`, SQLx | keine erzwungene Transitiv-Umschreibung |
| native/build | `libsqlite3-sys 0.30.1`, `cc 1.2.60`, `pkg-config`, `vcpkg` | unveraendert; Rustls statt OpenSSL |
| Quellen | crates.io-Registry-Index, keine direkte Git-Dependency | `cargo deny` blockiert unbekannte Quellen |
| Lizenzen | bestehende Allowlist in `deny.toml` | keine neue Ausnahme |

Die einzige Advisory-Ausnahme bleibt `RUSTSEC-2023-0071`. `rsa` liegt nur im
Lockfile-Pfad der deaktivierten optionalen `sqlx-mysql`-Funktion und ist fuer
kein ISCY-Target erreichbar. Der Gate-Aufruf darf keine weitere Ignore-ID
enthalten. Die beim ersten Candidate-Audit erkannte informative Unsoundness
`RUSTSEC-2026-0221` ist mit `event-listener 5.4.2` behoben und wird nicht
ignoriert. Die Ausnahme ist keine Aussage ueber Schwachstellenfreiheit.

## Secret- und Production-Grenzen

- Production nutzt file-basierte Quellen fuer Datenbank, PostgreSQL,
  initialen Admin, NVD, Alertmanager und S3-kompatiblen Evidence Storage.
- Direkter Wert und korrespondierende `*_FILE`-Quelle sind gegenseitig
  ausgeschlossen; Konflikt oder unsichere Datei fuehren zum Abbruch.
- Secret-Dateien muessen regulaer, symlinkfrei, maximal 16 KiB gross und ohne
  Group-/Other-Rechte sein. `/run/secrets` ist die Default-Wurzel.
- Production Compose bindet `ISCY_SECRETS_DIR` read-only nach `/run/secrets`.
- Logs und sichere Fehlerklassen duerfen keine Werte, credential-haltigen URLs,
  Tokens, Object Keys oder lokalen Secret-Pfade ausgeben.
- `make secrets` ist Teil von `make check`; `make secrets-history` bleibt ein
  bewusst manueller Wartungsschritt. Der redigierende Runner akzeptiert
  normale Checkouts und separate Git-Worktrees nur nach fail-closed
  Aufloesung ihrer Git-Metadaten.

## CI-Artefakt-Hygiene

- Rohdaten liegen ausschliesslich in einem privaten `0700`-Wegwerfroot unter
  `RUNNER_TEMP`; das Upload-Staging ist getrennt und wird atomar erzeugt.
- Der Sanitizer validiert kanonische Pfade, Eigentum, Modi, Dateiarten,
  Symlink-/Hardlinkfreiheit, Anzahl, Gesamtgroesse, Schemas, Medienarten,
  SHA-256-Inventar und Sensitive-Data-Marker.
- Performance-Staging besteht exakt aus `performance-smoke.json`,
  `performance-smoke.md` und `artifact-manifest.json`.
- Visual-Staging besteht aus `visual-summary.json`, Manifest und nur bei
  synthetisch belegter Abweichung aus streng validierten `*-diff.png`-Dateien.
- Traces, Videos, Rohscreenshots, Browserprofile, Cookies, Storage-State,
  Datenbanken, `.env`, Logs, Zertifikate und Schluessel sind nicht uploadfaehig.
- Fremde Pull-Request-Head-Repositories, fehlgeschlagene Sanitization oder
  unvollstaendige Staging-Daten blockieren den Upload.
- `actions/upload-artifact` ist commitgepinnt auf
  `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` (`7.0.1`), versteckte Dateien
  sind ausgeschlossen, fehlende Dateien sind Fehler, Retention ist sieben
  Tage.

## Release-Readiness-Matrix

| Bereich | Kandidatennachweis | Betriebs- oder Aussagegrenze |
| --- | --- | --- |
| Rust/Axum Backend | Locked Format/Clippy/Test, MSRV und Rust-Smokes | keine neue Produktfunktion |
| SQLite | Bootstrap, Restart und Restore | Single-Instance, kein HA-Backend |
| PostgreSQL 16 | Standardpfad, Restore-Drill, Performance und HA | Datenbank bleibt in der Topologie Einzelinstanz |
| PostgreSQL 18.4 | isolierter Fresh-/Restart-/Migrations-/Forward-Restore-Pfad | kein Standard, kein In-place-Upgrade, kein Rueckwaertsrestore |
| lokaler Evidence Storage | Auth-, Pfad- und Restore-Tests | nicht HA-faehig |
| S3-kompatibler Evidence Storage | isolierter MinIO-Lifecycle und Cross-Instance-Read | keine produktiven Cloud-Credentials |
| Graceful Shutdown | SIGINT/SIGTERM, Readiness-Abfall, sauberer Exit | begrenzter Timeout, kein Orchestrator-SLA |
| Performance | synthetische Budgetpruefung mit maximal vier parallelen Requests | CI-Regressionsbudget, keine Produktions-SLO |
| Zwei-Instanzen/Failover | zwei Backends hinter nginx mit gemeinsamem PostgreSQL/MinIO | keine Multi-Region- oder Infrastruktur-HA |
| Visual Regression | 42/42 versionierte Baselines in zwei Viewports | keine automatische Baseline-Aktualisierung |
| Docker/Compose | alle Varianten plus hardened Docker-Build | keine neue Runtime-Basis |
| Supply Chain | Locked Build, Audit, Deny, doppelte SBOM, Checksums | keine Signatur-, VEX- oder Schwachstellenfreiheitsaussage |
| Release Binary | Rust 1.88, zwei byteidentische Builds, ELF-/RPATH-/Pfad-/Runtime-Pruefung | x86_64 glibc, kein universelles Linux-Binary |
| GitHub-CI | elf Aggregationsabhaengigkeiten, separater Codex-Testjob und Aggregation | teure Topologien werden nicht doppelt ausgefuehrt |
| CodeQL | Actions, JavaScript/TypeScript und Rust | separater Pflichtnachweis am finalen Head |

## Reproduzierbarer lokaler Prüfpfad

Der Nix-Dev-Shell-Pfad stellt Rust, Clients, Audit-/Deny-/CycloneDX-Werkzeuge,
Actionlint, ShellCheck und Gitleaks bereit. `make release-candidate-check`
verlangt einen erreichbaren Docker-Daemon und zwei getrennte, wegwerfbare
PostgreSQL-Datenbanken:

```bash
nix develop
export ISCY_POSTGRES_RESTORE_DRILL_SOURCE_URL=postgresql://iscy@127.0.0.1:5432/iscy_rc_source
export ISCY_POSTGRES_RESTORE_DRILL_RESTORE_URL=postgresql://iscy@127.0.0.1:5432/iscy_rc_restore
make release-candidate-check
```

Die Einzelgates bleiben separat nachvollziehbar:

- [ ] `nix develop --command make secrets`
- [ ] `nix develop --command make artifact-hygiene-test`
- [ ] `nix develop --command make check`
- [ ] `nix develop --command make docker-check`
- [ ] `nix develop --command make rust-smoke`
- [ ] `nix develop --command make rust-restore-smoke`
- [ ] `nix develop --command make graceful-shutdown-smoke`
- [ ] `nix develop --command make object-storage-integration`
- [ ] `nix develop --command make performance-smoke`
- [ ] `nix develop --command make ha-integration`
- [ ] `nix develop --command make postgresql-18-compatibility`
- [ ] `nix develop --command make visual-regression`
- [ ] `nix develop --command make release-binary-gate`
- [ ] `nix develop --command make release-candidate-metadata-check`
- [ ] `nix develop --command make release-candidate-check`
- [ ] `cargo audit` mit ausschliesslich `RUSTSEC-2023-0071`
- [ ] `cargo deny check advisories licenses sources`
- [ ] `nix flake check`
- [ ] Actionlint, ShellCheck, Checksums und `git diff --check`
- [ ] zwei byteidentische Handbuch-PDF-Builds mit Text-, Metadaten- und
  visueller Seitenpruefung

Ein lokal fehlender Daemon, Port, Client oder eine nicht erreichbare
Wegwerf-Datenbank ist ein Blocker und darf nicht als erfolgreicher Test
dokumentiert werden. CI-Ergebnisse ersetzen keinen bewusst fehlgeschlagenen
lokalen Pflichtpfad.

## Deterministische Release-Artefakte

Die CycloneDX-1.5-SBOM wird zweimal getrennt erzeugt. Der Generator entfernt
die zufaellige Serialnummer, setzt den Timestamp auf die Zeit des
Vorgaenger-Basiscommits und normalisiert den lokalen Root-Pfad zum stabilen
Cargo-PURL. Beide Bytesaetze muessen identisch sein.

Das Handbuch-PDF wird zweimal aus `docs/ISCY_Handbuch.md` gebaut. Neben dem
Bytevergleich werden Seitenauswahl, extrahierter Text und gerenderte Seiten
fuer Titel, Inhaltsstruktur, Secret-Haertung, CI-Artefakt-Hygiene,
Release-Grenzen und Dokumentende geprueft.

Das portable Binary wird zweimal cachefrei im digest-gepinnten
Rust-1.88-Bookworm-Builder gebaut. Pflicht sind identische SHA-256-Werte,
regulaerer ELF-Interpreter, fehlendes RPATH/RUNPATH, keine lokalen Buildpfade,
die erwarteten vier Laufzeitbibliotheken sowie SQLite-Startup, Health und
Graceful Shutdown in einem sauberen Debian-Bookworm-Slim-Container ohne Nix,
Rust, Cargo oder Compiler.

Nur nach diesen Gates erzeugt `make release-candidate-artifacts` lokal unter
`artifacts/release-candidate/` exakt:

1. `iscy-backend`
2. `iscy-backend.cdx.json`
3. `ISCY_Handbuch.pdf`
4. `release-manifest.json`
5. `RELEASE_NOTES.md`
6. `SHA256SUMS`

Das Bundle-Manifest loest `git:HEAD` auf den konkreten Commit und dessen
`SOURCE_DATE_EPOCH` auf und uebernimmt den verifizierten Binary-SHA. Das
getrackte Root-Manifest behaelt dagegen `git:HEAD`, `source_date_epoch: null`
und `binary_sha256: null`. Das Bundle bleibt ignored, lokal und unsigniert.

## Bekannte Betriebs- und Sicherheitsgrenzen

- PostgreSQL, MinIO und nginx bleiben ohne Betreiber-Cluster Single Points of
  Failure; keine Multi-Region-HA oder automatische horizontale Skalierung.
- SQLite und `local_filesystem` sind keine Mehrinstanzpfade.
- Keine Cloud-native Secret-Manager-Anbindung oder automatische Credential-
  Discovery; Betreiber muessen Mount, Rotation, Backup und Recovery planen.
- Keine aktive Reaktion, automatische Softwareblockierung/-deinstallation,
  automatische VEX-Aussage, Risk Acceptance, Incident- oder Evidence-
  Erzeugung durch die passiven Governance-Bereiche.
- Keine produktive CA-/PKI-Provider-Anbindung oder Agent-Paketsignierung.
- Monitoring-Compose-Defaults mit `latest` bleiben vor produktiver Nutzung
  separat zu pinnen; diese Release-Vorbereitung erweitert den Scope nicht.
- Performance-Ergebnisse sind keine SLA-/SLO-Zusage. Der HA-Test belegt keine
  HA der verwendeten Infrastrukturkomponenten.
- Keine automatische Zertifizierung, Rechtsbewertung, Konformitaetsentscheidung
  oder Behoerdenmeldung.

## Menschliche Freigabegrenzen

- [ ] Vollstaendige GitHub-CI am finalen Head ist gruen.
- [ ] CodeQL fuer Actions, JavaScript/TypeScript und Rust ist gruen.
- [ ] Fachliche, sicherheitstechnische und betriebliche Review ist erfolgt.
- [ ] Rollback-/Restore-Annahmen und Produktions-Secret-Betrieb sind fuer die
  Zielumgebung menschlich bewertet.
- [ ] Erst danach darf separat ueber Ready-for-review und Merge entschieden
  werden.

Diese Candidate-Vorbereitung erzeugt keinen Tag, kein GitHub Release, keinen
Asset-Upload, keine produktive Signatur, keine Attestation und keine
VEX-Aussage. `V23.7.31`, sein Release, seine sechs Assets und der
Published-Snapshot bleiben unveraendert. Publikation und Asset-Upload sind
einer getrennten Phase 3 vorbehalten.
