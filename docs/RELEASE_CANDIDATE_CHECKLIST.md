# ISCY Release-Candidate-Checkliste V23.7.31

Diese Checkliste beschreibt die kontrollierte Release-Candidate-Vorbereitung
fuer `V23.7.31` auf Basis des vollstaendig gemergten Entwicklungsstands.
Sie ist ein technischer und fachlicher Review-Nachweis, keine Freigabe,
Zertifizierung, Rechtsberatung oder automatische Veroeffentlichung.

## Geprüfter Ausgangsstand

- Basis: veroeffentlichtes Stable Release `V23.7.30`
- Basis-Commit: `1c07af4e7cd196076220479d394242a3df589714`
- Release-ID: `358056010`
- Published-Snapshot: `release/published/V23.7.30.json`
- Zielversion: `V23.7.31`
- Candidate-Ausgangscommit: `74ba1f4a2239afbba2cb74c16199664914deb1c9`
- Enthaltene Feature-PRs: `#86`, `#87`, `#88`
- Root-Status: `prepared_not_published`
- Internes Rust-Paket: `0.3.22`
- Rust-Haupttoolchain: `1.97.0`
- MSRV und portabler Release-Builder: Rust `1.88`
- Nix: `nixos-26.05`, Nix-Rust `1.95.0`
- Datenbank: PostgreSQL 16 bleibt Standard; PostgreSQL 18.4 ist
  kompatibilitaetsgeprueft
- Migrationen: 45, fortlaufend `0001` bis `0045`
- Visual Regression: 42 Baselines
- Rust-Vollsuite auf dem aktuellen Entwicklungsstand: 376 Tests bestanden; der
  bestehende isolierte MinIO-Test bleibt im normalen Cargo-Lauf bewusst
  ignoriert und wird im separaten Object-Storage-Integrationsjob ausgefuehrt
- Lizenz: `AGPL-3.0-only`

`V23.7.30`, sein Tag, seine Release-ID und seine sechs Assets bleiben
unveraenderlich. Der Snapshot dokumentiert ausschliesslich bereits
veroeffentlichte Metadaten und ist keine Signatur oder Attestation.

## Lifecycle-Modi

`development_unreleased` bleibt der normale Root-Status fuer Feature-PRs. In
diesem Modus bricht `make release-candidate-artifacts` fail-closed ab und ein
erfolgreiches Vollgate endet mit `DEV_CHECK_OK`.

In diesem Development-Status bleibt die getrackte SBOM des letzten
veroeffentlichten Releases byteidentisch und wird per SHA-256 sowie
CycloneDX-Struktur validiert. Eine neue Release-SBOM wird erst im Status
`prepared_not_published` erzeugt; Development erzeugt weder Bundle noch neue
Release-SBOM.

`prepared_not_published` ist ausschliesslich in diesem separaten
Release-Prep-PR gesetzt. Dieser Modus verlangt vollstaendige Candidate Notes
und erlaubt nach dem Binary-Gate die lokale, unsignierte Bundle-Erzeugung. Eine automatische
Umwandlung aus dem Development-Modus, ein Tag oder eine GitHub-
Veroeffentlichung findet nicht statt. Das Candidate-Vollgate endet mit
`RC_CHECK_OK`.

Beide Modi lesen ihren Status ausschliesslich aus dem validierten Root-
Manifest. Migrationenzahl und Visual-Baselines werden gegen die dort
dokumentierten Integerwerte geprueft; Migrations-IDs muessen ab `0001`
lueckenlos, eindeutig und aufsteigend sein.

## Enthaltene Platform-Maintenance

- nginx `1.31-alpine` in Stage, Production und HA-Testtopologie
- Rust `1.97.0` fuer Build, Test, Clippy und Produktcontainer bei unveraenderter
  MSRV `1.88`
- nixpkgs `nixos-26.05` mit Nix-Rust `1.95.0`
- PostgreSQL-18.4-Kompatibilitaetsgate und logischer Forward-Restore 16 nach 18
- PostgreSQL 16 weiterhin als Standard mit unveraendertem Volumeziel
- Release-Manifest-Schema 2 trennt Produkt-, MSRV-, portablen Release- und
  Nix-Toolchainpfad sowie zehn CI-Pflichtabhaengigkeiten, Aggregationsjob und
  drei CodeQL-Sprachpruefungen

## Release-Readiness-Matrix

| Bereich | Status | Nachweis oder Einschränkung |
| --- | --- | --- |
| Rust/Axum Backend und Weboberfläche | implementiert und geprüft | Locked Build, Clippy und 376 Rust-/HTTP-Tests sind auf dem aktuellen Entwicklungsstand gruen. |
| SQLite | geprüft mit dokumentierter Einschränkung | Bootstrap, Restart und Restore; kein Mehrinstanz-/HA-Pfad. |
| PostgreSQL 16 | Candidate-Prüfung erforderlich | Standardpfad; Leerdatenbank, Bestand, Dump/Restore und Migrations-Race muessen im Candidate-Gate gruen sein. |
| PostgreSQL 18.4 | Candidate-Prüfung erforderlich | Zusatzgate fuer frischen Bootstrap, Restart, 45 Migrationen und logischen 16-nach-18-Forward-Restore; kein Produktionsstandard. |
| Lokale Evidence-Speicherung | geprüft mit dokumentierter Einschränkung | Authentifiziert und canonical-path-geprueft; nicht HA-faehig. |
| S3-kompatibler Evidence Storage | Candidate-Prüfung erforderlich | MinIO-Lifecycle und HA-Cross-Instance-Pfad muessen gruen sein; keine produktiven Cloud-Credentials. |
| Evidence Worker und Disposition | Candidate-Prüfung erforderlich | Atomare Claims, Legal Hold, Approval, Tombstone und Wiederanlauf werden im Gate geprueft. |
| Notifications | geprüft mit dokumentierter Einschränkung | Claim/Deduplizierung und sichere Webhooks; kein externer Queue-Cluster. |
| Supplier/Product Security | implementiert und geprüft | Tenant-, Rollen- und Evidence-Grenzen besitzen Negativtests. |
| Native Threat Intelligence und Security Observations | implementiert und geprüft | Tenantgebundene Indicators, begrenzte Observations, manuelle Links, Rollen und transaktionale Auditspur; keine aktive Reaktion oder automatische Incident-/Evidence-Erzeugung. |
| Continuous Vulnerability Intelligence | implementiert und geprüft | Feste offizielle Quellen, Provenance, Datenalter, konservative Korrelation und fail-closed unvollstaendige Laeufe; manuelle Triage, VEX und Risk Acceptance bleiben erhalten. |
| Software Approval und Exceptions | implementiert und geprüft | Exakte Tenantziele, restriktive Praezedenz, Pflichtablauf, Self-Approval-Schutz, Revisionen und passive Side-Effect-Grenze. |
| Regulatory und Management Reviews | implementiert und geprüft | Snapshots und Exporte bleiben eingefroren; keine Rechts- oder Compliance-Entscheidung. |
| AI Governance | implementiert und geprüft | Links und Gap-Tasks sind tenantgebunden und idempotent. |
| Agent Rollout 2.0 Phase 1 | implementiert und geprüft | Feste Ringe, Preflight/Postflight, menschliche Promotion, Pause, Abbruch und operatorgefuehrter Rollback. |
| Agent Rollout 2.0 Phase 2 | implementiert und geprüft | Kanonische unveraenderliche Manifeste, SHA-256, passive Handoffs sowie transaktionale Result-Importe mit Replay-/Konfliktschutz. |
| Externe Agent-Verteilung und Remote-Ausführung | bewusst nicht unterstützt | Keine Paketuebertragung, Deployment-Provider-Anbindung, Agent-Befehle, MDM/RMM/EDR oder C2. |
| Agent-Artefakte und Provenance | geprüft mit dokumentierter Einschränkung | SHA-256 und Statusmetadaten; produktive Signierung fehlt. |
| Agent PKI / CSR / mTLS | geprüft mit dokumentierter Einschränkung | Metadata-only; keine CA-Ausstellung oder privaten Schluessel. |
| Produktive Code-Signierung und CA-Ausstellung | bewusst nicht unterstützt | Signatur bleibt `unsigned`, Provenance `prepared_unsigned`. |
| Codex PR-Orchestrator | geprüft mit dokumentierter Einschränkung | Guards, Status und Automationstests sind vorhanden; Modellaufrufe brauchen separat finanzierten API-Zugang, produktives Auto-Fix-E2E ist ohne Credits nicht belegt. |
| Liveness, Readiness und Shutdown | Candidate-Prüfung erforderlich | Graceful-Shutdown-Smoke und sichere Fehlerklassen muessen gruen sein. |
| Performance-Smoke | Candidate-Prüfung erforderlich | CI-Budget, keine Produktions-SLO. |
| Zwei-Instanzen-/Failover-Test | Candidate-Prüfung erforderlich | Zwei App-Instanzen; PostgreSQL, MinIO und nginx bleiben im Test Einzelinstanzen. |
| Visual Regression | Candidate-Prüfung erforderlich | 42/42 Baselines, keine automatische Baseline-Aktualisierung. |
| Docker/Compose und hardened Build | Candidate-Prüfung erforderlich | Non-root, Cap-Drop/no-new-privileges und alle Compose-Varianten. |
| Dependency-/Supply-Chain-Prüfung | Candidate-Prüfung erforderlich | cargo audit, cargo deny, SBOM und CI muessen gruen sein. |

`Candidate-Prüfung erforderlich` bedeutet, dass die Funktion implementiert ist, der
konkrete Release-Nachweis aber erst mit der vollstaendigen lokalen beziehungsweise
GitHub-CI-Ausfuehrung abgeschlossen wird.

## Security-Hardening-Befunde

Behoben:

- Kritisch: Außerhalb Development konnte ein Request mit `tenant_id` und
  `user_id` ohne Passwort eine Session erzeugen. Demo und Production lehnen
  diesen Kompatibilitaetspfad jetzt generisch ab.
- Hoch: Demo vertraute Identitaetsheader standardmaessig. Nicht-Development-
  Modi verlangen jetzt sowohl explizites Header-Trust als auch eine
  konfigurierte Trusted-Proxy-Grenze.
- Mittel: Zwei Session-Lesepfade konnten interne Store-/SQL-Details in einer
  HTTP-500-Antwort ausgeben. Die Antworten sind jetzt stabil redigiert.
- Hoch: Der PostgreSQL-Restore-Drill konnte eine credential-haltige Source-URL
  protokollieren und unterschied Source/Restore nicht explizit. URLs werden
  nicht mehr ausgegeben; identische Ziele brechen vor dem Restore ab.
- Mittel: Lokale Rust-Build- und RC-Testartefakte waren nicht vollstaendig aus
  dem Docker-Buildkontext ausgeschlossen. `.dockerignore` schliesst diese
  reproduzierbaren Caches und lokalen Runtime-Verzeichnisse jetzt explizit aus.

Bestätigte Grenzen:

- Session-Cookies sind `HttpOnly`, `SameSite=Lax`, acht Stunden begrenzt und in
  Production `Secure`; Logout widerruft serverseitig und laesst das Cookie
  ablaufen.
- Login-Fehler sind generisch und werden tenant-/userbezogen begrenzt. Ein
  externer IP-/Geo-Schutz bleibt Reverse-Proxy-/WAF-Aufgabe.
- Fehlende CORS-Freigaben bedeuten Same-Origin-Betrieb; es gibt keine
  permissive Wildcard-CORS-Konfiguration.
- Evidence-Downloads und S3-Laufzeitoperationen bleiben authentifiziert,
  tenant-, rollen- und objektgebunden sowie `private/no-store`.
- Der Release-Diff von `V23.7.30` bis zum Candidate-Ausgangscommit wurde auf
  Cross-Tenant-IDOR, Privilege Escalation, Self-Approval, manipulierte IDs,
  Mass Assignment, XSS, SQL-/Command-Injection, SSRF, Race-/Replay-Zustaende,
  Revisionen, Rollback/Audit und unvollstaendige externe Daten geprueft. Es
  bleibt kein offener Critical-, High- oder releaseblockierender
  Medium-Befund.

Nach Release zeitnah prüfen:

- Server-seitige Session-Token werden derzeit in der Sessiontabelle als
  zufaellige kurzlebige Tokens statt als Einweg-Hash gespeichert. Eine
  Umstellung benoetigt eine explizite Kompatibilitaets- und Logout-Entscheidung.
- Aeltere API-Bereiche sollen schrittweise auf dieselbe zentral getestete
  Fehlerklassifizierung wie Agent-, Evidence- und neue Governance-Stores
  vereinheitlicht werden.

## Supply Chain

- `Cargo.lock` ist verbindlich; direkte Git-Dependencies wurden nicht gefunden.
- Die Advisory-Ausnahme `RUSTSEC-2023-0071` bleibt nur fuer den deaktivierten
  optionalen `sqlx-mysql`-Lockfile-Pfad dokumentiert. `rsa` ist fuer kein
  ISCY-Target erreichbar.
- Die Monitoring-Compose-Beispiele verwenden noch konfigurierbare `latest`-
  Defaults. Vor produktiver Nutzung muessen Betreiber Images pinnen; ein
  separates, einzeln getestetes Pinning ist nach dem RC erforderlich.
- Mehrere Actions und Containerbasen sind major-/tag-, aber nicht commit-/
  digest-gepinnt. Dies bleibt ein transparenter separater Hardening-Punkt.
- Die abgeschlossenen Maintenance-Bloecke fuer nginx, Rust, nixpkgs und die
  PostgreSQL-18-Kompatibilitaet sind Bestandteil von `V23.7.29`. PostgreSQL 18
  wird dadurch nicht zum Produktionsstandard.

## Reproduzierbarer Prüfpfad

Vollstaendig, ohne Veroeffentlichung:

```bash
nix develop
export ISCY_POSTGRES_RESTORE_DRILL_SOURCE_URL=postgresql://iscy@127.0.0.1:5432/iscy_rc_source
export ISCY_POSTGRES_RESTORE_DRILL_RESTORE_URL=postgresql://iscy@127.0.0.1:5432/iscy_rc_restore
make release-candidate-check
```

Mit dem Root-Status `prepared_not_published` erzeugt dieser Aufruf nach allen
Pflichtgates ausschliesslich ein lokales, unsigniertes Bundle unter
`artifacts/release-candidate/`. Es wird weder hochgeladen noch veroeffentlicht.

Der gepinnte Nix-Dev-Shell stellt die benoetigten Clients und Pruefwerkzeuge
bereit. Der Aufruf verlangt absichtlich einen erreichbaren lokalen Docker-
Daemon und zwei explizite Wegwerf-PostgreSQL-Datenbanken. Fehlende
Voraussetzungen brechen mit einer sicheren Fehlerklasse ab. Die GitHub-CI fuehrt die teuren Docker-, MinIO-,
Performance-, HA-, Visual- und hardened-Build-Pruefungen in bestehenden Jobs
aus; `release-candidate-check` aggregiert deren Ergebnis und validiert danach
Manifest, Checksums, Migrationen, Baselines, Referenzen und Sensitive-Data-
Scan, ohne die Pipeline doppelt auszufuehren. Der HA-Job enthaelt zusaetzlich
das PostgreSQL-18.4-Kompatibilitaets- und Forward-Restore-Gate.

Der portable Binary-Pfad kann separat mit `make release-binary-gate` geprueft
werden. Er baut das Backend zweimal cachefrei im digest-gepinnten
Rust-1.88-Bookworm-Builder, verlangt identische SHA-256-Werte und prueft das
Ergebnis in einem sauberen Debian-Bookworm-Slim-Runtime-Container. Das Ziel ist
`linux-x86_64-glibc`; der Systeminterpreter muss regulaer sein, RPATH/RUNPATH
muessen fehlen und lokale Home-, Worktree-, Runner- sowie Nix-Store-Pfade sind
verboten. Als dynamische Laufzeitbibliotheken werden `libgcc_s.so.1`,
`libm.so.6`, `libc.so.6` und `ld-linux-x86-64.so.2` erwartet.

## Lokale Candidate-Artefakte

Nur im validierten Status `prepared_not_published` erzeugt
`make release-candidate-artifacts` ausschließlich unter
`artifacts/release-candidate/`:

- portables `linux-x86_64-glibc` Rust-Backend-Binary
- Handbuch-PDF
- Release Notes
- reproduzierbare CycloneDX-1.5-SBOM
- auf den aktuellen Commit aufgeloestes Release-Manifest
- SHA-256-Pruefsummen

Diese Artefakte sind unsigniert und werden weder hochgeladen noch
veroeffentlicht. Das Binary wird aus einem neutralen Containerpfad mit
deaktiviertem inkrementellem Build und Release-Debuginfo sowie aktiviertem
Symbol-Strip erzeugt. Zwei getrennte Builds, Binary-Hygiene, Loader-/`ldd`-
Pruefung, SQLite-Startup, Health und Graceful Shutdown sind Pflicht. Der
Runtime-Test enthaelt weder Nix noch Rust, Cargo oder einen Compiler. Das
glibc-Binary ist fuer kompatible x86_64-Laufzeiten bestimmt und nicht als
universelles Linux-Artefakt zu verstehen. `cargo-cyclonedx` stammt als reines Build-Werkzeug aus dem
durch `flake.lock` gepinnten Nixpkgs-Stand. Der Generator entfernt die zufaellige
Serialnummer, setzt den Timestamp auf den Basis-Commit und ersetzt den lokalen
Root-Pfad durch einen stabilen Cargo-PURL. Zwei aufeinanderfolgende Laeufe
muessen in getrennten temporaeren Verzeichnissen byteidentisch sein, bevor die
SBOM uebernommen wird. Die SBOM ist ein Abhaengigkeitsinventar, keine
Signatur, VEX-Entscheidung oder Sicherheitsfreigabe. Ein Release-VEX wird
bewusst nicht erzeugt, weil fuer diesen Release keine separate, fachlich
freigegebene Vulnerability-Assertion vorliegt.

## Bekannte Betriebsgrenzen

- PostgreSQL und MinIO bleiben ohne Betreiber-Cluster Single Points of Failure.
- Keine Multi-Region-HA und keine automatische horizontale Skalierung.
- SQLite und `local_filesystem` sind keine Mehrinstanz-/HA-Pfade.
- Keine EOL-/EOS-Integration, keine erweiterten PURL-/CPE-Regeln und keine
  zusaetzlichen externen Feeds in diesem Candidate.
- Keine aktive Reaktion, automatische Softwareblockierung oder Deinstallation.
- Keine automatische VEX-Aussage, Risk Acceptance, Incident- oder
  Evidence-Erzeugung durch die drei neuen Bereiche.
- Keine produktive CA-/PKI-Provider-Anbindung oder Agent-Paketsignierung.
- Keine Cloud-native Secret-Manager-Anbindung.
- Performance-CI-Budgets sind keine Produktions-SLOs.
- Keine automatische Zertifizierung, Rechtsbewertung oder Behoerdenmeldung.

## Freigabekriterien

- [ ] Alle lokalen, in der Umgebung ausführbaren Pflichtprüfungen sind grün.
- [ ] SQLite leer/restartbar und PostgreSQL leer/Bestand/Restore/Race sind grün.
- [ ] PostgreSQL 18.4 und der logische Forward-Restore 16 nach 18 sind gruen.
- [ ] MinIO-Lifecycle, Performance, HA und Visual Regression 42/42 sind grün.
- [ ] Binary-Hygiene, sauberer Runtime-Container und zwei byteidentische
  portable Builds sind gruen.
- [ ] Manifest, Checksums, Handbuch und Release Notes sind konsistent.
- [ ] GitHub-CI einschließlich Aggregation ist vollständig grün.
- [ ] CodeQL Default Setup fuer Rust, Actions und JavaScript/TypeScript ist gruen.
- [ ] Menschliche Security- und Betriebsreview ist erfolgt.
- [ ] Erst danach darf separat über Ready-for-review, Merge, Tag und Release
  entschieden werden.

Diese Candidate-Vorbereitung erstellt keinen neuen Tag, kein GitHub Release,
keinen Asset-Upload, keine produktive Signatur und keine oeffentliche
Veroeffentlichung. Der veroeffentlichte Snapshot `V23.7.30` bleibt immutable.
