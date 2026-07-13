# ISCY V23.7.29 – Release Notes

Status: Stabiler Release vorbereitet; Tag und GitHub Release noch nicht erstellt.

Vorgänger: `V23.7.28-rc.1`.

ISCY bleibt eine selbst gehostete, local-first und datenschutzbewusste
Open-Source-Plattform unter `AGPL-3.0-only`. Die beschriebenen Funktionen
unterstuetzen Governance- und Nachweisprozesse; sie sind keine Rechtsberatung,
Zertifizierung, Konformitaetsbewertung oder automatische Behoerdenmeldung.

## Überblick

`V23.7.29` ist der stabile Folgerelease zu `V23.7.28-rc.1`. Er verbindet den
bereits veroeffentlichten Funktionsstand mit kontrollierter Platform-
Maintenance, Portabilitaetspruefungen und einer validierten PostgreSQL-
Upgradevorbereitung. Die Plattform unterstuetzt regulatorische Arbeits- und
Nachweisprozesse; sie liefert keine automatische Zertifizierung,
Konformitaetsentscheidung oder Rechtsberatung.

## nginx 1.31

- Stage, Production und die isolierte HA-Testtopologie verwenden
  `nginx:1.31-alpine`.
- Proxy-, Trusted-Header-, Authentifizierungs-, Tenant- und Evidence-Grenzen
  bleiben unveraendert.
- Ohne einen vom Betreiber bereitgestellten Cluster bleibt nginx ein Single
  Point of Failure; daraus folgt keine allgemeine HA-Zusage.

## Rust 1.97 und MSRV

- CI, Build, Test, Clippy und Produktcontainer verwenden Rust `1.97.0`.
- Die deklarierte MSRV bleibt Rust `1.88.0` und wird durch einen verpflichtenden
  CI-Job mit `cargo check --all-targets` und `cargo test --no-run` geprueft.
- Der portable Release-Builder bleibt separat und digest-gepinnt auf Rust 1.88
  mit Debian Bookworm. Produkt- und Release-Builder werden nicht automatisch
  gleichgesetzt.

## nixpkgs 26.05

- Der Nix-Pfad verwendet `nixos-26.05`, Nix-Rust `1.95.0` und `pkgs.nixfmt`.
- Playwright-, Chromium-, PDF- und Visual-Pfade wurden mit diesem Stand
  geprueft; die Visual Regression umfasst 34/34 Baselines.

## PostgreSQL 18

- PostgreSQL 16 bleibt der Standard- und Produktionspfad.
- PostgreSQL 18.4 ist als zusaetzlicher Kompatibilitaets- und Upgradezielpfad
  geprueft. Das PG18-Volume wird auf `/var/lib/postgresql` gemountet; PGDATA
  liegt bei `/var/lib/postgresql/18/docker`.
- Der getestete Forward-Upgradepfad verwendet PostgreSQL-18-Clientwerkzeuge,
  einen Custom-Format-Dump der PostgreSQL-16-Quelle, Restore in eine frische
  PostgreSQL-18-Datenbank, `ANALYZE` und den ISCY-Migrationslauf.
- Im Test wurden 110 Anwendungstabellen sowie Inhaltschecksummen, Sequenzen,
  Indizes, Constraints und Foreign Keys verglichen.
- Es gibt kein automatisches In-place-Upgrade, kein automatisiertes
  `pg_upgrade` und keine Rueckwaertsrestore-Garantie von PostgreSQL 18 nach 16.

## Datenbankkorrekturen

- PostgreSQL-Abfragen casten zuvor als Rust-`i64` dekodierte `INTEGER`-
  Ausdruecke explizit auf `bigint`.
- Datenmodell, Tenantfilter, SQLite-Semantik und API-Vertraege bleiben
  unveraendert.

## Governance und Compliance-Unterstuetzung

- AI-Governance-Systeme koennen mit Risiken, Roadmap-Tasks, Incidents und dem
  kanonischen Change-Register verknuepft werden.
- Management- und Regulatory-Review-Pakete unterstuetzen wiederholbare
  Templates, Previews, eingefrorene Snapshots und konsistente Exporte.
- Fachuebergreifende Notifications beziehen Evidence-, CVE-, Incident- und
  Roadmap-Signale in den bestehenden sicheren Kanalbetrieb ein.
- Supplier Reviews enthalten Freigabehistorie, Unterauftragnehmer,
  Vertragsfristen, Exit-Tests und tenantgesicherte Evidence-/Control-/Risk-Links.
- Der gefuehrte NIS2-Relevanz-Wizard verbindet Land, Einsatzlaender, Sektor,
  Mitarbeitendenzahl, Umsatz, kritische Dienstleistungen und organisatorischen
  Scope mit einer dokumentierten Applicability-Begruendung. Das Ergebnis ist
  eine Entscheidungshilfe und keine rechtsverbindliche Einstufung oder
  Rechtsberatung; es muss fachlich und rechtlich geprueft werden.
- NIS2- und KRITIS-Kontext koennen im Organisationsprofil gepflegt und mit
  Assessments, Requirements, Risiken, Evidence, Reports und Roadmap-Arbeit
  verbunden werden.
- Fuer DORA unterstuetzt ISCY die Dokumentation von Finanzunternehmen und
  IKT-Drittdienstleister-Rollen sowie die Verknuepfung mit Supplier-, Risiko-,
  Incident-, Evidence- und Review-Prozessen. Eine automatische
  DORA-Konformitaetsbewertung erfolgt nicht.
- Fuer den Cyber Resilience Act (CRA) verbindet ISCY Hersteller- und
  Product-Security-Kontext mit Produkten, digitalen Komponenten, SBOM, VEX,
  CVE, PSIRT, Suppliern, Evidence und Reviews. ISCY fuehrt keine automatische
  Konformitaetsbewertung oder CE-Freigabe durch.

## Evidence Integrity und Object Storage

- Evidence Integrity umfasst SHA-256-Pruefungen, Legal Hold, dokumentierte
  Disposition, Audit-Ereignisse und begrenzte Worker-Laeufe.
- Physische Disposition bleibt an Freigabe, Begruendung, Tenant und Legal-Hold-
  Status gebunden und erzeugt Tombstone-Metadaten.
- `local_filesystem` bleibt unterstuetzt; `s3_compatible` ergaenzt explizite
  Secret-Referenzen, SigV4, DNS-/SSRF-Revalidierung, begrenzte PUT-/HEAD-/GET-
  Operationen und kontrolliertes Remote-DELETE.
- Object Keys werden serverseitig kanonisch erzeugt und weder als frei
  waehlbarer Request-Wert noch vollstaendig in API oder Audit ausgegeben.

## Supplier und Product Security

- Supplier, Produkte/Services, lokale Advisory-/PSIRT-/CVE-Metadaten,
  SBOM-/VEX-Bezuege, Evidence, Reviews und Vertrags-/Exit-Historie sind
  tenantgebunden verbunden.
- Regulatory Review Packs koennen offene Supplier-/Product-Security-Gaps und
  fehlende Nachweise aggregieren, ohne eine automatische Compliance-Entscheidung
  zu treffen.

## Agent, Fleet, Zero Trust und PKI-Governance

- Gefuehrtes Agent-Onboarding nutzt Enrollment-Tokens, vorhandene Deployment-
  Artefakte, Policy-Zuordnung und Lifecycle-Audit.
- Agent-Artefakte erhalten SHA-256-, Signaturstatus- und Provenance-Metadaten.
  Produktive Paketsignierung ist nicht enthalten.
- CA-Provider, CSR-Review, Zertifikatsstatus, mTLS-Bindung, Rotation und
  Widerruf sind als Metadata-only-Governance modelliert. ISCY stellt keine
  Zertifikate aus und speichert keine privaten CA-Schluessel.

## Performance, Mehrinstanzbetrieb und Visual Regression

- Liveness, Readiness und Startup sind getrennt; Graceful Shutdown und
  PostgreSQL-Migrations-Lock sind geprueft.
- Ein begrenzter Performance-Smoke liefert p50, p95, p99, Maximum und
  Fehlerrate. Die Budgets sind keine Produktions-SLOs.
- Zwei Backend-Instanzen werden mit gemeinsamem PostgreSQL 16 und MinIO hinter
  nginx getestet. PostgreSQL, MinIO und nginx bleiben dabei Single Points of
  Failure; Multi-Region-HA wird nicht behauptet.
- 34 Playwright-Baselines decken 17 zentrale Webbereiche bei zwei Viewports ab.

## Portables Linux-Release-Artefakt

- Das unsignierte Backend-Binary wird fuer `linux-x86_64-glibc` in einem
  digest-gepinnten Rust-1.88-/Debian-Bookworm-Builder erzeugt.
- Compile-time-Pfade werden auf neutrale Containerpfade abgebildet. Lokale
  Home-, Worktree-, GitHub-Runner- und Nix-Store-Pfade sind im Artefakt nicht
  erlaubt.
- Das ELF-Binary verwendet den regulaeren x86_64-glibc-Systeminterpreter und
  besitzt weder RPATH noch RUNPATH. Seine dynamischen Laufzeitabhaengigkeiten
  sind `libgcc_s.so.1`, `libm.so.6`, `libc.so.6` und
  `ld-linux-x86-64.so.2`.
- Zwei unabhaengige, cachefreie Builds muessen byteidentische SHA-256-Werte
  liefern. Anschliessend werden Loader, `ldd`, SQLite-Initialisierung,
  `/health/live` und Graceful Shutdown in einem sauberen, digest-gepinnten
  Debian-Bookworm-Slim-Container ohne Nix, Rust, Cargo oder Compiler geprueft.
- Das Binary zielt auf kompatible x86_64-glibc-Systeme; daraus folgt keine
  Aussage, dass es auf jeder Linux-Distribution oder Architektur laeuft.

## Security-Hardening

- Passwortlose `tenant_id`-/`user_id`-Sessionerzeugung ist auf den expliziten
  Development-Kompatibilitaetspfad beschraenkt.
- Demo und Production akzeptieren `x-iscy-*`-Identitaetsheader nur hinter einer
  explizit konfigurierten vertrauenswuerdigen Proxy-Grenze.
- Session-Lesefehler geben keine SQL-, Tabellen- oder Store-Details aus.
- Der bestehende Secret-, Tenant-, Evidence-, Object-Storage-, Worker- und
  Supply-Chain-Pruefpfad wird in einem zentralen RC-Check zusammengefuehrt.

## Datenbank und Upgrade

- Der Stand enthaelt 39 fortlaufende Rust-Migrationen ohne doppelte oder
  fehlende ID.
- Seit `V23.7.27` kamen die additiven Migrationen `0027` bis `0039` hinzu.
- Vor einem Upgrade sind Datenbank und Evidence-Speicher gemeinsam zu sichern.
- Produktions-Upgrades muessen zuerst in einer umgebungsgleichen Staging-
  Instanz inklusive Restore-, Migration- und Rollback-Verfahren geprueft werden.
- SQLite bleibt ein lokaler Single-Instance-Pfad. Mehrinstanzbetrieb setzt
  PostgreSQL und gemeinsam erreichbaren S3-kompatiblen Evidence Storage voraus.
- PostgreSQL 16 bleibt Standard. Der PostgreSQL-18.4-Nachweis prueft frischen
  Bootstrap, Restart, 39 Migrationen, zweiten idempotenten Migrationslauf,
  Migrationsrennen und den logischen Forward-Restore von Version 16 nach 18.

## Betriebsanforderungen

- Production-Preflight, sichere Session-Cookies und ein expliziter Reverse-
  Proxy-Trust-Boundary muessen aktiv sein.
- S3-Credentials werden ausschliesslich ueber erlaubte `env:`-/`file:`-
  Referenzen bereitgestellt; echte Cloud-Credentials sind nicht Teil der Tests.
- Betreiber verantworten TLS, Netzwerk-Egress, Backup-Verschluesselung,
  Secret-Management, Monitoring, RPO/RTO und die fachliche Freigabe von
  Loeschungen und Meldungen.

## Bekannte Einschränkungen

- PostgreSQL und MinIO sind ohne Betreiber-Cluster Single Points of Failure;
  es gibt keine Multi-Region-HA und keine automatische horizontale Skalierung.
- `local_filesystem` und SQLite sind keine HA-Pfade.
- Produktive CA-Anbindung und Agent-Paketsignierung sind nicht enthalten.
- Cloud-native Secret-Manager sind nicht enthalten.
- Performance-CI-Budgets sind keine Produktions-SLOs.
- Das bereitgestellte Linux-Binary setzt eine kompatible x86_64-glibc-Laufzeit
  voraus; andere Architekturen und musl-only-Systeme sind nicht abgedeckt.
- Monitoring-Beispielimages sowie mehrere GitHub Actions sind noch nicht durch
  immutable Digests beziehungsweise Commit-SHAs gepinnt.
- Eine reproduzierbare CycloneDX-1.5-SBOM ist vorbereitet. Eine
  kryptografische Release-Signatur ist fuer diesen Release nicht
  konfiguriert; SBOM, Cargo.lock, Checksums und Provenance-Status werden
  transparent ausgewiesen.

## Versionsstatus

- Vorgänger: `V23.7.28-rc.1`
- Ziel: `V23.7.29`
- Internes Rust-Paket: `0.3.22`
- Geplanter Git-Tag: `V23.7.29`; noch nicht erstellt
- Geplanter GitHub-Release-Typ: Stable und Latest; noch nicht veroeffentlicht
- Vorbereitungsstatus: `prepared_not_published`
- SBOM: CycloneDX 1.5
- Signatur: `unsigned`
