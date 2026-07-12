# ISCY Release-Candidate-Checkliste

Diese Checkliste beschreibt den vorbereiteten Stand fuer `V23.7.28-rc.1`.
Sie ist ein technischer und fachlicher Review-Nachweis, keine Freigabe,
Zertifizierung, Rechtsberatung oder Veroeffentlichung.

## Geprüfter Ausgangsstand

- Basis: `origin/main` mit PR #48
- Basis-Commit: `89922d489ebbf658c4383d88a23dc6607e36eaa1`
- Letzte veröffentlichte Plattformversion: `V23.7.27`
- Internes Rust-Paket: `0.3.22`, MSRV `1.88`
- Vorgeschlagene Version: `V23.7.28-rc.1`
- Migrationen: 39, fortlaufend `0001` bis `0039`
- Lizenz: `AGPL-3.0-only`

Die vorgeschlagene Patch-Fortschreibung folgt der bestehenden
projektspezifischen `V23.7.x`-Konvention. Der Suffix `-rc.1` macht deutlich,
dass noch kein Tag und keine Veroeffentlichung vorliegen.

## Release-Readiness-Matrix

| Bereich | Status | Nachweis oder Einschränkung |
| --- | --- | --- |
| Rust/Axum Backend und Weboberfläche | bereit | Locked Build, Clippy, Rust-/HTTP-Tests und Smoke-Pfade sind Pflicht. |
| SQLite | bereit mit dokumentierter Einschränkung | Lokal und restartbar; kein Mehrinstanz-/HA-Pfad. |
| PostgreSQL | Prüfung erforderlich | Leerdatenbank, Bestand, Dump/Restore und Migrations-Race muessen fuer den RC gruen sein. |
| Lokale Evidence-Speicherung | bereit mit dokumentierter Einschränkung | Authentifiziert und canonical-path-geprueft; nicht HA-faehig. |
| S3-kompatibler Evidence Storage | Prüfung erforderlich | MinIO-Lifecycle und HA-Cross-Instance-Pfad muessen gruen sein; keine Cloud-Credentials. |
| Evidence Worker und Disposition | Prüfung erforderlich | Atomare Claims, Legal Hold, Approval, Tombstone und Wiederanlauf werden getestet. |
| Notifications | bereit mit dokumentierter Einschränkung | Claim/Deduplizierung und sichere Webhooks; kein externer Queue-Cluster. |
| Supplier/Product Security | bereit | Tenant-, Rollen- und Evidence-Grenzen besitzen Negativtests. |
| Regulatory und Management Reviews | bereit | Snapshots und Exporte bleiben eingefroren; keine Rechts- oder Compliance-Entscheidung. |
| AI Governance | bereit | Links und Gap-Tasks sind tenantgebunden und idempotent. |
| Zero Trust / Agent Fleet | bereit mit dokumentierter Einschränkung | Governance und Onboarding; kein allgemeiner EDR-/MDM-Ersatz. |
| Agent-Artefakte und Provenance | bereit mit dokumentierter Einschränkung | SHA-256 und Statusmetadaten; produktive Signierung fehlt. |
| Agent PKI / CSR / mTLS | bereit mit dokumentierter Einschränkung | Metadata-only; keine CA-Ausstellung oder privaten Schluessel. |
| Liveness, Readiness und Shutdown | Prüfung erforderlich | Graceful-Shutdown-Smoke und sichere Fehlerklassen muessen gruen sein. |
| Performance-Smoke | Prüfung erforderlich | CI-Budget, keine Produktions-SLO. |
| Zwei-Instanzen-/Failover-Test | Prüfung erforderlich | PostgreSQL, MinIO und nginx bleiben im Test Einzelinstanzen. |
| Visual Regression | Prüfung erforderlich | 34/34 Baselines, keine automatische Baseline-Aktualisierung. |
| Docker/Compose und hardened Build | Prüfung erforderlich | Non-root, Cap-Drop/no-new-privileges und alle Compose-Varianten. |
| Dependency-/Supply-Chain-Prüfung | Prüfung erforderlich | cargo audit, cargo deny und CI muessen gruen sein. |

`Prüfung erforderlich` bedeutet, dass die Funktion implementiert ist, der
konkrete RC-Nachweis aber erst mit der vollstaendigen lokalen beziehungsweise
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

Nach Release zeitnah prüfen:

- Server-seitige Session-Token werden derzeit in der Sessiontabelle als
  zufaellige kurzlebige Tokens statt als Einweg-Hash gespeichert. Eine
  Umstellung benoetigt eine explizite Kompatibilitaets- und Logout-Entscheidung.
- Aeltere API-Bereiche sollen schrittweise auf dieselbe zentral getestete
  Fehlerklassifizierung wie Agent-, Evidence- und neue Governance-Stores
  vereinheitlicht werden.

## Supply Chain und zurückgestellte Upgrades

- `Cargo.lock` ist verbindlich; direkte Git-Dependencies wurden nicht gefunden.
- Die Advisory-Ausnahme `RUSTSEC-2023-0071` bleibt nur fuer den deaktivierten
  optionalen `sqlx-mysql`-Lockfile-Pfad dokumentiert. `rsa` ist fuer kein
  ISCY-Target erreichbar.
- Die Monitoring-Compose-Beispiele verwenden noch konfigurierbare `latest`-
  Defaults. Vor produktiver Nutzung muessen Betreiber Images pinnen; ein
  separates, einzeln getestetes Pinning ist nach dem RC erforderlich.
- Mehrere Actions und Containerbasen sind major-/tag-, aber nicht commit-/
  digest-gepinnt. Dies bleibt ein transparenter separater Hardening-Punkt.
- Die offenen Plattform-PRs #7, #27, #28 und #29 bleiben unveraendert und sind
  keine Bestandteile dieses Release Candidates.

## Reproduzierbarer Prüfpfad

Vollstaendig, ohne Veroeffentlichung:

```bash
nix develop
export ISCY_POSTGRES_RESTORE_DRILL_SOURCE_URL=postgresql://iscy@127.0.0.1:5432/iscy_rc_source
export ISCY_POSTGRES_RESTORE_DRILL_RESTORE_URL=postgresql://iscy@127.0.0.1:5432/iscy_rc_restore
make release-candidate-check
```

Der gepinnte Nix-Dev-Shell stellt die benoetigten Clients und Pruefwerkzeuge
bereit. Der Aufruf verlangt absichtlich einen erreichbaren lokalen Docker-
Daemon und zwei explizite Wegwerf-PostgreSQL-Datenbanken. Fehlende
Voraussetzungen brechen mit einer sicheren Fehlerklasse ab. Die GitHub-CI fuehrt die teuren Docker-, MinIO-,
Performance-, HA-, Visual- und hardened-Build-Pruefungen in bestehenden Jobs
aus; `release-candidate-check` aggregiert deren Ergebnis und validiert danach
Manifest, Checksums, Migrationen, Baselines, Referenzen und Sensitive-Data-
Scan, ohne die Pipeline doppelt auszufuehren.

Der portable Binary-Pfad kann separat mit `make release-binary-gate` geprueft
werden. Er baut das Backend zweimal cachefrei im digest-gepinnten
Rust-1.88-Bookworm-Builder, verlangt identische SHA-256-Werte und prueft das
Ergebnis in einem sauberen Debian-Bookworm-Slim-Runtime-Container. Das Ziel ist
`linux-x86_64-glibc`; der Systeminterpreter muss regulaer sein, RPATH/RUNPATH
muessen fehlen und lokale Home-, Worktree-, Runner- sowie Nix-Store-Pfade sind
verboten. Als dynamische Laufzeitbibliotheken werden `libgcc_s.so.1`,
`libm.so.6`, `libc.so.6` und `ld-linux-x86-64.so.2` erwartet.

## Lokale Artefakte

Nach einem erfolgreichen Release-Build erzeugt
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
muessen byteidentisch sein. Die SBOM ist ein Abhaengigkeitsinventar, keine
Signatur, VEX-Entscheidung oder Sicherheitsfreigabe. Ein Release-VEX wird
bewusst nicht erzeugt, weil fuer diesen Candidate keine separate, fachlich
freigegebene Vulnerability-Assertion vorliegt.

## Bekannte Betriebsgrenzen

- PostgreSQL und MinIO bleiben ohne Betreiber-Cluster Single Points of Failure.
- Keine Multi-Region-HA und keine automatische horizontale Skalierung.
- SQLite und `local_filesystem` sind keine Mehrinstanz-/HA-Pfade.
- Keine produktive CA-/PKI-Provider-Anbindung oder Agent-Paketsignierung.
- Keine Cloud-native Secret-Manager-Anbindung.
- Performance-CI-Budgets sind keine Produktions-SLOs.
- Keine automatische Zertifizierung, Rechtsbewertung oder Behoerdenmeldung.

## Freigabekriterien

- [ ] Alle lokalen, in der Umgebung ausführbaren Pflichtprüfungen sind grün.
- [ ] SQLite leer/restartbar und PostgreSQL leer/Bestand/Restore/Race sind grün.
- [ ] MinIO-Lifecycle, Performance, HA und Visual Regression 34/34 sind grün.
- [ ] Binary-Hygiene, sauberer Runtime-Container und zwei byteidentische
  portable Builds sind gruen.
- [ ] Manifest, Checksums, Handbuch und Release Notes sind konsistent.
- [ ] GitHub-CI einschließlich Aggregation ist vollständig grün.
- [ ] CodeQL Default Setup `Analyze (rust)` und `Analyze (actions)` ist grün.
- [ ] Menschliche Security- und Betriebsreview ist erfolgt.
- [ ] Erst danach darf separat über Ready-for-review, Merge, Tag und Release
  entschieden werden.

Dieser PR erstellt keinen Tag, kein GitHub Release, keine produktive Signatur
und keine öffentliche Veröffentlichung.
