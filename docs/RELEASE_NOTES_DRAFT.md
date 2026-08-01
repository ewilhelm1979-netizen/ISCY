# ISCY V23.7.32 - Release Notes

Status: Stabiler Release.

Vorgänger: `V23.7.31` (`c595795296633ce4152aa0e817b063ee88c7028a`).

V23.7.32 ist ein Security-, Supply-Chain- und Maintenance-Release. Es bündelt die nach V23.7.31 gemergte Secret-Härtung, kontrollierte Dependency-Aktualisierungen und die fail-closed Absicherung von CI-Testartefakten.

Der Release fuegt keine neue Produktfunktion, Datenbankmigration, Visual-
Baseline oder aktive Response-Funktion hinzu. ISCY bleibt eine selbst
gehostete, local-first und datenschutzbewusste Open-Source-Plattform unter
`AGPL-3.0-only`.

## Secret-Härtung für Produktion

- Produktionskonfigurationen verwenden file-basierte Quellen unter
  `/run/secrets` fuer Datenbank, initialen Admin, NVD, Alertmanager und
  S3-kompatiblen Evidence Storage. Das Production-Compose bindet das
  konfigurierte Secret-Verzeichnis read-only ein.
- Direkte Werte und die jeweilige `*_FILE`-Quelle sind gegenseitig
  ausgeschlossen. Ein doppelt, unsicher oder unvollstaendig konfigurierter
  Wert laesst Startup beziehungsweise Production-Readiness fail-closed
  abbrechen.
- Secret-Dateien muessen regulaer, symlinkfrei, hoechstens 16 KiB gross und
  ohne Group-/Other-Rechte sein. Standardmaessig ist nur `/run/secrets`
  erlaubt; weitere Wurzeln brauchen eine explizite Konfiguration.
- Fehlerausgaben nennen nur Variablennamen und sichere Fehlerklassen. Werte,
  credential-haltige URLs, Tokens, private Schluessel und vollstaendige
  Object Keys werden nicht protokolliert.
- Der neue CI-Pflichtjob `secret-scan` prueft den aktuellen Baum redigiert mit
  Gitleaks. Der History-Scan bleibt ein bewusst getrennter manueller oder
  periodischer Wartungsschritt; `.gitignore` ist keine Sicherheitskontrolle.
  Der redigierende Runner validiert sowohl regulaere Checkouts als auch
  separate Git-Worktrees ueber deren aufgeloeste Git-Metadaten fail-closed.

## Fail-closed CI-Testartefakte

- Performance- und Visual-Tests schreiben Rohdaten in private, temporaere
  Verzeichnisse mit Modus `0700`. Rohverzeichnis und Upload-Staging sind
  disjunkt; kein Raw-Pfad wird hochgeladen.
- Der zentrale Sanitizer akzeptiert nur bekannte Dateinamen, regulaere
  symlink- und hardlinkfreie Dateien, enge Groessen-/Anzahlgrenzen und
  synthetische Daten mit expliziter Provenance. Ein Fehler entfernt Raw- und
  Staging-Daten und blockiert den Upload.
- Performance-Artefakte enthalten nur synthetische Aggregatmetriken als JSON
  und Markdown sowie ein gehashtes Manifest. Visual-Artefakte enthalten nur
  die minimierte synthetische Zusammenfassung, optional streng validierte
  Diff-PNGs und das Manifest; Traces, Videos, Screenshots, Browserprofile,
  Storage-State, Cookies, Logs und Datenbanken sind ausgeschlossen.
- Uploads laufen nur bei Pushes im eigenen Repository oder bei Pull Requests
  mit identischem Head-Repository. `actions/upload-artifact` ist auf Commit
  `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` (`7.0.1`) gepinnt, verlangt
  vorhandene Dateien, schliesst versteckte Dateien aus und bewahrt die
  minimierten Testartefakte sieben Tage auf.

## Kontrollierter Dependency- und nixpkgs-Refresh

- Das interne Rust-Paket bleibt `0.3.22`; Edition 2021 und die deklarierte MSRV
  Rust `1.88` bleiben unveraendert.
- Die direkte `base64`-Abhaengigkeit wechselt von `0.22.1` auf `0.23.0` mit
  deaktivierten Default-Features und ausschliesslich `std`. Transitive Nutzer
  von `hyper-util`, `reqwest` und SQLx behalten ihre kompatible Aufloesung
  `base64 0.22.1`.
- `Cargo.lock` loest ausserdem `anyhow 1.0.104`, `serde 1.0.229`,
  `serde_json 1.0.151` und `tokio 1.53.1` auf. `serde_derive` nutzt dabei
  `syn 3.0.3`; `syn 2.0.117` bleibt fuer andere Makro-Abhaengigkeiten
  vorhanden.
- Die transitive SQLx-Abhaengigkeit `event-listener` ist auf `5.4.2`
  aktualisiert. Damit ist die waehrend der Candidate-Pruefung erkannte
  Unsoundness `RUSTSEC-2026-0221` behoben; `concurrent-queue` wird von dieser
  Aufloesung nicht mehr benoetigt. Eine neue Ignore-Regel wurde nicht
  eingefuehrt.
- Die bestehenden nativen beziehungsweise Build-Abhaengigkeiten bleiben
  unveraendert: `libsqlite3-sys 0.30.1` nutzt die vorhandene
  `cc`-/`pkg-config`-/`vcpkg`-Kette; der TLS-Pfad bleibt Rustls-basiert. Das
  portable Binary darf zur Laufzeit nur `libgcc_s.so.1`, `libm.so.6`,
  `libc.so.6` und `ld-linux-x86-64.so.2` benoetigen.
- Alle Cargo-Quellen stammen weiterhin aus dem erlaubten crates.io-Registry-
  Index; direkte Git-Abhaengigkeiten und neue Lizenzfreigaben wurden nicht
  eingefuehrt. Die bestehende Advisory-Ausnahme `RUSTSEC-2023-0071` bleibt
  ausschliesslich fuer den fuer ISCY-Targets nicht erreichbaren,
  deaktivierten optionalen `sqlx-mysql`-Lockfile-Pfad bestehen.
- `nixos-26.05` ist auf nixpkgs-Commit
  `21ea275a7c46aef9d4d6ddc962e6d562e9d94183` gepinnt. Der Nix-
  Entwicklungspfad bleibt Rust `1.95.0`; Produkt-Build, Test, Clippy und
  Produktcontainer bleiben Rust `1.97.0`. MSRV bleibt Rust `1.88.0`; der
  portable Release-Builder bleibt ebenfalls Rust `1.88`.

## Release-Integrity und Artefaktvertrag

- Der Checkout des Aggregationsjobs holt die vollständige Historie und Tags,
  behaelt `persist-credentials: false` bei und verifiziert den Tag
  `V23.7.31` fail-closed gegen
  `c595795296633ce4152aa0e817b063ee88c7028a`. Ein fehlender oder abweichender
  Tag ist eine eindeutige Fehlerklasse.
- Das Root-Manifest verwendet repositorykonform `git:HEAD`, laesst
  `source_date_epoch` und den Binary-SHA leer und traegt den Lifecycle
  `prepared_not_published`. Erst die lokale Bundle-Erzeugung loest den
  konkreten Commit, dessen Commit-Epoch und den SHA-256 des zweifach
  byteidentischen Binaries auf.
- Die CycloneDX-1.5-SBOM wird zweimal in getrennten temporaeren Verzeichnissen
  erzeugt. Zufalls-Serial, fluechtiger Timestamp und lokaler Root-Pfad werden
  entfernt beziehungsweise durch Basis-Commit-Zeit und stabilen Cargo-PURL
  ersetzt.
- Das lokale, unsignierte Bundle enthaelt exakt Binary, Handbuch-PDF, Release
  Notes, CycloneDX-SBOM, aufgeloestes Manifest und `SHA256SUMS`. Es ist weder
  eine Signatur noch eine kryptografische Attestation oder VEX-Aussage.

## Plattform- und Datenbankgrenzen

- `nginx:1.31-alpine` bleibt der Reverse-Proxy-Stand fuer Stage, Production und
  HA-Testtopologie.
- PostgreSQL 16 bleibt der Standard. PostgreSQL 18.4 bleibt ein getrenntes
  Kompatibilitaetsgate fuer Fresh Bootstrap, Restart, 45 Migrationen,
  Migrationsrennen und logischen Forward-Restore von 16 nach 18. Das ist kein
  In-place-Upgrade und kein Wechsel des Produktionsstandards.
- SQLite und lokaler Evidence Storage bleiben Single-Instance-Pfade. Die
  Zwei-Instanzen-Topologie prueft gemeinsam genutztes PostgreSQL und
  S3-kompatiblen Storage; PostgreSQL, MinIO und nginx bleiben darin jeweils
  Einzelinstanzen.
- Performance-Grenzen sind CI-Regressionsbudgets und keine Produktions-SLOs.
  Es wird keine Multi-Region-HA, beliebige Skalierbarkeit oder allgemeine
  Hochverfuegbarkeit behauptet.

## Unveränderte fachliche Grenzen

Der NIS2-Relevanz-Wizard dokumentiert eine Applicability-Begruendung im
NIS2- und KRITIS-Kontext, aber keine rechtsverbindliche Einstufung. Eine
DORA-Konformitaetsbewertung erfolgt nicht. Fuer den Cyber Resilience Act (CRA) gibt
es keine automatische Konformitaetsbewertung oder CE-Freigabe. ISCY liefert
keine automatische Zertifizierung und keine Rechtsberatung.

Threat Intelligence, Security Observations, Vulnerability Intelligence und
Software-Approval bleiben passive Governance-Unterstuetzung. Sie erzeugen
keine aktive Reaktion, ueberschreiben keine menschliche Triage, erzeugen keine
automatische VEX-Aussage oder Risk Acceptance und installieren, blockieren
oder deinstallieren keine Software.

## Prüf- und Veröffentlichungsgrenze

Der Release-Vertrag verlangt Locked Build, Formatierung, Clippy, Rust-Tests,
MSRV, `cargo audit`, `cargo deny`, Secret-Scan, SQLite-/PostgreSQL-/MinIO-
Runtimepfade, Restore, Graceful Shutdown, Performance, HA, PostgreSQL 18.4,
Visual Regression, Compose, hardened Docker-Build, Nix-Flake-Pruefung,
deterministisches Handbuch, zweifaches Binary-Gate, SBOM, Checksums und
Metadatenregressionen. GitHub-CI und CodeQL bleiben eigenstaendige
Pflichtnachweise am finalen Pull-Request-Head.

Tagging, GitHub-Release-Erstellung, Asset-Upload, Signierung, Attestation und
Merge sind nicht Teil dieser Release-Vorbereitung und erfordern getrennte
menschliche Entscheidungen.
