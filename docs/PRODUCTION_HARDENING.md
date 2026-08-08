# Production Hardening

ISCY Community startet in Production nur, wenn die wichtigsten Sicherheitsannahmen explizit erfuellt sind.

## Startbremse

`ISCY_APP_MODE=production` aktiviert den Production-Preflight. Der Start wird abgebrochen, wenn:

- `DATABASE_URL` beziehungsweise `DATABASE_URL_FILE` fehlt, beide Quellen
  gleichzeitig gesetzt sind oder die aufgeloeste URL ein nicht
  unterstuetztes Schema nutzt,
- die aufgeloeste Datenbank-URL Beispielwerte wie `change-me` enthaelt,
- `RUST_BACKEND_BIND` oeffentlich lauscht und kein Trusted Proxy bestaetigt ist,
- Identity-Header vertraut werden sollen, aber kein Trusted Proxy bestaetigt ist,
- `ISCY_SECURE_COOKIES` deaktiviert ist,
- HSTS ohne bestaetigtes HTTPS aktiv ist,
- `ISCY_ALERTMANAGER_TOKEN` bzw. `ISCY_ALERTMANAGER_TOKEN_FILE` fehlt oder schwach ist,
- bekannte Demo-Zugangsdaten noch aktiv sind,
- Demo-Seeding im Production-Modus gestartet wird.

## File-basierte Produktionssecrets

Production Compose entfernt direkte Datenbank-, PostgreSQL-, NVD-, Admin-,
Alertmanager- und S3-Credential-Werte und bindet `ISCY_SECRETS_DIR` read-only
unter `/run/secrets` ein. Direkte Werte und korrespondierende `*_FILE`-Quellen
sind gegenseitig ausgeschlossen. Secret-Dateien muessen absolut, regulaer,
symlinkfrei, maximal 16 KiB gross und ohne Group-/Other-Rechte sein.
Standardmaessig ist nur `/run/secrets` erlaubt; weitere Wurzeln verlangen eine
explizite `ISCY_SECRET_ROOTS`- beziehungsweise
`ISCY_EVIDENCE_SECRET_ROOTS`-Konfiguration. Fehler nennen nur Variablennamen
und sichere Fehlerklassen, niemals Werte oder credential-haltige URLs.

Vor einem Produktionsstart muessen Betreiber die benoetigten Dateien mit
Modus `0400` oder `0600` anlegen, Eigentum und Mount pruefen, Rotation und
Recovery dokumentieren und `nix develop --command make secrets` ausfuehren.
Echte Secrets duerfen nicht als Nix-Strings konfiguriert werden, weil sie sonst
in den Nix Store gelangen koennen.

## Initialer Admin

Produktive Erstinitialisierung erfolgt ohne Demo-Seed:

```bash
ISCY_APP_MODE=production \
DATABASE_URL_FILE=/run/secrets/database_url \
ISCY_INITIAL_ADMIN_PASSWORD_FILE=/run/secrets/iscy_initial_admin_password \
nix run .#iscy-backend -- init-admin
```

Der Command fuehrt Migrationen aus, legt falls noetig einen Tenant an, erzeugt die Basisrollen `ADMIN`, `CONTRIBUTOR` und `AUDITOR` und erstellt einen aktiven Superuser/Admin. Existiert der Username bereits als aktiver Admin, bleibt der Account unveraendert. Existiert der Username ohne Admin-Rechte, bricht der Command ab.

## Login-Schutz

Lokale Username-/Passwort-Logins werden pro Tenant/Username begrenzt. Nach
fuenf fehlgeschlagenen Versuchen in 15 Minuten blockiert ISCY weitere Versuche
fuer 15 Minuten. Login-Identifier sind auf 254 Zeichen begrenzt;
Rate-Limit-Schluessel sind auf 255 Byte begrenzt. Abgelaufene Eintraege werden
global entfernt. Prozess- und Datenbankzustand akzeptieren jeweils hoechstens
4096 aktive Schluessel; bei erreichter Grenze werden neue Schluessel bis zum
Ablauf des Fensters fail-closed abgewiesen, ohne bestehende Benutzerlimits zu
verdraengen. Wenn `DATABASE_URL` gesetzt und Migration
`0023_rust_security_runtime_state` angewendet ist, liegt dieser Zustand in der
Datenbank und ist damit fuer mehrere Backend-Instanzen gemeinsam nutzbar. Ohne
Security-Store faellt ISCY fuer lokale Entwicklung auf einen Prozessspeicher
zurueck. Die Fehlermeldung bleibt generisch und liefert keine Benutzerexistenz
zurueck. Betreiber sollten weiterhin Reverse-Proxy-, WAF- oder SIEM-Regeln fuer
IP- und Geo-Anomalien nutzen.

Der historische passwortlose `tenant_id`-/`user_id`-Kompatibilitaetspfad ist
ausschliesslich im Modus `development` verfuegbar. `demo` und `production`
verlangen Benutzername/Passwort oder eine bereits gueltige serverseitige
Session. In Nicht-Development-Modi werden `x-iscy-*`-Identitaetsheader nur
akzeptiert, wenn sowohl Header-Trust als auch eine explizite Trusted-Proxy-
Grenze konfiguriert sind. Manipulierte IDs erzeugen keine Session; interne
Session-Store-Fehler werden als stabile Fehlerklasse ohne SQL-/Tabellendetails
ausgegeben.

## Alertmanager HMAC

Zusätzlich zum Bearer-Token kann der Operations-Webhook HMAC-Signaturen erzwingen:

```text
ISCY_ALERTMANAGER_HMAC_SECRET_FILE=/run/secrets/iscy_alertmanager_hmac_secret
ISCY_ALERTMANAGER_HMAC_MAX_AGE_SECONDS=300
```

Der Client signiert `timestamp.body` mit HMAC-SHA256 und sendet:

```text
x-iscy-alert-timestamp: <unix-epoch-seconds>
x-iscy-alert-signature: sha256=<hex-hmac>
x-iscy-alert-nonce: <optionaler-eindeutiger-request-wert>
```

Fuer Rotation kann temporaer `ISCY_ALERTMANAGER_HMAC_PREVIOUS_SECRET_FILE` gesetzt werden. Wenn der Security-Store aktiv ist, speichert ISCY verwendete Nonces im Replay-Fenster. Fehlt `x-iscy-alert-nonce`, wird die Kombination aus Timestamp und Signatur als Nonce-Schluessel genutzt.

## Agent-Policy-Webhooks

Agent-Notification-Kanaele duerfen produktiv nur auf explizit erlaubte Hosts
zeigen. Betreiber setzen beispielsweise:

```text
ISCY_NOTIFICATION_WEBHOOK_ALLOWED_HOSTS=soc-webhook.example.org
ISCY_NOTIFICATION_ALLOW_HTTP=0
ISCY_AGENT_NOTIFICATION_SECRET=<secret>
```

Der Kanal speichert bei Bearer- oder HMAC-Authentisierung ausschliesslich
`ISCY_AGENT_NOTIFICATION_SECRET` als Referenz, nicht den Wert. Andere
Environment-Variablen werden beim Speichern und erneut vor der Secret-Aufloesung
abgewiesen. HTTPS ist der Standard, URL-Zugangsdaten und Redirects sind gesperrt.
Die Host-Allowlist wird beim Speichern und erneut bei jeder Zustellung geprueft.
Die Production-Erkennung beruecksichtigt `ISCY_APP_MODE`, `ISCY_ENV` und
`APP_ENV`. Transiente
Verbindungs-/Timeoutfehler und ausgewaehlte HTTP-Status werden begrenzt erneut
versucht; Cooldown und Delivery-Audit reduzieren Doppelmeldungen und halten das
Ergebnis nachvollziehbar. DNS-/Netzwerk-Egress sollte zusaetzlich auf
Infrastrukturebene beschraenkt werden.

## Restore-Drills

`make rust-restore-smoke` prueft lokal SQLite plus Media-Dateien als zusammengehoerige Evidence-Einheit. Der Drill erzeugt einen Evidence-Upload ueber die Rust-API, restauriert Datenbank und Media-Verzeichnis, liest den Dateipfad aus der restaurierten Evidence-Zeile und vergleicht die SHA-256-Pruefsumme vor und nach dem Restore. Fuer PostgreSQL gibt es einen optionalen Drill gegen zwei wegwerfbare Testdatenbanken:

```bash
ISCY_POSTGRES_RESTORE_DRILL_SOURCE_URL=postgresql://isms:<password>@localhost:5432/iscy_drill_source \
ISCY_POSTGRES_RESTORE_DRILL_RESTORE_URL=postgresql://isms:<password>@localhost:5432/iscy_drill_restore \
nix develop --command make rust-postgres-restore-drill
```

Der Drill initialisiert die Source-Datenbank mit Demo-Daten, erzeugt einen `pg_dump`, leert das Restore-Ziel, spielt den Dump ein und validiert anschliessend die Migrationstabelle.

Der getrennte Kompatibilitaetstest `make postgresql-18-compatibility` validiert
zusaetzlich einen logischen Forward-Restore von einer isolierten
PostgreSQL-16-Quelle in eine frische PostgreSQL-18-Zielinstanz. PostgreSQL 16
bleibt der Standard. Insbesondere darf das PG16-Volumeziel
`/var/lib/postgresql/data` niemals durch PostgreSQL 18 geoeffnet werden; der
PG18-Pfad mountet ein eigenes Volume auf `/var/lib/postgresql` und verwendet
`/var/lib/postgresql/18/docker` als PGDATA. Betriebsablauf, Integritaetschecks
und die Rollback-Grenze stehen in `docs/POSTGRESQL_18_COMPATIBILITY.md`.

## Evidence-Integritaet und Lifecycle

Migration `0024_rust_evidence_lifecycle` persistiert fuer Evidence Items Version, Vorgaenger, SHA-256, Gueltigkeit, Aufbewahrungsdatum/-begruendung und Schutzklasse. Der Datei-Hash wird beim Upload serverseitig aus den empfangenen Bytes berechnet. Versionsvorgaenger werden tenantgebunden validiert; ein Vorgaenger darf nur einen direkten Nachfolger besitzen. Die Quality-Queue und Betriebszentrale melden abgelaufene, bald ablaufende und zur Retention-Pruefung faellige Nachweise.

SHA-256 belegt Dateiintegritaet, ersetzt aber weder eine digitale Signatur noch einen vertrauenswuerdigen Zeitstempel. Produktive Betreiber muessen Aufbewahrungsfristen fachlich festlegen; ISCY codiert bewusst keine universelle gesetzliche Frist. Legal Hold, Freigabe zur Loeschung und periodische Re-Hash-Pruefung bleiben als naechste Haertungsstufe dokumentiert.

## Security Header

ISCY setzt zentral:

- `Content-Security-Policy`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: no-referrer`
- `Permissions-Policy`
- `X-Frame-Options: DENY`
- `Cache-Control: no-store, max-age=0`
- optional `Strict-Transport-Security`

`unsafe-eval` wird nicht verwendet. `unsafe-inline` bleibt fuer Styles dokumentiert, weil die bestehende Rust-Web-UI CSS inline rendert.

## Betriebssignale

Die Hardening-Lage ist sichtbar in:

- `/status/`
- `/status/operations.json`
- `/metrics`

Prometheus-Metriken beginnen mit:

```text
iscy_operations_security_flag
```

## Bekannte Grenzen

- Ohne konfigurierten Security-Store fallen Login-Rate-Limits und HMAC-Nonce-Erkennung auf Einzelprozess-/Timestamp-Schutz zurueck.
- Der PostgreSQL-Restore-Drill nutzt wegwerfbare Testdatenbanken; produktive Restore-Prozesse muessen je Umgebung mit echten Backup-Speichern, RPO/RTO und Freigaben erprobt werden.
- S3-kompatible Evidence-Backends koennen ueber den begrenzten Evidence-Worker und manuelle Restore-Pruefungen validiert werden; ein produktiver periodischer Scheduler sowie betreiberspezifische RPO-/RTO-Nachweise bleiben Umgebungsaufgabe.

## S3-kompatibler Evidence-Storage

Produktive Backends muessen `https://` verwenden und duerfen weder lokale,
private, Link-Local-, CGNAT-, `.local`- noch Metadata-Service-Ziele aufloesen.
ISCY revalidiert DNS vor jeder Operation, deaktiviert Redirects und
Proxy-Autodiscovery und verwendet keine AWS-Profile, SSO-, Home-Verzeichnis-
oder EC2-/ECS-Metadata-Credentials.

Zugangsdaten werden nur ueber explizite Referenzen konfiguriert:

```text
env:ISCY_EVIDENCE_OBJECT_STORAGE_ACCESS_KEY
env:ISCY_EVIDENCE_OBJECT_STORAGE_SECRET_KEY
env:ISCY_EVIDENCE_OBJECT_STORAGE_SESSION_TOKEN
```

Jedes Credential-Feld ist auf seine zugehoerige dedizierte Variable und deren
`_FILE`-Variante begrenzt. Direkte `file:`-Referenzen und andere
Prozessvariablen sind nicht zulaessig, damit eine Backend-Konfiguration keine
fachfremden Runtime-Secrets aufloesen kann. Secret-Dateien duerfen maximal
16 KiB gross sein und keine Lese-/Schreib-/Ausfuehrungsrechte fuer Gruppe oder
Andere besitzen. Werte werden pro Operation aufgeloest, nicht persistiert und
nicht protokolliert. Production Compose verwendet die expliziten Variablen
`ISCY_EVIDENCE_OBJECT_STORAGE_ACCESS_KEY_FILE`,
`ISCY_EVIDENCE_OBJECT_STORAGE_SECRET_KEY_FILE` und optional
`ISCY_EVIDENCE_OBJECT_STORAGE_SESSION_TOKEN_FILE`.

`ISCY_EVIDENCE_ALLOW_LOCAL_TEST_ENDPOINT=true` ist ausschliesslich fuer den
Development-Modus und lokales MinIO vorgesehen. In Production bleibt die
Ausnahme wirkungslos. Vor dem produktiven Einsatz sind ein eigener
Live-Validation-Lauf, ein Upload-/Download-Test, eine Restore-Pruefung, ein
freigegebener Disposition-Test und die Aufnahme in das betriebliche RPO-/RTO-
Verfahren erforderlich.

## Performance-, Readiness- und Mehrinstanz-Haertung

ISCY trennt die Systempruefungen bewusst:

- `/health/live` meldet ausschliesslich, dass der Prozess lebt.
- `/health/ready` liefert nur bei erreichbarer Datenbank, vollstaendig
  angewendeten Migrationen und aktiver Request-Annahme HTTP 200.
- `/health/startup` liefert eine zufaellige nicht sensitive Instanz-ID und den
  Startzeitpunkt, aber keine Hostnamen, IPs, Pfade oder Connection Strings.

Readiness-Fehler verwenden sichere Klassen wie `database_unavailable`,
`migrations_incomplete` oder `shutdown_in_progress`. SIGINT/SIGTERM schalten
Readiness ab und starten einen begrenzten Graceful Shutdown. Der Timeout wird
mit `ISCY_SHUTDOWN_TIMEOUT_SECONDS` konfiguriert, auf 5 bis 120 Sekunden
begrenzt und betraegt standardmaessig 30 Sekunden.

PostgreSQL-Migrationen werden durch einen Advisory Lock serialisiert. Der Lock
wartet maximal 60 Sekunden und ersetzt keine kontrollierte Deployment-
Reihenfolge. SQLite ist weiterhin ausschliesslich fuer Single-Instance-Betrieb
vorgesehen.

Der technische Zwei-Instanzen-Test verwendet PostgreSQL 16, S3-kompatibles
MinIO, zwei Backend-Instanzen und nginx 1.31. `local_filesystem` wird nicht als
HA-faehig dargestellt. PostgreSQL, MinIO und nginx bleiben in dieser
Testtopologie jeweils Single Points of Failure; Multi-Region-, Cluster- und
SLA-Aussagen sind daraus nicht ableitbar.

Die Stage-, Production- und HA-Pfade verwenden konsistent
`nginx:1.31-alpine`. Die bestehende Proxy-Konfiguration wird mit `nginx -t`,
Reverse-Proxy-Smoke, Upload-/Download-Pruefung und beidseitigem Failover
validiert. Trusted-Proxy-, Forwarded-Header- und Evidence-Grenzen bleiben
unveraendert; es wird kein Container-Image veroeffentlicht.

Ausfuehrung und Grenzen sind in
`docs/PERFORMANCE_HA_VISUAL_TESTING.md` dokumentiert.

## Rust-Toolchain-Pfade

Die aktuelle CI-, Clippy-, Test- und Produkt-Build-Spur verwendet exakt Rust
`1.97.0`. Der gehärtete Produkt-Builder prueft die Compiler-Version vor dem
Locked Release-Build fail-closed. Die deklarierte MSRV bleibt Rust `1.88.0`
und wird in der verpflichtenden CI-Aggregation durch `cargo check --all-targets`
sowie `cargo test --no-run` mit Rust 1.88 abgesichert.

Der portable Release-Builder bleibt bewusst auf dem bestehenden
digest-gepinnten Rust-1.88-Bookworm-Image. Die Nix-Toolchain stammt aus dem auf
Commit `21ea275a7c46aef9d4d6ddc962e6d562e9d94183` gepinnten
`nixos-26.05`-Flake und liefert Rust `1.95.0`. V23.7.32 aktualisiert
kontrolliert die direkte `base64`-Abhaengigkeit und einzelne Lockfile-
Aufloesungen. Dazu gehoert `event-listener 5.4.2`, das
`RUSTSEC-2026-0221` im vorhandenen SQLx-Graph ohne neue Ignore-Regel behebt.
Die Pflege hebt weder Paketversion noch MSRV an und fuegt keine Git-Dependency
oder neue Lizenzfreigabe hinzu.

## Release-Candidate-Prüfung

`make release-candidate-check` fasst die lokale Pflichtmatrix zusammen und
veroeffentlicht keine Artefakte. Der Aufruf bricht bei fehlenden Werkzeugen,
fehlenden Wegwerf-PostgreSQL-URLs oder einem Testfehler ab. Die GitHub-CI nutzt
weiterhin elf zeitbegrenzte Aggregationsabhaengigkeiten fuer Secret-Scan,
Rust, MSRV, Bootstrap, Nix, MinIO, Performance, HA/PostgreSQL 18, Visual
Regression, Docker und das portable Linux-Binary. Codex-Automation ist ein
zusaetzlicher separater CI-Nachweis. Der abschliessende Aggregationsjob prueft
den Erfolg seiner Abhaengigkeiten sowie Manifest, Checksums, 45 Migrationen,
42 Baselines, Dokumentationsreferenzen, den wertredigierten Sensitive-Data-
Scan und den exakten V23.7.31-Tag. CodeQL fuer Actions,
JavaScript/TypeScript und Rust bleibt ein separater Pflichtnachweis.

`make release-binary-gate` erzeugt das Release-Binary zweimal cachefrei in
einem digest-gepinnten Rust-1.88-Bookworm-Builder unter `/usr/src/iscy`.
Cargo-Registry-Pfade werden auf neutrale Praefixe abgebildet, Release-Debuginfo
und inkrementeller Build sind deaktiviert und Symbole werden kontrolliert
gestrippt. Beide Builds muessen byteidentisch sein. Das finale
`linux-x86_64-glibc`-Binary darf keine lokalen Home-, temporaeren Worktree-,
Runner- oder Nix-Store-Pfade und weder RPATH noch RUNPATH enthalten. Erlaubt
ist nur ein regulaerer x86_64-glibc-Systeminterpreter.
Die dynamischen Laufzeitabhaengigkeiten sind auf `libgcc_s.so.1`, `libm.so.6`,
`libc.so.6` und `ld-linux-x86-64.so.2` begrenzt und werden im Release-Manifest
festgehalten.

Der Portabilitaetstest verwendet einen digest-gepinnten
Debian-Bookworm-Slim-Container ohne Nix, Rust, Cargo und Compiler. Er prueft
`ldd`, CLI-Start, SQLite-Initialisierung, `/health/live`, Log-Hygiene und
Graceful Shutdown. Das belegt den dokumentierten Bookworm-/glibc-Pfad, nicht
die Ausfuehrbarkeit auf jeder Linux-Distribution oder Architektur. Das Binary,
SBOM und Checksummen bleiben unsigniert; der Test veroeffentlicht weder Assets
noch Container.

Release-Artefakte unter `artifacts/release-candidate/` sind lokal, unsigniert
und nicht veroeffentlicht. Eine produktive Signatur oder SBOM wird nicht
vorgetaeuscht; Status und bekannte Grenzen stehen in
`docs/RELEASE_CANDIDATE_CHECKLIST.md`.
