# Production Hardening

ISCY Community startet in Production nur, wenn die wichtigsten Sicherheitsannahmen explizit erfuellt sind.

## Startbremse

`ISCY_APP_MODE=production` aktiviert den Production-Preflight. Der Start wird abgebrochen, wenn:

- `DATABASE_URL` fehlt oder ein nicht unterstuetztes Schema nutzt,
- `DATABASE_URL` Beispielwerte wie `change-me` enthaelt,
- `RUST_BACKEND_BIND` oeffentlich lauscht und kein Trusted Proxy bestaetigt ist,
- Identity-Header vertraut werden sollen, aber kein Trusted Proxy bestaetigt ist,
- `ISCY_SECURE_COOKIES` deaktiviert ist,
- HSTS ohne bestaetigtes HTTPS aktiv ist,
- `ISCY_ALERTMANAGER_TOKEN` bzw. `ISCY_ALERTMANAGER_TOKEN_FILE` fehlt oder schwach ist,
- bekannte Demo-Zugangsdaten noch aktiv sind,
- Demo-Seeding im Production-Modus gestartet wird.

## Initialer Admin

Produktive Erstinitialisierung erfolgt ohne Demo-Seed:

```bash
ISCY_APP_MODE=production \
DATABASE_URL=postgresql://isms:<strong-password>@db:5432/isms \
ISCY_INITIAL_ADMIN_PASSWORD_FILE=/run/secrets/iscy-initial-admin-password \
nix run .#iscy-backend -- init-admin
```

Der Command fuehrt Migrationen aus, legt falls noetig einen Tenant an, erzeugt die Basisrollen `ADMIN`, `CONTRIBUTOR` und `AUDITOR` und erstellt einen aktiven Superuser/Admin. Existiert der Username bereits als aktiver Admin, bleibt der Account unveraendert. Existiert der Username ohne Admin-Rechte, bricht der Command ab.

## Login-Schutz

Lokale Username-/Passwort-Logins werden pro Tenant/Username begrenzt. Nach fuenf fehlgeschlagenen Versuchen in 15 Minuten blockiert ISCY weitere Versuche fuer 15 Minuten. Wenn `DATABASE_URL` gesetzt und Migration `0023_rust_security_runtime_state` angewendet ist, liegt dieser Zustand in der Datenbank und ist damit fuer mehrere Backend-Instanzen gemeinsam nutzbar. Ohne Security-Store faellt ISCY fuer lokale Entwicklung auf einen Prozessspeicher zurueck. Die Fehlermeldung bleibt generisch und liefert keine Benutzerexistenz zurueck. Betreiber sollten weiterhin Reverse-Proxy-, WAF- oder SIEM-Regeln fuer IP- und Geo-Anomalien nutzen.

## Alertmanager HMAC

Zusätzlich zum Bearer-Token kann der Operations-Webhook HMAC-Signaturen erzwingen:

```text
ISCY_ALERTMANAGER_HMAC_SECRET_FILE=/run/secrets/iscy-alertmanager-hmac
ISCY_ALERTMANAGER_HMAC_MAX_AGE_SECONDS=300
```

Der Client signiert `timestamp.body` mit HMAC-SHA256 und sendet:

```text
x-iscy-alert-timestamp: <unix-epoch-seconds>
x-iscy-alert-signature: sha256=<hex-hmac>
x-iscy-alert-nonce: <optionaler-eindeutiger-request-wert>
```

Fuer Rotation kann temporaer `ISCY_ALERTMANAGER_HMAC_PREVIOUS_SECRET_FILE` gesetzt werden. Wenn der Security-Store aktiv ist, speichert ISCY verwendete Nonces im Replay-Fenster. Fehlt `x-iscy-alert-nonce`, wird die Kombination aus Timestamp und Signatur als Nonce-Schluessel genutzt.

## Restore-Drills

`make rust-restore-smoke` prueft lokal SQLite plus Media-Dateien als zusammengehoerige Evidence-Einheit. Der Drill erzeugt einen Evidence-Upload ueber die Rust-API, restauriert Datenbank und Media-Verzeichnis, liest den Dateipfad aus der restaurierten Evidence-Zeile und vergleicht die SHA-256-Pruefsumme vor und nach dem Restore. Fuer PostgreSQL gibt es einen optionalen Drill gegen zwei wegwerfbare Testdatenbanken:

```bash
ISCY_POSTGRES_RESTORE_DRILL_SOURCE_URL=postgresql://isms:<password>@localhost:5432/iscy_drill_source \
ISCY_POSTGRES_RESTORE_DRILL_RESTORE_URL=postgresql://isms:<password>@localhost:5432/iscy_drill_restore \
nix develop --command make rust-postgres-restore-drill
```

Der Drill initialisiert die Source-Datenbank mit Demo-Daten, erzeugt einen `pg_dump`, leert das Restore-Ziel, spielt den Dump ein und validiert anschliessend die Migrationstabelle.

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
- Objektspeicher-/S3-artige Evidence-Backends sind noch nicht Teil des automatischen Restore-Drills.
