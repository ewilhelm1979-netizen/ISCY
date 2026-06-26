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

Lokale Username-/Passwort-Logins werden pro Prozess und pro Tenant/Username begrenzt. Nach fuenf fehlgeschlagenen Versuchen in 15 Minuten blockiert ISCY weitere Versuche fuer 15 Minuten. Die Fehlermeldung bleibt generisch und liefert keine Benutzerexistenz zurueck. Betreiber sollten weiterhin Reverse-Proxy-, WAF- oder SIEM-Regeln fuer IP- und Geo-Anomalien nutzen.

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
```

Fuer Rotation kann temporaer `ISCY_ALERTMANAGER_HMAC_PREVIOUS_SECRET_FILE` gesetzt werden.

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

- Das Login-Rate-Limit ist pro Prozess und nicht clusterweit synchronisiert.
- Der HMAC-Replay-Schutz nutzt ein Timestamp-Fenster; Nonce-Persistenz ist noch nicht umgesetzt.
- Der Restore-Smoke deckt SQLite/Media lokal ab; produktive PostgreSQL-/Objektspeicher-Drills muessen pro Umgebung geplant werden.
