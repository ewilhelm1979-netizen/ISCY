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

- Login-Rate-Limiting ist noch offener Phase-1-Punkt.
- HMAC/Replay-Schutz fuer Webhooks ist noch offener Phase-1-Punkt.
- Automatisierte Restore-Smoke-Tests sind noch offener Phase-1-Punkt.
- Admin-Erstinitialisierung ohne Demo-Seed ist noch offener Phase-1-Punkt.
