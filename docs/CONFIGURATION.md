# ISCY Configuration

ISCY Community wird lokal und auf eigener Infrastruktur betrieben. Production darf nicht mit Demo- oder Entwicklungsannahmen starten.

## Betriebsmodi

| Variable | Zweck | Erforderlich | Sicherer Standard | Gueltige Werte | Sicherheitsauswirkung | Secret-Datei |
| --- | --- | --- | --- | --- | --- | --- |
| `ISCY_APP_MODE` | Betriebsmodus | Production: ja | `development` | `development`, `demo`, `production` | Steuert Preflight, Cookie- und Header-Grenzen | nein |
| `DATABASE_URL` | Datenbankverbindung | Production: ja | keine | `sqlite:*`, `postgres://*`, `postgresql://*` | Beispielwerte werden in Production abgewiesen | nein |
| `RUST_BACKEND_BIND` | Bind-Adresse | nein | `127.0.0.1:9000` | Socket-Adresse | `0.0.0.0` verlangt in Production einen bestaetigten Reverse Proxy | nein |
| `ISCY_MEDIA_ROOT` | Evidence-/Upload-Speicher | nein | `media` | Pfad | Muss durch Betreiber gesichert, gesichert und wiederherstellbar sein | nein |
| `ISCY_TRUST_PROXY_IDENTITY_HEADERS` | Akzeptiert `x-iscy-*` Identity-Header | nein | Production: `0` | `0/1`, `true/false` | Nur aktivieren, wenn ein vertrauenswuerdiger Proxy eingehende gleichnamige Client-Header entfernt | nein |
| `ISCY_TRUSTED_PROXY_CONFIGURED` | Proxy-Vertrauensgrenze bestaetigt | Production bei Public Bind: ja | `0` | `0/1`, `true/false` | Erlaubt Production-Bind auf `0.0.0.0` und optionales Header-Vertrauen | nein |
| `ISCY_SECURE_COOKIES` | Setzt Session-Cookie mit `Secure` | Production: ja | Production: `1` | `0/1`, `true/false` | Verhindert Session-Cookie ueber unsicheres HTTP | nein |
| `ISCY_HTTPS_CONFIRMED` | HTTPS ist fuer Nutzerzugriff bestaetigt | fuer HSTS: ja | `0` | `0/1`, `true/false` | Voraussetzung fuer HSTS | nein |
| `ISCY_HSTS_ENABLED` | Aktiviert `Strict-Transport-Security` | nein | `0` | `0/1`, `true/false` | Darf nur nach bestaetigtem HTTPS aktiv sein | nein |
| `ISCY_ALERTMANAGER_TOKEN` | Webhook-Secret | Production: ja | keine | starkes Secret, mind. 24 Zeichen | Schuetzt Alertmanager-Webhook | ja, `ISCY_ALERTMANAGER_TOKEN_FILE` |
| `NVD_API_BASE_URL` | Optionale NVD-Quelle | nein | NVD Default | URL | Externe Verbindung nur bei aktivem CVE-Abgleich | nein |
| `NVD_API_KEY` | Optionaler NVD API Key | nein | leer | Secret | Darf nicht in Logs oder Supportpaketen landen | ja, noch nicht fuer alle Callpaths |

## Secret-Dateien

Fuer Container, NixOS und systemd kann `ISCY_ALERTMANAGER_TOKEN_FILE` auf eine gemountete Secret-Datei zeigen. Der direkte Env-Wert hat Vorrang, danach wird die Datei gelesen. Secrets duerfen nicht ins Repository, in Logs, Metriken oder Supportpakete geschrieben werden.

## Production-Minimum

```bash
ISCY_APP_MODE=production
DATABASE_URL=postgresql://isms:<strong-password>@db:5432/isms
RUST_BACKEND_BIND=0.0.0.0:9000
ISCY_TRUSTED_PROXY_CONFIGURED=1
ISCY_TRUST_PROXY_IDENTITY_HEADERS=0
ISCY_SECURE_COOKIES=1
ISCY_HTTPS_CONFIRMED=1
ISCY_HSTS_ENABLED=1
ISCY_ALERTMANAGER_TOKEN_FILE=/run/secrets/iscy-alertmanager-token
```

Identity-Header duerfen produktiv nur aktiviert werden, wenn der Reverse Proxy eingehende `x-iscy-tenant-id`, `x-iscy-user-id`, `x-iscy-user-email`, `x-iscy-roles`, `x-iscy-is-staff` und `x-iscy-is-superuser` immer entfernt und nur selbst neu setzt.
