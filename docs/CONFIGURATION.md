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
| `ISCY_ALERTMANAGER_HMAC_SECRET` | Optionales HMAC-Secret fuer Alertmanager | nein | leer | starkes Secret | Signiert `timestamp.body` und reduziert Spoofing-/Replay-Risiko | ja, `ISCY_ALERTMANAGER_HMAC_SECRET_FILE` |
| `ISCY_ALERTMANAGER_HMAC_PREVIOUS_SECRET` | Altes HMAC-Secret fuer Rotation | nein | leer | starkes Secret | Erlaubt kurze Secret-Rotation ohne Monitoring-Ausfall | ja, `ISCY_ALERTMANAGER_HMAC_PREVIOUS_SECRET_FILE` |
| `ISCY_ALERTMANAGER_HMAC_MAX_AGE_SECONDS` | Replay-Fenster fuer HMAC-Timestamps | nein | `300` | positive Sekunden | Alte oder weit zukuenftige Signaturen werden abgewiesen | nein |
| `ISCY_AGENT_NOTIFICATION_INTERVAL_SECONDS` | Agent-Policy-Notification-Worker | nein | `300` | `0` oder mindestens 60 Sekunden | `0` deaktiviert; kleinere positive Werte werden auf 60 Sekunden begrenzt | nein |
| `ISCY_NOTIFICATION_ALLOW_HTTP` | Erlaubt HTTP-Webhookziele ausser Loopback | nein | `0` | `0/1`, `true/false` | Nur fuer kontrollierte Entwicklungsnetze; Production sollte HTTPS nutzen | nein |
| `ISCY_NOTIFICATION_WEBHOOK_ALLOWED_HOSTS` | Production-Allowlist fuer Notification-Ziele | Production bei aktivem Kanal: ja | leer | kommaseparierte exakte Hostnamen | Verhindert freie serverseitige Webhook-Ziele; Redirects bleiben deaktiviert | nein |
| `ISCY_INITIAL_ADMIN_TENANT_NAME` | Tenant-Name fuer `init-admin` | fuer `init-admin` empfohlen | `ISCY Production Tenant` | Text | Erstzugang ohne Demo-Seed | nein |
| `ISCY_INITIAL_ADMIN_TENANT_SLUG` | Tenant-Slug fuer `init-admin` | fuer `init-admin` empfohlen | `iscy-production` | Kleinbuchstaben, Zahlen, Bindestrich | Eindeutige Mandantenkennung | nein |
| `ISCY_INITIAL_ADMIN_USERNAME` | Initialer Admin-Username | fuer `init-admin` empfohlen | `iscy-admin` | Text | Wird nicht ueberschrieben, wenn aktiver Admin existiert | nein |
| `ISCY_INITIAL_ADMIN_EMAIL` | Initiale Admin-E-Mail | fuer `init-admin` empfohlen | `iscy-admin@example.local` | E-Mail/Text | Kontaktadresse des Erstadmins | nein |
| `ISCY_INITIAL_ADMIN_FIRST_NAME` | Initialer Admin-Vorname | nein | `ISCY` | Text | Anzeigeprofil des Erstadmins | nein |
| `ISCY_INITIAL_ADMIN_LAST_NAME` | Initialer Admin-Nachname | nein | `Admin` | Text | Anzeigeprofil des Erstadmins | nein |
| `ISCY_INITIAL_ADMIN_PASSWORD` | Initiales Admin-Passwort | fuer `init-admin` ja | keine | mind. 14 Zeichen, kein Beispielwert | Erzeugt ersten Admin ohne Demo-Zugangsdaten | ja, `ISCY_INITIAL_ADMIN_PASSWORD_FILE` |
| `ISCY_POSTGRES_RESTORE_DRILL_SOURCE_URL` | Disposable PostgreSQL-Quelle fuer Restore-Drill | nur fuer Drill | leer | PostgreSQL-URL | Wird durch `make rust-postgres-restore-drill` mit Demo-Daten initialisiert | nein |
| `ISCY_POSTGRES_RESTORE_DRILL_RESTORE_URL` | Disposable PostgreSQL-Ziel fuer Restore-Drill | nur fuer Drill | leer | PostgreSQL-URL | Ziel-Schema wird beim Drill geloescht und aus Dump wiederhergestellt | nein |
| `NVD_API_BASE_URL` | Optionale NVD-Quelle | nein | NVD Default | URL | Externe Verbindung nur bei aktivem CVE-Abgleich | nein |
| `NVD_API_KEY` | Optionaler NVD API Key | nein | leer | Secret | Darf nicht in Logs oder Supportpaketen landen | ja, noch nicht fuer alle Callpaths |

## Secret-Dateien

Fuer Container, NixOS und systemd koennen `*_FILE`-Varianten auf gemountete Secret-Dateien zeigen. Der direkte Env-Wert hat Vorrang, danach wird die Datei gelesen. Secrets duerfen nicht ins Repository, in Logs, Metriken oder Supportpakete geschrieben werden.

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
ISCY_ALERTMANAGER_HMAC_SECRET_FILE=/run/secrets/iscy-alertmanager-hmac
ISCY_AGENT_NOTIFICATION_INTERVAL_SECONDS=300
ISCY_NOTIFICATION_ALLOW_HTTP=0
ISCY_NOTIFICATION_WEBHOOK_ALLOWED_HOSTS=soc-webhook.example.org
ISCY_AGENT_NOTIFICATION_SECRET=<strong-channel-secret>
ISCY_INITIAL_ADMIN_PASSWORD_FILE=/run/secrets/iscy-initial-admin-password
```

Ein Agent-Notification-Kanal speichert fuer Bearer oder HMAC nur den Namen der
Secret-Variable, beispielsweise `ISCY_AGENT_NOTIFICATION_SECRET`, nie den
Secret-Wert. Die referenzierte Variable muss im Backend-Prozess gesetzt sein.

Identity-Header duerfen produktiv nur aktiviert werden, wenn der Reverse Proxy eingehende `x-iscy-tenant-id`, `x-iscy-user-id`, `x-iscy-user-email`, `x-iscy-roles`, `x-iscy-is-staff` und `x-iscy-is-superuser` immer entfernt und nur selbst neu setzt.

## Initial-Admin ohne Demo-Seed

Produktive Systeme sollten mit Migrationen und einem eigenen Initial-Admin starten:

```bash
DATABASE_URL=postgresql://isms:<strong-password>@db:5432/isms \
ISCY_INITIAL_ADMIN_PASSWORD_FILE=/run/secrets/iscy-initial-admin-password \
nix run .#iscy-backend -- init-admin
```

`init-admin` fuehrt Migrationen aus, legt bei Bedarf einen Tenant und einen aktiven Admin an und seedet keine Demo-Daten.

## Restore-Drills

Der lokale Standard-Smoke startet eine isolierte Rust-Instanz, legt einen echten Evidence-Upload an und restauriert SQLite-Datenbank plus Media-Verzeichnis. Der Drill prueft anschliessend, ob die restaurierte Evidence-Zeile denselben Dateipfad referenziert und ob die SHA-256-Pruefsumme der Datei unveraendert ist:

```bash
nix develop --command make rust-restore-smoke
```

Fuer PostgreSQL kann ein Drill gegen zwei wegwerfbare Testdatenbanken aktiviert werden. Das Ziel-Schema wird geloescht.

```bash
ISCY_POSTGRES_RESTORE_DRILL_SOURCE_URL=postgresql://isms:<password>@localhost:5432/iscy_drill_source \
ISCY_POSTGRES_RESTORE_DRILL_RESTORE_URL=postgresql://isms:<password>@localhost:5432/iscy_drill_restore \
nix develop --command make rust-postgres-restore-drill
```
