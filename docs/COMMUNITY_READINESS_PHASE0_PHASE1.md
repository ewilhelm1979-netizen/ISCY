# ISCY Community Readiness - Phase 0/1 Bericht

Status: READY WITH DOCUMENTED LIMITATIONS

Dieser Bericht dokumentiert den ersten Community-Readiness-Lauf fuer Phase 0 und das erste P0-Paket aus Phase 1. Ziel war keine Big-Bang-Haertung, sondern eine belastbare Startbremse fuer produktionskritische Fehlkonfigurationen.

## Gepruefter Stand

- Repository: `ewilhelm1979-netizen/ISCY`
- Branch fuer diesen Lauf: `hardening/community-readiness`
- Ausgangsstand: `fbc4c4b`
- ISCY Release-Basis: `v23.7.24`
- Rust Backend: `0.3.20`
- Runtime: Rust-only Axum Backend

## Findings

| ID | Komponente | Risiko | Angriffsweg | Prioritaet | vorhandene Kontrolle | fehlende Kontrolle | Mitigation | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| CR-001 | Runtime-Konfiguration | Unsichere Demo-/Dev-Annahmen koennen produktiv starten | Betreiber startet mit `0.0.0.0`, Demo-Daten oder Beispiel-Secrets | P0 | Rust-only Startskripte, Demo-Seed getrennt als Command | Zentrale Production-Preflight-Pruefung | `ISCY_APP_MODE=production` blockiert unsichere Defaults, Demo-Seeding und Beispielwerte | Unit-/HTTP-Tests, Rust-Smoke |
| CR-002 | Identity-Header | Mandant, User oder Rollen koennen von normalen Clients manipuliert werden | Client sendet `x-iscy-user-id` oder `x-iscy-roles` direkt an Backend | P0 | Fachrouten pruefen Tenant/User-Kontext serverseitig | Vertrauensgrenze fuer Header-Kontext nicht zentral | Production blockiert `x-iscy-*` Identity-Header, ausser Trusted Proxy ist explizit konfiguriert | Negativtest `production_mode_blocks_untrusted_identity_headers` |
| CR-003 | Sessions | Cookies waeren in Production ohne `Secure` betreibbar | Session-Cookie wird ueber HTTP oder falsch terminierte Proxy-Strecke gesendet | P1 | `HttpOnly`, `SameSite=Lax`, DB-Session-Store | Production-Pflicht fuer `Secure` | `ISCY_SECURE_COOKIES=1` wird im Production-Preflight erzwungen | Cookie-Regression offen |
| CR-004 | Webhook-Secret | Alertmanager-Webhook waere ohne Token produktiv erreichbar | Dritter sendet Alerts und erzeugt Operations-Artefakte | P0 | Optionaler Token-Schutz vorhanden | Production-Pflicht und Secret-Datei-Unterstuetzung fehlte zentral | `ISCY_ALERTMANAGER_TOKEN` oder `_FILE` wird in Production verlangt | Token-Tests offen |
| CR-005 | HTTP-Sicherheitsheader | Browser-Schutz haengt von Proxy-Konfiguration ab | Clickjacking, MIME Sniffing, Referrer-Leaks, zu breite Browser-APIs | P1 | Keine zentrale Header-Schicht | Einheitliche Header-Middleware | CSP, nosniff, Referrer-Policy, Permissions-Policy, X-Frame-Options, Cache-Control, optional HSTS | Test `security_headers_are_added_to_http_responses` |
| CR-006 | Reverse Proxy/TLS | HSTS oder Proxy-Vertrauen kann falsch gesetzt werden | Backend akzeptiert Header ohne saeubernden Proxy oder setzt HSTS ohne HTTPS | P0/P1 | Nginx-/Monitoring-Doku vorhanden | Startbremse fuer widerspruechliche Annahmen | Preflight verlangt `ISCY_TRUSTED_PROXY_CONFIGURED=1` fuer Public Bind und Trusted Identity Header | Preflight-Unit-Tests |

## Umgesetzte Kontrollen

- Neues Rust-Modul `hardening` fuer Community-Security-Konfiguration.
- Eindeutige Modi `development`, `demo`, `production`.
- Production-Preflight vor HTTP-Start.
- Production blockiert `seed-demo` und `init-demo`.
- Production verlangt unter anderem `DATABASE_URL`, nicht-beispielhafte Secrets, sichere Cookies und Alertmanager-Token.
- Production erkennt bekannte Demo-Passwort-Hashes fuer `admin` und `ops-alertmanager`.
- `_FILE`-Secret-Muster fuer `ISCY_ALERTMANAGER_TOKEN_FILE`.
- `init-admin` erzeugt den ersten produktiven Tenant/Admin ohne Demo-Seed und ohne Beispielpasswort.
- Lokales Login-Rate-Limiting blockiert wiederholte Fehlversuche pro Tenant/Username.
- Alertmanager-Webhook unterstuetzt HMAC-SHA256 ueber `timestamp.body` inklusive Zeitfenster und Previous-Secret fuer Rotation.
- `make rust-restore-smoke` prueft einen einfachen SQLite-/Media-Restore lokal automatisiert.
- Zentrale Middleware fuer Security Header.
- Zentrale Deny-by-default-Grenze fuer `x-iscy-*` Identity Header im Production-Profil.
- Security-Signale in `/status/`, `/status/operations.json` und `/metrics`.

## Offene Risiken

- Vollstaendige Tenant-Isolation muss weiterhin routenweise durch Negativtests verdichtet werden.
- Login-Rate-Limiting ist pro Backend-Prozess umgesetzt; fuer mehrere Instanzen sollte ein gemeinsamer Store ergaenzt werden.
- Alertmanager-HMAC nutzt ein Timestamp-Fenster; persistente Nonce-Erkennung fuer strikten Replay-Schutz ist noch offen.
- Der Restore-Smoke deckt lokal SQLite und Media-Dateien ab; PostgreSQL-/Container-Restore-Drills sollten als naechste Betriebsreife-Stufe folgen.

## Empfehlung

Phase 1 ist fuer Community-/Einzelinstanzbetrieb deutlich belastbarer. Naechster fachlicher Schritt vor Phase 2: Tenant-Isolation-Negativtests verdichten, Login-Rate-Limit fuer Clusterbetrieb zentralisieren, HMAC-Nonce-Persistenz ergaenzen und Restore-Drills fuer PostgreSQL/Container automatisieren.
