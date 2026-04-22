# ISCY Rust-Cutover-Status

Stand: 2026-04-22

## Kurzfassung

ISCY ist fachlich weit in Richtung Rust migriert, aber noch nicht sicher Python-frei. Der Rust-Axum-Service ist als Backend direkt startbar, lokale Starts laufen Rust-only, Rust kann eigene Session-Cookies aus Django-kompatiblen Passwort-Hashes oder DB-validierten Tenant-/User-Kontexten ausstellen, liest Rollen aus `accounts_user` und `accounts_userrole`, und erzwingt schreibende Rollen fuer migrierte Write-Flows. Die Rust-Web-Shell ist aktiv und ersetzt die frueheren Platzhalter fuer Dashboard, Risks, Evidence, Reports, Roadmap, Assets und Processes durch serverseitig gerenderte, datengetriebene Seiten. Die Django-Schicht ist aber weiterhin fuer vollstaendige Browser-Workflows, Admin-/User-Management, Form-/Template-Schicht und einen Teil der Datei-/Import-Orchestrierung relevant.

Deshalb ist der finale Loeschschritt fuer Python noch nicht fachlich freigegeben. Python jetzt zu entfernen wuerde die Anwendung nicht abschliessen, sondern zentrale UI- und Betriebsfunktionen abschalten.

## Direkt startbarer Rust-Pfad

Rust-Backend auf NixOS aus dem Repository-Root starten:

```bash
nix run .#iscy-backend
```

Mit expliziter lokaler Konfiguration:

```bash
RUST_BACKEND_BIND=127.0.0.1:9000 DATABASE_URL=sqlite:///db.sqlite3 nix run .#iscy-backend
```

Rust-Demo-Datenbank ohne Django-Migration initialisieren:

```bash
DATABASE_URL=sqlite:///db.sqlite3 nix run .#iscy-backend -- init-demo
```

Healthcheck:

```bash
curl -fsS http://127.0.0.1:9000/health
```

Der lokale Wrapper initialisiert die Rust-Datenbank und startet den Rust-Axum-Service:

```bash
./start.sh
```

Rust-Demo-Login im Browser: `http://127.0.0.1:9000/login/` mit `admin / Admin123!`.

Der alte Django-Runserver ist damit nicht mehr der lokale Standardpfad.

## Bereits nach Rust verschoben

- CVE-/NVD-Normalisierung, Upsert- und Canary-Pfade.
- Lokaler LLM-Endpunkt, Risiko-Priorisierung, Guidance-Auswertung und CVE-Report-Summary.
- Dashboard-, Report-, Catalog-, Requirements-, Asset-, Process- und Assessment-Read-Flows.
- Risk-Register Read-, Detail-, Create- und Update-Flows.
- Evidence Read-/Detail-Flows und Evidence-Need-Sync.
- Rust-Web-Shell mit Kontext-Formular sowie datengetriebenem Dashboard, Risk-Register, Evidence-Ueberblick, Reports, Roadmap, Assets und Processes.
- Rust-DB-Admin-CLI mit `migrate`, `seed-demo` und `init-demo` fuer Rust-eigenen SQLite/PostgreSQL-Bootstrap der operativen Kern-Tabellen inklusive Product-Security sowie vollstaendigem Katalog-/Requirement-Seed.
- Rust-Session-Schicht mit `iscy_auth_session`, `/api/v1/auth/sessions`, `/api/v1/auth/session`, Logout, Cookie/Bearer-Aufloesung, Django-kompatibler `pbkdf2_sha256`-Passwortpruefung und Web-Kontext ohne Query-Parameter.
- Rust-RBAC-Grundlage mit `accounts_role`, `accounts_userrole`, Session-Rollencodes, Header-Rollen-Fallback und Schreibschutz fuer migrierte Write-Endpunkte.
- Rust-first CI mit Rust-Tests, Rust-DB-/HTTP-Smoke und Nix-Rust-App-Smoke.
- `start.sh` startet lokal Rust-only statt Django-runserver.
- Roadmap Liste, Detail, Kanban, Task-Updates und Exportdaten.
- Wizard Start-/Result-Flows.
- Import-Center bestaetigte Importjobs.
- Product-Security Liste, Produktdetail, Roadmap, Task-Updates und Vulnerability-Updates.
- Rust-only-/Strict-Guards fuer migrierte Backend-Schalter.

## Blocker vor Python-Loeschung

1. **Weboberflaeche:** Rust liefert fuer `/dashboard/`, `/risks/`, `/evidence/`, `/reports/`, `/roadmap/`, `/assets/` und `/processes/` bereits echte serverseitige Seiten. Die restlichen Views, Detail-/Form-Flows und Exporte liegen noch in Django-Templates und Django-Views.
2. **Auth, Sessions und Admin:** Rust-Sessions, Passwort-Login und grundlegende Rollen-/Schreibrechte sind vorhanden und werden in Web/API-Kontexten aufgeloest. Admin-Funktionen, User-/Rollenverwaltung und Berechtigungsoberflaechen sind noch nicht vollstaendig durch Rust ersetzt.
3. **Migrations und Seeds:** Ein Rust-eigener Bootstrap fuer operative Kern-Tabellen inklusive Product-Security, Catalog und Requirements ist vorhanden. Einzelne historische Django-Schema-Details ausserhalb dieser Cutover-Slices sind noch nicht vollstaendig abgeloest.
4. **Formulare und Uploads:** Validierung, Form-Flows, Evidence-Dateiuploads sowie CSV/XLSX-Import-Mapping sind noch teilweise Django-orchestriert.
5. **Python-Dateien im Repo:** CI und lokaler Start sind Rust-first. Python/Django-Dateien bleiben noch als Legacy-Kompatibilitaet und muessen nach Abschluss von Auth/Web/Form-Flows gezielt entfernt werden.

## Naechster fachlich sinnvoller Cutover-Schritt

Der naechste Abschlussblock ist nicht mehr ein weiterer einzelner API-Endpunkt, sondern die Web- und Betriebsablösung:

1. Admin-/User-Management und Rollenverwaltung in Rust finalisieren.
2. Django-Templates durch Rust-Web oder ein separates Frontend auf Rust-API ersetzen.
3. Upload-/Import-Dateifluss ohne Django bereitstellen.
4. Python-Dateien, Requirements, Django-Settings und Django-Startpfade entfernen.

## Cutover-Entscheidung

Aktueller Status: **Rust-Backend startbar, produktive Kern-APIs weit migriert, aber kein fachlich sicherer Python-Loeschzeitpunkt.**

Freigabe fuer `apps/`, `config/`, `manage.py`, `requirements*.txt` und Python-CI-Loeschung erst, wenn die oben genannten Blocker ersetzt und die Rust-Weboberflaeche nicht mehr nur Platzhalter ist.
