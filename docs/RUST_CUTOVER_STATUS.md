# ISCY Rust-Cutover-Status

Stand: 2026-04-24

## Kurzfassung

ISCY ist fachlich weit in Richtung Rust migriert, aber noch nicht sicher Python-frei. Der Rust-Axum-Service ist als Backend direkt startbar, lokale Starts laufen Rust-only, Rust kann eigene Session-Cookies aus Django-kompatiblen Passwort-Hashes oder DB-validierten Tenant-/User-Kontexten ausstellen, liest Rollen, Gruppen und Django-kompatible Permissions aus der Rust-DB-Schicht, und erzwingt schreibende Rollen fuer migrierte Write-Flows. Die Rust-Web-Shell ist aktiv und ersetzt die frueheren Platzhalter fuer Dashboard, Risks, Evidence, Reports, Roadmap, Assets, Processes, Imports und User-Administration durch serverseitig gerenderte, datengetriebene Seiten. Die Django-Schicht ist aber weiterhin fuer einzelne komplexe Browser-/Mapping-Flows relevant.

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

Rust-Demo-Login im Browser: `http://127.0.0.1:9000/login/` mit `admin / Admin123!`. Die Rust-Userverwaltung liegt danach unter `http://127.0.0.1:9000/admin/users/` und erlaubt User-Anlage, User-Bearbeitung, Rollen-/Gruppen-/Direktrechtewechsel und Passwortreset.

Der alte Django-Runserver ist damit nicht mehr der lokale Standardpfad.

## Bereits nach Rust verschoben

- CVE-/NVD-Normalisierung, Upsert- und Canary-Pfade.
- Lokaler LLM-Endpunkt, Risiko-Priorisierung, Guidance-Auswertung und CVE-Report-Summary.
- Dashboard-, Report-, Catalog-, Requirements-, Asset-, Process- und Assessment-Read-Flows.
- Risk-Register Read-, Detail-, Create- und Update-Flows.
- Evidence Read-/Detail-Flows, Evidence-Need-Sync und Evidence-Dateiuploads ueber Rust-Web/API.
- Rust-Web-Shell mit Kontext-Formular sowie datengetriebenem Dashboard, Risk-Register, Evidence-Ueberblick, Reports, Roadmap, Assets, Imports und Processes.
- Rust-DB-Admin-CLI mit `migrate`, `seed-demo` und `init-demo` fuer Rust-eigenen SQLite/PostgreSQL-Bootstrap der operativen Kern-Tabellen inklusive Product-Security sowie vollstaendigem Katalog-/Requirement-Seed.
- Rust-Session-Schicht mit `iscy_auth_session`, `/api/v1/auth/sessions`, `/api/v1/auth/session`, Logout, Cookie/Bearer-Aufloesung, Django-kompatibler `pbkdf2_sha256`-Passwortpruefung und Web-Kontext ohne Query-Parameter.
- Rust-RBAC-Grundlage mit `accounts_role`, `accounts_userrole`, Session-Rollencodes, Header-Rollen-Fallback und Schreibschutz fuer migrierte Write-Endpunkte.
- Rust-Account-Administration mit `/api/v1/accounts/users`, `/api/v1/accounts/users/{user_id}`, `/api/v1/accounts/roles`, `/api/v1/accounts/groups`, `/api/v1/accounts/permissions` sowie Webroute `/admin/users/` fuer User-Liste, User-Anlage, User-Bearbeitung, Passwort-Hashing/-Reset, tenant-scoped Rollenzuweisung, Django-kompatible Gruppenzuweisung und direkte User-Permissions.
- Rust-first CI mit Rust-Tests, Rust-DB-/HTTP-Smoke und Nix-Rust-App-Smoke.
- `start.sh` startet lokal Rust-only statt Django-runserver.
- Roadmap Liste, Detail, Kanban, Task-Updates und Exportdaten.
- Wizard Start-/Result-Flows.
- Import-Center bestaetigte Importjobs plus Rust-Preview-/CSV-APIs `/api/v1/import-center/preview` und `/api/v1/import-center/csv` sowie Rust-Webflow `/imports/` + `/imports/preview/` fuer CSV-/XLSX-/XLSM-Importe, Mapping-Vorschau und Bestaetigung von Business-Units, Prozessen, Lieferanten und Assets.
- Evidence-Upload-API `/api/v1/evidence/uploads` und Rust-Webupload unter `/evidence/` mit Django-kompatibler Dateiablage `evidence/YYYY/MM/...`.
- Product-Security Liste, Produktdetail, Roadmap, Task-Updates und Vulnerability-Updates.
- Rust-only-/Strict-Guards fuer migrierte Backend-Schalter.

## Blocker vor Python-Loeschung

1. **Weboberflaeche:** Rust liefert fuer `/dashboard/`, `/risks/`, `/evidence/`, `/reports/`, `/roadmap/`, `/assets/`, `/imports/` und `/processes/` bereits echte serverseitige Seiten. Die restlichen Views, Detail-/Form-Flows und Exporte liegen noch in Django-Templates und Django-Views.
2. **Auth, Sessions und Admin:** Rust-Sessions, Passwort-Login, Rollen-/Schreibrechte sowie Account-Administration fuer User/Rollen-/Gruppen-/Direktrechtewechsel sind vorhanden. Die Django-kompatiblen Tabellen fuer Gruppen, Permissions und User-Zuordnung sind gebootstrapped; vollstaendige Django-Admin-Paritaet ist noch nicht komplett ersetzt.
3. **Migrations und Seeds:** Ein Rust-eigener Bootstrap fuer operative Kern-Tabellen inklusive Product-Security, Catalog und Requirements ist vorhanden. Einzelne historische Django-Schema-Details ausserhalb dieser Cutover-Slices sind noch nicht vollstaendig abgeloest.
4. **Formulare und Uploads:** Evidence-Dateiuploads sowie Import-Center Datei-Upload, CSV/XLSX/XLSM-Parsing und Mapping-Vorschau laufen direkt ueber Rust-Web/API. Weitere Django-Formreste ausserhalb dieser Cutover-Slices muessen noch ersetzt werden.
5. **Python-Dateien im Repo:** CI und lokaler Start sind Rust-first. Python/Django-Dateien bleiben noch als Legacy-Kompatibilitaet und muessen nach Abschluss von Auth/Web/Form-Flows gezielt entfernt werden.

## Naechster fachlich sinnvoller Cutover-Schritt

Der naechste Abschlussblock ist nicht mehr ein weiterer einzelner API-Endpunkt, sondern die Web- und Betriebsablösung:

1. Letzte Admin-Paritaet in Rust finalisieren.
2. Django-Templates durch Rust-Web oder ein separates Frontend auf Rust-API ersetzen.
3. Verbleibende Django-Template-/Form-Reste systematisch durch Rust-Web oder ein separates Frontend auf Rust-API ersetzen.
4. Python-Dateien, Requirements, Django-Settings und Django-Startpfade entfernen.

## Cutover-Entscheidung

Aktueller Status: **Rust-Backend startbar, produktive Kern-APIs weit migriert, aber kein fachlich sicherer Python-Loeschzeitpunkt.**

Freigabe fuer `apps/`, `config/`, `manage.py`, `requirements*.txt` und Python-CI-Loeschung erst, wenn die oben genannten Blocker ersetzt und die Rust-Weboberflaeche nicht mehr nur Platzhalter ist.
