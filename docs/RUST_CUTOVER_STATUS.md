# ISCY Rust-Cutover-Status

Stand: 2026-04-20

## Kurzfassung

ISCY ist fachlich weit in Richtung Rust migriert, aber noch nicht sicher Python-frei. Der Rust-Axum-Service ist als Backend direkt startbar und viele produktive Lese-/Schreibpfade laufen bereits ueber `rust_service`. Die Django-Schicht ist aber weiterhin die Browser-App, Auth-/Session-Schicht, Form-/Template-Schicht, Migrations-/Seed-Schicht und ein Teil der Datei-/Import-Orchestrierung.

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

Healthcheck:

```bash
curl -fsS http://127.0.0.1:9000/health
```

Die vollstaendige Browser-App laeuft bis zum Web-Cutover weiterhin mit Django vor dem Rust-Service:

```bash
RUST_BACKEND_URL=http://127.0.0.1:9000 VERIFY_LOCAL_LLM=0 ./start.sh
```

## Bereits nach Rust verschoben

- CVE-/NVD-Normalisierung, Upsert- und Canary-Pfade.
- Lokaler LLM-Endpunkt, Risiko-Priorisierung, Guidance-Auswertung und CVE-Report-Summary.
- Dashboard-, Report-, Catalog-, Requirements-, Asset-, Process- und Assessment-Read-Flows.
- Risk-Register Read-, Detail-, Create- und Update-Flows.
- Evidence Read-/Detail-Flows und Evidence-Need-Sync.
- Roadmap Liste, Detail, Kanban, Task-Updates und Exportdaten.
- Wizard Start-/Result-Flows.
- Import-Center bestaetigte Importjobs.
- Product-Security Liste, Produktdetail, Roadmap, Task-Updates und Vulnerability-Updates.
- Rust-only-/Strict-Guards fuer migrierte Backend-Schalter.

## Blocker vor Python-Loeschung

1. **Weboberflaeche:** Rust liefert fuer `/dashboard/`, `/reports/`, `/evidence/`, `/risks/` usw. aktuell noch Platzhalterseiten; die echte UI liegt in Django-Templates und Django-Views.
2. **Auth, Sessions und Admin:** Login, Benutzer-/Tenant-Kontext, Admin-Funktionen und Berechtigungsoberflaechen sind noch nicht als Rust-Web-/API-Schicht ersetzt.
3. **Migrations und Seeds:** Datenbankschema, Initialdaten und Demo-/Katalog-Seedings laufen noch ueber Django-Migrations und Management-Commands.
4. **Formulare und Uploads:** Validierung, Form-Flows, Evidence-Dateiuploads sowie CSV/XLSX-Import-Mapping sind noch teilweise Django-orchestriert.
5. **CI und Startskripte:** `.github/workflows/ci.yml`, `start.sh`, Teile des `Makefile` und lokale Smoke-Flows erwarten noch Python/Django.

## Naechster fachlich sinnvoller Cutover-Schritt

Der naechste Abschlussblock ist nicht mehr ein weiterer einzelner API-Endpunkt, sondern die Web- und Betriebsablösung:

1. Rust-Migrationen und Seed-Commands fuer die bestehenden Tabellen bereitstellen.
2. Auth-/Tenant-/Session-API in Rust finalisieren.
3. Django-Templates durch Rust-Web oder ein separates Frontend auf Rust-API ersetzen.
4. Upload-/Import-Dateifluss ohne Django bereitstellen.
5. CI auf Rust-only Smoke, Rust-Migration und Rust-Web-Health umstellen.
6. Erst danach Python-Dateien, Requirements, Django-Settings und Django-Startpfade entfernen.

## Cutover-Entscheidung

Aktueller Status: **Rust-Backend startbar, produktive Kern-APIs weit migriert, aber kein fachlich sicherer Python-Loeschzeitpunkt.**

Freigabe fuer `apps/`, `config/`, `manage.py`, `requirements*.txt` und Python-CI-Loeschung erst, wenn die oben genannten Blocker ersetzt und die Rust-Weboberflaeche nicht mehr nur Platzhalter ist.
