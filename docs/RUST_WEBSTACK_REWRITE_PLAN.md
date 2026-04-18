# Rust-Webstack Umbauplan (Python-Ablösung)

Stand: 2026-04-18

## Zielbild
Vollständige Ablösung der Django-Anwendungslogik durch Rust-Services (API + Background Jobs + LLM + NVD), Python nur noch bis zum finalen Cutover als temporäre Kompatibilitätsschicht.

## Jetzt umgesetzt (dieser Schritt)
- Lokaler LLM-Pfad in der App ist auf **Rust-Service only** gestellt.
- Legacy `llama_cpp`-Codepfad wurde aus der CVE-Service-Logik entfernt.
- Runtime-Checks/Views verwenden nur noch den Rust-Provider.

## Nächste Umbaupakete
1. **Auth & Tenant API in Rust**
   - Login/Session/JWT
   - Tenant-Scoping und Rollenmodell
2. **Wizard/Guidance/Reporting in Rust**
   - bestehende Django-Views durch Rust-API + Frontend adapter ersetzen
3. **Datenzugriff konsolidieren**
   - Rust ORM/SQL Layer, Migrationen/Seeds in Rust-Pipeline
4. **Finaler Cutover**
   - Django-Server deaktivieren
   - Python-Dependencies + `manage.py` entfernen
   - CI auf Rust-only umstellen

## Abnahmekriterien
- Kein produktiver Request-Pfad mehr über Django
- Keine Python-Runtime in Build/Runtime-Images
- Rust-only CI (Tests, Lints, Migrations, Smoke)
