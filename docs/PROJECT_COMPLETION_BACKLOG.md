# ISCY – Projekt-Completion-Backlog (Production Readiness)

## Prioritaet P0 (vor breitem Produktivrollout)

1. Secrets-Management statt Plain `.env`
2. TLS-Absicherung und HSTS
3. Monitoring/Alerting (Logs, Metriken, Errors)
4. Regelmaessige Backup- und Restore-Drills
5. Rollen-/Rechtekonzept und Admin-Hardening

## Prioritaet P1 (direkt danach)

1. CI-Gates erweitern (team-test als Pflicht)
2. Security-Scans fuer Dependencies/Container
3. Betriebshandbuch + Incident-Runbooks
4. Performance-Baselines und Lasttests

## Prioritaet P2 (Reifegrad / Skalierung)

1. UI-Designsystem modularisieren (CSS aus `base.html` extrahieren)
2. Visuelle Regressionstests
3. Optional: Rust-Nebenservice fuer Performance-kritische Teilbereiche
