# ISCY V23.7.33

Status: Stabiler Release.
Vorgänger: `V23.7.32`

V23.7.33 bündelt Security-Hardening, Betriebsgrenzen und kontrollierte Dependency-Maintenance seit V23.7.32. Die Datenbankstruktur bleibt bei 45 Migrationen; die 42 visuellen Baselines bleiben unverändert.

## Security und Betriebsgrenzen

- Evidence-S3-Secret-Referenzen sind auf erlaubte, validierte Quellen begrenzt und verhalten sich bei ungültigen Referenzen fail-closed.
- Öffentliche Readiness-Prüfungen begrenzen Datenbankzugriffe und vermeiden unnötige interne Prüfdetails an der öffentlichen Grenze.
- Agent-Webhook-Secret-Referenzen werden kanonisch begrenzt; Legacy-Fälle sind durch Regressionstests abgedeckt.
- Login-Rate-Limit-Zustand und Passwortverifikation sind begrenzt, damit Angreifer keine unbeschränkte Zustands- oder Verifikationsarbeit erzwingen können.
- Alertmanager-Persistenz ist an eine vertrauenswürdige Service-Identität gebunden; Monitoring-Defaults und Dokumentation wurden gehärtet.
- Incident-Runbook-Expansion ist begrenzt und durch Datenbank- und API-Regressionstests abgesichert.
- Die dokumentierte `rkyv`-Advisory-Ausnahme bleibt auf einen inaktiven optionalen Dependency-Pfad beschränkt; CI blockiert eine unbeabsichtigte Aktivierung fail-closed.

## Supply Chain und Plattform

- `calamine` wurde kontrolliert von `0.36.0` auf `0.36.1` aktualisiert.
- `base64` wurde kontrolliert von `0.23.0` auf `0.23.1` aktualisiert.
- Der `nixos-26.05`-Lock wurde auf den validierten nixpkgs-Stand `8b8c811c7c2541c30382c5de7ed26be055569c60` aktualisiert.
- `actions/checkout` 7.0.1 und `taiki-e/install-action` 2.85.10 werden weiterhin über unveränderliche Commit-SHAs eingebunden.
- Die Produkt-Buildtoolchain bleibt Rust `1.97.0`; die MSRV bleibt Rust `1.88.0`. Der Reverse-Proxy-Stand bleibt `nginx:1.31-alpine`.
- PostgreSQL 16 bleibt der Standard. Die zusätzliche PostgreSQL 18.4-Kompatibilität und der logische Upgrade-Pfad werden weiterhin in der Pflichtpipeline geprüft.

## Governance-Grenzen

- Der NIS2-Relevanz-Wizard und seine Applicability-Begruendung unterstützen die nachvollziehbare Einordnung im NIS2- und KRITIS-Kontext, liefern aber keine rechtsverbindliche Einstufung.
- Eine DORA-Konformitaetsbewertung erfolgt nicht.
- Für den Cyber Resilience Act (CRA) erfolgt keine automatische Konformitaetsbewertung oder CE-Freigabe.
- ISCY liefert keine automatische Zertifizierung und ersetzt keine Rechtsberatung.

## Release-Qualität

Der Release-Gate umfasst Rust-Formatierung, Clippy und Tests, Supply-Chain-Audit und Lizenzprüfung, Secret-Scan, MSRV-Prüfung, Nix-Smoke, Docker-Konfiguration, Object-Storage-Integration, HA- und PostgreSQL-18-Prüfung, Performance-Smoke, Visual Regression sowie einen zweifachen reproduzierbaren Build des portablen Release-Binaries. SBOM und Release-Checksummen werden deterministisch aus dem Release-Stand erzeugt.
