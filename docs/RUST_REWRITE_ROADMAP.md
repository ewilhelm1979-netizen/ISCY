# ISCY Full-Rewrite nach Rust – Team-Roadmap

## Ziel

ISCY schrittweise von Django/Python auf Rust ueberfuehren, ohne Fachfunktionalitaet zu verlieren.

## Vorgehen (Strangler Pattern)

### Phase 1 – Foundation (jetzt)

- Rust-Service `rust/iscy-backend` mit Health und erstem API-Endpunkt
- Build/Test in Team-Workflow integrieren
- API-Vertraege fuer Migration definieren

### Phase 2 – Parallelbetrieb

- NVD-Import/Sync als Rust-Worker migrieren
- Django ruft Rust-Service ueber HTTP/gRPC auf
- Ergebnisvergleich Python vs Rust (Canary)
- Bridge-Command vorhanden: `import_nvd_cves_via_rust` (Rust-Normalisierung + Python-NVD-Upsert)
- Canary-Command vorhanden: `import_nvd_cves_canary` (Paritaetsvergleich Python vs Rust, optional strict)
- Parity-Report vorhanden: `report_nvd_canary_parity` (JSON/CSV-Ausgabe)

### Phase 3 – Domänenmigration

- nacheinander: Vulnerability-Intelligence -> Guidance -> Reports
- jede Migration mit Feature-Parity-Check, Data-Mapping und Rollback-Pfad

### Phase 4 – Cutover

- Python-Endpunkte stilllegen
- Rust-Service als System of Record
- verbleibende Django-Teile entfernen

## Engineering-Gates pro Phase

1. Unit + Integration Tests gruen
2. API-Kontrakte stabil
3. Performance-Benchmark dokumentiert
4. Security-Review abgeschlossen
5. Rollback getestet
