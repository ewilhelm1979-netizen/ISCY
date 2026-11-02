# ISCY – Projekt-Completion-Backlog (Production Readiness)

## Aktueller Produktstand

ISCY ist im aktuellen `main` eine Rust-only/Axum-Plattform in der
V23.7.34-`development_unreleased`-Phase. Der letzte Stable Release ist
V23.7.33; das Rust-Paket steht auf `0.3.22`.

Bereits umgesetzt sind unter anderem:

- ISMS-/Governance-, Risk-, Control-, Assessment-, Evidence-, Incident-,
  Roadmap-, Supplier- und Management-/Regulatory-Review-Workflows,
- lesende Webansichten vorhandener Assessment-Durchlaeufe mit ausdruecklich
  gekennzeichneter Zusammenfassung bei fehlender historischer Detailschicht,
- Product Security mit CSAF, CycloneDX, SPDX, VEX, SBOM-Diff,
  CVE-Korrelation und CRA-Readiness,
- Continuous Vulnerability Intelligence mit NVD, CISA KEV und FIRST EPSS
  sowie passiver tenantgebundener Software-Hygiene,
- Native Threat Intelligence und Security Observations,
- Software Approval und befristete Exceptions mit getrennten Review-Rechten,
- Zero-Trust-Agenten mit read-only Posture, Enrollment, Secret-Rotation,
  Offline-Queue, Policy-Profilen, PKI-/CSR-Governance und kontrollierter
  Rollout-Governance ohne Remote-Control,
- Evidence Integrity, Legal Hold, kontrollierte Disposition sowie
  S3-kompatible Evidence-Storage-Runtime,
- commit-gepruefte lokale und S3-Evidence-Download-Entscheidungen in der bestehenden
  tenantgebundenen Auditspur; Auditfehler sperren die Dateiausgabe,
- PostgreSQL 16 als Standardpfad und PostgreSQL 18.4 als getesteter
  logischer Forward-Restore-/Kompatibilitaetspfad,
- Release-SBOM, Checksummen, Reproduzierbarkeits-/Provenance-Metadaten,
  Secret-Scan, CodeQL und umfangreiche CI-Gates.

Der CVE-Bereich besitzt weiterhin einen LLM-bezeichneten Workflow
(`run_llm`, `/api/v1/llm/generate`, `/cves/llm-test/`). Dieser ist
aktuell ein deterministischer Rust-Stub. Es wird kein echtes Sprachmodell
ausgefuehrt und es existiert keine RAG-/Embedding-/Retrieval-Runtime.

## Prioritaet P0 – vor breitem Produktivrollout

Die am 10. Oktober 2026 identifizierten repository-weiten Maintenance-Blocker
fuer MinIO-basierte CI-Gates und `RUSTSEC-2026-0285` sind im aktuellen
`main` behoben. Die folgenden Punkte bleiben vor breitem Produktivrollout offen:

1. **Unabhaengige Security-Pruefung.** Externer Penetrationstest beziehungsweise
   unabhaengige Security-Review fuer die produktiven Trust Boundaries.
2. **Zielumgebung abnehmen.** TLS/HSTS, Reverse Proxy, Secret-Dateien,
   Netzwerksegmentierung und Betreiber-Rechte in der konkreten
   Produktionsumgebung verifizieren; vorhandene sichere Defaults ersetzen
   keine Betreiberfreigabe.
3. **Disaster-Recovery-Nachweis fuer die Zielumgebung.** Vorhandene Backup- und
   Restore-Skripte mit echten RPO/RTO-Zielen, verschluesseltem Backup-Speicher
   und wiederholbaren Restore-Drills nachweisen.
4. **Monitoring/Eskalation produktiv anbinden.** Prometheus, Alertmanager,
   Grafana und Log-/Error-Pipeline an den realen Betreiberprozess koppeln.

## Prioritaet P1 – technische Produktreife

1. **CVE-Stub-Semantik im Development umgesetzt.** Feste Generatoridentitaet,
   `STUB_GENERATED` und explizite Provenance verhindern, dass konfigurierte
   Modellnamen als Inferenzherkunft ausgegeben werden. Historische Ausgaben
   bleiben erhalten; eine echte lokale Modellruntime bleibt eigener Scope.
2. **Spaetere LLM-Konfiguration.** Der aktuelle Stub ignoriert alle
   `LOCAL_LLM_*`-Werte einschliesslich beider GPU-Layer-Schreibweisen und
   behauptet keine angewendeten Runtimeparameter. Eine echte Runtime muss
   ihre Konfiguration und Alias-/Konfliktregeln separat definieren und testen.
3. **Kryptografische Release-Signierung/Attestation.** Der aktuelle
   Release-Vertrag liefert SBOM, Checksummen und Provenance-Metadaten, ist aber
   ausdruecklich `unsigned`.
4. **Parser-/Upload-Hardening vertiefen.** XLSX/XLSM-Importe besitzen
   inzwischen fail-closed Archiv-, Entpack-, Shared-String-, Zell- und
   Zeilenlimits sowie sparse Verarbeitung. Fuer riskantere Einsatzumgebungen
   bleiben Malware-Scanning und/oder Parser-Sandboxing als
   Betreiber-/Produktoption zu evaluieren.
5. **Durables Download-Audit im Development umgesetzt.** Lokale und
   S3-Runtime-Downloads speichern Entscheidungen fuer bekannte tenant-eigene
   Objekte vor der Antwort dauerhaft; fehlendes Audit bedeutet HTTP 503 ohne
   Datei. Unauthentifizierte sowie fehlende/fremde Objekte erhalten keine
   objektbezogene persistente Historie. Das Audit belegt Antwortvorbereitung,
   keine Zustellung; S3 weist einen Vergleich mit erwartetem Hash nur dann
   aus, wenn er tatsaechlich erfolgte. Zielumgebungs-/Storageabnahme bleibt P0.

## Prioritaet P2 – Skalierung und neue Integrationen

1. Groessere Last-/HA-Szenarien ueber die synthetischen Zwei-Instanzen-Tests
   hinaus pruefen; keine allgemeine HA- oder SLA-Aussage ohne separaten Nachweis.
2. UI-Designsystem und grosse Review-Ansichten fuer PSIRT-/SOC-/Risk-Teams
   weiter modularisieren.
3. Belastbare EOL/EOS-Quellen und weitere ecosystemspezifische
   PURL-/Versionssemantik ergaenzen.
4. Eine echte lokale Modell-/RAG-Integration nur als separaten,
   tenantgebundenen Trust Boundary einfuehren. Retrieval und Modellvorschlaege
   duerfen keine Firewall-, Endpoint-, Incident-, Risk-Acceptance- oder
   Release-Aktion ohne die vorhandenen Berechtigungs-, Audit- und
   Freigabeprozesse ausfuehren.
5. Produktive Code-Signing-/PKI-Adapter fuer Agent-Artefakte erst nach Review
   der vorhandenen Metadata-/Governance-Schicht anbinden.

## Strategische Produktagenda

Die technische Rust-Migration ist abgeschlossen. Fuer die fachliche
Weiterentwicklung ist `docs/ISCY_STRATEGIC_ROADMAP.md` massgeblich.

Der aktuelle V23.7.34-Development-Schwerpunkt ist Machinery & CRA
Safety-Security Co-Engineering (Migration `0046`) sowie die tenantgebundene
SoA-Rust-Wiederherstellung fuer SQLite und PostgreSQL (Migration `0047`).
Die lesenden Assessment-Durchlaufansichten sind wieder verfuegbar; der
Profil-/Fortsetzen-Schritt des Unternehmens-Wizards ist als W1 wiederhergestellt;
fachliche Betroffenheit und Ergebnisgenerierung (W2/W3) bleiben offen. Funktionen bis
einschliesslich Migration `0045` sind bereits im Stable-Tag V23.7.33
enthalten.
