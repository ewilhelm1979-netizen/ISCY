# ISCY – Projekt-Completion-Backlog (Production Readiness)

## Aktueller Produktstand

ISCY ist im aktuellen `main` eine Rust-only/Axum-Plattform in der
V23.7.34-`development_unreleased`-Phase. Der letzte Stable Release ist
V23.7.33; das Rust-Paket steht auf `0.3.22`.

Bereits umgesetzt sind unter anderem:

- ISMS-/Governance-, Risk-, Control-, Assessment-, Evidence-, Incident-,
  Roadmap-, Supplier- und Management-/Regulatory-Review-Workflows,
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
- PostgreSQL 16 als Standardpfad und PostgreSQL 18.4 als getesteter
  logischer Forward-Restore-/Kompatibilitaetspfad,
- Release-SBOM, Checksummen, Reproduzierbarkeits-/Provenance-Metadaten,
  Secret-Scan, CodeQL und umfangreiche CI-Gates.

Der CVE-Bereich besitzt weiterhin einen LLM-bezeichneten Workflow
(`run_llm`, `/api/v1/llm/generate`, `/cves/llm-test/`). Dieser ist
aktuell ein deterministischer Rust-Stub. Es wird kein echtes Sprachmodell
ausgefuehrt und es existiert keine RAG-/Embedding-/Retrieval-Runtime.

## Prioritaet P0 – vor breitem Produktivrollout

1. **CI-Reproduzierbarkeit wiederherstellen.** Die Object-Storage-, HA- und
   Performance-Gates duerfen nicht von nicht mehr abrufbaren historischen
   MinIO-/`mc`-Image-Referenzen abhaengen. Ersatzimages muessen kontrolliert,
   nach Moeglichkeit immutable/digest-gepinnt und mit unveraenderter
   Testsemantik validiert werden.

2. **Aktiven RustSec-Befund beheben.** Der am 10. Oktober 2026 gepruefte
   `main`-Lockfile-Stand enthaelt `rustls 0.23.38`, das von
   `RUSTSEC-2026-0285` betroffen ist. Der Fix muss auf eine nicht betroffene
   Version (`>= 0.23.45`) aktualisieren; ein dauerhaftes Advisory-Ignore ist
   kein akzeptierter Abschluss.
2. **Unabhaengige Security-Pruefung.** Externer Penetrationstest beziehungsweise
   unabhaengige Security-Review fuer die produktiven Trust Boundaries.
3. **Zielumgebung abnehmen.** TLS/HSTS, Reverse Proxy, Secret-Dateien,
   Netzwerksegmentierung und Betreiber-Rechte in der konkreten
   Produktionsumgebung verifizieren; vorhandene sichere Defaults ersetzen
   keine Betreiberfreigabe.
4. **Disaster-Recovery-Nachweis fuer die Zielumgebung.** Vorhandene Backup- und
   Restore-Skripte mit echten RPO/RTO-Zielen, verschluesseltem Backup-Speicher
   und wiederholbaren Restore-Drills nachweisen.
5. **Monitoring/Eskalation produktiv anbinden.** Prometheus, Alertmanager,
   Grafana und Log-/Error-Pipeline an den realen Betreiberprozess koppeln.

## Prioritaet P1 – technische Produktreife

1. **CVE-LLM-Semantik bereinigen.** Entweder den aktuellen Stub explizit als
   Stub/regelbasierte Assistenz im Datenmodell kennzeichnen oder eine echte,
   lokal betriebene Modellruntime mit belastbarer Provenance implementieren.
   Ein frei gesetztes `LOCAL_LLM_MODEL_NAME` darf nicht als Beweis echter
   Modellinferenz missverstanden werden.
3. **LLM-Konfiguration vereinheitlichen.** Der Code liest derzeit
   `LOCAL_LLM_N_GPU_LAYERS`, waehrend die Env-/Compose-Beispiele
   `LOCAL_LLM_GPU_LAYERS` setzen. Diese Kompatibilitaetsabweichung technisch
   bereinigen und erst danach GPU-Offload dokumentieren.
4. **Kryptografische Release-Signierung/Attestation.** Der aktuelle
   Release-Vertrag liefert SBOM, Checksummen und Provenance-Metadaten, ist aber
   ausdruecklich `unsigned`.
4. **Parser-/Upload-Hardening vertiefen.** Fuer riskantere Einsatzumgebungen
   Malware-Scanning und/oder Parser-Sandboxing als Betreiber-/Produktoption
   evaluieren.
5. **Durables Audit fuer besonders sensitive Downloads vertiefen.** Die
   vorhandenen Runtime-Security-Events fuer Evidence-Downloads koennen um eine
   explizite persistente Auditspur erweitert werden.

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
Safety-Security Co-Engineering (Migration `0046`). Funktionen bis
einschliesslich Migration `0045` sind bereits im Stable-Tag V23.7.33
enthalten.
