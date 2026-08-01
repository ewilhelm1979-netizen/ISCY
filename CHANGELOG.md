# Changelog

All notable changes to ISCY are documented in this file.

The project uses release tags for immutable release points. Changes under **Unreleased** are part of the next release candidate until they are assigned to a version.

## Unreleased

### Software Approval and Exception Policy - Phase 2

- adds migration `0045_rust_software_approval_exception_policy` with tenant-scoped policies, mandatory-expiry exceptions, persisted evaluations and bounded audit events for exact existing product, asset, component and imported SBOM-component targets
- adds deterministic restrictive precedence for `APPROVED`, `RESTRICTED`, `PROHIBITED`, `EXCEPTION_ACTIVE`, `UNMANAGED` and `REVIEW_REQUIRED`, with current server-time expiry checks and no fail-open approval
- adds separate request/review/revoke permissions, unconditional self-approval denial, immutable approved requests, optimistic revisions, PostgreSQL locking, SQLite write serialization and atomic state/audit rollback
- adds the `/software-policies/` workspace and tenant-bound `/api/v1/software-policies*` and `/api/v1/software-policy-exceptions*` endpoints with IDOR, RBAC, concurrency, expiry, pagination and XSS regression coverage
- remains passive and advisory: no software enforcement, Agent command, Incident, Evidence, Security Observation, VEX, Risk Acceptance or synthetic CVE is created or changed

### Continuous Vulnerability Intelligence and Software Hygiene - Phase 1

- hardens the existing NVD import boundary and disables caller-controlled CVE payload upserts while preserving a validated, authorized single-CVE import
- adds bounded NVD 2.0 delta synchronization, persistent checkpoints and leases, CISA KEV enrichment with removal history, and batched FIRST EPSS enrichment with provenance
- correlates existing tenant-scoped assets, software components and SBOM imports conservatively through explainable CPE/version evidence and reuses existing Product Security Vulnerability Findings where a canonical product binding exists
- adds deterministic passive hygiene priority from CVSS, KEV, EPSS, asset criticality, freshness, VEX and documented controls without creating Security Observations, Incidents, Evidence or active actions
- adds migration `0043_rust_continuous_vulnerability_intelligence`, granular view/review/global-sync permissions, minimal status/sync/hygiene APIs and the `/cves/` workflow
- adds migration `0044_rust_vulnerability_hygiene_lifecycle` with tenant-scoped evaluation generations, complete-scope-only stale reconciliation, transactional finding re-evaluation and explicit incomplete-run status without overwriting manual triage, VEX, controls or risk acceptance
- restricts feed access to fixed official HTTPS sources with DNS/SSRF, redirect, timeout, compression, payload, parser, retry and secret-handling controls; no SIEM/EDR/XDR, Wazuh, scanning, Agent command, remote execution or Hackback capability is introduced
- hardens the Phase-1 review findings with transaction-time lease fencing, current NVD single-CVE parameters, KEV count/rollback validation, fair EPSS coverage, conservative handling of complex CPE contexts, scoped compensating controls, requester audit attribution and redacted global operational metadata for tenant roles

### Native Threat Intelligence and Security Observations - Phase 1

- adds tenant-scoped, locally validated IPv4, IPv6, domain, URL and SHA-256 indicators with provenance, confidence, validity, lifecycle, classification and audit history
- adds bounded Security Observations sourced manually or from existing tenant-local Agent Findings and Product Security Vulnerability Findings without creating a competing finding model
- adds manual, triageable Indicator/Observation links with transactional audit, tenant-local deduplication and explicit `SOC_ANALYST`/`SECURITY_ADMIN` permissions
- adds the `/security-observations/` workspace and `/api/v1/threat-intelligence/*` and `/api/v1/security-observations/*` endpoints with negative tenant, role, payload and side-effect tests
- adds migration `0042_rust_native_threat_intelligence_observations` for SQLite and PostgreSQL; no raw-log ingestion, external feed, network lookup, automatic matching, Incident/Evidence creation or active response is introduced

### Release lifecycle

- beginnt den Entwicklungszyklus fuer `V23.7.31` auf Basis des unveraenderten, veroeffentlichten Stable Release `V23.7.30`
- dokumentiert Tag, Release-ID, Zielcommit und die sechs geprueften Assets von `V23.7.30` in einem unveraenderlichen Published-Snapshot
- setzt den Root-Lifecycle fail-closed auf `development_unreleased`; Release-Bundle, Tag, GitHub Release und Upload bleiben einer separaten Release-Vorbereitung vorbehalten
- oeffnet die Produktentwicklung fuer `V23.7.31`; die darunter dokumentierten
  Unreleased-Aenderungen sind weiterhin weder getaggt noch veroeffentlicht
- bereitet `V23.7.31` repositorykonform als `prepared_not_published` mit
  Candidate Notes, 45 Migrationen, 42 Visual-Baselines, reproduzierbarer
  CycloneDX-SBOM und lokalem unsigniertem Artefaktvertrag vor; Feature Freeze
  gilt, und Tag, GitHub Release sowie Upload bleiben einem getrennten Auftrag
  vorbehalten
- dokumentiert die anschliessende Veroeffentlichung von `V23.7.31` mit
  Release-ID `358600823`, Tagziel
  `c595795296633ce4152aa0e817b063ee88c7028a` und sechs kontrolliert
  heruntergeladenen, per SHA-256 verifizierten Assets im unveraenderlichen
  Published-Snapshot `release/published/V23.7.31.json`
- beginnt den Entwicklungszyklus fuer `V23.7.32` auf Basis des unveraenderten,
  veroeffentlichten Stable Release `V23.7.31` und setzt den Root-Lifecycle auf
  `development_unreleased`
- setzt Release-Artefakt- und Teststatus fail-closed auf erneute Development-
  und Release-Validierung zurueck; in diesem Zustand kann kein Release-Bundle
  fuer `V23.7.32` oder eine bereits veroeffentlichte Version erzeugt werden

## V23.7.30 - 2026-07-22

### Automation

- adds an owner-controlled, same-repository Draft-PR orchestrator for the exact commands `/iscy status`, `/iscy review`, `/iscy fix-ci`, and `/iscy verify`
- separates read-only Codex review/verification, workspace-only correction, diff validation, bot commit, and Fast-Forward push into least-privilege jobs without automatic merge or Ready-for-review transitions
- limits managed CI correction to two bot-recorded attempts, blocks forks, Dependabot, foreign actors, protected automation/security paths, secrets, local paths, runtime artifacts, symlinks, submodules, and unexpected binaries
- adds offline guard, injection, attempt-limit, workflow-head, and diff regression tests; normal pull-request CI performs no OpenAI API request

### Release lifecycle

- beginnt den Entwicklungszyklus fuer `V23.7.30` auf Basis des unveraenderten, veroeffentlichten Stands `V23.7.29`
- trennt den nicht veroeffentlichten Development-Modus fail-closed von einer spaeteren, separaten Release-Candidate-Vorbereitung
- bereitet `V23.7.30` als `prepared_not_published` mit Candidate Notes, 41 Migrationen, 36 Visual-Baselines, reproduzierbarer CycloneDX-SBOM sowie lokalem unsigniertem Artefaktvertrag vor, ohne Tag, GitHub Release, Upload oder Veroeffentlichung
- dokumentiert den bereits auf `main` gemergten Pin des Produkt-Builders auf das offizielle Rust-1.97.0-Bookworm-Multiarch-Image per Digest; Toolchain und Produktfunktion bleiben unveraendert
- enthaelt in diesem PR keine Produkt-, Migrations- oder Dependency-Aenderung

### Agent Rollout 2.0 - Phase 1

- ergaenzt mit Migration `0040_rust_agent_rollout_governance` eine tenantgebundene Rollout-Control-Plane fuer bestehende Agent Devices mit den festen Ringen Lab, Canary, Pilot, Production und Critical
- ergaenzt serverseitige Preflight-/Postflight-Pruefungen, Ring-Gates, explizite menschliche Promotion, Pause/Resume, Abbruch sowie operatorgefuehrte Rollback-Dokumentation
- integriert Rollout-Uebersicht und -Detailakte unter `/zero-trust/rollouts/`, eingefrorene Management-Review-Aggregate und niedrig-kardinale Operations-/Prometheus-Signale
- sichert Rollen, Tenantgrenzen, Statusuebergaenge, Audit-Events und konkurrierende Start-/Promotion-Aktionen fail-closed ab
- fuehrt keine Remote-Installation, Agent-Befehle, automatische Softwareverteilung oder technische Rollback-Ausfuehrung aus und fuegt weder Wazuh-, IOC-, Behavioral-Detection- noch Threat-Modeling-Funktionen hinzu

### Agent Rollout 2.0 - Phase 2

- ergaenzt mit Migration `0041_rust_agent_rollout_manifest_handoff` unveraenderliche, versionierte und tenantgebundene Ring-Manifeste mit kanonischem kompaktem JSON, stabil sortierten Targets und reproduzierbarem SHA-256
- verlangt vor jedem Ringstart ein integres aktives Manifest und friert Artefakt-, Provenance-, Policy-, Plattform-, PKI-/mTLS- und Preflight-Metadaten ein
- ergaenzt passive externe Deployment-Handoffs, sichere JSON-Exporte und einen strikt validierten, transaktionalen Result-Import mit 1-MiB-/500-Target-Grenzen, Replay-Schutz und Wiederverwendung der bestehenden Deployment-Result-Logik
- integriert Manifest-, Handoff-, Rueckmeldungs-, Fehler- und Versionsabweichungssignale in Rollout-Audit, Postflight, Management-/Regulatory-Reviews, Betriebszentrale und niedrig-kardinale Prometheus-Metriken
- erweitert die bestehende Rollout-Detailakte um Manifest-Freeze, Export, Handoff-Lifecycle und Importhistorie; kritische Aktionen bleiben rollen- und bestaetigungsgebunden
- behaelt ISCY als Governance- und Evidence-Control-Plane ohne Remote-Ausfuehrung, Paketuebertragung, externe Credentials, automatische Promotion oder technische Deployment-Integration

## V23.7.29 - 2026-07-13

### Platform maintenance

- aktualisiert den nginx-Reverse-Proxy in Stage, Production und der isolierten HA-Testtopologie von `nginx:1.27-alpine` auf `nginx:1.31-alpine`, ohne Produkt-, API-, Datenbank- oder Berechtigungslogik zu aendern
- aktualisiert die aktuelle CI-, Clippy-, Test- und Produkt-Build-Toolchain auf Rust `1.97.0`, behaelt die deklarierte MSRV und einen verpflichtenden Kompatibilitaetsjob auf Rust `1.88.0` bei und laesst den digest-gepinnten portablen Release-Builder unveraendert auf Rust 1.88
- aktualisiert den reproduzierbaren Nix-Entwicklungspfad auf `nixos-26.05` mit Nix-Rust `1.95.0` und behaelt die getrennten Produkt-, MSRV- und portablen Release-Builder-Grenzen bei
- ergaenzt einen isolierten PostgreSQL-18.4-Kompatibilitaets- und Forward-Restore-Nachweis mit PG18-Clientdump, dynamischem Datenintegritaetsvergleich, Restart, Anwendungssmoke und Migrationsrennen; PostgreSQL 16 und sein Volumeziel bleiben der unveraenderte Standard
- korrigiert PostgreSQL-SELECTs durch explizite `bigint`-Casts fuer als Rust-`i64` dekodierte Integer-Ausdruecke, ohne Datenmodell, Tenantfilter, SQLite-Semantik oder API zu aendern
- ersetzt die zurueckgezogene transitive Version `spin 0.9.8` durch die kleinste kompatible, nicht zurueckgezogene Aufloesung `spin 0.9.9`; Produkt- und Datenbanksemantik bleiben unveraendert

### Release preparation

- prepares the stable platform version `V23.7.29` without creating a tag, GitHub Release, signature, or public artifact
- adds a release-readiness matrix, German release-notes draft, machine-readable release manifest, tracked SHA-256 inputs, and a local unsigned artifact bundle
- adds `make release-candidate-check` plus a lightweight CI aggregation job that requires all existing Rust, Nix, Object Storage, Performance, HA, Visual, Compose, and hardened-build jobs without duplicating the full pipeline
- adds only pinned build/test clients for cargo-audit, cargo-deny, cargo-cyclonedx, Docker Compose, and PostgreSQL to the existing Nix development shell; no runtime or platform version is upgraded
- prepares a reproducible CycloneDX 1.5 dependency SBOM with deterministic source timestamp and stable local-root PURL; it remains unsigned and unpublished
- adds a value-redacting tracked-file sensitive-data scan and deterministic checks for 39 migrations, 34 visual baselines, screenshot references, manifest fields, and checksums

## V23.7.28-rc.1 - 2026-07-12

### Added

- ergaenzt getrennte Liveness-, Readiness- und Startup-Systempruefungen mit sicherer DB-/Migrationsklassifizierung, nicht sensitiver Runtime-ID und begrenztem Graceful Shutdown
- ergaenzt einen kurzen PostgreSQL-/MinIO-Performance-Smoke mit fester Parallelitaet, grosszuegigen CI-Regressionsbudgets sowie JSON-/Markdown-Artefakten fuer p50, p95, p99, Maximum und Fehlerrate
- ergaenzt einen isolierten Zwei-Instanzen-Test mit PostgreSQL 16, MinIO, Backend A/B, nginx-1.31-Proxy, Cross-Instance-S3-Read/Verify, beidseitigem Failover und parallelem Migrationsstart
- ergaenzt 34 Nix-/Playwright-Baselines fuer 17 zentrale Webbereiche bei 1440 x 1200 und 1024 x 900 mit Pixel-Diff, Overflow-/Clipping-/Secret-Pruefung und CI-Diff-Artefakten
- dokumentiert Performance-, HA-, Worker-/Side-Effect-, Shutdown- und Visual-Regression-Grenzen ohne SLA-, Multi-Region- oder allgemeine Hochverfuegbarkeitsaussage
- ergaenzt den echten S3-kompatiblen Evidence-Storage-Runtime-Client ueber additive Migration `0039_rust_evidence_s3_runtime_client` mit tenantgebundenen opaque Object-IDs, Upload-/Verify-/Orphan-/Delete-Status und Tombstone-Nachweis
- ergaenzt explizite `env:`- und allowlist-gebundene `file:`-Secret-Aufloesung, Request-Time-DNS-/SSRF-Revalidierung, AWS-SigV4 sowie begrenzte PUT-, HEAD-, GET- und kontrollierte DELETE-Operationen ohne automatische Credential-Provider-Chain
- erweitert bestehende Evidence-Uploads, autorisierte Downloads, Integritaets-Worker, Restore-Pruefungen und freigegebene Disposition um `s3_compatible`, waehrend `local_filesystem` unterstuetzt bleibt
- ergaenzt einen isolierten MinIO-Integrationstest und CI-Job fuer PUT/HEAD/GET, SHA-256, Hash-Mismatch, Object-missing, Access-denied, kontrolliertes DELETE, idempotenten Wiederanlauf und Cleanup
- erweitert `/evidence/integrity/` und Management-/Regulatory-Review-Signale um S3-Runtime-, Upload-, Restore-, Fehler- und Orphan-Status ohne Secretwerte oder vollstaendige Object Keys
- ergaenzt Agent-CA-/PKI-/CSR-Governance ueber additive Migration `0037_rust_agent_pki_csr_governance`
- ergaenzt tenantgebundene Agent-PKI-APIs fuer Provider-Metadaten, CSR-Lifecycle, Zertifikatsstatus, mTLS-Bindungsstatus, Rotation und Widerruf unter `/api/v1/agents/pki*`, `/api/v1/agents/{agent_id}/pki` und `/api/v1/agents/onboarding/pki`
- erweitert `/zero-trust/` und den gefuehrten Agent-Onboarding-Assistenten um deutsche PKI-/CSR-/mTLS-Governance-Hinweise mit Provider-, CSR- und Zertifikatsstatus, ohne produktive CA-Ausstellung vorzutaueschen
- erweitert Management-/Regulatory-Review-Pakete fuer NIS2, DORA, DSGVO und generische Governance um Agent-PKI-, CSR-, Zertifikats-, mTLS-, Rotations- und Widerruf-Gaps
- ergaenzt Agent-Release-Artefakte und Release-Provenance ueber additive Migration `0036_rust_agent_release_artifact_provenance`
- ergaenzt tenantgebundene Agent-Artefakt-APIs fuer Manifestliste/-detail, Refresh, SHA-256-Pruefung, Signaturstatuspruefung, Provenance-Liste/-detail und Onboarding-Artefakte unter `/api/v1/agents/artifacts*`, `/api/v1/agents/release-provenance*` und `/api/v1/agents/onboarding/artifacts`
- erweitert `/zero-trust/` und den gefuehrten Agent-Onboarding-Assistenten um deutsche Artefakt-/Pruefsummen-/Signatur-/Provenance-Hinweise fuer systemd, NixOS, Windows Scheduled Task, PowerShell, macOS LaunchDaemon und Konfigurationsbeispiele
- erweitert Management-/Regulatory-Review-Pakete fuer NIS2, DORA, DSGVO und generische Governance um Agent-Artefakt-, Signatur-, Pruefsummen- und Release-Provenance-Gaps
- ergaenzt Evidence-Worker, kontrollierte physische Disposition und vorbereitetes Object-Storage-Backend ueber additive Migration `0035_rust_evidence_worker_disposition_storage`
- ergaenzt tenantgebundene Evidence-Worker-APIs fuer Status, manuelle begrenzte Worker-Laeufe und Laufhistorie unter `/api/v1/evidence/integrity/worker*`
- ergaenzt kontrollierte Disposition-APIs fuer Kandidaten, Preview, Approval, Execute, Cancel und Ereignisse; physische Aussonderung erfolgt nur nach dokumentierter Freigabe, ohne Legal Hold und ueber die sichere Storage-Abstraktion
- ergaenzt Storage-Backend-Status unter `/api/v1/evidence/storage/backends` mit `local_filesystem` als Default und sicher vorbereiteten `s3_compatible`-Konfigurationssignalen ohne Live-Credentials oder Netzwerkaufrufe
- ergaenzt Evidence Object Storage Client Phase 3 ueber additive Migration `0038_rust_evidence_object_storage_client` mit tenantgebundenen Backend-Konfigurationen, Secret-Referenzstatus, redaktionellen Object-Referenzen, Backend-Events und Contract-Drills
- ergaenzt API-Pfade fuer Object-Storage-Backend-Metadaten, Endpoint-/Secret-Validierung, Backend-Events, Object-Referenz-Anbindung und Object-Storage-Drills unter `/api/v1/evidence/storage/backends*` und `/api/v1/evidence/{evidence_id}/storage/*`
- erweitert `/evidence/integrity/` um Integritaets-Worker-Status, letzte Worker-Laeufe, Storage-Backend-Status, Disposition-Kandidaten sowie Freigabe-/Aussonderungsaktionen fuer schreibende Rollen
- erweitert `/evidence/integrity/` um tenantgebundene Object-Storage-Backend-Metadaten mit Endpoint-Policy, Bucket, Prefix, Validierungsstatus und sicheren Fehlerklassen ohne Secretwerte oder vollstaendige Object-Keys
- erweitert Regulatory Review-Pakete fuer NIS2, DORA, DSGVO und generische Governance um Evidence-Worker-, Storage-/Restore-, Object-Storage-Contract- und kontrollierte Disposition-Signale
- dokumentiert den lokalen PostgreSQL-Live-Haertungstest fuer Migration `0034_rust_supplier_product_security_governance` als erfolgreich nachgezogenen Preflight-Drill
- ergaenzt Supplier/Product-Security-Deepening mit tenantgebundenem Governance-Modell fuer Lieferant, Produkt/Service, lokale Advisory-/PSIRT-/CVE-Metadaten, SBOM-/VEX-Bezuege, Review-Status, offene Massnahmen und Management-/Regulatory-Review-Bezug
- ergaenzt additive Migration `0034_rust_supplier_product_security_governance` fuer Supplier/Product-Security-Datensaetze, Evidence-Links, Ereignis-/Audit-Historie und Vertrags-/Exit-Plan-Historie ohne destruktive Datenbankoperationen
- ergaenzt API-Pfade fuer Supplier/Product Security unter `/api/v1/suppliers/product-security`, Detail-, Status-, Evidence-, Ereignis- und Supplier-bezogene Contract-/Exit-History-Abfragen
- ergaenzt die deutsche Weboberflaeche `/suppliers/product-security/` mit Filtern nach Supplier, Produkt/Service, Status, Schweregrad, ueberfaelligen Reviews sowie DORA-, NIS2-, DSGVO- und kritischer-Service-Relevanz
- erweitert Regulatory Review-Pakete fuer NIS2, DORA, DSGVO und generische Security Governance um Supplier/Product-Security-Gaps, offene Advisorys, kritische Lieferantenabhaengigkeiten, fehlende Evidence, fehlende Owner, offene Massnahmen sowie Vertrags-/Exit-Plan-Hinweise
- ergaenzt Review-Pack-Filter fuer Pack-Typ, Status, Zeitraum, offene/kritische Luecken und sichere Limits
- ergaenzt Owner-/Verantwortlichen-Hinweise in Regulatory Review Pack Previews, ohne fehlende Verantwortliche zu erfinden oder Kontaktdaten unnoetig auszugeben
- ergaenzt pack-spezifische Lueckengruppierung fuer NIS2, DORA, DSGVO/GDPR und generische Security Governance
- verbessert die deutsche UI-/Doku-Sprachkonsistenz der Regulatory Review-Pakete und aktualisiert die zugehoerigen Screenshots
- ergaenzt kontextsensitive Regulatory Review-Pakete fuer NIS2, DORA, DSGVO/GDPR und generische Security Governance
- ergaenzt tenantgebundene Regulatory-Review-Pack-APIs fuer Pack-Katalog, Preview, Snapshot-Erzeugung, Snapshot-Liste/-Detail und Markdown/HTML/PDF/JSON-Exporte
- ergaenzt die Weboberflaeche `/regulatory-review-packs/` mit Pack-Auswahl, Preview, Snapshot-Erzeugung und Snapshot-Liste
- erweitert Management-/Regulatory-Snapshots um Evidence-Integrity-, Worker-, Storage-/Restore-, Legal-Hold- und kontrollierte Disposition-Aggregate
- ergaenzt aktualisierte GUI-Screenshot-Dokumentation fuer Regulatory Review-Pakete und angrenzende Governance-Module
- ergaenzt Evidence Object Storage & Restore Drill Phase 2 mit interner lokaler Artefakt-Storage-Abstraktion
- ergaenzt tenantgebundene Evidence-Storage-Uebersichts-/Detail-APIs, begrenzte Storage-Drill-APIs und Storage-Event-Filter ohne produktive S3-Credentials
- erweitert `/evidence/integrity/` um lokale Storage-Metadaten und Admin-/Editor-Aktionen fuer Storage-/Restore-Drills
- ergaenzt Evidence Integrity & Disposition Phase 1 ueber additive Migration `0033_rust_evidence_integrity_disposition`
- ergaenzt tenantgebundene Evidence-Integrity-Uebersichten, manuelle und begrenzte Batch-SHA-256-Pruefungen, Legal-Hold-Metadaten, Disposition-Entscheidungen und Integritaets-/Disposition-Audit-Events
- ergaenzt Web-UI-Unterstuetzung unter `/evidence/integrity/` fuer sichere Evidence-Integritaetsmetadaten, Re-Hash-Aktionen, Legal Hold Set/Release und dokumentierte Disposition-Entscheidungen
- add Management-/Regulatory-Templates for ISO 27001, NIS2, DORA, KRITIS, and generic security governance reviews through additive migration `0032_rust_management_regulatory_templates`
- extend Management Review snapshots with template metadata, regulatory context, supplier review summaries, source counts, gap summaries, and management decision hints
- add authenticated template list/detail APIs, regulatory preview API, and Management Review Web UI template selection without creating snapshots during preview
- add a tenant-scoped Supplier Review Workflow with additive migration `0031_rust_supplier_review_workflow`
- add Supplier review statuses for draft, in_review, approved, approved_with_conditions, rejected, expired, and archived decisions
- add Supplier approval history, subprocessor records, contract lifecycle metadata, exit-test status, and explicit Evidence, Control, and Risk links
- extend Supplier APIs and Web UI with create, update, review, subprocessor, and link-management flows
- extend the existing secure notification channels, worker, cooldown, and delivery audit to Evidence lifecycle and quality, Product Security/CVE reviews, Incident non-reporting decisions, and Roadmap task deadlines
- add tenant-scoped cross-domain signal evaluation and safe delivery metadata through additive migration `0029_rust_cross_domain_notifications`
- expose safe cross-domain delivery history to authenticated read-only roles while keeping channel and signal-scope configuration administrator-only
- add a guided, three-step Zero-Trust Agent onboarding workflow for Windows, Linux, macOS, and NixOS using the existing deployment artifacts
- add tenant-scoped enrollment-token metadata, revocation, policy assignment, fleet status, and lifecycle audit views
- add enrollment-token lifecycle states for pending, partial, consumed, expired, and revoked rollouts with bounded multi-use support
- connect tenant-scoped AI Governance systems to existing risks, roadmap tasks, incidents, and canonical change records
- add explicit, duplicate-safe roadmap task creation from open AI Governance gaps with a stable origin key
- include frozen AI Governance link summaries in management review UI and Markdown, HTML, PDF, and JSON exports
- add authenticated APIs and Web UI actions to list, create, and remove AI Governance links

### Security

- blocks the development-only passwordless `tenant_id`/`user_id` session compatibility flow in Demo and Production
- requires an explicitly configured trusted proxy boundary before Demo or Production can accept `x-iscy-*` identity headers
- redacts internal SQL, table, and store details from session-read and session-creation failures
- prevents PostgreSQL restore drills from logging credential-bearing database URLs and rejects identical source/restore targets before destructive restore preparation
- excludes Rust target directories, local RC/test artifacts, runtime state, backups, and local tool caches from the Docker build context

- serialisiert parallele PostgreSQL-Migrationen mit einem begrenzten Advisory Lock und verhindert parallele tenantgleiche Evidence-Worker-Laeufe sowie doppelte S3-Disposition durch atomare, lease-gebundene DB-Claims
- liefert Readiness-Fehler ausschliesslich als kompakte sichere Klassen ohne Connection Strings, SQL-/Store-Details, Secrets oder interne Pfade
- loest S3-Zugangsdaten ausschliesslich pro Operation aus expliziten Secret-Referenzen auf; AWS-Profile, SSO, Home-Verzeichnisse, EC2/ECS-Metadata-Credentials, Proxy-Autodiscovery und Redirects sind nicht aktiviert
- erzwingt fuer produktive S3-Endpoints HTTPS und blockiert Credentials in URLs, Loopback, Link-Local, private/CGNAT-Netze, `.local` und Metadata-Dienste; lokales MinIO ist nur im Development-Modus mit `ISCY_EVIDENCE_ALLOW_LOCAL_TEST_ENDPOINT=true` zulaessig
- erzeugt kanonische Object Keys serverseitig aus Tenant-, Evidence- und opaque Object-ID, persistiert nur die opaque ID, den Key-Hash und eine redigierte Anzeige und akzeptiert keine frei gewaehlten Runtime-Keys aus Requests
- begrenzt S3-Objekte auf das Evidence-Upload-Limit, liest GET-Antworten chunkweise mit harter Obergrenze und protokolliert weder Object-Inhalte noch Credentials, Secret-Dateipfade, Authorization Header oder SDK-/SQL-Details
- fuehrt Remote-DELETE ausschliesslich nach bestehender Approval-, Begruendungs- und Legal-Hold-Pruefung aus, verifiziert die Abwesenheit und erhaelt Tombstone-/Key-Hash-Metadaten
- speichert Agent-PKI- und CSR-Daten ausschliesslich als Governance-/Statusmetadaten; rohe private Schluessel, produktive CA-Secrets, Cloud-Credentials, echte CA-Ausstellung, automatische mTLS-Aktivierung und produktive Rotation/Widerruf bleiben bewusst ausserhalb dieses PRs
- haelt Agent-PKI-Provider, CSR, Zertifikatsstatus und Auditereignisse tenantgebunden; schreibende Aktionen bleiben Admin-/Editor-Rollen vorbehalten, Read-only-Rollen sehen nur sichere Metadaten
- validiert Provider-, CSR-, Zertifikats-, mTLS-, Rotations- und Widerrufstatus mit sicheren 4xx-Antworten und blockiert private-key-, Secret-, Token- und lokale Pfadfragmente in PKI-Metadaten
- berechnet Agent-Artefakt-SHA-256 nur aus einer festen Repo-Artefakt-Allowlist und gibt keine Rohdateien, absoluten lokalen Pfade, Tokens, privaten Schluessel, Zertifikate oder Build-Secrets ueber API, UI oder Audit aus
- modelliert Signaturstatus und Provenance ohne produktive Code-Signing-Zertifikate, private Schluessel, externe PKI/CA, Sigstore-/Rekor-/Fulcio-Netzwerkaufrufe oder GitHub-Release-Veroeffentlichung
- haelt Agent-Artefakt-Refresh, Checksum-Verify und Signature-Verify auf schreibende Rollen beschraenkt; Read-only-Rollen sehen nur sichere tenantgebundene Metadaten
- verhindert physische Evidence-Aussonderung vor Approval-/Reason-/Legal-Hold-Pruefung; verweigerte Ausfuehrungen werden sicher auditierbar dokumentiert, ohne Storage-Pfade zu beruehren
- fuehrt physische Disposition nur ueber canonical-path-gepruefte Storage-Abstraktion aus und speichert Tombstone-Metadaten mit sicherer Fehlerklasse, Backend und Hash statt Rohpfaden oder Dateiinhalten
- haelt Evidence-Worker-Start, Disposition-Approval und Disposition-Execute auf Administrator-/Editor-Rollen beschraenkt; Read-only-Rollen sehen nur sichere, tenantgebundene Metadaten
- validiert vorbereitetes Object Storage nur ueber Endpoint-/Bucket-/Region- und Secret-Referenzsignale; echte Cloud-Credentials, Secretwerte und externe Netzwerkaufrufe werden nicht eingefuehrt
- validiert Object-Storage-Endpoints gegen Credentials in URLs, unsichere Schemes, Loopback, Link-Local, private Netze und Metadata-Services; produktive DNS-/Redirect-/Live-Checks bleiben fuer einen separaten echten S3-Client reserviert
- speichert Object-Storage-Secret-Referenzen nur als Referenzen und lehnt direkt wirkende Secretwerte, private-Key-Fragmente und URL-artige Secret-Inputs mit sicheren 4xx-Fehlerklassen ab
- speichert keine vollstaendigen Object-Keys; Object-Referenzen persistieren nur redaktionelle Anzeige, SHA-256 des Keys, Tenant-/Evidence-Bindung, erwartete Hashes und Contract-Status
- haelt Object-Storage-Backend-Konfiguration, Validierung, Object-Referenz-Anbindung und Contract-Drills tenantgebunden und auf Admin-/Editor-Schreibrollen beschraenkt; Read-only-Rollen sehen nur sichere Metadaten und Events
- haelt Supplier/Product-Security-Datensaetze, Evidence-Links, Events und Vertrags-/Exit-Historie tenantgebunden; Admin-/Editor-Rollen duerfen schreiben, Read-only-Rollen sehen nur sichere Metadaten
- validiert Status-, Severity-, Datums-, CVE-, Score-, Owner-, Supplier-, Evidence- und Referenzfelder mit sicheren 4xx-Fehlern ohne SQL-/Store-Details, Secrets, Rohpayloads oder absolute Dateipfade
- speichert Advisory-/PSIRT-/CVE-Referenzen nur lokal als Text/URL und fuehrt keine externen Live-Abfragen aus; URL-Ausgabe in API und Web UI bleibt gegen unsichere Schemes und HTML-Injection abgesichert
- auditierbare Supplier/Product-Security-Erstellung, Aenderung, Statuswechsel, Evidence-Verknuepfung und Vertrags-/Exit-Plan-Aenderung ohne vertrauliche Datei-Inhalte, Tokens, Authorization-Header oder fremde Tenant-IDs
- haelt Regulatory-Review-Pack-Filter, Previews, Snapshots und Exporte tenantgebunden; Read-only-Rollen duerfen sichere Inhalte lesen, Snapshot-Erzeugung bleibt schreibenden Rollen vorbehalten
- validiert Pack-Typ-, Status-, Zeitraum-, Gap- und Limit-Filter mit sicheren 4xx-Fehlern ohne SQL-/Store-Details
- nutzt die bestehende Management-Review-Snapshot- und Audit-Infrastruktur fuer Regulatory Review-Pakete, ohne zweiten Compliance-Store und ohne Evidence-Pfade, SQL-Details, Secrets oder rohe Evidence-Payloads offenzulegen
- routet Evidence-Artefaktpruefungen ueber ein canonical-media-root-geprueftes Filesystem-Backend, das Traversal, absolute Pfade und Symlink-Flucht blockiert
- auditiert Evidence-Storage-Drills, Artefaktstatus, Hash-Abweichungen, Drill-Fehler und kontrollierte Disposition ohne absolute Pfade, Rohpayloads, SQL-Details oder Secrets
- nutzt bestehende Evidence-Integrity-Metadaten und Audit-Tabellen fuer Storage-Drills und Disposition, ohne eine neue Evidence-Engine oder destruktive Migration einzufuehren
- haelt Evidence-Re-Hash, Legal Hold, Worker-Start und Disposition-Schreibpfade tenantgebunden und auf Admin-/Editor-Rollen beschraenkt
- macht `disposition_completed_metadata_only` weiterhin als Governance-Entscheidung sichtbar; physische Disposition ist davon getrennt und nur nach expliziter Freigabe ausfuehrbar
- audit Management Review template previews, snapshot creation, status changes, and exports without storing raw payloads or secret material
- keep Management-/Regulatory-Template previews and generated snapshots tenant-scoped and enforce read-only versus write-role separation for snapshot creation
- audit Supplier creation, updates, review decisions, subprocessor changes, and Evidence, Control, and Risk link changes without exposing SQL details or secret payloads
- enforce tenant-scoped Supplier writes, link validation, owner references, Evidence references, and subprocessor visibility
- reserve tenant- and channel-scoped notification dispatch claims atomically before webhook delivery through additive migration `0030_rust_notification_dispatch_claim`, preventing duplicate sends from overlapping manual and periodic evaluations
- correct PostgreSQL integer decoding in the Agent Governance notification path so policy, channel, CVE, device, and delivery metadata use the existing Rust API types consistently
- redact internal Agent Governance store and SQL errors from HTML responses while preserving safe API validation behavior
- keep cross-domain webhook payloads intentionally minimal and exclude stored payloads, internal errors, credentials, authorization headers, and secret references from delivery APIs and read-only views
- preserve production host allow-listing, disabled redirects, bounded retries, stable signal-key deduplication, and per-channel cooldown for every notification domain
- make token consumption, device enrollment, policy assignment, secret-hash persistence, and lifecycle audit events transactional on SQLite and PostgreSQL
- return enrollment tokens and agent secrets only in no-store responses, retain hashes instead of plaintext, and reject untrusted client-supplied mTLS fingerprint headers
- enforce administrator-only token creation and revocation while allowing authenticated read-only roles to inspect safe tenant-scoped metadata
- enforce tenant predicates while resolving every AI Governance system and linked target
- persist link and unlink audit events and reject foreign-tenant, manipulated, and duplicate relationships

### Security and supply chain

- expand staggered weekly Dependabot coverage to Cargo, the backend Dockerfile, root and monitoring Compose stacks, Nix inputs, and GitHub Actions
- update `chrono` from 0.4.44 to 0.4.45 after isolated review and a fully green CI run

## V23.7.27

### Security

- add authenticated, tenant-scoped Evidence downloads with protection-class authorization, safe canonical path resolution, private caching, and structured access decisions
- deny direct reverse-proxy access to uploaded Evidence under `/media/`
- remove legacy URL identity parameters before requests reach non-development route handlers
- keep the backend container port private in stage and production deployments
- bind development database and backend ports to localhost
- enforce explicit production mode, database configuration, secure-cookie settings, and trusted-proxy assumptions
- build the Rust container with `Cargo.lock` and run it as a dedicated non-root user
- drop container capabilities and enable `no-new-privileges` in stage and production
- stop logging complete database URLs
- mount operator-managed runtime secrets read-only and exclude local runtime material from Git
- exclude production environment snapshots from backups
- verify backup checksums and archive structure before destructive restore
- document the project threat model and mandatory AI-assisted contribution invariants
- add mandatory Rust advisory, dependency-license, and source-policy checks to CI

### Operations and community readiness

- add locked Rust and hardened Docker-image checks to CI
- add automated dependency update coverage for Cargo, Docker, and GitHub Actions
- strengthen the production-readiness check for file permissions, placeholders, runtime secrets, and effective Compose configuration
- protect `main` through pull requests, required CI checks, linear history, deletion protection, and force-push protection
- provide a fully English primary README and a maintained German overview
- clarify the implemented Evidence-download invariants in `AGENTS.md`

### Validation

- Rust formatting and Clippy with warnings denied
- locked Rust test suite and negative authorization tests
- Rust DB/bootstrap HTTP smoke
- Nix application smoke
- development, stage, production, and LLM Compose validation
- hardened non-root Docker image build
- Rust advisory, license, and source-policy checks

## V23.7.26

### Added

- versioned Product Security evidence packages for release and PSIRT decisions
- review states, blockers, conditional approvals, and immutable package versions
- Markdown, HTML, PDF, and JSON exports
- operational status signals for package backlog and blockers

### Validation

- 236 Rust tests reported successful for the release commit
- release commit: `4ed62c8`
