# Changelog

All notable changes to ISCY are documented in this file.

The project uses release tags for immutable release points. Changes under **Unreleased** are part of the next release candidate until they are assigned to a version.

## Unreleased

### Added

- ergaenzt Agent-Release-Artefakte und Release-Provenance ueber additive Migration `0036_rust_agent_release_artifact_provenance`
- ergaenzt tenantgebundene Agent-Artefakt-APIs fuer Manifestliste/-detail, Refresh, SHA-256-Pruefung, Signaturstatuspruefung, Provenance-Liste/-detail und Onboarding-Artefakte unter `/api/v1/agents/artifacts*`, `/api/v1/agents/release-provenance*` und `/api/v1/agents/onboarding/artifacts`
- erweitert `/zero-trust/` und den gefuehrten Agent-Onboarding-Assistenten um deutsche Artefakt-/Pruefsummen-/Signatur-/Provenance-Hinweise fuer systemd, NixOS, Windows Scheduled Task, PowerShell, macOS LaunchDaemon und Konfigurationsbeispiele
- erweitert Management-/Regulatory-Review-Pakete fuer NIS2, DORA, DSGVO und generische Governance um Agent-Artefakt-, Signatur-, Pruefsummen- und Release-Provenance-Gaps
- ergaenzt Evidence-Worker, kontrollierte physische Disposition und vorbereitetes Object-Storage-Backend ueber additive Migration `0035_rust_evidence_worker_disposition_storage`
- ergaenzt tenantgebundene Evidence-Worker-APIs fuer Status, manuelle begrenzte Worker-Laeufe und Laufhistorie unter `/api/v1/evidence/integrity/worker*`
- ergaenzt kontrollierte Disposition-APIs fuer Kandidaten, Preview, Approval, Execute, Cancel und Ereignisse; physische Aussonderung erfolgt nur nach dokumentierter Freigabe, ohne Legal Hold und ueber die sichere Storage-Abstraktion
- ergaenzt Storage-Backend-Status unter `/api/v1/evidence/storage/backends` mit `local_filesystem` als Default und sicher vorbereiteten `s3_compatible`-Konfigurationssignalen ohne Live-Credentials oder Netzwerkaufrufe
- erweitert `/evidence/integrity/` um Integritaets-Worker-Status, letzte Worker-Laeufe, Storage-Backend-Status, Disposition-Kandidaten sowie Freigabe-/Aussonderungsaktionen fuer schreibende Rollen
- erweitert Regulatory Review-Pakete fuer NIS2, DORA, DSGVO und generische Governance um Evidence-Worker-, Storage-/Restore- und kontrollierte Disposition-Signale
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

- berechnet Agent-Artefakt-SHA-256 nur aus einer festen Repo-Artefakt-Allowlist und gibt keine Rohdateien, absoluten lokalen Pfade, Tokens, privaten Schluessel, Zertifikate oder Build-Secrets ueber API, UI oder Audit aus
- modelliert Signaturstatus und Provenance ohne produktive Code-Signing-Zertifikate, private Schluessel, externe PKI/CA, Sigstore-/Rekor-/Fulcio-Netzwerkaufrufe oder GitHub-Release-Veroeffentlichung
- haelt Agent-Artefakt-Refresh, Checksum-Verify und Signature-Verify auf schreibende Rollen beschraenkt; Read-only-Rollen sehen nur sichere tenantgebundene Metadaten
- verhindert physische Evidence-Aussonderung vor Approval-/Reason-/Legal-Hold-Pruefung; verweigerte Ausfuehrungen werden sicher auditierbar dokumentiert, ohne Storage-Pfade zu beruehren
- fuehrt physische Disposition nur ueber canonical-path-gepruefte Storage-Abstraktion aus und speichert Tombstone-Metadaten mit sicherer Fehlerklasse, Backend und Hash statt Rohpfaden oder Dateiinhalten
- haelt Evidence-Worker-Start, Disposition-Approval und Disposition-Execute auf Administrator-/Editor-Rollen beschraenkt; Read-only-Rollen sehen nur sichere, tenantgebundene Metadaten
- validiert vorbereitetes Object Storage nur ueber Endpoint-/Bucket-/Region- und Secret-Referenzsignale; echte Cloud-Credentials, Secretwerte und externe Netzwerkaufrufe werden nicht eingefuehrt
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
