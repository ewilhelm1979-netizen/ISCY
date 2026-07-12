# ISCY Strategic Roadmap

Stand: 2026-07-09

Diese Roadmap beschreibt die fachlich sinnvollen naechsten Ausbaustufen nach dem Rust-only-Cutover. Sie ersetzt die alte Rust-Migrationsroadmap nicht, sondern beginnt danach: ISCY ist technisch auf Rust umgestellt und soll nun fachlich reifer, pruefbarer und im Betrieb wirksamer werden.

## Leitgedanke

ISCY soll keine Regulierungssilos bauen. Die Plattform soll Organisationen, Assets, Suppliers, Produkte, Controls, Risiken, Evidence, Incidents, Product Security, AI Governance, Agent-Posture und Roadmap-Arbeit so verbinden, dass neue regulatorische Anforderungen als Mapping und Entscheidungspfad aufgenommen werden koennen.

Die fachliche Ausrichtung orientiert sich an:

- NIS2 und der Einstufung erheblicher Sicherheitsvorfaelle
- DORA fuer IKT-Risikomanagement, IKT-Vorfaelle und IKT-Drittparteienrisiko
- DSGVO fuer Datenschutzverletzungen und Betroffenenrisiken
- Cyber Resilience Act fuer Product Security, Vulnerability Handling, Support und Security Updates
- EU AI Act fuer KI-Inventar, Klassifizierung, Logging, Transparenz, Human Oversight, Robustheit und Cybersecurity
- ISO 27001, TISAX, NIST CSF 2.0 sowie CSAF, CycloneDX und SPDX als praktische Struktur- und Nachweisreferenzen

## Prioritaet 1: Regulatorisches Organisationsprofil

Ziel: ISCY soll pro Tenant zentral verstehen, in welchem regulatorischen Kontext die Organisation arbeitet.

Status: In V23.7.19 als Rust-Web-/API-Pfad umgesetzt.

Umgesetzt:

- Organisationsprofil mit strukturierten Angaben zu Branche, Laendern, Groesse, kritischen Services, NIS2-Scope, KRITIS-Bezug, DORA-Finanzsektor- oder IKT-Drittparteienbezug, DSGVO-Rolle, CRA-Produktbezug, AI-Act-Relevanz, TISAX-Scope und ISO-27001-Zielbild.
- Schreibbare Weboberflaeche unter `/organizations/`.
- API-Pfad `GET` und `PATCH /api/v1/organizations/tenant-profile`.
- Regulatorische Matrix fuer aktive Pfade, Begruendung und naechsten fachlichen Schritt.
- Demo-Seed und Migration `0018_rust_tenant_regulatory_profile`.

Naechste Vertiefung:

- Incident-, Control-, Evidence- und Product-Security-Flows noch staerker aus diesem Profil vorsteuern.
- NIS2-/DORA-/DSGVO-Pruefpakete kontextsensitiv vorausfuellen, statt generische Hinweise zu erzeugen.
- Dashboard-Badges fuer regulatorische Betroffenheit anzeigen.

Erfolgskriterium:

- Ein Tenant kann auf einen Blick erkennen, welche regulatorischen Pfade aktiv sind und warum.

## Prioritaet 2: Management-Review- und Audit-Paket

Ziel: ISCY soll aus vorhandenen Daten automatisch ein Management-Review- und Audit-Paket erzeugen.

Status: In V23.7.20 als Rust-Web-/API-Pfad und persistierter Audit-Snapshot umgesetzt; V23.7.21 ergaenzt Exporte und Snapshot-Ruecklinks. Im Unreleased-Stand kommen Management-/Regulatory-Templates fuer ISO 27001, NIS2, DORA, DSGVO, KRITIS und generische Security-Governance-Reviews sowie kontextsensitive Regulatory Review-Pakete fuer NIS2, DORA und DSGVO hinzu. Der Review-Pack-Polish ergaenzt Filter, Owner-Hinweise, pack-spezifische Lueckengruppen und deutsch konsistente UI-Beschriftungen; Supplier/Product-Security-Gaps werden nun in NIS2-, DORA-, DSGVO- und generischen Review-Paketen beruecksichtigt.

Umgesetzt:

- Weboberflaeche unter `/management-reviews/`.
- API-Pfade `GET` und `POST /api/v1/reports/management-reviews`.
- API-Pfade `GET` und `PATCH /api/v1/reports/management-reviews/{review_id}` fuer Detail und Status.
- Persistierte Review-Pakete mit Zeitraum, Status, Executive Summary, Entscheidung, naechsten Massnahmen, freigebendem User und Freigabezeitpunkt.
- Automatisch erzeugter Snapshot mit Kennzahlen, Top-Risiken, ISCY-27-Control-Gaps, Evidence-Luecken, Evidence-Integrity-/Storage-Aggregaten, Incident-Entscheidungen, Roadmap-Fokus, Product-Security-Lage, Supplier Review, AI Governance und Agent-Posture.
- Direkte Ruecklinks aus Snapshot-Zeilen zu Risiken, Controls, Evidence, Incidents und Roadmap.
- Export als Markdown, HTML, PDF und JSON.
- Demo-Seed und Migration `0019_rust_management_review_packages`.
- Additive Migration `0032_rust_management_regulatory_templates` ergaenzt Template-Typ, Template-Version, regulatorischen Kontext, Supplier-Summary, Source Counts, Gap-Summary, Decision-Summary und eine Management-Review-Auditspur.
- API-Pfade `GET /api/v1/management/templates`, `GET /api/v1/management/templates/{template_type}`, `POST /api/v1/regulatory/templates/{template_type}/preview` sowie Alias-Pfade unter `/api/v1/management/reviews`.
- Regulatory-Review-Pack-API-Pfade `GET /api/v1/regulatory/review-packs`, `GET /api/v1/regulatory/review-packs/{pack_type}`, `POST /api/v1/regulatory/review-packs/{pack_type}/preview`, `GET` und `POST /api/v1/regulatory/review-packs/{pack_type}/snapshots`, `GET /api/v1/regulatory/review-pack-snapshots/{snapshot_id}` und `GET /api/v1/regulatory/review-pack-snapshots/{snapshot_id}/export?format=markdown|html|pdf|json`.
- Snapshot-Listen koennen sicher nach Pack-Typ, Status, Zeitraum, offenen Luecken, kritischen Luecken und Limit gefiltert werden.
- Weboberflaeche mit Template-Auswahl, Preview vor Snapshot-Erzeugung und Detailansicht fuer Quellen, Gaps, Management-Hinweise, Supplier Review und regulatorischen Kontext.
- Weboberflaeche `/regulatory-review-packs/` mit NIS2-, DORA- und DSGVO-Auswahl, Filterbereich, Preview, Owner-/Verantwortlichen-Hinweisen, pack-spezifischer Lueckenuebersicht, Snapshot-Erzeugung und Snapshot-Liste.
- Preview erzeugt keinen Review-Snapshot; Snapshot-Erzeugung bleibt schreibenden Rollen vorbehalten.
- Supplier/Product-Security-Daten aus Migration `0034_rust_supplier_product_security_governance` fliessen in Review-Pakete als offene Advisorys, kritische Lieferantenabhaengigkeiten, fehlende Evidence, fehlende Owner, offene Massnahmen, Vertrags-/Exit-Plan-Hinweise und relevante DORA-/NIS2-/DSGVO-Bezuege ein.
- Regulatory Review-Pakete liefern Governance- und Evidence-Unterstuetzung, aber keine Rechtsberatung, Zertifizierung, automatische Meldung oder formale Einreichung.

Naechste Vertiefung:

- Review-Pack-Bedienung fachlich weiter vertiefen, z. B. Review-Owner aus kuenftigen kanonischen Owner-Feldern, bessere Pack-spezifische Exportgliederung und spaetere visuelle Regression.

Erfolgskriterium:

- Ein Management-Review kann direkt aus ISCY vorbereitet, geprueft und auditierbar abgelegt werden.

## Prioritaet 3: Evidence-Qualitaet und Nachweisreife

Ziel: Evidence soll nicht nur vorhanden sein, sondern belastbar bewertet werden.

Status: In V23.7.21 als Evidence-Quality-API und Webansicht umgesetzt; am 2026-06-27 um den persistierten Evidence-Lifecycle erweitert. Im Unreleased-Stand sind Evidence Integrity & Disposition Phase 1, Evidence Object Storage & Restore Drill Phase 2, Integritaets-Worker, kontrollierte physische Disposition, die Object-Storage-Contract-Schicht sowie der echte S3-kompatible Runtime-Client mit Migration `0039_rust_evidence_s3_runtime_client` umgesetzt.

Umgesetzt:

- Weboberflaeche unter `/evidence/quality/`.
- API-Pfad `GET /api/v1/evidence/quality`.
- Evidence-Quality-Score je Evidence Item aus Status, Review, Datei-/Artefaktreferenz, Traceability, Owner und Review-Notiz.
- Issue-Queue fuer fehlende Datei, fehlenden Review, fehlenden Owner, fehlende Traceability oder fehlende Review-Notiz.
- Evidence-Need-Reife mit offen, teilweise und abgedeckt.
- Migration `0024_rust_evidence_lifecycle` fuer serverseitige Versionsketten, SHA-256, Gueltigkeit, Aufbewahrungsfrist/-begruendung und Schutzklasse.
- Automatische SHA-256-Bildung bei Datei-Uploads; der Hash wird nicht aus Client-Eingaben uebernommen.
- Tenantgebundene Versionskette ueber `supersedes_id`; pro Vorgaenger ist genau ein direkter Nachfolger zulaessig.
- Schutzklassen `PUBLIC`, `INTERNAL`, `CONFIDENTIAL` und `RESTRICTED`.
- Quality-Issues und Betriebszentrale fuer abgelaufene, bald ablaufende, ungehashte oder ohne Retention gefuehrte Evidence.
- Incident-/NIS2-/DORA-/DSGVO-Exporte weisen Version, Schutzklasse, Gueltigkeit und SHA-256 aus.
- Migration `0033_rust_evidence_integrity_disposition` ergaenzt Integritaetsstatus, letzten Re-Hash-Zeitpunkt, berechneten Hash, sichere Fehlerklasse, Quarantaene-/Review-Status, Legal Hold, Retention-/Disposition-Metadaten und eine eigene Evidence-Integritaetsereignistabelle.
- Weboberflaeche unter `/evidence/integrity/`.
- API-Pfade fuer sichere Integritaetsuebersicht, einzelne Re-Hash-Pruefung, begrenzte Batch-Pruefung, Integritaetsereignisse, Legal-Hold-Set/Release und dokumentierte Disposition-Entscheidungen.
- Serverseitige SHA-256-Neuberechnung vorhandener Evidence-Artefakte mit Status `valid`, `mismatch`, `missing_artifact` oder `check_failed`.
- Legal Hold kann Disposition-Entscheidungen blockieren und wird mit Begruendung, Akteurreferenz und Zeitpunkt auditierbar gefuehrt.
- Disposition bleibt in Phase 1 ein Governance-/Audit-Metadatenmodell; `disposition_completed_metadata_only` loescht keine Dateien.
- Interne Storage-Abstraktion fuer Evidence-Artefakte mit erstem Backend `local_filesystem`.
- Storage-API-Pfade fuer Uebersicht, Detail, einzelne Drills, begrenzte Batch-Drills und Storage-Events.
- Die bestehende Weboberflaeche `/evidence/integrity/` zeigt lokale Storage-Metadaten und bietet fuer Admin/Editor einen Storage-/Restore-Drill an.
- Filesystem-Backend prueft Artefaktreferenzen ueber canonical path containment, blockiert Traversal, absolute Pfade und Symlink-Flucht aus dem Media Root und gibt nur sichere Fehlerklassen zurueck.
- Restore-/Integrity-Drill belegt, dass referenzierte Artefakte am erwarteten lokalen Storage-Ort vorhanden, lesbar und SHA-256-konsistent sind; Ergebnisse werden in den bestehenden Evidence-Integrity-Feldern und `storage_*` Audit-Events dokumentiert.
- Migration `0035_rust_evidence_worker_disposition_storage` ergaenzt Worker-Laufhistorie, vorbereitete Storage-Backend-Statusdaten und kontrollierte Disposition-Ausfuehrungsmetadaten inklusive Tombstone-Hash.
- Integritaets-Worker-APIs `GET /api/v1/evidence/integrity/worker`, `POST /api/v1/evidence/integrity/worker/run` und `GET /api/v1/evidence/integrity/worker/runs` liefern Betriebssignale, begrenzte manuelle Laeufe, Batch-/Runtime-Grenzen, Dry-Run und Laufhistorie.
- Kontrollierte Disposition nutzt getrennte APIs fuer Kandidaten, Preview, Approval, Execute, Cancel und Ereignisse; Execute prueft vor jeder Storage-Operation Approval, Begruendung und Legal Hold und laeuft nur ueber die Storage-Abstraktion.
- Storage-Backend-Status `GET /api/v1/evidence/storage/backends` zeigt `local_filesystem` als Default und ein vorbereitetes `s3_compatible`-Backend mit Konfigurationsvalidierung, aber ohne echte Cloud-Credentials oder externe Netzwerkaufrufe.
- Migration `0038_rust_evidence_object_storage_client` ergaenzt tenantgebundene Object-Storage-Backend-Konfigurationen, Secret-Referenzstatus, sichere Object-Referenzen, Backend-Events und Contract-Drills.
- Neue API-Pfade verwalten Backend-Metadaten, validieren Endpoint-/Bucket-/Secret-Referenzen, binden Object-Referenzen an Evidence und dokumentieren Object-Storage-Drills, ohne vollstaendige Object-Keys, Secretwerte oder Objektinhalte offenzulegen.
- Endpoint- und Object-Key-Validierung blockiert Credentials in URLs, unsichere Schemes, Loopback, Link-Local, private Netze, Metadata-Services, Directory Traversal, fremde Prefixe und Object-Keys ohne aktuellen Tenant-/Evidence-Bezug.
- Management-/Regulatory-Review-Pakete nehmen Object-Storage-Backend-, Konfigurations-, Drill- und Objekt-/Hash-Gaps als aggregierte Snapshot-Signale auf.
- Migration `0039_rust_evidence_s3_runtime_client` ergaenzt echte SigV4-PUT-/HEAD-/GET-/DELETE-Operationen, explizite `env:`-/allowlisted-`file:`-Secret-Aufloesung, Request-Time-DNS-/SSRF-Revalidierung und serverseitig erzeugte opaque Object-IDs.
- Bestehender Evidence-Upload, autorisierter Download, Integritaets-Worker, Restore-Pruefung und kontrollierte Disposition verwenden tenantgebundene S3-Runtime-Referenzen; Remote-Delete bleibt Approval-, Reason- und Legal-Hold-gebunden.
- `make object-storage-integration` und der getrennte GitHub-CI-Job pruefen den realen S3-Lifecycle gegen versioniertes MinIO mit Dummy-Credentials und Cleanup.
- NIS2-, DORA-, DSGVO- und generische Review-Pakete nehmen Evidence-Worker-, Storage-/Restore-, Legal-Hold- und Disposition-Gaps als eingefrorene Snapshot-Signale auf.
- Der PostgreSQL-Live-Haertungstest fuer Migration `0034_rust_supplier_product_security_governance` wurde lokal mit temporaerer PostgreSQL-Instanz, Supplier/Product-Security-API, Evidence-Link, Event- und Vertrags-/Exit-Historie erfolgreich nachgezogen.

Naechste Vertiefung:

- Produktive Pilotierung eines S3-kompatiblen Backends mit Betreiber-Secret-Roots, Zertifikats-/Endpoint-Policy und Restore-Zeitplan getrennt vom Code-Review planen.
- Vier-Augen-Prinzip fuer physische Disposition vorbereiten, falls das bestehende Rollenmodell fachlich erweitert wird.
- Periodische Hintergrundausfuehrung des Evidence-Workers an den bestehenden Betriebs-/Scheduler-Rahmen anbinden.

Erfolgskriterium:

- ISCY unterscheidet zwischen "Nachweis existiert" und "Nachweis ist aktuell, vertrauenswuerdig und reviewt".

## Prioritaet 4: Third-Party- und Supplier-Risk

Ziel: Lieferanten, Cloud-, SaaS-, IKT- und Produktzulieferer sollen als eigener Risikobereich sichtbar werden.

Status: In V23.7.22 als Supplier-Risk-API und Webansicht umgesetzt. Im
Unreleased-Stand kommen der tenantgebundene Supplier-Review-Workflow und das
Supplier/Product-Security-Deepening hinzu.

Umgesetzt:

- Weboberflaeche unter `/suppliers/`.
- API-Pfade `GET` und `POST /api/v1/suppliers` sowie `GET` und `PATCH /api/v1/suppliers/{id}`.
- Supplier-Register mit Kritikalitaet, Services, Vertragsbezug, Security-Kontakt, Datenarten, Regionen, Exit-Abhaengigkeit, regulatorischem Scope, Review-Status, Review-Faelligkeit und Notes.
- Automatische Signale aus Produktkomponenten, offenen Product-Security-Schwachstellen, Supplier-bezogenen Risiken und Supplier-Evidence.
- DORA-IKT-Drittparteienbezug, NIS2-Supply-Chain-Bezug, CRA-Komponenten-/Herstellerbezug, DSGVO-Datenbezug und TISAX-Lieferkettennachweise werden als gemeinsame Flags sichtbar.
- Score- und Issue-Logik fuer kritische CVEs, ueberfaellige Reviews, fehlende Evidence, fehlenden Security-Kontakt, fehlende Exit-Strategie und fehlende Risikodokumentation.
- Evidence-Vorbefuellung mit stabilem Linked Requirement `SUPPLIER:{id}`.
- Migration `0031_rust_supplier_review_workflow` erweitert Supplier additiv um Review-Freigaben, Vertragslaufzeiten, Exit-Test-Nachweise, Verantwortungsreferenzen und explizite Linktabellen.
- Review-Statusmodell: draft, in_review, approved, approved_with_conditions, rejected, expired und archived.
- Freigabehistorie mit altem/neuem Status, Akteurreferenz, Begruendung, Risikostufe sowie optionalen Evidence- und Control-Referenzen.
- Unterauftragnehmer/Subprocessors sind nur im Supplier- und Tenant-Kontext sichtbar und werden bei Aenderungen auditierbar protokolliert.
- Supplier koennen explizit mit bestehenden Evidence-, ISCY-27-Control- und Risiko-Objekten verknuepft werden, ohne eine parallele Evidence-, Risiko- oder Control-Engine einzufuehren.
- Vertragsbeginn, Vertragsende, Kuendigungsfrist, automatische Verlaengerung, naechster Vertragsreview, Vertrags-Evidence sowie Exit-Test-Status und Exit-Test-Evidence sind als Metadaten abbildbar.
- Web-Detailansicht `/suppliers/{id}/` zeigt Reviewstand, Historie, Subprocessors, Vertrags-/Exit-Daten, Links und Auditspur; schreibende Aktionen bleiben Admin-/Editor-Rollen vorbehalten.
- Migration `0034_rust_supplier_product_security_governance` verbindet Supplier, Produkt/Service, lokale Advisory-/PSIRT-/CVE-Metadaten, SBOM-/VEX-Bezuege, Evidence, Review-Status, offene Massnahmen und Management-/Regulatory-Review-Bezug.
- Weboberflaeche `/suppliers/product-security/` zeigt Lieferant, Produkt/Service, Kritikalitaet, Advisory-/CVE-/PSIRT-Bezug, betroffene und behobene Versionen, Status, Owner, Faelligkeit, Evidence, Vertragsstatus, Exit-Plan-Status und DORA-/NIS2-/DSGVO-Relevanz.
- API-Pfade `GET`/`POST /api/v1/suppliers/product-security`, `GET`/`PATCH /api/v1/suppliers/product-security/{record_id}`, Status-, Evidence- und Event-Endpunkte sowie Supplier-bezogene Contract-/Exit-History-Abfragen.
- Vertrags-/Exit-Plan-Aenderungen werden als Historie mit Version, Akteurreferenz, Zeitpunkt, Grund, vorherigem/neuem Status, Summary und Evidence-Referenzen gefuehrt.
- Advisory-/PSIRT-/CVE-Referenzen bleiben lokale Metadaten und Import-Vorbereitung. ISCY ruft keine externen Hersteller-, NVD-, GitHub-Advisory- oder sonstigen Live-Feeds ab.

Naechste Vertiefung:

- Datenuebermittlungen und noch feinere Vertrags-/Exit-Dokumentenmodelle spaeter bewusst als eigenen Reifegrad betrachten.
- Externe Supplier-Advisory- und Herstellerfeeds erst als getrennten, sicherheitsgeprueften Import-Meilenstein anbinden.
- Management-/Regulatory-Templates nehmen Supplier-Review- und Supplier/Product-Security-Daten als eingefrorene Summary in wiederholbare Pruefpakete auf.

Erfolgskriterium:

- ISCY kann zeigen, welche externen Abhaengigkeiten kritisch sind, welche Nachweise fehlen und welche Risiken daraus entstehen.

## Prioritaet 5: Product-Security-Reife (umgesetzt in V23.7.23 und V23.7.26, vertieft im Unreleased-Stand)

Ziel: Der bestehende Product-Security-Bereich soll von Import/Korrelation zu einem echten PSIRT-/CRA-Arbeitsplatz wachsen.

Umgesetzt:

- VEX-Status je Schwachstelle aufnehmen: affected, not affected, fixed, under investigation.
- SBOM-Diff zwischen Importstaenden anzeigen.
- CRA-Readiness je Produkt aus SBOM, VEX/CVE-Triage, PSIRT/Advisories, Threat/TARA und Lifecycle ableiten.
- Migration `0026_rust_product_security_evidence_packages` fuer versionierte Release-/PSIRT-Pakete und eingefrorene Nachweispositionen.
- Web-/API-Workflow fuer Release- und PSIRT-Evidence-Pakete mit Readiness, Blockern, Warnungen und Reviewentscheidung.
- Blocker-Gate fuer vorbehaltlose Freigaben sowie dokumentierte bedingte Freigaben.
- Paketversionierung mit Vorgaengerbezug und Export als Markdown, HTML, PDF und JSON.
- Betriebs- und Prometheus-Signal fuer offene Paketreviews und Blocker.
- Supplier/Product-Security-Deepening verknuepft lokale Supplier-Advisory-, PSIRT- und CVE-Metadaten mit Lieferanten, Produkt/Service, Evidence, Review-Status, offenen Massnahmen, Vertrags-/Exit-Plan-Historie und Regulatory Review Packs.

Noch ausbaufähig:

- Security-Update- und Support-Ende je Produkt/Version pflegen.
- Externe Supplier-Advisory- und Herstellerfeeds je Produkt als separaten Import-/Validierungsmeilenstein verknuepfen.

Erfolgskriterium:

- ISCY kann fuer ein Produkt nachvollziehbar zeigen, welche Schwachstellen relevant sind, welche nicht, welche Releases betroffen sind und welche CRA-/PSIRT-Arbeit offen ist.

## Prioritaet 6: AI-Governance-Modul (umgesetzt in V23.7.24)

Ziel: KI-Systeme sollen als eigene Governance-Objekte in ISCY sichtbar werden.

Umgesetzt:

- Weboberflaeche unter `/ai-governance/`.
- API-Pfade `GET` und `POST /api/v1/ai-governance/systems`.
- API-Pfade `GET` und `PATCH /api/v1/ai-governance/systems/{id}`.
- KI-System-Inventar mit Zweck, Produktbezug, Owner, Datenarten, Modellquelle, Anbieter, Einsatzbereich, Kritikalitaet, Status und Review-Faelligkeit.
- AI-Act-Klassifizierung: nicht bewertet, verboten/nicht freigegeben, High Risk, Limited Risk, Minimal Risk oder nicht im Scope.
- Berechnete Governance-Anforderungen fuer Klassifizierung, Risikomanagement, Human Oversight, Logging, Transparenz, Cybersecurity/Robustheit sowie Monitoring/Evidence.
- Evidence-Vorbefuellung ueber stabile AI-Governance-Evidence-Keys.
- Rust-only-Betriebssignale fuer nicht bewertete AI-Systeme, faellige Reviews, fehlende Evidence und offene Governance-Gaps.
- Direkte tenantgebundene Links zu Risiken, Roadmap-Tasks, Incidents und kanonischen Changes.
- Link-Verwaltung und offene Governance-Gaps in der AI-System-Detailansicht.
- Explizite, durch `origin_key` duplikatgeschuetzte Roadmap-Task-Erzeugung aus offenen Gaps.
- Persistente Link-Auditspur und eingefrorene AI-Linkdaten in Management-Review-Paketen und Exporten.

Erfolgskriterium:

- ISCY kann KI-Systeme nicht nur inventarisieren, sondern ihre Governance-, Sicherheits- und Nachweislage steuerbar machen.

## Prioritaet 7: Agent-Flottenbetrieb und Benachrichtigungen

Ziel: Der Zero-Trust-Agent soll vom lokalen Collector zum betrieblich verwaltbaren Flottenbaustein wachsen.

Umgesetzt:

- persistenter, restriktiv geschuetzter Agent-State ohne Re-Enrollment bei jedem Start
- begrenzte At-least-once-Offline-Queue fuer Heartbeats und Findings
- administrative Agent-Secret-Rotation mit sofortiger Invalidierung des alten Secrets
- systemd-Timer, NixOS-Modul, Windows Scheduled Task und macOS LaunchDaemon
- Flottensignale in Betriebszentrale, JSON und Prometheus fuer Abdeckung, veraltete Heartbeats und kritische Findings
- Migration `0025_rust_agent_fleet_governance` fuer tenantgebundene Policy-Profile, Notification-Kanaele und Delivery-Audit
- editierbare Policy-Profile fuer Tenant, OS-Familie, Asset-Typ, Business Unit und Deployment-Channel
- Soll-/Ist-Coverage, Heartbeat-Freshness, Mindestscore und Finding-Grenzwerte je Policy
- sichere Webhook-Kanaele mit Production-Allowlist, Bearer-/HMAC-Secret-Referenz, Redirect-Sperre und Cooldown
- periodischer Worker, manuelle Auswertung, Delivery-Historie sowie Operations-/Prometheus-Signale
- fachuebergreifende Signale fuer Evidence-Ablauf und -Qualitaet, offene CVE-/Korrelationsreviews, offene Incident-Nicht-Meldeentscheidungen sowie faellige, ueberfaellige, blockierte oder kritische Roadmap-Tasks
- gemeinsame stabile Signal-Keys aus Tenant, Domaene, Objekttyp, Objekt-ID, Signaltyp und Zustands-/Faelligkeitskontext
- sichere Delivery-Metadaten mit Domaene, Objektbezug, Signaltyp, letzter Zustellung, Fehlerklasse und naechstem Cooldown-Zeitpunkt; Payloads und interne Fehler bleiben aus API und Read-only-Ansicht entfernt
- Migration `0029_rust_cross_domain_notifications` erweitert die bestehende Delivery-Historie additiv fuer SQLite und PostgreSQL
- gefuehrter Drei-Schritt-Assistent fuer Windows, Linux, macOS und NixOS auf Basis der vorhandenen Deployment-Artefakte
- begrenzter Enrollment-Token-Lifecycle mit sicheren Metadaten, Widerruf, Ablauf, partieller Verwendung und Auditspur
- transaktionssichere Token-Nutzung mit Policy-Zuordnung und Schutz gegen parallele Limitueberschreitung
- Flottenansicht mit Rollout-, Policy-, Token- und mTLS-Bindungsstatus
- additive Migration `0036_rust_agent_release_artifact_provenance` fuer Agent-Release-Artefaktmanifest, Signaturmetadaten, Release-Provenance und Verification-Audit
- SHA-256-Pruefsummen fuer vorhandene Agent-/Deployment-Artefakte aus einer festen Repo-Allowlist ohne frei waehlbare Dateipfade
- sichere Agent-Artefakt-APIs fuer Liste, Detail, Refresh, Checksum-Pruefung, Signaturstatuspruefung, Provenance und Onboarding-Artefakte
- Zero-Trust-Webansicht und Onboarding-Assistent zeigen Artefakte, Pruefsummen, Signaturstatus, Provenance-Status und bekannte Limitierungen ohne produktive Signierung vorzutaueschen
- Management-/Regulatory-Review-Pakete nehmen Agent-Artefakt-, Signatur-, Pruefsummen- und Provenance-Gaps als Supply-Chain-Signale auf
- additive Migration `0037_rust_agent_pki_csr_governance` fuer Agent-PKI-Provider, CSR-/Certificate-Request-Lifecycle, Zertifikatsstatus, mTLS-Bindung, Rotation, Widerruf und PKI-Audit
- sichere Agent-PKI-APIs fuer Provider, CSR-Review, Zertifikatsstatus, agentbezogene PKI-Uebersicht und Onboarding-PKI-Status
- Zero-Trust-Webansicht und Onboarding-Assistent zeigen PKI-/CSR-/mTLS-Governance als Metadata-only-Betriebscheck ohne produktive CA-Ausstellung
- Management-/Regulatory-Review-Pakete nehmen Agent-PKI-, CSR-, Zertifikats-, mTLS-, Rotations- und Widerruf-Gaps als Governance-Signale auf

Offen:

- echte produktive MSI-/PKG-/deb-/rpm-Signaturen mit freigegebenem Schluesselmanagement separat bereitstellen.
- produktive lokale CSR-Erzeugung, Provider-Adapter und CA-Anbindung als eigener spaeterer Security-Meilenstein untersuchen.

Bewusst nicht Teil der fachuebergreifenden Notifications sind Management-/
Regulatory-Templates, Evidence Integrity & Disposition als eigener
Governance-Workflow, kontrollierte physische Loeschung, Re-Hash-Worker,
Objektspeicher, echte produktive CA-/PKI-Ausstellung, echte produktive
Code-Signing-Schluessel, externe Attestation-Dienste, GitHub-Release-
Veroeffentlichung sowie Performance-, HA- und visuelle Regressionserweiterungen.

Erfolgskriterium:

- Agenten koennen realistisch in mehreren Systemen betrieben werden, und wichtige ISCY-Signale gehen nicht im Dashboard unter.

## Empfohlene Umsetzungsreihenfolge

1. Review-Pack-Bedienung weiter polishen, z. B. zusaetzliche Filter, Pack-spezifische Gap-Gruppierung und Review-Owner-Hinweise.
2. Den neuen S3-Runtime-Client nach menschlicher Security-Review in einer isolierten Betreiberumgebung pilotieren; Cloud-native Secret-Manager bleiben ein eigener spaeterer Adapter.
3. Produktive Signierung und eine spaetere produktive CA-/PKI-Stufe erst nach Review des jetzt vorhandenen Artefakt-/Provenance- und PKI-/CSR-Governance-Modells angehen.

## Verbleibende Roadmap

| Horizont | Arbeitspaket | Ergebnis |
| --- | --- | --- |
| Erledigt | Agent-State, Secret-Rotation, Offline-Queue und OS-Service-Beispiele | Agenten behalten ihre Identitaet, puffern Ausfaelle und koennen auf Linux, NixOS, Windows und macOS periodisch betrieben werden. |
| Erledigt | Agent-Policy, erwartete Coverage und Policy-Webhooks | Flottenabweichungen werden gegen einen Sollbestand bewertet, aktiv zugestellt und auditierbar protokolliert. |
| Erledigt | Product-Security-Evidence-Pakete und Produkt-Lifecycle | Versionierte Release-/PSIRT-Freigaben enthalten SBOM, VEX, Advisories, Support-Ende, offene Risiken, Roadmap und Evidence; Blocker-Gates und Exporte sind umgesetzt. |
| Erledigt | AI-Governance-Verknuepfungen | AI-Systeme sind direkt mit Risiken, Roadmap-Tasks, Incidents und Changes verbunden. |
| Erledigt | Gefuehrtes Agent-Onboarding | Enrollment-Tokens, Deployment-Artefakte und Flottenstatus sind ueber einen sicheren Admin-Assistenten bedienbar. |
| Unreleased | Fachuebergreifende Notifications | Evidence-Ablauf, CVE-Review, Incident-Entscheidung und Roadmap-Faelligkeit nutzen denselben sicheren Kanalbetrieb. |
| Unreleased | Supplier-Review-Workflow | Kritische Lieferanten erhalten Freigabehistorie, Unterauftragnehmer, Vertragsfristen, Exit-Test-Nachweise und tenantgesicherte Evidence-/Control-/Risk-Links. |
| Unreleased | Supplier/Product-Security-Deepening | Lieferanten, Produkte/Services, lokale Advisory-/PSIRT-/CVE-Metadaten, Evidence, Review-Status, Vertrags-/Exit-Plan-Historie und Regulatory Review Packs sind tenantgebunden verbunden. |
| Unreleased | Agent-Artefakte und Release-Provenance | Vorhandene Agent-Deployment-Artefakte sind als Manifest mit SHA-256, Signaturstatus, Provenance und Review-Pack-Gaps sichtbar; echte Produktionssignaturen bleiben ein separater Security-Meilenstein. |
| Unreleased | Agent-PKI, CSR und mTLS-Governance | CA-Provider, CSR-Review, Zertifikatsstatus, mTLS-Bindung, Rotation und Widerruf sind tenantgebunden als Metadata-only-Governance sichtbar; echte CA-Ausstellung bleibt ein separater Security-Meilenstein. |
| Umgesetzt / Vertiefung | Management-/Regulatory-Templates | Wiederholbare ISO-27001-, NIS2-, DORA-, KRITIS- und Governance-Pakete werden aus bestehenden Snapshots erzeugt; feinere Varianten koennen spaeter folgen. |
| Unreleased | Evidence Integrity & Disposition Phase 1 | Manuelle und begrenzte Batch-Re-Hash-Pruefung, Legal Hold, metadata-only Disposition und auditierbare Integritaetsereignisse sind tenantgebunden verfuegbar. |
| Unreleased | Evidence Object Storage & Restore Drill Phase 2 | Eine interne Storage-Abstraktion mit lokalem Filesystem-Backend prueft referenzierte Artefakte sicher auf Vorhandensein, Lesbarkeit und Hash-Konsistenz. |
| Unreleased | Evidence-Worker, kontrollierte physische Disposition und Object-Storage-Vorbereitung | Begrenzte Integritaets-Worker-Laeufe, Approval-gebundene physische Disposition, Tombstone-Metadaten und vorbereitete Object-Storage-Konfiguration sind tenantgebunden auditierbar. |
| Unreleased | S3-kompatibler Evidence-Storage-Runtime-Client | Explizite Secret-Referenzen, SigV4, DNS-/SSRF-Revalidierung, kanonische Object-IDs, begrenzte PUT-/HEAD-/GET-Operationen und kontrolliertes Remote-DELETE sind mit MinIO-Integrationstest umgesetzt. |
| Reifegrad | Performance, HA und visuelle Regression | Lastgrenzen, Mehrinstanzbetrieb und UI-Regressionen sind messbar abgesichert. |

## Abgrenzung

Diese Roadmap ist eine fachliche Produktagenda. Sie ist keine Rechtsberatung, keine Zertifizierung und kein Ersatz fuer eine formale Auditplanung. Sie beschreibt, welche Funktionen ISCY sinnvoll weiter abrunden, damit die Plattform als ISMS-, Product-Security-, Evidence-, Incident- und Governance-Werkzeug konsistent bleibt.
