# ISCY V23.7.28-rc.1 - Release-Notes-Entwurf

Status: Release Candidate vorbereitet, Veröffentlichung ausstehend.

ISCY bleibt eine selbst gehostete, local-first und datenschutzbewusste
Open-Source-Plattform unter `AGPL-3.0-only`. Die beschriebenen Funktionen
unterstuetzen Governance- und Nachweisprozesse; sie sind keine Rechtsberatung,
Zertifizierung, Konformitaetsbewertung oder automatische Behoerdenmeldung.

## Überblick

Der vorgeschlagene Release Candidate buendelt die seit `V23.7.27`
implementierten Roadmap-Bloecke und einen abschliessenden Hardening-Pass. Im
Mittelpunkt stehen tenantgebundene Governance-Verknuepfungen, kontrollierte
Evidence-Lebenszyklen, Supplier/Product Security, Agent-Governance sowie
reproduzierbare Performance-, Mehrinstanz- und UI-Regressionspruefungen.

## Governance und Compliance-Unterstuetzung

- AI-Governance-Systeme koennen mit Risiken, Roadmap-Tasks, Incidents und dem
  kanonischen Change-Register verknuepft werden.
- Management- und Regulatory-Review-Pakete unterstuetzen wiederholbare
  Templates, Previews, eingefrorene Snapshots und konsistente Exporte.
- Fachuebergreifende Notifications beziehen Evidence-, CVE-, Incident- und
  Roadmap-Signale in den bestehenden sicheren Kanalbetrieb ein.
- Supplier Reviews enthalten Freigabehistorie, Unterauftragnehmer,
  Vertragsfristen, Exit-Tests und tenantgesicherte Evidence-/Control-/Risk-Links.

## Evidence Integrity und Object Storage

- Evidence Integrity umfasst SHA-256-Pruefungen, Legal Hold, dokumentierte
  Disposition, Audit-Ereignisse und begrenzte Worker-Laeufe.
- Physische Disposition bleibt an Freigabe, Begruendung, Tenant und Legal-Hold-
  Status gebunden und erzeugt Tombstone-Metadaten.
- `local_filesystem` bleibt unterstuetzt; `s3_compatible` ergaenzt explizite
  Secret-Referenzen, SigV4, DNS-/SSRF-Revalidierung, begrenzte PUT-/HEAD-/GET-
  Operationen und kontrolliertes Remote-DELETE.
- Object Keys werden serverseitig kanonisch erzeugt und weder als frei
  waehlbarer Request-Wert noch vollstaendig in API oder Audit ausgegeben.

## Supplier und Product Security

- Supplier, Produkte/Services, lokale Advisory-/PSIRT-/CVE-Metadaten,
  SBOM-/VEX-Bezuege, Evidence, Reviews und Vertrags-/Exit-Historie sind
  tenantgebunden verbunden.
- Regulatory Review Packs koennen offene Supplier-/Product-Security-Gaps und
  fehlende Nachweise aggregieren, ohne eine automatische Compliance-Entscheidung
  zu treffen.

## Agent, Fleet, Zero Trust und PKI-Governance

- Gefuehrtes Agent-Onboarding nutzt Enrollment-Tokens, vorhandene Deployment-
  Artefakte, Policy-Zuordnung und Lifecycle-Audit.
- Agent-Artefakte erhalten SHA-256-, Signaturstatus- und Provenance-Metadaten.
  Produktive Paketsignierung ist nicht enthalten.
- CA-Provider, CSR-Review, Zertifikatsstatus, mTLS-Bindung, Rotation und
  Widerruf sind als Metadata-only-Governance modelliert. ISCY stellt keine
  Zertifikate aus und speichert keine privaten CA-Schluessel.

## Performance, Mehrinstanzbetrieb und Visual Regression

- Liveness, Readiness und Startup sind getrennt; Graceful Shutdown und
  PostgreSQL-Migrations-Lock sind geprueft.
- Ein begrenzter Performance-Smoke liefert p50, p95, p99, Maximum und
  Fehlerrate. Die Budgets sind keine Produktions-SLOs.
- Zwei Backend-Instanzen werden mit gemeinsamem PostgreSQL 16 und MinIO hinter
  nginx getestet. PostgreSQL, MinIO und nginx bleiben dabei Single Points of
  Failure; Multi-Region-HA wird nicht behauptet.
- 34 Playwright-Baselines decken 17 zentrale Webbereiche bei zwei Viewports ab.

## Security-Hardening dieses Release Candidates

- Passwortlose `tenant_id`-/`user_id`-Sessionerzeugung ist auf den expliziten
  Development-Kompatibilitaetspfad beschraenkt.
- Demo und Production akzeptieren `x-iscy-*`-Identitaetsheader nur hinter einer
  explizit konfigurierten vertrauenswuerdigen Proxy-Grenze.
- Session-Lesefehler geben keine SQL-, Tabellen- oder Store-Details aus.
- Der bestehende Secret-, Tenant-, Evidence-, Object-Storage-, Worker- und
  Supply-Chain-Pruefpfad wird in einem zentralen RC-Check zusammengefuehrt.

## Datenbank und Upgrade

- Der Stand enthaelt 39 fortlaufende Rust-Migrationen ohne doppelte oder
  fehlende ID.
- Seit `V23.7.27` kamen die additiven Migrationen `0027` bis `0039` hinzu.
- Vor einem Upgrade sind Datenbank und Evidence-Speicher gemeinsam zu sichern.
- Produktions-Upgrades muessen zuerst in einer umgebungsgleichen Staging-
  Instanz inklusive Restore-, Migration- und Rollback-Verfahren geprueft werden.
- SQLite bleibt ein lokaler Single-Instance-Pfad. Mehrinstanzbetrieb setzt
  PostgreSQL und gemeinsam erreichbaren S3-kompatiblen Evidence Storage voraus.

## Betriebsanforderungen

- Production-Preflight, sichere Session-Cookies und ein expliziter Reverse-
  Proxy-Trust-Boundary muessen aktiv sein.
- S3-Credentials werden ausschliesslich ueber erlaubte `env:`-/`file:`-
  Referenzen bereitgestellt; echte Cloud-Credentials sind nicht Teil der Tests.
- Betreiber verantworten TLS, Netzwerk-Egress, Backup-Verschluesselung,
  Secret-Management, Monitoring, RPO/RTO und die fachliche Freigabe von
  Loeschungen und Meldungen.

## Bekannte Einschränkungen

- PostgreSQL und MinIO sind ohne Betreiber-Cluster Single Points of Failure;
  es gibt keine Multi-Region-HA und keine automatische horizontale Skalierung.
- `local_filesystem` und SQLite sind keine HA-Pfade.
- Produktive CA-Anbindung und Agent-Paketsignierung sind nicht enthalten.
- Cloud-native Secret-Manager sind nicht enthalten.
- Performance-CI-Budgets sind keine Produktions-SLOs.
- Monitoring-Beispielimages sowie mehrere GitHub Actions sind noch nicht durch
  immutable Digests beziehungsweise Commit-SHAs gepinnt.
- Eine reproduzierbare CycloneDX-1.5-SBOM ist vorbereitet. Eine
  kryptografische Release-Signatur ist fuer diesen Candidate nicht
  konfiguriert; SBOM, Cargo.lock, Checksums und Provenance-Status werden
  transparent ausgewiesen.
- Die separaten Upgrade-Bloecke fuer Rust-Toolchain, PostgreSQL 18, nginx und
  nixpkgs sind bewusst nicht enthalten.

## Versionsstatus

- Letzte veröffentlichte Plattformversion: `V23.7.27`
- Vorgeschlagener Release Candidate: `V23.7.28-rc.1`
- Internes Rust-Paket: `0.3.22`
- Tag: nicht erstellt
- GitHub Release: nicht erstellt
- SBOM: CycloneDX 1.5, lokal/CI vorbereitet
- Signatur: `unsigned`
