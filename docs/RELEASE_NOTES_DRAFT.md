# ISCY V23.7.30 - Release Notes

Status: Stabiler Release.

Vorgänger: `V23.7.29` (`ba47201885435d57efc5042acde665f42dc000df`).

`V23.7.30` buendelt die nachfolgend beschriebenen Funktionen und Nachweise. Die
Release-Artefakte sind unsigniert; der Provenance-Status ist
`prepared_unsigned`. Der Vorgaenger `V23.7.29`, seine Release-ID `353634425`
und seine sechs Assets bleiben unveraendert.

## Agent Rollout 2.0 - Phase 1

ISCY stellt fuer bereits registrierte Agenten eine tenantgebundene und
auditierbare Rollout-Control-Plane bereit. Rollouts durchlaufen die feste
Reihenfolge Lab, Canary, Pilot, Production und Critical. Serverseitige
Preflight- und Postflight-Pruefungen, Beobachtungszeiten und Ring-Gates
unterstuetzen kontrollierte Entscheidungen. Promotion bleibt eine explizite
menschliche Aktion. Pause, Resume, Abbruch und operatorgefuehrter Rollback
werden dokumentiert.

ISCY installiert keine Software auf Endpunkten, uebertraegt keine Pakete,
stellt keine Agent-Befehle bereit und fuehrt keinen technischen Rollback aus.
Die Rollout-Funktion ist keine MDM-, RMM-, EDR- oder C2-Loesung und begruendet
keine Produktions-SLO.

## Agent Rollout 2.0 - Phase 2

Migration `0041_rust_agent_rollout_manifest_handoff` ergaenzt pro Rollout-Ring
ein unveraenderliches, versioniertes Manifest. Kontrollierte Rust-Strukturen,
kanonisches kompaktes JSON und stabil sortierte Targets ermoeglichen einen
reproduzierbaren SHA-256 ueber exakt die exportierten Manifest-Bytes. Beim
Freeze werden Artefakt-/Provenance-, Policy-, Plattform-, PKI-/mTLS- und
Preflight-Metadaten tenantgebunden eingefroren. Ein Ringstart ohne passendes,
integres und aktives Manifest wird blockiert.

Passive Deployment-Handoffs erzeugen manuell uebergebbare JSON-Pakete, ohne
externe Systeme oder URLs aufzurufen. Begrenzte Result-Importe verwenden
transaktional dieselbe interne Target-Result-Logik wie Phase 1. Serverseitige
Tenant-, Manifest-, Hash-, Target-, Device-, Zeit- und Statuspruefungen sowie
Replay- und Konfliktschutz verhindern eine zweite Ergebniswahrheit. Roh-Requests,
Credentials, Befehlsausgaben und Paketdaten werden nicht gespeichert. Eine
externe Deployment-Integration ist nicht Bestandteil dieses Release.

## ISCY Codex PR-Orchestrator

Der owner-kontrollierte Orchestrator kennt ausschließlich `/iscy status`,
`/iscy review`, `/iscy fix-ci` und `/iscy verify` fuer autorisierte
Same-Repository-Draft-PRs gegen `main`. Read-only Review/Verify,
Workspace-begrenzte Korrektur, getrennte Diff-/Head-Pruefung und maximal zwei
CI-Fix-Versuche folgen einem Least-Privilege- und fail-closed Design. Codex
erhaelt keine Merge-Berechtigung und kann einen PR weder freigeben noch mergen,
taggen oder veroeffentlichen; die Merge-Grenze bleibt menschlich.

Modellaufrufe benoetigen einen separat finanzierten OpenAI-API-Zugang. Fuer
diesen Release-Nachweis standen keine API-Credits zur Verfuegung; daher wird
kein erfolgreich abgeschlossener produktiver Auto-Fix-End-to-End-Test
behauptet. Die normalen GitHub-CI- und CodeQL-Pruefungen verwenden keine
OpenAI-Aufrufe.

## Migrationen und Datenbanken

- Migration `0040_rust_agent_rollout_governance` liefert die Rollout-Ringe,
  Preflight/Postflight, menschliche Promotion und operatorgefuehrten Rollback.
- Migration `0041_rust_agent_rollout_manifest_handoff` liefert unveraenderliche
  Manifeste, passive Handoffs und kontrollierte Result-Importe.
- Insgesamt sind 41 Migrationen von `0001` bis `0041` lueckenlos registriert.
- PostgreSQL 16 bleibt der Standard fuer den produktionsnahen Compose-Pfad.
- PostgreSQL 18.4 bleibt ein zusaetzlicher Kompatibilitaets- und logischer
  Forward-Restore-Pfad von PostgreSQL 16 nach 18. Ein In-place-Upgrade und ein
  Rueckwaertsrestore nach PostgreSQL 16 werden nicht versprochen.
- SQLite bleibt ein lokaler Single-Instance-Pfad und ist kein HA-Modell.

## Plattform und Supply Chain

- Produkt- und CI-Toolchain: Rust `1.97.0`
- MSRV bleibt Rust `1.88.0`; auch der portable Release-Builder bleibt auf 1.88.
- Produkt-Reverse-Proxy: `nginx:1.31-alpine`
- Nix-Entwicklungspfad: `nixos-26.05` mit Nix-Rust `1.95.0`
- Internes Rust-Paket: `0.3.22`
- 36 Visual-Baselines
- Signaturstatus: `unsigned`
- Provenance-Status: `prepared_unsigned`

`Cargo.lock`, `cargo audit`, `cargo deny`, die reproduzierbare
CycloneDX-1.5-SBOM, der Sensitive-Data-Scan und das portable Binary-Gate bilden
den Release-Nachweis. Die bestehende dokumentierte Ausnahme
`RUSTSEC-2023-0071` betrifft ausschließlich den deaktivierten optionalen
`sqlx-mysql`-Lockfile-Pfad; fuer kein ISCY-Target ist `rsa` erreichbar.

## Evidence, Betrieb und Testgrenzen

Der lokale Evidence-Pfad und der S3-kompatible Runtime-Pfad bleiben
authentifiziert, tenant-, rollen- und objektgebunden. Der isolierte
MinIO-/S3-Lifecycle prueft die implementierten PUT-/HEAD-/GET-, SHA-256-,
Fehler- und kontrollierten Delete-Pfade. Es werden keine produktiven
Cloud-Credentials mitgeliefert.

Performance-Smokes pruefen nur die dokumentierten CI-Budgets und sind keine
Produktions-SLO. Die Zwei-Instanzen-/Failover-Integration prueft zwei
ISCY-Prozesse gegen PostgreSQL und S3-kompatiblen Storage; PostgreSQL, MinIO und
nginx sind in dieser Testtopologie selbst Einzelinstanzen. Daraus folgt keine
allgemeine HA-, Multi-Region-, SLA- oder Skalierbarkeitszusage. Visual
Regression prueft 36 getrackte Baselines und aktualisiert sie in CI nicht.

## Governance- und Rechtsgrenzen

Der NIS2-Relevanz-Wizard dokumentiert eine Applicability-Begruendung im NIS2-
und KRITIS-Kontext, erzeugt jedoch keine rechtsverbindliche Einstufung. Eine
DORA-Konformitaetsbewertung erfolgt nicht. Die Unterstuetzung fuer den Cyber
Resilience Act (CRA) liefert keine automatische Konformitaetsbewertung oder
CE-Freigabe. ISCY trifft keine automatische Compliance-Entscheidung, erstellt
keine automatische Zertifizierung und ersetzt keine Rechtsberatung oder
Behoerdenmeldung.

Dieses Release enthaelt keine produktive Code-Signierung, keine produktive
CA-Ausstellung, keine privaten Signaturschluessel und keine automatische
Agent-Paketsignierung. Ebenso enthalten sind keine Wazuh-, IOC-, Behavioral-
Detection-, MDM-, RMM-, EDR- oder Command-and-Control-Funktionen.

## Release-Grenzen

Tag-Erstellung, GitHub-Release-Status, Asset-Upload, Container-Publishing und
Signatur werden nicht durch diese Notes belegt. Diese Zustaende werden getrennt
ueber den GitHub-Release-Zustand und den Published-Snapshot nachgewiesen. Eine
menschliche Security-, Betriebs- und Release-Review bleibt erforderlich.
