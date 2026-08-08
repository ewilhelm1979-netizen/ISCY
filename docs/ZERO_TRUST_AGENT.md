# Zero-Trust Agent

Version: ISCY Rust Backend `0.3.22`

## Zielbild

Der ISCY Agent ist ein read-only Posture Collector fuer Windows, macOS und Linux. Er meldet Endpoint-Inventar, Heartbeats und Zero-Trust-Findings an die Plattform. Die Plattform korreliert diese Daten mit Assets, Risiken, Evidenzen, Assessments und Roadmap-Arbeit.

Der Agent ist bewusst kein EDR, kein Remote-Control-Agent und kein automatischer Remediation-Daemon.

## Zero-Trust-Scope

Der Check-Katalog orientiert sich an den Zero-Trust-Saeulen:

- Identity
- Devices
- Networks
- Applications/Workloads
- Data
- Visibility/Analytics
- Automation/Orchestration
- Governance

Der Agent liefert sichere Baseline-Telemetrie und lokale read-only Posture-Signale:

- Hostname
- OS-Familie und OS-Version
- Architektur
- Agent-Version
- Deployment-Channel
- Heartbeat-Status
- `OBSERVED`-Finding fuer OS/Posture-Inventar
- Datentraeger-Verschluesselung: BitLocker, FileVault oder LUKS
- Secure Boot beziehungsweise vergleichbare Plattformintegritaet
- Host-Firewall
- MDM-/Endpoint-Management-Signale
- Endpoint Protection beziehungsweise EDR-Signale

## API

Die Admin- und Lesepfade nutzen den bestehenden ISCY Tenant/User-Kontext. Produktive Agenten nutzen Enrollment-Token und danach Agent-Secrets.

```text
GET  /api/v1/agents/enrollment-tokens
POST /api/v1/agents/enrollment-tokens
POST /api/v1/agents/enrollment-tokens/{token_id}/revoke
POST /api/v1/agents/enroll
GET  /api/v1/agents/posture
GET  /api/v1/agents/devices
POST /api/v1/agents/devices/{device_id}/rotate-secret
POST /api/v1/agents/devices/{device_id}/heartbeat
GET  /api/v1/agents/devices/{device_id}/findings
POST /api/v1/agents/devices/{device_id}/findings
GET  /api/v1/agents/governance
POST /api/v1/agents/policies
PATCH /api/v1/agents/policies/{policy_id}
GET  /api/v1/agents/notification-channels
POST /api/v1/agents/notification-channels
PATCH /api/v1/agents/notification-channels/{channel_id}
GET  /api/v1/agents/notification-deliveries
POST /api/v1/agents/notifications/evaluate
GET  /api/v1/agents/pki/providers
POST /api/v1/agents/pki/providers
GET  /api/v1/agents/pki/csrs
POST /api/v1/agents/pki/csrs
POST /api/v1/agents/pki/csrs/{csr_id}/approve
POST /api/v1/agents/pki/csrs/{csr_id}/reject
POST /api/v1/agents/pki/csrs/{csr_id}/cancel
GET  /api/v1/agents/pki/certificates
PATCH /api/v1/agents/pki/certificates/{certificate_id}/status
POST /api/v1/agents/pki/certificates/{certificate_id}/rotation-required
POST /api/v1/agents/pki/certificates/{certificate_id}/revocation-request
GET  /api/v1/agents/{agent_id}/pki
GET  /api/v1/agents/onboarding/pki
GET  /api/v1/agents/rollouts
POST /api/v1/agents/rollouts
GET   /api/v1/agents/rollouts/{rollout_id}
PATCH /api/v1/agents/rollouts/{rollout_id}
POST /api/v1/agents/rollouts/{rollout_id}/target-preview
GET  /api/v1/agents/rollouts/{rollout_id}/targets
POST /api/v1/agents/rollouts/{rollout_id}/targets
POST /api/v1/agents/rollouts/{rollout_id}/validate
POST /api/v1/agents/rollouts/{rollout_id}/rings/{ring_name}/preflight
POST /api/v1/agents/rollouts/{rollout_id}/rings/{ring_name}/start
POST /api/v1/agents/rollouts/{rollout_id}/targets/{target_id}/deployment-result
POST /api/v1/agents/rollouts/{rollout_id}/rings/{ring_name}/postflight
POST /api/v1/agents/rollouts/{rollout_id}/rings/{ring_name}/evaluate
POST /api/v1/agents/rollouts/{rollout_id}/rings/{ring_name}/promote
POST /api/v1/agents/rollouts/{rollout_id}/pause
POST /api/v1/agents/rollouts/{rollout_id}/resume
POST /api/v1/agents/rollouts/{rollout_id}/abort
POST /api/v1/agents/rollouts/{rollout_id}/rollback
POST /api/v1/agents/rollouts/{rollout_id}/rollback/complete
GET  /api/v1/agents/rollouts/{rollout_id}/events
```

Admin-/Demo-Headers:

```text
x-iscy-tenant-id: 1
x-iscy-user-id: 1
x-iscy-roles: ADMIN
```

Produktive Agent-Headers:

```text
x-iscy-tenant-id: 1
x-iscy-agent-enrollment-token: <token>
x-iscy-agent-secret: <secret>
x-iscy-agent-mtls-fingerprint: sha256:<fingerprint>
```

`x-iscy-agent-mtls-fingerprint` ist optional, aber sobald ein Token oder Device daran gebunden wurde, muss der Fingerprint bei Enrollment, Heartbeat und Findings passen. ISCY akzeptiert den Header nur mit `ISCY_TRUSTED_PROXY_CONFIGURED=1`. Der TLS terminierende Proxy muss das Client-Zertifikat tatsaechlich validieren, eingehende gleichnamige Header entfernen und den validierten Fingerprint neu setzen. Direkt vom Client gesetzte Fingerprint-Header werden ohne diese explizite Vertrauensgrenze abgelehnt.

Token erstellen:

```bash
curl -fsS -X POST http://127.0.0.1:9000/api/v1/agents/enrollment-tokens \
  -H 'content-type: application/json' \
  -H 'x-iscy-tenant-id: 1' \
  -H 'x-iscy-user-id: 1' \
  -H 'x-iscy-roles: ADMIN' \
  -d '{"label":"lab rollout","allowed_os_families":["WINDOWS","MACOS","LINUX"],"uses_remaining":10}'
```

## Gefuehrtes Agent-Onboarding

Administratoren starten den Assistenten unter `/zero-trust/onboarding/` oder ueber
`Agent hinzufuegen` in der Flottenansicht. Der Workflow besteht aus drei Schritten:

1. Betriebssystem, Deployment-Kanal, Rollout-Bezeichnung, optionales Policy-Profil,
   maximale Verwendungen, Ablaufzeit, optionale OS-/Kanalbegrenzung und optionale
   mTLS-Bindung auswaehlen.
2. Tenantgebundene Zusammenfassung pruefen. Fremde oder nicht vorhandene
   Policy-Profile werden serverseitig abgelehnt.
3. Token genau einmal erzeugen und die plattformspezifische Anweisung verwenden.

Unterstuetzte Plattformen sind Windows, Linux, macOS und NixOS. Unterstuetzte
Deployment-Kanaele sind `manual`, `systemd`, `nixos`, `intune`, `jamf` und
`other`. NixOS-Agenten melden technisch die OS-Familie Linux und werden durch
den Deployment-Kanal `nixos` unterschieden.

Die Installationshilfe verwendet ausschliesslich die vorhandenen Dateien unter
`deploy/agent/`. ISCY erzeugt bewusst keinen Bootstrap-Download: Die einmalige,
mit `Cache-Control: no-store` und `Referrer-Policy: no-referrer` ausgelieferte
Anweisung vermeidet einen weiteren sensitiven Download-Endpunkt. Das Token steht
nicht in einer URL und wird nicht dauerhaft im HTML oder in der Datenbank
gespeichert.

### Agent-Artefakte und Release-Provenance

ISCY kann die vorhandenen Agent-Deployment-Artefakte als Manifest erfassen:

- `deploy/agent/README.md`
- `deploy/agent/systemd/iscy-agent.service`
- `deploy/agent/systemd/iscy-agent.timer`
- `deploy/agent/systemd/iscy-agent.env.example`
- `deploy/agent/nixos/iscy-agent.nix`
- `deploy/agent/windows/install-iscy-agent-task.ps1`
- `deploy/agent/macos/com.iscy.agent.plist`

Das Manifest enthaelt sichere Metadaten, SHA-256, Signaturstatus,
Verification-Status, Release-Provenance und bekannte Limitierungen. Die
Pruefsummen werden aus einer festen Repo-Allowlist berechnet; Requests koennen
keine beliebigen lokalen Pfade angeben. API, UI und Audit geben keine
Rohdateien, absoluten Buildpfade, Tokens, Authorization-Header, privaten
Schluessel oder Zertifikat-Private-Keys aus.

Die wichtigsten Pfade:

```text
GET  /api/v1/agents/artifacts
POST /api/v1/agents/artifacts/refresh
POST /api/v1/agents/artifacts/{artifact_id}/verify-checksum
POST /api/v1/agents/artifacts/{artifact_id}/verify-signature
GET  /api/v1/agents/release-provenance
GET  /api/v1/agents/onboarding/artifacts
```

Read-only-Rollen sehen sichere Metadaten. Schreibende Rollen duerfen Manifest-
Refresh, SHA-256-Pruefung und Signaturstatuspruefung ausloesen. Das Artefakt- und
Signaturmodell ist bewusst vorbereitend: Es enthaelt keine produktiven
Code-Signing-Zertifikate, keine privaten Schluessel, keine externe PKI/CA, keine
produktive CA-/CSR-Operation, keine Sigstore-/Rekor-/Fulcio-Netzwerkaufrufe und
keine automatische GitHub-Release-Veroeffentlichung.

### Token-Lifecycle

Neue Tokens sind immer begrenzt und beginnen in `pending`. Nach einer von mehreren
erlaubten Verwendungen wechseln sie zu `partially_used`, nach der letzten zu
`consumed`. Ablauf und administrativer Widerruf setzen `expired` beziehungsweise
`revoked`. Der Klartext wird nur in der Erstellungsantwort ausgegeben; spaetere
Listen enthalten ausschliesslich Hint, Grenzen, Zaehler, Policy, mTLS-Status und
Zeitpunkte.

Token-Claim, Nutzungszaehler, Device-Upsert, Policy-Zuordnung, Agent-Secret-Hash
und Audit-Ereignisse werden in einer gemeinsamen Datenbanktransaktion gespeichert.
Parallele Single-Use-Versuche koennen das Limit deshalb nicht ueberschreiten.
Audit-Ereignisse sind `token_created`, `token_used`, `token_partially_used`,
`token_consumed`, `token_expired`, `token_revoked` und `enrollment_failed`.
Token-Klartext, Agent-Secret, Secret-Hash, Authorization-Header und Installations-
anweisung werden nicht in den Auditdetails gespeichert.

Authentifizierte Read-only-Rollen duerfen sichere Token-Metadaten und Auditdaten
ihres Tenants lesen. Nur Administratoren duerfen Tokens erstellen, widerrufen,
Policy-Profile zuordnen oder die einmalige Installationsansicht erzeugen.

## Lokaler Agent-Test

```bash
nix run .#iscy-agent -- --self-test
```

Meldung an eine lokale ISCY-Instanz:

```bash
ISCY_BACKEND_URL=http://127.0.0.1:9000 \
ISCY_TENANT_ID=1 \
ISCY_USER_ID=1 \
nix run .#iscy-agent
```

Meldung mit Enrollment-Token:

```bash
ISCY_BACKEND_URL=http://127.0.0.1:9000 \
ISCY_TENANT_ID=1 \
ISCY_AGENT_ENROLLMENT_TOKEN=<token> \
nix run .#iscy-agent
```

Wenn beim Enrollment ein `agent_secret` zurueckkommt, nutzt der Agent es sofort fuer Heartbeat und Findings. Fuer spaetere Starts kann es als `ISCY_AGENT_SECRET` oder `--agent-secret` uebergeben werden.

## Persistenter State und Offline-Queue

Nach dem ersten erfolgreichen Enrollment speichert der Agent Tenant-ID, stabile
Device-ID, serverseitige Device-ID und Agent-Secret lokal. Ein Neustart verwendet
diesen State und enrollt das Device nicht erneut.

Standardpfade:

- Linux/macOS mit XDG: `$XDG_STATE_HOME/iscy-agent/state.json`
- Linux/macOS ohne XDG: `$HOME/.local/state/iscy-agent/state.json`
- Windows: `%LOCALAPPDATA%\ISCY\Agent\state.json`
- Queue: Unterverzeichnis `queue` neben der State-Datei

Die Pfade lassen sich mit `--state-path`, `--queue-dir`,
`ISCY_AGENT_STATE_PATH` und `ISCY_AGENT_QUEUE_DIR` festlegen. Unter Unix werden
Verzeichnisse mit Modus `0700` und Dateien mit `0600` geschrieben. Der
Windows-Installer unter `deploy/agent/windows/` setzt eine ACL fuer `SYSTEM` und
lokale Administratoren.

Transportfehler, HTTP 429 und HTTP 5xx werden als temporaer behandelt. Der
vollstaendige Report wird in der lokalen Queue abgelegt und beim naechsten Lauf
vor dem aktuellen Report uebertragen. Die Queue ist standardmaessig auf 100
Dateien begrenzt und arbeitet mit At-least-once-Zustellung. Der Grenzwert ist
ueber `--queue-max-files` oder `ISCY_AGENT_QUEUE_MAX_FILES` konfigurierbar.
Dauerhafte HTTP-4xx-Fehler werden nicht endlos gequeued, sondern als
Konfigurations- oder Authentisierungsfehler beendet.

## Agent-Secret rotieren

Die Rotation ist eine administrative Aktion. Das alte Secret wird sofort
ungueltig; das neue Secret erscheint genau einmal in der API-Antwort.

```bash
curl -fsS -X POST http://127.0.0.1:9000/api/v1/agents/devices/<device_id>/rotate-secret \
  -H 'x-iscy-tenant-id: 1' \
  -H 'x-iscy-user-id: 1' \
  -H 'x-iscy-roles: ADMIN'
```

Das neue `agent_secret` muss anschliessend ueber den sicheren Deployment-Kanal
auf den Endpoint gebracht werden. Ein einmaliger Lauf mit
`ISCY_AGENT_SECRET=<neu>` beziehungsweise `--agent-secret <neu>` aktualisiert
den lokalen State. Bei mTLS-Bindung muss weiterhin derselbe validierte
Fingerprint uebergeben werden.

## Policy-Profile und Sollabdeckung

Unter `/zero-trust/` koennen schreibberechtigte Nutzer Policy-Profile anlegen
und bearbeiten. Ein Profil definiert Sollbestand, maximales Heartbeat-Alter,
Mindestscore sowie Grenzwerte fuer kritische und hohe Findings. Unterstuetzte
Scopes sind:

- `TENANT`: alle Agenten des Mandanten
- `OS_FAMILY`: beispielsweise `linux`, `windows` oder `macos`
- `ASSET_TYPE`: der am Device verknuepfte Asset-Typ
- `BUSINESS_UNIT`: ID oder Name der Business Unit
- `DEPLOYMENT_CHANNEL`: beispielsweise `nixos`, `intune` oder `jamf`

ISCY berechnet je Profil gemeldete, aktive, frische und fehlende Devices,
Coverage, Flottenscore sowie High-/Critical-Findings. Ueberlappende Scopes
werden in der Gesamt-Coverage bewusst mehrfach gezaehlt; sie misst die Erfuellung
der Policy-Sollwerte und ist keine eindeutige Endpoint-Inventur.

## Aktive Benachrichtigungen

Administratoren koennen Webhook-Kanaele in derselben Webansicht pflegen und die
Signalbereiche `AGENT_POLICY`, `EVIDENCE`, `PRODUCT_SECURITY`, `INCIDENT` und
`ROADMAP` je Kanal aktivieren. Damit nutzen Agent-Policy-Abweichungen,
Evidence-Ablauf und -Qualitaetsluecken, offene CVE-/Korrelationsreviews,
Incident-Nicht-Meldeentscheidungen und Roadmap-Faelligkeiten denselben sicheren
Zustellpfad.

Stabile Event-Keys enthalten Tenant, Domaene, Objekttyp, Objekt-ID, Signaltyp
und Zustands- oder Faelligkeitskontext. Der konfigurierbare Cooldown unterdrueckt
erneute Versuche desselben unveraenderten Signals nach erfolgreichen und
fehlgeschlagenen Zustellungen. Transiente Verbindungs-/Timeoutfehler sowie HTTP
429, 500, 502, 503 und 504 werden innerhalb eines Zustellversuchs begrenzt
wiederholt; permanente Clientfehler werden nicht wiederholt.

Vor der externen Zustellung reserviert Migration
`0030_rust_notification_dispatch_claim` den unveraenderten Event-Key atomar je
Tenant und Kanal. Parallele manuelle Auswertungen sowie ein gleichzeitiger
Hintergrundworker koennen denselben Key dadurch nicht doppelt senden. Der Claim
enthaelt weder Payload noch Secret und bleibt nach erfolgreichen wie
fehlgeschlagenen Versuchen bis zum Ende des Kanal-Cooldowns aktiv. Ein neuer
Zustand oder Faelligkeitskontext erzeugt einen neuen Key und bleibt zustellbar.

Die Delivery-Historie speichert nur sichere Betriebsmetadaten: Tenant, Domaene,
Objektbezug, Signaltyp, Schweregrad, Status, Kanal, Zeitpunkt, letzter Versuch,
sichere Fehlerklasse und naechsten Cooldown-Zeitpunkt. Vollstaendige Payloads,
interne Fehlerdetails, Bearer-/HMAC-Secrets und Authorization Header werden
weder ueber die API noch in der Read-only-Webansicht ausgegeben. Administratoren
duerfen Kanaele und Signalbereiche konfigurieren; authentifizierte Read-only-
Rollen sehen nur diese sicheren Delivery-Metadaten.

HTML-Fehlerseiten zeigen fuer interne Store-, Query- oder Datenbankfehler nur
generische Meldungen. Interne Fehlerdetails werden nicht an Browser oder API-
Clients durchgereicht.

Unterstuetzte Authentisierung:

- `NONE`: nur fuer bewusst ungeschuetzte Ziele
- `BEARER`: Secret aus der fest erlaubten Variable `ISCY_AGENT_NOTIFICATION_SECRET`
- `HMAC_SHA256`: Signatur `sha256=<hex>` ueber `timestamp.payload`

Secrets werden nicht in der Datenbank gespeichert. `secret_env_name` darf fuer
Bearer und HMAC ausschliesslich `ISCY_AGENT_NOTIFICATION_SECRET` referenzieren;
andere Environment-Namen werden vor jeder Aufloesung abgewiesen. HTTP ist nur fuer Loopback
oder mit `ISCY_NOTIFICATION_ALLOW_HTTP=1` erlaubt. Im Production-Modus muss der
Zielhost zusaetzlich exakt in `ISCY_NOTIFICATION_WEBHOOK_ALLOWED_HOSTS` stehen;
Redirects werden nicht verfolgt. Der Hintergrundworker wertet standardmaessig
alle 300 Sekunden aus. `ISCY_AGENT_NOTIFICATION_INTERVAL_SECONDS=0` deaktiviert
ihn, andere positive Werte werden auf mindestens 60 Sekunden begrenzt.

## Agent Rollout 2.0 - Phase 1

Migration `0040_rust_agent_rollout_governance` ergaenzt eine tenantgebundene
Rollout-Control-Plane fuer bereits registrierte Agent Devices. Jeder Plan
enthaelt genau die serverseitig definierten Ringe Lab, Canary, Pilot,
Production und Critical in dieser Reihenfolge. Targets werden aus vorhandenen
Devices vorgeschlagen und danach explizit einem Ring zugewiesen; die Vorschau
persistiert nichts und ist auf 500 Ergebnisse begrenzt.

Der kontrollierte Ablauf besteht aus Preflight, organisatorischer Freigabe des
Ringstarts, externer Verteilung, dokumentiertem Deployment-Ergebnis,
Postflight, Beobachtungszeit und Gate-Evaluierung. Ein bestandener Ring wird
nicht automatisch weitergeschaltet: Nur Admins koennen die naechste Stufe nach
erneuter Pruefung und expliziter Bestaetigung freigeben. Pause, Resume, Abbruch,
Rollback-Anforderung und Rollback-Abschluss sind serverseitig validierte,
auditierte Statuswechsel. Rollback bleibt ein operatorgefuehrter Prozess.

Admin-Rollen steuern Plan, Targets, Ringstart, Promotion und Rollback. Die
vorhandene Schreibrolle darf Preflight/Postflight ausloesen und sichere externe
Ergebnisse dokumentieren; Read-only-Rollen koennen die Fallakte lesen. Jede
Abfrage ist tenantgebunden. Fremde Rollout-, Device-, Policy-, Artefakt- oder
Owner-IDs werden ohne Fremddaten offenzulegen abgewiesen. Management-Reviews
frieren nur sichere Rollout-Aggregate ein; Operations und Prometheus verwenden
keine Tenantnamen oder hochkardinalen Labels.

Die Oberflaeche liegt unter `/zero-trust/rollouts/`. ISCY installiert oder
deinstalliert keine Software, sendet keine Befehle an Agenten, uebertraegt
keine Pakete und fuehrt keinen technischen Rollback aus. Phase 1 enthaelt
keine Wazuh-Anbindung, IOC-/Behavioral Detection, automatisches Threat
Modeling oder automatische Promotion. Sie garantiert weder fehlerfreie
produktive Rollouts noch eine Produktions-SLO.

## Agent Rollout 2.0 - Phase 2

Migration `0041_rust_agent_rollout_manifest_handoff` erweitert die vorhandene
Rollout-Control-Plane um unveraenderliche Ring-Manifeste und passive externe
Deployment-Handoffs. Eine Read-only-Vorschau persistiert nichts. Nur Admins
duerfen ein Manifest nach bestandenem Preflight und expliziter Bestaetigung
einfrieren oder vor dem Ringstart durch eine neue Version ersetzen.

Das kanonische Manifest ist kompaktes UTF-8-JSON aus kontrollierten
Rust-Strukturen. Es enthaelt Ringposition, Zielversion und Channel,
Artefakt-SHA-256 und vorhandene Provenance-/Signaturstatus, Policy-Revision,
stabil sortierte Targets, sichere Plattform- und PKI-/mTLS-Metadaten sowie
Preflight-Aggregate. Der SHA-256 wird ueber exakt die exportierten
Manifest-Bytes berechnet. Der Ringstart verifiziert Hash, Scope, Artefakt,
Policy und aktuelle Zielzuordnung erneut und bleibt bei jeder Abweichung ohne
Statusaenderung blockiert.

Ein Handoff referenziert genau ein Manifest und stellt ein manuell
uebertragbares JSON-Paket bereit. ISCY speichert dabei keine externen
Credentials, Pakete, Skripte, Rohlogs oder lokalen Pfade und ruft keine
externen Systeme auf. Admins steuern Vorbereitung, Bestaetigung, Abschluss und
Invalidierung; Auditoren koennen sichere Metadaten und Exporte lesen.

Externe Result-Pakete sind auf 1 MiB und 500 Targets begrenzt. ISCY validiert
Schema, Tenant, Manifest-/Handoff-Bezug, Hash, Targets, Device-Referenzen,
Zeitfenster, Statuswerte und Textgrenzen vor jeder Uebernahme. Identische
Batch-ID und identischer Payload-Hash sind idempotent; eine abweichende
Wiederholung oder ein widerspruechliches Target wird mit `409 Conflict`
abgewiesen. Import, bestehende Target-Result-Logik, Checks, Aggregate und Audit
werden gemeinsam transaktional geschrieben; der Roh-Request wird nicht
gespeichert.

Management-/Regulatory-Reviews, Betriebszentrale und Prometheus zeigen nur
sichere Aggregate fuer aktive Manifeste und Handoffs, fehlende oder
fehlgeschlagene Rueckmeldungen sowie Versionsabweichungen. Bestehende Review-
Snapshots bleiben unveraendert. Phase 2 ist keine MDM-/RMM-,
Command-and-Control- oder Deployment-Integration und fuehrt weder Remote-
Installation noch automatische Promotion oder technischen Rollback aus.

## Windows-Agent

Der Windows-Agent ist kein eigener Python-Zweig, sondern dasselbe Rust-Binary `iscy-agent`. Der Quellcode ist bereits im Repository enthalten. Ein `.exe` wird auf Windows so gebaut:

```powershell
cargo build --release --manifest-path rust/iscy-backend/Cargo.toml --bin iscy-agent
.\rust\iscy-backend\target\release\iscy-agent.exe --self-test
```

Fuer Intune oder andere MDM-Systeme kann dieses Binary als Win32-App verteilt und mit `ISCY_BACKEND_URL`, `ISCY_TENANT_ID` und `ISCY_AGENT_ENROLLMENT_TOKEN` gestartet werden.

Ein produktionsnaher Scheduled-Task-Installer liegt unter
`deploy/agent/windows/install-iscy-agent-task.ps1`. Er fuehrt das initiale
Enrollment aus, haertet das State-Verzeichnis und registriert einen periodischen
Task unter `SYSTEM`.

## Was der Agent aktuell prueft

Der aktuelle Collector arbeitet read-only und meldet belastbare lokale Signale:

- Hostname
- OS-Familie und OS-Version
- CPU-Architektur
- Agent-Version
- Deployment-Channel
- Heartbeat-Status
- `device.os_patch_level`
- `device.disk_encryption`
- `device.secure_boot`
- `network.host_firewall`
- `identity.mdm_enrollment`
- `device.endpoint_protection`

Die Plattform kann zusaetzlich diese Zero-Trust-Pruefpunkte ueber dieselben Findings-Endpunkte aufnehmen:

- Datentraeger-Verschluesselung: BitLocker, FileVault oder LUKS
- Secure-Boot- beziehungsweise Plattformintegritaetsstatus
- OS-Patch-Stand
- Endpoint-Protection- oder EDR-Sichtbarkeit
- lokale Administratoren
- MDM-/Device-Management-Enrolment
- Host-Firewall
- exponierte Remote-Administration wie RDP, SSH oder Remote Login
- Softwareinventar fuer CVE-Korrelation
- Removable-Media-Policy

Wichtig: In `0.3.22` liest der Agent lokale OS-/MDM-/EDR-Signale nur read-only und konservativ. Wenn ein Signal nicht sicher bestaetigt werden kann, wird das als offene Evidenzluecke gemeldet statt als erfundener Compliance-Nachweis.

## Deployment-Artefakte

| Plattform | Vorhandenes Betriebsbeispiel | Naechster Paket-Schritt |
|---|---|---|
| Windows | Scheduled Task unter `SYSTEM` | signiertes MSI / Intune Win32 App |
| macOS | LaunchDaemon | signiertes/notarisiertes PKG / Jamf-Profil |
| Linux | gehaerteter systemd Timer | signiertes deb, rpm oder tarball |
| NixOS | deklaratives NixOS-Modul | paketierter Flake-Output |

Die Dateien liegen unter `deploy/agent/`.

### Linux mit systemd

```bash
sudo install -Dm755 rust/iscy-backend/target/release/iscy-agent /usr/local/bin/iscy-agent
sudo install -Dm644 deploy/agent/systemd/iscy-agent.service /etc/systemd/system/iscy-agent.service
sudo install -Dm644 deploy/agent/systemd/iscy-agent.timer /etc/systemd/system/iscy-agent.timer
sudo install -Dm600 deploy/agent/systemd/iscy-agent.env.example /etc/iscy-agent/agent.env
sudo systemctl daemon-reload
sudo systemctl enable --now iscy-agent.timer
```

Die Environment-Datei enthaelt das Enrollment-Token nur fuer den ersten Lauf.
Nach erfolgreichem Enrollment wird die Token-Zeile entfernt.

### NixOS

Das Modul `deploy/agent/nixos/iscy-agent.nix` wird importiert und mindestens mit
Backend-URL sowie dem installierten Binary-Pfad konfiguriert:

```nix
{
  imports = [ ./deploy/agent/nixos/iscy-agent.nix ];
  services.iscy-agent = {
    enable = true;
    binary = "/usr/local/bin/iscy-agent";
    backendUrl = "https://iscy.example.org";
    tenantId = 1;
  };
}
```

### Windows

```powershell
.\deploy\agent\windows\install-iscy-agent-task.ps1 `
  -BackendUrl "https://iscy.example.org" `
  -TenantId 1 `
  -EnrollmentToken "iscy_enroll_replace_me"
```

### macOS

Das Binary wird unter `/usr/local/libexec/iscy-agent` installiert und einmalig
als `root` mit Enrollment-Token gestartet. Danach wird die angepasste plist nach
`/Library/LaunchDaemons/com.iscy.agent.plist` kopiert und mit
`launchctl bootstrap system` aktiviert. Das Secret steht nicht in der plist,
sondern im geschuetzten State unter `/Library/Application Support/ISCY Agent/`.

## Sicherheitsgrenzen

Der Agent darf im MVP nicht:

- Passwoerter, Keychains, Browserdaten oder Secrets auslesen
- Dateiinhalte klassifizieren oder exfiltrieren
- Netzwerkverkehr mitschneiden
- Systemeinstellungen automatisch veraendern
- Shell-Kommandos vom Server ausfuehren

Remediation sollte erst als eigener, policy-signierter und auditierbarer Schritt folgen.

## Plattform-Integration

Die Migrationen `0007_rust_zero_trust_agent_core`, `0008_rust_agent_enrollment_hardening`, `0025_rust_agent_fleet_governance`, `0028_rust_guided_agent_onboarding`, `0040_rust_agent_rollout_governance` und `0041_rust_agent_rollout_manifest_handoff` fuegen hinzu:

- `zero_trust_agent_device`
- `zero_trust_agent_heartbeat`
- `zero_trust_agent_finding`
- `zero_trust_agent_check_catalog`
- `zero_trust_agent_enrollment_token`
- `zero_trust_agent_policy_profile`
- `zero_trust_agent_notification_channel`
- `zero_trust_agent_notification_delivery`
- `zero_trust_agent_enrollment_audit`
- `zero_trust_agent_rollout`
- `zero_trust_agent_rollout_ring`
- `zero_trust_agent_rollout_target`
- `zero_trust_agent_rollout_check`
- `zero_trust_agent_rollout_event`
- `zero_trust_agent_rollout_manifest`
- `zero_trust_agent_rollout_manifest_target`
- `zero_trust_agent_rollout_handoff`
- `zero_trust_agent_rollout_result_import`

Die Webansicht ist unter `/zero-trust/` verfuegbar.

Die Betriebszentrale unter `/status/` und ihre JSON-/Prometheus-Ausgaben zeigen
zusaetzlich:

- aktive Agenten im Verhaeltnis zu registrierten Devices
- seit mindestens 14 Tagen veraltete Heartbeats
- kritische und hohe offene Agent-Findings
- Policy-Konformitaet und erwartete Coverage ueber alle konfigurierten Scopes
- aktivierte Notification-Kanaele und fehlende Secret-Konfiguration
- aktive oder pausierte Rollouts, Rollback-Pflichten, blockierte Ringe und fehlgeschlagene Targets

## Agent-PKI, CSR und mTLS-Governance

ISCY bildet eine vorbereitete CA-/PKI-/CSR-Governance-Schicht fuer Agenten ab.
Sie ist ein Metadata-only-Modell und keine produktive CA. Erfasst werden
CA-Provider-Status, Trust Domain, Issuing Policy, erlaubte Agent-Profile,
Zertifikatslaufzeit, Renewal-Fenster, Widerrufsmodus, CRL-/OCSP-Referenz,
Key-Storage-Policy, Secret-Referenzstatus und bekannte Limitierungen.

CSR-Datensaetze enthalten sichere Metadaten wie Agent-Bezug, Common Name,
SAN-Zusammenfassung, Key-Algorithmus, beantragte Nutzung, Fingerprints, Hashes,
Review-Status, Freigabe/Ablehnung und Audit-Summary. Rohe private Schluessel,
produktive CA-Secrets und lokale Pfade werden nicht gespeichert. Rohes CSR-PEM
wird bewusst nicht als Freitext abgelegt; bevorzugt werden Fingerprints und
Hashes.

Zertifikatsstatus wird pro Tenant und Agent als Governance-Sicht gepflegt:
Status, mTLS-Bindung, Rotation, Widerruf, Laufzeit, Fingerprint, sichere
Issuer-/Subject-Summaries und Evidence-IDs. Die Weboberflaeche unter
`/zero-trust/` zeigt Provider, offene CSR, Zertifikatsstatus, mTLS-Gaps,
Rotation und Widerruf. Der Onboarding-Assistent zeigt denselben Status als
Vorbereitungs- und Betriebscheck.

Bewusst nicht enthalten sind echte Zertifikatsausstellung, produktive
CA-Anbindung, automatische mTLS-Aktivierung, produktive Rotation, produktiver
Widerruf, private Schluessel, echte CA-Secrets und externe CA-Netzwerkaufrufe.
Eine spaetere produktive Stufe muss lokale Schluessel- und CSR-Erzeugung auf dem
Agenten, Provider-Adapter, Secret-Management und negative mTLS-/CA-Tests separat
reviewen. Der private Agent-Schluessel darf das Geraet dabei niemals verlassen.
