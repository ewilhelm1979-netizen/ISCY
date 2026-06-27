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
POST /api/v1/agents/enrollment-tokens
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

`x-iscy-agent-mtls-fingerprint` ist optional, aber sobald ein Token oder Device daran gebunden wurde, muss der Fingerprint bei Heartbeat und Findings passen. Der Header darf nur von einem TLS terminierenden Proxy gesetzt werden, der Client-Zertifikate wirklich validiert und eingehende gleichnamige Client-Header verwirft.

Token erstellen:

```bash
curl -fsS -X POST http://127.0.0.1:9000/api/v1/agents/enrollment-tokens \
  -H 'content-type: application/json' \
  -H 'x-iscy-tenant-id: 1' \
  -H 'x-iscy-user-id: 1' \
  -H 'x-iscy-roles: ADMIN' \
  -d '{"label":"lab rollout","allowed_os_families":["WINDOWS","MACOS","LINUX"],"uses_remaining":10}'
```

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

Administratoren koennen Webhook-Kanaele in derselben Webansicht pflegen. Der
Event `AGENT_POLICY` sendet Abweichungen als CloudEvents-aehnliches JSON. Pro
Policy, Stufe und Kanal unterdrueckt ein konfigurierbarer Cooldown erfolgreiche
Doppelmeldungen. Jeder Versuch wird mit Status, HTTP-Code, Fehler und Payload in
der Delivery-Historie protokolliert. Transiente Verbindungs-/Timeoutfehler sowie
HTTP 429, 500, 502, 503 und 504 werden begrenzt erneut versucht; permanente
Clientfehler werden nicht wiederholt.

Unterstuetzte Authentisierung:

- `NONE`: nur fuer bewusst ungeschuetzte Ziele
- `BEARER`: Secret aus der in `secret_env_name` referenzierten Variable
- `HMAC_SHA256`: Signatur `sha256=<hex>` ueber `timestamp.payload`

Secrets werden nicht in der Datenbank gespeichert. HTTP ist nur fuer Loopback
oder mit `ISCY_NOTIFICATION_ALLOW_HTTP=1` erlaubt. Im Production-Modus muss der
Zielhost zusaetzlich exakt in `ISCY_NOTIFICATION_WEBHOOK_ALLOWED_HOSTS` stehen;
Redirects werden nicht verfolgt. Der Hintergrundworker wertet standardmaessig
alle 300 Sekunden aus. `ISCY_AGENT_NOTIFICATION_INTERVAL_SECONDS=0` deaktiviert
ihn, andere positive Werte werden auf mindestens 60 Sekunden begrenzt.

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

Die Migrationen `0007_rust_zero_trust_agent_core`, `0008_rust_agent_enrollment_hardening` und `0025_rust_agent_fleet_governance` fuegen hinzu:

- `zero_trust_agent_device`
- `zero_trust_agent_heartbeat`
- `zero_trust_agent_finding`
- `zero_trust_agent_check_catalog`
- `zero_trust_agent_enrollment_token`
- `zero_trust_agent_policy_profile`
- `zero_trust_agent_notification_channel`
- `zero_trust_agent_notification_delivery`

Die Webansicht ist unter `/zero-trust/` verfuegbar.

Die Betriebszentrale unter `/status/` und ihre JSON-/Prometheus-Ausgaben zeigen
zusaetzlich:

- aktive Agenten im Verhaeltnis zu registrierten Devices
- seit mindestens 14 Tagen veraltete Heartbeats
- kritische und hohe offene Agent-Findings
- Policy-Konformitaet und erwartete Coverage ueber alle konfigurierten Scopes
- aktivierte Notification-Kanaele und fehlende Secret-Konfiguration
