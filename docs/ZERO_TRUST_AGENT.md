# Zero-Trust Agent

Version: ISCY Rust Backend `0.3.3`

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
POST /api/v1/agents/devices/{device_id}/heartbeat
GET  /api/v1/agents/devices/{device_id}/findings
POST /api/v1/agents/devices/{device_id}/findings
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

## Windows-Agent

Der Windows-Agent ist kein eigener Python-Zweig, sondern dasselbe Rust-Binary `iscy-agent`. Der Quellcode ist bereits im Repository enthalten. Ein `.exe` wird auf Windows so gebaut:

```powershell
cargo build --release --manifest-path rust/iscy-backend/Cargo.toml --bin iscy-agent
.\rust\iscy-backend\target\release\iscy-agent.exe --self-test
```

Fuer Intune oder andere MDM-Systeme kann dieses Binary als Win32-App verteilt und mit `ISCY_BACKEND_URL`, `ISCY_TENANT_ID` und `ISCY_AGENT_ENROLLMENT_TOKEN` gestartet werden.

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

Wichtig: In `0.3.3` liest der Agent lokale OS-/MDM-/EDR-Signale nur read-only und konservativ. Wenn ein Signal nicht sicher bestaetigt werden kann, wird das als offene Evidenzluecke gemeldet statt als erfundener Compliance-Nachweis.

## Deployment-Zielpfade

| Plattform | MVP-Start | Zielpaket |
|---|---|---|
| Windows | manuell oder MDM Script | MSI / Intune Win32 App |
| macOS | manuell oder MDM Script | PKG / Jamf / Apple MDM |
| Linux | systemd timer/service | deb, rpm oder tarball |

## Sicherheitsgrenzen

Der Agent darf im MVP nicht:

- Passwoerter, Keychains, Browserdaten oder Secrets auslesen
- Dateiinhalte klassifizieren oder exfiltrieren
- Netzwerkverkehr mitschneiden
- Systemeinstellungen automatisch veraendern
- Shell-Kommandos vom Server ausfuehren

Remediation sollte erst als eigener, policy-signierter und auditierbarer Schritt folgen.

## Plattform-Integration

Die Migrationen `0007_rust_zero_trust_agent_core` und `0008_rust_agent_enrollment_hardening` fuegen hinzu:

- `zero_trust_agent_device`
- `zero_trust_agent_heartbeat`
- `zero_trust_agent_finding`
- `zero_trust_agent_check_catalog`
- `zero_trust_agent_enrollment_token`

Die Webansicht ist unter `/zero-trust/` verfuegbar.
