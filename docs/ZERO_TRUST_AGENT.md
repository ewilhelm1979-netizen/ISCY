# Zero-Trust Agent MVP

Version: ISCY Rust Backend `0.2.0`

## Zielbild

Der ISCY Agent ist ein read-only Posture Collector fuer Windows, macOS und Linux. Er meldet Endpoint-Inventar, Heartbeats und Zero-Trust-Findings an die Plattform. Die Plattform korreliert diese Daten mit Assets, Risiken, Evidenzen, Assessments und Roadmap-Arbeit.

Der MVP ist bewusst kein EDR, kein Remote-Control-Agent und kein automatischer Remediation-Daemon.

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

Der erste Agent liefert sichere Baseline-Telemetrie:

- Hostname
- OS-Familie und OS-Version
- Architektur
- Agent-Version
- Deployment-Channel
- Heartbeat-Status
- `OBSERVED`-Finding fuer OS/Posture-Inventar

Konkrete Gaps wie fehlende Verschluesselung, fehlendes EDR oder offene Remote-Administration koennen ueber dieselben Intake-Endpunkte gemeldet werden, sobald MDM-, EDR- oder OS-spezifische Collector-Module belastbare Evidenz liefern.

## API

Alle MVP-Endpunkte nutzen den bestehenden ISCY Tenant/User-Kontext.

```text
POST /api/v1/agents/enroll
GET  /api/v1/agents/posture
GET  /api/v1/agents/devices
POST /api/v1/agents/devices/{device_id}/heartbeat
GET  /api/v1/agents/devices/{device_id}/findings
POST /api/v1/agents/devices/{device_id}/findings
```

Headers fuer den MVP:

```text
x-iscy-tenant-id: 1
x-iscy-user-id: 1
```

Spaetere Produktionshaertung sollte Enrollment-Tokens, mTLS oder signierte Agent-Zertifikate nutzen. Die Payloads bleiben kompatibel.

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

Die Migration `0007_rust_zero_trust_agent_core` fuegt hinzu:

- `zero_trust_agent_device`
- `zero_trust_agent_heartbeat`
- `zero_trust_agent_finding`
- `zero_trust_agent_check_catalog`

Die Webansicht ist unter `/zero-trust/` verfuegbar.
