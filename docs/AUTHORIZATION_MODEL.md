# Authorization Model

ISCY Community nutzt serverseitige Autorisierung. Mandant, Benutzer und Rollen duerfen nicht blind aus normalen Client-Headern uebernommen werden.

## Kontextquellen

1. Rust-Session-Cookie oder Bearer-Session-Token.
2. Development-/Demo-Header fuer lokale Tests und Smoke-Flows.
3. Production-Header nur hinter explizit vertrauenswuerdigem Reverse Proxy.

In Production gilt deny-by-default fuer:

```text
x-iscy-tenant-id
x-iscy-user-id
x-iscy-user-email
x-iscy-roles
x-iscy-is-staff
x-iscy-is-superuser
```

## Rollenmodell

Schreibende Operationen pruefen `can_write()`. Admin-Operationen pruefen zusaetzlich Admin-, Staff- oder Superuser-Kontext. Die konkrete Datenabfrage muss weiterhin tenantgebunden bleiben.

## Negativtests

Vor jedem Production-Cutover muessen mindestens diese Szenarien abgedeckt sein:

- Zugriff ohne Authentifizierung,
- Zugriff mit falscher Rolle,
- Zugriff auf fremden Tenant,
- manipulierte Tenant-ID,
- manipulierte User-ID,
- manipulierte Rollen-Header,
- manipulierte Objekt-ID,
- ungeschuetzte Admin-Funktionen.

Der erste Hardening-Lauf deckt die zentrale Production-Header-Grenze ab. Weitere routenspezifische Tenant-Isolationstests bleiben Phase-1-Restarbeit.
