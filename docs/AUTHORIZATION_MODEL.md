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

Die zentrale Production-Header-Grenze und die fachlichen Store-Abfragen sind durch Negativtests abgesichert. Die routenspezifische Suite prueft unter anderem fremde Supplier, Prozesse, Produkte, Product-Security-Tasks, Vulnerabilities, Risiken, Incidents, Incident-Writes, NIS2-/DORA-/DSGVO- und Timeline-Exporte, Evidence-Session-/Incident-Verknuepfungen, Roadmaps, Wizard-Sessions, Reports und Management-Review-Details/-Writes/-Exporte.

Evidence-Uploads validieren tenantgebundene Session-, Massnahmen-, Incident- und Versionsvorgaenger-Referenzen vor dem Insert. Bei einer ungueltigen oder fremden Referenz antwortet die API mit `400 invalid_evidence_upload`, gibt keine Fremdmandantendaten preis und entfernt eine bereits temporaer geschriebene Upload-Datei. Die Negativtest-Matrix bleibt ein fortlaufendes Release-Gate: neue objektbezogene Read-, Write- oder Export-Routen muessen einen Fremdmandantenfall erhalten.
