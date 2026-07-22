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

### Threat Intelligence und Security Observations

Migration `0042_rust_native_threat_intelligence_observations` ergaenzt die
Rollen `SOC_ANALYST` und `SECURITY_ADMIN` sowie granulare serverseitige
Permissions. Bestehende Rollen und Gruppen erhalten keine automatische
Zuweisung.

- `SOC_ANALYST`: Indicators und Observations lesen, Observations und manuelle
  Links triagieren sowie tenantlokale Indicator-Links anlegen.
- `SECURITY_ADMIN`: alle SOC-Rechte sowie Indicators erfassen, aendern und
  archivieren und Observations erfassen.
- direkte und gruppenbasierte Permissions: `view_threat_indicator`,
  `add_threat_indicator`, `change_threat_indicator`,
  `archive_threat_indicator`, `view_security_observation`,
  `add_security_observation`, `triage_security_observation` und
  `link_security_observation`.

Normale Client-Header koennen diese Permissions nicht setzen. Sie werden bei
Session-/Bearer-Authentifizierung aus dem serverseitigen Auth-Store geladen.
Admin-, Staff- und Superuser-Kontexte behalten die bestehende administrative
Semantik. Jede Source-, Asset-, Indicator-, Observation- und Link-Abfrage ist
zusaetzlich im SQL tenantgebunden.

### Vulnerability Intelligence und Software Hygiene

Migration `0043_rust_continuous_vulnerability_intelligence` ergaenzt drei
granulare Permissions ohne automatische Zuweisung an Bestandsgruppen:

- `view_vulnerability_intelligence`: globale CVE-/Feed-Provenance und
  tenantgebundene Findings lesen; implizit fuer `SOC_ANALYST` und
  `SECURITY_ADMIN`.
- `review_software_hygiene`: tenantlokale Korrelation und passive
  Finding-Aktualisierung ausloesen; implizit fuer `SECURITY_ADMIN`, nicht fuer
  `SOC_ANALYST`.
- `sync_vulnerability_intelligence`: globale NVD-/KEV-/EPSS-Synchronisation;
  ausschliesslich direkte Permission oder Superuser. Weder `SECURITY_ADMIN`
  noch Staff oder normale Adminrollen erhalten dieses globale Recht implizit.

Der Tenant fuer Hygiene-Findings und Bewertungen stammt ausschliesslich aus
dem authentifizierten serverseitigen Kontext. Query- oder Payload-Felder
koennen ihn nicht ueberschreiben. Feed-Checkpoints und globale CVE-
Referenzdaten uebertragen keine Leserechte auf tenantgebundene Assets,
Korrelationen oder Findings.

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

Fuer Threat Intelligence und Security Observations prueft die Suite fehlende
Berechtigungen, manipulierte Tenant-Felder, fremde Source Findings, Assets und
Indicators, idempotente Wiederholungs-/Parallelaufrufe sowie ausbleibende
Incident- und Evidence-Nebenwirkungen.

Fuer Vulnerability Intelligence und Software Hygiene prueft die Suite
unauthentifizierte und tenantlokale Sync-Versuche, fehlende globale Rechte,
die getrennten `SOC_ANALYST`-/`SECURITY_ADMIN`-Grenzen, tenantfremde Assets,
Komponenten und Findings, idempotente Korrelationen sowie ausbleibende
Incident-, Evidence- und Active-Response-Nebenwirkungen.

Evidence-Uploads validieren tenantgebundene Session-, Massnahmen-, Incident- und Versionsvorgaenger-Referenzen vor dem Insert. Bei einer ungueltigen oder fremden Referenz antwortet die API mit `400 invalid_evidence_upload`, gibt keine Fremdmandantendaten preis und entfernt eine bereits temporaer geschriebene Upload-Datei. Die Negativtest-Matrix bleibt ein fortlaufendes Release-Gate: neue objektbezogene Read-, Write- oder Export-Routen muessen einen Fremdmandantenfall erhalten.
