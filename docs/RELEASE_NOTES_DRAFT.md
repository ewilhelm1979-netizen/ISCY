# ISCY V23.7.31 - Release Notes

Status: Stabiler Release.

Vorgänger: `V23.7.30` (`1c07af4e7cd196076220479d394242a3df589714`).

`V23.7.31` buendelt drei passive Security-Governance-Bereiche: Native Threat
Intelligence und Security Observations, Continuous Vulnerability Intelligence
und Software Approval and Exception Policies. Der Funktionsumfang ist fuer
diesen Candidate eingefroren. ISCY bleibt eine selbst gehostete, local-first
und datenschutzbewusste Open-Source-Plattform unter `AGPL-3.0-only`.

Die Funktionen unterstuetzen nachvollziehbare Entscheidungen und Nachweise.
Sie garantieren weder Compliance noch Schwachstellenfreiheit und ersetzen
keine unabhaengige menschliche Security-Review.

## Native Threat Intelligence und Security Observations

- Tenantisolierte Indicators fuer IPv4, IPv6, Domains, HTTP(S)-URLs und
  SHA-256 werden lokal validiert und mit Provenance, Confidence, Gueltigkeit,
  Lifecycle und Klassifizierung verwaltet.
- Security Observations bleiben begrenzte Triage-Datensaetze. Bestehende
  Agent Findings und Product-Security-Vulnerability-Findings bleiben die
  kanonischen Quellen.
- Indicator-/Observation-Links werden manuell erstellt, tenantlokal
  dedupliziert und zusammen mit Triage und Auditspur gespeichert.
- Rollen und direkte beziehungsweise gruppenbasierte Permissions werden
  serverseitig ausgewertet. Bestehende Rollen erhalten keine automatische
  neue Berechtigung.
- Threat Intelligence erzeugt keine automatische aktive Reaktion, keinen
  Incident, keine Evidence, kein Risiko, keinen Roadmap-Task und keinen
  Agentenbefehl.

## Continuous Vulnerability Intelligence

- Der bestehende NVD-Pfad wurde um begrenzte NVD-2.0-Deltas, persistente
  Checkpoints und Leases sowie CISA-KEV- und FIRST-EPSS-Anreicherung erweitert.
- Vorhandene Products, Assets, Softwarekomponenten, SBOM-Importe und Product-
  Security-Findings werden wiederverwendet. CPE-/Versionskorrelationen bleiben
  erklaerbar und konservativ.
- Provenance, Parserstand, Abrufzeit und Datenalter bleiben nachvollziehbar.
  Unvollstaendige Laeufe liefern keine Entwarnung und aktualisieren den letzten
  vollstaendigen Auswertungsstand nicht.
- Continuous Vulnerability Intelligence ueberschreibt keine manuelle Triage,
  VEX-Aussage, Risk Acceptance oder dokumentierten Compensating Control.
- Es entstehen weder automatische VEX-Aussagen noch automatische Risk
  Acceptances, Incidents, Evidence, Security Observations oder aktive
  technische Massnahmen.

## Software Approval and Exception Policy

- Tenantgebundene Policies gelten nur fuer exakte vorhandene Products, Assets,
  kanonische Komponenten oder importierte SBOM-Komponenten.
- Policy-Entscheidungen sind `APPROVED`, `RESTRICTED` und `PROHIBITED`.
  Ohne wirksame Ausnahme gilt die deterministische Praezedenz
  `PROHIBITED > RESTRICTED > APPROVED`.
- `EXCEPTION_ACTIVE`, `UNMANAGED` und `REVIEW_REQUIRED` sind eigenstaendige
  effektive Zustaende. Fehlende Policy bedeutet nicht `APPROVED`; fehlende
  bekannte Schwachstellen bedeuten ebenfalls nicht `APPROVED`.
- Zeitlich begrenzte Exceptions durchlaufen einen getrennten Antrag-, Review-,
  Entscheidungs- und Widerrufsprozess. Self-Approval bleibt auch bei
  kombinierten Rollen serverseitig gesperrt.
- Abgelaufene oder widerrufene Exceptions sind bei jeder Auswertung
  unmittelbar unwirksam; dafuer ist kein Scheduler erforderlich.
- `EXCEPTION_ACTIVE` ist keine regulaere Freigabe. Eine Exception ist weder
  VEX noch Risk Acceptance und veraendert keine Finding-Triage.
- Policy-Auswertungen bleiben passiv. ISCY blockiert, installiert oder
  deinstalliert keine Software und sendet keinen Agentenbefehl.

## Migrationen und Upgrade

Migration `0045_rust_software_approval_exception_policy` ergaenzt die
tenantgebundenen Policy-, Exception-, Evaluations- und Auditstrukturen. Die
Migrationskette umfasst 45 fortlaufende Migrationen von `0001` bis `0045`.
Die vorherigen neuen Bereiche werden durch `0042`, `0043` und `0044`
eingefuehrt beziehungsweise gehaertet.

Vor dem Upgrade:

1. Datenbank und Evidence-/Object-Storage-Metadaten nach dem bestehenden
   Betreiberverfahren sichern.
2. Die Wiederherstellbarkeit in einer getrennten Umgebung pruefen.
3. Schreibzugriffe waehrend Migration und Anwendungswechsel koordinieren.
4. Fuer PostgreSQL weiterhin PostgreSQL 16 als Standard verwenden. PostgreSQL
   18.4 ist nur der separat gepruefte Kompatibilitaets- und logische
   Forward-Restore-Pfad.

Beim Start fuehrt das bestehende Migrationskommando nur fehlende additive
Migrationen aus. Es erzeugt keine Policy und keine Exception, setzt keine
vorhandene Software auf `APPROVED` und veraendert keine bestehende manuelle
Triage, VEX-Aussage, Risk Acceptance oder Compensating Controls.

Nach dem Upgrade:

1. Readiness und den vollstaendigen Migrationsstand pruefen.
2. Tenant- und Rollenvergabe fuer die neuen Bereiche explizit reviewen.
3. Feedstatus, Provenance und Datenalter vor fachlichen Entscheidungen
   kontrollieren.
4. Software ohne passende Policy als `UNMANAGED` behandeln und Exceptions
   unabhaengig pruefen.

## Rueckfall und Wiederherstellung

Vor jeder Rueckkehr ist ein getestetes Backup des vorherigen Anwendungs- und
Datenbankstands erforderlich. Ein Binary-Downgrade auf einen Stand vor
Migration `0045` ist kein Schema-Rollback. Der sichere Rueckfallpfad besteht
aus dem Wiederherstellen des zusammenpassenden Backups von Anwendung,
Datenbank und Evidence-/Object-Storage-Referenzen. PostgreSQL 16 nach 18 ist
als logischer Forward-Restore geprueft; ein In-place-Upgrade und ein
Rueckwaertsrestore nach PostgreSQL 16 werden nicht zugesagt.

## Security und Supply Chain

- Tenant-Isolation, RBAC, gruppenbasierte Permissions, Foreign-Tenant-IDs,
  Self-Approval, Revisionen, Parallelitaet und atomare Audittransaktionen
  besitzen negative beziehungsweise fokussierte Regressionstests.
- Externe Vulnerability-Daten sind untrusted input. Nur feste offizielle
  HTTPS-Quellen sind zugelassen; Redirect-, DNS-/SSRF-, Timeout-, Payload-,
  Kompressions-, Parser- und Secret-Grenzen bleiben fail-closed.
- `Cargo.lock`, cargo audit, cargo deny, Sensitive-Data-Scan, CycloneDX-1.5-
  SBOM und reproduzierbarer Doppel-Build bleiben Pflicht.
- Release-Artefakte sind unsigniert; der Provenance-Status ist
  `prepared_unsigned`. Die SBOM ist keine Signatur, VEX-Aussage oder
  Vulnerability-Freigabe.

## Plattform

nginx:1.31-alpine, Rust `1.97.0` und nixos-26.05 bleiben die geprueften
Plattformgrenzen. Die MSRV bleibt Rust `1.88.0`; auch der portable
Release-Builder bleibt auf Rust 1.88. PostgreSQL 16 bleibt der Standard.
PostgreSQL 18.4 bleibt ein zusaetzlicher Kompatibilitaets- und logischer
Forward-Restore-Pfad. SQLite bleibt ein lokaler Single-Instance-Pfad und ist
kein HA-Modell.

## Governance- und Rechtsgrenzen

Der NIS2-Relevanz-Wizard dokumentiert eine Applicability-Begruendung im
NIS2- und KRITIS-Kontext, liefert aber keine rechtsverbindliche Einstufung.
Eine DORA-Konformitaetsbewertung erfolgt nicht. Fuer den Cyber Resilience Act
(CRA) gibt es keine automatische Konformitaetsbewertung oder CE-Freigabe.
ISCY liefert keine automatische Zertifizierung und ersetzt keine
Rechtsberatung, Behoerdenmeldung oder unabhaengige fachliche Pruefung.

## Bekannte Einschraenkungen und bewusst verschobene Funktionen

- keine EOL-/EOS-Integration
- keine erweiterte PURL-/CPE-Auswertung ueber die konservativen vorhandenen
  Regeln hinaus
- keine neuen externen Feeds
- keine aktiven Reaktionsmassnahmen
- keine automatische Softwareblockierung oder Deinstallation
- keine automatische VEX-Aussage
- keine automatische Risk Acceptance
- keine automatische Incident- oder Evidence-Erzeugung aus den neuen
  Bereichen
- keine produktive Code-Signierung, CA-Ausstellung oder Cloud-native
  Secret-Manager-Anbindung
- keine Multi-Region-HA; PostgreSQL und Object Storage benoetigen fuer echte
  Hochverfuegbarkeit eine Betreiber-Clusterung
- Performance-CI-Budgets sind keine Produktions-SLOs

Jede Freigabe, Exception, Schwachstellenbewertung und regulatorische Einordnung
bleibt eine verantwortete menschliche Entscheidung.
