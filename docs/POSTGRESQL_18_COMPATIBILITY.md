# PostgreSQL-18-Kompatibilitaet und Upgradepfad

Stand: ISCY Unreleased

ISCY verwendet weiterhin PostgreSQL 16 als Standard- und Produktionspfad.
PostgreSQL 18 wird zusaetzlich als Anwendungskompatibilitaet und als Ziel eines
kontrollierten logischen Forward-Restores geprueft. Diese Aussage ist weder ein
automatisches Upgradeversprechen noch eine Freigabe fuer ein In-place-Upgrade.

## Unterstuetzter Stand

| Bereich | Gepruefter Pfad |
| --- | --- |
| Standard-Compose | `postgres:16` |
| PostgreSQL-16-Volumeziel | `/var/lib/postgresql/data` |
| Kompatibilitaetstest | `postgres:18` |
| Im Test aufgeloeste Serverversion | PostgreSQL 18.4 |
| PostgreSQL-18-Volumeziel | `/var/lib/postgresql` |
| PostgreSQL-18-PGDATA | `/var/lib/postgresql/18/docker` |
| Datenuebertragung | logischer Dump und Restore mit PostgreSQL-18-Clientwerkzeugen |
| Migrationen | alle 39 bestehenden Migrationen, ohne neue PG18-Migration |

Der am 2026-07-13 read-only gegen Docker Hub gepruefte OCI-Index fuer
`postgres:18` war
`sha256:22c89fe0d0f507606260237fd55e51f6137f58b2d5bcf6152242b96d9fe8f9a4`.
Das Linux/amd64-Manifest war
`sha256:0c49c0c906cb405ea65e70c284570fee91c7750ca9336369afc0edf4fce211db`
und bezeichnete PostgreSQL 18.4. Der produktive Standard wird dadurch nicht
gepinnt oder umgestellt. Da ein Tag spaeter auf einen neuen Patchstand zeigen
kann, muss der Digest in jeder konkreten Upgradefreigabe erneut aus der
offiziellen Registry geprueft werden.

## Automatisierter Nachweis

```bash
nix develop --command make postgresql-18-compatibility
```

Der Test verwendet ausschliesslich synthetische Demo-Daten und eine zufaellig
benannte Compose-Umgebung. Er startet:

- eine PostgreSQL-16-Quellinstanz mit eigenem Wegwerfvolume,
- eine PostgreSQL-18-Zielinstanz mit einem davon getrennten Wegwerfvolume,
- gehartete ISCY-Testprozesse fuer Source und Target,
- nur an `127.0.0.1` gebundene Anwendungsports und keine Datenbankports.

Der Lauf prueft Fresh Bootstrap, 42 Migrationen, einen zweiten idempotenten
Migrationslauf, Restart, Health, Login, Session, 401/403, zentrale Fachbereiche,
Risiko-Schreiben/-Lesen/-Aendern und einen synthetischen Evidence-Upload.
Danach erzeugt der PostgreSQL-18-Client einen Custom-Dump der PG16-Quelle,
restauriert ihn in eine frische PG18-Datenbank, fuehrt `ANALYZE` und den
ISCY-Migrationslauf aus und vergleicht dynamisch:

- Tabellen und Spalten,
- Zeilenanzahl und kanonische Inhaltschecksummen pro Tabelle,
- Sequenzen,
- Indizes,
- Unique-, Check- und Foreign-Key-Constraints,
- verwaiste Foreign Keys,
- Tenant-, Rollen-, Risiko- und Evidence-Invarianten.

Die Nullability wird versionsneutral ueber
`information_schema.columns.is_nullable` verglichen. PostgreSQL 18 bildet
`NOT NULL` zusaetzlich als eigenen `pg_constraint`-Typ `n` ab; diese
doppelte, in PostgreSQL 16 nicht vorhandene Katalogdarstellung wird aus dem
separaten Constraintvergleich ausgeschlossen. Primary-Key-, Unique-, Check-
und Foreign-Key-Constraints bleiben vollstaendig im Vergleich.

Ein zweiter Restore prueft die bestehende Betreiberbackup-Semantik mit
komprimiertem SQL-Dump, Media-Archiv, Manifest und `SHA256SUMS`. Archivpfade,
Symlinks und Hardlinks werden vor der Extraktion fail-closed geprueft. Ein
paralleler PG18-Migrationslauf validiert abschliessend den Advisory Lock.

Der rein statische Guard-Test kann ohne laufenden Container-Daemon ausgefuehrt
werden:

```bash
nix develop --command make postgresql-18-contract-tests
```

Er verhindert insbesondere vertauschte oder gemeinsame Volumes, falsche
PGDATA-Ziele, exponierte Datenbankports, `postgres:latest`, produktive
Umgebungswerte und externe Datenbank-URLs.

## Voraussetzungen fuer einen Betreiber-Upgrade

- freigegebenes Wartungsfenster und gestoppte Anwendungsschreibzugriffe,
- separat getestetes, verschluesseltes Datenbank- und Media-Backup,
- ausreichender freier Speicher fuer Dump, Restore und unveraendertes
  PostgreSQL-16-Rueckfallvolume,
- PostgreSQL-18-Clientwerkzeuge fuer Dump und Restore,
- eine neue leere PostgreSQL-18-Instanz mit eigenem Volume,
- dokumentierte Freigabe-, Integritaets- und Cutover-Verantwortung.

Keine Produktionsdatenbank darf direkt durch das Repository-Testskript
adressiert werden. Es akzeptiert weder externe URLs noch eine produktive oder
Stage-Umgebung.

## Kontrollierter Upgradeablauf

1. Anwendungsschreibzugriffe stoppen und den PG16-Datenbestand fachlich
   einfrieren.
2. PostgreSQL-16- und Media-Backup erzeugen, verschluesselt ablegen und dessen
   Checksummen vor dem Restore pruefen.
3. Das bestehende PG16-Volume unveraendert erhalten. PostgreSQL 18 darf dieses
   physische Volume niemals oeffnen.
4. Mit den freigegebenen PostgreSQL-18-Clientwerkzeugen einen logischen Dump
   der PG16-Quelle erzeugen. Fuer den geprueften Pfad wird ein Custom-Dump mit
   `--no-owner`, `--no-privileges` und `--quote-all-identifiers` verwendet.
5. Eine frische PG18-Instanz mit Volume-Mount `/var/lib/postgresql` und PGDATA
   `/var/lib/postgresql/18/docker` bereitstellen.
6. Den Dump mit `pg_restore --exit-on-error --no-owner --no-privileges`
   einspielen und anschliessend `ANALYZE` ausfuehren.
7. ISCY `migrate` zweimal ausfuehren. Der zweite Lauf darf keine weitere
   Migration anwenden; insgesamt muessen 42 Migrationen vorliegen.
8. Tabellen, Zeilen, Inhaltschecksummen, Sequenzen, Constraints, Tenantdaten,
   Rollen, Evidence-Metadaten und Media-Hashes gegen die eingefrorene Quelle
   vergleichen.
9. Health-, Auth-, Lese- und Schreibsmokes ausfuehren und Logs auf sichere
   Fehlerklassen ohne URLs, SQL-Details oder Credentials pruefen.
10. Erst nach technischer und fachlicher Freigabe den kontrollierten Cutover
    durchfuehren. Das PG16-Volume bleibt bis zur ausdruecklichen
    Ausserbetriebnahme unveraendert erhalten.

Die konkreten Verbindungsdaten und Secrets gehoeren in betreiberverwaltete
Secret-Dateien oder Secret-Stores. Sie duerfen nicht in Shell-History,
Prozesslisten, Logs, Tickets oder Backup-Manifeste gelangen.

## Rollback-Grenze

Vor dem Cutover beziehungsweise bevor neue Schreibvorgaenge auf PostgreSQL 18
erfolgen, kann der Betreiber den neuen Zielpfad verwerfen und zum unangetasteten
PostgreSQL-16-Stand zurueckkehren.

Nach neuen PG18-Schreibvorgaengen ist ein einfaches Zurueckschalten nicht
zulaessig: Es wuerde die neuen Daten verlieren. Eine Rueckmigration benoetigt
einen separat entwickelten und getesteten logischen Exportpfad. Ein Restore von
PostgreSQL 18 nach PostgreSQL 16 und ein automatischer Rollback sind nicht
Bestandteil dieses Kompatibilitaetsnachweises.

## Bewusste Grenzen

- PostgreSQL 18 ist noch nicht der ISCY-Produktionsstandard.
- Es gibt kein automatisiertes In-place-Upgrade und kein `pg_upgrade`-Skript.
- Es gibt keine automatische Volumeverschiebung oder Volume-Konvertierung.
- Der Nachweis trifft keine Aussage zu PostgreSQL-Clustern, Patroni,
  Streaming-Replikation, Multi-Region-HA oder Produktions-SLOs.
- Der Nachweis ist keine Rueckwaertskompatibilitaetsgarantie PG18 nach PG16.
- Betreiber muessen Groesse, Laufzeit, RPO/RTO, Extensions, Collations und
  Infrastrukturregeln mit ihren eigenen Daten und ihrer eigenen Umgebung
  getrennt pruefen.
