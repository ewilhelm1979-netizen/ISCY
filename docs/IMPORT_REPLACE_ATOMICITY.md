# Import-Center: atomarer Replace-Job

F07 ist ein bestaetigter funktionaler Datenintegritaetsfehler, vorlaeufig P1.
Ein entfernter Auth-/Tenant-Bypass oder vom API-Angreifer beliebig ausloesbarer
DB-Triggerfehler wird damit nicht behauptet.

`replace_existing=true` bindet Loeschung, alle Lookup-/Insert-/Update-Schritte
und neu angelegte Business-Unit-Helfer an dieselbe Datenbanktransaktion.
PostgreSQL verwendet eine SQLx-Transaktion; SQLite beginnt vor der ersten
Loeschung mit `BEGIN IMMEDIATE`. Erst ein erfolgreicher Commit erlaubt ein
Erfolgsresultat. Bei Fehlern einschliesslich zurueckgewiesenem Commit rollen
auch zuvor geloeschte oder ueber Fremdschluessel veraenderte Daten zurueck.

Die vier bestehenden Importtypen, ihre Whitespace-Normalisierung und die
bisherigen Feldaliase bleiben unveraendert.
Unbekannte Typen werden weiterhin vor der Mutation abgelehnt. Leerer Replace
loescht wie bisher den eigenen Zielbestand; eine Zeile ohne Namen wird wie
bisher uebersprungen. Das sind keine neu eingefuehrten Produktregeln.

`replace_existing=false` bleibt ausdruecklich Append mit Autocommit und
moeglichem bereits gespeichertem Teilfortschritt bei einer spaeter fehlerhaften
Zeile. Die gleichen konkreten verbindungsbasierten Worker laufen dann ohne
implizite Jobtransaktion. Es gibt keinen zweiten abweichenden Pool-Schreibpfad.
SQL, Feldnormalisierung, Zaehler, Rollen und Tenantauflosung werden durch den
Atomaritaetsfix nicht neu definiert.

API-JSON, API-CSV, direktes Web-CSV und Web-CSV-/XLSX-Preview-Confirm rufen
denselben Store auf. Vorschau schreibt nicht. Tests verwenden echte Production-
Sessions statt Headervertrauen und pruefen fehlende Authentisierung, VIEWER,
untrusted Identity-Headers und manipulierte Query-/Body-Identitaet.
Bestehende HTML-Fehlerseiten koennen HTTP200 liefern; ein Statuscode allein ist
deshalb KEIN Schreiberfolgsnachweis. Die Regression vergleicht komplette
Tabellenzeilen einschliesslich Zeitstempeln und verlangt den konkreten
kontrollierten Zeilenfehler, nicht irgendeinen Parser-/Auth-Fehler.

Die fokussierte SQLite-/PostgreSQL-Matrix deckt alle vier Typen, erste/mittlere/
letzte fehlerhafte Zeile, legitimen Replace und unveraenderten Appendvertrag
ab. Deferred-FK-Fixtures pruefen echte Commitfehler und Rollback der Trigger-
Nebenwirkungen. Es werden ausschliesslich neue synthetische Datenbanken
verwendet, keine existierenden Tabellen fuer einen erneuten Lauf geleert.

## Unabhaengige Voraussetzungen und Grenzen

Die aktuelle-main-Basis `adca384` enthaelt ausserdem einen eigenstaendigen
PostgreSQL-Supplier-DATE/TEXT-Bindungsfehler. Er wird im separaten Draft153
behoben, nicht in diesen Produktdiff aufgenommen. Die vollstaendige
PostgreSQL-F07-Matrix kann bis zu dessen Integration nur auf einem klar
gekennzeichneten lokalen Kombinationsstand geprueft werden. Ein bedingter
Nachweis ist keine gruen nachgewiesene aktuelle-main-Integration.

Der unabhaengige Handbuch-/PDF-Releasevertrag liegt in Draft151. Keine dieser
Voraussetzungen erlaubt ein rotes natives Gate als Erfolg auszugeben.

Atomaritaet bedeutet nicht, dass parallele PostgreSQL-Replace-Jobs fuer einen
Tenant bereits fachlich serialisiert sind. Last-writer-wins, Konfliktregeln,
Retry/Idempotenz, Cancellation und ein ungewisser Commit-Receipt benoetigen
gesonderte Entscheidungen/Nachweise. Diese Korrektur fuehrt keine neue
Versions-/Audit-/Importhistorienarchitektur ein und behauptet keine allgemeinen
Parser- oder Ressourcenbudgets als vollstaendig geprueft. Rollen und Tenant-
Isolation bleiben vorgeschaltet und unveraendert verbindlich.
