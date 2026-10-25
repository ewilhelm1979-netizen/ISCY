# Incident-Fristen: stabiler Erkennungszeitpunkt

F04 ist ein bestaetigter funktionaler Fristenintegritaetsfehler, vorlaeufig P1.
Eine rechtliche Bewertung oder ein Auth-/Tenant-Bypass wird nicht behauptet.
Die aktuelle-main-Revalidierung erfolgte auf `adca384` mit nativen SQLite- und
PostgreSQL-Migrationen, Production-Identitaetsmodus und echten Serversessions.

## Begrenzter Vertrag

Ein bereits vorhandener Erkennungszeitpunkt darf nicht per Null-/Leerwert
entfernt werden, wenn der Incident bisher oder nach dem Update als SIGNIFICANT
eingestuft ist. Auch eine widerspruechliche Legacy-Zeile mit SIGNIFICANT,
aber altem false-Meldekennzeichen, erlaubt keine kombinierte Entfernung und
Umklassifizierung. Die Ablehnung erfolgt in der gemeinsamen Store-Normalisierung,
bevor Incident oder Incidentevents geschrieben werden. Nur dieser neue
typisierte Validierungsfehler erhaelt API400/`incident_deadline_anchor_invalid`;
die sonstige bestehende Fehlerklassifikation wird nicht global umgestellt.

Bei unveraendertem Anker und unveraenderter Signifikanz-/Meldekennzeichnung bleiben alle drei
gespeicherten Fristen erhalten. Das gilt auch fuer Legacy-NULL-Anker mit
vorhandenen oder fehlenden Fristen. Zeitzonen-Darstellungen desselben gueltigen
Zeitpunkts gelten nicht als fachliche Zeitkorrektur. Ein fachfremder Summary-
oder Statuspatch darf keine neue Erkennung durch eine laufende Uhr ausloesen.

Bei einer expliziten Zeitkorrektur oder Einstufungsaenderung werden neue aktive
Fristen nur aus einem gueltigen vorhandenen oder gelieferten Anker abgeleitet.
Ein fehlender Legacy-Anker wird nicht durch `now`, `created_at`, `confirmed_at`
oder ein erfundenes Datum ersetzt. Neue aktive Fristen ohne solchen Anker
werden abgewiesen. Die reine Fristenfunktion besitzt keinen Jetzt-Fallback.

Bestehende Funktionalitaet bleibt erhalten: einmalige Erfassungszeit bei
Neuanlage ohne Datum, bestehende 24h/72h/30-Tage-Rechnung, explizite gueltige
Zeitkorrektur und NOT_SIGNIFICANT-/Reviewpfad. Sentmarker, Authorityreferenz
und bestehende Historie werden durch diese Berechnung nicht zurueckgesetzt.
Keine Migration oder automatische Altbestandsbereinigung.

## Web-Kompatibilitaet ausdruecklich erhalten

Der aktuelle Webkonverter behandelt ein leeres Datum bereits als fehlendes
Patchfeld, NICHT als JSON-Null. Ein ansonsten legitimes Formular darf deshalb
seine Summary speichern und mit 303 umleiten, ohne Anker/Fristen zu entfernen. Der
Konverter wird nicht geaendert. HTML-Fehlerseiten200 sind keine Schreiberfolge;
negative Rollen-/Tenanttests vergleichen den tatsaechlichen Datenbestand.

## Tests und bewusst offene Grenzen

`tests/incident_deadline_anchor.rs` prueft SQLite sowie eine ausdruecklich
frische PostgreSQL-DB auf Loopback, ohne bestehende DBs zu leeren. API-Null,
Leer-/Whitespacewerte, gleichzeitige Umklassifizierung/Legacyflag, inkonsistente
Legacy-Meldekennzeichnung, Legacy-
Summary/Status, fehlender neuer Anker, gueltige Korrektur/gleicher Zeitpunkt,
Neuanlageintervalle und Review bleiben getrennte Faelle. API und Web pruefen
fehlende Auth, VIEWER, fremdes Objekt/Tenant und untrusted Identity-Headers.
Bei Ablehnung bleiben komplette Incident-/Eventzeilen einschliesslich Freigabe-
und Zeitangaben unveraendert; fremde Tenants bleiben auch bei Erfolg unberuehrt.

Die korrigierte positive Web-Leerwertkontrolle wird auch auf unveraendertem
main ausgefuehrt. Ein frueher Test, der unberechtigt auch eine gewollte Summary-
Aenderung verbot, ist kein Beleg fuer einen Web-Ankerloeschungsfehler.

Dieser Fix erklaert nicht, welcher Kenntniszeitpunkt rechtlich massgeblich ist,
wer nach versandten Meldungen besondere Korrekturen freigeben muss oder wie
fehlende Legacy-Daten nachtraeglich festgestellt werden sollen. Bestehende
nicht signifikante Bearbeitung und fachlicher Review werden nicht durch eine
neue, unbeauftragte Policy ersetzt. Gleichzeitige konkurrierende Vollzeilen-
Updates, allgemeine Incident-/Audit-Atomaritaet und Versions-Snapshots sind
damit nicht als abschliessend geloest oder getestet dargestellt.
