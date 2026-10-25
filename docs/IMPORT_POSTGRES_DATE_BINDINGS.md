# Supplier-Import: PostgreSQL-Datumsbindung

Lokaler Maintenance-Befund `M-PG-IMPORT-DATE-01`, keine Codex-Cloud-Finding-ID.
Aktuelle Revalidierungsbasis: `adca384e1aa86726d796c37e47922623e5441821`.

Die regulaere Migration `0020_rust_supplier_risk_core` legt `last_reviewed_at`
und `next_review_due_at` als nullable `DATE` an. Der Import gewinnt die optionalen
Werte aus Textspalten; SQLx bindet auch `None::<String>` mit PostgreSQL-Texttyp.
Ohne explizite Konvertierung scheitern deshalb selbst Supplier-Importzeilen,
in denen beide Felder fehlen. SQLite hat dieses PostgreSQL-Typproblem nicht.

Der begrenzte Fix konvertiert genau diese vier Parameterpositionen in den
PostgreSQL-INSERT-/UPDATE-Statements mittels `::date`. Der bestehende
`supplier_store` verwendet dieselbe Konvertierung. Die Werte bleiben gebundene
Parameter, nicht zusammengesetzter SQL-Text. Spaltentypen, Migrationsinventar,
Tenant-/Rollenregeln, Datumsintervalle und SQLite bleiben unveraendert.

Erhaltene Semantik:

- fehlende, explizit null oder leere Werte ergeben weiterhin SQL-NULL;
- `last_review`/`next_review` bleiben bestehende Eingabealiase;
- wiederholter Name aktualisiert nur den im authentisierten Tenant gefundenen
  Supplier, fehlende Datumswerte koennen beim vollstaendigen Importupdate wie
  bisher auf NULL gesetzt werden;
- PostgreSQL prueft DATE-Werte weiterhin selbst; es wird kein Jetzt-Fallback,
  Ersatzdatum oder neues regulatorisches Fristmodell eingefuehrt;
- bestehende HTTP-Fehlerklassifikation wird hier nicht umdefiniert.

Regression `tests/import_supplier_dates.rs`: echter Production-Kontext mit
serverseitig erzeugten Sessions, fehlende Authentisierung, nicht schreibende
Rolle, zurueckgewiesene untrusted Identity-Headers und manipulierte Query-/
Body-Tenantangaben. Auf SQLite sowie einer echten frischen PostgreSQL-DB:
NULL-Insert, datiertes Insert/Update, Aliase, Clearing und unveraenderter
fremder Supplier. PostgreSQL zusaetzlich ungueltige Kalender-/Textwerte und
SQL-aehnlicher Parametertext ohne ausfuehrbaren SQL-Effekt. Der PG-Test darf
nur mit einer eigenen leeren `iscy_test_import_dates_*`-DB auf Loopback laufen;
er setzt keine vorhandene Datenbank zurueck.

Dieser Fix stellt den Datentypvertrag her, nicht die Replace-Job-Atomaritaet.
F07 bleibt eine getrennte Korrektur: ohne deren Transaktion kann ein spaeterer
Importfehler weiterhin Teilfortschritt hinterlassen. Allgemeine Parserbudgets,
weitere Feldvalidierung und Approval-/Versionsregeln werden nicht als durch
diese vier Konvertierungen vollstaendig auditiert oder geloest dargestellt.
