# ISCY-27: versionierte NIS2-Referenzkorrektur

Stand: 02.11.2026. Migration
`0049_rust_iscy27_nis2_reference_correction` korrigiert die zehn eindeutig
fehlerhaften Zuordnungen aus der [Fachpruefung](ISCY27_FRAMEWORK_REVIEW.md).
Grundlage ist Artikel 21 Absatz 2 der
[Richtlinie (EU) 2022/2555](https://eur-lex.europa.eu/eli/dir/2022/2555/oj).
Die Korrektur veraendert weder Betroffenheitsentscheidungen noch Bewertungen.

## Verhalten bei Neuinstallation und Upgrade

Die historischen Seeds bleiben unveraendert. Eine Neuinstallation und eine
bestehende Installation durchlaufen dieselbe neue Migration. Sie korrigiert
Quellcode und Rechtsreferenz fuer die Mapping-IDs 1007, 1020, 1026, 1029,
1035, 1042, 1044, 1048, 1072 und 1077; `updated_at` erhaelt den
Korrekturzeitpunkt. Titel, Einordnungsart und Rationale bleiben erhalten.
Die Uebersicht der alten und neuen Bezuege steht in der Fachpruefung.

Eine Zeile wird nur aktualisiert, wenn ID, Control-Zuordnung/-Code,
Framework, bisheriger Quellcode, Titel, Rechtsreferenz, Einordnungsart und
Rationale exakt dem mitgelieferten historischen Original entsprechen.
Abweichende eigene Zuordnungen bleiben unveraendert und brauchen eine
gesonderte fachliche Pruefung. Eine angewendete Migration bestaetigt daher
nicht automatisch die Korrektheit aller angepassten Mappings.

Alle zehn moeglichen Korrekturen bilden ein einzelnes SQL-Statement fuer
SQLite und PostgreSQL. Ein Datenbankfehler, etwa eine Kollision mit einer
eigenen bereits vorhandenen Zielreferenz, verwirft das gesamte Statement.
Die Migration wird dann nicht registriert; der regulare Migrationslauf
meldet den Fehler. Die eigene kollidierende Zuordnung muss vor einem
erneuten regulären Versuch fachlich geklaert werden. Keine automatische
Loeschung oder Zusammenfuehrung eigener Mappings vornehmen.

Nach bereits erfolgreichem Statement, aber noch fehlendem Migrationsreceipt
ist ein erneuter Lauf unschaedlich: Die alten Vergleichswerte treffen auf
korrigierte Zeilen nicht mehr zu. Registrierte Migrationen werden ohnehin
nicht erneut ausgefuehrt.

Mandantenstatus, Reifegrade, Evidence, Risiken, Wizard- und SoA-Daten werden
nicht bearbeitet. Demo-Statusseeds werden bei diesem Upgrade nicht erneut
ausgefuehrt. Vorhandene Organisationsentscheidungen behalten ihren Stand.

## Fachliche Grenzen und naechste Schritte

Die gemischten Begruendungen der IDs 1023 und 1080 bleiben gesondert offen.
Auch Quellen-/Regelversionierung fuer frei gepflegte Mappings,
Unterkontrollen, vollstaendiger Referenzabgleich und die Trennung von
deklarierter Umsetzung, Nachweis und gepruefter Wirksamkeit sind weitere
Meilensteine. Diese Korrektur bestaetigt keine vollstaendige NIS2- oder
ISO-Abdeckung und erzeugt keine SoA.

## Verifikation

Die Regressionstests pruefen frische und bestehende Datenbanken, alle zehn
Zielreferenzen, Erhaltung anderer Mappings und Mandantenstatus, eigene
Anpassungen, Control-Identitaet, Wiederholbarkeit sowie vollstaendigen
Rollback und fehlendes Migrationsreceipt bei einer Referenzkollision.
Der PostgreSQL-Test benoetigt eine ausdruecklich bereitgestellte frische
Loopback-Fixture; er ist standardmaessig ignoriert und wurde fuer diesen
Meilenstein getrennt auf PostgreSQL 17.11 ausgefuehrt. PostgreSQL 18 und
HA werden durch diesen lokalen Lauf nicht neu qualifiziert.
