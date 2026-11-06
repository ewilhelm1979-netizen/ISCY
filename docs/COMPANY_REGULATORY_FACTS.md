# Strukturierte Einzelfallangaben fuer die Anforderungspruefung

Stand: 06.11.2026. Erweiterung des gespeicherten Unternehmensprofils ohne neue
DDL-Migration. Kriterien bleiben `W2A-2026-11-03.1`; diese Angaben aendern die
bisherigen drei Pruefhinweise noch nicht.

Im Unternehmensprofil unter **Einzelfallangaben fuer die BSIG-/CRA-Pruefung**
den konkreten Dienste-/Produktbezug fuer die oben benannte Rechtseinheit
erlaeutern. Danach bekannte Angaben erfassen:

- Niederlassung in Deutschland;
- Taetigkeit aus BSIG-Anlage 1 und Anlage 2 getrennt nach eigener Einschaetzung;
- digitale Produkte fuer den EU-Markt, bereitgestellt oder geplant;
- CRA-Rollen als Mehrfachauswahl: Hersteller, Bevollmaechtigter, Einfuehrer,
  Haendler, Open-Source-Software-Steward oder andere/noch zu konkretisieren;
- Einrichtungsunterart, Produkte, Rollenbezug, Quellen und offene Sonderfaelle
  in der begrenzten Erlaeuterung.

Ja, Nein und unbekannt bleiben verschieden. Keine Rollenauswahl bedeutet
unbekannt; mehrere Rollen brauchen den konkreten Produktbezug. Erfasst sind
Selbstauskuenfte, keine bestaetigten gesetzlichen Kategorien. Niederlassung,
Laenderfreitext und nationale Taetigkeit ordnen keinen Rechtsraum automatisch
zu. Nein zu beiden Anlagen ersetzt keine Sonderfall-/Ausnahmepruefung.
Andere Rechtsraeume bleiben offen. Die Felder decken nicht alle fuer eine
Betroffenheitsentscheidung notwendigen Sachverhalte ab.

Fachliche Grundlage des Feldkonzepts, abgerufen 06.11.2026:

- [BSIG § 28](https://www.gesetze-im-internet.de/bsig_2025/__28.html):
  Einrichtungsarten, Groessenbezug, Verbundumstaende und Sonderfaelle muessen
  gemeinsam betrachtet werden; Mitarbeiterzahl allein ist kein Gesamtpruefer.
- [Anlage 1](https://www.gesetze-im-internet.de/bsig_2025/anlage_1.html) und
  [Anlage 2](https://www.gesetze-im-internet.de/bsig_2025/anlage_2.html):
  getrennte Taetigkeitsangaben als Einstieg; keine automatische Zuordnung
  einer konkreten Einrichtungsunterart.
- [CRA, VO (EU) 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj),
  insbesondere Artikel 2/3: Produkt-/Marktbezug und Rollen getrennt erfassen.
  Die Rollennamen allein belegen weder den Tatbestand noch eine Pflicht.

Diese Quellen stuetzen die Erhebungsstruktur, keine vollstaendige
Rechtspruefung. Neue regelbasierte Auswertungen, bestaetigte Anforderungen,
Anwendungszeitpunkte und fallbezogene Freigaben sind weitere Meilensteine.
Scope, Risiko, Control-Bindung und SoA werden hier nicht erzeugt.

## Speicherung und Kompatibilitaet

Speichern verwendet die bestehenden Session-/Rollen-/Tenant-/CSRF-,
Revisions- und Auditgrenzen. Die Kontextansicht zeigt die Angaben an der
gespeicherten Revision; ausdrueckliche Pruefstaende halten sie mit fest.
Historische JSON-Daten ohne den neuen Block bleiben lesbar und werden beim
Lesen nicht umgeschrieben. Fehlende Angaben erscheinen offen.

Der optionale JSON-Block `regulatory_context` wird bei voellig unbekanntem
Inhalt weggelassen. Alte Formularaufrufe ohne die gesamte Feldgruppe erhalten
bereits gespeicherte Einzelfallangaben. Die aktuelle vollstaendige Feldgruppe
kann Angaben bewusst leeren. Unbekannte Felder/Rollen, falsche Auswahlen,
Steuerzeichen und Laengenueberschreitungen werden vor dem Schreiben abgewiesen.

Ein Downgrade auf aeltere strikte Decoder kann Profile und Pruefstaende mit
dem neuen Block nicht lesen. Daher den bestehenden Schema-/Daten-
Wiederherstellungsvertrag beachten; keine Profile, Snapshots oder Receipts
zur Erzwingung eines Downgrades loeschen. Es gibt keine Datenbankmigration
und keine automatische Aenderung des Organisations-Stammprofils.
