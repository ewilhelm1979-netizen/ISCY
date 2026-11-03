# Versionierte Anforderungs-Pruefhinweise im Unternehmens-Wizard

Stand und Quellenabruf: 03.11.2026. Kriterienversion `W2A-2026-11-03.1`.
Die bestehende tenantgebundene Kontextansicht zeigt jetzt drei begrenzte,
begruendete Pruefhinweise zur gerade gelesenen gespeicherten Profilrevision.
Es gibt keine neue Route, Schreiboperation, Migration oder Profilfelder.

| Kriterium | Auswertung gespeicherter Angaben | Quelle / weiterer Pruefbedarf |
| --- | --- | --- |
| `ISO_ISMS_GOAL_V1` | ISO-Readiness/ISMS waehlt den Planungspfad, auch bei nationalem Unternehmen mit 0 Mitarbeitern; andere Ziele bleiben offen | [ISO/IEC 27001:2022 mit Amendment 1:2024](https://www.iso.org/standard/27001); Scope, Anforderungen und Risikobehandlung gesondert festlegen |
| `DE_BSIG_SIZE_SIGNAL_V1` | Mitarbeiterzahl ab 50 oder Umsatz **und** Bilanz jeweils ueber 10 Mio. EUR erzeugen einen Groessenhinweis | [BSIG § 28](https://www.gesetze-im-internet.de/bsig_2025/__28.html); Deutschlandbezug, Einrichtungsart, Bezugsgrundlage, Verbund-/Unabhaengigkeitsumstaende und Sonderfaelle bleiben offen |
| `EU_CRA_PRODUCT_SIGNAL_V1` | Eigene digitale Produktentwicklung = Ja erzeugt einen Produktpruefhinweis; Nein und unbekannt haben unterschiedliche Begruendungen, bleiben aber offen | [Kommissionszusammenfassung zur VO (EU) 2024/2847](https://digital-strategy.ec.europa.eu/en/policies/cra-summary); konkretes Produkt, EU-Markt, Rolle, Ausnahmen und gestaffelte Anwendung gesondert pruefen |

Die einzigen Zustaende sind `PLANNING_CHOICE`, `REVIEW_HINT` und `OPEN`.
Sie sind keine gesetzliche Betroffenheitsklasse. Insbesondere 49 Mitarbeiter,
0, fehlende Finanzwerte oder eine Nein-Antwort erzeugen keine Freistellung.
Finanzwerte werden dezimal ohne Gleitkomma verglichen; genau 10 Mio. EUR
ueberschreiten den Hinweiswert nicht. Eine einzelne grosse Finanzkennzahl
genuegt diesem Kriterium nicht. Die Rohangaben sind keine gepruefte
gesetzliche Groessenberechnung und ordnen keine Einrichtungsklasse zu.

Alle drei Pruefpfade bleiben als begrenzte Checkliste sichtbar. Der deutsche
Referenzpfad ist keine automatische Deutschlandzuordnung: Freitext-Laender,
Sektorbezeichnungen und nationale/grenzueberschreitende Taetigkeit ersetzen
keine Rechtsraumpruefung. Weitere Rechtsraeume und Regelwerke sind offen.
Fehlende Kriterien duerfen nicht als negative Pruefergebnisse gelten.
Die CRA-Zusammenfassung ist eine erlaeuternde Quelle, kein Ersatz des
verbindlichen Verordnungstextes fuer eine Einzelfallpruefung.

Quellenabrufdatum, Quellen-/Normbezeichnung und Kriterienversion sind
getrennt ausgewiesen. Der Abruf ist kein Inkrafttretensdatum und kein
Versprechen laufender Rechtsaktualisierung. Eine fachliche Aenderung braucht
eine neue Kriterienversion und erneut gepruefte Referenzfaelle. Bestehende
Besucher loesen keine externen Abrufe aus; Quellen sind statische Links.

Die Ansicht berechnet Hinweise bei jedem Abruf neu. Aendert sich das Profil,
erscheint die neue Profilrevision; ein historischer Bewertungsbeschluss oder
Snapshot wird nicht gespeichert. Bestehende Session-/Rollen-/Tenantgrenzen,
private/no-store-Caches und HTML-Escaping bleiben verbindlich. Es entstehen
keine Pflicht, Nichtbetroffenheitsentscheidung, Bewertung, Freigabe, SoA,
Massnahme oder Aenderung historischer Assessment-Ergebnisse.

Weitere W2a-Gates sind strukturierte Rechtsraum-/Einrichtungs-/Rollenangaben,
versionierte fallbezogene Anforderungsentscheidungen und menschliche
Bestaetigung. Scope-/Risiko-/Control-Bindung und SoA folgen gesondert.
