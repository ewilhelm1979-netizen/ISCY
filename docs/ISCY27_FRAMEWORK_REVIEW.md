# Fachpruefung des ISCY-27-Modells

Stand: 02.11.2026, Codebasis Main
`b18afb256219f27176ac654b084a82b978a7a3af`.
Untersucht wurden die eingecheckten Control-Seeds, deren Datenmodell,
Kennzahlen und die Verbindung zum geplanten Unternehmens-/SoA-Pfad.
Produktive Mandantendaten wurden nicht gelesen oder veraendert.

Fortschreibung: Die zehn eindeutigen NIS2-Errata werden inzwischen durch
[Migration 0049](ISCY27_REFERENCE_CORRECTION.md) fuer unveraenderte
Originalzuordnungen korrigiert. Die folgende Analyse dokumentiert den
historischen Befund der genannten Codebasis. Eigene Anpassungen, die zwei
gemischten Begruendungen und die Kennzahl-/Vollstaendigkeitsfragen bleiben
gesondert zu pruefen.

Die [Kennzahlentrennung](ISCY27_ASSESSMENT_METRICS.md) ist inzwischen als
additives Lesemodell umgesetzt: Selbstauskunft, Evidence-Verknuepfung,
N/A und nicht erfasste gepruefte Wirksamkeit werden unterschieden.
Pruefprozess, Stufenanker und begruendete Anwendbarkeit bleiben weitere Gates.

## Bewertung

Die 27 Bereiche sind eine brauchbare eigene Steuerungsstruktur: Ziele,
Owner und Nachweishinweise verbinden Governance, Betrieb, Produkte,
Lieferanten, Menschen und Verbesserung. Sie koennen auch fuer ein rein
nationales Unternehmen genutzt werden. M&A ist dabei ein moeglicher
Geschaeftskontext, keine Voraussetzung fuer die Nutzung.

Eigene Controls sind mit einem ISO-orientierten ISMS vereinbar. Die
notwendigen Massnahmen muessen aus Anforderungen und Risikobehandlung
bestimmt und gegen Annex A abgeglichen werden. 27 eigene Bereiche ersetzen
diesen Abgleich nicht. [SC27 Journal 2025, Issue 1, Seiten 18/19](https://committee.iso.org/files/live/sites/jtc1sc27/files/resources/Journal%202025.pdf)

Als Plausibilitaetsvergleich stuetzt NIST CSF 2.0 die Nutzung einer
organisationsgerechten Struktur von Sicherheitszielen. Daraus folgt weder
eine Anerkennung von ISCY-27 durch NIST noch eine gepruefte Gleichwertigkeit.
[NIST CSF 2.0](https://doi.org/10.6028/NIST.CSWP.29)

**Die Grundidee kann bleiben. Rechtsverweise, Abdeckungsmodell und
Nachweisregeln sind vor einer Konformitaetsaussage nachzuarbeiten.**

## Inventur und technische Grenzen

Die SQLite- und PostgreSQL-Seed-Dateien enthalten inhaltlich dieselben
27 Controls, 82 Mappings und 27 Demo-Statuszeilen. Das wurde durch
Auswertung beider INSERT-Datenbestaende in einer eigenen In-Memory-Fixture
verglichen; dies ist keine native PostgreSQL-Laufzeitabnahme.

Die Mappings verteilen sich auf NIS2 (23), DORA (19), ISO27001 (11),
TISAX (10), DSGVO (9), CRA (6) und AI Act (4). Ihre Anzahl sagt nichts
ueber die Vollstaendigkeit oder Erfuellung eines Regelwerks aus.
Demo-Status und mitgelieferte Nachweishinweise sind keine Nachweise einer
tatsaechlichen Umsetzung in einer Organisation.

Die ISCY-27-Mappingtabelle besitzt Referenztext, Einordnungsart und
Begruendung, aber keine expliziten Felder fuer Quell-URL, Normausgabe,
Rechtsstand, Gueltigkeitsintervall oder fachliche Mapping-Freigabe.
`created_at` und `updated_at` ersetzen diese Angaben nicht. Das
Anforderungsregister hat bereits weitergehende Quellen-/Versionskonzepte;
beide Modelle muessen nachvollziehbar verbunden werden.

## Konkrete NIS2-Errata

Abgleich der Seed-Referenzen mit Artikel 21 Absatz 2 der Richtlinie.
Die Tabelle beschreibt Korrekturvorschlaege fuer die jeweils benannten
Themen; sie ist keine Entscheidung ueber die Betroffenheit eines Unternehmens.
[Amtlicher NIS2-Text, Artikel 21](https://eur-lex.europa.eu/legal-content/EN/TXT/PDF/?uri=CELEX%3A32022L2555)

| Mapping-ID / ISCY-Bereich | Bisheriger Buchstabe in Art. 21(2) | Fachlich passender Bezug fuer das benannte Thema |
| --- | --- | --- |
| 1007 / 03 Projekt-Governance | d | e: sichere Beschaffung/Entwicklung/Wartung |
| 1020 / 07 Vulnerability Management | d, f | e: Schwachstellenbehandlung; g: Cyberhygiene; f nur fuer gesondert beschriebene Wirksamkeitspruefung |
| 1026 / 09 IAM | h, i | i: Zugriff; j: MFA; h beschreibt Kryptografie |
| 1029 / 10 Assets | h | i: Asset-Management |
| 1035 / 12 Change | d | e: sichere Wartung |
| 1042 / 14 SDLC | d | e: sichere Entwicklung |
| 1044 / 15 Third-Party Risk | c | d: Lieferkette |
| 1048 / 16 Supply Chain | c | d: Lieferkette |
| 1072 / 24 Verbesserung | b | f: Wirksamkeitspruefung |
| 1077 / 26 HR | h | i: Personalsicherheit |

Zwei weitere Zuordnungen brauchen eine aufgeteilte Begruendung:
1023 / ISCY-08 kann Incident Handling unter b unterstuetzen; die im Titel
genannte Wirksamkeit gehoert zu f. 1080 / ISCY-27 verweist fuer
Lieferkettenaenderungen auf c; dafuer ist d einschlaegig. Ein zusaetzlicher
BCM-Bezug unter c kann bei einer konkreten Integration sinnvoll sein.
Keinen Sammelverweis ohne Einzelbegruendung mechanisch ersetzen.

Auch Quellcodes, Titel und Rationale muessen mit den korrigierten
Referenzen zusammenpassen. Eine Beziehung `PRIMARY` oder `SUPPORTING`
beschreibt zunaechst die Art des Mappings, keinen Erfuellungsgrad.

Nationale Umsetzung und EU-Richtlinie sind getrennte versionierte Quellen.
Fuer deutsche Sachverhalte ist insbesondere der jeweils geltende BSIG-Stand
einzubeziehen. [BSIG, insbesondere §§ 28 und 30](https://www.gesetze-im-internet.de/bsig_2025/BSIG.pdf)

Die uebrigen Frameworks sind durch diese gezielte Pruefung nicht insgesamt
validiert. Beispielsweise muessen AI-Act-Mappings die Rolle und Kategorie
des konkreten Systems beruecksichtigen; ein allgemeines KI-Merkmal genuegt
nicht. [EU-Kommission: AI Act](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai)

## Kennzahlen und Entscheidungen

Codebefunde aus `rust/iscy-backend/src/control_store.rs`:

| Heutiges Verhalten | Konsequenz fuer die weitere Umsetzung |
| --- | --- |
| `covered_controls` zaehlt `IMPLEMENTED` und `EFFECTIVE` allein nach Status | Als deklarierter Umsetzungsstand benennen; belegte Umsetzung und gepruefte Wirksamkeit getrennt ausweisen |
| Status, Reifegrad und Evidence-Status sind unabhaengig setzbar | `EFFECTIVE` kann mit Reife 0 und fehlendem Nachweis kombiniert werden; fuer bestaetigte Wirksamkeit sind definierte Nachweise, Pruefung und Gueltigkeit erforderlich |
| Reife 0–5 wird begrenzt und ueber alle aktiven Controls gemittelt | Eigene Skala mit pruefbaren Stufenankern und kontextbezogenen Zielwerten dokumentieren; Durchschnitt ist keine Normkonformitaet |
| `NOT_APPLICABLE` existiert, bleibt aber im Nenner des Reifegradmittels | Anwendbare, ausgeschlossene und noch ungeklaerte Bereiche getrennt zaehlen; N/A nicht als Reife 0 oder als umgesetzt behandeln |
| N/A braucht im Status-Update keine verpflichtende Begruendung; `reviewed_at` wird bei jedem Update gesetzt | Scopebezug, Ausschlussgrund und ausdruecklichen Review erfassen; Edit-Zeitpunkt nicht als unabhaengige Pruefung ausgeben |
| Gap-Roadmap waehlt `GAP` und `PARTIAL` | Ein pauschaler Bereichsstatus darf spaeter keine notwendige Einzelmassnahme oder ungeklaerte Anwendbarkeit verdecken |

Die Heatmap zeigt Evidence-Zahl und Evidence-Status bereits getrennt.
Diese Trennung sollte in den Summen erhalten bleiben. Ein Dokument am
Control ist erst nach inhaltlicher Beurteilung ein geeigneter Nachweis.

## Fachliche Tiefe der 27 Bereiche

Die Oberstruktur muss nicht kuenstlich auf 93 Eintraege erweitert werden.
Stattdessen brauchen die Bereiche konkrete Unterkontrollen bzw.
Pruefkriterien mit nachvollziehbarer Mehrfachzuordnung zu Referenzen.
Explizit zu pruefen sind insbesondere physische/Umgebungssicherheit,
Kryptografie und Schluesselverwaltung, Netzwerksicherheit/Segmentierung,
sichere Konfiguration/Haertung sowie Cloud-/Kommunikationsschutz.
Breite Hinweise etwa auf Verschluesselung in Data Governance belegen noch
keine vollstaendige operative Ausarbeitung dieser Themen.

ISCY-03/12/13/14 und ISCY-05/06/18 duerfen sich fachlich ueberlappen.
Gemeinsame Nachweise koennen wiederverwendet werden; Verantwortlichkeit
und konkrete Pruefziele muessen pro Zuordnung erkennbar bleiben. M&A kann
im gegebenen Scope begruendet nicht anwendbar sein, waehrend Basisprozesse
wie Risiko- und Zugriffsmanagement weiterhin erforderlich sind.

## Verbindung mit Wizard, SoA und RAG

Der [Unternehmens-/SoA-Zielpfad](COMPANY_CONTEXT_TO_SOA_RESEARCH.md)
bleibt massgeblich: Profil, Scope, Anforderungen und Risiken begruenden
die notwendigen Controls. ISCY-27 bietet deren Arbeits- und
Verantwortungsstruktur. Die SoA haelt die konkreten notwendigen Controls
und den Annex-A-Abgleich fest. Eine aggregierte 27-Zeilen-Heatmap allein
reicht dafuer nicht aus.

RAG/Lokal Aegis bleibt ein getrenntes Projekt. Eine spaetere explizit
beauftragte Schnittstelle koennte Quellen und technische Evidence als
pruefbare Vorschlaege liefern. Eine Modellantwort oder ein Scannerfund
setzt keinen ISCY-Status automatisch auf konform oder wirksam.
Aktuell wird keine solche Verbindung implementiert.

## Priorisierte Abnahme vor einem Konformitaetsclaim

1. **Referenzkorrektur:** NIS2-Errata fachlich freigeben; passende
   Quellen-/Regelversion und Mapping-Begruendungen festhalten. Weitere
   Frameworks systematisch einzeln pruefen.
2. **Versionsgebundene Datenkorrektur:** Seeds fuer Neuinstallationen und
   einen expliziten Upgradepfad fuer Bestandsdaten gemeinsam vorsehen.
   `INSERT OR IGNORE` bzw. `ON CONFLICT DO NOTHING` repariert bestehende
   Mappingzeilen nicht. Keine Demo-Statuszeilen als Reparatur replayen.
3. **Bewertungsmodell:** Scope, begruendete Anwendbarkeit, Stufenanker,
   Nachweisgueltigkeit und ausdruecklichen Wirksamkeitsreview verbinden;
   Summen fuer Deklaration, Nachweis und Wirksamkeit trennen.
4. **Vollstaendigkeitspruefung:** Referenzkatalog und fachliche Unterkontrollen
   pruefen; Einzelreferenzen, eigene Controls und Managementsystem-
   Anforderungen getrennt halten; Verbindung zum W2c-/W3-Pfad abnehmen.

Diese Recherche aendert keine Seed-Datei, Migration oder Mandantenbewertung.
Sie dokumentiert die konkreten Befunde und den noetigen Reparaturpfad.
