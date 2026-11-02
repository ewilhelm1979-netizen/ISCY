# ISCY-27: Angaben, Evidence-Verknuepfung und Wirksamkeit

Stand: 02.11.2026. Dieser Meilenstein praezisiert das lesende Kennzahlenmodell
und die Control-Ansicht. Er fuegt keinen Freigabe-/Pruefprozess hinzu und
veraendert keine gespeicherten Mandantenentscheidungen.

## Bedeutung der Kennzahlen

Die Control-Library und ihre Gruppen liefern zusaetzlich `assessment_metrics`:

| Feld | Bedeutung |
| --- | --- |
| `declared_implemented_controls` | Status `IMPLEMENTED` oder `EFFECTIVE` laut Angabe |
| `declared_effective_controls` | Status `EFFECTIVE` laut Angabe |
| `declared_evidenced_controls` | Evidence-Status `EVIDENCED` laut Angabe |
| `controls_with_linked_evidence` | Mindestens ein Evidence-Eintrag dieses Mandanten ist verknuepft |
| `not_applicable_controls` | Status `NOT_APPLICABLE` laut Angabe |
| `non_excluded_controls` | Aktive Controls ohne gesetzten N/A-Status; keine bestaetigte Anwendbarkeitsentscheidung |
| `controls_without_status_record` | Kein gespeicherter Mandantenstatus; Legacy-Fallback GAP/0 ist keine bewusste Bewertung |
| `recorded_non_excluded_controls` | Gespeicherter Statusstand und kein N/A-Status |
| `recorded_non_excluded_average_maturity` | Gespeicherte Reife 0–5 ueber diese Statusstaende; ohne Nenner `null` |
| `verified_effective_controls` | Derzeit `null`: ein eigener Control-Wirksamkeitsreview wird noch nicht erfasst |

Die Mengen ueberlappen und werden nicht zu einem Konformitaetsscore addiert.
Eine Verknuepfung kann etwa auf einen Entwurf zeigen; Vorhandensein beweist
keine Nachweisqualitaet oder Wirksamkeit. Auch `APPROVED` an einem Dokument
ist keine eigene Pruefentscheidung zur Wirksamkeit des gesamten Controls.
Das bisherige `reviewed_at` wird beim Statusedit gesetzt und wird deshalb
nicht als Wirksamkeitspruefung interpretiert.

`null` bei gepruefter Wirksamkeit bedeutet **nicht erfasst**, nicht null
wirksame Controls. Dasselbe gilt fuer den Reifegrad bei leerer Library oder
ausschliesslich N/A-Controls. N/A wird weder als umgesetzt gezaehlt noch
als Reife 0 in den neuen Durchschnitt einbezogen. Fehlende Statusstaende
zaehlen ebenfalls nicht als gespeicherte Reife 0; `has_status_record` am
Control kennzeichnet den Unterschied zu den bisherigen GAP-/0-Fallbackwerten.
Ein Statusstand kann auch durch eine andere Statusbearbeitung entstanden
sein und ist keine bestaetigte Reifegradpruefung. Die bestehende Skala ist
eine eigene deklarative Skala und kein Nachweis einer Normerfuellung.

## Kompatibilitaet und Anzeige

Bestehende API-Felder `covered_controls`/`covered_count` bleiben als
deklarative Zaehler fuer `IMPLEMENTED`/`EFFECTIVE` erhalten. Auch
`average_maturity` behaelt fuer bestehende Clients den alten Nenner ueber
alle aktiven Controls. Neue Clients sollen die ausdruecklichen Kennzahlen
verwenden. Es gibt keine Datenbankmigration oder geaenderte Statuscodes.

Die Control-Ansicht zeigt Umsetzung und Wirksamkeit **laut Angabe**,
tatsaechliche Evidence-Verknuepfungen sowie gepruefte Wirksamkeit als
**nicht erfasst**. Gruppen weisen N/A, Controls ohne Statusstand und gespeicherte Reife ohne N/A aus. Der Hinweis
zu Selbstauskunft und Evidence-Qualitaet ist auch fuer lesende Rollen
sichtbar. Die Formulare behalten ihre bisherigen Werte und Schreibgrenzen.
Die Evidence-Lueckenanzeige in dieser Ansicht bezieht sich auf fehlende
Verknuepfungen bei nicht ausgeschlossenen Controls.

Mandantenbindung wird aus den bestehenden serverseitigen Queries
uebernommen; fremde Evidence-Eintraege zaehlen nicht mit. Die neuen
Kennzahlen und Seitenaufrufe veraendern weder Status noch Zeitstempel.

## Weitere fachliche Gates

Ein ausdruecklicher Wirksamkeitsreview braucht eigene Pruefkriterien,
Scope-/Control-/Nachweisversionen, Ergebnis, pruefende Person, Datum,
Gueltigkeit und Freigabegrenzen. Erst ein solcher nachvollziehbarer Prozess
kann gepruefte Wirksamkeit liefern. Auch begruendete Anwendbarkeit,
Stufenanker, Nachweisgueltigkeit und die Bindung an den Wizard-/SoA-Pfad
bleiben weitere Meilensteine. [Fachpruefung](ISCY27_FRAMEWORK_REVIEW.md)
und [SoA-Zielpfad](COMPANY_CONTEXT_TO_SOA_RESEARCH.md) bleiben massgeblich.
