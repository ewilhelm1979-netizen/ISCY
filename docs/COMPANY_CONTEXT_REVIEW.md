# Unternehmens-Wizard: Ziel und Kontext pruefen

Stand: 03.11.2026. Der W2a-Faktenbaustein enthaelt nun zusaetzlich
[versionierte Anforderungs-Pruefhinweise](COMPANY_REQUIREMENT_SCREENING.md).
Die bestaetigte fallbezogene Betroffenheitsentscheidung bleibt ein weiterer Meilenstein.

## Bedienung

Im Unternehmensprofil sind nun zwei ausdrueckliche Angaben moeglich:

- Ziel des Durchlaufs: noch offen, Betroffenheitsorientierung,
  ISO-Readiness oder ISMS-Aufbau/Weiterentwicklung.
- Geografischer Kontext laut Angabe: noch unbekannt, national oder
  grenzueberschreitend. Er wird nicht aus Freitext-Laendernamen abgeleitet.

Nach Speichern fuehrt **Gespeicherten Unternehmenskontext pruefen** zu
`/assessments/company-wizard/{id}/context/`. Die Ansicht zeigt die aktuelle
gespeicherte Profilrevision, die einzelnen Kontextfakten und offene Angaben.
Nicht gespeicherte Eingaben aus einem anderen Browserfenster gehoeren nicht
zu diesem Stand. Es wird kein historischer Snapshot oder Reviewbeschluss
erzeugt; ein erneuter Abruf zeigt die dann aktuelle gespeicherte Revision.

Ein nationales Unternehmen kann den ISO-/ISMS-Pfad nutzen, ohne ein zweites
operatives Land angeben zu muessen. Unbekannte Auslandsaktivitaet bleibt
unbekannt. Zahlen 0 und Antwort Nein bleiben von leer/unbekannt getrennt.
Eine ausgefuellte Zeile bedeutet nur **erfasst laut Angabe**; auch null
offene Felder beweisen keine vollstaendige oder richtige Rechtsbeurteilung.

Die naechsten Prueffragen richten sich nach dem gewaehlten Ziel. Fuer
ISO-/ISMS-Ziele werden Scope, Anforderungen und Risikobehandlung benannt;
fuer die Orientierung die konkrete Rechtsraum-/Taetigkeits-/Groessenpruefung.
Gesetzliche, vertragliche und geschaeftliche Anforderungen brauchen weiterhin
Quellen, Geltungsstand und Einheitenbezug. Produkt-/KI-/OT-/Automotive-Angaben
brauchen die konkrete Rolle und Taetigkeit. Die Ansicht generiert keine
Rechtspflicht, SoA, Massnahme oder Freigabe.

## Daten und Zugriff

`assessment_goal` und `activity_context` sind validierte Auswahlwerte im
bestehenden Profil-JSON. Aeltere Profile ohne die Felder werden als offen
gelesen. Neue Saves verwenden weiterhin die vorhandene CAS-Revision,
Session-/Rollen-/Tenantpruefung, CSRF und transaktionale Auditmetadaten.
Es gibt keine neue Datenbankmigration. Aeltere W1-Binaries mit striktem
JSON-Schema koennen neu gespeicherte Profile mit den zusaetzlichen Feldern
nicht lesen; ein Downgrade braucht deshalb eine eigene Kompatibilitaetspruefung.

Die Kontextansicht ist ausschliesslich lesend und tenantgebunden. Auch
leseberechtigte Rollen und gesperrte gespeicherte Entwuerfe koennen sie
ansehen. Fremde Objekt-IDs, unzureichende Rollen und manipulierte
Identitaetsheader bleiben gesperrt; Query-Parameter ersetzen keine Session.
Antworten sind privat/no-store. Angezeigte Benutzereingaben sind HTML-escaped.

Organisations-Stammprofil, historische Assessment-Ergebnisse, Controls,
Risiken, Evidence und SoA werden von diesem Schritt nicht veraendert.
Der [durchgaengige Zielpfad](COMPANY_CONTEXT_TO_SOA_RESEARCH.md) und die
[weiteren Wiederherstellungs-Gates](COMPANY_WIZARD_RESTORATION.md) bleiben offen.
