# Unternehmens-Pruefstaende dauerhaft festhalten

Stand: 05.11.2026. Additive Migration `0050_rust_company_context_snapshot`
fuer SQLite und PostgreSQL. Kriterien bleiben `W2A-2026-11-03.1` mit dem
bisher dokumentierten Quellenabruf 03.11.2026; Speichern aktualisiert keine
Quellen und behauptet keine neue Rechtspruefung.

Nach Speichern des Profils unter **Gespeicherten Unternehmenskontext pruefen**
den Button **Diesen Pruefstand dauerhaft speichern** verwenden. Er haelt
die gespeicherten Profilangaben und deren Revision sowie Kriterienversion,
Quellenbezeichnungen/-links, Abrufdatum, Hinweise, Begruendungen und offene
Fragen fest. Nicht gespeicherte Formulareingaben gehoeren nicht dazu.
Die Kontextansicht verlinkt die letzten 50 Pruefstaende dieses Entwurfs.

Ein spaeterer Profil-Save oder eine neue Kriterienimplementierung berechnet
alte Pruefstaende nicht neu. Die historische Ansicht liest die festgehaltenen
Felder. Die Anwendung bietet keine Aenderungs-/Loeschfunktion fuer diese
Staende. Das ist keine kryptografische Manipulationssicherung gegen direkte
Datenbankadministration und kein vollstaendiges Archiv aller Profilsaves.

Speichern ist ein technischer Dokumentationsschritt. Er bestaetigt keine
fachliche Review, Rechtsbetroffenheit, Nichtbetroffenheit, Zertifizierung,
Freigabe, SoA oder Massnahme. W2a braucht weiterhin strukturierte Rechtsraum-/
Einrichtungs-/Rollenangaben und bestaetigte Anforderungsentscheidungen;
Scope-/Risiko-/Control-Bindung und SoA bleiben eigene weitere Schritte.

## Zugriff und Gleichzeitigkeit

- Anlegen nur mit echter schreibberechtigter Session und bestehendem
  Wizard-CSRF-Token. Revision und Kriterienversion muessen noch aktuell sein.
- Profil-Save und Snapshot-Anlage verwenden dieselben Elternsperren:
  SQLite `BEGIN IMMEDIATE`, PostgreSQL `FOR UPDATE` auf Session/Profil.
  Veraltete oder abgeschlossene/gesperrte Staende liefern Konflikt.
- Doppelte Anfragen fuer dieselbe Profilrevision/Kriterienversion verwenden
  denselben Pruefstand und erzeugen kein zweites Anlageereignis. Das ist
  kein persoenlicher Reviewbeschluss jedes einzelnen Aufrufers.
- Pruefstand und Anlageereignis werden atomar gespeichert. Auditfehler
  verwerfen beide; das Profil und historische Ergebnisse bleiben erhalten.
- Lesen bleibt fuer die bestehenden Leserrollen moeglich, auch nach
  Abschluss des Profils. Tenant, Elternentwurf und Snapshot-ID sind in der
  Datenbankabfrage gebunden; Antworten privat/no-store, Inhalte HTML-escaped.

Der POST-Einstieg ist `/assessments/company-wizard/{id}/context/snapshots/`;
der historische GET endet zusaetzlich auf `{snapshot_id}/`. Gespeichert wird
Payloadschema 1, begrenzt auf 64 KiB. Unbekannte Schemaversion oder unpassende
Profil-/Kriterienbindung wird abgewiesen; es gibt keinen stillen Ersatz durch
eine neue Berechnung. Der Vorgang uebernimmt keine Sessiontokens oder
Verbindungs-Zugangsdaten aus der Anmeldung beziehungsweise Laufzeitumgebung.

Die Migration laeuft ueber den bestehenden Betreiber-/Deploymentweg, nicht
durch Aufruf der Webansicht. Vor einem Downgrade gilt der bestehende
Schema-/Wiederherstellungsvertrag; alte Binaries koennen die neuen Ansichten
nicht bereitstellen. Keine Snapshots oder Migrationsreceipts zur Erzwingung
eines Downgrades loeschen. Der veroeffentlichte SBOM-Snapshot bleibt historisch.
