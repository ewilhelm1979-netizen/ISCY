# Threat Model: CI-Artifact-Hygiene

## Sicherheitsziel

Performance- und Visual-Regression-Tests dürfen ausschließlich minimierte,
synthetische und vor dem Upload vollständig validierte Ergebnisdateien
freigeben. Rohdaten sind nicht uploadfähig. Wenn Herkunft, Dateityp, Inhalt,
Pfad oder Vollständigkeit nicht eindeutig nachgewiesen werden können, wird kein
Staging-Verzeichnis veröffentlicht.

## Schutzgüter und Bedrohungen

Der bisherige Upload vollständiger Ergebnisverzeichnisse konnte unbeabsichtigt
zusätzliche Dateien erfassen. Dazu gehören insbesondere Playwright-Traces,
Cookies, Storage-State, Sitzungsinformationen, Browserprofile, unerwartete
Screenshots und Videos, HTML- oder JSON-Rohreports, Backend-Logs,
SQLite-/PostgreSQL-/MinIO-Daten, `.env`-Dateien, Schlüssel und Zertifikate,
absolute interne Pfade, Tokens, vollständige HTTP-Nachrichten und
personenbezogene Daten.

Das Gate behandelt zusätzlich folgende Angriffe und Fehlerzustände:

1. Path-Traversal, absolute Pfade, Symlinks, Hardlinks nach außerhalb sowie
   Geräte, FIFOs und Sockets innerhalb des Raw-Verzeichnisses.
2. Neue oder umbenannte Dateien, die Testwerkzeuge ohne vorherige Freigabe
   erzeugen.
3. Zu viele oder übergroße Dateien und Artefakte, die festgelegte
   Gesamtgrößen überschreiten.
4. Dateien mit erlaubter Endung, aber falschem Binärtyp oder unerwartetem
   sensitiven Inhalt.
5. Uploads aus Pull Requests, deren Head-Repository nicht das aktuelle
   Repository ist.
6. Manipulation des Sanitizers durch nicht vertrauenswürdigen Pull-Request-Code.
7. Upload trotz fehlgeschlagener oder unvollständiger Sanitization.
8. Veränderungen von Quelldateien zwischen Prüfung und finalem Staging.

## Vertrauensgrenzen

- Tests schreiben ausschließlich in ein mit Modus `0700` erzeugtes Raw-Root
  unter `RUNNER_TEMP`; lokale Läufe verwenden `mktemp -d`.
- Rohdaten und Upload-Staging sind getrennte, disjunkte und kanonisch geprüfte
  Verzeichnisse. Kein Raw-Pfad wird an `upload-artifact` übergeben.
- Der zentrale Validator akzeptiert nur bekannte Artefakttypen, Optionen und
  Dateinamen. Er erstellt das endgültige Staging atomar aus privat erzeugten
  Kandidaten.
- Textausgaben werden schema-, marker-, pfad- und größenbasiert geprüft.
  Visual-Rohreports werden auf ein neues, minimiertes Schema reduziert.
- Das Manifest listet und hasht alle Payload-Dateien. Es listet sich nicht
  selbst, weil ein eingebetteter Hash der eigenen vollständigen Bytes
  zirkulär wäre; Schema, Größe und Inhalt des Manifests werden separat vor und
  nach der atomaren Veröffentlichung validiert.
- PNG-Diffs werden nur freigegeben, wenn Name, Signatur, Größe, Anzahl und
  synthetische Herkunft nachgewiesen sind. Andernfalls bleiben Bilder
  vollständig ausgeschlossen.
- Jeder Fehler und jedes unterstützte Signal entfernt Raw-, Kandidaten- und
  Staging-Daten. Fehlermeldungen enthalten nur relative Pfade und
  Finding-Kategorien, nie Trefferwerte.
- Workflow-Aufbereitung und Upload laufen nur bei Pushes im eigenen Repository
  oder Pull Requests mit exakt übereinstimmendem Head-Repository. Ein
  fehlgeschlagenes Hygiene-Gate verhindert den Upload und lässt den Job
  fehlschlagen.

## Restrisiken

Allowlist, Schema- und Markerscans können nicht semantisch beweisen, dass jeder
beliebige Pixelinhalt frei von sensiblen Daten ist. Daher sind PNG-Diffs nur
für die isolierte, lokale, synthetische Testinstanz zulässig; bei fehlendem
Herkunftsnachweis werden ausschließlich Zusammenfassung und Manifest
freigegeben. Nicht abfangbare Prozessabbrüche wie `SIGKILL` oder ein
Runner-Ausfall werden durch private temporäre Roots und den ephemeren
GitHub-Runner begrenzt; solche Roots sind niemals Uploadpfade.
