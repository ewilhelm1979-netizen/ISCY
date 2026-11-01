# ISCY Agent Deployment

Diese Beispiele betreiben den read-only `iscy-agent` periodisch. Der erste Lauf
erfolgt einmalig mit einem Enrollment-Token. Danach liegen Device-ID und
Agent-Secret im geschuetzten State-Verzeichnis; weitere Laeufe brauchen kein
Enrollment-Token.

## Reihenfolge

1. Release-Binary nach `/usr/local/bin/iscy-agent` beziehungsweise auf den
   plattformspezifischen Zielpfad installieren.
2. Enrollment-Token im vorhandenen Wizard `/zero-trust/onboarding/` erzeugen.
3. Lokal `--check` ausfuehren, dann Agent einmal bewusst starten (siehe unten).
4. Token aus der lokalen Konfiguration entfernen.
5. Timer, Scheduled Task oder LaunchDaemon aktivieren.

Die Queue arbeitet mit At-least-once-Zustellung. Bei Transportfehlern, HTTP 429
oder HTTP 5xx bleiben Reports lokal liegen und werden beim naechsten Lauf zuerst
gesendet. Dauerhafte HTTP-4xx-Fehler werden bewusst nicht endlos wiederholt.

Enthaltene Beispiele:

- `systemd/`: gehaerteter Linux-One-shot-Service mit Timer
- `nixos/`: deklaratives NixOS-Modul fuer denselben Timer
- `windows/`: Installation als Scheduled Task unter `SYSTEM`
- `macos/`: LaunchDaemon fuer macOS

Weitere Sicherheits- und Betriebsdetails stehen in `docs/ZERO_TRUST_AGENT.md`.

## Lokale Vorpruefung vor dem ersten Start

Token in einer privaten Datei ausserhalb des Repositorys bereitstellen. Unter
Unix nur Eigentuemerrechte (z.B. `0600`), unter Windows eine restriktive ACL
fuer die ausfuehrende Identitaet verwenden. Der Agent akzeptiert regulaere,
lesbare Dateien bis 16 KiB; Unix-Gruppen-/Fremdzugriff und Symlinks sind
unzulässig. ACLs unter Windows werden vom Agenten nicht automatisch bewertet.

```bash
export ISCY_BACKEND_URL=https://iscy.example.org
export ISCY_TENANT_ID=1  # eigenen Mandanten aus dem Wizard verwenden
export ISCY_AGENT_ENROLLMENT_TOKEN_FILE=/privater/pfad/enrollment-token
iscy-agent --check
# Erst nach erfolgreicher lokaler Pruefung bewusst registrieren/melden:
iscy-agent
```

Alternativ: `--enrollment-token-file PATH` oder fuer ein bereits registriertes
Geraet `--agent-secret-file PATH` / `ISCY_AGENT_SECRET_FILE`. Wert und Datei
fuer dasselbe Secret duerfen nicht gleichzeitig gesetzt sein. Tokens nicht
als Klartextargument in Shell-History oder Prozesslisten uebergeben.

`--check` prueft URL, Optionen, Secretdatei und vorhandene State-Metadaten;
es sammelt kein Inventar, schreibt weder State noch Queue und stellt keine
Netzverbindung her. Fehlende Credentials oder fremder Tenant-State liefern
einen Fehlerstatus. Backend-Erreichbarkeit, Token-Gueltigkeit, Berechtigungen
und stabile Geraetebindung werden erst beim echten Agentenlauf geprueft.
`--dry-run`/`--self-test` sammeln dagegen lokale Inventardaten.

Nach erfolgreichem Enrollment Token-Konfiguration entfernen; kuenftige
Laeufe verwenden das persistierte Agent-Secret. Fuer DynamicUser-Dienste
muss die Secretdatei fuer die Dienstidentitaet erreichbar sein; eine private
Root-Datei wird nicht allein durch Setzen von `*_FILE` lesbar. Die vorhandene
rootgelesene EnvironmentFile-Variante bleibt kompatibel. Keine Tokens in
Nix-Store-Ausdruecke schreiben. Timer-/Task-Aktivierung bleibt ein bewusster
Installationsschritt, kein Bestandteil der Vorpruefung.
