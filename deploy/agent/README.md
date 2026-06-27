# ISCY Agent Deployment

Diese Beispiele betreiben den read-only `iscy-agent` periodisch. Der erste Lauf
erfolgt einmalig mit einem Enrollment-Token. Danach liegen Device-ID und
Agent-Secret im geschuetzten State-Verzeichnis; weitere Laeufe brauchen kein
Enrollment-Token.

## Reihenfolge

1. Release-Binary nach `/usr/local/bin/iscy-agent` beziehungsweise auf den
   plattformspezifischen Zielpfad installieren.
2. Enrollment-Token in ISCY erzeugen.
3. Agent einmal mit Backend-URL, Tenant-ID und Enrollment-Token starten.
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
