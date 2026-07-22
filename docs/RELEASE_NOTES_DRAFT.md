# ISCY V23.7.30 - Development Notes

Status: Development / Unreleased.

Basis: `V23.7.29` (`ba47201885435d57efc5042acde665f42dc000df`).

Dieser Entwicklungsstand wurde noch nicht veroeffentlicht. Es gibt noch keinen
Tag und noch kein GitHub Release fuer `V23.7.30`. Implementierte Aenderungen
werden bis zur naechsten Release-Vorbereitung unter Unreleased dokumentiert.

## Fortbestehende Basis

ISCY bleibt eine selbst gehostete, local-first und datenschutzbewusste
Open-Source-Plattform unter `AGPL-3.0-only`. Der veroeffentlichte Stand
`V23.7.29` bleibt unveraendert und ist im Repository unter
`release/published/V23.7.29.json` als Metadaten-Snapshot dokumentiert.

Die vorhandenen Governance- und Nachweisfunktionen unterstuetzen unter anderem
ISO 27001, NIS2, KRITIS, DORA, den Cyber Resilience Act, den EU AI Act und die
DSGVO. Diese Unterstuetzung ist keine Rechtsberatung, Zertifizierung,
Konformitaetsentscheidung oder automatische Behoerdenmeldung.

## Entwicklungsgrenzen

- In diesem Stand wird kein Release-Bundle vorbereitet oder erzeugt.
- `V23.7.30` besitzt noch keinen Release Candidate und keine Stable-/Latest-
  Freigabe.
- Neue Produktfunktionen werden erst nach ihrer Implementierung und Pruefung
  unter `Unreleased` dokumentiert.
- Eine Wazuh-Integration, IOC-/Behavioral Detection und automatisches Threat
  Modeling sind nicht implementiert.

## Agent Rollout 2.0 - Phase 1

Der Entwicklungsstand ergaenzt eine tenantgebundene, auditierbare
Rollout-Control-Plane fuer bereits registrierte Agenten. Rollouts verwenden die
festen Ringe Lab, Canary, Pilot, Production und Critical sowie serverseitige
Preflight-/Postflight-Pruefungen, Gate-Evaluierung, explizite menschliche
Promotion, Pause/Resume, Abbruch und operatorgefuehrte Rollback-Dokumentation.

ISCY dokumentiert die extern durchgefuehrte Verteilung und ihre Ergebnisse,
fuehrt jedoch keine Remote-Installation, Agent-Befehle, Paketuebertragung oder
technische Rollback-Ausfuehrung aus. Die Funktion garantiert keine fehlerfreien
produktiven Rollouts und begruendet keine Produktions-SLO.

## Agent Rollout 2.0 - Phase 2

Migration `0041_rust_agent_rollout_manifest_handoff` ergaenzt pro Ring ein
unveraenderliches, versioniertes Manifest. ISCY erzeugt kanonisches kompaktes
JSON mit stabil sortierten Targets und berechnet den SHA-256 ueber exakt diese
exportierten Manifest-Bytes. Artefakt-/Provenance-, Policy-, Plattform-,
PKI-/mTLS- und Preflight-Metadaten werden beim Freeze tenantgebunden
eingefroren; ein Ringstart ohne integres aktives Manifest wird blockiert.

Passive externe Handoffs und begrenzte Result-Pakete dokumentieren die
Uebergabe an ein externes Deployment-System. Der Import ist auf 1 MiB und 500
Targets begrenzt, validiert Referenzen und Replay serverseitig und verwendet
transaktional dieselbe interne Target-Result-Logik wie Phase 1. ISCY speichert
keine externen Credentials oder Roh-Requests, ruft keine Deployment-URL auf
und fuehrt weiterhin keine Remote-Installation, Paketuebertragung oder
automatische Promotion aus.

## Technische Basis

- Internes Rust-Paket: `0.3.22`
- Rust-Haupttoolchain: `1.97.0`
- Produkt-Builder: offizielles Rust-1.97.0-Bookworm-Multiarch-Image per Digest gepinnt; keine Toolchain- oder Produktfunktionsaenderung
- MSRV und portabler Release-Builder: Rust `1.88.0`
- PostgreSQL 16 bleibt der Standard.
- PostgreSQL 18.4 bleibt ein zusaetzlicher Kompatibilitaetspfad.
- Aktuell 41 fortlaufende Migrationen, `0001` bis `0041`
- 36 Visual-Baselines
- Signaturstatus: `unsigned`
- Provenance-Status: `prepared_unsigned`
