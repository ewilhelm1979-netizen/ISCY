# ISCY GUI Screenshots

Stand: ISCY Unreleased / Rust 0.3.22

Diese Screenshots dokumentieren die aktuelle serverseitige ISCY-Weboberflaeche fuer die wichtigsten Tabs und Funktionsbereiche.

Die getrennten Visual-Regression-Baselines unter `../tests/visual/baselines/`
werden mit dem durch `flake.lock` gepinnten Playwright-/Chromium-Pfad erzeugt.
Sie pruefen 18 zentrale Bereiche bei 1440 x 1200 und 1024 x 900. Die
Dokumentationsbilder in `docs/assets/` werden nicht automatisch als
Testbaselines verwendet oder durch CI ueberschrieben. Update- und Diff-Prozess
sind in `PERFORMANCE_HA_VISUAL_TESTING.md` beschrieben.

## Dashboard

![Dashboard](assets/iscy-dashboard.png)

## Organisation And Regulatory Profile

![Organizations](assets/iscy-organizations.png)

## Guidance Navigator

![Guidance Navigator](assets/iscy-navigator.png)

## Zero Trust Desktop

![Zero Trust Desktop](assets/iscy-zero-trust-desktop.png)

Die Zero-Trust-Ansicht enthaelt zusaetzlich Agent-Artefakte und
Release-Provenance mit SHA-256, Signaturstatus, Verification-Status,
Provenance-Status und sicheren schreibrollenbasierten Pruefaktionen.
Sie enthaelt ausserdem die Agent-PKI-/CSR-/mTLS-Governance mit Provider-,
CSR-, Zertifikats-, Rotations- und Widerrufstatus als Metadata-only-Ansicht
ohne produktive CA-Ausstellung.

## Zero Trust Mobile

![Zero Trust Mobile](assets/iscy-zero-trust-mobile.png)

## Agent-Rollouts

![Agent-Rollouts](assets/iscy-agent-rollouts.png)

Die Rollout-Ansicht plant bestehende Agent Devices in den festen Ringen Lab,
Canary, Pilot, Production und Critical. Sie dokumentiert Preflight,
Postflight, Gate-Evaluierung, menschliche Promotion und operatorgefuehrten
Rollback. ISCY fuehrt dabei keine Remote-Installation, Agent-Befehle oder
automatische Softwareverteilung aus.

## CVEs

![CVEs](assets/iscy-cves.png)

## Risks

![Risks](assets/iscy-risks.png)

## Evidence

![Evidence](assets/iscy-evidence.png)

## Evidence Quality

![Evidence Quality](assets/iscy-evidence-quality.png)

## Nachweis-Integritaet und Storage

Die Ansicht buendelt lokale und S3-kompatible Evidence-Integritaet,
Storage-/Restore-Pruefungen, Worker-/Disposition-Signale, Runtime-Status,
Upload-/Verify-Zustand und tenantgebundene Object-Storage-Metadaten ohne
Secretwerte oder vollstaendige Object Keys. Der vorhandene Demo-Screenshot
enthaelt ausschliesslich sichere Testmetadaten; Live-Credentials und private
Endpoints werden nicht fuer Screenshot-Artefakte verwendet.

![Nachweis-Integritaet und Storage](assets/iscy-evidence-integrity-storage.png)

## Roadmap

![Roadmap](assets/iscy-roadmap.png)

## Reports

![Reports](assets/iscy-reports.png)

## Regulatory Review-Pakete

![Regulatory Review-Pakete](assets/iscy-regulatory-review-packs.png)

## NIS2 Review-Paket Vorschau

![NIS2 Review-Paket Vorschau](assets/iscy-regulatory-review-pack-nis2.png)

## DORA Review-Paket Vorschau

![DORA Review-Paket Vorschau](assets/iscy-regulatory-review-pack-dora.png)

## DSGVO Review-Paket Vorschau

![DSGVO Review-Paket Vorschau](assets/iscy-regulatory-review-pack-dsgvo.png)

## Assets

![Assets](assets/iscy-assets.png)

## Supplier Review

![Supplier Review](assets/iscy-supplier-review.png)

## Supplier/Product Security

![Supplier/Product Security](assets/iscy-supplier-product-security.png)

## Imports

![Imports](assets/iscy-imports.png)

## Processes

![Processes](assets/iscy-processes.png)

## Product Security

![Product Security](assets/iscy-product-security.png)

## Product Security Evidence Packages

![Product Security Evidence Packages](assets/iscy-product-security-evidence-packages.png)

## AI Governance

![AI Governance](assets/iscy-ai-governance.png)

## Status Operations

![Status Operations](assets/iscy-status-operations.png)

## Users

![Users](assets/iscy-users.png)
