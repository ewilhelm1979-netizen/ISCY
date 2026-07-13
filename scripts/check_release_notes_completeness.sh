#!/usr/bin/env bash
set -euo pipefail

notes_path="${1:-}"
fail() {
    printf 'RC_NOTES_ERROR[%s]: %s\n' "$1" "$2" >&2
    exit 1
}
require_phrase() {
    local category="$1"
    local phrase="$2"
    local message="$3"
    [[ "$notes_text" == *"$phrase"* ]] || fail "$category" "$message"
}
reject_phrase() {
    local category="$1"
    local phrase="$2"
    local message="$3"
    [[ "$notes_text" != *"$phrase"* ]] || fail "$category" "$message"
}

[[ -n "$notes_path" && -f "$notes_path" ]] \
    || fail file 'Das Release-Notes-Asset fehlt.'
notes_text="$(tr '\n\r\t' '   ' <"$notes_path" | tr -s ' ')"

require_phrase target_version 'ISCY V23.7.29' \
    'Die Zielversion V23.7.29 fehlt.'
require_phrase release_status 'Stabiler Release vorbereitet' \
    'Der stabile, noch nicht veroeffentlichte Vorbereitungsstatus fehlt.'
require_phrase unpublished 'Tag und GitHub Release noch nicht erstellt' \
    'Die Abgrenzung zu Tag und Veroeffentlichung fehlt.'
require_phrase predecessor "Vorgänger: \`V23.7.28-rc.1\`" \
    'Der veroeffentlichte Vorgaenger V23.7.28-rc.1 fehlt.'
require_phrase nginx 'nginx:1.31-alpine' \
    'Die nginx-1.31-Maintenance fehlt.'
require_phrase rust_toolchain "Rust \`1.97.0\`" \
    'Die Rust-1.97-Produkttoolchain fehlt.'
require_phrase msrv "MSRV bleibt Rust \`1.88.0\`" \
    'Die unveraenderte MSRV 1.88 fehlt.'
require_phrase nixpkgs 'nixos-26.05' \
    'Der nixpkgs-26.05-Stand fehlt.'
require_phrase postgresql_18 'PostgreSQL 18.4' \
    'Der PostgreSQL-18.4-Kompatibilitaetsnachweis fehlt.'
require_phrase postgresql_standard 'PostgreSQL 16 bleibt der Standard' \
    'PostgreSQL 16 ist nicht eindeutig als Standard dokumentiert.'
require_phrase nis2_wizard 'NIS2-Relevanz-Wizard' \
    'Der dokumentierte NIS2-Relevanz-Wizard fehlt.'
require_phrase applicability 'Applicability-Begruendung' \
    'Die nachvollziehbare Applicability-Begruendung fehlt.'
require_phrase nis2_kritis 'NIS2- und KRITIS-Kontext' \
    'Die gemeinsame NIS2-/KRITIS-Einordnung fehlt.'
require_phrase legal_boundary 'keine rechtsverbindliche Einstufung' \
    'Die rechtliche Abgrenzung der Relevanzbewertung fehlt.'
require_phrase dora_boundary 'DORA-Konformitaetsbewertung erfolgt nicht' \
    'Die DORA-Unterstuetzung oder ihre fachliche Abgrenzung fehlt.'
require_phrase cra_name 'Cyber Resilience Act (CRA)' \
    'Die ausgeschriebene CRA-Bezeichnung fehlt.'
require_phrase cra_boundary 'keine automatische Konformitaetsbewertung oder CE-Freigabe' \
    'Die CRA-Unterstuetzung oder ihre Konformitaetsabgrenzung fehlt.'
require_phrase certification_boundary 'keine automatische Zertifizierung' \
    'Die Zertifizierungsabgrenzung fehlt.'
require_phrase legal_advice_boundary 'Rechtsberatung' \
    'Die Rechtsberatungsabgrenzung fehlt.'

reject_phrase prerelease 'Prerelease' \
    'V23.7.29 darf nicht als GitHub-Prerelease beschrieben werden.'
reject_phrase latest 'nicht als Latest Release vorgesehen' \
    'V23.7.29 ist nach Veroeffentlichung als Stable/Latest vorgesehen.'
reject_phrase obsolete_latest "Letzte veröffentlichte Plattformversion: \`V23.7.27\`" \
    'V23.7.27 darf nicht mehr als letzter veroeffentlichter Stand erscheinen.'
reject_phrase obsolete_target "Release Candidate: \`V23.7.28-rc.1\`" \
    'Der Vorgaenger darf nicht als aktives Releaseziel erscheinen.'

echo 'RC_NOTES_OK: V23.7.29, Platform-Maintenance, PostgreSQL, Governance und rechtliche Grenzen sind konsistent.'
