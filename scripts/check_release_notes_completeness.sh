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

[[ -n "$notes_path" && -f "$notes_path" ]] \
    || fail file 'Das Release-Notes-Asset fehlt.'
notes_text="$(tr '\n\r\t' '   ' <"$notes_path" | tr -s ' ')"

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

echo 'RC_NOTES_OK: NIS2, KRITIS, DORA, CRA, Wizard und rechtliche Abgrenzungen sind enthalten.'
