#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

source_notes='docs/RELEASE_NOTES_DRAFT.md'
guard='./scripts/check_release_notes_completeness.sh'
tmp_dir="$(mktemp -d)"
cleanup() {
    rm -rf "$tmp_dir"
}
trap cleanup EXIT

expect_rejected() {
    local label="$1"
    local needle="$2"
    local replacement="$3"
    local expected_category="$4"
    local candidate="$tmp_dir/$label.md"
    local output

    sed "s|$needle|$replacement|g" "$source_notes" >"$candidate"
    if output="$($guard "$candidate" 2>&1)"; then
        printf 'RELEASE_NOTES_TEST_ERROR[%s]: Unvollstaendige Notes wurden akzeptiert.\n' "$label" >&2
        exit 1
    fi
    [[ "$output" == *"RC_NOTES_ERROR[$expected_category]"* ]] || {
        printf 'RELEASE_NOTES_TEST_ERROR[%s]: Unerwartete Fehlerklasse.\n' "$label" >&2
        exit 1
    }
}

$guard "$source_notes" >/dev/null
expect_rejected nis2 'NIS2' 'Regelwerk-Zwei' nis2_wizard
expect_rejected kritis 'KRITIS' 'Kritische-Infrastruktur' nis2_kritis
expect_rejected dora 'DORA' 'Finanzaufsicht' dora_boundary
expect_rejected cra_name 'Cyber Resilience Act' 'Produktregulierung' cra_name
expect_rejected cra_acronym 'CRA' 'Produktregelwerk' cra_name
expect_rejected wizard 'Relevanz-Wizard' 'Bewertungsweg' nis2_wizard

echo 'Release-Notes-Completeness Positiv- und Negativtests OK'
