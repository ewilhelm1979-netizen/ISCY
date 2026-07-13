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

expect_missing_rejected() {
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

expect_forbidden_rejected() {
    local label="$1"
    local phrase="$2"
    local expected_category="$3"
    local candidate="$tmp_dir/$label.md"
    local output

    cp "$source_notes" "$candidate"
    printf '\n%s\n' "$phrase" >>"$candidate"
    if output="$($guard "$candidate" 2>&1)"; then
        printf 'RELEASE_NOTES_TEST_ERROR[%s]: Widerspruechliche Notes wurden akzeptiert.\n' "$label" >&2
        exit 1
    fi
    [[ "$output" == *"RC_NOTES_ERROR[$expected_category]"* ]] || {
        printf 'RELEASE_NOTES_TEST_ERROR[%s]: Unerwartete Fehlerklasse.\n' "$label" >&2
        exit 1
    }
}

$guard "$source_notes" >/dev/null
expect_missing_rejected target_version 'ISCY V23.7.29' 'ISCY Zielversion' target_version
expect_missing_rejected predecessor "Vorgänger: \`V23.7.28-rc.1\`" 'Vorgänger fehlt' predecessor
expect_missing_rejected nginx 'nginx:1.31-alpine' 'nginx:1.31' nginx
expect_missing_rejected rust_toolchain "Rust \`1.97.0\`" "Rust \`1.96.0\`" rust_toolchain
expect_missing_rejected msrv "MSRV bleibt Rust \`1.88.0\`" "MSRV bleibt Rust \`1.89.0\`" msrv
expect_missing_rejected nixpkgs 'nixos-26.05' 'nixos-25.11' nixpkgs
expect_missing_rejected postgresql_18 'PostgreSQL 18.4' 'PostgreSQL Zielversion' postgresql_18
expect_missing_rejected postgresql_standard 'PostgreSQL 16 bleibt der Standard' 'Datenbankstandard fehlt' postgresql_standard
expect_missing_rejected nis2 'NIS2-Relevanz-Wizard' 'Regelwerk-Zwei-Wizard' nis2_wizard
expect_missing_rejected kritis 'NIS2- und KRITIS-Kontext' 'NIS2-Kontext' nis2_kritis
expect_missing_rejected dora 'DORA-Konformitaetsbewertung' 'DORA-Pruefung' dora_boundary
expect_missing_rejected cra_name 'Cyber Resilience Act (CRA)' 'Produktregulierung' cra_name
expect_missing_rejected cra_boundary 'CE-Freigabe' 'Produktfreigabe' cra_boundary
expect_missing_rejected legal_boundary 'keine automatische Zertifizierung' 'keine automatische Freigabe' certification_boundary
expect_forbidden_rejected prerelease 'GitHub-Release-Typ: Prerelease' prerelease
expect_forbidden_rejected latest 'V23.7.29 ist nicht als Latest Release vorgesehen' latest
expect_forbidden_rejected obsolete_latest "Letzte veröffentlichte Plattformversion: \`V23.7.27\`" obsolete_latest
expect_forbidden_rejected obsolete_target "Release Candidate: \`V23.7.28-rc.1\`" obsolete_target

echo 'Release-Notes-Completeness Positiv- und Negativtests OK'
