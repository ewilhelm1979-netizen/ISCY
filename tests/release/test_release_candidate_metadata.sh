#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

source_manifest='release/release-manifest.json'
source_snapshot='release/published/V23.7.29.json'
source_db_admin='rust/iscy-backend/src/db_admin.rs'
source_notes='docs/RELEASE_NOTES_DRAFT.md'
guard='./scripts/check_release_candidate_metadata.sh'
tmp_dir="$(mktemp -d)"
cleanup() {
    rm -rf "$tmp_dir"
}
trap cleanup EXIT

run_guard() {
    local manifest="$1"
    local snapshot="${2:-$source_snapshot}"
    local db_admin="${3:-$source_db_admin}"
    local notes="${4:-$source_notes}"

    ISCY_RELEASE_MANIFEST_PATH="$manifest" \
    ISCY_PUBLISHED_SNAPSHOT_PATH="$snapshot" \
    ISCY_DB_ADMIN_PATH="$db_admin" \
    ISCY_RELEASE_NOTES_PATH="$notes" \
    ISCY_SKIP_RELEASE_REGRESSION_TESTS=true \
        "$guard"
}

expect_rejected() {
    local label="$1"
    local manifest="$2"
    local snapshot="$3"
    local db_admin="$4"
    local notes="$5"
    local expected_category="$6"
    local output

    if output="$(run_guard "$manifest" "$snapshot" "$db_admin" "$notes" 2>&1)"; then
        printf 'RELEASE_METADATA_TEST_ERROR[%s]: Ungueltige Metadaten wurden akzeptiert.\n' "$label" >&2
        exit 1
    fi
    [[ "$output" == *"RC_METADATA_ERROR[$expected_category]"* ]] || {
        printf 'RELEASE_METADATA_TEST_ERROR[%s]: Unerwartete Fehlerklasse.\n' "$label" >&2
        exit 1
    }
}

mutate_manifest() {
    local label="$1"
    local filter="$2"
    local candidate="$tmp_dir/$label-manifest.json"
    jq "$filter" "$source_manifest" >"$candidate"
    printf '%s\n' "$candidate"
}

mutate_snapshot() {
    local label="$1"
    local filter="$2"
    local candidate="$tmp_dir/$label-snapshot.json"
    jq "$filter" "$source_snapshot" >"$candidate"
    printf '%s\n' "$candidate"
}

run_guard "$source_manifest" >/dev/null

candidate="$(mutate_manifest wrong_development_version '.proposed_version = "V23.7.31"')"
expect_rejected wrong_development_version "$candidate" "$source_snapshot" "$source_db_admin" "$source_notes" manifest

candidate="$(mutate_manifest development_stable_claim '
    .test_suite_summary.status = "validated_by_release_candidate_check_and_ci"
    | .release_artifact.reproducibility_status = "verified_two_build_sha256"
    | .release_artifact.binary_sha256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
')"
expect_rejected development_stable_claim "$candidate" "$source_snapshot" "$source_db_admin" "$source_notes" manifest

candidate="$(mutate_manifest migration_count_low '.migration_count = 38')"
expect_rejected migration_count_low "$candidate" "$source_snapshot" "$source_db_admin" "$source_notes" migration_count

candidate="$(mutate_manifest migration_count_high '.migration_count = 40')"
expect_rejected migration_count_high "$candidate" "$source_snapshot" "$source_db_admin" "$source_notes" migration_count

gap_db_admin="$tmp_dir/gap-db-admin.rs"
sed '/version: "0020_/d' "$source_db_admin" >"$gap_db_admin"
gap_manifest="$(mutate_manifest migration_gap '.migration_count = 38')"
expect_rejected migration_gap "$gap_manifest" "$source_snapshot" "$gap_db_admin" "$source_notes" migration_sequence

duplicate_db_admin="$tmp_dir/duplicate-db-admin.rs"
sed 's/version: "0020_/version: "0019_/' "$source_db_admin" >"$duplicate_db_admin"
expect_rejected migration_duplicate "$source_manifest" "$source_snapshot" "$duplicate_db_admin" "$source_notes" migration_duplicate

expect_rejected missing_snapshot "$source_manifest" "$tmp_dir/missing-snapshot.json" "$source_db_admin" "$source_notes" published_snapshot

snapshot="$(mutate_snapshot wrong_release_id '.release_id = 1')"
expect_rejected wrong_release_id "$source_manifest" "$snapshot" "$source_db_admin" "$source_notes" published_snapshot

snapshot="$(mutate_snapshot wrong_target_commit '.target_commit = "ffffffffffffffffffffffffffffffffffffffff"')"
expect_rejected wrong_target_commit "$source_manifest" "$snapshot" "$source_db_admin" "$source_notes" published_snapshot

snapshot="$(mutate_snapshot wrong_asset_count '.assets = .assets[0:5] | .asset_count = 5')"
expect_rejected wrong_asset_count "$source_manifest" "$snapshot" "$source_db_admin" "$source_notes" published_snapshot

snapshot="$(mutate_snapshot duplicate_asset_name '.assets[1].name = .assets[0].name')"
expect_rejected duplicate_asset_name "$source_manifest" "$snapshot" "$source_db_admin" "$source_notes" published_snapshot

snapshot="$(mutate_snapshot truncated_digest '.assets[0].sha256 = "2f4d649c"')"
expect_rejected truncated_digest "$source_manifest" "$snapshot" "$source_db_admin" "$source_notes" published_snapshot

candidate_manifest="$(mutate_manifest prepared_mode '
    .release_status = "prepared_not_published"
    | .test_suite_summary.status = "validated_by_release_candidate_check_and_ci"
    | .release_artifact.reproducibility_status = "required_two_build_sha256"
')"
candidate_notes="$tmp_dir/candidate-notes.md"
cat >"$candidate_notes" <<'EOF'
# ISCY V23.7.30 - Release Notes
Status: Stabiler Release vorbereitet; Tag und GitHub Release noch nicht erstellt.
Vorgänger: `V23.7.29`.
nginx:1.31-alpine, Rust `1.97.0`, MSRV bleibt Rust `1.88.0`, nixos-26.05.
PostgreSQL 16 bleibt der Standard; PostgreSQL 18.4 ist zusaetzlich geprueft.
Der NIS2-Relevanz-Wizard erzeugt eine Applicability-Begruendung im NIS2- und
KRITIS-Kontext, aber keine rechtsverbindliche Einstufung. Eine
DORA-Konformitaetsbewertung erfolgt nicht. Der Cyber Resilience Act (CRA)
erhaelt keine automatische Konformitaetsbewertung oder CE-Freigabe. ISCY
liefert keine automatische Zertifizierung und keine Rechtsberatung.
EOF
run_guard "$candidate_manifest" "$source_snapshot" "$source_db_admin" "$candidate_notes" >/dev/null

echo 'Release-Metadaten-Modus-, Migrations- und Snapshot-Tests OK'
