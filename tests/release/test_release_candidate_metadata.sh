#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

source_manifest='release/release-manifest.json'
source_snapshot='release/published/V23.7.33.json'
source_db_admin='rust/iscy-backend/src/db_admin.rs'
source_notes='docs/RELEASE_NOTES_DRAFT.md'
guard='./scripts/check_release_candidate_metadata.sh'
published_version='V23.7.33'
published_commit='2820f19f5fa33069db81e05c10949f2558948d04'
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

run_tag_fixture_guard() {
    (
        cd "$tag_fixture"
        ISCY_SKIP_RELEASE_REGRESSION_TESTS=true \
            ./scripts/check_release_candidate_metadata.sh
    )
}

expect_tag_fixture_category() {
    local label="$1"
    local category="$2"
    local output

    if output="$(run_tag_fixture_guard 2>&1)"; then
        printf 'RELEASE_METADATA_TEST_ERROR[%s]: Ungueltiger Tagkontext wurde akzeptiert.\n' "$label" >&2
        exit 1
    fi
    [[ "$output" == *"RC_METADATA_ERROR[$category]"* ]] || {
        printf 'RELEASE_METADATA_TEST_ERROR[%s]: Unerwartete Fehlerklasse.\n' "$label" >&2
        exit 1
    }
}

expect_tag_fixture_rejected() {
    local label="$1"
    local output

    if output="$(run_tag_fixture_guard 2>&1)"; then
        printf 'RELEASE_METADATA_TEST_ERROR[%s]: Ungueltiger Tagkontext wurde akzeptiert.\n' "$label" >&2
        exit 1
    fi
    [[ "$output" == *'RC_METADATA_ERROR[published_tag]'* ]] || {
        printf 'RELEASE_METADATA_TEST_ERROR[%s]: Unerwartete Fehlerklasse.\n' "$label" >&2
        exit 1
    }
}

run_guard "$source_manifest" >/dev/null

tag_fixture="$tmp_dir/tag-fixture"
git init --quiet --initial-branch=fixture "$tag_fixture"
git -C "$tag_fixture" fetch --quiet --no-tags "$repo_root" HEAD
git -C "$tag_fixture" checkout --quiet --detach FETCH_HEAD
git -C "$tag_fixture" tag "$published_version" "$published_commit"
cp -- "$guard" "$tag_fixture/scripts/check_release_candidate_metadata.sh"
cp -- scripts/check_release_notes_completeness.sh "$tag_fixture/scripts/check_release_notes_completeness.sh"
cp -- "$source_manifest" "$tag_fixture/$source_manifest"
cp -- "$source_snapshot" "$tag_fixture/$source_snapshot"
cp -- "$source_notes" "$tag_fixture/$source_notes"
cp -- docs/RELEASE_CANDIDATE_CHECKLIST.md "$tag_fixture/docs/RELEASE_CANDIDATE_CHECKLIST.md"
cp -- release/SHA256SUMS "$tag_fixture/release/SHA256SUMS"
run_tag_fixture_guard >/dev/null

git -C "$tag_fixture" tag --delete "$published_version" >/dev/null
expect_tag_fixture_rejected missing_published_tag

wrong_tag_commit="$(git -C "$tag_fixture" rev-parse "${published_commit}^1")"
[[ "$wrong_tag_commit" != "$published_commit" ]] || {
    echo 'RELEASE_METADATA_TEST_ERROR[tag_fixture]: Falscher Tag-Commit ist nicht vom Published-Commit getrennt.' >&2
    exit 1
}
git -C "$tag_fixture" tag "$published_version" "$wrong_tag_commit"
expect_tag_fixture_rejected wrong_published_tag_target

git -C "$tag_fixture" tag --delete "$published_version" >/dev/null
git -C "$tag_fixture" tag "$published_version" "$published_commit"
git -C "$tag_fixture" tag 'V23.7.34' "$wrong_tag_commit"
expect_tag_fixture_category existing_candidate_tag candidate_tag

candidate="$(mutate_manifest wrong_candidate_version '.proposed_version = "V23.7.35"')"
expect_rejected wrong_candidate_version "$candidate" "$source_snapshot" "$source_db_admin" "$source_notes" manifest

candidate="$(mutate_manifest root_binary_claim '
    .release_artifact.reproducibility_status = "verified_two_build_sha256"
    | .release_artifact.binary_sha256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
')"
expect_rejected root_binary_claim "$candidate" "$source_snapshot" "$source_db_admin" "$source_notes" manifest

candidate="$(mutate_manifest migration_count_low '.migration_count = 44')"
expect_rejected migration_count_low "$candidate" "$source_snapshot" "$source_db_admin" "$source_notes" migration_count

candidate="$(mutate_manifest migration_count_high '.migration_count = 46')"
expect_rejected migration_count_high "$candidate" "$source_snapshot" "$source_db_admin" "$source_notes" migration_count

gap_db_admin="$tmp_dir/gap-db-admin.rs"
sed '/version: "0020_/d' "$source_db_admin" >"$gap_db_admin"
gap_manifest="$(mutate_manifest migration_gap '.migration_count = 44')"
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

snapshot="$(mutate_snapshot changed_valid_digest '.assets[0].sha256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"')"
expect_rejected changed_valid_digest "$source_manifest" "$snapshot" "$source_db_admin" "$source_notes" published_snapshot

snapshot="$(mutate_snapshot changed_asset_size '.assets[0].size_bytes += 1')"
expect_rejected changed_asset_size "$source_manifest" "$snapshot" "$source_db_admin" "$source_notes" published_snapshot

snapshot="$(mutate_snapshot changed_content_type '.assets[0].content_type = "application/x-elf"')"
expect_rejected changed_content_type "$source_manifest" "$snapshot" "$source_db_admin" "$source_notes" published_snapshot

snapshot="$(mutate_snapshot changed_download_url '.assets[0].download_url = "https://github.com/ewilhelm1979-netizen/ISCY/releases/download/V23.7.33/replacement"')"
expect_rejected changed_download_url "$source_manifest" "$snapshot" "$source_db_admin" "$source_notes" published_snapshot

snapshot="$(mutate_snapshot removed_evidence_notice 'del(.evidence_notice)')"
expect_rejected removed_evidence_notice "$source_manifest" "$snapshot" "$source_db_admin" "$source_notes" published_snapshot

candidate_manifest="$(mutate_manifest prepared_mode '
    .release_status = "prepared_not_published"
    | .test_suite_summary.status = "validated_by_release_candidate_check_and_ci"
    | .release_artifact.reproducibility_status = "required_two_build_sha256"
')"
candidate_notes="$tmp_dir/candidate-notes.md"
cat >"$candidate_notes" <<'EOF'
# ISCY V23.7.34 - Release Notes
Status: Stabiler Release.
Vorgänger: `V23.7.33`.
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
