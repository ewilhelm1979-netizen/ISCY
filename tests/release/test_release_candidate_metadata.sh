#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

source_manifest='release/release-manifest.json'
guard='./scripts/check_release_candidate_metadata.sh'
tmp_dir="$(mktemp -d)"
cleanup() {
    rm -rf "$tmp_dir"
}
trap cleanup EXIT

expect_manifest_rejected() {
    local label="$1"
    local filter="$2"
    local expected_category="$3"
    local candidate="$tmp_dir/$label.json"
    local output

    jq "$filter" "$source_manifest" >"$candidate"
    if output="$(
        ISCY_RELEASE_MANIFEST_PATH="$candidate" \
        ISCY_SKIP_RELEASE_REGRESSION_TESTS=true \
        "$guard" 2>&1
    )"; then
        printf 'RELEASE_METADATA_TEST_ERROR[%s]: Ungueltiges Manifest wurde akzeptiert.\n' "$label" >&2
        exit 1
    fi
    [[ "$output" == *"RC_METADATA_ERROR[$expected_category]"* ]] || {
        printf 'RELEASE_METADATA_TEST_ERROR[%s]: Unerwartete Fehlerklasse.\n' "$label" >&2
        exit 1
    }
}

expect_manifest_rejected \
    obsolete_version \
    '.proposed_version = "V23.7.28-rc.1"' \
    manifest
expect_manifest_rejected \
    prerelease_status \
    '.release_status = "release_candidate_prerelease"' \
    manifest
expect_manifest_rejected \
    flake_lock_hash \
    '.flake_lock_sha256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' \
    manifest_hash
expect_manifest_rejected \
    product_toolchain \
    '.rust_version.ci_product_builder = "1.96.0"' \
    manifest
expect_manifest_rejected \
    postgresql_standard \
    '.database_support.standard = "postgresql_18"' \
    manifest

echo 'Release-Metadaten-Negativtests OK'
