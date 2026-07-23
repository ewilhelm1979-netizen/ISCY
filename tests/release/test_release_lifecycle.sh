#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

source_manifest='release/release-manifest.json'
published_snapshot='release/published/V23.7.30.json'
published_snapshot_sha256='eec9e24ecdd6ea9cae4c0095a1ed367fa8d83de5b49e1f0f263338071033a517'
artifact_guard='./scripts/prepare_release_candidate_artifacts.sh'
tmp_dir="$(mktemp -d)"
output_dir="artifacts/release-lifecycle-test-$$"
cleanup() {
    rm -rf "$tmp_dir" "$output_dir"
}
trap cleanup EXIT

[[ "$(jq -r '.release_status' "$source_manifest")" == 'prepared_not_published' ]] || {
    echo 'RELEASE_LIFECYCLE_TEST_ERROR[root_status]: Root-Manifest ist nicht prepared_not_published.' >&2
    exit 1
}
[[ "$(sha256sum "$published_snapshot" | cut -d ' ' -f 1)" == "$published_snapshot_sha256" ]] || {
    echo 'RELEASE_LIFECYCLE_TEST_ERROR[published_snapshot]: V23.7.30-Snapshot wurde veraendert.' >&2
    exit 1
}
grep -Fq '.release_status = "stable_release_prepared"' "$artifact_guard" || {
    echo 'RELEASE_LIFECYCLE_TEST_ERROR[bundle_status]: Bundle-Manifest-Status ist nicht stabil abgesichert.' >&2
    exit 1
}
grep -Fq "cp docs/RELEASE_NOTES_DRAFT.md \"\$output_dir/RELEASE_NOTES.md\"" "$artifact_guard" || {
    echo 'RELEASE_LIFECYCLE_TEST_ERROR[notes_asset]: Publiziertes Notes-Asset ist nicht RELEASE_NOTES.md.' >&2
    exit 1
}

development_manifest="$tmp_dir/development-manifest.json"
jq '
    .release_status = "development_unreleased"
    | .test_suite_summary.status = "development_validation_required"
    | .release_artifact.reproducibility_status = "not_prepared"
    | .release_artifact.binary_sha256 = null
' "$source_manifest" >"$development_manifest"

set +e
development_output="$(
    ISCY_RELEASE_MANIFEST_PATH="$development_manifest" \
        ISCY_RC_ARTIFACT_DIR="$output_dir" \
        make release-candidate-artifacts 2>&1
)"
development_status=$?
set -e
[[ "$development_status" -ne 0 ]] || {
    echo 'RELEASE_LIFECYCLE_TEST_ERROR[development_artifacts]: Development-Bundle wurde akzeptiert.' >&2
    exit 1
}
[[ "$development_output" == *'RC_ARTIFACT_ERROR[release_status]'* ]] || {
    echo 'RELEASE_LIFECYCLE_TEST_ERROR[development_artifacts]: Erwartete Fehlerklasse fehlt.' >&2
    exit 1
}
[[ ! -e "$output_dir" ]] || {
    echo 'RELEASE_LIFECYCLE_TEST_ERROR[development_artifacts]: Development-Bundle wurde angelegt.' >&2
    exit 1
}

candidate_manifest="$tmp_dir/candidate-manifest.json"
jq '
    .release_status = "prepared_not_published"
    | .test_suite_summary.status = "validated_by_release_candidate_check_and_ci"
    | .release_artifact.reproducibility_status = "required_two_build_sha256"
' "$source_manifest" >"$candidate_manifest"
ISCY_RELEASE_MANIFEST_PATH="$candidate_manifest" \
    "$artifact_guard" --check-status

unsupported_manifest="$tmp_dir/unsupported-manifest.json"
jq '.release_status = "stable_release_prepared"' "$source_manifest" >"$unsupported_manifest"
set +e
unsupported_output="$(
    ISCY_RELEASE_MANIFEST_PATH="$unsupported_manifest" \
        "$artifact_guard" --check-status 2>&1
)"
unsupported_status=$?
set -e
[[ "$unsupported_status" -ne 0 ]] || {
    echo 'RELEASE_LIFECYCLE_TEST_ERROR[unsupported_status]: Unzulaessiger Root-Status wurde akzeptiert.' >&2
    exit 1
}
[[ "$unsupported_output" == *'RC_ARTIFACT_ERROR[release_status]'* ]] || {
    echo 'RELEASE_LIFECYCLE_TEST_ERROR[unsupported_status]: Erwartete Fehlerklasse fehlt.' >&2
    exit 1
}

echo 'Release-Lifecycle- und Artefaktblockade-Tests OK'
