#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

source_manifest='release/release-manifest.json'
published_snapshot='release/published/V23.7.31.json'
published_snapshot_sha256='f480b2d3a19e687e0c1ae6831a9c7f44531f879e07fa2b524d5b0e40423743af'
published_version='V23.7.31'
published_commit='c595795296633ce4152aa0e817b063ee88c7028a'
candidate_version='V23.7.32'
artifact_guard='./scripts/prepare_release_candidate_artifacts.sh'
tmp_dir="$(mktemp -d)"
output_dir="artifacts/release-lifecycle-test-$$"
cleanup() {
    rm -rf "$tmp_dir" "$output_dir"
}
trap cleanup EXIT

source_status="$(jq -r '.release_status' "$source_manifest")"
source_version="$(jq -r '.proposed_version' "$source_manifest")"
source_base_commit="$(jq -r '.source_base_commit' "$source_manifest")"
source_test_status="$(jq -r '.test_suite_summary.status' "$source_manifest")"
source_artifact_status="$(jq -r '.release_artifact.reproducibility_status' "$source_manifest")"
source_binary_sha="$(jq -r '.release_artifact.binary_sha256' "$source_manifest")"
source_commit_marker="$(jq -r '.source_commit' "$source_manifest")"
source_date_epoch="$(jq -r '.source_date_epoch' "$source_manifest")"
[[ "$source_status" == 'prepared_not_published' \
    && "$source_version" == "$candidate_version" \
    && "$source_base_commit" == "$published_commit" \
    && "$source_commit_marker" == 'git:HEAD' \
    && "$source_date_epoch" == 'null' \
    && "$source_test_status" == 'validated_by_release_candidate_check_and_ci' \
    && "$source_artifact_status" == 'required_two_build_sha256' \
    && "$source_binary_sha" == 'null' ]] || {
    echo 'RELEASE_LIFECYCLE_TEST_ERROR[root_status]: Root-Manifest bereitet V23.7.32 nicht repositorykonform und publikationsneutral vor.' >&2
    exit 1
}
if git show-ref --verify --quiet "refs/tags/$candidate_version"; then
    echo 'RELEASE_LIFECYCLE_TEST_ERROR[candidate_tag]: V23.7.32 ist im vorbereiteten Zustand bereits getaggt.' >&2
    exit 1
fi
[[ "$(sha256sum "$published_snapshot" | cut -d ' ' -f 1)" == "$published_snapshot_sha256" ]] || {
    echo 'RELEASE_LIFECYCLE_TEST_ERROR[published_snapshot]: V23.7.31-Snapshot wurde veraendert.' >&2
    exit 1
}
[[ "$(jq -r '.target_commit' "$published_snapshot")" == "$published_commit" ]] || {
    echo 'RELEASE_LIFECYCLE_TEST_ERROR[published_tag]: V23.7.31-Tagziel wurde im Snapshot verschoben.' >&2
    exit 1
}
if git show-ref --verify --quiet "refs/tags/$published_version"; then
    [[ "$(git rev-list -n 1 "refs/tags/$published_version")" == "$published_commit" ]] || {
        echo 'RELEASE_LIFECYCLE_TEST_ERROR[published_tag]: Lokaler V23.7.31-Tag wurde verschoben.' >&2
        exit 1
    }
fi
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

published_candidate_manifest="$tmp_dir/published-candidate-manifest.json"
jq --arg version "$published_version" '
    .proposed_version = $version
    | .release_status = "prepared_not_published"
    | .test_suite_summary.status = "validated_by_release_candidate_check_and_ci"
    | .release_artifact.reproducibility_status = "required_two_build_sha256"
' "$source_manifest" >"$published_candidate_manifest"
set +e
published_candidate_output="$(
    ISCY_RELEASE_MANIFEST_PATH="$published_candidate_manifest" \
        "$artifact_guard" --check-status 2>&1
)"
published_candidate_status=$?
set -e
[[ "$published_candidate_status" -ne 0 ]] || {
    echo 'RELEASE_LIFECYCLE_TEST_ERROR[published_version]: V23.7.31 konnte erneut vorbereitet werden.' >&2
    exit 1
}
[[ "$published_candidate_output" == *'RC_ARTIFACT_ERROR[published_version]'* ]] || {
    echo 'RELEASE_LIFECYCLE_TEST_ERROR[published_version]: Erwartete Fehlerklasse fehlt.' >&2
    exit 1
}
[[ ! -e "$output_dir" ]] || {
    echo 'RELEASE_LIFECYCLE_TEST_ERROR[published_version]: Published-Version hat ein Bundle angelegt.' >&2
    exit 1
}

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
