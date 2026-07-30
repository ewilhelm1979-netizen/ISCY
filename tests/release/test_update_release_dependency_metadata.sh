#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

generator="$repo_root/scripts/update_release_dependency_metadata.sh"
test_root="$(mktemp -d "$repo_root/release/.dependency-metadata-test.XXXXXX")"

fail() {
    printf 'RELEASE_DEPENDENCY_METADATA_TEST_ERROR[%s]: %s\n' "$1" "$2" >&2
    exit 1
}

cleanup() {
    case "${test_root:-}" in
        "$repo_root"/release/.dependency-metadata-test.*)
            if [[ -d "$test_root" && ! -L "$test_root" ]]; then
                rm -rf -- "$test_root"
            fi
            ;;
    esac
}
trap cleanup EXIT

create_fixture() {
    local fixture="$1"
    local path
    local checksum_paths=(
        'rust/iscy-backend/Cargo.lock'
        'flake.lock'
        'docs/ISCY_Handbuch.pdf'
        'docs/RELEASE_NOTES_DRAFT.md'
        'release/iscy-backend.cdx.json'
        'release/release-manifest.json'
    )

    mkdir -p \
        "$fixture/scripts" \
        "$fixture/rust/iscy-backend" \
        "$fixture/docs" \
        "$fixture/release"
    for path in "${checksum_paths[@]}"; do
        cp --parents -- "$path" "$fixture"
    done
    cp -- "$generator" "$fixture/scripts/update_release_dependency_metadata.sh"
    chmod +x "$fixture/scripts/update_release_dependency_metadata.sh"

    jq '
        .cargo_lock_sha256 = "test-fixture-cargo-lock"
        | .flake_lock_sha256 = "test-fixture-flake-lock"
        | .sbom_sha256 = "test-fixture-sbom"
    ' "$fixture/release/release-manifest.json" \
        >"$fixture/release/release-manifest.initial"
    mv -fT \
        "$fixture/release/release-manifest.initial" \
        "$fixture/release/release-manifest.json"

    (
        cd "$fixture"
        sha256sum "${checksum_paths[@]}" >release/SHA256SUMS
        git init -q
    )
}

assert_no_generator_temporary_files() {
    local fixture="$1"
    local leftover

    leftover="$(
        find "$fixture/release" \
            -mindepth 1 \
            -maxdepth 1 \
            -name '.dependency-metadata.*' \
            -print -quit
    )"
    [[ -z "$leftover" ]] \
        || fail temporary_files 'Generator hat temporaere Dateien hinterlassen.'
}

assert_pair_unchanged() {
    local fixture="$1"
    local baseline="$2"
    local label="$3"

    cmp -s \
        "$baseline/release-manifest.json" \
        "$fixture/release/release-manifest.json" \
        || fail "$label" 'Release-Manifest wurde trotz Fehler veraendert.'
    cmp -s \
        "$baseline/SHA256SUMS" \
        "$fixture/release/SHA256SUMS" \
        || fail "$label" 'SHA256SUMS wurde trotz Fehler veraendert.'
    assert_no_generator_temporary_files "$fixture"
}

run_failure_case() {
    local label="$1"
    local failure_point="$2"
    local fixture="$test_root/$label"
    local baseline="$test_root/$label-baseline"

    create_fixture "$fixture"
    mkdir -p "$baseline"
    cp -- "$fixture/release/release-manifest.json" "$baseline/release-manifest.json"
    cp -- "$fixture/release/SHA256SUMS" "$baseline/SHA256SUMS"

    if (
        cd "$fixture"
        ISCY_TEST_RELEASE_METADATA_FAIL_AT="$failure_point" \
            ./scripts/update_release_dependency_metadata.sh
    ) >/dev/null 2>&1; then
        fail "$label" 'Erzwungener Fehler wurde nicht ausgeloest.'
    fi
    assert_pair_unchanged "$fixture" "$baseline" "$label"
}

normal_fixture="$test_root/normal"
create_fixture "$normal_fixture"
(
    cd "$normal_fixture"
    ./scripts/update_release_dependency_metadata.sh >/dev/null
)
cp \
    "$normal_fixture/release/release-manifest.json" \
    "$test_root/normal-manifest-first.json"
cp \
    "$normal_fixture/release/SHA256SUMS" \
    "$test_root/normal-checksums-first"
(
    cd "$normal_fixture"
    ./scripts/update_release_dependency_metadata.sh >/dev/null
)
cmp -s \
    "$test_root/normal-manifest-first.json" \
    "$normal_fixture/release/release-manifest.json" \
    || fail idempotence 'Zweiter Lauf hat das Manifest veraendert.'
cmp -s \
    "$test_root/normal-checksums-first" \
    "$normal_fixture/release/SHA256SUMS" \
    || fail idempotence 'Zweiter Lauf hat SHA256SUMS veraendert.'
assert_no_generator_temporary_files "$normal_fixture"

run_failure_case before_first_exchange before_first_exchange
run_failure_case between_exchanges between_exchanges
run_failure_case after_both_exchanges after_both_exchanges
run_failure_case signal_int_before_first signal_int_before_first_exchange
run_failure_case signal_term_between signal_term_between_exchanges
run_failure_case signal_hup_after_both signal_hup_after_both_exchanges
run_failure_case unknown_failure_point unsupported-test-value

echo 'Transaktionale Release-Dependency-Metadaten-Tests OK'
