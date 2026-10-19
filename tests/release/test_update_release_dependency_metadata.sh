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
    local stale_handbook="${2:-false}"
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

    jq --argjson stale_handbook "$stale_handbook" '
        .cargo_lock_sha256 = "test-fixture-cargo-lock"
        | .flake_lock_sha256 = "test-fixture-flake-lock"
        | .sbom_sha256 = "test-fixture-sbom"
        | if $stale_handbook then .handbook_sha256 = "test-fixture-stale-handbook" else . end
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
    local -a options=()
    local stale_handbook=false
    if [[ "$#" -eq 3 ]]; then
        options=("$3")
        stale_handbook=true
    fi

    create_fixture "$fixture" "$stale_handbook"
    mkdir -p "$baseline"
    cp -- "$fixture/release/release-manifest.json" "$baseline/release-manifest.json"
    cp -- "$fixture/release/SHA256SUMS" "$baseline/SHA256SUMS"

    if (
        cd "$fixture"
        ISCY_TEST_RELEASE_METADATA_FAIL_AT="$failure_point" \
            ./scripts/update_release_dependency_metadata.sh "${options[@]}"
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

handbook_fixture="$test_root/handbook"
create_fixture "$handbook_fixture" true
(
    cd "$handbook_fixture"
    ./scripts/update_release_dependency_metadata.sh >/dev/null
    jq -e '.handbook_sha256 == "test-fixture-stale-handbook"' \
        release/release-manifest.json >/dev/null \
        || fail handbook_default 'Dependency-Abgleich hat das Handbuch implizit freigegeben.'
    cp -- release/release-manifest.json "$test_root/handbook-before-explicit.json"
    ./scripts/update_release_dependency_metadata.sh --include-handbook >/dev/null
    handbook_hash="$(sha256sum docs/ISCY_Handbuch.pdf | cut -d ' ' -f 1)"
    jq -e --arg hash "$handbook_hash" '.handbook_sha256 == $hash' \
        release/release-manifest.json >/dev/null \
        || fail handbook_update 'Expliziter Handbuch-Abgleich hat den PDF-Hash nicht aktualisiert.'
    jq -e --slurpfile before "$test_root/handbook-before-explicit.json" \
        'del(.handbook_sha256) == ($before[0] | del(.handbook_sha256))' \
        release/release-manifest.json >/dev/null \
        || fail handbook_scope 'Handbuch-Abgleich hat weitere Manifestfelder veraendert.'
    sha256sum -c release/SHA256SUMS >/dev/null
)
cmp -s release/iscy-backend.cdx.json "$handbook_fixture/release/iscy-backend.cdx.json" \
    || fail handbook_sbom 'Handbuch-Abgleich hat den SBOM-Snapshot veraendert.'
cmp -s docs/ISCY_Handbuch.pdf "$handbook_fixture/docs/ISCY_Handbuch.pdf" \
    || fail handbook_pdf 'Metadaten-Abgleich hat das PDF veraendert.'
cp -- "$handbook_fixture/release/release-manifest.json" "$test_root/handbook-manifest-first.json"
cp -- "$handbook_fixture/release/SHA256SUMS" "$test_root/handbook-checksums-first"
(
    cd "$handbook_fixture"
    ./scripts/update_release_dependency_metadata.sh --include-handbook >/dev/null
)
cmp -s "$test_root/handbook-manifest-first.json" "$handbook_fixture/release/release-manifest.json" \
    || fail handbook_idempotence 'Zweiter Handbuch-Abgleich veraendert das Manifest.'
cmp -s "$test_root/handbook-checksums-first" "$handbook_fixture/release/SHA256SUMS" \
    || fail handbook_idempotence 'Zweiter Handbuch-Abgleich veraendert SHA256SUMS.'
assert_no_generator_temporary_files "$handbook_fixture"

prepared_fixture="$test_root/handbook-prepared"
create_fixture "$prepared_fixture" true
jq '.release_status = "prepared_not_published"' \
    "$prepared_fixture/release/release-manifest.json" >"$test_root/prepared-manifest.json"
mv -fT "$test_root/prepared-manifest.json" "$prepared_fixture/release/release-manifest.json"
(
    cd "$prepared_fixture"
    ./scripts/update_release_dependency_metadata.sh --include-handbook >/dev/null
    handbook_hash="$(sha256sum docs/ISCY_Handbuch.pdf | cut -d ' ' -f 1)"
    jq -e --arg hash "$handbook_hash" \
        '.release_status == "prepared_not_published" and .handbook_sha256 == $hash' \
        release/release-manifest.json >/dev/null \
        || fail handbook_prepared 'Unveroeffentlichter vorbereiteter Stand wurde nicht korrekt aktualisiert.'
    sha256sum -c release/SHA256SUMS >/dev/null
)
assert_no_generator_temporary_files "$prepared_fixture"

for failure_point in before_first_exchange between_exchanges after_both_exchanges \
    signal_int_before_first_exchange signal_term_between_exchanges signal_hup_after_both_exchanges; do
    run_failure_case "handbook-$failure_point" "$failure_point" --include-handbook
done

for rejection in unknown_argument multiple_arguments published_status; do
    fixture="$test_root/$rejection"
    baseline="$test_root/$rejection-baseline"
    create_fixture "$fixture" true
    options=(--include-handbook)
    expected_category=arguments
    case "$rejection" in
        unknown_argument) options=(--include-unreviewed-artifacts) ;;
        multiple_arguments) options+=(unexpected) ;;
        published_status)
            jq '.release_status = "stable_release_prepared"' \
                "$fixture/release/release-manifest.json" >"$test_root/published-manifest.json"
            mv -fT "$test_root/published-manifest.json" "$fixture/release/release-manifest.json"
            expected_category=release_status
            ;;
    esac
    mkdir -p "$baseline"
    cp -- "$fixture/release/release-manifest.json" "$baseline/release-manifest.json"
    cp -- "$fixture/release/SHA256SUMS" "$baseline/SHA256SUMS"
    if output="$(cd "$fixture" && ./scripts/update_release_dependency_metadata.sh "${options[@]}" 2>&1)"; then
        fail "$rejection" 'Unzulaessiger Metadaten-Aufruf wurde akzeptiert.'
    fi
    [[ "$output" == *"RELEASE_DEPENDENCY_METADATA_ERROR[$expected_category]"* ]] \
        || fail "$rejection" 'Unerwartete Fehlerklasse.'
    assert_pair_unchanged "$fixture" "$baseline" "$rejection"
done

echo 'Transaktionale Release-Dependency-Metadaten-Tests OK'
