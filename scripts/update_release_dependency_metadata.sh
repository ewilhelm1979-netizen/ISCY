#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

fail() {
    printf 'RELEASE_DEPENDENCY_METADATA_ERROR[%s]: %s\n' "$1" "$2" >&2
    exit 1
}

for command in cmp cp cut git install jq mktemp mv realpath rm sha256sum; do
    command -v "$command" >/dev/null 2>&1 || fail prerequisite "$command fehlt."
done

manifest_path='release/release-manifest.json'
checksums_path='release/SHA256SUMS'
sbom_path='release/iscy-backend.cdx.json'
checksum_paths=(
    'rust/iscy-backend/Cargo.lock'
    'flake.lock'
    'docs/ISCY_Handbuch.pdf'
    'docs/RELEASE_NOTES_DRAFT.md'
    "$sbom_path"
    "$manifest_path"
)

# Test-only fault injection. Unset in normal operation; unknown values fail closed.
test_failure_point="${ISCY_TEST_RELEASE_METADATA_FAIL_AT:-}"
case "$test_failure_point" in
    '' \
        | before_first_exchange \
        | between_exchanges \
        | after_both_exchanges \
        | signal_int_before_first_exchange \
        | signal_term_between_exchanges \
        | signal_hup_after_both_exchanges)
        ;;
    *)
        fail test_failure \
            'ISCY_TEST_RELEASE_METADATA_FAIL_AT enthaelt einen unbekannten Testwert.'
        ;;
esac

assert_regular_repo_file() {
    local path="$1"
    local resolved

    if [[ ! -e "$path" && ! -L "$path" ]]; then
        fail missing_file "$path fehlt."
    fi
    [[ -f "$path" && ! -L "$path" ]] \
        || fail file_type "$path muss eine regulaere Datei und darf kein Symlink sein."

    resolved="$(realpath -e -- "$path")" \
        || fail repository_path "$path konnte nicht sicher aufgeloest werden."
    case "$resolved" in
        "$repo_root"/*)
            ;;
        *)
            fail repository_path "$path liegt ausserhalb des Repositorys."
            ;;
    esac
}

hash_file() {
    sha256sum "$1" | cut -d ' ' -f 1
}

validate_metadata_pair() {
    local manifest_candidate="$1"
    local checksums_candidate="$2"
    local phase="$3"
    local cargo_lock_sha256
    local flake_lock_sha256
    local sbom_sha256
    local expected_hash
    local expected_line
    local line
    local path
    local index=0

    [[ -f "$manifest_candidate" && ! -L "$manifest_candidate" ]] \
        || fail validation "$phase: Manifestkandidat ist keine regulaere Datei."
    [[ -f "$checksums_candidate" && ! -L "$checksums_candidate" ]] \
        || fail validation "$phase: Pruefsummenkandidat ist keine regulaere Datei."
    jq -e . "$manifest_candidate" >/dev/null \
        || fail validation "$phase: Manifest ist kein gueltiges JSON."

    for path in "${checksum_paths[@]}"; do
        if [[ "$path" != "$manifest_path" ]]; then
            assert_regular_repo_file "$path"
        fi
    done

    cargo_lock_sha256="$(hash_file rust/iscy-backend/Cargo.lock)"
    flake_lock_sha256="$(hash_file flake.lock)"
    sbom_sha256="$(hash_file "$sbom_path")"
    jq -e \
        --arg cargo_lock_sha256 "$cargo_lock_sha256" \
        --arg flake_lock_sha256 "$flake_lock_sha256" \
        --arg sbom_sha256 "$sbom_sha256" \
        '.cargo_lock_sha256 == $cargo_lock_sha256
        and .flake_lock_sha256 == $flake_lock_sha256
        and .sbom_sha256 == $sbom_sha256' \
        "$manifest_candidate" >/dev/null \
        || fail validation "$phase: Dependency-Hashes im Manifest stimmen nicht."

    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$index" -lt "${#checksum_paths[@]}" ]] \
            || fail validation "$phase: SHA256SUMS enthaelt unerwartete Eintraege."
        path="${checksum_paths[$index]}"
        if [[ "$path" == "$manifest_path" ]]; then
            expected_hash="$(hash_file "$manifest_candidate")"
        else
            expected_hash="$(hash_file "$path")"
        fi
        expected_line="$expected_hash  $path"
        [[ "$line" == "$expected_line" ]] \
            || fail validation "$phase: SHA256SUMS-Eintrag fuer $path stimmt nicht."
        index=$((index + 1))
    done <"$checksums_candidate"
    [[ "$index" -eq "${#checksum_paths[@]}" ]] \
        || fail validation "$phase: SHA256SUMS ist unvollstaendig."
}

inject_test_failure() {
    local point="$1"

    if [[ "$test_failure_point" == "$point" ]]; then
        printf 'RELEASE_DEPENDENCY_METADATA_TEST_FAILURE[%s]\n' "$point" >&2
        return 97
    fi
    case "$test_failure_point:$point" in
        signal_int_before_first_exchange:before_first_exchange)
            kill -s INT "$BASHPID"
            return 98
            ;;
        signal_term_between_exchanges:between_exchanges)
            kill -s TERM "$BASHPID"
            return 98
            ;;
        signal_hup_after_both_exchanges:after_both_exchanges)
            kill -s HUP "$BASHPID"
            return 98
            ;;
    esac
}

[[ -d release && ! -L release ]] \
    || fail repository_path 'release muss ein Verzeichnis sein und darf kein Symlink sein.'
[[ "$(realpath -e -- release)" == "$repo_root/release" ]] \
    || fail repository_path 'release liegt nicht direkt im Repository.'
for path in "${checksum_paths[@]}" "$checksums_path"; do
    assert_regular_repo_file "$path"
done

tmp_dir="$(mktemp -d "$repo_root/release/.dependency-metadata.XXXXXX")"
case "$(realpath -e -- "$tmp_dir")" in
    "$repo_root"/release/.dependency-metadata.*)
        ;;
    *)
        fail temporary_path 'Das temporaere Verzeichnis liegt nicht sicher im Repository.'
        ;;
esac

manifest_tmp="$tmp_dir/release-manifest.json"
checksums_tmp="$tmp_dir/SHA256SUMS"
manifest_install="$tmp_dir/release-manifest.install"
checksums_install="$tmp_dir/SHA256SUMS.install"
manifest_backup="$tmp_dir/release-manifest.backup"
checksums_backup="$tmp_dir/SHA256SUMS.backup"
transaction_active=0
transaction_complete=0
original_manifest_sha256=''
original_checksums_sha256=''

restore_backup() {
    local backup="$1"
    local target="$2"
    local expected_hash="$3"
    local label="$4"

    if [[ ! -f "$backup" || -L "$backup" ]]; then
        printf 'RELEASE_DEPENDENCY_METADATA_ROLLBACK_ERROR[%s]: Backup fehlt oder ist ein Symlink.\n' \
            "$label" >&2
        return 1
    fi
    if ! mv -fT -- "$backup" "$target"; then
        printf 'RELEASE_DEPENDENCY_METADATA_ROLLBACK_ERROR[%s]: Wiederherstellung fehlgeschlagen.\n' \
            "$label" >&2
        return 1
    fi
    if [[ ! -f "$target" || -L "$target" ]] \
        || [[ "$(hash_file "$target")" != "$expected_hash" ]]; then
        printf 'RELEASE_DEPENDENCY_METADATA_ROLLBACK_ERROR[%s]: Wiederhergestellte Datei stimmt nicht.\n' \
            "$label" >&2
        return 1
    fi
}

rollback_transaction() {
    local rollback_failed=0

    restore_backup \
        "$manifest_backup" "$manifest_path" "$original_manifest_sha256" manifest \
        || rollback_failed=1
    restore_backup \
        "$checksums_backup" "$checksums_path" "$original_checksums_sha256" checksums \
        || rollback_failed=1
    if [[ "$rollback_failed" -ne 0 ]]; then
        return 1
    fi
    transaction_active=0
}

cleanup_tmp_dir() {
    if [[ -z "${tmp_dir:-}" || ! -e "$tmp_dir" ]]; then
        return 0
    fi
    case "$tmp_dir" in
        "$repo_root"/release/.dependency-metadata.*)
            [[ -d "$tmp_dir" && ! -L "$tmp_dir" ]] || return 1
            rm -rf -- "$tmp_dir"
            ;;
        *)
            return 1
            ;;
    esac
}

on_exit() {
    local status="$1"

    trap - EXIT ERR
    trap '' INT TERM HUP
    if [[ "$transaction_active" -eq 1 && "$transaction_complete" -eq 0 ]]; then
        rollback_transaction || status=1
    fi
    cleanup_tmp_dir || status=1
    exit "$status"
}

on_error() {
    local status="$1"

    trap - ERR
    exit "$status"
}

on_signal() {
    local signal="$1"
    local status="$2"

    printf 'RELEASE_DEPENDENCY_METADATA_SIGNAL[%s]: Transaktion wird zurueckgerollt.\n' \
        "$signal" >&2
    trap '' INT TERM HUP
    exit "$status"
}

trap 'on_exit "$?"' EXIT
trap 'on_error "$?"' ERR
trap 'on_signal INT 130' INT
trap 'on_signal TERM 143' TERM
trap 'on_signal HUP 129' HUP

cargo_lock_sha256="$(hash_file rust/iscy-backend/Cargo.lock)"
flake_lock_sha256="$(hash_file flake.lock)"
sbom_sha256="$(hash_file "$sbom_path")"

jq \
    --arg cargo_lock_sha256 "$cargo_lock_sha256" \
    --arg flake_lock_sha256 "$flake_lock_sha256" \
    --arg sbom_sha256 "$sbom_sha256" \
    '.cargo_lock_sha256 = $cargo_lock_sha256
    | .flake_lock_sha256 = $flake_lock_sha256
    | .sbom_sha256 = $sbom_sha256' \
    "$manifest_path" >"$manifest_tmp"

: >"$checksums_tmp"
for path in "${checksum_paths[@]}"; do
    if [[ "$path" == "$manifest_path" ]]; then
        manifest_sha256="$(hash_file "$manifest_tmp")"
        printf '%s  %s\n' "$manifest_sha256" "$manifest_path" >>"$checksums_tmp"
    else
        sha256sum "$path" >>"$checksums_tmp"
    fi
done

install -m 0644 "$manifest_tmp" "$manifest_install"
install -m 0644 "$checksums_tmp" "$checksums_install"
validate_metadata_pair "$manifest_install" "$checksums_install" preparation

for path in "$manifest_path" "$checksums_path"; do
    assert_regular_repo_file "$path"
done
cp --preserve=mode,timestamps -- "$manifest_path" "$manifest_backup"
cp --preserve=mode,timestamps -- "$checksums_path" "$checksums_backup"
if [[ ! -f "$manifest_backup" || -L "$manifest_backup" ]] \
    || ! cmp -s -- "$manifest_path" "$manifest_backup"; then
    fail backup 'Manifest-Backup ist nicht byte-identisch.'
fi
if [[ ! -f "$checksums_backup" || -L "$checksums_backup" ]] \
    || ! cmp -s -- "$checksums_path" "$checksums_backup"; then
    fail backup 'SHA256SUMS-Backup ist nicht byte-identisch.'
fi
original_manifest_sha256="$(hash_file "$manifest_backup")"
original_checksums_sha256="$(hash_file "$checksums_backup")"
transaction_active=1

inject_test_failure before_first_exchange
assert_regular_repo_file "$manifest_path"
cmp -s -- "$manifest_path" "$manifest_backup" \
    || fail concurrent_change 'Release-Manifest wurde waehrend der Transaktion veraendert.'
mv -fT -- "$manifest_install" "$manifest_path"

inject_test_failure between_exchanges
assert_regular_repo_file "$checksums_path"
cmp -s -- "$checksums_path" "$checksums_backup" \
    || fail concurrent_change 'SHA256SUMS wurde waehrend der Transaktion veraendert.'
mv -fT -- "$checksums_install" "$checksums_path"

inject_test_failure after_both_exchanges
assert_regular_repo_file "$manifest_path"
assert_regular_repo_file "$checksums_path"
validate_metadata_pair "$manifest_path" "$checksums_path" final
sha256sum --check "$checksums_path" >/dev/null \
    || fail checksum 'Neu erzeugte Release-Pruefsummen sind inkonsistent.'

transaction_complete=1
transaction_active=0

echo 'RELEASE_DEPENDENCY_METADATA_OK: Manifest- und Release-Pruefsummen reproduzierbar aktualisiert.'
