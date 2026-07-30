#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

fail() {
    printf 'RELEASE_DEPENDENCY_METADATA_ERROR[%s]: %s\n' "$1" "$2" >&2
    exit 1
}

for command in cut git install jq mktemp rm sha256sum; do
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

for path in "${checksum_paths[@]}"; do
    if [[ ! -e "$path" && ! -L "$path" ]]; then
        fail missing_file "$path fehlt."
    fi
    [[ -f "$path" && ! -L "$path" ]] \
        || fail file_type "$path muss eine regulaere Datei und darf kein Symlink sein."
done
[[ -e "$checksums_path" || -L "$checksums_path" ]] \
    || fail missing_file "$checksums_path fehlt."
[[ -f "$checksums_path" && ! -L "$checksums_path" ]] \
    || fail file_type "$checksums_path muss eine regulaere Datei und darf kein Symlink sein."

tmp_dir="$(mktemp -d "$repo_root/release/.dependency-metadata.XXXXXX")"
cleanup() {
    rm -rf "$tmp_dir"
}
trap cleanup EXIT

manifest_tmp="$tmp_dir/release-manifest.json"
checksums_tmp="$tmp_dir/SHA256SUMS"

cargo_lock_sha256="$(sha256sum rust/iscy-backend/Cargo.lock | cut -d ' ' -f 1)"
flake_lock_sha256="$(sha256sum flake.lock | cut -d ' ' -f 1)"
sbom_sha256="$(sha256sum "$sbom_path" | cut -d ' ' -f 1)"

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
        manifest_sha256="$(sha256sum "$manifest_tmp" | cut -d ' ' -f 1)"
        printf '%s  %s\n' "$manifest_sha256" "$manifest_path" >>"$checksums_tmp"
    else
        sha256sum "$path" >>"$checksums_tmp"
    fi
done

install -m 0644 "$manifest_tmp" "$manifest_path"
install -m 0644 "$checksums_tmp" "$checksums_path"
sha256sum --check "$checksums_path" >/dev/null \
    || fail checksum 'Neu erzeugte Release-Pruefsummen sind inkonsistent.'

echo 'RELEASE_DEPENDENCY_METADATA_OK: Manifest- und Release-Pruefsummen reproduzierbar aktualisiert.'
