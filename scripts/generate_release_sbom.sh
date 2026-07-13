#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

output="${ISCY_RELEASE_SBOM_PATH:-release/iscy-backend.cdx.json}"
raw_name='.iscy-release-sbom-raw'
raw_path="rust/iscy-backend/${raw_name}.json"
tmp_dir="$(mktemp -d)"
cleanup() {
    rm -f "$raw_path"
    rm -rf "$tmp_dir"
}
trap cleanup EXIT

case "$output" in
    release/*) ;;
    *)
        echo 'SBOM_ERROR[output_path]: Ausgabe muss relativ unter release/ liegen.' >&2
        exit 1
        ;;
esac
if [[ "$output" == *'/../'* || "$output" == '../'* || "$output" == *'/..' ]]; then
    echo 'SBOM_ERROR[output_path]: Parent-Traversal ist nicht erlaubt.' >&2
    exit 1
fi

command -v cargo-cyclonedx >/dev/null 2>&1 \
    || { echo 'SBOM_ERROR[prerequisite]: cargo-cyclonedx fehlt.' >&2; exit 1; }
command -v jq >/dev/null 2>&1 \
    || { echo 'SBOM_ERROR[prerequisite]: jq fehlt.' >&2; exit 1; }
command -v cmp >/dev/null 2>&1 \
    || { echo 'SBOM_ERROR[prerequisite]: cmp fehlt.' >&2; exit 1; }

source_commit="$(jq -er '.source_base_commit' release/release-manifest.json)"
source_date_epoch="$(git show -s --format=%ct "$source_commit")"
timestamp="$(date -u -d "@$source_date_epoch" +'%Y-%m-%dT%H:%M:%SZ')"
package_version="$(
    cargo metadata --locked --no-deps --format-version 1 \
        --manifest-path rust/iscy-backend/Cargo.toml \
        | jq -er '.packages[] | select(.name == "iscy-backend") | .version'
)"
root_purl="pkg:cargo/iscy-backend@${package_version}"

generate_sbom() {
    local destination="$1"

    rm -f "$raw_path"
    SOURCE_DATE_EPOCH="$source_date_epoch" cargo cyclonedx \
        --manifest-path rust/iscy-backend/Cargo.toml \
        --format json \
        --spec-version 1.5 \
        --override-filename "$raw_name" \
        --quiet

    jq --arg timestamp "$timestamp" --arg root_purl "$root_purl" \
        '
        del(.serialNumber)
        | .metadata.timestamp = $timestamp
        | walk(
            if type == "string" and startswith("path+file://") then
              sub("^path\\+file://[^#]+#[^ ]+"; $root_purl)
              | gsub(" bin-target-"; "#bin-target-")
            elif type == "string" and startswith($root_purl + "?download_url=file://.") then
              sub("\\?download_url=file://\\."; "")
            else
              .
            end
          )
        ' \
        "$raw_path" >"$destination"
    jq -e '
        .bomFormat == "CycloneDX"
        and .specVersion == "1.5"
        and (has("serialNumber") | not)
        and (.components | length > 0)
        and (.dependencies | length > 0)
    ' "$destination" >/dev/null
    local local_home='/home/'
    local local_file_scheme='file://'
    local nix_root='/nix/'
    local github_root='/github/'
    local regex_backslash=$'\\\\'
    local local_path_pattern="${local_home}[A-Za-z0-9._-]+/|C:${regex_backslash}Users${regex_backslash}|${local_file_scheme}${local_home}|${nix_root}store/|${github_root}workspace/"
    if grep -aEq "$local_path_pattern" "$destination"; then
        echo 'SBOM_ERROR[local_path]: SBOM enthaelt einen lokalen absoluten Pfad.' >&2
        exit 1
    fi
}

mkdir -p "$tmp_dir/run-1" "$tmp_dir/run-2" "$(dirname "$output")"
first="$tmp_dir/run-1/iscy-backend.cdx.json"
second="$tmp_dir/run-2/iscy-backend.cdx.json"
generate_sbom "$first"
generate_sbom "$second"
cmp -s "$first" "$second" \
    || { echo 'SBOM_ERROR[reproducibility]: Zwei getrennte SBOM-Laeufe sind nicht byteidentisch.' >&2; exit 1; }
install -m 0644 "$first" "$output"
sbom_sha256="$(sha256sum "$output" | cut -d ' ' -f 1)"

echo "SBOM_OK: zwei byteidentische CycloneDX-1.5-Laeufe erzeugt: $output sha256=$sbom_sha256"
