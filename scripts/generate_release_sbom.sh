#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

output="${ISCY_RELEASE_SBOM_PATH:-release/iscy-backend.cdx.json}"
raw_name='.iscy-release-sbom-raw'
raw_path="rust/iscy-backend/${raw_name}.json"
cleanup() {
    rm -f "$raw_path"
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

source_commit="$(jq -er '.source_base_commit' release/release-manifest.json)"
source_date_epoch="$(git show -s --format=%ct "$source_commit")"
timestamp="$(date -u -d "@$source_date_epoch" +'%Y-%m-%dT%H:%M:%SZ')"
package_version="$(
    cargo metadata --locked --no-deps --format-version 1 \
        --manifest-path rust/iscy-backend/Cargo.toml \
        | jq -er '.packages[] | select(.name == "iscy-backend") | .version'
)"
root_purl="pkg:cargo/iscy-backend@${package_version}"

SOURCE_DATE_EPOCH="$source_date_epoch" cargo cyclonedx \
    --manifest-path rust/iscy-backend/Cargo.toml \
    --format json \
    --spec-version 1.5 \
    --override-filename "$raw_name" \
    --quiet

mkdir -p release
jq --arg timestamp "$timestamp" --arg root_purl "$root_purl" \
    '
    del(.serialNumber)
    | .metadata.timestamp = $timestamp
    | walk(
        if type == "string" and startswith("path+file://") then
          sub("^path\\+file://[^#]+#[^ ]+"; $root_purl)
          | gsub(" bin-target-"; "#bin-target-")
        else
          .
        end
      )
    ' \
    "$raw_path" >"$output"
jq -e '.bomFormat == "CycloneDX" and .specVersion == "1.5" and (.components | length > 0)' \
    "$output" >/dev/null
local_home='/home/'
local_file_scheme='file://'
regex_backslash=$'\\\\'
local_path_pattern="${local_home}[A-Za-z0-9._-]+/|C:${regex_backslash}Users${regex_backslash}|${local_file_scheme}${local_home}"
if grep -aEq "$local_path_pattern" "$output"; then
    echo 'SBOM_ERROR[local_path]: SBOM enthaelt einen lokalen absoluten Pfad.' >&2
    exit 1
fi

echo "SBOM_OK: reproduzierbare CycloneDX-1.5-SBOM erzeugt: $output"
