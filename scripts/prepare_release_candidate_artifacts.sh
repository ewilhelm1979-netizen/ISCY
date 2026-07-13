#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

output_dir="${ISCY_RC_ARTIFACT_DIR:-artifacts/release-candidate}"
binary="artifacts/portable-release/iscy-backend"
reproducibility="artifacts/portable-release/reproducibility.json"

case "$output_dir" in
    artifacts/*) ;;
    *)
        echo 'RC_ARTIFACT_ERROR[output_path]: Ausgabe muss relativ unter artifacts/ liegen.' >&2
        exit 1
        ;;
esac
if [[ "$output_dir" == *'/../'* || "$output_dir" == '../'* || "$output_dir" == *'/..' ]]; then
    echo 'RC_ARTIFACT_ERROR[output_path]: Parent-Traversal ist nicht erlaubt.' >&2
    exit 1
fi
mkdir -p artifacts
artifact_root="$(realpath artifacts)"
[[ "$artifact_root" == "$repo_root/artifacts" ]] || {
    echo 'RC_ARTIFACT_ERROR[output_path]: artifacts/ darf kein externer Symlink sein.' >&2
    exit 1
}

if [[ ! -x "$binary" ]]; then
    echo 'RC_ARTIFACT_ERROR[release_binary]: Portables Release-Binary fehlt; zuerst make release-binary-gate ausfuehren.' >&2
    exit 1
fi
[[ -f "$reproducibility" ]] \
    || { echo 'RC_ARTIFACT_ERROR[reproducibility]: Zwei-Build-Nachweis fehlt.' >&2; exit 1; }

commit="$(git rev-parse HEAD)"
binary_sha256="$(sha256sum "$binary" | cut -d ' ' -f 1)"
jq -e \
    --arg source_commit "$commit" \
    --arg sha256 "$binary_sha256" \
    '.status == "verified_two_build_sha256"
    and .source_commit == $source_commit
    and .sha256 == $sha256
    and .target == "linux-x86_64-glibc"
    and .builds == 2' \
    "$reproducibility" >/dev/null \
    || { echo 'RC_ARTIFACT_ERROR[reproducibility]: Zwei-Build-Nachweis ist inkonsistent.' >&2; exit 1; }
./scripts/check_release_binary_hygiene.sh "$binary"

rm -rf "$output_dir"
mkdir -p "$output_dir"

source_date_epoch="$(git show -s --format=%ct HEAD)"

cp "$binary" "$output_dir/iscy-backend"
cp docs/ISCY_Handbuch.pdf "$output_dir/ISCY_Handbuch.pdf"
cp docs/RELEASE_NOTES_DRAFT.md "$output_dir/RELEASE_NOTES.md"
cp release/iscy-backend.cdx.json "$output_dir/iscy-backend.cdx.json"
jq \
    --arg source_commit "$commit" \
    --argjson source_date_epoch "$source_date_epoch" \
    --arg binary_sha256 "$binary_sha256" \
    '.source_commit = $source_commit
    | .source_date_epoch = $source_date_epoch
    | .release_status = "stable_release_prepared"
    | .release_artifact.binary_sha256 = $binary_sha256
    | .release_artifact.reproducibility_status = "verified_two_build_sha256"' \
    release/release-manifest.json >"$output_dir/release-manifest.json"

(
    cd "$output_dir"
    sha256sum \
        ISCY_Handbuch.pdf \
        RELEASE_NOTES.md \
        iscy-backend \
        iscy-backend.cdx.json \
        release-manifest.json >SHA256SUMS
    sha256sum -c SHA256SUMS >/dev/null
)

mapfile -t bundle_entries < <(find "$output_dir" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)
expected_entries=(
    ISCY_Handbuch.pdf
    RELEASE_NOTES.md
    SHA256SUMS
    iscy-backend
    iscy-backend.cdx.json
    release-manifest.json
)
[[ "${bundle_entries[*]}" == "${expected_entries[*]}" ]] \
    || { echo 'RC_ARTIFACT_ERROR[contents]: Bundle muss exakt sechs erwartete Dateien enthalten.' >&2; exit 1; }
for entry in "${bundle_entries[@]}"; do
    path="$output_dir/$entry"
    [[ -f "$path" && ! -L "$path" ]] \
        || { echo 'RC_ARTIFACT_ERROR[file_type]: Bundle enthaelt keinen regulaeren Dateieintrag.' >&2; exit 1; }
done

jq -e \
    --arg source_commit "$commit" \
    --arg binary_sha256 "$binary_sha256" \
    '.schema_version == 2
    and .proposed_version == "V23.7.29"
    and .release_status == "stable_release_prepared"
    and .source_commit == $source_commit
    and (.source_date_epoch | type == "number")
    and .migration_count == 39
    and .signature_status == "unsigned"
    and .provenance_status == "prepared_unsigned"
    and .release_artifact.binary_sha256 == $binary_sha256
    and .release_artifact.reproducibility_status == "verified_two_build_sha256"' \
    "$output_dir/release-manifest.json" >/dev/null \
    || { echo 'RC_ARTIFACT_ERROR[manifest]: Bundle-Manifest ist inkonsistent.' >&2; exit 1; }
jq -e '
    .bomFormat == "CycloneDX"
    and .specVersion == "1.5"
    and (has("serialNumber") | not)
    and (.components | length > 0)
    and (.dependencies | length > 0)
' "$output_dir/iscy-backend.cdx.json" >/dev/null \
    || { echo 'RC_ARTIFACT_ERROR[sbom]: Bundle-SBOM ist ungueltig.' >&2; exit 1; }

local_home='/home/'
local_file_scheme='file://'
nix_root='/nix/'
github_root='/github/'
regex_backslash=$'\\\\'
local_path_pattern="${local_home}[A-Za-z0-9._-]+/|C:${regex_backslash}Users${regex_backslash}|${local_file_scheme}${local_home}|${nix_root}store/|${github_root}workspace/"
if grep -aEq "$local_path_pattern" "$output_dir"/*; then
    echo 'RC_ARTIFACT_ERROR[local_path]: Bundle enthaelt einen lokalen Buildpfad.' >&2
    exit 1
fi
secret_pattern='-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}'
if grep -aEq -e "$secret_pattern" "$output_dir"/*; then
    echo 'RC_ARTIFACT_ERROR[secret]: Bundle enthaelt einen sensitiven Marker.' >&2
    exit 1
fi

echo "RC_ARTIFACTS_OK: lokale, unsignierte Artefakte unter $output_dir erzeugt; keine Veroeffentlichung."
