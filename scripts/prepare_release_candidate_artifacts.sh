#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

output_dir="${ISCY_RC_ARTIFACT_DIR:-artifacts/release-candidate}"
binary="rust/iscy-backend/target/release/iscy-backend"

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
    echo 'RC_ARTIFACT_ERROR[release_binary]: Release-Binary fehlt; zuerst cargo build --release --locked ausfuehren.' >&2
    exit 1
fi

rm -rf "$output_dir"
mkdir -p "$output_dir"

commit="$(git rev-parse HEAD)"
source_date_epoch="$(git show -s --format=%ct HEAD)"

cp "$binary" "$output_dir/iscy-backend"
cp docs/ISCY_Handbuch.pdf "$output_dir/ISCY_Handbuch.pdf"
cp docs/RELEASE_NOTES_DRAFT.md "$output_dir/RELEASE_NOTES.md"
cp release/iscy-backend.cdx.json "$output_dir/iscy-backend.cdx.json"
jq \
    --arg source_commit "$commit" \
    --argjson source_date_epoch "$source_date_epoch" \
    '.source_commit = $source_commit
    | .source_date_epoch = $source_date_epoch
    | .release_status = "release_candidate_prerelease"' \
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

echo "RC_ARTIFACTS_OK: lokale, unsignierte Artefakte unter $output_dir erzeugt; keine Veroeffentlichung."
