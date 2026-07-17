#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

fail() {
    printf 'RC_SBOM_ERROR[%s]: %s\n' "$1" "$2" >&2
    exit 1
}

for command in grep jq sha256sum; do
    command -v "$command" >/dev/null 2>&1 || fail prerequisite "$command fehlt."
done

manifest_path="${ISCY_RELEASE_MANIFEST_PATH:-release/release-manifest.json}"
sbom_path="${ISCY_RELEASE_SBOM_PATH:-release/iscy-backend.cdx.json}"

release_status="$(jq -er '.release_status | select(type == "string")' "$manifest_path" 2>/dev/null)" \
    || fail release_status 'Release-Manifest fehlt, ist ungueltig oder enthaelt keinen gueltigen Status.'

case "$release_status" in
    development_unreleased)
        manifest_hash="$(jq -er '.sbom_sha256 | select(type == "string")' "$manifest_path" 2>/dev/null)" \
            || fail manifest_hash 'Vollstaendiger SBOM-Manifesthash fehlt.'
        [[ "$manifest_hash" =~ ^[0-9a-f]{64}$ ]] \
            || fail manifest_hash 'SBOM-Manifesthash ist kein gueltiger lowercase SHA-256-Wert.'
        [[ -f "$sbom_path" && ! -L "$sbom_path" ]] \
            || fail sbom 'SBOM-Snapshot fehlt, ist kein regulaeres File oder ist ein Symlink.'

        actual_hash="$(sha256sum "$sbom_path" | cut -d ' ' -f 1)"
        [[ "$actual_hash" == "$manifest_hash" ]] \
            || fail manifest_hash 'Manifesthash fuer sbom_sha256 stimmt nicht.'

        jq -e '
            .bomFormat == "CycloneDX" and
            .specVersion == "1.5" and
            (has("serialNumber") | not)
        ' "$sbom_path" >/dev/null 2>&1 \
            || fail structure 'CycloneDX-Struktur oder reproduzierbare Metadaten sind ungueltig.'

        local_home='/home/'
        local_file_scheme='file://'
        nix_root='/nix/'
        github_root='/github/'
        regex_backslash=$'\\\\'
        local_path_pattern="${local_home}[A-Za-z0-9._-]+/|C:${regex_backslash}Users${regex_backslash}|${local_file_scheme}${local_home}|${nix_root}store/|${github_root}workspace/"
        if grep -aEq "$local_path_pattern" "$sbom_path"; then
            fail local_path 'CycloneDX-SBOM enthaelt einen lokalen absoluten Pfad.'
        fi

        echo 'RC_SBOM_OK[development_snapshot]: vorhandener veroeffentlichter SBOM-Snapshot validiert; keine Neuerzeugung durchgefuehrt.'
        ;;
    prepared_not_published)
        exec make release-sbom
        ;;
    *)
        fail release_status 'Nicht unterstuetzter Root-Release-Status.'
        ;;
esac
