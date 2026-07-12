#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

fail() {
    printf 'RC_METADATA_ERROR[%s]: %s\n' "$1" "$2" >&2
    exit 1
}

command -v git >/dev/null || fail prerequisite 'git fehlt.'
command -v jq >/dev/null || fail prerequisite 'jq fehlt.'
command -v sha256sum >/dev/null || fail prerequisite 'sha256sum fehlt.'

[[ -f docs/RELEASE_NOTES_DRAFT.md ]] || fail documentation 'Release Notes fehlen.'
[[ -f docs/RELEASE_CANDIDATE_CHECKLIST.md ]] || fail documentation 'RC-Checkliste fehlt.'
[[ -f docs/ISCY_Handbuch.pdf ]] || fail documentation 'Handbuch-PDF fehlt.'
[[ -f release/release-manifest.json ]] || fail manifest 'Release-Manifest fehlt.'
[[ -f release/SHA256SUMS ]] || fail checksum 'Release-Checksummen fehlen.'
[[ -f release/iscy-backend.cdx.json ]] || fail sbom 'CycloneDX-SBOM fehlt.'

jq -e '
    .proposed_version == "V23.7.28-rc.1" and
    .release_status == "prepared_not_published" and
    .source_commit == "git:HEAD" and
    .migration_count == 39 and
    .signature_status == "unsigned" and
    .provenance_status == "prepared_unsigned" and
    .sbom_status == "generated_cyclonedx_1.5"
' release/release-manifest.json >/dev/null \
    || fail manifest 'Pflichtfelder oder sichere Statuswerte sind ungueltig.'
jq -e '
    .bomFormat == "CycloneDX" and
    .specVersion == "1.5" and
    (has("serialNumber") | not) and
    (.components | length > 0) and
    (.dependencies | length > 0)
' release/iscy-backend.cdx.json >/dev/null \
    || fail sbom 'CycloneDX-Struktur oder reproduzierbare Metadaten sind ungueltig.'
local_home='/home/'
local_file_scheme='file://'
regex_backslash=$'\\\\'
local_path_pattern="${local_home}[A-Za-z0-9._-]+/|C:${regex_backslash}Users${regex_backslash}|${local_file_scheme}${local_home}"
if grep -aEq "$local_path_pattern" release/iscy-backend.cdx.json; then
    fail sbom 'CycloneDX-SBOM enthaelt einen lokalen absoluten Pfad.'
fi

mapfile -t migration_ids < <(
    grep -oE 'version: "[0-9]{4}_' rust/iscy-backend/src/db_admin.rs \
        | grep -oE '[0-9]{4}'
)
[[ "${#migration_ids[@]}" -eq 39 ]] \
    || fail migration "Erwartet 39 Migrationen, gefunden ${#migration_ids[@]}."
for index in "${!migration_ids[@]}"; do
    expected="$(printf '%04d' "$((index + 1))")"
    [[ "${migration_ids[$index]}" == "$expected" ]] \
        || fail migration "Erwartet $expected, gefunden ${migration_ids[$index]}."
done

baseline_count="$(find tests/visual/baselines -type f -name '*.png' | wc -l | tr -d ' ')"
[[ "$baseline_count" -eq 34 ]] \
    || fail visual_baselines "Erwartet 34 Baselines, gefunden $baseline_count."

while IFS= read -r path; do
    [[ -f "$path" ]] || fail screenshot_reference "Referenz fehlt: $path"
done < <(grep -oE 'docs/assets/[A-Za-z0-9._/-]+\.png' docs/GUI_SCREENSHOTS.md | sort -u)

sha256sum -c release/SHA256SUMS >/dev/null \
    || fail checksum 'Mindestens eine getrackte RC-Pruefsumme stimmt nicht.'

secret_marker='rc-regression-secret-must-not-be-logged'
database_scheme='postgresql'
same_url="${database_scheme}://iscy:${secret_marker}@127.0.0.1:1/same"
set +e
restore_guard_output="$(
    ISCY_POSTGRES_RESTORE_DRILL_SOURCE_URL="$same_url" \
    ISCY_POSTGRES_RESTORE_DRILL_RESTORE_URL="$same_url" \
    make rust-postgres-restore-drill 2>&1
)"
restore_guard_status=$?
set -e
[[ "$restore_guard_status" -ne 0 ]] \
    || fail restore_guard 'Identische Source-/Restore-Ziele wurden nicht abgelehnt.'
[[ "$restore_guard_output" != *"$secret_marker"* ]] \
    || fail secret_redaction 'Der Restore-Drill hat einen Credential-Marker ausgegeben.'

./scripts/check_release_sensitive_data.sh
git diff --check

echo 'RC_METADATA_OK: Manifest, 39 Migrationen, 34 Baselines, Referenzen und Checksums sind konsistent.'
