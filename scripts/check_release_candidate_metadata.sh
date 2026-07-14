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

notes_path="${ISCY_RELEASE_NOTES_PATH:-docs/RELEASE_NOTES_DRAFT.md}"
manifest_path="${ISCY_RELEASE_MANIFEST_PATH:-release/release-manifest.json}"
sbom_path="${ISCY_RELEASE_SBOM_PATH:-release/iscy-backend.cdx.json}"
checksums_path="${ISCY_RELEASE_CHECKSUMS_PATH:-release/SHA256SUMS}"

[[ -f "$notes_path" ]] || fail documentation 'Release Notes fehlen.'
[[ -f docs/RELEASE_CANDIDATE_CHECKLIST.md ]] || fail documentation 'RC-Checkliste fehlt.'
[[ -f docs/ISCY_Handbuch.pdf ]] || fail documentation 'Handbuch-PDF fehlt.'
[[ -f "$manifest_path" ]] || fail manifest 'Release-Manifest fehlt.'
[[ -f "$checksums_path" ]] || fail checksum 'Release-Checksummen fehlen.'
[[ -f "$sbom_path" ]] || fail sbom 'CycloneDX-SBOM fehlt.'
./scripts/check_release_notes_completeness.sh "$notes_path"
generated_notes_path='artifacts/release-candidate/RELEASE_NOTES.md'
if [[ -f "$generated_notes_path" && "$notes_path" != "$generated_notes_path" ]]; then
    ./scripts/check_release_notes_completeness.sh "$generated_notes_path"
fi
if [[ "${ISCY_SKIP_RELEASE_REGRESSION_TESTS:-false}" != 'true' ]]; then
    ./tests/release/test_release_notes_completeness.sh
    ./tests/release/test_release_candidate_metadata.sh
    ./tests/release/test_pg18_release_environment_isolation.sh
fi

jq -e '
    .schema_version == 2 and
    .proposed_version == "V23.7.29" and
    .release_status == "prepared_not_published" and
    .source_commit == "git:HEAD" and
    .source_base_commit == "99fe2af95930c576469890ef8b5719f7dd268941" and
    .migration_count == 39 and
    .cargo_package_version == "0.3.22" and
    .rust_version.package_msrv == "1.88" and
    .rust_version.ci_product_builder == "1.97.0" and
    .rust_version.product_container_builder == "1.97.0" and
    .rust_version.portable_release_builder == "1.88" and
    .rust_version.nix_development_path == "1.95.0" and
    .platform_versions.nginx == "1.31-alpine" and
    .platform_versions.nixpkgs == "nixos-26.05" and
    .database_support.standard == "postgresql_16" and
    .database_support.additional_compatibility == ["sqlite_single_instance", "postgresql_18.4"] and
    .database_support.upgrade_path == "logical_dump_restore_16_to_18" and
    .database_support.in_place_upgrade == false and
    .test_suite_summary.required_dependency_job_count == 10 and
    (.test_suite_summary.required_dependency_jobs | length) == 10 and
    .test_suite_summary.aggregation_job == "release-candidate-check" and
    .test_suite_summary.aggregation_job_count == 1 and
    .test_suite_summary.codeql_checks == ["actions", "javascript-typescript", "rust"] and
    .test_suite_summary.visual_baselines == 34 and
    .signature_status == "unsigned" and
    .provenance_status == "prepared_unsigned" and
    .sbom_status == "generated_cyclonedx_1.5" and
    .release_artifact.type == "linux-x86_64-glibc" and
    .release_artifact.elf_interpreter == "/lib64/ld-linux-x86-64.so.2" and
    .release_artifact.runtime_libraries == ["libgcc_s.so.1", "libm.so.6", "libc.so.6", "ld-linux-x86-64.so.2"] and
    .release_artifact.rpath_status == "absent" and
    .release_artifact.reproducibility_status == "required_two_build_sha256" and
    .release_artifact.binary_sha256 == null
' "$manifest_path" >/dev/null \
    || fail manifest 'Pflichtfelder oder sichere Statuswerte sind ungueltig.'
jq -e '
    .bomFormat == "CycloneDX" and
    .specVersion == "1.5" and
    (has("serialNumber") | not) and
    (.components | length > 0) and
    (.dependencies | length > 0)
' "$sbom_path" >/dev/null \
    || fail sbom 'CycloneDX-Struktur oder reproduzierbare Metadaten sind ungueltig.'
local_home='/home/'
local_file_scheme='file://'
regex_backslash=$'\\\\'
local_path_pattern="${local_home}[A-Za-z0-9._-]+/|C:${regex_backslash}Users${regex_backslash}|${local_file_scheme}${local_home}"
if grep -aEq "$local_path_pattern|/nix/store/|/github/workspace/" "$sbom_path"; then
    fail sbom 'CycloneDX-SBOM enthaelt einen lokalen absoluten Pfad.'
fi

declare -A tracked_hashes=(
    [cargo_lock_sha256]='rust/iscy-backend/Cargo.lock'
    [flake_lock_sha256]='flake.lock'
    [handbook_sha256]='docs/ISCY_Handbuch.pdf'
    [sbom_sha256]="$sbom_path"
)
for field in "${!tracked_hashes[@]}"; do
    path="${tracked_hashes[$field]}"
    actual_hash="$(sha256sum "$path" | cut -d ' ' -f 1)"
    manifest_hash="$(jq -er --arg field "$field" '.[$field]' "$manifest_path")" \
        || fail manifest_hash "Manifestfeld $field fehlt."
    [[ "$manifest_hash" == "$actual_hash" ]] \
        || fail manifest_hash "Manifesthash fuer $field stimmt nicht."
done

mapfile -t ci_dependency_jobs < <(
    awk '
        /^  release-candidate-check:$/ { in_job = 1; next }
        in_job && /^    needs:$/ { in_needs = 1; next }
        in_job && in_needs && /^      - / { sub(/^      - /, ""); print; next }
        in_job && in_needs { exit }
    ' .github/workflows/ci.yml
)
mapfile -t manifest_dependency_jobs < <(
    jq -er '.test_suite_summary.required_dependency_jobs[]' "$manifest_path"
)
[[ "${#ci_dependency_jobs[@]}" -eq 10 ]] \
    || fail ci_jobs "Erwartet 10 CI-Pflichtabhaengigkeiten, gefunden ${#ci_dependency_jobs[@]}."
[[ "${ci_dependency_jobs[*]}" == "${manifest_dependency_jobs[*]}" ]] \
    || fail ci_jobs 'Manifest und tatsaechliche CI-Pflichtabhaengigkeiten weichen ab.'
grep -Fq 'make postgresql-18-compatibility' .github/workflows/ci.yml \
    || fail postgresql_18 'PostgreSQL-18-Kompatibilitaet fehlt in der Pflichtpipeline.'
grep -Eq '^[[:space:]]*image:[[:space:]]*postgres:16[[:space:]]*$' docker-compose.yml \
    || fail postgresql_standard 'Standard-Compose verwendet nicht eindeutig PostgreSQL 16.'
if grep -Eq '^[[:space:]]*image:[[:space:]]*postgres:18[[:space:]]*$' docker-compose.yml; then
    fail postgresql_standard 'PostgreSQL 18 darf nicht Standard im Produkt-Compose sein.'
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

sha256sum -c "$checksums_path" >/dev/null \
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

echo 'RC_METADATA_OK: V23.7.29, Toolchains, 10 CI-Abhaengigkeiten, PostgreSQL-Gate, 39 Migrationen, 34 Baselines und Checksums sind konsistent.'
