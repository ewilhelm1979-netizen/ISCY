#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

fail() {
    printf 'RC_METADATA_ERROR[%s]: %s\n' "$1" "$2" >&2
    exit 1
}

for command in git jq sha256sum; do
    command -v "$command" >/dev/null || fail prerequisite "$command fehlt."
done

notes_path="${ISCY_RELEASE_NOTES_PATH:-docs/RELEASE_NOTES_DRAFT.md}"
manifest_path="${ISCY_RELEASE_MANIFEST_PATH:-release/release-manifest.json}"
sbom_path="${ISCY_RELEASE_SBOM_PATH:-release/iscy-backend.cdx.json}"
checksums_path="${ISCY_RELEASE_CHECKSUMS_PATH:-release/SHA256SUMS}"
snapshot_path="${ISCY_PUBLISHED_SNAPSHOT_PATH:-release/published/V23.7.29.json}"
db_admin_path="${ISCY_DB_ADMIN_PATH:-rust/iscy-backend/src/db_admin.rs}"
published_version='V23.7.29'
published_commit='ba47201885435d57efc5042acde665f42dc000df'
development_version='V23.7.30'

[[ -f "$notes_path" ]] || fail documentation 'Release Notes fehlen.'
[[ -f docs/RELEASE_CANDIDATE_CHECKLIST.md ]] || fail documentation 'Release-Checkliste fehlt.'
[[ -f docs/ISCY_Handbuch.pdf ]] || fail documentation 'Handbuch-PDF fehlt.'
[[ -f "$manifest_path" ]] || fail manifest 'Release-Manifest fehlt.'
[[ -f "$checksums_path" ]] || fail checksum 'Release-Checksummen fehlen.'
[[ -f "$sbom_path" ]] || fail sbom 'CycloneDX-SBOM fehlt.'
[[ -f "$snapshot_path" ]] || fail published_snapshot 'V23.7.29-Published-Snapshot fehlt.'
[[ -f "$db_admin_path" ]] || fail migration 'Migrationsquelle fehlt.'

release_status="$(jq -er '.release_status | select(type == "string")' "$manifest_path")" \
    || fail manifest 'Release-Status fehlt oder ist ungueltig.'
proposed_version="$(jq -er '.proposed_version | select(type == "string")' "$manifest_path")" \
    || fail manifest 'Zielversion fehlt oder ist ungueltig.'

case "$release_status" in
    development_unreleased)
        jq -e \
            --arg version "$development_version" \
            --arg base "$published_commit" \
            '.proposed_version == $version and
            .source_base_commit == $base and
            .source_date_epoch == null and
            .test_suite_summary.status == "development_validation_required" and
            .release_artifact.reproducibility_status == "not_prepared" and
            .release_artifact.binary_sha256 == null' \
            "$manifest_path" >/dev/null \
            || fail manifest 'Development-Lifecycle-Felder sind inkonsistent.'
        ;;
    prepared_not_published)
        jq -e \
            --arg version "$development_version" \
            --arg base "$published_commit" \
            '.proposed_version == $version and
            .source_base_commit == $base and
            .source_date_epoch == null and
            .test_suite_summary.status == "validated_by_release_candidate_check_and_ci" and
            .release_artifact.reproducibility_status == "required_two_build_sha256" and
            .release_artifact.binary_sha256 == null' \
            "$manifest_path" >/dev/null \
            || fail manifest 'Release-Candidate-Lifecycle-Felder sind inkonsistent.'
        ;;
    *)
        fail manifest 'Nicht unterstuetzter Root-Release-Status.'
        ;;
esac

ISCY_RELEASE_MANIFEST_PATH="$manifest_path" \
    ./scripts/check_release_notes_completeness.sh "$notes_path"
generated_notes_path='artifacts/release-candidate/RELEASE_NOTES.md'
if [[ "$release_status" == 'prepared_not_published' \
    && "$manifest_path" == 'release/release-manifest.json' \
    && -f "$generated_notes_path" \
    && "$notes_path" != "$generated_notes_path" ]]; then
    ISCY_RELEASE_MANIFEST_PATH="$manifest_path" \
        ./scripts/check_release_notes_completeness.sh "$generated_notes_path"
fi
if [[ "${ISCY_SKIP_RELEASE_REGRESSION_TESTS:-false}" != 'true' ]]; then
    ./tests/release/test_release_notes_completeness.sh
    ./tests/release/test_release_candidate_metadata.sh
    ./tests/release/test_release_lifecycle.sh
    ./tests/release/test_release_sbom_lifecycle.sh
    ./tests/release/test_pg18_release_environment_isolation.sh
fi

jq -e '
    .schema_version == 2 and
    .source_commit == "git:HEAD" and
    (.migration_count | type) == "number" and
    .migration_count > 0 and
    .migration_count == (.migration_count | floor) and
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
    (.test_suite_summary.required_dependency_job_count | type) == "number" and
    .test_suite_summary.required_dependency_job_count == (.test_suite_summary.required_dependency_jobs | length) and
    .test_suite_summary.aggregation_job == "release-candidate-check" and
    .test_suite_summary.aggregation_job_count == 1 and
    .test_suite_summary.codeql_checks == ["actions", "javascript-typescript", "rust"] and
    .test_suite_summary.visual_baselines == 36 and
    .signature_status == "unsigned" and
    .provenance_status == "prepared_unsigned" and
    .sbom_status == "generated_cyclonedx_1.5" and
    .release_artifact.type == "linux-x86_64-glibc" and
    .release_artifact.elf_interpreter == "/lib64/ld-linux-x86-64.so.2" and
    .release_artifact.runtime_libraries == ["libgcc_s.so.1", "libm.so.6", "libc.so.6", "ld-linux-x86-64.so.2"] and
    .release_artifact.rpath_status == "absent" and
    .release_artifact.binary_sha256 == null
' "$manifest_path" >/dev/null \
    || fail manifest 'Pflichtfelder oder sichere Plattformwerte sind ungueltig.'

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

jq -e \
    --arg version "$published_version" \
    --arg commit "$published_commit" \
    '.schema_version == 1 and
    .tag_name == $version and
    .release_name == "ISCY V23.7.29" and
    .release_id == 353634425 and
    .target_commit == $commit and
    (.published_at | type) == "string" and
    (.published_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")) and
    .draft == false and
    .prerelease == false and
    .latest_at_snapshot == true and
    .immutable == true and
    .signature_status == "unsigned" and
    .provenance_status == "prepared_unsigned" and
    .asset_count == 6 and
    (.assets | length) == 6 and
    ([.assets[].name] | sort) == ["ISCY_Handbuch.pdf", "RELEASE_NOTES.md", "SHA256SUMS", "iscy-backend", "iscy-backend.cdx.json", "release-manifest.json"] and
    ([.assets[].name] | unique | length) == 6 and
    ([.assets[].asset_id] | unique | length) == 6 and
    all(.assets[];
        (.asset_id | type) == "number" and .asset_id > 0 and
        (.size_bytes | type) == "number" and .size_bytes > 0 and
        (.sha256 | type) == "string" and (.sha256 | test("^[0-9a-f]{64}$")) and
        (.content_type | type) == "string" and (.content_type | length) > 0 and
        (.download_url | type) == "string" and
        (.download_url | startswith("https://github.com/ewilhelm1979-netizen/ISCY/releases/download/V23.7.29/")) and
        (.download_url | contains("?")) == false and
        (.download_url | contains("@")) == false)' "$snapshot_path" >/dev/null \
    || fail published_snapshot 'V23.7.29-Published-Snapshot ist ungueltig.'
if grep -aEq '/home/|/nix/store/|/github/workspace/|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----' "$snapshot_path"; then
    fail published_snapshot 'Published-Snapshot enthaelt lokale Pfade oder sensitive Marker.'
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
manifest_job_count="$(jq -er '.test_suite_summary.required_dependency_job_count' "$manifest_path")"
[[ "${#ci_dependency_jobs[@]}" -eq "$manifest_job_count" ]] \
    || fail ci_jobs "Manifest erwartet $manifest_job_count CI-Pflichtabhaengigkeiten, gefunden ${#ci_dependency_jobs[@]}."
[[ "${ci_dependency_jobs[*]}" == "${manifest_dependency_jobs[*]}" ]] \
    || fail ci_jobs 'Manifest und tatsaechliche CI-Pflichtabhaengigkeiten weichen ab.'
grep -Fq 'make postgresql-18-compatibility' .github/workflows/ci.yml \
    || fail postgresql_18 'PostgreSQL-18-Kompatibilitaet fehlt in der Pflichtpipeline.'
grep -Eq '^[[:space:]]*image:[[:space:]]*postgres:16[[:space:]]*$' docker-compose.yml \
    || fail postgresql_standard 'Standard-Compose verwendet nicht eindeutig PostgreSQL 16.'
if grep -Eq '^[[:space:]]*image:[[:space:]]*postgres:18[[:space:]]*$' docker-compose.yml; then
    fail postgresql_standard 'PostgreSQL 18 darf nicht Standard im Produkt-Compose sein.'
fi

migration_count="$(jq -er '.migration_count' "$manifest_path")"
mapfile -t migration_versions < <(
    sed -nE 's/^[[:space:]]*version: "([^"]+)",[[:space:]]*$/\1/p' "$db_admin_path"
)
[[ "${#migration_versions[@]}" -eq "$migration_count" ]] \
    || fail migration_count "Manifest erwartet $migration_count Migrationen, gefunden ${#migration_versions[@]}."
declare -A seen_migration_ids=()
for index in "${!migration_versions[@]}"; do
    version="${migration_versions[$index]}"
    [[ "$version" =~ ^([0-9]{4})_[A-Za-z0-9][A-Za-z0-9_]*$ ]] \
        || fail migration_format "Ungueltige Migrationsversion an Position $((index + 1))."
    migration_id="${BASH_REMATCH[1]}"
    [[ -z "${seen_migration_ids[$migration_id]:-}" ]] \
        || fail migration_duplicate "Doppelte Migrations-ID $migration_id."
    seen_migration_ids[$migration_id]=1
    expected="$(printf '%04d' "$((index + 1))")"
    [[ "$migration_id" == "$expected" ]] \
        || fail migration_sequence "Erwartet $expected, gefunden $migration_id."
done
latest_migration="${migration_versions[-1]%%_*}"

baseline_count="$(find tests/visual/baselines -type f -name '*.png' | wc -l | tr -d ' ')"
manifest_baseline_count="$(jq -er '.test_suite_summary.visual_baselines' "$manifest_path")"
[[ "$baseline_count" -eq "$manifest_baseline_count" ]] \
    || fail visual_baselines "Manifest erwartet $manifest_baseline_count Baselines, gefunden $baseline_count."

while IFS= read -r path; do
    [[ -f "$path" ]] || fail screenshot_reference "Referenz fehlt: $path"
done < <(grep -oE 'docs/assets/[A-Za-z0-9._/-]+\.png' docs/GUI_SCREENSHOTS.md | sort -u)

sha256sum -c "$checksums_path" >/dev/null \
    || fail checksum 'Mindestens eine getrackte Release-Pruefsumme stimmt nicht.'

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

if [[ "$release_status" == 'development_unreleased' ]]; then
    printf 'DEV_METADATA_OK: %s, Basis %s, %s Migrationen bis %s, %s Baselines und Published-Snapshot sind konsistent.\n' \
        "$proposed_version" "$published_version" "$migration_count" "$latest_migration" "$baseline_count"
else
    printf 'RC_METADATA_OK: %s, %s Migrationen bis %s, %s Baselines und Release-Candidate-Metadaten sind konsistent.\n' \
        "$proposed_version" "$migration_count" "$latest_migration" "$baseline_count"
fi
