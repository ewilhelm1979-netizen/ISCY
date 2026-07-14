#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

wrapper='./scripts/run_postgresql_18_compatibility_isolated.sh'
tmp_dir="$(mktemp -d)"
cleanup() {
    rm -rf "$tmp_dir"
}
trap cleanup EXIT

fail() {
    printf 'PG18_ENV_ISOLATION_TEST_ERROR[%s]: %s\n' "$1" "$2" >&2
    exit 1
}

mkdir -p "$tmp_dir/bin"
cat >"$tmp_dir/bin/make" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

fail() {
    printf 'PG18_ENV_ISOLATION_FAKE_MAKE_ERROR[%s]: %s\n' "$1" "$2" >&2
    exit 1
}

[[ "$#" -eq 1 ]] || fail arguments 'Erwartet wird genau ein Argument.'
[[ "$1" == 'postgresql-18-compatibility' ]] \
    || fail target 'Unerwartetes Make-Target.'
[[ ! -v ISCY_POSTGRES_RESTORE_DRILL_SOURCE_URL ]] \
    || fail source_url 'SOURCE_URL ist im Kindprozess weiterhin gesetzt.'
[[ ! -v ISCY_POSTGRES_RESTORE_DRILL_RESTORE_URL ]] \
    || fail restore_url 'RESTORE_URL ist im Kindprozess weiterhin gesetzt.'
[[ "${ISCY_PG18_TEST_SENTINEL:-}" == 'sentinel-preserved' ]] \
    || fail sentinel 'Die Sentinel-Variable wurde nicht erhalten.'
[[ "${DATABASE_URL:-}" == 'postgresql://database-url-guard-preserved' ]] \
    || fail database_url 'DATABASE_URL wurde unerwartet entfernt oder veraendert.'

printf '%s\n' "$1" >"$ISCY_PG18_TEST_MARKER"
exit "${ISCY_PG18_TEST_EXIT_CODE:-0}"
EOF
chmod +x "$tmp_dir/bin/make"

export ISCY_POSTGRES_RESTORE_DRILL_SOURCE_URL='postgresql://disposable-source'
export ISCY_POSTGRES_RESTORE_DRILL_RESTORE_URL='postgresql://disposable-restore'
export ISCY_PG18_TEST_SENTINEL='sentinel-preserved'
export DATABASE_URL='postgresql://database-url-guard-preserved'

success_marker="$tmp_dir/success.marker"
PATH="$tmp_dir/bin:$PATH" \
ISCY_PG18_TEST_MARKER="$success_marker" \
    "$wrapper"

[[ -f "$success_marker" ]] \
    || fail success_marker 'Der erfolgreiche Fake-Make-Aufruf wurde nicht markiert.'
[[ "$(<"$success_marker")" == 'postgresql-18-compatibility' ]] \
    || fail success_target 'Der Marker enthaelt nicht das erwartete Target.'
[[ "$ISCY_POSTGRES_RESTORE_DRILL_SOURCE_URL" == 'postgresql://disposable-source' ]] \
    || fail parent_source 'SOURCE_URL wurde im Elternprozess veraendert.'
[[ "$ISCY_POSTGRES_RESTORE_DRILL_RESTORE_URL" == 'postgresql://disposable-restore' ]] \
    || fail parent_restore 'RESTORE_URL wurde im Elternprozess veraendert.'

failure_marker="$tmp_dir/failure.marker"
set +e
PATH="$tmp_dir/bin:$PATH" \
ISCY_PG18_TEST_MARKER="$failure_marker" \
ISCY_PG18_TEST_EXIT_CODE=23 \
    "$wrapper"
failure_status=$?
set -e

[[ "$failure_status" -eq 23 ]] \
    || fail exit_code "Erwartet Exit-Code 23, erhalten $failure_status."
[[ -f "$failure_marker" ]] \
    || fail failure_marker 'Der fehlschlagende Fake-Make-Aufruf wurde nicht markiert.'
[[ "$ISCY_POSTGRES_RESTORE_DRILL_SOURCE_URL" == 'postgresql://disposable-source' ]] \
    || fail parent_source_after_failure 'SOURCE_URL wurde nach Fehler im Elternprozess veraendert.'
[[ "$ISCY_POSTGRES_RESTORE_DRILL_RESTORE_URL" == 'postgresql://disposable-restore' ]] \
    || fail parent_restore_after_failure 'RESTORE_URL wurde nach Fehler im Elternprozess veraendert.'

echo 'PostgreSQL-18-Release-Environment-Isolationstest OK'
