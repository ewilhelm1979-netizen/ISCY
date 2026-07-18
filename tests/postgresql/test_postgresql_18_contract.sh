#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNNER="$ROOT_DIR/scripts/run_postgresql_18_compatibility.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TMP_DIR"' EXIT INT TERM

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'PG18_CONTRACT_TEST_ERROR: %s fehlt.\n' "$1" >&2
    exit 1
  }
}
require_command docker
require_command jq

clean_env=(
  env
  -u DATABASE_URL
  -u ISCY_APP_MODE
  -u ISCY_ENVIRONMENT
  -u ENVIRONMENT
  -u ISCY_POSTGRES_RESTORE_DRILL_SOURCE_URL
  -u ISCY_POSTGRES_RESTORE_DRILL_RESTORE_URL
)

ISCY_POSTGRESQL_18_PROJECT=iscy-pg18-contract \
ISCY_PG18_SOURCE_HTTP_PORT=29181 \
ISCY_PG18_TARGET_HTTP_PORT=29180 \
  "${clean_env[@]}" "$RUNNER" --validate-only >/dev/null

expect_rejected() {
  local label="$1"
  shift
  local output="$TMP_DIR/$label.log"
  if "$@" >"$output" 2>&1; then
    printf 'PG18_CONTRACT_TEST_ERROR: %s wurde nicht abgelehnt.\n' "$label" >&2
    exit 1
  fi
}

expect_rejected invalid-project \
  "${clean_env[@]}" ISCY_POSTGRESQL_18_PROJECT=production "$RUNNER" --validate-only
expect_rejected production-mode \
  "${clean_env[@]}" ISCY_POSTGRESQL_18_PROJECT=iscy-pg18-production \
  ISCY_APP_MODE=production "$RUNNER" --validate-only
expect_rejected identical-ports \
  "${clean_env[@]}" ISCY_POSTGRESQL_18_PROJECT=iscy-pg18-identical \
  ISCY_PG18_SOURCE_HTTP_PORT=29180 ISCY_PG18_TARGET_HTTP_PORT=29180 \
  "$RUNNER" --validate-only

secret_marker='pg18-contract-secret-must-not-be-logged'
printf -v external_url '%s://user:%s@external.invalid/source' postgresql "$secret_marker"
expect_rejected external-url \
  "${clean_env[@]}" ISCY_POSTGRESQL_18_PROJECT=iscy-pg18-external \
  ISCY_POSTGRES_RESTORE_DRILL_SOURCE_URL="$external_url" \
  "$RUNNER" --validate-only
if grep -R -Fq "$secret_marker" "$TMP_DIR"; then
  echo 'PG18_CONTRACT_TEST_ERROR: Ein Credential-Marker wurde ausgegeben.' >&2
  exit 1
fi

standard_config="$TMP_DIR/standard.json"
ha_config="$TMP_DIR/ha.json"
docker compose --project-name iscy-pg18-standard-contract \
  --env-file "$ROOT_DIR/.env.example" --file "$ROOT_DIR/docker-compose.yml" \
  config --format json >"$standard_config"
docker compose --project-name iscy-pg18-ha-contract \
  --env-file /dev/null --file "$ROOT_DIR/tests/resilience/docker-compose.ha.yml" \
  config --format json >"$ha_config"

jq --exit-status '
  .services.db.image == "postgres:16" and
  ((.services.db.volumes | map(select(.target == "/var/lib/postgresql/data"))) | length) == 1
' "$standard_config" >/dev/null
jq --exit-status '
  .services.postgres.image == "postgres:16" and
  ((.services.postgres.volumes | map(select(.target == "/var/lib/postgresql/data"))) | length) == 1
' "$ha_config" >/dev/null
grep -Fq 'pkgs.postgresql_16' "$ROOT_DIR/flake.nix"
grep -Fq 'pg_get_serial_sequence(' "$RUNNER"
grep -Fq 'c.contype::text' "$RUNNER"
grep -Fq "c.contype <> 'n'" "$RUNNER"
grep -Fq 'c.relkind::text' "$RUNNER"
grep -Fq "run_backend_admin app-target postgres18 \"\$RACE_DB\" seed-demo" "$RUNNER"

source_constraints="$TMP_DIR/source.constraints"
target_constraints="$TMP_DIR/target.constraints"
different_constraints="$TMP_DIR/different.constraints"
source_canonical="$TMP_DIR/source.canonical"
target_canonical="$TMP_DIR/target.canonical"
different_canonical="$TMP_DIR/different.canonical"
constraint_prefix=$'zero_trust_agent_rollout\tstatus_check\tc\ttrue\tCHECK (status::text = ANY ('
constraint_suffix='))'
printf '%s%s%s\n' \
  "$constraint_prefix" \
  "ARRAY['draft'::character varying, 'active'::character varying]::text[]" \
  "$constraint_suffix" >"$source_constraints"
printf '%s%s%s\n' \
  "$constraint_prefix" \
  "ARRAY['draft'::character varying::text, 'active'::character varying::text]" \
  "$constraint_suffix" >"$target_constraints"
printf '%s%s%s\n' \
  "$constraint_prefix" \
  "ARRAY['draft'::character varying::text, 'paused'::character varying::text]" \
  "$constraint_suffix" >"$different_constraints"

RUNNER="$RUNNER" INPUT="$source_constraints" OUTPUT="$source_canonical" \
  bash -c 'source "$RUNNER"; canonicalize_constraint_snapshot "$INPUT" >"$OUTPUT"'
RUNNER="$RUNNER" INPUT="$target_constraints" OUTPUT="$target_canonical" \
  bash -c 'source "$RUNNER"; canonicalize_constraint_snapshot "$INPUT" >"$OUTPUT"'
RUNNER="$RUNNER" INPUT="$different_constraints" OUTPUT="$different_canonical" \
  bash -c 'source "$RUNNER"; canonicalize_constraint_snapshot "$INPUT" >"$OUTPUT"'
cmp --silent "$source_canonical" "$target_canonical"
if cmp --silent "$source_canonical" "$different_canonical"; then
  echo 'PG18_CONTRACT_TEST_ERROR: Eine echte Constraint-Abweichung wurde normalisiert.' >&2
  exit 1
fi

echo 'PostgreSQL 18 compatibility guards OK'
