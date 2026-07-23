#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/tests/postgresql/docker-compose.pg18.yml"
PROJECT_NAME="${ISCY_POSTGRESQL_18_PROJECT:-iscy-pg18-${RANDOM}-$$}"
SOURCE_PORT="${ISCY_PG18_SOURCE_HTTP_PORT:-19181}"
TARGET_PORT="${ISCY_PG18_TARGET_HTTP_PORT:-19180}"
SOURCE_BASE="http://127.0.0.1:${SOURCE_PORT}"
TARGET_BASE="http://127.0.0.1:${TARGET_PORT}"
DB_USER="iscy_test"
DB_PASSWORD="iscy_test_password"
SOURCE_DB="iscy_source"
TARGET_DB="iscy_target"
OPERATOR_RESTORE_DB="iscy_operator_restore"
RACE_DB="iscy_race"
TMP_DIR="$(mktemp -d)"
RESOURCES_STARTED=0

export ISCY_PG18_BACKEND_IMAGE="${PROJECT_NAME}-backend:local"
export ISCY_PG18_SOURCE_HTTP_PORT="$SOURCE_PORT"
export ISCY_PG18_TARGET_HTTP_PORT="$TARGET_PORT"

fail() {
  local class="$1"
  local message="$2"
  printf 'PG18_COMPAT_ERROR[%s]: %s\n' "$class" "$message" >&2
  exit 1
}

compose() {
  docker compose --env-file /dev/null --project-name "$PROJECT_NAME" \
    --file "$COMPOSE_FILE" "$@"
}

cleanup() {
  if [[ "$RESOURCES_STARTED" == "1" && "$PROJECT_NAME" == iscy-pg18-* ]]; then
    compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
  rm -rf -- "$TMP_DIR"
}
trap cleanup EXIT INT TERM

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail prerequisite "$1 fehlt."
}

validate_project_name() {
  [[ "$PROJECT_NAME" =~ ^iscy-pg18-[a-z0-9][a-z0-9_-]{0,31}$ ]] \
    || fail project_name "Der Compose-Projektname ist nicht als isolierter ISCY-PG18-Testname erkennbar."
  [[ "$SOURCE_PORT" =~ ^[0-9]+$ && "$TARGET_PORT" =~ ^[0-9]+$ ]] \
    || fail ports "Die synthetischen HTTP-Ports muessen numerisch sein."
  [[ "$SOURCE_PORT" != "$TARGET_PORT" ]] \
    || fail ports "Source- und Target-HTTP-Port muessen verschieden sein."
}

validate_non_production_environment() {
  local value
  for value in "${ISCY_APP_MODE:-}" "${ISCY_ENVIRONMENT:-}" "${ENVIRONMENT:-}"; do
    case "${value,,}" in
      production|prod|stage|staging)
        fail environment "Der PostgreSQL-18-Test darf nicht in einer produktiven oder Stage-Umgebung laufen."
        ;;
    esac
  done
  [[ -z "${DATABASE_URL:-}" ]] \
    || fail environment "Eine externe DATABASE_URL ist fuer den isolierten Test nicht erlaubt."
  [[ -z "${ISCY_POSTGRES_RESTORE_DRILL_SOURCE_URL:-}" ]] \
    || fail environment "Externe Restore-Drill-URLs duerfen in diesem Test nicht gesetzt sein."
  [[ -z "${ISCY_POSTGRES_RESTORE_DRILL_RESTORE_URL:-}" ]] \
    || fail environment "Externe Restore-Drill-URLs duerfen in diesem Test nicht gesetzt sein."
}

validate_compose_contract() {
  local config_file="$TMP_DIR/compose.json"
  compose config --format json >"$config_file"

  jq --exit-status '
    (.services | keys | sort) == ["app-source", "app-target", "postgres16", "postgres18"] and
    .services.postgres16.image == "postgres:16" and
    .services.postgres18.image == "postgres:18" and
    ((.services.postgres16.ports // []) | length) == 0 and
    ((.services.postgres18.ports // []) | length) == 0 and
    ((.services.postgres16.volumes | map(select(.target == "/var/lib/postgresql/data"))) | length) == 1 and
    ((.services.postgres18.volumes | map(select(.target == "/var/lib/postgresql"))) | length) == 1 and
    ((.services.postgres18.volumes | map(select(.target == "/var/lib/postgresql/data"))) | length) == 0 and
    .services.postgres18.environment.PGDATA == "/var/lib/postgresql/18/docker" and
    .services.postgres16.volumes[0].source != .services.postgres18.volumes[0].source and
    ((.services["app-source"].ports | map(select(.host_ip == "127.0.0.1"))) | length) == 1 and
    ((.services["app-target"].ports | map(select(.host_ip == "127.0.0.1"))) | length) == 1
  ' "$config_file" >/dev/null \
    || fail compose_contract "Image-, Service-, Port- oder Volumegrenzen sind nicht fail-closed."

  if grep -Fq 'postgres:latest' "$config_file"; then
    fail compose_contract "postgres:latest ist nicht erlaubt."
  fi
}

preflight() {
  for command in docker jq curl sha256sum cmp diff gzip tar awk sed sort grep mktemp; do
    require_command "$command"
  done
  docker compose version >/dev/null 2>&1 \
    || fail prerequisite "Docker Compose v2 ist nicht verfuegbar."
  validate_project_name
  validate_non_production_environment
  validate_compose_contract
}

db_exec() {
  local service="$1"
  local database="$2"
  shift 2
  compose exec -T "$service" psql -X --username "$DB_USER" --dbname "$database" \
    --set=ON_ERROR_STOP=1 "$@"
}

db_scalar() {
  local service="$1"
  local database="$2"
  local sql="$3"
  db_exec "$service" "$database" --tuples-only --no-align --quiet --command "$sql"
}

database_url() {
  local service="$1"
  local database="$2"
  local scheme='postgresql'
  printf '%s://%s:%s@%s:5432/%s' "$scheme" "$DB_USER" "$DB_PASSWORD" "$service" "$database"
}

wait_database() {
  local service="$1"
  local database="$2"
  for _ in $(seq 1 90); do
    if compose exec -T "$service" pg_isready --username "$DB_USER" --dbname "$database" \
      >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  fail database_start "$service wurde nicht rechtzeitig bereit."
}

wait_http() {
  local base_url="$1"
  local label="$2"
  for _ in $(seq 1 120); do
    if curl --fail --silent --show-error "$base_url/health/ready" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  fail application_start "$label wurde nicht rechtzeitig bereit."
}

reset_database() {
  local service="$1"
  local database="$2"
  db_exec "$service" postgres --command \
    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$database' AND pid <> pg_backend_pid();" \
    >/dev/null
  compose exec -T "$service" dropdb --username "$DB_USER" --if-exists --force "$database"
  compose exec -T "$service" createdb --username "$DB_USER" "$database"
}

sync_owned_sequences() {
  local service="$1"
  local database="$2"
  db_exec "$service" "$database" --quiet >/dev/null <<'SQL'
DO $sync$
DECLARE
  sequence_column record;
  maximum_id bigint;
BEGIN
  FOR sequence_column IN
    SELECT
      table_schema,
      table_name,
      column_name,
      pg_get_serial_sequence(
        format('%I.%I', table_schema, table_name),
        column_name
      ) AS sequence_name
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND pg_get_serial_sequence(
        format('%I.%I', table_schema, table_name),
        column_name
      ) IS NOT NULL
  LOOP
    EXECUTE format(
      'SELECT COALESCE(MAX(%I), 0) FROM %I.%I',
      sequence_column.column_name,
      sequence_column.table_schema,
      sequence_column.table_name
    ) INTO maximum_id;
    PERFORM setval(
      sequence_column.sequence_name::regclass,
      GREATEST(maximum_id, 1),
      maximum_id > 0
    );
  END LOOP;
END
$sync$;
SQL
}

run_backend_admin() {
  local app_service="$1"
  local database_service="$2"
  local database="$3"
  local command="$4"
  local url
  url="$(database_url "$database_service" "$database")"
  compose run --rm --no-deps --env "DATABASE_URL=$url" "$app_service" \
    /usr/local/bin/iscy-backend "$command"
}

migration_versions() {
  local service="$1"
  local database="$2"
  db_exec "$service" "$database" --tuples-only --no-align --quiet \
    --command 'SELECT version FROM iscy_schema_migrations ORDER BY version;'
}

assert_migrations() {
  local service="$1"
  local database="$2"
  local count
  count="$(db_scalar "$service" "$database" 'SELECT COUNT(*) FROM iscy_schema_migrations;')"
  [[ "$count" == "44" ]] || fail migrations "Erwartet 44 Migrationen, gefunden $count."
  local latest
  latest="$(db_scalar "$service" "$database" 'SELECT MAX(version) FROM iscy_schema_migrations;')"
  [[ "$latest" == 0044_* ]] || fail migrations "Die erwartete Migration 0044 fehlt."
}

snapshot_database() {
  local service="$1"
  local database="$2"
  local prefix="$3"

  db_exec "$service" "$database" --tuples-only --no-align --quiet \
    --command "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY table_name;" \
    >"$prefix.tables"

  : >"$prefix.rows"
  local table_name
  while IFS= read -r table_name; do
    [[ "$table_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] \
      || fail integrity "Unerwarteter Tabellenname im public-Schema."
    db_exec "$service" "$database" --tuples-only --no-align --quiet \
      --command "
        SELECT '$table_name' || chr(9) || count(*)::text || chr(9) ||
               md5(COALESCE(string_agg(to_jsonb(row_value)::text, chr(10)
                   ORDER BY to_jsonb(row_value)::text), ''))
        FROM public.\"$table_name\" AS row_value;
      " >>"$prefix.rows"
  done <"$prefix.tables"

  db_exec "$service" "$database" --tuples-only --no-align --quiet \
    --command "
      SELECT table_name || chr(9) || ordinal_position || chr(9) || column_name || chr(9) ||
             data_type || chr(9) || udt_name || chr(9) || is_nullable || chr(9) || COALESCE(column_default, '')
      FROM information_schema.columns
      WHERE table_schema = 'public'
      ORDER BY table_name, ordinal_position;
    " >"$prefix.columns"

  db_exec "$service" "$database" --tuples-only --no-align --quiet \
    --command "
      SELECT c.conrelid::regclass::text || chr(9) || c.conname || chr(9) || c.contype::text || chr(9) ||
             c.convalidated::text || chr(9) || pg_get_constraintdef(c.oid, true)
      FROM pg_constraint c
      JOIN pg_namespace n ON n.oid = c.connamespace
      WHERE n.nspname = 'public'
        AND c.contype <> 'n'
      ORDER BY c.conrelid::regclass::text, c.conname;
    " >"$prefix.constraints"

  db_exec "$service" "$database" --tuples-only --no-align --quiet \
    --command "
      SELECT schemaname || chr(9) || tablename || chr(9) || indexname || chr(9) || indexdef
      FROM pg_indexes
      WHERE schemaname = 'public'
      ORDER BY tablename, indexname;
    " >"$prefix.indexes"

  local sequence_names="$prefix.sequence-names"
  db_exec "$service" "$database" --tuples-only --no-align --quiet \
    --command "SELECT sequencename FROM pg_sequences WHERE schemaname = 'public' ORDER BY sequencename;" \
    >"$sequence_names"
  : >"$prefix.sequences"
  local sequence_name
  while IFS= read -r sequence_name; do
    [[ "$sequence_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] \
      || fail integrity "Unerwarteter Sequenzname im public-Schema."
    db_exec "$service" "$database" --tuples-only --no-align --quiet \
      --command "
        SELECT '$sequence_name' || chr(9) || last_value::text || chr(9) || is_called::text
        FROM public.\"$sequence_name\";
      " >>"$prefix.sequences"
  done <"$sequence_names"
  rm -f -- "$sequence_names"

  db_exec "$service" "$database" --tuples-only --no-align --quiet \
    --command "
      SELECT c.relkind::text || chr(9) || c.relname
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind IN ('r', 'S', 'i', 'v', 'm', 'p')
      ORDER BY c.relkind, c.relname;
    " >"$prefix.objects"

  local suffix
  for suffix in tables rows columns constraints indexes sequences objects; do
    LC_ALL=C sort -o "$prefix.$suffix" "$prefix.$suffix"
  done
}

canonicalize_constraint_snapshot() {
  LC_ALL=C sed -E \
    -e 's/::character varying::text/::character varying/g' \
    -e 's/(ARRAY\[[^]]*::character varying[^]]*\])::text\[\]/\1/g' \
    "$1"
}

compare_snapshots() {
  local source_prefix="$1"
  local target_prefix="$2"
  local suffix
  for suffix in tables rows columns constraints indexes sequences objects; do
    local source_snapshot="$source_prefix.$suffix"
    local target_snapshot="$target_prefix.$suffix"
    if [[ "$suffix" == "constraints" ]]; then
      source_snapshot="$TMP_DIR/source-constraints.canonical"
      target_snapshot="$TMP_DIR/target-constraints.canonical"
      canonicalize_constraint_snapshot "$source_prefix.$suffix" >"$source_snapshot"
      canonicalize_constraint_snapshot "$target_prefix.$suffix" >"$target_snapshot"
    fi
    if ! cmp --silent "$source_snapshot" "$target_snapshot"; then
      diff --unified "$source_snapshot" "$target_snapshot" >&2 || true
      fail integrity "Datenbankvergleich fuer $suffix ist abgewichen."
    fi
  done
}

check_referential_integrity() {
  local service="$1"
  local database="$2"
  local invalid_constraints
  invalid_constraints="$(db_scalar "$service" "$database" "
    SELECT COUNT(*) FROM pg_constraint c
    JOIN pg_namespace n ON n.oid = c.connamespace
    WHERE n.nspname = 'public' AND NOT c.convalidated;
  ")"
  [[ "$invalid_constraints" == "0" ]] \
    || fail constraints "Nicht validierte Constraints wurden gefunden."

  db_exec "$service" "$database" --quiet >/dev/null <<'SQL'
DO $check$
DECLARE
  foreign_key record;
  join_predicate text;
  non_null_predicate text;
  orphan_exists boolean;
BEGIN
  FOR foreign_key IN
    SELECT c.oid, c.conrelid, c.confrelid,
           child_ns.nspname AS child_schema, child.relname AS child_table,
           parent_ns.nspname AS parent_schema, parent.relname AS parent_table,
           c.conkey, c.confkey
    FROM pg_constraint c
    JOIN pg_class child ON child.oid = c.conrelid
    JOIN pg_namespace child_ns ON child_ns.oid = child.relnamespace
    JOIN pg_class parent ON parent.oid = c.confrelid
    JOIN pg_namespace parent_ns ON parent_ns.oid = parent.relnamespace
    WHERE c.contype = 'f' AND child_ns.nspname = 'public'
  LOOP
    SELECT
      string_agg(format('child.%I = parent.%I', child_attribute.attname, parent_attribute.attname), ' AND ' ORDER BY key.ordinality),
      string_agg(format('child.%I IS NOT NULL', child_attribute.attname), ' AND ' ORDER BY key.ordinality)
    INTO join_predicate, non_null_predicate
    FROM unnest(foreign_key.conkey, foreign_key.confkey) WITH ORDINALITY
      AS key(child_number, parent_number, ordinality)
    JOIN pg_attribute child_attribute
      ON child_attribute.attrelid = foreign_key.conrelid AND child_attribute.attnum = key.child_number
    JOIN pg_attribute parent_attribute
      ON parent_attribute.attrelid = foreign_key.confrelid AND parent_attribute.attnum = key.parent_number;

    EXECUTE format(
      'SELECT EXISTS (SELECT 1 FROM %I.%I child WHERE (%s) AND NOT EXISTS (SELECT 1 FROM %I.%I parent WHERE %s))',
      foreign_key.child_schema,
      foreign_key.child_table,
      non_null_predicate,
      foreign_key.parent_schema,
      foreign_key.parent_table,
      join_predicate
    ) INTO orphan_exists;

    IF orphan_exists THEN
      RAISE EXCEPTION 'orphaned foreign key rows detected';
    END IF;
  END LOOP;
END
$check$;
SQL
}

check_domain_invariants() {
  local service="$1"
  local database="$2"
  [[ "$(db_scalar "$service" "$database" "SELECT COUNT(*) FROM organizations_tenant WHERE id = 1 AND slug = 'demo';")" == "1" ]] \
    || fail domain_invariant "Demo-Tenant fehlt."
  [[ "$(db_scalar "$service" "$database" "SELECT COUNT(*) FROM accounts_user WHERE tenant_id = 1 AND username = 'admin' AND role = 'ADMIN' AND is_active;")" == "1" ]] \
    || fail domain_invariant "Tenantgebundener Admin fehlt."
  [[ "$(db_scalar "$service" "$database" "SELECT COUNT(*) FROM risks_risk WHERE tenant_id = 1;")" -gt "0" ]] \
    || fail domain_invariant "Risiken fehlen."
  [[ "$(db_scalar "$service" "$database" "SELECT COUNT(*) FROM evidence_evidenceitem WHERE tenant_id = 1 AND file_sha256 <> '';")" -gt "0" ]] \
    || fail domain_invariant "Evidence-Hashdaten fehlen."
}

login() {
  local base_url="$1"
  local cookie_file="$2"
  local username="$3"
  curl --fail --silent --show-error --cookie-jar "$cookie_file" \
    --header 'content-type: application/json' \
    --data "{\"tenant_id\":1,\"username\":\"$username\",\"password\":\"Admin123!\"}" \
    "$base_url/api/v1/auth/sessions" >/dev/null
}

expect_status() {
  local expected="$1"
  shift
  local actual
  local target="${!#}"
  actual="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' "$@")"
  [[ "$actual" == "$expected" ]] \
    || fail http_status "HTTP $expected fuer $target erwartet, HTTP $actual erhalten."
}

application_smoke() {
  local base_url="$1"
  local label="$2"
  local cookie_file="$TMP_DIR/${label}-admin.cookies"
  local contributor_cookie="$TMP_DIR/${label}-contributor.cookies"
  local evidence_file="$TMP_DIR/${label}-evidence.txt"
  local invalid_code

  curl --fail --silent --show-error "$base_url/health/live" >/dev/null
  curl --fail --silent --show-error "$base_url/health/ready" >/dev/null
  curl --fail --silent --show-error "$base_url/health/startup" >/dev/null

  invalid_code="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
    --header 'content-type: application/json' \
    --data '{"tenant_id":1,"username":"admin","password":"invalid"}' \
    "$base_url/api/v1/auth/sessions")"
  [[ "$invalid_code" == "401" ]] || fail authentication "Ungueltiger Login wurde nicht mit 401 abgelehnt."
  expect_status 401 "$base_url/api/v1/risks"

  login "$base_url" "$cookie_file" admin
  login "$base_url" "$contributor_cookie" ops-alertmanager
  expect_status 403 --cookie "$contributor_cookie" \
    "$base_url/api/v1/accounts/users"

  local path
  for path in \
    /dashboard/ /risks/ /controls/ /incidents/ /evidence/ \
    /suppliers/product-security/ /product-security/ /regulatory-review-packs/ \
    /zero-trust/ /security-observations/ /status/ /status/operations.json; do
    expect_status 200 --cookie "$cookie_file" "$base_url$path"
  done
  for path in \
    /api/v1/risks /api/v1/controls /api/v1/incidents /api/v1/evidence \
    /api/v1/suppliers/product-security /api/v1/product-security/overview \
    /api/v1/threat-intelligence/indicators /api/v1/security-observations \
    /api/v1/status/operations; do
    expect_status 200 --cookie "$cookie_file" "$base_url$path"
  done
  curl --fail --silent --show-error --cookie "$cookie_file" \
    --header 'content-type: application/json' --data '{}' \
    "$base_url/api/v1/regulatory/review-packs/nis2/preview" >/dev/null

  local indicator_response indicator_id observation_response observation_id
  indicator_response="$(curl --fail --silent --show-error --cookie "$cookie_file" \
    --header 'content-type: application/json' \
    --data "{\"indicator_type\":\"DOMAIN\",\"value\":\"$label.invalid\",\"source_type\":\"MANUAL\",\"source_name\":\"PostgreSQL compatibility\",\"provenance_reference\":\"pg:$label\",\"confidence\":70,\"valid_from\":\"2026-07-22T00:00:00Z\",\"valid_until\":null,\"classification\":\"INTERNAL\"}" \
    "$base_url/api/v1/threat-intelligence/indicators")"
  indicator_id="$(printf '%s' "$indicator_response" | jq --exit-status --raw-output '.data.indicator.id')"
  [[ "$indicator_id" =~ ^[0-9]+$ ]] || fail application_write "Indicator-ID ist ungueltig."
  observation_response="$(curl --fail --silent --show-error --cookie "$cookie_file" \
    --header 'content-type: application/json' \
    --data "{\"source_type\":\"MANUAL\",\"source_reference\":\"pg:$label:observation\",\"asset_id\":null,\"deduplication_key\":\"pg:$label:observation\",\"observed_at\":\"2026-07-22T00:01:00Z\",\"category\":\"THREAT_ACTIVITY\",\"severity\":\"MEDIUM\",\"title\":\"PostgreSQL compatibility observation\",\"description\":\"Synthetic bounded test record\",\"attributes\":{\"test_scope\":\"postgresql_compatibility\"},\"provenance_type\":\"MANUAL\",\"provenance_reference\":\"pg:$label\",\"owner_id\":null}" \
    "$base_url/api/v1/security-observations")"
  observation_id="$(printf '%s' "$observation_response" | jq --exit-status --raw-output '.data.observation.id')"
  [[ "$observation_id" =~ ^[0-9]+$ ]] || fail application_write "Observation-ID ist ungueltig."
  curl --fail --silent --show-error --cookie "$cookie_file" \
    --header 'content-type: application/json' \
    --data "{\"indicator_id\":$indicator_id,\"match_type\":\"CONTEXTUAL\",\"rationale\":\"PostgreSQL compatibility test\"}" \
    "$base_url/api/v1/security-observations/$observation_id/indicator-links" >/dev/null

  local risk_payload="$TMP_DIR/${label}-risk.json"
  jq --null-input --arg title "PostgreSQL 18 $label Risk" '{
    category_id:1,
    process_id:1,
    asset_id:1,
    owner_id:1,
    title:$title,
    description:"Disposable compatibility test",
    threat:"Database upgrade regression",
    vulnerability:"Untested database major version",
    impact:3,
    likelihood:2,
    residual_impact:1,
    residual_likelihood:1,
    status:"ANALYZING",
    treatment_strategy:"MITIGATE",
    treatment_plan:"Run compatibility validation",
    treatment_due_date:"2026-12-01",
    review_date:"2026-12-15"
  }' >"$risk_payload"
  local risk_response
  risk_response="$(curl --fail --silent --show-error --cookie "$cookie_file" \
    --header 'content-type: application/json' --data "@$risk_payload" \
    "$base_url/api/v1/risks")"
  local risk_id
  risk_id="$(printf '%s' "$risk_response" | jq --exit-status --raw-output '.risk.id')"
  [[ "$risk_id" =~ ^[0-9]+$ ]] || fail application_write "Risiko-ID ist ungueltig."
  curl --fail --silent --show-error --cookie "$cookie_file" \
    "$base_url/api/v1/risks/$risk_id" >/dev/null
  curl --fail --silent --show-error --cookie "$cookie_file" --request PATCH \
    --header 'content-type: application/json' \
    --data '{"status":"TREATING","impact":2}' \
    "$base_url/api/v1/risks/$risk_id" >/dev/null

  printf 'ISCY PostgreSQL 18 synthetic Evidence\n' >"$evidence_file"
  local upload_response
  upload_response="$(curl --fail --silent --show-error --cookie "$cookie_file" \
    --form "title=PostgreSQL 18 $label Evidence" --form 'status=SUBMITTED' \
    --form 'sensitivity=INTERNAL' \
    --form "file=@$evidence_file;filename=pg18-$label-evidence.txt;type=text/plain" \
    "$base_url/api/v1/evidence/uploads")"
  local evidence_id
  evidence_id="$(printf '%s' "$upload_response" | jq --exit-status --raw-output '.item.id')"
  [[ "$evidence_id" =~ ^[0-9]+$ ]] || fail evidence "Evidence-ID ist ungueltig."
  LAST_EVIDENCE_FILE_NAME="$(printf '%s' "$upload_response" | jq --exit-status --raw-output '.item.file_name')"
  [[ "$LAST_EVIDENCE_FILE_NAME" =~ ^[A-Za-z0-9._/-]+$ \
    && "$LAST_EVIDENCE_FILE_NAME" != /* \
    && "$LAST_EVIDENCE_FILE_NAME" != *..* ]] \
    || fail evidence "Der synthetische Evidence-Pfad ist nicht sicher relativ."

  curl --fail --silent --show-error --cookie "$cookie_file" --request POST \
    "$base_url/api/v1/auth/logout" >/dev/null
  expect_status 401 --cookie "$cookie_file" "$base_url/api/v1/risks"
}

create_custom_dump() {
  local dump_file="$1"
  local client_version
  client_version="$(compose exec -T postgres18 pg_dump --version)"
  [[ "$client_version" == *"PostgreSQL) 18."* ]] \
    || fail dump_client "Der logische Dump wird nicht mit PostgreSQL-18-Werkzeugen erstellt."
  compose exec -T --env "PGPASSWORD=$DB_PASSWORD" postgres18 \
    pg_dump --host postgres16 --username "$DB_USER" --dbname "$SOURCE_DB" \
    --format=custom --no-owner --no-privileges --quote-all-identifiers >"$dump_file"
  chmod 600 "$dump_file"
  [[ -s "$dump_file" ]] || fail dump "Der Custom-Dump ist leer."
  compose exec -T postgres18 pg_restore --list <"$dump_file" >/dev/null
}

restore_custom_dump() {
  local dump_file="$1"
  reset_database postgres18 "$TARGET_DB"
  compose exec -T postgres18 pg_restore --exit-on-error --no-owner --no-privileges \
    --username "$DB_USER" --dbname "$TARGET_DB" <"$dump_file"
  db_exec postgres18 "$TARGET_DB" --command 'ANALYZE;' >/dev/null
  run_backend_admin app-target postgres18 "$TARGET_DB" migrate >"$TMP_DIR/target-migrate.log" 2>&1
  assert_migrations postgres18 "$TARGET_DB"
  run_backend_admin app-target postgres18 "$TARGET_DB" migrate >"$TMP_DIR/target-migrate-second.log" 2>&1
  assert_migrations postgres18 "$TARGET_DB"
}

create_operator_backup() {
  local backup_dir="$1"
  mkdir -p "$backup_dir"
  chmod 700 "$backup_dir"
  compose exec -T --env "PGPASSWORD=$DB_PASSWORD" postgres18 \
    pg_dump --host postgres16 --username "$DB_USER" --dbname "$SOURCE_DB" \
    --format=plain --no-owner --no-privileges --quote-all-identifiers \
    | gzip -c >"$backup_dir/postgres.sql.gz"
  compose run --rm --no-deps --entrypoint sh app-source \
    -c 'test -d /app/media && tar -C /app -czf - media' \
    >"$backup_dir/storage.tar.gz"
  cat >"$backup_dir/manifest.txt" <<'EOF'
source_major=16
target_major=18
includes=postgres.sql.gz,storage.tar.gz
environment_snapshot_included=false
contains_production_data=false
EOF
  (
    cd "$backup_dir"
    sha256sum postgres.sql.gz storage.tar.gz manifest.txt >SHA256SUMS
    chmod 600 postgres.sql.gz storage.tar.gz manifest.txt SHA256SUMS
    sha256sum --check SHA256SUMS >/dev/null
    gzip --test postgres.sql.gz
    tar --list --gzip --file storage.tar.gz >/dev/null
  )
}

validate_and_restore_media() {
  local backup_dir="$1"
  local member
  while IFS= read -r member; do
    [[ -n "$member" && "$member" != /* && "$member" != ../* && "$member" != */../* ]] \
      || fail media_archive "Das Media-Archiv enthaelt einen unsicheren Pfad."
  done < <(tar --list --gzip --file "$backup_dir/storage.tar.gz")
  if tar --list --verbose --gzip --file "$backup_dir/storage.tar.gz" \
    | awk 'substr($1, 1, 1) == "l" || substr($1, 1, 1) == "h" { found = 1 } END { exit(found ? 0 : 1) }'; then
    fail media_archive "Symlinks oder Hardlinks sind im Test-Media-Archiv nicht erlaubt."
  fi
  cat "$backup_dir/storage.tar.gz" | compose run --rm --no-deps --entrypoint sh app-target \
    -c 'find /app/media -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +; tar -C /app -xzf -'
  local restored_hash
  restored_hash="$(compose run --rm --no-deps --entrypoint sha256sum app-target "/app/media/$SOURCE_EVIDENCE_FILE_NAME" | awk '{print $1}')"
  [[ "$restored_hash" == "$SOURCE_EVIDENCE_SHA256" ]] \
    || fail media_integrity "Die wiederhergestellte Evidence-Datei weicht ab."
}

restore_operator_backup() {
  local backup_dir="$1"
  reset_database postgres18 "$OPERATOR_RESTORE_DB"
  gunzip -c "$backup_dir/postgres.sql.gz" | db_exec postgres18 "$OPERATOR_RESTORE_DB" >/dev/null
  db_exec postgres18 "$OPERATOR_RESTORE_DB" --command 'ANALYZE;' >/dev/null
  run_backend_admin app-target postgres18 "$OPERATOR_RESTORE_DB" migrate \
    >"$TMP_DIR/operator-migrate.log" 2>&1
  assert_migrations postgres18 "$OPERATOR_RESTORE_DB"
}

run_oneoff_backend() {
  local database="$1"
  local label="$2"
  local container_id
  local url
  url="$(database_url postgres18 "$database")"
  compose stop --timeout 25 app-target >/dev/null 2>&1 || true
  container_id="$(compose run --detach --no-deps --service-ports \
    --env "DATABASE_URL=$url" app-target)"
  [[ -n "$container_id" ]] || fail application_start "$label konnte nicht gestartet werden."
  wait_http "$TARGET_BASE" "$label"
  local cookie_file="$TMP_DIR/${label}.cookies"
  login "$TARGET_BASE" "$cookie_file" admin
  curl --fail --silent --show-error --cookie "$cookie_file" \
    "$TARGET_BASE/api/v1/evidence" >/dev/null
  docker stop --time 25 "$container_id" >/dev/null
  [[ "$(docker inspect --format '{{.State.ExitCode}}' "$container_id")" == "0" ]] \
    || fail application_shutdown "$label wurde nicht kontrolliert beendet."
  docker rm "$container_id" >/dev/null
}

run_migration_race() {
  reset_database postgres18 "$RACE_DB"
  local race_url
  race_url="$(database_url postgres18 "$RACE_DB")"
  compose run --rm --no-deps --env "DATABASE_URL=$race_url" app-target \
    /usr/local/bin/iscy-backend migrate >"$TMP_DIR/race-a.log" 2>&1 &
  local race_a_pid=$!
  compose run --rm --no-deps --env "DATABASE_URL=$race_url" app-target \
    /usr/local/bin/iscy-backend migrate >"$TMP_DIR/race-b.log" 2>&1 &
  local race_b_pid=$!
  local failed=0
  wait "$race_a_pid" || failed=1
  wait "$race_b_pid" || failed=1
  if [[ "$failed" != "0" ]]; then
    sed -E 's#postgresql://[^ ]+#<redacted-database-url>#g' \
      "$TMP_DIR/race-a.log" "$TMP_DIR/race-b.log" >&2
    fail migration_race "Mindestens ein paralleler Migrationsprozess ist fehlgeschlagen."
  fi
  assert_migrations postgres18 "$RACE_DB"
  [[ "$(db_scalar postgres18 "$RACE_DB" "SELECT COUNT(*) FROM pg_locks WHERE locktype = 'advisory' AND granted;")" == "0" ]] \
    || fail migration_race "Ein Advisory Lock blieb nach dem Test bestehen."
  check_referential_integrity postgres18 "$RACE_DB"
  run_backend_admin app-target postgres18 "$RACE_DB" seed-demo \
    >"$TMP_DIR/race-seed.log" 2>&1
  sync_owned_sequences postgres18 "$RACE_DB"
  run_oneoff_backend "$RACE_DB" race-backend
}

scan_logs_for_secrets() {
  compose logs --no-color app-source app-target >"$TMP_DIR/application.log" 2>&1 || true
  if grep -Fq "$DB_PASSWORD" "$TMP_DIR/application.log" \
    || grep -Fq 'postgresql://' "$TMP_DIR/application.log"; then
    fail secret_redaction "Anwendungslogs enthalten Datenbank-Credentials oder Connection Strings."
  fi
}

main() {
  preflight
  if [[ "${1:-}" == "--validate-only" ]]; then
    echo 'PostgreSQL 18 compatibility contract OK'
    return 0
  fi
  [[ $# -eq 0 ]] || fail usage "Unterstuetzt wird nur --validate-only oder ein Lauf ohne Argumente."
  docker info >/dev/null 2>&1 || fail docker_daemon "Ein erreichbarer isolierter Container-Daemon ist erforderlich."

  RESOURCES_STARTED=1
  compose up --detach postgres16 postgres18
  wait_database postgres16 "$SOURCE_DB"
  wait_database postgres18 "$TARGET_DB"
  compose build app-source

  local source_version source_version_num source_data_dir source_pg_version
  local target_version target_version_num target_data_dir target_pg_version
  source_version="$(db_scalar postgres16 postgres "SHOW server_version;")"
  source_version_num="$(db_scalar postgres16 postgres "SHOW server_version_num;")"
  source_data_dir="$(db_scalar postgres16 postgres "SHOW data_directory;")"
  source_pg_version="$(compose exec -T postgres16 cat /var/lib/postgresql/data/PG_VERSION)"
  target_version="$(db_scalar postgres18 postgres "SHOW server_version;")"
  target_version_num="$(db_scalar postgres18 postgres "SHOW server_version_num;")"
  target_data_dir="$(db_scalar postgres18 postgres "SHOW data_directory;")"
  target_pg_version="$(compose exec -T postgres18 cat /var/lib/postgresql/18/docker/PG_VERSION)"
  [[ "$source_version_num" =~ ^16[0-9]{4}$ && "$source_pg_version" == "16" \
    && "$source_data_dir" == "/var/lib/postgresql/data" ]] \
    || fail version "Die Quellinstanz entspricht nicht PostgreSQL 16 mit dem alten Volumeziel."
  [[ "$target_version_num" =~ ^18[0-9]{4}$ && "$target_pg_version" == "18" \
    && "$target_data_dir" == "/var/lib/postgresql/18/docker" ]] \
    || fail version "Die Zielinstanz entspricht nicht PostgreSQL 18 mit dem neuen Volumeziel."

  run_backend_admin app-target postgres18 "$TARGET_DB" init-demo >"$TMP_DIR/fresh-init.log" 2>&1
  sync_owned_sequences postgres18 "$TARGET_DB"
  assert_migrations postgres18 "$TARGET_DB"
  local fresh_versions="$TMP_DIR/fresh-migrations.txt"
  migration_versions postgres18 "$TARGET_DB" >"$fresh_versions"
  run_backend_admin app-target postgres18 "$TARGET_DB" migrate >"$TMP_DIR/fresh-second.log" 2>&1
  assert_migrations postgres18 "$TARGET_DB"
  migration_versions postgres18 "$TARGET_DB" | cmp --silent "$fresh_versions" - \
    || fail migrations "Der zweite PostgreSQL-18-Migrationslauf hat den Stand veraendert."
  compose up --detach --no-deps app-target
  wait_http "$TARGET_BASE" "Frisches PostgreSQL-18-Backend"
  application_smoke "$TARGET_BASE" fresh
  local target_tenant_count
  target_tenant_count="$(db_scalar postgres18 "$TARGET_DB" 'SELECT COUNT(*) FROM organizations_tenant;')"
  compose restart postgres18 >/dev/null
  wait_database postgres18 "$TARGET_DB"
  wait_http "$TARGET_BASE" "PostgreSQL-18-Backend nach Restart"
  [[ "$(db_scalar postgres18 "$TARGET_DB" 'SELECT COUNT(*) FROM organizations_tenant;')" == "$target_tenant_count" ]] \
    || fail restart "Bestandsdaten fehlen nach PostgreSQL-18-Restart."
  compose stop --timeout 25 app-target >/dev/null

  run_backend_admin app-source postgres16 "$SOURCE_DB" init-demo >"$TMP_DIR/source-init.log" 2>&1
  sync_owned_sequences postgres16 "$SOURCE_DB"
  assert_migrations postgres16 "$SOURCE_DB"
  compose up --detach --no-deps app-source
  wait_http "$SOURCE_BASE" "PostgreSQL-16-Quellbackend"
  application_smoke "$SOURCE_BASE" source
  SOURCE_EVIDENCE_FILE_NAME="$LAST_EVIDENCE_FILE_NAME"
  SOURCE_EVIDENCE_SHA256="$(printf 'ISCY PostgreSQL 18 synthetic Evidence\n' | sha256sum | awk '{print $1}')"
  export SOURCE_EVIDENCE_FILE_NAME SOURCE_EVIDENCE_SHA256
  check_domain_invariants postgres16 "$SOURCE_DB"
  check_referential_integrity postgres16 "$SOURCE_DB"
  compose stop --timeout 25 app-source >/dev/null

  local source_snapshot="$TMP_DIR/source"
  local target_snapshot="$TMP_DIR/target"
  snapshot_database postgres16 "$SOURCE_DB" "$source_snapshot"

  local custom_dump="$TMP_DIR/iscy-16-to-18.dump"
  create_custom_dump "$custom_dump"
  restore_custom_dump "$custom_dump"
  snapshot_database postgres18 "$TARGET_DB" "$target_snapshot"
  compare_snapshots "$source_snapshot" "$target_snapshot"
  check_referential_integrity postgres18 "$TARGET_DB"
  check_domain_invariants postgres18 "$TARGET_DB"

  compose up --detach --no-deps app-target
  wait_http "$TARGET_BASE" "Wiederhergestelltes PostgreSQL-18-Backend"
  application_smoke "$TARGET_BASE" restored
  compose stop --timeout 25 app-target >/dev/null

  local backup_dir="$TMP_DIR/operator-backup"
  create_operator_backup "$backup_dir"
  validate_and_restore_media "$backup_dir"
  restore_operator_backup "$backup_dir"
  local operator_snapshot="$TMP_DIR/operator"
  snapshot_database postgres18 "$OPERATOR_RESTORE_DB" "$operator_snapshot"
  compare_snapshots "$source_snapshot" "$operator_snapshot"
  check_referential_integrity postgres18 "$OPERATOR_RESTORE_DB"
  check_domain_invariants postgres18 "$OPERATOR_RESTORE_DB"
  run_oneoff_backend "$OPERATOR_RESTORE_DB" operator-restore-backend

  run_migration_race
  scan_logs_for_secrets

  local table_count row_count
  table_count="$(wc -l <"$source_snapshot.tables" | tr -d ' ')"
  row_count="$(awk -F '\t' '{sum += $2} END {print sum + 0}' "$source_snapshot.rows")"
  printf 'PostgreSQL 18 compatibility and upgrade validation OK\n'
  printf 'source_server_version=%s\n' "$source_version"
  printf 'target_server_version=%s\n' "$target_version"
  printf 'target_data_directory=%s\n' "$target_data_dir"
  printf 'migration_count=44\n'
  printf 'application_table_count=%s\n' "$table_count"
  printf 'application_row_count=%s\n' "$row_count"
  printf 'integrity=rows,content_hashes,sequences,constraints,indexes,foreign_keys,media\n'
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
