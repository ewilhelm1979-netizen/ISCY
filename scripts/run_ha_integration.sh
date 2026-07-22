#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STACK="$ROOT_DIR/scripts/resilience_stack.sh"
TMP_DIR="$(mktemp -d)"
export ISCY_RESILIENCE_PROJECT="iscy-ha-$RANDOM-$$"

cleanup() {
  "$STACK" down >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

BASE_A="http://127.0.0.1:19101"
BASE_B="http://127.0.0.1:19102"
BASE_PROXY="http://127.0.0.1:19100"
COOKIE="$TMP_DIR/session.cookies"
EVIDENCE_FILE="$TMP_DIR/evidence.txt"
DOWNLOAD_FILE="$TMP_DIR/download.txt"

printf 'ISCY synthetischer HA-Evidence-Test\n' >"$EVIDENCE_FILE"
"$STACK" up

curl --fail --silent --show-error --cookie-jar "$COOKIE" \
  --header "content-type: application/json" \
  --data '{"tenant_id":1,"username":"admin","password":"Admin123!"}' \
  "$BASE_A/api/v1/auth/sessions" >/dev/null

curl --fail --silent --show-error --cookie "$COOKIE" \
  --request PATCH --header "content-type: application/json" \
  --data '{"status":"IN_PROGRESS","planned_start":"2026-05-02","due_date":"2026-05-15","notes":"Synthetischer HA-Test"}' \
  "$BASE_A/api/v1/roadmap/tasks/1" >/dev/null
curl --fail --silent --show-error --cookie "$COOKIE" \
  "$BASE_B/api/v1/roadmap/plans/1" >/dev/null

curl --fail --silent --show-error --cookie "$COOKIE" \
  --header "content-type: application/json" \
  --data @- "$BASE_A/api/v1/evidence/storage/backends" >/dev/null <<'JSON'
{
  "backend_id": "ha-s3",
  "backend_type": "s3_compatible",
  "display_name": "HA Test Object Storage",
  "status": "validation_required",
  "endpoint_reference": "http://minio:9000",
  "region": "us-east-1",
  "bucket_name": "iscy-ha-evidence",
  "key_prefix": "ha-test",
  "access_key_secret_ref": "env:ISCY_TEST_S3_ACCESS_KEY",
  "secret_key_secret_ref": "env:ISCY_TEST_S3_SECRET_KEY",
  "tls_required": false,
  "allow_path_style": true,
  "allowed_endpoint_policy": "local_dev_only",
  "known_limitations": "Ausschliesslich isolierter lokaler HA-Test."
}
JSON
curl --fail --silent --show-error --cookie "$COOKIE" --request POST \
  "$BASE_A/api/v1/evidence/storage/backends/ha-s3/validate" >/dev/null
curl --fail --silent --show-error --cookie "$COOKIE" --request POST \
  "$BASE_A/api/v1/evidence/storage/backends/ha-s3/validate-live" >/dev/null

upload_json="$(curl --fail --silent --show-error --cookie "$COOKIE" \
  --form 'title=HA Evidence' --form 'status=SUBMITTED' \
  --form 'sensitivity=INTERNAL' --form 'storage_backend_id=ha-s3' \
  --form 'valid_until=2027-01-31' --form 'retention_until=2028-01-31' \
  --form "file=@$EVIDENCE_FILE;filename=ha-evidence.txt;type=text/plain" \
  "$BASE_A/api/v1/evidence/uploads")"
evidence_id="$(printf '%s' "$upload_json" | jq --exit-status --raw-output '.item.id')"

curl --fail --silent --show-error --cookie "$COOKIE" \
  "$BASE_B/api/v1/evidence/$evidence_id/storage/download" --output "$DOWNLOAD_FILE"
cmp "$EVIDENCE_FILE" "$DOWNLOAD_FILE"
curl --fail --silent --show-error --cookie "$COOKIE" --request POST \
  "$BASE_B/api/v1/evidence/$evidence_id/storage/verify-runtime" >/dev/null
curl --fail --silent --show-error --cookie "$COOKIE" \
  --header "content-type: application/json" --data '{}' \
  "$BASE_A/api/v1/regulatory/review-packs/nis2/preview" >/dev/null
curl --fail --silent --show-error --cookie "$COOKIE" \
  --header "content-type: application/json" --data '{}' \
  "$BASE_B/api/v1/regulatory/review-packs/nis2/preview" >/dev/null

"$STACK" compose exec --no-TTY postgres \
  psql --username iscy_test --dbname postgres --command 'CREATE DATABASE iscy_race' >/dev/null
race_url='postgresql://iscy_test:iscy_test_password@postgres:5432/iscy_race'
"$STACK" compose run --rm --no-deps --env "DATABASE_URL=$race_url" app-a \
  /usr/local/bin/iscy-backend migrate >"$TMP_DIR/race-a.log" 2>&1 &
race_a_pid=$!
"$STACK" compose run --rm --no-deps --env "DATABASE_URL=$race_url" app-b \
  /usr/local/bin/iscy-backend migrate >"$TMP_DIR/race-b.log" 2>&1 &
race_b_pid=$!
race_failed=0
wait "$race_a_pid" || race_failed=1
wait "$race_b_pid" || race_failed=1
if [[ "$race_failed" -ne 0 ]]; then
  cat "$TMP_DIR/race-a.log" "$TMP_DIR/race-b.log" >&2
  exit 1
fi
migration_count="$("$STACK" compose exec --no-TTY postgres psql --tuples-only --no-align \
  --username iscy_test --dbname iscy_race \
  --command 'SELECT COUNT(*) FROM iscy_schema_migrations')"
[[ "$migration_count" == "43" ]]

app_a_container="$("$STACK" compose ps --quiet app-a)"
"$STACK" compose stop --timeout 25 app-a >/dev/null
[[ "$(docker inspect --format '{{.State.ExitCode}}' "$app_a_container")" == "0" ]]
"$STACK" wait "$BASE_PROXY" "HA-Proxy nach Stopp von A"
curl --fail --silent --show-error --cookie "$COOKIE" "$BASE_PROXY/dashboard/" >/dev/null
curl --fail --silent --show-error --cookie "$COOKIE" --request PATCH \
  --header "content-type: application/json" \
  --data '{"status":"IN_PROGRESS","notes":"Failover ueber Backend B"}' \
  "$BASE_PROXY/api/v1/roadmap/tasks/1" >/dev/null
"$STACK" compose start app-a >/dev/null
"$STACK" wait "$BASE_A" "Backend A nach Neustart"

app_b_container="$("$STACK" compose ps --quiet app-b)"
"$STACK" compose stop --timeout 25 app-b >/dev/null
[[ "$(docker inspect --format '{{.State.ExitCode}}' "$app_b_container")" == "0" ]]
"$STACK" wait "$BASE_PROXY" "HA-Proxy nach Stopp von B"
curl --fail --silent --show-error --cookie "$COOKIE" \
  "$BASE_PROXY/api/v1/evidence/$evidence_id/storage/download" --output "$DOWNLOAD_FILE"
cmp "$EVIDENCE_FILE" "$DOWNLOAD_FILE"
"$STACK" compose start app-b >/dev/null
"$STACK" wait "$BASE_B" "Backend B nach Neustart"

curl --fail --silent --show-error --cookie "$COOKIE" \
  "$BASE_A/api/v1/evidence/$evidence_id/storage/download" --output "$DOWNLOAD_FILE"
cmp "$EVIDENCE_FILE" "$DOWNLOAD_FILE"

echo "ISCY Zwei-Instanzen-HA-Test OK"
