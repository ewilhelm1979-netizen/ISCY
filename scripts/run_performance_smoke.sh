#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STACK="$ROOT_DIR/scripts/resilience_stack.sh"
TMP_DIR="$(mktemp -d)"
REPORT_DIR="${ISCY_PERFORMANCE_REPORT_DIR:-$ROOT_DIR/artifacts/performance}"
REPORT_JSON="$REPORT_DIR/performance-smoke.json"
REPORT_MD="$REPORT_DIR/performance-smoke.md"
RESULTS="$TMP_DIR/results.tsv"
export ISCY_RESILIENCE_PROJECT="iscy-perf-$RANDOM-$$"

cleanup() {
  "$STACK" down >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

mkdir -p "$REPORT_DIR"
: >"$RESULTS"
BASE_URL="http://127.0.0.1:19100"
COOKIE="$TMP_DIR/session.cookies"
EVIDENCE_FILE="$TMP_DIR/performance-evidence.txt"
printf 'ISCY synthetischer Performance-Evidence-Test\n' >"$EVIDENCE_FILE"

record_request() {
  local group="$1"
  local method="$2"
  local path="$3"
  local body="$4"
  local output="$5"
  local response
  if [[ -n "$body" ]]; then
    if ! response="$(curl --silent --show-error --connect-timeout 3 --max-time 10 --output /dev/null \
      --cookie "$COOKIE" --request "$method" --header "content-type: application/json" \
      --data "$body" --write-out '%{http_code} %{time_total}' "$BASE_URL$path")"; then
      response="000 10.000"
    fi
  else
    if ! response="$(curl --silent --show-error --connect-timeout 3 --max-time 10 --output /dev/null \
      --cookie "$COOKIE" --request "$method" \
      --write-out '%{http_code} %{time_total}' "$BASE_URL$path")"; then
      response="000 10.000"
    fi
  fi
  local code="${response%% *}"
  local seconds="${response##* }"
  local milliseconds
  milliseconds="$(awk -v seconds="$seconds" 'BEGIN { printf "%.3f", seconds * 1000 }')"
  printf '%s\t%s\t%s\n' "$group" "$milliseconds" "$code" >"$output"
}

measure() {
  local group="$1"
  local method="$2"
  local path="$3"
  local body="$4"
  local count="$5"
  local parallel="$6"
  local index=0
  while ((index < count)); do
    local batch_end=$((index + parallel))
    if ((batch_end > count)); then
      batch_end="$count"
    fi
    local batch_start="$index"
    while ((index < batch_end)); do
      record_request "$group" "$method" "$path" "$body" "$TMP_DIR/result-$group-$index" &
      index=$((index + 1))
    done
    wait
    while ((batch_start < batch_end)); do
      cat "$TMP_DIR/result-$group-$batch_start" >>"$RESULTS"
      batch_start=$((batch_start + 1))
    done
  done
}

"$STACK" up
curl --fail --silent --show-error --cookie-jar "$COOKIE" \
  --header "content-type: application/json" \
  --data '{"tenant_id":1,"username":"admin","password":"Admin123!"}' \
  "$BASE_URL/api/v1/auth/sessions" >/dev/null

curl --fail --silent --show-error --cookie "$COOKIE" \
  --header "content-type: application/json" --data @- \
  "$BASE_URL/api/v1/evidence/storage/backends" >/dev/null <<'JSON'
{
  "backend_id": "performance-s3",
  "backend_type": "s3_compatible",
  "display_name": "Performance Test Object Storage",
  "status": "validation_required",
  "endpoint_reference": "http://minio:9000",
  "region": "us-east-1",
  "bucket_name": "iscy-ha-evidence",
  "key_prefix": "performance-test",
  "access_key_secret_ref": "env:ISCY_TEST_S3_ACCESS_KEY",
  "secret_key_secret_ref": "env:ISCY_TEST_S3_SECRET_KEY",
  "tls_required": false,
  "allow_path_style": true,
  "allowed_endpoint_policy": "local_dev_only",
  "known_limitations": "Ausschliesslich isolierter Performance-Smoke."
}
JSON
curl --fail --silent --show-error --cookie "$COOKIE" --request POST \
  "$BASE_URL/api/v1/evidence/storage/backends/performance-s3/validate" >/dev/null
curl --fail --silent --show-error --cookie "$COOKIE" --request POST \
  "$BASE_URL/api/v1/evidence/storage/backends/performance-s3/validate-live" >/dev/null

measurement_started_ns="$(date +%s%N)"
measure health GET /health/live '' 12 4
measure health GET /health/ready '' 12 4
measure read GET /status/ '' 6 4
measure read GET /dashboard/ '' 6 4
measure read GET /risks/ '' 6 4
measure read GET /controls/ '' 6 4
measure read GET /evidence/ '' 6 4
measure read GET /evidence/integrity/ '' 6 4
measure read GET /suppliers/product-security/ '' 6 4
measure read GET /product-security/ '' 6 4
measure read GET /regulatory-review-packs/ '' 6 4
measure read GET /zero-trust/ '' 6 4
measure review POST /api/v1/regulatory/review-packs/nis2/preview '{}' 6 2
measure write PATCH /api/v1/roadmap/tasks/1 \
  '{"status":"IN_PROGRESS","notes":"Synthetischer Performance-Smoke"}' 4 2

upload_result="$(curl --silent --show-error --cookie "$COOKIE" \
  --output "$TMP_DIR/upload.json" --write-out '%{http_code} %{time_total}' \
  --form 'title=Performance Evidence' --form 'status=SUBMITTED' \
  --form 'sensitivity=INTERNAL' --form 'storage_backend_id=performance-s3' \
  --form "file=@$EVIDENCE_FILE;filename=performance-evidence.txt;type=text/plain" \
  "$BASE_URL/api/v1/evidence/uploads")"
upload_code="${upload_result%% *}"
upload_seconds="${upload_result##* }"
upload_ms="$(awk -v seconds="$upload_seconds" 'BEGIN { printf "%.3f", seconds * 1000 }')"
printf 'object_storage\t%s\t%s\n' "$upload_ms" "$upload_code" >>"$RESULTS"
evidence_id="$(jq --exit-status --raw-output '.item.id' "$TMP_DIR/upload.json")"
measure object_storage GET "/api/v1/evidence/$evidence_id/storage/download" '' 6 2
measure object_storage POST "/api/v1/evidence/$evidence_id/storage/verify-runtime" '' 4 2
measurement_finished_ns="$(date +%s%N)"

duration_ms="$(awk -v start="$measurement_started_ns" -v finish="$measurement_finished_ns" \
  'BEGIN { printf "%.3f", (finish - start) / 1000000 }')"
total_requests="$(wc -l <"$RESULTS")"
throughput_per_second="$(awk -v requests="$total_requests" -v duration="$duration_ms" \
  'BEGIN { if (duration <= 0) print 0; else printf "%.3f", requests / (duration / 1000) }')"
timeout_count="$(awk -F '\t' '$3 == "000" {count++} END {print count + 0}' "$RESULTS")"
database_connection_errors="$(awk -F '\t' '$3 == "503" {count++} END {print count + 0}' "$RESULTS")"

groups=(health read review write object_storage)
budgets=(500 1000 2500 2000 2500)
category_files=()
budget_failed=0
for index in "${!groups[@]}"; do
  group="${groups[$index]}"
  budget="${budgets[$index]}"
  mapfile -t values < <(awk -F '\t' -v group="$group" '$1 == group {print $2}' "$RESULTS" | sort -n)
  count="${#values[@]}"
  [[ "$count" -gt 0 ]]
  p50_index=$(((50 * count + 99) / 100 - 1))
  p95_index=$(((95 * count + 99) / 100 - 1))
  p99_index=$(((99 * count + 99) / 100 - 1))
  success_count="$(awk -F '\t' -v group="$group" '$1 == group && $3 >= 200 && $3 < 400 {count++} END {print count + 0}' "$RESULTS")"
  error_count=$((count - success_count))
  p95="${values[$p95_index]}"
  passed=true
  if [[ "$error_count" -ne 0 ]] || awk -v actual="$p95" -v limit="$budget" 'BEGIN {exit !(actual > limit)}'; then
    passed=false
    budget_failed=1
  fi
  category_file="$TMP_DIR/category-$group.json"
  jq --null-input \
    --arg name "$group" --argjson count "$count" --argjson success "$success_count" \
    --argjson errors "$error_count" --argjson p50 "${values[$p50_index]}" \
    --argjson p95 "$p95" --argjson p99 "${values[$p99_index]}" \
    --argjson maximum "${values[$((count - 1))]}" --argjson budget "$budget" \
    --argjson passed "$passed" \
    '{name:$name,requests:$count,successes:$success,errors:$errors,p50_ms:$p50,p95_ms:$p95,p99_ms:$p99,max_ms:$maximum,p95_budget_ms:$budget,budget_passed:$passed}' \
    >"$category_file"
  category_files+=("$category_file")
done

jq --slurp \
  --arg generated_at "$(date --utc +%Y-%m-%dT%H:%M:%SZ)" \
  --arg environment "synthetic-postgresql16-minio-two-instance" \
  --argjson concurrency 4 \
  --argjson total_requests "$total_requests" --argjson duration_ms "$duration_ms" \
  --argjson throughput_per_second "$throughput_per_second" \
  --argjson timeout_count "$timeout_count" \
  --argjson database_connection_errors "$database_connection_errors" \
  '{schema_version:1,generated_at:$generated_at,environment:$environment,concurrency:$concurrency,total_requests:$total_requests,duration_ms:$duration_ms,throughput_per_second:$throughput_per_second,timeout_count:$timeout_count,database_connection_errors:$database_connection_errors,categories:.,contains_personal_data:false,contains_secrets:false}' \
  "${category_files[@]}" >"$REPORT_JSON"
{
  echo '# ISCY Performance-Smoke'
  echo
  echo "- Testdauer: ${duration_ms} ms"
  echo "- Durchsatz: ${throughput_per_second} Requests/s"
  echo "- Timeouts: ${timeout_count}"
  echo "- DB-/Service-Unavailable-Antworten: ${database_connection_errors}"
  echo
  echo '| Kategorie | Requests | Fehler | p50 ms | p95 ms | p99 ms | Budget |'
  echo '|---|---:|---:|---:|---:|---:|---:|'
  jq --raw-output '.categories[] | "| \(.name) | \(.requests) | \(.errors) | \(.p50_ms) | \(.p95_ms) | \(.p99_ms) | \(.p95_budget_ms) |"' "$REPORT_JSON"
} >"$REPORT_MD"

"$ROOT_DIR/scripts/check_performance_report.sh" "$REPORT_JSON"

echo "ISCY Performance-Smoke OK: $REPORT_JSON"
