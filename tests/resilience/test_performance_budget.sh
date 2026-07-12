#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

cat >"$TMP_DIR/pass.json" <<'JSON'
{"schema_version":1,"concurrency":4,"total_requests":10,"duration_ms":1000,"throughput_per_second":10,"timeout_count":0,"database_connection_errors":0,"contains_personal_data":false,"contains_secrets":false,"categories":[{"requests":10,"errors":0,"p95_ms":499,"p95_budget_ms":500,"budget_passed":true}]}
JSON
"$ROOT_DIR/scripts/check_performance_report.sh" "$TMP_DIR/pass.json"

cat >"$TMP_DIR/fail.json" <<'JSON'
{"schema_version":1,"concurrency":4,"total_requests":10,"duration_ms":1000,"throughput_per_second":10,"timeout_count":0,"database_connection_errors":0,"contains_personal_data":false,"contains_secrets":false,"categories":[{"requests":10,"errors":0,"p95_ms":501,"p95_budget_ms":500,"budget_passed":false}]}
JSON
if "$ROOT_DIR/scripts/check_performance_report.sh" "$TMP_DIR/fail.json" >/dev/null 2>&1; then
  echo "Budget-Ueberschreitung wurde nicht erkannt." >&2
  exit 1
fi

cat >"$TMP_DIR/timeout.json" <<'JSON'
{"schema_version":1,"concurrency":4,"total_requests":10,"duration_ms":1000,"throughput_per_second":10,"timeout_count":1,"database_connection_errors":0,"contains_personal_data":false,"contains_secrets":false,"categories":[{"requests":10,"errors":1,"p95_ms":499,"p95_budget_ms":500,"budget_passed":false}]}
JSON
if "$ROOT_DIR/scripts/check_performance_report.sh" "$TMP_DIR/timeout.json" >/dev/null 2>&1; then
  echo "Timeout wurde nicht erkannt." >&2
  exit 1
fi

echo "Performance-Berichts- und Budgettest OK"
