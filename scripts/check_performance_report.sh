#!/usr/bin/env bash
set -euo pipefail

REPORT="${1:?Performance-Bericht fehlt}"
jq --exit-status '
  (.schema_version == 1)
  and (.contains_personal_data == false)
  and (.contains_secrets == false)
  and (.concurrency > 0 and .concurrency <= 4)
  and (.total_requests > 0)
  and (.duration_ms > 0)
  and (.throughput_per_second > 0)
  and (.timeout_count == 0)
  and (.database_connection_errors == 0)
  and ([.categories[] | select(
    .requests < 1
    or .errors != 0
    or .p95_ms > .p95_budget_ms
    or .budget_passed != true
  )] | length == 0)
' "$REPORT" >/dev/null || {
  echo "Performance-Grenzwert ueberschritten oder Bericht ungueltig." >&2
  exit 1
}
