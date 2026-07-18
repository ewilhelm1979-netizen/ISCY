#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly EXPECTED_REPOSITORY='ewilhelm1979-netizen/ISCY'
readonly MAX_FAILED_LOGS=10
readonly MAX_LOG_BYTES=262144

fail() {
  printf 'ISCY_CODEX_CI_ERROR[%s]: %s\n' "$1" "$2" >&2
  exit 1
}

validate_sha() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]] || fail sha 'Ungueltiger Commit-SHA.'
}

required_checks_json() {
  jq -cn '[
    {name:"rust-backend-tests", app:"github-actions"},
    {name:"rust-msrv-1.88", app:"github-actions"},
    {name:"rust-bootstrap-smoke", app:"github-actions"},
    {name:"nix-rust-smoke", app:"github-actions"},
    {name:"object-storage-integration", app:"github-actions"},
    {name:"performance-smoke", app:"github-actions"},
    {name:"ha-integration", app:"github-actions"},
    {name:"visual-regression", app:"github-actions"},
    {name:"docker-config", app:"github-actions"},
    {name:"release-binary-portability", app:"github-actions"},
    {name:"codex-automation-tests", app:"github-actions"},
    {name:"release-candidate-check", app:"github-actions"},
    {name:"Analyze (actions)", app:"github-actions"},
    {name:"Analyze (javascript-typescript)", app:"github-actions"},
    {name:"Analyze (rust)", app:"github-actions"},
    {name:"CodeQL", app:"github-advanced-security"}
  ]'
}

summarize_checks() {
  local input_file="$1"
  local expected_head="$2"
  local output_file="$3"
  validate_sha "$expected_head"
  [[ -f "$input_file" ]] || fail input 'Check-Run-Datei fehlt.'
  local required
  required="$(required_checks_json)"
  jq -e \
    --arg head "$expected_head" \
    --argjson required "$required" '
      (.check_runs // .) as $all
      | if ($all | type) != "array" then error("check_runs must be an array") else . end
      | [
          $required[] as $wanted
          | ([
              $all[]
              | select(.name == $wanted.name)
              | select(.app.slug == $wanted.app)
              | select(.head_sha == $head)
            ] | sort_by(.started_at // "") | last) as $run
          | {
              name: $wanted.name,
              app: $wanted.app,
              present: ($run != null),
              status: ($run.status // "missing"),
              conclusion: ($run.conclusion // ""),
              details_url: ($run.details_url // "")
            }
        ] as $checks
      | {
          head_sha: $head,
          required_total: ($required | length),
          required_present: ([$checks[] | select(.present)] | length),
          terminal: ([$checks[] | select(.present and .status == "completed")] | length) == ($required | length),
          all_green: ([$checks[] | select(.present and .status == "completed" and .conclusion == "success")] | length) == ($required | length),
          has_failure: any($checks[]; .present and .status == "completed" and (.conclusion != "success")),
          missing: [$checks[] | select(.present | not) | .name],
          pending: [$checks[] | select(.present and .status != "completed") | .name],
          failed: [$checks[] | select(.present and .status == "completed" and .conclusion != "success") | {name, app, conclusion, details_url}],
          checks: $checks
        }
    ' "$input_file" >"$output_file" || fail input 'Check-Run-Daten sind ungueltig.'
}

redact_log() {
  local input_file="$1"
  local output_file="$2"
  local local_root='/'"home"'/'
  head -c "$MAX_LOG_BYTES" "$input_file" \
    | sed -E \
        -e 's/(Authorization:[[:space:]]*(Bearer|token)[[:space:]]+)[^[:space:]]+/\1[REDACTED]/Ig' \
        -e 's#(https?://)[^/@:[:space:]]+:[^/@[:space:]]+@#\1[REDACTED]@#g' \
        -e 's/(gh[pousr]_|github_pat_|xox[baprs]-|sk-)[A-Za-z0-9_-]{10,}/[REDACTED-TOKEN]/g' \
        -e "s#${local_root}[A-Za-z0-9._-]+/[^[:space:]]*#[REDACTED-LOCAL-PATH]#g" \
        -e 's/-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----/[REDACTED-PRIVATE-KEY]/g' \
    >"$output_file"
}

fetch_checks() {
  local repository="$1"
  local expected_head="$2"
  local output_dir="$3"
  local include_logs="${4:-false}"
  [[ "$repository" == "$EXPECTED_REPOSITORY" ]] || fail repository 'Falsches Repository.'
  validate_sha "$expected_head"
  [[ "$include_logs" == 'true' || "$include_logs" == 'false' ]] \
    || fail usage 'include_logs muss true oder false sein.'
  [[ -n "${GH_TOKEN:-}" ]] || fail token 'Read-only GitHub-Token fehlt.'
  command -v gh >/dev/null 2>&1 || fail prerequisite 'gh fehlt.'
  command -v jq >/dev/null 2>&1 || fail prerequisite 'jq fehlt.'
  rm -rf -- "$output_dir"
  mkdir -p -- "$output_dir/logs"
  gh api -H 'Accept: application/vnd.github+json' \
    "repos/$repository/commits/$expected_head/check-runs?filter=latest&per_page=100" \
    >"$output_dir/checks.json"
  summarize_checks "$output_dir/checks.json" "$expected_head" "$output_dir/summary.json"

  if [[ "$include_logs" == 'true' ]]; then
    local count=0 details_url job_id raw_log safe_log
    while IFS= read -r details_url; do
      (( count += 1 ))
      (( count <= MAX_FAILED_LOGS )) || fail log_limit 'Zu viele fehlgeschlagene Jobs.'
      if [[ "$details_url" =~ ^https://github\.com/ewilhelm1979-netizen/ISCY/actions/runs/[0-9]+/job/([0-9]+)$ ]]; then
        job_id="${BASH_REMATCH[1]}"
      else
        continue
      fi
      raw_log="$output_dir/logs/job-${job_id}.raw"
      safe_log="$output_dir/logs/job-${job_id}.log"
      gh api "repos/$repository/actions/jobs/$job_id/logs" >"$raw_log"
      redact_log "$raw_log" "$safe_log"
      rm -f -- "$raw_log"
    done < <(jq -r '.failed[].details_url | select(length > 0)' "$output_dir/summary.json")
  fi
}

case "${1:-}" in
  summarize) summarize_checks "${2:-}" "${3:-}" "${4:-}" ;;
  fetch) fetch_checks "${2:-}" "${3:-}" "${4:-}" "${5:-false}" ;;
  *) fail usage 'Erlaubt sind summarize und fetch.' ;;
esac
