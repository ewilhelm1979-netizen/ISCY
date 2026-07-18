#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly ISCY_REPOSITORY_EXPECTED='ewilhelm1979-netizen/ISCY'
readonly ISCY_OWNER_EXPECTED='ewilhelm1979-netizen'
readonly ISCY_FIX_LIMIT=2
guard_tmp_dir=''

cleanup() {
  if [[ -n "$guard_tmp_dir" ]]; then
    rm -rf -- "$guard_tmp_dir"
  fi
}

trap cleanup EXIT INT TERM

fail() {
  local class="$1"
  local message="$2"
  printf 'ISCY_CODEX_GUARD_ERROR[%s]: %s\n' "$class" "$message" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail prerequisite "$1 fehlt."
}

require_env() {
  local name="$1"
  [[ -n "${!name:-}" ]] || fail environment "$name fehlt."
}

validate_sha() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]] || fail sha "Ungueltiger Commit-SHA."
}

has_label() {
  local wanted="$1"
  grep -Fxq -- "$wanted" <<<"${ISCY_PR_LABELS:-}"
}

parse_command() {
  require_env ISCY_COMMAND_TEXT
  local value="$ISCY_COMMAND_TEXT"
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] \
    || fail command "Mehrzeilige Kommandos sind nicht erlaubt."
  shopt -s extglob
  value="${value##+([[:space:]])}"
  value="${value%%+([[:space:]])}"
  case "$value" in
    '/iscy status') printf 'status\n' ;;
    '/iscy review') printf 'review\n' ;;
    '/iscy fix-ci') printf 'fix-ci\n' ;;
    '/iscy verify') printf 'verify\n' ;;
    *) fail command "Unbekanntes oder nicht exakt formuliertes Kommando." ;;
  esac
}

validate_pr() {
  local mode="${1:-manual}"
  for name in \
    ISCY_REPOSITORY ISCY_EVENT_ACTOR ISCY_PR_AUTHOR ISCY_PR_STATE \
    ISCY_PR_DRAFT ISCY_PR_BASE_REF ISCY_PR_BASE_SHA ISCY_PR_HEAD_REPOSITORY \
    ISCY_PR_HEAD_REF ISCY_PR_HEAD_SHA ISCY_PR_LABELS; do
    require_env "$name"
  done
  [[ "$ISCY_REPOSITORY" == "$ISCY_REPOSITORY_EXPECTED" ]] \
    || fail repository "Falsches Repository."
  if [[ "$mode" == 'automatic' ]]; then
    case "$ISCY_EVENT_ACTOR" in
      "$ISCY_OWNER_EXPECTED"|'github-actions[bot]') ;;
      *) fail actor "Der automatische Lauf wurde nicht durch einen erlaubten Actor ausgeloest." ;;
    esac
  else
    [[ "$ISCY_EVENT_ACTOR" == "$ISCY_OWNER_EXPECTED" ]] \
      || fail actor "Nur der freigegebene Maintainer darf den Orchestrator ausloesen."
  fi
  [[ "$ISCY_PR_AUTHOR" == "$ISCY_OWNER_EXPECTED" ]] \
    || fail author "Pull Requests fremder Benutzer sind nicht erlaubt."
  if [[ "$mode" == 'manual' ]]; then
    require_env ISCY_EVENT_ASSOCIATION
    case "$ISCY_EVENT_ASSOCIATION" in
      OWNER|MEMBER) ;;
      *) fail association "Die Kommentar-Association ist nicht ausreichend." ;;
    esac
  fi
  [[ "$ISCY_PR_STATE" == 'open' ]] || fail state "Der Pull Request ist nicht offen."
  [[ "$ISCY_PR_DRAFT" == 'true' ]] || fail draft "Nur Draft-Pull-Requests sind erlaubt."
  [[ "$ISCY_PR_BASE_REF" == 'main' ]] || fail base "Der Zielbranch muss main sein."
  validate_sha "$ISCY_PR_BASE_SHA"
  validate_sha "$ISCY_PR_HEAD_SHA"
  [[ "$ISCY_PR_HEAD_REPOSITORY" == "$ISCY_REPOSITORY_EXPECTED" ]] \
    || fail fork "Fork-Pull-Requests sind nicht erlaubt."
  [[ "$ISCY_PR_HEAD_REF" != 'main' && "$ISCY_PR_HEAD_REF" != dependabot/* ]] \
    || fail branch "main und Dependabot-Branches sind nicht erlaubt."
  has_label codex-approved || fail label "Das Label codex-approved fehlt."
  if [[ "$mode" == 'automatic' || "${ISCY_COMMAND:-}" == 'fix-ci' ]]; then
    has_label codex-managed || fail label "Das Label codex-managed fehlt."
  fi
}

attempt_state() {
  local comments_file="$1"
  [[ -f "$comments_file" ]] || fail attempts "Kommentar-Datei fehlt."
  require_command jq
  local used
  used="$(jq -er '
    if type != "array" then error("comments must be an array") else . end
    | [
        .[]
        | select(.user.login == "github-actions[bot]")
        | .body
        | try capture("(?m)^<!-- iscy-codex-fix-attempt:(?<attempt>[12]) -->$").attempt
          catch empty
      ]
    | unique
    | length
  ' "$comments_file")" || fail attempts "Kommentar-Marker sind ungueltig."
  local remaining=$((ISCY_FIX_LIMIT - used))
  local allowed=true
  local next=$((used + 1))
  if (( remaining <= 0 )); then
    remaining=0
    allowed=false
    next=0
  fi
  jq -cn \
    --argjson used "$used" \
    --argjson remaining "$remaining" \
    --argjson next "$next" \
    --argjson allowed "$allowed" \
    '{used: $used, remaining: $remaining, next: $next, allowed: $allowed}'
}

validate_result() {
  local result_file="${1:-}"
  local expected_action="${2:-}"
  [[ -f "$result_file" ]] || fail result 'Codex-Ergebnis fehlt.'
  case "$expected_action" in
    review|fix-ci|verify) ;;
    *) fail result 'Ungueltige erwartete Ergebnisaktion.' ;;
  esac
  local result_size
  result_size="$(wc -c <"$result_file")"
  (( result_size > 0 && result_size <= 65536 )) \
    || fail result 'Codex-Ergebnis liegt ausserhalb der Groessenbegrenzung.'
  jq -e --arg action "$expected_action" '
    (keys_unsorted - [
      "action", "status", "summary", "root_cause", "changed_files",
      "tests_run", "tests_passed", "blockers", "security_notes",
      "scope_notes", "recommended_human_action"
    ] | length) == 0
    and .action == $action
    and (.status | IN(
      "READY_FOR_HUMAN_REVIEW", "FIX_PREPARED", "BLOCKED", "INCOMPLETE",
      "SECURITY_REVIEW_REQUIRED"
    ))
    and (.summary | type == "string" and length > 0 and length <= 4000)
    and (.root_cause | type == "string" and length <= 4000)
    and (.changed_files | type == "array" and length <= 200 and all(.[]; type == "string" and length <= 500))
    and (.tests_run | type == "array" and length <= 100 and all(.[]; type == "string" and length <= 1000))
    and (.tests_passed | type == "boolean")
    and (.blockers | type == "array" and length <= 100 and all(.[]; type == "string" and length <= 2000))
    and (.security_notes | type == "array" and length <= 100 and all(.[]; type == "string" and length <= 2000))
    and (.scope_notes | type == "array" and length <= 100 and all(.[]; type == "string" and length <= 2000))
    and (.recommended_human_action | type == "string" and length > 0 and length <= 2000)
  ' "$result_file" >/dev/null || fail result 'Codex-Ergebnis verletzt das geschlossene Schema.'

  local local_root='/'"home"'/'
  if grep -Eiq \
    -e '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}' \
    "$result_file"; then
    fail result 'Codex-Ergebnis enthaelt einen moeglichen Secretwert.'
  fi
  if grep -Fq -- "$local_root" "$result_file"; then
    fail result 'Codex-Ergebnis enthaelt einen lokalen absoluten Pfad.'
  fi
  if grep -Eiq -e 'https?://[^/@:[:space:]"<>]+:[^/@[:space:]"<>]+@' "$result_file"; then
    fail result 'Codex-Ergebnis enthaelt eine URL mit moeglichen Zugangsdaten.'
  fi
}

reserve_attempt() {
  local repository="${1:-}"
  local pr_number="${2:-}"
  local expected_head="${3:-}"
  [[ "$repository" == "$ISCY_REPOSITORY_EXPECTED" ]] || fail repository "Falsches Repository."
  [[ "$pr_number" =~ ^[1-9][0-9]*$ ]] || fail pull_request "Ungueltige PR-Nummer."
  validate_sha "$expected_head"
  require_env GH_TOKEN
  require_command gh
  require_command jq

  guard_tmp_dir="$(mktemp -d)"
  gh api "repos/$repository/pulls/$pr_number" >"$guard_tmp_dir/pr.json"
  gh api --paginate --slurp "repos/$repository/issues/$pr_number/comments?per_page=100" \
    | jq 'add // []' >"$guard_tmp_dir/comments.json"

  export ISCY_REPOSITORY="$repository"
  export ISCY_EVENT_ACTOR="$ISCY_OWNER_EXPECTED"
  export ISCY_EVENT_ASSOCIATION='OWNER'
  export ISCY_COMMAND='fix-ci'
  export ISCY_PR_AUTHOR
  export ISCY_PR_STATE
  export ISCY_PR_DRAFT
  export ISCY_PR_BASE_REF
  export ISCY_PR_BASE_SHA
  export ISCY_PR_HEAD_REPOSITORY
  export ISCY_PR_HEAD_REF
  export ISCY_PR_HEAD_SHA
  export ISCY_PR_LABELS
  ISCY_PR_AUTHOR="$(jq -er '.user.login' "$guard_tmp_dir/pr.json")"
  ISCY_PR_STATE="$(jq -er '.state' "$guard_tmp_dir/pr.json")"
  ISCY_PR_DRAFT="$(jq -er '.draft' "$guard_tmp_dir/pr.json")"
  ISCY_PR_BASE_REF="$(jq -er '.base.ref' "$guard_tmp_dir/pr.json")"
  ISCY_PR_BASE_SHA="$(jq -er '.base.sha' "$guard_tmp_dir/pr.json")"
  ISCY_PR_HEAD_REPOSITORY="$(jq -er '.head.repo.full_name' "$guard_tmp_dir/pr.json")"
  ISCY_PR_HEAD_REF="$(jq -er '.head.ref' "$guard_tmp_dir/pr.json")"
  ISCY_PR_HEAD_SHA="$(jq -er '.head.sha' "$guard_tmp_dir/pr.json")"
  ISCY_PR_LABELS="$(jq -r '.labels[].name' "$guard_tmp_dir/pr.json")"
  validate_pr automatic
  [[ "$ISCY_PR_HEAD_SHA" == "$expected_head" ]] \
    || fail head_race "Der PR-Head hat sich vor der Reservierung geaendert."

  local state allowed attempt
  state="$(attempt_state "$guard_tmp_dir/comments.json")"
  allowed="$(jq -er '.allowed' <<<"$state")"
  [[ "$allowed" == 'true' ]] || {
    local stopped_marker='<!-- iscy-codex-stopped:maximum-fix-attempts -->'
    if ! jq -e --arg marker "$stopped_marker" '
      any(.[]; .user.login == "github-actions[bot]" and (.body | startswith($marker)))
    ' "$guard_tmp_dir/comments.json" >/dev/null; then
      gh api --method POST "repos/$repository/issues/$pr_number/comments" \
        --raw-field body="${stopped_marker}

CODEX_STOPPED: maximum_fix_attempts_reached" >/dev/null
    fi
    printf 'CODEX_STOPPED: maximum_fix_attempts_reached\n' >&2
    exit 4
  }
  attempt="$(jq -er '.next' <<<"$state")"
  local marker body response
  marker="<!-- iscy-codex-fix-attempt:${attempt} -->"
  body="${marker}

Codex CI-Fix-Versuch ${attempt} von ${ISCY_FIX_LIMIT} wurde fuer Head \`${expected_head}\` reserviert."
  response="$(gh api --method POST "repos/$repository/issues/$pr_number/comments" \
    --raw-field body="$body")"
  jq -cn \
    --argjson attempt "$attempt" \
    --argjson comment_id "$(jq -er '.id' <<<"$response")" \
    --arg marker "$marker" \
    '{attempt: $attempt, comment_id: $comment_id, marker: $marker}'
}

case "${1:-}" in
  command) parse_command ;;
  pr) validate_pr "${2:-manual}" ;;
  attempts) attempt_state "${2:-}" ;;
  result) validate_result "${2:-}" "${3:-}" ;;
  reserve-attempt) reserve_attempt "${2:-}" "${3:-}" "${4:-}" ;;
  *) fail usage "Erlaubt sind command, pr, attempts, result und reserve-attempt." ;;
esac
